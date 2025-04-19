// SPDX-License-Identifier: GPL-2.0-or-later
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <inttypes.h>
#include <string.h>
#include <time.h>

#include "nvme.h"
#include "libnvme.h"
#include "plugin.h"
#include "transcend-nvme.h"
#include "common.h"

#define CREATE_CMD

#define PLP_RECORD_PATH		"PLPRec.txt"
#define PLP_DATA_EXPIRED_TIME	20


/* Bad block command parameters */
static const __u32 OP_BAD_BLOCK  = 0xc2;
static const __u32 DW10_BAD_BLOCK = 0x400;
static const __u32 DW12_BAD_BLOCK = 0x5a;

/* Health command parameters */
static const __u32 OP_HEALTH	= 0xc2;
static const __u32 DW10_HEALTH	= 0x01;
static const __u32 DW12_HEALTH	= 0xb3;

/* ID command parameters */
static const __u32 OP_ID	= 0x06;
static const __u32 DW10_ID	= 0x01;

/* PLP constants */
static const int i_dis		= 20;
static const double full_value	= 170;

enum plp_error_code {
	PLP_ERROR_NO_MATCH	= -1,
	PLP_ERROR_DATA_EXPIRED	= -2,
};

static const char *string_list[] = {
	"UTE210T",
	"MTE712P",
	"MTE560P",
	"MTE662P",
	"MTE662P-I",
	"MTS970P",
	"MTS952P",
	"MTS952P-I",
	"MTS570P",
	"MTS400P",
	"SSD910T",
	"SSD470P",
	"SSD470P-I",
	"SSD452P",
	"SSD452P-I",
	"SSD420P",
	"MSA470P",
	"MSA452P",
};

static const int list_size = ARRAY_SIZE(string_list);

static int get_plp_health(int argc, char **argv, struct command *cmd,
			  struct plugin *plugin);
static int read_useful_plp_value(const char *device);
static void record_plp_value(const char *device, int value, bool is_replace);

static int get_health_value(int argc, char **argv, struct command *cmd,
			    struct plugin *plugin)
{
	struct nvme_smart_log smart_log;
	struct nvme_dev *dev;
	char *desc = "Get nvme health percentage.";
	int percent_used = 0;
	int health_value = 0;
	int ret;
	
	OPT_ARGS(opts) = {
		OPT_END()
	};

	ret = parse_and_open(&dev, argc, argv, desc, opts);
	if (ret) {
		pr_err("Device not found\n");
		return -ENODEV;
	}

	ret = nvme_get_log_smart(dev_fd(dev), 0xffffffff, false, &smart_log);
	if (!ret) {
		pr_info("Transcend NVME health value: ");
		percent_used = smart_log.percent_used;

		if (percent_used > 100 || percent_used < 0) {
			pr_info("0%%\n");
		} else {
			health_value = 100 - percent_used;
			pr_info("%d%%\n", health_value);
		}
	}

	dev_close(dev);
	return ret;
}

static int get_bad_block(int argc, char **argv, struct command *cmd,
			struct plugin *plugin)
{
	struct nvme_passthru_cmd nvme_cmd = { 0 };
	struct nvme_dev *dev;
	char *desc = "Get nvme bad block number.";
	unsigned char data[1] = { 0 };
	int ret;

	OPT_ARGS(opts) = {
		OPT_END()
	};

	ret = parse_and_open(&dev, argc, argv, desc, opts);
	if (ret) {
		pr_err("Device not found\n");
		return -ENODEV;
	}

	nvme_cmd.opcode = OP_BAD_BLOCK;
	nvme_cmd.cdw10 = DW10_BAD_BLOCK;
	nvme_cmd.cdw12 = DW12_BAD_BLOCK;
	nvme_cmd.addr = (__u64)(uintptr_t)data;
	nvme_cmd.data_len = 0x1;

	ret = nvme_submit_admin_passthru(dev_fd(dev), &nvme_cmd, NULL);
	if (!ret)
		pr_info("Transcend NVME badblock count: %d\n", data[0]);

	dev_close(dev);
	return ret;
}

static const char *format_char_array(char *str, int str_size,
				   unsigned char *chr, int chr_size)
{
	int b = 0;
	int n = 0;
	int i;

	while (b < chr_size && chr[b] == ' ')
		b++;

	while (b + n < chr_size && chr[b + n])
		n++;

	while (n > 0 && chr[b + n - 1] == ' ')
		n--;

	if (n >= str_size)
		n = str_size - 1;

	for (i = 0; i < n; i++) {
		char c = chr[b + i];
		str[i] = (' ' <= c && c <= '~' ? c : '?');
	}

	str[n] = 0;
	return str;
}

static int contains_string(const char *str)
{
	int i;

	for (i = 0; i < list_size; i++) {
		if (strstr(str, string_list[i]))
			return 1;
	}

	return 0;
}

static int get_plp_health(int argc, char **argv, struct command *cmd,
			 struct plugin *plugin)
{
	struct nvme_passthru_cmd nvme_cmd = { 0 };
	struct nvme_dev *dev;
	char *desc = "Get nvme PLP Health.";
	char model_name[40];
	unsigned char data_id[4096];
	unsigned char data[512];
	const char *model_str;
	int txt_plp_health = -1;
	int plp_health = -1;
	int ret;

	OPT_ARGS(opts) = {
		OPT_END()
	};

	ret = parse_and_open(&dev, argc, argv, desc, opts);
	if (ret) {
		pr_err("Device not found\n");
		return -ENODEV;
	}

	/* Check if device is supported */
	memset(&nvme_cmd, 0, sizeof(nvme_cmd));
	nvme_cmd.opcode = OP_ID;
	nvme_cmd.cdw10 = DW10_ID;
	nvme_cmd.addr = (__u64)(uintptr_t)data_id;
	nvme_cmd.data_len = 4096;

	ret = nvme_submit_admin_passthru(dev_fd(dev), &nvme_cmd, NULL);
	if (ret) {
		pr_err("Device is not supported\n");
		goto close_dev;
	}

	model_str = format_char_array(model_name, sizeof(model_name),
				     data_id, sizeof(data_id));
	if (!contains_string(model_str)) {
		pr_err("Device is not supported\n");
		ret = -EINVAL;
		goto close_dev;
	}

	/* Try reading from cache first */
	txt_plp_health = read_useful_plp_value(dev->name);
	if (txt_plp_health >= 0) {
		plp_health = txt_plp_health;
		pr_info("Capacitor health for PLP: %d%%\n", plp_health);
		goto record_value;
	}

	/* Query device directly */
	memset(&nvme_cmd, 0, sizeof(nvme_cmd));
	nvme_cmd.opcode = OP_HEALTH;
	nvme_cmd.cdw10 = DW10_HEALTH;
	nvme_cmd.cdw12 = DW12_HEALTH;
	nvme_cmd.addr = (__u64)(uintptr_t)data;
	nvme_cmd.data_len = 512;

	ret = nvme_submit_admin_passthru(dev_fd(dev), &nvme_cmd, NULL);
	if (ret) {
		pr_err("Failed to get PLP Health\n");
		ret = -EIO;
		goto close_dev;
	}

	/* Calculate PLP health */
	{
		int t_dis = (int)(data[4 + 3] << 24) + (int)(data[4 + 2] << 16) +
			    (int)(data[4 + 1] << 8) + (int)(data[4]);
		int v_dis1 = (int)(data[0]);
		int v_dis2 = (int)(data[1]);
		int normal_health;

		if (v_dis1 == 0 && v_dis2 == 0)
			goto close_dev;

		if (v_dis1 - v_dis2 != 0)
			normal_health = (i_dis * t_dis) / (v_dis1 - v_dis2);
		else
			normal_health = 0;

		if (normal_health >= 0) {
			if (full_value - normal_health >= 0)
				plp_health = (normal_health / full_value) * 100;
			else
				plp_health = 100;
		} else {
			plp_health = 0;
		}

		pr_info("Capacitor health for PLP: %d%%\n", plp_health);
	}

record_value:
	if (plp_health >= 0) {
		if (txt_plp_health == PLP_ERROR_DATA_EXPIRED)
			record_plp_value(dev->name, plp_health, true);
		else
			record_plp_value(dev->name, plp_health, false);
	}

close_dev:
	dev_close(dev);
	return ret;
}
static int read_useful_plp_value(const char *device)
{
	char log_file_path[256];
	char str[256];
	char matched_str[256] = "";
	FILE *file;
	char *token;
	struct tm tm = { 0 };
	time_t t, t_current;
	int time_diff;
	int ret = -1;

	snprintf(log_file_path, sizeof(log_file_path), "%s", PLP_RECORD_PATH);
	file = fopen(log_file_path, "r");
	if (!file)
		return PLP_ERROR_NO_MATCH;

	while (fgets(str, sizeof(str), file)) {
		if (strncmp(str, device, strlen(device)) == 0) {
			strcpy(matched_str, str);
			break;
		}
	}

	fclose(file);

	if (matched_str[0] == '\0')
		return PLP_ERROR_NO_MATCH;

	token = strtok(matched_str, "#");
	token = strtok(NULL, "#");

	if (!strptime(token, "%a %b %d %H:%M:%S %Y", &tm))
		return PLP_ERROR_NO_MATCH;

	t = mktime(&tm);
	t_current = time(NULL);
	time_diff = difftime(t_current, t);

	if (time_diff > PLP_DATA_EXPIRED_TIME)
		return PLP_ERROR_DATA_EXPIRED;

	token = strtok(NULL, "#");
	ret = atoi(token);

	return ret;
}

static void record_plp_value(const char *device, int value, bool is_replace)
{
	char log_path[256];
	char tmp_path[] = "temp.txt";
	time_t cur_time;
	char *time_str;
	char line[256];
	FILE *fp_in, *fp_out;

	strncpy(log_path, PLP_RECORD_PATH, sizeof(log_path) - 1);
	log_path[sizeof(log_path) - 1] = '\0';

	cur_time = time(0);
	time_str = ctime(&cur_time);
	if (!time_str) {
		perror("Failed to get current time");
		return;
	}
	time_str[strcspn(time_str, "\n")] = '\0';

	snprintf(line, sizeof(line), "%s#%s#%d", device, time_str, value);

	if (!is_replace) {
		fp_out = fopen(log_path, "a");
		if (!fp_out) {
			perror("Failed to open log file");
			return;
		}
		fprintf(fp_out, "%s\n", line);
		fclose(fp_out);
		return;
	}

	/* Handle replace case */
	fp_in = fopen(log_path, "r");
	fp_out = fopen(tmp_path, "w");
	if (!fp_in || !fp_out) {
		perror("Failed to open files");
		if (fp_in)
			fclose(fp_in);
		if (fp_out)
			fclose(fp_out);
		return;
	}

	while (fgets(line, sizeof(line), fp_in)) {
		if (strncmp(line, device, strlen(device)) == 0)
			fprintf(fp_out, "%s\n", line);
		else
			fprintf(fp_out, "%s", line);
	}

	fclose(fp_in);
	fclose(fp_out);

	if (remove(log_path) == 0) {
		rename(tmp_path, log_path);
	} else {
		remove(tmp_path);
	}
}