// SPDX-License-Identifier: GPL-2.0-or-later
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <inttypes.h>

#include "nvme.h"
#include "libnvme.h"
#include "plugin.h"
#include <string.h>
#include <time.h>

#define CREATE_CMD

#define PLPRecordPath "PLPRec.txt"
#define PLPDataExpiredTime 20

#include "transcend-nvme.h"

static const __u32 OP_BAD_BLOCK = 0xc2;
static const __u32 DW10_BAD_BLOCK = 0x400;
static const __u32 DW12_BAD_BLOCK = 0x5a;

static const __u32 OP_HEALTH = 0xc2;
static const __u32 DW10_HEALTH = 0x01;
static const __u32 DW12_HEALTH = 0xb3;

static const __u32 OP_ID = 0x06;
static const __u32 DW10_ID = 0x01;

static const int iDis = 20;
static const double fullValue = 170;

enum PLPErrorCode
{
	PLP_ERROR_NO_MATCH = -1,
	PLP_ERROR_DATA_EXPIRED = -2
};

const char *string_list[] = {
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
	"MSA452P"};
const int list_size = sizeof(string_list) / sizeof(string_list[0]);

static int getPLPHealth(int argc, char **argv, struct command *cmd, struct plugin *plugin);
static int readUsefulPLPValue(const char *device);
static void recordPLPValue(const char *device, int value, bool isReplace);

static int getHealthValue(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	struct nvme_smart_log smart_log;
	char *desc = "Get nvme health percentage.";
	int percent_used = 0;
	int healthvalue = 0;
	struct nvme_dev *dev;
	int result;

	OPT_ARGS(opts) = {
		OPT_END()
	};

	result = parse_and_open(&dev, argc, argv, desc, opts);
	if (result) {
		printf("\nDevice not found\n");
		return PLP_ERROR_NO_MATCH;
	}
	result = nvme_get_log_smart(dev_fd(dev), 0xffffffff, false, &smart_log);
	if (!result) {
		printf("Transcend NVME heath value: ");
		percent_used = smart_log.percent_used;

		if (percent_used > 100 || percent_used < 0) {
			printf("0%%\n");
		}
		else {
			healthvalue = 100 - percent_used;
			printf("%d%%\n", healthvalue);
		}
	}
	dev_close(dev);
	return result;
}

static int getBadblock(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{

	char *desc = "Get nvme bad block number.";
	struct nvme_dev *dev;
	int result;

	OPT_ARGS(opts) = {
		OPT_END()
	};

	result = parse_and_open(&dev, argc, argv, desc, opts);
	if (result) {
		printf("\nDevice not found\n");
		return -1;
	}
	unsigned char data[1] = {0};
	struct nvme_passthru_cmd nvmecmd;

	memset(&nvmecmd, 0, sizeof(nvmecmd));
	nvmecmd.opcode = OP_BAD_BLOCK;
	nvmecmd.cdw10 = DW10_BAD_BLOCK;
	nvmecmd.cdw12 = DW12_BAD_BLOCK;
	nvmecmd.addr = (__u64)(uintptr_t)data;
	nvmecmd.data_len = 0x1;
	result = nvme_submit_admin_passthru(dev_fd(dev), &nvmecmd, NULL);
	if (!result) {
		int badblock = data[0];
		printf("Transcend NVME badblock count: %d\n", badblock);
	}
	dev_close(dev);
	return result;
}

const char *format_char_array(char *str, int strsize, unsigned char *chr, int chrsize)
{
	int b = 0;
	int n = 0;
	int i;

	while (b < chrsize && chr[b] == ' ')
		b++;

	while (b + n < chrsize && chr[b + n])
		n++;

	while (n > 0 && chr[b + n - 1] == ' ')
		n--;

	if (n >= strsize)
		n = strsize - 1;

	for (i = 0; i < n; i++) {
		char c = chr[b + i];
		str[i] = (' ' <= c && c <= '~' ? c : '?');
	}

	str[n] = 0;
	return str;
}

int contains_string(const char *str)
{
	for (int i = 0; i < list_size; i++)
	{
		if (strstr(str, string_list[i]) != NULL)
		{
			return 1;
		}
	}
	return 0;
}

static int getPLPHealth(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	char *desc = "Get nvme PLP Health.";
	struct nvme_dev *dev;
	int result;
	int txtPLPHealth = -1;
	int plpHealth_percentage = -1;
	OPT_ARGS(opts) = {
		OPT_END()
	};

	result = parse_and_open(&dev, argc, argv, desc, opts);
	if (result) {
		printf("\nDevice not found\n");
		return -1;
	}

	unsigned char dataID[4096];
	struct nvme_passthru_cmd nvmecmdID;

	memset(&nvmecmdID, 0, sizeof(nvmecmdID));
	nvmecmdID.opcode = OP_ID;
	nvmecmdID.cdw10 = DW10_ID;
	nvmecmdID.addr = (__u64)(uintptr_t)dataID;
	nvmecmdID.data_len = 4096;
	result = nvme_submit_admin_passthru(dev_fd(dev), &nvmecmdID, NULL);
	if (result) {
		printf("\nThis device is not support.\n");
		return -1;
	}
	else {
		char modelName[40];
		const char *model_str_byte;
		model_str_byte = format_char_array((char *)modelName, sizeof(modelName), dataID, sizeof(dataID));
		if (!contains_string(model_str_byte)) {
			printf("\nThis device is not support.\n");
			return -1;
		}
	}

	txtPLPHealth = readUsefulPLPValue(dev->name);
	if (txtPLPHealth >= 0) {
		plpHealth_percentage = txtPLPHealth;
		printf("Capacitor health for PLP: %d%%\n", plpHealth_percentage);
	}
	else {
		unsigned char data[512];
		struct nvme_passthru_cmd nvmecmd;

		memset(&nvmecmd, 0, sizeof(nvmecmd));
		nvmecmd.opcode = OP_HEALTH;
		nvmecmd.cdw10 = DW10_HEALTH;
		nvmecmd.cdw12 = DW12_HEALTH;
		nvmecmd.addr = (__u64)(uintptr_t)data;
		nvmecmd.data_len = 512;
		result = nvme_submit_admin_passthru(dev_fd(dev), &nvmecmd, NULL);
		if (result) {
			printf("\nGet PLP Health Fail.\n");
			return PLP_ERROR_NO_MATCH;
		}
		else {
			int tDis = (int)(data[4 + 3] << 24) + (int)(data[4 + 2] << 16) + (int)(data[4 + 1] << 8) + (int)(data[4]);
			int vDis1 = (int)(data[0]);
			int vDis2 = (int)(data[1]);
			if (vDis1 != 0 || vDis2 != 0) {
				int normalHealth = 0;

				if (vDis1 - vDis2 != 0) {
					normalHealth = (iDis * tDis) / (vDis1 - vDis2);
				}
				else {
					normalHealth = 0;
				}
				if (normalHealth >= 0) {
					if (fullValue - normalHealth >= 0) {
						plpHealth_percentage = (normalHealth / fullValue) * 100;
					}
					else {
						plpHealth_percentage = 100;
					}
				}
				else {
					plpHealth_percentage = 0;
				}
				printf("Capacitor health for PLP: %d%%\n", plpHealth_percentage);
			}
		}
	}
	if (plpHealth_percentage >= 0) {
		if (txtPLPHealth == PLP_ERROR_DATA_EXPIRED) {
			recordPLPValue(dev->name, plpHealth_percentage, true);
		}
		else {
			recordPLPValue(dev->name, plpHealth_percentage, false);
		}
	}
	dev_close(dev);
	return result;
}

int readUsefulPLPValue(const char *device)
{
	FILE *file;
	char logFilePath[256];
	char str[256];
	char matchedStr[256] = "";
	int ret = -1;

	snprintf(logFilePath, sizeof(logFilePath), "%s", PLPRecordPath);
	file = fopen(logFilePath, "r");
	if (!file) {
		return PLP_ERROR_NO_MATCH;
	}

	while (fgets(str, sizeof(str), file))
	{
		if (strncmp(str, device, strlen(device)) == 0) {
			strcpy(matchedStr, str);
			break;
		}
	}

	fclose(file);

	if (matchedStr[0] == '\0') {
		return PLP_ERROR_NO_MATCH;
	}

	char *token;
	token = strtok(matchedStr, "#");
	token = strtok(NULL, "#");
	struct tm tm;
	memset(&tm, 0, sizeof(tm));
	strptime(token, "%a %b %d %H:%M:%S %Y", &tm);
	time_t t = mktime(&tm);

	time_t t_current = time(NULL);
	int timeDiff = difftime(t_current, t);

	if (timeDiff <= PLPDataExpiredTime) {
		token = strtok(NULL, "#");
		ret = atoi(token);
		return ret;
	}
	else {
		return PLP_ERROR_DATA_EXPIRED;
	}
}

void recordPLPValue(const char *device, int value, bool isReplace)
{
	char logFilePath[256];
	strncpy(logFilePath, PLPRecordPath, sizeof(logFilePath) - 1);
	logFilePath[sizeof(logFilePath) - 1] = '\0';
	char tempFilePath[] = "temp.txt";

	time_t ct = time(0);
	char *timeStr = ctime(&ct);
	if (timeStr == NULL) {
		perror("Error getting current time");
		return;
	}
	timeStr[strcspn(timeStr, "\n")] = '\0';

	char line[256];
	sprintf(line, "%s#%s#%d", device, timeStr, value);

	if (isReplace) {
		FILE *filein = fopen(logFilePath, "r");
		FILE *fileout = fopen(tempFilePath, "w");
		if (filein == NULL || fileout == NULL) {
			perror("Error opening file");
			if (filein != NULL)
				fclose(filein);
			if (fileout != NULL)
				fclose(fileout);
			return;
		}

		char str[256];
		while (fgets(str, sizeof(str), filein))
		{
			if (strncmp(str, device, strlen(device)) == 0) {
				fprintf(fileout, "%s\n", line);
			}
			else {
				fprintf(fileout, "%s", str);
			}
		}
		fclose(filein);
		fclose(fileout);

		if (remove(logFilePath) == 0) {
			rename(tempFilePath, logFilePath);
		}
		else {
			remove(tempFilePath);
		}
	}
	else {
		FILE *out = fopen(logFilePath, "a");
		if (out == NULL) {
			perror("Error opening file");
			return;
		}
		fprintf(out, "%s\n", line);
		fclose(out);
	}
}
