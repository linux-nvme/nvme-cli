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

#define PLP_RECORD_PATH "PLPRec.txt"
#define PLP_DATA_EXPIRED_TIME 20

static const __u32 OP_BAD_BLOCK = 0xc2;
static const __u32 DW10_BAD_BLOCK = 0x400;
static const __u32 DW12_BAD_BLOCK = 0x5a;

static const __u32 OP_HEALTH = 0xc2;
static const __u32 DW10_HEALTH = 0x01;
static const __u32 DW12_HEALTH = 0xb3;

static const __u32 OP_ID = 0x06;
static const __u32 DW10_ID = 0x01;

static const int i_dis = 20;
static const double full_value = 170;

enum plp_error_code {
	PLP_ERROR_NO_MATCH = -1,
	PLP_ERROR_DATA_EXPIRED  = -2
};

static const char *string_list[] = {
    "UTE210T",   "MTE712P",   "MTE560P",   "MTE662P", "MTE662P-I", "MTS970P",
    "MTS952P",   "MTS952P-I", "MTS570P",   "MTS400P", "SSD910T",   "SSD470P",
    "SSD470P-I", "SSD452P",   "SSD452P-I", "SSD420P", "MSA470P",   "MSA452P"
};

static const int list_size = ARRAY_SIZE(string_list);

static int get_plp_health(int argc, char **argv, struct command *cmd, struct plugin *plugin);
static int read_useful_plp_value(const char *device);
static void record_plp_value(const char *device, int value, bool is_replace);

static int get_health_value(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
    struct nvme_smart_log smart_log;
    char *desc = "Get nvme health percentage.";
    int percent_used = 0;
    int health_value = 0;
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
        printf("Transcend NVME health value: ");
        percent_used = smart_log.percent_used;

        if (percent_used > 100 || percent_used < 0) {
            printf("0%%\n");
        } else {
            health_value = 100 - percent_used;
            printf("%d%%\n", health_value);
        }
    }
    dev_close(dev);
    return result;
}

static int get_bad_block(int argc, char **argv, struct command *cmd, struct plugin *plugin)
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
    struct nvme_passthru_cmd nvme_cmd;

    memset(&nvme_cmd, 0, sizeof(nvme_cmd));
    nvme_cmd.opcode = OP_BAD_BLOCK;
    nvme_cmd.cdw10 = DW10_BAD_BLOCK;
    nvme_cmd.cdw12 = DW12_BAD_BLOCK;
    nvme_cmd.addr = (__u64)(uintptr_t)data;
    nvme_cmd.data_len = 0x1;
    result = nvme_submit_admin_passthru(dev_fd(dev), &nvme_cmd, NULL);
    if (!result) {
        int bad_block = data[0];
        printf("Transcend NVME badblock count: %d\n", bad_block);
    }
    dev_close(dev);
    return result;
}

static const char *format_char_array(char *str, int str_size, unsigned char *chr, int chr_size)
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

int contains_string(const char *str)
{
    int i;

    for (i = 0; i < list_size; i++) {
        if (strstr(str, string_list[i]) != NULL) {
            return 1;
        }
    }
    return 0;
}

static int get_plp_health(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
    char *desc = "Get nvme PLP Health.";
    struct nvme_dev *dev;
    int result;
    int txt_plp_health = -1;
    int plp_health_percentage = -1;
    OPT_ARGS(opts) = {
        OPT_END()
    };

    result = parse_and_open(&dev, argc, argv, desc, opts);
    if (result) {
        printf("\nDevice not found\n");
        return -1;
    }

    unsigned char data_id[4096];
    struct nvme_passthru_cmd nvme_cmd_id;

    memset(&nvme_cmd_id, 0, sizeof(nvme_cmd_id));
    nvme_cmd_id.opcode = OP_ID;
    nvme_cmd_id.cdw10 = DW10_ID;
    nvme_cmd_id.addr = (__u64)(uintptr_t)data_id;
    nvme_cmd_id.data_len = 4096;
    result = nvme_submit_admin_passthru(dev_fd(dev), &nvme_cmd_id, NULL);
    if (result) {
        printf("\nThis device is not supported.\n");
        dev_close(dev);
        return -1;
    }
    char model_name[40];
    const char *model_str_byte;
    model_str_byte = format_char_array((char *)model_name, sizeof(model_name), data_id, sizeof(data_id));
    if (!contains_string(model_str_byte)) {
        printf("\nThis device is not supported.\n");
        dev_close(dev);
        return -1;
    }

    txt_plp_health = read_useful_plp_value(dev->name);
    if (txt_plp_health >= 0) {
        plp_health_percentage = txt_plp_health;
        printf("Capacitor health for PLP: %d%%\n", plp_health_percentage);
    } else {
        unsigned char data[512];
        struct nvme_passthru_cmd nvme_cmd;

        memset(&nvme_cmd, 0, sizeof(nvme_cmd));
        nvme_cmd.opcode = OP_HEALTH;
        nvme_cmd.cdw10 = DW10_HEALTH;
        nvme_cmd.cdw12 = DW12_HEALTH;
        nvme_cmd.addr = (__u64)(uintptr_t)data;
        nvme_cmd.data_len = 512;
        result = nvme_submit_admin_passthru(dev_fd(dev), &nvme_cmd, NULL);
        if (result) {
            printf("\nGet PLP Health Fail.\n");
            dev_close(dev);
            return PLP_ERROR_NO_MATCH;
        } else {
            int t_dis = (int)(data[4 + 3] << 24) + (int)(data[4 + 2] << 16) + (int)(data[4 + 1] << 8) + (int)(data[4]);
            int v_dis1 = (int)(data[0]);
            int v_dis2 = (int)(data[1]);
            if (v_dis1 != 0 || v_dis2 != 0) {
                int normal_health = 0;

                if (v_dis1 - v_dis2 != 0) {
                    normal_health = (i_dis * t_dis) / (v_dis1 - v_dis2);
                } else {
                    normal_health = 0;
                }
                if (normal_health >= 0) {
                    if (full_value - normal_health >= 0) {
                        plp_health_percentage = (normal_health / full_value) * 100;
                    } else {
                        plp_health_percentage = 100;
                    }
                } else {
                    plp_health_percentage = 0;
                }
                printf("Capacitor health for PLP: %d%%\n", plp_health_percentage);
            }
        }
    }
    if (plp_health_percentage >= 0) {
        if (txt_plp_health == PLP_ERROR_DATA_EXPIRED) {
            record_plp_value(dev->name, plp_health_percentage, true);
        } else {
            record_plp_value(dev->name, plp_health_percentage, false);
        }
    }
    dev_close(dev);
    return result;
}

static int read_useful_plp_value(const char *device)
{
    FILE *file;
    char log_file_path[256];
    char str[256];
    char matched_str[256] = "";
    int ret = -1;

    snprintf(log_file_path, sizeof(log_file_path), "%s", PLP_RECORD_PATH);
    file = fopen(log_file_path, "r");
    if (!file) {
        return PLP_ERROR_NO_MATCH;
    }

    while (fgets(str, sizeof(str), file)) {
        if (strncmp(str, device, strlen(device)) == 0) {
            strcpy(matched_str, str);
            break;
        }
    }

    fclose(file);

    if (matched_str[0] == '\0') {
        return PLP_ERROR_NO_MATCH;
    }

    char *token;
    token = strtok(matched_str, "#");
    token = strtok(NULL, "#");
    struct tm tm;
    memset(&tm, 0, sizeof(tm));
    strptime(token, "%a %b %d %H:%M:%S %Y", &tm);
    time_t t = mktime(&tm);

    time_t t_current = time(NULL);
    int time_diff = difftime(t_current, t);

    if (time_diff <= PLP_DATA_EXPIRED_TIME) {
        token = strtok(NULL, "#");
        ret = atoi(token);
        return ret;
    } else {
        return PLP_ERROR_DATA_EXPIRED;
    }
}

static void record_plp_value(const char *device, int value, bool is_replace)
{
    char log_file_path[256];
    strncpy(log_file_path, PLP_RECORD_PATH, sizeof(log_file_path) - 1);
    log_file_path[sizeof(log_file_path) - 1] = '\0';
    char temp_file_path[] = "temp.txt";

    time_t ct = time(0);
    char *time_str = ctime(&ct);
    if (time_str == NULL) {
        perror("Error getting current time");
        return;
    }
    time_str[strcspn(time_str, "\n")] = '\0';

    char line[256];
    snprintf(line, sizeof(line), "%s#%s#%d", device, time_str, value);

    if (is_replace) {
        FILE *file_in = fopen(log_file_path, "r");
        FILE *file_out = fopen(temp_file_path, "w");
        if (file_in == NULL || file_out == NULL) {
            perror("Error opening file");
            if (file_in != NULL)
                fclose(file_in);
            if (file_out != NULL)
                fclose(file_out);
            return;
        }

        char str[256];
        while (fgets(str, sizeof(str), file_in)) {
            if (strncmp(str, device, strlen(device)) == 0) {
                fprintf(file_out, "%s\n", line);
            } else {
                fprintf(file_out, "%s", str);
            }
        }
        fclose(file_in);
        fclose(file_out);

        if (remove(log_file_path) == 0) {
            rename(temp_file_path, log_file_path);
        } else {
            remove(temp_file_path);
        }
    } else {
        FILE *out = fopen(log_file_path, "a");
        if (out == NULL) {
            perror("Error opening file");
            return;
        }
        fprintf(out, "%s\n", line);
        fclose(out);
    }
}