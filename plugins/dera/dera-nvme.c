#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <dirent.h> 
#include <ctype.h> 
#include <sys/stat.h>
#include <sys/time.h>

#include "nvme.h"
#include "nvme-print.h"
#include "nvme-ioctl.h"
#include "plugin.h"

#include "argconfig.h"
#include "suffix.h"

#define CREATE_CMD
#include "dera-nvme.h"

static int char4_to_int(__u8 *data)
{
	int i;
	int result = 0;

	for (i = 0; i < 4; i++) {
		result = result << 8;
		result += data[3 - i];
	}
	return result;
}

struct nvme_dera_smart_info_log
{
	__u8 quick_rebuild_cnt0[4]; 
	__u8 quick_rebuild_cnt1[4]; 
	__u8 full_rebuild_cnt0[4];
	__u8 full_rebuild_cnt1[4];
	__u8 raw_rebuild_cnt0[4];
	__u8 raw_rebuild_cnt1[4];
	__u8 cap_aged;		
	__u8 cap_aged_ratio;
	__u8 cap_status;	
	__u8 cap_voltage[4];
	__u8 cap_charge_ctrl_en;	 
	__u8 cap_charge_ctrl_val[2];
	__u8 cap_charge_max_thr[2]; 
	__u8 cap_charge_min_thr[2]; 
	__u8 dev_status; 
	__u8 dev_status_up;
	__u8 nand_erase_err_cnt[4]; 
	__u8 nand_program_err_cnt[4]; 
	__u8 ddra_1bit_err[2];
	__u8 ddra_2bit_err[2];
	__u8 ddrb_1bit_err[2];
	__u8 ddrb_2bit_err[2];
	__u8 ddr_err_bit;
	__u8 pcie_corr_err[2];
	__u8 pcie_uncorr_err[2];
	__u8 pcie_fatal_err[2];
	__u8 pcie_err_bit;
	__u8 power_level; 
	__u8 current_power[2]; 
	__u8 nand_init_fail[2]; 
	__u8 fw_loader_version[8]; 
	__u8 uefi_driver_version[8]; 
	__u8 gpio0_err[2]; 
	__u8 gpio5_err[2]; 
	__u8 gpio_err_bit[2]; 
	__u8 rebuild_percent; 
	__u8 pcie_volt_status; 
	__u8 current_pcie_volt[2]; 
	__u8 init_pcie_volt_thr[2]; 
	__u8 rt_pcie_volt_thr[2]; 
	__u8 init_pcie_volt_low[2]; 
	__u8 rt_pcie_volt_low[2]; 
	__u8 temp_sensor_abnormal[2];
	__u8 nand_read_retry_fail_cnt[4]; 
	__u8 fw_slot_version[8]; 
	__u8 rsved[395];
};

enum dera_device_status
{
	DEVICE_STATUS_READY = 0x00,
	DEVICE_STATUS_QUICK_REBUILDING = 0x01,
	DEVICE_STATUS_FULL_REBUILDING = 0x02,
	DEVICE_STATUS_RAW_REBUILDING = 0x03,
	DEVICE_STATUS_CARD_READ_ONLY = 0x04,
	DEVICE_STATUS_FATAL_ERROR = 0x05,
	DEVICE_STATUS_BUSY = 0x06,
	DEVICE_STAUTS_LOW_LEVEL_FORMAT = 0x07,
	DEVICE_STAUTS_FW_COMMITING = 0x08,
	DEVICE_STAUTS__OVER_TEMPRATURE = 0x09,
};

static int nvme_dera_get_device_status(int fd, enum dera_device_status *result)
{
	int err = 0;

	struct nvme_passthru_cmd cmd = {
		.opcode = 0xc0, 
		.addr = (__u64)(uintptr_t)NULL,
		.data_len = 0,
		.cdw10 = 0,
		.cdw12 = 0x104, 
	};

	err = nvme_submit_passthru(fd, NVME_IOCTL_ADMIN_CMD, &cmd);
	if (!err && result) {
		*result = cmd.result;
	}

	return err;
}

static int get_status(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	int fd, err;
	struct nvme_dera_smart_info_log log;
	enum dera_device_status state = DEVICE_STATUS_FATAL_ERROR;
	char *desc = "Get the Dera device status";

	OPT_ARGS(opts) = {
		OPT_END()
	};

	fd = parse_and_open(argc, argv, desc, opts);
	if (fd < 0)
		return fd;
	
	err = nvme_get_log(fd, 0xffffffff, 0xc0, false, NVME_NO_LOG_LSP,
		sizeof(log), &log);
	if (err) {
		goto exit;
	}

	const char* dev_status[] = {
		"Normal",
		"Quick Rebuilding",
		"Full Rebuilding",
		"Raw Rebuilding",
		"Card Read Only",
		"Fatal Error",
		"Busy",
		"Low Level Format",
		"Firmware Committing",
		"Over Temperature" };

	const char *volt_status[] = {
		"Normal",
		"Initial Low",
		"Runtime Low",
	};

	err = nvme_dera_get_device_status(fd, &state);
	if (!err){
		if (state > 0 && state < 4){
			printf("device_status                       : %s %d%% completed\n", dev_status[state], log.rebuild_percent);
		}
		else{
			printf("device_status                       : %s\n", dev_status[state]);
		}
	}
	else {
		goto exit;
	}
	
	printf("dev_status_up                       : %s\n", dev_status[log.dev_status_up]);
	printf("cap_aged                            : %s\n", log.cap_aged == 1 ? "True" : "False");
	printf("cap_aged_ratio                      : %d%%\n", log.cap_aged_ratio < 100 ? log.cap_aged_ratio : 100);
	printf("cap_status                          : %s\n", log.cap_status == 0 ? "Normal" : (log.cap_status == 1 ? "Warning" : "Critical"));
	printf("cap_voltage                         : %d mV\n", char4_to_int(log.cap_voltage));
	printf("nand_erase_err_cnt                  : %d\n", char4_to_int(log.nand_erase_err_cnt));
	printf("nand_program_err_cnt                : %d\n", char4_to_int(log.nand_program_err_cnt));
	printf("ddra_1bit_err                       : %d\n", log.ddra_1bit_err[1] << 8 | log.ddra_1bit_err[0]);
	printf("ddra_2bit_err                       : %d\n", log.ddra_2bit_err[1] << 8 | log.ddra_2bit_err[0]);
	printf("ddrb_1bit_err                       : %d\n", log.ddrb_1bit_err[1] << 8 | log.ddrb_1bit_err[0]);
	printf("ddrb_2bit_err                       : %d\n", log.ddrb_2bit_err[1] << 8 | log.ddrb_2bit_err[0]);
	printf("ddr_err_bit                         : %d\n", log.ddr_err_bit);
	printf("pcie_corr_err                       : %d\n", log.pcie_corr_err[1] << 8 | log.pcie_corr_err[0]);
	printf("pcie_uncorr_err                     : %d\n", log.pcie_uncorr_err[1] << 8 | log.pcie_uncorr_err[0]);
	printf("pcie_fatal_err                      : %d\n", log.pcie_fatal_err[1] << 8 | log.pcie_fatal_err[0]);
	printf("power_level                         : %d W\n", log.power_level);
	printf("current_power                       : %d mW\n", log.current_power[1] << 8 | log.current_power[0]);
	printf("nand_init_fail                      : %d\n", log.nand_init_fail[1] << 8 | log.nand_init_fail[0]);
	printf("fw_loader_version                   : %.*s\n", 8, log.fw_loader_version);
	printf("uefi_driver_version                 : %.*s\n", 8, log.uefi_driver_version);

	if (log.pcie_volt_status >= 0 && log.pcie_volt_status <= sizeof(volt_status) / sizeof(const char *)){
		printf("pcie_volt_status                    : %s\n", volt_status[log.pcie_volt_status]);
	}
	else{
		printf("pcie_volt_status                    : Unknown\n");
	}

	printf("current_pcie_volt                   : %d mV\n", log.current_pcie_volt[1] << 8 | log.current_pcie_volt[0]);
	printf("init_pcie_volt_low_cnt              : %d\n", log.init_pcie_volt_low[1] << 8 | log.init_pcie_volt_low[0]);
	printf("rt_pcie_volt_low_cnt                : %d\n", log.rt_pcie_volt_low[1] << 8 | log.rt_pcie_volt_low[0]);
	printf("temp_sensor_abnormal_cnt            : %d\n", log.temp_sensor_abnormal[1] << 8 | log.temp_sensor_abnormal[0]);
	printf("nand_read_retry_fail_cnt            : %d\n", char4_to_int(log.nand_read_retry_fail_cnt));
	printf("fw_slot_version                     : %.*s\n", 8, log.fw_slot_version);

exit:
	if (err > 0)
		fprintf(stderr, "\nNVMe status:%s(0x%x)\n",	nvme_status_to_string(err), err);

	return err;
}

