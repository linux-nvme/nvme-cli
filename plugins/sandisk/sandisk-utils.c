// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2025 Sandisk Corporation or its affiliates.
 *
 *   Author: Jeff Lien <jeff.lien@sandisk.com>
 *           Brandon Paupore <brandon.paupore@sandisk.com>
 */

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include "nvme.h"
#include "libnvme.h"
#include "nvme-print.h"
#include "sandisk-utils.h"
#include "plugins/wdc/wdc-nvme-cmds.h"


int sndk_get_pci_ids(nvme_root_t r, struct nvme_dev *dev,
			   uint32_t *device_id, uint32_t *vendor_id)
{
	char vid[256], did[256], id[32];
	nvme_ctrl_t c = NULL;
	nvme_ns_t n = NULL;
	int fd, ret;

	c = nvme_scan_ctrl(r, dev->name);
	if (c) {
		snprintf(vid, sizeof(vid), "%s/device/vendor",
			nvme_ctrl_get_sysfs_dir(c));
		snprintf(did, sizeof(did), "%s/device/device",
			nvme_ctrl_get_sysfs_dir(c));
		nvme_free_ctrl(c);
	} else {
		n = nvme_scan_namespace(dev->name);
		if (!n) {
			fprintf(stderr, "Unable to find %s\n", dev->name);
			return -1;
		}

		snprintf(vid, sizeof(vid), "%s/device/device/vendor",
			nvme_ns_get_sysfs_dir(n));
		snprintf(did, sizeof(did), "%s/device/device/device",
			nvme_ns_get_sysfs_dir(n));
		nvme_free_ns(n);
	}

	fd = open(vid, O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "ERROR: SNDK: %s : Open vendor file failed\n", __func__);
		return -1;
	}

	ret = read(fd, id, 32);
	close(fd);

	if (ret < 0) {
		fprintf(stderr, "%s: Read of pci vendor id failed\n", __func__);
		return -1;
	}
	id[ret < 32 ? ret : 31] = '\0';
	if (id[strlen(id) - 1] == '\n')
		id[strlen(id) - 1] = '\0';

	*vendor_id = strtol(id, NULL, 0);
	ret = 0;

	fd = open(did, O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "ERROR: SNDK: %s : Open device file failed\n", __func__);
		return -1;
	}

	ret = read(fd, id, 32);
	close(fd);

	if (ret < 0) {
		fprintf(stderr, "ERROR: SNDK: %s: Read of pci device id failed\n", __func__);
		return -1;
	}
	id[ret < 32 ? ret : 31] = '\0';
	if (id[strlen(id) - 1] == '\n')
		id[strlen(id) - 1] = '\0';

	*device_id = strtol(id, NULL, 0);
	return 0;
}

int sndk_get_vendor_id(struct nvme_dev *dev, uint32_t *vendor_id)
{
	int ret;
	struct nvme_id_ctrl ctrl;

	memset(&ctrl, 0, sizeof(struct nvme_id_ctrl));
	ret = nvme_identify_ctrl(dev_fd(dev), &ctrl);
	if (ret) {
		fprintf(stderr, "ERROR: SNDK: nvme_identify_ctrl() failed 0x%x\n", ret);
		return -1;
	}

	*vendor_id = (uint32_t) ctrl.vid;

	return ret;
}

bool sndk_check_device(nvme_root_t r, struct nvme_dev *dev)
{
	int ret;
	bool supported;
	uint32_t read_device_id = -1, read_vendor_id = -1;

	ret = sndk_get_pci_ids(r, dev, &read_device_id, &read_vendor_id);
	if (ret < 0) {
		/* Use the identify nvme command to get vendor id due to NVMeOF device. */
		if (sndk_get_vendor_id(dev, &read_vendor_id) < 0)
			return false;
	}

	supported = false;

	if (read_vendor_id == SNDK_NVME_SNDK_VID ||
	    read_vendor_id == SNDK_NVME_WDC_VID)
		supported = true;
	else
		fprintf(stderr,
			"ERROR: SNDK: unsupported Sandisk device, Vendor ID = 0x%x, Device ID = 0x%x\n",
			read_vendor_id, read_device_id);

	return supported;
}

__u64 sndk_get_drive_capabilities(nvme_root_t r, struct nvme_dev *dev)
{
	__u64 capabilities = 0;

	int ret;
	uint32_t read_device_id = -1, read_vendor_id = -1;

	ret = sndk_get_pci_ids(r, dev, &read_device_id, &read_vendor_id);
	if (ret < 0) {
		if (sndk_get_vendor_id(dev, &read_vendor_id) < 0)
			return capabilities;
	}

	/*
	 * Below check condition is added due in NVMeOF device
	 * We aren't able to read the device_id in this case
	 * so we can only use the vendor_id
	 */
	if (read_device_id == -1 && read_vendor_id != -1) {
		capabilities = sndk_get_enc_drive_capabilities(r, dev);
		return capabilities;
	}

	switch (read_vendor_id) {
	case SNDK_NVME_WDC_VID:
		switch (read_device_id) {
		case SNDK_NVME_SNTMP_DEV_ID:
			capabilities |= (SNDK_DRIVE_CAP_C0_LOG_PAGE |
					SNDK_DRIVE_CAP_C3_LOG_PAGE |
					SNDK_DRIVE_CAP_CA_LOG_PAGE |
					SNDK_DRIVE_CAP_OCP_C4_LOG_PAGE |
					SNDK_DRIVE_CAP_OCP_C5_LOG_PAGE |
					SNDK_DRIVE_CAP_UDUI |
					SNDK_DRIVE_CAP_FW_ACTIVATE_HISTORY_C2 |
					SNDK_DRIVE_CAP_VU_FID_CLEAR_PCIE |
					SNDK_DRIVE_CAP_VU_FID_CLEAR_FW_ACT_HISTORY |
					SNDK_DRIVE_CAP_INFO |
					SNDK_DRIVE_CAP_CLOUD_SSD_VERSION |
					SNDK_DRIVE_CAP_LOG_PAGE_DIR |
					SNDK_DRIVE_CAP_DRIVE_STATUS |
					SNDK_DRIVE_CAP_SET_LATENCY_MONITOR);
			break;

		default:
			capabilities = 0;
		}
		break;

	case SNDK_NVME_SNDK_VID:
		switch (read_device_id) {
		case SNDK_NVME_SN7150_DEV_ID_1:
		case SNDK_NVME_SN7150_DEV_ID_2:
		case SNDK_NVME_SN7150_DEV_ID_3:
		case SNDK_NVME_SN7150_DEV_ID_4:
		case SNDK_NVME_SN7150_DEV_ID_5:
			capabilities = SNDK_DRIVE_CAP_UDUI;
			break;

		default:
			capabilities = 0;
		}
		break;
	default:
		capabilities = 0;
	}

	/* Check for fallback WDC plugin support */
	if (!capabilities)
		capabilities = run_wdc_get_drive_capabilities(r, dev);

	return capabilities;
}

__u64 sndk_get_enc_drive_capabilities(nvme_root_t r,
					    struct nvme_dev *dev)
{
	int ret;
	uint32_t read_vendor_id;
	__u64 capabilities = 0;
	__u32 cust_id;

	ret = sndk_get_vendor_id(dev, &read_vendor_id);
	if (ret < 0)
		return capabilities;

	switch (read_vendor_id) {
	case SNDK_NVME_WDC_VID:
		capabilities = (SNDK_DRIVE_CAP_INTERNAL_LOG |
			SNDK_DRIVE_CAP_DRIVE_STATUS |
			SNDK_DRIVE_CAP_CLEAR_ASSERT |
			SNDK_DRIVE_CAP_RESIZE);

		/* verify the 0xC3 log page is supported */
		if (run_wdc_nvme_check_supported_log_page(r, dev,
			SNDK_LATENCY_MON_LOG_ID))
			capabilities |= SNDK_DRIVE_CAP_C3_LOG_PAGE;

		/* verify the 0xCB log page is supported */
		if (run_wdc_nvme_check_supported_log_page(r, dev,
			SNDK_NVME_GET_FW_ACT_HISTORY_LOG_ID))
			capabilities |= SNDK_DRIVE_CAP_FW_ACTIVATE_HISTORY;

		/* verify the 0xCA log page is supported */
		if (run_wdc_nvme_check_supported_log_page(r, dev,
			SNDK_NVME_GET_DEVICE_INFO_LOG_ID))
			capabilities |= SNDK_DRIVE_CAP_CA_LOG_PAGE;

		/* verify the 0xD0 log page is supported */
		if (run_wdc_nvme_check_supported_log_page(r, dev,
			SNDK_NVME_GET_VU_SMART_LOG_ID))
			capabilities |= SNDK_DRIVE_CAP_D0_LOG_PAGE;

		cust_id = run_wdc_get_fw_cust_id(r, dev);
		if (cust_id == SNDK_INVALID_CUSTOMER_ID) {
			fprintf(stderr, "%s: ERROR: SNDK: invalid customer id\n", __func__);
			return -1;
		}

		if ((cust_id == SNDK_CUSTOMER_ID_0x1004) ||
			(cust_id == SNDK_CUSTOMER_ID_0x1008) ||
			(cust_id == SNDK_CUSTOMER_ID_0x1005) ||
			(cust_id == SNDK_CUSTOMER_ID_0x1304))
			capabilities |= (SNDK_DRIVE_CAP_VU_FID_CLEAR_FW_ACT_HISTORY |
					SNDK_DRIVE_CAP_VU_FID_CLEAR_PCIE);
		else
			capabilities |= (SNDK_DRIVE_CAP_CLEAR_FW_ACT_HISTORY |
					SNDK_DRIVE_CAP_CLEAR_PCIE);

		break;
	default:
		capabilities = 0;
	}

	return capabilities;
}

int sndk_get_serial_name(struct nvme_dev *dev, char *file, size_t len,
				const char *suffix)
{
	int i;
	int ret;
	int res_len = 0;
	char orig[PATH_MAX] = {0};
	struct nvme_id_ctrl ctrl;
	int ctrl_sn_len = sizeof(ctrl.sn);

	i = sizeof(ctrl.sn) - 1;
	strncpy(orig, file, PATH_MAX - 1);
	memset(file, 0, len);
	memset(&ctrl, 0, sizeof(struct nvme_id_ctrl));
	ret = nvme_identify_ctrl(dev_fd(dev), &ctrl);
	if (ret) {
		fprintf(stderr, "ERROR: SNDK: nvme_identify_ctrl() failed 0x%x\n", ret);
		return -1;
	}
	/* Remove trailing spaces from the name */
	while (i && ctrl.sn[i] == ' ') {
		ctrl.sn[i] = '\0';
		i--;
	}
	if (ctrl.sn[sizeof(ctrl.sn) - 1] == '\0')
		ctrl_sn_len = strlen(ctrl.sn);

	res_len = snprintf(file, len, "%s%.*s%s", orig, ctrl_sn_len, ctrl.sn, suffix);
	if (len <= res_len) {
		fprintf(stderr,
			"ERROR: SNDK: cannot format SN due to unexpected length\n");
		return -1;
	}

	return 0;
}

void sndk_UtilsGetTime(struct SNDK_UtilsTimeInfo *timeInfo)
{
	time_t currTime;
	struct tm currTimeInfo;

	tzset();
	time(&currTime);
	localtime_r(&currTime, &currTimeInfo);

	timeInfo->year			=  currTimeInfo.tm_year + 1900;
	timeInfo->month			=  currTimeInfo.tm_mon + 1;
	timeInfo->dayOfWeek		=  currTimeInfo.tm_wday;
	timeInfo->dayOfMonth		=  currTimeInfo.tm_mday;
	timeInfo->hour			=  currTimeInfo.tm_hour;
	timeInfo->minute		=  currTimeInfo.tm_min;
	timeInfo->second		=  currTimeInfo.tm_sec;
	timeInfo->msecs			=  0;
	timeInfo->isDST			=  currTimeInfo.tm_isdst;
#ifdef HAVE_TM_GMTOFF
	timeInfo->zone			= -currTimeInfo.tm_gmtoff / 60;
#else /* HAVE_TM_GMTOFF */
	timeInfo->zone			= -1 * (timezone / 60);
#endif /* HAVE_TM_GMTOFF */
}

int sndk_UtilsSnprintf(char *buffer, unsigned int sizeOfBuffer, const char *format, ...)
{
	int res = 0;
	va_list vArgs;

	va_start(vArgs, format);
	res = vsnprintf(buffer, sizeOfBuffer, format, vArgs);
	va_end(vArgs);

	return res;
}

/* Verify the Controller Initiated Option is enabled */
int sndk_check_ctrl_telemetry_option_disabled(struct nvme_dev *dev)
{
	int err;
	__u32 result;

	err = nvme_get_features_data(dev_fd(dev),
		 SNDK_VU_DISABLE_CNTLR_TELEMETRY_OPTION_FEATURE_ID,
		 0, 4, NULL, &result);
	if (!err) {
		if (result) {
			fprintf(stderr,
				"%s: Controller-initiated option telemetry disabled\n",
				__func__);
			return -EINVAL;
		}
	} else {
		fprintf(stderr, "ERROR: SNDK: Get telemetry option feature failed.");
		nvme_show_status(err);
		return -EPERM;
	}

	return 0;
}
