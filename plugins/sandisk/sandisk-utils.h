/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (c) 2025 Sandisk Corporation or its affiliates.
 *
 *   Author: Jeff Lien <jeff.lien@sandisk.com>
 *           Brandon Paupore <brandon.paupore@sandisk.com>
 */

#include <stdio.h>
#include <ctype.h>
#include <stdarg.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <assert.h>
#include <time.h>
#include <sys/time.h>
#include <sys/stat.h>

#include <stdbool.h>
#include <string.h>
#include <unistd.h>

/* Device Config */
#define SNDK_NVME_WDC_VID                   0x1b96
#define SNDK_NVME_SNDK_VID                  0x15b7

#define SNDK_NVME_SN630_DEV_ID              0x2200
#define SNDK_NVME_SN630_DEV_ID_1            0x2201
#define SNDK_NVME_SN840_DEV_ID              0x2300
#define SNDK_NVME_SN840_DEV_ID_1            0x2500
#define SNDK_NVME_SN640_DEV_ID              0x2400
#define SNDK_NVME_SN640_DEV_ID_1            0x2401
#define SNDK_NVME_SN640_DEV_ID_2            0x2402
#define SNDK_NVME_SN640_DEV_ID_3            0x2404
#define SNDK_NVME_SN650_DEV_ID              0x2700
#define SNDK_NVME_SN650_DEV_ID_1            0x2701
#define SNDK_NVME_SN650_DEV_ID_2            0x2702
#define SNDK_NVME_SN650_DEV_ID_3            0x2720
#define SNDK_NVME_SN650_DEV_ID_4            0x2721
#define SNDK_NVME_SN655_DEV_ID              0x2722
#define SNDK_NVME_SN655_DEV_ID_1            0x2723
#define SNDK_NVME_SN861_DEV_ID              0x2750
#define SNDK_NVME_SN861_DEV_ID_1            0x2751
#define SNDK_NVME_SN861_DEV_ID_2            0x2752
#define SNDK_NVME_SNTMP_DEV_ID              0x2761

#define SNDK_NVME_SN520_DEV_ID              0x5003
#define SNDK_NVME_SN520_DEV_ID_1            0x5004
#define SNDK_NVME_SN520_DEV_ID_2            0x5005

#define SNDK_NVME_SN530_DEV_ID_1            0x5007
#define SNDK_NVME_SN530_DEV_ID_2            0x5008
#define SNDK_NVME_SN530_DEV_ID_3            0x5009
#define SNDK_NVME_SN530_DEV_ID_4            0x500b
#define SNDK_NVME_SN530_DEV_ID_5            0x501d

#define SNDK_NVME_SN350_DEV_ID              0x5019

#define SNDK_NVME_SN570_DEV_ID              0x501A

#define SNDK_NVME_SN850X_DEV_ID             0x5030

#define SNDK_NVME_SN5000_DEV_ID_1           0x5034
#define SNDK_NVME_SN5000_DEV_ID_2           0x5035
#define SNDK_NVME_SN5000_DEV_ID_3           0x5036
#define SNDK_NVME_SN5000_DEV_ID_4           0x504A

#define SNDK_NVME_SN7000S_DEV_ID_1          0x5039

#define SNDK_NVME_SN7150_DEV_ID_1           0x503b
#define SNDK_NVME_SN7150_DEV_ID_2           0x503c
#define SNDK_NVME_SN7150_DEV_ID_3           0x503d
#define SNDK_NVME_SN7150_DEV_ID_4           0x503e
#define SNDK_NVME_SN7150_DEV_ID_5           0x503f

#define SNDK_NVME_SN7100_DEV_ID_1           0x5043
#define SNDK_NVME_SN7100_DEV_ID_2           0x5044
#define SNDK_NVME_SN7100_DEV_ID_3           0x5045

#define SNDK_NVME_SN8000S_DEV_ID            0x5049

#define SNDK_NVME_SN720_DEV_ID              0x5002
#define SNDK_NVME_SN730_DEV_ID              0x5006
#define SNDK_NVME_SN740_DEV_ID              0x5015
#define SNDK_NVME_SN740_DEV_ID_1            0x5016
#define SNDK_NVME_SN740_DEV_ID_2            0x5017
#define SNDK_NVME_SN740_DEV_ID_3            0x5025
#define SNDK_NVME_SN340_DEV_ID              0x500d
#define SNDK_NVME_ZN350_DEV_ID              0x5010
#define SNDK_NVME_ZN350_DEV_ID_1            0x5018
#define SNDK_NVME_SN810_DEV_ID              0x5011
#define SNDK_NVME_SN820CL_DEV_ID            0x5037

#define SNDK_NVME_SN5100S_DEV_ID_1          0x5061
#define SNDK_NVME_SN5100S_DEV_ID_2          0x5062
#define SNDK_NVME_SN5100S_DEV_ID_3          0x5063

/* Shared flag space with WDC plugin */
#define SNDK_DRIVE_CAP_RESERVED1			0x0000000000000001
#define SNDK_DRIVE_CAP_INTERNAL_LOG			0x0000000000000002
#define SNDK_DRIVE_CAP_C1_LOG_PAGE			0x0000000000000004
#define SNDK_DRIVE_CAP_CA_LOG_PAGE			0x0000000000000008
#define SNDK_DRIVE_CAP_D0_LOG_PAGE			0x0000000000000010
#define SNDK_DRIVE_CAP_DRIVE_STATUS			0x0000000000000020
#define SNDK_DRIVE_CAP_CLEAR_ASSERT			0x0000000000000040
#define SNDK_DRIVE_CAP_CLEAR_PCIE			0x0000000000000080
#define SNDK_DRIVE_CAP_RESIZE				0x0000000000000100
#define SNDK_DRIVE_CAP_NAND_STATS			0x0000000000000200
#define SNDK_DRIVE_CAP_RESERVED2			0x0000000000000400
#define SNDK_DRIVE_CAP_RESERVED3			0x0000000000000800
#define SNDK_DRIVE_CAP_RESERVED4			0x0000000000001000
#define SNDK_DRIVE_CAP_FW_ACTIVATE_HISTORY		0x0000000000002000
#define SNDK_DRIVE_CAP_CLEAR_FW_ACT_HISTORY		0x0000000000004000
#define SNDK_DRIVE_CAP_DISABLE_CTLR_TELE_LOG		0x0000000000008000
#define SNDK_DRIVE_CAP_REASON_ID			0x0000000000010000
#define SNDK_DRIVE_CAP_LOG_PAGE_DIR			0x0000000000020000
#define SNDK_DRIVE_CAP_NS_RESIZE			0x0000000000040000
#define SNDK_DRIVE_CAP_INFO				0x0000000000080000
#define SNDK_DRIVE_CAP_C0_LOG_PAGE			0x0000000000100000
#define SNDK_DRIVE_CAP_TEMP_STATS			0x0000000000200000
#define SNDK_DRIVE_CAP_VUC_CLEAR_PCIE			0x0000000000400000
#define SNDK_DRIVE_CAP_VU_FID_CLEAR_PCIE		0x0000000000800000
#define SNDK_DRIVE_CAP_FW_ACTIVATE_HISTORY_C2		0x0000000001000000
#define SNDK_DRIVE_CAP_VU_FID_CLEAR_FW_ACT_HISTORY	0x0000000002000000
#define SNDK_DRIVE_CAP_CLOUD_SSD_VERSION		0x0000000004000000
#define SNDK_DRIVE_CAP_PCIE_STATS			0x0000000008000000
#define SNDK_DRIVE_CAP_HW_REV_LOG_PAGE			0x0000000010000000
#define SNDK_DRIVE_CAP_C3_LOG_PAGE			0x0000000020000000
#define SNDK_DRIVE_CAP_CLOUD_BOOT_SSD_VERSION		0x0000000040000000
#define SNDK_DRIVE_CAP_CLOUD_LOG_PAGE			0x0000000080000000
#define SNDK_DRIVE_CAP_RESERVED5			0x0000000100000000
#define SNDK_DRIVE_CAP_DUI_DATA				0x0000000200000000
#define SNDK_DRIVE_CAP_VUC_LOG				0x0000000400000000
#define SNDK_DRIVE_CAP_DUI				0x0000000800000000
#define SNDK_DRIVE_CAP_RESERVED6			0x0000001000000000
#define SNDK_DRIVE_CAP_OCP_C1_LOG_PAGE			0x0000002000000000
#define SNDK_DRIVE_CAP_OCP_C4_LOG_PAGE			0x0000004000000000
#define SNDK_DRIVE_CAP_OCP_C5_LOG_PAGE			0x0000008000000000
#define SNDK_DRIVE_CAP_DEVICE_WAF			0x0000010000000000
#define SNDK_DRIVE_CAP_SET_LATENCY_MONITOR		0x0000020000000000
#define SNDK_DRIVE_CAP_UDUI				0x0000040000000000
/* Any new capability flags should be added to the WDC plugin */

#define SNDK_DRIVE_CAP_SMART_LOG_MASK       (SNDK_DRIVE_CAP_C0_LOG_PAGE | \
		SNDK_DRIVE_CAP_C1_LOG_PAGE | \
		SNDK_DRIVE_CAP_CA_LOG_PAGE | \
		SNDK_DRIVE_CAP_D0_LOG_PAGE)
#define SNDK_DRIVE_CAP_CLEAR_PCIE_MASK      (SNDK_DRIVE_CAP_CLEAR_PCIE | \
		SNDK_DRIVE_CAP_VUC_CLEAR_PCIE | \
		SNDK_DRIVE_CAP_VU_FID_CLEAR_PCIE)
#define SNDK_DRIVE_CAP_INTERNAL_LOG_MASK    (SNDK_DRIVE_CAP_INTERNAL_LOG | \
		SNDK_DRIVE_CAP_DUI | \
		SNDK_DRIVE_CAP_UDUI | \
		SNDK_DRIVE_CAP_DUI_DATA | \
		SNDK_DRIVE_CAP_VUC_LOG)
#define SNDK_DRIVE_CAP_FW_ACTIVATE_HISTORY_MASK     (SNDK_DRIVE_CAP_FW_ACTIVATE_HISTORY | \
		SNDK_DRIVE_CAP_FW_ACTIVATE_HISTORY_C2)
#define SNDK_DRIVE_CAP_CLEAR_FW_ACT_HISTORY_MASK    (SNDK_DRIVE_CAP_CLEAR_FW_ACT_HISTORY | \
		SNDK_DRIVE_CAP_VU_FID_CLEAR_FW_ACT_HISTORY)

/* Vendor defined Log Page IDs */
#define SNDK_NVME_GET_SMART_CLOUD_ATTR_LOG_ID       0xC0
#define SNDK_NVME_GET_EOL_STATUS_LOG_ID             0xC0
#define SNDK_ERROR_REC_LOG_ID                       0xC1
#define SNDK_NVME_GET_FW_ACT_HISTORY_C2_LOG_ID      0xC2
#define SNDK_LATENCY_MON_LOG_ID                     0xC3
#define SNDK_DEV_CAP_LOG_ID                         0xC4
#define SNDK_UNSUPPORTED_REQS_LOG_ID                0xC5

#define SNDK_NVME_GET_DEVICE_INFO_LOG_ID            0xCA
#define SNDK_NVME_GET_FW_ACT_HISTORY_LOG_ID         0xCB
#define SNDK_NVME_GET_VU_SMART_LOG_ID               0xD0

/* Vendor defined Feature IDs */
#define SNDK_VU_DISABLE_CNTLR_TELEMETRY_OPTION_FEATURE_ID	0xD2

/* Customer ID's */
#define SNDK_CUSTOMER_ID_GN             0x0001
#define SNDK_CUSTOMER_ID_GD             0x0101
#define SNDK_CUSTOMER_ID_BD             0x1009

#define SNDK_CUSTOMER_ID_0x1004         0x1004
#define SNDK_CUSTOMER_ID_0x1005         0x1005
#define SNDK_CUSTOMER_ID_0x1008         0x1008
#define SNDK_CUSTOMER_ID_0x1304         0x1304
#define SNDK_INVALID_CUSTOMER_ID            -1

/* Capture Device Unit Info */
#define SNDK_NVME_CAP_UDUI_OPCODE			0xFA

/* Telemtery types for vs-internal-log command */
#define SNDK_TELEMETRY_TYPE_NONE			0x0
#define SNDK_TELEMETRY_TYPE_HOST			0x1
#define SNDK_TELEMETRY_TYPE_CONTROLLER			0x2

/* Misc */
#define SNDK_MAX_PATH_LEN	256

struct SNDK_UtilsTimeInfo {
	unsigned int year;
	unsigned int month;
	unsigned int dayOfWeek;
	unsigned int dayOfMonth;
	unsigned int hour;
	unsigned int minute;
	unsigned int second;
	unsigned int msecs;
	unsigned char isDST; /*0 or 1 */
	int zone; /* Zone value like +530 or -300 */
};

int sndk_get_pci_ids(nvme_root_t r,
		struct nvme_dev *dev,
		uint32_t *device_id,
		uint32_t *vendor_id);

int sndk_get_vendor_id(struct nvme_dev *dev,
		uint32_t *vendor_id);

bool sndk_check_device(nvme_root_t r,
		struct nvme_dev *dev);

__u64 sndk_get_drive_capabilities(nvme_root_t r,
		struct nvme_dev *dev);

__u64 sndk_get_enc_drive_capabilities(nvme_root_t r,
	    struct nvme_dev *dev);

int sndk_get_serial_name(struct nvme_dev *dev, char *file, size_t len,
			 const char *suffix);

void sndk_UtilsGetTime(struct SNDK_UtilsTimeInfo *timeInfo);

int sndk_UtilsSnprintf(char *buffer, unsigned int sizeOfBuffer,
		       const char *format, ...);

int sndk_check_ctrl_telemetry_option_disabled(struct nvme_dev *dev);
