/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright (c) 2022 Meta Platforms, Inc.
 *
 * Authors: Arthur Shau <arthurshau@fb.com>,
 *          Wei Zhang <wzhang@fb.com>,
 *          Venkat Ramesh <venkatraghavan@fb.com>
 */

#include "common.h"
#include "linux/types.h"

#ifndef OCP_SMART_EXTENDED_LOG_H
#define OCP_SMART_EXTENDED_LOG_H

struct command;
struct plugin;

/**
 * struct ocp_smart_extended_log -	SMART / Health Information Extended
 * @physical_media_units_written:	Physical Media Units Written
 * @physical_media_units_read:		Physical Media Units Read
 * @bad_user_nand_blocks_raw:		Bad User NAND Blocks raw
 * @bad_user_nand_blocks_normalized:	Bad User NAND Blocks normalized
 * @bad_system_nand_blocks_raw:		Bad System NAND Blocks raw
 * @bad_system_nand_blocks_normalized:	Bad System NAND Blocks normalized
 * @xor_recovery_count:			XOR Recovery Count
 * @uncorrectable_read_err_count:	Uncorrectable Read Error Count
 * @soft_ecc_err_count:			Soft ECC Error Count
 * @end_to_end_detected_err:		End to End detected errors
 * @end_to_end_corrected_err:		End to End corrected errors
 * @system_data_used_percent:		System data percent used
 * @refresh_counts:			Refresh Counts
 * @user_data_erase_count_max:		Max User data erase counts
 * @user_data_erase_count_min:		Min User data erase counts
 * @thermal_throttling_event_count:	Number of Thermal throttling events
 * @dssd_errata_version:		DSSD Errata Version
 * @dssd_point_version:			DSSD Point Version
 * @dssd_minor_version:			DSSD Minor Version
 * @dssd_major_version:			DSSD Major Version
 * @pcie_correctable_err_count:		PCIe Correctable Error Count
 * @incomplete_shoutdowns:		Incomplete Shutdowns
 * @rsvd116:				Reserved
 * @percent_free_blocks:		Percent free blocks
 * @rsvd121:				Reserved
 * @capacitor_health:			Capacitor health
 * @nvme_base_errata_version:		NVM Express Base Errata Version
 * @nvme_cmdset_errata_version:		NVMe Command Set Errata Version
 * @rsvd132:				Reserved
 * @unaligned_io:			Unaligned I/O
 * @security_version:			Security Version Number
 * @total_nuse:				Total NUSE - Namespace utilization
 * @plp_start_count:			PLP start count
 * @endurance_estimate:			Endurance Estimate
 * @pcie_link_retaining_count:		PCIe Link Retraining Count
 * @power_state_change_count:		Power State Change Count
 * @lowest_permitted_fw_rev:		Lowest Permitted Firmware Revision -------------
 * @rsvd216:				Reserved
 * @log_page_version:			Log page version
 * @log_page_guid:			Log page GUID
 */
struct __packed ocp_smart_extended_log {
	__u8   physical_media_units_written[16];	/* [15:0] */
	__u8   physical_media_units_read[16];		/* [31:16] */
	__u8   bad_user_nand_blocks_raw[6];		/* [37:32] */
	__le16 bad_user_nand_blocks_normalized;		/* [39:38] */
	__u8   bad_system_nand_blocks_raw[6];		/* [45:40] */
	__le16 bad_system_nand_blocks_normalized;	/* [47:46] */
	__le64 xor_recovery_count;			/* [55:48] */
	__le64 uncorrectable_read_err_count;		/* [63:56] */
	__le64 soft_ecc_err_count;			/* [71:64] */
	__le32 end_to_end_detected_err;			/* [75:72] */
	__le32 end_to_end_corrected_err;		/* [79:76] */
	__u8   system_data_used_percent;		/* [80] */
	__u8   refresh_counts[7];			/* [87:81] */
	__le32 user_data_erase_count_max;		/* [91:88] */
	__le32 user_data_erase_count_min;		/* [95:92] */
	__u8   thermal_throttling_event_count;		/* [96] */
	__u8   thermal_throttling_current_status;	/* [97] */
	__u8   dssd_errata_version;			/* [98] */
	__le16 dssd_point_version;			/* [100:99] */
	__le16 dssd_minor_version;			/* [102:101] */
	__u8   dssd_major_version;			/* [103] */
	__le64 pcie_correctable_err_count;		/* [111:104] */
	__le32 incomplete_shoutdowns;			/* [115:112] */
	__u8   rsvd116[4];				/* [119:116] */
	__u8   percent_free_blocks;			/* [120] */
	__u8   rsvd121[7];				/* [127:121] */
	__le16 capacitor_health;			/* [129:128] */
	__u8   nvme_base_errata_version;		/* [130] */
	__u8   nvme_cmdset_errata_version;		/* [131] */
	__u8   rsvd132[4];				/* [135:132] */
	__le64 unaligned_io;				/* [143:136] */
	__le64 security_version;			/* [151:144] */
	__le64 total_nuse;				/* [159:152] */
	__u8   plp_start_count[16];			/* [175:160] */
	__u8   endurance_estimate[16];			/* [191:176] */
	__le64 pcie_link_retaining_count;		/* [199:192] */
	__le64 power_state_change_count;		/* [207:200] */
	__le64 lowest_permitted_fw_rev;			/* [215:208] */
	__u8   rsvd216[278];				/* [493:216] */
	__le16  log_page_version;			/* [495:494] */
	__u8    log_page_guid[16];			/* [511:496] */
};

int ocp_smart_add_log(int argc, char **argv, struct command *cmd,
	struct plugin *plugin);

#endif
