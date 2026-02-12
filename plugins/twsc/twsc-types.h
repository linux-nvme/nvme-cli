/* SPDX-License-Identifier: GPL-2.0-or-later */

#include <inttypes.h>

#define FMT_RED     "\x1b[31m"
#define FMT_GREEN   "\x1b[32m"
#define FMT_YELLOW  "\x1b[33m"
#define FMT_BLUE    "\x1b[34m"
#define FMT_RESET   "\x1b[0m"


enum TWSC_VU_LOGS {
	TWSC_LOG_EXTENDED_HEALTH     = 0xc3,
	TWSC_LOG_ADDL_SMART          = 0xca,
};

enum TWSC_CRIT_WARN {
	TWSC_CRIT_PWR_FAIL_DATA_LOSS = 0x01,
	TWSC_CRIT_OVER_CAP           = 0x02,
	TWSC_CRIT_RW_LOCK            = 0x04,
};

enum twsc_nvme_admin_opcode {
	nvme_admin_query_cap_info   = 0xd6,
};

struct twsc_device_config {
	char  vendor_id[8];
	char  device_id[8];
	char  ctrl_name[16];
	char  pcie_slot[64];
};

struct twsc_freespace_ctx {
	__u64 free_space;
	__u64 phy_cap;      /* physical capacity, in unit of sector */
	__u64 phy_space;    /* physical space considering OP, in unit of sector */
	__u64 user_space;   /* user required space, in unit of sector*/
	__u64 hw_used;      /* hw space used in 4K */
	__u64 app_written;  /* app data written in 4K */
	__u64 out_of_space;
	__u64 map_unit;
	__u64 max_user_space;
	__u64 extendible_user_cap_lba_count;
	__u64 friendly_change_cap_support;
};

struct nvme_cust_args {
	__u32 *result;
	void  *data;
	__u32  opcode;
	__u32  timeout;
	__u32  cdw11;
	__u32  bufid;
	__u32  cdw13;
	__u32  cdw14;
	__u32  custid;
	__u32  data_len;
};

struct __packed nvme_additional_smart_log_item {
	__u8            key;
	__u8            _kp[2];
	__u8            norm;
	__u8            _np;
	union __packed {
		__u8        raw[6];
		struct __packed  wear_level {
			__le16    min;
			__le16    max;
			__le16    avg;
		} wear_level;
		struct __packed thermal_throttle {
			__u8    pct;
			__u32   count;
		} thermal_throttle;
	};
	__u8            _rp;
};

struct nvme_additional_smart_log {
	struct nvme_additional_smart_log_item program_fail_cnt;
	struct nvme_additional_smart_log_item erase_fail_cnt;
	struct nvme_additional_smart_log_item wear_leveling_cnt;
	struct nvme_additional_smart_log_item e2e_err_cnt;
	struct nvme_additional_smart_log_item crc_err_cnt;
	struct nvme_additional_smart_log_item timed_workload_media_wear;
	struct nvme_additional_smart_log_item timed_workload_host_reads;
	struct nvme_additional_smart_log_item timed_workload_timer;
	struct nvme_additional_smart_log_item thermal_throttle_status;
	struct nvme_additional_smart_log_item retry_buffer_overflow_cnt;
	struct nvme_additional_smart_log_item pll_lock_loss_cnt;
	struct nvme_additional_smart_log_item nand_bytes_written;
	struct nvme_additional_smart_log_item host_bytes_written;
	struct nvme_additional_smart_log_item raid_recover_cnt;
			/* errors which can be recovered by RAID */
	struct nvme_additional_smart_log_item prog_timeout_cnt;
	struct nvme_additional_smart_log_item erase_timeout_cnt;
	struct nvme_additional_smart_log_item read_timeout_cnt;
	struct nvme_additional_smart_log_item read_ecc_cnt; /* retry cnt */
	struct nvme_additional_smart_log_item non_media_crc_err_cnt;
	struct nvme_additional_smart_log_item compression_path_err_cnt;
	struct nvme_additional_smart_log_item out_of_space_flag;
	struct nvme_additional_smart_log_item physical_usage_ratio;
	struct nvme_additional_smart_log_item grown_bb_count; /* grown bad block */
	struct nvme_additional_smart_log_item system_area_life_remaining;
	struct nvme_additional_smart_log_item user_available_space_rate;
	struct nvme_additional_smart_log_item over_provisioning_rate;
};

struct __packed extended_health_info {
	__u32            soft_read_recoverable_errs;
	__u32            flash_die_raid_recoverable_errs;
	__u32            pcie_rx_correct_errs;
	__u32            pcie_rx_uncorrect_errs;
	__u32            data_read_from_flash;
	__u32            data_write_to_flash;
	__u32            temp_throttle_info;// bit0: 0--> normal, 1 --> throttled
										// bit 31:1 --> throttle events count, resets on power cycle
	__u32            power_consumption;
	__u32            pf_bbd_read_cnt;
	__u32            twsc_critical_warning;
	__u32            raid_recovery_total_count;
	__u32            rsvd;
	__u8             opn[32];
	__u64            total_physical_capability;
	__u64            free_physical_capability;
	__u32            physical_usage_ratio;
	__u32            comp_ratio;
	__u32            otp_rsa_en;
	__u32            power_mw_consumption;
	__u32            io_speed;
	__u64            max_formatted_capability;
	__u32            map_unit;
	__u64            extendible_cap_lbacount;
	__u32            friendly_changecap_support;
	__u32            rvd1;
	__u64            cur_formatted_capability;
};


