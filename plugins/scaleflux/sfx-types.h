/* SPDX-License-Identifier: GPL-2.0-or-later */

#include <inttypes.h>

#define FMT_RED     "\x1b[31m"
#define FMT_GREEN   "\x1b[32m"
#define FMT_YELLOW  "\x1b[33m"
#define FMT_BLUE    "\x1b[34m"
#define FMT_RESET   "\x1b[0m"


enum {
	SFX_LOG_LATENCY_READ_STATS  = 0xc1,
	SFX_LOG_EXTENDED_HEALTH     = 0xc2,
	SFX_LOG_LATENCY_WRITE_STATS = 0xc3,
	SFX_LOG_QUAL                = 0xc4,
	SFX_LOG_MISMATCHLBA         = 0xc5,
	SFX_LOG_MEDIA               = 0xc6,
	SFX_LOG_BBT                 = 0xc7,
	SFX_LOG_IDENTIFY            = 0xcc,
	SFX_FEAT_ATOMIC             = 0x01,
	SFX_FEAT_UP_P_CAP           = 0xac,
	SFX_LOG_EXTENDED_HEALTH_ALT = 0xd2,
	SFX_FEAT_CLR_CARD           = 0xdc,
};

enum {
	SFX_CRIT_PWR_FAIL_DATA_LOSS = 0x01,
	SFX_CRIT_OVER_CAP           = 0x02,
	SFX_CRIT_RW_LOCK            = 0x04,
};

enum sfx_nvme_admin_opcode {
	nvme_admin_query_cap_info   = 0xd3,
	nvme_admin_change_cap       = 0xd4,
	nvme_admin_sfx_set_features = 0xd5,
	nvme_admin_sfx_get_features = 0xd6,
};

struct sfx_freespace_ctx {
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

struct nvme_capacity_info {
	__u64 lba_sec_sz;
	__u64 phy_sec_sz;
	__u64 used_space;
	__u64 free_space;
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
			__u32    count;
		} thermal_throttle;
	};
	__u8            _rp;
};

struct __packed sfx_lat_stats_vanda {
	__u16    maj;
	__u16    min;
	__u32     bucket_1[32];    /* 0~1ms, step 32us */
	__u32     bucket_2[31];    /* 1~32ms, step 1ms */
	__u32     bucket_3[31];    /* 32ms~1s, step 32ms */
	__u32     bucket_4[1];     /* 1s~2s, specifically 1024ms~2047ms */
	__u32     bucket_5[1];     /* 2s~4s, specifically 2048ms~4095ms */
	__u32     bucket_6[1];     /* 4s+, specifically 4096ms+ */
};

struct __packed sfx_lat_stats_myrtle {
	__u16    maj;
	__u16    min;
	__u32     bucket_1[64]; /* 0us~63us, step 1us */
	__u32     bucket_2[64]; /* 63us~127us, step 1us */
	__u32     bucket_3[64]; /* 127us~255us, step 2us */
	__u32     bucket_4[64]; /* 255us~510us, step 4us */
	__u32     bucket_5[64]; /* 510us~1.02ms step 8us */
	__u32     bucket_6[64]; /* 1.02ms~2.04ms step 16us */
	__u32    bucket_7[64];  /* 2.04ms~4.08ms step 32us */
	__u32    bucket_8[64];  /* 4.08ms~8.16ms step 64us */
	__u32    bucket_9[64];  /* 8.16ms~16.32ms step 128us */
	__u32    bucket_10[64]; /* 16.32ms~32.64ms step 256us */
	__u32    bucket_11[64]; /* 32.64ms~65.28ms step 512us */
	__u32    bucket_12[64]; /* 65.28ms~130.56ms step 1.024ms */
	__u32    bucket_13[64]; /* 130.56ms~261.12ms step 2.048ms */
	__u32    bucket_14[64]; /* 261.12ms~522.24ms step 4.096ms */
	__u32    bucket_15[64]; /* 522.24ms~1.04s step 8.192ms */
	__u32    bucket_16[64]; /* 1.04s~2.09s step 16.384ms */
	__u32    bucket_17[64]; /* 2.09s~4.18s step 32.768ms */
	__u32    bucket_18[64]; /* 4.18s~8.36s step 65.536ms */
	__u32    bucket_19[64]; /* 8.36s~ step 131.072ms */
	__u64    average;       /* average latency statistics */
};


struct __packed sfx_lat_status_ver {
	__u16 maj;
	__u16 min;
};

struct sfx_lat_stats {
	union {
		struct sfx_lat_status_ver   ver;
		struct sfx_lat_stats_vanda  vanda;
		struct sfx_lat_stats_myrtle myrtle;
	};
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
	struct nvme_additional_smart_log_item grown_bb; /* grown bad block */
};


struct __packed extended_health_info_myrtle {
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
	__u32            sfx_critical_warning;
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


