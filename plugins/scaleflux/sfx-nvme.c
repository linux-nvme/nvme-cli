#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <linux/fs.h>
#include <inttypes.h>
#include <asm/byteorder.h>
#include <sys/ioctl.h>
#include <sys/sysinfo.h>
#include <sys/stat.h>
#include <unistd.h>

#include "linux/nvme_ioctl.h"

#include "nvme.h"
#include "nvme-print.h"
#include "nvme-ioctl.h"
#include "nvme-status.h"
#include "json.h"
#include "plugin.h"

#include "argconfig.h"
#include "suffix.h"

#define CREATE_CMD
#include "sfx-nvme-def.h"
#include "sfx-nvme.h"

enum {
	SFX_LOG_LATENCY_READ_STATS	= 0xc1,
	SFX_LOG_SMART			= 0xc2,
	SFX_LOG_LATENCY_WRITE_STATS	= 0xc3,
	SFX_LOG_QUAL			= 0xc4,
	SFX_LOG_MISMATCHLBA		= 0xc5,
	SFX_LOG_MEDIA			= 0xc6,
	SFX_LOG_BBT			= 0xc7,
	SFX_LOG_IDENTIFY		= 0xcc,
	SFX_FEAT_ATOMIC			= 0x01,
	SFX_FEAT_ACT_MODE		= 0x02,
	SFX_FEAT_UP_P_CAP		= 0xac,
	SFX_FEAT_CLR_CARD		= 0xdc,
};

enum sfx_nvme_admin_opcode {
	nvme_admin_query_cap_info	= 0xd3,
	nvme_admin_change_cap		= 0xd4,
	nvme_admin_sfx_set_features	= 0xd5,
	nvme_admin_sfx_get_features	= 0xd6,
	nvme_admin_get_keyinfo		= 0xd7,
	nvme_admin_set_keyinfo		= 0xd8,
	nvme_admin_geometry		= 0xe2,
};

struct sfx_freespace_ctx
{
	__u64 free_space;
	__u64 phy_cap;		/* physical capacity, in unit of sector */
	__u64 phy_space;	/* physical space considering OP, in unit of sector */
	__u64 user_space;	/* user required space, in unit of sector*/
	__u64 hw_used;		/* hw space used in 4K */
	__u64 app_written;	/* app data written in 4K */
};

struct nvme_capacity_info {
	__u64 lba_sec_sz;
	__u64 phy_sec_sz;
	__u64 used_space;
	__u64 free_space;
};
struct	__attribute__((packed)) nvme_additional_smart_log_item {
	uint8_t			   key;
	uint8_t			   _kp[2];
	uint8_t			   norm;
	uint8_t			   _np;
	union {
		uint8_t		   raw[6];
		struct wear_level {
			uint16_t	min;
			uint16_t	max;
			uint16_t	avg;
		} wear_level ;
		struct thermal_throttle {
			uint8_t    pct;
			uint32_t	count;
		} thermal_throttle;
	};
	uint8_t			   _rp;
};

struct nvme_additional_smart_log {
	struct nvme_additional_smart_log_item	 program_fail_cnt;
	struct nvme_additional_smart_log_item	 erase_fail_cnt;
	struct nvme_additional_smart_log_item	 wear_leveling_cnt;
	struct nvme_additional_smart_log_item	 e2e_err_cnt;
	struct nvme_additional_smart_log_item	 crc_err_cnt;
	struct nvme_additional_smart_log_item	 timed_workload_media_wear;
	struct nvme_additional_smart_log_item	 timed_workload_host_reads;
	struct nvme_additional_smart_log_item	 timed_workload_timer;
	struct nvme_additional_smart_log_item	 thermal_throttle_status;
	struct nvme_additional_smart_log_item	 retry_buffer_overflow_cnt;
	struct nvme_additional_smart_log_item	 pll_lock_loss_cnt;
	struct nvme_additional_smart_log_item	 nand_bytes_written;
	struct nvme_additional_smart_log_item	 host_bytes_written;
	struct nvme_additional_smart_log_item	 raid_recover_cnt; // errors which can be recovered by RAID
	struct nvme_additional_smart_log_item	 prog_timeout_cnt;
	struct nvme_additional_smart_log_item	 erase_timeout_cnt;
	struct nvme_additional_smart_log_item	 read_timeout_cnt;
	struct nvme_additional_smart_log_item	 read_ecc_cnt;//retry cnt
};

typedef struct sfx_capacity_ctx_s
{
	uint32_t capacity;
	uint32_t p_capacity;
} sfx_capacity_ctx;

typedef struct sfx_phy_cap_range_ctx_s
{
	uint32_t max_capacity;
	uint32_t pret_prov_cap;
} sfx_phy_cap_range_ctx;

int nvme_change_cap(int fd, __u32 nsid, __u64 capacity)
{
	struct nvme_admin_cmd cmd = {
	.opcode		 = nvme_admin_change_cap,
	.nsid		 = nsid,
	.cdw10		 = (capacity & 0xffffffff),
	.cdw11		 = (capacity >> 32),
	};

	return nvme_submit_passthru(fd, NVME_IOCTL_ADMIN_CMD,&cmd);
}

int nvme_sfx_set_features(int fd, __u32 nsid, __u32 fid, __u32 value)
{
	struct nvme_admin_cmd cmd = {
	.opcode		 = nvme_admin_sfx_set_features,
	.nsid		 = nsid,
	.cdw10		 = fid,
	.cdw11		 = value,
	};

	return nvme_submit_passthru(fd, NVME_IOCTL_ADMIN_CMD,&cmd);
}

int nvme_sfx_get_features(int fd, __u32 nsid, __u32 fid, __u32 *result)
{
	int err = 0;
	struct nvme_admin_cmd cmd = {
	.opcode		 = nvme_admin_sfx_get_features,
	.nsid		 = nsid,
	.cdw10		 = fid,
	};

	err = nvme_submit_passthru(fd, NVME_IOCTL_ADMIN_CMD,&cmd);
	if (!err && result) {
		*result = cmd.result;
	}

	return err;
}

static void show_sfx_smart_log_jsn(struct nvme_additional_smart_log *smart,
		unsigned int nsid, const char *devname)
{
	struct json_object *root, *entry_stats, *dev_stats, *multi;

	root = json_create_object();
	json_object_add_value_string(root, "Intel Smart log", devname);

	dev_stats = json_create_object();

	entry_stats = json_create_object();
	json_object_add_value_int(entry_stats, "normalized", smart->program_fail_cnt.norm);
	json_object_add_value_int(entry_stats, "raw", int48_to_long(smart->program_fail_cnt.raw));
	json_object_add_value_object(dev_stats, "program_fail_count", entry_stats);

	entry_stats = json_create_object();
	json_object_add_value_int(entry_stats, "normalized", smart->erase_fail_cnt.norm);
	json_object_add_value_int(entry_stats, "raw", int48_to_long(smart->erase_fail_cnt.raw));
	json_object_add_value_object(dev_stats, "erase_fail_count", entry_stats);

	entry_stats = json_create_object();
	json_object_add_value_int(entry_stats, "normalized", smart->wear_leveling_cnt.norm);
	multi = json_create_object();
	json_object_add_value_int(multi, "min", le16_to_cpu(smart->wear_leveling_cnt.wear_level.min));
	json_object_add_value_int(multi, "max", le16_to_cpu(smart->wear_leveling_cnt.wear_level.max));
	json_object_add_value_int(multi, "avg", le16_to_cpu(smart->wear_leveling_cnt.wear_level.avg));
	json_object_add_value_object(entry_stats, "raw", multi);
	json_object_add_value_object(dev_stats, "wear_leveling", entry_stats);

	entry_stats = json_create_object();
	json_object_add_value_int(entry_stats, "normalized", smart->e2e_err_cnt.norm);
	json_object_add_value_int(entry_stats, "raw", int48_to_long(smart->e2e_err_cnt.raw));
	json_object_add_value_object(dev_stats, "end_to_end_error_detection_count", entry_stats);

	entry_stats = json_create_object();
	json_object_add_value_int(entry_stats, "normalized", smart->crc_err_cnt.norm);
	json_object_add_value_int(entry_stats, "raw", int48_to_long(smart->crc_err_cnt.raw));
	json_object_add_value_object(dev_stats, "crc_error_count", entry_stats);

	entry_stats = json_create_object();
	json_object_add_value_int(entry_stats, "normalized", smart->timed_workload_media_wear.norm);
	json_object_add_value_float(entry_stats, "raw", ((float)int48_to_long(smart->timed_workload_media_wear.raw)) / 1024);
	json_object_add_value_object(dev_stats, "timed_workload_media_wear", entry_stats);

	entry_stats = json_create_object();
	json_object_add_value_int(entry_stats, "normalized", smart->timed_workload_host_reads.norm);
	json_object_add_value_int(entry_stats, "raw", int48_to_long(smart->timed_workload_host_reads.raw));
	json_object_add_value_object(dev_stats, "timed_workload_host_reads", entry_stats);

	entry_stats = json_create_object();
	json_object_add_value_int(entry_stats, "normalized", smart->timed_workload_timer.norm);
	json_object_add_value_int(entry_stats, "raw", int48_to_long(smart->timed_workload_timer.raw));
	json_object_add_value_object(dev_stats, "timed_workload_timer", entry_stats);

	entry_stats = json_create_object();
	json_object_add_value_int(entry_stats, "normalized", smart->thermal_throttle_status.norm);
	multi = json_create_object();
	json_object_add_value_int(multi, "pct", smart->thermal_throttle_status.thermal_throttle.pct);
	json_object_add_value_int(multi, "cnt", smart->thermal_throttle_status.thermal_throttle.count);
	json_object_add_value_object(entry_stats, "raw", multi);
	json_object_add_value_object(dev_stats, "thermal_throttle_status", entry_stats);

	entry_stats = json_create_object();
	json_object_add_value_int(entry_stats, "normalized", smart->retry_buffer_overflow_cnt.norm);
	json_object_add_value_int(entry_stats, "raw",	  int48_to_long(smart->retry_buffer_overflow_cnt.raw));
	json_object_add_value_object(dev_stats, "retry_buffer_overflow_count", entry_stats);

	entry_stats = json_create_object();
	json_object_add_value_int(entry_stats, "normalized", smart->pll_lock_loss_cnt.norm);
	json_object_add_value_int(entry_stats, "raw",	  int48_to_long(smart->pll_lock_loss_cnt.raw));
	json_object_add_value_object(dev_stats, "pll_lock_loss_count", entry_stats);

	entry_stats = json_create_object();
	json_object_add_value_int(entry_stats, "normalized", smart->nand_bytes_written.norm);
	json_object_add_value_int(entry_stats, "raw",	  int48_to_long(smart->nand_bytes_written.raw));
	json_object_add_value_object(dev_stats, "nand_bytes_written", entry_stats);

	entry_stats = json_create_object();
	json_object_add_value_int(entry_stats, "normalized", smart->host_bytes_written.norm);
	json_object_add_value_int(entry_stats, "raw",	  int48_to_long(smart->host_bytes_written.raw));
	json_object_add_value_object(dev_stats, "host_bytes_written", entry_stats);

	entry_stats = json_create_object();
	json_object_add_value_int(entry_stats, "normalized", smart->raid_recover_cnt.norm);
	json_object_add_value_int(entry_stats, "raw",	  int48_to_long(smart->raid_recover_cnt.raw));
	json_object_add_value_object(dev_stats, "raid_recover_cnt", entry_stats);

	entry_stats = json_create_object();
	json_object_add_value_int(entry_stats, "normalized", smart->prog_timeout_cnt.norm);
	json_object_add_value_int(entry_stats, "raw",	  int48_to_long(smart->prog_timeout_cnt.raw));
	json_object_add_value_object(dev_stats, "prog_timeout_cnt", entry_stats);

	entry_stats = json_create_object();
	json_object_add_value_int(entry_stats, "normalized", smart->erase_timeout_cnt.norm);
	json_object_add_value_int(entry_stats, "raw",	  int48_to_long(smart->erase_timeout_cnt.raw));
	json_object_add_value_object(dev_stats, "erase_timeout_cnt", entry_stats);

	entry_stats = json_create_object();
	json_object_add_value_int(entry_stats, "normalized", smart->read_timeout_cnt.norm);
	json_object_add_value_int(entry_stats, "raw",	  int48_to_long(smart->read_timeout_cnt.raw));
	json_object_add_value_object(dev_stats, "read_timeout_cnt", entry_stats);

	entry_stats = json_create_object();
	json_object_add_value_int(entry_stats, "normalized", smart->read_ecc_cnt.norm);
	json_object_add_value_int(entry_stats, "raw",	  int48_to_long(smart->read_ecc_cnt.raw));
	json_object_add_value_object(dev_stats, "read_ecc_cnt", entry_stats);

	json_object_add_value_object(root, "Device stats", dev_stats);

	json_print_object(root, NULL);
	printf("/n");
	json_free_object(root);
}

static void show_sfx_smart_log(struct nvme_additional_smart_log *smart,
		unsigned int nsid, const char *devname)
{
	printf("Additional Smart Log for ScaleFlux device:%s namespace-id:%x\n",
			devname, nsid);
	printf("key                               normalized raw\n");
	printf("program_fail_count              : %3d%%       %"PRIu64"\n",
			smart->program_fail_cnt.norm,
			int48_to_long(smart->program_fail_cnt.raw));
	printf("erase_fail_count                : %3d%%       %"PRIu64"\n",
			smart->erase_fail_cnt.norm,
			int48_to_long(smart->erase_fail_cnt.raw));
	printf("wear_leveling                   : %3d%%       min: %u, max: %u, avg: %u\n",
			smart->wear_leveling_cnt.norm,
			le16_to_cpu(smart->wear_leveling_cnt.wear_level.min),
			le16_to_cpu(smart->wear_leveling_cnt.wear_level.max),
			le16_to_cpu(smart->wear_leveling_cnt.wear_level.avg));
	printf("end_to_end_error_detection_count: %3d%%       %"PRIu64"\n",
			smart->e2e_err_cnt.norm,
			int48_to_long(smart->e2e_err_cnt.raw));
	printf("crc_error_count                 : %3d%%       %"PRIu64"\n",
			smart->crc_err_cnt.norm,
			int48_to_long(smart->crc_err_cnt.raw));
	printf("timed_workload_media_wear       : %3d%%       %.3f%%\n",
			smart->timed_workload_media_wear.norm,
			((float)int48_to_long(smart->timed_workload_media_wear.raw)) / 1024);
	printf("timed_workload_host_reads       : %3d%%       %"PRIu64"%%\n",
			smart->timed_workload_host_reads.norm,
			int48_to_long(smart->timed_workload_host_reads.raw));
	printf("timed_workload_timer            : %3d%%       %"PRIu64" min\n",
			smart->timed_workload_timer.norm,
			int48_to_long(smart->timed_workload_timer.raw));
	printf("thermal_throttle_status         : %3d%%       %u%%, cnt: %u\n",
			smart->thermal_throttle_status.norm,
			smart->thermal_throttle_status.thermal_throttle.pct,
			smart->thermal_throttle_status.thermal_throttle.count);
	printf("retry_buffer_overflow_count     : %3d%%       %"PRIu64"\n",
			smart->retry_buffer_overflow_cnt.norm,
			int48_to_long(smart->retry_buffer_overflow_cnt.raw));
	printf("pll_lock_loss_count             : %3d%%       %"PRIu64"\n",
			smart->pll_lock_loss_cnt.norm,
			int48_to_long(smart->pll_lock_loss_cnt.raw));
	printf("nand_bytes_written              : %3d%%       sectors: %"PRIu64"\n",
			smart->nand_bytes_written.norm,
			int48_to_long(smart->nand_bytes_written.raw));
	printf("host_bytes_written              : %3d%%       sectors: %"PRIu64"\n",
			smart->host_bytes_written.norm,
			int48_to_long(smart->host_bytes_written.raw));
	printf("raid_recover_cnt                : %3d%%       %"PRIu64"\n",
			smart->raid_recover_cnt.norm,
			int48_to_long(smart->raid_recover_cnt.raw));
	printf("read_ecc_cnt                    : %3d%%       %"PRIu64"\n",
			smart->read_ecc_cnt.norm,
			int48_to_long(smart->read_ecc_cnt.raw));
	printf("prog_timeout_cnt                : %3d%%       %"PRIu64"\n",
			smart->prog_timeout_cnt.norm,
			int48_to_long(smart->prog_timeout_cnt.raw));
	printf("erase_timeout_cnt               : %3d%%       %"PRIu64"\n",
			smart->erase_timeout_cnt.norm,
			int48_to_long(smart->erase_timeout_cnt.raw));
	printf("read_timeout_cnt                : %3d%%       %"PRIu64"\n",
			smart->read_timeout_cnt.norm,
			int48_to_long(smart->read_timeout_cnt.raw));
}

static int get_additional_smart_log(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	struct nvme_additional_smart_log smart_log;
	int err, fd;
	char *desc = "Get ScaleFlux vendor specific additional smart log (optionally, "\
			  "for the specified namespace), and show it.";
	const char *namespace = "(optional) desired namespace";
	const char *raw = "dump output in binary format";
	const char *json= "Dump output in json format";
	struct config {
		__u32 namespace_id;
		int   raw_binary;
		int   json;
	};

	struct config cfg = {
		.namespace_id = 0xffffffff,
	};

	OPT_ARGS(opts) = {
		OPT_UINT("namespace-id", 'n', &cfg.namespace_id, namespace),
		OPT_FLAG("raw-binary",	 'b', &cfg.raw_binary,	 raw),
		OPT_FLAG("json",		 'j', &cfg.json,		 json),
		OPT_END()
	};


	fd = parse_and_open(argc, argv, desc, opts);

	err = nvme_get_log(fd, cfg.namespace_id, 0xca, false, sizeof(smart_log),
			(void *)&smart_log);
	if (!err) {
		if (cfg.json)
			show_sfx_smart_log_jsn(&smart_log, cfg.namespace_id, devicename);
		else if (!cfg.raw_binary)
			show_sfx_smart_log(&smart_log, cfg.namespace_id, devicename);
		else
			d_raw((unsigned char *)&smart_log, sizeof(smart_log));
	}
	else if (err > 0)
		fprintf(stderr, "NVMe Status:%s(%x)\n",
					nvme_status_to_string(err), err);
	return err;
}

struct sfx_lat_stats {
	__u16	 maj;
	__u16	 min;
	__u32	 bucket_1[32];	/* 0~1ms, step 32us */
	__u32	 bucket_2[31];	/* 1~32ms, step 1ms */
	__u32	 bucket_3[31];	/* 32ms~1s, step 32ms */
	__u32	 bucket_4[1];	/* 1s~2s, specifically 1024ms~2047ms */
	__u32	 bucket_5[1];	/* 2s~4s, specifically 2048ms~4095ms */
	__u32	 bucket_6[1];	/* 4s+, specifically 4096ms+ */
};

static void show_lat_stats(struct sfx_lat_stats *stats, int write)
{
	int i;

	printf(" ScaleFlux IO %s Command Latency Statistics\n", write ? "Write" : "Read");
	printf("-------------------------------------\n");
	printf("Major Revision : %u\n", stats->maj);
	printf("Minor Revision : %u\n", stats->min);

	printf("\nGroup 1: Range is 0-1ms, step is 32us\n");
	for (i = 0; i < 32; i++)
		printf("Bucket %2d: %u\n", i, stats->bucket_1[i]);

	printf("\nGroup 2: Range is 1-32ms, step is 1ms\n");
	for (i = 0; i < 31; i++)
		printf("Bucket %2d: %u\n", i, stats->bucket_2[i]);

	printf("\nGroup 3: Range is 32ms-1s, step is 32ms:\n");
	for (i = 0; i < 31; i++)
		printf("Bucket %2d: %u\n", i, stats->bucket_3[i]);

	printf("\nGroup 4: Range is 1s-2s:\n");
	printf("Bucket %2d: %u\n", 0, stats->bucket_4[0]);

	printf("\nGroup 5: Range is 2s-4s:\n");
	printf("Bucket %2d: %u\n", 0, stats->bucket_5[0]);

	printf("\nGroup 6: Range is 4s+:\n");
	printf("Bucket %2d: %u\n", 0, stats->bucket_6[0]);
}

static int get_lat_stats_log(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	struct sfx_lat_stats stats;
	int err, fd;

	char *desc = "Get ScaleFlux Latency Statistics log and show it.";
	const char *raw = "dump output in binary format";
	const char *write = "Get write statistics (read default)";
	struct config {
		int  raw_binary;
		int  write;
	};

	struct config cfg = {
	};

	OPT_ARGS(opts) = {
		OPT_FLAG("write",	   'w', &cfg.write,		 write),
		OPT_FLAG("raw-binary", 'b', &cfg.raw_binary, raw),
		OPT_END()
	};

	fd = parse_and_open(argc, argv, desc, opts);

	err = nvme_get_log(fd, 0xffffffff, cfg.write ? 0xc3 : 0xc1, false, sizeof(stats), (void *)&stats);
	if (!err) {
		if (!cfg.raw_binary)
			show_lat_stats(&stats, cfg.write);
		else
			d_raw((unsigned char *)&stats, sizeof(stats));
	} else if (err > 0)
		fprintf(stderr, "NVMe Status:%s(%x)\n",
				nvme_status_to_string(err), err);
	return err;
}

int sfx_nvme_get_log(int fd, __u32 nsid, __u8 log_id, __u32 data_len, void *data)
{
	struct nvme_admin_cmd cmd = {
		.opcode		   = nvme_admin_get_log_page,
		.nsid		 = nsid,
		.addr		 = (__u64)(uintptr_t) data,
		.data_len	 = data_len,
	};
	__u32 numd = (data_len >> 2) - 1;
	__u16 numdu = numd >> 16, numdl = numd & 0xffff;

	cmd.cdw10 = log_id | (numdl << 16);
	cmd.cdw11 = numdu;

	return nvme_submit_admin_passthru(fd, &cmd);
}

/**
 * @brief	get bb table through admin_passthru
 *
 * @param fd
 * @param buf
 * @param size
 *
 * @return -1 fail ; 0 success
 */
static int get_bb_table(int fd, __u32 nsid, unsigned char *buf, __u64 size)
{
	if (fd < 0 || !buf || size != 256*4096*sizeof(unsigned char)) {
		fprintf(stderr, "Invalid Param \r\n");
		return EINVAL;
	}

	return sfx_nvme_get_log(fd, nsid, SFX_LOG_BBT, size, (void *)buf);
}

/**
 * @brief display bb table
 *
 * @param bd_table		buffer that contain bb table dumped from drvier
 * @param table_size	buffer size (BYTES), should at least has 8 bytes for mf_bb_count and grown_bb_count
 */
static void bd_table_show(unsigned char *bd_table, __u64 table_size)
{
	__u32 mf_bb_count = 0;
	__u32 grown_bb_count = 0;
	__u32 total_bb_count = 0;
	__u32 remap_mfbb_count = 0;
	__u32 remap_gbb_count = 0;
	__u64 *bb_elem;
	__u64 *elem_end = (__u64 *)(bd_table + table_size);
	__u64 i;

	/*buf should at least have 8bytes for mf_bb_count & total_bb_count*/
	if (!bd_table || table_size < sizeof(__u64))
		return;

	mf_bb_count = *((__u32 *)bd_table);
	grown_bb_count = *((__u32 *)(bd_table + sizeof(__u32)));
	total_bb_count = *((__u32 *)(bd_table + 2 * sizeof(__u32)));
	remap_mfbb_count = *((__u32 *)(bd_table + 3 * sizeof(__u32)));
	remap_gbb_count = *((__u32 *)(bd_table + 4 * sizeof(__u32)));
	bb_elem = (__u64 *)(bd_table + 5 * sizeof(__u32));

	printf("Bad Block Table \n");
	printf("MF_BB_COUNT:           %u\n", mf_bb_count);
	printf("GROWN_BB_COUNT:        %u\n", grown_bb_count);
	printf("TOTAL_BB_COUNT:        %u\n", total_bb_count);
	printf("REMAP_MFBB_COUNT:      %u\n", remap_mfbb_count);
	printf("REMAP_GBB_COUNT:       %u\n", remap_gbb_count);

	printf("REMAP_MFBB_TABLE [");
	i = 0;
	while (bb_elem < elem_end && i < remap_mfbb_count) {
		printf(" 0x%llx", *(bb_elem++));
		i++;
	}
	printf(" ]\n");

	printf("REMAP_GBB_TABLE [");
	i = 0;
	while (bb_elem < elem_end && i < remap_gbb_count) {
		printf(" 0x%llx",*(bb_elem++));
		i++;
	}
	printf(" ]\n");
}

/**
 * @brief	"hooks of sfx get-bad-block"
 *
 * @param argc
 * @param argv
 * @param cmd
 * @param plugin
 *
 * @return
 */
static int sfx_get_bad_block(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	int fd;
	unsigned char *data_buf;
	const __u64 buf_size = 256*4096*sizeof(unsigned char);
	int err = 0;

	char *desc = "Get bad block table of sfx block device.";

	OPT_ARGS(opts) = {
		OPT_END()
	};

	fd = parse_and_open(argc, argv, desc, opts);

	if (fd < 0) {
		return fd;
	}

	data_buf = malloc(buf_size);
	if (!data_buf) {
		fprintf(stderr, "malloc fail, errno %d\r\n", errno);
		return -1;
	}

	err = get_bb_table(fd, 0xffffffff, data_buf, buf_size);
	if (err < 0) {
		perror("get-bad-block");
	} else if (err != 0) {
		fprintf(stderr, "NVMe IO command error:%s(%x)\n",
				nvme_status_to_string(err), err);
	} else {
		bd_table_show(data_buf, buf_size);
		printf("ScaleFlux get bad block table: success\n");
	}

	free(data_buf);
	return 0;
}

static __u64 get_capacity(int fd, sfx_capacity_ctx *cap_val)
{
	struct sfx_freespace_ctx ctx = { 0 };
	__u64 cap_GB = 0;
	__u64 pcap_GB = 0;
	if (ioctl(fd, SFX_GET_FREESPACE, &ctx)) {
		fprintf(stderr, "Get p_capacity fail, errno=%d\n", errno);
		return INVALID_PARAM;
	}
	/*Convert to GB*/
	cap_GB = IDEMA_CAP2GB(ctx.user_space);
	pcap_GB = ((ctx.phy_space - 97696368llu) / 1953504llu) + 50llu;

	cap_val->capacity = cap_GB;
	cap_val->p_capacity = pcap_GB;
	return 0;
}

/**
 * @brief convert the file name to it's target file name if the input file is symbol link.
 * Otherwise, just copy the input file name to target file name
 *
 * @param dir		abs dir path of input file
 * @param link_name	input file name
 * @param tg_name	target file name
 * @param tg_size	size of tg_name
 *
 * @return 0, success; -1, fail
 */
static int name_from_link(const char *dir, char *link_name, char *tg_name,
			  int tg_size)
{
	char path[50] = { 0 };
	struct stat f_state;

	if (!dir || !link_name || !tg_name || tg_size == 0) {
		fprintf(stderr, "%s: Invalid params\r\n", __func__);
		return -1;
	}
	memset(tg_name, 0x00, tg_size);
	snprintf(path, sizeof(path), "%s/%s", dir, link_name);

	if (lstat(path, &f_state) < 0) {
		fprintf(stderr, "lstate fail, errno=%d\r\n", errno);
		return -1;
	}
	if (S_ISLNK(f_state.st_mode)) {
		if (readlink(path, tg_name, tg_size) < 0) {
			fprintf(stderr, "readlink fail, errno =%d \n", errno);
			return -1;
		}
	} else {
		snprintf(tg_name, tg_size, "%s", link_name);
	}
	return 0;
}

static int nvme_block_from_char(char *char_dev, char *blk_dev, int blk_dev_len)
{
	char slen[16];
	unsigned len;
	char tg_name[50];
	NVME_DEV_TYPE type;

	if (name_from_link("/dev", char_dev, tg_name, sizeof(tg_name)) < 0) {
		return -1;
	}
	type = sfx_dev_type(tg_name);

	if (type == NVME_SFX_B_DEV_VANDA || type == NVME_SFX_B_DEV_TPLUS) {
		snprintf(blk_dev, blk_dev_len, "%s", tg_name);
	} else if (type == NVME_SFX_C_DEV_VANDA) {
		sscanf(tg_name, SFX_NVME_DEV_C_VANDA "%d", &len);
		snprintf(blk_dev, blk_dev_len, SFX_NVME_DEV_B_VANDA "%dn1", len);
		snprintf(slen, sizeof(slen), "%d", len);
		blk_dev[SFX_NVME_DEV_LEN_VANDA + strlen(slen) + 2] = 0;
	} else if (type == NVME_SFX_C_DEV_TPLUS) {
		sscanf(tg_name, SFX_NVME_DEV_C_TPLUS "%d", &len);
		snprintf(blk_dev, blk_dev_len, SFX_NVME_DEV_B_TPLUS "%dn1", len);
		snprintf(slen, sizeof(slen), "%dn1", len);
		blk_dev[SFX_NVME_DEV_LEN_TPLUS + strlen(slen) + 2] = 0;
	}
	return 0;
}

static int sfx_blk_dev_ref()
{
	FILE *fd;
	char buffer[128];
	char blk_base[64];
	char cmd[256];
	int chars_read;
	int ref_cnt = 0;

	NVME_DEV_TYPE type = sfx_dev_type((char *)devicename);
	if (type == NVME_SFX_C_DEV_VANDA || type == NVME_SFX_C_DEV_TPLUS) {
		nvme_block_from_char((char *)devicename, blk_base, sizeof(blk_base));
	} else {
		snprintf(blk_base, sizeof(blk_base), "%s", (char *)devicename);
	}

	/*
	 * lsof cannot tell which device is referenced when FS mounted
	 * So Use mount to check if current device is mounted
	 * Then lsof to show if current device is opened by application
	 */
	snprintf(cmd, sizeof(cmd), "mount | grep %s | wc -l", blk_base);
	fd = popen(cmd, "r");
	if (!fd) {
		fprintf(stderr, "check mount point failed\n");
		return -1;
	}
	chars_read = fread(buffer, sizeof(char), (sizeof(buffer) - 1), fd);
	if (chars_read > 0) {
		ref_cnt = atoi(buffer);
	}
	if (ref_cnt > 0) {
		pclose(fd);
		return ref_cnt;
	}
	pclose(fd);

	snprintf(cmd, sizeof(cmd), "lsof | grep %s | wc -l", blk_base);
	fd = popen(cmd, "r");
	if (!fd) {
		fprintf(stderr, "check lsof failed\n");
		return -1;
	}

	chars_read = fread(buffer, sizeof(char), (sizeof(buffer) - 1), fd);
	if (chars_read > 0) {
		ref_cnt = atoi(buffer);
	}
	pclose(fd);
	return ref_cnt;
}

static void show_cap_info(struct sfx_freespace_ctx *ctx)
{

	printf("logic            capacity:%5lluGB(0x%llx)\n",
			IDEMA_CAP2GB(ctx->user_space), ctx->user_space);
	printf("provisioned      capacity:%5lluGB(0x%llx)\n",
			IDEMA_CAP2GB(ctx->phy_space), ctx->phy_space);
	printf("free provisioned capacity:%5lluGB(0x%llx)\n",
			IDEMA_CAP2GB(ctx->free_space), ctx->free_space);
	printf("used provisioned capacity:%5lluGB(0x%llx)\n",
			IDEMA_CAP2GB(ctx->phy_space) - IDEMA_CAP2GB(ctx->free_space),
			ctx->phy_space - ctx->free_space);
}

static int query_cap_info(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	struct sfx_freespace_ctx ctx = { 0 };
	int err = 0, fd;
	char *desc = "query current capacity info of vanda";
	const char *raw = "dump output in binary format";
	const char *json= "Dump output in json format";
	struct config {
		int   raw_binary;
		int   json;
	};
	struct config cfg;

	OPT_ARGS(opts) = {
		OPT_FLAG("raw-binary", 'b', &cfg.raw_binary, raw),
		OPT_FLAG("json",	   'j', &cfg.json,		 json),
		OPT_END()
	};

	fd = parse_and_open(argc, argv, desc, opts);
	if (fd < 0) {
		return fd;
	}

	if (ioctl(fd, SFX_GET_FREESPACE, &ctx)) {
		fprintf(stderr, "vu ioctl fail, errno %d\r\n", errno);
		return -1;
	}

	show_cap_info(&ctx);
	return err;
}

static int change_sanity_check(int fd, __u64 trg_in_4k, int *shrink)
{
	struct sfx_freespace_ctx freespace_ctx = { 0 };
	struct sysinfo s_info;
	__u64 mem_need = 0;
	__u64 cur_in_4k = 0;
	__u64 provisoned_cap_4k = 0;
	__u32 cnt_ms = 0;
	int extend = 0;

	while (ioctl(fd, SFX_GET_FREESPACE, &freespace_ctx)) {
		if (cnt_ms++ > 600) {//1min
			return -1;
		}
		usleep(100000);
	}

	/*
	 * capacity illegal check
	 */
	provisoned_cap_4k = freespace_ctx.phy_space >>
			    (SFX_PAGE_SHIFT - SECTOR_SHIFT);
	if (trg_in_4k < provisoned_cap_4k ||
	    trg_in_4k > ((__u64)provisoned_cap_4k * 4)) {
		fprintf(stderr,
			"WARNING: Only support 1.0~4.0 x provisoned capacity!\n");
		if (trg_in_4k < provisoned_cap_4k) {
			fprintf(stderr,
				"WARNING: The target capacity is less than 1.0 x provisioned capacity!\n");
		} else {
			fprintf(stderr,
				"WARNING: The target capacity is larger than 4.0 x provisioned capacity!\n");
		}
		return -1;
	}
	if (trg_in_4k > ((__u64)provisoned_cap_4k*4)) {
		fprintf(stderr, "WARNING: the target capacity is too large\n");
		return -1;
	}

	/*
	 * check whether mem enough if extend
	 * */
	cur_in_4k = freespace_ctx.user_space >> (SFX_PAGE_SHIFT - SECTOR_SHIFT);
	extend = (cur_in_4k <= trg_in_4k);
	if (extend) {
		if (sysinfo(&s_info) < 0) {
			printf("change-cap query mem info fail\n");
			return -1;
		}
		mem_need = (trg_in_4k - cur_in_4k) * 8;
		if (s_info.freeram <= 10 || mem_need > s_info.freeram) {
			fprintf(stderr,
				"WARNING: Free memory is not enough! "
				"Please drop cache or extend more memory and retry\n"
				"WARNING: Memory needed is %llu, free memory is %lu\n",
				mem_need, s_info.freeram);
			return -1;
		}
	}
	*shrink = !extend;

	return 0;
}

/**
 * @brief prompt and get user confirm input
 *
 * @param str, prompt string
 *
 * @return 0, cancled; 1 confirmed
 */
static int sfx_confirm_change(const char *str)
{
	char confirm;
	fprintf(stderr, "WARNING: %s.\n"
			"Use the force [--force] option to suppress this warning.\n", str);

	fprintf(stderr, "Confirm Y/y, Others cancel:\n");
	confirm = fgetc(stdin);
	if (confirm != 'y' && confirm != 'Y') {
		fprintf(stderr, "Cancled.\n");
		return 0;
	}
	fprintf(stderr, "Sending operation ... \n");
	return 1;
}

static int change_cap(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	int err = -1, fd;
	char *desc = "query current capacity info of vanda";
	const char *raw = "dump output in binary format";
	const char *json= "Dump output in json format";
	const char *cap_gb = "cap size in GB";
	const char *cap_byte = "cap size in byte";
	const char *force = "The \"I know what I'm doing\" flag, skip confirmation before sending command";
	__u64 cap_in_4k = 0;
	__u64 cap_in_sec = 0;
	int shrink = 0;

	struct config {
		__u64 cap_in_byte;
		__u32 capacity_in_gb;
		int   raw_binary;
		int   json;
		int   force;
	};

	struct config cfg = {
	.cap_in_byte = 0,
	.capacity_in_gb = 0,
	.force = 0,
	};

	OPT_ARGS(opts) = {
		OPT_UINT("cap",			'c',	&cfg.capacity_in_gb,	cap_gb),
		OPT_SUFFIX("cap-byte",	'z',	&cfg.cap_in_byte,		cap_byte),
		OPT_FLAG("force",		'f',	&cfg.force,				force),
		OPT_FLAG("raw-binary",	'b',	&cfg.raw_binary,		raw),
		OPT_FLAG("json",		'j',	&cfg.json,				json),
		OPT_END()
	};

	fd = parse_and_open(argc, argv, desc, opts);
	if (fd < 0) {
		return fd;
	}

	cap_in_sec = IDEMA_CAP(cfg.capacity_in_gb);
	cap_in_4k = cap_in_sec >> 3;
	if (cfg.cap_in_byte)
		cap_in_4k = cfg.cap_in_byte >> 12;
	printf("%dG %lluB %llu 4K\n",
		cfg.capacity_in_gb, cfg.cap_in_byte, cap_in_4k);

	if (change_sanity_check(fd, cap_in_4k, &shrink)) {
		printf("ScaleFlux change-capacity: fail\n");
		return err;
	}

	if (!cfg.force && shrink && !sfx_confirm_change("Changing Cap may irrevocably delete this device's data")) {
		return 0;
	}

	err = nvme_change_cap(fd, 0xffffffff, cap_in_4k);
	if (err < 0)
		perror("sfx-change-cap");
	else if (err != 0)
		fprintf(stderr, "NVMe IO command error:%s(%x)\n",
				nvme_status_to_string(err), err);
	else {
		printf("ScaleFlux change-capacity: success\n");
		ioctl(fd, BLKRRPART);
	}
	return err;
}

static int sfx_verify_chr(int fd)
{
	static struct stat nvme_stat;
	int err = fstat(fd, &nvme_stat);

	if (err < 0) {
		perror("fstat");
		return errno;
	}
	if (!S_ISCHR(nvme_stat.st_mode)) {
		fprintf(stderr,
			"Error: requesting clean card on non-controller handle\n");
		return ENOTBLK;
	}
	return 0;
}

static int sfx_clean_card(int fd, unsigned int cap, unsigned int p_cap)
{
	int ret;
	sfx_capacity_ctx cap_val = { .capacity = 0, .p_capacity = 0 };

	ret = sfx_verify_chr(fd);
	if (ret)
		return ret;

	cap_val.capacity = cap;
	cap_val.p_capacity = p_cap;
	ret = ioctl(fd, NVME_IOCTL_CLR_CARD, &cap_val);
	if (ret)
		perror("Ioctl Fail.");
	else
		printf("ScaleFlux clean card success\n");

	return ret;
}

char *sfx_feature_to_string(int feature)
{
	switch (feature) {
		case SFX_FEAT_ATOMIC:
			return "ATOMIC";
		case SFX_FEAT_ACT_MODE:
			return "ACT MODE";
		case SFX_FEAT_UP_P_CAP:
			return "UPDATE_PROVISION_CAPACITY";

		default:
			return "Unknown";
	}
}

static int sfx_get_phy_cap_range(int fd, sfx_phy_cap_range_ctx *phy_cap_range)
{
	int ret = 0;
	sfx_phy_cap_range_ctx ctx;

	ret = ioctl(fd, SFX_BLK_FTL_IOCTL_GET_PHY_CAP_RANGE, &ctx);
	if (ret) {
		perror("Ioctl Fail");
		return INVALID_PARAM;
	}
	phy_cap_range->max_capacity = ctx.max_capacity;
	phy_cap_range->pret_prov_cap = ctx.pret_prov_cap;

	return ret;
}

int nvme_set_keyinfo(int fd, __u32 data_len, void *data)
{
	struct nvme_admin_cmd cmd = {
		.opcode = nvme_admin_set_keyinfo,
		.addr = (__u64)(uintptr_t)data,
		.data_len = data_len,
	};
	return nvme_submit_admin_passthru(fd, &cmd);
}

int nvme_get_keyinfo(int fd, __u32 data_len, void *data)
{
	struct nvme_admin_cmd cmd = {
		.opcode = nvme_admin_get_keyinfo,
		.addr = (__u64)(uintptr_t)data,
		.data_len = data_len,
	};
	return nvme_submit_admin_passthru(fd, &cmd);
}

/**
 * @brief test bd_probe finish by test file /sys/devices/virtual/block/sfd0n1/serial
 *
 * @param blk_dev
 *
 * @return
 */
int sfx_wait_bd_probe_done()
{
	int cnt = 0;
	char flg_file_test[100] = { 0 };
	int dev_index = -1;
	NVME_DEV_TYPE type = sfx_dev_type((char *)devicename);
	if (type == NVME_SFX_C_DEV_VANDA) {
		//vanda device
		sscanf(devicename, SFX_NVME_DEV_C_VANDA "%d", &dev_index);
		snprintf(flg_file_test, sizeof(flg_file_test),
			"cat /sys/devices/virtual/block/%s%dn1/serial >/dev/null 2>&1",
			SFX_NVME_DEV_B_VANDA, dev_index);
	} else if (type == NVME_SFX_C_DEV_TPLUS) {
		sscanf(devicename, SFX_NVME_DEV_C_TPLUS "%d", &dev_index);
		snprintf(flg_file_test, sizeof(flg_file_test),
			"cat /sys/devices/virtual/block/%s%dn1/serial >/dev/null 2>&1",
			SFX_NVME_DEV_B_TPLUS, dev_index);
	} else {
		fprintf(stderr, "Invalid device name: %s.\n", devicename);
		return -1;
	}

	while (0 != system(flg_file_test) && cnt++ < 45) {
		sleep(1);
	};

	return 0;
}


static int sfx_set_feature(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	int err = 0, fd;
	char blk_base[64];
	char blk_path[128];
	int blk_fd = -1;
	__u32 atomic = 0;
	int sector_size = 0;
	__u32 act_mode = 0;
	int lbaf = 0;
	int sec_erase = 0;
	int card_cleaned = 0;
	sfx_capacity_ctx cap_val = { .capacity = 0, .p_capacity = 0 };
	sfx_phy_cap_range_ctx phy_cap_range = { .max_capacity = 0,
						.pret_prov_cap = 0 };
	const __u32 keyinfo_len = 1024;
	char keyinfo[keyinfo_len];
	char *desc = "ScaleFlux internal set features\n"
				 "feature id 1: ATOMIC\n"
				 "value 0: Disable atomic write\n"
				 "	1: Enable atomic write";
	const char *value = "new value of feature (required)";
	const char *feature_id = "hex feature name (required)";
	const char *namespace_id = "desired namespace";
	const char *force = "The \"I know what I'm doing\" flag, skip confirmation before sending command";

	struct nvme_id_ns ns;

	struct config {
		__u32 namespace_id;
		__u32 feature_id;
		__u32 value;
		__u32 force;
	};
	struct config cfg = {
		.namespace_id = 1,
		.feature_id = 0,
		.value = 0,
		.force = 0,
	};

	OPT_ARGS(opts) = {
		OPT_UINT("namespace-id",		'n',	&cfg.namespace_id,		namespace_id),
		OPT_UINT("feature-id",			'f',	&cfg.feature_id,		feature_id),
		OPT_UINT("value",			'v',	&cfg.value,			value),
		OPT_FLAG("force",			's',	&cfg.force,			force),
		OPT_END()
	};

	fd = parse_and_open(argc, argv, desc, opts);
	if (fd < 0) {
		return fd;
	}

	if (!cfg.feature_id) {
		fprintf(stderr, "feature-id required param\n");
		return EINVAL;
	}

	if (cfg.feature_id == SFX_FEAT_CLR_CARD) {
		/* Find and open block device via sfxv[X] misc device */
		nvme_block_from_char((char *)devicename, blk_base, sizeof(blk_base));
		if (sfx_blk_dev_ref() > 0) {
			fprintf(stderr,
				"Current device %s is mounted with filesystem or opened by application, "
				"Please umount filesystem or close the device in application first!\n",
				blk_base);
			return -1;
		}

		snprintf(blk_path, sizeof(blk_path), "/dev/%s", blk_base);
		blk_fd = open(blk_path, O_RDWR);
		if (blk_fd < 0) {
			goto clean_card;
		}

		/* Get sector size */
		if (cfg.namespace_id != 0xffffffff) {
			err = nvme_identify_ns(blk_fd, cfg.namespace_id, 0,
					       &ns);
			if (err) {
				goto clean_card;
			} else {
				sector_size = ((ns.flbas & 0xf) ? 4096 : 512);
			}
		}

		/* Get logical and physical capacity */
		if (get_capacity(blk_fd, &cap_val) != 0) {
			goto clean_card;
		}

		/* Get atomic write status */
		err = nvme_sfx_get_features(blk_fd, cfg.namespace_id,
					    SFX_FEAT_ATOMIC, &atomic);
		if (err) {
			goto clean_card;
		}

		/* Get ACT mode */
		err = nvme_sfx_get_features(blk_fd, cfg.namespace_id,
					    SFX_FEAT_ACT_MODE, &act_mode);
		if (err) {
			goto clean_card;
		}

		/* backup smart info */
		err = nvme_get_keyinfo(blk_fd, keyinfo_len, keyinfo);
		if (err) {
			goto clean_card;
		}
		/*Warning for clean card*/
		if (!cfg.force && !sfx_confirm_change("Going to clean device's data, confirm umount fs and try again")) {
			close(blk_fd);
			return 0;
		} else {
			/* do clean card and re-probe blk device*/
			if (sfx_clean_card(fd, cap_val.capacity,
					   cap_val.p_capacity) != 0) {
				fprintf(stderr, "clean card failed!\n");
				close(blk_fd);
				return -1;
			}
			card_cleaned = 1;
			sfx_wait_bd_probe_done();
			/* Need to reopen block device since it's new */
			close(blk_fd);

			/*
			 * /dev/sfdv[x]n1 is not re-created right after block
			 * device probe done, need to add delay here to make sure
			 * the device node was updated.
			 */
			sleep(1);

			blk_fd = open(blk_path, O_RDWR);
			if (blk_fd < 0) {
				fprintf(stderr, "open block device %s failed\n",
					blk_base);
				return blk_fd;
			}

			err = nvme_set_keyinfo(blk_fd, keyinfo_len, keyinfo);
			if (err) {
				if (err < 0) {
					fprintf(stderr,
						"NVME Admin command set-keyinfo error:%s(%x)\n",
						nvme_status_to_string(err),
						err);
				}
				close(blk_fd);
				return err;
			}

			/* Set sector size back, default is 512, no need to reset it */
			if (sector_size == 4096) {
				lbaf = 1;
				sec_erase = 1;
				err = nvme_format(blk_fd, cfg.namespace_id,
						  lbaf, sec_erase, 0, 0, 0, 0);
				if (err < 0) {
					fprintf(stderr,
						"NVME Admin command set sector size error:%s(%x)\n",
						nvme_status_to_string(err),
						err);
					close(blk_fd);
					return err;
				} else {
					__u8 retry = 0;
					printf("Success formatting namespace:%x\n",
					       cfg.namespace_id);
					while (ioctl(fd, BLKRRPART)) {
						if (retry++ > 50)
							break;
						usleep(100000);
					}
				}
			}

			/* Set atomic write back */
			if (atomic != 0) {
				if (cfg.namespace_id != 0xffffffff) {
					err = nvme_identify_ns(blk_fd,
							       cfg.namespace_id,
							       0, &ns);
					if (err) {
						fprintf(stderr,
							"NVME Admin command id ns error:%s(%x)\n",
							nvme_status_to_string(
								err),
							err);
						close(blk_fd);
						return err;
					}
					/*
					 * atomic only support with sector-size = 4k now
					 */
					if ((ns.flbas & 0xf) == 1) {
						err = nvme_sfx_set_features(
							blk_fd,
							cfg.namespace_id,
							SFX_FEAT_ATOMIC,
							atomic);
						if (err) {
							fprintf(stderr,
								"NVME Admin command set atomic write error:%s(%x)\n",
								nvme_status_to_string(
									err),
								err);
							close(blk_fd);
							return err;
						}
					}
				}
			}

			/* Set act mode back */
			if (act_mode != 0) {
				err = nvme_sfx_set_features(blk_fd,
							    cfg.namespace_id,
							    SFX_FEAT_ACT_MODE,
							    act_mode);
				if (err) {
					fprintf(stderr,
						"NVME Admin command set act mode error:%s(%x)\n",
						nvme_status_to_string(err),
						err);
					close(blk_fd);
					return err;
				}
			}
		}
	clean_card:
		if (blk_fd >= 0) {
			close(blk_fd);
		}
		if (card_cleaned == 0) {
			/*Warning for clean card*/
			if (!cfg.force &&
			    !sfx_confirm_change(
				    "Going to clean device's data, confirm umount fs and try again")) {
				close(blk_fd);
				return 0;
			}
			fprintf(stderr,
				"Cannot restore previous configuration, drive will be formatted to default!\n");
			if (sfx_clean_card(fd, cap_val.capacity,
					   cap_val.p_capacity) != 0) {
				fprintf(stderr, "clean card failed!\n");
				return -1;
			} else {
				card_cleaned = 1;
			}
		}
		return 0;
	}

	if (cfg.feature_id == SFX_FEAT_ATOMIC && cfg.value != 0) {
		if (cfg.namespace_id != 0xffffffff) {
			err = nvme_identify_ns(fd, cfg.namespace_id, 0, &ns);
			if (err) {
				if (err < 0)
					perror("identify-namespace");
				else
					fprintf(stderr,
						"NVMe Admin command error:%s(%x)\n",
						nvme_status_to_string(err), err);
				return err;
			}
			/*
			 * atomic only support with sector-size = 4k now
			 */
			if ((ns.flbas & 0xf) != 1) {
				printf("Please change-sector size to 4K, then retry\n");
				return EFAULT;
			}
		}
	} else if (cfg.feature_id == SFX_FEAT_UP_P_CAP) {
		if (sfx_get_phy_cap_range(fd, &phy_cap_range) != 0) {
			fprintf(stderr, "Get physical capacity range failed\n");
			return EINVAL;
		} else {
			if (cfg.value > phy_cap_range.max_capacity ||
			    cfg.value < (phy_cap_range.pret_prov_cap / 2)) {
				fprintf(stderr,
					"Invalid physical capacity value %d, valid range [%dGB-%dGB]\n",
					cfg.value,
					(phy_cap_range.pret_prov_cap / 2),
					phy_cap_range.max_capacity);
				return EINVAL;
			}
		}

		/*Warning for change pacp by GB*/
		if (!cfg.force && !sfx_confirm_change("Changing physical capacity may irrevocably delete this device's data")) {
			return 0;
		}
	}

	err = nvme_sfx_set_features(fd, cfg.namespace_id, cfg.feature_id, cfg.value);

	if (err < 0) {
		perror("ScaleFlux-set-feature");
		return errno;
	} else if (!err) {
		printf("ScaleFlux set-feature:%#02x (%s), value:%d\n", cfg.feature_id,
			sfx_feature_to_string(cfg.feature_id), cfg.value);
	} else if (err > 0)
		fprintf(stderr, "NVMe Status:%s(%x)\n",
				nvme_status_to_string(err), err);

	return err;
}

static int sfx_get_feature(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	int err = 0, fd;
	char *desc = "ScaleFlux internal set features\n"
				 "feature id 1: ATOMIC";
	const char *feature_id = "hex feature name (required)";
	const char *namespace_id = "desired namespace";
	__u32 result = 0;

	struct config {
		__u32 namespace_id;
		__u32 feature_id;
	};
	struct config cfg = {
		.namespace_id = 0,
		.feature_id = 0,
	};

	OPT_ARGS(opts) = {
		OPT_UINT("namespace-id",		'n',	&cfg.namespace_id,		namespace_id),
		OPT_UINT("feature-id",			'f',	&cfg.feature_id,		feature_id),
		OPT_END()
	};

	fd = parse_and_open(argc, argv, desc, opts);

	if (fd < 0) {
		return fd;
	}

	if (!cfg.feature_id) {
		fprintf(stderr, "feature-id required param\n");
		return EINVAL;
	}

	err = nvme_sfx_get_features(fd, cfg.namespace_id, cfg.feature_id, &result);
	if (err < 0) {
		perror("ScaleFlux-get-feature");
		return errno;
	} else if (!err) {
		printf("ScaleFlux get-feature:%02x (%s), value:%d\n", cfg.feature_id,
			sfx_feature_to_string(cfg.feature_id), result);
	} else if (err > 0)
		fprintf(stderr, "NVMe Status:%s(%x)\n",
				nvme_status_to_string(err), err);

	return err;

}
