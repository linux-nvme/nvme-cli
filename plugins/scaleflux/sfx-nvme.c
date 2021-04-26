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
#include "plugin.h"

#include "argconfig.h"
#include "suffix.h"

#define CREATE_CMD
#include "sfx-nvme.h"

#define SFX_PAGE_SHIFT						12
#define SECTOR_SHIFT						9

#define SFX_GET_FREESPACE			_IOWR('N', 0x240, struct sfx_freespace_ctx)
#define NVME_IOCTL_CLR_CARD			_IO('N', 0x47)

#define IDEMA_CAP(exp_GB)			(((__u64)exp_GB - 50ULL) * 1953504ULL + 97696368ULL)
#define IDEMA_CAP2GB(exp_sector)		(((__u64)exp_sector - 97696368ULL) / 1953504ULL + 50ULL)

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
	SFX_FEAT_UP_P_CAP		= 0xac,
	SFX_FEAT_CLR_CARD		= 0xdc,
};

enum sfx_nvme_admin_opcode {
	nvme_admin_query_cap_info	= 0xd3,
	nvme_admin_change_cap		= 0xd4,
	nvme_admin_sfx_set_features	= 0xd5,
	nvme_admin_sfx_get_features	= 0xd6,
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

	err = nvme_get_log(fd, cfg.namespace_id, 0xca, false, NVME_NO_LOG_LSP,
		sizeof(smart_log), (void *)&smart_log);
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

	err = nvme_get_log(fd, 0xffffffff, cfg.write ? 0xc3 : 0xc1, false, NVME_NO_LOG_LSP,
		sizeof(stats), (void *)&stats);
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
		printf(" 0x%"PRIx64"", (uint64_t)*(bb_elem++));
		i++;
	}
	printf(" ]\n");

	printf("REMAP_GBB_TABLE [");
	i = 0;
	while (bb_elem < elem_end && i < remap_gbb_count) {
		printf(" 0x%"PRIx64"", (uint64_t)*(bb_elem++));
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

static void show_cap_info(struct sfx_freespace_ctx *ctx)
{

	printf("logic            capacity:%5lluGB(0x%"PRIx64")\n",
			IDEMA_CAP2GB(ctx->user_space), (uint64_t)ctx->user_space);
	printf("provisioned      capacity:%5lluGB(0x%"PRIx64")\n",
			IDEMA_CAP2GB(ctx->phy_space), (uint64_t)ctx->phy_space);
	printf("free provisioned capacity:%5lluGB(0x%"PRIx64")\n",
			IDEMA_CAP2GB(ctx->free_space), (uint64_t)ctx->free_space);
	printf("used provisioned capacity:%5lluGB(0x%"PRIx64")\n",
			IDEMA_CAP2GB(ctx->phy_space) - IDEMA_CAP2GB(ctx->free_space),
			(uint64_t)(ctx->phy_space - ctx->free_space));
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
				"WARNING: Memory needed is %"PRIu64", free memory is %"PRIu64"\n",
				(uint64_t)mem_need, (uint64_t)s_info.freeram);
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
	printf("%dG %"PRIu64"B %"PRIu64" 4K\n",
		cfg.capacity_in_gb, (uint64_t)cfg.cap_in_byte, (uint64_t)cap_in_4k);

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

static int sfx_clean_card(int fd)
{
	int ret;

	ret = sfx_verify_chr(fd);
	if (ret)
		return ret;
	ret = ioctl(fd, NVME_IOCTL_CLR_CARD);
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
		case SFX_FEAT_UP_P_CAP:
			return "UPDATE_PROVISION_CAPACITY";

		default:
			return "Unknown";
	}
}

static int sfx_set_feature(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	int err = 0, fd;
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
		/*Warning for clean card*/
		if (!cfg.force && !sfx_confirm_change("Going to clean device's data, confirm umount fs and try again")) {
			return 0;
		} else {
			return sfx_clean_card(fd);
		}

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
		if (cfg.value <= 0) {
			fprintf(stderr, "Invalid Param\n");
			return EINVAL;
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
