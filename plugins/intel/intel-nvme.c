#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <inttypes.h>

#include "linux/nvme_ioctl.h"

#include "common.h"
#include "nvme.h"
#include "nvme-print.h"
#include "nvme-ioctl.h"
#include "json.h"
#include "plugin.h"

#include "argconfig.h"
#include "suffix.h"

#define CREATE_CMD
#include "intel-nvme.h"

#pragma pack(push,1)
struct nvme_additional_smart_log_item {
	__u8			key;
	__u8			_kp[2];
	__u8			norm;
	__u8			_np;
	union {
		__u8		raw[6];
		struct wear_level {
			__le16	min;
			__le16	max;
			__le16	avg;
		} wear_level ;
		struct thermal_throttle {
			__u8	pct;
			__u32	count;
		} thermal_throttle;
	};
	__u8			_rp;
};
#pragma pack(pop)

struct nvme_additional_smart_log {
	struct nvme_additional_smart_log_item	program_fail_cnt;
	struct nvme_additional_smart_log_item	erase_fail_cnt;
	struct nvme_additional_smart_log_item	wear_leveling_cnt;
	struct nvme_additional_smart_log_item	e2e_err_cnt;
	struct nvme_additional_smart_log_item	crc_err_cnt;
	struct nvme_additional_smart_log_item	timed_workload_media_wear;
	struct nvme_additional_smart_log_item	timed_workload_host_reads;
	struct nvme_additional_smart_log_item	timed_workload_timer;
	struct nvme_additional_smart_log_item	thermal_throttle_status;
	struct nvme_additional_smart_log_item	retry_buffer_overflow_cnt;
	struct nvme_additional_smart_log_item	pll_lock_loss_cnt;
	struct nvme_additional_smart_log_item	nand_bytes_written;
	struct nvme_additional_smart_log_item	host_bytes_written;
};

static void intel_id_ctrl(__u8 *vs, struct json_object *root)
{
	char bl[9];
        char health[21];

	memcpy(bl, &vs[28], sizeof(bl));
	memcpy(health, &vs[4], sizeof(health));

	bl[sizeof(bl) - 1] = '\0';
	health[sizeof(health) - 1] = '\0';

	if (root) {
		json_object_add_value_int(root, "ss", vs[3]);
		json_object_add_value_string(root, "health", health[0] ? health : "healthy");
		json_object_add_value_string(root, "bl", bl);
	} else {
		printf("ss      : %d\n", vs[3]);
		printf("health  : %s\n", health[0] ? health : "healthy");
		printf("bl      : %s\n", bl);
	}
}

static int id_ctrl(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	return __id_ctrl(argc, argv, cmd, plugin, intel_id_ctrl);
}

static void show_intel_smart_log_jsn(struct nvme_additional_smart_log *smart,
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
	json_object_add_value_float(entry_stats, "raw", ((long double)int48_to_long(smart->timed_workload_media_wear.raw)) / 1024);
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
	json_object_add_value_int(entry_stats, "raw", 	int48_to_long(smart->retry_buffer_overflow_cnt.raw));
	json_object_add_value_object(dev_stats, "retry_buffer_overflow_count", entry_stats);

	entry_stats = json_create_object();
	json_object_add_value_int(entry_stats, "normalized", smart->pll_lock_loss_cnt.norm);
	json_object_add_value_int(entry_stats, "raw", 	int48_to_long(smart->pll_lock_loss_cnt.raw));
	json_object_add_value_object(dev_stats, "pll_lock_loss_count", entry_stats);

	entry_stats = json_create_object();
	json_object_add_value_int(entry_stats, "normalized", smart->nand_bytes_written.norm);
	json_object_add_value_int(entry_stats, "raw", 	int48_to_long(smart->nand_bytes_written.raw));
	json_object_add_value_object(dev_stats, "nand_bytes_written", entry_stats);

	entry_stats = json_create_object();
	json_object_add_value_int(entry_stats, "normalized", smart->host_bytes_written.norm);
	json_object_add_value_int(entry_stats, "raw", 	int48_to_long(smart->host_bytes_written.raw));
	json_object_add_value_object(dev_stats, "host_bytes_written", entry_stats);

	json_object_add_value_object(root, "Device stats", dev_stats);

	json_print_object(root, NULL);
	json_free_object(root);
}

static void show_intel_smart_log(struct nvme_additional_smart_log *smart,
		unsigned int nsid, const char *devname)
{
	printf("Additional Smart Log for NVME device:%s namespace-id:%x\n",
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
}

static int get_additional_smart_log(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	struct nvme_additional_smart_log smart_log;
	int err, fd;
	const char *desc = "Get Intel vendor specific additional smart log (optionally, "\
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
		.namespace_id = NVME_NSID_ALL,
	};

	const struct argconfig_commandline_options command_line_options[] = {
		{"namespace-id", 'n', "NUM", CFG_POSITIVE, &cfg.namespace_id, required_argument, namespace},
		{"raw-binary",   'b', "",    CFG_NONE,     &cfg.raw_binary,   no_argument,       raw},
		{"json",         'j', "",    CFG_NONE,     &cfg.json,         no_argument,       json},
		{NULL}
	};

	fd = parse_and_open(argc, argv, desc, command_line_options, &cfg, sizeof(cfg));
	if (fd < 0)
		return fd;

	err = nvme_get_log(fd, cfg.namespace_id, 0xca, false,
			   sizeof(smart_log), &smart_log);
	if (!err) {
		if (cfg.json)
			show_intel_smart_log_jsn(&smart_log, cfg.namespace_id, devicename);
		else if (!cfg.raw_binary)
			show_intel_smart_log(&smart_log, cfg.namespace_id, devicename);
		else
			d_raw((unsigned char *)&smart_log, sizeof(smart_log));
	}
	else if (err > 0)
		fprintf(stderr, "NVMe Status:%s(%x)\n",
					nvme_status_to_string(err), err);
	return err;
}

static int get_market_log(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	char log[512];
	int err, fd;

	const char *desc = "Get Intel Marketing Name log and show it.";
	const char *raw = "dump output in binary format";
	struct config {
		int  raw_binary;
	};

	struct config cfg = {
	};

	const struct argconfig_commandline_options command_line_options[] = {
		{"raw-binary", 'b', "", CFG_NONE, &cfg.raw_binary, no_argument, raw},
		{NULL}
	};

	fd = parse_and_open(argc, argv, desc, command_line_options, &cfg, sizeof(cfg));
	if (fd < 0)
		return fd;

	err = nvme_get_log(fd, NVME_NSID_ALL, 0xdd, false,
			   sizeof(log), log);
	if (!err) {
		if (!cfg.raw_binary)
			printf("Intel Marketing Name Log:\n%s\n", log);
		else
			d_raw((unsigned char *)&log, sizeof(log));
	} else if (err > 0)
		fprintf(stderr, "NVMe Status:%s(%x)\n",
					nvme_status_to_string(err), err);
	return err;
}


struct intel_temp_stats {
	__le64	curr;
	__le64	last_overtemp;
	__le64	life_overtemp;
	__le64	highest_temp;
	__le64	lowest_temp;
	__u8	rsvd[40];
	__le64	max_operating_temp;
	__le64	min_operating_temp;
	__le64	est_offset;
};

static void show_temp_stats(struct intel_temp_stats *stats)
{
	printf("  Intel Temperature Statistics\n");
	printf("--------------------------------\n");
	printf("Current temperature         : %"PRIu64"\n", le64_to_cpu(stats->curr));
	printf("Last critical overtemp flag : %"PRIu64"\n", le64_to_cpu(stats->last_overtemp));
	printf("Life critical overtemp flag : %"PRIu64"\n", le64_to_cpu(stats->life_overtemp));
	printf("Highest temperature         : %"PRIu64"\n", le64_to_cpu(stats->highest_temp));
	printf("Lowest temperature          : %"PRIu64"\n", le64_to_cpu(stats->lowest_temp));
	printf("Max operating temperature   : %"PRIu64"\n", le64_to_cpu(stats->max_operating_temp));
	printf("Min operating temperature   : %"PRIu64"\n", le64_to_cpu(stats->min_operating_temp));
	printf("Estimated offset            : %"PRIu64"\n", le64_to_cpu(stats->est_offset));
}

static int get_temp_stats_log(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	struct intel_temp_stats stats;
	int err, fd;

	const char *desc = "Get Intel Marketing Name log and show it.";
	const char *raw = "dump output in binary format";
	struct config {
		int  raw_binary;
	};

	struct config cfg = {
	};

	const struct argconfig_commandline_options command_line_options[] = {
		{"raw-binary", 'b', "", CFG_NONE, &cfg.raw_binary, no_argument, raw},
		{NULL}
	};

	fd = parse_and_open(argc, argv, desc, command_line_options, &cfg, sizeof(cfg));
	if (fd < 0)
		return fd;

	err = nvme_get_log(fd, NVME_NSID_ALL, 0xc5, false,
			   sizeof(stats), &stats);
	if (!err) {
		if (!cfg.raw_binary)
			show_temp_stats(&stats);
		else
			d_raw((unsigned char *)&stats, sizeof(stats));
	} else if (err > 0)
		fprintf(stderr, "NVMe Status:%s(%x)\n",
					nvme_status_to_string(err), err);
	return err;
}

struct intel_lat_stats {
	__u16	maj;
	__u16	min;
	__u32	bucket_1[32];
	__u32	bucket_2[31];
	__u32	bucket_3[31];
};

static void show_lat_stats(struct intel_lat_stats *stats, int write)
{
	int i;

	printf(" Intel IO %s Command Latency Statistics\n", write ? "Write" : "Read");
	printf("-------------------------------------\n");
	printf("Major Revision : %u\n", stats->maj);
	printf("Minor Revision : %u\n", stats->min);

	printf("\nGroup 1: Range is 0-1ms, step is 32us\n");
	for (i = 0; i < 32; i++)
		printf("Bucket %2d: %u\n", i, stats->bucket_1[i]);

	printf("\nGroup 2: Range is 1-32ms, step is 1ms\n");
	for (i = 0; i < 31; i++)
		printf("Bucket %2d: %u\n", i, stats->bucket_2[i]);

	printf("\nGroup 3: Range is 32-1s, step is 32ms:\n");
	for (i = 0; i < 31; i++)
		printf("Bucket %2d: %u\n", i, stats->bucket_3[i]);
}

static int get_lat_stats_log(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	struct intel_lat_stats stats;
	int err, fd;

	const char *desc = "Get Intel Latency Statistics log and show it.";
	const char *raw = "dump output in binary format";
	const char *write = "Get write statistics (read default)";
	struct config {
		int  raw_binary;
		int  write;
	};

	struct config cfg = {
	};

	const struct argconfig_commandline_options command_line_options[] = {
		{"write",      'w', "", CFG_NONE, &cfg.write,      no_argument, write},
		{"raw-binary", 'b', "", CFG_NONE, &cfg.raw_binary, no_argument, raw},
		{NULL}
	};

	fd = parse_and_open(argc, argv, desc, command_line_options, &cfg, sizeof(cfg));
	if (fd < 0)
		return fd;

	err = nvme_get_log(fd, NVME_NSID_ALL, cfg.write ? 0xc2 : 0xc1,
			   false, sizeof(stats), &stats);
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

struct intel_assert_dump {
    __u32 coreoffset;
    __u32 assertsize;
    __u8  assertdumptype;
    __u8  assertvalid;
    __u8  reserved[2];
};

struct intel_event_dump {
	__u32 numeventdumps;
	__u32 coresize;
	__u32 coreoffset;
	__u32 eventidoffset[16];
	__u8  eventIdValidity[16];
};

struct intel_vu_version {
	__u16    major;
	__u16    minor;
};

struct intel_event_header {
	__u32 eventidsize;
	struct intel_event_dump edumps[0];
};

struct intel_vu_log {
    struct intel_vu_version ver;
    __u32    header;
    __u32    size;
    __u32    numcores;
    __u8     reserved[4080];
};

struct intel_vu_nlog {
	struct intel_vu_version ver;
	__u32 logselect;
	__u32 totalnlogs;
	__u32 nlognum;
	__u32 nlogname;
	__u32 nlogbytesize;
	__u32 nlogprimarybuffsize;
	__u32 tickspersecond;
	__u32 corecount;
	__u32 nlogpausestatus;
	__u32 selectoffsetref;
	__u32 selectnlogpause;
	__u32 selectaddedoffset;
	__u32 nlogbufnum;
	__u32 nlogbufnummax;
	__u32 coreselected;
	__u32 reserved[3];
};

struct intel_cd_log {
    union {
	struct {
		__u32 selectLog  : 3;
		__u32 selectCore : 2;
		__u32 selectNlog : 8;
		__u8  selectOffsetRef : 1;
		__u32 selectNlogPause : 2;
		__u32 reserved2  : 16;
	}fields;
	__u32 entireDword;
    }u;
};

static void print_intel_nlog(struct intel_vu_nlog *intel_nlog)
{
	printf("Version Major %u\n"
	       "Version Minor %u\n"
	       "Log_select %u\n"
	       "totalnlogs %u\n"
	       "nlognum %u\n"
	       "nlogname %u\n"
	       "nlogbytesze %u\n"
	       "nlogprimarybuffsize %u\n"
	       "tickspersecond %u\n"
	       "corecount %u\n"
	       "nlogpausestatus %u\n"
	       "selectoffsetref %u\n"
	       "selectnlogpause %u\n"
	       "selectaddedoffset %u\n"
	       "nlogbufnum %u\n"
	       "nlogbufnummax %u\n"
	       "coreselected %u\n",
	       intel_nlog->ver.major, intel_nlog->ver.minor,
	       intel_nlog->logselect, intel_nlog->totalnlogs, intel_nlog->nlognum,
	       intel_nlog->nlogname, intel_nlog->nlogbytesize,
	       intel_nlog->nlogprimarybuffsize, intel_nlog->tickspersecond,
	       intel_nlog->corecount, intel_nlog->nlogpausestatus,
	       intel_nlog->selectoffsetref, intel_nlog->selectnlogpause,
	       intel_nlog->selectaddedoffset, intel_nlog->nlogbufnum,
	       intel_nlog->nlogbufnummax, intel_nlog->coreselected);
}

static int read_entire_cmd(struct nvme_passthru_cmd *cmd, int total_size,
			   const size_t max_tfer, int out_fd, int ioctl_fd,
			   __u8 *buf)
{
	int err = 0;
	size_t dword_tfer = 0;

	dword_tfer = min(max_tfer, total_size);
	while (total_size > 0) {
		err = nvme_submit_passthru(ioctl_fd, NVME_IOCTL_ADMIN_CMD, cmd);
		if (err) {
			fprintf(stderr, "failed on cmd.data_len %u cmd.cdw13 %u cmd.cdw12 %x cmd.cdw10 %u err %x remaining size %d\n", cmd->data_len, cmd->cdw13, cmd->cdw12, cmd->cdw10, err, total_size);
			goto out;
		}

		if (out_fd > 0) {
			err = write(out_fd, buf, cmd->data_len);
			if (err < 0) {
				perror("write failure");
				goto out;
			}
			err = 0;
		}
		total_size -= dword_tfer;
		cmd->cdw13 += dword_tfer;
		cmd->cdw10 = dword_tfer = min(max_tfer, total_size);
		cmd->data_len = (min(max_tfer, total_size)) * 4;
	}

 out:
	return err;
}

static int write_header(__u8 *buf, int fd, size_t amnt)
{
	if (write(fd, buf, amnt) < 0)
		return 1;
	return 0;
}

static int read_header(struct nvme_passthru_cmd *cmd,__u8 *buf, int ioctl_fd, __u32 dw12, int nsid)
{
	memset(cmd, 0, sizeof(*cmd));
	memset(buf, 0, 4096);
	cmd->opcode = 0xd2;
	cmd->nsid = nsid;
	cmd->cdw10 = 0x400;
	cmd->cdw12 = dw12;
	cmd->data_len = 0x1000;
	cmd->addr = (unsigned long)(void *)buf;
	return read_entire_cmd(cmd, 0x400, 0x400, -1, ioctl_fd, buf);
}

static int setup_file(char *f, char *file, int fd, int type)
{
	struct nvme_id_ctrl ctrl;
	int err = 0, i = sizeof(ctrl.sn) - 1;

	err = nvme_identify_ctrl(fd, &ctrl);
	if (err)
		return err;

	/* Remove trailing spaces from the name */
	while (i && ctrl.sn[i] == ' ') {
		ctrl.sn[i] = '\0';
		i--;
	}

	sprintf(f, "%s_%-.*s.bin", type == 0 ? "Nlog" :
		type == 1 ? "EventLog" :  "AssertLog",
		(int)sizeof(ctrl.sn), ctrl.sn);
	return err;
}

static int get_internal_log_old(__u8 *buf, int output, int fd,
				struct nvme_passthru_cmd *cmd)
{
	struct intel_vu_log *intel;
	int err = 0;
	const int dwmax = 0x400;
	const int dmamax = 0x1000;

	intel = (struct intel_vu_log *)buf;

	printf("Log major:%d minor:%d header:%d size:%d\n",
		intel->ver.major, intel->ver.minor, intel->header, intel->size);

	err = write(output, buf, 0x1000);
	if (err < 0) {
		perror("write failure");
		goto out;
	}
	intel->size -= 0x400;
	cmd->opcode = 0xd2;
	cmd->cdw10 = min(dwmax, intel->size);
	cmd->data_len = min(dmamax, intel->size);
	err = read_entire_cmd(cmd, intel->size, dwmax, output, fd, buf);
	if (err)
		goto out;

	err = 0;
 out:
	return err;
}

static int get_internal_log(int argc, char **argv, struct command *command, struct plugin *plugin)
{
	__u8 buf[0x2000];
	char f[0x100];
	int err, fd, output, i, j, count = 0, core_num = 1;//, remainder;
	struct nvme_passthru_cmd cmd;
	struct intel_cd_log cdlog;
	struct intel_vu_log *intel = malloc(sizeof(struct intel_vu_log));
	struct intel_vu_nlog *intel_nlog = (struct intel_vu_nlog *)buf;
	struct intel_assert_dump *ad = (struct intel_assert_dump *) intel->reserved;
	struct intel_event_header *ehdr = (struct intel_event_header *)intel->reserved;

	const char *desc = "Get Intel Firmware Log and save it.";
	const char *log = "Log type: 0, 1, or 2 for nlog, event log, and assert log, respectively.";
	const char *core = "Select which region log should come from. -1 for all";
	const char *nlognum = "Select which nlog to read. -1 for all nlogs";
	const char *file = "Output file; defaults to device name provided";
	const char *verbose = "To print out verbose nlog info";
	const char *namespace_id = "Namespace to get logs from";

	struct config {
		__u32 namespace_id;
		__u32 log;
		int core;
		int lnum;
		char *file;
		bool verbose;
	};

	struct config cfg = {
		.namespace_id = -1,
		.file = NULL,
		.lnum = -1,
		.core = -1
	};

	const struct argconfig_commandline_options command_line_options[] = {
		{"log",          'l', "NUM",  CFG_POSITIVE, &cfg.log,          required_argument, log},
		{"region",       'r', "NUM",  CFG_INT,      &cfg.core,         required_argument, core},
		{"nlognum",      'm', "NUM",  CFG_INT,      &cfg.lnum,         required_argument, nlognum},
		{"namespace-id", 'n', "NUM",  CFG_POSITIVE, &cfg.namespace_id, required_argument, namespace_id},
		{"output-file",  'o', "FILE", CFG_STRING,   &cfg.file,         required_argument, file},
		{"verbose_nlog", 'v', ""    , CFG_NONE,     &cfg.verbose,      no_argument,       verbose},
		{NULL}
	};

	fd = parse_and_open(argc, argv, desc, command_line_options, &cfg, sizeof(cfg));
	if (fd < 0) {
		free(intel);
		return fd;
	}

	if (cfg.log > 2 || cfg.core > 4 || cfg.lnum > 255) {
		free(intel);
		return EINVAL;
	}

	if (!cfg.file) {
		err = setup_file(f, cfg.file, fd, cfg.log);
		if (err)
			goto out;
		cfg.file = f;
	}

	cdlog.u.entireDword = 0;

	cdlog.u.fields.selectLog = cfg.log;
	cdlog.u.fields.selectCore = cfg.core < 0 ? 0 : cfg.core;
	cdlog.u.fields.selectNlog = cfg.lnum < 0 ? 0 : cfg.lnum;

	output = open(cfg.file, O_WRONLY | O_CREAT | O_TRUNC, 0666);

	err = read_header(&cmd, buf, fd, cdlog.u.entireDword, cfg.namespace_id);
	if (err)
		goto out;
	memcpy(intel, buf, sizeof(*intel));

	/* for 1.1 Fultondales will use old nlog, but current assert/event */
	if ((intel->ver.major < 1 && intel->ver.minor < 1) ||
	    (intel->ver.major <= 1 && intel->ver.minor <= 1 && cfg.log == 0)) {
		cmd.addr = (unsigned long)(void *)buf;
		err = get_internal_log_old(buf, output, fd, &cmd);
		goto out;
	}

	if (cfg.log == 2) {
		if (cfg.verbose)
			printf("Log major:%d minor:%d header:%d size:%d numcores:%d\n",
			       intel->ver.major, intel->ver.minor, intel->header, intel->size,
			       intel->numcores);

		err = write_header(buf, output, 0x1000);
		if (err) {
			perror("write failure");
			goto out;
		}

		count = intel->numcores;
	} else if (cfg.log == 0) {
		if (cfg.lnum < 0)
			count = intel_nlog->totalnlogs;
		else
			count = 1;
		if (cfg.core < 0)
			core_num = intel_nlog->corecount;
	} else if (cfg.log == 1) {
		core_num = intel->numcores;
		count = 1;
		err = write_header(buf, output, sizeof(*intel));
		if (err)
			goto out;
	}

	for (j = (cfg.core < 0 ? 0 : cfg.core); j < (cfg.core < 0 ? core_num : cfg.core + 1); j++) {
		cdlog.u.fields.selectCore = j;
		for (i = 0; i < count; i++) {
			if (cfg.log == 2) {
				if (!ad[i].assertvalid)
					continue;
				cmd.cdw13 = ad[i].coreoffset;
				cmd.cdw10 = 0x400;
				cmd.data_len = min(0x400, ad[i].assertsize) * 4;
				err = read_entire_cmd(&cmd, ad[i].assertsize,
						      0x400, output, fd, buf);
				if (err)
					goto out;

			} else if(cfg.log == 0) {
				/* If the user selected to read the entire nlog */
				if (count > 1)
					cdlog.u.fields.selectNlog = i;

				err = read_header(&cmd, buf, fd, cdlog.u.entireDword,
						cfg.namespace_id);
				if (err)
					goto out;
				err = write_header(buf, output, sizeof(*intel_nlog));
				if (err)
					goto out;
				if (cfg.verbose)
					print_intel_nlog(intel_nlog);
				cmd.cdw13 = 0x400;
				cmd.cdw10 = 0x400;
				cmd.data_len = min(0x1000, intel_nlog->nlogbytesize);
				err = read_entire_cmd(&cmd, intel_nlog->nlogbytesize / 4,
						      0x400, output, fd, buf);
				if (err)
					goto out;
			} else if (cfg.log == 1) {
				cmd.cdw13 = ehdr->edumps[j].coreoffset;
				cmd.cdw10 = 0x400;
				cmd.data_len = 0x400;
				err = read_entire_cmd(&cmd, ehdr->edumps[j].coresize,
						      0x400, output, fd, buf);
				if (err)
					goto out;
			}
		}
	}
	err = 0;
 out:
	if (err > 0) {
		fprintf(stderr, "NVMe Status:%s(%x)\n",
				nvme_status_to_string(err), err);
	} else if (err < 0) {
		perror("intel log");
		err = EIO;
	} else
		printf("Successfully wrote log to %s\n", cfg.file);
	free(intel);
	return err;

}
