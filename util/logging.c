// SPDX-License-Identifier: GPL-2.0-or-later

#include <inttypes.h>

#include <stdint.h>
#include <sys/ioctl.h>
#include <sys/syslog.h>
#include <sys/time.h>
#include <linux/types.h>

#include <libnvme.h>

#include "logging.h"

int log_level;
static bool dry_run;

int map_log_level(int verbose, bool quiet)
{
	int log_level;

	/*
	 * LOG_NOTICE is unused thus the user has to provide two 'v' for getting
	 * any feedback at all. Thus skip this level
	 */
	verbose++;

	switch (verbose) {
	case 0:
		log_level = LOG_WARNING;
		break;
	case 1:
		log_level = LOG_NOTICE;
		break;
	case 2:
		log_level = LOG_INFO;
		break;
	default:
		log_level = LOG_DEBUG;
		break;
	}
	if (quiet)
		log_level = LOG_ERR;

	return log_level;
}

void set_dry_run(bool enable)
{
	dry_run = enable;
}

static void nvme_show_common(struct nvme_passthru_cmd *cmd)
{
	printf("opcode       : %02x\n", cmd->opcode);
	printf("flags        : %02x\n", cmd->flags);
	printf("rsvd1        : %04x\n", cmd->rsvd1);
	printf("nsid         : %08x\n", cmd->nsid);
	printf("cdw2         : %08x\n", cmd->cdw2);
	printf("cdw3         : %08x\n", cmd->cdw3);
	printf("data_len     : %08x\n", cmd->data_len);
	printf("metadata_len : %08x\n", cmd->metadata_len);
	printf("addr         : %"PRIx64"\n", (uint64_t)(uintptr_t)cmd->addr);
	printf("metadata     : %"PRIx64"\n", (uint64_t)(uintptr_t)cmd->metadata);
	printf("cdw10        : %08x\n", cmd->cdw10);
	printf("cdw11        : %08x\n", cmd->cdw11);
	printf("cdw12        : %08x\n", cmd->cdw12);
	printf("cdw13        : %08x\n", cmd->cdw13);
	printf("cdw14        : %08x\n", cmd->cdw14);
	printf("cdw15        : %08x\n", cmd->cdw15);
	printf("timeout_ms   : %08x\n", cmd->timeout_ms);
}

static void nvme_show_command(struct nvme_passthru_cmd *cmd, int err)
{
	nvme_show_common(cmd);
	printf("result       : %08x\n", cmd->result);
	printf("err          : %d\n", err);
}

static void nvme_show_command64(struct nvme_passthru_cmd64 *cmd, int err)
{
	nvme_show_common((struct nvme_passthru_cmd *)cmd);
	printf("result       : %"PRIx64"\n", (uint64_t)(uintptr_t)cmd->result);
	printf("err          : %d\n", err);
}

static void nvme_show_latency(struct timeval start, struct timeval end)
{
	printf("latency      : %llu us\n",
	       (unsigned long long)((end.tv_sec - start.tv_sec) * 1000000 +
				    (end.tv_usec - start.tv_usec)));
}

int nvme_submit_passthru(int fd, unsigned long ioctl_cmd,
			 struct nvme_passthru_cmd *cmd, __u32 *result)
{
	struct timeval start;
	struct timeval end;
	int err;

	if (dry_run) {
		nvme_show_common(cmd);
		return 0;
	}

	if (log_level >= LOG_DEBUG)
		gettimeofday(&start, NULL);

	err = ioctl(fd, ioctl_cmd, cmd);

	if (log_level >= LOG_DEBUG) {
		gettimeofday(&end, NULL);
		nvme_show_command(cmd, err);
		nvme_show_latency(start, end);
	}

	if (err >= 0 && result)
		*result = cmd->result;

	return err;
}

int nvme_submit_passthru64(int fd, unsigned long ioctl_cmd,
			   struct nvme_passthru_cmd64 *cmd,
			   __u64 *result)
{
	struct timeval start;
	struct timeval end;
	int err = 0;

	if (dry_run) {
		nvme_show_common((struct nvme_passthru_cmd *)cmd);
		return 0;
	}

	if (log_level >= LOG_DEBUG)
		gettimeofday(&start, NULL);

	err = ioctl(fd, ioctl_cmd, cmd);

	if (log_level >= LOG_DEBUG) {
		gettimeofday(&end, NULL);
		nvme_show_command64(cmd, err);
		nvme_show_latency(start, end);
	}

	if (err >= 0 && result)
		*result = cmd->result;

	return err;
}

static void nvme_show_io_command(struct nvme_io_args *args, __u8 opcode)
{
	__u32 dsmgmt = args->dsm;
	__u8 dtype = (args->control >> 4) & 0xf;

	if (dtype)
		dsmgmt |= ((__u32)args->dspec) << 16;

	printf("opcode       : %02x\n", opcode);
	printf("nsid         : %02x\n", args->nsid);
	printf("flags        : %02x\n", 0);
	printf("control      : %04x\n", args->control);
	printf("nblocks      : %04x\n", args->nlb);
	printf("metadata     : %"PRIx64"\n", (uint64_t)(uintptr_t)args->metadata);
	printf("addr         : %"PRIx64"\n", (uint64_t)(uintptr_t)args->data);
	printf("slba         : %"PRIx64"\n", (uint64_t)(uintptr_t)args->slba);
	printf("dsmgmt       : %08x\n", dsmgmt);
	printf("reftag       : %"PRIx64"\n", (uint64_t)args->reftag_u64);
	printf("apptag       : %04x\n", args->apptag);
	printf("appmask      : %04x\n", args->appmask);
	printf("storagetagcheck : %04x\n", args->control & NVME_IO_STC ? true : false);
	printf("storagetag      : %"PRIx64"\n", (uint64_t)args->storage_tag);
	printf("pif             : %02x\n", args->pif);
	printf("sts             : %02x\n", args->sts);
}

int nvme_submit_io(struct nvme_io_args *args, __u8 opcode, bool show, bool latency)
{
	struct timeval start_time;
	struct timeval end_time;
	int err;

	if (show || dry_run)
		nvme_show_io_command(args, opcode);

	if (dry_run)
		return 0;

	gettimeofday(&start_time, NULL);
	err = nvme_io(args, opcode);
	gettimeofday(&end_time, NULL);

	if (latency)
		nvme_show_latency(start_time, end_time);

	return err;
}
