// SPDX-License-Identifier: GPL-2.0-or-later

#include <inttypes.h>
#include <signal.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/syslog.h>
#include <sys/time.h>
#include <linux/types.h>

#include <libnvme.h>
#include <libnvme-mi.h>

#include <ccan/endian/endian.h>

#include "logging.h"
#include "sighdl.h"

struct submit_data {
	struct timeval start;
	struct timeval end;
};

int log_level;
static bool dry_run;
static struct submit_data sb;

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

static void nvme_log_retry(int errnum)
{
	if (log_level < LOG_DEBUG)
		return;

	printf("passthru command returned '%s'\n", strerror(errnum));
}

int nvme_submit_passthru(int fd, unsigned long ioctl_cmd,
			 struct nvme_passthru_cmd *cmd, __u32 *result)
{
	struct timeval start;
	struct timeval end;
	int err = 0;

	if (log_level >= LOG_DEBUG)
		gettimeofday(&start, NULL);

	if (!dry_run) {
retry:
		err = ioctl(fd, ioctl_cmd, cmd);
		if (err && (errno == EAGAIN ||
			    (errno == EINTR && !nvme_sigint_received))) {
			nvme_log_retry(errno);
			goto retry;
		}
	}

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

	if (log_level >= LOG_DEBUG)
		gettimeofday(&start, NULL);

	if (!dry_run) {
retry:
		err = ioctl(fd, ioctl_cmd, cmd);
		if (err && (errno == EAGAIN ||
			    (errno == EINTR && !nvme_sigint_received))) {
			nvme_log_retry(errno);
			goto retry;
		}
	}

	if (log_level >= LOG_DEBUG) {
		gettimeofday(&end, NULL);
		nvme_show_command64(cmd, err);
		nvme_show_latency(start, end);
	}

	if (err >= 0 && result)
		*result = cmd->result;

	return err;
}

static void nvme_show_req_admin(const struct nvme_mi_admin_req_hdr *hdr, size_t hdr_len,
				const void *data, size_t data_len)
{
	struct nvme_passthru_cmd cmd = {
		.opcode = hdr->opcode,
		.flags = hdr->flags,
		.nsid = le32_to_cpu(hdr->cdw1),
		.cdw2 = le32_to_cpu(hdr->cdw2),
		.cdw3 = le32_to_cpu(hdr->cdw3),
		.addr = (uint64_t)(uintptr_t)data,
		.data_len = data_len,
		.cdw10 = le32_to_cpu(hdr->cdw10),
		.cdw11 = le32_to_cpu(hdr->cdw11),
		.cdw12 = le32_to_cpu(hdr->cdw12),
		.cdw13 = le32_to_cpu(hdr->cdw13),
		.cdw14 = le32_to_cpu(hdr->cdw14),
		.cdw15 = le32_to_cpu(hdr->cdw15),
	};

	nvme_show_common(&cmd);
	printf("doff         : %08x\n", le32_to_cpu(hdr->doff));
	printf("dlen         : %08x\n", le32_to_cpu(hdr->dlen));
}

static void nvme_show_req(__u8 type, const struct nvme_mi_msg_hdr *hdr, size_t hdr_len,
			  const void *data, size_t data_len)
{
	if (type != NVME_MI_MSGTYPE_NVME)
		return;

	switch (hdr->nmp >> 3 & 0xf) {
	case NVME_MI_MT_CONTROL:
		break;
	case NVME_MI_MT_MI:
		break;
	case NVME_MI_MT_ADMIN:
		nvme_show_req_admin((struct nvme_mi_admin_req_hdr *)hdr, hdr_len, data, data_len);
		break;
	case NVME_MI_MT_PCIE:
		break;
	case NVME_MI_MT_AE:
		break;
	default:
		break;
	}
}

void *nvme_mi_submit_entry(__u8 type, const struct nvme_mi_msg_hdr *hdr, size_t hdr_len,
			   const void *data, size_t data_len)
{
	memset(&sb, 0, sizeof(sb));

	if (log_level >= LOG_DEBUG) {
		nvme_show_req(type, hdr, hdr_len, data, data_len);
		gettimeofday(&sb.start, NULL);
	}

	return &sb;
}

static void nvme_show_resp_admin(const struct nvme_mi_admin_resp_hdr *hdr, size_t hdr_len,
				 const void *data, size_t data_len)
{
	printf("result       : %08x\n", le32_to_cpu(hdr->cdw0));
	printf("err          : %d\n", hdr->status);
}

static void nvme_show_resp(__u8 type, const struct nvme_mi_msg_hdr *hdr, size_t hdr_len,
			   const void *data, size_t data_len)
{
	if (type != NVME_MI_MSGTYPE_NVME)
		return;

	switch (hdr->nmp >> 3 & 0xf) {
	case NVME_MI_MT_CONTROL:
		break;
	case NVME_MI_MT_MI:
		break;
	case NVME_MI_MT_ADMIN:
		nvme_show_resp_admin((struct nvme_mi_admin_resp_hdr *)hdr, hdr_len, data, data_len);
		break;
	case NVME_MI_MT_PCIE:
		break;
	case NVME_MI_MT_AE:
		break;
	default:
		break;
	}
}

void nvme_mi_submit_exit(__u8 type, const struct nvme_mi_msg_hdr *hdr, size_t hdr_len,
			 const void *data, size_t data_len, void *user_data)
{
	struct submit_data *sb = user_data;

	if (log_level >= LOG_DEBUG) {
		gettimeofday(&sb->end, NULL);
		nvme_show_resp(type, hdr, hdr_len, data, data_len);
		nvme_show_latency(sb->start, sb->end);
	}
}
