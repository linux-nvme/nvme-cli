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
#include "util/sighdl.h"
#include "nvme-print.h"

struct submit_data {
	struct timeval start;
	struct timeval end;
};

int log_level;
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

static void nvme_show_common(struct nvme_passthru_cmd *cmd)
{
	nvme_show_key_value("opcode       ", "%02x", cmd->opcode);
	nvme_show_key_value("flags        ", "%02x", cmd->flags);
	nvme_show_key_value("rsvd1        ", "%04x", cmd->rsvd1);
	nvme_show_key_value("nsid         ", "%08x", cmd->nsid);
	nvme_show_key_value("cdw2         ", "%08x", cmd->cdw2);
	nvme_show_key_value("cdw3         ", "%08x", cmd->cdw3);
	nvme_show_key_value("data_len     ", "%08x", cmd->data_len);
	nvme_show_key_value("metadata_len ", "%08x", cmd->metadata_len);
	nvme_show_key_value("addr         ", "%"PRIx64"", (uint64_t)(uintptr_t)cmd->addr);
	nvme_show_key_value("metadata     ", "%"PRIx64"", (uint64_t)(uintptr_t)cmd->metadata);
	nvme_show_key_value("cdw10        ", "%08x", cmd->cdw10);
	nvme_show_key_value("cdw11        ", "%08x", cmd->cdw11);
	nvme_show_key_value("cdw12        ", "%08x", cmd->cdw12);
	nvme_show_key_value("cdw13        ", "%08x", cmd->cdw13);
	nvme_show_key_value("cdw14        ", "%08x", cmd->cdw14);
	nvme_show_key_value("cdw15        ", "%08x", cmd->cdw15);
	nvme_show_key_value("timeout_ms   ", "%08x", cmd->timeout_ms);
}

static void nvme_show_command(struct nvme_passthru_cmd *cmd, int err)
{
	nvme_show_common(cmd);
	nvme_show_key_value("result       ", "%08x", cmd->result);
	nvme_show_key_value("err          ", "%d", err);
}

static void nvme_show_command64(struct nvme_passthru_cmd64 *cmd, int err)
{
	nvme_show_common((struct nvme_passthru_cmd *)cmd);
	nvme_show_key_value("result       ", "%"PRIx64"", (uint64_t)(uintptr_t)cmd->result);
	nvme_show_key_value("err          ", "%d", err);
}

static void nvme_show_latency(struct timeval start, struct timeval end)
{
	nvme_show_key_value("latency      ", "%llu us",
			    (unsigned long long)((end.tv_sec - start.tv_sec) * 1000000 +
						 (end.tv_usec - start.tv_usec)));
}

static void nvme_log_retry(int errnum)
{
	if (log_level < LOG_DEBUG)
		return;

	printf("passthru command returned '%s'\n", strerror(errnum));
}

int nvme_submit_passthru(struct nvme_transport_handle *hdl, unsigned long ioctl_cmd,
			 struct nvme_passthru_cmd *cmd, __u32 *result)
{
	struct timeval start;
	struct timeval end;
	int err = 0;

	if (log_level >= LOG_DEBUG)
		gettimeofday(&start, NULL);

	if (!nvme_cfg.dry_run) {
retry:
		err = ioctl(nvme_transport_handle_get_fd(hdl), ioctl_cmd, cmd);
		if ((err && (errno == EAGAIN ||
			     (errno == EINTR && !nvme_sigint_received))) &&
		    !nvme_cfg.no_retries) {
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

int nvme_submit_passthru64(struct nvme_transport_handle *hdl, unsigned long ioctl_cmd,
			   struct nvme_passthru_cmd64 *cmd,
			   __u64 *result)
{
	struct timeval start;
	struct timeval end;
	int err = 0;

	if (log_level >= LOG_DEBUG)
		gettimeofday(&start, NULL);

	if (!nvme_cfg.dry_run) {
retry:
		err = ioctl(nvme_transport_handle_get_fd(hdl), ioctl_cmd, cmd);
		if ((err && (errno == EAGAIN ||
			     (errno == EINTR && !nvme_sigint_received))) &&
		    !nvme_cfg.no_retries) {
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
	nvme_show_key_value("doff         ", "%08x", le32_to_cpu(hdr->doff));
	nvme_show_key_value("dlen         ", "%08x", le32_to_cpu(hdr->dlen));
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
