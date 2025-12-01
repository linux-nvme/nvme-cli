// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libnvme.
 * Copyright (c) 2020 Western Digital Corporation or its affiliates.
 *
 * Authors: Keith Busch <keith.busch@wdc.com>
 * 	    Chaitanya Kulkarni <chaitanya.kulkarni@wdc.com>
 */
#include <errno.h>
#include <fcntl.h>
#ifdef CONFIG_LIBURING
#include <liburing.h>
#endif
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <inttypes.h>

#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/time.h>

#include <ccan/build_assert/build_assert.h>
#include <ccan/ccan/minmax/minmax.h>
#include <ccan/endian/endian.h>

#include "ioctl.h"
#include "private.h"

static int nvme_verify_chr(struct nvme_transport_handle *hdl)
{
	static struct stat nvme_stat;
	int err = fstat(hdl->fd, &nvme_stat);

	if (err < 0)
		return -errno;

	if (!S_ISCHR(nvme_stat.st_mode))
		return -ENOTBLK;
	return 0;
}

int nvme_subsystem_reset(struct nvme_transport_handle *hdl)
{
	int ret;

	ret = nvme_verify_chr(hdl);
	if (ret)
		return ret;

	ret = ioctl(hdl->fd, NVME_IOCTL_SUBSYS_RESET);
	if (ret < 0)
		return -errno;
	return ret;
}

int nvme_ctrl_reset(struct nvme_transport_handle *hdl)
{
	int ret;

	ret = nvme_verify_chr(hdl);
	if (ret)
		return ret;

	ret = ioctl(hdl->fd, NVME_IOCTL_RESET);
	if (ret < 0)
		return -errno;
	return ret;
}

int nvme_ns_rescan(struct nvme_transport_handle *hdl)
{
	int ret;

	ret = nvme_verify_chr(hdl);
	if (ret)
		return ret;

	ret = ioctl(hdl->fd, NVME_IOCTL_RESCAN);
	if (ret < 0)
		return -errno;
	return ret;
}

int nvme_get_nsid(struct nvme_transport_handle *hdl, __u32 *nsid)
{
	__u32 tmp;

	errno = 0;
	tmp = ioctl(hdl->fd, NVME_IOCTL_ID);
	if (errno)
		return -errno;

	*nsid = tmp;
	return 0;
}

void *__nvme_submit_entry(struct nvme_transport_handle *hdl,
		struct nvme_passthru_cmd *cmd)
{
	return NULL;
}

void __nvme_submit_exit(struct nvme_transport_handle *hdl,
		struct nvme_passthru_cmd *cmd, int err, void *user_data)
{
}

bool __nvme_decide_retry(struct nvme_transport_handle *hdl,
		struct nvme_passthru_cmd *cmd, int err)
{
	return false;
}

/*
 * The 64 bit version is the preferred version to use, but for backwards
 * compatibility keep a 32 version.
 */
static int nvme_submit_passthru32(struct nvme_transport_handle *hdl,
		unsigned long ioctl_cmd, struct nvme_passthru_cmd *cmd)
{
	struct linux_passthru_cmd32 cmd32;
	void *user_data;
	int err = 0;

	user_data = hdl->submit_entry(hdl, cmd);
	if (hdl->ctx->dry_run)
		goto out;

	memcpy(&cmd32, cmd, offsetof(struct linux_passthru_cmd32, result));
	cmd32.result = 0;

	do {
		err = ioctl(hdl->fd, ioctl_cmd, &cmd32);
		if (err >= 0)
			break;
		err = -errno;
	} while (hdl->decide_retry(hdl, cmd, err));

out:
	cmd->result = cmd32.result;
	hdl->submit_exit(hdl, cmd, err, user_data);
	return err;
}

/*
 * supported since kernel 5.4, see
 * 65e68edce0db ("nvme: allow 64-bit results in passthru commands")
 */
static int nvme_submit_passthru64(struct nvme_transport_handle *hdl,
		unsigned long ioctl_cmd, struct nvme_passthru_cmd *cmd)
{
	void *user_data;
	int err = 0;

	user_data = hdl->submit_entry(hdl, cmd);
	if (hdl->ctx->dry_run)
		goto out;

	do {
		/*
		 * struct nvme_passtrhu_cmd is identically to struct
		 * linux_passthru_cmd64, thus just pass it in directly.
		 */
		err = ioctl(hdl->fd, ioctl_cmd, cmd);
		if (err >= 0)
			break;
		err = -errno;
	} while (hdl->decide_retry(hdl, cmd, err));

out:
	hdl->submit_exit(hdl, cmd, err, user_data);
	return err;
}

int nvme_submit_io_passthru(struct nvme_transport_handle *hdl,
		struct nvme_passthru_cmd *cmd)
{
	if (hdl->ioctl64)
		return nvme_submit_passthru64(hdl, NVME_IOCTL_IO64_CMD, cmd);
	return nvme_submit_passthru32(hdl, NVME_IOCTL_IO_CMD, cmd);
}

int nvme_submit_admin_passthru(struct nvme_transport_handle *hdl,
		struct nvme_passthru_cmd *cmd)
{
	switch (hdl->type) {
	case NVME_TRANSPORT_HANDLE_TYPE_DIRECT:
		if (hdl->ioctl64)
			return nvme_submit_passthru64(hdl,
				NVME_IOCTL_ADMIN64_CMD, cmd);
		if (cmd->opcode == nvme_admin_fabrics)
			return -ENOTSUP;
		return nvme_submit_passthru32(hdl,
				NVME_IOCTL_ADMIN_CMD, cmd);
	case NVME_TRANSPORT_HANDLE_TYPE_MI:
		return nvme_mi_admin_admin_passthru(hdl, cmd);
	default:
		break;
	}

	return -ENOTSUP;
}

static bool force_4k;

__attribute__((constructor))
static void nvme_init_env(void)
{
	char *val;

	val = getenv("LIBNVME_FORCE_4K");
	if (!val)
		return;
	if (!strcmp(val, "1") ||
	    !strcasecmp(val, "true") ||
	    !strncasecmp(val, "enable", 6))
		force_4k = true;
}

#ifdef CONFIG_LIBURING
enum {
	IO_URING_NOT_AVAILABLE,
	IO_URING_AVAILABLE,
} io_uring_kernel_support = IO_URING_NOT_AVAILABLE;

/*
 * gcc specific attribute, call automatically on the library loading.
 * if IORING_OP_URING_CMD is not supported, fallback to ioctl interface.
 *
 * The uring API expects the command of type struct nvme_passthru_cmd64.
 */
__attribute__((constructor))
static void nvme_uring_cmd_probe()
{
	struct io_uring_probe *probe = io_uring_get_probe();

	if (!probe)
		return;

	if (!io_uring_opcode_supported(probe, IORING_OP_URING_CMD))
		return;

	io_uring_kernel_support = IO_URING_AVAILABLE;
}

static int nvme_uring_cmd_setup(struct io_uring *ring)
{
	if (io_uring_queue_init(NVME_URING_ENTRIES, ring,
				   IORING_SETUP_SQE128 | IORING_SETUP_CQE32))
		return -errno;
	return 0;
}

static void nvme_uring_cmd_exit(struct io_uring *ring)
{
	io_uring_queue_exit(ring);
}

static int nvme_uring_cmd_admin_passthru_async(struct nvme_transport_handle *hdl,
		struct io_uring *ring, struct nvme_passthru_cmd *cmd)
{
	struct io_uring_sqe *sqe;
	int ret;

	sqe = io_uring_get_sqe(ring);
	if (!sqe)
		return -1;

	memcpy(&sqe->cmd, cmd, sizeof(*cmd));

	sqe->fd = hdl->fd;
	sqe->opcode = IORING_OP_URING_CMD;
	sqe->cmd_op = NVME_URING_CMD_ADMIN;

	ret = io_uring_submit(ring);
	if (ret < 0)
		return -errno;

	return 0;
}

static int nvme_uring_cmd_wait_complete(struct io_uring *ring, int n)
{
	struct io_uring_cqe *cqe;
	int ret, i;

	for (i = 0; i < n; i++) {
		ret = io_uring_wait_cqe(ring, &cqe);
		if (ret < 0)
			return -errno;
		io_uring_cqe_seen(ring, cqe);
	}

	return 0;
}

static bool nvme_uring_is_usable(struct nvme_transport_handle *hdl)
{
	struct stat st;

	if (io_uring_kernel_support != IO_URING_AVAILABLE ||
	    hdl->type != NVME_TRANSPORT_HANDLE_TYPE_DIRECT ||
	    fstat(hdl->fd, &st) || !S_ISCHR(st.st_mode))
		return false;

	return true;
}
#endif /* CONFIG_LIBURING */

int nvme_get_log(struct nvme_transport_handle *hdl,
		struct nvme_passthru_cmd *cmd, bool rae,
		__u32 xfer_len)
{
	__u64 offset = 0, xfer, data_len = cmd->data_len;
	__u64 start = (__u64)cmd->cdw13 << 32 | cmd->cdw12;
	__u64 lpo;
	void *ptr = (void *)(uintptr_t)cmd->addr;
	int ret;
	bool _rae;
	__u32 numd;
	__u16 numdu, numdl;
	__u32 cdw10 = cmd->cdw10 & (NVME_VAL(LOG_CDW10_LID) |
				    NVME_VAL(LOG_CDW10_LSP));
	__u32 cdw11 = cmd->cdw11 & NVME_VAL(LOG_CDW11_LSI);
#ifdef CONFIG_LIBURING
	bool use_uring = nvme_uring_is_usable(hdl);
	struct io_uring ring;
	int n = 0;

	if (use_uring) {
		ret = nvme_uring_cmd_setup(&ring);
		if (ret)
			return ret;
	}
#endif /* CONFIG_LIBURING */

	if (force_4k)
		xfer_len = NVME_LOG_PAGE_PDU_SIZE;

	/*
	 * 4k is the smallest possible transfer unit, so restricting to 4k
	 * avoids having to check the MDTS value of the controller.
	 */
	do {
		if (!force_4k) {
			xfer = data_len - offset;
			if (xfer > xfer_len)
				xfer  = xfer_len;
		} else {
			xfer = NVME_LOG_PAGE_PDU_SIZE;
		}

		/*
		 * Always retain regardless of the RAE parameter until the very
		 * last portion of this log page so the data remains latched
		 * during the fetch sequence.
		 */
		lpo = start + offset;
		numd = (xfer >> 2) - 1;
		numdu = numd >> 16;
		numdl = numd & 0xffff;
		_rae = offset + xfer < data_len || rae;

		cmd->cdw10 = cdw10 |
			NVME_SET(!!_rae, LOG_CDW10_RAE) |
			NVME_SET(numdl, LOG_CDW10_NUMDL);
		cmd->cdw11 = cdw11 |
			NVME_SET(numdu, LOG_CDW11_NUMDU);
		cmd->cdw12 = lpo & 0xffffffff;
		cmd->cdw13 = lpo >> 32;
		cmd->data_len = xfer;
		cmd->addr = (__u64)(uintptr_t)ptr;

#ifdef CONFIG_LIBURING
		if (use_uring) {
			if (n >= NVME_URING_ENTRIES) {
				ret = nvme_uring_cmd_wait_complete(&ring, n);
				if (ret)
					goto uring_exit;
				n = 0;
			}
			n += 1;
			ret = nvme_uring_cmd_admin_passthru_async(hdl,
				&ring, cmd);
			if (ret)
				goto uring_exit;
		} else {
			ret = nvme_submit_admin_passthru(hdl, cmd);
			if (ret)
				return ret;
		}
#else /* CONFIG_LIBURING */
		ret = nvme_submit_admin_passthru(hdl, cmd);
#endif /* CONFIG_LIBURING */
		if (ret)
			return ret;

		offset += xfer;
		ptr += xfer;
	} while (offset < data_len);

#ifdef CONFIG_LIBURING
	if (use_uring) {
		ret = nvme_uring_cmd_wait_complete(&ring, n);
uring_exit:
		nvme_uring_cmd_exit(&ring);
		if (ret)
			return ret;
	}
#endif /* CONFIG_LIBURING */

	return 0;
}

static int read_ana_chunk(struct nvme_transport_handle *hdl, enum nvme_log_ana_lsp lsp, bool rae,
			  __u8 *log, __u8 **read, __u8 *to_read, __u8 *log_end)
{
	struct nvme_passthru_cmd cmd;

	if (to_read > log_end)
		return -ENOSPC;

	while (*read < to_read) {
		__u32 len = min_t(__u32, log_end - *read, NVME_LOG_PAGE_PDU_SIZE);
		int ret;

		nvme_init_get_log_ana(&cmd, lsp, *read - log, *read, len);
		ret = nvme_get_log(hdl, &cmd, rae, NVME_LOG_PAGE_PDU_SIZE);
		if (ret)
			return ret;

		*read += len;
	}
	return 0;
}

static int try_read_ana(struct nvme_transport_handle *hdl, enum nvme_log_ana_lsp lsp, bool rae,
			struct nvme_ana_log *log, __u8 *log_end,
			__u8 *read, __u8 **to_read, bool *may_retry)
{
	__u16 ngrps = le16_to_cpu(log->ngrps);

	while (ngrps--) {
		__u8 *group = *to_read;
		int ret;
		__le32 nnsids;

		*to_read += sizeof(*log->descs);
		ret = read_ana_chunk(hdl, lsp, rae,
				     (__u8 *)log, &read, *to_read, log_end);
		if (ret) {
			/*
			 * If the provided buffer isn't long enough,
			 * the log page may have changed while reading it
			 * and the computed length was inaccurate.
			 * Have the caller check chgcnt and retry.
			 */
			*may_retry = ret == -ENOSPC;
			return ret;
		}

		/*
		 * struct nvme_ana_group_desc has 8-byte alignment
		 * but the group pointer is only 4-byte aligned.
		 * Don't dereference the misaligned pointer.
		 */
		memcpy(&nnsids,
		       group + offsetof(struct nvme_ana_group_desc, nnsids),
		       sizeof(nnsids));
		*to_read += le32_to_cpu(nnsids) * sizeof(__le32);
		ret = read_ana_chunk(hdl, lsp, rae,
				     (__u8 *)log, &read, *to_read, log_end);
		if (ret) {
			*may_retry = ret == -ENOSPC;
			return ret;
		}
	}

	*may_retry = true;
	return 0;
}

int nvme_get_ana_log_atomic(struct nvme_transport_handle *hdl, bool rae, bool rgo,
			    struct nvme_ana_log *log, __u32 *len,
			    unsigned int retries)
{
	const enum nvme_log_ana_lsp lsp =
		rgo ? NVME_LOG_ANA_LSP_RGO_GROUPS_ONLY : 0;
	/* Get Log Page can only fetch multiples of dwords */
	__u8 * const log_end = (__u8 *)log + (*len & -4);
	__u8 *read = (__u8 *)log;
	__u8 *to_read;
	int ret;

	if (!retries)
		return -EINVAL;

	to_read = (__u8 *)log->descs;
	ret = read_ana_chunk(hdl, lsp, rae,
			     (__u8 *)log, &read, to_read, log_end);
	if (ret)
		return ret;

	do {
		bool may_retry = false;
		int saved_ret;
		int saved_errno;
		__le64 chgcnt;

		saved_ret = try_read_ana(hdl, lsp, rae, log, log_end,
					 read, &to_read, &may_retry);
		/*
		 * If the log page was read with multiple Get Log Page commands,
		 * chgcnt must be checked afterwards to ensure atomicity
		 */
		*len = to_read - (__u8 *)log;
		if (*len <= NVME_LOG_PAGE_PDU_SIZE || !may_retry)
			return saved_ret;

		saved_errno = errno;
		chgcnt = log->chgcnt;
		read = (__u8 *)log;
		to_read = (__u8 *)log->descs;
		ret = read_ana_chunk(hdl, lsp, rae,
				     (__u8 *)log, &read, to_read, log_end);
		if (ret)
			return ret;

		if (log->chgcnt == chgcnt) {
			/* Log hasn't changed; return try_read_ana() result */
			errno = saved_errno;
			return saved_ret;
		}
	} while (--retries);

	return -EAGAIN;
}
