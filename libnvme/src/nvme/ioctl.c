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
#include "util.h"
#include "log.h"
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

__attribute__((weak))
int nvme_submit_passthru64(struct nvme_transport_handle *hdl, unsigned long ioctl_cmd,
			   struct nvme_passthru_cmd64 *cmd,
			   __u64 *result)
{
	int err = ioctl(hdl->fd, ioctl_cmd, cmd);

	if (err >= 0 && result)
		*result = cmd->result;
	if (err < 0)
		return -errno;
	return err;
}

__attribute__((weak))
int nvme_submit_passthru(struct nvme_transport_handle *hdl, unsigned long ioctl_cmd,
			 struct nvme_passthru_cmd *cmd, __u32 *result)
{
	int err = ioctl(hdl->fd, ioctl_cmd, cmd);

	if (err >= 0 && result)
		*result = cmd->result;
	if (err < 0)
		return -errno;
	return err;
}

static int nvme_passthru64(struct nvme_transport_handle *hdl, unsigned long ioctl_cmd, __u8 opcode,
			   __u8 flags, __u16 rsvd, __u32 nsid, __u32 cdw2,
			   __u32 cdw3, __u32 cdw10, __u32 cdw11, __u32 cdw12,
			   __u32 cdw13, __u32 cdw14, __u32 cdw15,
			   __u32 data_len, void *data, __u32 metadata_len,
			   void *metadata, __u32 timeout_ms, __u64 *result)
{
	struct nvme_passthru_cmd64 cmd = {
		.opcode		= opcode,
		.flags		= flags,
		.rsvd1		= rsvd,
		.nsid		= nsid,
		.cdw2		= cdw2,
		.cdw3		= cdw3,
		.metadata	= (__u64)(uintptr_t)metadata,
		.addr		= (__u64)(uintptr_t)data,
		.metadata_len	= metadata_len,
		.data_len	= data_len,
		.cdw10		= cdw10,
		.cdw11		= cdw11,
		.cdw12		= cdw12,
		.cdw13		= cdw13,
		.cdw14		= cdw14,
		.cdw15		= cdw15,
		.timeout_ms	= timeout_ms,
	};

	return nvme_submit_passthru64(hdl, ioctl_cmd, &cmd, result);
}

static int nvme_passthru(struct nvme_transport_handle *hdl, unsigned long ioctl_cmd, __u8 opcode,
			 __u8 flags, __u16 rsvd, __u32 nsid, __u32 cdw2,
			 __u32 cdw3, __u32 cdw10, __u32 cdw11, __u32 cdw12,
			 __u32 cdw13, __u32 cdw14, __u32 cdw15, __u32 data_len,
			 void *data, __u32 metadata_len, void *metadata,
			 __u32 timeout_ms, __u32 *result)
{
	struct nvme_passthru_cmd cmd = {
		.opcode		= opcode,
		.flags		= flags,
		.rsvd1		= rsvd,
		.nsid		= nsid,
		.cdw2		= cdw2,
		.cdw3		= cdw3,
		.metadata	= (__u64)(uintptr_t)metadata,
		.addr		= (__u64)(uintptr_t)data,
		.metadata_len	= metadata_len,
		.data_len	= data_len,
		.cdw10		= cdw10,
		.cdw11		= cdw11,
		.cdw12		= cdw12,
		.cdw13		= cdw13,
		.cdw14		= cdw14,
		.cdw15		= cdw15,
		.timeout_ms	= timeout_ms,
	};

	return nvme_submit_passthru(hdl, ioctl_cmd, &cmd, result);
}

int nvme_submit_admin_passthru64(struct nvme_transport_handle *hdl, struct nvme_passthru_cmd64 *cmd,
				 __u64 *result)
{
	return nvme_submit_passthru64(hdl, NVME_IOCTL_ADMIN64_CMD, cmd, result);
}

int nvme_admin_passthru64(struct nvme_transport_handle *hdl, __u8 opcode, __u8 flags, __u16 rsvd,
			 __u32 nsid, __u32 cdw2, __u32 cdw3, __u32 cdw10,
			 __u32 cdw11, __u32 cdw12, __u32 cdw13, __u32 cdw14,
			 __u32 cdw15, __u32 data_len, void *data,
			 __u32 metadata_len, void *metadata, __u32 timeout_ms,
			 __u64 *result)
{
	return nvme_passthru64(hdl, NVME_IOCTL_ADMIN64_CMD, opcode, flags, rsvd,
			       nsid, cdw2, cdw3, cdw10, cdw11, cdw12, cdw13,
			       cdw14, cdw15, data_len, data, metadata_len,
			       metadata, timeout_ms, result);
}

int nvme_submit_admin_passthru(struct nvme_transport_handle *hdl, struct nvme_passthru_cmd *cmd, __u32 *result)
{
	switch (hdl->type) {
	case NVME_TRANSPORT_HANDLE_TYPE_DIRECT:
		return nvme_submit_passthru(hdl, NVME_IOCTL_ADMIN_CMD, cmd, result);
	case NVME_TRANSPORT_HANDLE_TYPE_MI:
		return nvme_mi_admin_admin_passthru(
			hdl, cmd->opcode, cmd->flags, cmd->rsvd1,
			cmd->nsid, cmd->cdw2, cmd->cdw3, cmd->cdw10,
			cmd->cdw11, cmd->cdw12, cmd->cdw13,
			cmd->cdw14, cmd->cdw15,
			cmd->data_len, (void *)(uintptr_t)cmd->addr,
			cmd->metadata_len, (void *)(uintptr_t)cmd->metadata,
			cmd->timeout_ms, result);
	default:
		break;
	}

	return -ENOTSUP;
}

int nvme_admin_passthru(struct nvme_transport_handle *hdl, __u8 opcode, __u8 flags, __u16 rsvd,
			__u32 nsid, __u32 cdw2, __u32 cdw3, __u32 cdw10,
			__u32 cdw11, __u32 cdw12, __u32 cdw13, __u32 cdw14,
			__u32 cdw15, __u32 data_len, void *data,
			__u32 metadata_len, void *metadata, __u32 timeout_ms,
			__u32 *result)
{
	return nvme_passthru(hdl, NVME_IOCTL_ADMIN_CMD, opcode, flags, rsvd,
			     nsid, cdw2, cdw3, cdw10, cdw11, cdw12, cdw13,
			     cdw14, cdw15, data_len, data, metadata_len,
			     metadata, timeout_ms, result);
}

enum features {
	NVME_FEATURES_ARBITRATION_BURST_SHIFT			= 0,
	NVME_FEATURES_ARBITRATION_LPW_SHIFT			= 8,
	NVME_FEATURES_ARBITRATION_MPW_SHIFT			= 16,
	NVME_FEATURES_ARBITRATION_HPW_SHIFT			= 24,
	NVME_FEATURES_ARBITRATION_BURST_MASK			= 0x7,
	NVME_FEATURES_ARBITRATION_LPW_MASK			= 0xff,
	NVME_FEATURES_ARBITRATION_MPW_MASK			= 0xff,
	NVME_FEATURES_ARBITRATION_HPW_MASK			= 0xff,
	NVME_FEATURES_PWRMGMT_PS_SHIFT				= 0,
	NVME_FEATURES_PWRMGMT_WH_SHIFT				= 5,
	NVME_FEATURES_PWRMGMT_PS_MASK				= 0x1f,
	NVME_FEATURES_PWRMGMT_WH_MASK				= 0x7,
	NVME_FEATURES_TMPTH_SHIFT				= 0,
	NVME_FEATURES_TMPSEL_SHIFT				= 16,
	NVME_FEATURES_THSEL_SHIFT				= 20,
	NVME_FEATURES_TMPTH_MASK				= 0xff,
	NVME_FEATURES_TMPSEL_MASK				= 0xf,
	NVME_FEATURES_THSEL_MASK				= 0x3,
	NVME_FEATURES_ERROR_RECOVERY_TLER_SHIFT			= 0,
	NVME_FEATURES_ERROR_RECOVERY_DULBE_SHIFT		= 16,
	NVME_FEATURES_ERROR_RECOVERY_TLER_MASK			= 0xff,
	NVME_FEATURES_ERROR_RECOVERY_DULBE_MASK			= 0x1,
	NVME_FEATURES_VWC_WCE_SHIFT				= 0,
	NVME_FEATURES_VWC_WCE_MASK				= 0x1,
	NVME_FEATURES_IRQC_THR_SHIFT				= 0,
	NVME_FEATURES_IRQC_TIME_SHIFT				= 8,
	NVME_FEATURES_IRQC_THR_MASK				= 0xff,
	NVME_FEATURES_IRQC_TIME_MASK				= 0xff,
	NVME_FEATURES_IVC_IV_SHIFT				= 0,
	NVME_FEATURES_IVC_CD_SHIFT				= 16,
	NVME_FEATURES_IVC_IV_MASK				= 0xffff,
	NVME_FEATURES_IVC_CD_MASK				= 0x1,
	NVME_FEATURES_WAN_DN_SHIFT				= 0,
	NVME_FEATURES_WAN_DN_MASK				= 0x1,
	NVME_FEATURES_APST_APSTE_SHIFT				= 0,
	NVME_FEATURES_APST_APSTE_MASK				= 0x1,
	NVME_FEATURES_HCTM_TMT2_SHIFT				= 0,
	NVME_FEATURES_HCTM_TMT1_SHIFT				= 16,
	NVME_FEATURES_HCTM_TMT2_MASK				= 0xffff,
	NVME_FEATURES_HCTM_TMT1_MASK				= 0xffff,
	NVME_FEATURES_NOPS_NOPPME_SHIFT				= 0,
	NVME_FEATURES_NOPS_NOPPME_MASK				= 0x1,
	NVME_FEATURES_PLM_PLE_SHIFT				= 0,
	NVME_FEATURES_PLM_PLE_MASK				= 0x1,
	NVME_FEATURES_PLM_WINDOW_SELECT_SHIFT			= 0,
	NVME_FEATURES_PLM_WINDOW_SELECT_MASK			= 0xf,
	NVME_FEATURES_LBAS_LSIRI_SHIFT				= 0,
	NVME_FEATURES_LBAS_LSIPI_SHIFT				= 16,
	NVME_FEATURES_LBAS_LSIRI_MASK				= 0xffff,
	NVME_FEATURES_LBAS_LSIPI_MASK				= 0xffff,
	NVME_FEATURES_IOCSP_IOCSCI_SHIFT			= 0,
	NVME_FEATURES_IOCSP_IOCSCI_MASK				= 0xff,
};

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
		struct io_uring *ring, struct nvme_passthru_cmd *cmd, __u32 *result)
{
	struct io_uring_sqe *sqe;
	int ret;

	sqe = io_uring_get_sqe(ring);
	if (!sqe)
		return -1;

	memcpy(&sqe->cmd, cmd, sizeof(*cmd));

	sqe->fd = l->fd;
	sqe->opcode = IORING_OP_URING_CMD;
	sqe->cmd_op = NVME_URING_CMD_ADMIN;
	sqe->user_data = (__u64)(uintptr_t)result;

	ret = io_uring_submit(ring);
	if (ret < 0)
		return -errno;

	return 0;
}

static int nvme_uring_cmd_wait_complete(struct io_uring *ring, int n)
{
	struct io_uring_cqe *cqe;
	int i, ret = 0;
	__u32 *result;

	for (i = 0; i < n; i++) {
		ret = io_uring_wait_cqe(ring, &cqe);
		if (ret)
			return -1;

		if (cqe->res) {
			result = (__u32 *)cqe->user_data;
			if (result)
				*result = cqe->res;
			ret = cqe->res;
			break;
		}

		io_uring_cqe_seen(ring, cqe);
	}

	return ret;
}
#endif

int nvme_get_log(struct nvme_transport_handle *hdl,
		struct nvme_passthru_cmd *cmd, bool rae,
		__u32 xfer_len, __u32 *result)
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

	if (force_4k)
		xfer_len = NVME_LOG_PAGE_PDU_SIZE;

#ifdef CONFIG_LIBURING
	int n = 0;
	struct io_uring ring;
	struct stat st;
	bool use_uring = false;

	if (io_uring_kernel_support == IO_URING_AVAILABLE && l->type == NVME_LINK_TYPE_DIRECT) {
		if (fstat(l->fd, &st) == 0 && S_ISCHR(st.st_mode)) {
			use_uring = true;

			ret = nvme_uring_cmd_setup(&ring);
			if (ret)
				return ret;
		}
	}
#endif
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
		if (io_uring_kernel_support == IO_URING_AVAILABLE && use_uring) {
			if (n >= NVME_URING_ENTRIES) {
				ret = nvme_uring_cmd_wait_complete(&ring, n);
				n = 0;
			}
			n += 1;
			ret = nvme_uring_cmd_admin_passthru_async(hdl, &ring, cmd, result);

			if (ret)
				nvme_uring_cmd_exit(&ring);
		} else
#endif
		ret = nvme_submit_admin_passthru(hdl, cmd, result);
		if (ret)
			return ret;

		offset += xfer;
		ptr += xfer;
	} while (offset < data_len);

#ifdef CONFIG_LIBURING
	if (io_uring_kernel_support == IO_URING_AVAILABLE && use_uring) {
		ret = nvme_uring_cmd_wait_complete(&ring, n);
		nvme_uring_cmd_exit(&ring);
		if (ret)
			return ret;
	}
#endif
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
		ret = nvme_get_log(hdl, &cmd, rae, NVME_LOG_PAGE_PDU_SIZE, NULL);
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

int nvme_ns_mgmt(struct nvme_transport_handle *hdl, struct nvme_ns_mgmt_args *args)
{
	__u32 cdw10    = NVME_SET(args->sel, NAMESPACE_MGMT_CDW10_SEL);
	__u32 cdw11    = NVME_SET(args->csi, NAMESPACE_MGMT_CDW11_CSI);

	struct nvme_passthru_cmd cmd = {
		.nsid	    = args->nsid,
		.opcode	    = nvme_admin_ns_mgmt,
		.cdw10	    = cdw10,
		.cdw11	    = cdw11,
		.timeout_ms = args->timeout,
	};

	if (args->data) {
                cmd.data_len = sizeof(*args->data);
                cmd.addr = (__u64)(uintptr_t)args->data;
	}
	return nvme_submit_admin_passthru(hdl, &cmd, args->result);
}

int nvme_ns_attach(struct nvme_transport_handle *hdl, struct nvme_ns_attach_args *args)
{
	__u32 cdw10 = NVME_SET(args->sel, NAMESPACE_ATTACH_CDW10_SEL);

	struct nvme_passthru_cmd cmd = {
		.opcode		= nvme_admin_ns_attach,
		.nsid		= args->nsid,
		.cdw10		= cdw10,
		.data_len	= sizeof(*args->ctrlist),
		.addr		= (__u64)(uintptr_t)args->ctrlist,
		.timeout_ms	= args->timeout,
	};

	if (args->args_size < sizeof(*args))
		return -EINVAL;

	return nvme_submit_admin_passthru(hdl, &cmd, args->result);
}

int nvme_fw_download(struct nvme_transport_handle *hdl, struct nvme_fw_download_args *args)
{
	__u32 cdw10 = (args->data_len >> 2) - 1;
	__u32 cdw11 = args->offset >> 2;

	struct nvme_passthru_cmd cmd = {
		.opcode		= nvme_admin_fw_download,
		.cdw10		= cdw10,
		.cdw11		= cdw11,
		.data_len	= args->data_len,
		.addr		= (__u64)(uintptr_t)args->data,
		.timeout_ms	= args->timeout,
	};

	if (args->args_size < sizeof(*args))
		return -EINVAL;

	if ((args->data_len & 0x3) || (!args->data_len))
		return -EINVAL;

	if (args->offset & 0x3)
		return -EINVAL;

	return nvme_submit_admin_passthru(hdl, &cmd, args->result);
}

int nvme_fw_commit(struct nvme_transport_handle *hdl, struct nvme_fw_commit_args *args)
{
	__u32 cdw10 = NVME_SET(args->slot, FW_COMMIT_CDW10_FS) |
			NVME_SET(args->action, FW_COMMIT_CDW10_CA) |
			NVME_SET(args->bpid, FW_COMMIT_CDW10_BPID);

	struct nvme_passthru_cmd cmd = {
		.opcode		= nvme_admin_fw_commit,
		.cdw10		= cdw10,
		.timeout_ms	= args->timeout,
	};

	if (args->args_size < sizeof(*args))
		return -EINVAL;

	return nvme_submit_admin_passthru(hdl, &cmd, args->result);
}

int nvme_security_send(struct nvme_transport_handle *hdl, struct nvme_security_send_args *args)
{
	__u32 cdw10 = NVME_SET(args->secp, SECURITY_SECP) |
			NVME_SET(args->spsp0, SECURITY_SPSP0)  |
			NVME_SET(args->spsp1, SECURITY_SPSP1) |
			NVME_SET(args->nssf, SECURITY_NSSF);
	__u32 cdw11 = args->tl;

	struct nvme_passthru_cmd cmd = {
		.opcode		= nvme_admin_security_send,
		.nsid		= args->nsid,
		.cdw10		= cdw10,
		.cdw11		= cdw11,
		.data_len	= args->data_len,
		.addr		= (__u64)(uintptr_t)args->data,
		.timeout_ms	= args->timeout,
	};

	if (args->args_size < sizeof(*args))
		return -EINVAL;

	return nvme_submit_admin_passthru(hdl, &cmd, args->result);
}

int nvme_security_receive(struct nvme_transport_handle *hdl, struct nvme_security_receive_args *args)
{
	__u32 cdw10 = NVME_SET(args->secp, SECURITY_SECP) |
			NVME_SET(args->spsp0, SECURITY_SPSP0)  |
			NVME_SET(args->spsp1, SECURITY_SPSP1) |
			NVME_SET(args->nssf, SECURITY_NSSF);
	__u32 cdw11 = args->al;

	struct nvme_passthru_cmd cmd = {
		.opcode		= nvme_admin_security_recv,
		.nsid		= args->nsid,
		.cdw10		= cdw10,
		.cdw11		= cdw11,
		.data_len	= args->data_len,
		.addr		= (__u64)(uintptr_t)args->data,
		.timeout_ms	= args->timeout,
	};

	if (args->args_size < sizeof(*args))
		return -EINVAL;

	return nvme_submit_admin_passthru(hdl, &cmd, args->result);
}

int nvme_get_lba_status(struct nvme_transport_handle *hdl, struct nvme_get_lba_status_args *args)
{
	__u32 cdw10 = args->slba & 0xffffffff;
	__u32 cdw11 = args->slba >> 32;
	__u32 cdw12 = args->mndw;
	__u32 cdw13 = NVME_SET(args->rl, GET_LBA_STATUS_CDW13_RL) |
			NVME_SET(args->atype, GET_LBA_STATUS_CDW13_ATYPE);

	struct nvme_passthru_cmd cmd = {
		.opcode =  nvme_admin_get_lba_status,
		.nsid = args->nsid,
		.addr = (__u64)(uintptr_t)args->lbas,
		.data_len = (args->mndw + 1) << 2,
		.cdw10 = cdw10,
		.cdw11 = cdw11,
		.cdw12 = cdw12,
		.cdw13 = cdw13,
		.timeout_ms = args->timeout,
	};

	if (args->args_size < sizeof(*args))
		return -EINVAL;

	return nvme_submit_admin_passthru(hdl, &cmd, args->result);
}

int nvme_directive_send(struct nvme_transport_handle *hdl, struct nvme_directive_send_args *args)
{
	__u32 cdw10 = args->data_len ? (args->data_len >> 2) - 1 : 0;
	__u32 cdw11 = NVME_SET(args->doper, DIRECTIVE_CDW11_DOPER) |
			NVME_SET(args->dtype, DIRECTIVE_CDW11_DTYPE) |
			NVME_SET(args->dspec, DIRECTIVE_CDW11_DPSEC);

        struct nvme_passthru_cmd cmd = {
                .opcode         = nvme_admin_directive_send,
                .nsid           = args->nsid,
                .cdw10          = cdw10,
                .cdw11          = cdw11,
                .cdw12          = args->cdw12,
                .data_len       = args->data_len,
                .addr           = (__u64)(uintptr_t)args->data,
		.timeout_ms	= args->timeout,
        };

	if (args->args_size < sizeof(*args))
		return -EINVAL;

	return nvme_submit_admin_passthru(hdl, &cmd, args->result);
}

int nvme_directive_send_id_endir(struct nvme_transport_handle *hdl, __u32 nsid, bool endir,
				 enum nvme_directive_dtype dtype,
				 struct nvme_id_directives *id)
{
	__u32 cdw12 = NVME_SET(dtype, DIRECTIVE_SEND_IDENTIFY_CDW12_DTYPE) |
		NVME_SET(endir, DIRECTIVE_SEND_IDENTIFY_CDW12_ENDIR);
	struct nvme_directive_send_args args = {
		.args_size = sizeof(args),
		.nsid = nsid,
		.dspec = 0,
		.dtype = NVME_DIRECTIVE_DTYPE_IDENTIFY,
		.doper = NVME_DIRECTIVE_SEND_IDENTIFY_DOPER_ENDIR,
		.cdw12 = cdw12,
		.data_len = sizeof(*id),
		.data = id,
		.timeout = NVME_DEFAULT_IOCTL_TIMEOUT,
		.result = NULL,
	};

	return nvme_directive_send(hdl, &args);
}

int nvme_directive_recv(struct nvme_transport_handle *hdl, struct nvme_directive_recv_args *args)
{
	__u32 cdw10 = args->data_len ? (args->data_len >> 2) - 1 : 0;
	__u32 cdw11 = NVME_SET(args->doper, DIRECTIVE_CDW11_DOPER) |
			NVME_SET(args->dtype, DIRECTIVE_CDW11_DTYPE) |
			NVME_SET(args->dspec, DIRECTIVE_CDW11_DPSEC);

        struct nvme_passthru_cmd cmd = {
                .opcode         = nvme_admin_directive_recv,
                .nsid           = args->nsid,
                .cdw10          = cdw10,
                .cdw11          = cdw11,
                .cdw12          = args->cdw12,
                .data_len       = args->data_len,
                .addr           = (__u64)(uintptr_t)args->data,
		.timeout_ms	= args->timeout,
        };

	if (args->args_size < sizeof(*args))
		return -EINVAL;

	return nvme_submit_admin_passthru(hdl, &cmd, args->result);
}

int nvme_capacity_mgmt(struct nvme_transport_handle *hdl, struct nvme_capacity_mgmt_args *args)
{
	__u32 cdw10 = args->op | args->element_id << 16;

        struct nvme_passthru_cmd cmd = {
		.opcode		= nvme_admin_capacity_mgmt,
		.cdw10		= cdw10,
		.cdw11		= args->cdw11,
		.cdw12		= args->cdw12,
		.timeout_ms	= args->timeout,
	};

	if (args->args_size < sizeof(*args))
		return -EINVAL;

	return nvme_submit_admin_passthru(hdl, &cmd, args->result);
}

int nvme_lockdown(struct nvme_transport_handle *hdl, struct nvme_lockdown_args *args)
{
	__u32 cdw10 =  args->ofi << 8 |
		(args->ifc & 0x3) << 5 |
		(args->prhbt & 0x1) << 4 |
		(args->scp & 0xF);

	struct nvme_passthru_cmd cmd = {
		.opcode         = nvme_admin_lockdown,
		.cdw10          = cdw10,
		.cdw14          = args->uuidx & 0x3F,
		.timeout_ms	= args->timeout,
	};

	if (args->args_size < sizeof(*args))
		return -EINVAL;

	return nvme_submit_admin_passthru(hdl, &cmd, args->result);
}

int nvme_set_property(struct nvme_transport_handle *hdl, struct nvme_set_property_args *args)
{
	__u32 cdw10 = nvme_is_64bit_reg(args->offset);

	struct nvme_passthru_cmd cmd = {
		.opcode		= nvme_admin_fabrics,
		.nsid		= nvme_fabrics_type_property_set,
		.cdw10		= cdw10,
		.cdw11		= args->offset,
		.cdw12		= args->value & 0xffffffff,
		.cdw13		= args->value >> 32,
		.timeout_ms	= args->timeout,
	};

	if (args->args_size < sizeof(*args))
		return -EINVAL;

	return nvme_submit_admin_passthru(hdl, &cmd, args->result);
}

int nvme_get_property(struct nvme_transport_handle *hdl, struct nvme_get_property_args *args)
{
	__u32 cdw10 = nvme_is_64bit_reg(args->offset);

	struct nvme_passthru_cmd64 cmd = {
		.opcode		= nvme_admin_fabrics,
		.nsid		= nvme_fabrics_type_property_get,
		.cdw10		= cdw10,
		.cdw11		= args->offset,
		.timeout_ms	= args->timeout,
	};

	if (args->args_size < sizeof(*args))
		return -EINVAL;

	return nvme_submit_admin_passthru64(hdl, &cmd, args->value);
}

int nvme_sanitize_nvm(struct nvme_transport_handle *hdl, struct nvme_sanitize_nvm_args *args)
{
	__u32 cdw10, cdw11;
	cdw10 = NVME_SET(args->sanact, SANITIZE_CDW10_SANACT) |
		NVME_SET(!!args->ause, SANITIZE_CDW10_AUSE) |
		NVME_SET(args->owpass, SANITIZE_CDW10_OWPASS) |
		NVME_SET(!!args->oipbp, SANITIZE_CDW10_OIPBP) |
		NVME_SET(!!args->nodas, SANITIZE_CDW10_NODAS) |
		NVME_SET(!!args->emvs, SANITIZE_CDW10_EMVS);

	cdw11 = args->ovrpat;

	struct nvme_passthru_cmd cmd = {
		.opcode		= nvme_admin_sanitize_nvm,
		.cdw10		= cdw10,
		.cdw11		= cdw11,
		.timeout_ms	= args->timeout,
	};

	return nvme_submit_admin_passthru(hdl, &cmd, args->result);
}

int nvme_dev_self_test(struct nvme_transport_handle *hdl, struct nvme_dev_self_test_args *args)
{
	__u32 cdw10 = NVME_SET(args->stc, DEVICE_SELF_TEST_CDW10_STC);

	struct nvme_passthru_cmd cmd = {
		.opcode		= nvme_admin_dev_self_test,
		.nsid		= args->nsid,
		.cdw10		= cdw10,
		.timeout_ms	= args->timeout,
	};

	if (args->args_size < sizeof(*args))
		return -EINVAL;

	return nvme_submit_admin_passthru(hdl, &cmd, args->result);
}

int nvme_virtual_mgmt(struct nvme_transport_handle *hdl, struct nvme_virtual_mgmt_args *args)
{
	__u32 cdw10 = NVME_SET(args->act, VIRT_MGMT_CDW10_ACT) |
			NVME_SET(args->rt, VIRT_MGMT_CDW10_RT) |
			NVME_SET(args->cntlid, VIRT_MGMT_CDW10_CNTLID);
	__u32 cdw11 = NVME_SET(args->nr, VIRT_MGMT_CDW11_NR);

	struct nvme_passthru_cmd cmd = {
		.opcode		= nvme_admin_virtual_mgmt,
		.cdw10		= cdw10,
		.cdw11		= cdw11,
		.timeout_ms	= args->timeout,
	};

	if (args->args_size < sizeof(*args))
		return -EINVAL;

	return nvme_submit_admin_passthru(hdl, &cmd, args->result);
}

int nvme_submit_io_passthru64(struct nvme_transport_handle *hdl, struct nvme_passthru_cmd64 *cmd,
			      __u64 *result)
{
	return nvme_submit_passthru64(hdl, NVME_IOCTL_IO64_CMD, cmd, result);
}

int nvme_io_passthru64(struct nvme_transport_handle *hdl, __u8 opcode, __u8 flags, __u16 rsvd,
		       __u32 nsid, __u32 cdw2, __u32 cdw3, __u32 cdw10,
		       __u32 cdw11, __u32 cdw12, __u32 cdw13, __u32 cdw14,
		       __u32 cdw15, __u32 data_len, void *data, __u32 metadata_len,
		       void *metadata, __u32 timeout_ms, __u64 *result)
{
	return nvme_passthru64(hdl, NVME_IOCTL_IO64_CMD, opcode, flags, rsvd,
			       nsid, cdw2, cdw3, cdw10, cdw11, cdw12, cdw13,
			       cdw14, cdw15, data_len, data, metadata_len, metadata,
			       timeout_ms, result);
}

int nvme_submit_io_passthru(struct nvme_transport_handle *hdl, struct nvme_passthru_cmd *cmd, __u32 *result)
{
	return nvme_submit_passthru(hdl, NVME_IOCTL_IO_CMD, cmd, result);
}

int nvme_io_passthru(struct nvme_transport_handle *hdl, __u8 opcode, __u8 flags, __u16 rsvd,
		     __u32 nsid, __u32 cdw2, __u32 cdw3, __u32 cdw10,
		     __u32 cdw11, __u32 cdw12, __u32 cdw13, __u32 cdw14,
		     __u32 cdw15, __u32 data_len, void *data, __u32 metadata_len,
		     void *metadata, __u32 timeout_ms, __u32 *result)
{
	return nvme_passthru(hdl, NVME_IOCTL_IO_CMD, opcode, flags, rsvd, nsid,
			     cdw2, cdw3, cdw10, cdw11, cdw12, cdw13, cdw14,
			     cdw15, data_len, data, metadata_len, metadata,
			     timeout_ms, result);
}

static int nvme_set_var_size_tags(__u32 *cmd_dw2, __u32 *cmd_dw3, __u32 *cmd_dw14,
		__u8 pif, __u8 sts, __u64 reftag, __u64 storage_tag)
{
	__u32 cdw2 = 0, cdw3 = 0, cdw14;

	switch (pif) {
	case NVME_NVM_PIF_16B_GUARD:
		cdw14 = reftag & 0xffffffff;
		cdw14 |= ((storage_tag << (32 - sts)) & 0xffffffff);
		break;
	case NVME_NVM_PIF_32B_GUARD:
		cdw14 = reftag & 0xffffffff;
		cdw3 = reftag >> 32;
		cdw14 |= ((storage_tag << (80 - sts)) & 0xffff0000);
		if (sts >= 48)
			cdw3 |= ((storage_tag >> (sts - 48)) & 0xffffffff);
		else
			cdw3 |= ((storage_tag << (48 - sts)) & 0xffffffff);
		cdw2 = (storage_tag >> (sts - 16)) & 0xffff;
		break;
	case NVME_NVM_PIF_64B_GUARD:
		cdw14 = reftag & 0xffffffff;
		cdw3 = (reftag >> 32) & 0xffff;
		cdw14 |= ((storage_tag << (48 - sts)) & 0xffffffff);
		if (sts >= 16)
			cdw3 |= ((storage_tag >> (sts - 16)) & 0xffff);
		else
			cdw3 |= ((storage_tag << (16 - sts)) & 0xffff);
		break;
	default:
		perror("Unsupported Protection Information Format");
		return -EINVAL;
	}

	*cmd_dw2 = cdw2;
	*cmd_dw3 = cdw3;
	*cmd_dw14 = cdw14;
	return 0;
}

int nvme_io(struct nvme_transport_handle *hdl, struct nvme_io_args *args, __u8 opcode)
{
	__u32 cdw2, cdw3, cdw10, cdw11, cdw12, cdw13, cdw14, cdw15;

	cdw10 = args->slba & 0xffffffff;
	cdw11 = args->slba >> 32;
	cdw12 = args->nlb | (args->control << 16);
	cdw13 = args->dsm | (args->dspec << 16);
	cdw15 = args->apptag | (args->appmask << 16);

	if (nvme_set_var_size_tags(&cdw2, &cdw3, &cdw14,
				args->pif,
				args->sts,
				args->reftag_u64,
				args->storage_tag))
		return -EINVAL;

	struct nvme_passthru_cmd cmd = {
		.opcode		= opcode,
		.nsid		= args->nsid,
		.cdw2		= cdw2,
		.cdw3		= cdw3,
		.cdw10		= cdw10,
		.cdw11		= cdw11,
		.cdw12		= cdw12,
		.cdw13		= cdw13,
		.cdw14		= cdw14,
		.cdw15		= cdw15,
		.data_len	= args->data_len,
		.metadata_len	= args->metadata_len,
		.addr		= (__u64)(uintptr_t)args->data,
		.metadata	= (__u64)(uintptr_t)args->metadata,
		.timeout_ms	= args->timeout,
	};

	return nvme_submit_io_passthru(hdl, &cmd, args->result);
}

int nvme_copy(struct nvme_transport_handle *hdl, struct nvme_copy_args *args)
{
	__u32 cdw3, cdw12, cdw14, data_len;

	cdw12 = ((args->nr - 1) & 0xff) | ((args->format & 0xf) <<  8) |
		((args->prinfor & 0xf) << 12) | ((args->dtype & 0xf) << 20) |
		((args->prinfow & 0xf) << 26) | ((args->fua & 0x1) << 30) |
		((args->lr & 0x1) << 31);
	cdw3 = (args->ilbrt_u64 >> 32) & 0xffffffff;
	cdw14 = args->ilbrt_u64 & 0xffffffff;

	if (args->format == 1)
		data_len = args->nr * sizeof(struct nvme_copy_range_f1);
	else if (args->format == 2)
		data_len = args->nr * sizeof(struct nvme_copy_range_f2);
	else if (args->format == 3)
		data_len = args->nr * sizeof(struct nvme_copy_range_f3);
	else
		data_len = args->nr * sizeof(struct nvme_copy_range);

	struct nvme_passthru_cmd cmd = {
		.opcode         = nvme_cmd_copy,
		.nsid           = args->nsid,
		.addr           = (__u64)(uintptr_t)args->copy,
		.data_len       = data_len,
		.cdw3           = cdw3,
		.cdw10          = args->sdlba & 0xffffffff,
		.cdw11          = args->sdlba >> 32,
		.cdw12          = cdw12,
		.cdw13		= (args->dspec & 0xffff) << 16,
		.cdw14          = cdw14,
		.cdw15		= (args->lbatm << 16) | args->lbat,
		.timeout_ms	= args->timeout,
	};

	return nvme_submit_io_passthru(hdl, &cmd, args->result);
}

int nvme_resv_acquire(struct nvme_transport_handle *hdl, struct nvme_resv_acquire_args *args)
{
	__le64 payload[2] = {
		cpu_to_le64(args->crkey),
		cpu_to_le64(args->nrkey)
	};
	__u32 cdw10 = (args->racqa & 0x7) |
		(args->iekey ? 1 << 3 : 0) |
		(args->rtype << 8);

	struct nvme_passthru_cmd cmd = {
		.opcode		= nvme_cmd_resv_acquire,
		.nsid		= args->nsid,
		.cdw10		= cdw10,
		.data_len	= sizeof(payload),
		.addr		= (__u64)(uintptr_t)(payload),
		.timeout_ms	= args->timeout,
	};

	if (args->args_size < sizeof(*args))
		return -EINVAL;

	return nvme_submit_io_passthru(hdl, &cmd, args->result);
}

int nvme_resv_register(struct nvme_transport_handle *hdl, struct nvme_resv_register_args *args)
{
	__le64 payload[2] = {
		cpu_to_le64(args->crkey),
		cpu_to_le64(args->nrkey)
	};
	__u32 cdw10 = (args->rrega & 0x7) |
		(args->iekey ? 1 << 3 : 0) |
		(args->cptpl << 30);

	struct nvme_passthru_cmd cmd = {
		.opcode		= nvme_cmd_resv_register,
		.nsid		= args->nsid,
		.cdw10		= cdw10,
		.data_len	= sizeof(payload),
		.addr		= (__u64)(uintptr_t)(payload),
		.timeout_ms	= args->timeout,
	};

	if (args->args_size < sizeof(*args))
		return -EINVAL;

	return nvme_submit_io_passthru(hdl, &cmd, args->result);
}

int nvme_resv_release(struct nvme_transport_handle *hdl, struct nvme_resv_release_args *args)
{
	__le64 payload[1] = { cpu_to_le64(args->crkey) };
	__u32 cdw10 = (args->rrela & 0x7) |
		(args->iekey ? 1 << 3 : 0) |
		(args->rtype << 8);

	struct nvme_passthru_cmd cmd = {
		.opcode		= nvme_cmd_resv_release,
		.nsid		= args->nsid,
		.cdw10		= cdw10,
		.addr		= (__u64)(uintptr_t)(payload),
		.data_len	= sizeof(payload),
		.timeout_ms	= args->timeout,
	};

	if (args->args_size < sizeof(*args))
		return -EINVAL;

	return nvme_submit_io_passthru(hdl, &cmd, args->result);
}

int nvme_resv_report(struct nvme_transport_handle *hdl, struct nvme_resv_report_args *args)
{
	struct nvme_passthru_cmd cmd = {
		.opcode		= nvme_cmd_resv_report,
		.nsid		= args->nsid,
		.cdw10		= (args->len >> 2) - 1,
		.cdw11		= args->eds ? 1 : 0,
		.addr		= (__u64)(uintptr_t)args->report,
		.data_len	= args->len,
		.timeout_ms	= args->timeout,
	};

	if (args->args_size < sizeof(*args))
		return -EINVAL;

	return nvme_submit_io_passthru(hdl, &cmd, args->result);
}

int nvme_io_mgmt_recv(struct nvme_transport_handle *hdl, struct nvme_io_mgmt_recv_args *args)
{
	__u32 cdw10 = args->mo | (args->mos << 16);
	__u32 cdw11 = (args->data_len >> 2) - 1;

	struct nvme_passthru_cmd cmd = {
		.opcode		= nvme_cmd_io_mgmt_recv,
		.nsid		= args->nsid,
		.cdw10		= cdw10,
		.cdw11		= cdw11,
		.addr		= (__u64)(uintptr_t)args->data,
		.data_len	= args->data_len,
		.timeout_ms	= args->timeout,
	};

	if (args->args_size < sizeof(*args))
		return -EINVAL;

	return nvme_submit_io_passthru(hdl, &cmd, NULL);
}

int nvme_io_mgmt_send(struct nvme_transport_handle *hdl, struct nvme_io_mgmt_send_args *args)
{
	__u32 cdw10 = args->mo | (args->mos << 16);

	struct nvme_passthru_cmd cmd = {
		.opcode		= nvme_cmd_io_mgmt_send,
		.nsid		= args->nsid,
		.cdw10		= cdw10,
		.addr		= (__u64)(uintptr_t)args->data,
		.data_len	= args->data_len,
		.timeout_ms	= args->timeout,
	};

	if (args->args_size < sizeof(*args))
		return -EINVAL;

	return nvme_submit_io_passthru(hdl, &cmd, NULL);
}

int nvme_zns_mgmt_send(struct nvme_transport_handle *hdl, struct nvme_zns_mgmt_send_args *args)
{
	__u32 cdw10 = args->slba & 0xffffffff;
	__u32 cdw11 = args->slba >> 32;
	__u32 cdw13 = NVME_SET(args->zsaso, ZNS_MGMT_SEND_ZSASO) |
			NVME_SET(!!args->select_all, ZNS_MGMT_SEND_SEL) |
			NVME_SET(args->zsa, ZNS_MGMT_SEND_ZSA);

	struct nvme_passthru_cmd cmd = {
		.opcode		= nvme_zns_cmd_mgmt_send,
		.nsid		= args->nsid,
		.cdw10		= cdw10,
		.cdw11		= cdw11,
		.cdw13		= cdw13,
		.addr		= (__u64)(uintptr_t)args->data,
		.data_len	= args->data_len,
		.timeout_ms	= args->timeout,
	};

	if (args->args_size < sizeof(*args))
		return -EINVAL;

	return nvme_submit_io_passthru(hdl, &cmd, args->result);
}

int nvme_zns_mgmt_recv(struct nvme_transport_handle *hdl, struct nvme_zns_mgmt_recv_args *args)
{
	__u32 cdw10 = args->slba & 0xffffffff;
	__u32 cdw11 = args->slba >> 32;
	__u32 cdw12 = (args->data_len >> 2) - 1;
	__u32 cdw13 = NVME_SET(args->zra, ZNS_MGMT_RECV_ZRA) |
			NVME_SET(args->zrasf, ZNS_MGMT_RECV_ZRASF) |
			NVME_SET(args->zras_feat, ZNS_MGMT_RECV_ZRAS_FEAT);

	struct nvme_passthru_cmd cmd = {
		.opcode		= nvme_zns_cmd_mgmt_recv,
		.nsid		= args->nsid,
		.cdw10		= cdw10,
		.cdw11		= cdw11,
		.cdw12		= cdw12,
		.cdw13		= cdw13,
		.addr		= (__u64)(uintptr_t)args->data,
		.data_len	= args->data_len,
		.timeout_ms	= args->timeout,
	};

	if (args->args_size < sizeof(*args))
		return -EINVAL;

	return nvme_submit_io_passthru(hdl, &cmd, args->result);
}

int nvme_zns_append(struct nvme_transport_handle *hdl, struct nvme_zns_append_args *args)
{
	__u32 cdw3, cdw10, cdw11, cdw12, cdw14, cdw15;

	cdw10 = args->zslba & 0xffffffff;
	cdw11 = args->zslba >> 32;
	cdw12 = args->nlb | (args->control << 16);
	cdw15 = args->lbat | (args->lbatm << 16);
	cdw3 = (args->ilbrt_u64 >> 32) & 0xffffffff;
	cdw14 = args->ilbrt_u64 & 0xffffffff;

	struct nvme_passthru_cmd64 cmd = {
		.opcode		= nvme_zns_cmd_append,
		.nsid		= args->nsid,
		.cdw3		= cdw3,
		.cdw10		= cdw10,
		.cdw11		= cdw11,
		.cdw12		= cdw12,
		.cdw14		= cdw14,
		.cdw15		= cdw15,
		.data_len	= args->data_len,
		.addr		= (__u64)(uintptr_t)args->data,
		.metadata_len	= args->metadata_len,
		.metadata	= (__u64)(uintptr_t)args->metadata,
		.timeout_ms	= args->timeout,
	};

	return nvme_submit_io_passthru64(hdl, &cmd, args->result);
}

int nvme_dim_send(struct nvme_transport_handle *hdl, struct nvme_dim_args *args)
{
	__u32 cdw10 = NVME_SET(args->tas, DIM_TAS);

	struct nvme_passthru_cmd  cmd = {
		.opcode     = nvme_admin_discovery_info_mgmt,
		.cdw10      = cdw10,
		.addr       = (__u64)(uintptr_t)args->data,
		.data_len   = args->data_len,
		.timeout_ms = args->timeout,
	};

	if (args->args_size < sizeof(*args))
		return -EINVAL;

	return nvme_submit_admin_passthru(hdl, &cmd, args->result);
}


int nvme_lm_cdq(struct nvme_transport_handle *hdl, struct nvme_lm_cdq_args *args)
{
	__u32 cdw10 = NVME_SET(args->sel, LM_CDQ_SEL) |
		      NVME_SET(args->mos, LM_CDQ_MOS);
	__u32 cdw11 = 0, data_len = 0, sz = 0;
	int err;

	sz = args->sz;

	if (args->sel == NVME_LM_SEL_CREATE_CDQ) {
		cdw11 = NVME_SET(NVME_SET(args->cntlid, LM_CREATE_CDQ_CNTLID), LM_CQS) |
			NVME_LM_CREATE_CDQ_PC;
		data_len = sz << 2;
	} else if (args->sel == NVME_LM_SEL_DELETE_CDQ) {
		cdw11 = NVME_SET(args->cdqid, LM_DELETE_CDQ_CDQID);
	}

	struct nvme_passthru_cmd cmd = {
		.opcode = nvme_admin_ctrl_data_queue,
		.cdw10 = cdw10,
		.cdw11 = cdw11,
		.cdw12 = sz,
		.addr = (__u64)(uintptr_t)args->data,
		.data_len = data_len,
		.timeout_ms = args->timeout,
	};

	if (args->args_size < sizeof(*args))
		return -EINVAL;

	err = nvme_submit_admin_passthru(hdl, &cmd, args->result);

	if (!err)
		args->cdqid = NVME_GET(cmd.result, LM_CREATE_CDQ_CDQID);

	return err;
}

int nvme_lm_track_send(struct nvme_transport_handle *hdl, struct nvme_lm_track_send_args *args)
{
	__u32 cdw10 = NVME_SET(args->sel, LM_TRACK_SEND_SEL) |
		      NVME_SET(args->mos, LM_TRACK_SEND_MOS);

	struct nvme_passthru_cmd cmd = {
		.opcode = nvme_admin_track_send,
		.cdw10 = cdw10,
		.cdw11 = args->cdqid,
		.timeout_ms = args->timeout,
	};

	if (args->args_size < sizeof(*args))
		return -EINVAL;

	return nvme_submit_admin_passthru(hdl, &cmd, args->result);
}

int nvme_lm_migration_send(struct nvme_transport_handle *hdl, struct nvme_lm_migration_send_args *args)
{
	__u32 cdw10 = NVME_SET(args->sel, LM_MIGRATION_SEND_SEL) |
		      NVME_SET(args->mos, LM_MIGRATION_SEND_MOS);
	__u32 cdw11 = 0;

	if (args->sel == NVME_LM_SEL_SUSPEND) {
		cdw11 = NVME_SET(args->stype, LM_STYPE) |
			NVME_SET(args->cntlid, LM_SUSPEND_CNTLID);
		if (args->dudmq)
			cdw11 |= NVME_LM_DUDMQ;
	} else if (args->sel == NVME_LM_SEL_RESUME) {
		cdw11 = NVME_SET(args->cntlid, LM_RESUME_CNTLID);
	} else if (args->sel == NVME_LM_SEL_SET_CONTROLLER_STATE) {
		cdw11 = NVME_SET(args->csuuidi, LM_SET_CONTROLLER_STATE_CSUUIDI) |
			NVME_SET(args->csvi, LM_SET_CONTROLLER_STATE_CSVI) |
			NVME_SET(args->cntlid, LM_SET_CONTROLLER_STATE_CNTLID);
	}

	struct nvme_passthru_cmd cmd = {
		.opcode = nvme_admin_migration_send,
		.cdw10 = cdw10,
		.cdw11 = cdw11,
		.cdw12 = (__u32)args->offset,
		.cdw13 = (__u32)(args->offset >> 32),
		.cdw14 = NVME_SET(args->uidx, LM_MIGRATION_SEND_UIDX),
		.cdw15 = args->numd,
		.addr = (__u64)(uintptr_t)args->data,
		.data_len = args->numd << 2,
		.timeout_ms = args->timeout,
	};

	if (args->args_size < sizeof(*args))
		return -EINVAL;

	return nvme_submit_admin_passthru(hdl, &cmd, args->result);
}

int nvme_lm_migration_recv(struct nvme_transport_handle *hdl, struct nvme_lm_migration_recv_args *args)
{
	__u32 cdw10 = NVME_SET(args->sel, LM_MIGRATION_RECV_SEL) |
		      NVME_SET(args->mos, LM_MIGRATION_RECV_MOS);
	__u32 cdw11 = 0, data_len = 0;

	if (args->sel == NVME_LM_SEL_GET_CONTROLLER_STATE) {
		cdw11 = NVME_SET(args->csuidxp, LM_GET_CONTROLLER_STATE_CSUIDXP) |
			NVME_SET(args->csuuidi, LM_GET_CONTROLLER_STATE_CSUUIDI) |
			NVME_SET(args->cntlid, LM_GET_CONTROLLER_STATE_CNTLID);
		data_len = (args->numd + 1 /*0's based*/) << 2;
	}

	struct nvme_passthru_cmd cmd = {
		.opcode = nvme_admin_migration_receive,
		.cdw10 = cdw10,
		.cdw11 = cdw11,
		.cdw12 = (__u32)args->offset,
		.cdw13 = (__u32)(args->offset >> 32),
		.cdw14 = NVME_SET(args->uidx, LM_MIGRATION_RECV_UIDX),
		.cdw15 = args->numd,
		.addr = (__u64)(uintptr_t)args->data,
		.data_len = data_len,
		.timeout_ms = args->timeout,
	};

	if (args->args_size < sizeof(*args))
		return -EINVAL;

	return nvme_submit_admin_passthru(hdl, &cmd, args->result);
}

int nvme_lm_set_features_ctrl_data_queue(struct nvme_transport_handle *hdl, __u16 cdqid, __u32 hp, __u32 tpt, bool etpt,
					 __u32 *result)
{
	struct nvme_passthru_cmd cmd;

	nvme_init_set_features(&cmd, NVME_FEAT_FID_CTRL_DATA_QUEUE, false);
	cmd.cdw11 = cdqid | NVME_SET(etpt, LM_CTRL_DATA_QUEUE_ETPT);
	cmd.cdw12 = hp;
	cmd.cdw13 = tpt;

	return nvme_submit_admin_passthru(hdl, &cmd, result);
}

int nvme_lm_get_features_ctrl_data_queue(struct nvme_transport_handle *hdl, __u16 cdqid,
					 struct nvme_lm_ctrl_data_queue_fid_data *data,
					 __u32 *result)
{
	struct nvme_passthru_cmd cmd;

	nvme_init_get_features(&cmd, NVME_FEAT_FID_CTRL_DATA_QUEUE, 0);
	cmd.cdw11 = cdqid;
	cmd.data_len = sizeof(*data);
	cmd.addr = (__u64)(uintptr_t)data;

	return nvme_submit_admin_passthru(hdl, &cmd, result);
}
