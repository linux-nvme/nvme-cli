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
#include <ccan/endian/endian.h>

#include "ioctl.h"
#include "util.h"
#include "log.h"

static int nvme_verify_chr(int fd)
{
	static struct stat nvme_stat;
	int err = fstat(fd, &nvme_stat);

	if (err < 0)
		return errno;

	if (!S_ISCHR(nvme_stat.st_mode)) {
		errno = ENOTBLK;
		return -1;
	}
	return 0;
}

int nvme_subsystem_reset(int fd)
{
	int ret;

	ret = nvme_verify_chr(fd);
	if (ret)
		return ret;
	return ioctl(fd, NVME_IOCTL_SUBSYS_RESET);
}

int nvme_ctrl_reset(int fd)
{
	int ret;

	ret = nvme_verify_chr(fd);
	if (ret)
		return ret;
	return ioctl(fd, NVME_IOCTL_RESET);
}

int nvme_ns_rescan(int fd)
{
	int ret;

	ret = nvme_verify_chr(fd);
	if (ret)
		return ret;
	return ioctl(fd, NVME_IOCTL_RESCAN);
}

int nvme_get_nsid(int fd, __u32 *nsid)
{
	errno = 0;
	*nsid = ioctl(fd, NVME_IOCTL_ID);
	return -1 * (errno != 0);
}

__attribute__((weak))
int nvme_submit_passthru64(int fd, unsigned long ioctl_cmd,
			   struct nvme_passthru_cmd64 *cmd,
			   __u64 *result)
{
	int err = ioctl(fd, ioctl_cmd, cmd);

	if (err >= 0 && result)
		*result = cmd->result;
	return err;
}

__attribute__((weak))
int nvme_submit_passthru(int fd, unsigned long ioctl_cmd,
			 struct nvme_passthru_cmd *cmd, __u32 *result)
{
	int err = ioctl(fd, ioctl_cmd, cmd);

	if (err >= 0 && result)
		*result = cmd->result;
	return err;
}

static int nvme_passthru64(int fd, unsigned long ioctl_cmd, __u8 opcode,
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

	return nvme_submit_passthru64(fd, ioctl_cmd, &cmd, result);
}

static int nvme_passthru(int fd, unsigned long ioctl_cmd, __u8 opcode,
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

	return nvme_submit_passthru(fd, ioctl_cmd, &cmd, result);
}

int nvme_submit_admin_passthru64(int fd, struct nvme_passthru_cmd64 *cmd,
				 __u64 *result)
{
	return nvme_submit_passthru64(fd, NVME_IOCTL_ADMIN64_CMD, cmd, result);
}

int nvme_admin_passthru64(int fd, __u8 opcode, __u8 flags, __u16 rsvd,
			 __u32 nsid, __u32 cdw2, __u32 cdw3, __u32 cdw10,
			 __u32 cdw11, __u32 cdw12, __u32 cdw13, __u32 cdw14,
			 __u32 cdw15, __u32 data_len, void *data,
			 __u32 metadata_len, void *metadata, __u32 timeout_ms,
			 __u64 *result)
{
	return nvme_passthru64(fd, NVME_IOCTL_ADMIN64_CMD, opcode, flags, rsvd,
			       nsid, cdw2, cdw3, cdw10, cdw11, cdw12, cdw13,
			       cdw14, cdw15, data_len, data, metadata_len,
			       metadata, timeout_ms, result);
}

int nvme_submit_admin_passthru(int fd, struct nvme_passthru_cmd *cmd, __u32 *result)
{
	return nvme_submit_passthru(fd, NVME_IOCTL_ADMIN_CMD, cmd, result);
}

int nvme_admin_passthru(int fd, __u8 opcode, __u8 flags, __u16 rsvd,
			__u32 nsid, __u32 cdw2, __u32 cdw3, __u32 cdw10,
			__u32 cdw11, __u32 cdw12, __u32 cdw13, __u32 cdw14,
			__u32 cdw15, __u32 data_len, void *data,
			__u32 metadata_len, void *metadata, __u32 timeout_ms,
			__u32 *result)
{
	return nvme_passthru(fd, NVME_IOCTL_ADMIN_CMD, opcode, flags, rsvd,
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

int nvme_identify(struct nvme_identify_args *args)
{
	__u32 cdw10 = NVME_SET(args->cntid, IDENTIFY_CDW10_CNTID) |
			NVME_SET(args->cns, IDENTIFY_CDW10_CNS);
	__u32 cdw11 = NVME_SET(args->cns_specific_id, IDENTIFY_CDW11_CNSSPECID) |
			NVME_SET(args->csi, IDENTIFY_CDW11_CSI);
	__u32 cdw14 = NVME_SET(args->uuidx, IDENTIFY_CDW14_UUID);

	struct nvme_passthru_cmd cmd = {
		.opcode		= nvme_admin_identify,
		.nsid		= args->nsid,
		.addr		= (__u64)(uintptr_t)args->data,
		.data_len	= NVME_IDENTIFY_DATA_SIZE,
		.cdw10		= cdw10,
		.cdw11		= cdw11,
		.cdw14		= cdw14,
		.timeout_ms	= args->timeout,
	};

	if (args->args_size < sizeof(*args)) {
		errno = EINVAL;
		return -1;
	}
	return nvme_submit_admin_passthru(args->fd, &cmd, args->result);
}

int nvme_get_log(struct nvme_get_log_args *args)
{
	__u32 numd = (args->len >> 2) - 1;
	__u16 numdu = numd >> 16, numdl = numd & 0xffff;

	__u32 cdw10 = NVME_SET(args->lid, LOG_CDW10_LID) |
			NVME_SET(args->lsp, LOG_CDW10_LSP) |
			NVME_SET(!!args->rae, LOG_CDW10_RAE) |
			NVME_SET(numdl, LOG_CDW10_NUMDL);
	__u32 cdw11 = NVME_SET(numdu, LOG_CDW11_NUMDU) |
			NVME_SET(args->lsi, LOG_CDW11_LSI);
	__u32 cdw12 = args->lpo & 0xffffffff;
	__u32 cdw13 = args->lpo >> 32;
	__u32 cdw14 = NVME_SET(args->uuidx, LOG_CDW14_UUID) |
			NVME_SET(!!args->ot, LOG_CDW14_OT) |
			NVME_SET(args->csi, LOG_CDW14_CSI);

	struct nvme_passthru_cmd cmd = {
		.opcode		= nvme_admin_get_log_page,
		.nsid		= args->nsid,
		.addr		= (__u64)(uintptr_t)args->log,
		.data_len	= args->len,
		.cdw10		= cdw10,
		.cdw11		= cdw11,
		.cdw12		= cdw12,
		.cdw13		= cdw13,
		.cdw14		= cdw14,
		.timeout_ms	= args->timeout,
	};

	if (args->args_size < sizeof(struct nvme_get_log_args)) {
		errno = EINVAL;
		return -1;
	}
	return nvme_submit_admin_passthru(args->fd, &cmd, args->result);
}

int nvme_get_log_page(int fd, __u32 xfer_len, struct nvme_get_log_args *args)
{
	__u64 offset = 0, xfer, data_len = args->len;
	__u64 start = args->lpo;
	bool retain = args->rae;
	void *ptr = args->log;
	int ret;

	args->fd = fd;

	/*
	 * 4k is the smallest possible transfer unit, so restricting to 4k
	 * avoids having to check the MDTS value of the controller.
	 */
	do {
		xfer = data_len - offset;
		if (xfer > xfer_len)
			xfer  = xfer_len;

		/*
		 * Always retain regardless of the RAE parameter until the very
		 * last portion of this log page so the data remains latched
		 * during the fetch sequence.
		 */
		args->lpo = start + offset;
		args->len = xfer;
		args->log = ptr;
		args->rae = offset + xfer < data_len || retain;
		ret = nvme_get_log(args);
		if (ret)
			return ret;

		offset += xfer;
		ptr += xfer;
	} while (offset < data_len);

	return 0;
}

static int read_ana_chunk(int fd, enum nvme_log_ana_lsp lsp, bool rae,
			  __u8 *log, __u8 **read, __u8 *to_read, __u8 *log_end)
{
	if (to_read > log_end) {
		errno = ENOSPC;
		return -1;
	}

	while (*read < to_read) {
		__u32 len = min(log_end - *read, NVME_LOG_PAGE_PDU_SIZE);
		int ret;

		ret = nvme_get_log_ana(fd, lsp, rae, *read - log, len, *read);
		if (ret)
			return ret;

		*read += len;
	}
	return 0;
}

static int try_read_ana(int fd, enum nvme_log_ana_lsp lsp, bool rae,
			struct nvme_ana_log *log, __u8 *log_end,
			__u8 *read, __u8 **to_read, bool *may_retry)
{
	__u16 ngrps = le16_to_cpu(log->ngrps);

	while (ngrps--) {
		__u8 *group = *to_read;
		int ret;
		__le32 nnsids;

		*to_read += sizeof(*log->descs);
		ret = read_ana_chunk(fd, lsp, rae,
				     (__u8 *)log, &read, *to_read, log_end);
		if (ret) {
			/*
			 * If the provided buffer isn't long enough,
			 * the log page may have changed while reading it
			 * and the computed length was inaccurate.
			 * Have the caller check chgcnt and retry.
			 */
			*may_retry = errno == ENOSPC;
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
		ret = read_ana_chunk(fd, lsp, rae,
				     (__u8 *)log, &read, *to_read, log_end);
		if (ret) {
			*may_retry = errno == ENOSPC;
			return ret;
		}
	}

	*may_retry = true;
	return 0;
}

int nvme_get_ana_log_atomic(int fd, bool rgo, bool rae, unsigned int retries,
			    struct nvme_ana_log *log, __u32 *len)
{
	const enum nvme_log_ana_lsp lsp =
		rgo ? NVME_LOG_ANA_LSP_RGO_GROUPS_ONLY : 0;
	/* Get Log Page can only fetch multiples of dwords */
	__u8 * const log_end = (__u8 *)log + (*len & -4);
	__u8 *read = (__u8 *)log;
	__u8 *to_read;
	int ret;

	if (!retries) {
		errno = EINVAL;
		return -1;
	}

	to_read = (__u8 *)log->descs;
	ret = read_ana_chunk(fd, lsp, rae,
			     (__u8 *)log, &read, to_read, log_end);
	if (ret)
		return ret;

	do {
		bool may_retry = false;
		int saved_ret;
		int saved_errno;
		__le64 chgcnt;

		saved_ret = try_read_ana(fd, lsp, rae, log, log_end,
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
		ret = read_ana_chunk(fd, lsp, rae,
				     (__u8 *)log, &read, to_read, log_end);
		if (ret)
			return ret;

		if (log->chgcnt == chgcnt) {
			/* Log hasn't changed; return try_read_ana() result */
			errno = saved_errno;
			return saved_ret;
		}
	} while (--retries);

	errno = EAGAIN;
	return -1;
}

int nvme_set_features(struct nvme_set_features_args *args)
{
	__u32 cdw10 = NVME_SET(args->fid, FEATURES_CDW10_FID) |
			NVME_SET(!!args->save, SET_FEATURES_CDW10_SAVE);
	__u32 cdw14 = NVME_SET(args->uuidx, FEATURES_CDW14_UUID);

	struct nvme_passthru_cmd cmd = {
		.opcode		= nvme_admin_set_features,
		.nsid		= args->nsid,
		.addr		= (__u64)(uintptr_t)args->data,
		.data_len	= args->data_len,
		.cdw10		= cdw10,
		.cdw11		= args->cdw11,
		.cdw12		= args->cdw12,
		.cdw13		= args->cdw13,
		.cdw14		= cdw14,
		.cdw15		= args->cdw15,
		.timeout_ms	= args->timeout,
	};
	if (args->args_size < sizeof(*args)) {
		errno = EINVAL;
		return -1;
	}
	return nvme_submit_admin_passthru(args->fd, &cmd, args->result);
}

static int __nvme_set_features(int fd, __u8 fid, __u32 cdw11, bool save,
			       __u32 *result)
{
	struct nvme_set_features_args args = {
		.args_size = sizeof(args),
		.fd = fd,
		.fid = fid,
		.nsid = NVME_NSID_NONE,
		.cdw11 = cdw11,
		.cdw12 = 0,
		.save = save,
		.uuidx = NVME_UUID_NONE,
		.cdw15 = 0,
		.data_len = 0,
		.data = NULL,
		.timeout = NVME_DEFAULT_IOCTL_TIMEOUT,
		.result = result,
	};
	return nvme_set_features(&args);
}

int nvme_set_features_arbitration(int fd, __u8 ab, __u8 lpw, __u8 mpw,
				  __u8 hpw, bool save, __u32 *result)
{
	__u32 value = NVME_SET(ab, FEAT_ARBITRATION_BURST) |
			NVME_SET(lpw, FEAT_ARBITRATION_LPW) |
			NVME_SET(mpw, FEAT_ARBITRATION_MPW) |
			NVME_SET(hpw, FEAT_ARBITRATION_HPW);

	return __nvme_set_features(fd, NVME_FEAT_FID_ARBITRATION, value, save,
				   result);
}

int nvme_set_features_power_mgmt(int fd, __u8 ps, __u8 wh, bool save,
				 __u32 *result)
{
	__u32 value = NVME_SET(ps, FEAT_PWRMGMT_PS) |
			NVME_SET(wh, FEAT_PWRMGMT_WH);

	return __nvme_set_features(fd, NVME_FEAT_FID_POWER_MGMT, value, save,
				   result);
}

int nvme_set_features_lba_range(int fd, __u32 nsid, __u8 nr_ranges, bool save,
				struct nvme_lba_range_type *data, __u32 *result)
{
	return nvme_set_features_data(
		fd, NVME_FEAT_FID_LBA_RANGE, nsid, nr_ranges - 1, save,
		sizeof(*data), data, result);
}

int nvme_set_features_temp_thresh(int fd, __u16 tmpth, __u8 tmpsel,
				  enum nvme_feat_tmpthresh_thsel thsel,
				  bool save, __u32 *result)
{
	__u32 value = NVME_SET(tmpth, FEAT_TT_TMPTH) |
			NVME_SET(tmpsel, FEAT_TT_TMPSEL) |
			NVME_SET(thsel, FEAT_TT_THSEL);

	return __nvme_set_features(fd, NVME_FEAT_FID_TEMP_THRESH, value, save,
				   result);
}

int nvme_set_features_err_recovery(int fd, __u32 nsid, __u16 tler, bool dulbe,
				   bool save, __u32 *result)
{
	__u32 value = NVME_SET(tler, FEAT_ERROR_RECOVERY_TLER) |
			NVME_SET(!!dulbe, FEAT_ERROR_RECOVERY_DULBE);

	return nvme_set_features_simple(
		fd, NVME_FEAT_FID_ERR_RECOVERY, nsid, value, save, result);
}

int nvme_set_features_volatile_wc(int fd, bool wce, bool save, __u32 *result)
{
	__u32 value = NVME_SET(!!wce, FEAT_VWC_WCE);

	return __nvme_set_features(fd, NVME_FEAT_FID_VOLATILE_WC, value, save,
				   result);
}

int nvme_set_features_irq_coalesce(int fd, __u8 thr, __u8 time, bool save,
				   __u32 *result)
{
	__u32 value = NVME_SET(thr, FEAT_IRQC_THR) |
			NVME_SET(time, FEAT_IRQC_TIME);

	return __nvme_set_features(fd, NVME_FEAT_FID_IRQ_COALESCE, value, save,
				   result);
}

int nvme_set_features_irq_config(int fd, __u16 iv, bool cd, bool save,
				 __u32 *result)
{
	__u32 value = NVME_SET(iv, FEAT_ICFG_IV) |
			NVME_SET(!!cd, FEAT_ICFG_CD);

	return __nvme_set_features(fd, NVME_FEAT_FID_IRQ_CONFIG, value, save,
				   result);
}

int nvme_set_features_write_atomic(int fd, bool dn, bool save, __u32 *result)
{
	__u32 value = NVME_SET(!!dn, FEAT_WA_DN);

	return __nvme_set_features(fd, NVME_FEAT_FID_WRITE_ATOMIC, value, save,
				   result);
}

int nvme_set_features_async_event(int fd, __u32 events,
				  bool save, __u32 *result)
{
	return __nvme_set_features(fd, NVME_FEAT_FID_ASYNC_EVENT, events, save,
				   result);
}

int nvme_set_features_auto_pst(int fd, bool apste, bool save,
			       struct nvme_feat_auto_pst *apst, __u32 *result)
{
	return nvme_set_features_data(fd, NVME_FEAT_FID_AUTO_PST,
		NVME_NSID_NONE, NVME_SET(!!apste, FEAT_APST_APSTE), save,
		sizeof(*apst), apst, result);
}

int nvme_set_features_timestamp(int fd, bool save, __u64 timestamp)
{
	__le64 t = cpu_to_le64(timestamp);
	struct nvme_timestamp ts = {};
	memcpy(ts.timestamp, &t, sizeof(ts.timestamp));

	return nvme_set_features_data(fd, NVME_FEAT_FID_TIMESTAMP,
		NVME_NSID_NONE, 0, save, sizeof(ts), &ts, NULL);
}

int nvme_set_features_hctm(int fd, __u16 tmt2, __u16 tmt1,
			   bool save, __u32 *result)
{
	__u32 value = NVME_SET(tmt2, FEAT_HCTM_TMT2) |
			NVME_SET(tmt1, FEAT_HCTM_TMT1);

	return __nvme_set_features(fd, NVME_FEAT_FID_HCTM, value, save,
				   result);
}

int nvme_set_features_nopsc(int fd, bool noppme, bool save, __u32 *result)
{
	__u32 value = NVME_SET(noppme, FEAT_NOPS_NOPPME);

	return __nvme_set_features(fd, NVME_FEAT_FID_NOPSC, value, save,
				   result);
}

int nvme_set_features_rrl(int fd, __u8 rrl, __u16 nvmsetid,
			  bool save, __u32 *result)
{
	struct nvme_set_features_args args = {
		.args_size = sizeof(args),
		.fd = fd,
		.fid = NVME_FEAT_FID_RRL,
		.nsid = NVME_NSID_NONE,
		.cdw11 = nvmsetid,
		.cdw12 = rrl,
		.save = save,
		.uuidx = NVME_UUID_NONE,
		.cdw15 = 0,
		.data_len = 0,
		.data = NULL,
		.timeout = NVME_DEFAULT_IOCTL_TIMEOUT,
		.result = result,
	};

	return nvme_set_features(&args);
}

int nvme_set_features_plm_config(int fd, bool plm, __u16 nvmsetid, bool save,
				 struct nvme_plm_config *data, __u32 *result)
{
	struct nvme_set_features_args args = {
		.args_size = sizeof(args),
		.fd = fd,
		.fid = NVME_FEAT_FID_PLM_CONFIG,
		.nsid = NVME_NSID_NONE,
		.cdw11 = nvmsetid,
		.cdw12 = !!plm,
		.save = save,
		.uuidx = NVME_UUID_NONE,
		.cdw15 = 0,
		.data_len = sizeof(*data),
		.data = data,
		.timeout = NVME_DEFAULT_IOCTL_TIMEOUT,
		.result = result,
	};

	return nvme_set_features(&args);
}

int nvme_set_features_plm_window(int fd, enum nvme_feat_plm_window_select sel,
				 __u16 nvmsetid, bool save, __u32 *result)
{
	__u32 cdw12 = NVME_SET(sel, FEAT_PLMW_WS);
	struct nvme_set_features_args args = {
		.args_size = sizeof(args),
		.fd = fd,
		.fid = NVME_FEAT_FID_PLM_WINDOW,
		.nsid = NVME_NSID_NONE,
		.cdw11 = nvmsetid,
		.cdw12 = cdw12,
		.save = save,
		.uuidx = NVME_UUID_NONE,
		.cdw15 = 0,
		.data_len = 0,
		.data = NULL,
		.timeout = NVME_DEFAULT_IOCTL_TIMEOUT,
		.result = result,
	};

	return nvme_set_features(&args);
}

int nvme_set_features_lba_sts_interval(int fd, __u16 lsiri, __u16 lsipi,
				       bool save, __u32 *result)
{
	__u32 value = NVME_SET(lsiri, FEAT_LBAS_LSIRI) |
			NVME_SET(lsipi, FEAT_LBAS_LSIPI);

	return __nvme_set_features(fd, NVME_FEAT_FID_LBA_STS_INTERVAL, value,
				   save, result);
}

int nvme_set_features_host_behavior(int fd, bool save,
	struct nvme_feat_host_behavior *data)
{
	return nvme_set_features_data(fd, NVME_FEAT_FID_HOST_BEHAVIOR,
		NVME_NSID_NONE, 0, false, sizeof(*data), data, NULL);
}

int nvme_set_features_sanitize(int fd, bool nodrm, bool save, __u32 *result)
{
	return __nvme_set_features(fd, NVME_FEAT_FID_SANITIZE, !!nodrm, save,
				   result);
}

int nvme_set_features_endurance_evt_cfg(int fd, __u16 endgid, __u8 egwarn,
					bool save, __u32 *result)
{
	__u32 value = endgid | egwarn << 16;

	return __nvme_set_features(fd, NVME_FEAT_FID_ENDURANCE_EVT_CFG, value,
				   save, result);
}

int nvme_set_features_sw_progress(int fd, __u8 pbslc, bool save,
				  __u32 *result)
{
	return __nvme_set_features(fd, NVME_FEAT_FID_SW_PROGRESS, pbslc, save,
				   result);
}

int nvme_set_features_host_id(int fd, bool exhid, bool save, __u8 *hostid)
{
	__u32 len = exhid ? 16 : 8;
	__u32 value = !!exhid;

	return nvme_set_features_data(fd, NVME_FEAT_FID_HOST_ID,
		NVME_NSID_NONE, value, save, len, hostid, NULL);
}

int nvme_set_features_resv_mask(int fd, __u32 mask, bool save, __u32 *result)
{
	return __nvme_set_features(fd, NVME_FEAT_FID_RESV_MASK, mask, save,
				   result);
}

int nvme_set_features_resv_mask2(int fd, __u32 nsid, __u32 mask, bool save,
				 __u32 *result)
{
	return nvme_set_features_simple(
		fd, NVME_FEAT_FID_RESV_MASK, nsid, mask, save, result);
}

int nvme_set_features_resv_persist(int fd, bool ptpl, bool save, __u32 *result)
{
	return __nvme_set_features(fd, NVME_FEAT_FID_RESV_PERSIST, !!ptpl, save,
				   result);
}

int nvme_set_features_resv_persist2(int fd, __u32 nsid, bool ptpl, bool save,
				    __u32 *result)
{
	return nvme_set_features_simple(
		fd, NVME_FEAT_FID_RESV_PERSIST, nsid, !!ptpl, save, result);
}

int nvme_set_features_write_protect(int fd, enum nvme_feat_nswpcfg_state state,
				    bool save, __u32 *result)
{
	return __nvme_set_features(fd, NVME_FEAT_FID_WRITE_PROTECT, state,
				   false, result);
}

int nvme_set_features_write_protect2(int fd, __u32 nsid,
				     enum nvme_feat_nswpcfg_state state,
				     bool save, __u32 *result)
{
	return nvme_set_features_simple(
		fd, NVME_FEAT_FID_WRITE_PROTECT, nsid, state, false, result);
}

int nvme_set_features_iocs_profile(int fd, __u16 iocsi, bool save)
{
	__u32 value = NVME_SET(iocsi, FEAT_IOCSP_IOCSCI);

	return __nvme_set_features(fd, NVME_FEAT_FID_IOCS_PROFILE, value,
				   save, NULL);
}

int nvme_get_features(struct nvme_get_features_args *args)
{
	__u32 cdw10 = NVME_SET(args->fid, FEATURES_CDW10_FID) |
			NVME_SET(args->sel, GET_FEATURES_CDW10_SEL);
	__u32 cdw14 = NVME_SET(args->uuidx, FEATURES_CDW14_UUID);

	struct nvme_passthru_cmd cmd = {
		.opcode		= nvme_admin_get_features,
		.nsid		= args->nsid,
		.addr		= (__u64)(uintptr_t)args->data,
		.data_len	= args->data_len,
		.cdw10		= cdw10,
		.cdw11		= args->cdw11,
		.cdw14		= cdw14,
		.timeout_ms	= args->timeout,
	};

	if (args->args_size < sizeof(*args)) {
		errno = EINVAL;
		return -1;
	}
	return nvme_submit_admin_passthru(args->fd, &cmd, args->result);
}

static int __nvme_get_features(int fd, enum nvme_features_id fid,
			       enum nvme_get_features_sel sel, __u32 *result)
{
	struct nvme_get_features_args args = {
		.args_size = sizeof(args),
		.fd = fd,
		.fid = fid,
		.nsid = NVME_NSID_NONE,
		.sel = sel,
		.cdw11 = 0,
		.uuidx = NVME_UUID_NONE,
		.data_len = 0,
		.data = NULL,
		.timeout = NVME_DEFAULT_IOCTL_TIMEOUT,
		.result = result,
	};

	return nvme_get_features(&args);
}

int nvme_get_features_arbitration(int fd, enum nvme_get_features_sel sel,
				  __u32 *result)
{
	return __nvme_get_features(fd, NVME_FEAT_FID_ARBITRATION, sel, result);
}

int nvme_get_features_power_mgmt(int fd, enum nvme_get_features_sel sel,
				 __u32 *result)
{
	return __nvme_get_features(fd, NVME_FEAT_FID_POWER_MGMT, sel, result);
}

int nvme_get_features_lba_range(int fd, enum nvme_get_features_sel sel,
				struct nvme_lba_range_type *data,
				__u32 *result)
{
	struct nvme_get_features_args args = {
		.args_size = sizeof(args),
		.fd = fd,
		.fid = NVME_FEAT_FID_LBA_RANGE,
		.nsid = NVME_NSID_NONE,
		.sel = sel,
		.cdw11 = 0,
		.uuidx = NVME_UUID_NONE,
		.data_len = sizeof(*data),
		.data = data,
		.timeout = NVME_DEFAULT_IOCTL_TIMEOUT,
		.result = result,
	};

	return nvme_get_features(&args);
}

int nvme_get_features_lba_range2(int fd, enum nvme_get_features_sel sel,
				 __u32 nsid, struct nvme_lba_range_type *data,
				 __u32 *result)
{
	struct nvme_get_features_args args = {
		.args_size = sizeof(args),
		.fd = fd,
		.fid = NVME_FEAT_FID_LBA_RANGE,
		.nsid = nsid,
		.sel = sel,
		.uuidx = NVME_UUID_NONE,
		.data = data,
		.data_len = sizeof(*data),
		.timeout = NVME_DEFAULT_IOCTL_TIMEOUT,
		.result = result,
	};

	return nvme_get_features(&args);
}

int nvme_get_features_temp_thresh(int fd, enum nvme_get_features_sel sel,
				  __u32 *result)
{
	return __nvme_get_features(fd, NVME_FEAT_FID_TEMP_THRESH, sel, result);
}

int nvme_get_features_err_recovery(int fd, enum nvme_get_features_sel sel,
				   __u32 *result)
{
	return __nvme_get_features(fd, NVME_FEAT_FID_ERR_RECOVERY, sel,
				   result);
}

int nvme_get_features_err_recovery2(int fd, enum nvme_get_features_sel sel,
				    __u32 nsid, __u32 *result)
{

	struct nvme_get_features_args args = {
		.args_size = sizeof(args),
		.fd = fd,
		.fid = NVME_FEAT_FID_ERR_RECOVERY,
		.nsid = nsid,
		.sel = sel,
		.uuidx = NVME_UUID_NONE,
		.timeout = NVME_DEFAULT_IOCTL_TIMEOUT,
		.result = result,
	};

	return nvme_get_features(&args);
}

int nvme_get_features_volatile_wc(int fd, enum nvme_get_features_sel sel,
				  __u32 *result)
{
	return __nvme_get_features(fd, NVME_FEAT_FID_VOLATILE_WC, sel, result);
}

int nvme_get_features_num_queues(int fd, enum nvme_get_features_sel sel,
				 __u32 *result)
{
	return __nvme_get_features(fd, NVME_FEAT_FID_NUM_QUEUES, sel, result);
}

int nvme_get_features_irq_coalesce(int fd, enum nvme_get_features_sel sel,
				   __u32 *result)
{
	return __nvme_get_features(fd, NVME_FEAT_FID_IRQ_COALESCE, sel,
				   result);
}

int nvme_get_features_irq_config(int fd, enum nvme_get_features_sel sel,
				 __u16 iv, __u32 *result)
{
	struct nvme_get_features_args args = {
		.args_size = sizeof(args),
		.fd = fd,
		.fid = NVME_FEAT_FID_IRQ_CONFIG,
		.nsid = NVME_NSID_NONE,
		.sel = sel,
		.cdw11 = iv,
		.uuidx = NVME_UUID_NONE,
		.data_len = 0,
		.data = NULL,
		.timeout = NVME_DEFAULT_IOCTL_TIMEOUT,
		.result = result,
	};

	return nvme_get_features(&args);
}

int nvme_get_features_write_atomic(int fd, enum nvme_get_features_sel sel,
				   __u32 *result)
{
	return __nvme_get_features(fd, NVME_FEAT_FID_WRITE_ATOMIC, sel,
				   result);
}

int nvme_get_features_async_event(int fd, enum nvme_get_features_sel sel,
				  __u32 *result)
{
	return __nvme_get_features(fd, NVME_FEAT_FID_ASYNC_EVENT, sel, result);
}

int nvme_get_features_auto_pst(int fd, enum nvme_get_features_sel sel,
			       struct nvme_feat_auto_pst *apst, __u32 *result)
{
	struct nvme_get_features_args args = {
		.args_size = sizeof(args),
		.fd = fd,
		.fid = NVME_FEAT_FID_AUTO_PST,
		.nsid = NVME_NSID_NONE,
		.sel = sel,
		.cdw11 = 0,
		.uuidx = NVME_UUID_NONE,
		.data_len = sizeof(*apst),
		.data = apst,
		.timeout = NVME_DEFAULT_IOCTL_TIMEOUT,
		.result = result,
	};

	return nvme_get_features(&args);
}

int nvme_get_features_host_mem_buf(int fd, enum nvme_get_features_sel sel,
				   __u32 *result)
{
	return __nvme_get_features(fd, NVME_FEAT_FID_HOST_MEM_BUF, sel, result);
}

int nvme_get_features_host_mem_buf2(int fd, enum nvme_get_features_sel sel,
				    struct nvme_host_mem_buf_attrs *attrs,
				    __u32 *result)
{
	struct nvme_get_features_args args = {
		.args_size = sizeof(args),
		.fd = fd,
		.fid = NVME_FEAT_FID_HOST_MEM_BUF,
		.nsid = NVME_NSID_NONE,
		.sel = sel,
		.uuidx = NVME_UUID_NONE,
		.data = attrs,
		.data_len = sizeof(*attrs),
		.timeout = NVME_DEFAULT_IOCTL_TIMEOUT,
		.result = result,
	};

	return nvme_get_features(&args);
}

int nvme_get_features_timestamp(int fd, enum nvme_get_features_sel sel,
				struct nvme_timestamp *ts)
{
	struct nvme_get_features_args args = {
		.args_size = sizeof(args),
		.fd = fd,
		.fid = NVME_FEAT_FID_TIMESTAMP,
		.nsid = NVME_NSID_NONE,
		.sel = sel,
		.cdw11 = 0,
		.uuidx = NVME_UUID_NONE,
		.data_len = sizeof(*ts),
		.data = ts,
		.timeout = NVME_DEFAULT_IOCTL_TIMEOUT,
		.result = NULL,
	};

	return nvme_get_features(&args);
}

int nvme_get_features_kato(int fd, enum nvme_get_features_sel sel, __u32 *result)
{
	return __nvme_get_features(fd, NVME_FEAT_FID_KATO, sel, result);
}

int nvme_get_features_hctm(int fd, enum nvme_get_features_sel sel, __u32 *result)
{
	return __nvme_get_features(fd, NVME_FEAT_FID_HCTM, sel, result);
}

int nvme_get_features_nopsc(int fd, enum nvme_get_features_sel sel, __u32 *result)
{
	return __nvme_get_features(fd, NVME_FEAT_FID_NOPSC, sel, result);
}

int nvme_get_features_rrl(int fd, enum nvme_get_features_sel sel, __u32 *result)
{
	return __nvme_get_features(fd, NVME_FEAT_FID_RRL, sel, result);
}

int nvme_get_features_plm_config(int fd, enum nvme_get_features_sel sel,
				 __u16 nvmsetid, struct nvme_plm_config *data,
				 __u32 *result)
{
	struct nvme_get_features_args args = {
		.args_size = sizeof(args),
		.fd = fd,
		.fid = NVME_FEAT_FID_PLM_CONFIG,
		.nsid = NVME_NSID_NONE,
		.sel = sel,
		.cdw11 = nvmsetid,
		.uuidx = NVME_UUID_NONE,
		.data_len = sizeof(*data),
		.data = data,
		.timeout = NVME_DEFAULT_IOCTL_TIMEOUT,
		.result = result,
	};

	return nvme_get_features(&args);
}

int nvme_get_features_plm_window(int fd, enum nvme_get_features_sel sel,
				 __u16 nvmsetid, __u32 *result)
{
	struct nvme_get_features_args args = {
		.args_size = sizeof(args),
		.fd = fd,
		.fid = NVME_FEAT_FID_PLM_WINDOW,
		.nsid = NVME_NSID_NONE,
		.sel = sel,
		.cdw11 = nvmsetid,
		.uuidx = NVME_UUID_NONE,
		.data_len = 0,
		.data = NULL,
		.timeout = NVME_DEFAULT_IOCTL_TIMEOUT,
		.result = result,
	};

	return nvme_get_features(&args);
}

int nvme_get_features_lba_sts_interval(int fd, enum nvme_get_features_sel sel,
				       __u32 *result)
{
	return __nvme_get_features(fd, NVME_FEAT_FID_LBA_STS_INTERVAL, sel,
				   result);
}

int nvme_get_features_host_behavior(int fd, enum nvme_get_features_sel sel,
				    struct nvme_feat_host_behavior *data,
				    __u32 *result)
{
	struct nvme_get_features_args args = {
		.args_size = sizeof(args),
		.fd = fd,
		.fid = NVME_FEAT_FID_HOST_BEHAVIOR,
		.nsid = NVME_NSID_NONE,
		.sel = sel,
		.cdw11 = 0,
		.uuidx = NVME_UUID_NONE,
		.data_len = sizeof(*data),
		.data = data,
		.timeout = NVME_DEFAULT_IOCTL_TIMEOUT,
		.result = result,
	};

	return nvme_get_features(&args);
}

int nvme_get_features_sanitize(int fd, enum nvme_get_features_sel sel,
			       __u32 *result)
{
	return __nvme_get_features(fd, NVME_FEAT_FID_SANITIZE, sel, result);
}

int nvme_get_features_endurance_event_cfg(int fd, enum nvme_get_features_sel sel,
					  __u16 endgid, __u32 *result)
{
	struct nvme_get_features_args args = {
		.args_size = sizeof(args),
		.fd = fd,
		.fid = NVME_FEAT_FID_ENDURANCE_EVT_CFG,
		.nsid = NVME_NSID_NONE,
		.sel = sel,
		.cdw11 = endgid,
		.uuidx = NVME_UUID_NONE,
		.data_len = 0,
		.data = NULL,
		.timeout = NVME_DEFAULT_IOCTL_TIMEOUT,
		.result = result,
	};

	return nvme_get_features(&args);
}

int nvme_get_features_sw_progress(int fd, enum nvme_get_features_sel sel,
				  __u32 *result)
{
	return __nvme_get_features(fd, NVME_FEAT_FID_SW_PROGRESS, sel, result);
}

int nvme_get_features_host_id(int fd, enum nvme_get_features_sel sel,
			      bool exhid, __u32 len, __u8 *hostid)
{
	struct nvme_get_features_args args = {
		.args_size = sizeof(args),
		.fd = fd,
		.fid = NVME_FEAT_FID_HOST_ID,
		.nsid = NVME_NSID_NONE,
		.sel = sel,
		.cdw11 = !!exhid,
		.uuidx = NVME_UUID_NONE,
		.data_len = len,
		.data = hostid,
		.timeout = NVME_DEFAULT_IOCTL_TIMEOUT,
		.result = NULL,
	};

	return nvme_get_features(&args);
}

int nvme_get_features_resv_mask(int fd, enum nvme_get_features_sel sel,
				__u32 *result)
{
	return __nvme_get_features(fd, NVME_FEAT_FID_RESV_MASK, sel, result);
}

int nvme_get_features_resv_mask2(int fd, enum nvme_get_features_sel sel,
				 __u32 nsid, __u32 *result)
{
	struct nvme_get_features_args args = {
		.args_size = sizeof(args),
		.fd = fd,
		.fid = NVME_FEAT_FID_RESV_MASK,
		.nsid = nsid,
		.sel = sel,
		.uuidx = NVME_UUID_NONE,
		.timeout = NVME_DEFAULT_IOCTL_TIMEOUT,
		.result = result,
	};

	return nvme_get_features(&args);
}

int nvme_get_features_resv_persist(int fd, enum nvme_get_features_sel sel,
				   __u32 *result)
{
	return __nvme_get_features(fd, NVME_FEAT_FID_RESV_PERSIST, sel, result);
}

int nvme_get_features_resv_persist2(int fd, enum nvme_get_features_sel sel,
				    __u32 nsid, __u32 *result)
{
	struct nvme_get_features_args args = {
		.args_size = sizeof(args),
		.fd = fd,
		.fid = NVME_FEAT_FID_RESV_PERSIST,
		.nsid = nsid,
		.sel = sel,
		.uuidx = NVME_UUID_NONE,
		.timeout = NVME_DEFAULT_IOCTL_TIMEOUT,
		.result = result,
	};

	return nvme_get_features(&args);
}

int nvme_get_features_write_protect(int fd, __u32 nsid,
				    enum nvme_get_features_sel sel,
				    __u32 *result)
{
	struct nvme_get_features_args args = {
		.args_size = sizeof(args),
		.fd = fd,
		.fid = NVME_FEAT_FID_WRITE_PROTECT,
		.nsid = nsid,
		.sel = sel,
		.cdw11 = 0,
		.uuidx = NVME_UUID_NONE,
		.data_len = 0,
		.data = NULL,
		.timeout = NVME_DEFAULT_IOCTL_TIMEOUT,
		.result = result,
	};

	return nvme_get_features(&args);
}

int nvme_get_features_iocs_profile(int fd, enum nvme_get_features_sel sel,
				   __u32 *result)
{
	return __nvme_get_features(fd, NVME_FEAT_FID_IOCS_PROFILE, sel, result);
}

int nvme_format_nvm(struct nvme_format_nvm_args *args)
{
	const size_t size_v1 = sizeof_args(struct nvme_format_nvm_args, lbaf, __u64);
	const size_t size_v2 = sizeof_args(struct nvme_format_nvm_args, lbafu, __u64);
	__u32 cdw10;

	if (args->args_size < size_v1 || args->args_size > size_v2) {
		errno = EINVAL;
		return -1;
	}

	cdw10 = NVME_SET(args->lbaf, FORMAT_CDW10_LBAF) |
		NVME_SET(args->mset, FORMAT_CDW10_MSET) |
		NVME_SET(args->pi, FORMAT_CDW10_PI) |
		NVME_SET(args->pil, FORMAT_CDW10_PIL) |
		NVME_SET(args->ses, FORMAT_CDW10_SES);

	if (args->args_size == size_v2) {
		/* set lbafu extension */
		cdw10 |= NVME_SET(args->lbafu, FORMAT_CDW10_LBAFU);
	}

	struct nvme_passthru_cmd cmd = {
		.opcode		= nvme_admin_format_nvm,
		.nsid		= args->nsid,
		.cdw10		= cdw10,
		.timeout_ms	= args->timeout,
	};

	return nvme_submit_admin_passthru(args->fd, &cmd, args->result);
}

int nvme_ns_mgmt(struct nvme_ns_mgmt_args *args)
{
	const size_t size_v1 = sizeof_args(struct nvme_ns_mgmt_args, csi, __u64);
	const size_t size_v2 = sizeof_args(struct nvme_ns_mgmt_args, data, __u64);
	__u32 cdw10    = NVME_SET(args->sel, NAMESPACE_MGMT_CDW10_SEL);
	__u32 cdw11    = NVME_SET(args->csi, NAMESPACE_MGMT_CDW11_CSI);

	if (args->args_size < size_v1 || args->args_size > size_v2) {
		errno = EINVAL;
		return -1;
	}

	struct nvme_passthru_cmd cmd = {
		.nsid	    = args->nsid,
		.opcode	    = nvme_admin_ns_mgmt,
		.cdw10	    = cdw10,
		.cdw11	    = cdw11,
		.timeout_ms = args->timeout,
	};

	if (args->args_size == size_v2) {
		if (args->data) {
			cmd.data_len = sizeof(*args->data);
			cmd.addr = (__u64)(uintptr_t)args->data;
		}
	}
	else {
		if (args->ns) {
			cmd.data_len = sizeof(*args->ns);
			cmd.addr = (__u64)(uintptr_t)args->ns;
		}
	}
	return nvme_submit_admin_passthru(args->fd, &cmd, args->result);
}

int nvme_ns_attach(struct nvme_ns_attach_args *args)
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

	if (args->args_size < sizeof(*args)) {
		errno = EINVAL;
		return -1;
	}
	return nvme_submit_admin_passthru(args->fd, &cmd, args->result);
}

int nvme_fw_download(struct nvme_fw_download_args *args)
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

	if (args->args_size < sizeof(*args)) {
		errno = EINVAL;
		return -1;
	}
	return nvme_submit_admin_passthru(args->fd, &cmd, args->result);
}

int nvme_fw_commit(struct nvme_fw_commit_args *args)
{
	__u32 cdw10 = NVME_SET(args->slot, FW_COMMIT_CDW10_FS) |
			NVME_SET(args->action, FW_COMMIT_CDW10_CA) |
			NVME_SET(args->bpid, FW_COMMIT_CDW10_BPID);

	struct nvme_passthru_cmd cmd = {
		.opcode		= nvme_admin_fw_commit,
		.cdw10		= cdw10,
		.timeout_ms	= args->timeout,
	};

	if (args->args_size < sizeof(*args)) {
		errno = EINVAL;
		return -1;
	}
	return nvme_submit_admin_passthru(args->fd, &cmd, args->result);
}

int nvme_security_send(struct nvme_security_send_args *args)
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

	if (args->args_size < sizeof(*args)) {
		errno = EINVAL;
		return -1;
	}
	return nvme_submit_admin_passthru(args->fd, &cmd, args->result);
}

int nvme_security_receive(struct nvme_security_receive_args *args)
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

	if (args->args_size < sizeof(*args)) {
		errno = EINVAL;
		return -1;
	}
	return nvme_submit_admin_passthru(args->fd, &cmd, args->result);
}

int nvme_get_lba_status(struct nvme_get_lba_status_args *args)
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

	if (args->args_size < sizeof(*args)) {
		errno = EINVAL;
		return -1;
	}
	return nvme_submit_admin_passthru(args->fd, &cmd, args->result);
}

int nvme_directive_send(struct nvme_directive_send_args *args)
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

	if (args->args_size < sizeof(*args)) {
		errno = EINVAL;
		return -1;
	}
        return nvme_submit_admin_passthru(args->fd, &cmd, args->result);
}

int nvme_directive_send_id_endir(int fd, __u32 nsid, bool endir,
				 enum nvme_directive_dtype dtype,
				 struct nvme_id_directives *id)
{
	__u32 cdw12 = NVME_SET(dtype, DIRECTIVE_SEND_IDENTIFY_CDW12_DTYPE) |
		NVME_SET(endir, DIRECTIVE_SEND_IDENTIFY_CDW12_ENDIR);
	struct nvme_directive_send_args args = {
		.args_size = sizeof(args),
		.fd = fd,
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

	return nvme_directive_send(&args);
}

int nvme_directive_recv(struct nvme_directive_recv_args *args)
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

	if (args->args_size < sizeof(*args)) {
		errno = EINVAL;
		return -1;
	}
	return nvme_submit_admin_passthru(args->fd, &cmd, args->result);
}

int nvme_capacity_mgmt(struct nvme_capacity_mgmt_args *args)
{
	__u32 cdw10 = args->op | args->element_id << 16;

        struct nvme_passthru_cmd cmd = {
		.opcode		= nvme_admin_capacity_mgmt,
		.cdw10		= cdw10,
		.cdw11		= args->cdw11,
		.cdw12		= args->cdw12,
		.timeout_ms	= args->timeout,
	};

	if (args->args_size < sizeof(*args)) {
		errno = EINVAL;
		return -1;
	}
	return nvme_submit_admin_passthru(args->fd, &cmd, args->result);
}

int nvme_lockdown(struct nvme_lockdown_args *args)
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

	if (args->args_size < sizeof(*args)) {
		errno = EINVAL;
		return -1;
	}
	return nvme_submit_admin_passthru(args->fd, &cmd, args->result);
}

int nvme_set_property(struct nvme_set_property_args *args)
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

	if (args->args_size < sizeof(*args)) {
		errno = EINVAL;
		return -1;
	}
	return nvme_submit_admin_passthru(args->fd, &cmd, args->result);
}

int nvme_get_property(struct nvme_get_property_args *args)
{
	__u32 cdw10 = nvme_is_64bit_reg(args->offset);

	struct nvme_passthru_cmd64 cmd = {
		.opcode		= nvme_admin_fabrics,
		.nsid		= nvme_fabrics_type_property_get,
		.cdw10		= cdw10,
		.cdw11		= args->offset,
		.timeout_ms	= args->timeout,
	};

	if (args->args_size < sizeof(*args)) {
		errno = EINVAL;
		return -1;
	}
	return nvme_submit_admin_passthru64(args->fd, &cmd, args->value);
}

int nvme_sanitize_nvm(struct nvme_sanitize_nvm_args *args)
{
	const size_t size_v1 = sizeof_args(struct nvme_sanitize_nvm_args, nodas, __u64);
	const size_t size_v2 = sizeof_args(struct nvme_sanitize_nvm_args, emvs, __u64);
	__u32 cdw10, cdw11;

	if (args->args_size < size_v1 || args->args_size > size_v2) {
		errno = EINVAL;
		return -1;
	}

	cdw10 = NVME_SET(args->sanact, SANITIZE_CDW10_SANACT) |
		NVME_SET(!!args->ause, SANITIZE_CDW10_AUSE) |
		NVME_SET(args->owpass, SANITIZE_CDW10_OWPASS) |
		NVME_SET(!!args->oipbp, SANITIZE_CDW10_OIPBP) |
		NVME_SET(!!args->nodas, SANITIZE_CDW10_NODAS);

	if (args->args_size == size_v2)
		cdw10 |= NVME_SET(!!args->emvs, SANITIZE_CDW10_EMVS);

	cdw11 = args->ovrpat;

	struct nvme_passthru_cmd cmd = {
		.opcode		= nvme_admin_sanitize_nvm,
		.cdw10		= cdw10,
		.cdw11		= cdw11,
		.timeout_ms	= args->timeout,
	};

	return nvme_submit_admin_passthru(args->fd, &cmd, args->result);
}

int nvme_dev_self_test(struct nvme_dev_self_test_args *args)
{
	__u32 cdw10 = NVME_SET(args->stc, DEVICE_SELF_TEST_CDW10_STC);

	struct nvme_passthru_cmd cmd = {
		.opcode		= nvme_admin_dev_self_test,
		.nsid		= args->nsid,
		.cdw10		= cdw10,
		.timeout_ms	= args->timeout,
	};

	if (args->args_size < sizeof(*args)) {
		errno = EINVAL;
		return -1;
	}
	return nvme_submit_admin_passthru(args->fd, &cmd, args->result);
}

int nvme_virtual_mgmt(struct nvme_virtual_mgmt_args *args)
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

	if (args->args_size < sizeof(*args)) {
		errno = EINVAL;
		return -1;
	}
	return nvme_submit_admin_passthru(args->fd, &cmd, args->result);
}

int nvme_submit_io_passthru64(int fd, struct nvme_passthru_cmd64 *cmd,
			      __u64 *result)
{
	return nvme_submit_passthru64(fd, NVME_IOCTL_IO64_CMD, cmd, result);
}

int nvme_io_passthru64(int fd, __u8 opcode, __u8 flags, __u16 rsvd,
		       __u32 nsid, __u32 cdw2, __u32 cdw3, __u32 cdw10,
		       __u32 cdw11, __u32 cdw12, __u32 cdw13, __u32 cdw14,
		       __u32 cdw15, __u32 data_len, void *data, __u32 metadata_len,
		       void *metadata, __u32 timeout_ms, __u64 *result)
{
	return nvme_passthru64(fd, NVME_IOCTL_IO64_CMD, opcode, flags, rsvd,
			       nsid, cdw2, cdw3, cdw10, cdw11, cdw12, cdw13,
			       cdw14, cdw15, data_len, data, metadata_len, metadata,
			       timeout_ms, result);
}

int nvme_submit_io_passthru(int fd, struct nvme_passthru_cmd *cmd, __u32 *result)
{
	return nvme_submit_passthru(fd, NVME_IOCTL_IO_CMD, cmd, result);
}

int nvme_io_passthru(int fd, __u8 opcode, __u8 flags, __u16 rsvd,
		     __u32 nsid, __u32 cdw2, __u32 cdw3, __u32 cdw10,
		     __u32 cdw11, __u32 cdw12, __u32 cdw13, __u32 cdw14,
		     __u32 cdw15, __u32 data_len, void *data, __u32 metadata_len,
		     void *metadata, __u32 timeout_ms, __u32 *result)
{
	return nvme_passthru(fd, NVME_IOCTL_IO_CMD, opcode, flags, rsvd, nsid,
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
		errno = EINVAL;
		return -1;
	}

	*cmd_dw2 = cpu_to_be32(cdw2);
	*cmd_dw3 = cpu_to_be32(cdw3);
	*cmd_dw14 = cpu_to_be32(cdw14);
	return 0;
}

int nvme_io(struct nvme_io_args *args, __u8 opcode)
{
	const size_t size_v1 = sizeof_args(struct nvme_io_args, dsm, __u64);
	const size_t size_v2 = sizeof_args(struct nvme_io_args, pif, __u64);
	__u32 cdw2, cdw3, cdw10, cdw11, cdw12, cdw13, cdw14, cdw15;

	if (args->args_size < size_v1 || args->args_size > size_v2) {
		errno = EINVAL;
		return -1;
	}

	cdw10 = args->slba & 0xffffffff;
	cdw11 = args->slba >> 32;
	cdw12 = args->nlb | (args->control << 16);
	cdw13 = args->dsm | (args->dspec << 16);
	cdw15 = args->apptag | (args->appmask << 16);

	if (args->args_size == size_v1) {
		cdw2 = (args->storage_tag >> 32) & 0xffff;
		cdw3 = args->storage_tag & 0xffffffff;
		cdw14 = args->reftag;
	} else {
		if (nvme_set_var_size_tags(&cdw2, &cdw3, &cdw14,
				args->pif,
				args->sts,
				args->reftag_u64,
				args->storage_tag)) {
			errno = EINVAL;
			return -1;
		}
	}

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

	return nvme_submit_io_passthru(args->fd, &cmd, args->result);
}

int nvme_dsm(struct nvme_dsm_args *args)
{
	struct nvme_passthru_cmd cmd = {
		.opcode		= nvme_cmd_dsm,
		.nsid		= args->nsid,
		.addr		= (__u64)(uintptr_t)args->dsm,
		.data_len	= args->nr_ranges * sizeof(*args->dsm),
		.cdw10		= args->nr_ranges - 1,
		.cdw11		= args->attrs,
		.timeout_ms	= args->timeout,
	};

	if (args->args_size < sizeof(*args)) {
		errno = EINVAL;
		return -1;
	}
	return nvme_submit_io_passthru(args->fd, &cmd, args->result);
}

int nvme_copy(struct nvme_copy_args *args)
{
	const size_t size_v1 = sizeof_args(struct nvme_copy_args, format, __u64);
	const size_t size_v2 = sizeof_args(struct nvme_copy_args, ilbrt_u64, __u64);
	__u32 cdw3, cdw12, cdw14, data_len;

	if (args->args_size < size_v1 || args->args_size > size_v2) {
		errno = EINVAL;
		return -1;
	}

	cdw12 = ((args->nr - 1) & 0xff) | ((args->format & 0xf) <<  8) |
		((args->prinfor & 0xf) << 12) | ((args->dtype & 0xf) << 20) |
		((args->prinfow & 0xf) << 26) | ((args->fua & 0x1) << 30) |
		((args->lr & 0x1) << 31);

	if (args->args_size == size_v1) {
		cdw3 = 0;
		cdw14 = args->ilbrt;
	} else {
		cdw3 = (args->ilbrt_u64 >> 32) & 0xffffffff;
		cdw14 = args->ilbrt_u64 & 0xffffffff;
	}

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

	return nvme_submit_io_passthru(args->fd, &cmd, args->result);
}

int nvme_resv_acquire(struct nvme_resv_acquire_args *args)
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

	if (args->args_size < sizeof(*args)) {
		errno = EINVAL;
		return -1;
	}
	return nvme_submit_io_passthru(args->fd, &cmd, args->result);
}

int nvme_resv_register(struct nvme_resv_register_args *args)
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

	if (args->args_size < sizeof(*args)) {
		errno = EINVAL;
		return -1;
	}
	return nvme_submit_io_passthru(args->fd, &cmd, args->result);
}

int nvme_resv_release(struct nvme_resv_release_args *args)
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

	if (args->args_size < sizeof(*args)) {
		errno = EINVAL;
		return -1;
	}
	return nvme_submit_io_passthru(args->fd, &cmd, args->result);
}

int nvme_resv_report(struct nvme_resv_report_args *args)
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

	if (args->args_size < sizeof(*args)) {
		errno = EINVAL;
		return -1;
	}
	return nvme_submit_io_passthru(args->fd, &cmd, args->result);
}

int nvme_io_mgmt_recv(struct nvme_io_mgmt_recv_args *args)
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

	if (args->args_size < sizeof(*args)) {
		errno = EINVAL;
		return -1;
	}

	return nvme_submit_io_passthru(args->fd, &cmd, NULL);
}

int nvme_io_mgmt_send(struct nvme_io_mgmt_send_args *args)
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

	if (args->args_size < sizeof(*args)) {
		errno = EINVAL;
		return -1;
	}

	return nvme_submit_io_passthru(args->fd, &cmd, NULL);
}

int nvme_zns_mgmt_send(struct nvme_zns_mgmt_send_args *args)
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

	if (args->args_size < sizeof(*args)) {
		errno = EINVAL;
		return -1;
	}
	return nvme_submit_io_passthru(args->fd, &cmd, args->result);
}

int nvme_zns_mgmt_recv(struct nvme_zns_mgmt_recv_args *args)
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

	if (args->args_size < sizeof(*args)) {
		errno = EINVAL;
		return -1;
	}
	return nvme_submit_io_passthru(args->fd, &cmd, args->result);
}

int nvme_zns_append(struct nvme_zns_append_args *args)
{
	const size_t size_v1 = sizeof_args(struct nvme_zns_append_args, lbatm, __u64);
	const size_t size_v2 = sizeof_args(struct nvme_zns_append_args, ilbrt_u64, __u64);
	__u32 cdw3, cdw10, cdw11, cdw12, cdw14, cdw15;

	if (args->args_size < size_v1 || args->args_size > size_v2) {
		errno = EINVAL;
		return -1;
	}

	cdw10 = args->zslba & 0xffffffff;
	cdw11 = args->zslba >> 32;
	cdw12 = args->nlb | (args->control << 16);
	cdw15 = args->lbat | (args->lbatm << 16);

	if (args->args_size == size_v1) {
		cdw3 = 0;
		cdw14 = args->ilbrt;
	} else {
		cdw3 = (args->ilbrt_u64 >> 32) & 0xffffffff;
		cdw14 = args->ilbrt_u64 & 0xffffffff;
	}

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

	return nvme_submit_io_passthru64(args->fd, &cmd, args->result);
}

int nvme_dim_send(struct nvme_dim_args *args)
{
	__u32 cdw10 = NVME_SET(args->tas, DIM_TAS);

	struct nvme_passthru_cmd  cmd = {
		.opcode     = nvme_admin_discovery_info_mgmt,
		.cdw10      = cdw10,
		.addr       = (__u64)(uintptr_t)args->data,
		.data_len   = args->data_len,
		.timeout_ms = args->timeout,
	};

	if (args->args_size < sizeof(*args)) {
		errno = EINVAL;
		return -1;
	}

	return nvme_submit_admin_passthru(args->fd, &cmd, args->result);
}
