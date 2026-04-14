// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libnvme.
 * Copyright (c) 2020 Western Digital Corporation or its affiliates.
 *
 * Authors: Keith Busch <keith.busch@wdc.com>
 *	    Chaitanya Kulkarni <chaitanya.kulkarni@wdc.com>
 */

#include <ccan/endian/endian.h>
#include <ccan/minmax/minmax.h>

#include <libnvme.h>

#include "cleanup.h"
#include "private.h"
#include "compiler-attributes.h"

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

__public int libnvme_get_log(struct libnvme_transport_handle *hdl,
		struct libnvme_passthru_cmd *cmd, bool rae,
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

		if (hdl->uring_enabled)
			ret = libnvme_submit_admin_passthru_async(hdl, cmd);
		else
			ret = libnvme_submit_admin_passthru(hdl, cmd);
		if (ret)
			return ret;

		offset += xfer;
		ptr += xfer;
	} while (offset < data_len);

	if (hdl->uring_enabled) {
		ret = libnvme_wait_complete_passthru(hdl);
		if (ret)
			return ret;
	}

	return 0;
}

static int read_ana_chunk(struct libnvme_transport_handle *hdl,
		enum nvme_log_ana_lsp lsp, bool rae,
		__u8 *log, __u8 **read, __u8 *to_read, __u8 *log_end)
{
	struct libnvme_passthru_cmd cmd;

	if (to_read > log_end)
		return -ENOSPC;

	while (*read < to_read) {
		__u32 len = min_t(__u32, log_end - *read,
			NVME_LOG_PAGE_PDU_SIZE);
		int ret;

		nvme_init_get_log_ana(&cmd, lsp, *read - log, *read, len);
		ret = libnvme_get_log(hdl, &cmd, rae, NVME_LOG_PAGE_PDU_SIZE);
		if (ret)
			return ret;

		*read += len;
	}
	return 0;
}

static int try_read_ana(struct libnvme_transport_handle *hdl,
		enum nvme_log_ana_lsp lsp, bool rae,
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

__public int libnvme_get_ana_log_atomic(struct libnvme_transport_handle *hdl,
		bool rae, bool rgo, struct nvme_ana_log *log, __u32 *len,
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

__public int libnvme_set_etdas(struct libnvme_transport_handle *hdl, bool *changed)
{
	struct nvme_feat_host_behavior da4;
	struct libnvme_passthru_cmd cmd;
	int err;

	nvme_init_get_features_host_behavior(&cmd, 0, &da4);
	err = libnvme_submit_admin_passthru(hdl, &cmd);
	if (err)
		return err;

	if (da4.etdas) {
		*changed = false;
		return 0;
	}

	da4.etdas = 1;

	nvme_init_set_features_host_behavior(&cmd, false, &da4);
	err = libnvme_submit_admin_passthru(hdl, &cmd);
	if (err)
		return err;

	*changed = true;
	return 0;
}

__public int libnvme_clear_etdas(struct libnvme_transport_handle *hdl, bool *changed)
{
	struct nvme_feat_host_behavior da4;
	struct libnvme_passthru_cmd cmd;
	int err;

	nvme_init_get_features_host_behavior(&cmd, 0, &da4);
	err = libnvme_submit_admin_passthru(hdl, &cmd);
	if (err)
		return err;

	if (!da4.etdas) {
		*changed = false;
		return 0;
	}

	da4.etdas = 0;
	nvme_init_set_features_host_behavior(&cmd, false, &da4);
	err = libnvme_submit_admin_passthru(hdl, &cmd);
	if (err)
		return err;

	*changed = true;
	return 0;
}

__public int libnvme_get_uuid_list(struct libnvme_transport_handle *hdl,
		struct nvme_id_uuid_list *uuid_list)
{
	struct libnvme_passthru_cmd cmd;
	struct nvme_id_ctrl ctrl;
	int err;

	memset(&ctrl, 0, sizeof(struct nvme_id_ctrl));
	nvme_init_identify_ctrl(&cmd, &ctrl);
	err = libnvme_submit_admin_passthru(hdl, &cmd);
	if (err) {
		libnvme_msg(hdl->ctx, LOG_ERR,
			 "ERROR: nvme_identify_ctrl() failed 0x%x\n", err);
		return err;
	}

	if ((ctrl.ctratt & NVME_CTRL_CTRATT_UUID_LIST) ==
			NVME_CTRL_CTRATT_UUID_LIST) {
		nvme_init_identify_uuid_list(&cmd, uuid_list);
		err = libnvme_submit_admin_passthru(hdl, &cmd);
	}

	return err;
}

__public int libnvme_get_telemetry_max(struct libnvme_transport_handle *hdl,
		enum nvme_telemetry_da *da, size_t *data_tx)
{
	__cleanup_free struct nvme_id_ctrl *id_ctrl = NULL;
	struct libnvme_passthru_cmd cmd;
	int err;

	id_ctrl = __libnvme_alloc(sizeof(*id_ctrl));
	if (!id_ctrl)
		return -ENOMEM;

	nvme_init_identify_ctrl(&cmd, id_ctrl);
	err = libnvme_submit_admin_passthru(hdl, &cmd);
	if (err)
		return err;

	if (data_tx) {
		*data_tx = id_ctrl->mdts;
		if (id_ctrl->mdts) {
			/*
			 * assuming CAP.MPSMIN is zero minimum Memory Page Size
			 * is at least 4096 bytes
			 */
			*data_tx = (1 << id_ctrl->mdts) * 4096;
		}
	}
	if (da) {
		if (id_ctrl->lpa & 0x8)
			*da = NVME_TELEMETRY_DA_3;
		if (id_ctrl->lpa & 0x40)
			*da = NVME_TELEMETRY_DA_4;

	}
	return err;
}

__public int libnvme_get_telemetry_log(struct libnvme_transport_handle *hdl, bool create,
		bool ctrl, bool rae, size_t max_data_tx,
		enum nvme_telemetry_da da, struct nvme_telemetry_log **buf,
		size_t *size)
{
	static const __u32 xfer = NVME_LOG_TELEM_BLOCK_SIZE;
	struct nvme_telemetry_log *telem;
	struct libnvme_passthru_cmd cmd;
	__cleanup_free void *log = NULL;
	void *tmp;
	int err;
	size_t dalb;

	*size = 0;

	log = __libnvme_alloc(xfer);
	if (!log)
		return -ENOMEM;

	if (ctrl) {
		nvme_init_get_log_telemetry_ctrl(&cmd, 0, log, xfer);
		err = libnvme_get_log(hdl, &cmd, true, xfer);
	} else {
		if (create) {
			nvme_init_get_log_create_telemetry_host_mcda(&cmd,
				da, log);
			err = libnvme_get_log(hdl, &cmd, false, xfer);
		} else {
			nvme_init_get_log_telemetry_host(&cmd, 0, log, xfer);
			err = libnvme_get_log(hdl, &cmd, false, xfer);
		}
	}

	if (err)
		return err;

	telem = log;
	if (ctrl && !telem->ctrlavail) {
		*buf = log;
		log = NULL;
		*size = xfer;
		return 0;
	}

	switch (da) {
	case NVME_TELEMETRY_DA_1:
		dalb = le16_to_cpu(telem->dalb1);
		break;
	case NVME_TELEMETRY_DA_2:
		dalb = le16_to_cpu(telem->dalb2);
		break;
	case NVME_TELEMETRY_DA_3:
		/* dalb3 >= dalb2 >= dalb1 */
		dalb = le16_to_cpu(telem->dalb3);
		break;
	case NVME_TELEMETRY_DA_4:
		dalb = le32_to_cpu(telem->dalb4);
		break;
	default:
		return -EINVAL;
	}

	if (dalb == 0)
		return -ENOENT;

	*size = (dalb + 1) * xfer;
	tmp = __libnvme_realloc(log, *size);
	if (!tmp)
		return -ENOMEM;
	log = tmp;

	if (ctrl)
		nvme_init_get_log_telemetry_ctrl(&cmd, 0, log, *size);
	else
		nvme_init_get_log_telemetry_host(&cmd, 0, log, *size);
	err = libnvme_get_log(hdl, &cmd, rae, max_data_tx);
	if (err)
		return err;

	*buf = log;
	log = NULL;
	return 0;
}

static int nvme_check_get_telemetry_log(struct libnvme_transport_handle *hdl,
		bool create, bool ctrl, bool rae,
		struct nvme_telemetry_log **log, enum nvme_telemetry_da da,
		size_t *size)
{
	enum nvme_telemetry_da max_da = 0;
	int err;

	err = libnvme_get_telemetry_max(hdl, &max_da, NULL);
	if (err)
		return err;

	if (da > max_da)
		return -ENOENT;

	return libnvme_get_telemetry_log(hdl, create, ctrl, rae, 4096, da,
		log, size);
}


__public int libnvme_get_ctrl_telemetry(struct libnvme_transport_handle *hdl, bool rae,
		struct nvme_telemetry_log **log,
		enum nvme_telemetry_da da, size_t *size)
{
	return nvme_check_get_telemetry_log(hdl, false, true, rae, log,
		da, size);
}

__public int libnvme_get_host_telemetry(struct libnvme_transport_handle *hdl,
		struct nvme_telemetry_log **log,
		enum nvme_telemetry_da da, size_t *size)
{
	return nvme_check_get_telemetry_log(hdl, false, false, false, log,
		da, size);
}

__public int libnvme_get_new_host_telemetry(struct libnvme_transport_handle *hdl,
		struct nvme_telemetry_log **log,
		enum nvme_telemetry_da da, size_t *size)
{
	return nvme_check_get_telemetry_log(hdl, true, false, false, log,
		da, size);
}

int libnvme_get_lba_status_log(struct libnvme_transport_handle *hdl, bool rae,
		struct nvme_lba_status_log **log)
{
	__cleanup_free struct nvme_lba_status_log *buf = NULL;
	struct libnvme_passthru_cmd cmd;
	__u32 size;
	void *tmp;
	int err;

	buf = malloc(sizeof(*buf));
	if (!buf)
		return -ENOMEM;

	nvme_init_get_log_lba_status(&cmd, 0, log, sizeof(*buf));
	err = libnvme_get_log(hdl, &cmd, true, sizeof(*buf));
	if (err) {
		*log = NULL;
		return err;
	}

	size = le32_to_cpu(buf->lslplen);
	if (!size) {
		*log = buf;
		buf = NULL;
		return 0;
	}

	tmp = realloc(buf, size);
	if (!tmp) {
		*log = NULL;
		return -ENOMEM;
	}
	buf = tmp;

	nvme_init_get_log_lba_status(&cmd, 0, buf, size);
	err = libnvme_get_log(hdl, &cmd, rae, NVME_LOG_PAGE_PDU_SIZE);
	if (err) {
		*log = NULL;
		return err;
	}

	*log = buf;
	buf = NULL;
	return 0;
}

__public size_t libnvme_get_ana_log_len_from_id_ctrl(const struct nvme_id_ctrl *id_ctrl,
					 bool rgo)
{
	__u32 nanagrpid = le32_to_cpu(id_ctrl->nanagrpid);
	size_t size = sizeof(struct nvme_ana_log) +
		nanagrpid * sizeof(struct nvme_ana_group_desc);

	return rgo ? size : size + le32_to_cpu(id_ctrl->mnan) * sizeof(__le32);
}

__public int libnvme_get_ana_log_len(struct libnvme_transport_handle *hdl, size_t *analen)
{
	__cleanup_free struct nvme_id_ctrl *ctrl = NULL;
	struct libnvme_passthru_cmd cmd;
	int ret;

	ctrl = __libnvme_alloc(sizeof(*ctrl));
	if (!ctrl)
		return -ENOMEM;

	nvme_init_identify_ctrl(&cmd, ctrl);
	ret = libnvme_submit_admin_passthru(hdl, &cmd);
	if (ret)
		return ret;

	*analen = libnvme_get_ana_log_len_from_id_ctrl(ctrl, false);
	return 0;
}

__public int libnvme_get_logical_block_size(struct libnvme_transport_handle *hdl,
		__u32 nsid, int *blksize)
{
	__cleanup_free struct nvme_id_ns *ns = NULL;
	struct libnvme_passthru_cmd cmd;
	__u8 flbas;
	int ret;

	ns = __libnvme_alloc(sizeof(*ns));
	if (!ns)
		return -ENOMEM;

	nvme_init_identify_ns(&cmd, nsid, ns);
	ret = libnvme_submit_admin_passthru(hdl, &cmd);
	if (ret)
		return ret;

	nvme_id_ns_flbas_to_lbaf_inuse(ns->flbas, &flbas);
	*blksize = 1 << ns->lbaf[flbas].ds;

	return 0;
}

__public int libnvme_get_feature_length(int fid, __u32 cdw11, enum nvme_data_tfr dir,
			     __u32 *len)
{
	switch (fid) {
	case NVME_FEAT_FID_LBA_RANGE:
		*len = sizeof(struct nvme_lba_range_type);
		break;
	case NVME_FEAT_FID_AUTO_PST:
		*len = sizeof(struct nvme_feat_auto_pst);
		break;
	case NVME_FEAT_FID_PLM_CONFIG:
		*len = sizeof(struct nvme_plm_config);
		break;
	case NVME_FEAT_FID_TIMESTAMP:
		*len = sizeof(struct nvme_timestamp);
		break;
	case NVME_FEAT_FID_HOST_BEHAVIOR:
		*len = sizeof(struct nvme_feat_host_behavior);
		break;
	case NVME_FEAT_FID_HOST_ID:
		*len = (cdw11 & 0x1) ? 16 : 8;
		break;
	case NVME_FEAT_FID_HOST_MEM_BUF:
		if (dir == NVME_DATA_TFR_HOST_TO_CTRL) {
			*len = 0;
			break;
		}
		*len = sizeof(struct nvme_host_mem_buf_attrs);
		break;
	case NVME_FEAT_FID_ARBITRATION:
	case NVME_FEAT_FID_POWER_MGMT:
	case NVME_FEAT_FID_TEMP_THRESH:
	case NVME_FEAT_FID_ERR_RECOVERY:
	case NVME_FEAT_FID_VOLATILE_WC:
	case NVME_FEAT_FID_NUM_QUEUES:
	case NVME_FEAT_FID_IRQ_COALESCE:
	case NVME_FEAT_FID_IRQ_CONFIG:
	case NVME_FEAT_FID_WRITE_ATOMIC:
	case NVME_FEAT_FID_ASYNC_EVENT:
	case NVME_FEAT_FID_KATO:
	case NVME_FEAT_FID_HCTM:
	case NVME_FEAT_FID_NOPSC:
	case NVME_FEAT_FID_RRL:
	case NVME_FEAT_FID_PLM_WINDOW:
	case NVME_FEAT_FID_LBA_STS_INTERVAL:
	case NVME_FEAT_FID_SANITIZE:
	case NVME_FEAT_FID_ENDURANCE_EVT_CFG:
	case NVME_FEAT_FID_SW_PROGRESS:
	case NVME_FEAT_FID_RESV_MASK:
	case NVME_FEAT_FID_RESV_PERSIST:
	case NVME_FEAT_FID_WRITE_PROTECT:
	case NVME_FEAT_FID_POWER_LIMIT:
	case NVME_FEAT_FID_POWER_MEASUREMENT:
		*len = 0;
		break;
	case NVME_FEAT_FID_ENH_CTRL_METADATA:
	case NVME_FEAT_FID_CTRL_METADATA:
	case NVME_FEAT_FID_NS_METADATA:
		*len = sizeof(struct nvme_host_metadata);
		break;
	case NVME_FEAT_FID_PERF_CHARACTERISTICS:
		*len = sizeof(struct nvme_perf_characteristics);
		break;
	case NVME_FEAT_FID_FDP_EVENTS:
		*len = NVME_FEAT_FDPE_NOET_MASK *
			sizeof(struct nvme_fdp_supported_event_desc);
		break;
	default:
		return -EINVAL;
	}
	return 0;
}

__public int libnvme_get_directive_receive_length(enum nvme_directive_dtype dtype,
		enum nvme_directive_receive_doper doper, __u32 *len)
{
	switch (dtype) {
	case NVME_DIRECTIVE_DTYPE_IDENTIFY:
		switch (doper) {
		case NVME_DIRECTIVE_RECEIVE_IDENTIFY_DOPER_PARAM:
			*len = sizeof(struct nvme_id_directives);
			return 0;
		default:
			return -EINVAL;
		}
	case NVME_DIRECTIVE_DTYPE_STREAMS:
		switch (doper) {
		case NVME_DIRECTIVE_RECEIVE_STREAMS_DOPER_PARAM:
			*len = sizeof(struct nvme_streams_directive_params);
			return 0;
		case NVME_DIRECTIVE_RECEIVE_STREAMS_DOPER_STATUS:
			*len = (128 * 1024) * sizeof(__le16);
			return 0;
		case NVME_DIRECTIVE_RECEIVE_STREAMS_DOPER_RESOURCE:
			*len = 0;
			return 0;
		default:
			return -EINVAL;
		}
	default:
		return -EINVAL;
	}
}
