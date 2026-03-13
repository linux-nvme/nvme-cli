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

int nvme_fw_download_seq(struct nvme_transport_handle *hdl, bool ish,
		__u32 size, __u32 xfer, __u32 offset, void *buf)
{
	struct nvme_passthru_cmd cmd;
	void *data = buf;
	int err = 0;

	if (ish && nvme_transport_handle_is_mi(hdl))
		nvme_init_mi_cmd_flags(&cmd, ish);

	while (size > 0) {
		__u32 chunk = min(xfer, size);

		err = nvme_init_fw_download(&cmd, data, chunk, offset);
		if (err)
			break;
		err = nvme_submit_admin_passthru(hdl, &cmd);
		if (err)
			break;

		data += chunk;
		size -= chunk;
		offset += chunk;
	}

	return err;
}

int nvme_set_etdas(struct nvme_transport_handle *hdl, bool *changed)
{
	struct nvme_feat_host_behavior da4;
	struct nvme_passthru_cmd cmd;
	int err;

	nvme_init_get_features_host_behavior(&cmd, 0, &da4);
	err = nvme_submit_admin_passthru(hdl, &cmd);
	if (err)
		return err;

	if (da4.etdas) {
		*changed = false;
		return 0;
	}

	da4.etdas = 1;

	nvme_init_set_features_host_behavior(&cmd, false, &da4);
	err = nvme_submit_admin_passthru(hdl, &cmd);
	if (err)
		return err;

	*changed = true;
	return 0;
}

int nvme_clear_etdas(struct nvme_transport_handle *hdl, bool *changed)
{
	struct nvme_feat_host_behavior da4;
	struct nvme_passthru_cmd cmd;
	int err;

	nvme_init_get_features_host_behavior(&cmd, 0, &da4);
	err = nvme_submit_admin_passthru(hdl, &cmd);
	if (err)
		return err;

	if (!da4.etdas) {
		*changed = false;
		return 0;
	}

	da4.etdas = 0;
	nvme_init_set_features_host_behavior(&cmd, false, &da4);
	err = nvme_submit_admin_passthru(hdl, &cmd);
	if (err)
		return err;

	*changed = true;
	return 0;
}

int nvme_get_uuid_list(struct nvme_transport_handle *hdl,
		struct nvme_id_uuid_list *uuid_list)
{
	struct nvme_passthru_cmd cmd;
	struct nvme_id_ctrl ctrl;
	int err;

	memset(&ctrl, 0, sizeof(struct nvme_id_ctrl));
	nvme_init_identify_ctrl(&cmd, &ctrl);
	err = nvme_submit_admin_passthru(hdl, &cmd);
	if (err) {
		nvme_msg(hdl->ctx, LOG_ERR,
			 "ERROR: nvme_identify_ctrl() failed 0x%x\n", err);
		return err;
	}

	if ((ctrl.ctratt & NVME_CTRL_CTRATT_UUID_LIST) ==
			NVME_CTRL_CTRATT_UUID_LIST) {
		nvme_init_identify_uuid_list(&cmd, uuid_list);
		err = nvme_submit_admin_passthru(hdl, &cmd);
	}

	return err;
}

int nvme_get_telemetry_max(struct nvme_transport_handle *hdl,
		enum nvme_telemetry_da *da, size_t *data_tx)
{
	_cleanup_free_ struct nvme_id_ctrl *id_ctrl = NULL;
	struct nvme_passthru_cmd cmd;
	int err;

	id_ctrl = __nvme_alloc(sizeof(*id_ctrl));
	if (!id_ctrl)
		return -ENOMEM;

	nvme_init_identify_ctrl(&cmd, id_ctrl);
	err = nvme_submit_admin_passthru(hdl, &cmd);
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

int nvme_get_telemetry_log(struct nvme_transport_handle *hdl, bool create,
		bool ctrl, bool rae, size_t max_data_tx,
		enum nvme_telemetry_da da, struct nvme_telemetry_log **buf,
		size_t *size)
{
	static const __u32 xfer = NVME_LOG_TELEM_BLOCK_SIZE;
	struct nvme_telemetry_log *telem;
	struct nvme_passthru_cmd cmd;
	_cleanup_free_ void *log = NULL;
	void *tmp;
	int err;
	size_t dalb;

	*size = 0;

	log = __nvme_alloc(xfer);
	if (!log)
		return -ENOMEM;

	if (ctrl) {
		nvme_init_get_log_telemetry_ctrl(&cmd, 0, log, xfer);
		err = nvme_get_log(hdl, &cmd, true, xfer);
	} else {
		if (create) {
			nvme_init_get_log_create_telemetry_host_mcda(&cmd,
				da, log);
			err = nvme_get_log(hdl, &cmd, false, xfer);
		} else {
			nvme_init_get_log_telemetry_host(&cmd, 0, log, xfer);
			err = nvme_get_log(hdl, &cmd, false, xfer);
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
	tmp = __nvme_realloc(log, *size);
	if (!tmp)
		return -ENOMEM;
	log = tmp;

	if (ctrl)
		nvme_init_get_log_telemetry_ctrl(&cmd, 0, log, *size);
	else
		nvme_init_get_log_telemetry_host(&cmd, 0, log, *size);
	err = nvme_get_log(hdl, &cmd, rae, max_data_tx);
	if (err)
		return err;

	*buf = log;
	log = NULL;
	return 0;
}

static int nvme_check_get_telemetry_log(struct nvme_transport_handle *hdl,
		bool create, bool ctrl, bool rae,
		struct nvme_telemetry_log **log, enum nvme_telemetry_da da,
		size_t *size)
{
	enum nvme_telemetry_da max_da = 0;
	int err;

	err = nvme_get_telemetry_max(hdl, &max_da, NULL);
	if (err)
		return err;

	if (da > max_da)
		return -ENOENT;

	return nvme_get_telemetry_log(hdl, create, ctrl, rae, 4096, da,
		log, size);
}


int nvme_get_ctrl_telemetry(struct nvme_transport_handle *hdl, bool rae,
		struct nvme_telemetry_log **log,
		enum nvme_telemetry_da da, size_t *size)
{
	return nvme_check_get_telemetry_log(hdl, false, true, rae, log,
		da, size);
}

int nvme_get_host_telemetry(struct nvme_transport_handle *hdl,
		struct nvme_telemetry_log **log,
		enum nvme_telemetry_da da, size_t *size)
{
	return nvme_check_get_telemetry_log(hdl, false, false, false, log,
		da, size);
}

int nvme_get_new_host_telemetry(struct nvme_transport_handle *hdl,
		struct nvme_telemetry_log **log,
		enum nvme_telemetry_da da, size_t *size)
{
	return nvme_check_get_telemetry_log(hdl, true, false, false, log,
		da, size);
}

int nvme_get_lba_status_log(struct nvme_transport_handle *hdl, bool rae,
		struct nvme_lba_status_log **log)
{
	_cleanup_free_ struct nvme_lba_status_log *buf = NULL;
	struct nvme_passthru_cmd cmd;
	__u32 size;
	void *tmp;
	int err;

	buf = malloc(sizeof(*buf));
	if (!buf)
		return -ENOMEM;

	nvme_init_get_log_lba_status(&cmd, 0, log, sizeof(*buf));
	err = nvme_get_log(hdl, &cmd, true, sizeof(*buf));
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
	err = nvme_get_log(hdl, &cmd, rae, NVME_LOG_PAGE_PDU_SIZE);
	if (err) {
		*log = NULL;
		return err;
	}

	*log = buf;
	buf = NULL;
	return 0;
}

static int nvme_ns_attachment(struct nvme_transport_handle *hdl, bool ish,
		__u32 nsid, __u16 num_ctrls, __u16 *ctrlist, bool attach)
{
	struct nvme_ctrl_list cntlist = { 0 };
	struct nvme_passthru_cmd cmd;

	nvme_init_ctrl_list(&cntlist, num_ctrls, ctrlist);
	if (ish && nvme_transport_handle_is_mi(hdl))
		nvme_init_mi_cmd_flags(&cmd, ish);

	if (attach)
		nvme_init_ns_attach_ctrls(&cmd, nsid, &cntlist);
	else
		nvme_init_ns_detach_ctrls(&cmd, nsid, &cntlist);

	return nvme_submit_admin_passthru(hdl, &cmd);
}

int nvme_namespace_attach_ctrls(struct nvme_transport_handle *hdl, bool ish,
		__u32 nsid, __u16 num_ctrls, __u16 *ctrlist)
{
	return nvme_ns_attachment(hdl, ish, nsid, num_ctrls, ctrlist, true);
}

int nvme_namespace_detach_ctrls(struct nvme_transport_handle *hdl, bool ish,
		__u32 nsid, __u16 num_ctrls, __u16 *ctrlist)
{
	return nvme_ns_attachment(hdl, ish, nsid, num_ctrls, ctrlist, false);
}

size_t nvme_get_ana_log_len_from_id_ctrl(const struct nvme_id_ctrl *id_ctrl,
					 bool rgo)
{
	__u32 nanagrpid = le32_to_cpu(id_ctrl->nanagrpid);
	size_t size = sizeof(struct nvme_ana_log) +
		nanagrpid * sizeof(struct nvme_ana_group_desc);

	return rgo ? size : size + le32_to_cpu(id_ctrl->mnan) * sizeof(__le32);
}

int nvme_get_ana_log_len(struct nvme_transport_handle *hdl, size_t *analen)
{
	_cleanup_free_ struct nvme_id_ctrl *ctrl = NULL;
	struct nvme_passthru_cmd cmd;
	int ret;

	ctrl = __nvme_alloc(sizeof(*ctrl));
	if (!ctrl)
		return -ENOMEM;

	nvme_init_identify_ctrl(&cmd, ctrl);
	ret = nvme_submit_admin_passthru(hdl, &cmd);
	if (ret)
		return ret;

	*analen = nvme_get_ana_log_len_from_id_ctrl(ctrl, false);
	return 0;
}

int nvme_get_logical_block_size(struct nvme_transport_handle *hdl,
		__u32 nsid, int *blksize)
{
	_cleanup_free_ struct nvme_id_ns *ns = NULL;
	struct nvme_passthru_cmd cmd;
	__u8 flbas;
	int ret;

	ns = __nvme_alloc(sizeof(*ns));
	if (!ns)
		return -ENOMEM;

	nvme_init_identify_ns(&cmd, nsid, ns);
	ret = nvme_submit_admin_passthru(hdl, &cmd);
	if (ret)
		return ret;

	nvme_id_ns_flbas_to_lbaf_inuse(ns->flbas, &flbas);
	*blksize = 1 << ns->lbaf[flbas].ds;

	return 0;
}

static inline void nvme_init_copy_range_elbt(__u8 *elbt, __u64 eilbrt)
{
	int i;

	for (i = 0; i < 8; i++)
		elbt[9 - i] = (eilbrt >> (8 * i)) & 0xff;
	elbt[1] = 0;
	elbt[0] = 0;
}

void nvme_init_copy_range(struct nvme_copy_range *copy, __u16 *nlbs,
			  __u64 *slbas, __u32 *elbts, __u32 *elbatms,
			  __u32 *elbats, __u16 nr)
{
	int i;

	for (i = 0; i < nr; i++) {
		copy[i].nlb = cpu_to_le16(nlbs[i]);
		copy[i].slba = cpu_to_le64(slbas[i]);
		copy[i].elbt = cpu_to_be32(elbts[i]);
		copy[i].elbatm = cpu_to_le16(elbatms[i]);
		copy[i].elbat = cpu_to_le16(elbats[i]);
	}
}

void nvme_init_copy_range_f1(struct nvme_copy_range_f1 *copy, __u16 *nlbs,
			  __u64 *slbas, __u64 *eilbrts, __u32 *elbatms,
			  __u32 *elbats, __u16 nr)
{
	int i;

	for (i = 0; i < nr; i++) {
		copy[i].nlb = cpu_to_le16(nlbs[i]);
		copy[i].slba = cpu_to_le64(slbas[i]);
		copy[i].elbatm = cpu_to_le16(elbatms[i]);
		copy[i].elbat = cpu_to_le16(elbats[i]);
		nvme_init_copy_range_elbt(copy[i].elbt, eilbrts[i]);
	}
}

void nvme_init_copy_range_f2(struct nvme_copy_range_f2 *copy, __u32 *snsids,
			  __u16 *nlbs, __u64 *slbas, __u16 *sopts,
			  __u32 *elbts, __u32 *elbatms, __u32 *elbats,
			  __u16 nr)
{
	int i;

	for (i = 0; i < nr; i++) {
		copy[i].snsid = cpu_to_le32(snsids[i]);
		copy[i].nlb = cpu_to_le16(nlbs[i]);
		copy[i].slba = cpu_to_le64(slbas[i]);
		copy[i].sopt = cpu_to_le16(sopts[i]);
		copy[i].elbt = cpu_to_be32(elbts[i]);
		copy[i].elbatm = cpu_to_le16(elbatms[i]);
		copy[i].elbat = cpu_to_le16(elbats[i]);
	}
}

void nvme_init_copy_range_f3(struct nvme_copy_range_f3 *copy, __u32 *snsids,
			  __u16 *nlbs, __u64 *slbas, __u16 *sopts,
			  __u64 *eilbrts, __u32 *elbatms, __u32 *elbats,
			  __u16 nr)
{
	int i;

	for (i = 0; i < nr; i++) {
		copy[i].snsid = cpu_to_le32(snsids[i]);
		copy[i].nlb = cpu_to_le16(nlbs[i]);
		copy[i].slba = cpu_to_le64(slbas[i]);
		copy[i].sopt = cpu_to_le16(sopts[i]);
		copy[i].elbatm = cpu_to_le16(elbatms[i]);
		copy[i].elbat = cpu_to_le16(elbats[i]);
		nvme_init_copy_range_elbt(copy[i].elbt, eilbrts[i]);
	}
}

void nvme_init_dsm_range(struct nvme_dsm_range *dsm, __u32 *ctx_attrs,
			 __u32 *llbas, __u64 *slbas, __u16 nr_ranges)
{
	int i;

	for (i = 0; i < nr_ranges; i++) {
		dsm[i].cattr = cpu_to_le32(ctx_attrs[i]);
		dsm[i].nlb = cpu_to_le32(llbas[i]);
		dsm[i].slba = cpu_to_le64(slbas[i]);
	}
}

void nvme_init_ctrl_list(struct nvme_ctrl_list *cntlist, __u16 num_ctrls,
			  __u16 *ctrlist)
{
	int i;

	cntlist->num = cpu_to_le16(num_ctrls);
	for (i = 0; i < num_ctrls; i++)
		cntlist->identifier[i] = cpu_to_le16(ctrlist[i]);
}

int nvme_get_feature_length(int fid, __u32 cdw11, enum nvme_data_tfr dir,
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

int nvme_get_directive_receive_length(enum nvme_directive_dtype dtype,
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
