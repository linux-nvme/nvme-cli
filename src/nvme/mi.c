// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libnvme.
 * Copyright (c) 2021 Code Construct Pty Ltd
 *
 * Authors: Jeremy Kerr <jk@codeconstruct.com.au>
 */

#include <errno.h>
#include <stdlib.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>

#include <ccan/array_size/array_size.h>
#include <ccan/endian/endian.h>

#include "log.h"
#include "mi.h"
#include "private.h"

static const int default_timeout = 1000; /* milliseconds; endpoints may
					    override */

static bool nvme_mi_probe_enabled_default(void)
{
	char *val;

	val = getenv("LIBNVME_MI_PROBE_ENABLED");
	if (!val)
		return true;

	return strcmp(val, "0") &&
		strcasecmp(val, "false") &&
		strncasecmp(val, "disable", 7);

}

/* MI-equivalent of nvme_create_root, but avoids clashing symbol names
 * when linking against both libnvme and libnvme-mi.
 */
nvme_root_t nvme_mi_create_root(FILE *fp, int log_level)
{
	struct nvme_root *r = calloc(1, sizeof(*r));

	if (!r) {
		return NULL;
	}
	r->log_level = log_level;
	r->fp = stderr;
	r->mi_probe_enabled = nvme_mi_probe_enabled_default();
	if (fp)
		r->fp = fp;
	list_head_init(&r->hosts);
	list_head_init(&r->endpoints);
	return r;
}

void nvme_mi_free_root(nvme_root_t root)
{
	nvme_mi_ep_t ep, tmp;

	nvme_mi_for_each_endpoint_safe(root, ep, tmp)
		nvme_mi_close(ep);

	free(root);
}

void nvme_mi_set_probe_enabled(nvme_root_t root, bool enabled)
{
	root->mi_probe_enabled = enabled;
}

static void nvme_mi_record_resp_time(struct nvme_mi_ep *ep)
{
	int rc;

	rc = clock_gettime(CLOCK_MONOTONIC, &ep->last_resp_time);
	ep->last_resp_time_valid = !rc;
}

static bool nvme_mi_compare_vid_mn(struct nvme_mi_ep *ep,
				   struct nvme_id_ctrl *id,
				   __u16 vid, const char *mn)

{
	int len;

	len = strlen(mn);
	if (len >= sizeof(id->mn)) {
		nvme_msg(ep->root, LOG_ERR,
			 "Internal error: invalid model number for %s\n",
			 __func__);
		return false;
	}

	return le16_to_cpu(id->vid) == vid && !strncmp(id->mn, mn, len);
}

static void __nvme_mi_format_mn(struct nvme_id_ctrl *id,
				char *mn, size_t mn_len)
{
	const size_t id_mn_size = sizeof(id->mn);
	int i;

	/* A BUILD_ASSERT() would be nice here, but we're not const enough for
	 * that
	 */
	if (mn_len <= id_mn_size)
		abort();

	memcpy(mn, id->mn, id_mn_size);
	mn[id_mn_size] = '\0';

	for (i = id_mn_size - 1; i >= 0; i--) {
		if (mn[i] != '\0' && mn[i] != ' ')
			break;
		mn[i] = '\0';
	}
}

#define nvme_mi_format_mn(id, m) __nvme_mi_format_mn(id, m, sizeof(m))

void nvme_mi_ep_probe(struct nvme_mi_ep *ep)
{
	struct nvme_identify_args id_args = { 0 };
	struct nvme_id_ctrl id = { 0 };
	struct nvme_mi_ctrl *ctrl;
	int rc;

	if (!ep->root->mi_probe_enabled)
		return;

	/* start with no quirks, detect as we go */
	ep->quirks = 0;

	ctrl = nvme_mi_init_ctrl(ep, 0);
	if (!ctrl)
		return;

	/* Do enough of an identify (assuming controller 0) to retrieve
	 * device and firmware identification information. This gives us the
	 * following fields in id:
	 *
	 *  - vid (PCI vendor ID)
	 *  - ssvid (PCI subsystem vendor ID)
	 *  - sn (Serial number)
	 *  - mn (Model number)
	 *  - fr (Firmware revision)
	 *
	 * all other fields - rab and onwards - will be zero!
	 */
	id_args.args_size = sizeof(id_args);
	id_args.data = &id;
	id_args.cns = NVME_IDENTIFY_CNS_CTRL;
	id_args.nsid = NVME_NSID_NONE;
	id_args.cntid = 0;
	id_args.csi = NVME_CSI_NVM;

	rc = nvme_mi_admin_identify_partial(ctrl, &id_args, 0,
				    offsetof(struct nvme_id_ctrl, rab));
	if (rc) {
		nvme_msg(ep->root, LOG_WARNING,
			 "Identify Controller failed, no quirks applied\n");
		goto out_close;
	}

	/* Samsung MZUL2512: cannot receive commands sent within ~1ms of
	 * the previous response. Set an inter-command delay of 1.2ms for
	 * a little extra tolerance.
	 */
	if (nvme_mi_compare_vid_mn(ep, &id, 0x144d, "MZUL2512HCJQ")) {
		ep->quirks |= NVME_QUIRK_MIN_INTER_COMMAND_TIME;
		ep->inter_command_us = 1200;
	}

	/* If we're quirking for the inter-command time, record the last
	 * command time now, so we don't conflict with the just-sent identify.
	 */
	if (ep->quirks & NVME_QUIRK_MIN_INTER_COMMAND_TIME)
		nvme_mi_record_resp_time(ep);

	if (ep->quirks) {
		char tmp[sizeof(id.mn) + 1];

		nvme_mi_format_mn(&id, tmp);
		nvme_msg(ep->root, LOG_DEBUG,
			 "device %02x:%s: applying quirks 0x%08lx\n",
			 id.vid, tmp, ep->quirks);
	}

out_close:
	nvme_mi_close_ctrl(ctrl);
}

static const int nsec_per_sec = 1000 * 1000 * 1000;
/* timercmp and timersub, but for struct timespec */
#define timespec_cmp(a, b, CMP)						\
	(((a)->tv_sec == (b)->tv_sec)					\
		? ((a)->tv_nsec CMP (b)->tv_nsec)			\
		: ((a)->tv_sec CMP (b)->tv_sec))

#define timespec_sub(a, b, result)					\
	do {								\
		(result)->tv_sec = (a)->tv_sec - (b)->tv_sec;		\
		(result)->tv_nsec = (a)->tv_nsec - (b)->tv_nsec;	\
		if ((result)->tv_nsec < 0) {				\
			--(result)->tv_sec;				\
			(result)->tv_nsec += nsec_per_sec;		\
		}							\
	} while (0)

static void nvme_mi_insert_delay(struct nvme_mi_ep *ep)
{
	struct timespec now, next, delay;
	int rc;

	if (!ep->last_resp_time_valid)
		return;

	/* calculate earliest next command time */
	next.tv_nsec = ep->last_resp_time.tv_nsec + ep->inter_command_us * 1000;
	next.tv_sec = ep->last_resp_time.tv_sec;
	if (next.tv_nsec > nsec_per_sec) {
		next.tv_nsec -= nsec_per_sec;
		next.tv_sec += 1;
	}

	rc = clock_gettime(CLOCK_MONOTONIC, &now);
	if (rc) {
		/* not much we can do; continue immediately */
		return;
	}

	if (timespec_cmp(&now, &next, >=))
		return;

	timespec_sub(&next, &now, &delay);

	nanosleep(&delay, NULL);
}

struct nvme_mi_ep *nvme_mi_init_ep(nvme_root_t root)
{
	struct nvme_mi_ep *ep;

	ep = calloc(1, sizeof(*ep));
	if (!ep)
		return NULL;

	list_node_init(&ep->root_entry);
	ep->root = root;
	ep->controllers_scanned = false;
	ep->timeout = default_timeout;
	ep->mprt_max = 0;
	list_head_init(&ep->controllers);

	list_add(&root->endpoints, &ep->root_entry);

	return ep;
}

int nvme_mi_ep_set_timeout(nvme_mi_ep_t ep, unsigned int timeout_ms)
{
	if (ep->transport->check_timeout) {
		int rc;
		rc = ep->transport->check_timeout(ep, timeout_ms);
		if (rc)
			return rc;
	}

	ep->timeout = timeout_ms;
	return 0;
}

void nvme_mi_ep_set_mprt_max(nvme_mi_ep_t ep, unsigned int mprt_max_ms)
{
	ep->mprt_max = mprt_max_ms;
}

unsigned int nvme_mi_ep_get_timeout(nvme_mi_ep_t ep)
{
	return ep->timeout;
}

static bool nvme_mi_ep_has_quirk(nvme_mi_ep_t ep, unsigned long quirk)
{
	return ep->quirks & quirk;
}

struct nvme_mi_ctrl *nvme_mi_init_ctrl(nvme_mi_ep_t ep, __u16 ctrl_id)
{
	struct nvme_mi_ctrl *ctrl;

	ctrl = malloc(sizeof(*ctrl));
	if (!ctrl)
		return NULL;

	ctrl->ep = ep;
	ctrl->id = ctrl_id;

	list_add_tail(&ep->controllers, &ctrl->ep_entry);

	return ctrl;
}

int nvme_mi_scan_ep(nvme_mi_ep_t ep, bool force_rescan)
{
	struct nvme_ctrl_list list;
	unsigned int i, n_ctrl;
	int rc;

	if (ep->controllers_scanned) {
		if (force_rescan) {
			struct nvme_mi_ctrl *ctrl, *tmp;
			nvme_mi_for_each_ctrl_safe(ep, ctrl, tmp)
				nvme_mi_close_ctrl(ctrl);
		} else {
			return 0;
		}
	}

	rc = nvme_mi_mi_read_mi_data_ctrl_list(ep, 0, &list);
	if (rc)
		return -1;

	n_ctrl = le16_to_cpu(list.num);
	if (n_ctrl > NVME_ID_CTRL_LIST_MAX) {
		errno = EPROTO;
		return -1;
	}

	for (i = 0; i < n_ctrl; i++) {
		struct nvme_mi_ctrl *ctrl;
		__u16 id;

		id = le16_to_cpu(list.identifier[i]);

		ctrl = nvme_mi_init_ctrl(ep, id);
		if (!ctrl)
			break;
	}

	ep->controllers_scanned = true;
	return 0;
}

__u32 nvme_mi_crc32_update(__u32 crc, void *data, size_t len)
{
	int i;

	while (len--) {
		crc ^= *(unsigned char *)(data++);
		for (i = 0; i < 8; i++)
			crc = (crc >> 1) ^ ((crc & 1) ? 0x82F63B78 : 0);
	}
	return crc;
}

static void nvme_mi_calc_req_mic(struct nvme_mi_req *req)
{
	__u32 crc = 0xffffffff;

	crc = nvme_mi_crc32_update(crc, req->hdr, req->hdr_len);
	crc = nvme_mi_crc32_update(crc, req->data, req->data_len);

	req->mic = ~crc;
}

/* returns zero on correct MIC */
static int nvme_mi_verify_resp_mic(struct nvme_mi_resp *resp)
{
	__u32 crc = 0xffffffff;

	crc = nvme_mi_crc32_update(crc, resp->hdr, resp->hdr_len);
	crc = nvme_mi_crc32_update(crc, resp->data, resp->data_len);

	return resp->mic != ~crc;
}

int nvme_mi_submit(nvme_mi_ep_t ep, struct nvme_mi_req *req,
		   struct nvme_mi_resp *resp)
{
	int rc;

	if (req->hdr_len < sizeof(struct nvme_mi_msg_hdr)) {
		errno = EINVAL;
		return -1;
	}

	if (req->hdr_len & 0x3) {
		errno = EINVAL;
		return -1;
	}

	if (req->data_len & 0x3) {
		errno = EINVAL;
		return -1;
	}

	if (resp->hdr_len < sizeof(struct nvme_mi_msg_hdr)) {
		errno = EINVAL;
		return -1;
	}

	if (resp->hdr_len & 0x3) {
		errno = EINVAL;
		return -1;
	}

	if (resp->data_len & 0x3) {
		errno = EINVAL;
		return -1;
	}

	if (ep->transport->mic_enabled)
		nvme_mi_calc_req_mic(req);

	if (nvme_mi_ep_has_quirk(ep, NVME_QUIRK_MIN_INTER_COMMAND_TIME))
		nvme_mi_insert_delay(ep);

	rc = ep->transport->submit(ep, req, resp);

	if (nvme_mi_ep_has_quirk(ep, NVME_QUIRK_MIN_INTER_COMMAND_TIME))
		nvme_mi_record_resp_time(ep);

	if (rc) {
		nvme_msg(ep->root, LOG_INFO, "transport failure\n");
		return rc;
	}

	if (ep->transport->mic_enabled) {
		rc = nvme_mi_verify_resp_mic(resp);
		if (rc) {
			nvme_msg(ep->root, LOG_WARNING, "crc mismatch\n");
			return rc;
		}
	}

	/* basic response checks */
	if (resp->hdr_len < sizeof(struct nvme_mi_msg_hdr)) {
		nvme_msg(ep->root, LOG_DEBUG,
			 "Bad response header len: %zd\n", resp->hdr_len);
		errno = EPROTO;
		return -1;
	}

	if (resp->hdr->type != NVME_MI_MSGTYPE_NVME) {
		nvme_msg(ep->root, LOG_DEBUG,
			 "Invalid message type 0x%02x\n", resp->hdr->type);
		errno = EPROTO;
		return -1;
	}

	if (!(resp->hdr->nmp & (NVME_MI_ROR_RSP << 7))) {
		nvme_msg(ep->root, LOG_DEBUG,
			 "ROR value in response indicates a request\n");
		errno = EIO;
		return -1;
	}

	if ((resp->hdr->nmp & 0x1) != (req->hdr->nmp & 0x1)) {
		nvme_msg(ep->root, LOG_WARNING,
			 "Command slot mismatch: req %d, resp %d\n",
			 req->hdr->nmp & 0x1,
			 resp->hdr->nmp & 0x1);
		errno = EIO;
		return -1;
	}

	return 0;
}

static void nvme_mi_admin_init_req(struct nvme_mi_req *req,
				   struct nvme_mi_admin_req_hdr *hdr,
				   __u16 ctrl_id, __u8 opcode)
{
	memset(req, 0, sizeof(*req));
	memset(hdr, 0, sizeof(*hdr));

	hdr->hdr.type = NVME_MI_MSGTYPE_NVME;
	hdr->hdr.nmp = (NVME_MI_ROR_REQ << 7) |
		(NVME_MI_MT_ADMIN << 3); /* we always use command slot 0 */
	hdr->opcode = opcode;
	hdr->ctrl_id = cpu_to_le16(ctrl_id);

	req->hdr = &hdr->hdr;
	req->hdr_len = sizeof(*hdr);
}

static void nvme_mi_admin_init_resp(struct nvme_mi_resp *resp,
				    struct nvme_mi_admin_resp_hdr *hdr)
{
	memset(resp, 0, sizeof(*resp));
	resp->hdr = &hdr->hdr;
	resp->hdr_len = sizeof(*hdr);
}

static int nvme_mi_admin_parse_status(struct nvme_mi_resp *resp, __u32 *result)
{
	struct nvme_mi_admin_resp_hdr *admin_hdr;
	struct nvme_mi_msg_resp *resp_hdr;
	__u32 nvme_status;
	__u32 nvme_result;

	/* we have a few different sources of "result" here: the status header
	 * in the MI response, the cdw3 status field, and (command specific)
	 * return values in cdw0. The latter is returned in the result pointer,
	 * the former two generate return values here
	 */

	if (resp->hdr_len < sizeof(*resp_hdr)) {
		errno = -EPROTO;
		return -1;
	}
	resp_hdr = (struct nvme_mi_msg_resp *)resp->hdr;

	/* If we have a MI error, we can't be sure there's an admin header
	 * following; return just the MI status, with the status type
	 * indicator of MI.
	 */
	if (resp_hdr->status)
		return resp_hdr->status |
			(NVME_STATUS_TYPE_MI << NVME_STATUS_TYPE_SHIFT);

	/* We shouldn't hit this, as we'd have an error reported earlier.
	 * However, for pointer safety, ensure we have a full admin header
	 */
	if (resp->hdr_len < sizeof(*admin_hdr)) {
		errno = EPROTO;
		return -1;
	}

	admin_hdr = (struct nvme_mi_admin_resp_hdr *)resp->hdr;
	nvme_result = le32_to_cpu(admin_hdr->cdw0);

	/* Shift down 17 here: the SC starts at bit 17, and the NVME_SC_*
	 * definitions align to this bit (and up). The CRD, MORE and DNR
	 * bits are defined accordingly (eg., DNR is 0x4000).
	 */
	nvme_status = le32_to_cpu(admin_hdr->cdw3) >> 17;

	/* the result pointer, optionally stored if the caller needs it */
	if (result)
		*result = nvme_result;

	return nvme_status;
}

int nvme_mi_admin_xfer(nvme_mi_ctrl_t ctrl,
		       struct nvme_mi_admin_req_hdr *admin_req,
		       size_t req_data_size,
		       struct nvme_mi_admin_resp_hdr *admin_resp,
		       off_t resp_data_offset,
		       size_t *resp_data_size)
{
	struct nvme_mi_resp resp;
	struct nvme_mi_req req;
	int rc;

	/* length/offset checks. The common _submit() API will do further
	 * checking on the message lengths too, so these are kept specific
	 * to the requirements of the Admin command set
	 */

	/* NVMe-MI v1.2 imposes a limit of 4096 bytes on the dlen field */
	if (*resp_data_size > 4096) {
		errno = EINVAL;
		return -1;
	}

	/* we only have 32 bits of offset */
	if (resp_data_offset > 0xffffffff) {
		errno = EINVAL;
		return -1;
	}

	/* must be aligned */
	if (resp_data_offset & 0x3) {
		errno = EINVAL;
		return -1;
	}

	/* bidirectional not permitted (see DLEN definition) */
	if (req_data_size && *resp_data_size) {
		errno = EINVAL;
		return -1;
	}

	if (!*resp_data_size && resp_data_offset) {
		errno = EINVAL;
		return -1;
	}

	admin_req->hdr.type = NVME_MI_MSGTYPE_NVME;
	admin_req->hdr.nmp = (NVME_MI_ROR_REQ << 7) |
				(NVME_MI_MT_ADMIN << 3);
	admin_req->ctrl_id = cpu_to_le16(ctrl->id);
	memset(&req, 0, sizeof(req));
	req.hdr = &admin_req->hdr;
	req.hdr_len = sizeof(*admin_req);
	req.data = admin_req + 1;
	req.data_len = req_data_size;

	nvme_mi_calc_req_mic(&req);

	memset(&resp, 0, sizeof(resp));
	resp.hdr = &admin_resp->hdr;
	resp.hdr_len = sizeof(*admin_resp);
	resp.data = admin_resp + 1;
	resp.data_len = *resp_data_size;

	/* limit the response size, specify offset */
	admin_req->flags = 0x3;
	admin_req->dlen = cpu_to_le32(resp.data_len & 0xffffffff);
	admin_req->doff = cpu_to_le32(resp_data_offset & 0xffffffff);

	rc = nvme_mi_submit(ctrl->ep, &req, &resp);
	if (rc)
		return rc;

	*resp_data_size = resp.data_len;

	return 0;
}

int nvme_mi_admin_admin_passthru(nvme_mi_ctrl_t ctrl, __u8 opcode, __u8 flags,
				 __u16 rsvd, __u32 nsid, __u32 cdw2, __u32 cdw3,
				 __u32 cdw10, __u32 cdw11, __u32 cdw12,
				 __u32 cdw13, __u32 cdw14, __u32 cdw15,
				 __u32 data_len, void *data, __u32 metadata_len,
				 void *metadata, __u32 timeout_ms, __u32 *result)
{
	/* Input parameters flags, rsvd, metadata, metadata_len are not used */
	struct nvme_mi_admin_resp_hdr resp_hdr;
	struct nvme_mi_admin_req_hdr req_hdr;
	struct nvme_mi_resp resp;
	struct nvme_mi_req req;
	int rc;
	int direction = opcode & 0x3;
	bool has_write_data = false;
	bool has_read_data = false;

	if (direction == NVME_DATA_TFR_BIDIRECTIONAL) {
		nvme_msg(ctrl->ep->root, LOG_ERR,
			"nvme_mi_admin_admin_passthru doesn't support bidirectional commands\n");
		errno = EINVAL;
		return -1;
	}

	if (data_len > 4096) {
		nvme_msg(ctrl->ep->root, LOG_ERR,
			"nvme_mi_admin_admin_passthru doesn't support data_len over 4096 bytes.\n");
		errno = EINVAL;
		return -1;
	}

	if (data != NULL && data_len != 0) {
		if (direction == NVME_DATA_TFR_HOST_TO_CTRL)
			has_write_data = true;
		if (direction == NVME_DATA_TFR_CTRL_TO_HOST)
			has_read_data = true;
	}

	if (timeout_ms > nvme_mi_ep_get_timeout(ctrl->ep)) {
		/* Set timeout if user needs a bigger timeout */
		nvme_mi_ep_set_timeout(ctrl->ep, timeout_ms);
	}

	nvme_mi_admin_init_req(&req, &req_hdr, ctrl->id, opcode);
	req_hdr.cdw1 = cpu_to_le32(nsid);
	req_hdr.cdw2 = cpu_to_le32(cdw2);
	req_hdr.cdw3 = cpu_to_le32(cdw3);
	req_hdr.cdw10 = cpu_to_le32(cdw10);
	req_hdr.cdw11 = cpu_to_le32(cdw11);
	req_hdr.cdw12 = cpu_to_le32(cdw12);
	req_hdr.cdw13 = cpu_to_le32(cdw13);
	req_hdr.cdw14 = cpu_to_le32(cdw14);
	req_hdr.cdw15 = cpu_to_le32(cdw15);
	req_hdr.doff = 0;
	if (data_len != 0) {
		req_hdr.dlen = cpu_to_le32(data_len);
		/* Bit 0 set to 1 means DLEN contains a value */
		req_hdr.flags = 0x1;
	}

	if (has_write_data) {
		req.data = data;
		req.data_len = data_len;
	}

	nvme_mi_calc_req_mic(&req);

	nvme_mi_admin_init_resp(&resp, &resp_hdr);

	if (has_read_data) {
		resp.data = data;
		resp.data_len = data_len;
	}

	rc = nvme_mi_submit(ctrl->ep, &req, &resp);
	if (rc)
		return rc;

	rc = nvme_mi_admin_parse_status(&resp, result);
	if (rc)
		return rc;

	if (has_read_data && (resp.data_len != data_len)) {
		errno = EPROTO;
		return -1;
	}

	return 0;
}

int nvme_mi_admin_identify_partial(nvme_mi_ctrl_t ctrl,
				   struct nvme_identify_args *args,
				   off_t offset, size_t size)
{
	struct nvme_mi_admin_resp_hdr resp_hdr;
	struct nvme_mi_admin_req_hdr req_hdr;
	struct nvme_mi_resp resp;
	struct nvme_mi_req req;
	int rc;

	if (args->args_size < sizeof(*args)) {
		errno = EINVAL;
		return -1;
	}

	if (!size || size > 0xffffffff) {
		errno = EINVAL;
		return -1;
	}

	nvme_mi_admin_init_req(&req, &req_hdr, ctrl->id, nvme_admin_identify);
	req_hdr.cdw1 = cpu_to_le32(args->nsid);
	req_hdr.cdw10 = cpu_to_le32(args->cntid << 16 | args->cns);
	req_hdr.cdw11 = cpu_to_le32((args->csi & 0xff) << 24 |
				    args->cns_specific_id);
	req_hdr.cdw14 = cpu_to_le32(args->uuidx);
	req_hdr.dlen = cpu_to_le32(size & 0xffffffff);
	req_hdr.flags = 0x1;
	if (offset) {
		req_hdr.flags |= 0x2;
		req_hdr.doff = cpu_to_le32(offset);
	}

	nvme_mi_calc_req_mic(&req);

	nvme_mi_admin_init_resp(&resp, &resp_hdr);
	resp.data = args->data;
	resp.data_len = size;

	rc = nvme_mi_submit(ctrl->ep, &req, &resp);
	if (rc)
		return rc;

	rc = nvme_mi_admin_parse_status(&resp, args->result);
	if (rc)
		return rc;

	/* callers will expect a full response; if the data buffer isn't
	 * fully valid, return an error */
	if (resp.data_len != size) {
		errno = EPROTO;
		return -1;
	}

	return 0;
}

/* retrieves a MCTP-messsage-sized chunk of log page data. offset and len are
 * specified within the args->data area. The `offset` parameter is a relative
 * offset to the args->lpo !
 *
 * What's more, we change the LPO of original command to chunk the request
 * message into proper size which is allowed by MI interface. One reason is that
 * this option seems to be supported better by devices.  For more information
 * about this option, please check https://github.com/linux-nvme/libnvme/pull/539
 * */
static int __nvme_mi_admin_get_log(nvme_mi_ctrl_t ctrl,
				   const struct nvme_get_log_args *args,
				   off_t offset, size_t *lenp, bool final)
{
	__u64 log_page_offset = args->lpo + offset;
	struct nvme_mi_admin_resp_hdr resp_hdr;
	struct nvme_mi_admin_req_hdr req_hdr;
	struct nvme_mi_resp resp;
	struct nvme_mi_req req;
	size_t len;
	__u32 ndw;
	int rc;

	/* MI spec requires that the data length field is less than or equal
	 * to 4096 */
	len = *lenp;
	if (!len || len > 4096 || len < 4) {
		errno = EINVAL;
		return -1;
	}

	if (offset < 0 || offset >= args->len || offset + len > args->len) {
		errno = EINVAL;
		return -1;
	}

	ndw = (len >> 2) - 1;

	nvme_mi_admin_init_req(&req, &req_hdr, ctrl->id, nvme_admin_get_log_page);
	req_hdr.cdw1 = cpu_to_le32(args->nsid);
	req_hdr.cdw10 = cpu_to_le32((ndw & 0xffff) << 16 |
				    ((!final || args->rae) ? 1 : 0) << 15 |
				    args->lsp << 8 |
				    (args->lid & 0xff));
	req_hdr.cdw11 = cpu_to_le32(args->lsi << 16 |
				    ndw >> 16);
	req_hdr.cdw12 = cpu_to_le32(log_page_offset & 0xffffffff);
	req_hdr.cdw13 = cpu_to_le32(log_page_offset >> 32);
	req_hdr.cdw14 = cpu_to_le32(args->csi << 24 |
				    (args->ot ? 1 : 0) << 23 |
				    args->uuidx);
	req_hdr.flags = 0x1;
	req_hdr.dlen = cpu_to_le32(len & 0xffffffff);

	nvme_mi_calc_req_mic(&req);

	nvme_mi_admin_init_resp(&resp, &resp_hdr);
	resp.data = args->log + offset;
	resp.data_len = len;

	rc = nvme_mi_submit(ctrl->ep, &req, &resp);
	if (rc)
		return rc;

	rc = nvme_mi_admin_parse_status(&resp, args->result);
	if (!rc)
		*lenp = resp.data_len;

	return rc;
}

int nvme_mi_admin_get_log(nvme_mi_ctrl_t ctrl, struct nvme_get_log_args *args)
{
	const size_t max_xfer_size = 4096;
	off_t xfer_offset;
	int rc = 0;

	if (args->args_size < sizeof(*args)) {
		errno = EINVAL;
		return -1;
	}

	if (args->ot && (args->len > max_xfer_size)) {
		errno = EINVAL;
		return -1;
	}

	for (xfer_offset = 0; xfer_offset < args->len;) {
		size_t xfered_size, cur_xfer_size = max_xfer_size;
		bool final;

		if (xfer_offset + cur_xfer_size > args->len)
			cur_xfer_size = args->len - xfer_offset;

		xfered_size = cur_xfer_size;

		final = xfer_offset + cur_xfer_size >= args->len;

		/* xfered_size is used as both input and output parameter */
		rc = __nvme_mi_admin_get_log(ctrl, args, xfer_offset,
					     &xfered_size, final);
		if (rc)
			break;

		xfer_offset += xfered_size;
		/* if we returned less data than expected, consider that
		 * the end of the log page */
		if (xfered_size != cur_xfer_size)
			break;
	}

	if (!rc)
		args->len = xfer_offset;

	return rc;
}

int nvme_mi_admin_security_send(nvme_mi_ctrl_t ctrl,
				struct nvme_security_send_args *args)
{

	struct nvme_mi_admin_resp_hdr resp_hdr;
	struct nvme_mi_admin_req_hdr req_hdr;
	struct nvme_mi_resp resp;
	struct nvme_mi_req req;
	int rc;

	if (args->args_size < sizeof(*args)) {
		errno = EINVAL;
		return -1;
	}

	if (args->data_len > 4096) {
		errno = EINVAL;
		return -1;
	}

	nvme_mi_admin_init_req(&req, &req_hdr, ctrl->id,
			       nvme_admin_security_send);

	req_hdr.cdw10 = cpu_to_le32(args->secp << 24 |
				    args->spsp1 << 16 |
				    args->spsp0 << 8 |
				    args->nssf);

	req_hdr.cdw11 = cpu_to_le32(args->data_len & 0xffffffff);

	req_hdr.flags = 0x1;
	req_hdr.dlen = cpu_to_le32(args->data_len & 0xffffffff);
	req.data = args->data;
	req.data_len = args->data_len;

	nvme_mi_calc_req_mic(&req);

	nvme_mi_admin_init_resp(&resp, &resp_hdr);

	rc = nvme_mi_submit(ctrl->ep, &req, &resp);
	if (rc)
		return rc;

	return nvme_mi_admin_parse_status(&resp, args->result);
}

int nvme_mi_admin_security_recv(nvme_mi_ctrl_t ctrl,
				struct nvme_security_receive_args *args)
{

	struct nvme_mi_admin_resp_hdr resp_hdr;
	struct nvme_mi_admin_req_hdr req_hdr;
	struct nvme_mi_resp resp;
	struct nvme_mi_req req;
	int rc;

	if (args->args_size < sizeof(*args)) {
		errno = EINVAL;
		return -1;
	}

	if (args->data_len > 4096) {
		errno = EINVAL;
		return -1;
	}

	nvme_mi_admin_init_req(&req, &req_hdr, ctrl->id,
			       nvme_admin_security_recv);

	req_hdr.cdw10 = cpu_to_le32(args->secp << 24 |
				    args->spsp1 << 16 |
				    args->spsp0 << 8 |
				    args->nssf);

	req_hdr.cdw11 = cpu_to_le32(args->data_len & 0xffffffff);

	req_hdr.flags = 0x1;
	req_hdr.dlen = cpu_to_le32(args->data_len & 0xffffffff);

	nvme_mi_calc_req_mic(&req);

	nvme_mi_admin_init_resp(&resp, &resp_hdr);
	resp.data = args->data;
	resp.data_len = args->data_len;

	rc = nvme_mi_submit(ctrl->ep, &req, &resp);
	if (rc)
		return rc;

	rc = nvme_mi_admin_parse_status(&resp, args->result);
	if (rc)
		return rc;

	args->data_len = resp.data_len;

	return 0;
}

int nvme_mi_admin_get_features(nvme_mi_ctrl_t ctrl,
			       struct nvme_get_features_args *args)
{
	struct nvme_mi_admin_resp_hdr resp_hdr;
	struct nvme_mi_admin_req_hdr req_hdr;
	struct nvme_mi_resp resp;
	struct nvme_mi_req req;
	int rc;

	if (args->args_size < sizeof(*args))
		return -EINVAL;

	nvme_mi_admin_init_req(&req, &req_hdr, ctrl->id,
			       nvme_admin_get_features);

	req_hdr.cdw1 = cpu_to_le32(args->nsid);
	req_hdr.cdw10 = cpu_to_le32((args->sel & 0x7) << 8 | args->fid);
	req_hdr.cdw14 = cpu_to_le32(args->uuidx & 0x7f);
	req_hdr.cdw11 = cpu_to_le32(args->cdw11);

	nvme_mi_calc_req_mic(&req);

	nvme_mi_admin_init_resp(&resp, &resp_hdr);
	resp.data = args->data;
	resp.data_len = args->data_len;

	rc = nvme_mi_submit(ctrl->ep, &req, &resp);
	if (rc)
		return rc;

	rc = nvme_mi_admin_parse_status(&resp, args->result);
	if (rc)
		return rc;

	args->data_len = resp.data_len;

	return 0;
}

int nvme_mi_admin_set_features(nvme_mi_ctrl_t ctrl,
			       struct nvme_set_features_args *args)
{
	struct nvme_mi_admin_resp_hdr resp_hdr;
	struct nvme_mi_admin_req_hdr req_hdr;
	struct nvme_mi_resp resp;
	struct nvme_mi_req req;
	int rc;

	if (args->args_size < sizeof(*args))
		return -EINVAL;

	nvme_mi_admin_init_req(&req, &req_hdr, ctrl->id,
			       nvme_admin_set_features);

	req_hdr.cdw1 = cpu_to_le32(args->nsid);
	req_hdr.cdw10 = cpu_to_le32((args->save ? 1 : 0) << 31 |
				    (args->fid & 0xff));
	req_hdr.cdw14 = cpu_to_le32(args->uuidx & 0x7f);
	req_hdr.cdw11 = cpu_to_le32(args->cdw11);
	req_hdr.cdw12 = cpu_to_le32(args->cdw12);
	req_hdr.cdw13 = cpu_to_le32(args->cdw13);
	req_hdr.cdw15 = cpu_to_le32(args->cdw15);

	req.data_len = args->data_len;
	req.data = args->data;

	nvme_mi_calc_req_mic(&req);

	nvme_mi_admin_init_resp(&resp, &resp_hdr);

	rc = nvme_mi_submit(ctrl->ep, &req, &resp);
	if (rc)
		return rc;

	rc = nvme_mi_admin_parse_status(&resp, args->result);
	if (rc)
		return rc;

	args->data_len = resp.data_len;

	return 0;
}

int nvme_mi_admin_ns_mgmt(nvme_mi_ctrl_t ctrl,
			  struct nvme_ns_mgmt_args *args)
{
	struct nvme_mi_admin_resp_hdr resp_hdr;
	struct nvme_mi_admin_req_hdr req_hdr;
	struct nvme_mi_resp resp;
	struct nvme_mi_req req;
	int rc;

	if (args->args_size < sizeof(*args))
		return -EINVAL;

	nvme_mi_admin_init_req(&req, &req_hdr, ctrl->id,
			       nvme_admin_ns_mgmt);

	req_hdr.cdw1 = cpu_to_le32(args->nsid);
	req_hdr.cdw10 = cpu_to_le32(args->sel & 0xf);
	req_hdr.cdw11 = cpu_to_le32(args->csi << 24);
	if (args->ns) {
		req.data = args->ns;
		req.data_len = sizeof(*args->ns);
		req_hdr.dlen = cpu_to_le32(sizeof(*args->ns));
		req_hdr.flags = 0x1;
	}

	nvme_mi_calc_req_mic(&req);

	nvme_mi_admin_init_resp(&resp, &resp_hdr);

	rc = nvme_mi_submit(ctrl->ep, &req, &resp);
	if (rc)
		return rc;

	return nvme_mi_admin_parse_status(&resp, args->result);
}

int nvme_mi_admin_ns_attach(nvme_mi_ctrl_t ctrl,
			    struct nvme_ns_attach_args *args)
{
	struct nvme_mi_admin_resp_hdr resp_hdr;
	struct nvme_mi_admin_req_hdr req_hdr;
	struct nvme_mi_resp resp;
	struct nvme_mi_req req;
	int rc;

	if (args->args_size < sizeof(*args))
		return -EINVAL;

	nvme_mi_admin_init_req(&req, &req_hdr, ctrl->id,
			       nvme_admin_ns_attach);

	req_hdr.cdw1 = cpu_to_le32(args->nsid);
	req_hdr.cdw10 = cpu_to_le32(args->sel & 0xf);
	req.data = args->ctrlist;
	req.data_len = sizeof(*args->ctrlist);
	req_hdr.dlen = cpu_to_le32(sizeof(*args->ctrlist));
	req_hdr.flags = 0x1;

	nvme_mi_calc_req_mic(&req);

	nvme_mi_admin_init_resp(&resp, &resp_hdr);

	rc = nvme_mi_submit(ctrl->ep, &req, &resp);
	if (rc)
		return rc;

	return nvme_mi_admin_parse_status(&resp, args->result);
}

int nvme_mi_admin_fw_download(nvme_mi_ctrl_t ctrl,
			      struct nvme_fw_download_args *args)
{
	struct nvme_mi_admin_resp_hdr resp_hdr;
	struct nvme_mi_admin_req_hdr req_hdr;
	struct nvme_mi_resp resp;
	struct nvme_mi_req req;
	int rc;

	if (args->args_size < sizeof(*args))
		return -EINVAL;

	if (args->data_len & 0x3)
		return -EINVAL;

	if (args->offset & 0x3)
		return -EINVAL;

	if (!args->data_len)
		return -EINVAL;

	nvme_mi_admin_init_req(&req, &req_hdr, ctrl->id,
			       nvme_admin_fw_download);

	req_hdr.cdw10 = cpu_to_le32((args->data_len >> 2) - 1);
	req_hdr.cdw11 = cpu_to_le32(args->offset >> 2);
	req.data = args->data;
	req.data_len = args->data_len;
	req_hdr.dlen = cpu_to_le32(args->data_len);
	req_hdr.flags = 0x1;

	nvme_mi_calc_req_mic(&req);

	nvme_mi_admin_init_resp(&resp, &resp_hdr);

	rc = nvme_mi_submit(ctrl->ep, &req, &resp);
	if (rc)
		return rc;

	return nvme_mi_admin_parse_status(&resp, NULL);
}

int nvme_mi_admin_fw_commit(nvme_mi_ctrl_t ctrl,
			    struct nvme_fw_commit_args *args)
{
	struct nvme_mi_admin_resp_hdr resp_hdr;
	struct nvme_mi_admin_req_hdr req_hdr;
	struct nvme_mi_resp resp;
	struct nvme_mi_req req;
	int rc;

	if (args->args_size < sizeof(*args))
		return -EINVAL;

	nvme_mi_admin_init_req(&req, &req_hdr, ctrl->id,
			       nvme_admin_fw_commit);

	req_hdr.cdw10 = cpu_to_le32(((args->bpid & 0x1) << 31) |
				    ((args->action & 0x7) << 3) |
				    ((args->slot & 0x7) << 0));

	nvme_mi_calc_req_mic(&req);

	nvme_mi_admin_init_resp(&resp, &resp_hdr);

	rc = nvme_mi_submit(ctrl->ep, &req, &resp);
	if (rc)
		return rc;

	return nvme_mi_admin_parse_status(&resp, NULL);
}

int nvme_mi_admin_format_nvm(nvme_mi_ctrl_t ctrl,
			     struct nvme_format_nvm_args *args)
{
	struct nvme_mi_admin_resp_hdr resp_hdr;
	struct nvme_mi_admin_req_hdr req_hdr;
	struct nvme_mi_resp resp;
	struct nvme_mi_req req;
	int rc;

	if (args->args_size < sizeof(*args))
		return -EINVAL;

	nvme_mi_admin_init_req(&req, &req_hdr, ctrl->id,
			       nvme_admin_format_nvm);

	req_hdr.cdw1 = cpu_to_le32(args->nsid);
	req_hdr.cdw10 = cpu_to_le32(((args->lbafu & 0x3) << 12)
				    | ((args->ses & 0x7) << 9)
				    | ((args->pil & 0x1) << 8)
				    | ((args->pi & 0x7) << 5)
				    | ((args->mset & 0x1) << 4)
				    | ((args->lbaf & 0xf) << 0));

	nvme_mi_calc_req_mic(&req);

	nvme_mi_admin_init_resp(&resp, &resp_hdr);

	rc = nvme_mi_submit(ctrl->ep, &req, &resp);
	if (rc)
		return rc;

	return nvme_mi_admin_parse_status(&resp, args->result);
}

int nvme_mi_admin_sanitize_nvm(nvme_mi_ctrl_t ctrl,
			       struct nvme_sanitize_nvm_args *args)
{
	struct nvme_mi_admin_resp_hdr resp_hdr;
	struct nvme_mi_admin_req_hdr req_hdr;
	struct nvme_mi_resp resp;
	struct nvme_mi_req req;
	int rc;

	if (args->args_size < sizeof(*args))
		return -EINVAL;

	nvme_mi_admin_init_req(&req, &req_hdr, ctrl->id,
			       nvme_admin_sanitize_nvm);

	req_hdr.cdw10 = cpu_to_le32(((args->nodas ? 1 : 0) << 9)
				    | ((args->oipbp ? 1 : 0) << 8)
				    | ((args->owpass & 0xf) << 4)
				    | ((args->ause ? 1 : 0) << 3)
				    | ((args->sanact & 0x7) << 0));
	req_hdr.cdw11 = cpu_to_le32(args->ovrpat);

	nvme_mi_calc_req_mic(&req);

	nvme_mi_admin_init_resp(&resp, &resp_hdr);

	rc = nvme_mi_submit(ctrl->ep, &req, &resp);
	if (rc)
		return rc;

	return nvme_mi_admin_parse_status(&resp, args->result);
}

static int nvme_mi_read_data(nvme_mi_ep_t ep, __u32 cdw0,
			     void *data, size_t *data_len)
{
	struct nvme_mi_mi_resp_hdr resp_hdr;
	struct nvme_mi_mi_req_hdr req_hdr;
	struct nvme_mi_resp resp;
	struct nvme_mi_req req;
	int rc;

	memset(&req_hdr, 0, sizeof(req_hdr));
	req_hdr.hdr.type = NVME_MI_MSGTYPE_NVME;
	req_hdr.hdr.nmp = (NVME_MI_ROR_REQ << 7) |
		(NVME_MI_MT_MI << 3); /* we always use command slot 0 */
	req_hdr.opcode = nvme_mi_mi_opcode_mi_data_read;
	req_hdr.cdw0 = cpu_to_le32(cdw0);

	memset(&req, 0, sizeof(req));
	req.hdr = &req_hdr.hdr;
	req.hdr_len = sizeof(req_hdr);

	memset(&resp, 0, sizeof(resp));
	resp.hdr = &resp_hdr.hdr;
	resp.hdr_len = sizeof(resp_hdr);
	resp.data = data;
	resp.data_len = *data_len;

	rc = nvme_mi_submit(ep, &req, &resp);
	if (rc)
		return rc;

	if (resp_hdr.status)
		return resp_hdr.status;

	*data_len = resp.data_len;

	return 0;
}

int nvme_mi_mi_read_mi_data_subsys(nvme_mi_ep_t ep,
				   struct nvme_mi_read_nvm_ss_info *s)
{
	size_t len;
	__u32 cdw0;
	int rc;

	cdw0 = (__u8)nvme_mi_dtyp_subsys_info << 24;
	len = sizeof(*s);

	rc = nvme_mi_read_data(ep, cdw0, s, &len);
	if (rc)
		return rc;

	if (len != sizeof(*s)) {
		nvme_msg(ep->root, LOG_WARNING,
			 "MI read data length mismatch: "
			 "got %zd bytes, expected %zd\n",
			 len, sizeof(*s));
		errno = EPROTO;
		return -1;
	}

	return 0;
}

int nvme_mi_mi_read_mi_data_port(nvme_mi_ep_t ep, __u8 portid,
				 struct nvme_mi_read_port_info *p)
{
	size_t len;
	__u32 cdw0;
	int rc;

	cdw0 = ((__u8)nvme_mi_dtyp_port_info << 24) | (portid << 16);
	len = sizeof(*p);

	rc = nvme_mi_read_data(ep, cdw0, p, &len);
	if (rc)
		return rc;

	if (len != sizeof(*p)) {
		errno = EPROTO;
		return -1;
	}

	return 0;
}

int nvme_mi_mi_read_mi_data_ctrl_list(nvme_mi_ep_t ep, __u8 start_ctrlid,
				       struct nvme_ctrl_list *list)
{
	size_t len;
	__u32 cdw0;
	int rc;

	cdw0 = ((__u8)nvme_mi_dtyp_ctrl_list << 24) | (start_ctrlid << 16);
	len = sizeof(*list);

	rc = nvme_mi_read_data(ep, cdw0, list, &len);
	if (rc)
		return rc;

	return 0;
}

int nvme_mi_mi_read_mi_data_ctrl(nvme_mi_ep_t ep, __u16 ctrl_id,
				       struct nvme_mi_read_ctrl_info *ctrl)
{
	size_t len;
	__u32 cdw0;
	int rc;

	cdw0 = ((__u8)nvme_mi_dtyp_ctrl_info << 24) | cpu_to_le16(ctrl_id);
	len = sizeof(*ctrl);

	rc = nvme_mi_read_data(ep, cdw0, ctrl, &len);
	if (rc)
		return rc;

	if (len != sizeof(*ctrl)) {
		errno = EPROTO;
		return -1;
	}

	return 0;
}

int nvme_mi_mi_subsystem_health_status_poll(nvme_mi_ep_t ep, bool clear,
					    struct nvme_mi_nvm_ss_health_status *sshs)
{
	struct nvme_mi_mi_resp_hdr resp_hdr;
	struct nvme_mi_mi_req_hdr req_hdr;
	struct nvme_mi_resp resp;
	struct nvme_mi_req req;
	int rc;

	memset(&req_hdr, 0, sizeof(req_hdr));
	req_hdr.hdr.type = NVME_MI_MSGTYPE_NVME;;
	req_hdr.hdr.nmp = (NVME_MI_ROR_REQ << 7) |
		(NVME_MI_MT_MI << 3);
	req_hdr.opcode = nvme_mi_mi_opcode_subsys_health_status_poll;
	req_hdr.cdw1 = (clear ? 1 : 0) << 31;

	memset(&req, 0, sizeof(req));
	req.hdr = &req_hdr.hdr;
	req.hdr_len = sizeof(req_hdr);

	memset(&resp, 0, sizeof(resp));
	resp.hdr = &resp_hdr.hdr;
	resp.hdr_len = sizeof(resp_hdr);
	resp.data = sshs;
	resp.data_len = sizeof(*sshs);

	rc = nvme_mi_submit(ep, &req, &resp);
	if (rc)
		return rc;

	if (resp_hdr.status)
		return resp_hdr.status;

	if (resp.data_len != sizeof(*sshs)) {
		nvme_msg(ep->root, LOG_WARNING,
			 "MI Subsystem Health Status length mismatch: "
			 "got %zd bytes, expected %zd\n",
			 resp.data_len, sizeof(*sshs));
		errno = EPROTO;
		return -1;
	}

	return 0;
}

int nvme_mi_mi_config_get(nvme_mi_ep_t ep, __u32 dw0, __u32 dw1,
			  __u32 *nmresp)
{
	struct nvme_mi_mi_resp_hdr resp_hdr;
	struct nvme_mi_mi_req_hdr req_hdr;
	struct nvme_mi_resp resp;
	struct nvme_mi_req req;
	int rc;

	memset(&req_hdr, 0, sizeof(req_hdr));
	req_hdr.hdr.type = NVME_MI_MSGTYPE_NVME;
	req_hdr.hdr.nmp = (NVME_MI_ROR_REQ << 7) | (NVME_MI_MT_MI << 3);
	req_hdr.opcode = nvme_mi_mi_opcode_configuration_get;
	req_hdr.cdw0 = cpu_to_le32(dw0);
	req_hdr.cdw1 = cpu_to_le32(dw1);

	memset(&req, 0, sizeof(req));
	req.hdr = &req_hdr.hdr;
	req.hdr_len = sizeof(req_hdr);

	memset(&resp, 0, sizeof(resp));
	resp.hdr = &resp_hdr.hdr;
	resp.hdr_len = sizeof(resp_hdr);

	rc = nvme_mi_submit(ep, &req, &resp);
	if (rc)
		return rc;

	if (resp_hdr.status)
		return resp_hdr.status;

	*nmresp = resp_hdr.nmresp[0] |
		  resp_hdr.nmresp[1] << 8 |
		  resp_hdr.nmresp[2] << 16;

	return 0;
}

int nvme_mi_mi_config_set(nvme_mi_ep_t ep, __u32 dw0, __u32 dw1)
{
	struct nvme_mi_mi_resp_hdr resp_hdr;
	struct nvme_mi_mi_req_hdr req_hdr;
	struct nvme_mi_resp resp;
	struct nvme_mi_req req;
	int rc;

	memset(&req_hdr, 0, sizeof(req_hdr));
	req_hdr.hdr.type = NVME_MI_MSGTYPE_NVME;
	req_hdr.hdr.nmp = (NVME_MI_ROR_REQ << 7) | (NVME_MI_MT_MI << 3);
	req_hdr.opcode = nvme_mi_mi_opcode_configuration_set;
	req_hdr.cdw0 = cpu_to_le32(dw0);
	req_hdr.cdw1 = cpu_to_le32(dw1);

	memset(&req, 0, sizeof(req));
	req.hdr = &req_hdr.hdr;
	req.hdr_len = sizeof(req_hdr);

	memset(&resp, 0, sizeof(resp));
	resp.hdr = &resp_hdr.hdr;
	resp.hdr_len = sizeof(resp_hdr);

	rc = nvme_mi_submit(ep, &req, &resp);
	if (rc)
		return rc;

	if (resp_hdr.status)
		return resp_hdr.status;

	return 0;
}

void nvme_mi_close(nvme_mi_ep_t ep)
{
	struct nvme_mi_ctrl *ctrl, *tmp;

	/* don't look for controllers during destruction */
	ep->controllers_scanned = true;

	nvme_mi_for_each_ctrl_safe(ep, ctrl, tmp)
		nvme_mi_close_ctrl(ctrl);

	if (ep->transport && ep->transport->close)
		ep->transport->close(ep);
	list_del(&ep->root_entry);
	free(ep);
}

void nvme_mi_close_ctrl(nvme_mi_ctrl_t ctrl)
{
	list_del(&ctrl->ep_entry);
	free(ctrl);
}

char *nvme_mi_endpoint_desc(nvme_mi_ep_t ep)
{
	char tsbuf[101], *s = NULL;
	size_t tslen;
	int rc;

	rc = -1;
	memset(tsbuf, 0, sizeof(tsbuf));
	if (ep->transport->desc_ep)
		rc = ep->transport->desc_ep(ep, tsbuf, sizeof(tsbuf) - 1);

	if (!rc) {
		/* don't overflow if the transport gives us an invalid string */
		tsbuf[sizeof(tsbuf)-1] = '\0';
		tslen = strlen(tsbuf);
	} else {
		tslen = 0;
	}

	if (tslen)
		rc = asprintf(&s, "%s: %s", ep->transport->name, tsbuf);
	else
		rc = asprintf(&s, "%s endpoint", ep->transport->name);

	if (rc < 0)
		return NULL;

	return s;
}

nvme_mi_ep_t nvme_mi_first_endpoint(nvme_root_t m)
{
	return list_top(&m->endpoints, struct nvme_mi_ep, root_entry);
}

nvme_mi_ep_t nvme_mi_next_endpoint(nvme_root_t m, nvme_mi_ep_t ep)
{
	return ep ? list_next(&m->endpoints, ep, root_entry) : NULL;
}

nvme_mi_ctrl_t nvme_mi_first_ctrl(nvme_mi_ep_t ep)
{
	return list_top(&ep->controllers, struct nvme_mi_ctrl, ep_entry);
}

nvme_mi_ctrl_t nvme_mi_next_ctrl(nvme_mi_ep_t ep, nvme_mi_ctrl_t c)
{
	return c ? list_next(&ep->controllers, c, ep_entry) : NULL;
}


static const char *const mi_status[] = {
        [NVME_MI_RESP_MPR]                   = "More Processing Required: The command message is in progress and requires more time to complete processing",
        [NVME_MI_RESP_INTERNAL_ERR]          = "Internal Error: The request message could not be processed due to a vendor-specific error",
        [NVME_MI_RESP_INVALID_OPCODE]        = "Invalid Command Opcode",
        [NVME_MI_RESP_INVALID_PARAM]         = "Invalid Parameter",
        [NVME_MI_RESP_INVALID_CMD_SIZE]      = "Invalid Command Size: The size of the message body of the request was different than expected",
        [NVME_MI_RESP_INVALID_INPUT_SIZE]    = "Invalid Command Input Data Size: The command requires data and contains too much or too little data",
        [NVME_MI_RESP_ACCESS_DENIED]         = "Access Denied. Processing prohibited due to a vendor-specific mechanism of the Command and Feature lockdown function",
        [NVME_MI_RESP_VPD_UPDATES_EXCEEDED]  = "VPD Updates Exceeded",
        [NVME_MI_RESP_PCIE_INACCESSIBLE]     = "PCIe Inaccessible. The PCIe functionality is not available at this time",
        [NVME_MI_RESP_MEB_SANITIZED]         = "Management Endpoint Buffer Cleared Due to Sanitize",
        [NVME_MI_RESP_ENC_SERV_FAILURE]      = "Enclosure Services Failure",
        [NVME_MI_RESP_ENC_SERV_XFER_FAILURE] = "Enclosure Services Transfer Failure: Communication with the Enclosure Services Process has failed",
        [NVME_MI_RESP_ENC_FAILURE]           = "An unrecoverable enclosure failure has been detected by the Enclosuer Services Process",
        [NVME_MI_RESP_ENC_XFER_REFUSED]      = "Enclosure Services Transfer Refused: The NVM Subsystem or Enclosure Services Process indicated an error or an invalid format in communication",
        [NVME_MI_RESP_ENC_FUNC_UNSUP]        = "Unsupported Enclosure Function: An SES Send command has been attempted to a simple Subenclosure",
        [NVME_MI_RESP_ENC_SERV_UNAVAIL]      = "Enclosure Services Unavailable: The NVM Subsystem or Enclosure Services Process has encountered an error but may become available again",
        [NVME_MI_RESP_ENC_DEGRADED]          = "Enclosure Degraded: A noncritical failure has been detected by the Enclosure Services Process",
        [NVME_MI_RESP_SANITIZE_IN_PROGRESS]  = "Sanitize In Progress: The requested command is prohibited while a sanitize operation is in progress",
};

/* kept in mi.c while we have a split libnvme/libnvme-mi; consider moving
 * to utils.c (with nvme_status_to_string) if we ever merge. */
const char *nvme_mi_status_to_string(int status)
{
	const char *s = "Unknown status";

	if (status < ARRAY_SIZE(mi_status) && mi_status[status])
                s = mi_status[status];

        return s;
}
