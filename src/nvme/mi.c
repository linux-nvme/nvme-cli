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

#include <ccan/endian/endian.h>

#include "log.h"
#include "mi.h"
#include "private.h"

/* MI-equivalent of nvme_create_root, but avoids clashing symbol names
 * when linking against both libnvme and libnvme-mi.
 */
nvme_root_t nvme_mi_create_root(FILE *fp, int log_level)
{
	struct nvme_root *r = calloc(1, sizeof(*r));

	if (!r) {
		errno = ENOMEM;
		return NULL;
	}
	r->log_level = log_level;
	r->fp = stderr;
	if (fp)
		r->fp = fp;
	return r;
}

void nvme_mi_free_root(nvme_root_t root)
{
	free(root);
}

struct nvme_mi_ep *nvme_mi_init_ep(nvme_root_t root)
{
	struct nvme_mi_ep *ep;

	ep = malloc(sizeof(*ep));
	ep->root = root;

	return ep;
}

struct nvme_mi_ctrl *nvme_mi_init_ctrl(nvme_mi_ep_t ep, __u16 ctrl_id)
{
	struct nvme_mi_ctrl *ctrl;

	ctrl = malloc(sizeof(*ctrl));
	if (!ctrl)
		return NULL;

	ctrl->ep = ep;
	ctrl->id = ctrl_id;

	return ctrl;
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

	if (ep->transport->mic_enabled)
		nvme_mi_calc_req_mic(req);

	rc = ep->transport->submit(ep, req, resp);
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

	if (*resp_data_size > 0xffffffff)
		return -EINVAL;
	if (resp_data_offset > 0xffffffff)
		return -EINVAL;

	admin_req->hdr.type = NVME_MI_MSGTYPE_NVME;
	admin_req->hdr.nmp = (NVME_MI_ROR_REQ << 7) |
				(NVME_MI_MT_ADMIN << 3);
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

int nvme_mi_admin_identify_partial(nvme_mi_ctrl_t ctrl,
				   struct nvme_identify_args *args,
				   off_t offset, size_t size)
{
	struct nvme_mi_admin_resp_hdr resp_hdr;
	struct nvme_mi_admin_req_hdr req_hdr;
	struct nvme_mi_resp resp;
	struct nvme_mi_req req;
	int rc;

	if (args->args_size < sizeof(*args))
		return -EINVAL;

	if (!size || size > 0xffffffff)
		return -EINVAL;

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

	if (args->result)
		*args->result = le32_to_cpu(resp_hdr.cdw0);

	/* callers will expect a full response; if the data buffer isn't
	 * fully valid, return an error */
	if (resp.data_len != size)
		return -EPROTO;

	return 0;
}

/* retrieves a MCTP-messsage-sized chunk of log page data. offset and len are
 * specified within the args->data area */
static int __nvme_mi_admin_get_log_page(nvme_mi_ctrl_t ctrl,
					const struct nvme_get_log_args *args,
					off_t offset, size_t *lenp, bool final)
{
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
	if (!len || len > 4096 || len < 4)
		return -EINVAL;

	if (offset < 0 || offset >= len)
		return -EINVAL;

	ndw = (len >> 2) - 1;

	nvme_mi_admin_init_req(&req, &req_hdr, ctrl->id, nvme_admin_get_log_page);
	req_hdr.cdw1 = cpu_to_le32(args->nsid);
	req_hdr.cdw10 = cpu_to_le32((ndw & 0xffff) << 16 |
				    ((!final || args->rae) ? 1 : 0) << 15 |
				    args->lsp << 8 |
				    (args->lid & 0xff));
	req_hdr.cdw11 = cpu_to_le32(args->lsi << 16 |
				    ndw >> 16);
	req_hdr.cdw12 = cpu_to_le32(args->lpo & 0xffffffff);
	req_hdr.cdw13 = cpu_to_le32(args->lpo >> 32);
	req_hdr.cdw14 = cpu_to_le32(args->csi << 24 |
				    (args->ot ? 1 : 0) << 23 |
				    args->uuidx);
	req_hdr.flags = 0x1;
	req_hdr.dlen = cpu_to_le32(len & 0xffffffff);
	if (offset) {
		req_hdr.flags |= 0x2;
		req_hdr.doff = cpu_to_le32(offset);
	}

	nvme_mi_calc_req_mic(&req);

	nvme_mi_admin_init_resp(&resp, &resp_hdr);
	resp.data = args->log + offset;
	resp.data_len = len;

	rc = nvme_mi_submit(ctrl->ep, &req, &resp);
	if (rc)
		return rc;

	if (resp_hdr.status)
		return resp_hdr.status;

	*lenp = resp.data_len;

	return 0;
}

int nvme_mi_admin_get_log_page(nvme_mi_ctrl_t ctrl,
			       struct nvme_get_log_args *args)
{
	const size_t xfer_size = 4096;
	off_t xfer_offset;
	int rc = 0;

	if (args->args_size < sizeof(*args))
		return -EINVAL;

	for (xfer_offset = 0; xfer_offset < args->len;) {
		size_t tmp, cur_xfer_size = xfer_size;
		bool final;

		if (xfer_offset + cur_xfer_size > args->len)
			cur_xfer_size = args->len - xfer_offset;

		tmp = cur_xfer_size;

		final = xfer_offset + cur_xfer_size >= args->len;

		rc = __nvme_mi_admin_get_log_page(ctrl, args, xfer_offset,
						  &tmp, final);
		if (rc)
			break;

		xfer_offset += tmp;
		/* if we returned less data than expected, consider that
		 * the end of the log page */
		if (tmp != cur_xfer_size)
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

	if (args->args_size < sizeof(*args))
		return -EINVAL;

	if (args->data_len > 4096)
		return -EINVAL;

	nvme_mi_admin_init_req(&req, &req_hdr, ctrl->id,
			       nvme_admin_security_send);

	req_hdr.cdw10 = cpu_to_le32(args->secp << 24 |
				    args->spsp0 << 16 |
				    args->spsp1 << 8 |
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

	if (resp_hdr.status)
		return resp_hdr.status;

	if (args->result)
		*args->result = le32_to_cpu(resp_hdr.cdw0);

	return 0;
}

int nvme_mi_admin_security_recv(nvme_mi_ctrl_t ctrl,
				struct nvme_security_receive_args *args)
{

	struct nvme_mi_admin_resp_hdr resp_hdr;
	struct nvme_mi_admin_req_hdr req_hdr;
	struct nvme_mi_resp resp;
	struct nvme_mi_req req;
	int rc;

	if (args->args_size < sizeof(*args))
		return -EINVAL;

	if (args->data_len > 4096)
		return -EINVAL;

	nvme_mi_admin_init_req(&req, &req_hdr, ctrl->id,
			       nvme_admin_security_recv);

	req_hdr.cdw10 = cpu_to_le32(args->secp << 24 |
				    args->spsp0 << 16 |
				    args->spsp1 << 8 |
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

	if (resp_hdr.status)
		return resp_hdr.status;

	if (args->result)
		*args->result = resp_hdr.cdw0;

	args->data_len = resp.data_len;

	return 0;
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
	req_hdr.cdw0 = cdw0;

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

	*data_len = resp.data_len;

	/* check status, map to return value */
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
		return -EPROTO;
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
		/* log? */
		return -EPROTO;
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

	if (len != sizeof(*ctrl))
		return -EPROTO;

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

	if (resp.data_len != sizeof(*sshs)) {
		nvme_msg(ep->root, LOG_WARNING,
			 "MI Subsystem Health Status length mismatch: "
			 "got %zd bytes, expected %zd\n",
			 resp.data_len, sizeof(*sshs));
		return -EIO;
	}

	/* check status, map to return value */
	return 0;
}

void nvme_mi_close(nvme_mi_ep_t ep)
{
	if (ep->transport->close)
		ep->transport->close(ep);
	free(ep);
}

void nvme_mi_close_ctrl(nvme_mi_ctrl_t ctrl)
{
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
