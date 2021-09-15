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

int nvme_mi_mi_read_mi_data_ctrl_list(nvme_mi_ep_t ep, __u8 start_portid,
				       struct nvme_ctrl_list *list)
{
	size_t len;
	__u32 cdw0;
	int rc;

	cdw0 = ((__u8)nvme_mi_dtyp_ctrl_list << 24) | (start_portid << 16);
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
