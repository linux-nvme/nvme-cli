// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libnvme.
 * Copyright (c) 2022 Code Construct
 */

#undef NDEBUG
#include <shared/assert-util.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <ccan/array_size/array_size.h>
#include <ccan/endian/endian.h>

#include <libnvme.h>
#include <libnvme-mi.h>

/* we define a custom transport, so need the internal headers */
#include "nvme/private.h"
#include "nvme/private-mi.h"

#include "utils.h"

typedef int (*test_submit_cb)(struct libnvme_mi_ep *ep,
			      struct libnvme_mi_req *req,
			      struct libnvme_mi_resp *resp,
			      void *data);

struct test_transport_data {
	unsigned int	magic;
	bool		named;
	test_submit_cb	submit_cb;
	void		*submit_cb_data;
};

static const int test_transport_magic = 0x74657374;

static int test_transport_submit(struct libnvme_mi_ep *ep,
				 struct libnvme_mi_req *req,
				 struct libnvme_mi_resp *resp)
{
	struct test_transport_data *tpd = ep->transport_data;

	shr_assert(tpd->magic == test_transport_magic);

	/* start from a minimal response: zeroed data, nmp to match request */
	memset(resp->hdr, 0, resp->hdr_len);
	if (resp->data_len)
		memset(resp->data, 0, resp->data_len);
	resp->hdr->type = NVME_MI_MSGTYPE_NVME;
	resp->hdr->nmp = req->hdr->nmp | (NVME_MI_ROR_RSP << 7);

	if (tpd->submit_cb)
		return tpd->submit_cb(ep, req, resp, tpd->submit_cb_data);

	return 0;
}

static void test_transport_close(struct libnvme_mi_ep *ep)
{
	struct test_transport_data *tpd = ep->transport_data;
	shr_assert(tpd->magic == test_transport_magic);
	free(tpd);
}

static int test_transport_desc_ep(struct libnvme_mi_ep *ep,
				    char *buf, size_t len)
{
	struct test_transport_data *tpd = ep->transport_data;

	shr_assert(tpd->magic == test_transport_magic);

	if (!tpd->named)
		return -1;

	snprintf(buf, len, "test endpoint 0x%x", tpd->magic);

	return 0;
}

/* internal test helper to generate correct response crc */
static void test_transport_resp_calc_mic(struct libnvme_mi_resp *resp)
{
	extern __u32 libnvme_mi_crc32_update(__u32 crc, void *data, size_t len);
	__u32 crc = 0xffffffff;

	crc = libnvme_mi_crc32_update(crc, resp->hdr, resp->hdr_len);
	crc = libnvme_mi_crc32_update(crc, resp->data, resp->data_len);

	resp->mic = ~crc;
}

static const struct libnvme_mi_transport test_transport = {
	.name = "test-mi",
	.mic_enabled = true,
	.submit = test_transport_submit,
	.close = test_transport_close,
	.desc_ep = test_transport_desc_ep,
	//The following aren't actually used by the test_transport
	.aem_fd = NULL,
	.aem_purge = NULL,
	.aem_read = NULL,
};

static void test_set_transport_callback(struct libnvme_mi_ep *ep, test_submit_cb cb,
					void *data)
{
	struct test_transport_data *tpd = ep->transport_data;
	shr_assert(tpd->magic == test_transport_magic);

	tpd->submit_cb = cb;
	tpd->submit_cb_data = data;
}

struct libnvme_mi_ep *libnvme_mi_open_test(struct libnvme_global_ctx *ctx)
{
	struct test_transport_data *tpd;
	struct libnvme_mi_ep *ep;

	ep = libnvme_mi_init_ep(ctx);
	shr_assert(ep);

	/* preempt the quirk probe to avoid clutter */
	ep->quirks_probed = true;

	tpd = malloc(sizeof(*tpd));
	shr_assert(tpd);

	tpd->magic = test_transport_magic;
	tpd->named = true;

	ep->transport = &test_transport;
	ep->transport_data = tpd;

	return ep;
}

unsigned int count_root_eps(struct libnvme_global_ctx *ctx)
{
	unsigned int i = 0;
	struct libnvme_mi_ep *ep;

	libnvme_mi_for_each_endpoint(ctx, ep)
		i++;

	return i;
}

/* test that the root->endpoints list is updated on endpoint
 * creation/destruction */
static void test_endpoint_lifetime(struct libnvme_mi_ep *ep)
{
	struct libnvme_global_ctx *ctx= ep->ctx;
	unsigned int count;
	struct libnvme_mi_ep *ep2;

	count = count_root_eps(ctx);
	shr_assert(count == 1);

	ep2 = libnvme_mi_open_test(ctx);
	count = count_root_eps(ctx);
	shr_assert(count == 2);

	libnvme_mi_close(ep2);
	count = count_root_eps(ctx);
	shr_assert(count == 1);
}

unsigned int count_ep_controllers(struct libnvme_mi_ep *ep)
{
	struct libnvme_transport_handle *hdl;
	unsigned int i = 0;

	libnvme_mi_for_each_transport_handle(ep, hdl)
		i++;

	return i;
}

/* test that the ep->controllers list is updated on controller
 * creation/destruction */
static void test_ctrl_lifetime(struct libnvme_mi_ep *ep)
{
	struct libnvme_transport_handle *hdl1, *hdl2;
	int count;

	ep->controllers_scanned = true;

	count = count_ep_controllers(ep);
	shr_assert(count == 0);

	hdl1 = libnvme_mi_init_transport_handle(ep, 1);
	count = count_ep_controllers(ep);
	shr_assert(count == 1);

	hdl2 = libnvme_mi_init_transport_handle(ep, 2);
	count = count_ep_controllers(ep);
	shr_assert(count == 2);

	libnvme_close(hdl1);
	count = count_ep_controllers(ep);
	shr_assert(count == 1);

	libnvme_close(hdl2);
	count = count_ep_controllers(ep);
	shr_assert(count == 0);
}


/* test: basic read MI datastructure command */
static int test_read_mi_data_cb(struct libnvme_mi_ep *ep,
				 struct libnvme_mi_req *req,
				 struct libnvme_mi_resp *resp,
				 void *data)
{
	__u8 ror, mt, *hdr, *buf;

	shr_assert(req->hdr->type == NVME_MI_MSGTYPE_NVME);

	ror = req->hdr->nmp >> 7;
	mt = req->hdr->nmp >> 3 & 0x7;
	shr_assert(ror == NVME_MI_ROR_REQ);
	shr_assert(mt == NVME_MI_MT_MI);

	/* do we have enough for a mi header? */
	shr_assert(req->hdr_len == sizeof(struct nvme_mi_mi_req_hdr));

	/* inspect response as raw bytes */
	hdr = (__u8 *)req->hdr;
	shr_assert(hdr[4] == nvme_mi_mi_opcode_mi_data_read);

	/* create basic response */
	shr_assert(resp->hdr_len >= sizeof(struct nvme_mi_mi_resp_hdr));
	shr_assert(resp->data_len >= 4);

	hdr = (__u8 *)resp->hdr;
	hdr[4] = 0; /* status */

	buf = (__u8 *)resp->data;
	memset(buf, 0, resp->data_len);
	buf[0] = 1; /* NUMP */
	buf[1] = 1; /* MJR */
	buf[2] = 2; /* MNR */

	test_transport_resp_calc_mic(resp);

	return 0;
}

static void test_read_mi_data(struct libnvme_mi_ep *ep)
{
	struct nvme_mi_read_nvm_ss_info ss_info;
	int rc;

	test_set_transport_callback(ep, test_read_mi_data_cb, NULL);

	rc = libnvme_mi_mi_read_mi_data_subsys(ep, &ss_info);
	shr_assert(rc == 0);
}

/* test: failed transport */
static int test_transport_fail_cb(struct libnvme_mi_ep *ep,
				  struct libnvme_mi_req *req,
				  struct libnvme_mi_resp *resp,
				  void *data)
{
	return -1;
}

static void test_transport_fail(struct libnvme_mi_ep *ep)
{
	struct nvme_mi_read_nvm_ss_info ss_info;
	int rc;

	test_set_transport_callback(ep, test_transport_fail_cb, NULL);
	rc = libnvme_mi_mi_read_mi_data_subsys(ep, &ss_info);
	shr_assert(rc != 0);
}

static void test_transport_describe(struct libnvme_mi_ep *ep)
{
	struct test_transport_data *tpd;
	char *str;

	tpd = (struct test_transport_data *)ep->transport_data;

	tpd->named = false;
	str = libnvme_mi_endpoint_desc(ep);
	shr_assert(str);
	shr_assert(!strcmp(str, "test-mi endpoint"));
	free(str);

	tpd->named = true;
	str = libnvme_mi_endpoint_desc(ep);
	shr_assert(str);
	shr_assert(!strcmp(str, "test-mi: test endpoint 0x74657374"));
	free(str);
}

/* test: invalid crc */
static int test_invalid_crc_cb(struct libnvme_mi_ep *ep,
				      struct libnvme_mi_req *req,
				      struct libnvme_mi_resp *resp,
				      void *data)
{
	resp->mic = 0;
	return 0;
}

static void test_invalid_crc(struct libnvme_mi_ep *ep)
{
	struct nvme_mi_read_nvm_ss_info ss_info;
	int rc;

	test_set_transport_callback(ep, test_invalid_crc_cb, NULL);
	rc = libnvme_mi_mi_read_mi_data_subsys(ep, &ss_info);
	shr_assert(rc < 0);
}

/* test: test that the controller list populates the endpoint's list of
 * controllers */
static int test_scan_ctrl_list_cb(struct libnvme_mi_ep *ep,
				  struct libnvme_mi_req *req,
				  struct libnvme_mi_resp *resp,
				  void *data)
{
	__u8 ror, mt, *hdr, *buf;

	shr_assert(req->hdr->type == NVME_MI_MSGTYPE_NVME);

	ror = req->hdr->nmp >> 7;
	mt = req->hdr->nmp >> 3 & 0x7;
	shr_assert(ror == NVME_MI_ROR_REQ);
	shr_assert(mt == NVME_MI_MT_MI);

	/* do we have enough for a mi header? */
	shr_assert(req->hdr_len == sizeof(struct nvme_mi_mi_req_hdr));

	/* inspect response as raw bytes */
	hdr = (__u8 *)req->hdr;
	shr_assert(hdr[4] == nvme_mi_mi_opcode_mi_data_read);
	shr_assert(hdr[11] == nvme_mi_dtyp_ctrl_list);

	/* create basic response */
	shr_assert(resp->hdr_len >= sizeof(struct nvme_mi_mi_resp_hdr));
	shr_assert(resp->data_len >= 4);

	hdr = (__u8 *)resp->hdr;
	hdr[4] = 0; /* status */

	buf = (__u8 *)resp->data;
	memset(buf, 0, resp->data_len);
	buf[0] = 3; buf[1] = 0; /* num controllers */
	buf[2] = 1; buf[3] = 0; /* id 1 */
	buf[4] = 4; buf[5] = 0; /* id 4 */
	buf[6] = 5; buf[7] = 0; /* id 5 */

	test_transport_resp_calc_mic(resp);

	return 0;
}

static void test_scan_ctrl_list(struct libnvme_mi_ep *ep)
{
	struct libnvme_transport_handle *hdl;

	ep->controllers_scanned = false;

	test_set_transport_callback(ep, test_scan_ctrl_list_cb, NULL);

	libnvme_mi_scan_ep(ep, false);

	hdl = libnvme_mi_first_transport_handle(ep);
	shr_assert(hdl);
	shr_assert(hdl->id == 1);

	hdl = libnvme_mi_next_transport_handle(ep, hdl);
	shr_assert(hdl);
	shr_assert(hdl->id == 4);

	hdl = libnvme_mi_next_transport_handle(ep, hdl);
	shr_assert(hdl);
	shr_assert(hdl->id == 5);

	hdl = libnvme_mi_next_transport_handle(ep, hdl);
	shr_assert(hdl == NULL);
}

/* test: simple NVMe admin request/response */
static int test_admin_id_cb(struct libnvme_mi_ep *ep,
				  struct libnvme_mi_req *req,
				  struct libnvme_mi_resp *resp,
				  void *data)
{
	__u8 ror, mt, *hdr;
	__u32 dlen, cdw10;
	__u16 ctrl_id;
	__u8 flags;

	shr_assert(req->hdr->type == NVME_MI_MSGTYPE_NVME);

	ror = req->hdr->nmp >> 7;
	mt = req->hdr->nmp >> 3 & 0x7;
	shr_assert(ror == NVME_MI_ROR_REQ);
	shr_assert(mt == NVME_MI_MT_ADMIN);

	/* do we have enough for a mi header? */
	shr_assert(req->hdr_len == sizeof(struct nvme_mi_admin_req_hdr));

	/* inspect response as raw bytes */
	hdr = (__u8 *)req->hdr;
	shr_assert(hdr[4] == nvme_admin_identify);
	flags = hdr[5];

	ctrl_id = hdr[7] << 8 | hdr[6];
	shr_assert(ctrl_id == 0x5); /* controller id */

	/* we requested a full id; if we've set the length flag,
	 * ensure the length matches */
	dlen = hdr[35] << 24 | hdr[34] << 16 | hdr[33] << 8 | hdr[32];
	if (flags & 0x1) {
		shr_assert(dlen == sizeof(struct nvme_id_ctrl));
	}
	shr_assert(!(flags & 0x2));

	/* CNS value of 1 in cdw10 field */
	cdw10 = hdr[47] << 24 | hdr[46] << 16 | hdr[45] << 8 | hdr[44];
	shr_assert(cdw10 == 0x1);

	/* create valid (but somewhat empty) response */
	hdr = (__u8 *)resp->hdr;
	hdr[4] = 0x00; /* status: success */

	test_transport_resp_calc_mic(resp);

	return 0;
}

static void test_admin_id(struct libnvme_mi_ep *ep)
{
	struct libnvme_transport_handle *hdl;
	struct libnvme_passthru_cmd cmd;
	struct nvme_id_ctrl id;
	int rc;

	test_set_transport_callback(ep, test_admin_id_cb, NULL);

	hdl = libnvme_mi_init_transport_handle(ep, 5);
	shr_assert(hdl);

	nvme_init_identify_ctrl(&cmd, &id);
	rc = libnvme_exec_admin_passthru(hdl, &cmd);
	shr_assert(rc == 0);
}

/* test: simple NVMe error response, error reported in the MI header */
static int test_admin_err_mi_resp_cb(struct libnvme_mi_ep *ep,
				  struct libnvme_mi_req *req,
				  struct libnvme_mi_resp *resp,
				  void *data)
{
	__u8 ror, mt, *hdr;

	shr_assert(req->hdr->type == NVME_MI_MSGTYPE_NVME);

	ror = req->hdr->nmp >> 7;
	mt = req->hdr->nmp >> 3 & 0x7;
	shr_assert(ror == NVME_MI_ROR_REQ);
	shr_assert(mt == NVME_MI_MT_ADMIN);

	/* do we have enough for a mi header? */
	shr_assert(req->hdr_len == sizeof(struct nvme_mi_admin_req_hdr));

	/* inspect response as raw bytes */
	hdr = (__u8 *)req->hdr;
	shr_assert(hdr[4] == nvme_admin_identify);

	/* we need at least 8 bytes for error information */
	shr_assert(resp->hdr_len >= 8);

	/* create error response */
	hdr = (__u8 *)resp->hdr;
	hdr[4] = 0x02; /* status: internal error */
	hdr[5] = 0;
	hdr[6] = 0;
	hdr[7] = 0;
	resp->hdr_len = 8;
	resp->data_len = 0;

	test_transport_resp_calc_mic(resp);

	return 0;
}

static void test_admin_err_mi_resp(struct libnvme_mi_ep *ep)
{
	struct libnvme_transport_handle *hdl;
	struct libnvme_passthru_cmd cmd;
	struct nvme_id_ctrl id;
	int rc;

	test_set_transport_callback(ep, test_admin_err_mi_resp_cb, NULL);

	hdl = libnvme_mi_init_transport_handle(ep, 1);
	shr_assert(hdl);

	nvme_init_identify_ctrl(&cmd, &id);
	rc = libnvme_exec_admin_passthru(hdl, &cmd);
	shr_assert(rc != 0);
	shr_assert(nvme_status_get_type(rc) == NVME_STATUS_TYPE_MI);
	shr_assert(nvme_status_get_value(rc) == NVME_MI_RESP_INTERNAL_ERR);
}

/* test: NVMe Admin error, with the error reported in the Admin response */
static int test_admin_err_nvme_resp_cb(struct libnvme_mi_ep *ep,
				  struct libnvme_mi_req *req,
				  struct libnvme_mi_resp *resp,
				  void *data)
{
	__u8 ror, mt, *hdr;

	shr_assert(req->hdr->type == NVME_MI_MSGTYPE_NVME);

	ror = req->hdr->nmp >> 7;
	mt = req->hdr->nmp >> 3 & 0x7;
	shr_assert(ror == NVME_MI_ROR_REQ);
	shr_assert(mt == NVME_MI_MT_ADMIN);

	/* do we have enough for a mi header? */
	shr_assert(req->hdr_len == sizeof(struct nvme_mi_admin_req_hdr));

	/* inspect response as raw bytes */
	hdr = (__u8 *)req->hdr;
	shr_assert(hdr[4] == nvme_admin_identify);

	/* we need at least 8 bytes for error information */
	shr_assert(resp->hdr_len >= sizeof(struct nvme_mi_admin_resp_hdr));

	/* create error response */
	hdr = (__u8 *)resp->hdr;
	hdr[4] = 0; /* MI status: success */
	hdr[5] = 0;
	hdr[6] = 0;
	hdr[7] = 0;

	hdr[16] = 0; /* cdw3: SC: internal, SCT: generic, DNR */
	hdr[17] = 0;
	hdr[18] = 0x0c;
	hdr[19] = 0x80;

	resp->hdr_len = sizeof(struct nvme_mi_admin_resp_hdr);
	resp->data_len = 0;

	test_transport_resp_calc_mic(resp);

	return 0;
}

static void test_admin_err_nvme_resp(struct libnvme_mi_ep *ep)
{
	struct nvme_id_ctrl id;
	struct libnvme_transport_handle *hdl;
	struct libnvme_passthru_cmd cmd;
	int rc;

	test_set_transport_callback(ep, test_admin_err_nvme_resp_cb, NULL);

	hdl = libnvme_mi_init_transport_handle(ep, 1);
	shr_assert(hdl);

	nvme_init_identify_ctrl(&cmd, &id);
	rc = libnvme_exec_admin_passthru(hdl, &cmd);
	shr_assert(rc != 0);
	shr_assert(nvme_status_get_type(rc) == NVME_STATUS_TYPE_NVME);
	shr_assert(nvme_status_get_value(rc) ==
	       (NVME_SC_INTERNAL | (NVME_SCT_GENERIC << NVME_SCT_SHIFT)
		| NVME_SC_DNR));
}

/* invalid command transfers */
static int test_rejected_command_cb(struct libnvme_mi_ep *ep,
					 struct libnvme_mi_req *req,
					 struct libnvme_mi_resp *resp,
					 void *data)
{
	/* none of the tests should result in message transfer */
	shr_assert(0);
	return -1;
}

static void test_admin_invalid_formats(struct libnvme_mi_ep *ep)
{
	struct {
		struct nvme_mi_admin_req_hdr hdr;
		uint8_t data[4];
	} req = { 0 };
	struct nvme_mi_admin_resp_hdr resp = { 0 };
	struct libnvme_transport_handle *hdl;
	size_t len;
	int rc;

	test_set_transport_callback(ep, test_rejected_command_cb, NULL);

	hdl = libnvme_mi_init_transport_handle(ep, 1);
	shr_assert(hdl);

	/* unaligned req size */
	len = 0;
	rc = libnvme_mi_admin_xfer(hdl, &req.hdr, 1, &resp, 0, &len);
	shr_assert(rc != 0);

	/* unaligned resp size */
	len = 1;
	rc = libnvme_mi_admin_xfer(hdl, &req.hdr, 0, &resp, 0, &len);
	shr_assert(rc != 0);

	/* unaligned resp offset */
	len = 4;
	rc = libnvme_mi_admin_xfer(hdl, &req.hdr, 0, &resp, 1, &len);
	shr_assert(rc != 0);

	/* resp too large */
	len = 4096 + 4;
	rc = libnvme_mi_admin_xfer(hdl, &req.hdr, 0, &resp, 0, &len);
	shr_assert(rc != 0);

	/* resp offset too large */
	len = 4;
	rc = libnvme_mi_admin_xfer(hdl, &req.hdr, 0, &resp, (off_t)1 << 32, &len);
	shr_assert(rc != 0);

	/* resp offset with no len */
	len = 0;
	rc = libnvme_mi_admin_xfer(hdl, &req.hdr, 0, &resp, 4, &len);
	shr_assert(rc != 0);

	/* req and resp payloads */
	len = 4;
	rc = libnvme_mi_admin_xfer(hdl, &req.hdr, 4, &resp, 0, &len);
	shr_assert(rc != 0);
}

static void test_mi_invalid_formats(struct libnvme_mi_ep *ep)
{
	struct {
		struct nvme_mi_mi_req_hdr hdr;
		uint8_t data[4];
	} req = { 0 };
	struct nvme_mi_mi_resp_hdr resp = { 0 };
	struct libnvme_transport_handle *hdl;
	size_t len;
	int rc;

	test_set_transport_callback(ep, test_rejected_command_cb, NULL);

	hdl = libnvme_mi_init_transport_handle(ep, 1);
	shr_assert(hdl);

	/* resp too large */
	len = 4096 + 4;
	rc = libnvme_mi_mi_xfer(ep, &req.hdr, 0, &resp, &len);
	shr_assert(rc != 0);
}

/* test: header length too small */
static int test_resp_hdr_small_cb(struct libnvme_mi_ep *ep,
				  struct libnvme_mi_req *req,
				  struct libnvme_mi_resp *resp,
				  void *data)
{
	resp->hdr_len = 2;
	test_transport_resp_calc_mic(resp);
	return 0;
}

static void test_resp_hdr_small(struct libnvme_mi_ep *ep)
{
	struct nvme_mi_read_nvm_ss_info ss_info;
	int rc;

	test_set_transport_callback(ep, test_resp_hdr_small_cb, NULL);

	rc = libnvme_mi_mi_read_mi_data_subsys(ep, &ss_info);
	shr_assert(rc != 0);
}

/* test: respond with a request message */
static int test_resp_req_cb(struct libnvme_mi_ep *ep,
			    struct libnvme_mi_req *req,
			    struct libnvme_mi_resp *resp,
			    void *data)
{
	resp->hdr->nmp &= ~(NVME_MI_ROR_RSP << 7);
	test_transport_resp_calc_mic(resp);
	return 0;
}

static void test_resp_req(struct libnvme_mi_ep *ep)
{
	struct nvme_mi_read_nvm_ss_info ss_info;
	int rc;

	test_set_transport_callback(ep, test_resp_req_cb, NULL);

	rc = libnvme_mi_mi_read_mi_data_subsys(ep, &ss_info);
	shr_assert(rc != 0);
}

/* test: invalid MCTP type in response */
static int test_resp_invalid_type_cb(struct libnvme_mi_ep *ep,
				     struct libnvme_mi_req *req,
				     struct libnvme_mi_resp *resp,
				     void *data)
{
	resp->hdr->type = 0x3;
	test_transport_resp_calc_mic(resp);
	return 0;
}

static void test_resp_invalid_type(struct libnvme_mi_ep *ep)
{
	struct nvme_mi_read_nvm_ss_info ss_info;
	int rc;

	test_set_transport_callback(ep, test_resp_invalid_type_cb, NULL);

	rc = libnvme_mi_mi_read_mi_data_subsys(ep, &ss_info);
	shr_assert(rc != 0);
}

/* test: response with mis-matching command slot */
static int test_resp_csi_invert_cb(struct libnvme_mi_ep *ep,
			    struct libnvme_mi_req *req,
			    struct libnvme_mi_resp *resp,
			    void *data)
{
	resp->hdr->nmp ^= 0x1;
	test_transport_resp_calc_mic(resp);
	return 0;
}

/* test: validation of proper csi setting */
static int test_resp_csi_check_cb(struct libnvme_mi_ep *ep,
	struct libnvme_mi_req *req,
	struct libnvme_mi_resp *resp,
	void *data)
{
	shr_assert((req->hdr->nmp & 1) == (ep->csi & 1));
	return 0;
}

/* test: Ensure that csi bit is set properly in the request */
static void test_resp_csi_request(struct libnvme_mi_ep *ep)
{
	struct nvme_mi_read_nvm_ss_info ss_info;
	int rc;

	test_set_transport_callback(ep, test_resp_csi_check_cb, NULL);

	rc = libnvme_mi_mi_read_mi_data_subsys(ep, &ss_info);
	shr_assert(rc != 0);

	libnvme_mi_set_csi(ep, 1);//Change CSI

	rc = libnvme_mi_mi_read_mi_data_subsys(ep, &ss_info);
	shr_assert(rc != 0);

	libnvme_mi_set_csi(ep, 0);//Change CSI
}

/* test: Ensure that when csi bit set wrong in response,
 * it results in an error
 */
static void test_resp_csi_mismatch(struct libnvme_mi_ep *ep)
{
	struct nvme_mi_read_nvm_ss_info ss_info;
	int rc;

	test_set_transport_callback(ep, test_resp_csi_invert_cb, NULL);

	rc = libnvme_mi_mi_read_mi_data_subsys(ep, &ss_info);
	shr_assert(rc != 0);

	libnvme_mi_set_csi(ep, 1);//Change CSI

	rc = libnvme_mi_mi_read_mi_data_subsys(ep, &ss_info);
	shr_assert(rc != 0);

	libnvme_mi_set_csi(ep, 0);//Change CSI
}

/* test: config get MTU request & response layout, ensure we're handling
 * endianness in the 3-byte NMRESP field correctly */
static int test_mi_config_get_mtu_cb(struct libnvme_mi_ep *ep,
			    struct libnvme_mi_req *req,
			    struct libnvme_mi_resp *resp,
			    void *data)
{
	struct nvme_mi_mi_resp_hdr *mi_resp;
	uint8_t *buf;

	shr_assert(req->hdr_len == sizeof(struct nvme_mi_mi_req_hdr));
	shr_assert(req->data_len == 0);

	/* validate req as raw bytes */
	buf = (void *)req->hdr;
	shr_assert(buf[4] == nvme_mi_mi_opcode_configuration_get);
	/* dword 0: port and config id */
	shr_assert(buf[11] == 0x5);
	shr_assert(buf[8] == NVME_MI_CONFIG_MCTP_MTU);

	/* set MTU in response */
	mi_resp = (void *)resp->hdr;
	mi_resp->nmresp[1] = 0x12;
	mi_resp->nmresp[0] = 0x34;
	resp->hdr_len = sizeof(*mi_resp);
	resp->data_len = 0;

	test_transport_resp_calc_mic(resp);
	return 0;
}

static void test_mi_config_get_mtu(struct libnvme_mi_ep *ep)
{
	uint16_t mtu;
	int rc;

	test_set_transport_callback(ep, test_mi_config_get_mtu_cb, NULL);

	rc = libnvme_mi_mi_config_get_mctp_mtu(ep, 5, &mtu);
	shr_assert(rc == 0);
	shr_assert(mtu == 0x1234);
}

/* test: config set SMBus freq, both valid and invalid */
static int test_mi_config_set_freq_cb(struct libnvme_mi_ep *ep,
			    struct libnvme_mi_req *req,
			    struct libnvme_mi_resp *resp,
			    void *data)
{
	struct nvme_mi_mi_resp_hdr *mi_resp;
	uint8_t *buf;

	shr_assert(req->hdr_len == sizeof(struct nvme_mi_mi_req_hdr));
	shr_assert(req->data_len == 0);

	/* validate req as raw bytes */
	buf = (void *)req->hdr;
	shr_assert(buf[4] == nvme_mi_mi_opcode_configuration_set);
	/* dword 0: port and config id */
	shr_assert(buf[11] == 0x5);
	shr_assert(buf[8] == NVME_MI_CONFIG_SMBUS_FREQ);

	mi_resp = (void *)resp->hdr;
	resp->hdr_len = sizeof(*mi_resp);
	resp->data_len = 0;

	/* accept 100 & 400, reject others */
	switch (buf[9]) {
	case NVME_MI_CONFIG_SMBUS_FREQ_100kHz:
	case NVME_MI_CONFIG_SMBUS_FREQ_400kHz:
		mi_resp->status = 0;
		break;
	case NVME_MI_CONFIG_SMBUS_FREQ_1MHz:
	default:
		mi_resp->status = 0x4;
		break;
	}

	test_transport_resp_calc_mic(resp);
	return 0;
}

static void test_mi_config_set_freq(struct libnvme_mi_ep *ep)
{
	int rc;

	test_set_transport_callback(ep, test_mi_config_set_freq_cb, NULL);

	rc = libnvme_mi_mi_config_set_smbus_freq(ep, 5,
					      NVME_MI_CONFIG_SMBUS_FREQ_100kHz);
	shr_assert(rc == 0);
}

static void test_mi_config_set_freq_invalid(struct libnvme_mi_ep *ep)
{
	int rc;

	test_set_transport_callback(ep, test_mi_config_set_freq_cb, NULL);

	rc = libnvme_mi_mi_config_set_smbus_freq(ep, 5,
					      NVME_MI_CONFIG_SMBUS_FREQ_1MHz);
	shr_assert(rc == 4);
}

/* test: PDA read request layout (opcode, DFORMAT, DOFST, DLEN), and that a
 * response shorter than the caller's buffer updates *data_len accordingly */
static int test_mi_pda_read_cb(struct libnvme_mi_ep *ep,
			    struct libnvme_mi_req *req,
			    struct libnvme_mi_resp *resp,
			    void *data)
{
	struct nvme_mi_mi_resp_hdr *mi_resp;
	uint8_t *buf, *rs_data;
	__u32 dofst, dlen;

	shr_assert(req->hdr_len == sizeof(struct nvme_mi_mi_req_hdr));
	shr_assert(req->data_len == 0);

	/* validate req as raw bytes */
	buf = (void *)req->hdr;
	shr_assert(buf[4] == nvme_mi_mi_opcode_pda_read);
	/* DFORMAT is the first reserved byte, following the opcode */
	shr_assert(buf[5] == nvme_mi_pda_dformat_512b);

	/* cdw0: DOFST, cdw1: DLEN */
	dofst = buf[8] | buf[9] << 8 | buf[10] << 16 | buf[11] << 24;
	dlen = buf[12] | buf[13] << 8 | buf[14] << 16 | buf[15] << 24;
	shr_assert(dofst == 0x1000);
	shr_assert(dlen == 4);

	shr_assert(resp->data_len >= 2);

	mi_resp = (void *)resp->hdr;
	mi_resp->status = 0;
	resp->hdr_len = sizeof(*mi_resp);

	/* return fewer bytes than the caller's buffer can hold */
	rs_data = resp->data;
	rs_data[0] = 0xa5;
	rs_data[1] = 0x5a;
	resp->data_len = 2;

	test_transport_resp_calc_mic(resp);
	return 0;
}

static void test_mi_pda_read(struct libnvme_mi_ep *ep)
{
	unsigned char buf[16] = { 0 };
	size_t data_len = sizeof(buf);
	int rc;

	test_set_transport_callback(ep, test_mi_pda_read_cb, NULL);

	rc = libnvme_mi_mi_pda_read(ep, nvme_mi_pda_dformat_512b, 0x1000, 4,
				 buf, &data_len);
	shr_assert(rc == 0);
	shr_assert(data_len == 2);
	shr_assert(buf[0] == 0xa5 && buf[1] == 0x5a);
}

/* test: PDA write request layout (opcode, DFORMAT, DOFST, DLEN) and payload */
static int test_mi_pda_write_cb(struct libnvme_mi_ep *ep,
			     struct libnvme_mi_req *req,
			     struct libnvme_mi_resp *resp,
			     void *data)
{
	struct nvme_mi_mi_resp_hdr *mi_resp;
	uint8_t *buf, *rq_data;
	__u32 dofst, dlen;
	int i;

	shr_assert(req->hdr_len == sizeof(struct nvme_mi_mi_req_hdr));
	shr_assert(req->data_len == 4);

	buf = (void *)req->hdr;
	shr_assert(buf[4] == nvme_mi_mi_opcode_pda_write);
	shr_assert(buf[5] == nvme_mi_pda_dformat_byte);

	dofst = buf[8] | buf[9] << 8 | buf[10] << 16 | buf[11] << 24;
	dlen = buf[12] | buf[13] << 8 | buf[14] << 16 | buf[15] << 24;
	shr_assert(dofst == 0x20);
	shr_assert(dlen == 4);

	rq_data = req->data;
	for (i = 0; i < 4; i++)
		shr_assert(rq_data[i] == i + 1);

	mi_resp = (void *)resp->hdr;
	mi_resp->status = 0;
	resp->hdr_len = sizeof(*mi_resp);
	resp->data_len = 0;

	test_transport_resp_calc_mic(resp);
	return 0;
}

static void test_mi_pda_write(struct libnvme_mi_ep *ep)
{
	unsigned char buf[4] = { 1, 2, 3, 4 };
	int rc;

	test_set_transport_callback(ep, test_mi_pda_write_cb, NULL);

	rc = libnvme_mi_mi_pda_write(ep, nvme_mi_pda_dformat_byte, 0x20, 4,
				  buf, sizeof(buf));
	shr_assert(rc == 0);
}

/* test: PDA write zeroes request layout (opcode, DFORMAT, DOFST, DLEN) */
static int test_mi_pda_write_zeroes_cb(struct libnvme_mi_ep *ep,
				    struct libnvme_mi_req *req,
				    struct libnvme_mi_resp *resp,
				    void *data)
{
	struct nvme_mi_mi_resp_hdr *mi_resp;
	uint8_t *buf;
	__u32 dofst, dlen;

	shr_assert(req->hdr_len == sizeof(struct nvme_mi_mi_req_hdr));
	shr_assert(req->data_len == 0);

	buf = (void *)req->hdr;
	shr_assert(buf[4] == nvme_mi_mi_opcode_pda_write_zeroes);
	shr_assert(buf[5] == nvme_mi_pda_dformat_4kib);

	dofst = buf[8] | buf[9] << 8 | buf[10] << 16 | buf[11] << 24;
	dlen = buf[12] | buf[13] << 8 | buf[14] << 16 | buf[15] << 24;
	shr_assert(dofst == 1);
	shr_assert(dlen == 2);

	mi_resp = (void *)resp->hdr;
	mi_resp->status = 0;
	resp->hdr_len = sizeof(*mi_resp);
	resp->data_len = 0;

	test_transport_resp_calc_mic(resp);
	return 0;
}

static void test_mi_pda_write_zeroes(struct libnvme_mi_ep *ep)
{
	int rc;

	test_set_transport_callback(ep, test_mi_pda_write_zeroes_cb, NULL);

	rc = libnvme_mi_mi_pda_write_zeroes(ep, nvme_mi_pda_dformat_4kib, 1, 2);
	shr_assert(rc == 0);
}

/* Get Features callback, implementing Arbitration (which doesn't return
 * additional data) and Timestamp (which does).
 */
static int test_admin_get_features_cb(struct libnvme_mi_ep *ep,
			    struct libnvme_mi_req *req,
			    struct libnvme_mi_resp *resp,
			    void *data)
{
	__u8 sel, fid, ror, mt, *rq_hdr, *rs_hdr, *rs_data;
	__u16 ctrl_id;
	int i;

	shr_assert(req->hdr->type == NVME_MI_MSGTYPE_NVME);

	ror = req->hdr->nmp >> 7;
	mt = req->hdr->nmp >> 3 & 0x7;
	shr_assert(ror == NVME_MI_ROR_REQ);
	shr_assert(mt == NVME_MI_MT_ADMIN);

	/* do we have enough for a mi header? */
	shr_assert(req->hdr_len == sizeof(struct nvme_mi_admin_req_hdr));

	/* inspect response as raw bytes */
	rq_hdr = (__u8 *)req->hdr;

	/* opcode */
	shr_assert(rq_hdr[4] == nvme_admin_get_features);

	/* controller */
	ctrl_id = rq_hdr[7] << 8 | rq_hdr[6];
	shr_assert(ctrl_id == 0x5); /* controller id */

	/* sel & fid from lower bytes of cdw10 */
	fid = rq_hdr[44];
	sel = rq_hdr[45] & 0x7;

	/* reserved fields */
	shr_assert(!(rq_hdr[46] || rq_hdr[47] || rq_hdr[45] & 0xf8));

	shr_assert(sel == 0x00);

	rs_hdr = (__u8 *)resp->hdr;
	rs_hdr[4] = 0x00; /* status: success */
	rs_data = resp->data;

	/* feature-id specific checks, and response generation */
	switch (fid) {
	case NVME_FEAT_FID_ARBITRATION:
		/* arbitrary (hah!) arbitration value in cdw0 of response */
		rs_hdr[8] = 1;
		rs_hdr[9] = 2;
		rs_hdr[10] = 3;
		rs_hdr[11] = 4;
		resp->data_len = 0;
		break;

	case NVME_FEAT_FID_TIMESTAMP:
		resp->data_len = 8;
		for (i = 0; i < 6; i++)
			rs_data[i] = i;
		rs_data[6] = 1;
		break;

	default:
		shr_assert(0);
	}

	test_transport_resp_calc_mic(resp);

	return 0;
}

static void test_get_features(struct libnvme_mi_ep *ep)
{
	struct libnvme_transport_handle *hdl;
	struct libnvme_passthru_cmd cmd;
	int rc;

	test_set_transport_callback(ep, test_admin_get_features_cb, NULL);

	hdl = libnvme_mi_init_transport_handle(ep, 5);
	shr_assert(hdl);

	nvme_init_get_features(&cmd, NVME_FEAT_FID_ARBITRATION, 0);
	rc = libnvme_exec_admin_passthru(hdl, &cmd);
	shr_assert(rc == 0);
	shr_assert(cmd.result == 0x04030201);
}

/* Set Features callback for timestamp */
static int test_admin_set_features_cb(struct libnvme_mi_ep *ep,
			    struct libnvme_mi_req *req,
			    struct libnvme_mi_resp *resp,
			    void *data)
{
	__u8 save, fid, ror, mt, *rq_hdr, *rq_data, *rs_hdr;
	__u16 ctrl_id;
	uint8_t ts[6];
	int i;

	shr_assert(req->hdr->type == NVME_MI_MSGTYPE_NVME);

	ror = req->hdr->nmp >> 7;
	mt = req->hdr->nmp >> 3 & 0x7;
	shr_assert(ror == NVME_MI_ROR_REQ);
	shr_assert(mt == NVME_MI_MT_ADMIN);
	shr_assert(req->hdr_len == sizeof(struct nvme_mi_admin_req_hdr));
	shr_assert(req->data_len == 8);

	rq_hdr = (__u8 *)req->hdr;
	rq_data = req->data;

	/* opcode */
	shr_assert(rq_hdr[4] == nvme_admin_set_features);

	/* controller */
	ctrl_id = rq_hdr[7] << 8 | rq_hdr[6];
	shr_assert(ctrl_id == 0x5); /* controller id */

	/* fid from lower bytes of cdw10, save from top bit */
	fid = rq_hdr[44];
	save = rq_hdr[47] & 0x80;

	/* reserved fields */
	shr_assert(!(rq_hdr[45] || rq_hdr[46]));

	shr_assert(fid == NVME_FEAT_FID_TIMESTAMP);
	shr_assert(save == 0x80);

	for (i = 0; i < sizeof(ts); i++)
		ts[i] = i;
	shr_assert(!memcmp(ts, rq_data, sizeof(ts)));

	rs_hdr = (__u8 *)resp->hdr;
	rs_hdr[4] = 0x00;

	test_transport_resp_calc_mic(resp);

	return 0;
}

static void test_set_features(struct libnvme_mi_ep *ep)
{
	struct nvme_timestamp tstmp = { 0 };
	struct libnvme_transport_handle *hdl;
	struct libnvme_passthru_cmd cmd;
	int rc;

	test_set_transport_callback(ep, test_admin_set_features_cb, NULL);

	hdl = libnvme_mi_init_transport_handle(ep, 5);
	shr_assert(hdl);

	nvme_init_set_features_timestamp(&cmd, true, 0x050403020100, &tstmp);
	rc = libnvme_exec_admin_passthru(hdl, &cmd);
	shr_assert(rc == 0);
}

enum ns_type {
	NS_ACTIVE,
	NS_ALLOC,
};

static int test_admin_id_ns_list_cb(struct libnvme_mi_ep *ep,
				    struct libnvme_mi_req *req,
				    struct libnvme_mi_resp *resp,
				    void *data)
{
	struct nvme_ns_list *list;
	enum ns_type type;
	int offset;
	__u8 *hdr;
	__u16 cns;

	hdr = (__u8 *)req->hdr;
	shr_assert(hdr[4] == nvme_admin_identify);

	shr_assert(req->data_len == 0);

	cns = hdr[45] << 8 | hdr[44];

	/* NSID */
	shr_assert(hdr[8] == 1 && !hdr[9] && !hdr[10] && !hdr[11]);

	type = *(enum ns_type *)data;
	resp->data_len = sizeof(*list);
	list = resp->data;

	switch (type) {
	case NS_ALLOC:
		shr_assert(cns == NVME_IDENTIFY_CNS_ALLOCATED_NS_LIST);
		offset = 2;
		break;
	case NS_ACTIVE:
		shr_assert(cns == NVME_IDENTIFY_CNS_NS_ACTIVE_LIST);
		offset = 4;
		break;
	default:
		shr_assert(0);
	}

	list->ns[0] = cpu_to_le32(offset);
	list->ns[1] = cpu_to_le32(offset + 1);

	test_transport_resp_calc_mic(resp);

	return 0;
}

static void test_admin_id_alloc_ns_list(struct libnvme_mi_ep *ep)
{
	struct libnvme_transport_handle *hdl;
	struct libnvme_passthru_cmd cmd;
	struct nvme_ns_list list;
	enum ns_type type;
	int rc;

	type = NS_ALLOC;
	test_set_transport_callback(ep, test_admin_id_ns_list_cb, &type);

	hdl = libnvme_mi_init_transport_handle(ep, 5);
	shr_assert(hdl);

	nvme_init_identify_allocated_ns_list(&cmd, 1, &list);
	rc = libnvme_exec_admin_passthru(hdl, &cmd);
	shr_assert(!rc);

	shr_assert(le32_to_cpu(list.ns[0]) == 2);
	shr_assert(le32_to_cpu(list.ns[1]) == 3);
	shr_assert(le32_to_cpu(list.ns[2]) == 0);
}

static void test_admin_id_active_ns_list(struct libnvme_mi_ep *ep)
{
	struct libnvme_transport_handle *hdl;
	struct libnvme_passthru_cmd cmd;
	struct nvme_ns_list list;
	enum ns_type type;
	int rc;

	type = NS_ACTIVE;
	test_set_transport_callback(ep, test_admin_id_ns_list_cb, &type);

	hdl = libnvme_mi_init_transport_handle(ep, 5);
	shr_assert(hdl);

	nvme_init_identify_active_ns_list(&cmd, 1, &list);
	rc = libnvme_exec_admin_passthru(hdl, &cmd);
	shr_assert(!rc);

	shr_assert(le32_to_cpu(list.ns[0]) == 4);
	shr_assert(le32_to_cpu(list.ns[1]) == 5);
	shr_assert(le32_to_cpu(list.ns[2]) == 0);
}

static int test_admin_id_ns_cb(struct libnvme_mi_ep *ep,
			       struct libnvme_mi_req *req,
			       struct libnvme_mi_resp *resp,
			       void *data)
{
	struct nvme_id_ns *id;
	enum ns_type type;
	__u16 nsid, cns;
	__u8 *hdr;

	hdr = (__u8 *)req->hdr;
	shr_assert(hdr[4] == nvme_admin_identify);

	shr_assert(req->data_len == 0);

	cns = hdr[45] << 8 | hdr[44];

	/* NSID */
	nsid = hdr[8];
	shr_assert(!hdr[9] && !hdr[10] && !hdr[11]);

	type = *(enum ns_type *)data;
	resp->data_len = sizeof(*id);
	id = resp->data;
	id->nsze = cpu_to_le64(nsid);

	switch (type) {
	case NS_ALLOC:
		shr_assert(cns == NVME_IDENTIFY_CNS_ALLOCATED_NS);
		break;
	case NS_ACTIVE:
		shr_assert(cns == NVME_IDENTIFY_CNS_NS);
		break;
	default:
		shr_assert(0);
	}

	test_transport_resp_calc_mic(resp);

	return 0;
}

static void test_admin_id_alloc_ns(struct libnvme_mi_ep *ep)
{
	struct libnvme_transport_handle *hdl;
	struct libnvme_passthru_cmd cmd;
	struct nvme_id_ns id;
	enum ns_type type;
	int rc;

	type = NS_ALLOC;
	test_set_transport_callback(ep, test_admin_id_ns_cb, &type);

	hdl = libnvme_mi_init_transport_handle(ep, 5);
	shr_assert(hdl);

	nvme_init_identify_allocated_ns(&cmd, 1, &id);
	rc = libnvme_exec_admin_passthru(hdl, &cmd);
	shr_assert(!rc);
	shr_assert(le64_to_cpu(id.nsze) == 1);
}

static void test_admin_id_active_ns(struct libnvme_mi_ep *ep)
{
	struct libnvme_transport_handle *hdl;
	struct libnvme_passthru_cmd cmd;
	struct nvme_id_ns id;
	enum ns_type type;
	int rc;

	type = NS_ACTIVE;
	test_set_transport_callback(ep, test_admin_id_ns_cb, &type);

	hdl = libnvme_mi_init_transport_handle(ep, 5);
	shr_assert(hdl);

	nvme_init_identify_ns(&cmd, 1, &id);
	rc = libnvme_exec_admin_passthru(hdl, &cmd);
	shr_assert(!rc);
	shr_assert(le64_to_cpu(id.nsze) == 1);
}

static int test_admin_id_ns_ctrl_list_cb(struct libnvme_mi_ep *ep,
					 struct libnvme_mi_req *req,
					 struct libnvme_mi_resp *resp,
					 void *data)
{
	__u16 cns, ctrlid;
	__u32 nsid;
	__u8 *hdr;

	hdr = (__u8 *)req->hdr;
	shr_assert(hdr[4] == nvme_admin_identify);

	shr_assert(req->data_len == 0);

	cns = hdr[45] << 8 | hdr[44];
	shr_assert(cns == NVME_IDENTIFY_CNS_NS_CTRL_LIST);

	nsid = hdr[11] << 24 | hdr[10] << 16 | hdr[9] << 8 | hdr[8];
	shr_assert(nsid == 0x01020304);

	ctrlid = hdr[47] << 8 | hdr[46];
	shr_assert(ctrlid == 5);

	resp->data_len = sizeof(struct nvme_ctrl_list);
	test_transport_resp_calc_mic(resp);

	return 0;
}

static void test_admin_id_ns_ctrl_list(struct libnvme_mi_ep *ep)
{
	struct libnvme_transport_handle *hdl;
	struct libnvme_passthru_cmd cmd;
	struct nvme_ctrl_list list;
	int rc;

	test_set_transport_callback(ep, test_admin_id_ns_ctrl_list_cb, NULL);

	hdl = libnvme_mi_init_transport_handle(ep, 5);
	shr_assert(hdl);

	nvme_init_identify_ns_ctrl_list(&cmd, 0x01020304, 5, &list);
	rc = libnvme_exec_admin_passthru(hdl, &cmd);
	shr_assert(!rc);
}

static int test_admin_id_secondary_ctrl_list_cb(struct libnvme_mi_ep *ep,
						struct libnvme_mi_req *req,
						struct libnvme_mi_resp *resp,
						void *data)
{
	__u16 cns, ctrlid;
	__u8 *hdr;

	hdr = (__u8 *)req->hdr;
	shr_assert(hdr[4] == nvme_admin_identify);

	shr_assert(req->data_len == 0);

	cns = hdr[45] << 8 | hdr[44];
	shr_assert(cns == NVME_IDENTIFY_CNS_SECONDARY_CTRL_LIST);

	ctrlid = hdr[47] << 8 | hdr[46];
	shr_assert(ctrlid == 5);

	resp->data_len = sizeof(struct nvme_secondary_ctrl_list);
	test_transport_resp_calc_mic(resp);

	return 0;
}

static void test_admin_id_secondary_ctrl_list(struct libnvme_mi_ep *ep)
{
	struct nvme_secondary_ctrl_list list;
	struct libnvme_transport_handle *hdl;
	struct libnvme_passthru_cmd cmd;
	int rc;

	test_set_transport_callback(ep, test_admin_id_secondary_ctrl_list_cb,
				    NULL);

	hdl = libnvme_mi_init_transport_handle(ep, 5);
	shr_assert(hdl);

	nvme_init_identify_secondary_ctrl_list(&cmd, 5, &list);
	rc = libnvme_exec_admin_passthru(hdl, &cmd);
	shr_assert(!rc);
}

static int test_admin_ns_mgmt_cb(struct libnvme_mi_ep *ep,
				 struct libnvme_mi_req *req,
				 struct libnvme_mi_resp *resp,
				 void *data)
{
	__u8 *rq_hdr, *rs_hdr, sel, csi;
	struct nvme_ns_mgmt_host_sw_specified *create_data;
	__u32 nsid;

	rq_hdr = (__u8 *)req->hdr;
	shr_assert(rq_hdr[4] == nvme_admin_ns_mgmt);

	sel = rq_hdr[44];
	csi = rq_hdr[45];
	nsid = rq_hdr[11] << 24 | rq_hdr[10] << 16 | rq_hdr[9] << 8 | rq_hdr[8];

	rs_hdr = (__u8 *)resp->hdr;

	switch (sel) {
	case NVME_NS_MGMT_SEL_CREATE:
		shr_assert(req->data_len == sizeof(struct nvme_ns_mgmt_host_sw_specified));
		create_data = req->data;

		/* No NSID on created namespaces */
		shr_assert(nsid == 0);
		shr_assert(csi == 0);

		/* allow operations on nsze == 42, reject others */
		if (le64_to_cpu(create_data->nsze) != 42) {
			rs_hdr[4] = 0;
			/* response cdw0 is created NSID */
			rs_hdr[8] = 0x04;
			rs_hdr[9] = 0x03;
			rs_hdr[10] = 0x02;
			rs_hdr[11] = 0x01;
		} else {
			rs_hdr[4] = NVME_MI_RESP_INVALID_PARAM;
		}
		break;

	case NVME_NS_MGMT_SEL_DELETE:
		shr_assert(req->data_len == 0);
		/* NSID required on delete */
		shr_assert(nsid == 0x05060708);
		break;

	default:
		shr_assert(0);
	}

	test_transport_resp_calc_mic(resp);

	return 0;
}

static void test_admin_ns_mgmt_create(struct libnvme_mi_ep *ep)
{
	struct nvme_ns_mgmt_host_sw_specified data = { 0 };
	struct libnvme_transport_handle *hdl;
	struct libnvme_passthru_cmd cmd;
	__u64 ns;
	int rc;

	test_set_transport_callback(ep, test_admin_ns_mgmt_cb, NULL);

	hdl = libnvme_mi_init_transport_handle(ep, 5);
	shr_assert(hdl);

	nvme_init_ns_mgmt_create(&cmd, NVME_CSI_NVM, &data);
	rc = libnvme_exec_admin_passthru(hdl, &cmd);
	shr_assert(!rc);
	ns = cmd.result;
	shr_assert(ns == 0x01020304);

	data.nsze = cpu_to_le64(42);
	nvme_init_ns_mgmt_create(&cmd, NVME_CSI_NVM, &data);
	rc = libnvme_exec_admin_passthru(hdl, &cmd);
	shr_assert(rc);
}

static void test_admin_ns_mgmt_delete(struct libnvme_mi_ep *ep)
{
	struct libnvme_transport_handle *hdl;
	struct libnvme_passthru_cmd cmd;
	int rc;

	test_set_transport_callback(ep, test_admin_ns_mgmt_cb, NULL);

	hdl = libnvme_mi_init_transport_handle(ep, 5);
	shr_assert(hdl);

	nvme_init_ns_mgmt_delete(&cmd, 0x05060708);
	rc = libnvme_exec_admin_passthru(hdl, &cmd);
	shr_assert(!rc);
}

struct attach_op {
	enum {
		NS_ATTACH,
		NS_DETACH,
	} op;
	struct nvme_ctrl_list *list;
};

static int test_admin_ns_attach_cb(struct libnvme_mi_ep *ep,
				   struct libnvme_mi_req *req,
				   struct libnvme_mi_resp *resp,
				   void *data)
{
	struct attach_op *op = data;
	__u8 *rq_hdr, sel;
	__u32 nsid;

	rq_hdr = (__u8 *)req->hdr;
	shr_assert(rq_hdr[4] == nvme_admin_ns_attach);

	sel = rq_hdr[44];
	nsid = rq_hdr[11] << 24 | rq_hdr[10] << 16 | rq_hdr[9] << 8 | rq_hdr[8];

	shr_assert(req->data_len == sizeof(*op->list));

	shr_assert(nsid == 0x02030405);
	switch (op->op) {
	case NS_ATTACH:
		shr_assert(sel == NVME_NS_ATTACH_SEL_CTRL_ATTACH);
		break;
	case NS_DETACH:
		shr_assert(sel == NVME_NS_ATTACH_SEL_CTRL_DEATTACH);
		break;
	default:
		shr_assert(0);
	}

	shr_assert(!memcmp(req->data, op->list, sizeof(*op->list)));

	test_transport_resp_calc_mic(resp);

	return 0;
}

static void test_admin_ns_attach(struct libnvme_mi_ep *ep)
{
	struct nvme_ctrl_list list = { 0 };
	struct attach_op aop;
	struct libnvme_transport_handle *hdl;
	struct libnvme_passthru_cmd cmd;
	int rc;

	list.num = cpu_to_le16(2);
	list.identifier[0] = 4;
	list.identifier[1] = 5;

	aop.op = NS_ATTACH;
	aop.list = &list;

	test_set_transport_callback(ep, test_admin_ns_attach_cb, &aop);

	hdl = libnvme_mi_init_transport_handle(ep, 5);
	shr_assert(hdl);

	nvme_init_ns_attach_ctrls(&cmd, 0x02030405, &list);
	rc = libnvme_exec_admin_passthru(hdl, &cmd);
	shr_assert(!rc);
}

static void test_admin_ns_detach(struct libnvme_mi_ep *ep)
{
	struct nvme_ctrl_list list = { 0 };
	struct attach_op aop;
	struct libnvme_transport_handle *hdl;
	struct libnvme_passthru_cmd cmd;
	int rc;

	list.num = cpu_to_le16(2);
	list.identifier[0] = 6;
	list.identifier[1] = 7;

	aop.op = NS_DETACH;
	aop.list = &list;

	test_set_transport_callback(ep, test_admin_ns_attach_cb, &aop);

	hdl = libnvme_mi_init_transport_handle(ep, 5);
	shr_assert(hdl);

	nvme_init_ns_detach_ctrls(&cmd, 0x02030405, &list);
	rc = libnvme_exec_admin_passthru(hdl, &cmd);
	shr_assert(!rc);
}

struct fw_download_info {
	uint32_t offset;
	uint32_t len;
	void *data;
};

static int test_admin_fw_download_cb(struct libnvme_mi_ep *ep,
				     struct libnvme_mi_req *req,
				     struct libnvme_mi_resp *resp,
				     void *data)
{
	struct fw_download_info *info = data;
	__u32 len, off;
	__u8 *rq_hdr;

	rq_hdr = (__u8 *)req->hdr;
	shr_assert(rq_hdr[4] == nvme_admin_fw_download);

	len = rq_hdr[47] << 24 | rq_hdr[46] << 16 | rq_hdr[45] << 8 | rq_hdr[44];
	off = rq_hdr[51] << 24 | rq_hdr[50] << 16 | rq_hdr[49] << 8 | rq_hdr[48];

	shr_assert(off << 2 == info->offset);
	shr_assert(((len+1) << 2) == info->len);

	/* ensure that the request len matches too */
	shr_assert(req->data_len == info->len);

	shr_assert(!memcmp(req->data, info->data, len));

	test_transport_resp_calc_mic(resp);

	return 0;
}

static void test_admin_fw_download(struct libnvme_mi_ep *ep)
{
	struct fw_download_info info;
	unsigned char fw[4096];
	struct libnvme_transport_handle *hdl;
	struct libnvme_passthru_cmd cmd;
	int rc, i;

	for (i = 0; i < sizeof(fw); i++)
		fw[i] = i % 0xff;

	info.offset = 0;
	info.len = 0;
	info.data = fw;

	test_set_transport_callback(ep, test_admin_fw_download_cb, &info);

	hdl = libnvme_mi_init_transport_handle(ep, 5);
	shr_assert(hdl);

	/* invalid (zero) len */
	info.len = 1;
	info.offset = 0;
	rc = nvme_init_fw_download(&cmd, fw, info.len, info.offset);
	shr_assert(rc);

	/* invalid (unaligned) len */
	info.len = 1;
	info.offset = 0;
	rc = nvme_init_fw_download(&cmd, fw, info.len, info.offset);
	shr_assert(rc);

	/* invalid offset */
	info.len = 4;
	info.offset = 1;
	rc = nvme_init_fw_download(&cmd, fw, info.len, info.offset);
	shr_assert(rc);

	/* smallest len */
	info.len = 4;
	info.offset = 0;
	rc = nvme_init_fw_download(&cmd, fw, info.len, info.offset);
	shr_assert(!rc);
	rc = libnvme_exec_admin_passthru(hdl, &cmd);
	shr_assert(!rc);

	/* largest len */
	info.len = 4096;
	info.offset = 0;
	rc = nvme_init_fw_download(&cmd, fw, info.len, info.offset);
	shr_assert(!rc);
	rc = libnvme_exec_admin_passthru(hdl, &cmd);
	shr_assert(!rc);

	/* offset value */
	info.len = 4096;
	info.offset = 4096;
	rc = nvme_init_fw_download(&cmd, fw, info.len, info.offset);
	shr_assert(!rc);
	rc = libnvme_exec_admin_passthru(hdl, &cmd);
	shr_assert(!rc);
}

struct fw_commit_info {
	__u8 bpid;
	__u8 action;
	__u8 slot;
};

static int test_admin_fw_commit_cb(struct libnvme_mi_ep *ep,
				   struct libnvme_mi_req *req,
				   struct libnvme_mi_resp *resp,
				   void *data)
{
	struct fw_commit_info *info = data;
	__u8 bpid, action, slot;
	__u8 *rq_hdr;

	rq_hdr = (__u8 *)req->hdr;
	shr_assert(rq_hdr[4] == nvme_admin_fw_commit);

	bpid = (rq_hdr[47] >> 7) & 0x1;
	slot = rq_hdr[44] & 0x7;
	action = (rq_hdr[44] >> 3) & 0x7;

	shr_assert(!!bpid == !!info->bpid);
	shr_assert(slot == info->slot);
	shr_assert(action == info->action);

	test_transport_resp_calc_mic(resp);

	return 0;
}

static void test_admin_fw_commit(struct libnvme_mi_ep *ep)
{
	struct libnvme_transport_handle *hdl;
	struct libnvme_passthru_cmd cmd;
	struct fw_commit_info info;
	int rc;

	info.bpid = 0;

	test_set_transport_callback(ep, test_admin_fw_commit_cb, &info);

	hdl = libnvme_mi_init_transport_handle(ep, 5);
	shr_assert(hdl);

	/* all zeros */
	info.bpid = 0;
	info.slot = 0;
	info.action = 0;
	nvme_init_fw_commit(&cmd, info.slot, info.action, info.bpid);
	rc = libnvme_exec_admin_passthru(hdl, &cmd);
	shr_assert(!rc);

	/* all ones */
	info.bpid = 1;
	info.slot = 0x7;
	info.action = 0x7;
	nvme_init_fw_commit(&cmd, info.slot, info.action, info.bpid);
	rc = libnvme_exec_admin_passthru(hdl, &cmd);
	shr_assert(!rc);

	/* correct fields */
	info.bpid = 1;
	info.slot = 2;
	info.action = 3;
	nvme_init_fw_commit(&cmd, info.slot, info.action, info.bpid);
	rc = libnvme_exec_admin_passthru(hdl, &cmd);
	shr_assert(!rc);
}

struct format_data {
	__u32 nsid;
	__u8 ses;
	__u8 pil;
	__u8 pi;
	__u8 mset;
	__u8 lbaf;
};

static int test_admin_format_nvm_cb(struct libnvme_mi_ep *ep,
				    struct libnvme_mi_req *req,
				    struct libnvme_mi_resp *resp,
				    void *data)
{
	struct format_data *args = data;
	__u8 *rq_hdr;
	__u32 nsid;

	shr_assert(req->data_len == 0);

	rq_hdr = (__u8 *)req->hdr;

	shr_assert(rq_hdr[4] == nvme_admin_format_nvm);

	nsid = (__u32)rq_hdr[11] << 24
	     | rq_hdr[10] << 16
	     | rq_hdr[9] << 8
	     | rq_hdr[8];
	shr_assert(nsid == args->nsid);

	shr_assert(((rq_hdr[44] >> 0) & 0xf) == (args->lbaf & 0xf));
	shr_assert(((rq_hdr[44] >> 4) & 0x1) == args->mset);
	shr_assert(((rq_hdr[44] >> 5) & 0x7) == args->pi);

	shr_assert(((rq_hdr[45] >> 0) & 0x1) == args->pil);
	shr_assert(((rq_hdr[45] >> 1) & 0x7) == args->ses);
	shr_assert(((rq_hdr[45] >> 4) & 0x3) == (args->lbaf >> 4));

	test_transport_resp_calc_mic(resp);

	return 0;
}

static void test_admin_format_nvm(struct libnvme_mi_ep *ep)
{
	struct format_data args = { 0 };
	struct libnvme_transport_handle *hdl;
	struct libnvme_passthru_cmd cmd;
	int rc;

	hdl = libnvme_mi_init_transport_handle(ep, 5);
	shr_assert(hdl);

	test_set_transport_callback(ep, test_admin_format_nvm_cb, &args);

	/* ensure we have the cdw0 bit field encoding correct, by testing twice
	 * with inverted bit values */
	args.nsid = 0x04030201;
	args.ses = 0x0;
	args.pil = 0x1;
	args.pi = 0x0;
	args.mset = 0x1;
	args.lbaf = 0x30;

	nvme_init_format_nvm(&cmd, args.nsid, args.lbaf, args.mset,
			     args.pi, args.pil, args.ses);
	rc = libnvme_exec_admin_passthru(hdl, &cmd);
	shr_assert(!rc);

	args.nsid = ~args.nsid;
	args.ses = 0x7;
	args.pil = 0x0;
	args.pi = 0x7;
	args.mset = 0x0;
	args.lbaf = 0x0f;

	nvme_init_format_nvm(&cmd, args.nsid, args.lbaf, args.mset,
			     args.pi, args.pil, args.ses);
	rc = libnvme_exec_admin_passthru(hdl, &cmd);
	shr_assert(!rc);
}

struct nvme_sanitize_nvm_args {
	enum nvme_sanitize_sanact sanact;
	__u32 ovrpat;
	bool ause;
	__u8 owpass;
	bool oipbp;
	bool ndas;
	bool emvs;
	bool preq;
};

static int test_admin_sanitize_nvm_cb(struct libnvme_mi_ep *ep,
				      struct libnvme_mi_req *req,
				      struct libnvme_mi_resp *resp,
				      void *data)
{
	struct nvme_sanitize_nvm_args *args = data;
	__u8 *rq_hdr;
	__u32 ovrpat;

	shr_assert(req->data_len == 0);

	rq_hdr = (__u8 *)req->hdr;

	shr_assert(rq_hdr[4] == nvme_admin_sanitize_nvm);

	shr_assert(((rq_hdr[44] >> 0) & 0x7) == args->sanact);
	shr_assert(((rq_hdr[44] >> 3) & 0x1) == args->ause);
	shr_assert(((rq_hdr[44] >> 4) & 0xf) == args->owpass);

	shr_assert(((rq_hdr[45] >> 0) & 0x1) == args->oipbp);
	shr_assert(((rq_hdr[45] >> 1) & 0x1) == args->ndas);
	shr_assert(((rq_hdr[45] >> 3) & 0x1) == args->preq);

	ovrpat = (__u32)rq_hdr[51] << 24 | rq_hdr[50] << 16 |
		rq_hdr[49] << 8 | rq_hdr[48];
	shr_assert(ovrpat == args->ovrpat);

	test_transport_resp_calc_mic(resp);

	return 0;
}

static void test_admin_sanitize_nvm(struct libnvme_mi_ep *ep)
{
	struct nvme_sanitize_nvm_args args = { 0 };
	struct libnvme_transport_handle *hdl;
	struct libnvme_passthru_cmd cmd;
	int rc;

	hdl = libnvme_mi_init_transport_handle(ep, 5);
	shr_assert(hdl);

	test_set_transport_callback(ep, test_admin_sanitize_nvm_cb, &args);

	args.sanact = 0x7;
	args.ause = 0x0;
	args.owpass = 0xf;
	args.oipbp = 0x0;
	args.ndas = 0x1;
	args.preq = 0x1;
	args.ovrpat = ~0x04030201;

	nvme_init_sanitize_nvm(&cmd, args.sanact, args.ause, args.owpass,
		args.oipbp, args.ndas, args.emvs, args.preq, args.ovrpat);
	rc = libnvme_exec_admin_passthru(hdl, &cmd);
	shr_assert(!rc);

	args.sanact = 0x0;
	args.ause = 0x1;
	args.owpass = 0x0;
	args.oipbp = 0x1;
	args.ndas = 0x0;
	args.preq = 0x0;
	args.ovrpat = 0x04030201;

	nvme_init_sanitize_nvm(&cmd, args.sanact, args.ause, args.owpass,
		args.oipbp, args.ndas, args.emvs, args.preq, args.ovrpat);
	rc = libnvme_exec_admin_passthru(hdl, &cmd);
	shr_assert(!rc);
}

/* test that we set the correct offset and size on get_log() calls that
 * are split into multiple requests */
struct log_data {
	int n;
};

static int test_admin_get_log_split_cb(struct libnvme_mi_ep *ep,
				       struct libnvme_mi_req *req,
				       struct libnvme_mi_resp *resp,
				       void *data)
{
	uint32_t log_page_offset_lower;
	struct log_data *ldata = data;
	uint32_t len, off;
	__u8 *rq_hdr;

	shr_assert(req->data_len == 0);

	rq_hdr = (__u8 *)req->hdr;

	shr_assert(rq_hdr[4] == nvme_admin_get_log_page);

	/* from the MI message's DOFST/DLEN fields */
	off = rq_hdr[31] << 24 | rq_hdr[30] << 16 | rq_hdr[29] << 8 | rq_hdr[28];
	len = rq_hdr[35] << 24 | rq_hdr[34] << 16 | rq_hdr[33] << 8 | rq_hdr[32];

	/* From the MI message's Command Dword 12 */
	log_page_offset_lower = rq_hdr[55] << 24 | rq_hdr[54] << 16 | rq_hdr[53] << 8 | rq_hdr[52];

	/* we should have a full-sized start and middle, and a short end */
	switch (ldata->n) {
	case 0:
		shr_assert(log_page_offset_lower == 0);
		shr_assert(len == 4096);
		shr_assert(off == 0);
		break;
	case 1:
		shr_assert(log_page_offset_lower == 4096);
		shr_assert(len == 4096);
		shr_assert(off == 0);
		break;
	case 2:
		shr_assert(log_page_offset_lower == 8192);
		shr_assert(len == 4);
		shr_assert(off == 0);
		break;
	default:
		shr_assert(0);
	}

	/* ensure we've sized the expected response correctly */
	shr_assert(resp->data_len == len);
	memset(resp->data, ldata->n & 0xff, len);

	test_transport_resp_calc_mic(resp);

	ldata->n++;

	return 0;
}

static void test_admin_get_log_split(struct libnvme_mi_ep *ep)
{
	unsigned char buf[4096 * 2 + 4];
	struct log_data ldata;
	struct libnvme_transport_handle *hdl;
	struct libnvme_passthru_cmd cmd;
	int rc;

	ldata.n = 0;
	test_set_transport_callback(ep, test_admin_get_log_split_cb, &ldata);

	hdl = libnvme_mi_init_transport_handle(ep, 5);

	nvme_init_get_log(&cmd, NVME_NSID_ALL, NVME_LOG_LID_ERROR,
		NVME_CSI_NVM, buf, sizeof(buf));
	rc = libnvme_get_log(hdl, &cmd, false, NVME_LOG_PAGE_PDU_SIZE);
	shr_assert(!rc);

	/* we should have sent three commands */
	shr_assert(ldata.n == 3);
}

static int test_endpoint_quirk_probe_cb_stage2(struct libnvme_mi_ep *ep,
						struct libnvme_mi_req *req,
						struct libnvme_mi_resp *resp,
						void *data)
{
	return test_read_mi_data_cb(ep, req, resp, data);
}

static int test_endpoint_quirk_probe_cb_stage1(struct libnvme_mi_ep *ep,
						struct libnvme_mi_req *req,
						struct libnvme_mi_resp *resp,
						void *data)
{
	struct nvme_mi_admin_req_hdr *admin_req;
	__u8 ror, mt;

	shr_assert(req->hdr->type == NVME_MI_MSGTYPE_NVME);

	ror = req->hdr->nmp >> 7;
	mt = req->hdr->nmp >> 3 & 0x7;
	shr_assert(ror == NVME_MI_ROR_REQ);
	shr_assert(mt == NVME_MI_MT_ADMIN);

	shr_assert(req->hdr_len == sizeof(struct nvme_mi_admin_req_hdr));

	admin_req = (struct nvme_mi_admin_req_hdr *)req->hdr;
	shr_assert(admin_req->opcode == nvme_admin_identify);
	shr_assert(le32_to_cpu(admin_req->doff) == 0);
	shr_assert(le32_to_cpu(admin_req->dlen) == offsetof(struct nvme_id_ctrl, rab));

	test_set_transport_callback(ep, test_endpoint_quirk_probe_cb_stage2, data);

	return 0;
}

static void test_endpoint_quirk_probe(struct libnvme_mi_ep *ep)
{
	struct nvme_mi_read_nvm_ss_info ss_info;
	int rc;

	/* force the probe to occur */
	ep->quirks_probed = false;

	test_set_transport_callback(ep, test_endpoint_quirk_probe_cb_stage1, NULL);

	rc = libnvme_mi_mi_read_mi_data_subsys(ep, &ss_info);
	shr_assert(rc == 0);
}

struct req_dlen_doff_data {
	enum {
		DATA_DIR_IN,
		DATA_DIR_OUT,
	} direction;
	unsigned int req_len;
	unsigned int resp_len;
	unsigned int exp_doff;
};

static int test_admin_dlen_doff_cb(struct libnvme_mi_ep *ep,
			      struct libnvme_mi_req *req,
			      struct libnvme_mi_resp *resp,
			      void *data)
{
	struct req_dlen_doff_data *args = data;
	__u8 *hdr = (__u8 *)req->hdr;
	__u32 dlen, doff;

	dlen = hdr[35] << 24 | hdr[34] << 16 | hdr[33] << 8 | hdr[32];
	doff = hdr[39] << 24 | hdr[38] << 16 | hdr[37] << 8 | hdr[36];

	if (args->direction == DATA_DIR_OUT) {
		shr_assert(dlen == args->req_len);
		shr_assert(dlen == req->data_len);
		shr_assert(doff == 0);
	} else {
		shr_assert(dlen == args->resp_len);
		shr_assert(dlen == resp->data_len);
		shr_assert(doff == args->exp_doff);
	}

	/* minimal valid response */
	hdr = (__u8 *)resp->hdr;
	hdr[4] = 0x00; /* status: success */

	test_transport_resp_calc_mic(resp);

	return 0;
}

/* Check dlen value on admin_xfer requests that include data. */
static void test_admin_dlen_doff_req(struct libnvme_mi_ep *ep)
{
	struct {
		struct nvme_mi_admin_req_hdr	hdr;
		unsigned char			data[4096];
	} admin_req = { 0 };
	struct nvme_mi_admin_resp_hdr admin_resp = { 0 };
	struct req_dlen_doff_data data = { 0 };
	size_t resp_sz = 0;
	struct libnvme_transport_handle *hdl;
	int rc;

	data.direction = DATA_DIR_OUT;
	data.req_len = sizeof(admin_req.data);

	test_set_transport_callback(ep, test_admin_dlen_doff_cb, &data);

	hdl = libnvme_mi_init_transport_handle(ep, 0);
	shr_assert(hdl);

	rc = libnvme_mi_admin_xfer(hdl, &admin_req.hdr, sizeof(admin_req.data),
				&admin_resp, 0, &resp_sz);

	shr_assert(!rc);
};

/* Check dlen value on admin_xfer requests that return data in their response.
 */
static void test_admin_dlen_doff_resp(struct libnvme_mi_ep *ep)
{
	struct {
		struct nvme_mi_admin_resp_hdr	hdr;
		unsigned char			data[4096];
	} admin_resp = { 0 };
	struct nvme_mi_admin_req_hdr admin_req = { 0 };
	struct req_dlen_doff_data data = { 0 };
	struct libnvme_transport_handle *hdl;
	size_t resp_sz;
	int rc;

	data.direction = DATA_DIR_IN;
	data.resp_len = sizeof(admin_resp.data);
	resp_sz = sizeof(admin_resp.data);

	test_set_transport_callback(ep, test_admin_dlen_doff_cb, &data);

	hdl = libnvme_mi_init_transport_handle(ep, 0);
	shr_assert(hdl);

	rc = libnvme_mi_admin_xfer(hdl, &admin_req, 0, &admin_resp.hdr, 0,
				&resp_sz);

	shr_assert(!rc);
};

#define DEFINE_TEST(name) { #name, test_ ## name }
struct test {
	const char *name;
	void (*fn)(struct libnvme_mi_ep *);
} tests[] = {
	DEFINE_TEST(endpoint_lifetime),
	DEFINE_TEST(ctrl_lifetime),
	DEFINE_TEST(read_mi_data),
	DEFINE_TEST(transport_fail),
	DEFINE_TEST(transport_describe),
	DEFINE_TEST(scan_ctrl_list),
	DEFINE_TEST(invalid_crc),
	DEFINE_TEST(admin_id),
	DEFINE_TEST(admin_err_mi_resp),
	DEFINE_TEST(admin_err_nvme_resp),
	DEFINE_TEST(admin_invalid_formats),
	DEFINE_TEST(resp_req),
	DEFINE_TEST(resp_hdr_small),
	DEFINE_TEST(resp_invalid_type),
	DEFINE_TEST(resp_csi_request),
	DEFINE_TEST(resp_csi_mismatch),
	DEFINE_TEST(mi_config_get_mtu),
	DEFINE_TEST(mi_config_set_freq),
	DEFINE_TEST(mi_config_set_freq_invalid),
	DEFINE_TEST(mi_pda_read),
	DEFINE_TEST(mi_pda_write),
	DEFINE_TEST(mi_pda_write_zeroes),
	DEFINE_TEST(get_features),
	DEFINE_TEST(set_features),
	DEFINE_TEST(admin_id_alloc_ns_list),
	DEFINE_TEST(admin_id_active_ns_list),
	DEFINE_TEST(admin_id_alloc_ns),
	DEFINE_TEST(admin_id_active_ns),
	DEFINE_TEST(admin_id_ns_ctrl_list),
	DEFINE_TEST(admin_id_secondary_ctrl_list),
	DEFINE_TEST(admin_ns_mgmt_create),
	DEFINE_TEST(admin_ns_mgmt_delete),
	DEFINE_TEST(admin_ns_attach),
	DEFINE_TEST(admin_ns_detach),
	DEFINE_TEST(admin_fw_download),
	DEFINE_TEST(admin_fw_commit),
	DEFINE_TEST(admin_format_nvm),
	DEFINE_TEST(admin_sanitize_nvm),
	DEFINE_TEST(admin_get_log_split),
	DEFINE_TEST(endpoint_quirk_probe),
	DEFINE_TEST(admin_dlen_doff_req),
	DEFINE_TEST(admin_dlen_doff_resp),
	DEFINE_TEST(mi_invalid_formats),
};

static void run_test(struct test *test, FILE *logfd, struct libnvme_mi_ep *ep)
{
	printf("Running test %s...", test->name);
	fflush(stdout);
	test->fn(ep);
	/* tests will assert on failure; if we're here, we're OK */
	printf("  OK\n");
	test_print_log_buf(logfd);
}

int main(void)
{
	struct libnvme_global_ctx *ctx;
	struct libnvme_mi_ep *ep;
	unsigned int i;
	FILE *fd;

	fd = test_setup_log();

	ctx = libnvme_create_global_ctx();
	shr_assert(ctx);
	libnvme_set_logging_file(ctx, fd);

	ep = libnvme_mi_open_test(ctx);
	shr_assert(ep);

	for (i = 0; i < ARRAY_SIZE(tests); i++) {
		run_test(&tests[i], fd, ep);
	}

	libnvme_mi_close(ep);
	libnvme_free_global_ctx(ctx);

	test_close_log(fd);

	return EXIT_SUCCESS;
}
