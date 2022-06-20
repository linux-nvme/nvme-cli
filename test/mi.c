// SPDX-License-Identifier: LGPL-2.1-or-later
/**
 * This file is part of libnvme.
 * Copyright (c) 2022 Code Construct
 */

#undef NDEBUG
#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

#include <ccan/array_size/array_size.h>

/* we define a custom transport, so need the internal headers */
#include "nvme/private.h"

#include "libnvme-mi.h"

typedef int (*test_submit_cb)(struct nvme_mi_ep *ep,
			      struct nvme_mi_req *req,
			      struct nvme_mi_resp *resp,
			      void *data);

struct test_transport_data {
	unsigned int	magic;
	test_submit_cb	submit_cb;
	void		*submit_cb_data;
};

static const int test_transport_magic = 0x74657374;

static int test_transport_submit(struct nvme_mi_ep *ep,
				 struct nvme_mi_req *req,
				 struct nvme_mi_resp *resp)
{
	struct test_transport_data *tpd = ep->transport_data;

	assert(tpd->magic == test_transport_magic);

	/* start from a zeroed response */
	memset(resp->hdr, 0, resp->hdr_len);
	memset(resp->data, 0, resp->data_len);

	if (tpd->submit_cb)
		return tpd->submit_cb(ep, req, resp, tpd->submit_cb_data);

	return 0;
}

static void test_transport_close(struct nvme_mi_ep *ep)
{
	struct test_transport_data *tpd = ep->transport_data;
	assert(tpd->magic == test_transport_magic);
	free(tpd);
}

/* internal test helper to generate correct response crc */
static void test_transport_resp_calc_mic(struct nvme_mi_resp *resp)
{
	extern __u32 nvme_mi_crc32_update(__u32 crc, void *data, size_t len);
	__u32 crc = 0xffffffff;

	crc = nvme_mi_crc32_update(crc, resp->hdr, resp->hdr_len);
	crc = nvme_mi_crc32_update(crc, resp->data, resp->data_len);

	resp->mic = ~crc;
}

static const struct nvme_mi_transport test_transport = {
	.name = "test-mi",
	.mic_enabled = true,
	.submit = test_transport_submit,
	.close = test_transport_close,
};

static void test_set_transport_callback(nvme_mi_ep_t ep, test_submit_cb cb,
					void *data)
{
	struct test_transport_data *tpd = ep->transport_data;
	assert(tpd->magic == test_transport_magic);

	tpd->submit_cb = cb;
	tpd->submit_cb_data = data;
}

nvme_mi_ep_t nvme_mi_open_test(nvme_root_t root)
{
	struct test_transport_data *tpd;
	struct nvme_mi_ep *ep;

	ep = nvme_mi_init_ep(root);
	assert(ep);

	tpd = malloc(sizeof(*tpd));
	assert(tpd);

	tpd->magic = test_transport_magic;

	ep->transport = &test_transport;
	ep->transport_data = tpd;

	return ep;
}

/* test: basic read MI datastructure command */
static int test_read_mi_data_cb(struct nvme_mi_ep *ep,
				 struct nvme_mi_req *req,
				 struct nvme_mi_resp *resp,
				 void *data)
{
	__u8 ror, mt, *hdr, *buf;

	assert(req->hdr->type == NVME_MI_MSGTYPE_NVME);

	ror = req->hdr->nmp >> 7;
	mt = req->hdr->nmp >> 3 & 0x7;
	assert(ror == NVME_MI_ROR_REQ);
	assert(mt == NVME_MI_MT_MI);

	/* do we have enough for a mi header? */
	assert(req->hdr_len == sizeof(struct nvme_mi_mi_req_hdr));

	/* inspect response as raw bytes */
	hdr = (__u8 *)req->hdr;
	assert(hdr[4] == nvme_mi_mi_opcode_mi_data_read);

	/* create basic response */
	assert(resp->hdr_len >= sizeof(struct nvme_mi_mi_resp_hdr));
	assert(resp->data_len >= 4);

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

static void test_read_mi_data(nvme_mi_ep_t ep)
{
	struct nvme_mi_read_nvm_ss_info ss_info;
	int rc;

	test_set_transport_callback(ep, test_read_mi_data_cb, NULL);

	rc = nvme_mi_mi_read_mi_data_subsys(ep, &ss_info);
	assert(rc == 0);
}

/* test: failed transport */
static int test_transport_fail_cb(struct nvme_mi_ep *ep,
				  struct nvme_mi_req *req,
				  struct nvme_mi_resp *resp,
				  void *data)
{
	return -1;
}

static void test_transport_fail(nvme_mi_ep_t ep)
{
	struct nvme_mi_read_nvm_ss_info ss_info;
	int rc;

	test_set_transport_callback(ep, test_transport_fail_cb, NULL);
	rc = nvme_mi_mi_read_mi_data_subsys(ep, &ss_info);
	assert(rc != 0);
}

/* test: invalid crc */
static int test_invalid_crc_cb(struct nvme_mi_ep *ep,
				      struct nvme_mi_req *req,
				      struct nvme_mi_resp *resp,
				      void *data)
{
	resp->mic = 0;
	return 0;
}

static void test_invalid_crc(nvme_mi_ep_t ep)
{
	struct nvme_mi_read_nvm_ss_info ss_info;
	int rc;

	test_set_transport_callback(ep, test_invalid_crc_cb, NULL);
	rc = nvme_mi_mi_read_mi_data_subsys(ep, &ss_info);
	assert(rc != 0);
}

/* test: simple NVMe admin request/response */
static int test_admin_id_cb(struct nvme_mi_ep *ep,
				  struct nvme_mi_req *req,
				  struct nvme_mi_resp *resp,
				  void *data)
{
	__u8 ror, mt, *hdr;
	__u32 dlen, cdw10;
	__u16 ctrl_id;
	__u8 flags;

	assert(req->hdr->type == NVME_MI_MSGTYPE_NVME);

	ror = req->hdr->nmp >> 7;
	mt = req->hdr->nmp >> 3 & 0x7;
	assert(ror == NVME_MI_ROR_REQ);
	assert(mt == NVME_MI_MT_ADMIN);

	/* do we have enough for a mi header? */
	assert(req->hdr_len == sizeof(struct nvme_mi_admin_req_hdr));

	/* inspect response as raw bytes */
	hdr = (__u8 *)req->hdr;
	assert(hdr[4] == nvme_admin_identify);
	flags = hdr[5];

	ctrl_id = hdr[7] << 8 | hdr[6];
	assert(ctrl_id == 0x5); /* controller id */

	/* we requested a full id; if we've set the length flag,
	 * ensure the length matches */
	dlen = hdr[35] << 24 | hdr[34] << 16 | hdr[33] << 8 | hdr[32];
	if (flags & 0x1) {
		assert(dlen == sizeof(struct nvme_id_ctrl));
	}
	assert(!(flags & 0x2));

	/* CNS value of 1 in cdw10 field */
	cdw10 = hdr[47] << 24 | hdr[46] << 16 | hdr[45] << 8 | hdr[44];
	assert(cdw10 == 0x1);

	/* create valid (but somewhat empty) response */
	hdr = (__u8 *)resp->hdr;
	memset(resp->hdr, 0, resp->hdr_len);
	memset(resp->data, 0, resp->data_len);
	hdr[4] = 0x00; /* status: success */

	test_transport_resp_calc_mic(resp);

	return 0;
}

static void test_admin_id(nvme_mi_ep_t ep)
{
	struct nvme_id_ctrl id;
	nvme_mi_ctrl_t ctrl;
	int rc;

	test_set_transport_callback(ep, test_admin_id_cb, NULL);

	ctrl = nvme_mi_init_ctrl(ep, 5);
	assert(ctrl);

	rc = nvme_mi_admin_identify_ctrl(ctrl, &id);
	assert(rc == 0);
}

/* test: simple NVMe error response */
static int test_admin_err_resp_cb(struct nvme_mi_ep *ep,
				  struct nvme_mi_req *req,
				  struct nvme_mi_resp *resp,
				  void *data)
{
	__u8 ror, mt, *hdr;

	assert(req->hdr->type == NVME_MI_MSGTYPE_NVME);

	ror = req->hdr->nmp >> 7;
	mt = req->hdr->nmp >> 3 & 0x7;
	assert(ror == NVME_MI_ROR_REQ);
	assert(mt == NVME_MI_MT_ADMIN);

	/* do we have enough for a mi header? */
	assert(req->hdr_len == sizeof(struct nvme_mi_admin_req_hdr));

	/* inspect response as raw bytes */
	hdr = (__u8 *)req->hdr;
	assert(hdr[4] == nvme_admin_identify);

	/* we need at least 8 bytes for error information */
	assert(resp->hdr_len >= 8);

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

static void test_admin_err_resp(nvme_mi_ep_t ep)
{
	struct nvme_id_ctrl id;
	nvme_mi_ctrl_t ctrl;
	int rc;

	test_set_transport_callback(ep, test_admin_err_resp_cb, NULL);

	ctrl = nvme_mi_init_ctrl(ep, 1);
	assert(ctrl);

	rc = nvme_mi_admin_identify_ctrl(ctrl, &id);
	assert(rc != 0);
}

#define DEFINE_TEST(name) { #name, test_ ## name }
struct test {
	const char *name;
	void (*fn)(nvme_mi_ep_t);
} tests[] = {
	DEFINE_TEST(read_mi_data),
	DEFINE_TEST(transport_fail),
	DEFINE_TEST(invalid_crc),
	DEFINE_TEST(admin_id),
	DEFINE_TEST(admin_err_resp),
};

static void print_log_buf(FILE *logfd)
{
	char buf[4096];
	int rc;

	if (!ftell(logfd))
		return;

	rewind(logfd);

	printf("--- begin test output\n");

	while (!feof(logfd) && !ferror(logfd)) {
		size_t rlen, wlen, wpos;

		rlen = fread(buf, 1, sizeof(buf), logfd);
		if (rlen <= 0)
			break;

		for (wpos = 0; wpos < rlen;) {
			wlen = fwrite(buf + wpos, 1, rlen - wpos, stdout);
			if (wlen == 0)
				break;
			wpos += wlen;
		}

		if (feof(logfd) || ferror((logfd)))
			break;
	}

	printf("--- end test output\n");
	rewind(logfd);
	rc = ftruncate(fileno(logfd), 0);
	assert(!rc);
}

static void run_test(struct test *test, FILE *logfd, nvme_mi_ep_t ep)
{
	printf("Running test %s...", test->name);
	fflush(stdout);
	test->fn(ep);
	/* tests will assert on failure; if we're here, we're OK */
	printf("  OK\n");
	print_log_buf(logfd);
}

int main(void)
{
	nvme_root_t root;
	nvme_mi_ep_t ep;
	unsigned int i;
	FILE *fd;

	fd = tmpfile();
	assert(fd);

	root = nvme_mi_create_root(fd, DEFAULT_LOGLEVEL);
	assert(root);

	ep = nvme_mi_open_test(root);
	assert(ep);

	for (i = 0; i < ARRAY_SIZE(tests); i++) {
		run_test(&tests[i], fd, ep);
	}

	nvme_mi_close(ep);
	nvme_mi_free_root(root);

	return EXIT_SUCCESS;
}
