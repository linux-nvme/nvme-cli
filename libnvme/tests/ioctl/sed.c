// SPDX-License-Identifier: LGPL-2.1-or-later

#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include <ccan/array_size/array_size.h>

#include <libnvme.h>
#include <libnvme-sed.h>
#include <nvme/endian.h>

#include "nvme/loopback.h"
#include "util.h"

static struct libnvme_transport_handle *test_hdl;

/*
 * Level 0 Discovery response with a TPer, a Locking and an Opal SSC
 * V2 feature descriptor. The header length excludes the length field.
 */
struct test_l0 {
	struct tcg_l0_header hdr;
	struct tcg_l0_desc tper_desc;
	struct tcg_l0_tper tper;
	struct tcg_l0_desc locking_desc;
	struct tcg_l0_locking locking;
	struct tcg_l0_desc opal_desc;
	struct tcg_l0_opal_v2 opal;
} __attribute__((packed));

static void init_l0(struct test_l0 *l0)
{
	memset(l0, 0, sizeof(*l0));
	l0->hdr.length = htobe32(sizeof(*l0) - sizeof(l0->hdr.length));
	l0->hdr.revision = htobe32(1);
	l0->tper_desc.code = htobe16(TCG_L0_CODE_TPER);
	l0->tper_desc.length = sizeof(l0->tper);
	l0->locking_desc.code = htobe16(TCG_L0_CODE_LOCKING);
	l0->locking_desc.length = sizeof(l0->locking);
	l0->locking.features = TCG_L0_LOCKING_SUPPORTED |
		TCG_L0_LOCKING_ENABLED;
	l0->opal_desc.code = htobe16(TCG_L0_CODE_OPAL_V2);
	l0->opal_desc.length = sizeof(l0->opal);
}

static void test_discover(void)
{
	struct test_l0 expected_data, data;
	struct libnvme_loopback_cmd mock_admin_cmd = {
		.opcode = nvme_admin_security_recv,
		.cdw10 = (TCG_L0_DISCOVERY_COMID << 8) |
			 ((__u32)TCG_L0_DISCOVERY_SECP << 24),
		.cdw11 = sizeof(data),
		.data_len = sizeof(data),
		.out_data = &expected_data,
	};
	int err;

	init_l0(&expected_data);
	memset(&data, 0, sizeof(data));
	libnvme_loopback_set_admin_cmds(test_hdl, &mock_admin_cmd, 1);
	err = libnvme_sed_discover(test_hdl, &data, sizeof(data));
	libnvme_loopback_end(test_hdl);
	check(err == 0, "returned error %d", err);
	cmp(&data, &expected_data, sizeof(data), "incorrect data");
}

static void test_discover_status(void)
{
	__u8 data[64];
	struct libnvme_loopback_cmd mock_admin_cmd = {
		.opcode = nvme_admin_security_recv,
		.cdw10 = (TCG_L0_DISCOVERY_COMID << 8) |
			 ((__u32)TCG_L0_DISCOVERY_SECP << 24),
		.cdw11 = sizeof(data),
		.data_len = sizeof(data),
		.err = NVME_SC_INVALID_FIELD,
	};
	int err;

	libnvme_loopback_set_admin_cmds(test_hdl, &mock_admin_cmd, 1);
	err = libnvme_sed_discover(test_hdl, data, sizeof(data));
	libnvme_loopback_end(test_hdl);
	check(err == NVME_SC_INVALID_FIELD, "returned %d", err);
}

static void test_l0_for_each(void)
{
	static const __u16 codes[] = {
		TCG_L0_CODE_TPER, TCG_L0_CODE_LOCKING, TCG_L0_CODE_OPAL_V2,
	};
	struct tcg_l0_desc *desc;
	struct test_l0 l0;
	size_t i = 0;

	init_l0(&l0);
	libnvme_sed_l0_for_each(desc, &l0, sizeof(l0)) {
		check(i < ARRAY_SIZE(codes), "too many descriptors");
		check(be16toh(desc->code) == codes[i],
		      "descriptor %zu: code 0x%04x", i, be16toh(desc->code));
		i++;
	}
	check(i == ARRAY_SIZE(codes), "found %zu descriptors", i);
}

static void test_l0_find(void)
{
	struct tcg_l0_locking *locking;
	struct tcg_l0_desc *desc;
	struct test_l0 l0;

	init_l0(&l0);
	desc = libnvme_sed_l0_find(&l0, sizeof(l0), TCG_L0_CODE_LOCKING);
	check(desc == &l0.locking_desc, "locking descriptor not found");
	locking = libnvme_sed_l0_data(desc);
	check(locking->features & TCG_L0_LOCKING_ENABLED,
	      "wrong locking features 0x%02x", locking->features);

	desc = libnvme_sed_l0_find(&l0, sizeof(l0), TCG_L0_CODE_OPAL_V2);
	check(desc == &l0.opal_desc, "last descriptor not found");

	desc = libnvme_sed_l0_find(&l0, sizeof(l0), TCG_L0_CODE_RUBY);
	check(!desc, "found missing descriptor");
}

static void test_l0_bounds(void)
{
	struct tcg_l0_desc *desc;
	struct test_l0 l0;

	init_l0(&l0);

	/* the buffer is shorter than the header length */
	desc = libnvme_sed_l0_find(&l0, sizeof(l0) - 1, TCG_L0_CODE_OPAL_V2);
	check(!desc, "found descriptor past the buffer");

	/* the header length is shorter than the buffer */
	l0.hdr.length = htobe32(offsetof(struct test_l0, opal) -
				sizeof(l0.hdr.length));
	desc = libnvme_sed_l0_find(&l0, sizeof(l0), TCG_L0_CODE_OPAL_V2);
	check(!desc, "found descriptor past the header length");

	/* a descriptor length running past the end */
	init_l0(&l0);
	l0.locking_desc.length = 0xff;
	desc = libnvme_sed_l0_find(&l0, sizeof(l0), TCG_L0_CODE_LOCKING);
	check(!desc, "found truncated descriptor");

	/* too short for the header */
	desc = libnvme_sed_l0_next(&l0, sizeof(l0.hdr) - 1, NULL);
	check(!desc, "found descriptor without a header");
}

/*
 * The Opal operations go through the kernel's block device ioctls,
 * which the loopback handle doesn't emulate. Check that they reject
 * it and the arguments they validate before issuing the ioctl.
 */
static void test_opal_args(void)
{
	struct libnvme_sed_key key = {
		.type = LIBNVME_SED_KEY_INCLUDED,
		.len = 4,
		.key = "test",
	};
	struct libnvme_sed_key bad_key = {
		.type = 0xff,
	};
#if NVME_HAVE_SED_OPAL
	int einval = -EINVAL, enotsup = -ENOTSUP;
#else
	int einval = -ENOTSUP, enotsup = -ENOTSUP;
#endif
	int err;

	err = libnvme_sed_take_ownership(test_hdl, &key);
	check(err == einval, "take_ownership returned %d", err);
	err = libnvme_sed_lock_unlock(test_hdl, &key, LIBNVME_SED_LOCK_RW);
	check(err == einval, "lock_unlock returned %d", err);
	err = libnvme_sed_lock_unlock(test_hdl, &key, 0);
	check(err == einval, "lock_unlock bad state returned %d", err);
	err = libnvme_sed_set_password(test_hdl, &key, &bad_key);
	check(err == enotsup, "set_password bad key returned %d", err);
	err = libnvme_sed_activate_lsp(test_hdl, &bad_key);
	check(err == enotsup, "activate_lsp bad key returned %d", err);
}

static void run_test(const char *test_name, void (*test_fn)(void))
{
	printf("Running test %s...", test_name);
	fflush(stdout);
	test_fn();
	puts(" OK");
}

#define RUN_TEST(name) run_test(#name, test_##name)

int main(void)
{
	struct libnvme_global_ctx *ctx = libnvme_create_global_ctx();

	libnvme_set_logging_file(ctx, stdout);

	check(!libnvme_open_loopback(ctx, &test_hdl),
	      "opening test link failed");

	RUN_TEST(discover);
	RUN_TEST(discover_status);
	RUN_TEST(l0_for_each);
	RUN_TEST(l0_find);
	RUN_TEST(l0_bounds);
	RUN_TEST(opal_args);

	libnvme_free_global_ctx(ctx);
}
