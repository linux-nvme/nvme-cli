// SPDX-License-Identifier: LGPL-2.1-or-later

#include <inttypes.h>

#include <libnvme.h>

#include "nvme/loopback.h"
#include "util.h"

#define TEST_NSID 0x12345678
#define TEST_SLBA 0xffffffff12345678

static struct libnvme_transport_handle *test_hdl;

static void test_zns_append(void)
{
	__u8 expected_data[8], data[8] = {};
	__u64 zslba = TEST_SLBA;
	__u16 control = 0xcd;
	__u16 cev = 0;
	__u16 dspec = 0;
	__u16 lbatm = 0x98;
	__u16 lbat = 0xef;
	__u16 nlb = 0xab;
	__u64 result = 0;
	bool elbas = true;
	__u8 sts = 48;
	__u8 pif = NVME_NVM_PIF_32B_GUARD;
	__u64 storage_tag = 0x12;
	__u64 reftag = 0x1234;
	struct libnvme_loopback_cmd mock_io_cmd = {
		.opcode = nvme_zns_cmd_append,
		.nsid = TEST_NSID,
		.cdw3 = storage_tag,
		.cdw10 = zslba & 0xffffffff,
		.cdw11 = zslba >> 32,
		.cdw12 = nlb | (control << 16),
		.cdw14 = reftag,
		.cdw15 = lbat | (lbatm << 16),
		.data_len = sizeof(expected_data),
		.out_data = &expected_data,
	};
	struct libnvme_passthru_cmd cmd;
	int err;

	arbitrary(&expected_data, sizeof(expected_data));
	libnvme_loopback_set_io_cmds(test_hdl, &mock_io_cmd, 1);
	nvme_init_zns_append(&cmd, TEST_NSID, zslba, nlb, control, cev, dspec,
		data, sizeof(data), NULL, 0);
	if (elbas)
		nvme_init_var_size_tags(&cmd, pif, sts, reftag, storage_tag);
	nvme_init_app_tag(&cmd, lbat, lbatm);
	err = libnvme_exec_io_passthru(test_hdl, &cmd);
	libnvme_loopback_end(test_hdl);
	check(err == 0, "returned error %d", err);
	check(result == 0, "wrong result");
	cmp(&data, &expected_data, sizeof(data), "incorrect data");
}

/*
 * nvme_init_var_size_tags()'s 32B Guard case packs an 80-bit combined
 * reference/storage tag field across cdw14 (bits 0-31), cdw3 (bits 32-63)
 * and cdw2 (bits 64-79), with the storage tag occupying the top `sts` bits
 * of that field, at [80-sts, 80). Per the NVM Command Set spec (Figure 119,
 * STS field), the only valid `sts` range for this PIF is [16, 64] --
 * @reftag and @storage_tag are each only 64 bits wide, so an sts outside
 * that range would require one of them to hold more than 64 meaningful
 * bits, which this interface can't represent. Cover both valid boundaries
 * and the first rejected value past each.
 */
static void test_zns_var_size_tags_32b_guard_sts_bounds(void)
{
	__u64 reftag = 0x123456;
	__u64 storage_tag = 0xab;
	struct libnvme_passthru_cmd cmd = { 0 };
	int ret;

	/* sts = 16: the spec minimum -- the exact boundary where
	 * 80 - sts == 64, so cdw14 must get no storage_tag contribution.
	 */
	cmd = (struct libnvme_passthru_cmd){ 0 };
	ret = nvme_init_var_size_tags(&cmd, NVME_NVM_PIF_32B_GUARD, 16, reftag, storage_tag);
	check(ret == 0, "sts=16 should be accepted, got %d", ret);
	check(cmd.cdw14 == (__u32)reftag, "cdw14 %#x, expected %#x", cmd.cdw14, (__u32)reftag);
	check(cmd.cdw3 == 0, "cdw3 %#x, expected 0", cmd.cdw3);
	check(cmd.cdw2 == storage_tag, "cdw2 %#x, expected %#llx",
	      cmd.cdw2, (unsigned long long)storage_tag);

	/*
	 * sts = 64: the spec maximum. The reference tag is only 16 bits
	 * wide at this boundary (80 - 64), unlike sts=16's 64-bit-wide
	 * reference tag above -- reusing the wider `reftag` here would
	 * overflow into the bits storage_tag's own contribution occupies,
	 * masking a packing bug behind the overlap instead of catching it.
	 */
	cmd = (struct libnvme_passthru_cmd){ 0 };
	ret = nvme_init_var_size_tags(&cmd, NVME_NVM_PIF_32B_GUARD, 64, 0x1234, storage_tag);
	check(ret == 0, "sts=64 should be accepted, got %d", ret);
	check(cmd.cdw14 == 0x00ab1234, "cdw14 %#x, expected %#x", cmd.cdw14, 0x00ab1234);
	check(cmd.cdw3 == 0, "cdw3 %#x, expected 0", cmd.cdw3);
	check(cmd.cdw2 == 0, "cdw2 %#x, expected 0", cmd.cdw2);

	/* sts = 15: just below the spec minimum -- rejected. */
	ret = nvme_init_var_size_tags(&cmd, NVME_NVM_PIF_32B_GUARD, 15, reftag, storage_tag);
	check(ret == -EINVAL, "sts=15 should be rejected, got %d", ret);

	/* sts = 65: just above the spec maximum -- rejected. Before this
	 * was enforced, sts=80 (storage_tag occupying the entire 80-bit
	 * field) silently encoded to cdw2=0, discarding storage_tag rather
	 * than reporting that it can't be represented.
	 */
	ret = nvme_init_var_size_tags(&cmd, NVME_NVM_PIF_32B_GUARD, 65, reftag, storage_tag);
	check(ret == -EINVAL, "sts=65 should be rejected, got %d", ret);
}

/*
 * nvme_init_var_size_tags() enforces a per-PIF sts range from the same
 * spec table: [0, 32] for 16b Guard, [0, 48] for 64b Guard. Cover
 * just-past-the-maximum rejection for both, mirroring the 32B Guard
 * coverage above.
 */
static void test_zns_var_size_tags_16b_64b_guard_sts_bounds(void)
{
	__u64 reftag = 0x1234;
	__u64 storage_tag = 0xab;
	struct libnvme_passthru_cmd cmd = { 0 };
	int ret;

	ret = nvme_init_var_size_tags(&cmd, NVME_NVM_PIF_16B_GUARD, 33, reftag, storage_tag);
	check(ret == -EINVAL, "16B Guard sts=33 should be rejected, got %d", ret);

	ret = nvme_init_var_size_tags(&cmd, NVME_NVM_PIF_64B_GUARD, 49, reftag, storage_tag);
	check(ret == -EINVAL, "64B Guard sts=49 should be rejected, got %d", ret);
}

static void test_zns_report_zones(void)
{
	enum nvme_zns_report_options opts = NVME_ZNS_ZRAS_REPORT_CLOSED;
	__u8 expected_data[8], data[8] = {};
	bool extended = true;
	bool partial = true;
	__u64 result = 0;
	struct libnvme_loopback_cmd mock_io_cmd = {
		.opcode = nvme_zns_cmd_mgmt_recv,
		.nsid = TEST_NSID,
		.cdw10 = TEST_SLBA & 0xffffffff,
		.cdw11 = TEST_SLBA >> 32,
		.cdw12 = (sizeof(expected_data) >> 2) - 1,
		.cdw13 = (extended << 0) | ((__u16)opts << 8) | (partial << 16),
		.data_len = sizeof(expected_data),
		.out_data = &expected_data,
	};
	struct libnvme_passthru_cmd cmd;
	int err;

	arbitrary(&expected_data, sizeof(expected_data));
	libnvme_loopback_set_io_cmds(test_hdl, &mock_io_cmd, 1);
	nvme_init_zns_report_zones(&cmd, TEST_NSID, TEST_SLBA, opts,
		extended, partial, &data, sizeof(data));
	err = libnvme_exec_io_passthru(test_hdl, &cmd);
	libnvme_loopback_end(test_hdl);
	check(err == 0, "returned error %d", err);
	check(result == 0, "returned result %"PRIu64, (uint64_t)result);
	cmp(&data, &expected_data, sizeof(data), "incorrect data");
}

static void test_zns_mgmt_send(void)
{
	enum nvme_zns_send_action zsa = NVME_ZNS_ZSA_OPEN;
	__u8 expected_data[8], data[8] = {};
	__u64 slba = TEST_SLBA;
	bool select_all = true;
	__u8 zsaso = 0x1;
	__u64 result = 0;
	struct libnvme_loopback_cmd mock_io_cmd = {
		.opcode = nvme_zns_cmd_mgmt_send,
		.nsid = TEST_NSID,
		.cdw10 = slba & 0xffffffff,
		.cdw11 = slba >> 32,
		.cdw13 = (zsaso << 9) | (select_all << 8) |
			 (zsa << 0),
		.data_len = sizeof(expected_data),
		.out_data = &expected_data,
	};
	struct libnvme_passthru_cmd cmd;
	int err;

	arbitrary(&expected_data, sizeof(expected_data));
	libnvme_loopback_set_io_cmds(test_hdl, &mock_io_cmd, 1);
	nvme_init_zns_mgmt_send(&cmd, TEST_NSID, slba, zsa, select_all, zsaso,
		false, data, sizeof(data));
	err = libnvme_exec_io_passthru(test_hdl, &cmd);
	libnvme_loopback_end(test_hdl);
	check(err == 0, "returned error %d", err);
	check(result == 0, "returned result %"PRIu64, (uint64_t)result);
	cmp(&data, &expected_data, sizeof(data), "incorrect data");
}

static void test_zns_mgmt_recv(void)
{
	enum nvme_zns_recv_action zra = NVME_ZNS_ZRA_REPORT_ZONES;
	__u8 expected_data[8], data[8] = {};
	__u16 zrasf = (__u16)NVME_ZNS_ZRAS_REPORT_ALL;
	bool zras_feat = false;
	__u64 result = 0;
	struct libnvme_loopback_cmd mock_io_cmd = {
		.opcode = nvme_zns_cmd_mgmt_recv,
		.nsid = TEST_NSID,
		.cdw12 = (sizeof(expected_data) >> 2) - 1,
		.cdw13 = (zra << 0) | (zrasf << 8) | (zras_feat << 16),
		.data_len = sizeof(expected_data),
		.out_data = &expected_data,
	};
	struct libnvme_passthru_cmd cmd;
	int err;

	arbitrary(&expected_data, sizeof(expected_data));
	libnvme_loopback_set_io_cmds(test_hdl, &mock_io_cmd, 1);
	nvme_init_zns_mgmt_recv(&cmd, TEST_NSID, 0, zra, zrasf, zras_feat,
		data, sizeof(data));
	err = libnvme_exec_io_passthru(test_hdl, &cmd);
	libnvme_loopback_end(test_hdl);
	check(err == 0, "returned error %d", err);
	check(result == 0, "returned result %"PRIu64, (uint64_t)result);
	cmp(&data, &expected_data, sizeof(data), "incorrect data");
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

	RUN_TEST(zns_append);
	RUN_TEST(zns_var_size_tags_32b_guard_sts_bounds);
	RUN_TEST(zns_var_size_tags_16b_64b_guard_sts_bounds);
	RUN_TEST(zns_report_zones);
	RUN_TEST(zns_mgmt_send);
	RUN_TEST(zns_mgmt_recv);

	libnvme_free_global_ctx(ctx);
}
