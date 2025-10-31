// SPDX-License-Identifier: LGPL-2.1-or-later

#include <libnvme.h>

#include "mock.h"
#include "util.h"
#include <nvme/ioctl.h>
#include <nvme/types.h>

#define TEST_FD 0xFD
#define TEST_NSID 0x12345678
#define TEST_SLBA 0xffffffff12345678

static struct nvme_transport_handle *test_hdl;

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
	struct mock_cmd mock_io_cmd = {
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
	struct nvme_passthru_cmd64 cmd;
	int err;

	arbitrary(&expected_data, sizeof(expected_data));
	set_mock_io_cmds(&mock_io_cmd, 1);
	nvme_init_zns_append(&cmd, TEST_NSID, zslba, nlb, control, cev, dspec,
		data, sizeof(data), NULL, 0);
	if (elbas)
		nvme_init_var_size_tags(&cmd, pif, sts, reftag, storage_tag);
	nvme_init_app_tag(&cmd, lbat, lbatm);
	err = nvme_submit_io_passthru64(test_hdl, &cmd, &result);
	end_mock_cmds();
	check(err == 0, "returned error %d", err);
	check(result == 0, "wrong result");
	cmp(&data, &expected_data, sizeof(data), "incorrect data");
}

static void test_zns_report_zones(void)
{
	enum nvme_zns_report_options opts = NVME_ZNS_ZRAS_REPORT_CLOSED;
	__u8 expected_data[8], data[8] = {};
	bool extended = true;
	bool partial = true;
	__u32 result = 0;
	struct mock_cmd mock_io_cmd = {
		.opcode = nvme_zns_cmd_mgmt_recv,
		.nsid = TEST_NSID,
		.cdw10 = TEST_SLBA & 0xffffffff,
		.cdw11 = TEST_SLBA >> 32,
		.cdw12 = (sizeof(expected_data) >> 2) - 1,
		.cdw13 = (extended << 0) | ((__u16)opts << 8) | (partial << 16),
		.data_len = sizeof(expected_data),
		.out_data = &expected_data,
	};
	struct nvme_passthru_cmd cmd;
	int err;

	arbitrary(&expected_data, sizeof(expected_data));
	set_mock_io_cmds(&mock_io_cmd, 1);
	nvme_init_zns_report_zones(&cmd, TEST_NSID, TEST_SLBA, opts,
		extended, partial, &data, sizeof(data));
	err = nvme_submit_io_passthru(test_hdl, &cmd, &result);
	end_mock_cmds();
	check(err == 0, "returned error %d", err);
	check(result == 0, "returned result %u", result);
	cmp(&data, &expected_data, sizeof(data), "incorrect data");
}

static void test_zns_mgmt_send(void)
{
	enum nvme_zns_send_action zsa = NVME_ZNS_ZSA_OPEN;
	__u8 expected_data[8], data[8] = {};
	__u64 slba = TEST_SLBA;
	bool select_all = true;
	__u8 zsaso = 0x1;
	__u32 result = 0;
	struct mock_cmd mock_io_cmd = {
		.opcode = nvme_zns_cmd_mgmt_send,
		.nsid = TEST_NSID,
		.cdw10 = slba & 0xffffffff,
		.cdw11 = slba >> 32,
		.cdw13 = (zsaso << 9) | (select_all << 8) |
			 (zsa << 0),
		.data_len = sizeof(expected_data),
		.out_data = &expected_data,
	};
	struct nvme_passthru_cmd cmd;
	int err;

	arbitrary(&expected_data, sizeof(expected_data));
	set_mock_io_cmds(&mock_io_cmd, 1);
	nvme_init_zns_mgmt_send(&cmd, TEST_NSID, slba, zsa, select_all, zsaso,
		false, data, sizeof(data));
	err = nvme_submit_io_passthru(test_hdl, &cmd, &result);
	end_mock_cmds();
	check(err == 0, "returned error %d", err);
	check(result == 0, "returned result %u", result);
	cmp(&data, &expected_data, sizeof(data), "incorrect data");
}

static void test_zns_mgmt_recv(void)
{
	enum nvme_zns_recv_action zra = NVME_ZNS_ZRA_REPORT_ZONES;
	__u8 expected_data[8], data[8] = {};
	__u16 zrasf = (__u16)NVME_ZNS_ZRAS_REPORT_ALL;
	bool zras_feat = false;
	__u32 result = 0;
	struct mock_cmd mock_io_cmd = {
		.opcode = nvme_zns_cmd_mgmt_recv,
		.nsid = TEST_NSID,
		.cdw12 = (sizeof(expected_data) >> 2) - 1,
		.cdw13 = (zra << 0) | (zrasf << 8) | (zras_feat << 16),
		.data_len = sizeof(expected_data),
		.out_data = &expected_data,
	};
	struct nvme_passthru_cmd cmd;
	int err;

	arbitrary(&expected_data, sizeof(expected_data));
	set_mock_io_cmds(&mock_io_cmd, 1);
	nvme_init_zns_mgmt_recv(&cmd, TEST_NSID, 0, zra, zrasf, zras_feat,
		data, sizeof(data));
	err = nvme_submit_io_passthru(test_hdl, &cmd, &result);
	end_mock_cmds();
	check(err == 0, "returned error %d", err);
	check(result == 0, "returned result %u", result);
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
	struct nvme_global_ctx *ctx =
		nvme_create_global_ctx(stdout, DEFAULT_LOGLEVEL);

	set_mock_fd(TEST_FD);
	check(!nvme_open(ctx, "NVME_TEST_FD", &test_hdl),
	      "opening test link failed");

	RUN_TEST(zns_append);
	RUN_TEST(zns_report_zones);
	RUN_TEST(zns_mgmt_send);
	RUN_TEST(zns_mgmt_recv);

	nvme_free_global_ctx(ctx);
}
