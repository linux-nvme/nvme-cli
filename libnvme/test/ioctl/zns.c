// SPDX-License-Identifier: LGPL-2.1-or-later

#include <libnvme.h>

#include "mock.h"
#include "util.h"
#include <nvme/api-types.h>
#include <nvme/ioctl.h>
#include <nvme/types.h>

#define TEST_FD 0xFD
#define TEST_NSID 0x12345678
#define TEST_SLBA 0xffffffff12345678

static struct nvme_transport_handle *test_hdl;

static void test_zns_append(void)
{
	__u8 expected_data[8], data[8] = {};
	__u64 result = 0;
	struct nvme_zns_append_args args = {
		.zslba = TEST_SLBA,
		.result = &result,
		.data = &data,
		.args_size = sizeof(args),
		.nsid = TEST_NSID,
		.data_len = sizeof(data),
		.nlb = 0xab,
		.control = 0xcd,
		.lbat = 0xef,
		.lbatm = 0x98,
		.ilbrt_u64 = 0x76,
	};

	struct mock_cmd mock_io_cmd = {
		.opcode = nvme_zns_cmd_append,
		.nsid = TEST_NSID,
		.cdw3 = (args.ilbrt_u64 >> 32) & 0xffffffff,
		.cdw10 = args.zslba & 0xffffffff,
		.cdw11 = args.zslba >> 32,
		.cdw12 = args.nlb | (args.control << 16),
		.cdw14 = args.ilbrt_u64 & 0xffffffff,
		.cdw15 = args.lbat | (args.lbatm << 16),
		.data_len = sizeof(expected_data),
		.out_data = &expected_data,
	};

	int err;

	arbitrary(&expected_data, sizeof(expected_data));
	set_mock_io_cmds(&mock_io_cmd, 1);
	err = nvme_zns_append(test_hdl, &args);
	end_mock_cmds();
	check(err == 0, "returned error %d", err);
	check(result == 0, "wrong result");
	cmp(&data, &expected_data, sizeof(data), "incorrect data");
}

static void test_zns_report_zones(void)
{
	__u8 expected_data[8], data[8] = {};
	__u32 result = 0;
	uint32_t timeout = 1234;
	bool extended = true;
	bool partial = true;
	enum nvme_zns_report_options opts = NVME_ZNS_ZRAS_REPORT_CLOSED;

	struct mock_cmd mock_io_cmd = {
		.opcode = nvme_zns_cmd_mgmt_recv,
		.nsid = TEST_NSID,
		.cdw10 = TEST_SLBA & 0xffffffff,
		.cdw11 = TEST_SLBA >> 32,
		.cdw12 = (sizeof(expected_data) >> 2) - 1,
		.cdw13 = (!!extended << 0) | ((__u16)opts << 8) |
			 (!!partial << 16),
		.data_len = sizeof(expected_data),
		.out_data = &expected_data,
		.timeout_ms = timeout,
	};

	int err;

	arbitrary(&expected_data, sizeof(expected_data));
	set_mock_io_cmds(&mock_io_cmd, 1);
	err = nvme_zns_report_zones(test_hdl, TEST_NSID, TEST_SLBA, opts,
				    extended, partial, sizeof(data), &data,
				    timeout, &result);
	end_mock_cmds();
	check(err == 0, "returned error %d", err);
	check(result == 0, "returned result %u", result);
	cmp(&data, &expected_data, sizeof(data), "incorrect data");
}

static void test_zns_mgmt_send(void)
{
	__u8 expected_data[8], data[8] = {};
	__u32 result = 0;
	uint32_t timeout = 1234;

	struct nvme_zns_mgmt_send_args args = {
		.slba = TEST_SLBA,
		.result = &result,
		.data = data,
		.args_size = sizeof(args),
		.timeout = timeout,
		.nsid = TEST_NSID,
		.zsa = NVME_ZNS_ZSA_OPEN,
		.data_len = sizeof(data),
		.select_all = true,
		.zsaso = !!true,
	};

	struct mock_cmd mock_io_cmd = {
		.opcode = nvme_zns_cmd_mgmt_send,
		.nsid = TEST_NSID,
		.cdw10 = args.slba & 0xffffffff,
		.cdw11 = args.slba >> 32,
		.cdw13 = (args.zsaso << 9) | (!!args.select_all << 8) |
			 (args.zsa << 0),
		.data_len = sizeof(expected_data),
		.out_data = &expected_data,
		.timeout_ms = timeout,
	};

	int err;

	arbitrary(&expected_data, sizeof(expected_data));
	set_mock_io_cmds(&mock_io_cmd, 1);
	err = nvme_zns_mgmt_send(test_hdl, &args);
	end_mock_cmds();
	check(err == 0, "returned error %d", err);
	check(result == 0, "returned result %u", result);
	cmp(&data, &expected_data, sizeof(data), "incorrect data");
}

static void test_zns_mgmt_recv(void)
{
	__u8 expected_data[8], data[8] = {};
	__u32 result = 0;
	uint32_t timeout = 1234;
	bool partial = false;

	struct nvme_zns_mgmt_recv_args args = {
		.slba = 0,
		.result = &result,
		.data = data,
		.args_size = sizeof(args),
		.timeout = timeout,
		.nsid = TEST_NSID,
		.zra = NVME_ZNS_ZRA_REPORT_ZONES,
		.data_len = sizeof(data),
		.zrasf = (__u16)NVME_ZNS_ZRAS_REPORT_ALL,
		.zras_feat = partial,
	};

	struct mock_cmd mock_io_cmd = {
		.opcode = nvme_zns_cmd_mgmt_recv,
		.nsid = TEST_NSID,
		.cdw12 = (sizeof(expected_data) >> 2) - 1,
		.cdw13 = (!!args.zra << 0) | ((__u16)args.zrasf << 8) |
			 (!!args.zras_feat << 16),
		.data_len = sizeof(expected_data),
		.out_data = &expected_data,
		.timeout_ms = timeout,
	};

	int err;

	arbitrary(&expected_data, sizeof(expected_data));
	set_mock_io_cmds(&mock_io_cmd, 1);
	err = nvme_zns_mgmt_recv(test_hdl, &args);
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
