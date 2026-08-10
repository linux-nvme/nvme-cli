// SPDX-License-Identifier: LGPL-2.1-or-later
/**
 * This file is part of libnvme.
 * Copyright (c) 2026 Daniel Wagner, SUSE Software Solutions
 */

#include <errno.h>
#include <stdint.h>
#include <stdio.h>

#include <libnvme.h>

#include "mock.h"
#include "util.h"

static struct libnvme_transport_handle *test_hdl;

static void test_submit_admin_not_supported(void)
{
	struct nvme_id_ctrl id = {};
	struct libnvme_passthru_cmd cmd;
	int err;

	nvme_init_identify_ctrl(&cmd, &id);
	err = libnvme_submit_admin_passthru(test_hdl, &cmd,
			(void *)(uintptr_t)0x1234);
	check(err == -ENOTSUP, "submit async returned %d, expected %d",
	      err, -ENOTSUP);
}

static void test_submit_io_not_supported(void)
{
	struct libnvme_passthru_cmd cmd = {};
	int err;

	err = libnvme_submit_io_passthru(test_hdl, &cmd,
			(void *)(uintptr_t)0x5678);
	check(err == -ENOTSUP, "IO submit async returned %d, expected %d",
	      err, -ENOTSUP);
}

static void test_reap_not_supported(void)
{
	struct libnvme_passthru_completion completion = {};
	int err;

	err = libnvme_reap_passthru(test_hdl, &completion);
	check(err == -ENOTSUP, "reap async returned %d, expected %d",
	      err, -ENOTSUP);
}

static void test_exec_admin(void)
{
	struct nvme_id_ctrl expected_id = {}, id = {};
	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_identify,
		.data_len = sizeof(expected_id),
		.cdw10 = NVME_IDENTIFY_CNS_CTRL,
		.out_data = &expected_id,
	};
	struct libnvme_passthru_cmd cmd;
	int err;

	arbitrary(&expected_id, sizeof(expected_id));
	set_mock_admin_cmds(&mock_admin_cmd, 1);
	nvme_init_identify_ctrl(&cmd, &id);
	err = libnvme_exec_admin_passthru(test_hdl, &cmd);
	end_mock_cmds();
	check(err == 0, "sync fallback returned %d", err);
	cmp(&id, &expected_id, sizeof(id), "incorrect identify data");
}

static void test_exec_io(void)
{
	struct libnvme_passthru_cmd cmd = {};
	struct mock_cmd mock_io_cmd = {
		.opcode = nvme_cmd_read,
		.data_len = 0,
	};
	int err;

	set_mock_io_cmds(&mock_io_cmd, 1);
	cmd.opcode = nvme_cmd_read;
	err = libnvme_exec_io_passthru(test_hdl, &cmd);
	end_mock_cmds();
	check(err == 0, "IO sync fallback returned %d", err);
}

static void run_test(const char *test_name, void (*test_fn)(void))
{
	printf("Running test %s...", test_name);
	fflush(stdout);
	test_fn();
	puts(" OK");
}

#define RUN_TEST(name) run_test(#name, test_ ## name)

int main(void)
{
	struct libnvme_global_ctx *ctx = libnvme_create_global_ctx();
	libnvme_set_logging_file(ctx, stdout);

	set_mock_fd(LIBNVME_TEST_FD);
	check(!libnvme_open(ctx, "NVME_TEST_FD", &test_hdl),
	      "opening test link failed");

	RUN_TEST(submit_admin_not_supported);
	RUN_TEST(submit_io_not_supported);
	RUN_TEST(reap_not_supported);
	RUN_TEST(exec_admin);
	RUN_TEST(exec_io);

	libnvme_free_global_ctx(ctx);
}
