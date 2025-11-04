// SPDX-License-Identifier: LGPL-2.1-or-later

#include <errno.h>
#include <stdlib.h>

#include <libnvme.h>

#include "mock.h"
#include "util.h"

#define TEST_FD 0xFD
#define TEST_NSID 0x12345678
#define TEST_NVMSETID 0xABCD
#define TEST_UUID 123
#define TEST_CSI NVME_CSI_KV
#define TEST_CNTID 0x4321
#define TEST_DOMID 0xFEDC
#define TEST_ENDGID 0x0123
#define TEST_FIDX 0xF
#define TEST_SC NVME_SC_INVALID_FIELD

static void test_ns(void)
{
	struct nvme_id_ns expected_id, id = {};
	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_identify,
		.nsid = TEST_NSID,
		.data_len = sizeof(expected_id),
		.cdw10 = NVME_IDENTIFY_CNS_NS,
		.out_data = &expected_id,
	};
	int err;

	arbitrary(&expected_id, sizeof(expected_id));
	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_identify_ns(TEST_FD, TEST_NSID, &id);
	end_mock_cmds();
	check(err == 0, "identify returned error %d, errno %m", err);
	cmp(&id, &expected_id, sizeof(id), "incorrect identify data");
}

static void test_ctrl(void)
{
	struct nvme_id_ctrl expected_id, id = {};
	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_identify,
		.data_len = sizeof(expected_id),
		.cdw10 = NVME_IDENTIFY_CNS_CTRL,
		.out_data = &expected_id,
	};
	int err;

	arbitrary(&expected_id, sizeof(expected_id));
	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_identify_ctrl(TEST_FD, &id);
	end_mock_cmds();
	check(err == 0, "identify returned error %d, errno %m", err);
	cmp(&id, &expected_id, sizeof(id), "incorrect identify data");
}

static void test_active_ns_list(void)
{
	struct nvme_ns_list expected_id, id = {};
	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_identify,
		.nsid = TEST_NSID,
		.data_len = sizeof(expected_id),
		.cdw10 = NVME_IDENTIFY_CNS_NS_ACTIVE_LIST,
		.out_data = &expected_id,
	};
	int err;

	arbitrary(&expected_id, sizeof(expected_id));
	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_identify_active_ns_list(TEST_FD, TEST_NSID, &id);
	end_mock_cmds();
	check(err == 0, "identify returned error %d, errno %m", err);
	cmp(&id, &expected_id, sizeof(id), "incorrect identify data");
}

static void test_ns_descs(void)
{
	uint8_t expected_id[NVME_IDENTIFY_DATA_SIZE];
	struct nvme_ns_id_desc *id;
	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_identify,
		.nsid = TEST_NSID,
		.data_len = sizeof(expected_id),
		.cdw10 = NVME_IDENTIFY_CNS_NS_DESC_LIST,
		.out_data = &expected_id,
	};
	int err;

	arbitrary(expected_id, sizeof(expected_id));
	id = calloc(1, NVME_IDENTIFY_DATA_SIZE);
	check(id, "memory allocation failed");
	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_identify_ns_descs(TEST_FD, TEST_NSID, id);
	end_mock_cmds();
	check(err == 0, "identify returned error %d, errno %m", err);
	cmp(id, expected_id, sizeof(expected_id), "incorrect identify data");
	free(id);
}

static void test_nvmset_list(void)
{
	struct nvme_id_nvmset_list expected_id, id = {};
	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_identify,
		.data_len = sizeof(expected_id),
		.cdw10 = NVME_IDENTIFY_CNS_NVMSET_LIST,
		.cdw11 = TEST_NVMSETID,
		.out_data = &expected_id,
	};
	int err;

	arbitrary(&expected_id, sizeof(expected_id));
	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_identify_nvmset_list(TEST_FD, TEST_NVMSETID, &id);
	end_mock_cmds();
	check(err == 0, "identify returned error %d, errno %m", err);
	cmp(&id, &expected_id, sizeof(id), "incorrect identify data");
}

static void test_ns_csi(void)
{
	uint8_t expected_id[NVME_IDENTIFY_DATA_SIZE];
	uint8_t id[NVME_IDENTIFY_DATA_SIZE] = {};
	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_identify,
		.nsid = TEST_NSID,
		.data_len = sizeof(expected_id),
		.cdw10 = NVME_IDENTIFY_CNS_CSI_NS,
		.cdw11 = TEST_CSI << 24,
		.cdw14 = TEST_UUID,
		.out_data = expected_id,
	};
	int err;

	arbitrary(expected_id, sizeof(expected_id));
	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_identify_ns_csi(TEST_FD, TEST_NSID, TEST_UUID, TEST_CSI, id);
	end_mock_cmds();
	check(err == 0, "identify returned error %d, errno %m", err);
	cmp(id, expected_id, sizeof(id), "incorrect identify data");
}

static void test_zns_identify_ns(void)
{
	struct nvme_zns_id_ns expected_id, id = {};
	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_identify,
		.nsid = TEST_NSID,
		.data_len = sizeof(expected_id),
		.cdw10 = NVME_IDENTIFY_CNS_CSI_NS,
		.cdw11 = NVME_CSI_ZNS << 24,
		.out_data = &expected_id,
	};
	int err;

	arbitrary(&expected_id, sizeof(expected_id));
	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_zns_identify_ns(TEST_FD, TEST_NSID, &id);
	end_mock_cmds();
	check(err == 0, "identify returned error %d, errno %m", err);
	cmp(&id, &expected_id, sizeof(id), "incorrect identify data");
}

static void test_nvm_identify_ctrl(void)
{
	struct nvme_id_ctrl_nvm expected_id, id = {};
	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_identify,
		.data_len = sizeof(expected_id),
		.cdw10 = NVME_IDENTIFY_CNS_CSI_CTRL,
		.cdw11 = NVME_CSI_NVM << 24,
		.out_data = &expected_id,
	};
	int err;

	arbitrary(&expected_id, sizeof(expected_id));
	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_nvm_identify_ctrl(TEST_FD, &id);
	end_mock_cmds();
	check(err == 0, "identify returned error %d, errno %m", err);
	cmp(&id, &expected_id, sizeof(id), "incorrect identify data");
}

static void test_zns_identify_ctrl(void)
{
	struct nvme_zns_id_ctrl expected_id, id = {};
	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_identify,
		.data_len = sizeof(expected_id),
		.cdw10 = NVME_IDENTIFY_CNS_CSI_CTRL,
		.cdw11 = NVME_CSI_ZNS << 24,
		.out_data = &expected_id,
	};
	int err;

	arbitrary(&expected_id, sizeof(expected_id));
	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_zns_identify_ctrl(TEST_FD, &id);
	end_mock_cmds();
	check(err == 0, "identify returned error %d, errno %m", err);
	cmp(&id, &expected_id, sizeof(id), "incorrect identify data");
}

static void test_active_ns_list_csi(void)
{
	struct nvme_ns_list expected_id, id = {};
	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_identify,
		.nsid = TEST_NSID,
		.data_len = sizeof(expected_id),
		.cdw10 = NVME_IDENTIFY_CNS_CSI_NS_ACTIVE_LIST,
		.cdw11 = TEST_CSI << 24,
		.out_data = &expected_id,
	};
	int err;

	arbitrary(&expected_id, sizeof(expected_id));
	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_identify_active_ns_list_csi(
		TEST_FD, TEST_NSID, TEST_CSI, &id);
	end_mock_cmds();
	check(err == 0, "identify returned error %d, errno %m", err);
	cmp(&id, &expected_id, sizeof(id), "incorrect identify data");
}

static void test_independent_identify_ns(void)
{
	struct nvme_id_independent_id_ns expected_id, id = {};
	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_identify,
		.nsid = TEST_NSID,
		.data_len = sizeof(expected_id),
		.cdw10 = NVME_IDENTIFY_CNS_CSI_INDEPENDENT_ID_NS,
		.out_data = &expected_id,
	};
	int err;

	arbitrary(&expected_id, sizeof(expected_id));
	set_mock_admin_cmds(&mock_admin_cmd, 1);
	/* That's a mouthful! */
	err = nvme_identify_independent_identify_ns(TEST_FD, TEST_NSID, &id);
	end_mock_cmds();
	check(err == 0, "identify returned error %d, errno %m", err);
	cmp(&id, &expected_id, sizeof(id), "incorrect identify data");
}

static void test_allocated_ns_list(void)
{
	struct nvme_ns_list expected_id, id = {};
	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_identify,
		.nsid = TEST_NSID,
		.data_len = sizeof(expected_id),
		.cdw10 = NVME_IDENTIFY_CNS_ALLOCATED_NS_LIST,
		.out_data = &expected_id,
	};
	int err;

	arbitrary(&expected_id, sizeof(expected_id));
	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_identify_allocated_ns_list(TEST_FD, TEST_NSID, &id);
	end_mock_cmds();
	check(err == 0, "identify returned error %d, errno %m", err);
	cmp(&id, &expected_id, sizeof(id), "incorrect identify data");
}

static void test_allocated_ns(void)
{
	struct nvme_id_ns expected_id, id = {};
	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_identify,
		.nsid = TEST_NSID,
		.data_len = sizeof(expected_id),
		.cdw10 = NVME_IDENTIFY_CNS_ALLOCATED_NS,
		.out_data = &expected_id,
	};
	int err;

	arbitrary(&expected_id, sizeof(expected_id));
	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_identify_allocated_ns(TEST_FD, TEST_NSID, &id);
	end_mock_cmds();
	check(err == 0, "identify returned error %d, errno %m", err);
	cmp(&id, &expected_id, sizeof(id), "incorrect identify data");
}

static void test_nsid_ctrl_list(void)
{
	struct nvme_ctrl_list expected_id, id = {};
	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_identify,
		.nsid = TEST_NSID,
		.data_len = sizeof(expected_id),
		.cdw10 = TEST_CNTID << 16
		       | NVME_IDENTIFY_CNS_NS_CTRL_LIST,
		.out_data = &expected_id,
	};
	int err;

	arbitrary(&expected_id, sizeof(expected_id));
	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_identify_nsid_ctrl_list(TEST_FD, TEST_NSID, TEST_CNTID, &id);
	end_mock_cmds();
	check(err == 0, "identify returned error %d, errno %m", err);
	cmp(&id, &expected_id, sizeof(id), "incorrect identify data");
}

static void test_ctrl_list(void)
{
	struct nvme_ctrl_list expected_id, id = {};
	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_identify,
		.data_len = sizeof(expected_id),
		.cdw10 = TEST_CNTID << 16
		       | NVME_IDENTIFY_CNS_CTRL_LIST,
		.out_data = &expected_id,
	};
	int err;

	arbitrary(&expected_id, sizeof(expected_id));
	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_identify_ctrl_list(TEST_FD, TEST_CNTID, &id);
	end_mock_cmds();
	check(err == 0, "identify returned error %d, errno %m", err);
	cmp(&id, &expected_id, sizeof(id), "incorrect identify data");
}

static void test_primary_ctrl(void)
{
	struct nvme_primary_ctrl_cap expected_id, id = {};
	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_identify,
		.data_len = sizeof(expected_id),
		.cdw10 = TEST_CNTID << 16
		       | NVME_IDENTIFY_CNS_PRIMARY_CTRL_CAP,
		.out_data = &expected_id,
	};
	int err;

	arbitrary(&expected_id, sizeof(expected_id));
	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_identify_primary_ctrl(TEST_FD, TEST_CNTID, &id);
	end_mock_cmds();
	check(err == 0, "identify returned error %d, errno %m", err);
	cmp(&id, &expected_id, sizeof(id), "incorrect identify data");
}

static void test_secondary_ctrl_list(void)
{
	struct nvme_secondary_ctrl_list expected_id, id = {};
	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_identify,
		.data_len = sizeof(expected_id),
		.cdw10 = TEST_CNTID << 16
		       | NVME_IDENTIFY_CNS_SECONDARY_CTRL_LIST,
		.out_data = &expected_id,
	};
	int err;

	arbitrary(&expected_id, sizeof(expected_id));
	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_identify_secondary_ctrl_list(TEST_FD, TEST_CNTID, &id);
	end_mock_cmds();
	check(err == 0, "identify returned error %d, errno %m", err);
	cmp(&id, &expected_id, sizeof(id), "incorrect identify data");
}

static void test_ns_granularity(void)
{
	struct nvme_id_ns_granularity_list expected_id, id = {};
	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_identify,
		.data_len = sizeof(expected_id),
		.cdw10 = NVME_IDENTIFY_CNS_NS_GRANULARITY,
		.out_data = &expected_id,
	};
	int err;

	arbitrary(&expected_id, sizeof(expected_id));
	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_identify_ns_granularity(TEST_FD, &id);
	end_mock_cmds();
	check(err == 0, "identify returned error %d, errno %m", err);
	cmp(&id, &expected_id, sizeof(id), "incorrect identify data");
}

static void test_uuid(void)
{
	struct nvme_id_uuid_list expected_id, id = {};
	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_identify,
		.data_len = sizeof(expected_id),
		.cdw10 = NVME_IDENTIFY_CNS_UUID_LIST,
		.out_data = &expected_id,
	};
	int err;

	arbitrary(&expected_id, sizeof(expected_id));
	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_identify_uuid(TEST_FD, &id);
	end_mock_cmds();
	check(err == 0, "identify returned error %d, errno %m", err);
	cmp(&id, &expected_id, sizeof(id), "incorrect identify data");
}

static void test_domain_list(void)
{
	struct nvme_id_domain_list expected_id, id = {};
	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_identify,
		.data_len = sizeof(expected_id),
		.cdw10 = NVME_IDENTIFY_CNS_DOMAIN_LIST,
		.cdw11 = TEST_DOMID,
		.out_data = &expected_id,
	};
	int err;

	arbitrary(&expected_id, sizeof(expected_id));
	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_identify_domain_list(TEST_FD, TEST_DOMID, &id);
	end_mock_cmds();
	check(err == 0, "identify returned error %d, errno %m", err);
	cmp(&id, &expected_id, sizeof(id), "incorrect identify data");
}

static void test_endurance_group_list(void)
{
	struct nvme_id_endurance_group_list expected_id, id = {};
	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_identify,
		.data_len = sizeof(expected_id),
		.cdw10 = NVME_IDENTIFY_CNS_ENDURANCE_GROUP_ID,
		.cdw11 = TEST_ENDGID,
		.out_data = &expected_id,
	};
	int err;

	arbitrary(&expected_id, sizeof(expected_id));
	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_identify_endurance_group_list(TEST_FD, TEST_ENDGID, &id);
	end_mock_cmds();
	check(err == 0, "identify returned error %d, errno %m", err);
	cmp(&id, &expected_id, sizeof(id), "incorrect identify data");
}

static void test_allocated_ns_list_csi(void)
{
	struct nvme_ns_list expected_id, id = {};
	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_identify,
		.nsid = TEST_NSID,
		.data_len = sizeof(expected_id),
		.cdw10 = NVME_IDENTIFY_CNS_CSI_ALLOCATED_NS_LIST,
		.cdw11 = TEST_CSI << 24,
		.out_data = &expected_id,
	};
	int err;

	arbitrary(&expected_id, sizeof(expected_id));
	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_identify_allocated_ns_list_csi(
		TEST_FD, TEST_NSID, TEST_CSI, &id);
	end_mock_cmds();
	check(err == 0, "identify returned error %d, errno %m", err);
	cmp(&id, &expected_id, sizeof(id), "incorrect identify data");
}

static void test_iocs(void)
{
	struct nvme_id_iocs expected_id, id = {};
	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_identify,
		.data_len = sizeof(expected_id),
		.cdw10 = TEST_CNTID << 16
		       | NVME_IDENTIFY_CNS_COMMAND_SET_STRUCTURE,
		.out_data = &expected_id,
	};
	int err;

	arbitrary(&expected_id, sizeof(expected_id));
	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_identify_iocs(TEST_FD, TEST_CNTID, &id);
	end_mock_cmds();
	check(err == 0, "identify returned error %d, errno %m", err);
	cmp(&id, &expected_id, sizeof(id), "incorrect identify data");
}

/*
 * All identify functions tail-call nvme_identify(),
 * so testing errors in any of them will do
 */

static void test_status_code_error(void)
{
	struct nvme_id_nvmset_list id = {};
	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_identify,
		.data_len = sizeof(id),
		.cdw10 = NVME_IDENTIFY_CNS_NVMSET_LIST,
		.cdw11 = TEST_NVMSETID,
		.err = TEST_SC,
	};
	int err;

	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_identify_nvmset_list(TEST_FD, TEST_NVMSETID, &id);
	end_mock_cmds();
	check(err == TEST_SC, "got error %d, expected %d", err, TEST_SC);
}

static void test_kernel_error(void)
{
	struct nvme_id_ns id = {};
	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_identify,
		.nsid = TEST_NSID,
		.data_len = sizeof(id),
		.cdw10 = NVME_IDENTIFY_CNS_NS,
		.err = -EIO,
	};
	int err;

	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_identify_ns(TEST_FD, TEST_NSID, &id);
	end_mock_cmds();
	check(err == -1, "got error %d, expected -1", err);
	check(errno == EIO, "unexpected error %m");
}

static void test_identify_ns_csi_user_data_format(void)
{
	struct nvme_id_ns expected_id, id = {};
	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_identify,
		.nsid = NVME_NSID_NONE,
		.data_len = sizeof(expected_id),
		.cdw10 = NVME_IDENTIFY_CNS_NS_USER_DATA_FORMAT,
		//TEST_CSI=NVME_CSI_KV does not implement this command
		.cdw11 = (TEST_FIDX << 0) | (NVME_CSI_NVM << 24),
		.cdw14 = TEST_UUID,
		.out_data = &expected_id,
	};
	int err;

	arbitrary(&expected_id, sizeof(expected_id));
	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_identify_ns_csi_user_data_format(
		TEST_FD, TEST_FIDX, TEST_UUID, NVME_CSI_NVM, &id);
	end_mock_cmds();
	check(err == 0, "identify returned error %d, errno %m", err);
	cmp(&id, &expected_id, sizeof(id), "incorrect identify data");
}

static void test_identify_iocs_ns_csi_user_data_format(void)
{
	struct nvme_id_ns expected_id, id = {};
	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_identify,
		.nsid = NVME_NSID_NONE,
		.data_len = sizeof(expected_id),
		.cdw10 = NVME_IDENTIFY_CNS_CSI_NS_USER_DATA_FORMAT,
		.cdw11 = (TEST_FIDX << 0) | (TEST_CSI << 24),
		.cdw14 = TEST_UUID,
		.out_data = &expected_id,
	};
	int err;

	arbitrary(&expected_id, sizeof(expected_id));
	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_identify_iocs_ns_csi_user_data_format(
		TEST_FD, TEST_FIDX, TEST_UUID, TEST_CSI, &id);
	end_mock_cmds();
	check(err == 0, "identify returned error %d, errno %m", err);
	cmp(&id, &expected_id, sizeof(id), "incorrect identify data");
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
	set_mock_fd(TEST_FD);
	RUN_TEST(ns);
	RUN_TEST(ctrl);
	RUN_TEST(active_ns_list);
	RUN_TEST(ns_descs);
	RUN_TEST(nvmset_list);
	RUN_TEST(ns_csi);
	RUN_TEST(zns_identify_ns);
	RUN_TEST(nvm_identify_ctrl);
	RUN_TEST(zns_identify_ctrl);
	RUN_TEST(active_ns_list_csi);
	RUN_TEST(independent_identify_ns);
	RUN_TEST(allocated_ns_list);
	RUN_TEST(allocated_ns);
	RUN_TEST(nsid_ctrl_list);
	RUN_TEST(ctrl_list);
	RUN_TEST(primary_ctrl);
	RUN_TEST(secondary_ctrl_list);
	RUN_TEST(ns_granularity);
	RUN_TEST(uuid);
	RUN_TEST(domain_list);
	RUN_TEST(endurance_group_list);
	RUN_TEST(allocated_ns_list_csi);
	RUN_TEST(iocs);
	RUN_TEST(status_code_error);
	RUN_TEST(kernel_error);
	RUN_TEST(identify_ns_csi_user_data_format);
	RUN_TEST(identify_iocs_ns_csi_user_data_format);
}
