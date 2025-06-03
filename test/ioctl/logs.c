// SPDX-License-Identifier: LGPL-2.1-or-later

#include <libnvme.h>

#include "mock.h"
#include "util.h"
#include <nvme/ioctl.h>
#include <nvme/types.h>

#define TEST_FD 0xFD
#define TEST_NSID 0x12345678
#define TEST_NVMSETID 0xABCD
#define TEST_CSI NVME_CSI_KV
#define TEST_CNTID 0x4321
#define TEST_DOMID 0xFEDC
#define TEST_ENDGID 0x0123
#define TEST_RAE true
#define TEST_MCDA NVME_TELEMETRY_DA_3
#define TEST_OFFSET 0xFFFFFFFF1
#define TEST_OFFSET_32 0xFFFFFFFF
#define TEST_EVENTS true
#define TEST_ANA_LSP NVME_LOG_ANA_LSP_RGO_NAMESPACES
#define TEST_LSP NVME_LOG_CDW10_LSP_MASK
#define TEST_PEVENT NVME_PEVENT_LOG_RELEASE_CTX

static void test_get_log_sanitize(void)
{
	struct nvme_sanitize_log_page expected_log, log = {};
	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_get_log_page,
		.nsid = NVME_NSID_ALL,
		.data_len = sizeof(expected_log),
		.cdw10 = (NVME_LOG_LID_SANITIZE << 0) | (!!TEST_RAE << 15) |
			 (((sizeof(expected_log) >> 2) - 1) << 16),
		.out_data = &expected_log,
	};
	int err;

	arbitrary(&expected_log, sizeof(expected_log));
	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_get_log_sanitize(TEST_FD, true, &log);
	end_mock_cmds();
	check(err == 0, "get log returned error %d, errno %m", err);
	cmp(&log, &expected_log, sizeof(log), "incorrect log data");
}

static void test_get_log_mgmt_addr_list(void)
{
	struct nvme_mgmt_addr_list_log expected_log, log = {};
	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_get_log_page,
		.nsid = NVME_NSID_ALL,
		.data_len = sizeof(expected_log),
		.cdw10 = (NVME_LOG_LID_MGMT_ADDR_LIST << 0) |
			 (((sizeof(expected_log) >> 2) - 1) << 16),
		.out_data = &expected_log,
	};
	int err;

	arbitrary(&expected_log, sizeof(expected_log));
	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_get_log_mgmt_addr_list(TEST_FD, sizeof(log), &log);
	end_mock_cmds();
	check(err == 0, "get log returned error %d, errno %m", err);
	cmp(&log, &expected_log, sizeof(log), "incorrect log data");
}

static void test_get_log_supported_log_pages(void)
{
	struct nvme_supported_log_pages expected_log, log = {};
	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_get_log_page,
		.nsid = NVME_NSID_ALL,
		.data_len = sizeof(expected_log),
		.cdw10 = (NVME_LOG_LID_SUPPORTED_LOG_PAGES << 0) |
			 (!TEST_RAE << 15) |
			 (((sizeof(expected_log) >> 2) - 1) << 16),
		.out_data = &expected_log,
	};
	int err;

	arbitrary(&expected_log, sizeof(expected_log));
	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_get_log_supported_log_pages(TEST_FD, !TEST_RAE, &log);
	end_mock_cmds();
	check(err == 0, "get log returned error %d, errno %m", err);
	cmp(&log, &expected_log, sizeof(log), "incorrect log data");
}

static void test_get_log_error(void)
{
	struct nvme_error_log_page expected_log, log = {};
	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_get_log_page,
		.nsid = NVME_NSID_ALL,
		.data_len = sizeof(expected_log),
		.cdw10 = (NVME_LOG_LID_ERROR << 0) | (!!TEST_RAE << 15) |
			 (((sizeof(expected_log) >> 2) - 1) << 16),
		.out_data = &expected_log,
	};
	int err;

	arbitrary(&expected_log, sizeof(expected_log));
	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_get_log_error(TEST_FD, 1, TEST_RAE, &log);
	end_mock_cmds();
	check(err == 0, "get log returned error %d, errno %m", err);
	cmp(&log, &expected_log, sizeof(log), "incorrect log data");
}

static void test_get_log_smart(void)
{
	struct nvme_smart_log expected_log, log = {};
	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_get_log_page,
		.nsid = TEST_NSID,
		.data_len = sizeof(expected_log),
		.cdw10 = (NVME_LOG_LID_SMART << 0) | (!!TEST_RAE << 15) |
			 (((sizeof(expected_log) >> 2) - 1) << 16),
		.out_data = &expected_log,
	};
	int err;

	arbitrary(&expected_log, sizeof(expected_log));
	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_get_log_smart(TEST_FD, TEST_NSID, TEST_RAE, &log);
	end_mock_cmds();
	check(err == 0, "get log returned error %d, errno %m", err);
	cmp(&log, &expected_log, sizeof(log), "incorrect log data");
}

static void test_get_log_fw_slot(void)
{
	struct nvme_firmware_slot expected_log, log = {};
	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_get_log_page,
		.nsid = NVME_NSID_ALL,
		.data_len = sizeof(expected_log),
		.cdw10 = (NVME_LOG_LID_FW_SLOT << 0) | (!!TEST_RAE << 15) |
			 (((sizeof(expected_log) >> 2) - 1) << 16),
		.out_data = &expected_log,
	};
	int err;

	arbitrary(&expected_log, sizeof(expected_log));
	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_get_log_fw_slot(TEST_FD, TEST_RAE, &log);
	end_mock_cmds();
	check(err == 0, "get log returned error %d, errno %m", err);
	cmp(&log, &expected_log, sizeof(log), "incorrect log data");
}

static void test_get_log_changed_ns_list(void)
{
	struct nvme_ns_list expected_log, log = {};
	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_get_log_page,
		.nsid = NVME_NSID_ALL,
		.data_len = sizeof(expected_log),
		.cdw10 = (NVME_LOG_LID_CHANGED_NS << 0) | (!!TEST_RAE << 15) |
			 (((sizeof(expected_log) >> 2) - 1) << 16),
		.out_data = &expected_log,
	};
	int err;

	arbitrary(&expected_log, sizeof(expected_log));
	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_get_log_changed_ns_list(TEST_FD, TEST_RAE, &log);
	end_mock_cmds();
	check(err == 0, "get log returned error %d, errno %m", err);
	cmp(&log, &expected_log, sizeof(log), "incorrect log data");
}

static void test_get_log_cmd_effects(void)
{
	struct nvme_cmd_effects_log expected_log, log = {};
	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_get_log_page,
		.nsid = NVME_NSID_ALL,
		.data_len = sizeof(expected_log),
		.cdw10 = (NVME_LOG_LID_CMD_EFFECTS << 0) |
			 (((sizeof(expected_log) >> 2) - 1) << 16),
		.cdw14 = (TEST_CSI << 24),
		.out_data = &expected_log,
	};
	int err;

	arbitrary(&expected_log, sizeof(expected_log));
	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_get_log_cmd_effects(TEST_FD, TEST_CSI, &log);
	end_mock_cmds();
	check(err == 0, "get log returned error %d, errno %m", err);
	cmp(&log, &expected_log, sizeof(log), "incorrect log data");
}

static void test_get_log_device_self_test(void)
{
	struct nvme_self_test_log expected_log, log = {};
	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_get_log_page,
		.nsid = NVME_NSID_ALL,
		.data_len = sizeof(expected_log),
		.cdw10 = (NVME_LOG_LID_DEVICE_SELF_TEST << 0) |
			 (((sizeof(expected_log) >> 2) - 1) << 16),
		.out_data = &expected_log,
	};
	int err;

	arbitrary(&expected_log, sizeof(expected_log));
	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_get_log_device_self_test(TEST_FD, &log);
	end_mock_cmds();
	check(err == 0, "get log returned error %d, errno %m", err);
	cmp(&log, &expected_log, sizeof(log), "incorrect log data");
}

static void test_get_log_create_telemetry_host_mcda(void)
{
	struct nvme_telemetry_log expected_log, log = {};
	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_get_log_page,
		.nsid = NVME_NSID_NONE,
		.data_len = sizeof(expected_log),
		.cdw10 = (NVME_LOG_LID_TELEMETRY_HOST << 0) |
			 (((TEST_MCDA << 1) | NVME_LOG_TELEM_HOST_LSP_CREATE)
			  << 8) |
			 (((sizeof(expected_log) >> 2) - 1) << 16),
		.out_data = &expected_log,
	};
	int err;

	arbitrary(&expected_log, sizeof(expected_log));
	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_get_log_create_telemetry_host_mcda(TEST_FD, TEST_MCDA, &log);
	end_mock_cmds();
	check(err == 0, "get log returned error %d, errno %m", err);
	cmp(&log, &expected_log, sizeof(log), "incorrect log data");
}

static void test_get_log_create_telemetry_host(void)
{
	struct nvme_telemetry_log expected_log, log = {};
	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_get_log_page,
		.nsid = NVME_NSID_NONE,
		.data_len = sizeof(expected_log),
		.cdw10 = (NVME_LOG_LID_TELEMETRY_HOST << 0) |
			 (((NVME_TELEMETRY_DA_CTRL_DETERMINE << 1) |
			   NVME_LOG_TELEM_HOST_LSP_CREATE)
			  << 8) |
			 (((sizeof(expected_log) >> 2) - 1) << 16),
		.out_data = &expected_log,
	};
	int err;

	arbitrary(&expected_log, sizeof(expected_log));
	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_get_log_create_telemetry_host(TEST_FD, &log);
	end_mock_cmds();
	check(err == 0, "get log returned error %d, errno %m", err);
	cmp(&log, &expected_log, sizeof(log), "incorrect log data");
}

static void test_get_log_telemetry_host(void)
{
	struct nvme_telemetry_log expected_log, log = {};
	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_get_log_page,
		.nsid = NVME_NSID_NONE,
		.data_len = sizeof(expected_log),
		.cdw10 = (NVME_LOG_LID_TELEMETRY_HOST << 0) |
			 (((NVME_TELEMETRY_DA_CTRL_DETERMINE << 1) |
			   NVME_LOG_TELEM_HOST_LSP_RETAIN)
			  << 8) |
			 (((sizeof(expected_log) >> 2) - 1) << 16),
		.cdw12 = TEST_OFFSET & 0xffffffff,
		.cdw13 = TEST_OFFSET >> 32,
		.out_data = &expected_log,
	};
	int err;

	arbitrary(&expected_log, sizeof(expected_log));
	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_get_log_telemetry_host(TEST_FD, TEST_OFFSET, sizeof(log),
					  &log);
	end_mock_cmds();
	check(err == 0, "get log returned error %d, errno %m", err);
	cmp(&log, &expected_log, sizeof(log), "incorrect log data");
}

static void test_get_log_telemetry_ctrl(void)
{
	struct nvme_telemetry_log expected_log, log = {};
	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_get_log_page,
		.nsid = NVME_NSID_NONE,
		.data_len = sizeof(expected_log),
		.cdw10 = (NVME_LOG_LID_TELEMETRY_CTRL << 0) |
			 (((NVME_TELEMETRY_DA_CTRL_DETERMINE << 1) |
			   NVME_LOG_TELEM_HOST_LSP_RETAIN)
			  << 8) |
			 (!!TEST_RAE << 15) |
			 (((sizeof(expected_log) >> 2) - 1) << 16),
		.cdw12 = TEST_OFFSET & 0xffffffff,
		.cdw13 = TEST_OFFSET >> 32,
		.out_data = &expected_log,
	};
	int err;

	arbitrary(&expected_log, sizeof(expected_log));
	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_get_log_telemetry_ctrl(TEST_FD, TEST_RAE, TEST_OFFSET,
					  sizeof(log), &log);
	end_mock_cmds();
	check(err == 0, "get log returned error %d, errno %m", err);
	cmp(&log, &expected_log, sizeof(log), "incorrect log data");
}

static void test_get_log_endurance_group(void)
{
	struct nvme_endurance_group_log expected_log, log = {};
	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_get_log_page,
		.nsid = NVME_NSID_NONE,
		.data_len = sizeof(expected_log),
		.cdw10 = (NVME_LOG_LID_ENDURANCE_GROUP << 0) |
			 (((sizeof(expected_log) >> 2) - 1) << 16),
		.cdw11 = (TEST_ENDGID << 16),
		.out_data = &expected_log,
	};
	int err;

	arbitrary(&expected_log, sizeof(expected_log));
	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_get_log_endurance_group(TEST_FD, TEST_ENDGID, &log);
	end_mock_cmds();
	check(err == 0, "get log returned error %d, errno %m", err);
	cmp(&log, &expected_log, sizeof(log), "incorrect log data");
}

static void test_get_log_predictable_lat_nvmset(void)
{
	struct nvme_nvmset_predictable_lat_log expected_log, log = {};
	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_get_log_page,
		.nsid = NVME_NSID_NONE,
		.data_len = sizeof(expected_log),
		.cdw10 = (NVME_LOG_LID_PREDICTABLE_LAT_NVMSET << 0) |
			 (((sizeof(expected_log) >> 2) - 1) << 16),
		.cdw11 = (TEST_NVMSETID << 16),
		.out_data = &expected_log,
	};
	int err;

	arbitrary(&expected_log, sizeof(expected_log));
	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_get_log_predictable_lat_nvmset(TEST_FD, TEST_NVMSETID, &log);
	end_mock_cmds();
	check(err == 0, "get log returned error %d, errno %m", err);
	cmp(&log, &expected_log, sizeof(log), "incorrect log data");
}

static void test_get_log_predictable_lat_event(void)
{
	__u8 expected_log[32], log[32] = {};
	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_get_log_page,
		.nsid = NVME_NSID_NONE,
		.data_len = sizeof(expected_log),
		.cdw10 = (NVME_LOG_LID_PREDICTABLE_LAT_AGG << 0) |
			 (!!TEST_RAE << 15) |
			 (((sizeof(expected_log) >> 2) - 1) << 16),
		.cdw12 = TEST_OFFSET_32,
		.out_data = &expected_log,
	};
	int err;

	arbitrary(&expected_log, sizeof(expected_log));
	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_get_log_predictable_lat_event(
		TEST_FD, TEST_RAE, TEST_OFFSET_32, sizeof(log), &log);
	end_mock_cmds();
	check(err == 0, "get log returned error %d, errno %m", err);
	cmp(&log, &expected_log, sizeof(log), "incorrect log data");
}

static void test_get_log_fdp_configurations(void)
{
	__u8 expected_log[32], log[32] = {};
	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_get_log_page,
		.nsid = NVME_NSID_NONE,
		.data_len = sizeof(expected_log),
		.cdw10 = (NVME_LOG_LID_FDP_CONFIGS << 0) |
			 (((sizeof(expected_log) >> 2) - 1) << 16),
		.cdw11 = (TEST_ENDGID << 16),
		.cdw12 = TEST_OFFSET_32,
		.out_data = &expected_log,
	};
	int err;

	arbitrary(&expected_log, sizeof(expected_log));
	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_get_log_fdp_configurations(
		TEST_FD, TEST_ENDGID, TEST_OFFSET_32, sizeof(log), &log);
	end_mock_cmds();
	check(err == 0, "get log returned error %d, errno %m", err);
	cmp(&log, &expected_log, sizeof(log), "incorrect log data");
}

static void test_get_log_reclaim_unit_handle_usage(void)
{
	__u8 expected_log[32], log[32] = {};
	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_get_log_page,
		.nsid = NVME_NSID_NONE,
		.data_len = sizeof(expected_log),
		.cdw10 = (NVME_LOG_LID_FDP_RUH_USAGE << 0) |
			 (((sizeof(expected_log) >> 2) - 1) << 16),
		.cdw11 = (TEST_ENDGID << 16),
		.cdw12 = TEST_OFFSET_32,
		.out_data = &expected_log,
	};
	int err;

	arbitrary(&expected_log, sizeof(expected_log));
	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_get_log_reclaim_unit_handle_usage(
		TEST_FD, TEST_ENDGID, TEST_OFFSET_32, sizeof(log), &log);
	end_mock_cmds();
	check(err == 0, "get log returned error %d, errno %m", err);
	cmp(&log, &expected_log, sizeof(log), "incorrect log data");
}

static void test_get_log_fdp_stats(void)
{
	__u8 expected_log[32], log[32] = {};
	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_get_log_page,
		.nsid = NVME_NSID_NONE,
		.data_len = sizeof(expected_log),
		.cdw10 = (NVME_LOG_LID_FDP_STATS << 0) |
			 (((sizeof(expected_log) >> 2) - 1) << 16),
		.cdw11 = (TEST_ENDGID << 16),
		.cdw12 = TEST_OFFSET_32,
		.out_data = &expected_log,
	};
	int err;

	arbitrary(&expected_log, sizeof(expected_log));
	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_get_log_fdp_stats(TEST_FD, TEST_ENDGID, TEST_OFFSET_32,
				     sizeof(log), &log);
	end_mock_cmds();
	check(err == 0, "get log returned error %d, errno %m", err);
	cmp(&log, &expected_log, sizeof(log), "incorrect log data");
}

static void test_get_log_fdp_events(void)
{
	__u8 expected_log[32], log[32] = {};
	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_get_log_page,
		.nsid = NVME_NSID_NONE,
		.data_len = sizeof(expected_log),
		.cdw10 = (NVME_LOG_LID_FDP_EVENTS << 0) |
			 (TEST_EVENTS ? 0x1 : 0x0) << 8 |
			 (((sizeof(expected_log) >> 2) - 1) << 16),
		.cdw11 = (TEST_ENDGID << 16),
		.cdw12 = TEST_OFFSET_32,
		.out_data = &expected_log,
	};
	int err;

	arbitrary(&expected_log, sizeof(expected_log));
	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_get_log_fdp_events(TEST_FD, TEST_ENDGID, TEST_EVENTS,
				      TEST_OFFSET_32, sizeof(log), &log);
	end_mock_cmds();
	check(err == 0, "get log returned error %d, errno %m", err);
	cmp(&log, &expected_log, sizeof(log), "incorrect log data");
}

static void test_get_log_ana(void)
{
	struct nvme_ana_log expected_log, log = {};
	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_get_log_page,
		.nsid = NVME_NSID_NONE,
		.data_len = sizeof(expected_log),
		.cdw10 = (NVME_LOG_LID_ANA << 0) | (TEST_ANA_LSP << 8) |
			 (!!TEST_RAE << 15) |
			 (((sizeof(expected_log) >> 2) - 1) << 16),
		.cdw12 = TEST_OFFSET & 0xffffffff,
		.cdw13 = TEST_OFFSET >> 32,
		.out_data = &expected_log,
	};
	int err;

	arbitrary(&expected_log, sizeof(expected_log));
	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_get_log_ana(TEST_FD, TEST_ANA_LSP, TEST_RAE, TEST_OFFSET,
			       sizeof(log), &log);
	end_mock_cmds();
	check(err == 0, "get log returned error %d, errno %m", err);
	cmp(&log, &expected_log, sizeof(log), "incorrect log data");
}

static void test_get_log_ana_groups(void)
{
	struct nvme_ana_log expected_log, log = {};
	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_get_log_page,
		.nsid = NVME_NSID_NONE,
		.data_len = sizeof(expected_log),
		.cdw10 = (NVME_LOG_LID_ANA << 0) |
			 (NVME_LOG_ANA_LSP_RGO_GROUPS_ONLY << 8) |
			 (!!TEST_RAE << 15) |
			 (((sizeof(expected_log) >> 2) - 1) << 16),
		.out_data = &expected_log,
	};
	int err;

	arbitrary(&expected_log, sizeof(expected_log));
	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_get_log_ana_groups(TEST_FD, TEST_RAE, sizeof(log), &log);
	end_mock_cmds();
	check(err == 0, "get log returned error %d, errno %m", err);
	cmp(&log, &expected_log, sizeof(log), "incorrect log data");
}

static void test_get_log_lba_status(void)
{
	__u8 expected_log[32], log[32] = {};
	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_get_log_page,
		.nsid = NVME_NSID_NONE,
		.data_len = sizeof(expected_log),
		.cdw10 = (NVME_LOG_LID_LBA_STATUS << 0) | (!!TEST_RAE << 15) |
			 (((sizeof(expected_log) >> 2) - 1) << 16),
		.cdw12 = TEST_OFFSET & 0xffffffff,
		.cdw13 = TEST_OFFSET >> 32,
		.out_data = &expected_log,
	};
	int err;

	arbitrary(&expected_log, sizeof(expected_log));
	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_get_log_lba_status(TEST_FD, TEST_RAE, TEST_OFFSET,
				      sizeof(log), &log);
	end_mock_cmds();
	check(err == 0, "get log returned error %d, errno %m", err);
	cmp(&log, &expected_log, sizeof(log), "incorrect log data");
}

static void test_get_log_endurance_grp_evt(void)
{
	__u8 expected_log[32], log[32] = {};
	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_get_log_page,
		.nsid = NVME_NSID_NONE,
		.data_len = sizeof(expected_log),
		.cdw10 = (NVME_LOG_LID_ENDURANCE_GRP_EVT << 0) |
			 (!!TEST_RAE << 15) |
			 (((sizeof(expected_log) >> 2) - 1) << 16),
		.cdw12 = TEST_OFFSET_32,
		.out_data = &expected_log,
	};
	int err;

	arbitrary(&expected_log, sizeof(expected_log));
	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_get_log_endurance_grp_evt(TEST_FD, TEST_RAE, TEST_OFFSET_32,
					     sizeof(log), &log);
	end_mock_cmds();
	check(err == 0, "get log returned error %d, errno %m", err);
	cmp(&log, &expected_log, sizeof(log), "incorrect log data");
}

static void test_get_log_fid_supported_effects(void)
{
	struct nvme_fid_supported_effects_log expected_log, log = {};
	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_get_log_page,
		.nsid = NVME_NSID_NONE,
		.data_len = sizeof(expected_log),
		.cdw10 = (NVME_LOG_LID_FID_SUPPORTED_EFFECTS << 0) |
			 (!!TEST_RAE << 15) |
			 (((sizeof(expected_log) >> 2) - 1) << 16),
		.out_data = &expected_log,
	};
	int err;

	arbitrary(&expected_log, sizeof(expected_log));
	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_get_log_fid_supported_effects(TEST_FD, TEST_RAE, &log);
	end_mock_cmds();
	check(err == 0, "get log returned error %d, errno %m", err);
	cmp(&log, &expected_log, sizeof(log), "incorrect log data");
}

static void test_get_log_mi_cmd_supported_effects(void)
{
	struct nvme_mi_cmd_supported_effects_log expected_log, log = {};
	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_get_log_page,
		.nsid = NVME_NSID_NONE,
		.data_len = sizeof(expected_log),
		.cdw10 = (NVME_LOG_LID_MI_CMD_SUPPORTED_EFFECTS << 0) |
			 (!!TEST_RAE << 15) |
			 (((sizeof(expected_log) >> 2) - 1) << 16),
		.out_data = &expected_log,
	};
	int err;

	arbitrary(&expected_log, sizeof(expected_log));
	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_get_log_mi_cmd_supported_effects(TEST_FD, TEST_RAE, &log);
	end_mock_cmds();
	check(err == 0, "get log returned error %d, errno %m", err);
	cmp(&log, &expected_log, sizeof(log), "incorrect log data");
}

static void test_get_log_boot_partition(void)
{
	struct nvme_boot_partition expected_log, log = {};
	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_get_log_page,
		.nsid = NVME_NSID_NONE,
		.data_len = sizeof(expected_log),
		.cdw10 = (NVME_LOG_LID_BOOT_PARTITION << 0) | (TEST_LSP << 8) |
			 (!!TEST_RAE << 15) |
			 (((sizeof(expected_log) >> 2) - 1) << 16),
		.out_data = &expected_log,
	};
	int err;

	arbitrary(&expected_log, sizeof(expected_log));
	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_get_log_boot_partition(TEST_FD, TEST_RAE, TEST_LSP,
					  sizeof(log), &log);
	end_mock_cmds();
	check(err == 0, "get log returned error %d, errno %m", err);
	cmp(&log, &expected_log, sizeof(log), "incorrect log data");
}

static void test_get_log_rotational_media_info(void)
{
	struct nvme_rotational_media_info_log expected_log, log = {};
	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_get_log_page,
		.nsid = NVME_NSID_NONE,
		.data_len = sizeof(expected_log),
		.cdw10 = (NVME_LOG_LID_ROTATIONAL_MEDIA_INFO << 0) |
			 (((sizeof(expected_log) >> 2) - 1) << 16),
		.cdw11 = (TEST_ENDGID << 16),
		.out_data = &expected_log,
	};
	int err;

	arbitrary(&expected_log, sizeof(expected_log));
	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_get_log_rotational_media_info(TEST_FD, TEST_ENDGID,
						 sizeof(log), &log);
	end_mock_cmds();
	check(err == 0, "get log returned error %d, errno %m", err);
	cmp(&log, &expected_log, sizeof(log), "incorrect log data");
}

static void test_get_log_dispersed_ns_participating_nss(void)
{
	struct nvme_dispersed_ns_participating_nss_log expected_log, log = {};
	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_get_log_page,
		.nsid = TEST_NSID,
		.data_len = sizeof(expected_log),
		.cdw10 = (NVME_LOG_LID_DISPERSED_NS_PARTICIPATING_NSS << 0) |
			 (((sizeof(expected_log) >> 2) - 1) << 16),
		.out_data = &expected_log,
	};
	int err;

	arbitrary(&expected_log, sizeof(expected_log));
	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_get_log_dispersed_ns_participating_nss(TEST_FD, TEST_NSID,
							  sizeof(log), &log);
	end_mock_cmds();
	check(err == 0, "get log returned error %d, errno %m", err);
	cmp(&log, &expected_log, sizeof(log), "incorrect log data");
}

static void test_get_log_phy_rx_eom(void)
{
	struct nvme_phy_rx_eom_log expected_log, log = {};
	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_get_log_page,
		.nsid = NVME_NSID_NONE,
		.data_len = sizeof(expected_log),
		.cdw10 = (NVME_LOG_LID_PHY_RX_EOM << 0) | (TEST_LSP << 8) |
			 (((sizeof(expected_log) >> 2) - 1) << 16),
		.cdw11 = (TEST_CNTID << 16),
		.out_data = &expected_log,
	};
	int err;

	arbitrary(&expected_log, sizeof(expected_log));
	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_get_log_phy_rx_eom(TEST_FD, TEST_LSP, TEST_CNTID,
				      sizeof(log), &log);
	end_mock_cmds();
	check(err == 0, "get log returned error %d, errno %m", err);
	cmp(&log, &expected_log, sizeof(log), "incorrect log data");
}

static void test_get_log_reachability_groups(void)
{
	struct nvme_reachability_groups_log expected_log, log = {};
	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_get_log_page,
		.nsid = NVME_NSID_ALL,
		.data_len = sizeof(expected_log),
		.cdw10 = (NVME_LOG_LID_REACHABILITY_GROUPS << 0) |
			 (!!TEST_LSP << 8) | (!!TEST_RAE << 15) |
			 (((sizeof(expected_log) >> 2) - 1) << 16),
		.out_data = &expected_log,
	};
	int err;

	arbitrary(&expected_log, sizeof(expected_log));
	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_get_log_reachability_groups(TEST_FD, !!TEST_LSP, TEST_RAE,
					       sizeof(log), &log);
	end_mock_cmds();
	check(err == 0, "get log returned error %d, errno %m", err);
	cmp(&log, &expected_log, sizeof(log), "incorrect log data");
}

static void test_get_log_reachability_associations(void)
{
	struct nvme_reachability_associations_log expected_log, log = {};
	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_get_log_page,
		.nsid = NVME_NSID_ALL,
		.data_len = sizeof(expected_log),
		.cdw10 = (NVME_LOG_LID_REACHABILITY_ASSOCIATIONS << 0) |
			 (!!TEST_LSP << 8) | (!!TEST_RAE << 15) |
			 (((sizeof(expected_log) >> 2) - 1) << 16),
		.out_data = &expected_log,
	};
	int err;

	arbitrary(&expected_log, sizeof(expected_log));
	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_get_log_reachability_associations(
		TEST_FD, !!TEST_LSP, TEST_RAE, sizeof(log), &log);
	end_mock_cmds();
	check(err == 0, "get log returned error %d, errno %m", err);
	cmp(&log, &expected_log, sizeof(log), "incorrect log data");
}

static void test_get_log_changed_alloc_ns_list(void)
{
	struct nvme_ns_list expected_log, log = {};
	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_get_log_page,
		.nsid = NVME_NSID_ALL,
		.data_len = sizeof(expected_log),
		.cdw10 = (NVME_LOG_LID_CHANGED_ALLOC_NS_LIST << 0) |
			 (!!TEST_RAE << 15) |
			 (((sizeof(expected_log) >> 2) - 1) << 16),
		.out_data = &expected_log,
	};
	int err;

	arbitrary(&expected_log, sizeof(expected_log));
	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_get_log_changed_alloc_ns_list(TEST_FD, TEST_RAE, sizeof(log),
						 &log);
	end_mock_cmds();
	check(err == 0, "get log returned error %d, errno %m", err);
	cmp(&log, &expected_log, sizeof(log), "incorrect log data");
}

static void test_get_log_discovery(void)
{
	__u8 expected_log[32], log[32] = {};
	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_get_log_page,
		.nsid = NVME_NSID_NONE,
		.data_len = sizeof(expected_log),
		.cdw10 = (NVME_LOG_LID_DISCOVER << 0) | (!!TEST_RAE << 15) |
			 (((sizeof(expected_log) >> 2) - 1) << 16),
		.cdw12 = TEST_OFFSET_32,
		.out_data = &expected_log,
	};
	int err;

	arbitrary(&expected_log, sizeof(expected_log));
	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_get_log_discovery(TEST_FD, TEST_RAE, TEST_OFFSET_32,
				     sizeof(log), &log);
	end_mock_cmds();
	check(err == 0, "get log returned error %d, errno %m", err);
	cmp(&log, &expected_log, sizeof(log), "incorrect log data");
}

static void test_get_log_host_discover(void)
{
	struct nvme_host_discover_log expected_log, log = {};
	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_get_log_page,
		.nsid = NVME_NSID_ALL,
		.data_len = sizeof(expected_log),
		.cdw10 = (NVME_LOG_LID_HOST_DISCOVER << 0) | (!!TEST_LSP << 8) |
			 (!!TEST_RAE << 15) |
			 (((sizeof(expected_log) >> 2) - 1) << 16),
		.out_data = &expected_log,
	};
	int err;

	arbitrary(&expected_log, sizeof(expected_log));
	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_get_log_host_discover(TEST_FD, !!TEST_LSP, TEST_RAE,
					 sizeof(log), &log);
	end_mock_cmds();
	check(err == 0, "get log returned error %d, errno %m", err);
	cmp(&log, &expected_log, sizeof(log), "incorrect log data");
}

static void test_get_log_ave_discover(void)
{
	struct nvme_ave_discover_log expected_log, log = {};
	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_get_log_page,
		.nsid = NVME_NSID_ALL,
		.data_len = sizeof(expected_log),
		.cdw10 = (NVME_LOG_LID_AVE_DISCOVER << 0) | (!!TEST_RAE << 15) |
			 (((sizeof(expected_log) >> 2) - 1) << 16),
		.out_data = &expected_log,
	};
	int err;

	arbitrary(&expected_log, sizeof(expected_log));
	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_get_log_ave_discover(TEST_FD, TEST_RAE, sizeof(log), &log);
	end_mock_cmds();
	check(err == 0, "get log returned error %d, errno %m", err);
	cmp(&log, &expected_log, sizeof(log), "incorrect log data");
}

static void test_get_log_pull_model_ddc_req(void)
{
	struct nvme_pull_model_ddc_req_log expected_log, log = {};
	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_get_log_page,
		.nsid = NVME_NSID_ALL,
		.data_len = sizeof(expected_log),
		.cdw10 = (NVME_LOG_LID_PULL_MODEL_DDC_REQ << 0) |
			 (!!TEST_RAE << 15) |
			 (((sizeof(expected_log) >> 2) - 1) << 16),
		.out_data = &expected_log,
	};
	int err;

	arbitrary(&expected_log, sizeof(expected_log));
	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_get_log_pull_model_ddc_req(TEST_FD, TEST_RAE, sizeof(log),
					      &log);
	end_mock_cmds();
	check(err == 0, "get log returned error %d, errno %m", err);
	cmp(&log, &expected_log, sizeof(log), "incorrect log data");
}

static void test_get_log_media_unit_stat(void)
{
	struct nvme_media_unit_stat_log expected_log, log = {};
	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_get_log_page,
		.nsid = NVME_NSID_NONE,
		.data_len = sizeof(expected_log),
		.cdw10 = (NVME_LOG_LID_MEDIA_UNIT_STATUS << 0) |
			 (((sizeof(expected_log) >> 2) - 1) << 16),
		.cdw11 = (TEST_DOMID << 16),
		.out_data = &expected_log,
	};
	int err;

	arbitrary(&expected_log, sizeof(expected_log));
	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_get_log_media_unit_stat(TEST_FD, TEST_DOMID, &log);
	end_mock_cmds();
	check(err == 0, "get log returned error %d, errno %m", err);
	cmp(&log, &expected_log, sizeof(log), "incorrect log data");
}

static void test_get_log_support_cap_config_list(void)
{
	struct nvme_supported_cap_config_list_log expected_log, log = {};
	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_get_log_page,
		.nsid = NVME_NSID_NONE,
		.data_len = sizeof(expected_log),
		.cdw10 = (NVME_LOG_LID_SUPPORTED_CAP_CONFIG_LIST << 0) |
			 (((sizeof(expected_log) >> 2) - 1) << 16),
		.cdw11 = (TEST_DOMID << 16),
		.out_data = &expected_log,
	};
	int err;

	arbitrary(&expected_log, sizeof(expected_log));
	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_get_log_support_cap_config_list(TEST_FD, TEST_DOMID, &log);
	end_mock_cmds();
	check(err == 0, "get log returned error %d, errno %m", err);
	cmp(&log, &expected_log, sizeof(log), "incorrect log data");
}

static void test_get_log_reservation(void)
{
	struct nvme_resv_notification_log expected_log, log = {};
	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_get_log_page,
		.nsid = NVME_NSID_ALL,
		.data_len = sizeof(expected_log),
		.cdw10 = (NVME_LOG_LID_RESERVATION << 0) | (!!TEST_RAE << 15) |
			 (((sizeof(expected_log) >> 2) - 1) << 16),
		.out_data = &expected_log,
	};
	int err;

	arbitrary(&expected_log, sizeof(expected_log));
	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_get_log_reservation(TEST_FD, TEST_RAE, &log);
	end_mock_cmds();
	check(err == 0, "get log returned error %d, errno %m", err);
	cmp(&log, &expected_log, sizeof(log), "incorrect log data");
}

static void test_get_log_zns_changed_zones(void)
{
	struct nvme_zns_changed_zone_log expected_log, log = {};
	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_get_log_page,
		.nsid = TEST_NSID,
		.data_len = sizeof(expected_log),
		.cdw10 = (NVME_LOG_LID_ZNS_CHANGED_ZONES << 0) |
			 (!!TEST_RAE << 15) |
			 (((sizeof(expected_log) >> 2) - 1) << 16),
		.cdw14 = NVME_CSI_ZNS << 24,
		.out_data = &expected_log,
	};
	int err;

	arbitrary(&expected_log, sizeof(expected_log));
	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_get_log_zns_changed_zones(TEST_FD, TEST_NSID, TEST_RAE,
					     &log);
	end_mock_cmds();
	check(err == 0, "get log returned error %d, errno %m", err);
	cmp(&log, &expected_log, sizeof(log), "incorrect log data");
}

static void test_get_log_persistent_event(void)
{
	__u8 expected_log[32], log[32] = {};
	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_get_log_page,
		.nsid = NVME_NSID_ALL,
		.data_len = sizeof(expected_log),
		.cdw10 = (NVME_LOG_LID_PERSISTENT_EVENT << 0) |
			 (TEST_PEVENT << 8) |
			 (((sizeof(expected_log) >> 2) - 1) << 16),
		.out_data = &expected_log,
	};
	int err;

	arbitrary(&expected_log, sizeof(expected_log));
	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_get_log_persistent_event(TEST_FD, TEST_PEVENT, sizeof(log),
					    &log);
	end_mock_cmds();
	check(err == 0, "get log returned error %d, errno %m", err);
	cmp(&log, &expected_log, sizeof(log), "incorrect log data");
}

static void test_get_log_lockdown(void)
{
	struct nvme_lockdown_log expected_log, log = {};
	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_get_log_page,
		.nsid = NVME_NSID_ALL,
		.data_len = sizeof(expected_log),
		.cdw10 = (NVME_LOG_LID_CMD_AND_FEAT_LOCKDOWN << 0) |
			 (TEST_LSP << 8) |
			 (((sizeof(expected_log) >> 2) - 1) << 16),
		.out_data = &expected_log,
	};
	int err;

	arbitrary(&expected_log, sizeof(expected_log));
	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_get_log_lockdown(TEST_FD, TEST_LSP, &log);
	end_mock_cmds();
	check(err == 0, "get log returned error %d, errno %m", err);
	cmp(&log, &expected_log, sizeof(log), "incorrect log data");
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
	set_mock_fd(TEST_FD);
	RUN_TEST(get_log_sanitize);
	RUN_TEST(get_log_mgmt_addr_list);
	RUN_TEST(get_log_supported_log_pages);
	RUN_TEST(get_log_error);
	RUN_TEST(get_log_smart);
	RUN_TEST(get_log_fw_slot);
	RUN_TEST(get_log_changed_ns_list);
	RUN_TEST(get_log_cmd_effects);
	RUN_TEST(get_log_device_self_test);
	RUN_TEST(get_log_create_telemetry_host_mcda);
	RUN_TEST(get_log_create_telemetry_host);
	RUN_TEST(get_log_telemetry_host);
	RUN_TEST(get_log_telemetry_ctrl);
	RUN_TEST(get_log_endurance_group);
	RUN_TEST(get_log_predictable_lat_nvmset);
	RUN_TEST(get_log_predictable_lat_event);
	RUN_TEST(get_log_fdp_configurations);
	RUN_TEST(get_log_reclaim_unit_handle_usage);
	RUN_TEST(get_log_fdp_stats);
	RUN_TEST(get_log_fdp_events);
	RUN_TEST(get_log_ana);
	RUN_TEST(get_log_ana_groups);
	RUN_TEST(get_log_lba_status);
	RUN_TEST(get_log_endurance_grp_evt);
	RUN_TEST(get_log_fid_supported_effects);
	RUN_TEST(get_log_mi_cmd_supported_effects);
	RUN_TEST(get_log_boot_partition);
	RUN_TEST(get_log_rotational_media_info);
	RUN_TEST(get_log_dispersed_ns_participating_nss);
	RUN_TEST(get_log_phy_rx_eom);
	RUN_TEST(get_log_reachability_groups);
	RUN_TEST(get_log_reachability_associations);
	RUN_TEST(get_log_changed_alloc_ns_list);
	RUN_TEST(get_log_discovery);
	RUN_TEST(get_log_host_discover);
	RUN_TEST(get_log_ave_discover);
	RUN_TEST(get_log_pull_model_ddc_req);
	RUN_TEST(get_log_media_unit_stat);
	RUN_TEST(get_log_support_cap_config_list);
	RUN_TEST(get_log_reservation);
	RUN_TEST(get_log_zns_changed_zones);
	RUN_TEST(get_log_persistent_event);
	RUN_TEST(get_log_lockdown);
}
