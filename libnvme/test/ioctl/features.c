// SPDX-License-Identifier: LGPL-2.1-or-later

#include <errno.h>
#include <inttypes.h>

#include <libnvme.h>

#include "mock.h"
#include "util.h"

#define TEST_FD 0xFD
#define TEST_TIMEOUT 1234
#define TEST_NSID 0x89ABCDEF
#define TEST_CDW11 0x11111111
#define TEST_CDW12 0x12121212
#define TEST_CDW13 0x13131313
#define TEST_CDW15 0x15151515
#define TEST_CDQID 0x8765
#define TEST_UUIDX 0b1001110
#define TEST_FID 0xFE
#define TEST_RESULT 0x12345678
#define TEST_SEL NVME_GET_FEATURES_SEL_SAVED
#define TEST_SC NVME_SC_INVALID_FIELD

static void test_set_features(void)
{
	uint32_t result = 0;
	uint8_t data[256];
	struct nvme_set_features_args args = {
		.result = &result,
		.data = data,
		.args_size = sizeof(args),
		.fd = TEST_FD,
		.timeout = TEST_TIMEOUT,
		.nsid = TEST_NSID,
		.cdw11 = TEST_CDW11,
		.cdw12 = TEST_CDW12,
		.cdw13 = TEST_CDW13,
		.cdw15 = TEST_CDW15,
		.data_len = sizeof(data),
		.save = true,
		.uuidx = TEST_UUIDX,
		.fid = TEST_FID,
	};
	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_set_features,
		.nsid = TEST_NSID,
		.in_data = data,
		.data_len = sizeof(data),
		.cdw10 = (uint32_t)1 << 31 /* SAVE */
		       | TEST_FID,
		.cdw11 = TEST_CDW11,
		.cdw12 = TEST_CDW12,
		.cdw13 = TEST_CDW13,
		.cdw14 = TEST_UUIDX,
		.cdw15 = TEST_CDW15,
		.timeout_ms = TEST_TIMEOUT,
		.result = TEST_RESULT,
	};
	int err;

	arbitrary(data, sizeof(data));
	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_set_features(&args);
	end_mock_cmds();
	check(err == 0, "set features returned error %d, errno %m", err);
	check(result == TEST_RESULT,
	      "got result %" PRIu32 ", expected %" PRIu32, result, TEST_RESULT);
}

static void test_get_features(void)
{
	uint32_t result = 0;
	uint8_t data[256], get_data[sizeof(data)] = {};
	struct nvme_get_features_args args = {
		.result = &result,
		.data = get_data,
		.args_size = sizeof(args),
		.fd = TEST_FD,
		.timeout = TEST_TIMEOUT,
		.nsid = TEST_NSID,
		.sel = TEST_SEL,
		.cdw11 = TEST_CDW11,
		.data_len = sizeof(data),
		.fid = TEST_FID,
		.uuidx = TEST_UUIDX,
	};
	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_get_features,
		.nsid = TEST_NSID,
		.data_len = sizeof(data),
		.cdw10 = TEST_SEL << 8 | TEST_FID,
		.cdw11 = TEST_CDW11,
		.cdw14 = TEST_UUIDX,
		.timeout_ms = TEST_TIMEOUT,
		.out_data = data,
		.result = TEST_RESULT,
	};
	int err;

	arbitrary(data, sizeof(data));
	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_get_features(&args);
	end_mock_cmds();
	check(err == 0, "get features returned error %d, errno %m", err);
	check(result == TEST_RESULT,
	      "got result %" PRIu32 ", expected %" PRIu32, result, TEST_RESULT);
	cmp(get_data, data, sizeof(data), "incorrect data");
}

static void test_set_features_data(void)
{
	uint8_t data[128];
	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_set_features,
		.nsid = TEST_NSID,
		.in_data = data,
		.data_len = sizeof(data),
		.cdw10 = TEST_FID,
		.cdw11 = TEST_CDW11,
		.result = TEST_RESULT,
	};
	uint32_t result = 0;
	int err;

	arbitrary(data, sizeof(data));
	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_set_features_data(
		TEST_FD, TEST_FID, TEST_NSID, TEST_CDW11, false,
		sizeof(data), data, &result);
	end_mock_cmds();
	check(err == 0, "set features returned error %d, errno %m", err);
	check(result == TEST_RESULT,
	      "got result %" PRIu32 ", expected %" PRIu32, result, TEST_RESULT);
}

static void test_get_features_data(void)
{
	uint8_t data[128], get_data[sizeof(data)] = {};
	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_get_features,
		.nsid = TEST_NSID,
		.data_len = sizeof(data),
		.cdw10 = NVME_GET_FEATURES_SEL_CURRENT << 8 | TEST_FID,
		.out_data = data,
		.result = TEST_RESULT,
	};
	uint32_t result = 0;
	int err;

	arbitrary(data, sizeof(data));
	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_get_features_data(
		TEST_FD, TEST_FID, TEST_NSID, sizeof(data), get_data, &result);
	end_mock_cmds();
	check(err == 0, "set features returned error %d, errno %m", err);
	check(result == TEST_RESULT,
	      "got result %" PRIu32 ", expected %" PRIu32, result, TEST_RESULT);
	cmp(get_data, data, sizeof(data), "incorrect data");
}

static void test_set_features_simple(void)
{
	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_set_features,
		.nsid = TEST_NSID,
		.cdw10 = (uint32_t)1 << 31 /* SAVE */
		       | TEST_FID,
		.cdw11 = TEST_CDW11,
		.result = TEST_RESULT,
	};
	uint32_t result = 0;
	int err;

	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_set_features_simple(
		TEST_FD, TEST_FID, TEST_NSID, TEST_CDW11, true, &result);
	end_mock_cmds();
	check(err == 0, "set features returned error %d, errno %m", err);
	check(result == TEST_RESULT,
	      "got result %" PRIu32 ", expected %" PRIu32, result, TEST_RESULT);
}

static void test_get_features_simple(void)
{
	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_get_features,
		.nsid = TEST_NSID,
		.cdw10 = NVME_GET_FEATURES_SEL_CURRENT << 8 | TEST_FID,
		.result = TEST_RESULT,
	};
	uint32_t result = 0;
	int err;

	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_get_features_simple(TEST_FD, TEST_FID, TEST_NSID, &result);
	end_mock_cmds();
	check(err == 0, "set features returned error %d, errno %m", err);
	check(result == TEST_RESULT,
	      "got result %" PRIu32 ", expected %" PRIu32, result, TEST_RESULT);
}

static void test_set_arbitration(void)
{
	uint8_t HPW = 0xAA, MPW = 0xBB, LPW = 0xCC, AB = 0b111;
	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_set_features,
		.cdw10 = NVME_FEAT_FID_ARBITRATION,
		.cdw11 = (uint32_t)HPW << 24 | MPW << 16 | LPW << 8 | AB,
		.result = TEST_RESULT,
	};
	uint32_t result = 0;
	int err;

	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_set_features_arbitration(
		TEST_FD, AB, LPW, MPW, HPW, false, &result);
	end_mock_cmds();
	check(err == 0, "set features returned error %d, errno %m", err);
	check(result == TEST_RESULT,
	      "got result %" PRIu32 ", expected %" PRIu32, result, TEST_RESULT);
}

static void test_get_arbitration(void)
{
	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_get_features,
		.cdw10 = TEST_SEL << 8 | NVME_FEAT_FID_ARBITRATION,
		.result = TEST_RESULT,
	};
	uint32_t result = 0;
	int err;

	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_get_features_arbitration(TEST_FD, TEST_SEL, &result);
	end_mock_cmds();
	check(err == 0, "get features returned error %d, errno %m", err);
	check(result == TEST_RESULT,
	      "got result %" PRIu32 ", expected %" PRIu32, result, TEST_RESULT);
}

static void test_set_power_mgmt(void)
{
	uint8_t PS = 0b10101, WH = 0b101;
	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_set_features,
		.cdw10 = (uint32_t)1 << 31 /* SAVE */
		       | NVME_FEAT_FID_POWER_MGMT,
		.cdw11 = WH << 5 | PS,
		.result = TEST_RESULT,
	};
	uint32_t result = 0;
	int err;

	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_set_features_power_mgmt(TEST_FD, PS, WH, true, &result);
	end_mock_cmds();
	check(err == 0, "set features returned error %d, errno %m", err);
	check(result == TEST_RESULT,
	      "got result %" PRIu32 ", expected %" PRIu32, result, TEST_RESULT);
}

static void test_get_power_mgmt(void)
{
	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_get_features,
		.cdw10 = TEST_SEL << 8 | NVME_FEAT_FID_POWER_MGMT,
		.result = TEST_RESULT,
	};
	uint32_t result = 0;
	int err;

	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_get_features_power_mgmt(TEST_FD, TEST_SEL, &result);
	end_mock_cmds();
	check(err == 0, "get features returned error %d, errno %m", err);
	check(result == TEST_RESULT,
	      "got result %" PRIu32 ", expected %" PRIu32, result, TEST_RESULT);
}

static void test_set_lba_range(void)
{
	uint8_t NUM = 64;
	struct nvme_lba_range_type range_types;
	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_set_features,
		.nsid = TEST_NSID,
		.in_data = &range_types,
		.data_len = sizeof(range_types),
		.cdw10 = NVME_FEAT_FID_LBA_RANGE,
		.cdw11 = NUM - 1,
		.result = TEST_RESULT,
	};
	uint32_t result = 0;
	int err;

	arbitrary(&range_types, sizeof(range_types));
	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_set_features_lba_range(
		TEST_FD, TEST_NSID, NUM, false, &range_types, &result);
	end_mock_cmds();
	check(err == 0, "set features returned error %d, errno %m", err);
	check(result == TEST_RESULT,
	      "got result %" PRIu32 ", expected %" PRIu32, result, TEST_RESULT);
}

static void test_get_lba_range(void)
{
	struct nvme_lba_range_type range_types, get_range_types = {};
	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_get_features,
		.nsid = TEST_NSID,
		.data_len = sizeof(range_types),
		.cdw10 = TEST_SEL << 8 | NVME_FEAT_FID_LBA_RANGE,
		.out_data = &range_types,
		.result = TEST_RESULT,
	};
	uint32_t result = 0;
	int err;

	arbitrary(&range_types, sizeof(range_types));
	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_get_features_lba_range(
		TEST_FD, TEST_SEL, TEST_NSID, &get_range_types, &result);
	end_mock_cmds();
	check(err == 0, "get features returned error %d, errno %m", err);
	check(result == TEST_RESULT,
	      "got result %" PRIu32 ", expected %" PRIu32, result, TEST_RESULT);
	cmp(&get_range_types, &range_types, sizeof(range_types),
	    "incorrect LBA range types");
}

static void test_set_temp_thresh(void)
{
	uint16_t TMPTH = 0xFEDC;
	uint8_t TMPSEL = 0x8;
	enum nvme_feat_tmpthresh_thsel THSEL =
		NVME_FEATURE_TEMPTHRESH_THSEL_UNDER;
	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_set_features,
		.cdw10 = (uint32_t)1 << 31 /* SAVE */
		       | NVME_FEAT_FID_TEMP_THRESH,
		.cdw11 = THSEL << 20 | TMPSEL << 16 | TMPTH,
		.result = TEST_RESULT,
	};
	uint32_t result = 0;
	int err;

	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_set_features_temp_thresh(
		TEST_FD, TMPTH, TMPSEL, THSEL, 0, true, &result);
	end_mock_cmds();
	check(err == 0, "set features returned error %d, errno %m", err);
	check(result == TEST_RESULT,
	      "got result %" PRIu32 ", expected %" PRIu32, result, TEST_RESULT);
}

static void test_get_temp_thresh(void)
{
	/*
	 * nvme_get_features_temp_thresh() doesn't support
	 * specifying TMPSEL and THSEL
	 */
	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_get_features,
		.cdw10 = TEST_SEL << 8 | NVME_FEAT_FID_TEMP_THRESH,
		.cdw11 = NVME_FEATURE_TEMPTHRESH_THSEL_OVER << 20,
		.result = TEST_RESULT,
	};
	uint32_t result = 0;
	int err;

	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_get_features_temp_thresh(TEST_FD, TEST_SEL, 0, 0, &result);
	end_mock_cmds();
	check(err == 0, "get features returned error %d, errno %m", err);
	check(result == TEST_RESULT,
	      "got result %" PRIu32 ", expected %" PRIu32, result, TEST_RESULT);
}

static void test_set_err_recovery(void)
{
	uint16_t TLER = 0xCDEF;
	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_set_features,
		.nsid = TEST_NSID,
		.cdw10 = NVME_FEAT_FID_ERR_RECOVERY,
		.cdw11 = 1 << 16 /* DULBE */
		       | TLER,
		.result = TEST_RESULT,
	};
	uint32_t result = 0;
	int err;

	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_set_features_err_recovery(
		TEST_FD, TEST_NSID, TLER, true, false, &result);
	end_mock_cmds();
	check(err == 0, "set features returned error %d, errno %m", err);
	check(result == TEST_RESULT,
	      "got result %" PRIu32 ", expected %" PRIu32, result, TEST_RESULT);
}

static void test_get_err_recovery(void)
{
	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_get_features,
		.nsid = TEST_NSID,
		.cdw10 = TEST_SEL << 8 | NVME_FEAT_FID_ERR_RECOVERY,
		.result = TEST_RESULT,
	};
	uint32_t result = 0;
	int err;

	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_get_features_err_recovery(
		TEST_FD, TEST_SEL, TEST_NSID, &result);
	end_mock_cmds();
	check(err == 0, "get features returned error %d, errno %m", err);
	check(result == TEST_RESULT,
	      "got result %" PRIu32 ", expected %" PRIu32, result, TEST_RESULT);
}

static void test_set_volatile_wc(void)
{
	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_set_features,
		.cdw10 = (uint32_t)1 << 31 /* SAVE */
		       | NVME_FEAT_FID_VOLATILE_WC,
		.cdw11 = 1 << 0, /* WCE */
		.result = TEST_RESULT,
	};
	uint32_t result = 0;
	int err;

	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_set_features_volatile_wc(TEST_FD, true, true, &result);
	end_mock_cmds();
	check(err == 0, "set features returned error %d, errno %m", err);
	check(result == TEST_RESULT,
	      "got result %" PRIu32 ", expected %" PRIu32, result, TEST_RESULT);
}

static void test_get_volatile_wc(void)
{
	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_get_features,
		.cdw10 = TEST_SEL << 8
		       | NVME_FEAT_FID_VOLATILE_WC,
		.result = TEST_RESULT,
	};
	uint32_t result = 0;
	int err;

	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_get_features_volatile_wc(TEST_FD, TEST_SEL, &result);
	end_mock_cmds();
	check(err == 0, "get features returned error %d, errno %m", err);
	check(result == TEST_RESULT,
	      "got result %" PRIu32 ", expected %" PRIu32, result, TEST_RESULT);
}

static void test_get_num_queues(void)
{
	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_get_features,
		.cdw10 = TEST_SEL << 8 | NVME_FEAT_FID_NUM_QUEUES,
		.result = TEST_RESULT,
	};
	uint32_t result = 0;
	int err;

	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_get_features_num_queues(TEST_FD, TEST_SEL, &result);
	end_mock_cmds();
	check(err == 0, "get features returned error %d, errno %m", err);
	check(result == TEST_RESULT,
	      "got result %" PRIu32 ", expected %" PRIu32, result, TEST_RESULT);
}

static void test_set_irq_coalesce(void)
{
	uint8_t THR = 0xAB, TIME = 0xCD;
	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_set_features,
		.cdw10 = NVME_FEAT_FID_IRQ_COALESCE,
		.cdw11 = TIME << 8 | THR,
		.result = TEST_RESULT,
	};
	uint32_t result = 0;
	int err;

	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_set_features_irq_coalesce(
		TEST_FD, THR, TIME, false, &result);
	end_mock_cmds();
	check(err == 0, "set features returned error %d, errno %m", err);
	check(result == TEST_RESULT,
	      "got result %" PRIu32 ", expected %" PRIu32, result, TEST_RESULT);
}

static void test_get_irq_coalesce(void)
{
	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_get_features,
		.cdw10 = TEST_SEL << 8 | NVME_FEAT_FID_IRQ_COALESCE,
		.result = TEST_RESULT,
	};
	uint32_t result = 0;
	int err;

	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_get_features_irq_coalesce(TEST_FD, TEST_SEL, &result);
	end_mock_cmds();
	check(err == 0, "get features returned error %d, errno %m", err);
	check(result == TEST_RESULT,
	      "got result %" PRIu32 ", expected %" PRIu32, result, TEST_RESULT);
}

static void test_set_irq_config(void)
{
	uint16_t IV = 0x1234;
	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_set_features,
		.cdw10 = (uint32_t)1 << 31 /* SAVE */
		       | NVME_FEAT_FID_IRQ_CONFIG,
		.cdw11 = 1 << 16 /* CD */
		       | IV,
		.result = TEST_RESULT,
	};
	uint32_t result = 0;
	int err;

	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_set_features_irq_config(TEST_FD, IV, true, true, &result);
	end_mock_cmds();
	check(err == 0, "set features returned error %d, errno %m", err);
	check(result == TEST_RESULT,
	      "got result %" PRIu32 ", expected %" PRIu32, result, TEST_RESULT);
}

static void test_get_irq_config(void)
{
	uint16_t IV = 0x5678;
	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_get_features,
		.cdw10 = TEST_SEL << 8 | NVME_FEAT_FID_IRQ_CONFIG,
		.cdw11 = IV,
		.result = TEST_RESULT,
	};
	uint32_t result = 0;
	int err;

	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_get_features_irq_config(TEST_FD, TEST_SEL, IV, &result);
	end_mock_cmds();
	check(err == 0, "get features returned error %d, errno %m", err);
	check(result == TEST_RESULT,
	      "got result %" PRIu32 ", expected %" PRIu32, result, TEST_RESULT);
}

static void test_set_write_atomic(void)
{
	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_set_features,
		.cdw10 = NVME_FEAT_FID_WRITE_ATOMIC,
		.cdw11 = 1 << 0, /* DN */
		.result = TEST_RESULT,
	};
	uint32_t result = 0;
	int err;

	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_set_features_write_atomic(TEST_FD, true, false, &result);
	end_mock_cmds();
	check(err == 0, "set features returned error %d, errno %m", err);
	check(result == TEST_RESULT,
	      "got result %" PRIu32 ", expected %" PRIu32, result, TEST_RESULT);
}

static void test_get_write_atomic(void)
{
	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_get_features,
		.cdw10 = TEST_SEL << 8 | NVME_FEAT_FID_WRITE_ATOMIC,
		.result = TEST_RESULT,
	};
	uint32_t result = 0;
	int err;

	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_get_features_write_atomic(TEST_FD, TEST_SEL, &result);
	end_mock_cmds();
	check(err == 0, "get features returned error %d, errno %m", err);
	check(result == TEST_RESULT,
	      "got result %" PRIu32 ", expected %" PRIu32, result, TEST_RESULT);
}

static void test_set_async_event(void)
{
	uint32_t EVENTS = 0x87654321;
	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_set_features,
		.cdw10 = (uint32_t)1 << 31 /* SAVE */
		       | NVME_FEAT_FID_ASYNC_EVENT,
		.cdw11 = EVENTS,
		.result = TEST_RESULT,
	};
	uint32_t result = 0;
	int err;

	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_set_features_async_event(TEST_FD, EVENTS, true, &result);
	end_mock_cmds();
	check(err == 0, "set features returned error %d, errno %m", err);
	check(result == TEST_RESULT,
	      "got result %" PRIu32 ", expected %" PRIu32, result, TEST_RESULT);
}

static void test_get_async_event(void)
{
	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_get_features,
		.cdw10 = TEST_SEL << 8 | NVME_FEAT_FID_ASYNC_EVENT,
		.result = TEST_RESULT,
	};
	uint32_t result = 0;
	int err;

	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_get_features_async_event(TEST_FD, TEST_SEL, &result);
	end_mock_cmds();
	check(err == 0, "get features returned error %d, errno %m", err);
	check(result == TEST_RESULT,
	      "got result %" PRIu32 ", expected %" PRIu32, result, TEST_RESULT);
}

static void test_set_auto_pst(void)
{
	struct nvme_feat_auto_pst apst;
	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_set_features,
		.in_data = &apst,
		.data_len = sizeof(apst),
		.cdw10 = NVME_FEAT_FID_AUTO_PST,
		.cdw11 = 1 << 0, /* APSTE */
		.result = TEST_RESULT,
	};
	uint32_t result = 0;
	int err;

	arbitrary(&apst, sizeof(apst));
	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_set_features_auto_pst(TEST_FD, true, false, &apst, &result);
	end_mock_cmds();
	check(err == 0, "set features returned error %d, errno %m", err);
	check(result == TEST_RESULT,
	      "got result %" PRIu32 ", expected %" PRIu32, result, TEST_RESULT);
}

static void test_get_auto_pst(void)
{
	struct nvme_feat_auto_pst apst, get_apst = {};
	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_get_features,
		.data_len = sizeof(apst),
		.cdw10 = TEST_SEL << 8 | NVME_FEAT_FID_AUTO_PST,
		.out_data = &apst,
		.result = TEST_RESULT,
	};
	uint32_t result = 0;
	int err;

	arbitrary(&apst, sizeof(apst));
	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_get_features_auto_pst(TEST_FD, TEST_SEL, &get_apst, &result);
	end_mock_cmds();
	check(err == 0, "get features returned error %d, errno %m", err);
	check(result == TEST_RESULT,
	      "got result %" PRIu32 ", expected %" PRIu32, result, TEST_RESULT);
	cmp(&get_apst, &apst, sizeof(apst), "incorrect apst");
}

static void test_get_host_mem_buf(void)
{
	struct nvme_host_mem_buf_attrs attrs, get_attrs = {};
	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_get_features,
		.data_len = sizeof(attrs),
		.cdw10 = TEST_SEL << 8 | NVME_FEAT_FID_HOST_MEM_BUF,
		.out_data = &attrs,
		.result = TEST_RESULT,
	};
	uint32_t result = 0;
	int err;

	arbitrary(&attrs, sizeof(attrs));
	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_get_features_host_mem_buf(
		TEST_FD, TEST_SEL, &get_attrs, &result);
	end_mock_cmds();
	check(err == 0, "get features returned error %d, errno %m", err);
	check(result == TEST_RESULT,
	      "got result %" PRIu32 ", expected %" PRIu32, result, TEST_RESULT);
	cmp(&get_attrs, &attrs, sizeof(attrs), "incorrect attrs");
}

static void test_set_timestamp(void)
{
	struct nvme_timestamp ts = {.timestamp = {1, 2, 3, 4, 5, 6}};
	uint64_t timestamp = ts.timestamp[0]
	                   | (uint64_t) ts.timestamp[1] << 8
	                   | (uint64_t) ts.timestamp[2] << 16
	                   | (uint64_t) ts.timestamp[3] << 24
	                   | (uint64_t) ts.timestamp[4] << 32
	                   | (uint64_t) ts.timestamp[5] << 40;
	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_set_features,
		.in_data = &ts,
		.data_len = sizeof(ts),
		.cdw10 = (uint32_t)1 << 31 /* SAVE */
		       | NVME_FEAT_FID_TIMESTAMP,
	};
	int err;

	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_set_features_timestamp(TEST_FD, true, timestamp);
	end_mock_cmds();
	check(err == 0, "set features returned error %d, errno %m", err);
}

static void test_get_timestamp(void)
{
	struct nvme_timestamp ts, get_ts = {};
	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_get_features,
		.data_len = sizeof(ts),
		.cdw10 = TEST_SEL << 8 | NVME_FEAT_FID_TIMESTAMP,
		.out_data = &ts,
	};
	int err;

	arbitrary(&ts, sizeof(ts));
	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_get_features_timestamp(TEST_FD, TEST_SEL, &get_ts);
	end_mock_cmds();
	check(err == 0, "get features returned error %d, errno %m", err);
	cmp(&get_ts, &ts, sizeof(ts), "incorrect timestamp");
}

static void test_get_kato(void)
{
	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_get_features,
		.cdw10 = TEST_SEL << 8 | NVME_FEAT_FID_KATO,
		.result = TEST_RESULT,
	};
	uint32_t result = 0;
	int err;

	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_get_features_kato(TEST_FD, TEST_SEL, &result);
	end_mock_cmds();
	check(err == 0, "get features returned error %d, errno %m", err);
	check(result == TEST_RESULT,
	      "got result %" PRIu32 ", expected %" PRIu32, result, TEST_RESULT);
}

static void test_set_hctm(void)
{
	uint16_t TMT2 = 0x4321, TMT1 = 0x8765;
	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_set_features,
		.cdw10 = NVME_FEAT_FID_HCTM,
		.cdw11 = (uint32_t)TMT1 << 16 | TMT2,
		.result = TEST_RESULT,
	};
	uint32_t result = 0;
	int err;

	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_set_features_hctm(TEST_FD, TMT2, TMT1, false, &result);
	end_mock_cmds();
	check(err == 0, "set features returned error %d, errno %m", err);
	check(result == TEST_RESULT,
	      "got result %" PRIu32 ", expected %" PRIu32, result, TEST_RESULT);
}

static void test_get_hctm(void)
{
	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_get_features,
		.cdw10 = TEST_SEL << 8 | NVME_FEAT_FID_HCTM,
		.result = TEST_RESULT,
	};
	uint32_t result = 0;
	int err;

	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_get_features_hctm(TEST_FD, TEST_SEL, &result);
	end_mock_cmds();
	check(err == 0, "get features returned error %d, errno %m", err);
	check(result == TEST_RESULT,
	      "got result %" PRIu32 ", expected %" PRIu32, result, TEST_RESULT);
}

static void test_set_nopsc(void)
{
	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_set_features,
		.cdw10 = (uint32_t)1 << 31 /* SAVE */
		       | NVME_FEAT_FID_NOPSC,
		.cdw11 = 1 << 0 /* NOPPME */,
		.result = TEST_RESULT,
	};
	uint32_t result = 0;
	int err;

	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_set_features_nopsc(TEST_FD, true, true, &result);
	end_mock_cmds();
	check(err == 0, "set features returned error %d, errno %m", err);
	check(result == TEST_RESULT,
	      "got result %" PRIu32 ", expected %" PRIu32, result, TEST_RESULT);
}

static void test_get_nopsc(void)
{
	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_get_features,
		.cdw10 = TEST_SEL << 8 | NVME_FEAT_FID_NOPSC,
		.result = TEST_RESULT,
	};
	uint32_t result = 0;
	int err;

	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_get_features_nopsc(TEST_FD, TEST_SEL, &result);
	end_mock_cmds();
	check(err == 0, "get features returned error %d, errno %m", err);
	check(result == TEST_RESULT,
	      "got result %" PRIu32 ", expected %" PRIu32, result, TEST_RESULT);
}

static void test_set_rrl(void)
{
	uint8_t RRL = 0xA;
	uint16_t NVMSETID = 0x1234;
	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_set_features,
		.cdw10 = NVME_FEAT_FID_RRL,
		.cdw11 = NVMSETID,
		.cdw12 = RRL,
		.result = TEST_RESULT,
	};
	uint32_t result = 0;
	int err;

	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_set_features_rrl(TEST_FD, RRL, NVMSETID, false, &result);
	end_mock_cmds();
	check(err == 0, "set features returned error %d, errno %m", err);
	check(result == TEST_RESULT,
	      "got result %" PRIu32 ", expected %" PRIu32, result, TEST_RESULT);
}

static void test_get_rrl(void)
{
	/* nvme_get_features_rrl() doesn't support specifying the NVMSETID */
	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_get_features,
		.cdw10 = TEST_SEL << 8 | NVME_FEAT_FID_RRL,
		.result = TEST_RESULT,
	};
	uint32_t result = 0;
	int err;

	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_get_features_rrl(TEST_FD, TEST_SEL, &result);
	end_mock_cmds();
	check(err == 0, "get features returned error %d, errno %m", err);
	check(result == TEST_RESULT,
	      "got result %" PRIu32 ", expected %" PRIu32, result, TEST_RESULT);
}

static void test_set_plm_config(void)
{
	uint16_t NVMSETID = 0xFEDC;
	struct nvme_plm_config config;
	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_set_features,
		.in_data = &config,
		.data_len = sizeof(config),
		.cdw10 = (uint32_t)1 << 31 /* SAVE */
		       | NVME_FEAT_FID_PLM_CONFIG,
		.cdw11 = NVMSETID,
		.cdw12 = 1 << 0 /* Predictable Latency Enable */,
		.result = TEST_RESULT,
	};
	uint32_t result = 0;
	int err;

	arbitrary(&config, sizeof(config));
	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_set_features_plm_config(
		TEST_FD, true, NVMSETID, true, &config, &result);
	end_mock_cmds();
	check(err == 0, "set features returned error %d, errno %m", err);
	check(result == TEST_RESULT,
	      "got result %" PRIu32 ", expected %" PRIu32, result, TEST_RESULT);
}

static void test_get_plm_config(void)
{
	uint16_t NVMSETID = 0xABCD;
	struct nvme_plm_config config, get_config = {};
	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_get_features,
		.data_len = sizeof(config),
		.cdw10 = TEST_SEL << 8 | NVME_FEAT_FID_PLM_CONFIG,
		.cdw11 = NVMSETID,
		.out_data = &config,
		.result = TEST_RESULT,
	};
	uint32_t result = 0;
	int err;

	arbitrary(&config, sizeof(config));
	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_get_features_plm_config(
		TEST_FD, TEST_SEL, NVMSETID, &get_config, &result);
	end_mock_cmds();
	check(err == 0, "get features returned error %d, errno %m", err);
	check(result == TEST_RESULT,
	      "got result %" PRIu32 ", expected %" PRIu32, result, TEST_RESULT);
	cmp(&get_config, &config, sizeof(config), "incorrect PLM config");
}

static void test_set_plm_window(void)
{
	enum nvme_feat_plm_window_select SEL = NVME_FEATURE_PLM_NDWIN;
	uint16_t NVMSETID = 0x4321;
	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_set_features,
		.cdw10 = NVME_FEAT_FID_PLM_WINDOW,
		.cdw11 = NVMSETID,
		.cdw12 = SEL,
		.result = TEST_RESULT,
	};
	uint32_t result = 0;
	int err;

	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_set_features_plm_window(
		TEST_FD, SEL, NVMSETID, false, &result);
	end_mock_cmds();
	check(err == 0, "set features returned error %d, errno %m", err);
	check(result == TEST_RESULT,
	      "got result %" PRIu32 ", expected %" PRIu32, result, TEST_RESULT);
}

static void test_get_plm_window(void)
{
	uint16_t NVMSETID = 0x8765;
	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_get_features,
		.cdw10 = TEST_SEL << 8 | NVME_FEAT_FID_PLM_WINDOW,
		.cdw11 = NVMSETID,
		.result = TEST_RESULT,
	};
	uint32_t result = 0;
	int err;

	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_get_features_plm_window(
		TEST_FD, TEST_SEL, NVMSETID, &result);
	end_mock_cmds();
	check(err == 0, "get features returned error %d, errno %m", err);
	check(result == TEST_RESULT,
	      "got result %" PRIu32 ", expected %" PRIu32, result, TEST_RESULT);
}

static void test_set_lba_sts_interval(void)
{
	uint16_t LSIRI = 0x1234, LSIPI = 0x5678;
	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_set_features,
		.cdw10 = (uint32_t)1 << 31 /* SAVE */
		       | NVME_FEAT_FID_LBA_STS_INTERVAL,
		.cdw11 = LSIPI << 16 | LSIRI,
		.result = TEST_RESULT,
	};
	uint32_t result = 0;
	int err;

	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_set_features_lba_sts_interval(
		TEST_FD, LSIRI, LSIPI, true, &result);
	end_mock_cmds();
	check(err == 0, "set features returned error %d, errno %m", err);
	check(result == TEST_RESULT,
	      "got result %" PRIu32 ", expected %" PRIu32, result, TEST_RESULT);
}

static void test_get_lba_sts_interval(void)
{
	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_get_features,
		.cdw10 = TEST_SEL << 8 | NVME_FEAT_FID_LBA_STS_INTERVAL,
		.result = TEST_RESULT,
	};
	uint32_t result = 0;
	int err;

	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_get_features_lba_sts_interval(TEST_FD, TEST_SEL, &result);
	end_mock_cmds();
	check(err == 0, "get features returned error %d, errno %m", err);
	check(result == TEST_RESULT,
	      "got result %" PRIu32 ", expected %" PRIu32, result, TEST_RESULT);
}

static void test_set_host_behavior(void)
{
	/* nvme_set_features_host_behavior() ignores SAVE */
	struct nvme_feat_host_behavior behavior;
	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_set_features,
		.in_data = &behavior,
		.data_len = sizeof(behavior),
		.cdw10 = NVME_FEAT_FID_HOST_BEHAVIOR,
	};
	int err;

	arbitrary(&behavior, sizeof(behavior));
	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_set_features_host_behavior(TEST_FD, true, &behavior);
	end_mock_cmds();
	check(err == 0, "set features returned error %d, errno %m", err);
}

static void test_get_host_behavior(void)
{
	struct nvme_feat_host_behavior behavior, get_behavior = {};
	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_get_features,
		.data_len = sizeof(behavior),
		.cdw10 = TEST_SEL << 8 | NVME_FEAT_FID_HOST_BEHAVIOR,
		.out_data = &behavior,
		.result = TEST_RESULT,
	};
	uint32_t result = 0;
	int err;

	arbitrary(&behavior, sizeof(behavior));
	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_get_features_host_behavior(
		TEST_FD, TEST_SEL, &get_behavior, &result);
	end_mock_cmds();
	check(err == 0, "get features returned error %d, errno %m", err);
	check(result == TEST_RESULT,
	      "got result %" PRIu32 ", expected %" PRIu32, result, TEST_RESULT);
	cmp(&get_behavior, &behavior, sizeof(behavior), "incorrect behavior");
}

static void test_set_sanitize(void)
{
	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_set_features,
		.cdw10 = NVME_FEAT_FID_SANITIZE,
		.cdw11 = 1 << 0, /* NODRM */
		.result = TEST_RESULT,
	};
	uint32_t result = 0;
	int err;

	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_set_features_sanitize(TEST_FD, true, false, &result);
	end_mock_cmds();
	check(err == 0, "set features returned error %d, errno %m", err);
	check(result == TEST_RESULT,
	      "got result %" PRIu32 ", expected %" PRIu32, result, TEST_RESULT);
}

static void test_get_sanitize(void)
{
	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_get_features,
		.cdw10 = TEST_SEL << 8 | NVME_FEAT_FID_SANITIZE,
		.result = TEST_RESULT,
	};
	uint32_t result = 0;
	int err;

	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_get_features_sanitize(TEST_FD, TEST_SEL, &result);
	end_mock_cmds();
	check(err == 0, "get features returned error %d, errno %m", err);
	check(result == TEST_RESULT,
	      "got result %" PRIu32 ", expected %" PRIu32, result, TEST_RESULT);
}

static void test_set_endurance_evt_cfg(void)
{
	uint16_t ENDGID = 0x9876;
	uint8_t EGWARN = 0xCD;
	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_set_features,
		.cdw10 = (uint32_t)1 << 31 /* SAVE */
		       | NVME_FEAT_FID_ENDURANCE_EVT_CFG,
		.cdw11 = EGWARN << 16 | ENDGID,
		.result = TEST_RESULT,
	};
	uint32_t result = 0;
	int err;

	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_set_features_endurance_evt_cfg(
		TEST_FD, ENDGID, EGWARN, true, &result);
	end_mock_cmds();
	check(err == 0, "set features returned error %d, errno %m", err);
	check(result == TEST_RESULT,
	      "got result %" PRIu32 ", expected %" PRIu32, result, TEST_RESULT);
}

static void test_get_endurance_event_cfg(void)
{
	uint16_t ENDGID = 0x6789;
	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_get_features,
		.cdw10 = TEST_SEL << 8 | NVME_FEAT_FID_ENDURANCE_EVT_CFG,
		.cdw11 = ENDGID,
		.result = TEST_RESULT,
	};
	uint32_t result = 0;
	int err;

	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_get_features_endurance_event_cfg(
		TEST_FD, TEST_SEL, ENDGID, &result);
	end_mock_cmds();
	check(err == 0, "get features returned error %d, errno %m", err);
	check(result == TEST_RESULT,
	      "got result %" PRIu32 ", expected %" PRIu32, result, TEST_RESULT);
}

static void test_set_iocs_profile(void)
{
	uint16_t IOCSI = 0b101100111;
	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_set_features,
		.cdw10 = NVME_FEAT_FID_IOCS_PROFILE,
		.cdw11 = IOCSI,
	};
	int err;

	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_set_features_iocs_profile(TEST_FD, IOCSI, false);
	end_mock_cmds();
	check(err == 0, "set features returned error %d, errno %m", err);
}

static void test_get_iocs_profile(void)
{
	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_get_features,
		.cdw10 = TEST_SEL << 8 | NVME_FEAT_FID_IOCS_PROFILE,
		.result = TEST_RESULT,
	};
	uint32_t result = 0;
	int err;

	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_get_features_iocs_profile(TEST_FD, TEST_SEL, &result);
	end_mock_cmds();
	check(err == 0, "get features returned error %d, errno %m", err);
	check(result == TEST_RESULT,
	      "got result %" PRIu32 ", expected %" PRIu32, result, TEST_RESULT);
}

static void test_set_sw_progress(void)
{
	uint8_t PBSLC = 0xBA;
	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_set_features,
		.cdw10 = (uint32_t)1 << 31 /* SAVE */
		       | NVME_FEAT_FID_SW_PROGRESS,
		.cdw11 = PBSLC,
		.result = TEST_RESULT,
	};
	uint32_t result = 0;
	int err;

	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_set_features_sw_progress(TEST_FD, PBSLC, true, &result);
	end_mock_cmds();
	check(err == 0, "set features returned error %d, errno %m", err);
	check(result == TEST_RESULT,
	      "got result %" PRIu32 ", expected %" PRIu32, result, TEST_RESULT);
}

static void test_get_sw_progress(void)
{
	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_get_features,
		.cdw10 = TEST_SEL << 8 | NVME_FEAT_FID_SW_PROGRESS,
		.result = TEST_RESULT,
	};
	uint32_t result = 0;
	int err;

	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_get_features_sw_progress(TEST_FD, TEST_SEL, &result);
	end_mock_cmds();
	check(err == 0, "get features returned error %d, errno %m", err);
	check(result == TEST_RESULT,
	      "got result %" PRIu32 ", expected %" PRIu32, result, TEST_RESULT);
}

static void test_set_host_id(void)
{
	uint8_t hostid[8];
	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_set_features,
		.in_data = hostid,
		.data_len = sizeof(hostid),
		.cdw10 = (uint32_t)1 << 31 /* SAVE */
		       | NVME_FEAT_FID_HOST_ID,
		.result = TEST_RESULT,
	};
	int err;

	arbitrary(hostid, sizeof(hostid));
	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_set_features_host_id(TEST_FD, false, true, hostid);
	end_mock_cmds();
	check(err == 0, "set features returned error %d, errno %m", err);
}

static void test_set_host_id_extended(void)
{
	uint8_t hostid[16];
	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_set_features,
		.in_data = hostid,
		.data_len = sizeof(hostid),
		.cdw10 = NVME_FEAT_FID_HOST_ID,
		.cdw11 = 1 << 0, /* EXHID */
		.result = TEST_RESULT,
	};
	int err;

	arbitrary(hostid, sizeof(hostid));
	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_set_features_host_id(TEST_FD, true, false, hostid);
	end_mock_cmds();
	check(err == 0, "set features returned error %d, errno %m", err);
}

static void test_get_host_id(void)
{
	uint8_t hostid[8], get_hostid[sizeof(hostid)] = {};
	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_get_features,
		.data_len = sizeof(hostid),
		.cdw10 = TEST_SEL << 8 | NVME_FEAT_FID_HOST_ID,
		.out_data = hostid,
		.result = TEST_RESULT,
	};
	int err;

	arbitrary(hostid, sizeof(hostid));
	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_get_features_host_id(
		TEST_FD, TEST_SEL, false, sizeof(hostid), get_hostid);
	end_mock_cmds();
	check(err == 0, "get features returned error %d, errno %m", err);
	cmp(get_hostid, hostid, sizeof(hostid), "incorrect host identifier");
}

static void test_get_host_id_extended(void)
{
	uint8_t hostid[16], get_hostid[sizeof(hostid)] = {};
	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_get_features,
		.data_len = sizeof(hostid),
		.cdw10 = TEST_SEL << 8 | NVME_FEAT_FID_HOST_ID,
		.cdw11 = 1 << 0, /* EXHID */
		.out_data = hostid,
		.result = TEST_RESULT,
	};
	int err;

	arbitrary(hostid, sizeof(hostid));
	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_get_features_host_id(
		TEST_FD, TEST_SEL, true, sizeof(hostid), get_hostid);
	end_mock_cmds();
	check(err == 0, "get features returned error %d, errno %m", err);
	cmp(get_hostid, hostid, sizeof(hostid), "incorrect host identifier");
}

static void test_set_resv_mask(void)
{
	uint32_t MASK = 0x23456789;
	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_set_features,
		.nsid = TEST_NSID,
		.cdw10 = (uint32_t)1 << 31 /* SAVE */
		       | NVME_FEAT_FID_RESV_MASK,
		.cdw11 = MASK,
		.result = TEST_RESULT,
	};
	uint32_t result = 0;
	int err;

	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_set_features_resv_mask(
		TEST_FD, TEST_NSID, MASK, true, &result);
	end_mock_cmds();
	check(err == 0, "set features returned error %d, errno %m", err);
	check(result == TEST_RESULT,
	      "got result %" PRIu32 ", expected %" PRIu32, result, TEST_RESULT);
}

static void test_get_resv_mask(void)
{
	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_get_features,
		.nsid = TEST_NSID,
		.cdw10 = TEST_SEL << 8 | NVME_FEAT_FID_RESV_MASK,
		.result = TEST_RESULT,
	};
	uint32_t result = 0;
	int err;

	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_get_features_resv_mask(
		TEST_FD, TEST_SEL, TEST_NSID, &result);
	end_mock_cmds();
	check(err == 0, "get features returned error %d, errno %m", err);
	check(result == TEST_RESULT,
	      "got result %" PRIu32 ", expected %" PRIu32, result, TEST_RESULT);
}

static void test_set_resv_persist(void)
{
	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_set_features,
		.nsid = TEST_NSID,
		.cdw10 = NVME_FEAT_FID_RESV_PERSIST,
		.cdw11 = 1 << 0, /* PTPL */
		.result = TEST_RESULT,
	};
	uint32_t result = 0;
	int err;

	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_set_features_resv_persist(
		TEST_FD, TEST_NSID, true, false, &result);
	end_mock_cmds();
	check(err == 0, "set features returned error %d, errno %m", err);
	check(result == TEST_RESULT,
	      "got result %" PRIu32 ", expected %" PRIu32, result, TEST_RESULT);
}

static void test_get_resv_persist(void)
{
	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_get_features,
		.nsid = TEST_NSID,
		.cdw10 = TEST_SEL << 8 | NVME_FEAT_FID_RESV_PERSIST,
		.result = TEST_RESULT,
	};
	uint32_t result = 0;
	int err;

	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_get_features_resv_persist(
		TEST_FD, TEST_SEL, TEST_NSID, &result);
	end_mock_cmds();
	check(err == 0, "get features returned error %d, errno %m", err);
	check(result == TEST_RESULT,
	      "got result %" PRIu32 ", expected %" PRIu32, result, TEST_RESULT);
}

static void test_set_write_protect(void)
{
	/* nvme_set_features_write_protect() ignores SAVE */
	enum nvme_feat_nswpcfg_state STATE =
		NVME_FEAT_NS_WRITE_PROTECT_PERMANENT;
	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_set_features,
		.nsid = TEST_NSID,
		.cdw10 = NVME_FEAT_FID_WRITE_PROTECT,
		.cdw11 = STATE,
		.result = TEST_RESULT,
	};
	uint32_t result = 0;
	int err;

	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_set_features_write_protect(
		TEST_FD, TEST_NSID, STATE, true, &result);
	end_mock_cmds();
	check(err == 0, "set features returned error %d, errno %m", err);
	check(result == TEST_RESULT,
	      "got result %" PRIu32 ", expected %" PRIu32, result, TEST_RESULT);
}

static void test_get_write_protect(void)
{
	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_get_features,
		.nsid = TEST_NSID,
		.cdw10 = TEST_SEL << 8 | NVME_FEAT_FID_WRITE_PROTECT,
		.result = TEST_RESULT,
	};
	uint32_t result = 0;
	int err;

	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_get_features_write_protect(
		TEST_FD, TEST_NSID, TEST_SEL, &result);
	end_mock_cmds();
	check(err == 0, "get features returned error %d, errno %m", err);
	check(result == TEST_RESULT,
	      "got result %" PRIu32 ", expected %" PRIu32, result, TEST_RESULT);
}

/*
 * All set_features functions tail-call nvme_set_features(),
 * so testing errors in any of them will do
 */

static void test_set_status_code_error(void)
{
	uint32_t EVENTS = 0x12345678;
	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_set_features,
		.cdw10 = NVME_FEAT_FID_ASYNC_EVENT,
		.cdw11 = EVENTS,
		.result = TEST_RESULT,
		.err = TEST_SC,
	};
	uint32_t result = 0;
	int err;

	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_set_features_async_event(TEST_FD, EVENTS, false, &result);
	end_mock_cmds();
	check(err == TEST_SC, "got error %d, expected %d", err, TEST_SC);
	check(result == TEST_RESULT,
	      "got result %" PRIu32 ", expected %" PRIu32, result, TEST_RESULT);
}

static void test_set_kernel_error(void)
{
	uint32_t MASK = 0x87654321;
	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_set_features,
		.nsid = TEST_NSID,
		.cdw10 = NVME_FEAT_FID_RESV_MASK,
		.cdw11 = MASK,
		.result = TEST_RESULT,
		.err = -EIO,
	};
	uint32_t result = 0;
	int err;

	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_set_features_resv_mask(
		TEST_FD, TEST_NSID, MASK, false, &result);
	end_mock_cmds();
	check(err == -1, "got error %d, expected -1", err);
	check(errno == EIO, "unexpected error %m");
	check(!result, "result unexpectedly set to %" PRIu32, result);
}

/*
 * All get_features functions tail-call nvme_get_features(),
 * so testing errors in any of them will do
 */

static void test_get_status_code_error(void)
{
	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_get_features,
		.cdw10 = TEST_SEL << 8 | NVME_FEAT_FID_KATO,
		.result = TEST_RESULT,
		.err = TEST_SC,
	};
	uint32_t result = 0;
	int err;

	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_get_features_kato(TEST_FD, TEST_SEL, &result);
	end_mock_cmds();
	check(err == TEST_SC, "got error %d, expected %d", err, TEST_SC);
	check(result == TEST_RESULT,
	      "got result %" PRIu32 ", expected %" PRIu32, result, TEST_RESULT);
}

static void test_get_kernel_error(void)
{
	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_get_features,
		.cdw10 = TEST_SEL << 8 | NVME_FEAT_FID_NUM_QUEUES,
		.result = TEST_RESULT,
		.err = -EBUSY,
	};
	uint32_t result = 0;
	int err;

	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_get_features_num_queues(TEST_FD, TEST_SEL, &result);
	end_mock_cmds();
	check(err == -1, "got error %d, expected -1", err);
	check(errno == EBUSY, "unexpected error %m");
	check(!result, "result unexpectedly set to %" PRIu32, result);
}

static void test_lm_set_features_ctrl_data_queue(void)
{
	__u32 hp = 0x12, tpt = 0x34;
	bool etpt = true;
	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_set_features,
		.nsid = NVME_NSID_NONE,
		.cdw10 = NVME_FEAT_FID_CTRL_DATA_QUEUE,
		.cdw11 = TEST_CDQID | etpt << 31,
		.cdw12 = hp,
		.cdw13 = tpt,
		.result = TEST_RESULT,
	};
	uint32_t result = 0;
	int err;

	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_lm_set_features_ctrl_data_queue(TEST_FD, TEST_CDQID, hp, tpt,
						   etpt, &result);
	end_mock_cmds();
	check(err == 0, "set features returned error %d, errno %m", err);
	check(result == TEST_RESULT,
	      "got result %" PRIu32 ", expected %" PRIu32, result, TEST_RESULT);
}

static void test_lm_get_features_ctrl_data_queue(void)
{
	struct nvme_lm_ctrl_data_queue_fid_data expected_data, data = {};
	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_get_features,
		.nsid = NVME_NSID_NONE,
		.cdw10 = NVME_FEAT_FID_CTRL_DATA_QUEUE,
		.cdw11 = TEST_CDQID,
		.data_len = sizeof(expected_data),
		.out_data = &expected_data,
		.result = TEST_RESULT,
	};
	uint32_t result = 0;
	int err;

	arbitrary(&expected_data, sizeof(expected_data));
	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_lm_get_features_ctrl_data_queue(TEST_FD, TEST_CDQID, &data,
						   &result);
	end_mock_cmds();
	check(err == 0, "get features returned error %d, errno %m", err);
	check(result == TEST_RESULT,
	      "got result %" PRIu32 ", expected %" PRIu32, result, TEST_RESULT);
	cmp(&data, &expected_data, sizeof(data), "incorrect data");
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
	RUN_TEST(set_features);
	RUN_TEST(get_features);
	RUN_TEST(set_features_data);
	RUN_TEST(get_features_data);
	RUN_TEST(set_features_simple);
	RUN_TEST(get_features_simple);
	RUN_TEST(set_arbitration);
	RUN_TEST(get_arbitration);
	RUN_TEST(set_power_mgmt);
	RUN_TEST(get_power_mgmt);
	RUN_TEST(set_lba_range);
	RUN_TEST(get_lba_range);
	RUN_TEST(set_temp_thresh);
	RUN_TEST(get_temp_thresh);
	RUN_TEST(set_err_recovery);
	RUN_TEST(get_err_recovery);
	RUN_TEST(set_volatile_wc);
	RUN_TEST(get_volatile_wc);
	RUN_TEST(get_num_queues);
	RUN_TEST(set_irq_coalesce);
	RUN_TEST(get_irq_coalesce);
	RUN_TEST(set_irq_config);
	RUN_TEST(get_irq_config);
	RUN_TEST(set_write_atomic);
	RUN_TEST(get_write_atomic);
	RUN_TEST(set_async_event);
	RUN_TEST(get_async_event);
	RUN_TEST(set_auto_pst);
	RUN_TEST(get_auto_pst);
	RUN_TEST(get_host_mem_buf);
	RUN_TEST(set_timestamp);
	RUN_TEST(get_timestamp);
	RUN_TEST(get_kato);
	RUN_TEST(set_hctm);
	RUN_TEST(get_hctm);
	RUN_TEST(set_nopsc);
	RUN_TEST(get_nopsc);
	RUN_TEST(set_rrl);
	RUN_TEST(get_rrl);
	RUN_TEST(set_plm_config);
	RUN_TEST(get_plm_config);
	RUN_TEST(set_plm_window);
	RUN_TEST(get_plm_window);
	RUN_TEST(set_lba_sts_interval);
	RUN_TEST(get_lba_sts_interval);
	RUN_TEST(set_host_behavior);
	RUN_TEST(get_host_behavior);
	RUN_TEST(set_sanitize);
	RUN_TEST(get_sanitize);
	RUN_TEST(set_endurance_evt_cfg);
	RUN_TEST(get_endurance_event_cfg);
	RUN_TEST(set_iocs_profile);
	RUN_TEST(get_iocs_profile);
	RUN_TEST(set_sw_progress);
	RUN_TEST(get_sw_progress);
	RUN_TEST(set_host_id);
	RUN_TEST(set_host_id_extended);
	RUN_TEST(get_host_id);
	RUN_TEST(get_host_id_extended);
	RUN_TEST(set_resv_mask);
	RUN_TEST(get_resv_mask);
	RUN_TEST(set_resv_persist);
	RUN_TEST(get_resv_persist);
	RUN_TEST(set_write_protect);
	RUN_TEST(get_write_protect);
	RUN_TEST(set_status_code_error);
	RUN_TEST(set_kernel_error);
	RUN_TEST(get_status_code_error);
	RUN_TEST(get_kernel_error);
	RUN_TEST(lm_set_features_ctrl_data_queue);
	RUN_TEST(lm_get_features_ctrl_data_queue);
}
