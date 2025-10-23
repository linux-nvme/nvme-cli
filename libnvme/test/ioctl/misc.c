// SPDX-License-Identifier: LGPL-2.1-or-later

#include <libnvme.h>

#include "mock.h"
#include "util.h"
#include <nvme/api-types.h>
#include <nvme/ioctl.h>
#include <nvme/types.h>
#include <string.h>

#define TEST_FD 0xFD
#define TEST_NSID 0x12345678
#define TEST_CSI NVME_CSI_KV

static struct nvme_transport_handle *test_hdl;

static void test_format_nvm(void)
{
	enum nvme_cmd_format_mset mset = NVME_FORMAT_MSET_EXTENDED;
	enum nvme_cmd_format_pi pi = NVME_FORMAT_PI_TYPE2;
	enum nvme_cmd_format_pil pil = NVME_FORMAT_PIL_FIRST;
	enum nvme_cmd_format_ses ses = NVME_FORMAT_SES_USER_DATA_ERASE;
	__u32 nsid = TEST_NSID;
	__u8 lbaf = 0x1F;
	__u32 result = 0;
	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_format_nvm,
		.nsid = nsid,
		.cdw10 = lbaf | (mset << 4) | (pi << 5) |
			 (pil << 8) | (ses << 9) | ((lbaf >> 4) << 12),
		.result = 0,
	};
	struct nvme_passthru_cmd cmd;
	int err;

	set_mock_admin_cmds(&mock_admin_cmd, 1);
	nvme_init_format_nvm(&cmd, nsid, lbaf, mset, pi, pil, ses);
	err = nvme_submit_admin_passthru(test_hdl, &cmd, &result);
	end_mock_cmds();
	check(err == 0, "returned error %d", err);
	check(result == 0, "returned result %u", result);
}

static void test_ns_mgmt(void)
{
	struct nvme_ns_mgmt_host_sw_specified expected_data, data = {};
	enum nvme_ns_mgmt_sel sel = NVME_NS_MGMT_SEL_CREATE;
	__u32 nsid = TEST_NSID;
	__u8 csi = TEST_CSI;
	__u32 result = 0;
	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_ns_mgmt,
		.nsid = nsid,
		.cdw10 = sel,
		.cdw11 = csi << 24,
		.result = 0,
		.data_len = sizeof(expected_data),
		.out_data = &expected_data,
	};
	struct nvme_passthru_cmd cmd;
	int err;

	arbitrary(&expected_data, sizeof(expected_data));
	set_mock_admin_cmds(&mock_admin_cmd, 1);
	nvme_init_ns_mgmt(&cmd, nsid, sel, csi, &data);
	err = nvme_submit_admin_passthru(test_hdl, &cmd, &result);
	end_mock_cmds();
	check(err == 0, "returned error %d", err);
	check(result == 0, "returned result %u", result);
	cmp(&data, &expected_data, sizeof(data), "incorrect data");
}

static void test_ns_mgmt_create(void)
{
	struct nvme_ns_mgmt_host_sw_specified expected_data, data = {};
	enum nvme_ns_mgmt_sel sel = NVME_NS_MGMT_SEL_CREATE;
	__u32 nsid = NVME_NSID_NONE;
	__u8 csi = NVME_CSI_ZNS;
	__u32 result = 0;
	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_ns_mgmt,
		.nsid = nsid,
		.cdw10 = sel,
		.cdw11 = csi << 24,
		.result = TEST_NSID,
		.data_len = sizeof(expected_data),
		.out_data = &expected_data,
	};
	struct nvme_passthru_cmd cmd;
	int err;

	arbitrary(&expected_data, sizeof(expected_data));
	set_mock_admin_cmds(&mock_admin_cmd, 1);
	nvme_init_ns_mgmt_create(&cmd, NVME_CSI_ZNS, &data);
	err = nvme_submit_admin_passthru(test_hdl, &cmd, &result);
	end_mock_cmds();
	check(err == 0, "returned error %d", err);
	check(result == TEST_NSID, "returned result %u", result);
	cmp(&data, &expected_data, sizeof(data), "incorrect data");
}

static void test_ns_mgmt_delete(void)
{
	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_ns_mgmt,
		.nsid = TEST_NSID,
		.cdw10 = NVME_NS_MGMT_SEL_DELETE,
	};
	struct nvme_passthru_cmd cmd;
	int err;

	set_mock_admin_cmds(&mock_admin_cmd, 1);
	nvme_init_ns_mgmt_delete(&cmd, TEST_NSID);
	err = nvme_submit_admin_passthru(test_hdl, &cmd, NULL);
	end_mock_cmds();
	check(err == 0, "returned error %d", err);
}

static void test_get_property(void)
{
	__u64 expected_result, result;
	arbitrary(&expected_result, sizeof(expected_result));
	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_fabrics,
		.nsid = nvme_fabrics_type_property_get,
		.cdw10 = true,
		.cdw11 = NVME_REG_ACQ,
		.result = expected_result,
	};
	struct nvme_passthru_cmd64 cmd;
	int err;

	set_mock_admin_cmds(&mock_admin_cmd, 1);
	nvme_init_get_property(&cmd, NVME_REG_ACQ);
	err = nvme_submit_admin_passthru64(test_hdl, &cmd, &result);
	end_mock_cmds();
	check(err == 0, "returned error %d", err);
	check(result == expected_result, "returned wrong result");
}

static void test_set_property(void)
{
	__u64 value = 0xffffffff;
	__u32 result;
	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_fabrics,
		.nsid = nvme_fabrics_type_property_set,
		.cdw10 = true,
		.cdw11 = NVME_REG_BPMBL,
		.cdw12 = value & 0xffffffff,
		.cdw13 = value >> 32,
	};
	struct nvme_passthru_cmd cmd;
	int err;

	set_mock_admin_cmds(&mock_admin_cmd, 1);
	nvme_init_set_property(&cmd, NVME_REG_BPMBL, value);
	err = nvme_submit_admin_passthru(test_hdl, &cmd, &result);
	end_mock_cmds();
	check(err == 0, "returned error %d", err);
	check(result == 0, "returned result %u", result);
}

static void test_ns_attach(void)
{
	struct nvme_ctrl_list expected_ctrlist, ctrlist;
	enum nvme_ns_attach_sel sel = NVME_NS_ATTACH_SEL_CTRL_ATTACH;
	__u32 nsid = TEST_NSID;
	__u32 result;
	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_ns_attach,
		.nsid = nsid,
		.cdw10 = sel,
		.data_len = sizeof(expected_ctrlist),
		.out_data = &expected_ctrlist,
	};
	struct nvme_passthru_cmd cmd;
	int err;

	arbitrary(&expected_ctrlist, sizeof(expected_ctrlist));
	set_mock_admin_cmds(&mock_admin_cmd, 1);
	nvme_init_ns_attach(&cmd, nsid, sel, &ctrlist);
	err = nvme_submit_admin_passthru(test_hdl, &cmd, &result);
	end_mock_cmds();
	check(err == 0, "returned error %d", err);
	check(result == 0, "returned result %u", result);
	cmp(&expected_ctrlist, &ctrlist, sizeof(expected_ctrlist),
	    "incorrect data");
}

static void test_ns_attach_ctrls(void)
{
	struct nvme_ctrl_list ctrlist;
	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_ns_attach,
		.nsid = TEST_NSID,
		.cdw10 = NVME_NS_ATTACH_SEL_CTRL_ATTACH,
		.data_len = sizeof(ctrlist),
		.out_data = &ctrlist,
	};
	struct nvme_passthru_cmd cmd;
	int err;

	arbitrary(&ctrlist, sizeof(ctrlist));
	set_mock_admin_cmds(&mock_admin_cmd, 1);
	nvme_init_ns_attach_ctrls(&cmd, TEST_NSID, &ctrlist);
	err = nvme_submit_admin_passthru(test_hdl, &cmd, NULL);
	end_mock_cmds();
	check(err == 0, "returned error %d", err);
}

static void test_ns_detach_ctrls(void)
{
	struct nvme_ctrl_list ctrlist;
	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_ns_attach,
		.nsid = TEST_NSID,
		.cdw10 = NVME_NS_ATTACH_SEL_CTRL_DEATTACH,
		.data_len = sizeof(ctrlist),
		.out_data = &ctrlist,
	};
	struct nvme_passthru_cmd cmd;
	int err;

	arbitrary(&ctrlist, sizeof(ctrlist));
	set_mock_admin_cmds(&mock_admin_cmd, 1);
	nvme_init_ns_detach_ctrls(&cmd, TEST_NSID, &ctrlist);
	err = nvme_submit_admin_passthru(test_hdl, &cmd, NULL);
	end_mock_cmds();
	check(err == 0, "returned error %d", err);
}

static void test_fw_download(void)
{
	__u32 result = 0;
	__u8 expected_data[8], data[8];
	__u32 data_len = sizeof(expected_data);
	__u32 offset = 120;
	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_fw_download,
		.cdw10 = (data_len >> 2) - 1,
		.cdw11 = offset >> 2,
		.data_len = data_len,
		.in_data = &data,
	};
	struct nvme_passthru_cmd cmd;
	int err;

	arbitrary(&expected_data, sizeof(expected_data));
	memcpy(&data, &expected_data, sizeof(expected_data));
	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_init_fw_download(&cmd, data, data_len, offset);
	check(err == 0, "download initializing error %d", err);
	err = nvme_submit_admin_passthru(test_hdl, &cmd, &result);
	end_mock_cmds();
	check(err == 0, "returned error %d", err);
	check(result == 0, "returned result %u", result);
}

static void test_fw_commit(void)
{
	enum nvme_fw_commit_ca action =
		NVME_FW_COMMIT_CA_REPLACE_AND_ACTIVATE_IMMEDIATE;
	__u8 slot = 0xf;
	bool bpid = true;
	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_fw_commit,
		.cdw10 = (bpid << 31) | (action << 3) | slot,
	};
	struct nvme_passthru_cmd cmd;
	__u32 result = 0;
	int err;

	set_mock_admin_cmds(&mock_admin_cmd, 1);
	nvme_init_fw_commit(&cmd, slot, action, bpid);
	err = nvme_submit_admin_passthru(test_hdl, &cmd, &result);
	end_mock_cmds();
	check(err == 0, "returned error %d", err);
	check(result == 0, "returned result %u", result);
}

static void test_security_send(void)
{
	__u8 expected_data[8], data[8];
	__u32 data_len = sizeof(expected_data);
	__u32 nsid = TEST_NSID;
	__u32 tl = 0xffff;
	__u32 result = 0;
	__u8 nssf = 0x1;
	__u16 spsp = 0x0101;
	__u8 secp = 0xE9;
	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_security_send,
		.nsid = TEST_NSID,
		.cdw10 = nssf | (spsp << 8) | (secp << 24),
		.cdw11 = tl,
		.data_len = data_len,
		.in_data = &expected_data,
	};
	struct nvme_passthru_cmd cmd;
	int err;

	arbitrary(&expected_data, sizeof(expected_data));
	memcpy(&data, &expected_data, sizeof(expected_data));
	set_mock_admin_cmds(&mock_admin_cmd, 1);
	nvme_init_security_send(&cmd, nsid, nssf, spsp, secp, tl,
		data, data_len);
	err = nvme_submit_admin_passthru(test_hdl, &cmd, &result);
	end_mock_cmds();
	check(err == 0, "returned error %d", err);
	check(result == 0, "returned result %u", result);
	cmp(&data, &expected_data, sizeof(data), "incorrect data");
}

static void test_security_receive(void)
{
	__u8 expected_data[8], data[8];
	__u32 result = 0;
	__u32 al = 0xffff;
	__u16 spsp = 0x0101;
	__u8 secp = 0xE9;
	__u8 nssf = 0x1;
	int err;
	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_security_recv,
		.nsid = TEST_NSID,
		.cdw10 = nssf | (spsp << 8) | (secp << 24),
		.cdw11 = al,
		.data_len = sizeof(expected_data),
		.out_data = &expected_data,
	};
	struct nvme_passthru_cmd cmd;

	arbitrary(&expected_data, sizeof(expected_data));
	set_mock_admin_cmds(&mock_admin_cmd, 1);
	nvme_init_security_receive(&cmd, TEST_NSID, nssf, spsp, secp, al,
		data, sizeof(data));
	err = nvme_submit_admin_passthru(test_hdl, &cmd, &result);
	end_mock_cmds();
	check(err == 0, "returned error %d", err);
	check(result == 0, "returned result %u", result);
	cmp(&data, &expected_data, sizeof(data), "incorrect data");
}

static void test_get_lba_status(void)
{
	__u8 nlsd = 3;
	int lba_status_size = sizeof(struct nvme_lba_status) +
			      nlsd * sizeof(struct nvme_lba_status_desc);
	enum nvme_lba_status_atype atype = 0x11;
	__u32 mndw = (lba_status_size - 1) >> 2;
	__u64 slba = 0x123456789;
	__u32 result = 0;
	__u16 rl = 0x42;
	int err;

	_cleanup_free_ struct nvme_lba_status *lbas = NULL;
	_cleanup_free_ struct nvme_lba_status *expected_lbas = NULL;

	lbas = malloc(lba_status_size);
	check(lbas, "lbas: ENOMEM");
	expected_lbas = malloc(lba_status_size);
	check(expected_lbas, "expected_lbas: ENOMEM");

	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_get_lba_status,
		.nsid = TEST_NSID,
		.cdw10 = slba & 0xffffffff,
		.cdw11 = slba >> 32,
		.cdw12 = mndw,
		.cdw13 = rl | (atype << 24),
		.data_len = (mndw + 1) << 2,
		.out_data = expected_lbas,
	};
	struct nvme_passthru_cmd cmd;

	arbitrary(expected_lbas, lba_status_size);
	set_mock_admin_cmds(&mock_admin_cmd, 1);
	nvme_init_get_lba_status(&cmd, TEST_NSID, slba, mndw, atype,
		rl, lbas);
	err = nvme_submit_admin_passthru(test_hdl, &cmd, &result);
	end_mock_cmds();
	check(err == 0, "returned error %d", err);
	check(result == 0, "returned wrong result");
	cmp(lbas, expected_lbas, lba_status_size, "incorrect lbas");
}

static void test_directive_send(void)
{
	enum nvme_directive_send_doper doper =
		NVME_DIRECTIVE_SEND_STREAMS_DOPER_RELEASE_RESOURCE;
	enum nvme_directive_dtype dtype = NVME_DIRECTIVE_DTYPE_STREAMS;
	__u8 expected_data[8], data[8];
	__u32 data_len = sizeof(expected_data);
	__u16 dspec = 0x0;
	__u32 result = 0;
	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_directive_send,
		.nsid = TEST_NSID,
		.cdw10 = data_len ? (data_len >> 2) - 1 : 0,
		.cdw11 = doper | (dtype << 8) | (dspec << 16),
		.data_len = data_len,
		.in_data = &data,
	};
	struct nvme_passthru_cmd cmd;
	int err;

	arbitrary(&expected_data, sizeof(expected_data));
	memcpy(&data, &expected_data, sizeof(expected_data));
	set_mock_admin_cmds(&mock_admin_cmd, 1);
	nvme_init_directive_send(&cmd, TEST_NSID, doper, dtype, dspec,
		expected_data, data_len);
	err = nvme_submit_admin_passthru(test_hdl, &cmd, &result);
	end_mock_cmds();
	check(err == 0, "returned error %d", err);
	check(result == 0, "returned wrong result");
	cmp(&data, &expected_data, sizeof(data), "incorrect data");
}

static void test_directive_send_id_endir(void)
{
	struct nvme_id_directives expected_id, id;
	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_directive_send,
		.nsid = TEST_NSID,
		.cdw10 = (sizeof(expected_id) >> 2) - 1,
		.cdw11 = NVME_DIRECTIVE_SEND_IDENTIFY_DOPER_ENDIR |
			 (NVME_DIRECTIVE_DTYPE_IDENTIFY << 8),
		.cdw12 = (!!true) | (NVME_DIRECTIVE_DTYPE_STREAMS << 1),
		.data_len = sizeof(id),
		.in_data = &id,
	};
	struct nvme_passthru_cmd cmd;
	int err;

	arbitrary(&expected_id, sizeof(expected_id));
	memcpy(&id, &expected_id, sizeof(expected_id));
	set_mock_admin_cmds(&mock_admin_cmd, 1);
	nvme_init_directive_send_id_endir(&cmd, TEST_NSID, true,
		NVME_DIRECTIVE_DTYPE_STREAMS, &id);
	err = nvme_submit_admin_passthru(test_hdl, &cmd, NULL);
	end_mock_cmds();
	check(err == 0, "returned error %d", err);
	cmp(&id, &expected_id, sizeof(id), "incorrect id");
}

static void test_directive_send_stream_release_identifier(void)
{
	__u16 stream_id = 0x1234;
	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_directive_send,
		.nsid = TEST_NSID,
		.cdw11 = NVME_DIRECTIVE_SEND_STREAMS_DOPER_RELEASE_IDENTIFIER |
			 (NVME_DIRECTIVE_DTYPE_STREAMS << 8) |
			 (stream_id << 16),
	};
	struct nvme_passthru_cmd cmd;
	int err;

	set_mock_admin_cmds(&mock_admin_cmd, 1);
	nvme_init_directive_send_stream_release_identifier(&cmd, TEST_NSID,
		stream_id);
	err = nvme_submit_admin_passthru(test_hdl, &cmd, NULL);
	end_mock_cmds();
	check(err == 0, "returned error %d", err);
}

static void test_directive_send_stream_release_resource(void)
{
	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_directive_send,
		.nsid = TEST_NSID,
		.cdw11 = NVME_DIRECTIVE_SEND_STREAMS_DOPER_RELEASE_RESOURCE |
			 (NVME_DIRECTIVE_DTYPE_STREAMS << 8),
	};
	struct nvme_passthru_cmd cmd;
	int err;

	set_mock_admin_cmds(&mock_admin_cmd, 1);
	nvme_init_directive_send_stream_release_resource(&cmd, TEST_NSID);
	err = nvme_submit_admin_passthru(test_hdl, &cmd, NULL);
	end_mock_cmds();
	check(err == 0, "returned error %d", err);
}

static void test_directive_recv(void)
{
	enum nvme_directive_receive_doper doper = NVME_DIRECTIVE_RECEIVE_STREAMS_DOPER_PARAM;
	enum nvme_directive_dtype dtype = NVME_DIRECTIVE_DTYPE_STREAMS;
 	__u8 expected_data[8], data[8];
	__u32 data_len = sizeof(data);
	__u16 dspec = 0x0;
	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_directive_recv,
		.nsid = TEST_NSID,
		.cdw10 = data_len ? (data_len >> 2) - 1 : 0,
		.cdw11 = doper | (dtype << 8) | (dspec << 16),
		.data_len = sizeof(expected_data),
		.out_data = &expected_data,
	};
	struct nvme_passthru_cmd cmd;
	uint32_t result = 0;
	int err;

	arbitrary(&expected_data, sizeof(expected_data));
	set_mock_admin_cmds(&mock_admin_cmd, 1);
	nvme_init_directive_recv(&cmd, TEST_NSID, doper, dtype, dspec,
		data, data_len);
	err = nvme_submit_admin_passthru(test_hdl, &cmd, &result);
	end_mock_cmds();
	check(err == 0, "returned error %d", err);
	check(result == 0, "returned wrong result");
	cmp(&data, &expected_data, sizeof(data), "incorrect data");
}

static void test_directive_recv_identify_parameters(void)
{
	struct nvme_id_directives expected_id, id;
	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_directive_recv,
		.nsid = TEST_NSID,
		.cdw10 = (sizeof(expected_id) >> 2) - 1,
		.cdw11 = NVME_DIRECTIVE_RECEIVE_IDENTIFY_DOPER_PARAM |
			 (NVME_DIRECTIVE_DTYPE_IDENTIFY << 8),
		.data_len = sizeof(expected_id),
		.out_data = &expected_id,
	};
	struct nvme_passthru_cmd cmd;
	int err;

	arbitrary(&expected_id, sizeof(expected_id));
	set_mock_admin_cmds(&mock_admin_cmd, 1);
	nvme_init_directive_recv_identify_parameters(&cmd, TEST_NSID, &id);
	err = nvme_submit_admin_passthru(test_hdl, &cmd, NULL);
	end_mock_cmds();
	check(err == 0, "returned error %d", err);
	cmp(&id, &expected_id, sizeof(id), "incorrect id");
}

static void test_directive_recv_stream_parameters(void)
{
	struct nvme_streams_directive_params expected_params, params;
	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_directive_recv,
		.nsid = TEST_NSID,
		.cdw10 = (sizeof(expected_params) >> 2) - 1,
		.cdw11 = NVME_DIRECTIVE_RECEIVE_STREAMS_DOPER_PARAM |
			 (NVME_DIRECTIVE_DTYPE_STREAMS << 8),
		.data_len = sizeof(expected_params),
		.out_data = &expected_params,
	};
	struct nvme_passthru_cmd cmd;
	int err;

	arbitrary(&expected_params, sizeof(expected_params));
	set_mock_admin_cmds(&mock_admin_cmd, 1);
	nvme_init_directive_recv_stream_parameters(&cmd, TEST_NSID, &params);
	err = nvme_submit_admin_passthru(test_hdl, &cmd, NULL);
	end_mock_cmds();
	check(err == 0, "returned error %d", err);
	cmp(&params, &expected_params, sizeof(params), "incorrect params");
}

static void test_directive_recv_stream_status(void)
{
	__u8 nr_entries = 3;
	uint32_t stream_status_size =
		sizeof(struct nvme_streams_directive_status) +
		nr_entries * sizeof(__le16);

	_cleanup_free_ struct nvme_streams_directive_status *expected_status =
		NULL;
	_cleanup_free_ struct nvme_streams_directive_status *status = NULL;

	status = malloc(stream_status_size);
	check(status, "status: ENOMEM");
	expected_status = malloc(stream_status_size);
	check(expected_status, "expected_status: ENOMEM");

	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_directive_recv,
		.nsid = TEST_NSID,
		.cdw10 = (stream_status_size >> 2) - 1,
		.cdw11 = NVME_DIRECTIVE_RECEIVE_STREAMS_DOPER_STATUS |
			 (NVME_DIRECTIVE_DTYPE_STREAMS << 8),
		.data_len = stream_status_size,
		.out_data = expected_status,
	};
	struct nvme_passthru_cmd cmd;
	int err;

	arbitrary(expected_status, stream_status_size);
	set_mock_admin_cmds(&mock_admin_cmd, 1);
	nvme_init_directive_recv_stream_status(&cmd, TEST_NSID, nr_entries,
		status);
	err = nvme_submit_admin_passthru(test_hdl, &cmd, NULL);
	end_mock_cmds();
	check(err == 0, "returned error %d", err);
	cmp(status, expected_status, stream_status_size, "incorrect status");
}

static void test_directive_recv_stream_allocate(void)
{
	__u32 expected_result = 0x45, result = 0;
	__u16 nsr = 0x67;
	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_directive_recv,
		.nsid = TEST_NSID,
		.cdw11 = NVME_DIRECTIVE_RECEIVE_STREAMS_DOPER_RESOURCE |
			 (NVME_DIRECTIVE_DTYPE_STREAMS << 8),
		.cdw12 = nsr,
		.result = expected_result,
	};
	struct nvme_passthru_cmd cmd;
	int err;

	set_mock_admin_cmds(&mock_admin_cmd, 1);
	nvme_init_directive_recv_stream_allocate(&cmd, TEST_NSID, nsr);
	err = nvme_submit_admin_passthru(test_hdl, &cmd, &result);
	end_mock_cmds();
	check(err == 0, "returned error %d", err);
	check(result == expected_result, "wrong result");
}

void test_capacity_mgmt(void)
{
	__u32 expected_result = 0x45, result = 0;
	__u16 elid = 0x12;
	__u64 cap = 0x0000567800001234;
	__u8 op = 0x3;
	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_capacity_mgmt,
		.nsid = NVME_NSID_NONE,
		.cdw10 = op | elid << 16,
		.cdw11 = cap & 0xffffffff,
		.cdw12 = cap >> 32,
		.result = expected_result,
	};
	struct nvme_passthru_cmd cmd;
	int err;

	set_mock_admin_cmds(&mock_admin_cmd, 1);
	nvme_init_capacity_mgmt(&cmd, op, elid, cap);
	err = nvme_submit_admin_passthru(test_hdl, &cmd, &result);
	end_mock_cmds();
	check(err == 0, "returned error %d", err);
	check(result == expected_result, "wrong result");
}

static void test_lockdown(void)
{
	__u32 expected_result = 0x45, result = 0;
	__u8 prhbt = !!true;
	__u8 uuidx = 0x34;
	__u8 ofi = 0x12;
	__u8 scp = 0x2;
	__u8 ifc = 0x1;
	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_lockdown,
		.cdw10 = ofi << 8 | (ifc & 0x3) << 5 |
			 (prhbt & 0x1) << 4 | (scp & 0xF),
		.cdw14 = uuidx & 0x3F,
		.result = expected_result,
	};
	struct nvme_passthru_cmd cmd;
	int err;

	set_mock_admin_cmds(&mock_admin_cmd, 1);
	nvme_init_lockdown(&cmd, scp, prhbt, ifc, ofi, uuidx);
	err = nvme_submit_admin_passthru(test_hdl, &cmd, &result);
	end_mock_cmds();
	check(err == 0, "returned error %d", err);
	check(result == expected_result, "wrong result");
}

static void test_sanitize_nvm(void)
{
	enum nvme_sanitize_sanact sanact =
		NVME_SANITIZE_SANACT_START_CRYPTO_ERASE;
	__u32 expected_result = 0x45, result = 0;
	__u32 ovrpat = 0x101010;
	bool oipbp = false;
	__u8 owpass = 0x2;
	bool ndas = true;
	bool emvs = false;
	bool ause = true;
	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_sanitize_nvm,
		.cdw10 = sanact | (ause << 3) | (owpass << 4) |
			 (oipbp << 8) | (ndas << 9),
		.cdw11 = ovrpat,
		.result = expected_result,
	};
	struct nvme_passthru_cmd cmd;
	int err;

	set_mock_admin_cmds(&mock_admin_cmd, 1);
	nvme_init_sanitize_nvm(&cmd, sanact, ause, owpass, oipbp, ndas,
		emvs, ovrpat);
	err = nvme_submit_admin_passthru(test_hdl, &cmd, &result);
	end_mock_cmds();
	check(err == 0, "returned error %d", err);
	check(result == expected_result, "wrong result");
}

static void test_dev_self_test(void)
{
	__u32 expected_result = 0x45, result = 0;
	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_dev_self_test,
		.nsid = TEST_NSID,
		.cdw10 = NVME_DST_STC_ABORT,
		.result = expected_result,
	};
	struct nvme_passthru_cmd cmd;
	int err;

	set_mock_admin_cmds(&mock_admin_cmd, 1);
	nvme_init_dev_self_test(&cmd, TEST_NSID, NVME_DST_STC_ABORT);
	err = nvme_submit_admin_passthru(test_hdl, &cmd, &result);
	end_mock_cmds();
	check(err == 0, "returned error %d", err);
	check(result == expected_result, "wrong result");
}

static void test_virtual_mgmt(void)
{
	enum nvme_virt_mgmt_act act = NVME_VIRT_MGMT_ACT_ASSIGN_SEC_CTRL;
	enum nvme_virt_mgmt_rt rt = NVME_VIRT_MGMT_RT_VI_RESOURCE;
	__u32 expected_result = 0x45, result = 0;
	__u16 cntlid = 0x0;
	__u16 nr = 0xff;
	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_virtual_mgmt,
		.cdw10 = act | (rt << 8) | (cntlid << 16),
		.cdw11 = nr,
		.result = expected_result,
	};
	struct nvme_passthru_cmd cmd;
	int err;

	set_mock_admin_cmds(&mock_admin_cmd, 1);
	nvme_init_virtual_mgmt(&cmd, act, rt, cntlid, nr);
	err = nvme_submit_admin_passthru(test_hdl, &cmd, &result);
	end_mock_cmds();
	check(err == 0, "returned error %d", err);
	check(result == expected_result, "wrong result");
}

static void test_flush(void)
{
	struct mock_cmd mock_io_cmd = {
		.opcode = nvme_cmd_flush,
		.nsid = TEST_NSID,
	};

	int err;

	set_mock_io_cmds(&mock_io_cmd, 1);
	err = nvme_flush(test_hdl, TEST_NSID);
	end_mock_cmds();
	check(err == 0, "returned error %d", err);
}

static void test_read(void)
{
	__u8 expected_data[512], data[512] = {};
	__u32 result = 0;
	__u64 slba = 0xffffffffff;
	__u16 nlb = 0x3;
	__u16 control = NVME_IO_FUA;
	__u8 dsm = NVME_IO_DSM_LATENCY_LOW;
	__u16 apptag = 0x12;
	__u16 appmask = 0x34;
	struct mock_cmd mock_io_cmd = {
		.opcode = nvme_cmd_read,
		.nsid = TEST_NSID,
		.cdw10 = slba & 0xffffffff,
		.cdw11 = slba >> 32,
		.cdw12 = nlb | (control << 16),
		.cdw13 = dsm,
		.cdw15 = apptag | (appmask << 16),
		.data_len = sizeof(expected_data),
		.out_data = &expected_data,
	};
	struct nvme_passthru_cmd cmd;
	int err;

	arbitrary(&expected_data, sizeof(expected_data));
	set_mock_io_cmds(&mock_io_cmd, 1);
	nvme_init_read(&cmd, TEST_NSID, slba, nlb, control, dsm, 0,
		data, sizeof(data), NULL, 0);
	nvme_init_app_tag((struct nvme_passthru_cmd64 *)&cmd, apptag, appmask);
	err = nvme_submit_io_passthru(test_hdl, &cmd, &result);
	end_mock_cmds();
	check(err == 0, "returned error %d", err);
	check(result == 0, "returned result %u", result);
}

static void test_write(void)
{
	__u8 expected_data[512];
	__u32 result = 0;
	__u64 slba = 0xfffffffabcde;
	__u16 nlb = 0x5;
	__u16 control = NVME_IO_FUA;
	__u8 dsm = NVME_IO_DSM_COMPRESSED;
	__u16 dspec = 0xa;
	__u16 apptag = 0x59;
	__u16 appmask = 0x94;
	struct mock_cmd mock_io_cmd = {
		.opcode = nvme_cmd_write,
		.nsid = TEST_NSID,
		.cdw10 = slba & 0xffffffff,
		.cdw11 = slba >> 32,
		.cdw12 = nlb | (control << 16),
		.cdw13 = dsm | (dspec << 16),
		.cdw15 = apptag | (appmask << 16),
		.data_len = sizeof(expected_data),
		.in_data = &expected_data,
	};
	struct nvme_passthru_cmd cmd;
	int err;

	arbitrary(&expected_data, sizeof(expected_data));
	set_mock_io_cmds(&mock_io_cmd, 1);
	nvme_init_write(&cmd, TEST_NSID, slba, nlb, control, dspec, dsm, 0,
		expected_data, sizeof(expected_data), NULL, 0);
	nvme_init_app_tag((struct nvme_passthru_cmd64 *)&cmd, apptag, appmask);
	err = nvme_submit_io_passthru(test_hdl, &cmd, &result);
	end_mock_cmds();
	check(err == 0, "returned error %d", err);
	check(result == 0, "returned result %u", result);
}

static void test_compare(void)
{
	__u8 expected_data[512], data[512] = {};
	__u32 result = 0;
	__u64 slba = 0xabcde;
	__u16 nlb = 0x0;
	__u16 control = NVME_IO_LR;
	__u16 cev = 0;
	__u16 apptag = 0x59;
	__u16 appmask = 0x94;
	struct mock_cmd mock_io_cmd = {
		.opcode = nvme_cmd_compare,
		.nsid = TEST_NSID,
		.cdw10 = slba & 0xffffffff,
		.cdw11 = slba >> 32,
		.cdw12 = nlb | (control << 16),
		.cdw15 = apptag | (appmask << 16),
		.data_len = sizeof(expected_data),
		.in_data = &expected_data,
	};
	struct nvme_passthru_cmd cmd;
	int err;

	arbitrary(&expected_data, sizeof(expected_data));
	memcpy(&data, &expected_data, sizeof(expected_data));
	set_mock_io_cmds(&mock_io_cmd, 1);
	nvme_init_compare(&cmd, TEST_NSID, slba, nlb, control, cev, data,
		sizeof(data), NULL, 0);
	nvme_init_app_tag((struct nvme_passthru_cmd64 *)&cmd, apptag, appmask);
	err = nvme_submit_io_passthru(test_hdl, &cmd, &result);
	end_mock_cmds();
	check(err == 0, "returned error %d", err);
	check(result == 0, "returned result %u", result);
}

static void test_write_zeros(void)
{
	__u32 result = 0;
	__u64 slba = 0x0;
	__u16 nlb = 0xffff;
	__u16 control = NVME_IO_LR;
	__u8 dsm = NVME_IO_DSM_FREQ_ONCE;
	__u16 cev = 0;
	__u16 dspec = 0xbb;
	__u16 apptag = 0xfa;
	__u16 appmask = 0x72;
	struct mock_cmd mock_io_cmd = {
		.opcode = nvme_cmd_write_zeroes,
		.nsid = TEST_NSID,
		.cdw10 = slba & 0xffffffff,
		.cdw11 = slba >> 32,
		.cdw12 = nlb | (control << 16),
		.cdw13 = dsm | (dspec << 16),
		.cdw15 = apptag | (appmask << 16),
	};
	struct nvme_passthru_cmd cmd;
	int err;

	set_mock_io_cmds(&mock_io_cmd, 1);
	nvme_init_write_zeros(&cmd, TEST_NSID, slba, nlb, control,
		dspec, dsm, cev);
	nvme_init_app_tag((struct nvme_passthru_cmd64 *)&cmd, apptag, appmask);
	err = nvme_submit_io_passthru(test_hdl, &cmd, &result);
	end_mock_cmds();
	check(err == 0, "returned error %d", err);
	check(result == 0, "returned result %u", result);
}

static void test_write_uncorrectable(void)
{
	__u32 result = 0;
	__u64 slba = 0x0;
	__u16 nlb = 0x0;
	__u16 control = 0x0;
	__u8 dsm = 0x0;
	__u16 dspec = 0x0;
	__u16 apptag = 0x0;
	__u16 appmask = 0x0;
	struct mock_cmd mock_io_cmd = {
		.opcode = nvme_cmd_write_uncor,
		.nsid = TEST_NSID,
		.cdw10 = slba & 0xffffffff,
		.cdw11 = slba >> 32,
		.cdw12 = nlb | (control << 16),
		.cdw13 = dsm | (dspec << 16),
		.cdw15 = apptag | (appmask << 16),
	};
	struct nvme_passthru_cmd cmd;
	int err;

	set_mock_io_cmds(&mock_io_cmd, 1);
	nvme_init_write_uncorrectable(&cmd, TEST_NSID, slba, nlb,
		control, dspec);
	nvme_init_app_tag((struct nvme_passthru_cmd64 *)&cmd, apptag, appmask);
	err = nvme_submit_io_passthru(test_hdl, &cmd, &result);
	end_mock_cmds();
	check(err == 0, "returned error %d", err);
	check(result == 0, "returned result %u", result);
}

static void test_verify(void)
{
	__u32 result = 0;
	__u64 slba = 0xffffffffffffffff;
	__u16 nlb = 0xffff;
	__u16 control = 0xffff;
	__u16 cev = 0;
	__u16 apptag = 0xffff;
	__u16 appmask = 0xffff;
	struct mock_cmd mock_io_cmd = {
		.opcode = nvme_cmd_verify,
		.nsid = TEST_NSID,
		.cdw10 = slba & 0xffffffff,
		.cdw11 = slba >> 32,
		.cdw12 = nlb | (control << 16),
		.cdw13 = cev,
		.cdw15 = apptag | (appmask << 16),
	};
	struct nvme_passthru_cmd cmd;
	int err;

	set_mock_io_cmds(&mock_io_cmd, 1);
	nvme_init_verify(&cmd, TEST_NSID, slba, nlb, control, cev,
		NULL, 0, NULL, 0);
	nvme_init_app_tag((struct nvme_passthru_cmd64 *)&cmd, apptag, appmask);
	err = nvme_submit_io_passthru(test_hdl, &cmd, &result);
	end_mock_cmds();
	check(err == 0, "returned error %d", err);
	check(result == 0, "returned result %u", result);
}

static void test_dsm(void)
{
	struct nvme_passthru_cmd cmd;
	__u32 result = 0;
	__u16 nr_ranges = 0xab;
	int dsm_size = sizeof(struct nvme_dsm_range) * nr_ranges;

	_cleanup_free_ struct nvme_dsm_range *dsm = NULL;

	dsm = malloc(dsm_size);
	check(dsm, "dsm: ENOMEM");

	struct mock_cmd mock_io_cmd = {
		.opcode = nvme_cmd_dsm,
		.nsid = TEST_NSID,
		.cdw10 = nr_ranges - 1,
		.cdw11 = NVME_DSMGMT_AD,
		.data_len = dsm_size,
		.in_data = dsm,
	};

	int err;

	arbitrary(dsm, dsm_size);
	set_mock_io_cmds(&mock_io_cmd, 1);
	nvme_init_dsm(&cmd, TEST_NSID, nr_ranges - 1, 0, 0, 1, dsm, dsm_size);
	err = nvme_submit_io_passthru(test_hdl, &cmd, &result);
	end_mock_cmds();
	check(err == 0, "returned error %d", err);
	check(result == 0, "returned result %u", result);
}

static void test_copy(void)
{
	__u32 result = 0;
	__u16 nr = 0x12;
	int copy_size = sizeof(struct nvme_copy_range) * nr;

	_cleanup_free_ struct nvme_copy_range *copy = NULL;

	copy = malloc(copy_size);
	check(copy, "copy: ENOMEM");

	struct nvme_copy_args args = {
		.sdlba = 0xfffff,
		.result = &result,
		.copy = copy,
		.args_size = sizeof(args),
		.nsid = TEST_NSID,
		.nr = nr,
		.format = 0xf,
	};

	struct mock_cmd mock_io_cmd = {
		.opcode = nvme_cmd_copy,
		.nsid = TEST_NSID,
		.cdw10 = args.sdlba & 0xffffffff,
		.cdw11 = args.sdlba >> 32,
		.cdw12 = ((args.nr - 1) & 0xff) | ((args.format & 0xf) << 8) |
			 ((args.prinfor & 0xf) << 12) |
			 ((args.dtype & 0xf) << 20) |
			 ((args.prinfow & 0xf) << 26) |
			 ((args.fua & 0x1) << 30) | ((args.lr & 0x1) << 31),
		.data_len = args.nr * sizeof(struct nvme_copy_range),
		.in_data = args.copy,
	};

	int err;

	set_mock_io_cmds(&mock_io_cmd, 1);
	err = nvme_copy(test_hdl, &args);
	end_mock_cmds();
	check(err == 0, "returned error %d", err);
	check(result == 0, "returned result %u", result);
}

static void test_resv_acquire(void)
{
	enum nvme_resv_rtype rtype = NVME_RESERVATION_RTYPE_EAAR;
	enum nvme_resv_racqa racqa = NVME_RESERVATION_RACQA_PREEMPT;
	__le64 expected_payload[2] = { htole64(1), htole64(2) };
	__le64 payload[2];
	bool iekey = true;
	__u32 result = 0;
	struct mock_cmd mock_io_cmd = {
		.opcode = nvme_cmd_resv_acquire,
		.nsid = TEST_NSID,
		.cdw10 = (racqa & 0x7) | (iekey ? 1 << 3 : 0) |
			 (rtype << 8),
		.data_len = sizeof(expected_payload),
		.in_data = expected_payload,
	};
	struct nvme_passthru_cmd cmd;
	int err;

	set_mock_io_cmds(&mock_io_cmd, 1);
	nvme_init_resv_acquire(&cmd, TEST_NSID, racqa, iekey, false, rtype,
		1, 2, payload);
	err = nvme_submit_io_passthru(test_hdl, &cmd, &result);
	end_mock_cmds();
	check(err == 0, "returned error %d", err);
	check(result == 0, "returned result %u", result);
}

static void test_resv_register(void)
{
	enum nvme_resv_rrega rrega = NVME_RESERVATION_RREGA_UNREGISTER_KEY;
	enum nvme_resv_cptpl cptpl = NVME_RESERVATION_CPTPL_PERSIST;
	__le64 expected_payload[2] = { 0xffffffffffffffff, 0 };
	__le64 payload[2];
	bool iekey = true;
	__u32 result = 0;
	struct mock_cmd mock_io_cmd = {
		.opcode = nvme_cmd_resv_register,
		.nsid = TEST_NSID,
		.cdw10 = (rrega & 0x7) | (iekey ? 1 << 3 : 0) |
			 (cptpl << 30),
		.data_len = sizeof(expected_payload),
		.in_data = expected_payload,
	};
	struct nvme_passthru_cmd cmd;
	int err;

	set_mock_io_cmds(&mock_io_cmd, 1);
	nvme_init_resv_register(&cmd, TEST_NSID, rrega, iekey, false, cptpl,
		0xffffffffffffffff, 0, payload);
	err = nvme_submit_io_passthru(test_hdl, &cmd, &result);
	end_mock_cmds();
	check(err == 0, "returned error %d", err);
	check(result == 0, "returned result %u", result);
}

static void test_resv_release(void)
{
	enum nvme_resv_rtype rtype = NVME_RESERVATION_RTYPE_WE;
	enum nvme_resv_rrela rrela = NVME_RESERVATION_RRELA_RELEASE;
	__le64 expected_payload[1] = { 0xffffffffffffffff };
	__le64 payload[1];
	bool iekey = true;
	__u32 result = 0;
	struct mock_cmd mock_io_cmd = {
		.opcode = nvme_cmd_resv_release,
		.nsid = TEST_NSID,
		.cdw10 = (rrela & 0x7) | (iekey ? 1 << 3 : 0) |
			 (rtype << 8),
		.data_len = sizeof(expected_payload),
		.in_data = expected_payload,
	};
	struct nvme_passthru_cmd cmd;
	int err;

	set_mock_io_cmds(&mock_io_cmd, 1);
	nvme_init_resv_release(&cmd, TEST_NSID, rrela, iekey, false, rtype,
		0xffffffffffffffff, payload);
	err = nvme_submit_io_passthru(test_hdl, &cmd, &result);
	end_mock_cmds();
	check(err == 0, "returned error %d", err);
	check(result == 0, "returned result %u", result);
}

static void test_resv_report(void)
{
	struct nvme_resv_status expected_status, status = {};
	__u32 len = sizeof(status);
	__u32 result = 0;
	bool eds = false;
	bool disnsrs = true;
	struct mock_cmd mock_io_cmd = {
		.opcode = nvme_cmd_resv_report,
		.nsid = TEST_NSID,
		.cdw10 = (len >> 2) - 1,
		.cdw11 = eds | disnsrs << 1,
		.data_len = len,
		.out_data = &expected_status,
	};
	struct nvme_passthru_cmd cmd;
	int err;

	arbitrary(&expected_status, sizeof(expected_status));
	set_mock_io_cmds(&mock_io_cmd, 1);
	nvme_init_resv_report(&cmd, TEST_NSID, eds, disnsrs, &status, len);
	err = nvme_submit_io_passthru(test_hdl, &cmd, &result);
	end_mock_cmds();
	check(err == 0, "returned error %d", err);
	check(result == 0, "returned result %u", result);
	cmp(&status, &expected_status, sizeof(status), "incorrect status");
}

static void test_io_mgmt_recv(void)
{
	__u8 expected_data[8], data[8] = {};
	__u32 data_len = sizeof(data);
	__u16 mos = 0x1;
	__u8 mo = 0x2;
	struct mock_cmd mock_io_cmd = {
		.opcode = nvme_cmd_io_mgmt_recv,
		.nsid = TEST_NSID,
		.cdw10 = mo | (mos << 16),
		.cdw11 = (data_len >> 2) - 1,
		.data_len = data_len,
		.out_data = &expected_data,
	};
	struct nvme_passthru_cmd cmd;
	int err;

	arbitrary(&expected_data, sizeof(expected_data));
	set_mock_io_cmds(&mock_io_cmd, 1);
	nvme_init_io_mgmt_recv(&cmd, TEST_NSID, mo, mos, data, data_len);
	err = nvme_submit_io_passthru(test_hdl, &cmd, NULL);
	end_mock_cmds();
	check(err == 0, "returned error %d", err);
	cmp(&data, &expected_data, sizeof(data), "incorrect data");
}

static void test_io_mgmt_send(void)
{
	__u8 expected_data[8], data[8] = {};
	__u32 data_len = sizeof(data);
	__u16 mos = 0x1;
	__u8 mo = 0x2;
	struct mock_cmd mock_io_cmd = {
		.opcode = nvme_cmd_io_mgmt_send,
		.nsid = TEST_NSID,
		.cdw10 = mo | (mos << 16),
		.data_len = data_len,
		.in_data = &expected_data,
	};
	struct nvme_passthru_cmd cmd;
	int err;

	arbitrary(&expected_data, sizeof(expected_data));
	memcpy(&data, &expected_data, sizeof(expected_data));
	set_mock_io_cmds(&mock_io_cmd, 1);
	nvme_init_io_mgmt_send(&cmd, TEST_NSID, mo, mos, data, data_len);
	err = nvme_submit_io_passthru(test_hdl, &cmd, NULL);
	end_mock_cmds();
	check(err == 0, "returned error %d", err);
	cmp(&data, &expected_data, sizeof(data), "incorrect data");
}

static void test_fdp_reclaim_unit_handle_status(void)
{
	__u8 expected_data[8], data[8] = {};
	__u32 data_len = sizeof(data);
	struct mock_cmd mock_io_cmd = {
		.opcode = nvme_cmd_io_mgmt_recv,
		.nsid = TEST_NSID,
		.cdw10 = NVME_IO_MGMT_RECV_RUH_STATUS,
		.cdw11 = (data_len >> 2) - 1,
		.data_len = data_len,
		.out_data = &expected_data,
	};
	struct nvme_passthru_cmd cmd;
	int err;

	arbitrary(&expected_data, sizeof(expected_data));
	set_mock_io_cmds(&mock_io_cmd, 1);
	nvme_init_fdp_reclaim_unit_handle_status(&cmd, TEST_NSID,
		&data, data_len);
	err = nvme_submit_io_passthru(test_hdl, &cmd, NULL);
	end_mock_cmds();
	check(err == 0, "returned error %d", err);
	cmp(&data, &expected_data, sizeof(data), "incorrect data");
}

static void test_fdp_reclaim_unit_handle_update(void)
{
	__u16 pids;
	unsigned int npids = 1;
	struct mock_cmd mock_io_cmd = {
		.opcode = nvme_cmd_io_mgmt_send,
		.nsid = TEST_NSID,
		.cdw10 = NVME_IO_MGMT_SEND_RUH_UPDATE | ((npids - 1) << 16),
		.data_len = npids * sizeof(__u16),
		.in_data = &pids,
	};
	struct nvme_passthru_cmd cmd;
	int err;

	arbitrary(&pids, sizeof(pids));
	set_mock_io_cmds(&mock_io_cmd, 1);
	nvme_init_fdp_reclaim_unit_handle_update(&cmd, TEST_NSID, &pids, npids);
	err = nvme_submit_io_passthru(test_hdl, &cmd, NULL);
	end_mock_cmds();
	check(err == 0, "returned error %d", err);
}

static void test_dim_send(void)
{
	__u8 expected_data[8], data[8] = {};
	__u32 data_len = sizeof(data);
	__u32 result = 0;
	__u8 tas = 0xf;
	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_discovery_info_mgmt,
		.cdw10 = tas,
		.data_len =data_len,
		.in_data = &expected_data,
	};
	struct nvme_passthru_cmd cmd;
	int err;

	arbitrary(&expected_data, sizeof(expected_data));
	memcpy(&data, &expected_data, sizeof(expected_data));
	set_mock_admin_cmds(&mock_admin_cmd, 1);
	nvme_init_dim_send(&cmd, tas, data, data_len);
	err = nvme_submit_admin_passthru(test_hdl, &cmd, &result);
	end_mock_cmds();
	check(err == 0, "returned error %d", err);
	check(result == 0, "returned result %u", result);
	cmp(&data, &expected_data, sizeof(data), "incorrect data");
}

static void test_lm_cdq_delete(void)
{
	__u32 result = 0;
	__u8 expected_data[8], data[8] = {};
	__u16 mos = 0x1;
	__u16 cdqid = 0x3;
	__u8 sel = NVME_LM_SEL_DELETE_CDQ;
	__u32 sz = 0;
	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_ctrl_data_queue,
		.cdw10 = sel | (mos << 16),
		.cdw11 = cdqid,
		.cdw12 = sz,
		.data_len = 0,
		.in_data = &expected_data,
	};
	struct nvme_passthru_cmd cmd;
	int err;

	arbitrary(&expected_data, sizeof(expected_data));
	memcpy(&data, &expected_data, sizeof(expected_data));
	set_mock_admin_cmds(&mock_admin_cmd, 1);
	nvme_init_lm_cdq_delete(&cmd, mos, cdqid);
	err = nvme_submit_admin_passthru(test_hdl, &cmd, &result);
	end_mock_cmds();
	check(err == 0, "returned error %d", err);
	check(result == 0, "returned result %u", result);
	cmp(&data, &expected_data, sizeof(data), "incorrect data");
}

static void test_lm_track_send(void)
{
	__u8 sel = NVME_LM_SEL_DELETE_CDQ;
	__u16 cdqid = 0x3;
	__u32 result = 0;
	__u16 mos = 0x1;
	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_track_send,
		.cdw10 = sel | (mos << 16),
		.cdw11 = cdqid,
	};
	struct nvme_passthru_cmd cmd;
	int err;

	set_mock_admin_cmds(&mock_admin_cmd, 1);
	nvme_init_lm_track_send(&cmd, sel, mos, cdqid);
	err = nvme_submit_admin_passthru(test_hdl, &cmd, &result);
	end_mock_cmds();
	check(err == 0, "returned error %d", err);
	check(result == 0, "returned result %u", result);
}

static void test_lm_migration_send(void)
{
	__u32 expected_data[8], data[8] = {};
	__u8 sel = NVME_LM_SEL_RESUME;
	__u64 offset = 0xffffffffff;
	__u32 numd = 8;
	__u16 cntlid = 0x2;
	__u32 result = 0;
	__u16 mos = 0x1;
	__u8 uidx = 0x4;
	__u8 stype = 0x1;
	__u8 csvi = 0x2;
	__u16 csuuidi = 0x13;
	bool dudmq = false;
	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_migration_send,
		.cdw10 = sel | (mos << 16),
		.cdw11 = cntlid,
		.cdw12 = (__u32)offset,
		.cdw13 = (__u32)(offset >> 32),
		.cdw14 = uidx,
		.cdw15 = numd,
		.data_len = numd << 2,
		.in_data = &expected_data,
	};
	struct nvme_passthru_cmd cmd;
	int err;

	arbitrary(&expected_data, sizeof(expected_data));
	memcpy(&data, &expected_data, sizeof(expected_data));
	set_mock_admin_cmds(&mock_admin_cmd, 1);
	nvme_init_lm_migration_send(&cmd, sel, mos, cntlid, stype, dudmq,
		csvi, csuuidi, offset, uidx, &data, sizeof(data));
	err = nvme_submit_admin_passthru(test_hdl, &cmd, &result);
	end_mock_cmds();
	check(err == 0, "returned error %d", err);
	check(result == 0, "returned result %u", result);
	cmp(&data, &expected_data, sizeof(data), "incorrect data");
}

static void test_lm_migration_recv(void)
{
	__u8 sel = NVME_LM_SEL_GET_CONTROLLER_STATE;
	__u32 expected_data[8], data[8] = {};
	__u64 offset = 0xffffffffff;
	__u16 csuuidi = 0x3;
	__u32 numd = 8 - 1;
	__u16 cntlid = 0x2;
	__u8 csuidxp = 0x5;
	__u32 result = 0;
	__u16 mos = 0x1;
	__u8 uidx = 0x4;
	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_migration_receive,
		.cdw10 = sel | (mos << 16),
		.cdw11 = cntlid | (csuuidi << 16) |
			 (csuidxp << 24),
		.cdw12 = (__u32)offset,
		.cdw13 = (__u32)(offset >> 32),
		.cdw14 = uidx,
		.cdw15 = numd,
		.data_len = (numd + 1) << 2,
		.out_data = &expected_data,
	};
	struct nvme_passthru_cmd cmd;
	int err;

	arbitrary(&expected_data, sizeof(expected_data));
	set_mock_admin_cmds(&mock_admin_cmd, 1);
	nvme_init_lm_migration_recv(&cmd, offset, mos, cntlid, csuuidi, sel,
		uidx, csuidxp, data, sizeof(data));
	err = nvme_submit_admin_passthru(test_hdl, &cmd, &result);
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

	RUN_TEST(format_nvm);
	RUN_TEST(ns_mgmt);
	RUN_TEST(ns_mgmt_create);
	RUN_TEST(ns_mgmt_delete);
	RUN_TEST(get_property);
	RUN_TEST(set_property);
	RUN_TEST(ns_attach);
	RUN_TEST(ns_attach_ctrls);
	RUN_TEST(ns_detach_ctrls);
	RUN_TEST(fw_download);
	RUN_TEST(fw_commit);
	RUN_TEST(security_send);
	RUN_TEST(security_receive);
	RUN_TEST(get_lba_status);
	RUN_TEST(directive_send);
	RUN_TEST(directive_send_id_endir);
	RUN_TEST(directive_send_stream_release_identifier);
	RUN_TEST(directive_send_stream_release_resource);
	RUN_TEST(directive_recv);
	RUN_TEST(directive_recv_identify_parameters);
	RUN_TEST(directive_recv_stream_parameters);
	RUN_TEST(directive_recv_stream_status);
	RUN_TEST(directive_recv_stream_allocate);
	RUN_TEST(capacity_mgmt);
	RUN_TEST(lockdown);
	RUN_TEST(sanitize_nvm);
	RUN_TEST(dev_self_test);
	RUN_TEST(virtual_mgmt);
	RUN_TEST(flush);
	RUN_TEST(read);
	RUN_TEST(write);
	RUN_TEST(compare);
	RUN_TEST(write_zeros);
	RUN_TEST(write_uncorrectable);
	RUN_TEST(verify);
	RUN_TEST(dsm);
	RUN_TEST(copy);
	RUN_TEST(resv_acquire);
	RUN_TEST(resv_register);
	RUN_TEST(resv_release);
	RUN_TEST(resv_report);
	RUN_TEST(io_mgmt_recv);
	RUN_TEST(io_mgmt_send);
	RUN_TEST(fdp_reclaim_unit_handle_status);
	RUN_TEST(fdp_reclaim_unit_handle_update);
	RUN_TEST(dim_send);
	RUN_TEST(lm_cdq_delete);
	RUN_TEST(lm_track_send);
	RUN_TEST(lm_migration_send);
	RUN_TEST(lm_migration_recv);

	nvme_free_global_ctx(ctx);
}
