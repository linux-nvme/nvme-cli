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

static void test_format_nvm(void)
{
	__u32 result = 0;
	struct nvme_format_nvm_args args = {
		.result = &result,
		.args_size = sizeof(args),
		.fd = TEST_FD,
		.nsid = TEST_NSID,
		.mset = NVME_FORMAT_MSET_EXTENDED,
		.pi = NVME_FORMAT_PI_TYPE2,
		.pil = NVME_FORMAT_PIL_FIRST,
		.ses = NVME_FORMAT_SES_USER_DATA_ERASE,
		.lbaf = 0xF,
		.lbafu = 0x1,
	};

	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_format_nvm,
		.nsid = TEST_NSID,
		.cdw10 = args.lbaf | (args.mset << 4) | (args.pi << 5) |
			 (args.pil << 8) | (args.ses << 9) | (args.lbafu << 12),
		.result = 0,
	};

	int err;

	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_format_nvm(&args);
	end_mock_cmds();
	check(err == 0, "returned error %d, errno %m", err);
	check(result == 0, "returned result %u", result);
}

static void test_ns_mgmt(void)
{
	struct nvme_ns_mgmt_host_sw_specified expected_data, data = {};
	__u32 result = 0;
	struct nvme_ns_mgmt_args args = {
		.result = &result,
		.ns = NULL,
		.args_size = sizeof(args),
		.fd = TEST_FD,
		.nsid = TEST_NSID,
		.sel = NVME_NS_MGMT_SEL_CREATE,
		.csi = TEST_CSI,
		.data = &data,
	};

	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_ns_mgmt,
		.nsid = TEST_NSID,
		.cdw10 = args.sel,
		.cdw11 = args.csi << 24,
		.result = 0,
		.data_len = sizeof(expected_data),
		.out_data = &expected_data,
	};

	int err;

	arbitrary(&expected_data, sizeof(expected_data));
	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_ns_mgmt(&args);
	end_mock_cmds();
	check(err == 0, "returned error %d, errno %m", err);
	check(result == 0, "returned result %u", result);
	cmp(&data, &expected_data, sizeof(data), "incorrect data");
}

static void test_ns_mgmt_create(void)
{
	struct nvme_ns_mgmt_host_sw_specified expected_data, data = {};
	__u32 result = 0;
	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_ns_mgmt,
		.nsid = NVME_NSID_NONE,
		.cdw10 = NVME_NS_MGMT_SEL_CREATE,
		.cdw11 = NVME_CSI_ZNS << 24,
		.result = TEST_NSID,
		.data_len = sizeof(expected_data),
		.out_data = &expected_data,
	};

	int err;

	arbitrary(&expected_data, sizeof(expected_data));
	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_ns_mgmt_create(TEST_FD, NULL, &result, 0, NVME_CSI_ZNS,
				  &data);
	end_mock_cmds();
	check(err == 0, "returned error %d, errno %m", err);
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

	int err;

	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_ns_mgmt_delete(TEST_FD, TEST_NSID);
	end_mock_cmds();
	check(err == 0, "returned error %d, errno %m", err);
}

static void test_get_property(void)
{
	__u64 expected_result, result;
	struct nvme_get_property_args args = {
		.value = &result,
		.args_size = sizeof(args),
		.fd = TEST_FD,
		.offset = NVME_REG_ACQ,
	};

	arbitrary(&expected_result, sizeof(expected_result));

	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_fabrics,
		.nsid = nvme_fabrics_type_property_get,
		.cdw10 = !!true,
		.cdw11 = NVME_REG_ACQ,
		.result = expected_result,
	};

	int err;

	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_get_property(&args);
	end_mock_cmds();
	check(err == 0, "returned error %d, errno %m", err);
	check(result == expected_result, "returned wrong result");
}

static void test_set_property(void)
{
	__u64 value = 0xffffffff;
	__u32 result;
	struct nvme_set_property_args args = {
		.value = value,
		.result = &result,
		.args_size = sizeof(args),
		.fd = TEST_FD,
		.offset = NVME_REG_BPMBL,
	};

	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_fabrics,
		.nsid = nvme_fabrics_type_property_set,
		.cdw10 = !!true,
		.cdw11 = NVME_REG_BPMBL,
		.cdw12 = value & 0xffffffff,
		.cdw13 = value >> 32,
	};

	int err;

	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_set_property(&args);
	end_mock_cmds();
	check(err == 0, "returned error %d, errno %m", err);
	check(result == 0, "returned result %u", result);
}

static void test_ns_attach(void)
{
	__u32 result;
	struct nvme_ctrl_list expected_ctrlist, ctrlist;
	struct nvme_ns_attach_args args = {
		.result = &result,
		.ctrlist = &ctrlist,
		.args_size = sizeof(args),
		.fd = TEST_FD,
		.nsid = TEST_NSID,
		.sel = NVME_NS_ATTACH_SEL_CTRL_DEATTACH,
	};

	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_ns_attach,
		.nsid = TEST_NSID,
		.cdw10 = NVME_NS_ATTACH_SEL_CTRL_DEATTACH,
		.data_len = sizeof(expected_ctrlist),
		.out_data = &expected_ctrlist,
	};

	int err;

	arbitrary(&expected_ctrlist, sizeof(expected_ctrlist));
	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_ns_attach(&args);
	end_mock_cmds();
	check(err == 0, "returned error %d, errno %m", err);
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

	int err;

	arbitrary(&ctrlist, sizeof(ctrlist));
	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_ns_attach_ctrls(TEST_FD, TEST_NSID, &ctrlist);
	end_mock_cmds();
	check(err == 0, "returned error %d, errno %m", err);
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

	int err;

	arbitrary(&ctrlist, sizeof(ctrlist));
	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_ns_detach_ctrls(TEST_FD, TEST_NSID, &ctrlist);
	end_mock_cmds();
	check(err == 0, "returned error %d, errno %m", err);
}

static void test_fw_download(void)
{
	__u32 result = 0;
	__u8 expected_data[8], data[8];

	struct nvme_fw_download_args args = {
		.result = &result,
		.data = &expected_data,
		.args_size = sizeof(args),
		.fd = TEST_FD,
		.offset = 123,
		.data_len = sizeof(expected_data),
	};

	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_fw_download,
		.cdw10 = (args.data_len >> 2) - 1,
		.cdw11 = args.offset >> 2,
		.data_len = args.data_len,
		.in_data = &data,
	};

	int err;

	arbitrary(&expected_data, sizeof(expected_data));
	memcpy(&data, &expected_data, sizeof(expected_data));
	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_fw_download(&args);
	end_mock_cmds();
	check(err == 0, "returned error %d, errno %m", err);
	check(result == 0, "returned result %u", result);
}

static void test_fw_commit(void)
{
	__u32 result = 0;

	struct nvme_fw_commit_args args = {
		.result = &result,
		.args_size = sizeof(args),
		.fd = TEST_FD,
		.action = NVME_FW_COMMIT_CA_REPLACE_AND_ACTIVATE_IMMEDIATE,
		.slot = 0xf,
		.bpid = true,
	};

	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_fw_commit,
		.cdw10 = (!!args.bpid << 31) | (args.action << 3) | args.slot,
	};

	int err;

	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_fw_commit(&args);
	end_mock_cmds();
	check(err == 0, "returned error %d, errno %m", err);
	check(result == 0, "returned result %u", result);
}

static void test_security_send(void)
{
	__u8 expected_data[8], data[8];
	__u32 result = 0;

	struct nvme_security_send_args args = {
		.result = &result,
		.data = &expected_data,
		.args_size = sizeof(args),
		.fd = TEST_FD,
		.nsid = TEST_NSID,
		.tl = 0xffff,
		.data_len = sizeof(expected_data),
		.nssf = 0x1,
		.spsp0 = 0x1,
		.spsp1 = 0x1,
		.secp = 0xE9,
	};

	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_security_send,
		.nsid = TEST_NSID,
		.cdw10 = args.nssf | (args.spsp0 << 8) | (args.spsp1 << 16) |
			 (args.secp << 24),
		.cdw11 = args.tl,
		.data_len = args.data_len,
		.in_data = &data,
	};

	int err;

	arbitrary(&expected_data, sizeof(expected_data));
	memcpy(&data, &expected_data, sizeof(expected_data));
	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_security_send(&args);
	end_mock_cmds();
	check(err == 0, "returned error %d, errno %m", err);
	check(result == 0, "returned result %u", result);
	cmp(&data, &expected_data, sizeof(data), "incorrect data");
}

static void test_security_receive(void)
{
	__u8 expected_data[8], data[8];
	__u32 result = 0;

	struct nvme_security_receive_args args = {
		.result = &result,
		.data = &data,
		.args_size = sizeof(args),
		.fd = TEST_FD,
		.nsid = TEST_NSID,
		.al = 0xffff,
		.data_len = sizeof(data),
		.nssf = 0x1,
		.spsp0 = 0x1,
		.spsp1 = 0x1,
		.secp = 0xE9,
	};

	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_security_recv,
		.nsid = TEST_NSID,
		.cdw10 = args.nssf | (args.spsp0 << 8) | (args.spsp1 << 16) |
			 (args.secp << 24),
		.cdw11 = args.al,
		.data_len = args.data_len,
		.out_data = &expected_data,
	};

	int err;

	arbitrary(&expected_data, sizeof(expected_data));
	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_security_receive(&args);
	end_mock_cmds();
	check(err == 0, "returned error %d, errno %m", err);
	check(result == 0, "returned result %u", result);
	cmp(&data, &expected_data, sizeof(data), "incorrect data");
}

static void test_get_lba_status(void)
{
	__u32 result = 0;
	__u8 nlsd = 3;
	int lba_status_size = sizeof(struct nvme_lba_status) +
			      nlsd * sizeof(struct nvme_lba_status_desc);

	_cleanup_free_ struct nvme_lba_status *lbas = NULL;
	_cleanup_free_ struct nvme_lba_status *expected_lbas = NULL;

	lbas = malloc(lba_status_size);
	check(lbas, "lbas: ENOMEM");
	expected_lbas = malloc(lba_status_size);
	check(expected_lbas, "expected_lbas: ENOMEM");

	struct nvme_get_lba_status_args args = {
		.slba = 0x123456789,
		.result = &result,
		.lbas = lbas,
		.args_size = sizeof(args),
		.fd = TEST_FD,
		.nsid = TEST_NSID,
		.mndw = ((lba_status_size - 1) >> 2),
		.atype = 0x11,
		.rl = 0x42,
	};

	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_get_lba_status,
		.nsid = TEST_NSID,
		.cdw10 = args.slba & 0xffffffff,
		.cdw11 = args.slba >> 32,
		.cdw12 = args.mndw,
		.cdw13 = args.rl | (args.atype << 24),
		.data_len = (args.mndw + 1) << 2,
		.out_data = expected_lbas,
	};

	int err;

	arbitrary(expected_lbas, lba_status_size);
	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_get_lba_status(&args);
	end_mock_cmds();
	check(err == 0, "returned error %d, errno %m", err);
	check(result == 0, "returned wrong result");
	cmp(lbas, expected_lbas, lba_status_size, "incorrect lbas");
}

static void test_directive_send(void)
{
	__u8 expected_data[8], data[8];
	__u32 result = 0;

	struct nvme_directive_send_args args = {
		.result = &result,
		.data = &expected_data,
		.args_size = sizeof(args),
		.fd = TEST_FD,
		.nsid = TEST_NSID,
		.doper = NVME_DIRECTIVE_SEND_STREAMS_DOPER_RELEASE_RESOURCE,
		.dtype = NVME_DIRECTIVE_DTYPE_STREAMS,
		.cdw12 = 0xffff,
		.data_len = sizeof(expected_data),
		.dspec = 0x0,
	};

	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_directive_send,
		.nsid = TEST_NSID,
		.cdw10 = args.data_len ? (args.data_len >> 2) - 1 : 0,
		.cdw11 = args.doper | (args.dtype << 8) | (args.dspec << 16),
		.cdw12 = args.cdw12,
		.data_len = args.data_len,
		.in_data = &data,
	};

	int err;

	arbitrary(&expected_data, sizeof(expected_data));
	memcpy(&data, &expected_data, sizeof(expected_data));
	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_directive_send(&args);
	end_mock_cmds();
	check(err == 0, "returned error %d, errno %m", err);
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

	int err;

	arbitrary(&expected_id, sizeof(expected_id));
	memcpy(&id, &expected_id, sizeof(expected_id));
	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_directive_send_id_endir(TEST_FD, TEST_NSID, true,
					   NVME_DIRECTIVE_DTYPE_STREAMS, &id);
	end_mock_cmds();
	check(err == 0, "returned error %d, errno %m", err);
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

	int err;

	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_directive_send_stream_release_identifier(TEST_FD, TEST_NSID,
							    stream_id);
	end_mock_cmds();
	check(err == 0, "returned error %d, errno %m", err);
}

static void test_directive_send_stream_release_resource(void)
{
	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_directive_send,
		.nsid = TEST_NSID,
		.cdw11 = NVME_DIRECTIVE_SEND_STREAMS_DOPER_RELEASE_RESOURCE |
			 (NVME_DIRECTIVE_DTYPE_STREAMS << 8),
	};

	int err;

	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_directive_send_stream_release_resource(TEST_FD, TEST_NSID);
	end_mock_cmds();
	check(err == 0, "returned error %d, errno %m", err);
}

static void test_directive_recv(void)
{
	__u8 expected_data[8], data[8];
	__u32 result = 0;

	struct nvme_directive_recv_args args = {
		.result = &result,
		.data = &data,
		.args_size = sizeof(args),
		.fd = TEST_FD,
		.nsid = TEST_NSID,
		.doper = NVME_DIRECTIVE_RECEIVE_STREAMS_DOPER_PARAM,
		.dtype = NVME_DIRECTIVE_DTYPE_STREAMS,
		.cdw12 = 0xffff,
		.data_len = sizeof(data),
		.dspec = 0x0,
	};

	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_directive_recv,
		.nsid = TEST_NSID,
		.cdw10 = args.data_len ? (args.data_len >> 2) - 1 : 0,
		.cdw11 = args.doper | (args.dtype << 8) | (args.dspec << 16),
		.cdw12 = args.cdw12,
		.data_len = sizeof(expected_data),
		.out_data = &expected_data,
	};

	int err;

	arbitrary(&expected_data, sizeof(expected_data));
	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_directive_recv(&args);
	end_mock_cmds();
	check(err == 0, "returned error %d, errno %m", err);
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

	int err;

	arbitrary(&expected_id, sizeof(expected_id));
	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_directive_recv_identify_parameters(TEST_FD, TEST_NSID, &id);
	end_mock_cmds();
	check(err == 0, "returned error %d, errno %m", err);
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

	int err;

	arbitrary(&expected_params, sizeof(expected_params));
	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_directive_recv_stream_parameters(TEST_FD, TEST_NSID,
						    &params);
	end_mock_cmds();
	check(err == 0, "returned error %d, errno %m", err);
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

	int err;

	arbitrary(expected_status, stream_status_size);
	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_directive_recv_stream_status(TEST_FD, TEST_NSID, nr_entries,
						status);
	end_mock_cmds();
	check(err == 0, "returned error %d, errno %m", err);
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

	int err;

	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_directive_recv_stream_allocate(TEST_FD, TEST_NSID, nsr,
						  &result);
	end_mock_cmds();
	check(err == 0, "returned error %d, errno %m", err);
	check(result == expected_result, "wrong result");
}

static void test_capacity_mgmt(void)
{
	__u32 expected_result = 0x45, result = 0;

	struct nvme_capacity_mgmt_args args = {
		.result = &result,
		.args_size = sizeof(args),
		.fd = TEST_FD,
		.cdw11 = 0x1234,
		.cdw12 = 0x5678,
		.element_id = 0x12,
		.op = 0x3,
	};

	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_capacity_mgmt,
		.nsid = NVME_NSID_NONE,
		.cdw10 = args.op | args.element_id << 16,
		.cdw11 = args.cdw11,
		.cdw12 = args.cdw12,
		.result = expected_result,
	};

	int err;

	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_capacity_mgmt(&args);
	end_mock_cmds();
	check(err == 0, "returned error %d, errno %m", err);
	check(result == expected_result, "wrong result");
}

static void test_lockdown(void)
{
	__u32 expected_result = 0x45, result = 0;

	struct nvme_lockdown_args args = {
		.result = &result,
		.args_size = sizeof(args),
		.fd = TEST_FD,
		.scp = 0x2,
		.prhbt = !!true,
		.ifc = 0x1,
		.ofi = 0x12,
		.uuidx = 0x34,
	};

	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_lockdown,
		.cdw10 = args.ofi << 8 | (args.ifc & 0x3) << 5 |
			 (args.prhbt & 0x1) << 4 | (args.scp & 0xF),
		.cdw14 = args.uuidx & 0x3F,
		.result = expected_result,
	};

	int err;

	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_lockdown(&args);
	end_mock_cmds();
	check(err == 0, "returned error %d, errno %m", err);
	check(result == expected_result, "wrong result");
}

static void test_sanitize_nvm(void)
{
	__u32 expected_result = 0x45, result = 0;

	struct nvme_sanitize_nvm_args args = {
		.result = &result,
		.args_size = sizeof(args),
		.fd = TEST_FD,
		.sanact = NVME_SANITIZE_SANACT_START_CRYPTO_ERASE,
		.ovrpat = 0x101010,
		.ause = true,
		.owpass = 0x2,
		.oipbp = false,
		.nodas = true,
		.emvs = false,
	};

	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_sanitize_nvm,
		.cdw10 = args.sanact | (!!args.ause << 3) | (args.owpass << 4) |
			 (!!args.oipbp << 8) | (!!args.nodas << 9),
		.cdw11 = args.ovrpat,
		.result = expected_result,
	};

	int err;

	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_sanitize_nvm(&args);
	end_mock_cmds();
	check(err == 0, "returned error %d, errno %m", err);
	check(result == expected_result, "wrong result");
}

static void test_dev_self_test(void)
{
	__u32 expected_result = 0x45, result = 0;

	struct nvme_dev_self_test_args args = {
		.result = &result,
		.args_size = sizeof(args),
		.fd = TEST_FD,
		.nsid = TEST_NSID,
		.stc = NVME_DST_STC_ABORT,
	};

	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_dev_self_test,
		.nsid = args.nsid,
		.cdw10 = args.stc,
		.result = expected_result,
	};

	int err;

	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_dev_self_test(&args);
	end_mock_cmds();
	check(err == 0, "returned error %d, errno %m", err);
	check(result == expected_result, "wrong result");
}

static void test_virtual_mgmt(void)
{
	__u32 expected_result = 0x45, result = 0;

	struct nvme_virtual_mgmt_args args = {
		.result = &result,
		.args_size = sizeof(args),
		.fd = TEST_FD,
		.act = NVME_VIRT_MGMT_ACT_ASSIGN_SEC_CTRL,
		.rt = NVME_VIRT_MGMT_RT_VI_RESOURCE,
		.cntlid = 0x0,
		.nr = 0xff,
	};

	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_virtual_mgmt,
		.cdw10 = args.act | (args.rt << 8) | (args.cntlid << 16),
		.cdw11 = args.nr,
		.result = expected_result,
	};

	int err;

	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_virtual_mgmt(&args);
	end_mock_cmds();
	check(err == 0, "returned error %d, errno %m", err);
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
	err = nvme_flush(TEST_FD, TEST_NSID);
	end_mock_cmds();
	check(err == 0, "returned error %d, errno %m", err);
}

static void test_read(void)
{
	__u8 expected_data[512], data[512] = {};
	__u32 result = 0;

	struct nvme_io_args args = {
		.slba = 0xffffffffff,
		.storage_tag = 0xef,
		.result = &result,
		.data = &data,
		.args_size = sizeof(args),
		.fd = TEST_FD,
		.nsid = TEST_NSID,
		.reftag = 0xab,
		.data_len = sizeof(data),
		.nlb = 0x3,
		.control = NVME_IO_FUA,
		.apptag = 0x12,
		.appmask = 0x34,
		.dspec = 0x0,
		.dsm = NVME_IO_DSM_LATENCY_LOW,
	};

	struct mock_cmd mock_io_cmd = {
		.opcode = nvme_cmd_read,
		.nsid = TEST_NSID,
		.cdw10 = args.slba & 0xffffffff,
		.cdw11 = args.slba >> 32,
		.cdw12 = args.nlb | (args.control << 16),
		.cdw13 = args.dsm | (args.dspec << 16),
		.cdw15 = args.apptag | (args.appmask << 16),
		.data_len = sizeof(expected_data),
		.out_data = &expected_data,
	};

	int err;

	arbitrary(&expected_data, sizeof(expected_data));
	set_mock_io_cmds(&mock_io_cmd, 1);
	err = nvme_read(&args);
	end_mock_cmds();
	check(err == 0, "returned error %d, errno %m", err);
	check(result == 0, "returned result %u", result);
}

static void test_write(void)
{
	__u8 expected_data[512], data[512] = {};
	__u32 result = 0;

	struct nvme_io_args args = {
		.slba = 0xfffffffabcde,
		.storage_tag = 0xab,
		.result = &result,
		.data = &expected_data,
		.args_size = sizeof(args),
		.fd = TEST_FD,
		.nsid = TEST_NSID,
		.reftag = 0xef,
		.data_len = sizeof(expected_data),
		.nlb = 0x5,
		.control = NVME_IO_FUA,
		.apptag = 0x59,
		.appmask = 0x94,
		.dspec = 0xa,
		.dsm = NVME_IO_DSM_COMPRESSED,
	};

	struct mock_cmd mock_io_cmd = {
		.opcode = nvme_cmd_write,
		.nsid = TEST_NSID,
		.cdw10 = args.slba & 0xffffffff,
		.cdw11 = args.slba >> 32,
		.cdw12 = args.nlb | (args.control << 16),
		.cdw13 = args.dsm | (args.dspec << 16),
		.cdw15 = args.apptag | (args.appmask << 16),
		.data_len = sizeof(data),
		.in_data = &data,
	};

	int err;

	arbitrary(&expected_data, sizeof(expected_data));
	memcpy(&data, &expected_data, sizeof(expected_data));
	set_mock_io_cmds(&mock_io_cmd, 1);
	err = nvme_write(&args);
	end_mock_cmds();
	check(err == 0, "returned error %d, errno %m", err);
	check(result == 0, "returned result %u", result);
}

static void test_compare(void)
{
	__u8 expected_data[512], data[512] = {};
	__u32 result = 0;

	struct nvme_io_args args = {
		.slba = 0xabcde,
		.storage_tag = 0xab,
		.result = &result,
		.data = &expected_data,
		.args_size = sizeof(args),
		.fd = TEST_FD,
		.nsid = TEST_NSID,
		.reftag = 0xff,
		.data_len = sizeof(expected_data),
		.nlb = 0x0,
		.control = NVME_IO_LR,
		.apptag = 0x59,
		.appmask = 0x94,
		.dspec = 0xa,
		.dsm = NVME_IO_DSM_COMPRESSED,
	};

	struct mock_cmd mock_io_cmd = {
		.opcode = nvme_cmd_compare,
		.nsid = TEST_NSID,
		.cdw10 = args.slba & 0xffffffff,
		.cdw11 = args.slba >> 32,
		.cdw12 = args.nlb | (args.control << 16),
		.cdw13 = args.dsm | (args.dspec << 16),
		.cdw15 = args.apptag | (args.appmask << 16),
		.data_len = sizeof(data),
		.in_data = &data,
	};

	int err;

	arbitrary(&expected_data, sizeof(expected_data));
	memcpy(&data, &expected_data, sizeof(expected_data));
	set_mock_io_cmds(&mock_io_cmd, 1);
	err = nvme_compare(&args);
	end_mock_cmds();
	check(err == 0, "returned error %d, errno %m", err);
	check(result == 0, "returned result %u", result);
}

static void test_write_zeros(void)
{
	__u8 expected_data[512], data[512] = {};
	__u32 result = 0;

	struct nvme_io_args args = {
		.slba = 0x0,
		.storage_tag = 0xab,
		.result = &result,
		.data = &expected_data,
		.args_size = sizeof(args),
		.fd = TEST_FD,
		.nsid = TEST_NSID,
		.reftag = 0xff,
		.data_len = sizeof(expected_data),
		.nlb = 0xffff,
		.control = NVME_IO_LR,
		.apptag = 0xfa,
		.appmask = 0x72,
		.dspec = 0xbb,
		.dsm = NVME_IO_DSM_FREQ_ONCE,
	};

	struct mock_cmd mock_io_cmd = {
		.opcode = nvme_cmd_write_zeroes,
		.nsid = TEST_NSID,
		.cdw10 = args.slba & 0xffffffff,
		.cdw11 = args.slba >> 32,
		.cdw12 = args.nlb | (args.control << 16),
		.cdw13 = args.dsm | (args.dspec << 16),
		.cdw15 = args.apptag | (args.appmask << 16),
		.data_len = sizeof(data),
		.in_data = &data,
	};

	int err;

	arbitrary(&expected_data, sizeof(expected_data));
	memcpy(&data, &expected_data, sizeof(expected_data));
	set_mock_io_cmds(&mock_io_cmd, 1);
	err = nvme_write_zeros(&args);
	end_mock_cmds();
	check(err == 0, "returned error %d, errno %m", err);
	check(result == 0, "returned result %u", result);
}

static void test_write_uncorrectable(void)
{
	__u8 expected_data[512], data[512] = {};
	__u32 result = 0;

	struct nvme_io_args args = {
		.slba = 0x0,
		.storage_tag = 0x0,
		.result = &result,
		.data = &expected_data,
		.args_size = sizeof(args),
		.fd = TEST_FD,
		.nsid = TEST_NSID,
		.reftag = 0x0,
		.data_len = sizeof(expected_data),
		.nlb = 0x0,
		.control = 0x0,
		.apptag = 0x0,
		.appmask = 0x0,
		.dspec = 0x0,
		.dsm = 0x0,
	};

	struct mock_cmd mock_io_cmd = {
		.opcode = nvme_cmd_write_uncor,
		.nsid = TEST_NSID,
		.cdw10 = args.slba & 0xffffffff,
		.cdw11 = args.slba >> 32,
		.cdw12 = args.nlb | (args.control << 16),
		.cdw13 = args.dsm | (args.dspec << 16),
		.cdw15 = args.apptag | (args.appmask << 16),
		.data_len = sizeof(data),
		.in_data = &data,
	};

	int err;

	arbitrary(&expected_data, sizeof(expected_data));
	memcpy(&data, &expected_data, sizeof(expected_data));
	set_mock_io_cmds(&mock_io_cmd, 1);
	err = nvme_write_uncorrectable(&args);
	end_mock_cmds();
	check(err == 0, "returned error %d, errno %m", err);
	check(result == 0, "returned result %u", result);
}

static void test_verify(void)
{
	__u8 expected_data[512], data[512] = {};
	__u32 result = 0;

	struct nvme_io_args args = {
		.slba = 0xffffffffffffffff,
		.storage_tag = 0xffffffffffffffff,
		.result = &result,
		.data = &expected_data,
		.args_size = sizeof(args),
		.fd = TEST_FD,
		.nsid = TEST_NSID,
		.reftag = 0xffffffff,
		.data_len = sizeof(expected_data),
		.nlb = 0xffff,
		.control = 0xffff,
		.apptag = 0xffff,
		.appmask = 0xffff,
		.dspec = 0xffff,
		.dsm = 0xff,
	};

	struct mock_cmd mock_io_cmd = {
		.opcode = nvme_cmd_verify,
		.nsid = TEST_NSID,
		.cdw10 = args.slba & 0xffffffff,
		.cdw11 = args.slba >> 32,
		.cdw12 = args.nlb | (args.control << 16),
		.cdw13 = args.dsm | (args.dspec << 16),
		.cdw15 = args.apptag | (args.appmask << 16),
		.data_len = sizeof(data),
		.in_data = &data,
	};

	int err;

	arbitrary(&expected_data, sizeof(expected_data));
	memcpy(&data, &expected_data, sizeof(expected_data));
	set_mock_io_cmds(&mock_io_cmd, 1);
	err = nvme_verify(&args);
	end_mock_cmds();
	check(err == 0, "returned error %d, errno %m", err);
	check(result == 0, "returned result %u", result);
}

static void test_dsm(void)
{
	__u32 result = 0;
	__u16 nr_ranges = 0xab;
	int dsm_size = sizeof(struct nvme_dsm_range) * nr_ranges;

	_cleanup_free_ struct nvme_dsm_range *dsm = NULL;

	dsm = malloc(dsm_size);
	check(dsm, "dsm: ENOMEM");

	struct nvme_dsm_args args = {
		.result = &result,
		.dsm = dsm,
		.args_size = sizeof(args),
		.fd = TEST_FD,
		.nsid = TEST_NSID,
		.attrs = NVME_DSMGMT_AD,
		.nr_ranges = nr_ranges,
	};

	struct mock_cmd mock_io_cmd = {
		.opcode = nvme_cmd_dsm,
		.nsid = TEST_NSID,
		.cdw10 = args.nr_ranges - 1,
		.cdw11 = args.attrs,
		.data_len = dsm_size,
		.in_data = args.dsm,
	};

	int err;

	arbitrary(dsm, dsm_size);
	set_mock_io_cmds(&mock_io_cmd, 1);
	err = nvme_dsm(&args);
	end_mock_cmds();
	check(err == 0, "returned error %d, errno %m", err);
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
		.fd = TEST_FD,
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
	err = nvme_copy(&args);
	end_mock_cmds();
	check(err == 0, "returned error %d, errno %m", err);
	check(result == 0, "returned result %u", result);
}

static void test_resv_acquire(void)
{
	__u32 result = 0;

	struct nvme_resv_acquire_args args = {
		.crkey = 0,
		.nrkey = 0,
		.result = &result,
		.args_size = sizeof(args),
		.fd = TEST_FD,
		.nsid = TEST_NSID,
		.rtype = NVME_RESERVATION_RTYPE_EAAR,
		.racqa = NVME_RESERVATION_RACQA_PREEMPT,
		.iekey = true,
	};

	__le64 payload[2] = { 0 };

	struct mock_cmd mock_io_cmd = {
		.opcode = nvme_cmd_resv_acquire,
		.nsid = TEST_NSID,
		.cdw10 = (args.racqa & 0x7) | (args.iekey ? 1 << 3 : 0) |
			 (args.rtype << 8),
		.data_len = sizeof(payload),
		.in_data = payload,
	};

	int err;

	set_mock_io_cmds(&mock_io_cmd, 1);
	err = nvme_resv_acquire(&args);
	end_mock_cmds();
	check(err == 0, "returned error %d, errno %m", err);
	check(result == 0, "returned result %u", result);
}

static void test_resv_register(void)
{
	__u32 result = 0;

	struct nvme_resv_register_args args = {
		.crkey = 0xffffffffffffffff,
		.nrkey = 0,
		.result = &result,
		.args_size = sizeof(args),
		.fd = TEST_FD,
		.nsid = TEST_NSID,
		.rrega = NVME_RESERVATION_RREGA_UNREGISTER_KEY,
		.cptpl = NVME_RESERVATION_CPTPL_PERSIST,
		.iekey = true,
	};

	__le64 payload[2] = { 0xffffffffffffffff, 0 };

	struct mock_cmd mock_io_cmd = {
		.opcode = nvme_cmd_resv_register,
		.nsid = TEST_NSID,
		.cdw10 = (args.rrega & 0x7) | (args.iekey ? 1 << 3 : 0) |
			 (args.cptpl << 30),
		.data_len = sizeof(payload),
		.in_data = payload,
	};

	int err;

	set_mock_io_cmds(&mock_io_cmd, 1);
	err = nvme_resv_register(&args);
	end_mock_cmds();
	check(err == 0, "returned error %d, errno %m", err);
	check(result == 0, "returned result %u", result);
}

static void test_resv_release(void)
{
	__u32 result = 0;

	struct nvme_resv_release_args args = {
		.crkey = 0xffffffffffffffff,
		.result = &result,
		.args_size = sizeof(args),
		.fd = TEST_FD,
		.nsid = TEST_NSID,
		.rtype = NVME_RESERVATION_RTYPE_WE,
		.rrela = NVME_RESERVATION_RRELA_RELEASE,
		.iekey = true,
	};

	__le64 payload[1] = { 0xffffffffffffffff };

	struct mock_cmd mock_io_cmd = {
		.opcode = nvme_cmd_resv_release,
		.nsid = TEST_NSID,
		.cdw10 = (args.rrela & 0x7) | (args.iekey ? 1 << 3 : 0) |
			 (args.rtype << 8),
		.data_len = sizeof(payload),
		.in_data = payload,
	};

	int err;

	set_mock_io_cmds(&mock_io_cmd, 1);
	err = nvme_resv_release(&args);
	end_mock_cmds();
	check(err == 0, "returned error %d, errno %m", err);
	check(result == 0, "returned result %u", result);
}

static void test_resv_report(void)
{
	__u32 result = 0;

	struct nvme_resv_status expected_status, status = {};

	struct nvme_resv_report_args args = {
		.result = &result,
		.report = &status,
		.args_size = sizeof(args),
		.fd = TEST_FD,
		.nsid = TEST_NSID,
		.len = sizeof(status),
		.eds = false,
	};

	struct mock_cmd mock_io_cmd = {
		.opcode = nvme_cmd_resv_report,
		.nsid = TEST_NSID,
		.cdw10 = (args.len >> 2) - 1,
		.cdw11 = args.eds ? 1 : 0,
		.data_len = args.len,
		.out_data = &expected_status,
	};

	int err;

	arbitrary(&expected_status, sizeof(expected_status));
	set_mock_io_cmds(&mock_io_cmd, 1);
	err = nvme_resv_report(&args);
	end_mock_cmds();
	check(err == 0, "returned error %d, errno %m", err);
	check(result == 0, "returned result %u", result);
	cmp(&status, &expected_status, sizeof(status), "incorrect status");
}

static void test_io_mgmt_recv(void)
{
	__u8 expected_data[8], data[8] = {};
	struct nvme_io_mgmt_recv_args args = {
		.data = &data,
		.args_size = sizeof(args),
		.fd = TEST_FD,
		.nsid = TEST_NSID,
		.data_len = sizeof(data),
		.mos = 0x1,
		.mo = 0x2,
	};

	struct mock_cmd mock_io_cmd = {
		.opcode = nvme_cmd_io_mgmt_recv,
		.nsid = TEST_NSID,
		.cdw10 = args.mo | (args.mos << 16),
		.cdw11 = (args.data_len >> 2) - 1,
		.data_len = args.data_len,
		.out_data = &expected_data,
	};

	int err;

	arbitrary(&expected_data, sizeof(expected_data));
	set_mock_io_cmds(&mock_io_cmd, 1);
	err = nvme_io_mgmt_recv(&args);
	end_mock_cmds();
	check(err == 0, "returned error %d, errno %m", err);
	cmp(&data, &expected_data, sizeof(data), "incorrect data");
}

static void test_io_mgmt_send(void)
{
	__u8 expected_data[8], data[8] = {};
	struct nvme_io_mgmt_send_args args = {
		.data = &expected_data,
		.args_size = sizeof(args),
		.fd = TEST_FD,
		.nsid = TEST_NSID,
		.data_len = sizeof(expected_data),
		.mos = 0x1,
		.mo = 0x2,
	};

	struct mock_cmd mock_io_cmd = {
		.opcode = nvme_cmd_io_mgmt_send,
		.nsid = TEST_NSID,
		.cdw10 = args.mo | (args.mos << 16),
		.data_len = args.data_len,
		.in_data = &data,
	};

	int err;

	arbitrary(&expected_data, sizeof(expected_data));
	memcpy(&data, &expected_data, sizeof(expected_data));
	set_mock_io_cmds(&mock_io_cmd, 1);
	err = nvme_io_mgmt_send(&args);
	end_mock_cmds();
	check(err == 0, "returned error %d, errno %m", err);
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

	int err;

	arbitrary(&expected_data, sizeof(expected_data));
	set_mock_io_cmds(&mock_io_cmd, 1);
	err = nvme_fdp_reclaim_unit_handle_status(TEST_FD, TEST_NSID, data_len,
						  &data);
	end_mock_cmds();
	check(err == 0, "returned error %d, errno %m", err);
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

	int err;

	arbitrary(&pids, sizeof(pids));
	set_mock_io_cmds(&mock_io_cmd, 1);
	err = nvme_fdp_reclaim_unit_handle_update(TEST_FD, TEST_NSID, npids,
						  &pids);
	end_mock_cmds();
	check(err == 0, "returned error %d, errno %m", err);
}

static void test_dim_send(void)
{
	__u32 result = 0;
	__u8 expected_data[8], data[8] = {};
	struct nvme_dim_args args = {
		.result = 0,
		.data = &data,
		.args_size = sizeof(args),
		.fd = TEST_FD,
		.data_len = sizeof(data),
		.tas = 0xf,
	};

	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_discovery_info_mgmt,
		.cdw10 = args.tas,
		.data_len = args.data_len,
		.in_data = &expected_data,
	};

	int err;

	arbitrary(&expected_data, sizeof(expected_data));
	memcpy(&data, &expected_data, sizeof(expected_data));
	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_dim_send(&args);
	end_mock_cmds();
	check(err == 0, "returned error %d, errno %m", err);
	check(result == 0, "returned result %u", result);
	cmp(&data, &expected_data, sizeof(data), "incorrect data");
}

static void test_lm_cdq(void)
{
	__u32 result = 0;
	__u8 expected_data[8], data[8] = {};
	struct nvme_lm_cdq_args args = {
		.result = 0,
		.data = &data,
		.args_size = sizeof(args),
		.fd = TEST_FD,
		.mos = 0x1,
		.cntlid = 0x2,
		.cdqid = 0x3,
		.sel = NVME_LM_SEL_DELETE_CDQ,
		.sz = 0x4,
	};

	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_ctrl_data_queue,
		.cdw10 = args.sel | (args.mos << 16),
		.cdw11 = args.cdqid,
		.cdw12 = args.sz,
		.data_len = 0,
		.in_data = &expected_data,
	};

	int err;

	arbitrary(&expected_data, sizeof(expected_data));
	memcpy(&data, &expected_data, sizeof(expected_data));
	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_lm_cdq(&args);
	end_mock_cmds();
	check(err == 0, "returned error %d, errno %m", err);
	check(result == 0, "returned result %u", result);
	cmp(&data, &expected_data, sizeof(data), "incorrect data");
}

static void test_lm_track_send(void)
{
	__u32 result = 0;
	struct nvme_lm_track_send_args args = {
		.result = 0,
		.args_size = sizeof(args),
		.fd = TEST_FD,
		.mos = 0x1,
		.cdqid = 0x3,
		.sel = NVME_LM_SEL_DELETE_CDQ,
	};

	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_track_send,
		.cdw10 = args.sel | (args.mos << 16),
		.cdw11 = args.cdqid,
	};

	int err;

	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_lm_track_send(&args);
	end_mock_cmds();
	check(err == 0, "returned error %d, errno %m", err);
	check(result == 0, "returned result %u", result);
}

static void test_lm_migration_send(void)
{
	__u32 result = 0;
	__u32 expected_data[8], data[8] = {};
	struct nvme_lm_migration_send_args args = {
		.offset = 0xffffffffff,
		.result = 0,
		.data = &expected_data,
		.args_size = sizeof(args),
		.fd = TEST_FD,
		.numd = 8 - 1,
		.mos = 0x1,
		.cntlid = 0x2,
		.csuuidi = 0x3,
		.sel = NVME_LM_SEL_RESUME,
		.uidx = 0x4,
		.stype = 0x5,
		.seqind = 0x6,
		.csvi = 0x7,
		.dudmq = true,
	};

	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_migration_send,
		.cdw10 = args.sel | (args.mos << 16),
		.cdw11 = args.cntlid,
		.cdw12 = (__u32)args.offset,
		.cdw13 = (__u32)(args.offset >> 32),
		.cdw14 = args.uidx,
		.cdw15 = args.numd,
		.data_len = args.numd << 2,
		.in_data = &data,
	};

	int err;

	arbitrary(&expected_data, sizeof(expected_data));
	memcpy(&data, &expected_data, sizeof(expected_data));
	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_lm_migration_send(&args);
	end_mock_cmds();
	check(err == 0, "returned error %d, errno %m", err);
	check(result == 0, "returned result %u", result);
	cmp(&data, &expected_data, sizeof(data), "incorrect data");
}

static void test_lm_migration_recv(void)
{
	__u32 result = 0;
	__u32 expected_data[8], data[8] = {};
	struct nvme_lm_migration_recv_args args = {
		.offset = 0xffffffffff,
		.result = 0,
		.data = &data,
		.args_size = sizeof(args),
		.fd = TEST_FD,
		.numd = 8 - 1,
		.mos = 0x1,
		.cntlid = 0x2,
		.csuuidi = 0x3,
		.sel = NVME_LM_SEL_GET_CONTROLLER_STATE,
		.uidx = 0x4,
		.csuidxp = 0x5,
	};

	struct mock_cmd mock_admin_cmd = {
		.opcode = nvme_admin_migration_receive,
		.cdw10 = args.sel | (args.mos << 16),
		.cdw11 = args.cntlid | (args.csuuidi << 16) |
			 (args.csuidxp << 24),
		.cdw12 = (__u32)args.offset,
		.cdw13 = (__u32)(args.offset >> 32),
		.cdw14 = args.uidx,
		.cdw15 = args.numd,
		.data_len = (args.numd + 1) << 2,
		.out_data = &expected_data,
	};

	int err;

	arbitrary(&expected_data, sizeof(expected_data));
	set_mock_admin_cmds(&mock_admin_cmd, 1);
	err = nvme_lm_migration_recv(&args);
	end_mock_cmds();
	check(err == 0, "returned error %d, errno %m", err);
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
	set_mock_fd(TEST_FD);
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
	RUN_TEST(lm_cdq);
	RUN_TEST(lm_track_send);
	RUN_TEST(lm_migration_send);
	RUN_TEST(lm_migration_recv);
}
