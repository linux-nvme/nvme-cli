// SPDX-License-Identifier: GPL-2.0-or-later
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <inttypes.h>

#include "nvme.h"
#include "libnvme.h"
#include "plugin.h"

#define CREATE_CMD
#include "transcend-nvme.h"

static const __u32 OP_BAD_BLOCK = 0xc2;
static const __u32 DW10_BAD_BLOCK = 0x400;
static const __u32 DW12_BAD_BLOCK = 0x5a;

static int getHealthValue(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	struct nvme_smart_log smart_log;
	char *desc = "Get nvme health percentage.";
	int  percent_used = 0, healthvalue = 0;
	_cleanup_nvme_global_ctx_ struct nvme_global_ctx *ctx = NULL;
	_cleanup_nvme_transport_handle_ struct nvme_transport_handle *hdl = NULL;
	int result;

	OPT_ARGS(opts) = {
		OPT_END()
	};

	result = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (result) {
		printf("\nDevice not found\n");
		return -1;
	}
	result = nvme_get_log_smart(hdl, 0xffffffff, false, &smart_log);
	if (!result) {
		printf("Transcend NVME heath value: ");
		percent_used = smart_log.percent_used;

		if (percent_used > 100 || percent_used < 0) {
			printf("0%%\n");
		} else {
			healthvalue = 100 - percent_used;
			printf("%d%%\n", healthvalue);
		}
	}

	return result;
}

static int getBadblock(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{

	char *desc = "Get nvme bad block number.";
	_cleanup_nvme_global_ctx_ struct nvme_global_ctx *ctx = NULL;
	_cleanup_nvme_transport_handle_ struct nvme_transport_handle *hdl = NULL;
	struct nvme_passthru_cmd nvmecmd;
	unsigned char data[1] = {0};
	int result;

	OPT_ARGS(opts) = {
		OPT_END()
	};

	result = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (result) {
		printf("\nDevice not found\n");
		return -1;
	}

	memset(&nvmecmd, 0, sizeof(nvmecmd));
	nvmecmd.opcode = OP_BAD_BLOCK;
	nvmecmd.cdw10 = DW10_BAD_BLOCK;
	nvmecmd.cdw12 = DW12_BAD_BLOCK;
	nvmecmd.addr = (__u64)(uintptr_t)data;
	nvmecmd.data_len = 0x1;

	result = nvme_submit_admin_passthru(hdl, &nvmecmd, NULL);
	if (!result) {
		int badblock  = data[0];

		printf("Transcend NVME badblock count: %d\n", badblock);
	}

	return result;
}
