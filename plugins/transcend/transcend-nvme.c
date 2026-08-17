// SPDX-License-Identifier: GPL-2.0-or-later
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <inttypes.h>

#include <libnvme.h>

#include <shared/compiler-attributes-util.h>

#include "nvme-cmds.h"
#include "nvme-print.h"
#include "cleanup.h"
#include "global-ctx.h"
#include "plugin.h"

static const __u32 OP_BAD_BLOCK = 0xc2;
static const __u32 DW10_BAD_BLOCK = 0x400;
static const __u32 DW12_BAD_BLOCK = 0x5a;

static int getHealthValue(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	struct nvme_smart_log smart_log;
	char *desc = "Get nvme health percentage.";
	int  percent_used = 0, healthvalue = 0;
	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	__cleanup_nvme_transport_handle struct libnvme_transport_handle *hdl = NULL;
	int result;

	NVME_ARGS(opts);

	result = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (result) {
		nvme_show_error("Device not found");
		return -1;
	}
	result = nvme_get_log_smart(hdl, NVME_NSID_ALL, &smart_log);
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

static int getBadblock(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{

	char *desc = "Get nvme bad block number.";
	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	__cleanup_nvme_transport_handle struct libnvme_transport_handle *hdl = NULL;
	struct libnvme_passthru_cmd nvmecmd;
	unsigned char data[1] = {0};
	int result;

	NVME_ARGS(opts);

	result = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (result) {
		nvme_show_error("Device not found");
		return -1;
	}

	memset(&nvmecmd, 0, sizeof(nvmecmd));
	nvmecmd.opcode = OP_BAD_BLOCK;
	nvmecmd.cdw10 = DW10_BAD_BLOCK;
	nvmecmd.cdw12 = DW12_BAD_BLOCK;
	nvmecmd.addr = (__u64)(uintptr_t)data;
	nvmecmd.data_len = 0x1;

	result = libnvme_exec_admin_passthru(hdl, &nvmecmd);
	if (!result) {
		int badblock  = data[0];

		printf("Transcend NVME badblock count: %d\n", badblock);
	}

	return result;
}

static struct command getHealthValue_cmd = {
	.name = "healthvalue",
	.help = "NVME health percentage",
	.fn = getHealthValue,
};

static struct command getBadblock_cmd = {
	.name = "badblock",
	.help = "Get NVME bad block number",
	.fn = getBadblock,
};

static struct command *commands[] = {
	&getHealthValue_cmd,
	&getBadblock_cmd,
	NULL,
};

static struct plugin plugin = {
	.name = "transcend",
	.desc = "Transcend vendor specific extensions",
	.version = NVME_VERSION,
};

static void __shr_constructor register_plugin(void)
{
	plugin_add_group(&plugin, NULL, commands);
	register_extension(&plugin);
}
