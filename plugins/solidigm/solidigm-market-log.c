// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2023 Solidigm.
 *
 * Authors: leonardo.da.cunha@solidigm.com
 * Hardeep.Dhillon@solidigm.com
 */

#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <inttypes.h>

#include "common.h"
#include "nvme.h"
#include "libnvme.h"
#include "plugin.h"
#include "nvme-print.h"
#include "solidigm-util.h"

#define MARKET_LOG_LID 0xDD
#define MARKET_LOG_MAX_SIZE 512

int sldgm_get_market_log(int argc, char **argv, struct command *command,
				struct plugin *plugin)
{
	const char *desc = "Get Solidigm Marketing Name log and show it.";
	const char *raw = "dump output in binary format";
	_cleanup_nvme_global_ctx_ struct nvme_global_ctx *ctx = NULL;
	_cleanup_nvme_transport_handle_ struct nvme_transport_handle *hdl = NULL;
	char log[MARKET_LOG_MAX_SIZE];
	int err;
	__u8 uuid_idx;
	bool  raw_binary = false;

	OPT_ARGS(opts) = {
		OPT_FLAG("raw-binary", 'b', &raw_binary, raw),
		OPT_INCR("verbose", 'v', &nvme_cfg.verbose, verbose),
		OPT_END()
	};

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	sldgm_get_uuid_index(hdl, &uuid_idx);

	struct nvme_get_log_args args = {
		.lpo	= 0,
		.result = NULL,
		.log	= log,
		.args_size = sizeof(args),
		.uuidx	= uuid_idx,
		.timeout = NVME_DEFAULT_IOCTL_TIMEOUT,
		.lid	= MARKET_LOG_LID,
		.len	= sizeof(log),
		.nsid	= NVME_NSID_ALL,
		.csi	= NVME_CSI_NVM,
		.lsi	= NVME_LOG_LSI_NONE,
		.lsp	= NVME_LOG_LSP_NONE,
		.rae	= false,
		.ot	= false,
	};

	err = nvme_get_log(hdl, &args);
	if (err) {
		nvme_show_status(err);
		return err;
	}
	if (!raw_binary)
		printf("Solidigm Marketing Name Log:\n%s\n", log);
	else
		d_raw((unsigned char *)&log, sizeof(log));

	return err;
}
