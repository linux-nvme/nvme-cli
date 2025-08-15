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

int sldgm_get_market_log(int argc, char **argv, struct command *acmd,
				struct plugin *plugin)
{
	const char *desc = "Get Solidigm Marketing Name log and show it.";
	const char *raw = "dump output in binary format";
	_cleanup_nvme_global_ctx_ struct nvme_global_ctx *ctx = NULL;
	_cleanup_nvme_transport_handle_ struct nvme_transport_handle *hdl = NULL;
	struct nvme_passthru_cmd cmd;
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

	nvme_init_get_log(&cmd, NVME_NSID_ALL,
			  MARKET_LOG_LID, NVME_CSI_NVM,
			  log, sizeof(log));
	cmd.cdw14 |= NVME_FIELD_ENCODE(uuid_idx,
				       NVME_LOG_CDW14_UUID_SHIFT,
				       NVME_LOG_CDW14_UUID_MASK);
	err = nvme_get_log(hdl, &cmd, false,
			   NVME_LOG_PAGE_PDU_SIZE, NULL);
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
