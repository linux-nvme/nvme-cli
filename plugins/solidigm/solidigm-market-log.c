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
#include <linux/limits.h>

#include "common.h"
#include "nvme.h"
#include "libnvme.h"
#include "plugin.h"
#include "nvme-print.h"

#define MARKET_LOG_MAX_SIZE 512

int sldgm_get_market_log(int argc, char **argv, struct command *command,
				struct plugin *plugin)
{
	const char *desc = "Get Solidigm Marketing Name log and show it.";
	const char *raw = "dump output in binary format";
	struct nvme_dev *dev;
	char log[MARKET_LOG_MAX_SIZE];
	int err;

	struct config {
		bool  raw_binary;
	};

	struct config cfg = {
	};

	OPT_ARGS(opts) = {
		OPT_FLAG("raw-binary", 'b', &cfg.raw_binary, raw),
		OPT_END()
	};

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		return err;

	err = nvme_get_log_simple(dev_fd(dev), 0xdd, sizeof(log), log);
	if (!err) {
		if (!cfg.raw_binary)
			printf("Solidigm Marketing Name Log:\n%s\n", log);
		else
			d_raw((unsigned char *)&log, sizeof(log));
	} else if (err > 0)

	nvme_show_status(err);
	/* Redundant close() to make static code analysis happy */
	close(dev->direct.fd);
	dev_close(dev);
	return err;
}
