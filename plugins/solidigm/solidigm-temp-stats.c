// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2023 Solidigm.
 *
 * Author: leonardo.da.cunha@solidigm.com
 */

#include <errno.h>

#include "common.h"
#include "nvme-print.h"
#include "solidigm-util.h"

#define SLDGM_TEMP_STATS_LID 0xC5

struct temp_stats {
	__le64	curr;
	__le64	last_overtemp;
	__le64	life_overtemp;
	__le64	highest_temp;
	__le64	lowest_temp;
	__u8	rsvd[40];
	__le64	max_operating_temp;
	__le64	min_operating_temp;
	__le64	est_offset;
};

static void show_temp_stats(struct temp_stats *stats)
{
	printf("Current temperature         : %"PRIu64"\n", le64_to_cpu(stats->curr));
	printf("Last critical overtemp flag : %"PRIu64"\n", le64_to_cpu(stats->last_overtemp));
	printf("Life critical overtemp flag : %"PRIu64"\n", le64_to_cpu(stats->life_overtemp));
	printf("Highest temperature         : %"PRIu64"\n", le64_to_cpu(stats->highest_temp));
	printf("Lowest temperature          : %"PRIu64"\n", le64_to_cpu(stats->lowest_temp));
	printf("Max operating temperature   : %"PRIu64"\n", le64_to_cpu(stats->max_operating_temp));
	printf("Min operating temperature   : %"PRIu64"\n", le64_to_cpu(stats->min_operating_temp));
	printf("Estimated offset            : %"PRIu64"\n", le64_to_cpu(stats->est_offset));
}

int sldgm_get_temp_stats_log(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	unsigned char buffer[4096] = {0};
	struct nvme_dev *dev;
	__u8 uuid_idx;
	int err;

	const char *desc = "Get/show Temperature Statistics log.";
	const char *raw = "dump output in binary format";
	struct config {
		bool  raw_binary;
	};

	struct config cfg = {
		.raw_binary = false,
	};

	OPT_ARGS(opts) = {
		OPT_FLAG("raw-binary", 'b', &cfg.raw_binary, raw),
		OPT_END()
	};

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		return err;

	uuid_idx = solidigm_get_vu_uuid_index(dev);

	struct nvme_get_log_args args = {
		.lpo	= 0,
		.result = NULL,
		.log	= buffer,
		.args_size = sizeof(args),
		.fd	= dev_fd(dev),
		.uuidx	= uuid_idx,
		.timeout = NVME_DEFAULT_IOCTL_TIMEOUT,
		.lid	= SLDGM_TEMP_STATS_LID,
		.len	= sizeof(buffer),
		.nsid	= NVME_NSID_ALL,
		.csi	= NVME_CSI_NVM,
		.lsi	= NVME_LOG_LSI_NONE,
		.lsp	= NVME_LOG_LSP_NONE,
		.rae	= false,
		.ot	= false,
	};

	err = nvme_get_log(&args);
	if (!err) {
		uint64_t *guid = (uint64_t *)&buffer[4080];

		if (guid[1] == 0xC7BB98B7D0324863 && guid[0] == 0xBB2C23990E9C722F) {
			fprintf(stderr, "Error: Log page has 'OCP unsupported Requirements' GUID\n");
			err = -EBADMSG;
			goto closefd;
		}
		if (!cfg.raw_binary)
			show_temp_stats((struct temp_stats *) buffer);
		else
			d_raw(buffer, sizeof(struct temp_stats));
	} else if (err > 0) {
		nvme_show_status(err);
	}

closefd:
	/* Redundant close() to make static code analysis happy */
	close(dev->direct.fd);
	dev_close(dev);
	return err;
}
