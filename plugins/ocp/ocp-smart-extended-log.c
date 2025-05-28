// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (c) 2022 Meta Platforms, Inc.
 *
 * Authors: Arthur Shau <arthurshau@fb.com>,
 *          Wei Zhang <wzhang@fb.com>,
 *          Venkat Ramesh <venkatraghavan@fb.com>
 */

#include "ocp-smart-extended-log.h"

#include <errno.h>
#include <stdio.h>

#include "common.h"
#include "nvme-print.h"
#include "ocp-print.h"
#include "ocp-utils.h"

/* C0 SCAO Log Page */
#define C0_SMART_CLOUD_ATTR_LEN			0x200

static __u8 scao_guid[GUID_LEN] = {
	0xC5, 0xAF, 0x10, 0x28,
	0xEA, 0xBF, 0xF2, 0xA4,
	0x9C, 0x4F, 0x6F, 0x7C,
	0xC9, 0x14, 0xD5, 0xAF
};

static int get_c0_log_page(struct nvme_transport_handle *hdl, char *format,
			   unsigned int format_version)
{
	nvme_print_flags_t fmt;
	struct ocp_smart_extended_log *data;
	int i;
	int ret;
	struct nvme_get_log_args args = {
		.args_size = sizeof(args),
		.timeout = NVME_DEFAULT_IOCTL_TIMEOUT,
		.lid = (enum nvme_cmd_get_log_lid)OCP_LID_SMART,
		.nsid = NVME_NSID_ALL,
		.len = C0_SMART_CLOUD_ATTR_LEN,
	};

	ret = validate_output_format(format, &fmt);
	if (ret < 0) {
		fprintf(stderr, "ERROR : OCP : invalid output format\n");
		return ret;
	}

	data = malloc(sizeof(__u8) * C0_SMART_CLOUD_ATTR_LEN);
	if (!data) {
		fprintf(stderr, "ERROR : OCP : malloc : %s\n", strerror(errno));
		return -1;
	}
	memset(data, 0, sizeof(__u8) * C0_SMART_CLOUD_ATTR_LEN);

	args.log = data;
	ocp_get_uuid_index(hdl, &args.uuidx);
	ret = nvme_get_log_page(hdl, NVME_LOG_PAGE_PDU_SIZE, &args);

	if (strcmp(format, "json"))
		fprintf(stderr, "NVMe Status:%s(%x)\n",
			nvme_status_to_string(ret, false), ret);

	if (ret == 0) {
		/* check log page guid */
		/* Verify GUID matches */
		for (i = 0; i < 16; i++) {
			if (scao_guid[i] != data->log_page_guid[i]) {
				int j;

				fprintf(stderr, "ERROR : OCP : Unknown GUID in C0 Log Page data\n");
				fprintf(stderr, "ERROR : OCP : Expected GUID:  0x");
				for (j = 0; j < 16; j++)
					fprintf(stderr, "%x", scao_guid[j]);

				fprintf(stderr, "\nERROR : OCP : Actual GUID:    0x");
				for (j = 0; j < 16; j++)
					fprintf(stderr, "%x", data->log_page_guid[j]);
				fprintf(stderr, "\n");

				ret = -1;
				goto out;
			}
		}

		/* print the data */
		ocp_smart_extended_log(data, format_version, fmt);
	} else {
		fprintf(stderr, "ERROR : OCP : Unable to read C0 data from buffer\n");
	}

out:
	free(data);
	return ret;
}

int ocp_smart_add_log(int argc, char **argv, struct command *cmd,
		      struct plugin *plugin)
{
	const char *desc = "Retrieve the extended SMART health data.";
	_cleanup_nvme_global_ctx_ struct nvme_global_ctx *ctx = NULL;
	_cleanup_nvme_transport_handle_ struct nvme_transport_handle *hdl = NULL;
	int ret = 0;

	struct config {
		char *output_format;
		unsigned int output_format_version;
	};

	struct config cfg = {
		.output_format = "normal",
		.output_format_version = 1,
	};

	OPT_ARGS(opts) = {
		OPT_FMT("output-format", 'o', &cfg.output_format, "output Format: normal|json"),
		OPT_UINT("output-format-version", 0, &cfg.output_format_version, "output Format version: 1|2"),
		OPT_END()
	};

	ret = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (ret)
		return ret;

	ret = get_c0_log_page(hdl, cfg.output_format,
			      cfg.output_format_version);
	if (ret)
		fprintf(stderr, "ERROR : OCP : Failure reading the C0 Log Page, ret = %d\n",
			ret);
	return ret;
}
