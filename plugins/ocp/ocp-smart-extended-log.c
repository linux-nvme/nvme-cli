// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (c) 2022 Meta Platforms, Inc.
 *
 * Authors: Arthur Shau <arthurshau@fb.com>,
 *          Wei Zhang <wzhang@fb.com>,
 *          Venkat Ramesh <venkatraghavan@fb.com>
 */

#include <errno.h>
#include <stdio.h>

#include "common.h"
#include "nvme-print.h"
#include "ocp-nvme.h"
#include "ocp-print.h"
#include "ocp-smart-extended-log.h"
#include "ocp-utils.h"

/* C0 SCAO Log Page */
#define C0_SMART_CLOUD_ATTR_LEN			0x200

static __u8 scao_guid[GUID_LEN] = {
	0xC5, 0xAF, 0x10, 0x28,
	0xEA, 0xBF, 0xF2, 0xA4,
	0x9C, 0x4F, 0x6F, 0x7C,
	0xC9, 0x14, 0xD5, 0xAF
};

static int get_c0_log_page(struct libnvme_transport_handle *hdl, char *format,
			   unsigned int format_version)
{
	struct ocp_smart_extended_log *data;
	struct libnvme_passthru_cmd cmd;
	nvme_print_flags_t fmt;
	__u8 uidx;
	int ret;
	int i;

	ret = validate_output_format(format, &fmt);
	if (ret < 0) {
		nvme_show_error("ERROR : OCP : invalid output format");
		return ret;
	}

	data = malloc(sizeof(__u8) * C0_SMART_CLOUD_ATTR_LEN);
	if (!data) {
		nvme_show_error("ERROR : OCP : malloc : %s", libnvme_strerror(errno));
		return -1;
	}
	memset(data, 0, sizeof(__u8) * C0_SMART_CLOUD_ATTR_LEN);

	ocp_get_uuid_index(hdl, &uidx);
	nvme_init_get_log(&cmd, NVME_NSID_ALL,
			  (enum nvme_cmd_get_log_lid)OCP_LID_SMART,
			  NVME_CSI_NVM, data, C0_SMART_CLOUD_ATTR_LEN);
	cmd.cdw14 |= NVME_FIELD_ENCODE(uidx,
				       NVME_LOG_CDW14_UUID_SHIFT,
				       NVME_LOG_CDW14_UUID_MASK);
	ret = libnvme_get_log(hdl, &cmd, false, NVME_LOG_PAGE_PDU_SIZE);

	if (strcmp(format, "json"))
		nvme_show_error("NVMe Status:%s(%x)",
			libnvme_status_to_string(ret, false), ret);

	if (ret == 0) {
		/* check log page guid */
		/* Verify GUID matches */
		for (i = 0; i < 16; i++) {
			if (scao_guid[i] != data->log_page_guid[i]) {
				int j;

				nvme_show_error("ERROR : OCP : Unknown GUID in C0 Log Page data");
				nvme_show_error("ERROR : OCP : Expected GUID:  0x");
				for (j = 0; j < 16; j++)
					nvme_show_error("%x", scao_guid[j]);

				nvme_show_error("\nERROR : OCP : Actual GUID:    0x");
				for (j = 0; j < 16; j++)
					nvme_show_error("%x", data->log_page_guid[j]);
				nvme_show_error("");

				ret = -1;
				goto out;
			}
		}

		/* print the data */
		ocp_smart_extended_log(data, format_version, fmt);
	} else {
		nvme_show_error("ERROR : OCP : Unable to read C0 data from buffer");
	}

out:
	free(data);
	return ret;
}

int ocp_smart_add_log(int argc, char **argv, struct command *acmd,
		      struct plugin *plugin)
{
	const char *desc = "Retrieve the extended SMART health data.";
	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	__cleanup_nvme_transport_handle struct libnvme_transport_handle *hdl = NULL;
	int ret = 0;

	NVME_ARGS(opts);

	ret = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (ret)
		return ret;

	ret = get_c0_log_page(hdl, nvme_args.output_format,
			      nvme_args.output_format_ver);
	if (ret)
		nvme_show_error("ERROR : OCP : Failure reading the C0 Log Page, ret = %d",
			ret);
	return ret;
}
