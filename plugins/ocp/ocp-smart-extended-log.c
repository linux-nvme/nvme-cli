// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (c) 2022 Meta Platforms, Inc.
 *
 * Authors: Arthur Shau <arthurshau@fb.com>,
 *          Wei Zhang <wzhang@fb.com>,
 *          Venkat Ramesh <venkatraghavan@fb.com>
 */

#include <errno.h>
#include <stdio.h>

#include <libnvme.h>

#include "cleanup.h"
#include "global-ctx.h"
#include "nvme-print.h"
#include "ocp-nvme.h"
#include "ocp-print.h"
#include "ocp-smart-extended-log.h"
#include "ocp-utils.h"
#include "plugin.h"

/* C0 SCAO Log Page */

static __u8 scao_guid[GUID_LEN] = {
	0xC5, 0xAF, 0x10, 0x28,
	0xEA, 0xBF, 0xF2, 0xA4,
	0x9C, 0x4F, 0x6F, 0x7C,
	0xC9, 0x14, 0xD5, 0xAF
};

/* Render a log page GUID as GUID_LEN * 2 lower-case hex digits. */
static void format_guid(char str[GUID_LEN * 2 + 1], const __u8 guid[GUID_LEN])
{
	int i;

	for (i = 0; i < GUID_LEN; i++)
		sprintf(&str[i * 2], "%02x", guid[i]);
}

static int get_c0_log_page(struct libnvme_transport_handle *hdl, char *format,
			   unsigned int format_version, bool uuid)
{
	struct ocp_smart_extended_log *data;
	struct libnvme_passthru_cmd cmd;
	nvme_print_flags_t fmt;
	__u8 uidx = 0;
	int ret;

	ret = validate_output_format(format, &fmt);
	if (ret < 0) {
		nvme_show_error("ERROR : OCP : invalid output format");
		return ret;
	}

	data = malloc(sizeof(*data));
	if (!data) {
		nvme_show_error("ERROR : OCP : malloc : %s", libnvme_strerror(errno));
		return -1;
	}
	memset(data, 0, sizeof(*data));

	if (uuid) {
		ret = ocp_get_uuid_index(hdl, &uidx);
		if (ret || !uidx) {
			nvme_show_error("ERROR : OCP : No OCP UUID index found");
			free(data);
			return ret ? ret : -ENOENT;
		}
	}

	nvme_init_get_log(&cmd, NVME_NSID_ALL,
			  (enum nvme_cmd_get_log_lid)OCP_LID_SMART,
			  NVME_CSI_NVM, data, sizeof(*data));
	cmd.cdw14 |= NVME_FIELD_ENCODE(uidx,
				       NVME_LOG_CDW14_UUID_SHIFT,
				       NVME_LOG_CDW14_UUID_MASK);
	ret = libnvme_get_log(hdl, &cmd, false, NVME_LOG_PAGE_PDU_SIZE);

	if (ret && strcmp(format, "json"))
		nvme_show_error("NVMe Status:%s(%x)",
			libnvme_status_to_string(ret, false), ret);

	if (ret) {
		nvme_show_error(
			"ERROR : OCP : Unable to read C0 data from buffer");
		goto out;
	}

	/* A page carrying any other GUID is not OCP's SCAO layout. */
	if (memcmp(scao_guid, data->log_page_guid, GUID_LEN)) {
		char expected[GUID_LEN * 2 + 1];
		char actual[GUID_LEN * 2 + 1];

		format_guid(expected, scao_guid);
		format_guid(actual, data->log_page_guid);

		nvme_show_error(
			"ERROR : OCP : Unknown GUID in C0 Log Page data");
		nvme_show_error("ERROR : OCP : Expected GUID: 0x%s", expected);
		nvme_show_error("ERROR : OCP : Actual GUID:   0x%s", actual);

		ret = -1;
		goto out;
	}

	ocp_smart_extended_log(data, format_version, fmt);

out:
	free(data);
	return ret;
}

int ocp_smart_add_log(int argc, char **argv, struct command *acmd,
		      struct plugin *plugin)
{
	const char *desc = "Retrieve the extended SMART health data.";
	const char *no_uuid = "Skip UUID index search (UUID index not required for OCP 1.0)";
	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	__cleanup_nvme_transport_handle struct libnvme_transport_handle *hdl = NULL;
	int ret = 0;

	NVME_ARGS(opts,
		OPT_FLAG("no-uuid", 'n', NULL, no_uuid));

	ret = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (ret)
		return ret;

	ret = get_c0_log_page(hdl, nvme_args.output_format,
			      nvme_args.output_format_ver,
			      !argconfig_parse_seen(opts, "no-uuid"));
	if (ret)
		nvme_show_error("ERROR : OCP : Failure reading the C0 Log Page, ret = %d",
			ret);
	return ret;
}
