// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2023 Solidigm.
 *
 * Authors: leonardo.da.cunha@solidigm.com
 */

#include <errno.h>
#include "nvme-print.h"
#include "nvme-wrap.h"
#include "common.h"

int sldgm_get_drive_info(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	_cleanup_nvme_dev_ struct nvme_dev *dev = NULL;
	const char *desc = "Get drive HW information";
	const char *FTL_unit_size_str = "FTL_unit_size";
	char *output_format = "normal";
	nvme_print_flags_t flags;
	nvme_root_t r;
	nvme_ctrl_t c;
	nvme_ns_t n;
	struct nvme_id_ns ns = { 0 };
	__u8 flbaf_inUse;
	__u16 lba_size;
	__u16 ftl_unit_size;
	int err;

	OPT_ARGS(opts) = {
		OPT_FMT("output-format", 'o', &output_format, "normal|json"),
		OPT_END()
	};

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		return err;

	err = validate_output_format(output_format, &flags);
	if ((err < 0) || !(flags == NORMAL || flags == JSON)) {
		nvme_show_error("Invalid output format");
		return err;
	}

	r = nvme_scan(NULL);
	c = nvme_scan_ctrl(r, dev->name);
	n = c ? nvme_ctrl_first_ns(c) : nvme_scan_namespace(dev->name);
	if (!n) {
		nvme_show_error("solidigm-vs-drive-info: drive missing namespace");
		return -EINVAL;
	}

	err = nvme_ns_identify(n, &ns);
	if (err) {
		nvme_show_error("identify namespace: %s", nvme_strerror(errno));
		return err;
	}

	if (!(ns.nsfeat & 0x10)) {
		nvme_show_error("solidigm-vs-drive-info: performance options not available");
		return -EINVAL;
	}

	nvme_id_ns_flbas_to_lbaf_inuse(ns.flbas, &flbaf_inUse);
	lba_size = 1 << ns.lbaf[flbaf_inUse].ds;
	ftl_unit_size = (le16_to_cpu(ns.npwg) + 1) * lba_size / 1024;

	if (flags == JSON) {
		struct json_object *root = json_create_object();

		json_object_add_value_int(root, FTL_unit_size_str, ftl_unit_size);
		json_print_object(root, NULL);
		printf("\n");
		json_free_object(root);
	} else {
		printf("%s: %d\n", FTL_unit_size_str, ftl_unit_size);
	}

	return err;
}
