/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 SUSE Software Solutions
 *
 * Authors: Daniel Wagner <dwagner@suse.de>
 */
#pragma once

#include <string.h>

#include <libnvme.h>

#include <ccan/str/str.h>

#include "nvme-print.h"

struct feat_cfg {
	__u8 feature_id;   /* enum nvme_features_id */
	__u8 sel;          /* enum nvme_get_features_sel */
	__u32 namespace_id;
	__u32 cdw11;
	__u32 cdw12;
	__u8 uuid_index;
	__u32 data_len;
	bool raw_binary;
	bool changed;
};

static inline bool nvme_match_devname(char *devname, struct libnvme_ns *ns)
{
	struct libnvme_ctrl *c = libnvme_ns_get_ctrl(ns);

	if (streq(devname, libnvme_ns_get_name(ns)) ||
	    (c && streq(devname, libnvme_ctrl_get_name(c))) ||
	    streq(devname, libnvme_ns_get_generic_name(ns)))
		return true;

	return false;
}

static inline bool nvme_match_device_filter(struct libnvme_subsystem *s,
		struct libnvme_ctrl *c, struct libnvme_ns *ns, void *f_args)
{
	char *devname = f_args;
	struct libnvme_ns *n;

	if (ns && nvme_match_devname(devname, ns))
		return true;

	if (c) {
		s = libnvme_ctrl_get_subsystem(c);
		libnvme_ctrl_for_each_ns(c, n) {
			if (nvme_match_devname(devname, n))
				return true;
		}
	}
	if (s) {
		libnvme_subsystem_for_each_ns(s, n) {
			if (streq(devname, libnvme_ns_get_name(n)))
				return true;
		}
	}

	return false;
}

static inline int handle_scan_topology_error(int err)
{
	/* Do not report an error when nvme_core module is not loaded */
	if (err == -ENOENT) {
		if (log_level >= LIBNVME_LOG_INFO)
			nvme_show_error("nvme modules not loaded");
		return 0;
	}

	nvme_show_error("Failed to scan topology: %s", libnvme_strerror(-err));
	return err;
}
