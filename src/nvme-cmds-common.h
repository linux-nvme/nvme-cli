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

struct passthru_config {
	__u8	opcode;
	__u8	flags;
	__u16	rsvd;
	__u32	namespace_id;
	__u32	data_len;
	__u32	metadata_len;
	__u32	cdw2;
	__u32	cdw3;
	__u32	cdw10;
	__u32	cdw11;
	__u32	cdw12;
	__u32	cdw13;
	__u32	cdw14;
	__u32	cdw15;
	char	*input_file;
	char	*metadata;
	bool	raw_binary;
	bool	show_command;
	bool	read;
	bool	write;
	__u8	prefill;
	bool	latency;
};

struct get_reg_config {
	int offset;
	bool cap;
	bool vs;
	bool intms;
	bool intmc;
	bool cc;
	bool csts;
	bool nssr;
	bool aqa;
	bool asq;
	bool acq;
	bool cmbloc;
	bool cmbsz;
	bool bpinfo;
	bool bprsel;
	bool bpmbl;
	bool cmbmsc;
	bool cmbsts;
	bool cmbebs;
	bool cmbswtp;
	bool nssd;
	bool crto;
	bool pmrcap;
	bool pmrctl;
	bool pmrsts;
	bool pmrebs;
	bool pmrswtp;
	bool pmrmscl;
	bool pmrmscu;
	bool fabrics;
};

struct set_reg_config {
	int offset;
	bool mmio32;
	__u64 value;
	__u32 intms;
	__u32 intmc;
	__u32 cc;
	__u32 csts;
	__u32 nssr;
	__u32 aqa;
	__u64 asq;
	__u64 acq;
	__u32 bprsel;
	__u64 bpmbl;
	__u64 cmbmsc;
	__u32 nssd;
	__u32 pmrctl;
	__u32 pmrmscl;
	__u32 pmrmscu;
};

struct nvme_get_log_args {
	__u32 nsid;
	bool rae;
	__u8 lsp;
	enum nvme_cmd_get_log_lid lid;
	__u16 lsi;
	enum nvme_csi csi;
	bool ot;
	__u8 uidx;
	__u64 lpo;
	void *log;
	__u32 len;
	__u64 *result;
};

static inline bool nvme_match_devname(char *devname, struct libnvme_ns *ns)
{
	struct libnvme_ctrl *c = libnvme_ns_get_ctrl(ns);

	if (!strcmp(devname, libnvme_ns_get_name(ns)) ||
	    (c && !strcmp(devname, libnvme_ctrl_get_name(c))) ||
	    !strcmp(devname, libnvme_ns_get_generic_name(ns)))
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
			if (!strcmp(devname, libnvme_ns_get_name(n)))
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
