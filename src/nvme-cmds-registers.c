// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * NVM-Express command line utility.
 *
 * Copyright (c) 2014-2015, Intel Corporation.
 *
 * Written by Keith Busch <kbusch@kernel.org>
 */

/**
 * This program uses NVMe IOCTLs to run native nvme commands to a device.
 */
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <inttypes.h>
#include <libgen.h>
#include <locale.h>
#include <math.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifdef NVME_HAVE_MMAP
#include <sys/mman.h>
#endif
#include <sys/stat.h>
#include <sys/types.h>

#include <libnvme.h>
#include <libnvme-mi.h>

#include <ccan/array_size/array_size.h>
#include <ccan/endian/endian.h>
#include <ccan/minmax/minmax.h>

#include <cleanup.h>
#include <shared/fs-util.h>
#include <shared/mmio-util.h>
#include <shared/parse-util.h>
#include <shared/sig-util.h>
#include <shared/suffix-util.h>
#include <shared/time-util.h>

#include "argconfig.h"
#include "fabrics.h"
#include "global-config.h"
#include "global-ctx.h"
#include "logging.h"
#include "nvme-cmds.h"
#include "nvme-print.h"
#include "nvme-regs.h"
#include "plugin.h"
#include "nvme-cmds-common.h"

static const char *only_ctrl_dev = "Only controller device is allowed";
static const char *offset = "offset of the requested register";
static const char *intms = "INTMS=0xc register offset";
static const char *intmc = "INTMC=0x10 register offset";
static const char *cc = "CC=0x14 register offset";
static const char *csts = "CSTS=0x1c register offset";
static const char *nssr = "NSSR=0x20 register offset";
static const char *aqa = "AQA=0x24 register offset";
static const char *asq = "ASQ=0x28 register offset";
static const char *acq = "ACQ=0x30 register offset";
static const char *bprsel = "BPRSEL=0x44 register offset";
static const char *bpmbl = "BPMBL=0x48 register offset";
static const char *cmbmsc = "CMBMSC=0x50 register offset";
static const char *nssd = "NSSD=0x64 register offset";
static const char *pmrctl = "PMRCTL=0xe04 register offset";
static const char *pmrmscl = "PMRMSCL=0xe14 register offset";
static const char *pmrmscu = "PMRMSCU=0xe18 register offset";

static int nvme_get_single_property(struct libnvme_transport_handle *hdl,
				    struct get_reg_config *cfg, __u64 *value)
{
	struct libnvme_passthru_cmd cmd;
	int err;

	nvme_init_get_property(&cmd, cfg->offset);
	err = libnvme_exec_admin_passthru(hdl, &cmd);
	if (!err) {
		*value = cmd.result;
		return 0;
	}

	if (cfg->fabrics && nvme_is_fabrics_optional_reg(cfg->offset)) {
		*value = -1;
		return 0;
	}

	if (!cfg->fabrics &&
	    nvme_status_equals(err, NVME_STATUS_TYPE_NVME,
			       NVME_SC_INVALID_FIELD)) {
		*value = -1;
		return 0;
	}

	nvme_show_err(err, "get-property");
	return err;
}

static int nvme_get_properties(struct libnvme_transport_handle *hdl, void **pbar,
			       struct get_reg_config *cfg)
{
	int err, size = shr_getpagesize();
	bool is_64bit = false;
	__u64 value;
	void *bar;
	int offset;

	bar = malloc(size);
	if (!bar)
		return -ENOMEM;

	memset(bar, 0xff, size);
	for (offset = NVME_REG_CAP; offset <= NVME_REG_CMBSZ;
	     offset += is_64bit ? sizeof(uint64_t) : sizeof(uint32_t)) {
		if (!nvme_is_fabrics_reg(offset))
			continue;

		cfg->offset = offset;
		err = nvme_get_single_property(hdl, cfg, &value);
		if (err)
			break;

		is_64bit = nvme_is_64bit_reg(cfg->offset);
		if (is_64bit)
			*(uint64_t *)(bar + cfg->offset) = value;
		else
			*(uint32_t *)(bar + cfg->offset) = value;
	}

	if (err)
		free(bar);
	else
		*pbar = bar;

	return err;
}

static int show_registers(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc = "Reads and shows the defined NVMe controller registers\n"
		"in binary or human-readable format";

	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	__cleanup_nvme_transport_handle struct libnvme_transport_handle *hdl = NULL;
	nvme_print_flags_t flags;
	void *bar;
	int err;

	struct get_reg_config cfg = {
		.fabrics = false,
	};

	NVME_ARGS(opts);

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	if (libnvme_transport_handle_is_ns(hdl)) {
		nvme_show_error(only_ctrl_dev);
		return -EINVAL;
	}

	err = validate_output_format(nvme_args.output_format, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	if (nvme_args.verbose)
		flags |= VERBOSE;

	bar = mmap_registers(hdl, false);
	if (!bar) {
		cfg.fabrics = true;
		err = nvme_get_properties(hdl, &bar, &cfg);
		if (err)
			return err;
	}

	nvme_show_ctrl_registers(bar, cfg.fabrics, flags);
	if (cfg.fabrics)
		free(bar);
	else
		munmap_registers(bar);

	return 0;
}

int get_reg_size(int offset)
{
	return nvme_is_64bit_reg(offset) ? sizeof(uint64_t) : sizeof(uint32_t);
}

static bool is_reg_selected(struct get_reg_config *cfg, int offset)
{
	switch (offset) {
	case NVME_REG_CAP:
		return cfg->cap;
	case NVME_REG_VS:
		return cfg->vs;
	case NVME_REG_INTMS:
		return cfg->intms;
	case NVME_REG_INTMC:
		return cfg->intmc;
	case NVME_REG_CC:
		return cfg->cc;
	case NVME_REG_CSTS:
		return cfg->csts;
	case NVME_REG_NSSR:
		return cfg->nssr;
	case NVME_REG_AQA:
		return cfg->aqa;
	case NVME_REG_ASQ:
		return cfg->asq;
	case NVME_REG_ACQ:
		return cfg->acq;
	case NVME_REG_CMBLOC:
		return cfg->cmbloc;
	case NVME_REG_CMBSZ:
		return cfg->cmbsz;
	case NVME_REG_BPINFO:
		return cfg->bpinfo;
	case NVME_REG_BPRSEL:
		return cfg->bprsel;
	case NVME_REG_BPMBL:
		return cfg->bpmbl;
	case NVME_REG_CMBMSC:
		return cfg->cmbmsc;
	case NVME_REG_CMBSTS:
		return cfg->cmbsts;
	case NVME_REG_CMBEBS:
		return cfg->cmbebs;
	case NVME_REG_CMBSWTP:
		return cfg->cmbswtp;
	case NVME_REG_NSSD:
		return cfg->nssd;
	case NVME_REG_CRTO:
		return cfg->crto;
	case NVME_REG_PMRCAP:
		return cfg->pmrcap;
	case NVME_REG_PMRCTL:
		return cfg->pmrctl;
	case NVME_REG_PMRSTS:
		return cfg->pmrsts;
	case NVME_REG_PMREBS:
		return cfg->pmrebs;
	case NVME_REG_PMRSWTP:
		return cfg->pmrswtp;
	case NVME_REG_PMRMSCL:
		return cfg->pmrmscl;
	case NVME_REG_PMRMSCU:
		return cfg->pmrmscu;
	default:
		break;
	}

	return false;
}

static int get_register_properties(struct libnvme_transport_handle *hdl, void **pbar, struct get_reg_config *cfg)
{
	struct libnvme_passthru_cmd cmd;
	int offset = NVME_REG_CRTO;
	__u64 value;
	int size;
	int err;
	void *bar;

	size = offset + get_reg_size(offset);
	bar = malloc(size);
	if (!bar)
		return -ENOMEM;

	for (offset = NVME_REG_CAP; offset <= NVME_REG_CRTO; offset += get_reg_size(offset)) {
		if ((cfg->offset != offset && !is_reg_selected(cfg, offset)) ||
		    !nvme_is_fabrics_reg(offset))
			continue;

		nvme_init_get_property(&cmd, offset);
		err = libnvme_exec_admin_passthru(hdl, &cmd);
		if (nvme_status_equals(err, NVME_STATUS_TYPE_NVME, NVME_SC_INVALID_FIELD)) {
			value = -1;
		} else if (err) {
			nvme_show_error("get-property: %s", libnvme_strerror(-err));
			free(bar);
			return err;
		} else {
			value = cmd.result;
		}

		if (nvme_is_64bit_reg(offset))
			*(uint64_t *)(bar + offset) = value;
		else
			*(uint32_t *)(bar + offset) = value;
	}

	*pbar = bar;

	return 0;
}

bool nvme_is_ctrl_reg(int offset)
{
	switch (offset) {
	case NVME_REG_CAP:
	case NVME_REG_VS:
	case NVME_REG_INTMS:
	case NVME_REG_INTMC:
	case NVME_REG_CC:
	case NVME_REG_CSTS:
	case NVME_REG_NSSR:
	case NVME_REG_AQA:
	case NVME_REG_ASQ:
	case NVME_REG_ACQ:
	case NVME_REG_CMBLOC:
	case NVME_REG_CMBSZ:
	case NVME_REG_BPINFO:
	case NVME_REG_BPRSEL:
	case NVME_REG_BPMBL:
	case NVME_REG_CMBMSC:
	case NVME_REG_CMBSTS:
	case NVME_REG_CMBEBS:
	case NVME_REG_CMBSWTP:
	case NVME_REG_NSSD:
	case NVME_REG_CRTO:
	case NVME_REG_PMRCAP:
	case NVME_REG_PMRCTL:
	case NVME_REG_PMRSTS:
	case NVME_REG_PMREBS:
	case NVME_REG_PMRSWTP:
	case NVME_REG_PMRMSCL:
	case NVME_REG_PMRMSCU:
		return true;
	default:
		break;
	}

	return false;
}

static bool get_register_offset(void *bar, bool fabrics, struct get_reg_config *cfg,
				nvme_print_flags_t flags)
{
	bool offset_matched = cfg->offset >= 0;
	int offset;

	if (offset_matched)
		nvme_show_ctrl_register(bar, fabrics, cfg->offset, flags);

	for (offset = NVME_REG_CAP; offset <= NVME_REG_PMRMSCU; offset += get_reg_size(offset)) {
		if (!nvme_is_ctrl_reg(offset) || offset == cfg->offset || !is_reg_selected(cfg, offset))
			continue;
		nvme_show_ctrl_register(bar, fabrics, offset, flags);
		if (!offset_matched)
			offset_matched = true;
	}

	return offset_matched;
}

static int get_register(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc = "Reads and shows the defined NVMe controller register.\n"
		"Register offset must be one of:\n"
		"CAP=0x0, VS=0x8, INTMS=0xc, INTMC=0x10, CC=0x14, CSTS=0x1c,\n"
		"NSSR=0x20, AQA=0x24, ASQ=0x28, ACQ=0x30, CMBLOC=0x38,\n"
		"CMBSZ=0x3c, BPINFO=0x40, BPRSEL=0x44, BPMBL=0x48, CMBMSC=0x50,\n"
		"CMBSTS=0x58, CRTO=0x68, PMRCAP=0xe00, PMRCTL=0xe04,\n"
		"PMRSTS=0xe08, PMREBS=0xe0c, PMRSWTP=0xe10, PMRMSCL=0xe14, PMRMSCU=0xe18";
	const char *cap = "CAP=0x0 register offset";
	const char *vs = "VS=0x8 register offset";
	const char *cmbloc = "CMBLOC=0x38 register offset";
	const char *cmbsz = "CMBSZ=0x3c register offset";
	const char *bpinfo = "BPINFO=0x40 register offset";
	const char *cmbsts = "CMBSTS=0x58 register offset";
	const char *cmbebs = "CMBEBS=0x5c register offset";
	const char *cmbswtp = "CMBSWTP=0x60 register offset";
	const char *crto = "CRTO=0x68 register offset";
	const char *pmrcap = "PMRCAP=0xe00 register offset";
	const char *pmrsts = "PMRSTS=0xe08 register offset";
	const char *pmrebs = "PMREBS=0xe0c register offset";
	const char *pmrswtp = "PMRSWTP=0xe10 register offset";
	const char *pmrmscl = "PMRMSCL=0xe14 register offset";
	const char *pmrmscu = "PMRMSCU=0xe18 register offset";

	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	__cleanup_nvme_transport_handle struct libnvme_transport_handle *hdl = NULL;
	int err;
	nvme_print_flags_t flags;
	bool fabrics = false;

	void *bar;

	struct get_reg_config cfg = {
		.offset = -1,
	};

	NVME_ARGS(opts,
		  OPT_UINT("offset",         'O', &cfg.offset,         offset),
		  OPT_FLAG("cap",              0, &cfg.cap,            cap),
		  OPT_FLAG("vs",               0, &cfg.vs,             vs),
		  OPT_FLAG("cmbloc",           0, &cfg.cmbloc,         cmbloc),
		  OPT_FLAG("cmbsz",            0, &cfg.cmbsz,          cmbsz),
		  OPT_FLAG("bpinfo",           0, &cfg.bpinfo,         bpinfo),
		  OPT_FLAG("cmbsts",           0, &cfg.cmbsts,         cmbsts),
		  OPT_FLAG("cmbebs",           0, &cfg.cmbebs,         cmbebs),
		  OPT_FLAG("cmbswtp",          0, &cfg.cmbswtp,        cmbswtp),
		  OPT_FLAG("crto",             0, &cfg.crto,           crto),
		  OPT_FLAG("pmrcap",           0, &cfg.pmrcap,         pmrcap),
		  OPT_FLAG("pmrsts",           0, &cfg.pmrsts,         pmrsts),
		  OPT_FLAG("pmrebs",           0, &cfg.pmrebs,         pmrebs),
		  OPT_FLAG("pmrswtp",          0, &cfg.pmrswtp,        pmrswtp),
		  OPT_FLAG("intms",            0, &cfg.intms,          intms),
		  OPT_FLAG("intmc",            0, &cfg.intmc,          intmc),
		  OPT_FLAG("cc",               0, &cfg.cc,             cc),
		  OPT_FLAG("csts",             0, &cfg.csts,           csts),
		  OPT_FLAG("nssr",             0, &cfg.nssr,           nssr),
		  OPT_FLAG("aqa",              0, &cfg.aqa,            aqa),
		  OPT_FLAG("asq",              0, &cfg.asq,            asq),
		  OPT_FLAG("acq",              0, &cfg.acq,            acq),
		  OPT_FLAG("bprsel",           0, &cfg.bprsel,         bprsel),
		  OPT_FLAG("bpmbl",            0, &cfg.bpmbl,          bpmbl),
		  OPT_FLAG("cmbmsc",           0, &cfg.cmbmsc,         cmbmsc),
		  OPT_FLAG("nssd",             0, &cfg.nssd,           nssd),
		  OPT_FLAG("pmrctl",           0, &cfg.pmrctl,         pmrctl),
		  OPT_FLAG("pmrmscl",          0, &cfg.pmrmscl,        pmrmscl),
		  OPT_FLAG("pmrmscu",          0, &cfg.pmrmscu,        pmrmscu));

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	if (libnvme_transport_handle_is_ns(hdl)) {
		nvme_show_error(only_ctrl_dev);
		return -EINVAL;
	}

	err = validate_output_format(nvme_args.output_format, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	if (nvme_args.verbose)
		flags |= VERBOSE;

	bar = mmap_registers(hdl, false);
	if (!bar) {
		err = get_register_properties(hdl, &bar, &cfg);
		if (err)
			return err;
		fabrics = true;
	}

	if (!get_register_offset(bar, fabrics, &cfg, flags)) {
		nvme_show_error("offset required param");
		err = -EINVAL;
	}

	if (fabrics)
		free(bar);
	else
		munmap_registers(bar);

	return err;
}

static int nvme_set_single_property(struct libnvme_transport_handle *hdl, int offset, uint64_t value)
{
	struct libnvme_passthru_cmd cmd;
	int err;

	nvme_init_set_property(&cmd, offset, value);
	err = libnvme_exec_admin_passthru(hdl, &cmd);
	if (err) {
		nvme_show_err(err, "set-property");
		return err;
	}

	nvme_show_result("set-property: %#02x (%s), value: %#"PRIx64, offset,
	                 nvme_register_to_string(offset), value);

	return err;
}

static int set_register_property(struct libnvme_transport_handle *hdl, int offset, uint64_t value)
{
	if (!nvme_is_fabrics_reg(offset)) {
		nvme_show_error("register: %#04x (%s) not fabrics", offset,
		                nvme_register_to_string(offset));
		return -EINVAL;
	}

	return nvme_set_single_property(hdl, offset, value);
}

static int nvme_set_register(struct libnvme_transport_handle *hdl, void *bar, int offset, uint64_t value, bool mmio32)
{
	if (!bar)
		return set_register_property(hdl, offset, value);

	if (nvme_is_64bit_reg(offset))
		shr_mmio_write64(bar + offset, value, mmio32);
	else
		shr_mmio_write32(bar + offset, value);

	nvme_show_result("set-register: %#02x (%s), value: %#"PRIx64, offset,
	                 nvme_register_to_string(offset), value);

	return 0;
}

static inline int set_register_names_check(struct argconfig_commandline_options *opts, int offset)
{
	switch (offset) {
	case NVME_REG_INTMS:
		if (argconfig_parse_seen(opts, "intms"))
			return -EINVAL;
		break;
	case NVME_REG_INTMC:
		if (argconfig_parse_seen(opts, "intmc"))
			return -EINVAL;
		break;
	case NVME_REG_CC:
		if (argconfig_parse_seen(opts, "cc"))
			return -EINVAL;
		break;
	case NVME_REG_CSTS:
		if (argconfig_parse_seen(opts, "csts"))
			return -EINVAL;
		break;
	case NVME_REG_NSSR:
		if (argconfig_parse_seen(opts, "nssr"))
			return -EINVAL;
		break;
	case NVME_REG_AQA:
		if (argconfig_parse_seen(opts, "aqa"))
			return -EINVAL;
		break;
	case NVME_REG_ASQ:
		if (argconfig_parse_seen(opts, "asq"))
			return -EINVAL;
		break;
	case NVME_REG_ACQ:
		if (argconfig_parse_seen(opts, "acq"))
			return -EINVAL;
		break;
	case NVME_REG_BPRSEL:
		if (argconfig_parse_seen(opts, "bprsel"))
			return -EINVAL;
		break;
	case NVME_REG_CMBMSC:
		if (argconfig_parse_seen(opts, "cmbmsc"))
			return -EINVAL;
		break;
	case NVME_REG_NSSD:
		if (argconfig_parse_seen(opts, "nssd"))
			return -EINVAL;
		break;
	case NVME_REG_PMRCTL:
		if (argconfig_parse_seen(opts, "pmrctl"))
			return -EINVAL;
		break;
	case NVME_REG_PMRMSCL:
		if (argconfig_parse_seen(opts, "pmrmscl"))
			return -EINVAL;
		break;
	case NVME_REG_PMRMSCU:
		if (argconfig_parse_seen(opts, "pmrmscu"))
			return -EINVAL;
		break;
	default:
		break;
	}

	return 0;
}

static int set_register_offset(struct libnvme_transport_handle *hdl, void *bar, struct argconfig_commandline_options *opts,
			       struct set_reg_config *cfg)
{
	int err;

	if (!argconfig_parse_seen(opts, "value")) {
		nvme_show_error("value required param");
		return -EINVAL;
	}

	err = set_register_names_check(opts, cfg->offset);
	if (err) {
		nvme_show_error("offset duplicated param");
		return err;
	}

	err = nvme_set_register(hdl, bar, cfg->offset, cfg->value, cfg->mmio32);
	if (err)
		return err;

	return 0;
}

static int set_register_names(struct libnvme_transport_handle *hdl, void *bar, struct argconfig_commandline_options *opts,
			      struct set_reg_config *cfg)
{
	int err;

	if (argconfig_parse_seen(opts, "intms")) {
		err = nvme_set_register(hdl, bar, NVME_REG_INTMS, cfg->intms, cfg->mmio32);
		if (err)
			return err;
	}

	if (argconfig_parse_seen(opts, "intmc")) {
		err = nvme_set_register(hdl, bar, NVME_REG_INTMC, cfg->intmc, cfg->mmio32);
		if (err)
			return err;
	}

	if (argconfig_parse_seen(opts, "cc")) {
		err = nvme_set_register(hdl, bar, NVME_REG_CC, cfg->cc, cfg->mmio32);
		if (err)
			return err;
	}

	if (argconfig_parse_seen(opts, "csts")) {
		err = nvme_set_register(hdl, bar, NVME_REG_CSTS, cfg->csts, cfg->mmio32);
		if (err)
			return err;
	}

	if (argconfig_parse_seen(opts, "nssr")) {
		err = nvme_set_register(hdl, bar, NVME_REG_NSSR, cfg->nssr, cfg->mmio32);
		if (err)
			return err;
	}

	if (argconfig_parse_seen(opts, "aqa")) {
		err = nvme_set_register(hdl, bar, NVME_REG_AQA, cfg->aqa, cfg->mmio32);
		if (err)
			return err;
	}

	if (argconfig_parse_seen(opts, "asq")) {
		err = nvme_set_register(hdl, bar, NVME_REG_ASQ, cfg->asq, cfg->mmio32);
		if (err)
			return err;
	}

	if (argconfig_parse_seen(opts, "acq")) {
		err = nvme_set_register(hdl, bar, NVME_REG_ACQ, cfg->acq, cfg->mmio32);
		if (err)
			return err;
	}

	if (argconfig_parse_seen(opts, "bprsel")) {
		err = nvme_set_register(hdl, bar, NVME_REG_BPRSEL, cfg->bprsel, cfg->mmio32);
		if (err)
			return err;
	}

	if (argconfig_parse_seen(opts, "cmbmsc")) {
		err = nvme_set_register(hdl, bar, NVME_REG_CMBMSC, cfg->cmbmsc, cfg->mmio32);
		if (err)
			return err;
	}

	if (argconfig_parse_seen(opts, "nssd")) {
		err = nvme_set_register(hdl, bar, NVME_REG_NSSD, cfg->nssd, cfg->mmio32);
		if (err)
			return err;
	}

	if (argconfig_parse_seen(opts, "pmrctl")) {
		err = nvme_set_register(hdl, bar, NVME_REG_PMRCTL, cfg->pmrctl, cfg->mmio32);
		if (err)
			return err;
	}

	if (argconfig_parse_seen(opts, "pmrmscl")) {
		err = nvme_set_register(hdl, bar, NVME_REG_PMRMSCL, cfg->pmrmscl, cfg->mmio32);
		if (err)
			return err;
	}

	if (argconfig_parse_seen(opts, "pmrmscu")) {
		err = nvme_set_register(hdl, bar, NVME_REG_PMRMSCU, cfg->pmrmscu, cfg->mmio32);
		if (err)
			return err;
	}

	return 0;
}

static int set_register(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc = "Writes and shows the defined NVMe controller register";
	const char *value = "the value of the register to be set";
	const char *mmio32 = "Access 64-bit registers as 2 32-bit";

	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	__cleanup_nvme_transport_handle struct libnvme_transport_handle *hdl = NULL;
	int err;
	void *bar;

	struct set_reg_config cfg = {
		.offset = -1,
	};

	NVME_ARGS(opts,
		  OPT_UINT("offset",  'O', &cfg.offset,  offset),
		  OPT_SUFFIX("value", 'V', &cfg.value,   value),
		  OPT_FLAG("mmio32",  'm', &cfg.mmio32,  mmio32),
		  OPT_UINT("intms",     0, &cfg.intms,   intms),
		  OPT_UINT("intmc",     0, &cfg.intmc,   intmc),
		  OPT_UINT("cc",        0, &cfg.cc,      cc),
		  OPT_UINT("csts",      0, &cfg.csts,    csts),
		  OPT_UINT("nssr",      0, &cfg.nssr,    nssr),
		  OPT_UINT("aqa",       0, &cfg.aqa,     aqa),
		  OPT_SUFFIX("asq",     0, &cfg.asq,     asq),
		  OPT_SUFFIX("acq",     0, &cfg.acq,     acq),
		  OPT_UINT("bprsel",    0, &cfg.bprsel,  bprsel),
		  OPT_SUFFIX("bpmbl",   0, &cfg.bpmbl,   bpmbl),
		  OPT_SUFFIX("cmbmsc",  0, &cfg.cmbmsc,  cmbmsc),
		  OPT_UINT("nssd",      0, &cfg.nssd,    nssd),
		  OPT_UINT("pmrctl",    0, &cfg.pmrctl,  pmrctl),
		  OPT_UINT("pmrmscl",   0, &cfg.pmrmscl, pmrmscl),
		  OPT_UINT("pmrmscu",   0, &cfg.pmrmscu, pmrmscu));

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	if (libnvme_transport_handle_is_ns(hdl)) {
		nvme_show_error(only_ctrl_dev);
		return -EINVAL;
	}

	bar = mmap_registers(hdl, true);

	if (argconfig_parse_seen(opts, "offset"))
		err = set_register_offset(hdl, bar, opts, &cfg);

	if (!err)
		err = set_register_names(hdl, bar, opts, &cfg);

	if (bar)
		munmap_registers(bar);

	return err;
}

static int get_property(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc = "Reads and shows the defined NVMe controller property\n"
		"for NVMe over Fabric. Property offset must be one of:\n"
		"CAP=0x0, VS=0x8, CC=0x14, CSTS=0x1c, NSSR=0x20, NSSD=0x64, CRTO=0x68";
	const char *offset = "offset of the requested property";

	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	__cleanup_nvme_transport_handle struct libnvme_transport_handle *hdl = NULL;
	__u64 value;
	int err;
	nvme_print_flags_t flags = NORMAL;

	struct get_reg_config cfg = {
		.offset		= -1,
		.fabrics	= true,
	};

	NVME_ARGS(opts,
		  OPT_UINT("offset",         'O', &cfg.offset,         offset));

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	err = validate_output_format(nvme_args.output_format, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	if (cfg.offset == -1) {
		nvme_show_error("offset required param");
		return -EINVAL;
	}

	if (nvme_args.verbose)
		flags |= VERBOSE;

	err = nvme_get_single_property(hdl, &cfg, &value);
	if (!err)
		nvme_show_single_property(cfg.offset, value, flags);

	return err;
}

static int set_property(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc =
	    "Writes and shows the defined NVMe controller property for NVMe over Fabric";
	const char *offset = "the offset of the property";
	const char *value = "the value of the property to be set";

	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	__cleanup_nvme_transport_handle struct libnvme_transport_handle *hdl = NULL;
	int err;
	nvme_print_flags_t flags;

	struct set_reg_config cfg = {
		.offset	= -1,
		.value	= -1,
	};

	NVME_ARGS(opts,
		  OPT_UINT("offset", 'O', &cfg.offset, offset),
		  OPT_UINT("value",  'V', &cfg.value,  value));

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	err = validate_output_format(nvme_args.output_format, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	if (cfg.offset == -1) {
		nvme_show_error("offset required param");
		return -EINVAL;
	}
	if (cfg.value == -1) {
		nvme_show_error("value required param");
		return -EINVAL;
	}

	return nvme_set_single_property(hdl, cfg.offset, cfg.value);
}
static struct command show_registers_cmd = {
	.name = "show-regs",
	.help = "Shows the controller registers or properties. Requires character device",
	.fn = show_registers,
};

static struct command set_register_cmd = {
	.name = "set-reg",
	.help = "Set a register and show the resulting value",
	.fn = set_register,
};

static struct command get_register_cmd = {
	.name = "get-reg",
	.help = "Get a register and show the resulting value",
	.fn = get_register,
};

static struct command set_property_cmd = {
	.name = "set-property",
	.help = "Set a property and show the resulting value",
	.fn = set_property,
};

static struct command get_property_cmd = {
	.name = "get-property",
	.help = "Get a property and show the resulting value",
	.fn = get_property,
};

static struct command *commands[] = {
	&show_registers_cmd,
	&set_register_cmd,
	&get_register_cmd,
	&set_property_cmd,
	&get_property_cmd,
	NULL,
};

static void __attribute__((constructor)) register_group(void)
{
	plugin_add_group(&builtin, "Registers", commands);
}
