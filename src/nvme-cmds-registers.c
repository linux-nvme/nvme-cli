// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * NVM-Express command line utility.
 *
 * Copyright (c) 2014-2015, Intel Corporation.
 * Copyright (c) 2026 SUSE LLC
 *
 * Written by Keith Busch <kbusch@kernel.org>
 */

/*
 * The commands of the controller registers, which a fabrics controller has
 * as properties: show-regs, get-reg, set-reg, get-property and
 * set-property. The registers are described by the table of nvme-regs.c.
 */
#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>

#include <libnvme.h>

#include <ccan/array_size/array_size.h>
#include <shared/compiler-attributes-util.h>
#include <shared/mmio-util.h>

#include "argconfig.h"
#include "cleanup.h"
#include "global-ctx.h"
#include "logging.h"
#include "nvme-cmds-common.h"
#include "nvme-print.h"
#include "nvme-regs.h"
#include "plugin.h"

#define ALL_REGS	((UINT32_C(1) << NVME_NR_REGS) - 1)

static const char *only_ctrl_dev = "Only controller device is allowed";
static const char *reg_required = "a register has to be given";

static bool reg_is_ns(struct libnvme_transport_handle *hdl)
{
	if (libnvme_transport_handle_is_ns(hdl)) {
		nvme_show_error(only_ctrl_dev);
		return true;
	}
	return false;
}

/* A property of the controller, or of a fabrics one at least */
static int property_get(struct libnvme_transport_handle *hdl,
			uint32_t offset, uint64_t *value)
{
	struct libnvme_passthru_cmd cmd;
	int err;

	nvme_init_get_property(&cmd, offset);
	err = libnvme_exec_admin_passthru(hdl, &cmd);
	if (!err)
		*value = cmd.result;

	return err;
}

/*
 * Reads the property of @reg into @value. A controller fails a property
 * it doesn't implement with Invalid Field in Command, maybe with the DNR
 * bit: @explicit fails for it, and for a register which is no property
 * of a fabrics controller, otherwise they are left out.
 *
 * Return: 0, PROPERTY_LEFT_OUT, PROPERTY_REFUSED or the error.
 */
#define PROPERTY_LEFT_OUT	1
#define PROPERTY_REFUSED	2

static int property_read(struct libnvme_transport_handle *hdl,
			 const struct nvme_reg *reg, bool explicit,
			 uint64_t *value)
{
	int err;

	if (!(reg->flags & NVME_REGF_FABRICS)) {
		if (!explicit)
			return PROPERTY_LEFT_OUT;
		nvme_show_error("register: %#04x (%s) not fabrics",
				reg->offset, reg->name);
		return PROPERTY_REFUSED;
	}

	err = property_get(hdl, reg->offset, value);
	if (err && libnvme_status_is_invalid_field(err)) {
		if (!explicit && reg->flags & NVME_REGF_OPTIONAL)
			return PROPERTY_LEFT_OUT;
		nvme_show_error("register: %#04x (%s) not implemented",
				reg->offset, reg->name);
		return PROPERTY_REFUSED;
	}
	if (err)
		nvme_show_err(err, "get-property");

	return err;
}

/*
 * Reads the registers of @sel, a bit for each of enum nvme_reg_idx, into
 * @vals and their number into @nr. Without the registers of a PCI
 * device, they are the properties of a fabrics controller (*@fabrics),
 * see property_read().
 *
 * Return: 0, or the error of the first register which failed: the others
 * are read regardless, unless the controller failed otherwise.
 */
static int regs_read(struct libnvme_transport_handle *hdl, uint32_t sel,
		     bool explicit, struct nvme_reg_val *vals,
		     unsigned int *nr, bool *fabrics)
{
	uint8_t page[NVME_REG_PMRMSCU + sizeof(uint32_t)];
	int err = 0, ret;
	unsigned int i;

	*nr = 0;
	*fabrics = libnvme_read_regs(hdl, NVME_REG_CAP, page,
				     NVME_REG_CRTO + sizeof(uint32_t)) ||
		   libnvme_read_regs(hdl, NVME_REG_PMRCAP,
				     page + NVME_REG_PMRCAP,
				     NVME_REG_PMRMSCU + sizeof(uint32_t) -
				     NVME_REG_PMRCAP);

	for (i = 0; i < NVME_NR_REGS; i++) {
		const struct nvme_reg *reg = &nvme_regs[i];
		uint64_t value;

		if (!(sel & (1U << i)))
			continue;

		if (!*fabrics) {
			value = reg->size == 8 ?
				shr_mmio_read64(page + reg->offset) :
				shr_mmio_read32(page + reg->offset);
		} else {
			ret = property_read(hdl, reg, explicit, &value);
			if (ret == PROPERTY_LEFT_OUT)
				continue;
			if (ret == PROPERTY_REFUSED) {
				err = err ?: -EINVAL;
				continue;
			}
			if (ret)
				return ret;
		}

		vals[(*nr)++] = (struct nvme_reg_val){ reg, value };
	}

	return err;
}

/*
 * Writes @value to @reg: to the register of the PCI device if it can be
 * accessed (@mapped), the property of a fabrics controller otherwise.
 */
static int reg_write(struct libnvme_transport_handle *hdl,
		     const struct nvme_reg *reg, uint64_t value, bool mmio32,
		     bool mapped)
{
	struct libnvme_passthru_cmd cmd;
	int err;

	if (reg->size == 4 && value > UINT32_MAX) {
		nvme_show_error("value %#"PRIx64" too large for %s", value,
				reg->sym);
		return -EINVAL;
	}

	if (mapped) {
		if (reg->size == 8)
			err = libnvme_write_reg64(hdl, reg->offset, value,
						  mmio32);
		else
			err = libnvme_write_reg32(hdl, reg->offset, value);
		if (err) {
			nvme_show_err(err, "set-register");
			return err;
		}
		nvme_show_result("set-register: %#02x (%s), value: %#"PRIx64,
				 reg->offset, reg->name, value);
		return 0;
	}

	if (!(reg->flags & NVME_REGF_FABRICS)) {
		nvme_show_error("register: %#04x (%s) not fabrics",
				reg->offset, reg->name);
		return -EINVAL;
	}

	nvme_init_set_property(&cmd, reg->offset, value);
	err = libnvme_exec_admin_passthru(hdl, &cmd);
	if (err) {
		nvme_show_err(err, "set-property");
		return err;
	}
	nvme_show_result("set-property: %#02x (%s), value: %#"PRIx64,
			 reg->offset, reg->name, value);

	return 0;
}

static nvme_print_flags_t reg_print_flags(void)
{
	nvme_print_flags_t flags = nvme_args.output_flags;

	if (nvme_args.verbose)
		flags |= VERBOSE;
	return flags;
}

static int show_registers(int argc, char **argv, struct command *acmd,
			  struct plugin *plugin)
{
	const char *desc =
		"Reads and shows the defined NVMe controller registers\n"
		"in binary or human-readable format";

	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	__cleanup_nvme_transport_handle
		struct libnvme_transport_handle *hdl = NULL;
	struct nvme_reg_val vals[NVME_NR_REGS];
	unsigned int nr;
	bool fabrics;
	int err;

	OPT_ARGS(opts) = {
		OPT_END()
	};

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	if (reg_is_ns(hdl))
		return -EINVAL;

	err = regs_read(hdl, ALL_REGS, false, vals, &nr, &fabrics);
	if (err)
		return err;

	nvme_show_ctrl_registers(vals, nr, NVME_REGS_TABLE, reg_print_flags());

	return 0;
}

/* The option of the register @idx */
#define OPT_REG_FLAG(sym, idx)						\
	OPT_FLAG(sym, 0, &old[NVME_REGI_##idx], "the " sym " register")

static int get_register(int argc, char **argv, struct command *acmd,
			struct plugin *plugin)
{
	const char *desc =
		"Reads and shows the defined NVMe controller registers.";
	const char *offset_desc = "the offset of a register";

	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	__cleanup_nvme_transport_handle
		struct libnvme_transport_handle *hdl = NULL;
	struct nvme_reg_val vals[NVME_NR_REGS];
	bool old[NVME_NR_REGS] = { false };
	const struct nvme_reg *reg;
	uint32_t offset = 0, sel = 0;
	unsigned int i, nr;
	bool fabrics;
	int err;

	OPT_ARGS(opts) = {
		OPT_UINT("offset", 'O', &offset, offset_desc),
		OPT_REG_FLAG("cap", CAP),
		OPT_REG_FLAG("vs", VS),
		OPT_REG_FLAG("intms", INTMS),
		OPT_REG_FLAG("intmc", INTMC),
		OPT_REG_FLAG("cc", CC),
		OPT_REG_FLAG("csts", CSTS),
		OPT_REG_FLAG("nssr", NSSR),
		OPT_REG_FLAG("aqa", AQA),
		OPT_REG_FLAG("asq", ASQ),
		OPT_REG_FLAG("acq", ACQ),
		OPT_REG_FLAG("cmbloc", CMBLOC),
		OPT_REG_FLAG("cmbsz", CMBSZ),
		OPT_REG_FLAG("bpinfo", BPINFO),
		OPT_REG_FLAG("bprsel", BPRSEL),
		OPT_REG_FLAG("bpmbl", BPMBL),
		OPT_REG_FLAG("cmbmsc", CMBMSC),
		OPT_REG_FLAG("cmbsts", CMBSTS),
		OPT_REG_FLAG("cmbebs", CMBEBS),
		OPT_REG_FLAG("cmbswtp", CMBSWTP),
		OPT_REG_FLAG("nssd", NSSD),
		OPT_REG_FLAG("crto", CRTO),
		OPT_REG_FLAG("pmrcap", PMRCAP),
		OPT_REG_FLAG("pmrctl", PMRCTL),
		OPT_REG_FLAG("pmrsts", PMRSTS),
		OPT_REG_FLAG("pmrebs", PMREBS),
		OPT_REG_FLAG("pmrswtp", PMRSWTP),
		OPT_REG_FLAG("pmrmscl", PMRMSCL),
		OPT_REG_FLAG("pmrmscu", PMRMSCU),
		OPT_END()
	};

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	if (reg_is_ns(hdl))
		return -EINVAL;

	/* The registers are read into a page: no other offset in there. */
	if (argconfig_given(opts, &offset)) {
		reg = nvme_reg_by_offset(offset);
		if (!reg) {
			nvme_show_error("invalid register offset: %#x", offset);
			return -EINVAL;
		}
		sel |= 1U << (reg - nvme_regs);
	}
	for (i = 0; i < NVME_NR_REGS; i++)
		if (old[i])
			sel |= 1U << i;
	if (!sel) {
		nvme_show_error(reg_required);
		return -EINVAL;
	}

	err = regs_read(hdl, sel, true, vals, &nr, &fabrics);
	nvme_show_ctrl_registers(vals, nr, NVME_REGS_REGISTER,
				 reg_print_flags());

	return err;
}

/* The option of the value of the register @idx */
#define OPT_REG_VAL(sym, idx)						\
	OPT_UINT(sym, 0, &val32[NVME_REGI_##idx],			\
		 "the value of the " sym " register")
#define OPT_REG_VAL64(sym, idx)						\
	OPT_SUFFIX(sym, 0, &val64[NVME_REGI_##idx],			\
		   "the value of the " sym " register")

static int set_register(int argc, char **argv, struct command *acmd,
			struct plugin *plugin)
{
	const char *desc =
		"Writes and shows the defined NVMe controller register";
	const char *offset_desc = "the offset of the register";
	const char *value = "the value of the register to be set";
	const char *mmio32 = "Access 64-bit registers as 2 32-bit";

	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	__cleanup_nvme_transport_handle
		struct libnvme_transport_handle *hdl = NULL;
	uint32_t val32[NVME_NR_REGS] = { 0 };
	uint64_t val64[NVME_NR_REGS] = { 0 };
	const struct nvme_reg *reg = NULL;
	struct argconfig_commandline_options *o;
	uint64_t vals[NVME_NR_REGS] = { 0 };
	uint32_t offset = 0, dummy, sel = 0;
	int err;
	unsigned int i;
	bool mapped;

	struct {
		uint64_t value;
		bool mmio32;
	} cfg = { 0 };

	OPT_ARGS(opts) = {
		OPT_UINT("offset", 'O', &offset, offset_desc),
		OPT_SUFFIX("value", 'V', &cfg.value, value),
		OPT_FLAG("mmio32", 'm', &cfg.mmio32, mmio32),
		OPT_REG_VAL("intms", INTMS),
		OPT_REG_VAL("intmc", INTMC),
		OPT_REG_VAL("cc", CC),
		OPT_REG_VAL("csts", CSTS),
		OPT_REG_VAL("nssr", NSSR),
		OPT_REG_VAL("aqa", AQA),
		OPT_REG_VAL64("asq", ASQ),
		OPT_REG_VAL64("acq", ACQ),
		OPT_REG_VAL("bprsel", BPRSEL),
		OPT_REG_VAL64("bpmbl", BPMBL),
		OPT_REG_VAL64("cmbmsc", CMBMSC),
		OPT_REG_VAL("nssd", NSSD),
		OPT_REG_VAL("pmrctl", PMRCTL),
		OPT_REG_VAL("pmrmscl", PMRMSCL),
		OPT_REG_VAL("pmrmscu", PMRMSCU),
		OPT_END()
	};

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	if (reg_is_ns(hdl))
		return -EINVAL;

	if (argconfig_given(opts, &offset)) {
		reg = nvme_reg_by_offset(offset);
		if (!reg) {
			nvme_show_error("invalid register offset: %#x", offset);
			return -EINVAL;
		}
	}

	if (reg) {
		if (!(reg->flags & NVME_REGF_WRITE)) {
			nvme_show_error("register %s is read only", reg->sym);
			return -EINVAL;
		}
		if (!argconfig_given(opts, &cfg.value)) {
			nvme_show_error("value required param");
			return -EINVAL;
		}
	}

	/* the registers of the options of each, in register order */
	for (o = opts; o->option; o++) {
		if (!argconfig_given(opts, o->default_value))
			continue;
		for (i = 0; i < NVME_NR_REGS; i++) {
			if (o->default_value == &val32[i])
				vals[i] = val32[i];
			else if (o->default_value == &val64[i])
				vals[i] = val64[i];
			else
				continue;
			if (reg == &nvme_regs[i]) {
				nvme_show_error("offset duplicated param");
				return -EINVAL;
			}
			sel |= 1U << i;
		}
	}

	mapped = !libnvme_read_regs(hdl, NVME_REG_CAP, &dummy, sizeof(dummy));

	if (reg) {
		err = reg_write(hdl, reg, cfg.value, cfg.mmio32, mapped);
		if (err)
			return err;
	}
	for (i = 0; i < NVME_NR_REGS; i++) {
		if (!(sel & (1U << i)))
			continue;
		err = reg_write(hdl, &nvme_regs[i], vals[i], cfg.mmio32,
				mapped);
		if (err)
			return err;
	}

	if (!reg && !sel) {
		nvme_show_error(reg_required);
		return -EINVAL;
	}

	return 0;
}

/*
 * The register at @offset, or a register of no name for a property out
 * of the table, in @unknown with its offset in @sym.
 */
static const struct nvme_reg *property_reg(uint32_t offset,
					   struct nvme_reg *unknown,
					   char *sym, size_t len)
{
	const struct nvme_reg *reg = nvme_reg_by_offset(offset);

	if (reg)
		return reg;

	snprintf(sym, len, "%#x", offset);
	*unknown = (struct nvme_reg) {
		.offset = offset,
		.size = nvme_is_64bit_reg(offset) ? 8 : 4,
		.sym = sym,
		.name = "Unknown",
	};
	return unknown;
}

static int get_property(int argc, char **argv, struct command *acmd,
			struct plugin *plugin)
{
	const char *desc = "Reads and shows the defined NVMe controller property\n"
		"for NVMe over Fabric. Property offset must be one of:\n"
		"CAP=0x0, VS=0x8, CC=0x14, CSTS=0x1c, NSSR=0x20, NSSD=0x64, CRTO=0x68";
	const char *offset_desc = "the offset of the property";

	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	__cleanup_nvme_transport_handle
		struct libnvme_transport_handle *hdl = NULL;
	struct nvme_reg unknown;
	struct nvme_reg_val val;
	uint32_t offset = 0;
	char sym[16];
	int err;

	OPT_ARGS(opts) = {
		OPT_UINT("offset", 'O', &offset, offset_desc),
		OPT_END()
	};

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	if (!argconfig_given(opts, &offset)) {
		nvme_show_error("offset required param");
		return -EINVAL;
	}

	/* Any failure, also of a property the controller doesn't implement */
	val.reg = property_reg(offset, &unknown, sym, sizeof(sym));
	err = property_get(hdl, offset, &val.value);
	if (err) {
		nvme_show_err(err, "get-property");
		return err;
	}

	nvme_show_ctrl_registers(&val, 1, NVME_REGS_PROPERTY,
				 reg_print_flags());

	return 0;
}

static int set_property(int argc, char **argv, struct command *acmd,
			struct plugin *plugin)
{
	const char *desc =
	    "Writes and shows the defined NVMe controller property for NVMe over Fabric";
	const char *offset_desc = "the offset of the property";
	const char *value = "the value of the property to be set";

	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	__cleanup_nvme_transport_handle
		struct libnvme_transport_handle *hdl = NULL;
	struct libnvme_passthru_cmd cmd;
	const struct nvme_reg *reg;
	struct nvme_reg unknown;
	uint32_t offset = 0;
	uint64_t val = 0;
	char sym[16];
	int err;

	OPT_ARGS(opts) = {
		OPT_UINT("offset", 'O', &offset, offset_desc),
		OPT_SUFFIX("value", 'V', &val, value),
		OPT_END()
	};

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	if (!argconfig_given(opts, &offset)) {
		nvme_show_error("offset required param");
		return -EINVAL;
	}
	if (!argconfig_given(opts, &val)) {
		nvme_show_error("value required param");
		return -EINVAL;
	}

	reg = property_reg(offset, &unknown, sym, sizeof(sym));
	nvme_init_set_property(&cmd, offset, val);
	err = libnvme_exec_admin_passthru(hdl, &cmd);
	if (err) {
		nvme_show_err(err, "set-property");
		return err;
	}

	nvme_show_result("set-property: %#02x (%s), value: %#"PRIx64, offset,
			 reg->name, val);

	return 0;
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

static void __shr_constructor register_group(void)
{
	plugin_add_group(&builtin, "Registers", commands);
}
