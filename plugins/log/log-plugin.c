/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * This file is part of nvme-cli.
 *
 * Copyright (c) 2014-2015, Intel Corporation.
 * Copyright (c) 2026 SUSE Software Solutions
 *
 * Authors: Keith Busch <kbusch@kernel.org>
 *          Daniel Wagner <dwagner@suse.com>
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
#include <shared/compiler-attributes-util.h>
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

static const char *csi = "command set identifier";
static const char *domainid = "Domain Identifier";
static const char *endgid = "Endurance Group Identifier (ENDGID)";
static const char *lsp = "log specific field";
static const char *rae = "Retain an Asynchronous Event";
static const char *raw_log = "show log in binary format";
static const char *raw_output = "output in binary format";
static const char *raw_use = "use binary output";

static int get_smart_log(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc = "Retrieve SMART log for the given device "
		"(or optionally a namespace) in either decoded format "
		"(default) or binary.";

	__cleanup_libnvme_free struct nvme_smart_log *smart_log = NULL;
	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	__cleanup_nvme_transport_handle struct libnvme_transport_handle *hdl = NULL;
	const char *namespace = "(optional) desired namespace";
	nvme_print_flags_t flags;
	int err = -1;

	struct config {
		__u32	namespace_id;
		bool	raw_binary;
	};

	struct config cfg = {
		.namespace_id	= NVME_NSID_ALL,
		.raw_binary	= false,
	};

	NVME_ARGS(opts,
		  OPT_UINT("namespace-id", 'n', &cfg.namespace_id, namespace),
		  OPT_FLAG("raw-binary",   'b', &cfg.raw_binary,   raw_output));

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	err = validate_output_format(nvme_args.output_format, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	if (cfg.raw_binary)
		flags = BINARY;

	if (nvme_args.verbose)
		flags |= VERBOSE;

	smart_log = libnvme_alloc(sizeof(*smart_log));
	if (!smart_log)
		return -ENOMEM;

	err = nvme_get_log_smart(hdl, cfg.namespace_id, smart_log);
	if (err) {
		nvme_show_err(err, "smart log");
		return err;
	}

	nvme_show_smart_log(smart_log, cfg.namespace_id,
			    libnvme_transport_handle_get_name(hdl), flags);

	return err;
}

static int get_ana_log(int argc, char **argv, struct command *acmd,
		struct plugin *plugin)
{
	const char *desc = "Retrieve ANA log for the given device in "
		"decoded format (default), json or binary.";
	const char *groups = "Return ANA groups only.";

	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	__cleanup_nvme_transport_handle struct libnvme_transport_handle *hdl = NULL;
	__cleanup_libnvme_free struct nvme_id_ctrl *ctrl = NULL;
	__cleanup_libnvme_free struct nvme_ana_log *ana_log = NULL;
	struct libnvme_passthru_cmd cmd;
	size_t max_ana_log_len;
	__u32 ana_log_len;
	nvme_print_flags_t flags;
	int err = -1;

	struct config {
		bool	groups;
	};

	struct config cfg = {
		.groups = false,
	};

	NVME_ARGS(opts,
		  OPT_FLAG("groups", 'g', &cfg.groups, groups));


	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	err = validate_output_format(nvme_args.output_format, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	ctrl = libnvme_alloc(sizeof(*ctrl));
	if (!ctrl)
		return -ENOMEM;

	nvme_init_identify_ctrl(&cmd, ctrl);
	err = libnvme_exec_admin_passthru(hdl, &cmd);
	if (err) {
		nvme_show_error("ERROR : nvme_identify_ctrl() failed: %s",
			libnvme_strerror(err));
		return err;
	}

	max_ana_log_len = libnvme_get_ana_log_len_from_id_ctrl(ctrl, cfg.groups);
	ana_log_len = max_ana_log_len;
	if (ana_log_len < max_ana_log_len) {
		nvme_show_error("ANA log length %zu too large", max_ana_log_len);
		return -ENOMEM;
	}

	ana_log = libnvme_alloc(ana_log_len);
	if (!ana_log)
		return -ENOMEM;

	err = libnvme_get_ana_log_atomic(hdl, true, cfg.groups, ana_log, &ana_log_len, 10);
	if (err) {
		nvme_show_err(err, "ana-log");
		return err;
	}

	nvme_show_ana_log(ana_log, libnvme_transport_handle_get_name(hdl),
			  ana_log_len, flags);

	return err;
}

static int parse_telemetry_da(struct libnvme_transport_handle *hdl,
			      enum nvme_telemetry_da da,
			      struct nvme_telemetry_log *telem,
			      size_t *size,
			      bool da4_support)

{
	size_t dalb, da1lb = le16_to_cpu(telem->dalb1), da2lb = le16_to_cpu(telem->dalb2),
		da3lb = le16_to_cpu(telem->dalb3), da4lb = le32_to_cpu(telem->dalb4);

	switch (da) {
	case NVME_TELEMETRY_DA_CTRL_DETERMINE:
		if (da4_support)
			dalb = da4lb;
		else
			dalb = da3lb;
		break;
	case NVME_TELEMETRY_DA_1:
		dalb = da1lb;
		break;
	case NVME_TELEMETRY_DA_2:
		dalb = da2lb;
		break;
	case NVME_TELEMETRY_DA_3:
		/* dalb3 >= dalb2 >= dalb1 */
		dalb = da3lb;
		break;
	case NVME_TELEMETRY_DA_4:
		if (da4_support) {
			dalb = da4lb;
		} else {
			nvme_show_error(
			    "Data area 4 unsupported, bit 6 of Log Page Attributes not set");
			return -EINVAL;
		}
		break;
	default:
		nvme_show_error("Invalid data area parameter - %d", da);
		return -EINVAL;
	}

	if (dalb == 0) {
		nvme_show_error("ERROR: No telemetry data block");
		return -ENOENT;
	}
	*size = (dalb + 1) * NVME_LOG_TELEM_BLOCK_SIZE;
	return 0;
}

static int get_log_telemetry_ctrl(struct libnvme_transport_handle *hdl, bool rae, size_t size,
				  struct nvme_telemetry_log **buf)
{
	struct nvme_telemetry_log *log;
	struct libnvme_passthru_cmd cmd;
	int err;

	log = libnvme_alloc(size);
	if (!log)
		return -ENOMEM;

	nvme_init_get_log_telemetry_ctrl(&cmd, 0, log, size);
	err = libnvme_get_log_dynamic_chunk(hdl, &cmd, rae, size);
	if (err) {
		libnvme_free(log);
		return err;
	}

	*buf = log;
	return 0;
}

static int get_log_telemetry_host(struct libnvme_transport_handle *hdl, size_t size,
				  struct nvme_telemetry_log **buf)
{
	struct nvme_telemetry_log *log;
	struct libnvme_passthru_cmd cmd;
	int err;

	log = libnvme_alloc(size);
	if (!log)
		return -ENOMEM;

	nvme_init_get_log_telemetry_host(&cmd, 0, log, size);
	err = libnvme_get_log_dynamic_chunk(hdl, &cmd, false, size);
	if (err) {
		libnvme_free(log);
		return err;
	}

	*buf = log;
	return 0;
}

static int __create_telemetry_log_host(struct libnvme_transport_handle *hdl,
				       enum nvme_telemetry_da da,
				       size_t *size,
				       struct nvme_telemetry_log **buf,
				       bool da4_support)
{
	__cleanup_libnvme_free struct nvme_telemetry_log *log = NULL;
	struct libnvme_passthru_cmd cmd;
	int err;

	log = libnvme_alloc(sizeof(*log));
	if (!log)
		return -ENOMEM;

	nvme_init_get_log_create_telemetry_host_mcda(&cmd, da, log);
	err = libnvme_get_log(hdl, &cmd, false, sizeof(*log));
	if (err)
		return err;

	err = parse_telemetry_da(hdl, da, log, size, da4_support);
	if (err)
		return err;

	return get_log_telemetry_host(hdl, *size, buf);
}

static int __get_telemetry_log_ctrl(struct libnvme_transport_handle *hdl,
				    bool rae,
				    enum nvme_telemetry_da da,
				    size_t *size,
				    struct nvme_telemetry_log **buf,
				    bool da4_support)
{
	struct nvme_telemetry_log *log;
	struct libnvme_passthru_cmd cmd;
	int err;

	log = libnvme_alloc(NVME_LOG_TELEM_BLOCK_SIZE);
	if (!log)
		return -ENOMEM;

	/*
	 * set rae = true so it won't clear the current telemetry log in
	 * controller
	 */
	nvme_init_get_log_telemetry_ctrl(&cmd, 0, log, NVME_LOG_TELEM_BLOCK_SIZE);
	err = libnvme_get_log_dynamic_chunk(hdl, &cmd, true, NVME_LOG_TELEM_BLOCK_SIZE);
	if (err)
		goto free;

	if (!log->ctrlavail) {
		if (!rae) {
			nvme_init_get_log_telemetry_ctrl(&cmd, 0, log,
				NVME_LOG_TELEM_BLOCK_SIZE);
			err = libnvme_get_log_dynamic_chunk(hdl, &cmd, rae,
				NVME_LOG_TELEM_BLOCK_SIZE);
			goto free;
		}

		*size = NVME_LOG_TELEM_BLOCK_SIZE;
		*buf = log;

		nvme_show_error("Warning: Telemetry Controller-Initiated Data Not Available.");
		return 0;
	}

	err = parse_telemetry_da(hdl, da, log, size, da4_support);
	if (err)
		goto free;

	return get_log_telemetry_ctrl(hdl, rae, *size, buf);

free:
	libnvme_free(log);
	return err;
}

static int __get_telemetry_log_host(struct libnvme_transport_handle *hdl,
				    enum nvme_telemetry_da da,
				    size_t *size,
				    struct nvme_telemetry_log **buf,
				    bool da4_support)
{
	__cleanup_libnvme_free struct nvme_telemetry_log *log = NULL;
	struct libnvme_passthru_cmd cmd;
	int err;

	log = libnvme_alloc(sizeof(*log));
	if (!log)
		return -ENOMEM;

	nvme_init_get_log_telemetry_host(&cmd, 0, log, NVME_LOG_TELEM_BLOCK_SIZE);
	err = libnvme_get_log_dynamic_chunk(hdl, &cmd, false, NVME_LOG_TELEM_BLOCK_SIZE);
	if (err)
		return  err;

	err = parse_telemetry_da(hdl, da, log, size, da4_support);
	if (err)
		return err;

	return get_log_telemetry_host(hdl, *size, buf);
}

static int get_telemetry_log(int argc, char **argv, struct command *acmd,
			     struct plugin *plugin)
{
	const char *desc = "Retrieve telemetry log and write to binary file";
	const char *fname = "File name to save raw binary, includes header";
	const char *hgen = "Have the host tell the controller to generate the report";
	const char *cgen = "Gather report generated by the controller.";
	const char *dgen = "Pick which telemetry data area to report. Default is 3 to fetch areas 1-3. Valid options are 1, 2, 3, 4.";
	const char *mcda = "Host-init Maximum Created Data Area. Valid options are 0 ~ 4 "
		"If given, This option will override dgen. 0 : controller determines data area";

	__cleanup_libnvme_free struct nvme_telemetry_log *log = NULL;
	__cleanup_libnvme_free struct nvme_id_ctrl *id_ctrl = NULL;
	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	__cleanup_nvme_transport_handle struct libnvme_transport_handle *hdl = NULL;
	__cleanup_fd int output = -1;
	struct libnvme_passthru_cmd cmd;
	int err = 0;
	size_t total_size = 0;
	__u8 *data_ptr = NULL;
	int data_written, data_remaining = 0;
	nvme_print_flags_t flags;
	bool da4_support = false,
	host_behavior_changed = false;

	struct config {
		char	*file_name;
		__u32	host_gen;
		bool	ctrl_init;
		int	data_area;
		bool	rae;
		__u8	mcda;
	};
	struct config cfg = {
		.file_name	= NULL,
		.host_gen	= 1,
		.ctrl_init	= false,
		.data_area	= 3,
		.rae		= false,
		.mcda		= 0xff,
	};

	NVME_ARGS(opts,
		  OPT_FILE("output-file",     'O', &cfg.file_name, fname),
		  OPT_UINT("host-generate",   'g', &cfg.host_gen,  hgen),
		  OPT_FLAG("controller-init", 'c', &cfg.ctrl_init, cgen),
		  OPT_UINT("data-area",       'd', &cfg.data_area, dgen),
		  OPT_FLAG("rae",             'r', &cfg.rae,       rae),
		  OPT_BYTE("mcda",            'm', &cfg.mcda,      mcda));


	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	err = validate_output_format(nvme_args.output_format, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	if (!cfg.file_name) {
		nvme_show_error("Please provide an output file!");
		return -EINVAL;
	}

	cfg.host_gen = !!cfg.host_gen;

	if (cfg.mcda != 0xff) {
		if (cfg.ctrl_init || !cfg.host_gen) {
			nvme_show_error("mcda allowed for Host-init Creation!");
			return -EINVAL;
		}
		cfg.data_area = cfg.mcda;
	}

	if (cfg.data_area == 4) {
		id_ctrl = libnvme_alloc(sizeof(*id_ctrl));
		if (!id_ctrl)
			return -ENOMEM;

		nvme_init_identify_ctrl(&cmd, id_ctrl);
		err = libnvme_exec_admin_passthru(hdl, &cmd);
		if (err) {
			nvme_show_error("identify-ctrl");
			return err;
		}

		da4_support = id_ctrl->lpa & 0x40;

		if (!da4_support) {
			nvme_show_error("%s: Telemetry data area 4 not supported by device",
				__func__);
			return -EINVAL;
		}

		err = libnvme_set_etdas(hdl, &host_behavior_changed);
		if (err) {
			nvme_show_error("%s: Failed to set ETDAS bit", __func__);
			return err;
		}
	}

	output = shr_open_rawdata(cfg.file_name, O_WRONLY | O_CREAT | O_TRUNC, 0666);
	if (output < 0) {
		nvme_show_error("Failed to open output file %s: %s!",
				cfg.file_name, libnvme_strerror(errno));
		return output;
	}

	log = libnvme_alloc(sizeof(*log));
	if (!log)
		return -ENOMEM;

	if (cfg.ctrl_init)
		err = __get_telemetry_log_ctrl(hdl, cfg.rae, cfg.data_area,
					       &total_size, &log, da4_support);
	else if (cfg.host_gen)
		err = __create_telemetry_log_host(hdl, cfg.data_area,
						  &total_size, &log, da4_support);
	else
		err = __get_telemetry_log_host(hdl, cfg.data_area,
					       &total_size, &log, da4_support);

	if (err) {
		nvme_show_err(err, "get-telemetry-log");
		if (err > 0)
			nvme_show_error("Failed to acquire telemetry log %d!", err);
		return err;
	}

	data_remaining = total_size;
	data_ptr = (__u8 *)log;

	while (data_remaining) {
		data_written = write(output, data_ptr, data_remaining);
		if (data_written < 0) {
			err = -errno;
			nvme_show_error("ERROR: %s: : write failed with error : %s",
					__func__, libnvme_strerror(errno));
			break;
		} else if (data_written <= data_remaining) {
			data_remaining -= data_written;
			data_ptr += data_written;
		} else {
			/* Unexpected overwrite */
			nvme_show_error("Failure: Unexpected telemetry log overwrite - data_remaining = 0x%x, data_written = 0x%x",
					data_remaining, data_written);
			err = -1;
			break;
		}
	}

	if (shr_fsync(output) < 0) {
		nvme_show_error("ERROR : %s: : fsync : %s", __func__, libnvme_strerror(errno));
		return -1;
	}

	if (host_behavior_changed) {
		host_behavior_changed = false;
		err = libnvme_clear_etdas(hdl, &host_behavior_changed);
		if (err) {
			nvme_show_error("%s: Failed to clear ETDAS bit", __func__);
			return err;
		}
	}

	return err;
}

static int get_endurance_log(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc = "Retrieves endurance groups log page and prints the log.";
	const char *group_id = "The endurance group identifier";

	__cleanup_libnvme_free struct nvme_endurance_group_log *endurance_log = NULL;
	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	__cleanup_nvme_transport_handle struct libnvme_transport_handle *hdl = NULL;
	struct libnvme_passthru_cmd cmd;
	nvme_print_flags_t flags;
	int err;

	struct config {
		__u16	group_id;
	};

	struct config cfg = {
		.group_id	= 0,
	};

	NVME_ARGS(opts,
		  OPT_SHRT("group-id",     'g', &cfg.group_id,      group_id));


	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	err = validate_output_format(nvme_args.output_format, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	endurance_log = libnvme_alloc(sizeof(*endurance_log));
	if (!endurance_log)
		return -ENOMEM;

	nvme_init_get_log_endurance_group(&cmd, cfg.group_id, endurance_log);
	err = libnvme_get_log(hdl, &cmd, false, sizeof(*endurance_log));
	if (err) {
		nvme_show_err(err, "endurance log");
		return err;
	}

	nvme_show_endurance_log(endurance_log, cfg.group_id,
				libnvme_transport_handle_get_name(hdl), flags);

	return err;
}

static int collect_effects_log(struct libnvme_transport_handle *hdl, enum nvme_csi csi,
			       struct list_head *list, int flags)
{
	nvme_effects_log_node_t *node;
	struct libnvme_passthru_cmd cmd;
	size_t len;
	int err;

	node = libnvme_alloc(sizeof(*node));
	if (!node)
		return -ENOMEM;

	node->csi = csi;

	len = sizeof(node->effects);
	nvme_init_get_log_cmd_effects(&cmd, csi, &node->effects);
	err = libnvme_get_log(hdl, &cmd, false, len);
	if (err) {
		libnvme_free(node);
		return err;
	}
	list_add(list, &node->node);
	return 0;
}

static int get_effects_log(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc = "Retrieve command effects log page and print the table.";

	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	__cleanup_nvme_transport_handle struct libnvme_transport_handle *hdl = NULL;
	struct libnvme_passthru_cmd cmd;
	struct list_head log_pages;
	nvme_effects_log_node_t *node;

	void *bar = NULL;

	int err = -1;
	nvme_print_flags_t flags;

	struct config {
		bool	raw_binary;
		int	csi;
	};

	struct config cfg = {
		.raw_binary	= false,
		.csi		= -1,
	};

	NVME_ARGS(opts,
		  OPT_FLAG("raw-binary",     'b', &cfg.raw_binary,     raw_log),
		  OPT_INT("csi",             'c', &cfg.csi,            csi));


	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	err = validate_output_format(nvme_args.output_format, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	if (cfg.raw_binary)
		flags = BINARY;

	if (nvme_args.verbose)
		flags |= VERBOSE;

	list_head_init(&log_pages);

	if (cfg.csi < 0) {
		__u64 cap;
		if (libnvme_transport_handle_is_ns(hdl)) {
			nvme_show_error("Namespace device isn't allowed without csi");
			return -EINVAL;
		}
		bar = mmap_registers(hdl, false);

		if (bar) {
			cap = shr_mmio_read64(bar + NVME_REG_CAP);
			munmap_registers(bar);
		} else {
			nvme_init_get_property(&cmd, NVME_REG_CAP);
			err = libnvme_exec_admin_passthru(hdl, &cmd);
			if (err)
				goto cleanup_list;
			cap = cmd.result;
		}

		if (NVME_CAP_CSS(cap) & NVME_CAP_CSS_NVM)
			err = collect_effects_log(hdl, NVME_CSI_NVM,
						  &log_pages, flags);

		if (!err && (NVME_CAP_CSS(cap) & NVME_CAP_CSS_CSI))
			err = collect_effects_log(hdl, NVME_CSI_ZNS,
						  &log_pages, flags);
	} else {
		err = collect_effects_log(hdl, cfg.csi, &log_pages, flags);
	}

	if (err) {
		nvme_show_err(err, "effects log page");
		goto cleanup_list;
	}

	nvme_print_effects_log_pages(&log_pages, flags);

cleanup_list:
	while ((node = list_pop(&log_pages, nvme_effects_log_node_t, node)))
		libnvme_free(node);

	return err;
}

static int get_error_log(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc = "Retrieve specified number of "
		"error log entries from a given device "
		"in either decoded format (default) or binary.";
	const char *log_entries = "number of entries to retrieve";
	const char *status = "output specified STATUS entry only";
	const char *nsid = "output specified NSID entry only";
	const char *trtype = "output specified TRTYPE entry only";
	const char *opcode = "output specified OPC entry only";
	const char *sqid = "output specified SQID entry only";
	const char *valid_entry = "output valid entry only";
	const char *lba = "output specified LBA entry only";
	const char *csi = "output specified CSI entry only";
	const char *raw = "dump in binary format";

	__cleanup_libnvme_free struct nvme_error_log_page *err_log = NULL;
	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	__cleanup_nvme_transport_handle struct libnvme_transport_handle *hdl = NULL;
	struct nvme_id_ctrl ctrl = { 0 };
	struct libnvme_passthru_cmd cmd;
	size_t err_log_len;
	nvme_print_flags_t flags;
	int err = -1;

	struct config {
		__u32	log_entries;
		bool	raw_binary;
		struct nvme_error_log_filter flt;
	};

	struct config cfg = {
		.log_entries	= 64,
		.raw_binary	= false,
	};

	NVME_ARGS(opts,
		  OPT_UINT("log-entries",  'e', &cfg.log_entries, log_entries),
		  OPT_FLAG("raw-binary",   'b', &cfg.raw_binary,  raw),
		  OPT_FLAG("valid-entry",  'V', &cfg.flt.valid,   valid_entry),
		  OPT_SHRT("sqid",         'S', &cfg.flt.sqid,    sqid),
		  OPT_SHRT("status",       's', &cfg.flt.status,  status),
		  OPT_SUFFIX("lba",        'l', &cfg.flt.lba,     lba),
		  OPT_UINT("namespace-id", 'n', &cfg.flt.nsid,    nsid),
		  OPT_BYTE("trtype",       't', &cfg.flt.trtype,  trtype),
		  OPT_BYTE("csi",          'c', &cfg.flt.csi,     csi),
		  OPT_BYTE("opcode",       'O', &cfg.flt.opcode,  opcode));

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	err = validate_output_format(nvme_args.output_format, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	if (cfg.raw_binary)
		flags = BINARY;

	if (!cfg.log_entries) {
		nvme_show_error("non-zero log-entries is required param");
		return -1;
	}

	nvme_init_identify_ctrl(&cmd, &ctrl);
	err = libnvme_exec_admin_passthru(hdl, &cmd);
	if (err) {
		nvme_show_err(err, "identify controller");
		return err;
	}

	cfg.log_entries = min(cfg.log_entries, ctrl.elpe + 1);
	err_log = libnvme_alloc(cfg.log_entries * sizeof(struct nvme_error_log_page));
	if (!err_log)
		return -ENOMEM;

	err_log_len = sizeof(*err_log) * cfg.log_entries;
	nvme_init_get_log(&cmd, NVME_NSID_ALL, NVME_LOG_LID_ERROR,
		NVME_CSI_NVM, err_log, err_log_len);

	err = libnvme_get_log(hdl, &cmd, false, err_log_len);
	if (err) {
		nvme_show_err(err, "error log");
		return err;
	}

	nvme_show_error_log(err_log, cfg.log_entries,
			    libnvme_transport_handle_get_name(hdl), &cfg.flt,
			    flags);

	return err;
}

static int get_fw_log(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc = "Retrieve the firmware log for the "
		"specified device in either decoded format (default) or binary.";

	__cleanup_libnvme_free struct nvme_firmware_slot *fw_log = NULL;
	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	__cleanup_nvme_transport_handle struct libnvme_transport_handle *hdl = NULL;
	struct libnvme_passthru_cmd cmd;
	nvme_print_flags_t flags;
	int err;

	struct config {
		bool	raw_binary;
	};

	struct config cfg = {
		.raw_binary	= false,
	};

	NVME_ARGS(opts,
		  OPT_FLAG("raw-binary",   'b', &cfg.raw_binary,    raw_use));

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	err = validate_output_format(nvme_args.output_format, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	if (cfg.raw_binary)
		flags = BINARY;

	fw_log = libnvme_alloc(sizeof(*fw_log));
	if (!fw_log)
		return -ENOMEM;

	nvme_init_get_log(&cmd, NVME_NSID_ALL, NVME_LOG_LID_FW_SLOT,
		NVME_CSI_NVM, fw_log, sizeof(*fw_log));

	err = libnvme_get_log(hdl, &cmd, false, sizeof(*fw_log));
	if (err) {
		nvme_show_err(err, "fw log");
		return err;
	}

	nvme_show_fw_log(fw_log, libnvme_transport_handle_get_name(hdl), flags);

	return err;
}

static int get_changed_ns_list_log(int argc, char **argv, bool alloc)
{
	__cleanup_free char *desc = NULL;
	__cleanup_libnvme_free struct nvme_ns_list *changed_ns_list_log = NULL;
	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	__cleanup_nvme_transport_handle struct libnvme_transport_handle *hdl = NULL;
	struct libnvme_passthru_cmd cmd;
	nvme_print_flags_t flags;
	int err;

	struct config {
		bool	raw_binary;
	};

	struct config cfg = {
		.raw_binary	= false,
	};

	NVME_ARGS(opts,
		  OPT_FLAG("raw-binary",   'b', &cfg.raw_binary,    raw_output));

	if (asprintf(&desc, "Retrieve Changed %s Namespaces log for the given device %s",
		     alloc ? "Allocated" : "Attached",
		     "in either decoded format (default) or binary.") < 0)
		desc = NULL;

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	err = validate_output_format(nvme_args.output_format, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	if (cfg.raw_binary)
		flags = BINARY;

	changed_ns_list_log = libnvme_alloc(sizeof(*changed_ns_list_log));
	if (!changed_ns_list_log)
		return -ENOMEM;

	if (alloc) {
		nvme_init_get_log_changed_ns(&cmd, changed_ns_list_log);
		err = libnvme_get_log(hdl, &cmd, true, sizeof(*changed_ns_list_log));
	} else {
		nvme_init_get_log(&cmd, NVME_NSID_NONE, NVME_LOG_LID_CHANGED_NS,
			NVME_CSI_NVM, changed_ns_list_log, sizeof(*changed_ns_list_log));
		err = libnvme_get_log(hdl, &cmd, true, sizeof(*changed_ns_list_log));
	}
	if (err) {
		nvme_show_err(err, alloc ? "changed allocated ns list log" :
			      "changed attached ns list log");
		return err;
	}

	nvme_show_changed_ns_list_log(changed_ns_list_log,
				      libnvme_transport_handle_get_name(hdl),
				      flags, alloc);

	return err;
}

static int get_changed_attach_ns_list_log(int argc, char **argv, struct command *acmd,
					  struct plugin *plugin)
{
	return get_changed_ns_list_log(argc, argv, false);
}

static int get_changed_alloc_ns_list_log(int argc, char **argv, struct command *acmd,
					 struct plugin *plugin)
{
	return get_changed_ns_list_log(argc, argv, true);
}

static int get_pred_lat_per_nvmset_log(int argc, char **argv,
	struct command *command, struct plugin *plugin)
{
	const char *desc = "Retrieve Predictable latency per nvm set log "
		"page and prints it for the given device in either decoded "
		"format(default),json or binary.";
	const char *nvmset_id = "NVM Set Identifier";

	__cleanup_libnvme_free struct nvme_nvmset_predictable_lat_log *plpns_log = NULL;
	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	__cleanup_nvme_transport_handle struct libnvme_transport_handle *hdl = NULL;
	struct libnvme_passthru_cmd cmd;
	nvme_print_flags_t flags;
	int err;

	struct config {
		__u16	nvmset_id;
		bool	raw_binary;
	};

	struct config cfg = {
		.nvmset_id	= 1,
		.raw_binary	= false,
	};

	NVME_ARGS(opts,
		  OPT_SHRT("nvmset-id",	   'i', &cfg.nvmset_id,     nvmset_id),
		  OPT_FLAG("raw-binary",   'b', &cfg.raw_binary,    raw_use));

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	err = validate_output_format(nvme_args.output_format, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	if (cfg.raw_binary)
		flags = BINARY;

	plpns_log = libnvme_alloc(sizeof(*plpns_log));
	if (!plpns_log)
		return -ENOMEM;

	nvme_init_get_log_predictable_lat_nvmset(&cmd, cfg.nvmset_id, plpns_log);
	err = libnvme_get_log(hdl, &cmd, false, sizeof(*plpns_log));
	if (err) {
		nvme_show_err(err, "predictable latency per nvm set");
		return err;
	}

	nvme_show_predictable_latency_per_nvmset(plpns_log, cfg.nvmset_id,
	    libnvme_transport_handle_get_name(hdl), flags);

	return err;
}

static int get_pred_lat_event_agg_log(int argc, char **argv,
		struct command *command, struct plugin *plugin)
{
	const char *desc = "Retrieve Predictable Latency Event "
		"Aggregate Log page and prints it, for the given "
		"device in either decoded format(default), json or binary.";
	const char *log_entries = "Number of pending NVM Set log Entries list";

	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	__cleanup_nvme_transport_handle struct libnvme_transport_handle *hdl = NULL;
	__cleanup_libnvme_free struct nvme_id_ctrl *ctrl = NULL;
	__cleanup_libnvme_free void *pea_log = NULL;
	struct libnvme_passthru_cmd cmd;
	nvme_print_flags_t flags;
	__u32 log_size;
	int err;

	struct config {
		__u64	log_entries;
		bool	rae;
		bool	raw_binary;
	};

	struct config cfg = {
		.log_entries	= 2044,
		.rae		= false,
		.raw_binary	= false,
	};

	NVME_ARGS(opts,
		  OPT_UINT("log-entries",  'e', &cfg.log_entries,   log_entries),
		  OPT_FLAG("rae",          'r', &cfg.rae,           rae),
		  OPT_FLAG("raw-binary",   'b', &cfg.raw_binary,    raw_use));

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	err = validate_output_format(nvme_args.output_format, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	if (cfg.raw_binary)
		flags = BINARY;

	if (!cfg.log_entries) {
		nvme_show_error("non-zero log-entries is required param");
		return -EINVAL;
	}

	ctrl = libnvme_alloc(sizeof(*ctrl));
	if (!ctrl)
		return -ENOMEM;

	nvme_init_identify_ctrl(&cmd, ctrl);
	err = libnvme_exec_admin_passthru(hdl, &cmd);
	if (err) {
		nvme_show_err(err, "identify controller");
		return err;
	}

	cfg.log_entries = min(cfg.log_entries, le32_to_cpu(ctrl->nsetidmax));
	log_size = sizeof(__u64) + cfg.log_entries * sizeof(__u16);

	pea_log = libnvme_alloc(log_size);
	if (!pea_log)
		return -ENOMEM;

	nvme_init_get_log_predictable_lat_event(&cmd, 0, pea_log, log_size);
	err = libnvme_get_log(hdl, &cmd, cfg.rae, log_size);
	if (err) {
		nvme_show_err(err,
			      "predictable latency event aggregate log page");
		return err;
	}

	nvme_show_predictable_latency_event_agg_log(pea_log, cfg.log_entries,
	    log_size, libnvme_transport_handle_get_name(hdl), flags);

	return err;
}

static int get_persistent_event_log(int argc, char **argv,
		struct command *command, struct plugin *plugin)
{
	const char *desc = "Retrieve Persistent Event log info for "
		"the given device in either decoded format(default), json or binary.";
	const char *action = "action the controller shall take during "
		"processing this persistent log page command.";
	const char *log_len = "number of bytes to retrieve";

	__cleanup_libnvme_free struct nvme_persistent_event_log *pevent = NULL;
	struct nvme_persistent_event_log *pevent_collected = NULL;
	__cleanup_huge struct libnvme_mem_huge mh = { 0, };
	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	__cleanup_nvme_transport_handle struct libnvme_transport_handle *hdl = NULL;
	nvme_print_flags_t flags;
	void *pevent_log_info;
	int err;

	struct config {
		__u8	action;
		__u32	log_len;
		bool	raw_binary;
	};

	struct config cfg = {
		.action		= 0xff,
		.log_len	= 0,
		.raw_binary	= false,
	};

	NVME_ARGS(opts,
		  OPT_BYTE("action",       'a', &cfg.action,        action),
		  OPT_UINT("log_len",	 'l', &cfg.log_len,	  log_len),
		  OPT_FLAG("raw-binary",   'b', &cfg.raw_binary,    raw_use));

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	err = validate_output_format(nvme_args.output_format, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	if (cfg.raw_binary)
		flags = BINARY;

	pevent = libnvme_alloc(sizeof(*pevent));
	if (!pevent)
		return -ENOMEM;

	err = nvme_get_log_persistent_event(hdl, cfg.action, pevent,
					    sizeof(*pevent));
	if (err) {
		nvme_show_err(err, "persistent event log");
		return err;
	}

	if (cfg.action == NVME_PEVENT_LOG_RELEASE_CTX) {
		nvme_show_error("Releasing Persistent Event Log Context");
		return 0;
	}

	if (!cfg.log_len && cfg.action != NVME_PEVENT_LOG_EST_CTX_AND_READ) {
		cfg.log_len = le64_to_cpu(pevent->tll);
	} else if (!cfg.log_len && cfg.action == NVME_PEVENT_LOG_EST_CTX_AND_READ) {
		nvme_show_error("Establishing Persistent Event Log Context");
		return 0;
	}

	/*
	 * if header already read with context establish action 0x1,
	 * action shall not be 0x1 again in the subsequent request,
	 * until the current context is released by issuing action
	 * with 0x2, otherwise throws command sequence error, make
	 * it as zero to read the log page
	 */
	if (cfg.action == NVME_PEVENT_LOG_EST_CTX_AND_READ)
		cfg.action = NVME_PEVENT_LOG_READ;

	pevent_log_info = libnvme_alloc_huge(cfg.log_len, &mh);
	if (!pevent_log_info) {
		nvme_show_error("failed to allocate huge memory");
		return -ENOMEM;
	}

	err = nvme_get_log_persistent_event(hdl, cfg.action,
					    pevent_log_info, cfg.log_len);
	if (err) {
		nvme_show_err(err, "persistent event log");
		return err;
	}

	err = nvme_get_log_persistent_event(hdl, cfg.action, pevent,
					    sizeof(*pevent));
	if (err) {
		nvme_show_err(err, "persistent event log");
		return err;
	}

	pevent_collected = pevent_log_info;
	if (pevent_collected->gen_number != pevent->gen_number) {
		nvme_show_error("Collected Persistent Event Log may be invalid, Re-read the log is required");
		return -EINVAL;
	}

	nvme_show_persistent_event_log(pevent_log_info, cfg.action,
		cfg.log_len, libnvme_transport_handle_get_name(hdl), flags);

	return err;
}

static int get_endurance_event_agg_log(int argc, char **argv,
		struct command *command, struct plugin *plugin)
{
	const char *desc = "Retrieve Retrieve Predictable Latency "
		"Event Aggregate page and prints it, for the given "
		"device in either decoded format(default), json or binary.";
	const char *log_entries = "Number of pending Endurance Group Event log Entries list";

	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	__cleanup_nvme_transport_handle struct libnvme_transport_handle *hdl = NULL;
	__cleanup_libnvme_free struct nvme_id_ctrl *ctrl = NULL;
	__cleanup_libnvme_free void *endurance_log = NULL;
	struct libnvme_passthru_cmd cmd;
	nvme_print_flags_t flags;
	__u32 log_size;
	int err;

	struct config {
		__u64	log_entries;
		bool	rae;
		bool	raw_binary;
	};

	struct config cfg = {
		.log_entries	= 2044,
		.rae		= false,
		.raw_binary	= false,
	};

	NVME_ARGS(opts,
		  OPT_UINT("log-entries",  'e', &cfg.log_entries,   log_entries),
		  OPT_FLAG("rae",          'r', &cfg.rae,           rae),
		  OPT_FLAG("raw-binary",   'b', &cfg.raw_binary,    raw_use));

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	err = validate_output_format(nvme_args.output_format, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	if (cfg.raw_binary)
		flags = BINARY;

	if (!cfg.log_entries) {
		nvme_show_error("non-zero log-entries is required param");
		return -EINVAL;
	}

	ctrl = libnvme_alloc(sizeof(*ctrl));
	if (!ctrl)
		return -ENOMEM;

	nvme_init_identify_ctrl(&cmd, ctrl);
	err = libnvme_exec_admin_passthru(hdl, &cmd);
	if (err < 0) {
		nvme_show_error("identify controller: %s", libnvme_strerror(-err));
		return err;
	} else if (err) {
		nvme_show_error("could not identify controller");
		return -ENODEV;
	}

	cfg.log_entries = min(cfg.log_entries, le16_to_cpu(ctrl->endgidmax));
	log_size = sizeof(__u64) + cfg.log_entries * sizeof(__u16);

	endurance_log = libnvme_alloc(log_size);
	if (!endurance_log)
		return -ENOMEM;

	nvme_init_get_log_endurance_grp_evt(&cmd, 0, endurance_log, log_size);
	err = libnvme_get_log(hdl, &cmd, cfg.rae, log_size);
	if (err) {
		nvme_show_err(err, "endurance group event aggregate log page");
		return err;
	}

	nvme_show_endurance_group_event_agg_log(endurance_log, cfg.log_entries,
	    log_size, libnvme_transport_handle_get_name(hdl), flags);

	return err;
}

static int get_lba_status_log(int argc, char **argv,
		struct command *command, struct plugin *plugin)
{
	const char *desc = "Retrieve Get LBA Status Info Log and prints it, "
		"for the given device in either decoded format(default),json or binary.";

	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	__cleanup_nvme_transport_handle struct libnvme_transport_handle *hdl = NULL;
	__cleanup_libnvme_free void *lba_status = NULL;
	struct libnvme_passthru_cmd cmd;
	nvme_print_flags_t flags;
	__u32 lslplen;
	int err;

	struct config {
		bool	rae;
	};

	struct config cfg = {
		.rae		= false,
	};

	NVME_ARGS(opts,
		  OPT_FLAG("rae",          'r', &cfg.rae,           rae));

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	err = validate_output_format(nvme_args.output_format, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	nvme_init_get_log_lba_status(&cmd, 0, &lslplen, sizeof(__u32));
	err = libnvme_get_log(hdl, &cmd, false, sizeof(__u32));
	if (err) {
		nvme_show_err(err, "lba status log page");
		return err;
	}

	lba_status = libnvme_alloc(lslplen);
	if (!lba_status)
		return -ENOMEM;

	nvme_init_get_log_lba_status(&cmd, 0, lba_status, lslplen);
	err = libnvme_get_log(hdl, &cmd, cfg.rae, lslplen);
	if (err) {
		nvme_show_err(err, "lba status log page");
		return err;
	}

	nvme_show_lba_status_log(lba_status, lslplen,
				 libnvme_transport_handle_get_name(hdl), flags);

	return err;
}

static int get_resv_notif_log(int argc, char **argv,
	struct command *command, struct plugin *plugin)
{

	const char *desc = "Retrieve Reservation Notification "
		"log page and prints it, for the given "
		"device in either decoded format(default), json or binary.";

	__cleanup_libnvme_free struct nvme_resv_notification_log *resv = NULL;
	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	__cleanup_nvme_transport_handle struct libnvme_transport_handle *hdl = NULL;
	struct libnvme_passthru_cmd cmd;
	nvme_print_flags_t flags;
	int err;

	NVME_ARGS(opts);

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	err = validate_output_format(nvme_args.output_format, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	resv = libnvme_alloc(sizeof(*resv));
	if (!resv)
		return -ENOMEM;

	nvme_init_get_log_reservation(&cmd, resv);
	err = libnvme_get_log(hdl, &cmd, false, sizeof(*resv));
	if (err) {
		nvme_show_err(err, "resv notifi log");
		return err;
	}

	nvme_show_resv_notif_log(resv, libnvme_transport_handle_get_name(hdl),
				 flags);

	return err;

}

static int get_boot_part_log(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc = "Retrieve Boot Partition "
		"log page and prints it, for the given "
		"device in either decoded format(default), json or binary.";
	const char *fname = "boot partition data output file name";

	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	__cleanup_nvme_transport_handle struct libnvme_transport_handle *hdl = NULL;
	__cleanup_libnvme_free struct nvme_boot_partition *boot = NULL;
	__cleanup_libnvme_free __u8 *bp_log = NULL;
	struct libnvme_passthru_cmd cmd;
	nvme_print_flags_t flags;
	int err = -1;
	__cleanup_fd int output = -1;
	__u32 bpsz = 0;

	struct config {
		__u8	lsp;
		char	*file_name;
	};

	struct config cfg = {
		.lsp		= 0,
		.file_name	= NULL,
	};

	NVME_ARGS(opts,
		  OPT_BYTE("lsp",          's', &cfg.lsp,           lsp),
		  OPT_FILE("output-file",  'f', &cfg.file_name,     fname));

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	err = validate_output_format(nvme_args.output_format, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	if (!cfg.file_name) {
		nvme_show_error("Please provide an output file!");
		return -1;
	}

	if (cfg.lsp > 127) {
		nvme_show_error("invalid lsp param: %u", cfg.lsp);
		return -1;
	}

	output = shr_open_rawdata(cfg.file_name, O_WRONLY | O_CREAT | O_TRUNC, 0666);
	if (output < 0) {
		nvme_show_error("Failed to open output file %s: %s!",
				cfg.file_name, libnvme_strerror(errno));
		return output;
	}

	boot = libnvme_alloc(sizeof(*boot));
	if (!boot)
		return -ENOMEM;

	nvme_init_get_log_boot_partition(&cmd, cfg.lsp, boot, sizeof(*boot));
	err = libnvme_get_log(hdl, &cmd, false, sizeof(*boot));
	if (err) {
		nvme_show_err(err, "boot partition log");
		return err;
	}

	bpsz = (boot->bpinfo & 0x7fff) * 128 * 1024;
	bp_log = libnvme_alloc(sizeof(*boot) + bpsz);
	if (!bp_log)
		return -ENOMEM;

	nvme_init_get_log_boot_partition(&cmd, cfg.lsp,
					 (struct nvme_boot_partition *)bp_log,
					 sizeof(*boot) + bpsz);
	err = libnvme_get_log(hdl, &cmd, false, sizeof(*boot) + bpsz);
	if (err)
		nvme_show_err(err, "boot partition log");
	else
		nvme_show_boot_part_log(&bp_log,
					libnvme_transport_handle_get_name(hdl),
					sizeof(*boot) + bpsz, flags);

	err = write(output, (void *) bp_log + sizeof(*boot), bpsz);
	if (err != bpsz)
		nvme_show_error("Failed to flush all data to file!");
	else
		nvme_show_result("Data flushed into file %s", cfg.file_name);

	return 0;
}

static int get_phy_rx_eom_log(int argc, char **argv, struct command *acmd,
		struct plugin *plugin)
{
	const char *desc = "Retrieve Physical Interface Receiver Eye Opening "
		"Measurement log for the given device in decoded format "
		"(default), json or binary.";
	const char *controller = "Target Controller ID.";
	__cleanup_libnvme_free struct nvme_phy_rx_eom_log *phy_rx_eom_log = NULL;
	size_t phy_rx_eom_log_len;
	nvme_print_flags_t flags;
	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	__cleanup_nvme_transport_handle struct libnvme_transport_handle *hdl = NULL;
	struct libnvme_passthru_cmd cmd;
	int err = -1;
	__u8 lsp_tmp;

	struct config {
		__u8	lsp;
		__u16	controller;
	};

	struct config cfg = {
		.lsp		= 0,
		.controller	= NVME_LOG_LSI_NONE,
	};

	NVME_ARGS(opts,
		  OPT_BYTE("lsp",        's', &cfg.lsp,        lsp),
		  OPT_SHRT("controller", 'c', &cfg.controller, controller));

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	err = validate_output_format(nvme_args.output_format, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	if (cfg.lsp > 127) {
		nvme_show_error("invalid lsp param: %u", cfg.lsp);
		return -1;
	} else if ((cfg.lsp & 3) == 3) {
		nvme_show_error("invalid measurement quality: %u", cfg.lsp & 3);
		return -1;
	} else if ((cfg.lsp & 12) == 12) {
		nvme_show_error("invalid action: %u", cfg.lsp & 12);
		return -1;
	}

	/* Fetching header to calculate total log length */
	phy_rx_eom_log_len = sizeof(struct nvme_phy_rx_eom_log);
	phy_rx_eom_log = libnvme_alloc(phy_rx_eom_log_len);
	if (!phy_rx_eom_log)
		return -ENOMEM;

	/* Just read measurement, take given action when fetching full log */
	lsp_tmp = cfg.lsp & 0xf3;

	nvme_init_get_log_phy_rx_eom(&cmd, lsp_tmp, cfg.controller,
				     phy_rx_eom_log, phy_rx_eom_log_len);
	err = libnvme_get_log(hdl, &cmd, false, phy_rx_eom_log_len);
	if (err) {
		nvme_show_err(err, "phy-rx-eom-log");
		return err;
	}

	if (phy_rx_eom_log->eomip == NVME_PHY_RX_EOM_COMPLETED)
		phy_rx_eom_log_len = le16_to_cpu(phy_rx_eom_log->hsize) +
				     le32_to_cpu(phy_rx_eom_log->dsize) *
				     le16_to_cpu(phy_rx_eom_log->nd);
	else
		phy_rx_eom_log_len = le16_to_cpu(phy_rx_eom_log->hsize);

	phy_rx_eom_log = libnvme_realloc(phy_rx_eom_log, phy_rx_eom_log_len);
	if (!phy_rx_eom_log)
		return -ENOMEM;

	nvme_init_get_log_phy_rx_eom(&cmd, cfg.lsp, cfg.controller,
				     phy_rx_eom_log, phy_rx_eom_log_len);
	err = libnvme_get_log(hdl, &cmd, false, phy_rx_eom_log_len);
	if (err) {
		nvme_show_err(err, "phy-rx-eom-log");
		return err;
	}

	nvme_show_phy_rx_eom_log(phy_rx_eom_log, cfg.controller, flags);

	return err;
}

static int get_media_unit_stat_log(int argc, char **argv, struct command *acmd,
				   struct plugin *plugin)
{
	const char *desc = "Retrieve the configuration and wear of media units and print it";

	__cleanup_libnvme_free struct nvme_media_unit_stat_log *mus = NULL;
	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	__cleanup_nvme_transport_handle struct libnvme_transport_handle *hdl = NULL;
	struct libnvme_passthru_cmd cmd;
	nvme_print_flags_t flags;
	int err = -1;

	struct config {
		__u16	domainid;
		bool	raw_binary;
	};

	struct config cfg = {
		.domainid	= 0,
		.raw_binary	= false,
	};

	NVME_ARGS(opts,
		  OPT_UINT("domain-id",     'd', &cfg.domainid, domainid),
		  OPT_FLAG("raw-binary",    'b', &cfg.raw_binary, raw_use));

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	err = validate_output_format(nvme_args.output_format, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	if (cfg.raw_binary)
		flags = BINARY;

	mus = libnvme_alloc(sizeof(*mus));
	if (!mus)
		return -ENOMEM;

	nvme_init_get_log_media_unit_stat(&cmd, cfg.domainid, mus);
	err = libnvme_get_log(hdl, &cmd, false, sizeof(*mus));
	if (err) {
		nvme_show_err(err, "media unit status log");
		return err;
	}

	nvme_show_media_unit_stat_log(mus, flags);

	return err;
}

static int get_supp_cap_config_log(int argc, char **argv, struct command *acmd,
				   struct plugin *plugin)
{
	const char *desc = "Retrieve the list of Supported Capacity Configuration Descriptors";

	__cleanup_libnvme_free struct nvme_supported_cap_config_list_log *cap_log = NULL;
	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	__cleanup_nvme_transport_handle struct libnvme_transport_handle *hdl = NULL;
	struct libnvme_passthru_cmd cmd;
	nvme_print_flags_t flags;
	int err = -1;

	struct config {
		__u16	domainid;
		bool	raw_binary;
	};

	struct config cfg = {
		.domainid	= 0,
		.raw_binary	= false,
	};

	NVME_ARGS(opts,
		  OPT_UINT("domain-id",     'd', &cfg.domainid,       domainid),
		  OPT_FLAG("raw-binary",    'b', &cfg.raw_binary,     raw_use));

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	err = validate_output_format(nvme_args.output_format, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	if (cfg.raw_binary)
		flags = BINARY;

	cap_log = libnvme_alloc(sizeof(*cap_log));
	if (!cap_log)
		return -ENOMEM;

	nvme_init_get_log_support_cap_config_list(&cmd, cfg.domainid, cap_log);
	err = libnvme_get_log(hdl, &cmd, false, sizeof(*cap_log));
	if (err) {
		nvme_show_err(err, "supported capacity configuration list log");
		return err;
	}

	nvme_show_supported_cap_config_log(cap_log, flags);

	return err;
}

static int sanitize_log(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc = "Retrieve sanitize log and show it.";

	__cleanup_libnvme_free struct nvme_sanitize_log_page *sanitize_log = NULL;
	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	__cleanup_nvme_transport_handle struct libnvme_transport_handle *hdl = NULL;
	struct libnvme_passthru_cmd cmd;
	nvme_print_flags_t flags;
	int err;

	struct config {
		bool	rae;
		bool	raw_binary;
	};

	struct config cfg = {
		.rae		= false,
		.raw_binary	= false,
	};

	NVME_ARGS(opts,
		  OPT_FLAG("rae",            'r', &cfg.rae,            rae),
		  OPT_FLAG("raw-binary",     'b', &cfg.raw_binary,     raw_log));

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	err = validate_output_format(nvme_args.output_format, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	if (cfg.raw_binary)
		flags = BINARY;

	if (nvme_args.verbose)
		flags |= VERBOSE;

	sanitize_log = libnvme_alloc(sizeof(*sanitize_log));
	if (!sanitize_log)
		return -ENOMEM;

	nvme_init_get_log_sanitize(&cmd, sanitize_log);
	err = libnvme_get_log(hdl, &cmd, cfg.rae, sizeof(*sanitize_log));
	if (err) {
		nvme_show_err(err, "sanitize status log");
		return err;
	}

	nvme_show_sanitize_log(sanitize_log,
			       libnvme_transport_handle_get_name(hdl), flags);

	return err;
}

static int get_fid_support_effects_log(int argc, char **argv, struct command *acmd,
	struct plugin *plugin)
{
	const char *desc = "Retrieve FID Support and Effects log and show it.";

	__cleanup_libnvme_free struct nvme_fid_supported_effects_log *fid_support_log = NULL;
	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	__cleanup_nvme_transport_handle struct libnvme_transport_handle *hdl = NULL;
	struct libnvme_passthru_cmd cmd;
	nvme_print_flags_t flags;
	int err = -1;

	NVME_ARGS(opts);

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	err = validate_output_format(nvme_args.output_format, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	if (nvme_args.verbose)
		flags |= VERBOSE;

	fid_support_log = libnvme_alloc(sizeof(*fid_support_log));
	if (!fid_support_log)
		return -ENOMEM;

	nvme_init_get_log_fid_supported_effects(&cmd, false, fid_support_log);
	err = libnvme_get_log(hdl, &cmd, false, sizeof(*fid_support_log));
	if (err) {
		nvme_show_err(err, "fid support effects log");
		return err;
	}

	nvme_show_fid_support_effects_log(fid_support_log,
					  libnvme_transport_handle_get_name(hdl),
					  flags);

	return err;
}

static int get_mi_cmd_support_effects_log(int argc, char **argv, struct command *acmd,
	struct plugin *plugin)
{
	const char *desc = "Retrieve NVMe-MI Command Support and Effects log and show it.";

	__cleanup_libnvme_free struct nvme_mi_cmd_supported_effects_log *mi_cmd_support_log = NULL;
	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	__cleanup_nvme_transport_handle struct libnvme_transport_handle *hdl = NULL;
	struct libnvme_passthru_cmd cmd;
	nvme_print_flags_t flags;
	int err = -1;

	NVME_ARGS(opts);

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	err = validate_output_format(nvme_args.output_format, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	if (nvme_args.verbose)
		flags |= VERBOSE;

	mi_cmd_support_log = libnvme_alloc(sizeof(*mi_cmd_support_log));
	if (!mi_cmd_support_log)
		return -ENOMEM;

	nvme_init_get_log_mi_cmd_supported_effects(&cmd, mi_cmd_support_log);
	err = libnvme_get_log(hdl, &cmd, false, sizeof(*mi_cmd_support_log));
	if (err) {
		nvme_show_err(err, "mi command support effects log");
		return err;
	}

	nvme_show_mi_cmd_support_effects_log(mi_cmd_support_log,
	    libnvme_transport_handle_get_name(hdl), flags);

	return err;
}
static int self_test_log(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc = "Retrieve the self-test log for the given device and given test "
		"(or optionally a namespace) in either decoded format (default) or binary.";
	const char *dst_entries = "Indicate how many DST log entries to be retrieved, "
		"by default all the 20 entries will be retrieved";

	__cleanup_libnvme_free struct nvme_self_test_log *log = NULL;
	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	__cleanup_nvme_transport_handle struct libnvme_transport_handle *hdl = NULL;
	struct libnvme_passthru_cmd cmd;
	nvme_print_flags_t flags;
	int err;

	struct config {
		__u8	dst_entries;
	};

	struct config cfg = {
		.dst_entries	= NVME_LOG_ST_MAX_RESULTS,
	};

	NVME_ARGS(opts,
		  OPT_BYTE("dst-entries",  'e', &cfg.dst_entries,   dst_entries));

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	err = validate_output_format(nvme_args.output_format, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	if (nvme_args.verbose)
		flags |= VERBOSE;

	log = libnvme_alloc(sizeof(*log));
	if (!log)
		return -ENOMEM;

	nvme_init_get_log(&cmd, NVME_NSID_ALL, NVME_LOG_LID_DEVICE_SELF_TEST,
		NVME_CSI_NVM, log, sizeof(*log));
	err = libnvme_get_log(hdl, &cmd, false, sizeof(*log));
	if (err) {
		nvme_show_err(err, "self test log");
		return err;
	}

	nvme_show_self_test_log(log, cfg.dst_entries, 0,
				libnvme_transport_handle_get_name(hdl), flags);

	return err;
}
static int get_mgmt_addr_list_log(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc = "Retrieve Management Address List Log, show it";
	nvme_print_flags_t flags;
	int err = -1;

	__cleanup_libnvme_free struct nvme_mgmt_addr_list_log *ma_log = NULL;
	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	__cleanup_nvme_transport_handle struct libnvme_transport_handle *hdl = NULL;
	struct libnvme_passthru_cmd cmd;

	NVME_ARGS(opts);

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	err = validate_output_format(nvme_args.output_format, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	ma_log = libnvme_alloc(sizeof(*ma_log));
	if (!ma_log)
		return -ENOMEM;

	nvme_init_get_log_mgmt_addr_list(&cmd, ma_log, sizeof(*ma_log));
	err = libnvme_get_log(hdl, &cmd, false, sizeof(*ma_log));
	if (err) {
		nvme_show_err(err, "management address list log");
		return err;
	}

	nvme_show_mgmt_addr_list_log(ma_log, flags);

	return err;
}

static int get_rotational_media_info_log(int argc, char **argv, struct command *acmd,
					 struct plugin *plugin)
{
	const char *desc = "Retrieve Rotational Media Information Log, show it";
	nvme_print_flags_t flags;
	int err = -1;

	__cleanup_libnvme_free struct nvme_rotational_media_info_log *info = NULL;
	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	__cleanup_nvme_transport_handle struct libnvme_transport_handle *hdl = NULL;
	struct libnvme_passthru_cmd cmd;

	struct config {
		__u16 endgid;
	};

	struct config cfg = {
		.endgid = 0,
	};

	NVME_ARGS(opts,
		  OPT_UINT("endg-id", 'e', &cfg.endgid, endgid));

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	err = validate_output_format(nvme_args.output_format, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	info = libnvme_alloc(sizeof(*info));
	if (!info)
		return -ENOMEM;

	nvme_init_get_log_rotational_media_info(&cmd, cfg.endgid, info, sizeof(*info));
	err = libnvme_get_log(hdl, &cmd, false, sizeof(*info));
	if (err) {
		nvme_show_err(err, "rotational media info log");
		return err;
	}

	nvme_show_rotational_media_info_log(info, flags);

	return err;
}

static int get_dispersed_ns_psub(struct libnvme_transport_handle *hdl, __u32 nsid,
				 struct nvme_dispersed_ns_participating_nss_log **logp)
{
	int err;
	__u64 header_len = sizeof(**logp);
	__u64 psub_list_len;
	struct nvme_dispersed_ns_participating_nss_log *log = libnvme_alloc(header_len);
	struct libnvme_passthru_cmd cmd;

	if (!log)
		return -ENOMEM;

	nvme_init_get_log_dispersed_ns_participating_nss(&cmd, nsid, log, header_len);
	err = libnvme_get_log(hdl, &cmd, false, header_len);
	if (err)
		goto err_free;

	psub_list_len = le64_to_cpu(log->numpsub) * NVME_NQN_LENGTH;

	log = libnvme_realloc(log, header_len + psub_list_len);
	if (!log) {
		err = -ENOMEM;
		goto err_free;
	}

	nvme_init_get_log_dispersed_ns_participating_nss(&cmd, nsid,
		(void *)log->participating_nss, psub_list_len);
	cmd.cdw12 = header_len & 0xffffffff;
	cmd.cdw13 = header_len >> 32;
	err = libnvme_get_log(hdl, &cmd, false, NVME_LOG_PAGE_PDU_SIZE);
	if (err)
		goto err_free;

	*logp = log;
	return 0;

err_free:
	libnvme_free(log);
	return err;
}

static int get_dispersed_ns_participating_nss_log(int argc, char **argv, struct command *acmd,
						  struct plugin *plugin)
{
	const char *desc = "Retrieve Dispersed Namespace Participating NVM Subsystems Log, show it";
	nvme_print_flags_t flags;
	int err;

	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	__cleanup_nvme_transport_handle struct libnvme_transport_handle *hdl = NULL;
	__cleanup_libnvme_free struct nvme_dispersed_ns_participating_nss_log *log = NULL;

	struct config {
		__u32 namespace_id;
	};

	struct config cfg = {
		.namespace_id = 1,
	};

	NVME_ARGS(opts, OPT_UINT("namespace-id", 'n', &cfg.namespace_id, namespace_id_desired));

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	err = validate_output_format(nvme_args.output_format, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	err = get_dispersed_ns_psub(hdl, cfg.namespace_id, &log);
	if (err) {
		nvme_show_err(err, "dispersed ns participating nss log");
		return err;
	}

	nvme_show_dispersed_ns_psub_log(log, flags);

	return err;
}

static int get_power_measurement_log(int argc, char **argv, struct command *acmd,
				     struct plugin *plugin)
{
	const char *desc = "Retrieve Power Measurement Log (Log ID 0x25) "
		"for the given device in either decoded format (default), "
		"json, or binary.";

	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	__cleanup_nvme_transport_handle struct libnvme_transport_handle *hdl = NULL;
	__cleanup_libnvme_free struct nvme_power_meas_log *log = NULL;
	struct libnvme_passthru_cmd cmd;
	nvme_print_flags_t flags;
	__u32 min_log_size = sizeof(struct nvme_power_meas_log);
	__u32 log_size;
	int err = -1;

	struct config {
		bool	raw_binary;
	};

	struct config cfg = {
		.raw_binary	= false,
	};

	NVME_ARGS(opts,
		  OPT_FLAG("raw-binary", 'b', &cfg.raw_binary, raw_output));

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	err = validate_output_format(nvme_args.output_format, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	if (cfg.raw_binary)
		flags = BINARY;

	if (nvme_args.verbose)
		flags |= VERBOSE;

	/* First read minimum size to discover the full log size */
	log = libnvme_alloc(min_log_size);
	if (!log)
		return -ENOMEM;

	nvme_init_get_log_power_measurement(&cmd, log, min_log_size);
	err = libnvme_get_log(hdl, &cmd, false, NVME_LOG_PAGE_PDU_SIZE);
	if (err) {
		nvme_show_err(err, "power-measurement-log");
		return err;
	}

	log_size = le32_to_cpu(log->sze);

	/* If sze is 0 or smaller than the minimum, just use minimum */
	if (log_size < min_log_size)
		log_size = min_log_size;

	/* If the log is larger, re-read with full size */
	if (log_size > min_log_size) {
		log = libnvme_realloc(log, log_size);
		if (!log)
			return -ENOMEM;

		nvme_init_get_log_power_measurement(&cmd, log, log_size);
		err = libnvme_get_log(hdl, &cmd, false, NVME_LOG_PAGE_PDU_SIZE);
		if (err) {
			nvme_show_err(err, "power-measurement-log");
			return err;
		}
	}

	nvme_show_power_meas_log(log, log_size, flags);

	return err;
}

static int get_log_offset(struct libnvme_transport_handle *hdl,
			  struct nvme_get_log_args *args, __u64 *offset,
			  __u32 len, void **log)
{
	struct libnvme_passthru_cmd cmd;
	int err;

	args->lpo = *offset;
	args->len = len;
	*offset += args->len;

	*log = libnvme_realloc(*log, *offset);
	if (!*log)
		return -ENOMEM;

	args->log = (char *)*log + args->lpo;

	nvme_init_get_log(&cmd, args->nsid, args->lid,
			  args->csi, args->log, args->len);
	cmd.cdw10 |= NVME_FIELD_ENCODE(args->lsp,
			NVME_LOG_CDW10_LSP_SHIFT,
			NVME_LOG_CDW10_LSP_MASK);
	cmd.cdw11 |= NVME_FIELD_ENCODE(args->lsi,
			NVME_LOG_CDW11_LSI_SHIFT,
			NVME_LOG_CDW11_LSI_MASK);
	cmd.cdw12 = args->lpo & 0xffffffff;
	cmd.cdw13 = args->lpo >> 32;
	cmd.cdw14 |= NVME_FIELD_ENCODE(args->uidx,
			NVME_LOG_CDW14_UUID_SHIFT,
			NVME_LOG_CDW14_UUID_MASK) |
		     NVME_FIELD_ENCODE(args->ot,
			NVME_LOG_CDW14_OT_SHIFT,
			NVME_LOG_CDW14_OT_MASK);

	err = libnvme_get_log(hdl, &cmd, args->rae, NVME_LOG_PAGE_PDU_SIZE);
	if (args->result)
		*args->result = cmd.result;
	return err;
}

static int get_reachability_group_desc(struct libnvme_transport_handle *hdl, struct nvme_get_log_args *args,
				       __u64 *offset, struct nvme_reachability_groups_log **logp)
{
	int err;
	struct nvme_reachability_groups_log *log = *logp;
	__u16 i;
	__u32 len;

	for (i = 0; i < le16_to_cpu(log->nrgd); i++) {
		len = sizeof(*log->rgd);
		err = get_log_offset(hdl, args, offset, len, (void **)&log);
		if (err)
			goto err_free;
		len = le32_to_cpu(log->rgd[i].nnid) * sizeof(*log->rgd[i].nsid);
		err = get_log_offset(hdl, args, offset, len, (void **)&log);
		if (err)
			goto err_free;
	}

	*logp = log;
	return 0;

err_free:
	libnvme_free(log);
	*logp = NULL;
	return err;
}

static int get_reachability_groups(struct libnvme_transport_handle *hdl, bool rgo, bool rae,
				   struct nvme_reachability_groups_log **logp,
				   __u64 *lenp)
{
	int err;
	struct nvme_reachability_groups_log *log;
	struct libnvme_passthru_cmd cmd;
	__u64 log_len = sizeof(*log);
	struct nvme_get_log_args args = {
		.lid = NVME_LOG_LID_REACHABILITY_GROUPS,
		.nsid = NVME_NSID_ALL,
		.lsp = rgo,
		.rae = rae,
	};

	log = libnvme_alloc(log_len);
	if (!log)
		return -ENOMEM;

	nvme_init_get_log_reachability_groups(&cmd, rgo, log, log_len);
	err = libnvme_get_log(hdl, &cmd, false, log_len);
	if (err)
		goto err_free;

	err = get_reachability_group_desc(hdl, &args, &log_len, &log);
	if (err)
		goto err_free;

	*logp = log;
	*lenp = log_len;
	return 0;

err_free:
	libnvme_free(log);
	return err;
}

static int get_reachability_groups_log(int argc, char **argv, struct command *acmd,
				       struct plugin *plugin)
{
	const char *desc = "Retrieve Reachability Groups Log, show it";
	const char *rgo = "Return Groups Only";
	nvme_print_flags_t flags;
	int err;
	__u64 len = 0;
	__cleanup_libnvme_free struct nvme_reachability_groups_log *log = NULL;
	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	__cleanup_nvme_transport_handle struct libnvme_transport_handle *hdl = NULL;

	struct config {
		bool rgo;
		bool rae;
	};

	struct config cfg = {
		.rgo = false,
		.rae = false,
	};

	NVME_ARGS(opts,
		  OPT_FLAG("groups-only", 'g', &cfg.rgo, rgo),
		  OPT_FLAG("rae", 'r', &cfg.rae, rae));

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	err = validate_output_format(nvme_args.output_format, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	err = get_reachability_groups(hdl, cfg.rgo, cfg.rae, &log, &len);
	if (err) {
		nvme_show_err(err, "reachability groups log");
		return err;
	}

	nvme_show_reachability_groups_log(log, len, flags);

	return err;
}

static int get_reachability_association_desc(struct libnvme_transport_handle *hdl, struct nvme_get_log_args *args,
					     __u64 *offset,
					     struct nvme_reachability_associations_log **logp)
{
	int err;
	struct nvme_reachability_associations_log *log = *logp;
	__u16 i;
	__u32 len;

	for (i = 0; i < le16_to_cpu(log->nrad); i++) {
		len = sizeof(*log->rad);
		err = get_log_offset(hdl, args, offset, len, (void **)&log);
		if (err)
			goto err_free;
		len = le32_to_cpu(log->rad[i].nrid) * sizeof(*log->rad[i].rgid);
		err = get_log_offset(hdl, args, offset, len, (void **)&log);
		if (err)
			goto err_free;
	}

	*logp = log;
	return 0;

err_free:
	libnvme_free(log);
	*logp = NULL;
	return err;
}

static int get_reachability_associations(struct libnvme_transport_handle *hdl, bool rao, bool rae,
					 struct nvme_reachability_associations_log **logp,
					 __u64 *lenp)
{
	int err;
	struct nvme_reachability_associations_log *log;
	struct libnvme_passthru_cmd cmd;
	__u64 log_len = sizeof(*log);
	struct nvme_get_log_args args = {
		.lid = NVME_LOG_LID_REACHABILITY_ASSOCIATIONS,
		.nsid = NVME_NSID_ALL,
		.lsp = rao,
		.rae = rae,
	};

	log = libnvme_alloc(log_len);
	if (!log)
		return -ENOMEM;

	nvme_init_get_log_reachability_associations(&cmd, rao, log, log_len);
	err = libnvme_get_log(hdl, &cmd, rae, log_len);
	if (err)
		goto err_free;

	err = get_reachability_association_desc(hdl, &args, &log_len, &log);
	if (err)
		goto err_free;

	*logp = log;
	*lenp = log_len;
	return 0;

err_free:
	libnvme_free(log);
	return err;
}

static int get_reachability_associations_log(int argc, char **argv, struct command *acmd,
					     struct plugin *plugin)
{
	const char *desc = "Retrieve Reachability Associations Log, show it";
	const char *rao = "Return Associations Only";
	nvme_print_flags_t flags;
	int err;
	__u64 len = 0;
	__cleanup_libnvme_free struct nvme_reachability_associations_log *log = NULL;
	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	__cleanup_nvme_transport_handle struct libnvme_transport_handle *hdl = NULL;

	struct config {
		bool rao;
		bool rae;
	};

	struct config cfg = {
		.rao = false,
		.rae = false,
	};

	NVME_ARGS(opts,
		  OPT_FLAG("associations-only", 'a', &cfg.rao, rao),
		  OPT_FLAG("rae", 'r', &cfg.rae, rae));

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	err = validate_output_format(nvme_args.output_format, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	err = get_reachability_associations(hdl, cfg.rao, cfg.rae, &log, &len);
	if (err) {
		nvme_show_err(err, "reachability associations log");
		return err;
	}

	nvme_show_reachability_associations_log(log, len, flags);

	return err;
}

static int get_host_discovery(struct libnvme_transport_handle *hdl, bool allhoste, bool rae,
			      struct nvme_host_discovery_log **logp)
{
	int err;
	struct nvme_host_discovery_log *log;
	struct libnvme_passthru_cmd cmd;
	__u64 log_len = sizeof(*log);
	struct nvme_get_log_args args = {
		.lid = NVME_LOG_LID_HOST_DISCOVERY,
		.nsid = NVME_NSID_ALL,
		.lsp = allhoste,
		.rae = rae,
	};

	log = libnvme_alloc(log_len);
	if (!log)
		return -ENOMEM;

	nvme_init_get_log_host_discovery(&cmd, rae, log, log_len);
	err = libnvme_get_log(hdl, &cmd, false, log_len);
	if (err)
		goto err_free;

	log_len = le32_to_cpu(log->thdlpl);
	err = get_log_offset(hdl, &args, &log_len, le32_to_cpu(log->thdlpl) - log_len,
			     (void **)&log);
	if (err)
		goto err_free;

	*logp = log;
	return 0;

err_free:
	libnvme_free(log);
	return err;
}

static int get_host_discovery_log(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc = "Retrieve Host Discovery Log, show it";
	const char *allhoste = "All Host Entries";
	nvme_print_flags_t flags;
	int err;
	__cleanup_libnvme_free struct nvme_host_discovery_log *log = NULL;
	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	__cleanup_nvme_transport_handle struct libnvme_transport_handle *hdl = NULL;

	struct config {
		bool allhoste;
		bool rae;
	};

	struct config cfg = {
		.allhoste = false,
		.rae = false,
	};

	NVME_ARGS(opts,
		  OPT_FLAG("all-host-entries", 'a', &cfg.allhoste, allhoste),
		  OPT_FLAG("rae", 'r', &cfg.rae, rae));


	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	err = validate_output_format(nvme_args.output_format, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	err = get_host_discovery(hdl, cfg.allhoste, cfg.rae, &log);
	if (err) {
		nvme_show_err(err, "host discovery log");
		return err;
	}

	nvme_show_host_discovery_log(log, flags);

	return err;
}

static int get_ave_discovery(struct libnvme_transport_handle *hdl, bool rae,
			     struct nvme_ave_discovery_log **logp)
{
	int err;
	struct nvme_ave_discovery_log *log;
	struct libnvme_passthru_cmd cmd;
	__u64 log_len = sizeof(*log);
	struct nvme_get_log_args args = {
		.lid = NVME_LOG_LID_AVE_DISCOVERY,
		.nsid = NVME_NSID_ALL,
		.rae = rae,
	};

	log = libnvme_alloc(log_len);
	if (!log)
		return -ENOMEM;

	nvme_init_get_log_ave_discovery(&cmd, log, log_len);
	err = libnvme_get_log(hdl, &cmd, rae, log_len);
	if (err)
		goto err_free;

	log_len = le32_to_cpu(log->tadlpl);
	err = get_log_offset(hdl, &args, &log_len, le32_to_cpu(log->tadlpl) - log_len,
			     (void **)&log);
	if (err)
		goto err_free;

	*logp = log;
	return 0;

err_free:
	libnvme_free(log);
	return err;
}

static int get_ave_discovery_log(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc = "Retrieve AVE Discovery Log, show it";
	nvme_print_flags_t flags;
	int err;

	__cleanup_libnvme_free struct nvme_ave_discovery_log *log = NULL;
	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	__cleanup_nvme_transport_handle struct libnvme_transport_handle *hdl = NULL;

	struct config {
		bool rae;
	};

	struct config cfg = {
		.rae = false,
	};

	NVME_ARGS(opts, OPT_FLAG("rae", 'r', &cfg.rae, rae));

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	err = validate_output_format(nvme_args.output_format, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	err = get_ave_discovery(hdl, cfg.rae, &log);
	if (err) {
		nvme_show_err(err, "ave discovery log");
		return err;
	}

	nvme_show_ave_discovery_log(log, flags);

	return err;
}

static int get_pull_model_ddc_req(struct libnvme_transport_handle *hdl,
				  bool rae, struct nvme_pull_model_ddc_req_log **logp)
{
	int err;
	struct nvme_pull_model_ddc_req_log *log;
	struct libnvme_passthru_cmd cmd;
	__u64 log_len = sizeof(*log);
	struct nvme_get_log_args args = {
		.lid = NVME_LOG_LID_PULL_MODEL_DDC_REQ,
		.nsid = NVME_NSID_ALL,
		.rae = rae,
	};

	log = libnvme_alloc(log_len);
	if (!log)
		return -ENOMEM;

	nvme_init_get_log_pull_model_ddc_req(&cmd, log, log_len);
	err = libnvme_get_log(hdl, &cmd, rae, log_len);
	if (err)
		goto err_free;

	log_len = le32_to_cpu(log->tpdrpl);
	err = get_log_offset(hdl, &args, &log_len, le32_to_cpu(log->tpdrpl) - log_len,
			     (void **)&log);
	if (err)
		goto err_free;

	*logp = log;
	return 0;

err_free:
	libnvme_free(log);
	return err;
}

static int get_pull_model_ddc_req_log(int argc, char **argv, struct command *acmd,
				      struct plugin *plugin)
{
	const char *desc = "Retrieve Pull Model DDC Request Log, show it";
	nvme_print_flags_t flags;
	int err;

	__cleanup_libnvme_free struct nvme_pull_model_ddc_req_log *log = NULL;
	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	__cleanup_nvme_transport_handle struct libnvme_transport_handle *hdl = NULL;

	struct config {
		bool rae;
	};

	struct config cfg = {
		.rae = false,
	};

	NVME_ARGS(opts, OPT_FLAG("rae", 'r', &cfg.rae, rae));

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	err = validate_output_format(nvme_args.output_format, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	err = get_pull_model_ddc_req(hdl, cfg.rae, &log);
	if (err) {
		nvme_show_err(err, "pull model ddc req log");
		return err;
	}

	nvme_show_pull_model_ddc_req_log(log, flags);

	return err;
}

static struct command smart_cmd = {
	.name = "smart",
	.help = "Retrieve SMART Log, show it",
	.fn = get_smart_log,
};

static struct command ana_cmd = {
	.name = "ana",
	.help = "Retrieve ANA Log, show it",
	.fn = get_ana_log,
};

static struct command telemetry_cmd = {
	.name = "telemetry",
	.help = "Retrieve FW Telemetry log write to file",
	.fn = get_telemetry_log,
};

static struct command fw_cmd = {
	.name = "fw",
	.help = "Retrieve FW Log, show it",
	.fn = get_fw_log,
};

static struct command endurance_cmd = {
	.name = "endurance",
	.help = "Retrieve Endurance Group Log, show it",
	.fn = get_endurance_log,
};

static struct command effects_cmd = {
	.name = "effects",
	.help = "Retrieve Command Effects Log, show it",
	.fn = get_effects_log,
};

static struct command error_cmd = {
	.name = "error",
	.help = "Retrieve Error Log, show it",
	.fn = get_error_log,
};

static struct command changed_ns_list_cmd = {
	.name = "changed-ns-list",
	.help = "Retrieve Changed Attached Namespace List, show it",
	.fn = get_changed_attach_ns_list_log,
};

static struct command changed_alloc_ns_list_cmd = {
	.name = "changed-alloc-ns-list",
	.help = "Retrieve Changed Allocated Namespace List, show it",
	.fn = get_changed_alloc_ns_list_log,
};

static struct command predictable_lat_cmd = {
	.name = "predictable-lat",
	.help = "Retrieve Predictable Latency per Nvmset Log, show it",
	.fn = get_pred_lat_per_nvmset_log,
};

static struct command pred_lat_event_agg_cmd = {
	.name = "pred-lat-event-agg",
	.help = "Retrieve Predictable Latency Event Aggregate Log, show it",
	.fn = get_pred_lat_event_agg_log,
};

static struct command persistent_event_cmd = {
	.name = "persistent-event",
	.help = "Retrieve Persistent Event Log, show it",
	.fn = get_persistent_event_log,
};

static struct command endurance_event_agg_cmd = {
	.name = "endurance-event-agg",
	.help = "Retrieve Endurance Group Event Aggregate Log, show it",
	.fn = get_endurance_event_agg_log,
};

static struct command lba_status_cmd = {
	.name = "lba-status",
	.help = "Retrieve LBA Status Information Log, show it",
	.fn = get_lba_status_log,
};

static struct command resv_notif_cmd = {
	.name = "resv-notif",
	.help = "Retrieve Reservation Notification Log, show it",
	.fn = get_resv_notif_log,
};

static struct command boot_part_cmd = {
	.name = "boot-part",
	.help = "Retrieve Boot Partition Log, show it",
	.fn = get_boot_part_log,
};

static struct command phy_rx_eom_cmd = {
	.name = "phy-rx-eom",
	.help = "Retrieve Physical Interface Receiver Eye Opening Measurement, show it",
	.fn = get_phy_rx_eom_log,
};

static struct command self_test_cmd = {
	.name = "self-test",
	.help = "Retrieve the SELF-TEST Log, show it",
	.fn = self_test_log,
};

static struct command fid_support_effects_cmd = {
	.name = "fid-support-effects",
	.help = "Retrieve FID Support and Effects log and show it",
	.fn = get_fid_support_effects_log,
};

static struct command mi_cmd_support_effects_cmd = {
	.name = "mi-cmd-support-effects",
	.help = "Retrieve MI Command Support and Effects log and show it",
	.fn = get_mi_cmd_support_effects_log,
};

static struct command media_unit_stat_cmd = {
	.name = "media-unit-stat",
	.help = "Retrieve the configuration and wear of media units, show it",
	.fn = get_media_unit_stat_log,
};

static struct command supported_cap_config_cmd = {
	.name = "supported-cap-config",
	.help = "Retrieve the list of Supported Capacity Configuration Descriptors",
	.fn = get_supp_cap_config_log,
};

static struct command mgmt_addr_list_cmd = {
	.name = "mgmt-addr-list",
	.help = "Retrieve Management Address List Log, show it",
	.fn = get_mgmt_addr_list_log,
};

static struct command rotational_media_info_cmd = {
	.name = "rotational-media-info",
	.help = "Retrieve Rotational Media Information Log, show it",
	.fn = get_rotational_media_info_log,
};

static struct command dispersed_ns_participating_nss_cmd = {
	.name = "dispersed-ns-participating-nss",
	.help = "Retrieve Dispersed Namespace Participating NVM Subsystems Log, show it",
	.fn = get_dispersed_ns_participating_nss_log,
};

static struct command reachability_groups_cmd = {
	.name = "reachability-groups",
	.help = "Retrieve Reachability Groups Log, show it",
	.fn = get_reachability_groups_log,
};

static struct command reachability_associations_cmd = {
	.name = "reachability-associations",
	.help = "Retrieve Reachability Associations Log, show it",
	.fn = get_reachability_associations_log,
};

static struct command host_discovery_cmd = {
	.name = "host-discovery",
	.help = "Retrieve Host Discovery Log, show it",
	.fn = get_host_discovery_log,
};

static struct command ave_discovery_cmd = {
	.name = "ave-discovery",
	.help = "Retrieve AVE Discovery Log, show it",
	.fn = get_ave_discovery_log,
};

static struct command pull_model_ddc_req_cmd = {
	.name = "pull-model-ddc-req",
	.help = "Retrieve Pull Model DDC Request Log, show it",
	.fn = get_pull_model_ddc_req_log,
};

static struct command power_measurement_cmd = {
	.name = "power-measurement",
	.help = "Retrieve Power Measurement Log, show it",
	.fn = get_power_measurement_log,
};

static struct command sanitize_cmd = {
	.name = "sanitize",
	.help = "Retrieve sanitize log, show it",
	.fn = sanitize_log,
};

static struct command *commands[] = {
	&smart_cmd,
	&ana_cmd,
	&telemetry_cmd,
	&fw_cmd,
	&endurance_cmd,
	&effects_cmd,
	&error_cmd,
	&changed_ns_list_cmd,
	&changed_alloc_ns_list_cmd,
	&predictable_lat_cmd,
	&pred_lat_event_agg_cmd,
	&persistent_event_cmd,
	&endurance_event_agg_cmd,
	&lba_status_cmd,
	&resv_notif_cmd,
	&boot_part_cmd,
	&phy_rx_eom_cmd,
	&self_test_cmd,
	&fid_support_effects_cmd,
	&mi_cmd_support_effects_cmd,
	&media_unit_stat_cmd,
	&supported_cap_config_cmd,
	&mgmt_addr_list_cmd,
	&rotational_media_info_cmd,
	&dispersed_ns_participating_nss_cmd,
	&reachability_groups_cmd,
	&reachability_associations_cmd,
	&host_discovery_cmd,
	&ave_discovery_cmd,
	&pull_model_ddc_req_cmd,
	&power_measurement_cmd,
	&sanitize_cmd,
	NULL,
};

static struct plugin plugin = {
	.name = "log",
	.desc = "Retrieve and show NVMe log pages",
	.version = NVME_VERSION,
	.core = true,
};

static void __shr_constructor register_plugin(void)
{
	plugin_add_group(&plugin, NULL, commands);
	register_extension(&plugin);
}
