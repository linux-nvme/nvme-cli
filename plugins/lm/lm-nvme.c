// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2024 Samsung Electronics Co., LTD.
 *
 * Authors: Nate Thornton <n.thornton@samsung.com>
 */

#include <assert.h>
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <linux/fs.h>
#include <inttypes.h>
#include <asm/byteorder.h>
#include <sys/mman.h>
#include <sys/shm.h>
#include <sys/sysinfo.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#include <time.h>

#include "common.h"
#include "nvme.h"
#include "nvme-print.h"
#include "libnvme.h"
#include "plugin.h"
#include "linux/types.h"
#include "util/cleanup.h"

#define CREATE_CMD
#include "lm-nvme.h"

#include "lm-print.h"

static inline const char * arg_str(const char * const *strings, size_t array_size, size_t idx)
{
	if (idx < array_size && strings[idx])
		return strings[idx];
	return "unrecognized";
}

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))
#define ARGSTR(s, i) arg_str(s, ARRAY_SIZE(s), i)

static int lm_create_cdq(int argc, char **argv, struct command *command, struct plugin *plugin)
{
	const char *desc = "Create Controller Data Queue for controller of specific type and size";
	const char *sz = "CDQ Size (in dwords)";
	const char *cntlid = "Controller ID";
	const char *qt = "Queue Type (default: 0 = User Data Migration Queue)";
	const char *consent = "I consent this will not work and understand a CDQ cannot be mapped "
			      "to user space. If I proceed with the creation of a CDQ, the device "
			      "will write to invalid memory, inevitably leading to MMU faults or "
			      "worse.";

	_cleanup_huge_ struct nvme_mem_huge mh = { 0, };
	_cleanup_nvme_global_ctx_ struct nvme_global_ctx *ctx = NULL;
	_cleanup_nvme_transport_handle_ struct nvme_transport_handle *hdl = NULL;
	struct lba_migration_queue_entry_type_0 *queue = NULL;
	int err = -1;

	struct config {
		__u32	sz;
		__u16	cntlid;
		__u8	qt;
		bool	consent;
		char	*file;
	};

	struct config cfg = {
		.sz = 0,
		.cntlid = 0,
		.qt = 0,
		.consent = false,
		.file = NULL,
	};

	OPT_ARGS(opts) = {
		OPT_UINT("size",	's', &cfg.sz,		sz),
		OPT_SHRT("cntlid",	'c', &cfg.cntlid,	cntlid),
		OPT_BYTE("queue-type",	'q', &cfg.qt,		qt),
		OPT_FLAG("consent",	  0, &cfg.consent,	consent),
		OPT_END()
	};

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	if (!consent) {
		nvme_show_error("ERROR: consent required");
		return -EINVAL;
	}

	// Not that it really matters, but we setup memory as if the CDQ can be held
	// in user space regardless.
	queue = nvme_alloc_huge(cfg.sz << 2, &mh);
	if (!queue) {
		nvme_show_error("ERROR: nvme_alloc of size %dB failed %s", cfg.sz << 2,
				strerror(errno));
		return -ENOMEM;
	}

	struct nvme_lm_cdq_args args = {
		.args_size = sizeof(args),
		.sel = NVME_LM_SEL_CREATE_CDQ,
		.mos = NVME_SET(cfg.qt, LM_QT),
		.cntlid = cfg.cntlid,
		.sz = cfg.sz,
		.data = queue
	};

	err = nvme_lm_cdq(hdl, &args);
	if (err < 0)
		nvme_show_error("ERROR: nvme_lm_cdq() failed: %s", nvme_strerror(errno));
	else if (err)
		nvme_show_status(err);
	else
		printf("Create CDQ Successful: CDQID=0x%04x\n", args.cdqid);

	return err;
}

static int lm_delete_cdq(int argc, char **argv, struct command *command, struct plugin *plugin)
{
	const char *desc = "Delete Controller Data Queue";
	const char *cdqid = "Controller Data Queue ID";

	_cleanup_nvme_global_ctx_ struct nvme_global_ctx *ctx = NULL;
	_cleanup_nvme_transport_handle_ struct nvme_transport_handle *hdl = NULL;
	int err = -1;

	struct config {
		__u16	cdqid;
	};

	struct config cfg = {
		.cdqid = 0
	};

	OPT_ARGS(opts) = {
		OPT_SHRT("cdqid", 'C', &cfg.cdqid, cdqid),
		OPT_END()
	};

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	struct nvme_lm_cdq_args args = {
		.args_size = sizeof(args),
		.sel = NVME_LM_SEL_DELETE_CDQ,
		.cdqid = cfg.cdqid,
	};

	err = nvme_lm_cdq(hdl, &args);
	if (err < 0)
		nvme_show_error("ERROR: nvme_lm_cdq() failed: %s", nvme_strerror(errno));
	else if (err > 0)
		nvme_show_status(err);
	else
		printf("Delete CDQ Successful: CDQID=0x%04x\n", cfg.cdqid);

	return err;
}

static const char * const lm_track_send_select_argstr[] = {
	[NVME_LM_SEL_LOG_USER_DATA_CHANGES] = "Log User Data Changes",
	[NVME_LM_SEL_TRACK_MEMORY_CHANGES] = "Track Memory Changes"
};

static int lm_track_send(int argc, char **argv, struct command *command, struct plugin *plugin)
{
	const char *desc = "Track Send command used to manage the tracking of information by a "
			   "controller";
	const char *sel = "Type of management operation to perform\n"
				 "  0h = Log User Data Changes\n"
				 "  1h = Track Memory Changes";
	const char *mos = "Management operation specific";
	const char *cdqid = "Controller Data Queue ID";
	const char *start = "Equivalent to start tracking with defaults";
	const char *stop = "Equivalent to stop tracking with defaults";


	_cleanup_nvme_global_ctx_ struct nvme_global_ctx *ctx = NULL;
	_cleanup_nvme_transport_handle_ struct nvme_transport_handle *hdl = NULL;
	int err = -1;

	struct config {
		__s8  sel;
		__u8  mos;
		__u16 cdqid;
		bool  start;
		bool  stop;
	};

	struct config cfg = {
		.sel = -1,
		.mos = 0,
		.cdqid = 0,
		.start = false,
		.stop = false,
	};

	OPT_ARGS(opts) = {
		OPT_BYTE("sel",		's', &cfg.sel,   sel),
		OPT_BYTE("mos",		'm', &cfg.mos,   mos),
		OPT_SHRT("cdqid",	'C', &cfg.cdqid, cdqid),
		OPT_FLAG("start",	  0, &cfg.start, start),
		OPT_FLAG("stop",	  0, &cfg.stop,  stop),
		OPT_END()
	};

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	if (cfg.sel == -1) {
		nvme_show_error("Select field required");
		return -EINVAL;
	}

	if (cfg.sel != NVME_LM_SEL_LOG_USER_DATA_CHANGES) {
		nvme_show_error("Unsupported select option %d (%s)", cfg.sel,
				ARGSTR(lm_track_send_select_argstr, cfg.sel));
		return -EINVAL;
	}

	if (cfg.start && cfg.stop) {
		nvme_show_error("Must select one of start & stop, not both");
		return -EINVAL;
	} else if (cfg.sel == NVME_LM_SEL_LOG_USER_DATA_CHANGES) {
		if (cfg.start)
			cfg.mos = NVME_SET(NVME_LM_LACT_START_LOGGING, LM_LACT);
		else if (cfg.stop)
			cfg.mos = NVME_SET(NVME_LM_LACT_STOP_LOGGING, LM_LACT);
	}

	struct nvme_lm_track_send_args args = {
		.args_size = sizeof(args),
		.cdqid = cfg.cdqid,
		.sel = cfg.sel,
		.mos = cfg.mos,
	};

	err = nvme_lm_track_send(hdl, &args);
	if (err < 0)
		nvme_show_error("ERROR: nvme_lm_track_send() failed %s", strerror(errno));
	else if (err)
		nvme_show_status(err);
	else
		printf("Track Send (%s) Successful\n",
		       ARGSTR(lm_track_send_select_argstr, cfg.sel));

	return err;
}

static const char * const lm_migration_send_select_argstr[] = {
	[NVME_LM_SEL_SUSPEND] = "Suspend",
	[NVME_LM_SEL_RESUME] = "Resume",
	[NVME_LM_SEL_SET_CONTROLLER_STATE] = "Set Controller State"
};

static int lm_migration_send(int argc, char **argv, struct command *command, struct plugin *plugin)
{
	const char *desc = "Migration Send command is used to manage the migration of a controller";
	const char *sel = "Select (SEL) the type of management operation to perform "
			   "(CDW10[07:00])\n"
			   "  0h = Suspend\n"
			   "  1h = Resume\n"
			   "  2h = Set Controller State";
	const char *cntlid = "Controller Identifier (CDW11[15:00])";
	const char *stype = "Type of suspend (STYPE) (CDW11[23:16]\n"
			    "  0h = Suspend Notification\n"
			    "  1h = Suspend";
	const char *dudmq = "Delete user data migration queue (DUDMQ) as part of suspend operation "
			     "(CDW11[31])";
	const char *seqind = "Sequence Indicator (CDW10[17:16])\n"
			     "  0h = Not first not last\n"
			     "  1h = First in two or more\n"
			     "  2h = Last in two or more\n"
			     "  3h = Entire state info";
	const char *csuuidi = "Controller State UUID Index (CSUUIDI) (CDW11[31:24])";
	const char *csvi = "Controller State Version Index (CSVI) (CDW11[23:16])";
	const char *uidx = "UUID Index (UIDX) (CDW14[16:00])";
	const char *offset = "Controller State Offset";
	const char *numd = "Number of Dwords (NUMD)";
	const char *input = "Controller State Data input file";

	_cleanup_nvme_global_ctx_ struct nvme_global_ctx *ctx = NULL;
	_cleanup_nvme_transport_handle_ struct nvme_transport_handle *hdl = NULL;
	_cleanup_file_ FILE *file = NULL;
	_cleanup_huge_ struct nvme_mem_huge mh = { 0, };
	void *data = NULL;
	int err = -1;

	struct config {
		__s8 sel;
		__u16 cntlid;
		__u8 stype;
		__u8 seqind;
		__u8 csuuidi;
		__u8 csvi;
		__u8 uidx;
		__u64 offset;
		__u32 numd;
		char  *input;
		bool  dudmq;
	};

	struct config cfg = {
		.sel = -1,
		.cntlid = 0,
		.stype = 0,
		.seqind = 0,
		.csuuidi = 0,
		.csvi = 0,
		.uidx = 0,
		.offset = 0,
		.numd = 0,
		.input = NULL,
		.dudmq = false
	};

	OPT_ARGS(opts) = {
		OPT_BYTE("sel",		's', &cfg.sel, sel),
		OPT_SHRT("cntlid",	'c', &cfg.cntlid, cntlid),
		OPT_BYTE("stype",	't', &cfg.stype, stype),
		OPT_FLAG("dudmq",	'd', &cfg.dudmq, dudmq),
		OPT_BYTE("seq-ind",	'S', &cfg.seqind, seqind),
		OPT_BYTE("csuuidi",	'U', &cfg.csuuidi, csuuidi),
		OPT_BYTE("csvi",	'V', &cfg.csvi, csvi),
		OPT_BYTE("uidx",	'u', &cfg.uidx, uidx),
		OPT_LONG("offset",	'o', &cfg.offset, offset),
		OPT_UINT("numd",	'n', &cfg.numd, numd),
		OPT_FILE("input-file",	'f', &cfg.input, input),
		OPT_END()
	};

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	if (cfg.sel == -1) {
		nvme_show_error("Select field required");
		return -EINVAL;
	}

	// Sanity check input parameters
	if (cfg.sel == NVME_LM_SEL_SUSPEND || cfg.sel == NVME_LM_SEL_RESUME) {
		if (cfg.csuuidi != 0 || cfg.csvi != 0) {
			nvme_show_error("Unexpected fields for %s",
					ARGSTR(lm_migration_send_select_argstr, cfg.sel));
			return -EINVAL;
		}
	} else if (cfg.sel == NVME_LM_SEL_SET_CONTROLLER_STATE) {
		if (cfg.dudmq || cfg.stype != 0) {
			nvme_show_error("Unexpected fields for %s",
					ARGSTR(lm_migration_send_select_argstr, cfg.sel));
			return -EINVAL;
		} else if (!strlen(cfg.input)) {
			nvme_show_error("Expected file for %s",
					ARGSTR(lm_migration_send_select_argstr, cfg.sel));
			return -EINVAL;
		}
	}

	if (cfg.input && strlen(cfg.input)) {
		file = fopen(cfg.input, "r");
		if (file == NULL) {
			nvme_show_perror(cfg.input);
			return -EINVAL;
		}

		data = nvme_alloc_huge(cfg.numd << 2, &mh);
		if (!data)
			return -ENOMEM;

		size_t n_data = fread(data, 1, cfg.numd << 2, file);

		fclose(file);

		if (n_data != (size_t)(cfg.numd << 2)) {
			nvme_show_error("failed to read controller state data %s", strerror(errno));
			return -errno;
		}
	}

	struct nvme_lm_migration_send_args args = {
		.args_size = sizeof(args),
		.sel = cfg.sel,
		.mos = NVME_SET(cfg.seqind, LM_SEQIND),
		.cntlid = cfg.cntlid,
		.csuuidi = cfg.csuuidi,
		.uidx = cfg.uidx,
		.stype = cfg.stype,
		.offset = cfg.offset,
		.dudmq = cfg.dudmq,
		.numd = cfg.numd,
		.data = data,
	};

	err = nvme_lm_migration_send(hdl, &args);
	if (err < 0)
		nvme_show_error("ERROR: nvme_lm_migration_send() failed %s", strerror(errno));
	else if (err > 0)
		nvme_show_status(err);
	else
		printf("Migration Send (%s) Successful\n",
		       ARGSTR(lm_migration_send_select_argstr, cfg.sel));


	return err;
}

static int lm_migration_recv(int argc, char **argv, struct command *command, struct plugin *plugin)
{
	const char *desc = "Migration Receive command is used to obtain information used to manage "
			   " a migratable controller";
	const char *sel = "Select (SEL) the type of management operation to perform "
			   "(CDW10[07:00])\n"
			   "  0h = Get Controller State";
	const char *cntlid = "Controller Identifier (CDW10[31:16])";
	const char *csuuidi = "Controller State UUID Index (CSUUIDI) (CDW11[23:16])";
	const char *csvi = "Controller State Version Index (CSVI) (CDW11[7:0])";
	const char *uidx = "UUID Index (UIDX) (CDW14[16:00])";
	const char *offset = "Controller State Offset";
	const char *numd = "Number of Dwords (NUMD)";
	const char *output = "Controller State Data output file";
	const char *human_readable_info = "show info in readable format";

	_cleanup_nvme_global_ctx_ struct nvme_global_ctx *ctx = NULL;
	_cleanup_nvme_transport_handle_ struct nvme_transport_handle *hdl = NULL;
	_cleanup_file_ FILE *fd = NULL;
	_cleanup_huge_ struct nvme_mem_huge mh = { 0, };
	nvme_print_flags_t flags;
	void *data = NULL;
	int err = -1;

	struct config {
		__u8 sel;
		__u16 cntlid;
		__u8  csuuidi;
		__u8  csvi;
		__u8  uidx;
		__u64 offset;
		__u32 numd;
		char  *output;
		char  *output_format;
		bool  human_readable;
	};

	struct config cfg = {
		.sel = -1,
		.cntlid = 0,
		.csuuidi = 0,
		.csvi = 0,
		.uidx = 0,
		.offset = 0,
		.numd = 0,
		.output = NULL,
		.output_format = "normal",
		.human_readable = false
	};

	OPT_ARGS(opts) = {
		OPT_BYTE("sel",			's', &cfg.sel, sel),
		OPT_SHRT("cntlid",		'c', &cfg.cntlid, cntlid),
		OPT_BYTE("csuuidi",		'U', &cfg.csuuidi, csuuidi),
		OPT_BYTE("csvi",		'V', &cfg.csvi, csvi),
		OPT_BYTE("uidx",		'u', &cfg.uidx, uidx),
		OPT_LONG("offset",		'o', &cfg.offset, offset),
		OPT_UINT("numd",		'n', &cfg.numd, numd),
		OPT_FILE("output-file",		'f', &cfg.output, output),
		OPT_FMT("output-format",	  0,   &cfg.output_format, output_format),
		OPT_FLAG("human-readable",	'H', &cfg.human_readable, human_readable_info),
		OPT_END()
	};

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	err = validate_output_format(cfg.output_format, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	if (cfg.output_format && cfg.offset != 0 && !(flags & BINARY)) {
		nvme_show_error("cannot parse non-zero offset");
		return -EINVAL;
	}

	if (cfg.human_readable)
		flags |= VERBOSE;

	if (cfg.output && strlen(cfg.output)) {
		fd = fopen(cfg.output, "w");
		if (fd < 0) {
			nvme_show_perror(cfg.output);
			return -errno;
		}
	}

	data = nvme_alloc_huge((cfg.numd + 1) << 2, &mh);
	if (!data)
		return -ENOMEM;

	__u32 result = 0;
	struct nvme_lm_migration_recv_args args = {
		.args_size = sizeof(args),
		.sel = cfg.sel,
		.mos = NVME_SET(cfg.csvi, LM_GET_CONTROLLER_STATE_CSVI),
		.uidx = cfg.uidx,
		.csuuidi = cfg.csuuidi,
		.offset = cfg.offset,
		.cntlid = cfg.cntlid,
		.numd = cfg.numd,
		.data = data,
		.result = &result,
	};

	err = nvme_lm_migration_recv(hdl, &args);
	if (err < 0)
		nvme_show_error("ERROR: nvme_lm_migration_recv() failed %s", strerror(errno));
	else if (err)
		nvme_show_status(err);
	else if (cfg.sel == NVME_LM_SEL_GET_CONTROLLER_STATE) {
		if (flags == NORMAL)
			printf("CDW0: 0x%x: Controller %sSuspended\n", result,
			       (result & NVME_LM_GET_CONTROLLER_STATE_CSUP) ? "" : "NOT ");

		if (cfg.output && strlen(cfg.output)) {
			if (fwrite(data, 1, cfg.numd << 2, fd) != (cfg.numd << 2)) {
				nvme_show_error("ERROR: %s: failed to write buffer to output file",
						strerror(errno));
				err = -errno;
			}
		} else {
			lm_show_controller_state_data((struct nvme_lm_controller_state_data *)data,
						      (cfg.numd + 1) << 2, cfg.offset, flags);
		}
	}

	return 0;
}

enum lm_controller_data_queue_feature_id {
	lm_cdq_feature_id = 0x21
};

static int lm_set_cdq(int argc, char **argv, struct command *command, struct plugin *plugin)
{
	const char *desc = "This Feature allows a host to update the status of the head pointer "
			   "of a CDQ and specify the configuration of a CDQ Tail event.";
	const char *cdqid = "Controller Data Queue ID";
	const char *hp = "The slot of the head pointer for the specified CDQ";
	const char *tpt = "If specified, the slot that causes the controller "
			  " to issue a CDQ Tail Pointer event";

	_cleanup_nvme_global_ctx_ struct nvme_global_ctx *ctx = NULL;
	_cleanup_nvme_transport_handle_ struct nvme_transport_handle *hdl = NULL;
	int err = -1;

	struct config {
		__u16 cdqid;
		__u32 hp;
		__s32 tpt;
	};

	struct config cfg = {
		.cdqid = 0,
		.hp = 0,
		.tpt = -1,
	};

	OPT_ARGS(opts) = {
		OPT_SHRT("cdqid",	'C', &cfg.cdqid, cdqid),
		OPT_UINT("hp",		'H', &cfg.hp, hp),
		OPT_UINT("tpt",		'T', &cfg.tpt, tpt),
		OPT_END()
	};

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	struct nvme_set_features_args args = {
		.args_size	= sizeof(args),
		.fid		= lm_cdq_feature_id,
		.cdw11		= cfg.cdqid |
				  ((cfg.tpt >= 0) ? NVME_SET(1, LM_CTRL_DATA_QUEUE_ETPT) : 0),
		.cdw12		= cfg.hp,
		.cdw13		= cfg.tpt
	};

	err = nvme_set_features(hdl, &args);
	if (err < 0)
		nvme_show_error("ERROR: nvme_set_features() failed %s", nvme_strerror(errno));
	else if (err)
		nvme_show_status(err);
	else
		printf("Success. Head Pointer: %d\n", cfg.hp);

	return err;
}

static int lm_get_cdq(int argc, char **argv, struct command *command, struct plugin *plugin)
{
	const char *desc = "This Feature allows a host to retrieve the status of the head pointer "
			   "of a CDQ and specify the configuration of a CDQ Tail event.";
	const char *cdqid = "Controller Data Queue ID";

	_cleanup_nvme_global_ctx_ struct nvme_global_ctx *ctx = NULL;
	_cleanup_nvme_transport_handle_ struct nvme_transport_handle *hdl = NULL;
	nvme_print_flags_t flags;
	int err = -1;

	struct config {
		__u16 cdqid;
		char *output_format;
	};

	struct config cfg = {
		.cdqid = 0,
		.output_format  = "normal",
	};

	OPT_ARGS(opts) = {
		OPT_SHRT("cdqid",	 'C', &cfg.cdqid,	  cdqid),
		OPT_FMT("output-format", 'o', &cfg.output_format, output_format),
		OPT_END()
	};

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	err = validate_output_format(cfg.output_format, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	struct nvme_lm_ctrl_data_queue_fid_data data;

	struct nvme_get_features_args args = {
		.args_size	= sizeof(args),
		.fid		= lm_cdq_feature_id,
		.cdw11		= cfg.cdqid,
		.data		= &data,
		.data_len	= sizeof(data)
	};

	err = nvme_get_features(hdl, &args);
	if (err < 0)
		nvme_show_error("ERROR: nvme_get_features() failed %s", nvme_strerror(errno));
	else if (err)
		nvme_show_status(err);
	else
		lm_show_controller_data_queue(&data, flags);

	return err;
}
