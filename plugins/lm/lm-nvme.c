/* SPDX-License-Identifier: GPL-2.0-or-later */
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
#include "libnvme.h"
#include "plugin.h"
#include "linux/types.h"
#include "nvme-wrap.h"
#include "nvme-print.h"
#include "util/cleanup.h"

#define CREATE_CMD
#include "lm-nvme.h"

static inline const char *arg_str(const char * const *strings,
		size_t array_size, size_t idx)
{
	if (idx < array_size && strings[idx])
		return strings[idx];
	return "unrecognized";
}

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))
#define ARGSTR(s, i) arg_str(s, ARRAY_SIZE(s), i)

// LBA Migration Queue Entry Type 0
struct lba_migration_queue_entry_type_0 {
	__u32 nsid;	// Namespace Identifier (NSID)
	__u32 nlb;	// Number of Logical Blocks (NLB)
	__u64 slba;	// Starting LBA (SLBA)
	__u8  rsvd16[15];
	struct {
		__u8 cdqp	: 1; // Controller Data Queue Phase Tag (CDQP)
		__u8 esa	: 3; // Entry Sequence Attribute (ESA)
		__u8 rsvd	: 1;
		__u8 dlba	: 1; // Deallocated LBAs (DLBA)
		__u8 lbacir	: 2; // LBA Change Information Attribute (LBACIR)
	};
};

// LBA Change Information Attribute (LBACIR): This field indicates attributes associated
// with the reporting of the LBA range in this entry.
enum lba_change_information_attr {
	LBA_RANGE_VALID                     = 0b00,
	ALL_LOGICAL_BLOCKS                  = 0b01,
	NO_RANGE_REPORTED                   = 0b10,
};

enum lm_nvme_admin_opcode {
	NVME_ADMIN_TRACK_SEND			= 0x3D,
	NVME_ADMIN_TRACK_RECEIVE		= 0x3E,
	NVME_ADMIN_MIGRATION_SEND		= 0x41,
	NVME_ADMIN_MIGRATION_RECEIVE		= 0x42,
	NVME_ADMIN_CONTROLLER_DATA_QUEUE	= 0x45
};

enum lm_cdq_select {
	CREATE_CONTROLLER_DATA_QUEUE = 0,
	DELETE_CONTROLLER_DATA_QUEUE = 1
};

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
	_cleanup_nvme_dev_ struct nvme_dev *dev = NULL;
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

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		return err;

	if (cfg.sz % (sizeof(struct lba_migration_queue_entry_type_0) >> 2)) {
		nvme_show_error("ERROR: Size must be dword multiple of queue entry size");
		return -EINVAL;
	}

	queue = nvme_alloc_huge(cfg.sz << 2, &mh);
	if (!queue) {
		nvme_show_error("ERROR: nvme_alloc of size %dB failed %s", cfg.sz << 2, strerror(errno));
		return -ENOMEM;
	}

	struct nvme_passthru_cmd cmd = {
		.opcode = NVME_ADMIN_CONTROLLER_DATA_QUEUE,
		.cdw10 = ((cfg.qt) << 16) | CREATE_CONTROLLER_DATA_QUEUE,
		.cdw11 = ((cfg.cntlid) << 16) | 0x1,
		.cdw12 = cfg.sz,
		.addr =  (unsigned long long) queue,
		.data_len = cfg.sz << 2
	};

	err = nvme_submit_admin_passthru(dev_fd(dev), &cmd, NULL);
	if (!err)
		printf("Create CDQ Successful: CDQID=0x%04x\n", cmd.result & 0xFFFF);
	else if (err > 0)
		nvme_show_status(err);
	else
		nvme_show_error("ERROR: nvme_submit_admin_passthru() failed: %s", nvme_strerror(errno));

	return err;
}

static int lm_delete_cdq(int argc, char **argv, struct command *command, struct plugin *plugin)
{
	const char *desc = "Delete Controller Data Queue";
	const char *cdqid = "Controller Data Queue ID";

	_cleanup_nvme_dev_ struct nvme_dev *dev = NULL;
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

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		return err;

	struct nvme_passthru_cmd cmd = {
		.opcode = NVME_ADMIN_CONTROLLER_DATA_QUEUE,
		.cdw10 = DELETE_CONTROLLER_DATA_QUEUE,
		.cdw11 = cfg.cdqid
	};

	err = nvme_submit_admin_passthru(dev_fd(dev), &cmd, NULL);

	if (!err)
		printf("Delete CDQ Successful: CDQID=0x%04x\n", cfg.cdqid);
	else if (err > 0)
		nvme_show_status(err);
	else
		nvme_show_error("ERROR: nvme_submit_admin_passthru() failed: %s", nvme_strerror(errno));

	return err;
}

enum lm_track_send_select {
	TRACK_SEND_SELECT_LOG_USER_DATA_CHANGES	= 0,
	TRACK_SEND_SELECT_TRACK_MEMORY_CHANGES	= 1
};

static const char * const lm_track_send_select_argstr[] = {
	[TRACK_SEND_SELECT_LOG_USER_DATA_CHANGES] = "Log User Data Changes",
	[TRACK_SEND_SELECT_TRACK_MEMORY_CHANGES] = "Track Memory Changes"
};

enum lm_track_send_mos {
	TRACK_SEND_MANAGEMENT_OPERATION_STOP_LOGGING	= 0,
	TRACK_SEND_MANAGEMENT_OPERATION_START_LOGGING	= 1,
};

static int lm_track_send(int argc, char **argv, struct command *command, struct plugin *plugin)
{
	const char *desc = "Track Send command used to manage the tracking of information by a "
			   "controller";
	const char *select = "Type of management operation to perform\n"
				 "  0h = Log User Data Changes\n"
				 "  1h = Track Memory Changes";
	const char *mos = "Management operation specific";
	const char *start = "Equivalent to start tracking with defaults";
	const char *stop = "Equivalent to stop tracking with defaults";
	const char *cdqid = "Controller Data Queue ID";

	_cleanup_nvme_dev_ struct nvme_dev *dev = NULL;
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
		OPT_BYTE("select",    's', &cfg.sel,   select),
		OPT_BYTE("mos",       'm', &cfg.mos,   mos),
		OPT_SHRT("cdqid",     'C', &cfg.cdqid, cdqid),
		OPT_FLAG("start",      0,  &cfg.start, start),
		OPT_FLAG("stop",       0,  &cfg.stop,  stop),
		OPT_END()
	};

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		return err;

	if (cfg.sel == -1) {
		nvme_show_error("Select field required");
		return -EINVAL;
	}

	if (cfg.sel != TRACK_SEND_SELECT_LOG_USER_DATA_CHANGES) {
		nvme_show_error("Unsupported select option %d (%s)", cfg.sel,
				ARGSTR(lm_track_send_select_argstr, cfg.sel));
		return -EINVAL;
	}

	if (cfg.start && cfg.stop) {
		nvme_show_error("Must select one of start & stop, not both");
		return -EINVAL;
	} else if (cfg.sel == TRACK_SEND_SELECT_LOG_USER_DATA_CHANGES) {
		if (cfg.start)
			cfg.mos = TRACK_SEND_MANAGEMENT_OPERATION_START_LOGGING;
		else if (cfg.stop)
			cfg.mos = TRACK_SEND_MANAGEMENT_OPERATION_STOP_LOGGING;
	}

	struct nvme_passthru_cmd cmd = {
		.opcode = NVME_ADMIN_TRACK_SEND,
		.cdw10 = (cfg.sel) | (cfg.mos) << 16,
		.cdw11 = cfg.cdqid,
	};

	err = nvme_submit_admin_passthru(dev_fd(dev), &cmd, NULL);
	if (!err)
		printf("Track Send (%s) Successful\n",
		       ARGSTR(lm_track_send_select_argstr, cfg.sel));
	else if (err > 0)
		nvme_show_status(err);
	else
		nvme_show_error("ERROR: nvme_submit_admin_passthru() failed %s", strerror(errno));

	return err;
}

enum lm_migration_send_select {
	MIGRATION_SEND_SUSPEND			= 0,
	MIGRATION_SEND_RESUME			= 1,
	MIGRATION_SEND_SET_CONTROLLER_STATE	= 2
};

static const char * const lm_migration_send_select_argstr[] = {
	[MIGRATION_SEND_SUSPEND] = "Suspend",
	[MIGRATION_SEND_RESUME] = "Resume",
	[MIGRATION_SEND_SET_CONTROLLER_STATE] = "Set Controller State"
};

enum lm_migration_send_suspend_type {
	SUSPEND_NOTIFICATION	= 0,
	SUSPEND			= 1
};

static int lm_migration_send(int argc, char **argv, struct command *command, struct plugin *plugin)
{
	const char *desc = "Migration Send command is used to manage the migration of a controller";
	const char *select = "Select (SEL) the type of management operation to perform "
			     "(CDW10[07:00])\n"
			     "  0h = Suspend\n"
			     "  1h = Resume\n"
			     "  2h = Set Controller State";
	const char *cntlid = "Controller Identifier (CDW11[15:00])";
	const char *stype = "Type of suspend/pause (PTYPE) (CDW11[23:16]\n"
			    "  0h = Suspend Notification\n"
			    "  1h = Suspend";
	const char *delete = "Delete user data migration queue as part of suspend operation "
			     "(CDW11[31])";
	const char *seqind = "Sequence Indicator (CDW11[17:16])\n"
			     "  0h = Not first not last\n"
			     "  1h = First in two or more\n"
			     "  2h = Last in two or more\n"
			     "  3h = Entire state info";
	const char *csuuidi = "Controller State UUID Index (CSUUIDI) (CDW11[31:24])";
	const char *csvi = "Controller State Version Index (CSVI) (CDW11[23:16])";
	const char *offset = "Controller State Offset";
	const char *numd = "Number of Dwords (NUMD)";
	const char *input = "Controller State Data input file";

	_cleanup_nvme_dev_ struct nvme_dev *dev = NULL;
	_cleanup_file_ FILE *file = NULL;
	_cleanup_huge_ struct nvme_mem_huge mh = { 0, };
	void *data = NULL;
	int err = -1;

	struct config {
		__s8 sel;
		__u8 stype;
		__u8 seqind;
		__u8 csuuidi;
		__u8 csvi;
		__u16 cntlid;
		__u64 offset;
		__u32 numd;
		char  *input;
		bool  delete;
	};

	struct config cfg = {
		.sel = -1,
		.stype = 0,
		.seqind = 0,
		.csuuidi = 0,
		.csvi = 0,
		.cntlid = 0,
		.offset = 0,
		.numd = 0,
		.input = NULL,
		.delete = false
	};

	OPT_ARGS(opts) = {
		OPT_BYTE("select",		's', &cfg.sel, select),
		OPT_SHRT("cntlid",		'c', &cfg.cntlid, cntlid),
		OPT_BYTE("suspend-type",	't', &cfg.stype, stype),
		OPT_FLAG("delete",		'd',   &cfg.delete, delete),
		OPT_BYTE("seq-ind",		'S', &cfg.seqind, seqind),
		OPT_BYTE("uuid-index",		'U', &cfg.csuuidi, csuuidi),
		OPT_BYTE("version-index",	'V', &cfg.csvi, csvi),
		OPT_LONG("offset",		'o', &cfg.offset, offset),
		OPT_UINT("numd",		'n', &cfg.numd, numd),
		OPT_FILE("input-file",		'f', &cfg.input, input),
		OPT_END()
	};

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		return err;

	if (cfg.sel == -1) {
		nvme_show_error("Select field required");
		return -EINVAL;
	}

	// Sanity check input parameters
	if (cfg.sel == MIGRATION_SEND_SUSPEND || cfg.sel == MIGRATION_SEND_RESUME) {
		if (cfg.csuuidi != 0 || cfg.csvi != 0) {
			nvme_show_error("Unexpected fields for %s",
					ARGSTR(lm_migration_send_select_argstr, cfg.sel));
			return -EINVAL;
		}
	} else if (cfg.sel == MIGRATION_SEND_SET_CONTROLLER_STATE) {
		if (cfg.delete || cfg.stype != 0) {
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

	struct nvme_passthru_cmd cmd = {
		.opcode = NVME_ADMIN_MIGRATION_SEND,
		.cdw10 = (cfg.seqind << 16) | cfg.sel,
		.cdw11 = (cfg.sel == MIGRATION_SEND_SET_CONTROLLER_STATE) ?
			 (cfg.csuuidi << 24) | (cfg.csvi << 16) | (cfg.cntlid) :
			 (cfg.delete << 31) | (cfg.stype << 16) | (cfg.cntlid),
		.cdw12 = (__u32)(cfg.offset),
		.cdw13 = (__u32)(cfg.offset >> 32),
		.cdw15 = cfg.numd,
		.addr =  (unsigned long long)data,
		.data_len = cfg.numd << 2
	};

	err = nvme_submit_admin_passthru(dev_fd(dev), &cmd, NULL);
	if (!err)
		printf("Migration Send (%s) Successful\n",
		       ARGSTR(lm_migration_send_select_argstr, cfg.sel));
	else if (err > 0)
		nvme_show_status(err);
	else
		nvme_show_error("ERROR: nvme_submit_admin_passthru() failed %s", strerror(errno));

	return err;
}


struct nvme_io_submission_queue_data {
	__u64 prp1;
	__u16 qsize;
	__u16 qid;
	__u16 cqid;
	__u16 attrs;
	__u16 hp;
	__u16 tp;
	__u8  rsvd[4];
};
static_assert(sizeof(struct nvme_io_submission_queue_data) == 24,
	      "Size mismatch for struct nvme_io_submission_queue_data");

struct nvme_io_completion_queue_data {
	__u64 prp1;
	__u16 qsize;
	__u16 qid;
	__u16 hp;
	__u16 tp;
	__u32 attrs;
	__u8  rsvd[4];
};
static_assert(sizeof(struct nvme_io_completion_queue_data) == 24,
	      "Size mismatch for struct nvme_io_completion_queue_data");

struct nvme_controller_state_header {
	__u16 ver;
	__u16 niosq;
	__u16 niocq;
	__u16 rsvd;
};
static_assert(sizeof(struct nvme_controller_state_header) == 8,
	      "Size mismatch for struct nvme_controller_state_header");

struct nvme_controller_state_data {
	struct nvme_controller_state_header hdr;
	union {
		struct nvme_io_submission_queue_data sq[0];
		struct nvme_io_completion_queue_data cq[0];
	};
};

struct controller_state_data_header {
	__u16 ver;
	__u8  csattr;
	__u8  rsvd3[13];
	__u8  nvmecss[16];
	__u8  vss[16];
};
static_assert(sizeof(struct controller_state_data_header) == 48,
	      "Size mismatch for struct controller_state_data_header");

struct controller_state_data {
	struct controller_state_data_header hdr;
	struct nvme_controller_state_data   sdata;
};

static void json_controller_state_data(struct controller_state_data *data, size_t len)
{
	struct json_object *root = json_create_object();
	struct json_object *nvmecs = json_create_object();
	struct json_object *iosqs = json_create_array();
	struct json_object *iocqs = json_create_array();

	json_object_add_value_uint(root, "version",
				   le16_to_cpu(data->hdr.ver));
	json_object_add_value_uint(root, "controller state attributes",
				   data->hdr.csattr);
	json_object_add_value_uint128(root, "nvme controller state size",
				      le128_to_cpu(data->hdr.nvmecss));
	json_object_add_value_uint128(root, "vendor specific size",
				      le128_to_cpu(data->hdr.vss));

	json_object_add_value_object(root, "nvme controller state", nvmecs);

	json_object_add_value_uint(nvmecs, "version",
				   le16_to_cpu(data->sdata.hdr.ver));
	json_object_add_value_uint(nvmecs, "number of io submission queues",
				   le16_to_cpu(data->sdata.hdr.niosq));
	json_object_add_value_uint(nvmecs, "number of io completion queues",
				   le16_to_cpu(data->sdata.hdr.niocq));

	json_object_add_value_array(nvmecs, "io submission queue list", iosqs);

	for (int i = 0; i < data->sdata.hdr.niosq; i++) {
		struct nvme_io_submission_queue_data *sq = &data->sdata.sq[i];
		struct json_object *sq_obj = json_create_object();

		json_object_add_value_uint64(sq_obj, "io submission prp entry 1",
					     le64_to_cpu(sq->prp1));
		json_object_add_value_uint(sq_obj, "io submission queue size",
					   le16_to_cpu(sq->qsize));
		json_object_add_value_uint(sq_obj, "io submission queue identifier",
					   le16_to_cpu(sq->qid));
		json_object_add_value_uint(sq_obj, "io completion queue identifier",
					   le16_to_cpu(sq->cqid));
		json_object_add_value_uint(sq_obj, "io submission queue attributes",
					   le16_to_cpu(sq->attrs));
		json_object_add_value_uint(sq_obj, "io submission queue head pointer",
					   le16_to_cpu(sq->hp));
		json_object_add_value_uint(sq_obj, "io submission queue tail pointer",
					   le16_to_cpu(sq->tp));

		json_array_add_value_object(iosqs, sq_obj);
	}

	json_object_add_value_array(nvmecs, "io completion queue list", iocqs);

	for (int i = 0; i < data->sdata.hdr.niocq; i++) {
		struct nvme_io_completion_queue_data *cq = &data->sdata.cq[i];
		struct json_object *cq_obj = json_create_object();

		json_object_add_value_uint64(cq_obj, "io completion prp entry 1",
					     le64_to_cpu(cq->prp1));
		json_object_add_value_uint(cq_obj, "io completion queue size",
					   le16_to_cpu(cq->qsize));
		json_object_add_value_uint(cq_obj, "io completion queue identifier",
					   le16_to_cpu(cq->qid));
		json_object_add_value_uint(cq_obj, "io completion queue head pointer",
					   le16_to_cpu(cq->hp));
		json_object_add_value_uint(cq_obj, "io completion queue tail pointer",
					   le16_to_cpu(cq->tp));
		json_object_add_value_uint(cq_obj, "io completion queue attributes",
					   le32_to_cpu(cq->attrs));

		json_array_add_value_object(iocqs, cq_obj);
	}

	json_print_object(root, NULL);
	printf("\n");
	json_free_object(root);
}

static void show_controller_state_data(struct controller_state_data *data, size_t len, __u32 offset,
				       enum nvme_print_flags flags)
{
	if (flags & BINARY)
		return d_raw((unsigned char *)data, len);

	if (offset) {
		nvme_show_error("Cannot parse non-zero offset");
		return;
	}

	if (flags & JSON)
		return json_controller_state_data(data, len);

	int human = flags & VERBOSE;

	if (sizeof(struct controller_state_data_header) <= len) {
		printf("Header:\n");
		printf("%-45s: 0x%x\n", "Version (VER)", data->hdr.ver);
		printf("%-45s: 0x%x\n", "Controller State Attributes (CSATTR)", data->hdr.csattr);
		if (human)
			printf("  [0:0] : 0x%x Controller %sSuspended\n",
				data->hdr.csattr & 1, data->hdr.csattr & 1 ? "" : "NOT ");
		printf("%-45s: %s\n", "NVMe Controller State Size (NVMECSS)",
		       uint128_t_to_string(le128_to_cpu(data->hdr.nvmecss)));
		printf("%-45s: %s\n", "Vendor Specific Size (VSS)",
		       uint128_t_to_string(le128_to_cpu(data->hdr.vss)));

		len -= sizeof(struct controller_state_data_header);
	} else {
		fprintf(stderr, "WARNING: Header truncated\n");
		len = 0;
	}

	if (!len)
		return;

	if (sizeof(struct nvme_controller_state_header) <= len) {
		int niosq = data->sdata.hdr.niosq;
		int niocq = data->sdata.hdr.niocq;

		printf("\nNVMe Controller State Data Structure:\n");
		printf("%-45s: 0x%x\n", "Version (VER)",
		       le16_to_cpu(data->sdata.hdr.ver));
		printf("%-45s: %d\n", "Number of I/O Submission Queues (NIOSQ)",
		       le16_to_cpu(niosq));
		printf("%-45s: %d\n", "Number of I/O Completion Queues (NIOCQ)",
		       le16_to_cpu(niocq));

		len -= sizeof(struct nvme_controller_state_header);

		if (len < niosq * sizeof(struct nvme_io_submission_queue_data)) {
			fprintf(stderr, "WARNING: I/O Submission Queues truncated\n");
			niosq = len / sizeof(struct nvme_io_submission_queue_data);
		}

		for (int i = 0; i < niosq; ++i) {
			struct nvme_io_submission_queue_data *sq = &(data->sdata.sq[i]);
			__u16 attrs = le16_to_cpu(sq->attrs);

			printf("\nNVMe I/O Submission Queue Data [%d]:\n", i);
			printf("%-45s: 0x%lx\n", "PRP Entry 1 (IOSQPRP1)",
			       le64_to_cpu(sq->prp1));
			printf("%-45s: 0x%x\n", "Queue Size (IOSQQSIZE)",
			       le16_to_cpu(sq->qsize));
			printf("%-45s: 0x%x\n", "Identifier (IOSQQID)",
			       le16_to_cpu(sq->qid));
			printf("%-45s: 0x%x\n", "Completion Queue Identifier (IOSQCQID)",
			       le16_to_cpu(sq->cqid));
			printf("%-45s: 0x%x\n", "Attributes (IOSQA)", attrs);
			if (human) {
				printf("  [2:1] : 0x%x Queue Priority (IOSQQPRIO)\n",
					(attrs & 0x6) >> 1);
				printf("  [0:0] : 0x%x Queue %sPhysically Contiguous (IOSQPC)\n",
					attrs & 1, attrs & 1 ? "" : "NOT ");
			}
			printf("%-45s: 0x%x\n", "I/O Submission Queue Head Pointer (IOSQHP)",
			       le16_to_cpu(sq->hp));
			printf("%-45s: 0x%x\n", "I/O Submission Queue Tail Pointer (IOSQTP)",
			       le16_to_cpu(sq->tp));
		}

		len -= niosq * sizeof(struct nvme_io_submission_queue_data);

		if (len < niocq * sizeof(struct nvme_io_completion_queue_data)) {
			fprintf(stderr, "WARNING: I/O Completion Queues truncated\n");
			niocq = len / sizeof(struct nvme_io_completion_queue_data);
		}

		for (int i = 0; i < niocq; ++i) {
			struct nvme_io_completion_queue_data *cq = &data->sdata.cq[niosq + i];
			__u32 attrs = le32_to_cpu(cq->attrs);

			printf("\nNVMe I/O Completion Queue Data [%d]:\n", i);
			printf("%-45s: 0x%lx\n", "I/O Completion PRP Entry 1 (IOCQPRP1)",
			       le64_to_cpu(cq->prp1));
			printf("%-45s: 0x%x\n", "I/O Completion Queue Size (IOCQQSIZE)",
			       le16_to_cpu(cq->qsize));
			printf("%-45s: 0x%x\n", "I/O Completion Queue Identifier",
			       le16_to_cpu(cq->qid));
			printf("%-45s: 0x%x\n", "I/O Completion Queue Head Pointer (IOSQHP)",
			       le16_to_cpu(cq->hp));
			printf("%-45s: 0x%x\n", "I/O Completion Queue Tail Pointer (IOSQTP)",
			       le16_to_cpu(cq->tp));
			printf("%-45s: 0x%x\n", "I/O Completion Queue Attributes (IOCQA)", attrs);
			if (human) {
				printf("  [31:16] : 0x%x I/O Completion Queue Interrupt Vector "
				       "(IOCQIV)\n",
				       attrs >> 16);
				printf("  [2:2] : 0x%x Slot 0 Phase Tag\n",
				       (attrs >> 2) & 1);
				printf("  [1:1] : 0x%x Interrupts %sEnabled (IOCQIEN)\n",
				       (attrs >> 1) & 1, attrs & 0x2 ? "" : "NOT ");
				printf("  [0:0] : 0x%x Queue %sPhysically Contiguous (IOCQPC)\n",
				       (attrs >> 0) & 1, attrs & 0x1 ? "" : "NOT ");
			}
		}
	} else
		fprintf(stderr, "WARNING: NVMe Controller State Data Structure truncated\n");
}

enum lm_migration_recv_select {
	MIGRATION_RECV_GET_CONTROLLER_STATE = 0,
};

static int lm_migration_recv(int argc, char **argv, struct command *command, struct plugin *plugin)
{
	const char *desc = "Migration Receive command is used to obtain information used to manage "
			   " a migratable controller";
	const char *cntlid = "Controller Identifier (CDW10[31:16])";
	const char *csuuidi = "Controller State UUID Index (CSUUIDI) (CDW11[23:16])";
	const char *csvi = "Controller State Version Index (CSVI) (CDW11[7:0])";
	const char *offset = "Controller State Offset";
	const char *numd = "Number of Dwords (NUMD)";
	const char *output = "Controller State Data output file";
	const char *human_readable_info = "show info in readable format";

	_cleanup_nvme_dev_ struct nvme_dev *dev = NULL;
	_cleanup_file_ FILE *fd = NULL;
	_cleanup_huge_ struct nvme_mem_huge mh = { 0, };
	enum nvme_print_flags flags;
	void *data = NULL;
	int err = -1;

	struct config {
		__u16 cntlid;
		__u8  csuuidi;
		__u8  csvi;
		__u64 offset;
		__u32 numd;
		char  *output;
		char  *output_format;
		bool  human_readable;
	};

	struct config cfg = {
		.cntlid = 0,
		.csuuidi = 0,
		.csvi = 0,
		.offset = 0,
		.numd = 0,
		.output = NULL,
		.output_format = "normal",
		.human_readable = false
	};

	OPT_ARGS(opts) = {
		OPT_SHRT("cntlid",		'c', &cfg.cntlid, cntlid),
		OPT_BYTE("uuid-index",		'U', &cfg.csuuidi, csuuidi),
		OPT_BYTE("version-index",	'V', &cfg.csvi, csvi),
		OPT_LONG("offset",		'o', &cfg.offset, offset),
		OPT_UINT("numd",		'n', &cfg.numd, numd),
		OPT_FILE("output-file",		'f', &cfg.output, output),
		OPT_FMT("output-format",	0,   &cfg.output_format, output_format),
		OPT_FLAG("human-readable",	'H', &cfg.human_readable, human_readable_info),
		OPT_END()
	};

	err = parse_and_open(&dev, argc, argv, desc, opts);
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

	struct nvme_passthru_cmd cmd = {
		.opcode =   NVME_ADMIN_MIGRATION_RECEIVE,
		.cdw10 =    (cfg.csvi << 16) | MIGRATION_RECV_GET_CONTROLLER_STATE,
		.cdw11 =    (cfg.csuuidi << 16) | cfg.cntlid,
		.cdw12 =    (__u32)(cfg.offset),
		.cdw13 =    (__u32)(cfg.offset >> 32),
		.cdw15 =    (cfg.numd),
		.addr =	    (unsigned long long) data,
		.data_len = (cfg.numd + 1) << 2
	};

	err = nvme_submit_admin_passthru(dev_fd(dev), &cmd, NULL);
	if (err < 0)
		nvme_show_error("ERROR: nvme_submit_admin_passthru() failed %s",
				nvme_strerror(errno));
	else if (err)
		nvme_show_status(err);
	else {
		if (flags == NORMAL)
			printf("CDW0: 0x%x: Controller %sSuspended\n", cmd.result,
			       (cmd.result & 0x1) == 0x1 ? "" : "NOT ");

		if (cfg.output && strlen(cfg.output)) {
			if (fwrite(data, 1, cfg.numd << 2, fd) != (cfg.numd << 2)) {
				nvme_show_error("ERROR: %s: failed to write buffer to output file",
						strerror(errno));
				err = -errno;
			}
		} else {
			show_controller_state_data((struct controller_state_data *)data,
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

	_cleanup_nvme_dev_ struct nvme_dev *dev = NULL;
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

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		return err;

	struct nvme_set_features_args args = {
		.args_size	= sizeof(args),
		.fd		= dev_fd(dev),
		.fid		= lm_cdq_feature_id,
		.cdw11		= cfg.cdqid | ((cfg.tpt >= 0) ? (1 << 31) : 0),
		.cdw12		= cfg.hp,
		.cdw13		= cfg.tpt
	};

	err = nvme_set_features(&args);
	if (!err)
		printf("Success. Head Pointer: %d\n", cfg.hp);
	else if (err > 0)
		nvme_show_status(err);
	else
		nvme_show_error("ERROR: nvme_set_features() failed %s", nvme_strerror(errno));

	return err;
}

struct controller_data_queue_fid_data {
	__u32 hp;
	__u32 tpt;
	__u8  rsvd8[504];
};

static void json_lm_controller_data_queue(struct controller_data_queue_fid_data *data)
{
	struct json_object *root = json_create_object();

	json_object_add_value_uint(root, "head_pointer", le32_to_cpu(data->hp));
	json_object_add_value_uint(root, "tail_pointer_trigger", le32_to_cpu(data->tpt));

	json_print_object(root, NULL);
	printf("\n");
	json_free_object(root);
}

static void lm_show_controller_data_queue(struct controller_data_queue_fid_data *data,
					  enum nvme_print_flags flags)
{
	if (flags & JSON)
		return json_lm_controller_data_queue(data);

	if (flags & BINARY)
		return d_raw((unsigned char *)data, sizeof(struct controller_data_queue_fid_data));

	printf("Head Pointer: 0x%x\n", le32_to_cpu(data->hp));
	printf("Tail Pointer Trigger: 0x%x\n", le32_to_cpu(data->tpt));
}

static int lm_get_cdq(int argc, char **argv, struct command *command, struct plugin *plugin)
{
	const char *desc = "This Feature allows a host to retrieve the status of the head pointer "
			   "of a CDQ and specify the configuration of a CDQ Tail event.";
	const char *cdqid = "Controller Data Queue ID";

	_cleanup_nvme_dev_ struct nvme_dev *dev = NULL;
	enum nvme_print_flags flags;
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

	err = parse_and_open(&dev, argc, argv, desc, opts);
	if (err)
		return err;

	err = validate_output_format(cfg.output_format, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	struct controller_data_queue_fid_data data;

	struct nvme_get_features_args args = {
		.args_size	= sizeof(args),
		.fd		= dev_fd(dev),
		.fid		= lm_cdq_feature_id,
		.cdw11		= cfg.cdqid,
		.data		= &data,
		.data_len	= sizeof(data)
	};

	err = nvme_get_features(&args);
	if (!err)
		lm_show_controller_data_queue(&data, flags);
	else if (err > 0)
		nvme_show_status(err);
	else
		nvme_show_error("ERROR: nvme_get_features() failed %s", nvme_strerror(errno));

	return err;
}