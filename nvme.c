// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * NVM-Express command line utility.
 *
 * Copyright (c) 2014-2015, Intel Corporation.
 *
 * Written by Keith Busch <kbusch@kernel.org>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

/**
 * This program uses NVMe IOCTLs to run native nvme commands to a device.
 */
#include "config.h"
#include "nvme/tree.h"
#include "nvme/types.h"
#include "util/cleanup.h"
#include <errno.h>
#include <getopt.h>
#include <fcntl.h>
#include <inttypes.h>
#include <locale.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <math.h>
#include <dirent.h>
#include <libgen.h>
#include <signal.h>

#include <linux/fs.h>

#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>

#if HAVE_SYS_RANDOM
	#include <sys/random.h>
#endif

#include <libnvme.h>

#include "common.h"
#include "nvme.h"
#include "nvme-print.h"
#include "plugin.h"
#include "util/base64.h"
#include "util/crc32.h"
#include "util/argconfig.h"
#include "util/suffix.h"
#include "logging.h"
#include "util/sighdl.h"
#include "fabrics.h"
#define CREATE_CMD
#include "nvme-builtin.h"
#include "malloc.h"

struct feat_cfg {
	__u8 feature_id;   /* enum nvme_features_id */
	__u8 sel;          /* enum nvme_get_features_sel */
	__u32 namespace_id;
	__u32 cdw11;
	__u32 cdw12;
	__u8 uuid_index;
	__u32 data_len;
	bool raw_binary;
	bool human_readable;
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
	bool human_readable;
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

static const char nvme_version_string[] = NVME_VERSION;

static struct plugin builtin = {
	.commands = commands,
	.name = NULL,
	.desc = NULL,
	.next = NULL,
	.tail = &builtin,
};

static struct program nvme = {
	.name = "nvme",
	.version = nvme_version_string,
	.usage = "<command> [<device>] [<args>]",
	.desc = "The '<device>' may be either an NVMe character "
		"device (ex: /dev/nvme0), an nvme block device "
		"(ex: /dev/nvme0n1), or a mctp address in the form "
		"mctp:<net>,<eid>[:ctrl-id]",
	.extensions = &builtin,
};

#ifdef CONFIG_JSONC
const char *output_format = "Output format: normal|json|binary";
#else /* CONFIG_JSONC */
const char *output_format = "Output format: normal|binary";
#endif /* CONFIG_JSONC */
const char *timeout = "timeout value, in milliseconds";
const char *verbose = "Increase output verbosity";
const char *dry_run = "show command instead of sending";

static const char *app_tag = "app tag for end-to-end PI";
static const char *app_tag_mask = "app tag mask for end-to-end PI";
static const char *block_count = "number of blocks (zeroes based) on device to access";
static const char *crkey = "current reservation key";
static const char *csi = "command set identifier";
static const char *buf_len = "buffer len (if) data is sent or received";
static const char *deprecated = "deprecated; does nothing";
static const char *domainid = "Domain Identifier";
static const char *doper = "directive operation";
static const char *dspec_w_dtype = "directive specification associated with directive type";
static const char *dtype = "directive type";
static const char *endgid = "Endurance Group Identifier (ENDGID)";
static const char *force_unit_access = "force device to commit data before command completes";
static const char *human_readable_directive = "show directive in readable format";
static const char *human_readable_identify = "show identify in readable format";
static const char *human_readable_info = "show info in readable format";
static const char *human_readable_log = "show log in readable format";
static const char *iekey = "ignore existing res. key";
static const char *latency = "output latency statistics";
static const char *lba_format_index = "The index into the LBA Format list\n"
	"identifying the LBA Format capabilities that are to be returned";
static const char *limited_retry = "limit media access attempts";
static const char *lsp = "log specific field";
static const char *mos = "management operation specific";
static const char *mo = "management operation";
static const char *namespace_desired = "desired namespace";
static const char *namespace_id_desired = "identifier of desired namespace";
static const char *namespace_id_optional = "optional namespace attached to controller";
static const char *nssf = "NVMe Security Specific Field";
static const char *prinfo = "PI and check field";
static const char *rae = "Retain an Asynchronous Event";
static const char *raw_directive = "show directive in binary format";
static const char *raw_dump = "dump output in binary format";
static const char *raw_identify = "show identify in binary format";
static const char *raw_log = "show log in binary format";
static const char *raw_output = "output in binary format";
static const char *ref_tag = "reference tag for end-to-end PI";
static const char *raw_use = "use binary output";
static const char *rtype = "reservation type";
static const char *secp = "security protocol (cf. SPC-4)";
static const char *spsp = "security-protocol-specific (cf. SPC-4)";
static const char *start_block = "64-bit LBA of first block to access";
static const char *storage_tag = "storage tag for end-to-end PI";
static const char *uuid_index = "UUID index";
static const char *uuid_index_specify = "specify uuid index";
static const char dash[51] = {[0 ... 49] = '=', '\0'};
static const char space[51] = {[0 ... 49] = ' ', '\0'};
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

struct nvme_config nvme_cfg = {
	.output_format = "normal",
	.output_format_ver = 1,
	.timeout = NVME_DEFAULT_IOCTL_TIMEOUT,
};

static void *mmap_registers(struct nvme_transport_handle *hdl, bool writable);

static OPT_VALS(feature_name) = {
	VAL_BYTE("arbitration", NVME_FEAT_FID_ARBITRATION),
	VAL_BYTE("power-mgmt", NVME_FEAT_FID_POWER_MGMT),
	VAL_BYTE("lba-range", NVME_FEAT_FID_LBA_RANGE),
	VAL_BYTE("temp-thresh", NVME_FEAT_FID_TEMP_THRESH),
	VAL_BYTE("err-recovery", NVME_FEAT_FID_ERR_RECOVERY),
	VAL_BYTE("volatile-wc", NVME_FEAT_FID_VOLATILE_WC),
	VAL_BYTE("num-queues", NVME_FEAT_FID_NUM_QUEUES),
	VAL_BYTE("irq-coalesce", NVME_FEAT_FID_IRQ_COALESCE),
	VAL_BYTE("irq-config", NVME_FEAT_FID_IRQ_CONFIG),
	VAL_BYTE("write-atomic", NVME_FEAT_FID_WRITE_ATOMIC),
	VAL_BYTE("async-event", NVME_FEAT_FID_ASYNC_EVENT),
	VAL_BYTE("auto-pst", NVME_FEAT_FID_AUTO_PST),
	VAL_BYTE("host-mem-buf", NVME_FEAT_FID_HOST_MEM_BUF),
	VAL_BYTE("timestamp", NVME_FEAT_FID_TIMESTAMP),
	VAL_BYTE("kato", NVME_FEAT_FID_KATO),
	VAL_BYTE("hctm", NVME_FEAT_FID_HCTM),
	VAL_BYTE("nopsc", NVME_FEAT_FID_NOPSC),
	VAL_BYTE("rrl", NVME_FEAT_FID_RRL),
	VAL_BYTE("plm-config", NVME_FEAT_FID_PLM_CONFIG),
	VAL_BYTE("plm-window", NVME_FEAT_FID_PLM_WINDOW),
	VAL_BYTE("lba-sts-interval", NVME_FEAT_FID_LBA_STS_INTERVAL),
	VAL_BYTE("host-behavior", NVME_FEAT_FID_HOST_BEHAVIOR),
	VAL_BYTE("sanitize", NVME_FEAT_FID_SANITIZE),
	VAL_BYTE("endurance-evt-cfg", NVME_FEAT_FID_ENDURANCE_EVT_CFG),
	VAL_BYTE("iocs-profile", NVME_FEAT_FID_IOCS_PROFILE),
	VAL_BYTE("spinup-control", NVME_FEAT_FID_SPINUP_CONTROL),
	VAL_BYTE("power-loss-signal", NVME_FEAT_FID_POWER_LOSS_SIGNAL),
	VAL_BYTE("perf-characteristics", NVME_FEAT_FID_PERF_CHARACTERISTICS),
	VAL_BYTE("fdp", NVME_FEAT_FID_FDP),
	VAL_BYTE("fdp-events", NVME_FEAT_FID_FDP_EVENTS),
	VAL_BYTE("ns-admin-label", NVME_FEAT_FID_NS_ADMIN_LABEL),
	VAL_BYTE("key-value", NVME_FEAT_FID_KEY_VALUE),
	VAL_BYTE("ctrl-data-queue", NVME_FEAT_FID_CTRL_DATA_QUEUE),
	VAL_BYTE("emb-mgmt-ctrl-addr", NVME_FEAT_FID_EMB_MGMT_CTRL_ADDR),
	VAL_BYTE("host-mgmt-agent-addr", NVME_FEAT_FID_HOST_MGMT_AGENT_ADDR),
	VAL_BYTE("enh-ctrl-metadata", NVME_FEAT_FID_ENH_CTRL_METADATA),
	VAL_BYTE("ctrl-metadata", NVME_FEAT_FID_CTRL_METADATA),
	VAL_BYTE("ns-metadata", NVME_FEAT_FID_NS_METADATA),
	VAL_BYTE("sw-progress", NVME_FEAT_FID_SW_PROGRESS),
	VAL_BYTE("host-id", NVME_FEAT_FID_HOST_ID),
	VAL_BYTE("resv-mask", NVME_FEAT_FID_RESV_MASK),
	VAL_BYTE("resv-persist", NVME_FEAT_FID_RESV_PERSIST),
	VAL_BYTE("write-protect", NVME_FEAT_FID_WRITE_PROTECT),
	VAL_BYTE("bp-write-protect", NVME_FEAT_FID_BP_WRITE_PROTECT),
	VAL_END()
};

const char *nvme_strerror(int errnum)
{
	if (errnum >= ENVME_CONNECT_RESOLVE)
		return nvme_errno_to_string(errnum);
	return strerror(errnum);
}

static ssize_t getrandom_bytes(void *buf, size_t buflen)
{
	ssize_t result;
#if HAVE_SYS_RANDOM
	result = getrandom(buf, buflen, GRND_NONBLOCK);
#else
	_cleanup_fd_ int fd = -1;

	fd = open("/dev/urandom", O_RDONLY);
	if (fd < 0)
		return -errno;
	result = read(fd, buf, buflen);
#endif
	if (result < 0)
		return -errno;
	return result;
}

static int check_arg_dev(int argc, char **argv)
{
	if (optind >= argc) {
		errno = EINVAL;
		nvme_show_perror(argv[0]);
		return -EINVAL;
	}
	return 0;
}

static int get_transport_handle(struct nvme_global_ctx *ctx, int argc,
					char **argv, int flags,
					struct nvme_transport_handle **hdl)
{
	char *devname;
	int ret;

	ret = check_arg_dev(argc, argv);
	if (ret)
		return ret;

	devname = argv[optind];

	ret = nvme_open(ctx, devname, hdl);
	if (!ret && log_level >= LOG_DEBUG)
		nvme_show_init();

	return ret;
}

static int parse_args(int argc, char *argv[], const char *desc,
		      struct argconfig_commandline_options *opts)
{
	int ret;

	ret = argconfig_parse(argc, argv, desc, opts);
	if (ret)
		return ret;

	log_level = map_log_level(nvme_cfg.verbose, false);
	nvme_init_default_logging(stderr, log_level, false, false);

	return 0;
}

int parse_and_open(struct nvme_global_ctx **ctx,
		   struct nvme_transport_handle **hdl, int argc, char **argv,
		   const char *desc, struct argconfig_commandline_options *opts)
{
	struct nvme_transport_handle *hdl_new;
	struct nvme_global_ctx *ctx_new;
	int ret;

	ret = parse_args(argc, argv, desc, opts);
	if (ret)
		return ret;

	ctx_new = nvme_create_global_ctx(stdout, log_level);
	if (!ctx_new)
		return -ENOMEM;

	ret = get_transport_handle(ctx_new, argc, argv, O_RDONLY, &hdl_new);
	if (ret) {
		nvme_free_global_ctx(ctx_new);
		argconfig_print_help(desc, opts);
		return -ENXIO;
	}

	*ctx = ctx_new;
	*hdl = hdl_new;
	return 0;
}

int open_exclusive(struct nvme_global_ctx **ctx,
		   struct nvme_transport_handle **hdl, int argc, char **argv,
		   int ignore_exclusive)
{
	struct nvme_transport_handle *hdl_new;
	struct nvme_global_ctx *ctx_new;
	int flags = O_RDONLY;
	int ret;

	if (!ignore_exclusive)
		flags |= O_EXCL;

	ctx_new = nvme_create_global_ctx(stdout, log_level);
	if (!ctx_new)
		return -ENOMEM;

	ret = get_transport_handle(ctx_new, argc, argv, flags, &hdl_new);
	if (ret) {
		nvme_free_global_ctx(ctx_new);
		return -ENXIO;
	}

	*ctx = ctx_new;
	*hdl = hdl_new;
	return 0;
}

int validate_output_format(const char *format, nvme_print_flags_t *flags)
{
	nvme_print_flags_t f;

	if (!format)
		return -EINVAL;

	if (!strcmp(format, "normal"))
		f = NORMAL;
#ifdef CONFIG_JSONC
	else if (!strcmp(format, "json"))
		f = JSON;
#endif /* CONFIG_JSONC */
	else if (!strcmp(format, "binary"))
		f = BINARY;
	else if (!strcmp(format, "tabular"))
		f = TABULAR;
	else
		return -EINVAL;

	*flags = f;

	return 0;
}

bool nvme_is_output_format_json(void)
{
	nvme_print_flags_t flags;

	if (validate_output_format(nvme_cfg.output_format, &flags))
		return false;

	return flags == JSON;
}

static int get_smart_log(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc = "Retrieve SMART log for the given device "
		"(or optionally a namespace) in either decoded format "
		"(default) or binary.";

	_cleanup_free_ struct nvme_smart_log *smart_log = NULL;
	_cleanup_nvme_global_ctx_ struct nvme_global_ctx *ctx = NULL;
	_cleanup_nvme_transport_handle_ struct nvme_transport_handle *hdl = NULL;
	const char *namespace = "(optional) desired namespace";
	nvme_print_flags_t flags;
	int err = -1;

	struct config {
		__u32	namespace_id;
		bool	raw_binary;
		bool	human_readable;
	};

	struct config cfg = {
		.namespace_id	= NVME_NSID_ALL,
		.raw_binary	= false,
		.human_readable	= false,
	};

	NVME_ARGS(opts,
		  OPT_UINT("namespace-id",   'n', &cfg.namespace_id,   namespace),
		  OPT_FLAG("raw-binary",     'b', &cfg.raw_binary,     raw_output),
		  OPT_FLAG("human-readable", 'H', &cfg.human_readable, human_readable_info));

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	err = validate_output_format(nvme_cfg.output_format, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	if (cfg.raw_binary)
		flags = BINARY;

	if (cfg.human_readable || argconfig_parse_seen(opts, "verbose"))
		flags |= VERBOSE;

	smart_log = nvme_alloc(sizeof(*smart_log));
	if (!smart_log)
		return -ENOMEM;

	err = nvme_get_log_smart(hdl, cfg.namespace_id, smart_log);
	if (!err)
		nvme_show_smart_log(smart_log, cfg.namespace_id,
				    nvme_transport_handle_get_name(hdl), flags);
	else if (err > 0)
		nvme_show_status(err);
	else
		nvme_show_error("smart log: %s", nvme_strerror(err));

	return err;
}

static int get_ana_log(int argc, char **argv, struct command *acmd,
		struct plugin *plugin)
{
	const char *desc = "Retrieve ANA log for the given device in "
		"decoded format (default), json or binary.";
	const char *groups = "Return ANA groups only.";

	_cleanup_nvme_global_ctx_ struct nvme_global_ctx *ctx = NULL;
	_cleanup_nvme_transport_handle_ struct nvme_transport_handle *hdl = NULL;
	_cleanup_free_ struct nvme_id_ctrl *ctrl = NULL;
	_cleanup_free_ struct nvme_ana_log *ana_log = NULL;
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

	err = validate_output_format(nvme_cfg.output_format, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	ctrl = nvme_alloc(sizeof(*ctrl));
	if (!ctrl)
		return -ENOMEM;

	err = nvme_identify_ctrl(hdl, ctrl);
	if (err) {
		nvme_show_error("ERROR : nvme_identify_ctrl() failed: %s",
			nvme_strerror(err));
		return err;
	}

	max_ana_log_len = nvme_get_ana_log_len_from_id_ctrl(ctrl, cfg.groups);
	ana_log_len = max_ana_log_len;
	if (ana_log_len < max_ana_log_len) {
		nvme_show_error("ANA log length %zu too large", max_ana_log_len);
		return -ENOMEM;
	}

	ana_log = nvme_alloc(ana_log_len);
	if (!ana_log)
		return -ENOMEM;

	err = nvme_get_ana_log_atomic(hdl, true, cfg.groups, ana_log, &ana_log_len, 10);
	if (!err)
		nvme_show_ana_log(ana_log, nvme_transport_handle_get_name(hdl), ana_log_len, flags);
	else if (err > 0)
		nvme_show_status(err);
	else
		nvme_show_error("ana-log: %s", nvme_strerror(err));

	return err;
}

static int parse_telemetry_da(struct nvme_transport_handle *hdl,
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

static int get_log_telemetry_ctrl(struct nvme_transport_handle *hdl, bool rae, size_t size,
				  struct nvme_telemetry_log **buf)
{
	struct nvme_telemetry_log *log;
	int err;

	log = nvme_alloc(size);
	if (!log)
		return -ENOMEM;

	err = nvme_get_log_telemetry_ctrl(hdl, rae, 0, log, size);
	if (err) {
		free(log);
		return err;
	}

	*buf = log;
	return 0;
}

static int get_log_telemetry_host(struct nvme_transport_handle *hdl, size_t size,
				  struct nvme_telemetry_log **buf)
{
	struct nvme_telemetry_log *log;
	int err;

	log = nvme_alloc(size);
	if (!log)
		return -ENOMEM;

	err = nvme_get_log_telemetry_host(hdl, 0, log, size);
	if (err) {
		free(log);
		return err;
	}

	*buf = log;
	return 0;
}

static int __create_telemetry_log_host(struct nvme_transport_handle *hdl,
				       enum nvme_telemetry_da da,
				       size_t *size,
				       struct nvme_telemetry_log **buf,
				       bool da4_support)
{
	_cleanup_free_ struct nvme_telemetry_log *log = NULL;
	int err;

	log = nvme_alloc(sizeof(*log));
	if (!log)
		return -ENOMEM;

	err = nvme_get_log_create_telemetry_host_mcda(hdl, da, log);
	if (err)
		return err;

	err = parse_telemetry_da(hdl, da, log, size, da4_support);
	if (err)
		return err;

	return get_log_telemetry_host(hdl, *size, buf);
}

static int __get_telemetry_log_ctrl(struct nvme_transport_handle *hdl,
				    bool rae,
				    enum nvme_telemetry_da da,
				    size_t *size,
				    struct nvme_telemetry_log **buf,
				    bool da4_support)
{
	struct nvme_telemetry_log *log;
	int err;

	log = nvme_alloc(NVME_LOG_TELEM_BLOCK_SIZE);
	if (!log)
		return -ENOMEM;

	/*
	 * set rae = true so it won't clear the current telemetry log in
	 * controller
	 */
	err = nvme_get_log_telemetry_ctrl(hdl, true, 0, log,
					  NVME_LOG_TELEM_BLOCK_SIZE);
	if (err)
		goto free;

	if (!log->ctrlavail) {
		if (!rae) {
			err = nvme_get_log_telemetry_ctrl(hdl, rae, 0, log,
				NVME_LOG_TELEM_BLOCK_SIZE);
			goto free;
		}

		*size = NVME_LOG_TELEM_BLOCK_SIZE;
		*buf = log;

		printf("Warning: Telemetry Controller-Initiated Data Not Available.\n");
		return 0;
	}

	err = parse_telemetry_da(hdl, da, log, size, da4_support);
	if (err)
		goto free;

	return get_log_telemetry_ctrl(hdl, rae, *size, buf);

free:
	free(log);
	return err;
}

static int __get_telemetry_log_host(struct nvme_transport_handle *hdl,
				    enum nvme_telemetry_da da,
				    size_t *size,
				    struct nvme_telemetry_log **buf,
				    bool da4_support)
{
	_cleanup_free_ struct nvme_telemetry_log *log = NULL;
	int err;

	log = nvme_alloc(sizeof(*log));
	if (!log)
		return -ENOMEM;

	err = nvme_get_log_telemetry_host(hdl, 0, log,
					  NVME_LOG_TELEM_BLOCK_SIZE);
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

	_cleanup_free_ struct nvme_telemetry_log *log = NULL;
	_cleanup_free_ struct nvme_id_ctrl *id_ctrl = NULL;
	_cleanup_nvme_global_ctx_ struct nvme_global_ctx *ctx = NULL;
	_cleanup_nvme_transport_handle_ struct nvme_transport_handle *hdl = NULL;
	_cleanup_fd_ int output = -1;
	int err = 0;
	size_t total_size = 0;
	__u8 *data_ptr = NULL;
	int data_written = 0, data_remaining = 0;
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

	err = validate_output_format(nvme_cfg.output_format, &flags);
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
		id_ctrl = nvme_alloc(sizeof(*id_ctrl));
		if (!id_ctrl)
			return -ENOMEM;

		err = nvme_identify_ctrl(hdl, id_ctrl);
		if (err) {
			nvme_show_error("identify-ctrl");
			return err;
		}

		da4_support = id_ctrl->lpa & 0x40;

		if (!da4_support) {
			fprintf(stderr, "%s: Telemetry data area 4 not supported by device\n",
				__func__);
			return -EINVAL;
		}

		err = nvme_set_etdas(hdl, &host_behavior_changed);
		if (err) {
			fprintf(stderr, "%s: Failed to set ETDAS bit\n", __func__);
			return err;
		}
	}

	output = open(cfg.file_name, O_WRONLY | O_CREAT | O_TRUNC, 0666);
	if (output < 0) {
		nvme_show_error("Failed to open output file %s: %s!",
				cfg.file_name, strerror(errno));
		return output;
	}

	log = nvme_alloc(sizeof(*log));
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

	if (err < 0) {
		nvme_show_error("get-telemetry-log: %s", nvme_strerror(err));
		return err;
	} else if (err > 0) {
		nvme_show_status(err);
		fprintf(stderr, "Failed to acquire telemetry log %d!\n", err);
		return err;
	}

	data_written = 0;
	data_remaining = total_size;
	data_ptr = (__u8 *)log;

	while (data_remaining) {
		data_written = write(output, data_ptr, data_remaining);
		if (data_written < 0) {
			err = -errno;
			nvme_show_error("ERROR: %s: : write failed with error : %s",
					__func__, strerror(errno));
			break;
		} else if (data_written <= data_remaining) {
			data_remaining -= data_written;
			data_ptr += data_written;
		} else {
			/* Unexpected overwrite */
			fprintf(stderr, "Failure: Unexpected telemetry log overwrite - data_remaining = 0x%x, data_written = 0x%x\n",
					data_remaining, data_written);
			err = -1;
			break;
		}
	}

	if (fsync(output) < 0) {
		nvme_show_error("ERROR : %s: : fsync : %s", __func__, strerror(errno));
		return -1;
	}

	if (host_behavior_changed) {
		host_behavior_changed = false;
		err = nvme_clear_etdas(hdl, &host_behavior_changed);
		if (err) {
			fprintf(stderr, "%s: Failed to clear ETDAS bit\n", __func__);
			return err;
		}
	}

	return err;
}

static int get_endurance_log(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc = "Retrieves endurance groups log page and prints the log.";
	const char *group_id = "The endurance group identifier";

	_cleanup_free_ struct nvme_endurance_group_log *endurance_log = NULL;
	_cleanup_nvme_global_ctx_ struct nvme_global_ctx *ctx = NULL;
	_cleanup_nvme_transport_handle_ struct nvme_transport_handle *hdl = NULL;
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

	err = validate_output_format(nvme_cfg.output_format, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	endurance_log = nvme_alloc(sizeof(*endurance_log));
	if (!endurance_log)
		return -ENOMEM;

	err = nvme_get_log_endurance_group(hdl, cfg.group_id,
					   endurance_log);
	if (!err)
		nvme_show_endurance_log(endurance_log, cfg.group_id,
					nvme_transport_handle_get_name(hdl), flags);
	else if (err > 0)
		nvme_show_status(err);
	else
		nvme_show_error("endurance log: %s", nvme_strerror(err));

	return err;
}

static int collect_effects_log(struct nvme_transport_handle *hdl, enum nvme_csi csi,
			       struct list_head *list, int flags)
{
	nvme_effects_log_node_t *node;
	int err;

	node = nvme_alloc(sizeof(*node));
	if (!node)
		return -ENOMEM;

	node->csi = csi;

	err = nvme_get_log_cmd_effects(hdl, csi, &node->effects);
	if (err) {
		free(node);
		return err;
	}
	list_add(list, &node->node);
	return 0;
}

static int get_effects_log(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc = "Retrieve command effects log page and print the table.";

	_cleanup_nvme_global_ctx_ struct nvme_global_ctx *ctx = NULL;
	_cleanup_nvme_transport_handle_ struct nvme_transport_handle *hdl = NULL;
	struct nvme_passthru_cmd64 cmd;
	struct list_head log_pages;
	nvme_effects_log_node_t *node;

	void *bar = NULL;

	int err = -1;
	nvme_print_flags_t flags;

	struct config {
		bool	human_readable;
		bool	raw_binary;
		int	csi;
	};

	struct config cfg = {
		.human_readable	= false,
		.raw_binary	= false,
		.csi		= -1,
	};

	NVME_ARGS(opts,
		  OPT_FLAG("human-readable", 'H', &cfg.human_readable, human_readable_log),
		  OPT_FLAG("raw-binary",     'b', &cfg.raw_binary,     raw_log),
		  OPT_INT("csi",             'c', &cfg.csi,            csi));


	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	err = validate_output_format(nvme_cfg.output_format, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	if (cfg.raw_binary)
		flags = BINARY;

	if (cfg.human_readable || argconfig_parse_seen(opts, "verbose"))
		flags |= VERBOSE;

	list_head_init(&log_pages);

	if (cfg.csi < 0) {
		__u64 cap;
		if (nvme_transport_handle_is_blkdev(hdl)) {
			nvme_show_error("Block device isn't allowed without csi");
			return -EINVAL;
		}
		bar = mmap_registers(hdl, false);

		if (bar) {
			cap = mmio_read64(bar + NVME_REG_CAP);
			munmap(bar, getpagesize());
		} else {
			nvme_init_get_property(&cmd, NVME_REG_CAP);
			err = nvme_submit_admin_passthru64(hdl, &cmd, &cap);
			if (err)
				goto cleanup_list;
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

	if (!err)
		nvme_print_effects_log_pages(&log_pages, flags);
	else if (err > 0)
		nvme_show_status(err);
	else
		nvme_show_perror("effects log page");

cleanup_list:
	while ((node = list_pop(&log_pages, nvme_effects_log_node_t, node)))
		free(node);

	return err;
}

static int get_supported_log_pages(int argc, char **argv, struct command *acmd,
	struct plugin *plugin)
{
	const char *desc = "Retrieve supported logs and print the table.";

	_cleanup_free_ struct nvme_supported_log_pages *supports = NULL;
	_cleanup_nvme_global_ctx_ struct nvme_global_ctx *ctx = NULL;
	_cleanup_nvme_transport_handle_ struct nvme_transport_handle *hdl = NULL;
	nvme_print_flags_t flags;
	int err = -1;

	NVME_ARGS(opts);

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	err = validate_output_format(nvme_cfg.output_format, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	if (argconfig_parse_seen(opts, "verbose"))
		flags |= VERBOSE;

	supports = nvme_alloc(sizeof(*supports));
	if (!supports)
		return -ENOMEM;

	err = nvme_get_log_supported_log_pages(hdl, supports);
	if (!err)
		nvme_show_supported_log(supports, nvme_transport_handle_get_name(hdl), flags);
	else if (err > 0)
		nvme_show_status(err);
	else
		nvme_show_error("supported log pages: %s", nvme_strerror(err));

	return err;
}

static int get_error_log(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc = "Retrieve specified number of "
		"error log entries from a given device "
		"in either decoded format (default) or binary.";
	const char *log_entries = "number of entries to retrieve";
	const char *raw = "dump in binary format";

	_cleanup_free_ struct nvme_error_log_page *err_log = NULL;
	_cleanup_nvme_global_ctx_ struct nvme_global_ctx *ctx = NULL;
	_cleanup_nvme_transport_handle_ struct nvme_transport_handle *hdl = NULL;
	struct nvme_id_ctrl ctrl = { 0 };
	nvme_print_flags_t flags;
	int err = -1;

	struct config {
		__u32	log_entries;
		bool	raw_binary;
	};

	struct config cfg = {
		.log_entries	= 64,
		.raw_binary	= false,
	};

	NVME_ARGS(opts,
		  OPT_UINT("log-entries",  'e', &cfg.log_entries,   log_entries),
		  OPT_FLAG("raw-binary",   'b', &cfg.raw_binary,    raw));

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	err = validate_output_format(nvme_cfg.output_format, &flags);
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

	err = nvme_identify_ctrl(hdl, &ctrl);
	if (err < 0) {
		nvme_show_perror("identify controller");
		return err;
	} else if (err) {
		nvme_show_error("could not identify controller");
		return err;
	}

	cfg.log_entries = min(cfg.log_entries, ctrl.elpe + 1);
	err_log = nvme_alloc(cfg.log_entries * sizeof(struct nvme_error_log_page));
	if (!err_log)
		return -ENOMEM;

	err = nvme_get_log_error(hdl, NVME_NSID_ALL, cfg.log_entries, err_log);
	if (!err)
		nvme_show_error_log(err_log, cfg.log_entries,
				    nvme_transport_handle_get_name(hdl), flags);
	else if (err > 0)
		nvme_show_status(err);
	else
		nvme_show_perror("error log");

	return err;
}

static int get_fw_log(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc = "Retrieve the firmware log for the "
		"specified device in either decoded format (default) or binary.";

	_cleanup_free_ struct nvme_firmware_slot *fw_log = NULL;
	_cleanup_nvme_global_ctx_ struct nvme_global_ctx *ctx = NULL;
	_cleanup_nvme_transport_handle_ struct nvme_transport_handle *hdl = NULL;
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

	err = validate_output_format(nvme_cfg.output_format, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	if (cfg.raw_binary)
		flags = BINARY;

	fw_log = nvme_alloc(sizeof(*fw_log));
	if (!fw_log)
		return -ENOMEM;

	err = nvme_get_log_fw_slot(hdl, false, fw_log);
	if (!err)
		nvme_show_fw_log(fw_log, nvme_transport_handle_get_name(hdl), flags);
	else if (err > 0)
		nvme_show_status(err);
	else
		nvme_show_error("fw log: %s", nvme_strerror(err));

	return err;
}

static int get_changed_ns_list_log(int argc, char **argv, bool alloc)
{
	_cleanup_free_ char *desc = NULL;
	_cleanup_free_ struct nvme_ns_list *changed_ns_list_log = NULL;
	_cleanup_nvme_global_ctx_ struct nvme_global_ctx *ctx = NULL;
	_cleanup_nvme_transport_handle_ struct nvme_transport_handle *hdl = NULL;
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

	err = validate_output_format(nvme_cfg.output_format, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	if (cfg.raw_binary)
		flags = BINARY;

	changed_ns_list_log = nvme_alloc(sizeof(*changed_ns_list_log));
	if (!changed_ns_list_log)
		return -ENOMEM;

	if (alloc)
		err = nvme_get_log_changed_alloc_ns_list(hdl,
			changed_ns_list_log, sizeof(*changed_ns_list_log));
	else
		err = nvme_get_log_changed_ns_list(hdl, NVME_NSID_NONE,
			changed_ns_list_log);
	if (!err)
		nvme_show_changed_ns_list_log(changed_ns_list_log, nvme_transport_handle_get_name(hdl),
					      flags, alloc);
	else if (err > 0)
		nvme_show_status(err);
	else
		nvme_show_error("changed %s ns list log: %s", alloc ? "allocated" : "attached",
				nvme_strerror(err));

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

	_cleanup_free_ struct nvme_nvmset_predictable_lat_log *plpns_log = NULL;
	_cleanup_nvme_global_ctx_ struct nvme_global_ctx *ctx = NULL;
	_cleanup_nvme_transport_handle_ struct nvme_transport_handle *hdl = NULL;
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

	err = validate_output_format(nvme_cfg.output_format, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	if (cfg.raw_binary)
		flags = BINARY;

	plpns_log = nvme_alloc(sizeof(*plpns_log));
	if (!plpns_log)
		return -ENOMEM;

	err = nvme_get_log_predictable_lat_nvmset(hdl, cfg.nvmset_id,
						  plpns_log);
	if (!err)
		nvme_show_predictable_latency_per_nvmset(plpns_log, cfg.nvmset_id,
							 nvme_transport_handle_get_name(hdl),
							 flags);
	else if (err > 0)
		nvme_show_status(err);
	else
		nvme_show_error("predictable latency per nvm set: %s", nvme_strerror(err));

	return err;
}

static int get_pred_lat_event_agg_log(int argc, char **argv,
		struct command *command, struct plugin *plugin)
{
	const char *desc = "Retrieve Predictable Latency Event "
		"Aggregate Log page and prints it, for the given "
		"device in either decoded format(default), json or binary.";
	const char *log_entries = "Number of pending NVM Set log Entries list";

	_cleanup_nvme_global_ctx_ struct nvme_global_ctx *ctx = NULL;
	_cleanup_nvme_transport_handle_ struct nvme_transport_handle *hdl = NULL;
	_cleanup_free_ struct nvme_id_ctrl *ctrl = NULL;
	_cleanup_free_ void *pea_log = NULL;
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

	err = validate_output_format(nvme_cfg.output_format, &flags);
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

	ctrl = nvme_alloc(sizeof(*ctrl));
	if (!ctrl)
		return -ENOMEM;

	err = nvme_identify_ctrl(hdl, ctrl);
	if (err < 0) {
		nvme_show_error("identify controller: %s", nvme_strerror(err));
		return err;
	} else if (err) {
		nvme_show_status(err);
		return err;
	}

	cfg.log_entries = min(cfg.log_entries, le32_to_cpu(ctrl->nsetidmax));
	log_size = sizeof(__u64) + cfg.log_entries * sizeof(__u16);

	pea_log = nvme_alloc(log_size);
	if (!pea_log)
		return -ENOMEM;

	err = nvme_get_log_predictable_lat_event(hdl, cfg.rae, 0,
						 pea_log, log_size);
	if (!err)
		nvme_show_predictable_latency_event_agg_log(pea_log, cfg.log_entries, log_size,
							    nvme_transport_handle_get_name(hdl), flags);
	else if (err > 0)
		nvme_show_status(err);
	else
		nvme_show_error("predictable latency event aggregate log page: %s",
				nvme_strerror(err));

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

	_cleanup_free_ struct nvme_persistent_event_log *pevent = NULL;
	struct nvme_persistent_event_log *pevent_collected = NULL;
	_cleanup_huge_ struct nvme_mem_huge mh = { 0, };
	_cleanup_nvme_global_ctx_ struct nvme_global_ctx *ctx = NULL;
	_cleanup_nvme_transport_handle_ struct nvme_transport_handle *hdl = NULL;
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

	err = validate_output_format(nvme_cfg.output_format, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	if (cfg.raw_binary)
		flags = BINARY;

	pevent = nvme_alloc(sizeof(*pevent));
	if (!pevent)
		return -ENOMEM;

	err = nvme_get_log_persistent_event(hdl, cfg.action,
					    pevent, sizeof(*pevent));
	if (err < 0) {
		nvme_show_error("persistent event log: %s", nvme_strerror(err));
		return err;
	} else if (err) {
		nvme_show_status(err);
		return err;
	}

	if (cfg.action == NVME_PEVENT_LOG_RELEASE_CTX) {
		printf("Releasing Persistent Event Log Context\n");
		return 0;
	}

	if (!cfg.log_len && cfg.action != NVME_PEVENT_LOG_EST_CTX_AND_READ) {
		cfg.log_len = le64_to_cpu(pevent->tll);
	} else if (!cfg.log_len && cfg.action == NVME_PEVENT_LOG_EST_CTX_AND_READ) {
		printf("Establishing Persistent Event Log Context\n");
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

	pevent_log_info = nvme_alloc_huge(cfg.log_len, &mh);
	if (!pevent_log_info) {
		nvme_show_error("failed to allocate huge memory");
		return -ENOMEM;
	}

	err = nvme_get_log_persistent_event(hdl, cfg.action,
					    pevent_log_info, cfg.log_len);
	if (!err) {
		err = nvme_get_log_persistent_event(hdl, cfg.action,
							pevent,
							sizeof(*pevent));
		if (err < 0) {
			nvme_show_error("persistent event log: %s", nvme_strerror(err));
			return err;
		} else if (err) {
			nvme_show_status(err);
			return err;
		}
		pevent_collected = pevent_log_info;
		if (pevent_collected->gen_number != pevent->gen_number) {
			printf("Collected Persistent Event Log may be invalid,\n"
			       "Re-read the log is required\n");
			return -EINVAL;
		}

		nvme_show_persistent_event_log(pevent_log_info, cfg.action,
			cfg.log_len, nvme_transport_handle_get_name(hdl), flags);
	} else if (err > 0) {
		nvme_show_status(err);
	} else {
		nvme_show_error("persistent event log: %s", nvme_strerror(err));
	}

	return err;
}

static int get_endurance_event_agg_log(int argc, char **argv,
		struct command *command, struct plugin *plugin)
{
	const char *desc = "Retrieve Retrieve Predictable Latency "
		"Event Aggregate page and prints it, for the given "
		"device in either decoded format(default), json or binary.";
	const char *log_entries = "Number of pending Endurance Group Event log Entries list";

	_cleanup_nvme_global_ctx_ struct nvme_global_ctx *ctx = NULL;
	_cleanup_nvme_transport_handle_ struct nvme_transport_handle *hdl = NULL;
	_cleanup_free_ struct nvme_id_ctrl *ctrl = NULL;
	_cleanup_free_ void *endurance_log = NULL;
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

	err = validate_output_format(nvme_cfg.output_format, &flags);
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

	ctrl = nvme_alloc(sizeof(*ctrl));
	if (!ctrl)
		return -ENOMEM;

	err = nvme_identify_ctrl(hdl, ctrl);
	if (err < 0) {
		nvme_show_error("identify controller: %s", nvme_strerror(err));
		return err;
	} else if (err) {
		nvme_show_error("could not identify controller");
		return -ENODEV;
	}

	cfg.log_entries = min(cfg.log_entries, le16_to_cpu(ctrl->endgidmax));
	log_size = sizeof(__u64) + cfg.log_entries * sizeof(__u16);

	endurance_log = nvme_alloc(log_size);
	if (!endurance_log)
		return -ENOMEM;

	err = nvme_get_log_endurance_grp_evt(hdl, cfg.rae, 0,
					     endurance_log, log_size);
	if (!err)
		nvme_show_endurance_group_event_agg_log(endurance_log, cfg.log_entries, log_size,
							nvme_transport_handle_get_name(hdl), flags);
	else if (err > 0)
		nvme_show_status(err);
	else
		nvme_show_error("endurance group event aggregate log page: %s",
				nvme_strerror(err));

	return err;
}

static int get_lba_status_log(int argc, char **argv,
		struct command *command, struct plugin *plugin)
{
	const char *desc = "Retrieve Get LBA Status Info Log and prints it, "
		"for the given device in either decoded format(default),json or binary.";

	_cleanup_nvme_global_ctx_ struct nvme_global_ctx *ctx = NULL;
	_cleanup_nvme_transport_handle_ struct nvme_transport_handle *hdl = NULL;
	_cleanup_free_ void *lba_status = NULL;
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

	err = validate_output_format(nvme_cfg.output_format, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	err = nvme_get_log_lba_status(hdl, false, 0, &lslplen, sizeof(__u32));
	if (err < 0) {
		nvme_show_error("lba status log page: %s", nvme_strerror(err));
		return err;
	} else if (err) {
		nvme_show_status(err);
		return err;
	}

	lba_status = nvme_alloc(lslplen);
	if (!lba_status)
		return -ENOMEM;

	err = nvme_get_log_lba_status(hdl, cfg.rae, 0, lba_status, lslplen);
	if (!err)
		nvme_show_lba_status_log(lba_status, lslplen, nvme_transport_handle_get_name(hdl), flags);
	else if (err > 0)
		nvme_show_status(err);
	else
		nvme_show_error("lba status log page: %s", nvme_strerror(err));

	return err;
}

static int get_resv_notif_log(int argc, char **argv,
	struct command *command, struct plugin *plugin)
{

	const char *desc = "Retrieve Reservation Notification "
		"log page and prints it, for the given "
		"device in either decoded format(default), json or binary.";

	_cleanup_free_ struct nvme_resv_notification_log *resv = NULL;
	_cleanup_nvme_global_ctx_ struct nvme_global_ctx *ctx = NULL;
	_cleanup_nvme_transport_handle_ struct nvme_transport_handle *hdl = NULL;
	nvme_print_flags_t flags;
	int err;

	NVME_ARGS(opts);

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	err = validate_output_format(nvme_cfg.output_format, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	resv = nvme_alloc(sizeof(*resv));
	if (!resv)
		return -ENOMEM;

	err = nvme_get_log_reservation(hdl, resv);
	if (!err)
		nvme_show_resv_notif_log(resv, nvme_transport_handle_get_name(hdl), flags);
	else if (err > 0)
		nvme_show_status(err);
	else
		nvme_show_error("resv notifi log: %s", nvme_strerror(err));

	return err;

}

static int get_boot_part_log(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc = "Retrieve Boot Partition "
		"log page and prints it, for the given "
		"device in either decoded format(default), json or binary.";
	const char *fname = "boot partition data output file name";

	_cleanup_nvme_global_ctx_ struct nvme_global_ctx *ctx = NULL;
	_cleanup_nvme_transport_handle_ struct nvme_transport_handle *hdl = NULL;
	_cleanup_free_ struct nvme_boot_partition *boot = NULL;
	_cleanup_free_ __u8 *bp_log = NULL;
	nvme_print_flags_t flags;
	int err = -1;
	_cleanup_fd_ int output = -1;
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

	err = validate_output_format(nvme_cfg.output_format, &flags);
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

	output = open(cfg.file_name, O_WRONLY | O_CREAT | O_TRUNC, 0666);
	if (output < 0) {
		nvme_show_error("Failed to open output file %s: %s!",
				cfg.file_name, strerror(errno));
		return output;
	}

	boot = nvme_alloc(sizeof(*boot));
	if (!boot)
		return -ENOMEM;

	err = nvme_get_log_boot_partition(hdl, cfg.lsp, boot, sizeof(*boot));
	if (err < 0) {
		nvme_show_error("boot partition log: %s", nvme_strerror(err));
		return err;
	} else if (err) {
		nvme_show_status(err);
		return err;
	}

	bpsz = (boot->bpinfo & 0x7fff) * 128 * 1024;
	bp_log = nvme_alloc(sizeof(*boot) + bpsz);
	if (!bp_log)
		return -ENOMEM;

	err = nvme_get_log_boot_partition(hdl, cfg.lsp,
					  (struct nvme_boot_partition *)bp_log,
					  sizeof(*boot) + bpsz);
	if (!err)
		nvme_show_boot_part_log(&bp_log, nvme_transport_handle_get_name(hdl),
					sizeof(*boot) + bpsz, flags);
	else if (err > 0)
		nvme_show_status(err);
	else
		nvme_show_error("boot partition log: %s", nvme_strerror(err));

	err = write(output, (void *) bp_log + sizeof(*boot), bpsz);
	if (err != bpsz)
		fprintf(stderr, "Failed to flush all data to file!\n");
	else
		printf("Data flushed into file %s\n", cfg.file_name);
	err = 0;

	return err;
}

static int get_phy_rx_eom_log(int argc, char **argv, struct command *acmd,
		struct plugin *plugin)
{
	const char *desc = "Retrieve Physical Interface Receiver Eye Opening "
		"Measurement log for the given device in decoded format "
		"(default), json or binary.";
	const char *controller = "Target Controller ID.";
	_cleanup_free_ struct nvme_phy_rx_eom_log *phy_rx_eom_log = NULL;
	size_t phy_rx_eom_log_len;
	nvme_print_flags_t flags;
	_cleanup_nvme_global_ctx_ struct nvme_global_ctx *ctx = NULL;
	_cleanup_nvme_transport_handle_ struct nvme_transport_handle *hdl = NULL;
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

	err = validate_output_format(nvme_cfg.output_format, &flags);
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
	phy_rx_eom_log = nvme_alloc(phy_rx_eom_log_len);
	if (!phy_rx_eom_log)
		return -ENOMEM;

	/* Just read measurement, take given action when fetching full log */
	lsp_tmp = cfg.lsp & 0xf3;

	err = nvme_get_log_phy_rx_eom(hdl, lsp_tmp, cfg.controller, phy_rx_eom_log,
								  phy_rx_eom_log_len);
	if (err) {
		if (err > 0)
			nvme_show_status(err);
		else
			nvme_show_error("phy-rx-eom-log: %s", nvme_strerror(err));

		return err;
	}

	if (phy_rx_eom_log->eomip == NVME_PHY_RX_EOM_COMPLETED)
		phy_rx_eom_log_len = le16_to_cpu(phy_rx_eom_log->hsize) +
				     le32_to_cpu(phy_rx_eom_log->dsize) *
				     le16_to_cpu(phy_rx_eom_log->nd);
	else
		phy_rx_eom_log_len = le16_to_cpu(phy_rx_eom_log->hsize);

	phy_rx_eom_log = nvme_realloc(phy_rx_eom_log, phy_rx_eom_log_len);
	if (!phy_rx_eom_log)
		return -ENOMEM;

	err = nvme_get_log_phy_rx_eom(hdl, cfg.lsp, cfg.controller, phy_rx_eom_log,
								  phy_rx_eom_log_len);
	if (!err)
		nvme_show_phy_rx_eom_log(phy_rx_eom_log, cfg.controller, flags);
	else if (err > 0)
		nvme_show_status(err);
	else
		nvme_show_error("phy-rx-eom-log: %s", nvme_strerror(err));

	return err;
}

static int get_media_unit_stat_log(int argc, char **argv, struct command *acmd,
				   struct plugin *plugin)
{
	const char *desc = "Retrieve the configuration and wear of media units and print it";

	_cleanup_free_ struct nvme_media_unit_stat_log *mus = NULL;
	_cleanup_nvme_global_ctx_ struct nvme_global_ctx *ctx = NULL;
	_cleanup_nvme_transport_handle_ struct nvme_transport_handle *hdl = NULL;
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

	err = validate_output_format(nvme_cfg.output_format, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	if (cfg.raw_binary)
		flags = BINARY;

	mus = nvme_alloc(sizeof(*mus));
	if (!mus)
		return -ENOMEM;

	err = nvme_get_log_media_unit_stat(hdl, cfg.domainid, mus);
	if (!err)
		nvme_show_media_unit_stat_log(mus, flags);
	else if (err > 0)
		nvme_show_status(err);
	else
		nvme_show_error("media unit status log: %s", nvme_strerror(err));

	return err;
}

static int get_supp_cap_config_log(int argc, char **argv, struct command *acmd,
				   struct plugin *plugin)
{
	const char *desc = "Retrieve the list of Supported Capacity Configuration Descriptors";

	_cleanup_free_ struct nvme_supported_cap_config_list_log *cap_log = NULL;
	_cleanup_nvme_global_ctx_ struct nvme_global_ctx *ctx = NULL;
	_cleanup_nvme_transport_handle_ struct nvme_transport_handle *hdl = NULL;
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

	err = validate_output_format(nvme_cfg.output_format, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	if (cfg.raw_binary)
		flags = BINARY;

	cap_log = nvme_alloc(sizeof(*cap_log));
	if (!cap_log)
		return -ENOMEM;

	err = nvme_get_log_support_cap_config_list(hdl, cfg.domainid,
						   cap_log);
	if (!err)
		nvme_show_supported_cap_config_log(cap_log, flags);
	else if (err > 0)
		nvme_show_status(err);
	else
		nvme_show_perror("supported capacity configuration list log");

	return err;
}

static int io_mgmt_send(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc = "I/O Management Send";
	const char *data = "optional file for data (default stdin)";

	_cleanup_nvme_transport_handle_ struct nvme_transport_handle *hdl = NULL;
	_cleanup_nvme_global_ctx_ struct nvme_global_ctx *ctx = NULL;
	_cleanup_fd_ int dfd = STDIN_FILENO;
	_cleanup_free_ void *buf = NULL;
	struct nvme_passthru_cmd cmd;
	int err = -1;

	struct config {
		__u32 nsid;
		__u16 mos;
		__u8  mo;
		char  *file;
		__u32 data_len;
	};

	struct config cfg = {
		.mos = 0,
	};

	NVME_ARGS(opts,
		  OPT_UINT("namespace-id",  'n', &cfg.nsid,		namespace_id_desired),
		  OPT_SHRT("mos",           's', &cfg.mos,		mos),
		  OPT_BYTE("mo",            'm', &cfg.mo,       mo),
		  OPT_FILE("data",          'd', &cfg.file,     data),
		  OPT_UINT("data-len",      'l', &cfg.data_len, buf_len));

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	if (!cfg.nsid) {
		err = nvme_get_nsid(hdl, &cfg.nsid);
		if (err < 0) {
			nvme_show_perror("get-namespace-id");
			return err;
		}
	}

	if (cfg.data_len) {
		buf = nvme_alloc(cfg.data_len);
		if (!buf)
			return -ENOMEM;
	}

	if (cfg.file) {
		dfd = open(cfg.file, O_RDONLY);
		if (dfd < 0) {
			nvme_show_perror(cfg.file);
			return -errno;
		}
	}

	err = read(dfd, buf, cfg.data_len);
	if (err < 0) {
		nvme_show_perror("read");
		return err;
	}

	nvme_init_io_mgmt_send(&cmd, cfg.nsid, cfg.mo, cfg.mos, buf, cfg.data_len);
	err = nvme_submit_io_passthru(hdl, &cmd, NULL);
	if (!err)
		printf("io-mgmt-send: Success, mos:%u mo:%u nsid:%d\n",
			cfg.mos, cfg.mo, cfg.nsid);
	else if (err > 0)
		nvme_show_status(err);
	else
		nvme_show_perror("io-mgmt-send");

	return err;
}

static int io_mgmt_recv(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc = "I/O Management Receive";
	const char *data = "optional file for data (default stdout)";

	_cleanup_nvme_transport_handle_ struct nvme_transport_handle *hdl = NULL;
	_cleanup_nvme_global_ctx_ struct nvme_global_ctx *ctx = NULL;
	_cleanup_free_ void *buf = NULL;
	struct nvme_passthru_cmd cmd;
	_cleanup_fd_ int dfd = -1;
	int err = -1;

	struct config {
		__u16 mos;
		__u8  mo;
		__u32 nsid;
		char  *file;
		__u32 data_len;
	};

	struct config cfg = {
		.mos = 0,
	};

	NVME_ARGS(opts,
		  OPT_UINT("namespace-id",  'n', &cfg.nsid,		namespace_id_desired),
		  OPT_SHRT("mos",           's', &cfg.mos,      mos),
		  OPT_BYTE("mo",            'm', &cfg.mo,       mo),
		  OPT_FILE("data",          'd', &cfg.file,     data),
		  OPT_UINT("data-len",      'l', &cfg.data_len, buf_len));

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	if (!cfg.nsid) {
		err = nvme_get_nsid(hdl, &cfg.nsid);
		if (err < 0) {
			nvme_show_perror("get-namespace-id");
			return err;
		}
	}

	if (cfg.data_len) {
		buf = nvme_alloc(cfg.data_len);
		if (!buf)
			return -ENOMEM;
	}

	nvme_init_io_mgmt_recv(&cmd, cfg.nsid, cfg.mo, cfg.mos, buf,
		cfg.data_len);
	err = nvme_submit_io_passthru(hdl, &cmd, NULL);
	if (!err) {
		printf("io-mgmt-recv: Success, mos:%u mo:%u nsid:%d\n",
			cfg.mos, cfg.mo, cfg.nsid);

		if (cfg.file) {
			dfd = open(cfg.file, O_WRONLY | O_CREAT, 0644);
			if (dfd < 0) {
				nvme_show_perror(cfg.file);
				return -errno;
			}

			err = write(dfd, buf, cfg.data_len);
			if (err < 0) {
				nvme_show_perror("write");
				return -errno;
			}
		} else {
			d((unsigned char *)buf, cfg.data_len, 16, 1);
		}
	} else if (err > 0) {
		nvme_show_status(err);
	} else {
		nvme_show_perror("io-mgmt-recv");
	}

	return err;
}

static int get_log(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc = "Retrieve desired number of bytes "
		"from a given log on a specified device in either "
		"hex-dump (default) or binary format";
	const char *log_id = "identifier of log to retrieve";
	const char *log_len = "how many bytes to retrieve";
	const char *aen = "result of the aen, use to override log id";
	const char *lpo = "log page offset specifies the location within a log page from where to start returning data";
	const char *lsi = "log specific identifier specifies an identifier that is required for a particular log page";
	const char *raw = "output in raw format";
	const char *offset_type = "offset type";
	const char *xfer_len = "read chunk size (default 4k)";

	_cleanup_nvme_global_ctx_ struct nvme_global_ctx *ctx = NULL;
	_cleanup_nvme_transport_handle_ struct nvme_transport_handle *hdl = NULL;
	_cleanup_free_ unsigned char *log = NULL;
	struct nvme_passthru_cmd cmd;
	int err;
	nvme_print_flags_t flags;

	struct config {
		__u32	namespace_id;
		__u8	log_id;
		__u32	log_len;
		__u32	aen;
		__u64	lpo;
		__u8	lsp;
		__u16	lsi;
		bool	rae;
		__u8	uuid_index;
		bool	raw_binary;
		__u8	csi;
		bool	ot;
		__u32	xfer_len;
	};

	struct config cfg = {
		.namespace_id	= NVME_NSID_ALL,
		.log_id		= 0xff,
		.log_len	= 0,
		.aen		= 0,
		.lpo		= NVME_LOG_LPO_NONE,
		.lsp		= NVME_LOG_LSP_NONE,
		.lsi		= NVME_LOG_LSI_NONE,
		.rae		= false,
		.uuid_index	= NVME_UUID_NONE,
		.raw_binary	= false,
		.csi		= NVME_CSI_NVM,
		.ot		= false,
		.xfer_len	= 4096,
	};

	OPT_VALS(log_name) = {
		VAL_BYTE("supported-log-pages", NVME_LOG_LID_SUPPORTED_LOG_PAGES),
		VAL_BYTE("error", NVME_LOG_LID_ERROR),
		VAL_BYTE("smart", NVME_LOG_LID_SMART),
		VAL_BYTE("fw-slot", NVME_LOG_LID_FW_SLOT),
		VAL_BYTE("changed-ns", NVME_LOG_LID_CHANGED_NS),
		VAL_BYTE("cmd-effects", NVME_LOG_LID_CMD_EFFECTS),
		VAL_BYTE("device-self-test", NVME_LOG_LID_DEVICE_SELF_TEST),
		VAL_BYTE("telemetry-host", NVME_LOG_LID_TELEMETRY_HOST),
		VAL_BYTE("telemetry-ctrl", NVME_LOG_LID_TELEMETRY_CTRL),
		VAL_BYTE("endurance-group", NVME_LOG_LID_ENDURANCE_GROUP),
		VAL_BYTE("predictable-lat-nvmset", NVME_LOG_LID_PREDICTABLE_LAT_NVMSET),
		VAL_BYTE("predictable-lat-agg", NVME_LOG_LID_PREDICTABLE_LAT_AGG),
		VAL_BYTE("ana", NVME_LOG_LID_ANA),
		VAL_BYTE("persistent-event", NVME_LOG_LID_PERSISTENT_EVENT),
		VAL_BYTE("lba-status", NVME_LOG_LID_LBA_STATUS),
		VAL_BYTE("endurance-grp-evt", NVME_LOG_LID_ENDURANCE_GRP_EVT),
		VAL_BYTE("media-unit-status", NVME_LOG_LID_MEDIA_UNIT_STATUS),
		VAL_BYTE("supported-cap-config-list", NVME_LOG_LID_SUPPORTED_CAP_CONFIG_LIST),
		VAL_BYTE("fid-supported-effects", NVME_LOG_LID_FID_SUPPORTED_EFFECTS),
		VAL_BYTE("mi-cmd-supported-effects", NVME_LOG_LID_MI_CMD_SUPPORTED_EFFECTS),
		VAL_BYTE("cmd-and-feat-lockdown", NVME_LOG_LID_CMD_AND_FEAT_LOCKDOWN),
		VAL_BYTE("boot-partition", NVME_LOG_LID_BOOT_PARTITION),
		VAL_BYTE("rotational-media-info",
			 NVME_LOG_LID_ROTATIONAL_MEDIA_INFO),
		VAL_BYTE("dispersed-ns-participating-ns",
			 NVME_LOG_LID_DISPERSED_NS_PARTICIPATING_NSS),
		VAL_BYTE("mgmt-addr-list", NVME_LOG_LID_MGMT_ADDR_LIST),
		VAL_BYTE("phy-rx-eom", NVME_LOG_LID_PHY_RX_EOM),
		VAL_BYTE("reachability-groups", NVME_LOG_LID_REACHABILITY_GROUPS),
		VAL_BYTE("reachability-associations", NVME_LOG_LID_REACHABILITY_ASSOCIATIONS),
		VAL_BYTE("changed-alloc-ns-list", NVME_LOG_LID_CHANGED_ALLOC_NS),
		VAL_BYTE("fdp-configs", NVME_LOG_LID_FDP_CONFIGS),
		VAL_BYTE("fdp-ruh-usage", NVME_LOG_LID_FDP_RUH_USAGE),
		VAL_BYTE("fdp-stats", NVME_LOG_LID_FDP_STATS),
		VAL_BYTE("fdp-events", NVME_LOG_LID_FDP_EVENTS),
		VAL_BYTE("discover", NVME_LOG_LID_DISCOVERY),
		VAL_BYTE("host-discover", NVME_LOG_LID_HOST_DISCOVERY),
		VAL_BYTE("ave-discover", NVME_LOG_LID_AVE_DISCOVERY),
		VAL_BYTE("pull-model-ddc-req", NVME_LOG_LID_PULL_MODEL_DDC_REQ),
		VAL_BYTE("reservation", NVME_LOG_LID_RESERVATION),
		VAL_BYTE("sanitize", NVME_LOG_LID_SANITIZE),
		VAL_BYTE("zns-changed-zones", NVME_LOG_LID_ZNS_CHANGED_ZONES),
		VAL_END()
	};

	NVME_ARGS(opts,
		  OPT_UINT("namespace-id", 'n', &cfg.namespace_id, namespace_desired),
		  OPT_BYTE("log-id",       'i', &cfg.log_id,       log_id, log_name),
		  OPT_UINT("log-len",      'l', &cfg.log_len,      log_len),
		  OPT_UINT("aen",          'a', &cfg.aen,          aen),
		  OPT_SUFFIX("lpo",        'L', &cfg.lpo,          lpo),
		  OPT_BYTE("lsp",          's', &cfg.lsp,          lsp),
		  OPT_SHRT("lsi",          'S', &cfg.lsi,          lsi),
		  OPT_FLAG("rae",          'r', &cfg.rae,          rae),
		  OPT_BYTE("uuid-index",   'U', &cfg.uuid_index,   uuid_index),
		  OPT_FLAG("raw-binary",   'b', &cfg.raw_binary,   raw),
		  OPT_BYTE("csi",          'y', &cfg.csi,          csi),
		  OPT_FLAG("ot",           'O', &cfg.ot,           offset_type),
		  OPT_UINT("xfer-len",     'x', &cfg.xfer_len,     xfer_len));

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	err = validate_output_format(nvme_cfg.output_format, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	if (cfg.aen) {
		cfg.log_len = 4096;
		cfg.log_id = (cfg.aen >> 16) & 0xff;
	}

	if (!cfg.log_len || cfg.log_len & 0x3) {
		nvme_show_error("non-zero or non-dw alignment log-len is required param");
		return -EINVAL;
	}

	if (cfg.lsp > 127) {
		nvme_show_error("invalid lsp param");
		return -EINVAL;
	}

	if (cfg.uuid_index > 127) {
		nvme_show_error("invalid uuid index param");
		return -EINVAL;
	}

	if (cfg.xfer_len == 0 || cfg.xfer_len % 4096) {
		nvme_show_error("xfer-len argument invalid. It needs to be multiple of 4k");
		return -EINVAL;
	}

	log = nvme_alloc(cfg.log_len);
	if (!log)
		return -ENOMEM;

	struct nvme_get_log_args args = {
		.nsid		= cfg.namespace_id,
		.rae		= cfg.rae,
		.lsp		= cfg.lsp,
		.lid		= cfg.log_id,
		.lsi		= cfg.lsi,
		.csi		= cfg.csi,
		.ot		= cfg.ot,
		.uidx		= cfg.uuid_index,
		.lpo		= cfg.lpo,
		.log		= log,
		.len		= cfg.log_len,
		.result		= NULL,
	};
	nvme_init_get_log(&cmd, cfg.namespace_id, cfg.log_id,
			  cfg.csi, log, cfg.log_len);
	cmd.cdw10 |= NVME_FIELD_ENCODE(cfg.lsp,
			NVME_LOG_CDW10_LSP_SHIFT,
			NVME_LOG_CDW10_LSP_MASK);
	cmd.cdw11 |= NVME_FIELD_ENCODE(cfg.lsi,
			NVME_LOG_CDW11_LSI_SHIFT,
			NVME_LOG_CDW11_LSI_MASK);
	cmd.cdw12 = cfg.lpo & 0xffffffff;
	cmd.cdw13 = cfg.lpo >> 32;
	cmd.cdw14 |= NVME_FIELD_ENCODE(cfg.uuid_index,
			NVME_LOG_CDW14_UUID_SHIFT,
			NVME_LOG_CDW14_UUID_MASK) |
		     NVME_FIELD_ENCODE(cfg.ot,
			NVME_LOG_CDW14_OT_SHIFT,
			NVME_LOG_CDW14_OT_MASK);

	err = nvme_get_log(hdl, &cmd, cfg.rae, NVME_LOG_PAGE_PDU_SIZE, NULL);
	if (!err) {
		if (!cfg.raw_binary) {
			printf("Device:%s log-id:%d namespace-id:%#x\n", nvme_transport_handle_get_name(hdl),
			       cfg.log_id, cfg.namespace_id);
			d(log, cfg.log_len, 16, 1);
			if (argconfig_parse_seen(opts, "verbose"))
				nvme_show_log(nvme_transport_handle_get_name(hdl), &args, VERBOSE);
		} else {
			d_raw((unsigned char *)log, cfg.log_len);
		}
	} else if (err > 0) {
		nvme_show_status(err);
	} else {
		nvme_show_error("log page: %s", nvme_strerror(err));
	}

	return err;
}

static int sanitize_log(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc = "Retrieve sanitize log and show it.";

	_cleanup_free_ struct nvme_sanitize_log_page *sanitize_log = NULL;
	_cleanup_nvme_global_ctx_ struct nvme_global_ctx *ctx = NULL;
	_cleanup_nvme_transport_handle_ struct nvme_transport_handle *hdl = NULL;
	nvme_print_flags_t flags;
	int err;

	struct config {
		bool	rae;
		bool	human_readable;
		bool	raw_binary;
	};

	struct config cfg = {
		.rae		= false,
		.human_readable	= false,
		.raw_binary	= false,
	};

	NVME_ARGS(opts,
		  OPT_FLAG("rae",            'r', &cfg.rae,            rae),
		  OPT_FLAG("human-readable", 'H', &cfg.human_readable, human_readable_log),
		  OPT_FLAG("raw-binary",     'b', &cfg.raw_binary,     raw_log));

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	err = validate_output_format(nvme_cfg.output_format, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	if (cfg.raw_binary)
		flags = BINARY;

	if (cfg.human_readable || argconfig_parse_seen(opts, "verbose"))
		flags |= VERBOSE;

	sanitize_log = nvme_alloc(sizeof(*sanitize_log));
	if (!sanitize_log)
		return -ENOMEM;

	err = nvme_get_log_sanitize(hdl, cfg.rae, sanitize_log);
	if (!err)
		nvme_show_sanitize_log(sanitize_log, nvme_transport_handle_get_name(hdl), flags);
	else if (err > 0)
		nvme_show_status(err);
	else
		nvme_show_error("sanitize status log: %s", nvme_strerror(err));

	return err;
}

static int get_fid_support_effects_log(int argc, char **argv, struct command *acmd,
	struct plugin *plugin)
{
	const char *desc = "Retrieve FID Support and Effects log and show it.";

	_cleanup_free_ struct nvme_fid_supported_effects_log *fid_support_log = NULL;
	_cleanup_nvme_global_ctx_ struct nvme_global_ctx *ctx = NULL;
	_cleanup_nvme_transport_handle_ struct nvme_transport_handle *hdl = NULL;
	nvme_print_flags_t flags;
	int err = -1;

	struct config {
		bool	human_readable;
	};

	struct config cfg = {
		.human_readable	= false,
	};

	NVME_ARGS(opts,
		  OPT_FLAG("human-readable", 'H', &cfg.human_readable, human_readable_log));

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	err = validate_output_format(nvme_cfg.output_format, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	if (cfg.human_readable || argconfig_parse_seen(opts, "verbose"))
		flags |= VERBOSE;

	fid_support_log = nvme_alloc(sizeof(*fid_support_log));
	if (!fid_support_log)
		return -ENOMEM;

	err = nvme_get_log_fid_supported_effects(hdl, false, fid_support_log);
	if (!err)
		nvme_show_fid_support_effects_log(fid_support_log, nvme_transport_handle_get_name(hdl), flags);
	else if (err > 0)
		nvme_show_status(err);
	else
		nvme_show_error("fid support effects log: %s", nvme_strerror(err));

	return err;
}

static int get_mi_cmd_support_effects_log(int argc, char **argv, struct command *acmd,
	struct plugin *plugin)
{
	const char *desc = "Retrieve NVMe-MI Command Support and Effects log and show it.";

	_cleanup_free_ struct nvme_mi_cmd_supported_effects_log *mi_cmd_support_log = NULL;
	_cleanup_nvme_global_ctx_ struct nvme_global_ctx *ctx = NULL;
	_cleanup_nvme_transport_handle_ struct nvme_transport_handle *hdl = NULL;
	nvme_print_flags_t flags;
	int err = -1;

	struct config {
		bool	human_readable;
	};

	struct config cfg = {
		.human_readable	= false,
	};

	NVME_ARGS(opts,
		  OPT_FLAG("human-readable", 'H', &cfg.human_readable, human_readable_log));

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	err = validate_output_format(nvme_cfg.output_format, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	if (cfg.human_readable || argconfig_parse_seen(opts, "verbose"))
		flags |= VERBOSE;

	mi_cmd_support_log = nvme_alloc(sizeof(*mi_cmd_support_log));
	if (!mi_cmd_support_log)
		return -ENOMEM;

	err = nvme_get_log_mi_cmd_supported_effects(hdl, mi_cmd_support_log);
	if (!err)
		nvme_show_mi_cmd_support_effects_log(mi_cmd_support_log, nvme_transport_handle_get_name(hdl), flags);
	else if (err > 0)
		nvme_show_status(err);
	else
		nvme_show_error("mi command support effects log: %s", nvme_strerror(err));

	return err;
}

static int list_ctrl(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc = "Show controller list information for the subsystem the "
		"given device is part of, or optionally controllers attached to a specific namespace.";
	const char *controller = "controller to display";

	_cleanup_free_ struct nvme_ctrl_list *cntlist = NULL;
	_cleanup_nvme_global_ctx_ struct nvme_global_ctx *ctx = NULL;
	_cleanup_nvme_transport_handle_ struct nvme_transport_handle *hdl = NULL;
	struct nvme_passthru_cmd cmd;
	nvme_print_flags_t flags;
	int err;

	struct config {
		__u16	cntid;
		__u32	namespace_id;
	};

	struct config cfg = {
		.cntid		= 0,
		.namespace_id	= NVME_NSID_NONE,
	};

	NVME_ARGS(opts,
		  OPT_SHRT("cntid",        'c', &cfg.cntid,         controller),
		  OPT_UINT("namespace-id", 'n', &cfg.namespace_id,  namespace_id_optional));

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	err = validate_output_format(nvme_cfg.output_format, &flags);
	if (err < 0 || (flags != JSON && flags != NORMAL)) {
		nvme_show_error("Invalid output format");
		return err;
	}

	cntlist = nvme_alloc(sizeof(*cntlist));
	if (!cntlist)
		return -ENOMEM;

	if (cfg.namespace_id == NVME_NSID_NONE)
		nvme_init_identify_ctrl_list(&cmd, cfg.cntid, cntlist);
	else
		nvme_init_identify_ns_ctrl_list(&cmd, cfg.namespace_id,
						cfg.cntid, cntlist);

	err = nvme_submit_admin_passthru(hdl, &cmd, NULL);
	if (!err)
		nvme_show_list_ctrl(cntlist, flags);
	else if (err > 0)
		nvme_show_status(err);
	else
		nvme_show_error("id controller list: %s", nvme_strerror(err));

	return err;
}

static int list_ns(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc = "For the specified controller handle, show the "
		"namespace list in the associated NVMe subsystem, optionally starting with a given nsid.";
	const char *namespace_id = "first nsid returned list should start from";
	const char *csi = "I/O command set identifier";
	const char *all = "show all namespaces in the subsystem, whether attached or inactive";

	_cleanup_free_ struct nvme_ns_list *ns_list = NULL;
	_cleanup_nvme_global_ctx_ struct nvme_global_ctx *ctx = NULL;
	_cleanup_nvme_transport_handle_ struct nvme_transport_handle *hdl = NULL;
	enum nvme_identify_cns cns;
	nvme_print_flags_t flags;
	int err;

	struct config {
		__u32	namespace_id;
		int	csi;
		bool	all;
	};

	struct config cfg = {
		.namespace_id	= 1,
		.csi		= -1,
		.all		= false,
	};

	NVME_ARGS(opts,
		  OPT_UINT("namespace-id", 'n', &cfg.namespace_id,  namespace_id),
		  OPT_INT("csi",           'y', &cfg.csi,           csi),
		  OPT_FLAG("all",          'a', &cfg.all,           all));

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	err = validate_output_format(nvme_cfg.output_format, &flags);
	if (err < 0 || (flags != JSON && flags != NORMAL)) {
		nvme_show_error("Invalid output format");
		return -EINVAL;
	}

	if (!cfg.namespace_id) {
		nvme_show_error("invalid nsid parameter");
		return -EINVAL;
	}

	if (argconfig_parse_seen(opts, "verbose"))
		flags |= VERBOSE;

	ns_list = nvme_alloc(sizeof(*ns_list));
	if (!ns_list)
		return -ENOMEM;

	if (cfg.csi < 0) {
		cns = cfg.all ? NVME_IDENTIFY_CNS_ALLOCATED_NS_LIST :
			NVME_IDENTIFY_CNS_NS_ACTIVE_LIST;
		cfg.csi = 0;
	} else 	{
		cns = cfg.all ? NVME_IDENTIFY_CNS_CSI_ALLOCATED_NS_LIST :
			NVME_IDENTIFY_CNS_CSI_NS_ACTIVE_LIST;
	}

	err = nvme_identify(hdl, cfg.namespace_id - 1, cfg.csi, cns, ns_list,
			    sizeof(*ns_list));
	if (!err)
		nvme_show_list_ns(ns_list, flags);
	else if (err > 0)
		nvme_show_status(err);
	else
		nvme_show_error("id namespace list: %s", nvme_strerror(err));

	return err;
}

static int id_ns_lba_format(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc = "Send an Identify Namespace command to the given "
		"device, returns capability field properties of the specified "
		"LBA Format index in  various formats.";

	_cleanup_nvme_global_ctx_ struct nvme_global_ctx *ctx = NULL;
	_cleanup_nvme_transport_handle_ struct nvme_transport_handle *hdl = NULL;
	_cleanup_free_ struct nvme_id_ns *ns = NULL;
	nvme_print_flags_t flags;
	int err = -1;

	struct config {
		__u16	lba_format_index;
		__u8	uuid_index;
	};

	struct config cfg = {
		.lba_format_index	= 0,
		.uuid_index		= NVME_UUID_NONE,
	};

	NVME_ARGS(opts,
		  OPT_UINT("lba-format-index", 'i', &cfg.lba_format_index, lba_format_index),
		  OPT_BYTE("uuid-index",       'U', &cfg.uuid_index,       uuid_index));

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	err = validate_output_format(nvme_cfg.output_format, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	if (argconfig_parse_seen(opts, "verbose"))
		flags |= VERBOSE;

	ns = nvme_alloc(sizeof(*ns));
	if (!ns)
		return -ENOMEM;

	err = nvme_identify_csi_ns_user_data_format(hdl, NVME_CSI_NVM,
						    cfg.lba_format_index,
						    cfg.uuid_index, ns);
	if (!err)
		nvme_show_id_ns(ns, 0, cfg.lba_format_index, true, flags);
	else if (err > 0)
		nvme_show_status(err);
	else
		nvme_show_perror("identify namespace for specific LBA format");

	return err;
}

static int id_endurance_grp_list(int argc, char **argv, struct command *acmd,
	struct plugin *plugin)
{
	const char *desc = "Show endurance group list information for the given endurance group id";
	const char *endurance_grp_id = "Endurance Group ID";

	_cleanup_free_ struct nvme_id_endurance_group_list *endgrp_list = NULL;
	_cleanup_nvme_global_ctx_ struct nvme_global_ctx *ctx = NULL;
	_cleanup_nvme_transport_handle_ struct nvme_transport_handle *hdl = NULL;
	struct nvme_passthru_cmd cmd;
	nvme_print_flags_t flags;
	int err = -1;

	struct config {
		__u16	endgrp_id;
	};

	struct config cfg = {
		.endgrp_id	= 0,
	};

	NVME_ARGS(opts,
		  OPT_SHRT("endgrp-id",    'i', &cfg.endgrp_id,     endurance_grp_id));

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	err = validate_output_format(nvme_cfg.output_format, &flags);
	if (err < 0 || (flags != JSON && flags != NORMAL)) {
		nvme_show_error("invalid output format");
		return -EINVAL;
	}

	endgrp_list = nvme_alloc(sizeof(*endgrp_list));
	if (!endgrp_list)
		return -ENOMEM;

	nvme_init_identify_endurance_group_id(&cmd, cfg.endgrp_id,
					      endgrp_list);
	err = nvme_submit_admin_passthru(hdl, &cmd, NULL);
	if (!err)
		nvme_show_endurance_group_list(endgrp_list, flags);
	else if (err > 0)
		nvme_show_status(err);
	else
		nvme_show_error("Id endurance group list: %s", nvme_strerror(err));

	return err;
}

static bool is_ns_mgmt_support(struct nvme_transport_handle *hdl)
{
	int err;

	_cleanup_free_ struct nvme_id_ctrl *ctrl = nvme_alloc(sizeof(*ctrl));

	if (ctrl)
		return false;

	err = nvme_identify_ctrl(hdl, ctrl);
	if (err)
		return false;

	return le16_to_cpu(ctrl->oacs) & NVME_CTRL_OACS_NS_MGMT;
}

static void ns_mgmt_show_status(struct nvme_transport_handle *hdl, int err, char *cmd, __u32 nsid)
{
	if (err < 0) {
		nvme_show_error("%s: %s", cmd, nvme_strerror(err));
		return;
	}

	nvme_show_init();

	if (!err) {
		nvme_show_key_value(cmd, "success");
		nvme_show_key_value("nsid", "%d", nsid);
	} else {
		nvme_show_status(err);
		if (!is_ns_mgmt_support(hdl))
			nvme_show_error("NS management and attachment not supported");
	}

	nvme_show_finish();
}

static int delete_ns(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc = "Delete the given namespace by "
		"sending a namespace management command to "
		"the provided device. All controllers should be detached from "
		"the namespace prior to namespace deletion. A namespace ID "
		"becomes inactive when that namespace is detached or, if "
		"the namespace is not already inactive, once deleted.";
	const char *namespace_id = "namespace to delete";

	_cleanup_nvme_transport_handle_ struct nvme_transport_handle *hdl = NULL;
	_cleanup_nvme_global_ctx_ struct nvme_global_ctx *ctx = NULL;
	struct nvme_passthru_cmd cmd;
	nvme_print_flags_t flags;
	int err;

	struct config {
		__u32	namespace_id;
	};

	struct config cfg = {
		.namespace_id	= 0,
	};

	NVME_ARGS(opts,
		  OPT_UINT("namespace-id", 'n', &cfg.namespace_id, namespace_id));

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	err = validate_output_format(nvme_cfg.output_format, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	if (!cfg.namespace_id) {
		err = nvme_get_nsid(hdl, &cfg.namespace_id);
		if (err < 0) {
			nvme_show_error("get-namespace-id: %s", nvme_strerror(err));
			return err;
		}
	}

	nvme_init_ns_mgmt_delete(&cmd, cfg.namespace_id);
	err = nvme_submit_admin_passthru(hdl, &cmd, NULL);
	ns_mgmt_show_status(hdl, err, acmd->name, cfg.namespace_id);

	return err;
}

static int nvme_attach_ns(int argc, char **argv, int attach, const char *desc, struct command *acmd)
{
	_cleanup_nvme_transport_handle_ struct nvme_transport_handle *hdl = NULL;
	_cleanup_nvme_global_ctx_ struct nvme_global_ctx *ctx = NULL;

	_cleanup_free_ struct nvme_ctrl_list *cntlist = NULL;
	__u16 list[NVME_ID_CTRL_LIST_MAX];
	struct nvme_passthru_cmd cmd;
	nvme_print_flags_t flags;
	int err, num;

	const char *namespace_id = "namespace to attach";
	const char *cont = "optional comma-sep controller id list";

	struct config {
		__u32	nsid;
		char	*cntlist;
	};

	struct config cfg = {
		.nsid		= 0,
		.cntlist	= "",
	};

	NVME_ARGS(opts,
		  OPT_UINT("namespace-id", 'n', &cfg.nsid,		namespace_id),
		  OPT_LIST("controllers",  'c', &cfg.cntlist,	cont));

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	err = validate_output_format(nvme_cfg.output_format, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	if (nvme_transport_handle_is_blkdev(hdl)) {
		nvme_show_error("%s: a block device opened (dev: %s, nsid: %d)", acmd->name,
				nvme_transport_handle_get_name(hdl), cfg.nsid);
		return -EINVAL;
	}

	if (!cfg.nsid) {
		nvme_show_error("%s: namespace-id parameter required", acmd->name);
		return -EINVAL;
	}

	num = argconfig_parse_comma_sep_array_u16(cfg.cntlist,
						  list, ARRAY_SIZE(list));
	if (num == -1) {
		nvme_show_error("%s: controller id list is malformed", acmd->name);
		return -EINVAL;
	}

	cntlist = nvme_alloc(sizeof(*cntlist));
	if (!cntlist)
		return -ENOMEM;

	if (argconfig_parse_seen(opts, "controllers")) {
		nvme_init_ctrl_list(cntlist, num, list);
	} else {
		struct nvme_id_ctrl ctrl = { 0 };

		err = nvme_identify_ctrl(hdl, &ctrl);
		if (err) {
			fprintf(stderr, "identify-ctrl %s\n", nvme_strerror(-err));
			return err;
		}
		cntlist->num = cpu_to_le16(1);
		cntlist->identifier[0] = ctrl.cntlid;
	}

	if (attach)
		nvme_init_ns_attach_ctrls(&cmd, cfg.nsid, cntlist);
	else
		nvme_init_ns_detach_ctrls(&cmd, cfg.nsid, cntlist);

	err = nvme_submit_admin_passthru(hdl, &cmd, NULL);
	ns_mgmt_show_status(hdl, err, acmd->name, cfg.nsid);

	return err;
}

static int attach_ns(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc = "Attach the given namespace to the "
		"given controller or comma-sep list of controllers. ID of the "
		"given namespace becomes active upon attachment to a "
		"controller. A namespace must be attached to a controller "
		"before IO commands may be directed to that namespace.";

	return nvme_attach_ns(argc, argv, 1, desc, acmd);
}

static int detach_ns(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc = "Detach the given namespace from the "
		"given controller; de-activates the given namespace's ID. A "
		"namespace must be attached to a controller before IO "
		"commands may be directed to that namespace.";

	return nvme_attach_ns(argc, argv, 0, desc, acmd);
}

static int parse_lba_num_si(struct nvme_transport_handle *hdl, const char *opt,
			    const char *val, __u8 flbas, __u64 *num, __u64 align)
{
	_cleanup_free_ struct nvme_ns_list *ns_list = NULL;
	_cleanup_free_ struct nvme_id_ctrl *ctrl = NULL;
	_cleanup_free_ struct nvme_id_ns *ns = NULL;
	__u32 nsid = 1;
	__u8 lbaf;
	unsigned int remainder;
	char *endptr;
	int err = -EINVAL;
	int lbas;

	if (!val)
		return 0;

	if (*num) {
		nvme_show_error(
		    "Invalid specification of both %s and its SI argument, please specify only one",
		    opt);
		return err;
	}

	ctrl = nvme_alloc(sizeof(*ctrl));
	if (!ctrl)
		return -ENOMEM;

	err = nvme_identify_ctrl(hdl, ctrl);
	if (err) {
		if (err < 0)
			nvme_show_error("identify controller: %s", nvme_strerror(err));
		else
			nvme_show_status(err);
		return err;
	}

	ns_list = nvme_alloc(sizeof(*ns_list));
	if (!ns_list)
		return -ENOMEM;

	if ((ctrl->oacs & 0x8) >> 3) {
		nsid = NVME_NSID_ALL;
	} else {
		err = nvme_identify_active_ns_list(hdl, nsid - 1, ns_list);
		if (err) {
			if (err < 0)
				nvme_show_error("identify namespace list: %s",
						nvme_strerror(err));
			else
				nvme_show_status(err);
			return err;
		}
		nsid = le32_to_cpu(ns_list->ns[0]);
	}

	ns = nvme_alloc(sizeof(*ns));
	if (!ns)
		return -ENOMEM;

	err = nvme_identify_ns(hdl, nsid, ns);
	if (err) {
		if (err < 0)
			nvme_show_error("identify namespace: %s", nvme_strerror(err));
		else
			nvme_show_status(err);
		return err;
	}

	nvme_id_ns_flbas_to_lbaf_inuse(flbas, &lbaf);
	lbas = (1 << ns->lbaf[lbaf].ds) + le16_to_cpu(ns->lbaf[lbaf].ms);

	err = suffix_si_parse(val, &endptr, (uint64_t *)num);
	if (err) {
		nvme_show_error("Expected long suffixed integer argument for '%s-si' but got '%s'!",
				opt, val);
		return -err;
	}

	if (endptr[0]) {
		remainder = *num % align;
		if (remainder)
			*num += align - remainder;
	}

	if (endptr[0] != '\0')
		*num /= lbas;

	return 0;
}

static int create_ns(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc = "Send a namespace management command "
		"to the specified device to create a namespace with the given "
		"parameters. The next available namespace ID is used for the "
		"create operation. Note that create-ns does not attach the "
		"namespace to a controller, the attach-ns command is needed.";
	const char *nsze = "size of ns (NSZE)";
	const char *ncap = "capacity of ns (NCAP)";
	const char *flbas =
	    "Formatted LBA size (FLBAS), if entering this value ignore \'block-size\' field";
	const char *dps = "data protection settings (DPS)";
	const char *nmic = "multipath and sharing capabilities (NMIC)";
	const char *anagrpid = "ANA Group Identifier (ANAGRPID)";
	const char *nvmsetid = "NVM Set Identifier (NVMSETID)";
	const char *csi = "command set identifier (CSI)";
	const char *lbstm = "logical block storage tag mask (LBSTM)";
	const char *nphndls = "Number of Placement Handles (NPHNDLS)";
	const char *bs = "target block size, specify only if \'FLBAS\' value not entered";
	const char *nsze_si = "size of ns (NSZE) in standard SI units";
	const char *ncap_si = "capacity of ns (NCAP) in standard SI units";
	const char *azr = "Allocate ZRWA Resources (AZR) for Zoned Namespace Command Set";
	const char *rar = "Requested Active Resources (RAR) for Zoned Namespace Command Set";
	const char *ror = "Requested Open Resources (ROR) for Zoned Namespace Command Set";
	const char *rnumzrwa =
	    "Requested Number of ZRWA Resources (RNUMZRWA) for Zoned Namespace Command Set";
	const char *phndls = "Comma separated list of Placement Handle Associated RUH";

	_cleanup_nvme_transport_handle_ struct nvme_transport_handle *hdl = NULL;
	_cleanup_free_ struct nvme_ns_mgmt_host_sw_specified *data = NULL;
	_cleanup_free_ struct nvme_id_ns_granularity_list *gr_list = NULL;
	_cleanup_nvme_global_ctx_ struct nvme_global_ctx *ctx = NULL;
	_cleanup_free_ struct nvme_id_ctrl *id = NULL;
	_cleanup_free_ struct nvme_id_ns *ns = NULL;
	__u64 align_nsze = 1 << 20; /* Default 1 MiB */
	__u64 align_ncap = align_nsze;
	struct nvme_passthru_cmd cmd;
	uint16_t phndl[128] = { 0, };
	nvme_print_flags_t flags;
	uint16_t num_phandle;
	int err = 0, i;
	__u32 nsid;

	struct config {
		__u64	nsze;
		__u64	ncap;
		__u8	flbas;
		__u8	dps;
		__u8	nmic;
		__u32	anagrpid;
		__u16	nvmsetid;
		__u16	endgid;
		__u64	bs;
		__u8	csi;
		__u64	lbstm;
		__u16	nphndls;
		char	*nsze_si;
		char	*ncap_si;
		bool	azr;
		__u32	rar;
		__u32	ror;
		__u32	rnumzrwa;
		char	*phndls;
	};

	struct config cfg = {
		.nsze		= 0,
		.ncap		= 0,
		.flbas		= 0xff,
		.dps		= 0,
		.nmic		= 0,
		.anagrpid	= 0,
		.nvmsetid	= 0,
		.endgid		= 0,
		.bs		= 0x00,
		.csi		= 0,
		.lbstm		= 0,
		.nphndls	= 0,
		.nsze_si	= NULL,
		.ncap_si	= NULL,
		.azr		= false,
		.rar		= 0,
		.ror		= 0,
		.rnumzrwa	= 0,
		.phndls		= "",
	};

	NVME_ARGS(opts,
		  OPT_SUFFIX("nsze",       's', &cfg.nsze,     nsze),
		  OPT_SUFFIX("ncap",       'c', &cfg.ncap,     ncap),
		  OPT_BYTE("flbas",        'f', &cfg.flbas,    flbas),
		  OPT_BYTE("dps",          'd', &cfg.dps,      dps),
		  OPT_BYTE("nmic",         'm', &cfg.nmic,     nmic),
		  OPT_UINT("anagrp-id",    'a', &cfg.anagrpid, anagrpid),
		  OPT_SHRT("nvmset-id",    'i', &cfg.nvmsetid, nvmsetid),
		  OPT_SHRT("endg-id",      'e', &cfg.endgid,   endgid),
		  OPT_SUFFIX("block-size", 'b', &cfg.bs,       bs),
		  OPT_BYTE("csi",          'y', &cfg.csi,      csi),
		  OPT_SUFFIX("lbstm",      'l', &cfg.lbstm,    lbstm),
		  OPT_SHRT("nphndls",      'n', &cfg.nphndls,  nphndls),
		  OPT_STR("nsze-si",       'S', &cfg.nsze_si,  nsze_si),
		  OPT_STR("ncap-si",       'C', &cfg.ncap_si,  ncap_si),
		  OPT_FLAG("azr",          'z', &cfg.azr,      azr),
		  OPT_UINT("rar",          'r', &cfg.rar,      rar),
		  OPT_UINT("ror",          'O', &cfg.ror,      ror),
		  OPT_UINT("rnumzrwa",     'u', &cfg.rnumzrwa, rnumzrwa),
		  OPT_LIST("phndls",       'p', &cfg.phndls,   phndls));

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	err = validate_output_format(nvme_cfg.output_format, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	if (cfg.flbas != 0xff && cfg.bs != 0x00) {
		nvme_show_error(
		    "Invalid specification of both FLBAS and Block Size, please specify only one");
		return -EINVAL;
	}
	if (cfg.bs) {
		if ((cfg.bs & (~cfg.bs + 1)) != cfg.bs) {
			nvme_show_error(
			    "Invalid value for block size (%"PRIu64"). Block size must be a power of two",
			    (uint64_t)cfg.bs);
			return -EINVAL;
		}


		ns = nvme_alloc(sizeof(*ns));
		if (!ns)
			return -ENOMEM;

		err = nvme_identify_ns(hdl, NVME_NSID_ALL, ns);
		if (err) {
			if (err < 0) {
				nvme_show_error("identify-namespace: %s", nvme_strerror(err));
			} else {
				fprintf(stderr, "identify failed\n");
				nvme_show_status(err);
			}
			return err;
		}
		for (i = 0; i <= ns->nlbaf; ++i) {
			if ((1 << ns->lbaf[i].ds) == cfg.bs && ns->lbaf[i].ms == 0) {
				cfg.flbas = i;
				break;
			}
		}

	}
	if (cfg.flbas == 0xff) {
		fprintf(stderr, "FLBAS corresponding to block size %"PRIu64" not found\n",
			(uint64_t)cfg.bs);
		fprintf(stderr, "Please correct block size, or specify FLBAS directly\n");

		return -EINVAL;
	}

	id = nvme_alloc(sizeof(*id));
	if (!id)
		return -ENOMEM;

	err = nvme_identify_ctrl(hdl, id);
	if (err) {
		if (err < 0) {
			nvme_show_error("identify-controller: %s", nvme_strerror(err));
		} else {
			fprintf(stderr, "identify controller failed\n");
			nvme_show_status(err);
		}
		return err;
	}

	if (id->ctratt & NVME_CTRL_CTRATT_NAMESPACE_GRANULARITY) {
		gr_list = nvme_alloc(sizeof(*gr_list));
		if (!gr_list)
			return -ENOMEM;

		if (!nvme_identify_ns_granularity(hdl, gr_list)) {
			struct nvme_id_ns_granularity_desc *desc;
			int index = cfg.flbas;

			/* FIXME: add a proper bitmask to libnvme */
			if (!(le32_to_cpu(gr_list->attributes) & 1)) {
				/* Only the first descriptor is valid */
				index = 0;
			} else if (index > gr_list->num_descriptors) {
				/*
				 * The descriptor will contain only zeroes
				 * so we don't need to read it.
				 */
				goto parse_lba;
			}
			desc = &gr_list->entry[index];

			if (desc->nszegran) {
				print_info("enforce nsze alignment to %"PRIx64
					   " because of namespace granularity requirements\n",
					   le64_to_cpu(desc->nszegran));
				align_nsze = le64_to_cpu(desc->nszegran);
			}
			if (desc->ncapgran) {
				print_info("enforce ncap alignment to %"PRIx64
					   " because of namespace granularity requirements\n",
					   le64_to_cpu(desc->ncapgran));
				align_ncap = le64_to_cpu(desc->ncapgran);
			}
		}
	}

parse_lba:
	err = parse_lba_num_si(hdl, "nsze", cfg.nsze_si, cfg.flbas, &cfg.nsze, align_nsze);
	if (err)
		return err;

	err = parse_lba_num_si(hdl, "ncap", cfg.ncap_si, cfg.flbas, &cfg.ncap, align_ncap);
	if (err)
		return err;

	if (cfg.csi != NVME_CSI_ZNS && (cfg.azr || cfg.rar || cfg.ror || cfg.rnumzrwa)) {
		nvme_show_error("Invalid ZNS argument is given (CSI:%#x)", cfg.csi);
		return -EINVAL;
	}

	data = nvme_alloc(sizeof(*data));
	if (!data)
		return -ENOMEM;

	data->nsze = cpu_to_le64(cfg.nsze);
	data->ncap = cpu_to_le64(cfg.ncap);
	data->flbas = cfg.flbas;
	data->dps = cfg.dps;
	data->nmic = cfg.nmic;
	data->anagrpid = cpu_to_le32(cfg.anagrpid);
	data->nvmsetid = cpu_to_le16(cfg.nvmsetid);
	data->endgid = cpu_to_le16(cfg.endgid);
	data->lbstm = cpu_to_le64(cfg.lbstm);
	data->zns.znsco = cfg.azr;
	data->zns.rar = cpu_to_le32(cfg.rar);
	data->zns.ror = cpu_to_le32(cfg.ror);
	data->zns.rnumzrwa = cpu_to_le32(cfg.rnumzrwa);
	data->nphndls = cpu_to_le16(cfg.nphndls);

	num_phandle = argconfig_parse_comma_sep_array_short(cfg.phndls, phndl, ARRAY_SIZE(phndl));
	if (cfg.nphndls != num_phandle) {
		nvme_show_error("Invalid Placement handle list");
		return -EINVAL;
	}

	for (i = 0; i < num_phandle; i++)
		data->phndl[i] = cpu_to_le16(phndl[i]);

	nvme_init_ns_mgmt_create(&cmd, cfg.csi, data);
	err = nvme_submit_admin_passthru(hdl, &cmd, &nsid);
	ns_mgmt_show_status(hdl, err, acmd->name, nsid);

	return err;
}

static bool nvme_match_device_filter(nvme_subsystem_t s,
		nvme_ctrl_t c, nvme_ns_t ns, void *f_args)
{
	char *devname = f_args;
	nvme_ns_t n;

	if (ns && !strcmp(devname, nvme_ns_get_name(ns)))
		return true;

	if (c) {
		s = nvme_ctrl_get_subsystem(c);
		nvme_ctrl_for_each_ns(c, n) {
			if (!strcmp(devname, nvme_ns_get_name(n)))
				return true;
		}
	}
	if (s) {
		nvme_subsystem_for_each_ns(s, n) {
			if (!strcmp(devname, nvme_ns_get_name(n)))
				return true;
		}
	}

	return false;
}

static int list_subsys(int argc, char **argv, struct command *acmd,
		struct plugin *plugin)
{
	_cleanup_nvme_global_ctx_ struct nvme_global_ctx *ctx = NULL;
	nvme_print_flags_t flags;
	const char *desc = "Retrieve information for subsystems";
	nvme_scan_filter_t filter = NULL;
	char *devname;
	int err;
	int nsid = NVME_NSID_ALL;

	NVME_ARGS(opts);

	err = parse_args(argc, argv, desc, opts);
	if (err)
		return err;

	devname = NULL;
	if (optind < argc)
		devname = basename(argv[optind++]);

	err = validate_output_format(nvme_cfg.output_format, &flags);
	if (err < 0 || (flags != JSON && flags != NORMAL)) {
		nvme_show_error("Invalid output format");
		return -EINVAL;
	}

	if (argconfig_parse_seen(opts, "verbose"))
		flags |= VERBOSE;

	ctx = nvme_create_global_ctx(stdout, log_level);
	if (!ctx) {
		if (devname)
			nvme_show_error("Failed to scan nvme subsystem for %s", devname);
		else
			nvme_show_error("Failed to scan nvme subsystem");
		return -ENOMEM;
	}

	if (devname) {
		int subsys_num;

		if (sscanf(devname, "nvme%dn%d", &subsys_num, &nsid) != 2) {
			nvme_show_error("Invalid device name %s", devname);
			return -EINVAL;
		}
		filter = nvme_match_device_filter;
	}

	err = nvme_scan_topology(ctx, filter, (void *)devname);
	if (err) {
		nvme_show_error("Failed to scan topology: %s", nvme_strerror(err));
		return -errno;
	}

	nvme_show_subsystem_list(ctx, nsid != NVME_NSID_ALL, flags);

	return 0;
}

static int list(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc = "Retrieve basic information for all NVMe namespaces";
	nvme_print_flags_t flags;
	_cleanup_nvme_global_ctx_ struct nvme_global_ctx *ctx = NULL;
	int err = 0;

	NVME_ARGS(opts);

	err = parse_args(argc, argv, desc, opts);
	if (err)
		return err;

	err = validate_output_format(nvme_cfg.output_format, &flags);
	if (err < 0 || (flags != JSON && flags != NORMAL)) {
		nvme_show_error("Invalid output format");
		return -EINVAL;
	}

	if (argconfig_parse_seen(opts, "verbose"))
		flags |= VERBOSE;

	ctx = nvme_create_global_ctx(stdout, log_level);
	if (!ctx) {
		nvme_show_error("Failed to create global context");
		return -ENOMEM;
	}
	err = nvme_scan_topology(ctx, NULL, NULL);
	if (err < 0) {
		nvme_show_error("Failed to scan topology: %s", nvme_strerror(err));
		return err;
	}

	nvme_show_list_items(ctx, flags);

	return err;
}

int __id_ctrl(int argc, char **argv, struct command *acmd, struct plugin *plugin,
		void (*vs)(__u8 *vs, struct json_object *root))
{
	const char *desc = "Send an Identify Controller command to "
		"the given device and report information about the specified "
		"controller in human-readable or "
		"binary format. May also return vendor-specific "
		"controller attributes in hex-dump if requested.";
	const char *vendor_specific = "dump binary vendor field";

	_cleanup_free_ struct nvme_id_ctrl *ctrl = NULL;
	_cleanup_nvme_global_ctx_ struct nvme_global_ctx *ctx = NULL;
	_cleanup_nvme_transport_handle_ struct nvme_transport_handle *hdl = NULL;
	nvme_print_flags_t flags;
	int err;

	struct config {
		bool	vendor_specific;
		bool	raw_binary;
		bool	human_readable;
	};

	struct config cfg = {
		.vendor_specific	= false,
		.raw_binary		= false,
		.human_readable		= false,
	};

	NVME_ARGS(opts,
		  OPT_FLAG("vendor-specific", 'V', &cfg.vendor_specific, vendor_specific),
		  OPT_FLAG("raw-binary",      'b', &cfg.raw_binary,      raw_identify),
		  OPT_FLAG("human-readable",  'H', &cfg.human_readable,  human_readable_identify));

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	err = validate_output_format(nvme_cfg.output_format, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	if (cfg.raw_binary)
		flags = BINARY;

	if (cfg.vendor_specific)
		flags |= VS;

	if (cfg.human_readable || argconfig_parse_seen(opts, "verbose"))
		flags |= VERBOSE;

	ctrl = nvme_alloc(sizeof(*ctrl));
	if (!ctrl)
		return -ENOMEM;

	err = nvme_identify_ctrl(hdl, ctrl);
	if (!err)
		nvme_show_id_ctrl(ctrl, flags, vs);
	else if (err > 0)
		nvme_show_status(err);
	else
		nvme_show_error("identify controller: %s", nvme_strerror(err));

	return err;
}

static int id_ctrl(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	return __id_ctrl(argc, argv, acmd, plugin, NULL);
}

static int nvm_id_ctrl(int argc, char **argv, struct command *acmd,
	struct plugin *plugin)
{
	const char *desc = "Send an Identify Controller NVM Command Set "
		"command to the given device and report information about "
		"the specified controller in various formats.";

	_cleanup_free_ struct nvme_id_ctrl_nvm *ctrl_nvm = NULL;
	_cleanup_nvme_global_ctx_ struct nvme_global_ctx *ctx = NULL;
	_cleanup_nvme_transport_handle_ struct nvme_transport_handle *hdl = NULL;
	struct nvme_passthru_cmd cmd;
	nvme_print_flags_t flags;
	int err = -1;

	NVME_ARGS(opts);

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	err = validate_output_format(nvme_cfg.output_format, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	if (argconfig_parse_seen(opts, "verbose"))
		flags |= VERBOSE;

	ctrl_nvm = nvme_alloc(sizeof(*ctrl_nvm));
	if (!ctrl_nvm)
		return -ENOMEM;

	nvme_init_identify_csi_ctrl(&cmd, NVME_CSI_NVM, ctrl_nvm);
	err = nvme_submit_admin_passthru(hdl, &cmd, NULL);
	if (!err)
		nvme_show_id_ctrl_nvm(ctrl_nvm, flags);
	else if (err > 0)
		nvme_show_status(err);
	else
		nvme_show_error("nvm identify controller: %s", nvme_strerror(err));

	return err;
}

static int nvm_id_ns(int argc, char **argv, struct command *acmd,
	struct plugin *plugin)
{
	const char *desc = "Send an Identify Namespace NVM Command Set "
		"command to the given device and report information about "
		"the specified namespace in various formats.";

	_cleanup_free_ struct nvme_nvm_id_ns *id_ns = NULL;
	_cleanup_free_ struct nvme_id_ns *ns = NULL;
	_cleanup_nvme_global_ctx_ struct nvme_global_ctx *ctx = NULL;
	_cleanup_nvme_transport_handle_ struct nvme_transport_handle *hdl = NULL;
	nvme_print_flags_t flags;
	int err = -1;

	struct config {
		__u32	namespace_id;
		__u8	uuid_index;
	};

	struct config cfg = {
		.namespace_id	= 0,
		.uuid_index	= NVME_UUID_NONE,
	};

	NVME_ARGS(opts,
		  OPT_UINT("namespace-id", 'n', &cfg.namespace_id,    namespace_id_desired),
		  OPT_BYTE("uuid-index",   'U', &cfg.uuid_index,      uuid_index));

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	err = validate_output_format(nvme_cfg.output_format, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	if (argconfig_parse_seen(opts, "verbose"))
		flags |= VERBOSE;

	if (!cfg.namespace_id) {
		err = nvme_get_nsid(hdl, &cfg.namespace_id);
		if (err < 0) {
			nvme_show_perror("get-namespace-id");
			return err;
		}
	}

	ns = nvme_alloc(sizeof(*ns));
	if (!ns)
		return -ENOMEM;

	err = nvme_identify_ns(hdl, cfg.namespace_id, ns);
	if (err) {
		nvme_show_status(err);
		return err;
	}

	id_ns = nvme_alloc(sizeof(*id_ns));
	if (!id_ns)
		return -ENOMEM;

	err = nvme_identify_csi_ns(hdl, cfg.namespace_id, NVME_CSI_NVM,
				   cfg.uuid_index, id_ns);
	if (!err)
		nvme_show_nvm_id_ns(id_ns, cfg.namespace_id, ns, 0, false, flags);
	else if (err > 0)
		nvme_show_status(err);
	else
		nvme_show_perror("nvm identify namespace");

	return err;
}

static int nvm_id_ns_lba_format(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc = "Send an NVM Command Set specific Identify Namespace "
		"command to the given device, returns capability field properties of "
		"the specified LBA Format index in the specified namespace in various formats.";

	_cleanup_free_ struct nvme_nvm_id_ns *nvm_ns = NULL;
	_cleanup_free_ struct nvme_id_ns *ns = NULL;
	_cleanup_nvme_global_ctx_ struct nvme_global_ctx *ctx = NULL;
	_cleanup_nvme_transport_handle_ struct nvme_transport_handle *hdl = NULL;
	nvme_print_flags_t flags;
	int err = -1;

	struct config {
		__u16	lba_format_index;
		__u8	uuid_index;
	};

	struct config cfg = {
		.lba_format_index	= 0,
		.uuid_index		= NVME_UUID_NONE,
	};

	NVME_ARGS(opts,
		  OPT_UINT("lba-format-index", 'i', &cfg.lba_format_index, lba_format_index),
		  OPT_BYTE("uuid-index",       'U', &cfg.uuid_index,       uuid_index));

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	err = validate_output_format(nvme_cfg.output_format, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	if (argconfig_parse_seen(opts, "verbose"))
		flags |= VERBOSE;

	ns = nvme_alloc(sizeof(*ns));
	if (!ns)
		return -ENOMEM;

	err = nvme_identify_ns(hdl, NVME_NSID_ALL, ns);
	if (err) {
		ns->nlbaf = NVME_FEAT_LBA_RANGE_MAX - 1;
		ns->nulbaf = 0;
	}

	nvm_ns = nvme_alloc(sizeof(*nvm_ns));
	if (!nvm_ns)
		return -ENOMEM;

	err = nvme_identify_csi_ns_user_data_format(hdl, NVME_CSI_NVM,
						    cfg.lba_format_index,
						    cfg.uuid_index, nvm_ns);
	if (!err)
		nvme_show_nvm_id_ns(nvm_ns, 0, ns, cfg.lba_format_index, true, flags);
	else if (err > 0)
		nvme_show_status(err);
	else
		nvme_show_perror("NVM identify namespace for specific LBA format");

	return err;
}

static int ns_descs(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc = "Send Namespace Identification Descriptors command to the "
		"given device, returns the namespace identification descriptors "
		"of the specific namespace in either human-readable or binary format.";
	const char *raw = "show descriptors in binary format";

	_cleanup_nvme_global_ctx_ struct nvme_global_ctx *ctx = NULL;
	_cleanup_nvme_transport_handle_ struct nvme_transport_handle *hdl = NULL;
	_cleanup_free_ void *nsdescs = NULL;
	nvme_print_flags_t flags;
	int err;

	struct config {
		__u32	namespace_id;
		bool	raw_binary;
	};

	struct config cfg = {
		.namespace_id	= 0,
		.raw_binary	= false,
	};

	NVME_ARGS(opts,
		  OPT_UINT("namespace-id",  'n', &cfg.namespace_id,  namespace_id_desired),
		  OPT_FLAG("raw-binary",    'b', &cfg.raw_binary,    raw));

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	err = validate_output_format(nvme_cfg.output_format, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	if (cfg.raw_binary)
		flags = BINARY;

	if (argconfig_parse_seen(opts, "verbose"))
		flags |= VERBOSE;

	if (!cfg.namespace_id) {
		err = nvme_get_nsid(hdl, &cfg.namespace_id);
		if (err < 0) {
			nvme_show_error("get-namespace-id: %s", nvme_strerror(err));
			return err;
		}
	}

	nsdescs = nvme_alloc(NVME_IDENTIFY_DATA_SIZE);
	if (!nsdescs)
		return -ENOMEM;

	err = nvme_identify_ns_descs_list(hdl, cfg.namespace_id, nsdescs);
	if (!err)
		nvme_show_id_ns_descs(nsdescs, cfg.namespace_id, flags);
	else if (err > 0)
		nvme_show_status(err);
	else
		nvme_show_error("identify namespace: %s", nvme_strerror(err));

	return err;
}

static int id_ns(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc = "Send an Identify Namespace command to the "
		"given device, returns properties of the specified namespace "
		"in either human-readable or binary format. Can also return "
		"binary vendor-specific namespace attributes.";
	const char *force = "Return this namespace, even if not attached (1.2 devices only)";
	const char *vendor_specific = "dump binary vendor fields";

	_cleanup_nvme_global_ctx_ struct nvme_global_ctx *ctx = NULL;
	_cleanup_nvme_transport_handle_ struct nvme_transport_handle *hdl = NULL;
	_cleanup_free_ struct nvme_id_ns *ns = NULL;
	struct nvme_passthru_cmd cmd;
	nvme_print_flags_t flags;
	int err;

	struct config {
		__u32	namespace_id;
		bool	force;
		bool	vendor_specific;
		bool	raw_binary;
		bool	human_readable;
	};

	struct config cfg = {
		.namespace_id		= 0,
		.force			= false,
		.vendor_specific	= false,
		.raw_binary		= false,
		.human_readable		= false,
	};

	NVME_ARGS(opts,
		  OPT_UINT("namespace-id",    'n', &cfg.namespace_id,    namespace_id_desired),
		  OPT_FLAG("force",             0, &cfg.force,           force),
		  OPT_FLAG("vendor-specific", 'V', &cfg.vendor_specific, vendor_specific),
		  OPT_FLAG("raw-binary",      'b', &cfg.raw_binary,      raw_identify),
		  OPT_FLAG("human-readable",  'H', &cfg.human_readable,  human_readable_identify));

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	err = validate_output_format(nvme_cfg.output_format, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	if (cfg.raw_binary)
		flags = BINARY;

	if (cfg.vendor_specific)
		flags |= VS;

	if (cfg.human_readable || argconfig_parse_seen(opts, "verbose"))
		flags |= VERBOSE;

	if (!cfg.namespace_id) {
		err = nvme_get_nsid(hdl, &cfg.namespace_id);
		if (err < 0) {
			nvme_show_error("get-namespace-id: %s", nvme_strerror(err));
			return err;
		}
	}

	ns = nvme_alloc(sizeof(*ns));
	if (!ns)
		return -ENOMEM;

	if (cfg.force) {
		nvme_init_identify_allocated_ns(&cmd, cfg.namespace_id, ns);
		err = nvme_submit_admin_passthru(hdl, &cmd, NULL);
	} else {
		err = nvme_identify_ns(hdl, cfg.namespace_id, ns);
	}

	if (!err)
		nvme_show_id_ns(ns, cfg.namespace_id, 0, false, flags);
	else if (err > 0)
		nvme_show_status(err);
	else
		nvme_show_error("identify namespace: %s", nvme_strerror(err));

	return err;
}

static int cmd_set_independent_id_ns(int argc, char **argv, struct command *acmd,
				     struct plugin *plugin)
{
	const char *desc = "Send an I/O Command Set Independent Identify "
		"Namespace command to the given device, returns properties of the "
		"specified namespace in human-readable or binary or json format.";

	_cleanup_free_ struct nvme_id_independent_id_ns *ns = NULL;
	_cleanup_nvme_global_ctx_ struct nvme_global_ctx *ctx = NULL;
	_cleanup_nvme_transport_handle_ struct nvme_transport_handle *hdl = NULL;
	struct nvme_passthru_cmd cmd;
	nvme_print_flags_t flags;
	int err = -1;

	struct config {
		__u32	namespace_id;
		bool	raw_binary;
		bool	human_readable;
	};

	struct config cfg = {
		.namespace_id	= 0,
		.raw_binary	= false,
		.human_readable	= false,
	};

	NVME_ARGS(opts,
		  OPT_UINT("namespace-id",    'n', &cfg.namespace_id,    namespace_id_desired),
		  OPT_FLAG("raw-binary",      'b', &cfg.raw_binary,      raw_identify),
		  OPT_FLAG("human-readable",  'H', &cfg.human_readable,  human_readable_identify));

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	err = validate_output_format(nvme_cfg.output_format, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	if (cfg.raw_binary)
		flags = BINARY;

	if (cfg.human_readable || argconfig_parse_seen(opts, "verbose"))
		flags |= VERBOSE;

	if (!cfg.namespace_id) {
		err = nvme_get_nsid(hdl, &cfg.namespace_id);
		if (err < 0) {
			nvme_show_perror("get-namespace-id");
			return err;
		}
	}

	ns = nvme_alloc(sizeof(*ns));
	if (!ns)
		return -ENOMEM;

	nvme_init_identify_csi_independent_identify_id_ns(&cmd,
							  cfg.namespace_id, ns);
	err = nvme_submit_admin_passthru(hdl, &cmd, NULL);
	if (!err)
		nvme_show_cmd_set_independent_id_ns(ns, cfg.namespace_id, flags);
	else if (err > 0)
		nvme_show_status(err);
	else
		nvme_show_error("I/O command set independent identify namespace: %s",
				nvme_strerror(err));

	return err;
}

static int id_ns_granularity(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc = "Send an Identify Namespace Granularity List command to the "
		"given device, returns namespace granularity list "
		"in either human-readable or binary format.";

	_cleanup_free_ struct nvme_id_ns_granularity_list *granularity_list = NULL;
	_cleanup_nvme_global_ctx_ struct nvme_global_ctx *ctx = NULL;
	_cleanup_nvme_transport_handle_ struct nvme_transport_handle *hdl = NULL;
	nvme_print_flags_t flags;
	int err;

	NVME_ARGS(opts);

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	err = validate_output_format(nvme_cfg.output_format, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	granularity_list = nvme_alloc(NVME_IDENTIFY_DATA_SIZE);
	if (!granularity_list)
		return -ENOMEM;

	err = nvme_identify_ns_granularity(hdl, granularity_list);
	if (!err)
		nvme_show_id_ns_granularity_list(granularity_list, flags);
	else if (err > 0)
		nvme_show_status(err);
	else
		nvme_show_error("identify namespace granularity: %s", nvme_strerror(err));

	return err;
}

static int id_nvmset(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc = "Send an Identify NVM Set List command to the "
		"given device, returns entries for NVM Set identifiers greater "
		"than or equal to the value specified CDW11.NVMSETID "
		"in either binary format or json format";
	const char *nvmset_id = "NVM Set Identify value";

	_cleanup_free_ struct nvme_id_nvmset_list *nvmset = NULL;
	_cleanup_nvme_global_ctx_ struct nvme_global_ctx *ctx = NULL;
	_cleanup_nvme_transport_handle_ struct nvme_transport_handle *hdl = NULL;
	struct nvme_passthru_cmd cmd;
	nvme_print_flags_t flags;
	int err;

	struct config {
		__u16	nvmset_id;
	};

	struct config cfg = {
		.nvmset_id	= 0,
	};

	NVME_ARGS(opts,
		  OPT_SHRT("nvmset_id",    'i', &cfg.nvmset_id,     nvmset_id));

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	err = validate_output_format(nvme_cfg.output_format, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	nvmset = nvme_alloc(sizeof(*nvmset));
	if (!nvmset)
		return -ENOMEM;

	nvme_init_identify_nvmset_list(&cmd, NVME_NSID_NONE,
				       cfg.nvmset_id, nvmset);
	err = nvme_submit_admin_passthru(hdl, &cmd, NULL);
	if (!err)
		nvme_show_id_nvmset(nvmset, cfg.nvmset_id, flags);
	else if (err > 0)
		nvme_show_status(err);
	else
		nvme_show_error("identify nvm set list: %s", nvme_strerror(err));

	return err;
}

static int id_uuid(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc = "Send an Identify UUID List command to the "
		"given device, returns list of supported Vendor Specific UUIDs "
		"in either human-readable or binary format.";
	const char *raw = "show uuid in binary format";
	const char *human_readable = "show uuid in readable format";

	_cleanup_free_ struct nvme_id_uuid_list *uuid_list = NULL;
	_cleanup_nvme_global_ctx_ struct nvme_global_ctx *ctx = NULL;
	_cleanup_nvme_transport_handle_ struct nvme_transport_handle *hdl = NULL;
	nvme_print_flags_t flags;
	int err;

	struct config {
		bool	raw_binary;
		bool	human_readable;
	};

	struct config cfg = {
		.raw_binary	= false,
		.human_readable	= false,
	};

	NVME_ARGS(opts,
		  OPT_FLAG("raw-binary",     'b', &cfg.raw_binary,     raw),
		  OPT_FLAG("human-readable", 'H', &cfg.human_readable, human_readable));

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	err = validate_output_format(nvme_cfg.output_format, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	if (cfg.raw_binary)
		flags = BINARY;

	if (cfg.human_readable || argconfig_parse_seen(opts, "verbose"))
		flags |= VERBOSE;

	uuid_list = nvme_alloc(sizeof(*uuid_list));
	if (!uuid_list)
		return -ENOMEM;

	err = nvme_identify_uuid_list(hdl, uuid_list);
	if (!err)
		nvme_show_id_uuid_list(uuid_list, flags);
	else if (err > 0)
		nvme_show_status(err);
	else
		nvme_show_error("identify UUID list: %s", nvme_strerror(err));

	return err;
}

static int id_iocs(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc = "Send an Identify Command Set Data command to "
		"the given device, returns properties of the specified controller "
		"in either human-readable or binary format.";
	const char *controller_id = "identifier of desired controller";

	_cleanup_free_ struct nvme_id_iocs *iocs = NULL;
	_cleanup_nvme_global_ctx_ struct nvme_global_ctx *ctx = NULL;
	_cleanup_nvme_transport_handle_ struct nvme_transport_handle *hdl = NULL;
	struct nvme_passthru_cmd cmd;
	nvme_print_flags_t flags;
	int err;

	struct config {
		__u16	cntid;
	};

	struct config cfg = {
		.cntid	= 0xffff,
	};

	NVME_ARGS(opts,
		  OPT_SHRT("controller-id", 'c', &cfg.cntid, controller_id));

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	err = validate_output_format(nvme_cfg.output_format, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	if (argconfig_parse_seen(opts, "verbose"))
		flags |= VERBOSE;

	iocs = nvme_alloc(sizeof(*iocs));
	if (!iocs)
		return -ENOMEM;

	nvme_init_identify_command_set_structure(&cmd, cfg.cntid, iocs);
	err = nvme_submit_admin_passthru(hdl, &cmd, NULL);
	if (!err) {
		printf("NVMe Identify I/O Command Set:\n");
		nvme_show_id_iocs(iocs, flags);
	} else if (err > 0) {
		nvme_show_status(err);
	} else {
		nvme_show_error("NVMe Identify I/O Command Set: %s", nvme_strerror(err));
	}

	return err;
}

static int id_domain(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc = "Send an Identify Domain List command to the "
		"given device, returns properties of the specified domain "
		"in either normal|json|binary format.";
	const char *domain_id = "identifier of desired domain";

	_cleanup_free_ struct nvme_id_domain_list *id_domain = NULL;
	_cleanup_nvme_global_ctx_ struct nvme_global_ctx *ctx = NULL;
	_cleanup_nvme_transport_handle_ struct nvme_transport_handle *hdl = NULL;
	struct nvme_passthru_cmd cmd;
	nvme_print_flags_t flags;
	int err;

	struct config {
		__u16	dom_id;
	};

	struct config cfg = {
		.dom_id		= 0xffff,
	};

	NVME_ARGS(opts,
		  OPT_SHRT("dom-id",         'd', &cfg.dom_id,         domain_id));

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	err = validate_output_format(nvme_cfg.output_format, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	id_domain = nvme_alloc(sizeof(*id_domain));
	if (!id_domain)
		return -ENOMEM;

	nvme_init_identify_domain_list(&cmd, cfg.dom_id, id_domain);
	err = nvme_submit_admin_passthru(hdl, &cmd, NULL);
	if (!err) {
		printf("NVMe Identify command for Domain List is successful:\n");
		printf("NVMe Identify Domain List:\n");
		nvme_show_id_domain_list(id_domain, flags);
	} else if (err > 0) {
		nvme_show_status(err);
	} else {
		nvme_show_error("NVMe Identify Domain List: %s", nvme_strerror(err));
	}

	return err;
}

static int get_ns_id(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc = "Get namespace ID of a the block device.";

	_cleanup_nvme_global_ctx_ struct nvme_global_ctx *ctx = NULL;
	_cleanup_nvme_transport_handle_ struct nvme_transport_handle *hdl = NULL;
	unsigned int nsid;
	int err;
	nvme_print_flags_t flags;

	NVME_ARGS(opts);

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	err = validate_output_format(nvme_cfg.output_format, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	err = nvme_get_nsid(hdl, &nsid);
	if (err < 0) {
		nvme_show_error("get namespace ID: %s", nvme_strerror(err));
		return -errno;
	}

	printf("%s: namespace-id:%d\n", nvme_transport_handle_get_name(hdl), nsid);

	return 0;
}

static int virtual_mgmt(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc = "The Virtualization Management command is supported by primary controllers "
		"that support the Virtualization Enhancements capability. This command is used for:\n"
		"  1. Modifying Flexible Resource allocation for the primary controller\n"
		"  2. Assigning Flexible Resources for secondary controllers\n"
		"  3. Setting the Online and Offline state for secondary controllers";
	const char *cntlid = "Controller Identifier(CNTLID)";
	const char *rt = "Resource Type(RT): [0,1]\n"
		"0h: VQ Resources\n"
		"1h: VI Resources";
	const char *act = "Action(ACT): [1,7,8,9]\n"
		"1h: Primary Flexible\n"
		"7h: Secondary Offline\n"
		"8h: Secondary Assign\n"
		"9h: Secondary Online";
	const char *nr = "Number of Controller Resources(NR)";

	_cleanup_nvme_transport_handle_ struct nvme_transport_handle *hdl = NULL;
	_cleanup_nvme_global_ctx_ struct nvme_global_ctx *ctx = NULL;
	struct nvme_passthru_cmd cmd;
	__u32 result;
	int err;

	struct config {
		__u16	cntlid;
		__u8	rt;
		__u8	act;
		__u16	nr;
	};

	struct config cfg = {
		.cntlid	= 0,
		.rt	= 0,
		.act	= 0,
		.nr	= 0,
	};

	NVME_ARGS(opts,
		  OPT_SHRT("cntlid", 'c', &cfg.cntlid, cntlid),
		  OPT_BYTE("rt",     'r', &cfg.rt,     rt),
		  OPT_BYTE("act",    'a', &cfg.act,    act),
		  OPT_SHRT("nr",     'n', &cfg.nr,     nr));

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	nvme_init_virtual_mgmt(&cmd, cfg.act, cfg.rt, cfg.cntlid, cfg.nr);
	err = nvme_submit_admin_passthru(hdl, &cmd, &result);
	if (!err)
		printf("success, Number of Controller Resources Modified (NRM):%#x\n", result);
	else if (err > 0)
		nvme_show_status(err);
	else
		nvme_show_error("virt-mgmt: %s", nvme_strerror(err));

	return err;
}

static int primary_ctrl_caps(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *cntlid = "Controller ID";
	const char *desc = "Send an Identify Primary Controller Capabilities "
		"command to the given device and report the information in a "
		"decoded format (default), json or binary.";

	_cleanup_free_ struct nvme_primary_ctrl_cap *caps = NULL;
	_cleanup_nvme_global_ctx_ struct nvme_global_ctx *ctx = NULL;
	_cleanup_nvme_transport_handle_ struct nvme_transport_handle *hdl = NULL;
	struct nvme_passthru_cmd cmd;
	nvme_print_flags_t flags;
	int err;

	struct config {
		__u16	cntlid;
		bool	human_readable;
	};

	struct config cfg = {
		.cntlid		= 0,
		.human_readable	= false,
	};

	NVME_ARGS(opts,
		  OPT_UINT("cntlid",         'c', &cfg.cntlid, cntlid),
		  OPT_FLAG("human-readable", 'H', &cfg.human_readable, human_readable_info));

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	err = validate_output_format(nvme_cfg.output_format, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	if (cfg.human_readable || argconfig_parse_seen(opts, "verbose"))
		flags |= VERBOSE;

	caps = nvme_alloc(sizeof(*caps));
	if (!caps)
		return -ENOMEM;

	nvme_init_identify_primary_ctrl_cap(&cmd, cfg.cntlid, caps);
	err = nvme_submit_admin_passthru(hdl, &cmd, NULL);
	if (!err)
		nvme_show_primary_ctrl_cap(caps, flags);
	else if (err > 0)
		nvme_show_status(err);
	else
		nvme_show_error("identify primary controller capabilities: %s",
				nvme_strerror(err));

	return err;
}

static int list_secondary_ctrl(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc =
	    "Show secondary controller list associated with the primary controller of the given device.";
	const char *controller = "lowest controller identifier to display";
	const char *num_entries = "number of entries to retrieve";

	_cleanup_free_ struct nvme_secondary_ctrl_list *sc_list = NULL;
	_cleanup_nvme_global_ctx_ struct nvme_global_ctx *ctx = NULL;
	_cleanup_nvme_transport_handle_ struct nvme_transport_handle *hdl = NULL;
	struct nvme_passthru_cmd cmd;
	nvme_print_flags_t flags;
	int err;

	struct config {
		__u16	cntid;
		__u32	num_entries;
	};

	struct config cfg = {
		.cntid		= 0,
		.num_entries	= ARRAY_SIZE(sc_list->sc_entry),
	};

	NVME_ARGS(opts,
		  OPT_SHRT("cntid",        'c', &cfg.cntid,         controller),
		  OPT_UINT("num-entries",  'e', &cfg.num_entries,   num_entries));

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	err = validate_output_format(nvme_cfg.output_format, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	if (!cfg.num_entries) {
		nvme_show_error("non-zero num-entries is required param");
		return -EINVAL;
	}

	sc_list = nvme_alloc(sizeof(*sc_list));
	if (!sc_list)
		return -ENOMEM;

	nvme_init_identify_secondary_ctrl_list(&cmd, cfg.cntid, sc_list);
	err = nvme_submit_admin_passthru(hdl, &cmd, NULL);
	if (!err)
		nvme_show_list_secondary_ctrl(sc_list, cfg.num_entries, flags);
	else if (err > 0)
		nvme_show_status(err);
	else
		nvme_show_error("id secondary controller list: %s", nvme_strerror(err));

	return err;
}

static int sleep_self_test(unsigned int seconds)
{
	nvme_sigint_received = false;

	sleep(seconds);

	if (nvme_sigint_received) {
		printf("\nInterrupted device self-test operation by SIGINT\n");
		return -SIGINT;
	}

	return 0;
}

static int wait_self_test(struct nvme_transport_handle *hdl)
{
	static const char spin[] = {'-', '\\', '|', '/' };
	_cleanup_free_ struct nvme_self_test_log *log = NULL;
	_cleanup_free_ struct nvme_id_ctrl *ctrl = NULL;
	int err, i = 0, p = 0, cnt = 0;
	int wthr;

	ctrl = nvme_alloc(sizeof(*ctrl));
	if (!ctrl)
		return -ENOMEM;

	log = nvme_alloc(sizeof(*log));
	if (!log)
		return -ENOMEM;

	err = nvme_identify_ctrl(hdl, ctrl);
	if (err) {
		nvme_show_error("identify-ctrl: %s", nvme_strerror(err));
		return err;
	}

	wthr = le16_to_cpu(ctrl->edstt) * 60 / 100 + 60;

	printf("Waiting for self test completion...\n");
	while (true) {
		printf("\r[%.*s%c%.*s] %3d%%", p / 2, dash, spin[i % 4], 49 - p / 2, space, p);
		fflush(stdout);
		err = sleep_self_test(1);
		if (err)
			return err;

		err = nvme_get_log_device_self_test(hdl, log);
		if (err) {
			printf("\n");
			if (err < 0)
				perror("self test log\n");
			else
				nvme_show_status(err);
			return err;
		}

		if (++cnt > wthr) {
			nvme_show_error("no progress for %d seconds, stop waiting", wthr);
			return -EIO;
		}

		if (log->completion == 0 && p > 0) {
			printf("\r[%.*s] %3d%%\n", 50, dash, 100);
			break;
		}

		if (log->completion < p) {
			printf("\n");
				nvme_show_error("progress broken");
				return -EIO;
		} else if (log->completion != p) {
			p = log->completion;
			cnt = 0;
		}

		i++;
	}

	return 0;
}

static void abort_self_test(struct nvme_transport_handle *hdl, __u32 nsid)
{
	struct nvme_passthru_cmd cmd;
	int err;

	nvme_init_dev_self_test(&cmd, nsid, NVME_DST_STC_ABORT);
	err = nvme_submit_admin_passthru(hdl, &cmd, NULL);
	if (!err)
		printf("Aborting device self-test operation\n");
	else if (err > 0)
		nvme_show_status(err);
	else
		nvme_show_error("Device self-test: %s", nvme_strerror(err));
}

static int device_self_test(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc = "Implementing the device self-test feature "
		"which provides the necessary log to determine the state of the device";
	const char *namespace_id =
	    "Indicate the namespace in which the device self-test has to be carried out";
	const char *self_test_code =
		"This field specifies the action taken by the device self-test command :\n"
		"0h Show current state of device self-test operation\n"
		"1h Start a short device self-test operation\n"
		"2h Start a extended device self-test operation\n"
		"3h Start a Host-Initiated Refresh operation\n"
		"eh Start a vendor specific device self-test operation\n"
		"fh Abort the device self-test operation";
	const char *wait = "Wait for the test to finish";

	_cleanup_nvme_transport_handle_ struct nvme_transport_handle *hdl = NULL;
	_cleanup_nvme_global_ctx_ struct nvme_global_ctx *ctx = NULL;
	struct nvme_passthru_cmd cmd;
	nvme_print_flags_t flags;
	int err;

	struct config {
		__u32	namespace_id;
		__u8	stc;
		bool	wait;
	};

	struct config cfg = {
		.namespace_id	= NVME_NSID_ALL,
		.stc		= NVME_ST_CODE_RESERVED,
		.wait		= false,
	};

	NVME_ARGS(opts,
		  OPT_UINT("namespace-id",   'n', &cfg.namespace_id, namespace_id),
		  OPT_BYTE("self-test-code", 's', &cfg.stc,          self_test_code),
		  OPT_FLAG("wait",           'w', &cfg.wait,         wait));

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	err = validate_output_format(nvme_cfg.output_format, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	if (cfg.stc == NVME_ST_CODE_RESERVED) {
		_cleanup_free_ struct nvme_self_test_log *log = NULL;

		log = nvme_alloc(sizeof(*log));
		if (!log)
			return -ENOMEM;

		err = nvme_get_log_device_self_test(hdl, log);
		if (err) {
			printf("\n");
			if (err < 0)
				perror("self test log\n");
			else
				nvme_show_status(err);
		}

		if (log->completion == 0) {
			printf("no self test running\n");
		} else {
			if (cfg.wait)
				err = wait_self_test(hdl);
			else
				printf("progress %d%%\n", log->completion);
		}

		goto check_abort;
	}

	nvme_init_dev_self_test(&cmd, cfg.namespace_id, cfg.stc);
	err = nvme_submit_admin_passthru(hdl, &cmd, NULL);
	if (!err) {
		if (cfg.stc == NVME_ST_CODE_ABORT)
			printf("Aborting device self-test operation\n");
		else if (cfg.stc == NVME_ST_CODE_EXTENDED)
			printf("Extended Device self-test started\n");
		else if (cfg.stc == NVME_ST_CODE_SHORT)
			printf("Short Device self-test started\n");
		else if (cfg.stc == NVME_ST_CODE_HOST_INIT)
			printf("Host-Initiated Refresh started\n");

		if (cfg.wait && cfg.stc != NVME_ST_CODE_ABORT)
			err = wait_self_test(hdl);
	} else if (err > 0) {
		nvme_show_status(err);
	} else {
		nvme_show_error("Device self-test: %s", nvme_strerror(err));
	}

check_abort:
	if (err == -EINTR)
		abort_self_test(hdl, cfg.namespace_id);

	return err;
}

static int self_test_log(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc = "Retrieve the self-test log for the given device and given test "
		"(or optionally a namespace) in either decoded format (default) or binary.";
	const char *dst_entries = "Indicate how many DST log entries to be retrieved, "
		"by default all the 20 entries will be retrieved";

	_cleanup_free_ struct nvme_self_test_log *log = NULL;
	_cleanup_nvme_global_ctx_ struct nvme_global_ctx *ctx = NULL;
	_cleanup_nvme_transport_handle_ struct nvme_transport_handle *hdl = NULL;
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

	err = validate_output_format(nvme_cfg.output_format, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	if (argconfig_parse_seen(opts, "verbose"))
		flags |= VERBOSE;

	log = nvme_alloc(sizeof(*log));
	if (!log)
		return -ENOMEM;

	err = nvme_get_log_device_self_test(hdl, log);
	if (!err)
		nvme_show_self_test_log(log, cfg.dst_entries, 0, nvme_transport_handle_get_name(hdl), flags);
	else if (err > 0)
		nvme_show_status(err);
	else
		nvme_show_error("self test log: %s", nvme_strerror(err));

	return err;
}

static int get_feature_id(struct nvme_transport_handle *hdl, struct feat_cfg *cfg,
			  void **buf, __u32 *result)
{
	if (!cfg->data_len)
		nvme_get_feature_length(cfg->feature_id, cfg->cdw11,
					NVME_DATA_TFR_CTRL_TO_HOST,	
					&cfg->data_len);

	if (cfg->feature_id == NVME_FEAT_FID_FDP_EVENTS) {
		cfg->data_len = 0xff * sizeof(__u16);
		cfg->cdw11 |= 0xff << 16;
	}

	if (NVME_CHECK(cfg->sel, GET_FEATURES_SEL, SUPPORTED))
		cfg->data_len = 0;

	if (cfg->data_len) {
		*buf = nvme_alloc(cfg->data_len - 1);
		if (!*buf)
			return -1;
	}

	return nvme_get_features(hdl, cfg->namespace_id, cfg->feature_id, cfg->sel,
			cfg->cdw11, cfg->uuid_index, *buf, cfg->data_len, result);
}

static int filter_out_flags(int status)
{
	return status & (NVME_VAL(SCT) | NVME_VAL(SC));
}

static void get_feature_id_print(struct feat_cfg cfg, int err, __u32 result,
		void *buf, nvme_print_flags_t flags)
{
	int status = filter_out_flags(err);
	int verbose = flags & VERBOSE;
	enum nvme_status_type type = NVME_STATUS_TYPE_NVME;

	if (!err) {
		if (!cfg.raw_binary || !buf) {
			nvme_feature_show(cfg.feature_id, cfg.sel, result);
			if (NVME_CHECK(cfg.sel, GET_FEATURES_SEL, SUPPORTED))
				nvme_show_select_result(cfg.feature_id, result);
			else if (verbose || !strcmp(nvme_cfg.output_format, "json"))
				nvme_feature_show_fields(cfg.feature_id, result, buf);
			else if (buf)
				d(buf, cfg.data_len, 16, 1);
		} else if (buf) {
			d_raw(buf, cfg.data_len);
		}
	} else if (err > 0) {
		if (!nvme_status_equals(status, type, NVME_SC_INVALID_FIELD) &&
		    !nvme_status_equals(status, type, NVME_SC_INVALID_NS))
			nvme_show_status(err);
	} else {
		nvme_show_error("get-feature: %s", nvme_strerror(err));
	}
}

static bool is_get_feature_result_set(enum nvme_features_id feature_id)
{
	switch (feature_id) {
	case NVME_FEAT_FID_PERF_CHARACTERISTICS:
		return false;
	default:
		break;
	}

	return true;
}

static int get_feature_id_changed(struct nvme_transport_handle *hdl, struct feat_cfg cfg,
		nvme_print_flags_t flags)
{
	int err;
	int err_def = 0;
	__u32 result;
	__u32 result_def;
	_cleanup_free_ void *buf = NULL;
	_cleanup_free_ void *buf_def = NULL;

	if (cfg.changed)
		cfg.sel = NVME_GET_FEATURES_SEL_CURRENT;

	err = get_feature_id(hdl, &cfg, &buf, &result);

	if (!err && cfg.changed) {
		cfg.sel = NVME_GET_FEATURES_SEL_DEFAULT;
		err_def = get_feature_id(hdl, &cfg, &buf_def, &result_def);
	}

	if (!err && !is_get_feature_result_set(cfg.feature_id))
		result = cfg.cdw11;

	if (err || !cfg.changed || err_def || result != result_def ||
	    (buf && buf_def && !strcmp(buf, buf_def)))
		get_feature_id_print(cfg, err, result, buf, flags);

	return err;
}

static int get_feature_ids(struct nvme_transport_handle *hdl, struct feat_cfg cfg,
		nvme_print_flags_t flags)
{
	int err = 0;
	int i;
	int feat_max = 0x100;
	int feat_num = 0;
	int status = 0;
	enum nvme_status_type type = NVME_STATUS_TYPE_NVME;

	if (cfg.feature_id)
		feat_max = cfg.feature_id + 1;

	for (i = cfg.feature_id; i < feat_max; i++, feat_num++) {
		cfg.feature_id = i;
		err = get_feature_id_changed(hdl, cfg, flags);
		if (!err)
			continue;
		status = filter_out_flags(err);
		if (nvme_status_equals(status, type, NVME_SC_INVALID_FIELD))
			continue;
		if (!nvme_status_equals(status, type, NVME_SC_INVALID_NS))
			break;
		nvme_show_error_status(err, "get-feature:%#0*x (%s)", cfg.feature_id ? 4 : 2,
				       cfg.feature_id, nvme_feature_to_string(cfg.feature_id));
	}

	if (feat_num == 1 && nvme_status_equals(status, type, NVME_SC_INVALID_FIELD))
		nvme_show_status(err);

	return err;
}

static int get_feature(int argc, char **argv, struct command *acmd,
		       struct plugin *plugin)
{
	const char *desc = "Read operating parameters of the "
		"specified controller. Operating parameters are grouped "
		"and identified by Feature Identifiers; each Feature "
		"Identifier contains one or more attributes that may affect "
		"behavior of the feature. Each Feature has three possible "
		"settings: default, saveable, and current. If a Feature is "
		"saveable, it may be modified by set-feature. Default values "
		"are vendor-specific and not changeable. Use set-feature to "
		"change saveable Features.";
	const char *raw = "show feature in binary format";
	const char *feature_id = "feature identifier";
	const char *sel = "[0-3]: current/default/saved/supported";
	const char *cdw11 = "feature specific dword 11";
	const char *human_readable = "show feature in readable format";
	const char *changed = "show feature changed";
	nvme_print_flags_t flags = NORMAL;

	_cleanup_nvme_global_ctx_ struct nvme_global_ctx *ctx = NULL;
	_cleanup_nvme_transport_handle_ struct nvme_transport_handle *hdl = NULL;
	int err;

	struct feat_cfg cfg = {
		.feature_id	= 0,
		.namespace_id	= 0,
		.sel		= NVME_GET_FEATURES_SEL_CURRENT,
		.data_len	= 0,
		.raw_binary	= false,
		.cdw11		= 0,
		.uuid_index	= 0,
		.human_readable	= false,
	};

	NVME_ARGS(opts,
		  OPT_BYTE("feature-id",     'f', &cfg.feature_id,     feature_id, feature_name),
		  OPT_UINT("namespace-id",   'n', &cfg.namespace_id,   namespace_id_desired),
		  OPT_BYTE("sel",            's', &cfg.sel,            sel),
		  OPT_UINT("data-len",       'l', &cfg.data_len,       buf_len),
		  OPT_FLAG("raw-binary",     'b', &cfg.raw_binary,     raw),
		  OPT_UINT("cdw11",          'c', &cfg.cdw11,          cdw11),
		  OPT_BYTE("uuid-index",     'U', &cfg.uuid_index,     uuid_index_specify),
		  OPT_FLAG("human-readable", 'H', &cfg.human_readable, human_readable),
		  OPT_FLAG("changed",        'C', &cfg.changed,        changed));

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	err = validate_output_format(nvme_cfg.output_format, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	if (!argconfig_parse_seen(opts, "namespace-id")) {
		err = nvme_get_nsid(hdl, &cfg.namespace_id);
		if (err < 0) {
			if (errno != ENOTTY) {
				nvme_show_error("get-namespace-id: %s", nvme_strerror(err));
				return err;
			}
			cfg.namespace_id = NVME_NSID_ALL;
		}
	}

	if (cfg.sel > NVME_GET_FEATURES_SEL_SUPPORTED) {
		nvme_show_error("invalid 'select' param:%d", cfg.sel);
		return -EINVAL;
	}

	if (cfg.uuid_index > 127) {
		nvme_show_error("invalid uuid index param: %u", cfg.uuid_index);
		return -1;
	}

	if (cfg.human_readable || argconfig_parse_seen(opts, "verbose"))
		flags |= VERBOSE;

	nvme_show_init();

	err = get_feature_ids(hdl, cfg, flags);

	nvme_show_finish();

	return err;
}

/*
 * Transfers one chunk of firmware to the device, and decodes & reports any
 * errors. Returns -1 on (fatal) error; signifying that the transfer should
 * be aborted.
 */
static int fw_download_single(struct nvme_transport_handle *hdl, void *fw_buf,
			      unsigned int fw_len, uint32_t offset,
			      uint32_t len, bool progress, bool ignore_ovr)
{
	const unsigned int max_retries = 3;
	struct nvme_passthru_cmd cmd;
	bool retryable, ovr;
	int err, try;

	if (progress) {
		printf("Firmware download: transferring 0x%08x/0x%08x bytes: %03d%%\r",
		       offset, fw_len, (int)(100 * offset / fw_len));
	}

	for (try = 0; try < max_retries; try++) {
		if (try > 0) {
			fprintf(stderr, "retrying offset %x (%u/%u)\n",
				offset, try, max_retries);
		}

		err = nvme_init_fw_download(&cmd, fw_buf, len, offset);
		if (err)
			return err;

		err = nvme_submit_admin_passthru(hdl, &cmd, NULL);
		if (!err)
			return 0;

		/*
		 * don't retry if the NVMe-type error indicates Do Not Resend.
		 */
		retryable = !((err > 0) &&
			(nvme_status_get_type(err) == NVME_STATUS_TYPE_NVME) &&
			(nvme_status_get_value(err) & NVME_SC_DNR));

		/*
		 * detect overwrite errors, which are handled differently
		 * depending on ignore_ovr
		 */
		ovr = (err > 0) &&
			(nvme_status_get_type(err) == NVME_STATUS_TYPE_NVME) &&
			(NVME_GET(err, SCT) == NVME_SCT_CMD_SPECIFIC) &&
			(NVME_GET(err, SC) == NVME_SC_OVERLAPPING_RANGE);

		if (ovr && ignore_ovr)
			return 0;

		/*
		 * if we're printing progress, we'll need a newline to separate
		 * error output from the progress data (which doesn't have a
		 * \n), and flush before we write to stderr.
		 */
		if (progress) {
			printf("\n");
			fflush(stdout);
		}

		fprintf(stderr, "fw-download: error on offset 0x%08x/0x%08x\n",
			offset, fw_len);

		if (err < 0) {
			fprintf(stderr, "fw-download: %s\n", nvme_strerror(err));
		} else {
			nvme_show_status(err);
			if (ovr) {
				/*
				 * non-ignored ovr error: print a little extra info
				 * about recovering
				 */
				fprintf(stderr,
					"Use --ignore-ovr to ignore overwrite errors\n");

				/*
				 * We'll just be attempting more overwrites if
				 * we retry. DNR will likely be set, but force
				 * an exit anyway.
				 */
				retryable = false;
			}
		}

		if (!retryable)
			break;
	}

	return -1;
}

static int fw_download(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc = "Copy all or part of a firmware image to "
		"a controller for future update. Optionally, specify how "
		"many KiB of the firmware to transfer at once. The offset will "
		"start at 0 and automatically adjust based on xfer size "
		"unless fw is split across multiple files. May be submitted "
		"while outstanding commands exist on the Admin and IO "
		"Submission Queues. Activate downloaded firmware with "
		"fw-activate, and then reset the device to apply the downloaded firmware.";
	const char *fw = "firmware file (required)";
	const char *xfer = "transfer chunksize limit";
	const char *offset = "starting dword offset, default 0";
	const char *progress = "display firmware transfer progress";
	const char *ignore_ovr = "ignore overwrite errors";

	_cleanup_nvme_global_ctx_ struct nvme_global_ctx *ctx = NULL;
	_cleanup_nvme_transport_handle_ struct nvme_transport_handle *hdl = NULL;
	_cleanup_huge_ struct nvme_mem_huge mh = { 0, };
	_cleanup_fd_ int fw_fd = -1;
	unsigned int fw_size, pos;
	int err;
	struct stat sb;
	void *fw_buf;
	struct nvme_id_ctrl ctrl = { 0 };
	nvme_print_flags_t flags;

	struct config {
		char	*fw;
		__u32	xfer;
		__u32	offset;
		bool	progress;
		bool	ignore_ovr;
	};

	struct config cfg = {
		.fw         = "",
		.xfer       = 0,
		.offset     = 0,
		.progress   = false,
		.ignore_ovr = false,
	};

	NVME_ARGS(opts,
		  OPT_FILE("fw",         'f', &cfg.fw,         fw),
		  OPT_UINT("xfer",       'x', &cfg.xfer,       xfer),
		  OPT_UINT("offset",     'O', &cfg.offset,     offset),
		  OPT_FLAG("progress",   'p', &cfg.progress,   progress),
		  OPT_FLAG("ignore-ovr", 'i', &cfg.ignore_ovr, ignore_ovr));

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	err = validate_output_format(nvme_cfg.output_format, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	fw_fd = open(cfg.fw, O_RDONLY);
	cfg.offset <<= 2;
	if (fw_fd < 0) {
		nvme_show_error("Failed to open firmware file %s: %s", cfg.fw, strerror(errno));
		return -EINVAL;
	}

	err = fstat(fw_fd, &sb);
	if (err < 0) {
		nvme_show_perror("fstat");
		return err;
	}

	fw_size = sb.st_size;
	if ((fw_size & 0x3) || (fw_size == 0)) {
		nvme_show_error("Invalid size:%d for f/w image", fw_size);
		return -EINVAL;
	}

	if (cfg.xfer == 0) {
		err = nvme_identify_ctrl(hdl, &ctrl);
		if (err) {
			nvme_show_error("identify-ctrl: %s", nvme_strerror(err));
			return err;
		}
		if (ctrl.fwug == 0 || ctrl.fwug == 0xff)
			cfg.xfer = 4096;
		else
			cfg.xfer = ctrl.fwug * 4096;
	} else if (cfg.xfer % 4096)
		cfg.xfer = 4096;

	if (ctrl.fwug && ctrl.fwug != 0xff && fw_size % cfg.xfer)
		nvme_show_error("WARNING: firmware file size %u not conform to FWUG alignment %lu",
				fw_size, cfg.xfer);

	fw_buf = nvme_alloc_huge(fw_size, &mh);
	if (!fw_buf) {
		nvme_show_error("failed to allocate huge memory");
		return -ENOMEM;
	}

	if (read(fw_fd, fw_buf, fw_size) != ((ssize_t)(fw_size))) {
		err = -errno;
		nvme_show_error("read :%s :%s", cfg.fw, strerror(errno));
		return err;
	}

	for (pos = 0; pos < fw_size; pos += cfg.xfer) {
		cfg.xfer = min(cfg.xfer, fw_size - pos);

		err = fw_download_single(hdl, fw_buf + pos, fw_size,
					 cfg.offset + pos, cfg.xfer,
					 cfg.progress, cfg.ignore_ovr);
		if (err)
			break;
	}

	if (!err) {
		/* end the progress output */
		if (cfg.progress)
			printf("\n");
		printf("Firmware download success\n");
	}

	return err;
}

static char *nvme_fw_status_reset_type(__u16 status)
{
	switch (status & 0x7ff) {
	case NVME_SC_FW_NEEDS_CONV_RESET:
		return "conventional";
	case NVME_SC_FW_NEEDS_SUBSYS_RESET:
		return "subsystem";
	case NVME_SC_FW_NEEDS_RESET:
		return "any controller";
	default:
		return "unknown";
	}
}

static bool fw_commit_support_mud(struct nvme_transport_handle *hdl)
{
	_cleanup_free_ struct nvme_id_ctrl *ctrl = NULL;
	int err;

	ctrl = nvme_alloc(sizeof(*ctrl));
	if (!ctrl)
		return false;

	err = nvme_identify_ctrl(hdl, ctrl);

	if (err)
		nvme_show_error("identify-ctrl: %s", nvme_strerror(err));
	else if (ctrl->frmw >> 5 & 0x1)
		return true;

	return false;
}

static void fw_commit_print_mud(struct nvme_transport_handle *hdl, __u32 result)
{
	if (!fw_commit_support_mud(hdl))
		return;

	printf("Multiple Update Detected (MUD) Value: %u\n", result);

	if (result & 0x1)
		printf("Detected an overlapping firmware/boot partition image update command\n"
		       "sequence due to processing a command from an Admin SQ on a controller\n");

	if (result >> 1 & 0x1)
		printf("Detected an overlapping firmware/boot partition image update command\n"
		       "sequence due to processing a command from a Management Endpoint\n");
}

static int fw_commit(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc = "Verify downloaded firmware image and "
		"commit to specific firmware slot. Device is not automatically "
		"reset following firmware activation. A reset may be issued "
		"with an 'echo 1 > /sys/class/nvme/nvmeX/reset_controller'. "
		"Ensure nvmeX is the device you just activated before reset.";
	const char *slot = "[0-7]: firmware slot for commit action";
	const char *action = "[0-7]: commit action";
	const char *bpid = "[0,1]: boot partition identifier, if applicable (default: 0)";

	_cleanup_nvme_global_ctx_ struct nvme_global_ctx *ctx = NULL;
	_cleanup_nvme_transport_handle_ struct nvme_transport_handle *hdl = NULL;
	struct nvme_passthru_cmd cmd;
	__u32 result;
	int err;
	nvme_print_flags_t flags;

	struct config {
		__u8	slot;
		__u8	action;
		__u8	bpid;
	};

	struct config cfg = {
		.slot	= 0,
		.action	= 0,
		.bpid	= 0,
	};

	NVME_ARGS(opts,
		  OPT_BYTE("slot",   's', &cfg.slot,   slot),
		  OPT_BYTE("action", 'a', &cfg.action, action),
		  OPT_BYTE("bpid",   'b', &cfg.bpid,   bpid));

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	err = validate_output_format(nvme_cfg.output_format, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	if (cfg.slot > 7) {
		nvme_show_error("invalid slot:%d", cfg.slot);
		return -EINVAL;
	}
	if (cfg.action > 7 || cfg.action == 4 || cfg.action == 5) {
		nvme_show_error("invalid action:%d", cfg.action);
		return -EINVAL;
	}
	if (cfg.bpid > 1) {
		nvme_show_error("invalid boot partition id:%d", cfg.bpid);
		return -EINVAL;
	}

	nvme_init_fw_commit(&cmd, cfg.slot, cfg.action, cfg.bpid);
	err = nvme_submit_admin_passthru(hdl, &cmd, &result);
	if (err < 0) {
		nvme_show_error("fw-commit: %s", nvme_strerror(err));
	} else if (err > 0) {
		__u32 val = nvme_status_get_value(err);
		int type = nvme_status_get_type(err);

		if (type == NVME_STATUS_TYPE_NVME) {
			switch (val & 0x7ff) {
			case NVME_SC_FW_NEEDS_CONV_RESET:
			case NVME_SC_FW_NEEDS_SUBSYS_RESET:
			case NVME_SC_FW_NEEDS_RESET:
				printf("Success activating firmware action:%d slot:%d",
				       cfg.action, cfg.slot);
				if (cfg.action == 6 || cfg.action == 7)
					printf(" bpid:%d", cfg.bpid);
				printf(", but firmware requires %s reset\n",
				       nvme_fw_status_reset_type(val));
				break;
			default:
				nvme_show_status(err);
				break;
			}
		} else {
			nvme_show_status(err);
		}
	} else {
		printf("Success committing firmware action:%d slot:%d",
		       cfg.action, cfg.slot);
		if (cfg.action == 6 || cfg.action == 7)
			printf(" bpid:%d", cfg.bpid);
		printf("\n");
		fw_commit_print_mud(hdl, result);
	}

	return err;
}

static int subsystem_reset(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc = "Resets the NVMe subsystem";

	_cleanup_nvme_global_ctx_ struct nvme_global_ctx *ctx = NULL;
	_cleanup_nvme_transport_handle_ struct nvme_transport_handle *hdl = NULL;
	int err;

	NVME_ARGS(opts);

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	err = nvme_subsystem_reset(hdl);
	if (err < 0) {
		if (errno == ENOTTY)
			nvme_show_error("Subsystem-reset: NVM Subsystem Reset not supported.");
		else
			nvme_show_error("Subsystem-reset: %s", nvme_strerror(err));
	} else if (argconfig_parse_seen(opts, "verbose"))
		printf("resetting subsystem through %s\n", nvme_transport_handle_get_name(hdl));

	return err;
}

static int reset(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc = "Resets the NVMe controller\n";

	_cleanup_nvme_global_ctx_ struct nvme_global_ctx *ctx = NULL;
	_cleanup_nvme_transport_handle_ struct nvme_transport_handle *hdl = NULL;
	int err;

	NVME_ARGS(opts);

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	err = nvme_ctrl_reset(hdl);
	if (err < 0)
		nvme_show_error("Reset: %s", nvme_strerror(err));
	else if (argconfig_parse_seen(opts, "verbose"))
		printf("resetting controller %s\n", nvme_transport_handle_get_name(hdl));

	return err;
}

static int ns_rescan(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc = "Rescans the NVMe namespaces\n";

	_cleanup_nvme_global_ctx_ struct nvme_global_ctx *ctx = NULL;
	_cleanup_nvme_transport_handle_ struct nvme_transport_handle *hdl = NULL;
	int err;
	nvme_print_flags_t flags;

	NVME_ARGS(opts);

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	err = validate_output_format(nvme_cfg.output_format, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	err = nvme_ns_rescan(hdl);
	if (err < 0)
		nvme_show_error("Namespace Rescan: %s\n", nvme_strerror(err));
	else if (argconfig_parse_seen(opts, "verbose"))
		printf("rescanning namespaces through %s\n", nvme_transport_handle_get_name(hdl));

	return err;
}

static int sanitize_cmd(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc = "Send a sanitize command.";
	const char *emvs_desc = "Enter media verification state.";
	const char *no_dealloc_desc = "No deallocate after sanitize.";
	const char *oipbp_desc = "Overwrite invert pattern between passes.";
	const char *owpass_desc = "Overwrite pass count.";
	const char *ause_desc = "Allow unrestricted sanitize exit.";
	const char *sanact_desc = "Sanitize action: 1 = Exit failure mode, 2 = Start block erase,"
				"3 = Start overwrite, 4 = Start crypto erase, 5 = Exit media verification";
	const char *ovrpat_desc = "Overwrite pattern.";

	_cleanup_nvme_transport_handle_ struct nvme_transport_handle *hdl = NULL;
	_cleanup_nvme_global_ctx_ struct nvme_global_ctx *ctx = NULL;
	struct nvme_passthru_cmd cmd;
	nvme_print_flags_t flags;
	int err;

	struct config {
		bool	no_dealloc;
		bool	oipbp;
		__u8	owpass;
		bool	ause;
		__u8	sanact;
		__u32	ovrpat;
		bool	emvs;
	};

	struct config cfg = {
		.no_dealloc	= false,
		.oipbp		= false,
		.owpass		= 0,
		.ause		= false,
		.sanact		= 0,
		.ovrpat		= 0,
		.emvs		= false,
	};

	OPT_VALS(sanact) = {
		VAL_BYTE("exit-failure", NVME_SANITIZE_SANACT_EXIT_FAILURE),
		VAL_BYTE("start-block-erase", NVME_SANITIZE_SANACT_START_BLOCK_ERASE),
		VAL_BYTE("start-overwrite", NVME_SANITIZE_SANACT_START_OVERWRITE),
		VAL_BYTE("start-crypto-erase", NVME_SANITIZE_SANACT_START_CRYPTO_ERASE),
		VAL_BYTE("exit-media-verification", NVME_SANITIZE_SANACT_EXIT_MEDIA_VERIF),
		VAL_END()
	};

	NVME_ARGS(opts,
		  OPT_FLAG("no-dealloc", 'd', &cfg.no_dealloc, no_dealloc_desc),
		  OPT_FLAG("oipbp",      'i', &cfg.oipbp,      oipbp_desc),
		  OPT_BYTE("owpass",     'n', &cfg.owpass,     owpass_desc),
		  OPT_FLAG("ause",       'u', &cfg.ause,       ause_desc),
		  OPT_BYTE("sanact",     'a', &cfg.sanact,     sanact_desc, sanact),
		  OPT_UINT("ovrpat",     'p', &cfg.ovrpat,     ovrpat_desc),
		  OPT_FLAG("emvs",       'e', &cfg.emvs,       emvs_desc));

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	err = validate_output_format(nvme_cfg.output_format, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	switch (cfg.sanact) {
	case NVME_SANITIZE_SANACT_EXIT_FAILURE:
	case NVME_SANITIZE_SANACT_START_BLOCK_ERASE:
	case NVME_SANITIZE_SANACT_START_OVERWRITE:
	case NVME_SANITIZE_SANACT_START_CRYPTO_ERASE:
	case NVME_SANITIZE_SANACT_EXIT_MEDIA_VERIF:
		break;
	default:
		nvme_show_error("Invalid Sanitize Action");
		return -EINVAL;
	}

	if (cfg.ause || cfg.no_dealloc) {
		if (cfg.sanact == NVME_SANITIZE_SANACT_EXIT_FAILURE) {
			nvme_show_error("SANACT is Exit Failure Mode");
			return -EINVAL;
		} else if (cfg.sanact == NVME_SANITIZE_SANACT_EXIT_MEDIA_VERIF) {
			nvme_show_error("SANACT is Exit Media Verification State");
			return -EINVAL;
		}
	}

	if (cfg.sanact == NVME_SANITIZE_SANACT_START_OVERWRITE) {
		if (cfg.owpass > 15) {
			nvme_show_error("OWPASS out of range [0-15]");
			return -EINVAL;
		}
	} else {
		if (cfg.owpass || cfg.oipbp || cfg.ovrpat) {
			nvme_show_error("SANACT is not Overwrite");
			return -EINVAL;
		}
	}

	nvme_init_sanitize_nvm(&cmd, cfg.sanact, cfg.ause, cfg.owpass,
			       cfg.oipbp, cfg.no_dealloc, cfg.emvs, cfg.ovrpat);
	err = nvme_submit_admin_passthru(hdl, &cmd, NULL);
	if (err < 0)
		nvme_show_error("sanitize: %s", nvme_strerror(err));
	else if (err > 0)
		nvme_show_status(err);

	return err;
}

static int nvme_get_single_property(struct nvme_transport_handle *hdl, struct get_reg_config *cfg, __u64 *value)
{
	struct nvme_passthru_cmd64 cmd;
	int err;

	nvme_init_get_property(&cmd, cfg->offset);
	err = nvme_submit_admin_passthru64(hdl, &cmd, value);
	if (!err)
		return 0;

	if (cfg->fabrics && nvme_is_fabrics_optional_reg(cfg->offset)) {
		*value = -1;
		return 0;
	}

	if (!cfg->fabrics &&
	    nvme_status_equals(err, NVME_STATUS_TYPE_NVME, NVME_SC_INVALID_FIELD)) {
		*value = -1;
		return 0;
	}

	if (cfg->fabrics && err > 0)
		nvme_show_status(err);
	else
		nvme_show_error("get-property: %s", nvme_strerror(err));

	return err;
}

static int nvme_get_properties(struct nvme_transport_handle *hdl, void **pbar, struct get_reg_config *cfg)
{
	int err, size = getpagesize();
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

static void *mmap_registers(struct nvme_transport_handle *hdl, bool writable)
{
	char path[512];
	void *membase;
	int fd;
	int prot = PROT_READ;

	if (writable)
		prot |= PROT_WRITE;

	sprintf(path, "/sys/class/nvme/%s/device/resource0", nvme_transport_handle_get_name(hdl));
	fd = open(path, writable ? O_RDWR : O_RDONLY);
	if (fd < 0) {
		if (log_level >= LOG_INFO)
			nvme_show_error("%s did not find a pci resource, open failed %s",
					nvme_transport_handle_get_name(hdl), strerror(errno));
		return NULL;
	}

	membase = mmap(NULL, getpagesize(), prot, MAP_SHARED, fd, 0);
	if (membase == MAP_FAILED) {
		if (log_level >= LOG_INFO) {
			fprintf(stderr, "Failed to map registers to userspace.\n\n"
				"Did your kernel enable CONFIG_IO_STRICT_DEVMEM?\n"
				"You can disable this feature with command line argument\n\n"
				"\tio_memory=relaxed\n\n"
				"Also ensure secure boot is disabled.\n\n");
		}
		membase = NULL;
	}

	close(fd);
	return membase;
}

static int show_registers(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc = "Reads and shows the defined NVMe controller registers\n"
		"in binary or human-readable format";
	const char *human_readable =
	    "show info in readable format in case of output_format == normal";

	_cleanup_nvme_global_ctx_ struct nvme_global_ctx *ctx = NULL;
	_cleanup_nvme_transport_handle_ struct nvme_transport_handle *hdl = NULL;
	nvme_print_flags_t flags;
	void *bar;
	int err;

	struct get_reg_config cfg = {
		.human_readable	= false,
		.fabrics = false,
	};

	NVME_ARGS(opts,
		  OPT_FLAG("human-readable", 'H', &cfg.human_readable, human_readable));

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	if (nvme_transport_handle_is_blkdev(hdl)) {
		nvme_show_error("Only character device is allowed");
		return -EINVAL;
	}

	err = validate_output_format(nvme_cfg.output_format, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	if (cfg.human_readable || argconfig_parse_seen(opts, "verbose"))
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
		munmap(bar, getpagesize());

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

static int get_register_properties(struct nvme_transport_handle *hdl, void **pbar, struct get_reg_config *cfg)
{
	struct nvme_passthru_cmd64 cmd;
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
		err = nvme_submit_admin_passthru64(hdl, &cmd, &value);
		if (nvme_status_equals(err, NVME_STATUS_TYPE_NVME, NVME_SC_INVALID_FIELD)) {
			value = -1;
		} else if (err) {
			nvme_show_error("get-property: %s", nvme_strerror(err));
			free(bar);
			return err;
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
	const char *human_readable = "show register in readable format";
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

	_cleanup_nvme_global_ctx_ struct nvme_global_ctx *ctx = NULL;
	_cleanup_nvme_transport_handle_ struct nvme_transport_handle *hdl = NULL;
	int err;
	nvme_print_flags_t flags;
	bool fabrics = false;

	void *bar;

	struct get_reg_config cfg = {
		.offset = -1,
	};

	NVME_ARGS(opts,
		  OPT_UINT("offset",         'O', &cfg.offset,         offset),
		  OPT_FLAG("human-readable", 'H', &cfg.human_readable, human_readable),
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

	if (nvme_transport_handle_is_blkdev(hdl)) {
		nvme_show_error("Only character device is allowed");
		return -EINVAL;
	}

	err = validate_output_format(nvme_cfg.output_format, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	if (cfg.human_readable || argconfig_parse_seen(opts, "verbose"))
		flags |= VERBOSE;

	bar = mmap_registers(hdl, false);
	if (!bar) {
		err = get_register_properties(hdl, &bar, &cfg);
		if (err)
			return err;
		fabrics = true;
	}

	nvme_show_init();

	if (!get_register_offset(bar, fabrics, &cfg, flags)) {
		nvme_show_error("offset required param");
		err = -EINVAL;
	}

	nvme_show_finish();

	if (fabrics)
		free(bar);
	else
		munmap(bar, getpagesize());

	return err;
}

static int nvme_set_single_property(struct nvme_transport_handle *hdl, int offset, uint64_t value)
{
	struct nvme_passthru_cmd cmd;
	int err;

	nvme_init_set_property(&cmd, offset, value);
	err = nvme_submit_admin_passthru(hdl, &cmd, NULL);
	if (err < 0)
		nvme_show_error("set-property: %s", nvme_strerror(err));
	else if (!err)
		printf("set-property: %#02x (%s), value: %#"PRIx64"\n", offset,
		       nvme_register_to_string(offset), value);
	else if (err > 0)
		nvme_show_status(err);

	return err;
}

static int set_register_property(struct nvme_transport_handle *hdl, int offset, uint64_t value)
{
	if (!nvme_is_fabrics_reg(offset)) {
		printf("register: %#04x (%s) not fabrics\n", offset,
		       nvme_register_to_string(offset));
		return -EINVAL;
	}

	return nvme_set_single_property(hdl, offset, value);
}

static int nvme_set_register(struct nvme_transport_handle *hdl, void *bar, int offset, uint64_t value, bool mmio32)
{
	if (!bar)
		return set_register_property(hdl, offset, value);

	if (nvme_is_64bit_reg(offset))
		mmio_write64(bar + offset, value, mmio32);
	else
		mmio_write32(bar + offset, value);

	printf("set-register: %#02x (%s), value: %#"PRIx64"\n", offset,
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

static int set_register_offset(struct nvme_transport_handle *hdl, void *bar, struct argconfig_commandline_options *opts,
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

static int set_register_names(struct nvme_transport_handle *hdl, void *bar, struct argconfig_commandline_options *opts,
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

	_cleanup_nvme_global_ctx_ struct nvme_global_ctx *ctx = NULL;
	_cleanup_nvme_transport_handle_ struct nvme_transport_handle *hdl = NULL;
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

	if (nvme_transport_handle_is_blkdev(hdl)) {
		nvme_show_error("Only character device is allowed");
		return -EINVAL;
	}

	bar = mmap_registers(hdl, true);

	if (argconfig_parse_seen(opts, "offset"))
		err = set_register_offset(hdl, bar, opts, &cfg);

	if (!err)
		err = set_register_names(hdl, bar, opts, &cfg);

	if (bar)
		munmap(bar, getpagesize());

	return err;
}

static int get_property(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc = "Reads and shows the defined NVMe controller property\n"
		"for NVMe over Fabric. Property offset must be one of:\n"
		"CAP=0x0, VS=0x8, CC=0x14, CSTS=0x1c, NSSR=0x20, NSSD=0x64, CRTO=0x68";
	const char *offset = "offset of the requested property";
	const char *human_readable = "show property in readable format";

	_cleanup_nvme_global_ctx_ struct nvme_global_ctx *ctx = NULL;
	_cleanup_nvme_transport_handle_ struct nvme_transport_handle *hdl = NULL;
	__u64 value;
	int err;
	nvme_print_flags_t flags = NORMAL;

	struct get_reg_config cfg = {
		.offset		= -1,
		.human_readable	= false,
		.fabrics	= true,
	};

	NVME_ARGS(opts,
		  OPT_UINT("offset",         'O', &cfg.offset,         offset),
		  OPT_FLAG("human-readable", 'H', &cfg.human_readable, human_readable));

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	err = validate_output_format(nvme_cfg.output_format, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	if (cfg.offset == -1) {
		nvme_show_error("offset required param");
		return -EINVAL;
	}

	if (cfg.human_readable || argconfig_parse_seen(opts, "verbose"))
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

	_cleanup_nvme_global_ctx_ struct nvme_global_ctx *ctx = NULL;
	_cleanup_nvme_transport_handle_ struct nvme_transport_handle *hdl = NULL;
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

	err = validate_output_format(nvme_cfg.output_format, &flags);
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

static void show_relatives(const char *name, nvme_print_flags_t flags)
{
	_cleanup_nvme_global_ctx_ struct nvme_global_ctx *ctx;
	int err;

	ctx = nvme_create_global_ctx(stderr, log_level);
	if (!ctx) {
		nvme_show_error("Failed to create global context");
		return;
	}

	err = nvme_scan_topology(ctx, NULL, NULL);
	if (err < 0) {
		nvme_show_error("Failed to scan topology: %s", nvme_strerror(-err));
		return;
	}

	nvme_show_relatives(ctx, name, flags);
}

static int format_cmd(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc = "Re-format a specified namespace on the\n"
		"given device. Can erase all data in namespace (user\n"
		"data erase) or delete data encryption key if specified.\n"
		"Can also be used to change LBAF to change the namespaces reported physical block format.";
	const char *lbaf = "LBA format to apply (required)";
	const char *ses = "[0-2]: secure erase";
	const char *pil = "[0-1]: protection info location last/first bytes of metadata";
	const char *pi = "[0-3]: protection info off/Type 1/Type 2/Type 3";
	const char *mset = "[0-1]: extended format off/on";
	const char *reset = "Automatically reset the controller after successful format";
	const char *bs = "target block size";
	const char *force = "The \"I know what I'm doing\" flag, skip confirmation before sending command";

	_cleanup_nvme_global_ctx_ struct nvme_global_ctx *ctx = NULL;
	_cleanup_nvme_transport_handle_ struct nvme_transport_handle *hdl = NULL;
	_cleanup_free_ struct nvme_id_ctrl *ctrl = NULL;
	_cleanup_free_ struct nvme_id_ns *ns = NULL;
	nvme_print_flags_t flags = NORMAL;
	struct nvme_passthru_cmd cmd;
	__u32 timeout_ms = 600000;
	__u8 prev_lbaf = 0;
	int block_size;
	int err, i;

	struct config {
		__u32	namespace_id;
		__u8	lbaf;
		__u8	ses;
		__u8	pi;
		__u8	pil;
		__u8	mset;
		bool	reset;
		bool	force;
		__u64	bs;
	};

	struct config cfg = {
		.namespace_id	= 0,
		.lbaf		= 0xff,
		.ses		= 0,
		.pi		= 0,
		.pil		= 0,
		.mset		= 0,
		.reset		= false,
		.force		= false,
		.bs		= 0,
	};

	if (nvme_cfg.timeout != NVME_DEFAULT_IOCTL_TIMEOUT)
		timeout_ms = nvme_cfg.timeout;

	NVME_ARGS(opts,
		  OPT_UINT("namespace-id", 'n', &cfg.namespace_id, namespace_id_desired),
		  OPT_BYTE("lbaf",         'l', &cfg.lbaf,         lbaf),
		  OPT_BYTE("ses",          's', &cfg.ses,          ses),
		  OPT_BYTE("pi",           'i', &cfg.pi,           pi),
		  OPT_BYTE("pil",          'p', &cfg.pil,          pil),
		  OPT_BYTE("ms",           'm', &cfg.mset,         mset),
		  OPT_FLAG("reset",        'r', &cfg.reset,        reset),
		  OPT_FLAG("force",          0, &cfg.force,        force),
		  OPT_SUFFIX("block-size", 'b', &cfg.bs,           bs));

	err = parse_args(argc, argv, desc, opts);
	if (err)
		return err;

	err = open_exclusive(&ctx, &hdl, argc, argv, cfg.force);
	if (err) {
		if (-err == EBUSY) {
			fprintf(stderr, "Failed to open %s.\n", basename(argv[optind]));
			fprintf(stderr, "Namespace is currently busy.\n");
			if (!cfg.force)
				fprintf(stderr, "Use the force [--force] option to ignore that.\n");
		} else {
			argconfig_print_help(desc, opts);
		}
		return err;
	}

	err = validate_output_format(nvme_cfg.output_format, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	if (cfg.lbaf != 0xff && cfg.bs != 0) {
		nvme_show_error(
		    "Invalid specification of both LBAF and Block Size, please specify only one");
		return -EINVAL;
	}
	if (cfg.bs) {
		if ((cfg.bs & (~cfg.bs + 1)) != cfg.bs) {
			nvme_show_error(
			    "Invalid value for block size (%"PRIu64"), must be a power of two",
			    (uint64_t) cfg.bs);
			return -EINVAL;
		}
	}

	ctrl = nvme_alloc(sizeof(*ctrl));
	if (!ctrl)
		return -ENOMEM;

	err = nvme_identify_ctrl(hdl, ctrl);
	if (err) {
		nvme_show_error("identify-ctrl: %s", nvme_strerror(err));
		return -errno;
	}

	if (ctrl->fna & NVME_CTRL_FNA_FMT_ALL_NAMESPACES) {
		/*
		 * FNA bit 0 set to 1: all namespaces ... shall be configured with the same
		 * attributes and a format (excluding secure erase) of any namespace results in a
		 * format of all namespaces.
		 */
		cfg.namespace_id = NVME_NSID_ALL;
	} else if (!cfg.namespace_id) {
		err = nvme_get_nsid(hdl, &cfg.namespace_id);
		if (err < 0) {
			nvme_show_error("get-namespace-id: %s", nvme_strerror(err));
			return -errno;
		}
	}

	if (cfg.namespace_id == 0) {
		nvme_show_error(
		    "Invalid namespace ID, specify a namespace to format or use\n"
		    "'-n 0xffffffff' to format all namespaces on this controller.");
		return -EINVAL;
	}

	if (cfg.namespace_id != NVME_NSID_ALL) {
		ns = nvme_alloc(sizeof(*ns));
		if (!ns)
			return -ENOMEM;

		err = nvme_identify_ns(hdl, cfg.namespace_id, ns);
		if (err) {
			if (err < 0) {
				nvme_show_error("identify-namespace: %s", nvme_strerror(err));
			} else {
				fprintf(stderr, "identify failed\n");
				nvme_show_status(err);
			}
			return err;
		}
		nvme_id_ns_flbas_to_lbaf_inuse(ns->flbas, &prev_lbaf);

		if (cfg.bs) {
			for (i = 0; i <= ns->nlbaf; ++i) {
				if ((1ULL << ns->lbaf[i].ds) == cfg.bs && ns->lbaf[i].ms == 0) {
					cfg.lbaf = i;
					break;
				}
			}
			if (cfg.lbaf == 0xff) {
				fprintf(stderr,
				    "LBAF corresponding to given block size %"PRIu64" not found\n",
				    (uint64_t)cfg.bs);
				fprintf(stderr,
					"Please correct block size, or specify LBAF directly\n");
				return -EINVAL;
			}
		} else  if (cfg.lbaf == 0xff) {
			cfg.lbaf = prev_lbaf;
		}
	} else {
		if (cfg.lbaf == 0xff)
			cfg.lbaf = 0;
	}

	/* ses & pi checks set to 7 for forward-compatibility */
	if (cfg.ses > 7) {
		nvme_show_error("invalid secure erase settings:%d", cfg.ses);
		return -EINVAL;
	}
	if (cfg.lbaf > 63) {
		nvme_show_error("invalid lbaf:%d", cfg.lbaf);
		return -EINVAL;
	}
	if (cfg.pi > 7) {
		nvme_show_error("invalid pi:%d", cfg.pi);
		return -EINVAL;
	}
	if (cfg.pil > 1) {
		nvme_show_error("invalid pil:%d", cfg.pil);
		return -EINVAL;
	}
	if (cfg.mset > 1) {
		nvme_show_error("invalid mset:%d", cfg.mset);
		return -EINVAL;
	}

	if (!cfg.force) {
		fprintf(stderr, "You are about to format %s, namespace %#x%s.\n",
			nvme_transport_handle_get_name(hdl), cfg.namespace_id,
			cfg.namespace_id == NVME_NSID_ALL ? "(ALL namespaces)" : "");
		show_relatives(nvme_transport_handle_get_name(hdl), flags);
		fprintf(stderr,
			"WARNING: Format may irrevocably delete this device's data.\n"
			"You have 10 seconds to press Ctrl-C to cancel this operation.\n\n"
			"Use the force [--force] option to suppress this warning.\n");
		sleep(10);
		fprintf(stderr, "Sending format operation ...\n");
	}

	nvme_init_format_nvm(&cmd, cfg.namespace_id, cfg.lbaf, cfg.mset,
		cfg.pi, cfg.pil, cfg.ses);
	cmd.timeout_ms = timeout_ms;
	err = nvme_submit_admin_passthru(hdl, &cmd, NULL);
	if (err < 0) {
		nvme_show_error("format: %s", nvme_strerror(err));
	} else if (err != 0) {
		nvme_show_status(err);
	} else {
		printf("Success formatting namespace:%x\n", cfg.namespace_id);
		if (nvme_transport_handle_is_direct(hdl) && cfg.lbaf != prev_lbaf) {
			if (nvme_transport_handle_is_chardev(hdl)) {
				if (ioctl(nvme_transport_handle_get_fd(hdl), NVME_IOCTL_RESCAN) < 0) {
					nvme_show_error("failed to rescan namespaces");
					return -errno;
				}
			} else if (cfg.namespace_id != NVME_NSID_ALL) {
				block_size = 1 << ns->lbaf[cfg.lbaf].ds;

				/*
				 * If block size has been changed by the format
				 * command up there, we should notify it to
				 * kernel blkdev to update its own block size
				 * to the given one because blkdev will not
				 * update by itself without re-opening fd.
				 */
				if (ioctl(nvme_transport_handle_get_fd(hdl), BLKBSZSET, &block_size) < 0) {
					nvme_show_error("failed to set block size to %d",
							block_size);
					return -errno;
				}

				if (ioctl(nvme_transport_handle_get_fd(hdl), BLKRRPART) < 0) {
					nvme_show_error("failed to re-read partition table");
					return -errno;
				}
			}
		}
		if (nvme_transport_handle_is_direct(hdl) && cfg.reset &&
		    nvme_transport_handle_is_chardev(hdl))
			nvme_ctrl_reset(hdl);
	}

	return err;
}

#define STRTOUL_AUTO_BASE              (0)
#define NVME_FEAT_TIMESTAMP_DATA_SIZE  (6)

static int set_feature(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc = "Modify the saveable or changeable "
		"current operating parameters of the controller. "
		"Operating parameters are grouped and identified by Feature"
		"Identifiers. Feature settings can be applied to the entire"
		"controller and all associated namespaces, or to only a few"
		"namespace(s) associated with the controller. Default values"
		"for each Feature are vendor-specific and may not be modified."
		"Use get-feature to determine which Features are supported by"
		"the controller and are saveable/changeable.";
	const char *fid = "feature identifier (required)";
	const char *data = "optional file for feature data (default stdin)";
	const char *value = "new value of feature (required)";
	const char *cdw12 = "feature cdw12, if used";
	const char *sv = "specifies that the controller shall save the attribute";

	_cleanup_nvme_global_ctx_ struct nvme_global_ctx *ctx = NULL;
	_cleanup_nvme_transport_handle_ struct nvme_transport_handle *hdl = NULL;
	_cleanup_free_ void *buf = NULL;
	_cleanup_fd_ int ffd = STDIN_FILENO;
	int err;
	__u32 result;
	nvme_print_flags_t flags;

	struct config {
		__u32	nsid;
		__u8	fid;
		__u64	value;
		__u32	cdw12;
		__u8	uidx;
		__u32	data_len;
		char	*file;
		bool	sv;
	};

	struct config cfg = {
		.nsid		= 0,
		.fid		= 0,
		.value		= 0,
		.uidx		= 0,
		.data_len	= 0,
		.file		= "",
		.sv			= false,
	};

	NVME_ARGS(opts,
		  OPT_UINT("namespace-id", 'n', &cfg.nsid,     namespace_desired),
		  OPT_BYTE("feature-id",   'f', &cfg.fid,      fid, feature_name),
		  OPT_SUFFIX("value",      'V', &cfg.value,    value),
		  OPT_UINT("cdw12",        'c', &cfg.cdw12,    cdw12),
		  OPT_BYTE("uuid-index",   'U', &cfg.uidx,     uuid_index_specify),
		  OPT_UINT("data-len",     'l', &cfg.data_len, buf_len),
		  OPT_FILE("data",         'd', &cfg.file,     data),
		  OPT_FLAG("save",         's', &cfg.sv,       sv));

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	err = validate_output_format(nvme_cfg.output_format, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	if (!argconfig_parse_seen(opts, "namespace-id")) {
		err = nvme_get_nsid(hdl, &cfg.nsid);
		if (err < 0) {
			if (errno != ENOTTY) {
				nvme_show_error("get-namespace-id: %s", nvme_strerror(err));
				return -errno;
			}
			cfg.nsid = NVME_NSID_ALL;
		}
	}

	if (!cfg.fid) {
		nvme_show_error("feature-id required param");
		return -EINVAL;
	}

	if (cfg.uidx > 127) {
		nvme_show_error("invalid uuid index param: %u", cfg.uidx);
		return -1;
	}

	if (!cfg.data_len)
		nvme_get_feature_length(cfg.fid, cfg.value,
					 NVME_DATA_TFR_HOST_TO_CTRL,
					 &cfg.data_len);

	if (cfg.data_len) {
		buf = nvme_alloc(cfg.data_len);
		if (!buf)
			return -ENOMEM;
	}

	if (buf) {
		/*
		 * Use the '-v' value for the timestamp feature if provided as
		 * a convenience since it can often fit in 4-bytes. The user
		 * should use the buffer method if the value exceeds this
		 * length.
		 */
		if (cfg.fid == NVME_FEAT_FID_TIMESTAMP &&
		    argconfig_parse_seen(opts, "value")) {
			memcpy(buf, &cfg.value, NVME_FEAT_TIMESTAMP_DATA_SIZE);
		} else {
			if (strlen(cfg.file))
				ffd = open(cfg.file, O_RDONLY);

			if (ffd < 0) {
				nvme_show_error("Failed to open file %s: %s",
						cfg.file, strerror(errno));
				return -EINVAL;
			}

			err = read(ffd, buf, cfg.data_len);
			if (err < 0) {
				nvme_show_error("failed to read data buffer from input file: %s",
						strerror(errno));
				return -errno;
			}
		}
	}

	err = nvme_set_features(hdl, cfg.nsid, cfg.fid, cfg.sv, cfg.value, cfg.cdw12,
			0, cfg.uidx, 0, buf, cfg.data_len, &result);
	if (err < 0) {
		nvme_show_error("set-feature: %s", nvme_strerror(err));
	} else if (!err) {
		printf("set-feature:%#0*x (%s), value:%#0*"PRIx64", cdw12:%#0*x, save:%#x\n",
		       cfg.fid ? 4 : 2, cfg.fid,
		       nvme_feature_to_string(cfg.fid),
		       cfg.value ? 10 : 8, (uint64_t)cfg.value,
		       cfg.cdw12 ? 10 : 8, cfg.cdw12, cfg.sv);
		if (cfg.fid == NVME_FEAT_FID_LBA_STS_INTERVAL)
			nvme_show_lba_status_info(result);
		if (buf) {
			if (cfg.fid == NVME_FEAT_FID_LBA_RANGE)
				nvme_show_lba_range((struct nvme_lba_range_type *)buf, result, 0);
			else
				d(buf, cfg.data_len, 16, 1);
		}
	} else if (err > 0) {
		nvme_show_status(err);
	}

	return err;
}

static int sec_send(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	struct stat sb;
	const char *desc = "Transfer security protocol data to\n"
		"a controller. Security Receives for the same protocol should be\n"
		"performed after Security Sends. The security protocol field\n"
		"associates Security Sends (security-send) and Security Receives (security-recv).";
	const char *file = "transfer payload";
	const char *tl = "transfer length (cf. SPC-4)";

	_cleanup_nvme_global_ctx_ struct nvme_global_ctx *ctx = NULL;
	_cleanup_nvme_transport_handle_ struct nvme_transport_handle *hdl = NULL;
	struct nvme_passthru_cmd cmd;
	_cleanup_free_ void *sec_buf = NULL;
	_cleanup_fd_ int sec_fd = -1;
	unsigned int sec_size;
	int err;
	nvme_print_flags_t flags;

	struct config {
		__u32	namespace_id;
		char	*file;
		__u8	nssf;
		__u8	secp;
		__u16	spsp;
		__u32	tl;
	};

	struct config cfg = {
		.namespace_id	= 0,
		.file		= "",
		.nssf		= 0,
		.secp		= 0,
		.spsp		= 0,
		.tl		= 0,
	};

	NVME_ARGS(opts,
		  OPT_UINT("namespace-id", 'n', &cfg.namespace_id, namespace_desired),
		  OPT_FILE("file",         'f', &cfg.file,         file),
		  OPT_BYTE("nssf",         'N', &cfg.nssf,         nssf),
		  OPT_BYTE("secp",         'p', &cfg.secp,         secp),
		  OPT_SHRT("spsp",         's', &cfg.spsp,         spsp),
		  OPT_UINT("tl",           't', &cfg.tl,           tl));

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	err = validate_output_format(nvme_cfg.output_format, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	if (cfg.tl == 0) {
		nvme_show_error("--tl unspecified or zero");
		return -EINVAL;
	}
	if ((cfg.tl & 3) != 0)
		nvme_show_error(
		    "WARNING: --tl not dword aligned; unaligned bytes may be truncated");

	if (strlen(cfg.file) == 0) {
		sec_fd = STDIN_FILENO;
		sec_size = cfg.tl;
	} else {
		sec_fd = open(cfg.file, O_RDONLY);
		if (sec_fd < 0) {
			nvme_show_error("Failed to open %s: %s", cfg.file, strerror(errno));
			return -EINVAL;
		}

		err = fstat(sec_fd, &sb);
		if (err < 0) {
			nvme_show_perror("fstat");
			return err;
		}

		sec_size = cfg.tl > sb.st_size ? cfg.tl : sb.st_size;
	}

	sec_buf = nvme_alloc(cfg.tl);
	if (!sec_buf)
		return -ENOMEM;

	err = read(sec_fd, sec_buf, sec_size);
	if (err < 0) {
		nvme_show_error("Failed to read data from security file %s with %s", cfg.file,
				strerror(errno));
		return -errno;
	}

	nvme_init_security_send(&cmd, cfg.namespace_id, cfg.nssf, cfg.spsp,
				cfg.secp, cfg.tl, sec_buf, cfg.tl);
	err = nvme_submit_admin_passthru(hdl, &cmd, NULL);
	if (err < 0)
		nvme_show_error("security-send: %s", nvme_strerror(err));
	else if (err > 0)
		nvme_show_status(err);
	else
		printf("NVME Security Send Command Success\n");

	return err;
}

static int dir_send(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc = "Set directive parameters of the specified directive type.";
	const char *endir = "directive enable";
	const char *ttype = "target directive type to be enabled/disabled";
	const char *input = "write/send file (default stdin)";

	_cleanup_nvme_global_ctx_ struct nvme_global_ctx *ctx = NULL;
	_cleanup_nvme_transport_handle_ struct nvme_transport_handle *hdl = NULL;
	_cleanup_free_ void *buf = NULL;
	struct nvme_passthru_cmd cmd;
	__u32 result;
	__u32 dw12 = 0;
	_cleanup_fd_ int ffd = STDIN_FILENO;
	int err;

	struct config {
		__u32	namespace_id;
		__u32	data_len;
		__u8	dtype;
		__u8	ttype;
		__u16	dspec;
		__u8	doper;
		__u16	endir;
		bool	human_readable;
		bool	raw_binary;
		char	*file;
	};

	struct config cfg = {
		.namespace_id	= 1,
		.data_len	= 0,
		.dtype		= 0,
		.ttype		= 0,
		.dspec		= 0,
		.doper		= 0,
		.endir		= 1,
		.human_readable	= false,
		.raw_binary	= false,
		.file		= "",
	};

	NVME_ARGS(opts,
		  OPT_UINT("namespace-id",   'n', &cfg.namespace_id,   namespace_id_desired),
		  OPT_UINT("data-len",       'l', &cfg.data_len,       buf_len),
		  OPT_BYTE("dir-type",       'D', &cfg.dtype,          dtype),
		  OPT_BYTE("target-dir",     'T', &cfg.ttype,          ttype),
		  OPT_SHRT("dir-spec",       'S', &cfg.dspec,          dspec_w_dtype),
		  OPT_BYTE("dir-oper",       'O', &cfg.doper,          doper),
		  OPT_SHRT("endir",          'e', &cfg.endir,          endir),
		  OPT_FLAG("human-readable", 'H', &cfg.human_readable, deprecated),
		  OPT_FLAG("raw-binary",     'b', &cfg.raw_binary,     raw_directive),
		  OPT_FILE("input-file",     'i', &cfg.file,           input));

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	switch (cfg.dtype) {
	case NVME_DIRECTIVE_DTYPE_IDENTIFY:
		switch (cfg.doper) {
		case NVME_DIRECTIVE_SEND_IDENTIFY_DOPER_ENDIR:
			if (!cfg.ttype) {
				nvme_show_error("target-dir required param\n");
				return -EINVAL;
			}
			dw12 = cfg.ttype << 8 | cfg.endir;
			break;
		default:
			nvme_show_error("invalid directive operations for Identify Directives");
			return -EINVAL;
		}
		break;
	case NVME_DIRECTIVE_DTYPE_STREAMS:
		switch (cfg.doper) {
		case NVME_DIRECTIVE_SEND_STREAMS_DOPER_RELEASE_IDENTIFIER:
		case NVME_DIRECTIVE_SEND_STREAMS_DOPER_RELEASE_RESOURCE:
			break;
		default:
			nvme_show_error("invalid directive operations for Streams Directives");
			return -EINVAL;
		}
		break;
	default:
		nvme_show_error("invalid directive type");
		return -EINVAL;
	}

	if (cfg.data_len) {
		buf = nvme_alloc(cfg.data_len);
		if (!buf)
			return -ENOMEM;
	}

	if (buf) {
		if (strlen(cfg.file)) {
			ffd = open(cfg.file, O_RDONLY);
			if (ffd <= 0) {
				nvme_show_error("Failed to open file %s: %s",
						cfg.file, strerror(errno));
				return -EINVAL;
			}
		}
		err = read(ffd, (void *)buf, cfg.data_len);
		if (err < 0) {
			nvme_show_error("failed to read data buffer from input file %s",
					strerror(errno));
			return -errno;
		}
	}

	nvme_init_directive_send(&cmd, cfg.namespace_id, cfg.doper, cfg.dtype,
		cfg.dspec, buf, cfg.data_len);
	cmd.cdw12 = dw12;
	err = nvme_submit_admin_passthru(hdl, &cmd, &result);
	if (err < 0) {
		nvme_show_error("dir-send: %s", nvme_strerror(err));
		return err;
	}
	if (!err) {
		printf("dir-send: type %#x, operation %#x, spec_val %#x, nsid %#x, result %#x\n",
		       cfg.dtype, cfg.doper, cfg.dspec, cfg.namespace_id, result);
		if (buf) {
			if (!cfg.raw_binary)
				d(buf, cfg.data_len, 16, 1);
			else
				d_raw(buf, cfg.data_len);
		}
	} else if (err > 0) {
		nvme_show_status(err);
	}

	return err;
}

static int write_uncor(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc =
	    "The Write Uncorrectable command is used to set a range of logical blocks to invalid.";

	_cleanup_nvme_global_ctx_ struct nvme_global_ctx *ctx = NULL;
	_cleanup_nvme_transport_handle_ struct nvme_transport_handle *hdl = NULL;
	struct nvme_passthru_cmd cmd;
	int err;

	struct config {
		__u32	namespace_id;
		__u64	start_block;
		__u16	block_count;
		__u8	dtype;
		__u16	dspec;
	};

	struct config cfg = {
		.namespace_id	= 0,
		.start_block	= 0,
		.block_count	= 0,
		.dtype			= 0,
		.dspec			= 0,
	};

	NVME_ARGS(opts,
		  OPT_UINT("namespace-id",  'n', &cfg.namespace_id, namespace_desired),
		  OPT_SUFFIX("start-block", 's', &cfg.start_block,  start_block),
		  OPT_SHRT("block-count",   'c', &cfg.block_count,  block_count),
		  OPT_BYTE("dir-type",      'T', &cfg.dtype,        dtype),
		  OPT_SHRT("dir-spec",      'S', &cfg.dspec,        dspec_w_dtype));

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	if (!cfg.namespace_id) {
		err = nvme_get_nsid(hdl, &cfg.namespace_id);
		if (err < 0) {
			nvme_show_error("get-namespace-id: %s", nvme_strerror(err));
			return err;
		}
	}

	if (cfg.dtype > 0xf) {
		nvme_show_error("Invalid directive type, %x",	cfg.dtype);
		return -EINVAL;
	}

	nvme_init_write_uncorrectable(&cmd, cfg.namespace_id, cfg.start_block,
		cfg.block_count, cfg.dtype << 4, cfg.dspec);
	err = nvme_submit_admin_passthru(hdl, &cmd, NULL);
	if (err < 0)
		nvme_show_error("write uncorrectable: %s", nvme_strerror(err));
	else if (err != 0)
		nvme_show_status(err);
	else
		printf("NVME Write Uncorrectable Success\n");

	return err;
}

static int invalid_tags(__u64 storage_tag, __u64 ref_tag, __u8 sts, __u8 pif)
{
	int result = 0;

	if (sts < 64 && storage_tag >= (1LL << sts)) {
		nvme_show_error("Storage tag larger than storage tag size");
		return 1;
	}

	switch (pif) {
	case NVME_NVM_PIF_16B_GUARD:
		if (ref_tag >= (1LL << (32 - sts)))
			result = 1;
		break;
	case NVME_NVM_PIF_32B_GUARD:
		if (sts > 16 && ref_tag >= (1LL << (80 - sts)))
			result = 1;
		break;
	case NVME_NVM_PIF_64B_GUARD:
		if (sts > 0 && ref_tag >= (1LL << (48 - sts)))
			result = 1;
		break;
	default:
		nvme_show_error("Invalid PIF");
		result = 1;
		break;
	}

	if (result)
		nvme_show_error("Reference tag larger than allowed by PIF");

	return result;
}

static void get_pif_sts(struct nvme_id_ns *ns, struct nvme_nvm_id_ns *nvm_ns, __u8 *pif, __u8 *sts)
{
	__u8 lba_index;
	__u32 elbaf;

	nvme_id_ns_flbas_to_lbaf_inuse(ns->flbas, &lba_index);
	elbaf = le32_to_cpu(nvm_ns->elbaf[lba_index]);
	*sts = elbaf & NVME_NVM_ELBAF_STS_MASK;
	*pif = (elbaf & NVME_NVM_ELBAF_PIF_MASK) >> 7;
	if (*pif == NVME_NVM_PIF_QTYPE && (nvm_ns->pic & 0x8))
		*pif = (elbaf & NVME_NVM_ELBAF_QPIF_MASK) >> 9;
}

static int write_zeroes(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	_cleanup_free_ struct nvme_nvm_id_ns *nvm_ns = NULL;
	_cleanup_free_ struct nvme_id_ns *ns = NULL;
	_cleanup_nvme_global_ctx_ struct nvme_global_ctx *ctx = NULL;
	_cleanup_nvme_transport_handle_ struct nvme_transport_handle *hdl = NULL;
	struct nvme_passthru_cmd cmd;
	__u8 sts = 0, pif = 0;
	__u16 control = 0;
	__u32 result = 0;
	int err;

	const char *desc =
	    "The Write Zeroes command is used to set a range of logical blocks to zero.";
	const char *deac =
	    "Set DEAC bit, requesting controller to deallocate specified logical blocks";
	const char *storage_tag_check =
	    "This bit specifies the Storage Tag field shall be checked as\n"
	    "part of end-to-end data protection processing";
	const char *nsz = "Clear all logical blocks to zero in the entire namespace";

	struct config {
		__u32	namespace_id;
		__u64	start_block;
		__u16	block_count;
		__u8	dtype;
		bool	deac;
		bool	limited_retry;
		bool	force_unit_access;
		__u8	prinfo;
		__u64	ref_tag;
		__u16	app_tag_mask;
		__u16	app_tag;
		__u64	storage_tag;
		bool	storage_tag_check;
		__u16	dspec;
		bool	nsz;
	};

	struct config cfg = {
		.namespace_id		= 0,
		.start_block		= 0,
		.block_count		= 0,
		.dtype			= 0,
		.deac			= false,
		.limited_retry		= false,
		.force_unit_access	= false,
		.prinfo			= 0,
		.ref_tag		= 0,
		.app_tag_mask		= 0,
		.app_tag		= 0,
		.storage_tag		= 0,
		.storage_tag_check	= false,
		.dspec			= 0,
		.nsz			= false,
	};

	NVME_ARGS(opts,
		  OPT_UINT("namespace-id",      'n', &cfg.namespace_id,      namespace_desired),
		  OPT_SUFFIX("start-block",     's', &cfg.start_block,       start_block),
		  OPT_SHRT("block-count",       'c', &cfg.block_count,       block_count),
		  OPT_BYTE("dir-type",          'T', &cfg.dtype,             dtype),
		  OPT_FLAG("deac",              'd', &cfg.deac,              deac),
		  OPT_FLAG("limited-retry",     'l', &cfg.limited_retry,     limited_retry),
		  OPT_FLAG("force-unit-access", 'f', &cfg.force_unit_access, force_unit_access),
		  OPT_BYTE("prinfo",            'p', &cfg.prinfo,            prinfo),
		  OPT_SUFFIX("ref-tag",         'r', &cfg.ref_tag,           ref_tag),
		  OPT_SHRT("app-tag-mask",      'm', &cfg.app_tag_mask,      app_tag_mask),
		  OPT_SHRT("app-tag",           'a', &cfg.app_tag,           app_tag),
		  OPT_SUFFIX("storage-tag",     'S', &cfg.storage_tag,       storage_tag),
		  OPT_FLAG("storage-tag-check", 'C', &cfg.storage_tag_check, storage_tag_check),
		  OPT_SHRT("dir-spec",          'D', &cfg.dspec,             dspec_w_dtype),
		  OPT_FLAG("namespace-zeroes",  'Z', &cfg.nsz,               nsz));

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	if (cfg.prinfo > 0xf)
		return -EINVAL;

	if (cfg.dtype > 0x7) {
		nvme_show_error("Invalid directive type, %x", cfg.dtype);
		return -EINVAL;
	}

	control |= (cfg.prinfo << 10);
	if (cfg.limited_retry)
		control |= NVME_IO_LR;
	if (cfg.force_unit_access)
		control |= NVME_IO_FUA;
	if (cfg.deac)
		control |= NVME_IO_DEAC;
	if (cfg.storage_tag_check)
		control |= NVME_IO_STC;
	if (cfg.nsz)
		control |= NVME_IO_NSZ;
	control |= (cfg.dtype << 4);
	if (!cfg.namespace_id) {
		err = nvme_get_nsid(hdl, &cfg.namespace_id);
		if (err < 0) {
			nvme_show_error("get-namespace-id: %s", nvme_strerror(err));
			return err;
		}
	}

	ns = nvme_alloc(sizeof(*ns));
	if (!ns)
		return -ENOMEM;

	err = nvme_identify_ns(hdl, cfg.namespace_id, ns);
	if (err < 0) {
		nvme_show_error("identify namespace: %s", nvme_strerror(err));
		return err;
	} else if (err) {
		nvme_show_status(err);
		return err;
	}

	nvm_ns = nvme_alloc(sizeof(*nvm_ns));
	if (!nvm_ns)
		return -ENOMEM;

	err = nvme_identify_csi_ns(hdl, cfg.namespace_id, NVME_CSI_NVM, 0,
				   nvm_ns);
	if (!err) {
		get_pif_sts(ns, nvm_ns, &pif, &sts);
	}

	if (invalid_tags(cfg.storage_tag, cfg.ref_tag, sts, pif))
		return -EINVAL;

	nvme_init_write_zeros(&cmd, cfg.namespace_id, cfg.start_block,
		cfg.block_count, control, cfg.dspec, 0, 0);
	nvme_init_var_size_tags((struct nvme_passthru_cmd64 *)&cmd, pif, sts,
		cfg.ref_tag, cfg.storage_tag);
	nvme_init_app_tag((struct nvme_passthru_cmd64 *)&cmd, cfg.app_tag,
		cfg.app_tag_mask);
	err = nvme_submit_io_passthru(hdl, &cmd, &result);
	if (err < 0)
		nvme_show_error("write-zeroes: %s", nvme_strerror(err));
	else if (err != 0)
		nvme_show_status(err);
	else {
		printf("NVME Write Zeroes Success\n");
		if (cfg.nsz && argconfig_parse_seen(opts, "verbose")) {
			if (result & 0x1)
				printf("All logical blocks in the entire namespace cleared to zero\n");
			else
				printf("%d logical blocks cleared to zero\n", cfg.block_count);
		}
	}

	return err;
}

static int dsm(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc = "The Dataset Management command is used by the host to\n"
		"indicate attributes for ranges of logical blocks. This includes attributes\n"
		"for discarding unused blocks, data read and write frequency, access size, and other\n"
		"information that may be used to optimize performance and reliability.";
	const char *blocks = "Comma separated list of the number of blocks in each range";
	const char *starting_blocks = "Comma separated list of the starting block in each range";
	const char *context_attrs = "Comma separated list of the context attributes in each range";
	const char *ad = "Attribute Deallocate";
	const char *idw = "Attribute Integral Dataset for Write";
	const char *idr = "Attribute Integral Dataset for Read";
	const char *cdw11 = "All the command DWORD 11 attributes. Use instead of specifying individual attributes";

	_cleanup_nvme_global_ctx_ struct nvme_global_ctx *ctx = NULL;
	_cleanup_nvme_transport_handle_ struct nvme_transport_handle *hdl = NULL;
	_cleanup_free_ struct nvme_dsm_range *dsm = NULL;
	struct nvme_passthru_cmd cmd;
	__u32 ctx_attrs[256] = {0,};
	__u32 nlbs[256] = {0,};
	__u64 slbas[256] = {0,};
	nvme_print_flags_t flags;
	uint16_t nc, nb, ns;
	int err;

	struct config {
		__u32	namespace_id;
		char	*ctx_attrs;
		char	*blocks;
		char	*slbas;
		bool	ad;
		bool	idw;
		bool	idr;
		__u32	cdw11;
	};

	struct config cfg = {
		.namespace_id	= 0,
		.ctx_attrs	= "",
		.blocks		= "",
		.slbas		= "",
		.ad		= false,
		.idw		= false,
		.idr		= false,
		.cdw11		= 0,
	};

	NVME_ARGS(opts,
		  OPT_UINT("namespace-id", 'n', &cfg.namespace_id, namespace_id_desired),
		  OPT_LIST("ctx-attrs",    'a', &cfg.ctx_attrs,    context_attrs),
		  OPT_LIST("blocks",       'b', &cfg.blocks,       blocks),
		  OPT_LIST("slbs",         's', &cfg.slbas,        starting_blocks),
		  OPT_FLAG("ad",           'd', &cfg.ad,           ad),
		  OPT_FLAG("idw",          'w', &cfg.idw,          idw),
		  OPT_FLAG("idr",          'r', &cfg.idr,          idr),
		  OPT_UINT("cdw11",        'c', &cfg.cdw11,        cdw11));

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	err = validate_output_format(nvme_cfg.output_format, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	nc = argconfig_parse_comma_sep_array_u32(cfg.ctx_attrs, ctx_attrs, ARRAY_SIZE(ctx_attrs));
	nb = argconfig_parse_comma_sep_array_u32(cfg.blocks, nlbs, ARRAY_SIZE(nlbs));
	ns = argconfig_parse_comma_sep_array_u64(cfg.slbas, slbas, ARRAY_SIZE(slbas));
	if (nc != nb || nb != ns) {
		nvme_show_error("No valid range definition provided");
		return -EINVAL;
	}
	if (!nc || nc > 256) {
		nvme_show_error("No range definition provided");
		return -EINVAL;
	}

	if (!cfg.namespace_id) {
		err = nvme_get_nsid(hdl, &cfg.namespace_id);
		if (err < 0) {
			nvme_show_error("get-namespace-id: %s", nvme_strerror(err));
			return err;
		}
	}
	if (cfg.cdw11) {
		cfg.ad = NVME_GET(cfg.cdw11, DSM_CDW11_AD);
		cfg.idw = NVME_GET(cfg.cdw11, DSM_CDW11_IDW);
		cfg.idr = NVME_GET(cfg.cdw11, DSM_CDW11_IDR);
	}

	dsm = nvme_alloc(sizeof(*dsm) * nc);
	if (!dsm)
		return -ENOMEM;

	nvme_init_dsm_range(dsm, ctx_attrs, nlbs, slbas, nc);
	nvme_init_dsm(&cmd, cfg.namespace_id, nc, cfg.idr, cfg.idw, cfg.ad, dsm,
		      sizeof(*dsm) * nc);
	err = nvme_submit_io_passthru(hdl, &cmd, NULL);
	if (err < 0)
		nvme_show_error("data-set management: %s", nvme_strerror(err));
	else if (err != 0)
		nvme_show_status(err);
	else
		printf("NVMe DSM: success\n");

	return err;
}

static int identify_pif_sts(struct nvme_transport_handle *hdl,
			    __u32 nsid, __u8 *pif, __u8 *sts)
{
	_cleanup_free_ struct nvme_nvm_id_ns *nvm_ns = NULL;
	_cleanup_free_ struct nvme_id_ns *ns = NULL;
	int err;

	ns = nvme_alloc(sizeof(*ns));
	if (!ns)
		return -ENOMEM;

	err = nvme_identify_ns(hdl, nsid, ns);
	if (err > 0) {
		nvme_show_status(err);
		return err;
	} else if (err < 0) {
		nvme_show_error("identify namespace: %s", nvme_strerror(-err));
		return err;
	}

	nvm_ns = nvme_alloc(sizeof(*nvm_ns));
	if (!nvm_ns)
		return -ENOMEM;

	err = nvme_identify_csi_ns(hdl, nsid, NVME_CSI_NVM, 0, nvm_ns);
	if (!err)
		get_pif_sts(ns, nvm_ns, pif, sts);

	return 0;
}

static int copy_cmd(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc = "The Copy command is used by the host to copy data\n"
		"from one or more source logical block ranges to a\n"
		"single consecutive destination logical block range.";
	const char *d_sdlba = "64-bit addr of first destination logical block";
	const char *d_slbas = "64-bit addr of first block per range (comma-separated list)";
	const char *d_nlbs = "number of blocks per range (comma-separated list, zeroes-based values)";
	const char *d_snsids = "source namespace identifier per range (comma-separated list)";
	const char *d_sopts = "source options per range (comma-separated list)";
	const char *d_lr = "limited retry";
	const char *d_fua = "force unit access";
	const char *d_prinfor = "protection information and check field (read part)";
	const char *d_prinfow = "protection information and check field (write part)";
	const char *d_ilbrt = "initial lba reference tag (write part)";
	const char *d_eilbrts = "expected lba reference tags (read part, comma-separated list)";
	const char *d_lbat = "lba application tag (write part)";
	const char *d_elbats = "expected lba application tags (read part, comma-separated list)";
	const char *d_lbatm = "lba application tag mask (write part)";
	const char *d_elbatms = "expected lba application tag masks (read part, comma-separated list)";
	const char *d_dtype = "directive type (write part)";
	const char *d_dspec = "directive specific (write part)";
	const char *d_format = "source range entry format";

	_cleanup_nvme_global_ctx_ struct nvme_global_ctx *ctx = NULL;
	_cleanup_nvme_transport_handle_ struct nvme_transport_handle *hdl = NULL;
	__u16 nr, nb, ns, nrts, natms, nats, nids;
	struct nvme_passthru_cmd cmd;
	__u16 nlbs[256] = { 0 };
	__u64 slbas[256] = { 0 };
	__u32 snsids[256] = { 0 };
	__u16 sopts[256] = { 0 };
	__u8 pif = 0;
	__u8 sts = 0;
	int err;

	union {
		__u32 short_pi[256];
		__u64 long_pi[256];
	} eilbrts;

	__u32 elbatms[256] = { 0 };
	__u32 elbats[256] = { 0 };

	_cleanup_free_ union {
		struct nvme_copy_range f0[256];
		struct nvme_copy_range_f1 f1[256];
		struct nvme_copy_range_f2 f2[256];
		struct nvme_copy_range_f3 f3[256];
	} *copy = NULL;

	struct config {
		__u32	namespace_id;
		__u64	sdlba;
		char	*slbas;
		char	*nlbs;
		char	*snsids;
		char	*sopts;
		bool	lr;
		bool	fua;
		__u8	prinfow;
		__u8	prinfor;
		__u64	ilbrt;
		char	*eilbrts;
		__u16	lbat;
		char	*elbats;
		__u16	lbatm;
		char	*elbatms;
		__u8	dtype;
		__u16	dspec;
		__u8	format;
	};

	struct config cfg = {
		.namespace_id	= 0,
		.sdlba		= 0,
		.slbas		= "",
		.nlbs		= "",
		.snsids		= "",
		.sopts		= "",
		.lr		= false,
		.fua		= false,
		.prinfow	= 0,
		.prinfor	= 0,
		.ilbrt		= 0,
		.eilbrts	= "",
		.lbat		= 0,
		.elbats		= "",
		.lbatm		= 0,
		.elbatms	= "",
		.dtype		= 0,
		.dspec		= 0,
		.format		= 0,
	};

	NVME_ARGS(opts,
		  OPT_UINT("namespace-id",           'n', &cfg.namespace_id,	namespace_id_desired),
		  OPT_SUFFIX("sdlba",                'd', &cfg.sdlba,		d_sdlba),
		  OPT_LIST("slbs",                   's', &cfg.slbas,		d_slbas),
		  OPT_LIST("blocks",                 'b', &cfg.nlbs,		d_nlbs),
		  OPT_LIST("snsids",                 'N', &cfg.snsids,		d_snsids),
		  OPT_LIST("sopts",                  'O', &cfg.sopts,		d_sopts),
		  OPT_FLAG("limited-retry",          'l', &cfg.lr,		d_lr),
		  OPT_FLAG("force-unit-access",      'f', &cfg.fua,		d_fua),
		  OPT_BYTE("prinfow",                'p', &cfg.prinfow,		d_prinfow),
		  OPT_BYTE("prinfor",                'P', &cfg.prinfor,		d_prinfor),
		  OPT_SUFFIX("ref-tag",              'r', &cfg.ilbrt,		d_ilbrt),
		  OPT_LIST("expected-ref-tags",      'R', &cfg.eilbrts,		d_eilbrts),
		  OPT_SHRT("app-tag",                'a', &cfg.lbat,		d_lbat),
		  OPT_LIST("expected-app-tags",      'A', &cfg.elbats,		d_elbats),
		  OPT_SHRT("app-tag-mask",           'm', &cfg.lbatm,		d_lbatm),
		  OPT_LIST("expected-app-tag-masks", 'M', &cfg.elbatms,		d_elbatms),
		  OPT_BYTE("dir-type",               'T', &cfg.dtype,		d_dtype),
		  OPT_SHRT("dir-spec",               'S', &cfg.dspec,		d_dspec),
		  OPT_BYTE("format",                 'F', &cfg.format,		d_format));

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	nb = argconfig_parse_comma_sep_array_u16(cfg.nlbs, nlbs,
						 ARRAY_SIZE(nlbs));
	ns = argconfig_parse_comma_sep_array_u64(cfg.slbas, slbas,
						 ARRAY_SIZE(slbas));
	nids = argconfig_parse_comma_sep_array_u32(cfg.snsids, snsids,
						 ARRAY_SIZE(snsids));
	argconfig_parse_comma_sep_array_u16(cfg.sopts, sopts,
						 ARRAY_SIZE(sopts));

	switch (cfg.format) {
	case 0:
	case 2:
		nrts = argconfig_parse_comma_sep_array_u32(cfg.eilbrts,
				eilbrts.short_pi, ARRAY_SIZE(eilbrts.short_pi));
		break;
	case 1:
	case 3:
		nrts = argconfig_parse_comma_sep_array_u64(cfg.eilbrts,
				eilbrts.long_pi, ARRAY_SIZE(eilbrts.long_pi));
		break;
	default:
		nvme_show_error("invalid format");
		return -EINVAL;
	}

	natms = argconfig_parse_comma_sep_array_u32(cfg.elbatms, elbatms,
						    ARRAY_SIZE(elbatms));
	nats = argconfig_parse_comma_sep_array_u32(cfg.elbats, elbats,
						   ARRAY_SIZE(elbats));

	nr = max(nb, max(ns, max(nrts, max(natms, nats))));
	if (cfg.format == 2 || cfg.format == 3) {
		if (nr != nids) {
			nvme_show_error("formats 2 and 3 require source namespace ids for each source range");
			return -EINVAL;
		}
	} else if (nids) {
		nvme_show_error("formats 0 and 1 do not support cross-namespace copy");
		return -EINVAL;
	}
	if (!nr || nr > 256) {
		nvme_show_error("invalid range");
		return -EINVAL;
	}

	if (!cfg.namespace_id) {
		err = nvme_get_nsid(hdl, &cfg.namespace_id);
		if (err < 0) {
			nvme_show_error("get-namespace-id: %s", nvme_strerror(err));
			return err;
		}
	}

	copy = nvme_alloc(sizeof(*copy));
	if (!copy)
		return -ENOMEM;

	switch (cfg.format) {
	case 1:
		nvme_init_copy_range_f1(copy->f1, nlbs, slbas, eilbrts.long_pi,
					elbatms, elbats, nr);
		break;
	case 2:
		nvme_init_copy_range_f2(copy->f2, snsids, nlbs, slbas, sopts,
					eilbrts.short_pi, elbatms, elbats, nr);
		break;
	case 3:
		nvme_init_copy_range_f3(copy->f3, snsids, nlbs, slbas, sopts,
					eilbrts.long_pi, elbatms, elbats, nr);
		break;
	default:
		nvme_init_copy_range(copy->f0, nlbs, slbas, eilbrts.short_pi,
				     elbatms, elbats, nr);
		break;
	}

	err = identify_pif_sts(hdl, cfg.namespace_id, &pif, &sts);
	if (err)
		return err;

	if (invalid_tags(0, cfg.ilbrt, sts, pif))
		return -EINVAL;

	nvme_init_copy(&cmd, cfg.namespace_id, cfg.sdlba, nr, cfg.format,
		       cfg.prinfor, cfg.prinfow, 0, cfg.dtype, false, false,
		       cfg.fua, cfg.lr, 0, cfg.dspec, copy->f0);
	nvme_init_var_size_tags((struct nvme_passthru_cmd64 *)&cmd, pif, sts,
				cfg.ilbrt, 0);
	nvme_init_app_tag((struct nvme_passthru_cmd64 *)&cmd, cfg.lbat,
		cfg.lbatm);
	err = nvme_submit_io_passthru(hdl, &cmd, NULL);
	if (err < 0)
		nvme_show_error("NVMe Copy: %s", nvme_strerror(err));
	else if (err != 0)
		nvme_show_status(err);
	else
		nvme_show_key_value("NVMe Copy", "success");

	return err;
}

static int flush_cmd(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc = "Commit data and metadata associated with\n"
		"given namespaces to nonvolatile media. Applies to all commands\n"
		"finished before the flush was submitted. Additional data may also be\n"
		"flushed by the controller, from any namespace, depending on controller and\n"
		"associated namespace status.";

	_cleanup_nvme_global_ctx_ struct nvme_global_ctx *ctx = NULL;
	_cleanup_nvme_transport_handle_ struct nvme_transport_handle *hdl = NULL;
	int err;

	struct config {
		__u32	namespace_id;
	};

	struct config cfg = {
		.namespace_id	= 0,
	};

	NVME_ARGS(opts,
		  OPT_UINT("namespace-id", 'n', &cfg.namespace_id, namespace_id_desired));

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	if (!cfg.namespace_id) {
		err = nvme_get_nsid(hdl, &cfg.namespace_id);
		if (err < 0) {
			nvme_show_error("get-namespace-id: %s", nvme_strerror(err));
			return err;
		}
	}

	err = nvme_flush(hdl, cfg.namespace_id);
	if (err < 0)
		nvme_show_error("flush: %s", nvme_strerror(err));
	else if (err != 0)
		nvme_show_status(err);
	else
		printf("NVMe Flush: success\n");

	return err;
}

static int resv_acquire(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc = "Obtain a reservation on a given\n"
		"namespace. Only one reservation is allowed at a time on a\n"
		"given namespace, though multiple controllers may register\n"
		"with that namespace. Namespace reservation will abort with\n"
		"status Reservation Conflict if the given namespace is already reserved.";
	const char *prkey = "pre-empt reservation key";
	const char *racqa = "reservation acquire action";

	_cleanup_nvme_transport_handle_ struct nvme_transport_handle *hdl = NULL;
	_cleanup_nvme_global_ctx_ struct nvme_global_ctx *ctx = NULL;
	struct nvme_passthru_cmd cmd;
	nvme_print_flags_t flags;
	__le64 payload[2];
	int err;

	struct config {
		__u32	namespace_id;
		__u64	crkey;
		__u64	prkey;
		__u8	rtype;
		__u8	racqa;
		bool	iekey;
	};

	struct config cfg = {
		.namespace_id	= 0,
		.crkey		= 0,
		.prkey		= 0,
		.rtype		= 0,
		.racqa		= 0,
		.iekey		= false,
	};

	NVME_ARGS(opts,
		  OPT_UINT("namespace-id", 'n', &cfg.namespace_id, namespace_id_desired),
		  OPT_SUFFIX("crkey",      'c', &cfg.crkey,        crkey),
		  OPT_SUFFIX("prkey",      'p', &cfg.prkey,        prkey),
		  OPT_BYTE("rtype",        't', &cfg.rtype,        rtype),
		  OPT_BYTE("racqa",        'a', &cfg.racqa,        racqa),
		  OPT_FLAG("iekey",        'i', &cfg.iekey,        iekey));

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	err = validate_output_format(nvme_cfg.output_format, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	if (!cfg.namespace_id) {
		err = nvme_get_nsid(hdl, &cfg.namespace_id);
		if (err < 0) {
			nvme_show_error("get-namespace-id: %s", nvme_strerror(err));
			return err;
		}
	}
	if (cfg.racqa > 7) {
		nvme_show_error("invalid racqa:%d", cfg.racqa);
		return -EINVAL;
	}

	nvme_init_resv_acquire(&cmd, cfg.namespace_id, cfg.racqa, cfg.iekey,
			       false, cfg.rtype, cfg.crkey, cfg.prkey, payload);
	err = nvme_submit_io_passthru(hdl, &cmd, NULL);
	if (err < 0)
		nvme_show_error("reservation acquire: %s", nvme_strerror(err));
	else if (err > 0)
		nvme_show_status(err);
	else
		printf("NVME Reservation Acquire success\n");

	return err;
}

static int resv_register(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc = "Register, de-register, or\n"
		"replace a controller's reservation on a given namespace.\n"
		"Only one reservation at a time is allowed on any namespace.";
	const char *nrkey = "new reservation key";
	const char *rrega = "reservation registration action";
	const char *cptpl = "change persistence through power loss setting";

	_cleanup_nvme_transport_handle_ struct nvme_transport_handle *hdl = NULL;
	_cleanup_nvme_global_ctx_ struct nvme_global_ctx *ctx = NULL;
	struct nvme_passthru_cmd cmd;
	nvme_print_flags_t flags;
	__le64 payload[2];
	int err;

	struct config {
		__u32	namespace_id;
		__u64	crkey;
		__u64	nrkey;
		__u8	rrega;
		__u8	cptpl;
		bool	iekey;
	};

	struct config cfg = {
		.namespace_id	= 0,
		.crkey		= 0,
		.nrkey		= 0,
		.rrega		= 0,
		.cptpl		= false,
	};

	NVME_ARGS(opts,
		  OPT_UINT("namespace-id", 'n', &cfg.namespace_id, namespace_id_desired),
		  OPT_SUFFIX("crkey",      'c', &cfg.crkey,        crkey),
		  OPT_SUFFIX("nrkey",      'k', &cfg.nrkey,        nrkey),
		  OPT_BYTE("rrega",        'r', &cfg.rrega,        rrega),
		  OPT_BYTE("cptpl",        'p', &cfg.cptpl,        cptpl),
		  OPT_FLAG("iekey",        'i', &cfg.iekey,        iekey));

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	err = validate_output_format(nvme_cfg.output_format, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	if (!cfg.namespace_id) {
		err = nvme_get_nsid(hdl, &cfg.namespace_id);
		if (err < 0) {
			nvme_show_error("get-namespace-id: %s", nvme_strerror(err));
			return err;
		}
	}
	if (cfg.cptpl > 3) {
		nvme_show_error("invalid cptpl:%d", cfg.cptpl);
		return -EINVAL;
	}

	if (cfg.rrega > 7) {
		nvme_show_error("invalid rrega:%d", cfg.rrega);
		return -EINVAL;
	}

	nvme_init_resv_register(&cmd, cfg.namespace_id, cfg.rrega, cfg.iekey,
				false, cfg.cptpl, cfg.crkey, cfg.nrkey,
				payload);
	err = nvme_submit_io_passthru(hdl, &cmd, NULL);
	if (err < 0)
		nvme_show_error("reservation register: %s", nvme_strerror(err));
	else if (err > 0)
		nvme_show_status(err);
	else
		printf("NVME Reservation  success\n");

	return err;
}

static int resv_release(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc = "Releases reservation held on a\n"
		"namespace by the given controller. If rtype != current reservation\n"
		"type, release will fails. If the given controller holds no\n"
		"reservation on the namespace or is not the namespace's current\n"
		"reservation holder, the release command completes with no\n"
		"effect. If the reservation type is not Write Exclusive or\n"
		"Exclusive Access, all registrants on the namespace except\n"
		"the issuing controller are notified.";
	const char *rrela = "reservation release action";

	_cleanup_nvme_transport_handle_ struct nvme_transport_handle *hdl = NULL;
	_cleanup_nvme_global_ctx_ struct nvme_global_ctx *ctx = NULL;
	struct nvme_passthru_cmd cmd;
	nvme_print_flags_t flags;
	__le64 payload[1];
	int err;

	struct config {
		__u32	nsid;
		__u64	crkey;
		__u8	rtype;
		__u8	rrela;
		__u8	iekey;
	};

	struct config cfg = {
		.nsid		= 0,
		.crkey		= 0,
		.rtype		= 0,
		.rrela		= 0,
		.iekey		= 0,
	};

	NVME_ARGS(opts,
		  OPT_UINT("namespace-id", 'n', &cfg.nsid,		namespace_desired),
		  OPT_SUFFIX("crkey",      'c', &cfg.crkey,     crkey),
		  OPT_BYTE("rtype",        't', &cfg.rtype,     rtype),
		  OPT_BYTE("rrela",        'a', &cfg.rrela,     rrela),
		  OPT_FLAG("iekey",        'i', &cfg.iekey,     iekey));

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	err = validate_output_format(nvme_cfg.output_format, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	if (!cfg.nsid) {
		err = nvme_get_nsid(hdl, &cfg.nsid);
		if (err < 0) {
			nvme_show_error("get-namespace-id: %s", nvme_strerror(err));
			return err;
		}
	}
	if (cfg.rrela > 7) {
		nvme_show_error("invalid rrela:%d", cfg.rrela);
		return -EINVAL;
	}

	nvme_init_resv_release(&cmd, cfg.nsid, cfg.rrela, cfg.iekey, false,
		cfg.rtype, cfg.crkey, payload);
	err = nvme_submit_io_passthru(hdl, &cmd, NULL);
	if (err < 0)
		nvme_show_error("reservation release: %s", nvme_strerror(err));
	else if (err != 0)
		nvme_show_status(err);
	else
		printf("NVME Reservation Release success\n");

	return err;
}

static int resv_report(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc = "Returns Reservation Status data\n"
		"structure describing any existing reservations on and the\n"
		"status of a given namespace. Namespace Reservation Status\n"
		"depends on the number of controllers registered for that namespace.";
	const char *numd = "number of dwords to transfer";
	const char *eds = "request extended data structure";

	_cleanup_nvme_transport_handle_ struct nvme_transport_handle *hdl = NULL;
	_cleanup_nvme_global_ctx_ struct nvme_global_ctx *ctx = NULL;
	_cleanup_free_ struct nvme_resv_status *status = NULL;
	_cleanup_free_ struct nvme_id_ctrl *ctrl = NULL;
	struct nvme_passthru_cmd cmd;
	nvme_print_flags_t flags;
	int err, size;

	struct config {
		__u32	nsid;
		__u32	numd;
		__u8	eds;
		bool	raw_binary;
	};

	struct config cfg = {
		.nsid		= 0,
		.numd		= 0,
		.eds		= false,
		.raw_binary	= false,
	};

	NVME_ARGS(opts,
		  OPT_UINT("namespace-id",  'n', &cfg.nsid,		  namespace_id_desired),
		  OPT_UINT("numd",          'd', &cfg.numd,       numd),
		  OPT_FLAG("eds",           'e', &cfg.eds,        eds),
		  OPT_FLAG("raw-binary",    'b', &cfg.raw_binary, raw_dump));

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	err = validate_output_format(nvme_cfg.output_format, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	if (cfg.raw_binary)
		flags = BINARY;

	if (!cfg.nsid) {
		err = nvme_get_nsid(hdl, &cfg.nsid);
		if (err < 0) {
			nvme_show_error("get-namespace-id: %s", nvme_strerror(err));
			return err;
		}
	}

	if (!cfg.numd || cfg.numd >= (0x1000 >> 2))
		cfg.numd = (0x1000 >> 2) - 1;
	if (cfg.numd < 3)
		cfg.numd = 3;

	size = (cfg.numd + 1) << 2;

	ctrl = nvme_alloc(sizeof(*ctrl));
	if (!ctrl)
		return -ENOMEM;

	err = nvme_identify_ctrl(hdl, ctrl);
	if (err) {
		nvme_show_error("identify-ctrl: %s", nvme_strerror(err));
		return -errno;
	}

	if (ctrl->ctratt & NVME_CTRL_CTRATT_128_ID)
		cfg.eds = true;

	status = nvme_alloc(size);
	if (!status)
		return -ENOMEM;

	nvme_init_resv_report(&cmd, cfg.nsid, cfg.eds, false, status, size);
	err = nvme_submit_io_passthru(hdl, &cmd, NULL);
	if (!err)
		nvme_show_resv_report(status, size, cfg.eds, flags);
	else if (err > 0)
		nvme_show_status(err);
	else
		nvme_show_error("reservation report: %s", nvme_strerror(err));

	return err;
}

unsigned long long elapsed_utime(struct timeval start_time,
					struct timeval end_time)
{
	unsigned long long err = (end_time.tv_sec - start_time.tv_sec) * 1000000 +
		(end_time.tv_usec - start_time.tv_usec);
	return err;
}

static int submit_io(int opcode, char *command, const char *desc, int argc, char **argv)
{
	_cleanup_nvme_transport_handle_ struct nvme_transport_handle *hdl = NULL;
	_cleanup_nvme_global_ctx_ struct nvme_global_ctx *ctx = NULL;
	unsigned long long buffer_size = 0, mbuffer_size = 0;
	_cleanup_free_ struct nvme_nvm_id_ns *nvm_ns = NULL;
	_cleanup_huge_ struct nvme_mem_huge mh = { 0, };
	_cleanup_free_ struct nvme_id_ns *ns = NULL;
	unsigned int logical_block_size = 0;
	struct timeval start_time, end_time;
	_cleanup_free_ void *mbuffer = NULL;
	_cleanup_fd_ int dfd = -1, mfd = -1;
	__u8 lba_index, sts = 0, pif = 0;
	__u16 control = 0, nblocks = 0;
	struct nvme_passthru_cmd cmd;
	int flags, pi_size;
	__u32 dsmgmt = 0;
	int mode = 0644;
	void *buffer;
	int err = 0;
	__u16 ms;

	const char *start_block_addr = "64-bit addr of first block to access";
	const char *block_size = "if specified, logical block size in bytes;\n"
		"discovered by identify namespace otherwise";
	const char *data_size = "size of data in bytes";
	const char *metadata_size = "size of metadata in bytes";
	const char *data = "data file";
	const char *metadata = "metadata file";
	const char *limited_retry_num = "limit num. media access attempts";
	const char *show = "show command before sending";
	const char *dtype_for_write = "directive type (for write-only)";
	const char *dspec = "directive specific (for write-only)";
	const char *dsm = "dataset management attributes (lower 8 bits)";
	const char *storage_tag_check = "This bit specifies the Storage Tag field shall be\n"
		"checked as part of end-to-end data protection processing";
	const char *force = "The \"I know what I'm doing\" flag, do not enforce exclusive access for write";

	struct config {
		__u32	namespace_id;
		__u64	start_block;
		__u16	block_count;
		__u16	block_size;
		__u64	data_size;
		__u64	metadata_size;
		__u64	ref_tag;
		char	*data;
		char	*metadata;
		__u8	prinfo;
		__u16	app_tag_mask;
		__u16	app_tag;
		__u64	storage_tag;
		bool	limited_retry;
		bool	force_unit_access;
		bool	storage_tag_check;
		__u8	dtype;
		__u16	dspec;
		__u8	dsmgmt;
		bool	show;
		bool	latency;
		bool	force;
	};

	struct config cfg = {
		.namespace_id		= 0,
		.start_block		= 0,
		.block_count		= 0,
		.block_size		= 0,
		.data_size		= 0,
		.metadata_size		= 0,
		.ref_tag		= 0,
		.data			= "",
		.metadata		= "",
		.prinfo			= 0,
		.app_tag_mask		= 0,
		.app_tag		= 0,
		.storage_tag		= 0,
		.limited_retry		= false,
		.force_unit_access	= false,
		.storage_tag_check	= false,
		.dtype			= 0,
		.dspec			= 0,
		.dsmgmt			= 0,
		.show			= false,
		.latency		= false,
		.force			= false,
	};

	NVME_ARGS(opts,
		  OPT_UINT("namespace-id",      'n', &cfg.namespace_id,      namespace_id_desired),
		  OPT_SUFFIX("start-block",     's', &cfg.start_block,       start_block_addr),
		  OPT_SHRT("block-count",       'c', &cfg.block_count,       block_count),
		  OPT_SHRT("block-size",        'b', &cfg.block_size,        block_size),
		  OPT_SUFFIX("data-size",       'z', &cfg.data_size,         data_size),
		  OPT_SUFFIX("metadata-size",   'y', &cfg.metadata_size,     metadata_size),
		  OPT_SUFFIX("ref-tag",         'r', &cfg.ref_tag,           ref_tag),
		  OPT_FILE("data",              'd', &cfg.data,              data),
		  OPT_FILE("metadata",          'M', &cfg.metadata,          metadata),
		  OPT_BYTE("prinfo",            'p', &cfg.prinfo,            prinfo),
		  OPT_SHRT("app-tag-mask",      'm', &cfg.app_tag_mask,      app_tag_mask),
		  OPT_SHRT("app-tag",           'a', &cfg.app_tag,           app_tag),
		  OPT_SUFFIX("storage-tag",     'g', &cfg.storage_tag,       storage_tag),
		  OPT_FLAG("limited-retry",     'l', &cfg.limited_retry,     limited_retry_num),
		  OPT_FLAG("force-unit-access", 'f', &cfg.force_unit_access, force_unit_access),
		  OPT_FLAG("storage-tag-check", 'C', &cfg.storage_tag_check, storage_tag_check),
		  OPT_BYTE("dir-type",          'T', &cfg.dtype,             dtype_for_write),
		  OPT_SHRT("dir-spec",          'S', &cfg.dspec,             dspec),
		  OPT_BYTE("dsm",               'D', &cfg.dsmgmt,            dsm),
		  OPT_FLAG("show-command",      'V', &cfg.show,              show),
		  OPT_FLAG("dry-run",           'w', &nvme_cfg.dry_run,      dry_run),
		  OPT_FLAG("latency",           't', &cfg.latency,           latency),
		  OPT_FLAG("force",               0, &cfg.force,             force));

	if (opcode != nvme_cmd_write) {
		err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
		if (err)
			return err;
	} else {
		err = parse_args(argc, argv, desc, opts);
		if (err)
			return err;
		err = open_exclusive(&ctx, &hdl, argc, argv, cfg.force);
		if (err) {
			if (err == -EBUSY) {
				fprintf(stderr, "Failed to open %s.\n", basename(argv[optind]));
				fprintf(stderr, "Namespace is currently busy.\n");
				if (!cfg.force)
					fprintf(stderr,
						"Use the force [--force] option to ignore that.\n");
			} else {
				argconfig_print_help(desc, opts);
			}
			return err;
		}
	}

	if (!cfg.namespace_id) {
		err = nvme_get_nsid(hdl, &cfg.namespace_id);
		if (err < 0) {
			nvme_show_error("get-namespace-id: %s", nvme_strerror(err));
			return err;
		}
	}

	if (cfg.prinfo > 0xf)
		return err;

	dsmgmt = cfg.dsmgmt;
	control |= (cfg.prinfo << 10);
	if (cfg.limited_retry)
		control |= NVME_IO_LR;
	if (cfg.force_unit_access)
		control |= NVME_IO_FUA;
	if (cfg.storage_tag_check)
		control |= NVME_IO_STC;
	if (cfg.dtype) {
		if (cfg.dtype > 0xf) {
			nvme_show_error("Invalid directive type, %x", cfg.dtype);
			return -EINVAL;
		}
		control |= cfg.dtype << 4;
		dsmgmt |= ((__u32)cfg.dspec) << 16;
	}

	if (opcode & 1) {
		dfd = mfd = STDIN_FILENO;
		flags = O_RDONLY;
	} else {
		dfd = mfd = STDOUT_FILENO;
		flags = O_WRONLY | O_CREAT;
	}

	if (strlen(cfg.data)) {
		dfd = open(cfg.data, flags, mode);
		if (dfd < 0) {
			nvme_show_perror(cfg.data);
			return -EINVAL;
		}
	}

	if (strlen(cfg.metadata)) {
		mfd = open(cfg.metadata, flags, mode);
		if (mfd < 0) {
			nvme_show_perror(cfg.metadata);
			return -EINVAL;
		}
	}

	if (!cfg.data_size) {
		nvme_show_error("data size not provided");
		return -EINVAL;
	}

	if (cfg.block_size) {
		logical_block_size = cfg.block_size;
		ms = cfg.metadata_size;
	} else {
		ns = nvme_alloc(sizeof(*ns));
		if (!ns)
			return -ENOMEM;

		err = nvme_identify_ns(hdl, cfg.namespace_id, ns);
		if (err > 0) {
			nvme_show_status(err);
			return err;
		} else if (err < 0) {
			nvme_show_error("identify namespace: %s", nvme_strerror(err));
			return err;
		}

		nvme_id_ns_flbas_to_lbaf_inuse(ns->flbas, &lba_index);
		logical_block_size = 1 << ns->lbaf[lba_index].ds;
		ms = le16_to_cpu(ns->lbaf[lba_index].ms);

		nvm_ns = nvme_alloc(sizeof(*nvm_ns));
		if (!nvm_ns)
			return -ENOMEM;

		err = nvme_identify_csi_ns(hdl, cfg.namespace_id, NVME_CSI_NVM, 0,
				   nvm_ns);
		if (!err)
			get_pif_sts(ns, nvm_ns, &pif, &sts);

		pi_size = (pif == NVME_NVM_PIF_16B_GUARD) ? 8 : 16;
		if (NVME_FLBAS_META_EXT(ns->flbas)) {
			/*
			 * No meta data is transferred for PRACT=1 and MD=PI size:
			 *   5.2.2.1 Protection Information and Write Commands
			 *   5.2.2.2 Protection Information and Read Commands
			 */
			if (!((cfg.prinfo & 0x8) != 0 && ms == pi_size))
				logical_block_size += ms;
		}

		if (invalid_tags(cfg.storage_tag, cfg.ref_tag, sts, pif))
			return -EINVAL;
	}

	buffer_size = ((long long)cfg.block_count + 1) * logical_block_size;
	if (cfg.data_size < buffer_size)
		nvme_show_error("Rounding data size to fit block count (%lld bytes)", buffer_size);
	else
		buffer_size = cfg.data_size;

	if (argconfig_parse_seen(opts, "block-count")) {
		/* Use the value provided */
		nblocks = cfg.block_count;
	} else {
		/* Get the required block count. Note this is a zeroes based value. */
		nblocks = ((buffer_size + (logical_block_size - 1)) / logical_block_size) - 1;

		/* Update the data size based on the required block count */
		buffer_size = ((unsigned long long)nblocks + 1) * logical_block_size;
	}

	buffer = nvme_alloc_huge(buffer_size, &mh);
	if (!buffer) {
		nvme_show_error("failed to allocate huge memory");
		return -ENOMEM;
	}

	if (cfg.metadata_size) {
		mbuffer_size = ((unsigned long long)cfg.block_count + 1) * ms;
		if (ms && cfg.metadata_size < mbuffer_size)
			nvme_show_error("Rounding metadata size to fit block count (%lld bytes)",
					mbuffer_size);
		else
			mbuffer_size = cfg.metadata_size;

		mbuffer = malloc(mbuffer_size);
		if (!mbuffer)
			return -ENOMEM;
		memset(mbuffer, 0, mbuffer_size);
	}

	if (opcode & 1) {
		err = read(dfd, (void *)buffer, cfg.data_size);
		if (err < 0) {
			err = -errno;
			nvme_show_error("failed to read data buffer from input file %s", strerror(errno));
			return err;
		}
	}

	if ((opcode & 1) && cfg.metadata_size) {
		err = read(mfd, (void *)mbuffer, mbuffer_size);
		if (err < 0) {
			err = -errno;
			nvme_show_error("failed to read meta-data buffer from input file %s", strerror(errno));
			return err;
		}
	}

	if (cfg.show || nvme_cfg.dry_run) {
		printf("opcode       : %02x\n", opcode);
		printf("nsid         : %02x\n", cfg.namespace_id);
		printf("flags        : %02x\n", 0);
		printf("control      : %04x\n", control);
		printf("nblocks      : %04x\n", nblocks);
		printf("metadata     : %"PRIx64"\n", (uint64_t)(uintptr_t)mbuffer);
		printf("addr         : %"PRIx64"\n", (uint64_t)(uintptr_t)buffer);
		printf("slba         : %"PRIx64"\n", (uint64_t)cfg.start_block);
		printf("dsmgmt       : %08x\n", dsmgmt);
		printf("reftag       : %"PRIx64"\n", (uint64_t)cfg.ref_tag);
		printf("apptag       : %04x\n", cfg.app_tag);
		printf("appmask      : %04x\n", cfg.app_tag_mask);
		printf("storagetagcheck : %04x\n", cfg.storage_tag_check);
		printf("storagetag      : %"PRIx64"\n", (uint64_t)cfg.storage_tag);
		printf("pif             : %02x\n", pif);
		printf("sts             : %02x\n", sts);
	}
	if (nvme_cfg.dry_run)
		return 0;

	nvme_init_io(&cmd, opcode, cfg.namespace_id, cfg.start_block, buffer,
		     buffer_size, mbuffer, mbuffer_size);
	cmd.cdw12 = NVME_FIELD_ENCODE(nblocks,
			NVME_IOCS_COMMON_CDW12_NLB_SHIFT,
			NVME_IOCS_COMMON_CDW12_NLB_MASK) |
		    NVME_FIELD_ENCODE(control,
			NVME_IOCS_COMMON_CDW12_CONTROL_SHIFT,
			NVME_IOCS_COMMON_CDW12_CONTROL_MASK);
	cmd.cdw13 = NVME_FIELD_ENCODE(cfg.dspec,
			NVME_IOCS_COMMON_CDW13_DSPEC_SHIFT,
			NVME_IOCS_COMMON_CDW13_DSPEC_MASK) |
		    NVME_FIELD_ENCODE(cfg.dsmgmt,
			NVME_IOCS_COMMON_CDW13_DSM_SHIFT,
			NVME_IOCS_COMMON_CDW13_DSM_MASK);
	nvme_init_var_size_tags((struct nvme_passthru_cmd64 *)&cmd, pif, sts,
		cfg.ref_tag, cfg.storage_tag);
	nvme_init_app_tag((struct nvme_passthru_cmd64 *)&cmd, cfg.app_tag,
		cfg.app_tag_mask);

	gettimeofday(&start_time, NULL);
	err = nvme_submit_io_passthru(hdl, &cmd, NULL);
	gettimeofday(&end_time, NULL);
	if (cfg.latency)
		printf(" latency: %s: %llu us\n", command, elapsed_utime(start_time, end_time));
	if (err < 0) {
		nvme_show_error("submit-io: %s", nvme_strerror(err));
	} else if (err) {
		nvme_show_status(err);
	} else {
		if (!(opcode & 1) && write(dfd, (void *)buffer, buffer_size) < 0) {
			nvme_show_error("write: %s: failed to write buffer to output file",
				strerror(errno));
			err = -EINVAL;
		} else if (!(opcode & 1) && cfg.metadata_size &&
			   write(mfd, (void *)mbuffer, mbuffer_size) < 0) {
			nvme_show_error(
			    "write: %s: failed to write meta-data buffer to output file",
			    strerror(errno));
			err = -EINVAL;
		} else {
			fprintf(stderr, "%s: Success\n", command);
		}
	}

	return err;
}

static int compare(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc = "Compare specified logical blocks on\n"
		"device with specified data buffer; return failure if buffer\n"
		"and block(s) are dissimilar";

	return submit_io(nvme_cmd_compare, "compare", desc, argc, argv);
}

static int read_cmd(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc = "Copy specified logical blocks on the given\n"
		"device to specified data buffer (default buffer is stdout).";

	return submit_io(nvme_cmd_read, "read", desc, argc, argv);
}

static int write_cmd(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc = "Copy from provided data buffer (default\n"
		"buffer is stdin) to specified logical blocks on the given device.";

	return submit_io(nvme_cmd_write, "write", desc, argc, argv);
}

static int verify_cmd(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	_cleanup_free_ struct nvme_nvm_id_ns *nvm_ns = NULL;
	_cleanup_free_ struct nvme_id_ns *ns = NULL;
	_cleanup_nvme_global_ctx_ struct nvme_global_ctx *ctx = NULL;
	_cleanup_nvme_transport_handle_ struct nvme_transport_handle *hdl = NULL;
	struct nvme_passthru_cmd cmd;
	__u8 sts = 0, pif = 0;
	__u16 control = 0;
	int err;

	const char *desc = "Verify specified logical blocks on the given device.";
	const char *force_unit_access_verify =
	    "force device to commit cached data before performing the verify operation";
	const char *storage_tag_check =
	    "This bit specifies the Storage Tag field shall be checked as part of Verify operation";

	struct config {
		__u32	namespace_id;
		__u64	start_block;
		__u16	block_count;
		bool	limited_retry;
		bool	force_unit_access;
		__u8	prinfo;
		__u32	ref_tag;
		__u16	app_tag;
		__u16	app_tag_mask;
		__u64	storage_tag;
		bool	storage_tag_check;
	};

	struct config cfg = {
		.namespace_id		= 0,
		.start_block		= 0,
		.block_count		= 0,
		.limited_retry		= false,
		.force_unit_access	= false,
		.prinfo			= 0,
		.ref_tag		= 0,
		.app_tag		= 0,
		.app_tag_mask		= 0,
		.storage_tag		= 0,
		.storage_tag_check	= false,
	};

	NVME_ARGS(opts,
		  OPT_UINT("namespace-id",      'n', &cfg.namespace_id,      namespace_desired),
		  OPT_SUFFIX("start-block",     's', &cfg.start_block,       start_block),
		  OPT_SHRT("block-count",       'c', &cfg.block_count,       block_count),
		  OPT_FLAG("limited-retry",     'l', &cfg.limited_retry,     limited_retry),
		  OPT_FLAG("force-unit-access", 'f', &cfg.force_unit_access, force_unit_access_verify),
		  OPT_BYTE("prinfo",            'p', &cfg.prinfo,            prinfo),
		  OPT_SUFFIX("ref-tag",         'r', &cfg.ref_tag,           ref_tag),
		  OPT_SHRT("app-tag",           'a', &cfg.app_tag,           app_tag),
		  OPT_SHRT("app-tag-mask",      'm', &cfg.app_tag_mask,      app_tag_mask),
		  OPT_SUFFIX("storage-tag",     'S', &cfg.storage_tag,       storage_tag),
		  OPT_FLAG("storage-tag-check", 'C', &cfg.storage_tag_check, storage_tag_check));


	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	if (cfg.prinfo > 0xf)
		return -EINVAL;

	control |= (cfg.prinfo << 10);
	if (cfg.limited_retry)
		control |= NVME_IO_LR;
	if (cfg.force_unit_access)
		control |= NVME_IO_FUA;
	if (cfg.storage_tag_check)
		control |= NVME_IO_STC;

	if (!cfg.namespace_id) {
		err = nvme_get_nsid(hdl, &cfg.namespace_id);
		if (err < 0) {
			nvme_show_error("get-namespace-id: %s", nvme_strerror(err));
			return err;
		}
	}

	ns = nvme_alloc(sizeof(*ns));
	if (!ns)
		return -ENOMEM;

	err = nvme_identify_ns(hdl, cfg.namespace_id, ns);
	if (err < 0) {
		nvme_show_error("identify namespace: %s", nvme_strerror(err));
		return err;
	} else if (err) {
		nvme_show_status(err);
		return err;
	}

	nvm_ns = nvme_alloc(sizeof(*nvm_ns));
	if (!nvm_ns)
		return -ENOMEM;

	err = nvme_identify_csi_ns(hdl, cfg.namespace_id, NVME_CSI_NVM, 0,
				   nvm_ns);
	if (!err) {
		get_pif_sts(ns, nvm_ns, &pif, &sts);
	}

	if (invalid_tags(cfg.storage_tag, cfg.ref_tag, sts, pif))
		return -EINVAL;

	nvme_init_verify(&cmd, cfg.namespace_id, cfg.start_block,
		cfg.block_count, control, 0, NULL, 0, NULL, 0);
	nvme_init_var_size_tags((struct nvme_passthru_cmd64 *)&cmd, pif, sts,
		cfg.ref_tag, cfg.storage_tag);
	nvme_init_app_tag((struct nvme_passthru_cmd64 *)&cmd, cfg.app_tag,
		cfg.app_tag_mask);
	err = nvme_submit_io_passthru(hdl, &cmd, NULL);
	if (err < 0)
		nvme_show_error("verify: %s", nvme_strerror(err));
	else if (err != 0)
		nvme_show_status(err);
	else
		printf("NVME Verify Success\n");

	return err;
}

static int sec_recv(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc = "Obtain results of one or more\n"
		"previously submitted security-sends. Results, and association\n"
		"between Security Send and Receive, depend on the security\n"
		"protocol field as they are defined by the security protocol\n"
		"used. A Security Receive must follow a Security Send made with\n"
		"the same security protocol.";
	const char *size = "size of buffer (prints to stdout on success)";
	const char *al = "allocation length (cf. SPC-4)";

	_cleanup_nvme_transport_handle_ struct nvme_transport_handle *hdl = NULL;
	_cleanup_nvme_global_ctx_ struct nvme_global_ctx *ctx = NULL;
	_cleanup_free_ void *sec_buf = NULL;
	struct nvme_passthru_cmd cmd;
	nvme_print_flags_t flags;
	int err;

	struct config {
		__u32	namespace_id;
		__u32	size;
		__u8	nssf;
		__u8	secp;
		__u16	spsp;
		__u32	al;
		bool	raw_binary;
	};

	struct config cfg = {
		.namespace_id	= 0,
		.size		= 0,
		.nssf		= 0,
		.secp		= 0,
		.spsp		= 0,
		.al		= 0,
		.raw_binary	= false,
	};

	NVME_ARGS(opts,
		  OPT_UINT("namespace-id", 'n', &cfg.namespace_id, namespace_desired),
		  OPT_UINT("size",         'x', &cfg.size,         size),
		  OPT_BYTE("nssf",         'N', &cfg.nssf,         nssf),
		  OPT_BYTE("secp",         'p', &cfg.secp,         secp),
		  OPT_SHRT("spsp",         's', &cfg.spsp,         spsp),
		  OPT_UINT("al",           't', &cfg.al,           al),
		  OPT_FLAG("raw-binary",   'b', &cfg.raw_binary,   raw_dump));

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	err = validate_output_format(nvme_cfg.output_format, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	if (cfg.size) {
		sec_buf = nvme_alloc(cfg.size);
		if (!sec_buf)
			return -ENOMEM;
	}

	nvme_init_security_receive(&cmd, cfg.namespace_id, cfg.nssf, cfg.spsp,
				   cfg.secp, cfg.al, sec_buf, cfg.size);
	err = nvme_submit_admin_passthru(hdl, &cmd, NULL);
	if (err < 0) {
		nvme_show_error("security receive: %s", nvme_strerror(err));
	} else if (err > 0) {
		nvme_show_status(err);
	} else {
		printf("NVME Security Receive Command Success\n");
		if (!cfg.raw_binary)
			d(sec_buf, cfg.size, 16, 1);
		else if (cfg.size)
			d_raw((unsigned char *)sec_buf, cfg.size);
	}

	return err;
}

static int get_lba_status(int argc, char **argv, struct command *acmd,
		struct plugin *plugin)
{
	const char *desc = "Information about potentially unrecoverable LBAs.";
	const char *slba =
	    "Starting LBA(SLBA) in 64-bit address of the first logical block addressed by this command";
	const char *mndw =
	    "Maximum Number of Dwords(MNDW) specifies maximum number of dwords to return";
	const char *atype = "Action Type(ATYPE) specifies the mechanism\n"
		"the controller uses in determining the LBA Status Descriptors to return.";
	const char *rl =
	    "Range Length(RL) specifies the length of the range of contiguous LBAs beginning at SLBA";

	_cleanup_nvme_global_ctx_ struct nvme_global_ctx *ctx = NULL;
	_cleanup_nvme_transport_handle_ struct nvme_transport_handle *hdl = NULL;
	struct nvme_passthru_cmd cmd;
	_cleanup_free_ void *buf = NULL;
	nvme_print_flags_t flags;
	unsigned long buf_len;
	int err;

	struct config {
		__u32	namespace_id;
		__u64	slba;
		__u32	mndw;
		__u8	atype;
		__u16	rl;
	};

	struct config cfg = {
		.namespace_id	= 0,
		.slba		= 0,
		.mndw		= 0,
		.atype		= 0,
		.rl		= 0,
	};

	NVME_ARGS(opts,
		  OPT_UINT("namespace-id", 'n', &cfg.namespace_id,  namespace_desired),
		  OPT_SUFFIX("start-lba",  's', &cfg.slba,          slba),
		  OPT_UINT("max-dw",       'm', &cfg.mndw,          mndw),
		  OPT_BYTE("action",       'a', &cfg.atype,         atype),
		  OPT_SHRT("range-len",    'l', &cfg.rl,            rl));

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	err = validate_output_format(nvme_cfg.output_format, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	if (!cfg.atype) {
		nvme_show_error("action type (--action) has to be given");
		return -EINVAL;
	}

	buf_len = (cfg.mndw + 1) * 4;
	buf = nvme_alloc(buf_len);
	if (!buf)
		return -ENOMEM;

	nvme_init_get_lba_status(&cmd, cfg.namespace_id, cfg.slba, cfg.mndw,
				 cfg.atype, cfg.rl, buf);
	err = nvme_submit_admin_passthru(hdl, &cmd, NULL);
	if (!err)
		nvme_show_lba_status(buf, buf_len, flags);
	else if (err > 0)
		nvme_show_status(err);
	else
		nvme_show_error("get lba status: %s", nvme_strerror(err));

	return err;
}

static int capacity_mgmt(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc = "Host software uses the Capacity Management command to\n"
		"configure Endurance Groups and NVM Sets in an NVM subsystem by either\n"
		"selecting one of a set of supported configurations or by specifying the\n"
		"capacity of the Endurance Group or NVM Set to be created";
	const char *operation = "Operation to be performed by the controller";
	const char *element_id = "Value specific to the value of the Operation field.";
	const char *cap_lower =
	    "Least significant 32 bits of the capacity in bytes of the Endurance Group or NVM Set to be created";
	const char *cap_upper =
	    "Most significant 32 bits of the capacity in bytes of the Endurance Group or NVM Set to be created";

	_cleanup_nvme_global_ctx_ struct nvme_global_ctx *ctx = NULL;
	_cleanup_nvme_transport_handle_ struct nvme_transport_handle *hdl = NULL;
	struct nvme_passthru_cmd cmd;
	int err = -1;
	__u32 result;
	nvme_print_flags_t flags;

	struct config {
		__u8	operation;
		__u16	element_id;
		__u32	dw11;
		__u32	dw12;
	};

	struct config cfg = {
		.operation	= 0xff,
		.element_id	= 0xffff,
		.dw11		= 0,
		.dw12		= 0,
	};

	NVME_ARGS(opts,
		  OPT_BYTE("operation",   'O', &cfg.operation,    operation),
		  OPT_SHRT("element-id",  'i', &cfg.element_id,   element_id),
		  OPT_UINT("cap-lower",   'l', &cfg.dw11,         cap_lower),
		  OPT_UINT("cap-upper",   'u', &cfg.dw12,         cap_upper));


	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	err = validate_output_format(nvme_cfg.output_format, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	if (cfg.operation > 0xf) {
		nvme_show_error("invalid operation field: %u", cfg.operation);
		return -1;
	}

	nvme_init_capacity_mgmt(&cmd, cfg.operation, cfg.element_id,
		(__u64)cfg.dw12 << 32 | cfg.dw11);
	err = nvme_submit_admin_passthru(hdl, &cmd, &result);
	if (!err) {
		printf("Capacity Management Command is Success\n");
		if (cfg.operation == 1)
			printf("Created Element Identifier for Endurance Group is: %u\n", result);
		else if (cfg.operation == 3)
			printf("Created Element Identifier for NVM Set is: %u\n", result);
	} else if (err > 0) {
		nvme_show_status(err);
	} else if (err < 0) {
		nvme_show_error("capacity management: %s", nvme_strerror(err));
	}

	return err;
}

static int dir_receive(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc = "Read directive parameters of the specified directive type.";
	const char *nsr = "namespace stream requested";

	nvme_print_flags_t flags = NORMAL;
	_cleanup_nvme_global_ctx_ struct nvme_global_ctx *ctx = NULL;
	_cleanup_nvme_transport_handle_ struct nvme_transport_handle *hdl = NULL;
	_cleanup_free_ void *buf = NULL;
	struct nvme_passthru_cmd cmd;
	__u32 result;
	__u32 dw12 = 0;
	int err;

	struct config {
		__u32	namespace_id;
		__u32	data_len;
		bool	raw_binary;
		__u8	dtype;
		__u16	dspec;
		__u8	doper;
		__u16	nsr; /* dw12 for NVME_DIR_ST_RCVOP_STATUS */
		bool	human_readable;
	};

	struct config cfg = {
		.namespace_id	= 1,
		.data_len	= 0,
		.raw_binary	= false,
		.dtype		= 0,
		.dspec		= 0,
		.doper		= 0,
		.nsr		= 0,
		.human_readable	= false,
	};

	NVME_ARGS(opts,
		  OPT_UINT("namespace-id",   'n', &cfg.namespace_id,   namespace_id_desired),
		  OPT_UINT("data-len",       'l', &cfg.data_len,       buf_len),
		  OPT_FLAG("raw-binary",     'b', &cfg.raw_binary,     raw_directive),
		  OPT_BYTE("dir-type",       'D', &cfg.dtype,          dtype),
		  OPT_SHRT("dir-spec",       'S', &cfg.dspec,          dspec_w_dtype),
		  OPT_BYTE("dir-oper",       'O', &cfg.doper,          doper),
		  OPT_SHRT("req-resource",   'r', &cfg.nsr,            nsr),
		  OPT_FLAG("human-readable", 'H', &cfg.human_readable, human_readable_directive));

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	if (cfg.human_readable || argconfig_parse_seen(opts, "verbose"))
		flags |= VERBOSE;
	if (cfg.raw_binary)
		flags = BINARY;

	switch (cfg.dtype) {
	case NVME_DIRECTIVE_DTYPE_IDENTIFY:
		switch (cfg.doper) {
		case NVME_DIRECTIVE_RECEIVE_IDENTIFY_DOPER_PARAM:
			if (!cfg.data_len)
				cfg.data_len = 4096;
			break;
		default:
			nvme_show_error("invalid directive operations for Identify Directives");
			return -EINVAL;
		}
		break;
	case NVME_DIRECTIVE_DTYPE_STREAMS:
		switch (cfg.doper) {
		case NVME_DIRECTIVE_RECEIVE_STREAMS_DOPER_PARAM:
			if (!cfg.data_len)
				cfg.data_len = 32;
			break;
		case NVME_DIRECTIVE_RECEIVE_STREAMS_DOPER_STATUS:
			if (!cfg.data_len)
				cfg.data_len = 128 * 1024;
			break;
		case NVME_DIRECTIVE_RECEIVE_STREAMS_DOPER_RESOURCE:
			dw12 = cfg.nsr;
			break;
		default:
			nvme_show_error("invalid directive operations for Streams Directives");
			return -EINVAL;
		}
		break;
	default:
		nvme_show_error("invalid directive type");
		return -EINVAL;
	}

	if (cfg.data_len) {
		buf = nvme_alloc(cfg.data_len);
		if (!buf)
			return -ENOMEM;
	}

	nvme_init_directive_recv(&cmd, cfg.namespace_id, cfg.doper, cfg.dtype,
		cfg.dspec, buf, cfg.data_len);
	cmd.cdw12 = dw12;
	err = nvme_submit_admin_passthru(hdl, &cmd, &result);
	if (!err)
		nvme_directive_show(cfg.dtype, cfg.doper, cfg.dspec, cfg.namespace_id,
				    result, buf, cfg.data_len, flags);
	else if (err > 0)
		nvme_show_status(err);
	else if (err < 0)
		nvme_show_error("dir-receive: %s", nvme_strerror(err));

	return err;
}

/* rpmb_cmd_option is defined in nvme-rpmb.c */
extern int rpmb_cmd_option(int, char **, struct command *, struct plugin *);
static int rpmb_cmd(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	return rpmb_cmd_option(argc, argv, acmd, plugin);
}

static int lockdown_cmd(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc = "The Lockdown command is used to control the\n"
		"Command and Feature Lockdown capability which configures the\n"
		"prohibition or allowance of execution of the specified command\n"
		"or Set Features command targeting a specific Feature Identifier.";
	const char *ofi_desc = "Opcode or Feature Identifier (OFI)\n"
		"specifies the command opcode or Set Features Feature Identifier\n"
		"identified by the Scope field.";
	const char *ifc_desc =
	    "[0-3] Interface (INF) field identifies the interfaces affected by this command.";
	const char *prhbt_desc = "[0-1]Prohibit(PRHBT) bit specifies whether\n"
		"to prohibit or allow the command opcode or Set Features Feature\n"
		"Identifier specified by this command.";
	const char *scp_desc =
	    "[0-15]Scope(SCP) field specifies the contents of the Opcode or Feature Identifier field.";
	const char *uuid_desc = "UUID Index - If this field is set to a non-zero\n"
		"value, then the value of this field is the index of a UUID in the UUID\n"
		"List that is used by the command.If this field is cleared to 0h,\n"
		"then no UUID index is specified";

	_cleanup_nvme_global_ctx_ struct nvme_global_ctx *ctx = NULL;
	_cleanup_nvme_transport_handle_ struct nvme_transport_handle *hdl = NULL;
	struct nvme_passthru_cmd cmd;
	int err = -1;

	struct config {
		__u8	ofi;
		__u8	ifc;
		__u8	prhbt;
		__u8	scp;
		__u8	uuid;
	};

	struct config cfg = {
		.ofi	= 0,
		.ifc	= 0,
		.prhbt	= 0,
		.scp	= 0,
		.uuid	= 0,
	};

	NVME_ARGS(opts,
		  OPT_BYTE("ofi",	'O', &cfg.ofi,      ofi_desc),
		  OPT_BYTE("ifc",	'f', &cfg.ifc,      ifc_desc),
		  OPT_BYTE("prhbt",	'p', &cfg.prhbt,    prhbt_desc),
		  OPT_BYTE("scp",	's', &cfg.scp,      scp_desc),
		  OPT_BYTE("uuid",	'U', &cfg.uuid,     uuid_desc));

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	/* check for input argument limit */
	if (cfg.ifc > 3) {
		nvme_show_error("invalid interface settings:%d", cfg.ifc);
		return -1;
	}
	if (cfg.prhbt > 1) {
		nvme_show_error("invalid prohibit settings:%d", cfg.prhbt);
		return -1;
	}
	if (cfg.scp > 15) {
		nvme_show_error("invalid scope settings:%d", cfg.scp);
		return -1;
	}
	if (cfg.uuid > 127) {
		nvme_show_error("invalid UUID index settings:%d", cfg.uuid);
		return -1;
	}

	nvme_init_lockdown(&cmd, cfg.scp, cfg.prhbt, cfg.ifc, cfg.ofi,
			   cfg.uuid);
	err = nvme_submit_admin_passthru(hdl, &cmd, NULL);
	if (err < 0)
		nvme_show_error("lockdown: %s", nvme_strerror(err));
	else if (err > 0)
		nvme_show_status(err);
	else
		printf("Lockdown Command is Successful\n");

	return err;
}

static void passthru_print_read_output(struct passthru_config cfg, void *data, int dfd, void *mdata,
				       int mfd, int err)
{
	if (strlen(cfg.input_file)) {
		if (write(dfd, (void *)data, cfg.data_len) < 0)
			perror("failed to write data buffer");
	} else if (data) {
		if (cfg.raw_binary)
			d_raw((unsigned char *)data, cfg.data_len);
		else if (!err)
			d((unsigned char *)data, cfg.data_len, 16, 1);
	}
	if (cfg.metadata_len && cfg.metadata) {
		if (strlen(cfg.metadata)) {
			if (write(mfd, (void *)mdata, cfg.metadata_len) < 0)
				perror("failed to write metadata buffer");
		} else {
			if (cfg.raw_binary)
				d_raw((unsigned char *)mdata, cfg.metadata_len);
			else if (!err)
				d((unsigned char *)mdata, cfg.metadata_len, 16, 1);
		}
	}
}

static int passthru(int argc, char **argv, bool admin,
		const char *desc, struct command *acmd)
{
	const char *opcode = "opcode (required)";
	const char *cflags = "command flags";
	const char *rsvd = "value for reserved field";
	const char *data_len = "data I/O length (bytes)";
	const char *metadata_len = "metadata seg. length (bytes)";
	const char *metadata = "metadata input or output file";
	const char *cdw2 = "command dword 2 value";
	const char *cdw3 = "command dword 3 value";
	const char *cdw10 = "command dword 10 value";
	const char *cdw11 = "command dword 11 value";
	const char *cdw12 = "command dword 12 value";
	const char *cdw13 = "command dword 13 value";
	const char *cdw14 = "command dword 14 value";
	const char *cdw15 = "command dword 15 value";
	const char *input = "data input or output file";
	const char *show = "print command before sending";
	const char *re = "set dataflow direction to receive";
	const char *wr = "set dataflow direction to send";
	const char *prefill = "prefill buffers with known byte-value, default 0";

	_cleanup_huge_ struct nvme_mem_huge mh = { 0, };
	_cleanup_nvme_global_ctx_ struct nvme_global_ctx *ctx = NULL;
	_cleanup_nvme_transport_handle_ struct nvme_transport_handle *hdl = NULL;
	_cleanup_fd_ int dfd = -1, mfd = -1;
	int flags;
	int mode = 0644;
	void *data = NULL;
	_cleanup_free_ void *mdata = NULL;
	int err = 0;
	__u32 result;
	const char *cmd_name = NULL;
	struct timeval start_time, end_time;
	nvme_print_flags_t flags_t;

	struct passthru_config cfg = {
		.opcode		= 0,
		.flags		= 0,
		.prefill	= 0,
		.rsvd		= 0,
		.namespace_id	= 0,
		.data_len	= 0,
		.metadata_len	= 0,
		.cdw2		= 0,
		.cdw3		= 0,
		.cdw10		= 0,
		.cdw11		= 0,
		.cdw12		= 0,
		.cdw13		= 0,
		.cdw14		= 0,
		.cdw15		= 0,
		.input_file	= "",
		.metadata	= "",
		.raw_binary	= false,
		.show_command	= false,
		.read		= false,
		.write		= false,
		.latency	= false,
	};

	NVME_ARGS(opts,
		  OPT_BYTE("opcode",       'O', &cfg.opcode,       opcode),
		  OPT_BYTE("flags",        'f', &cfg.flags,        cflags),
		  OPT_BYTE("prefill",      'p', &cfg.prefill,      prefill),
		  OPT_SHRT("rsvd",         'R', &cfg.rsvd,         rsvd),
		  OPT_UINT("namespace-id", 'n', &cfg.namespace_id, namespace_desired),
		  OPT_UINT("data-len",     'l', &cfg.data_len,     data_len),
		  OPT_UINT("metadata-len", 'm', &cfg.metadata_len, metadata_len),
		  OPT_UINT("cdw2",         '2', &cfg.cdw2,         cdw2),
		  OPT_UINT("cdw3",         '3', &cfg.cdw3,         cdw3),
		  OPT_UINT("cdw10",        '4', &cfg.cdw10,        cdw10),
		  OPT_UINT("cdw11",        '5', &cfg.cdw11,        cdw11),
		  OPT_UINT("cdw12",        '6', &cfg.cdw12,        cdw12),
		  OPT_UINT("cdw13",        '7', &cfg.cdw13,        cdw13),
		  OPT_UINT("cdw14",        '8', &cfg.cdw14,        cdw14),
		  OPT_UINT("cdw15",        '9', &cfg.cdw15,        cdw15),
		  OPT_FILE("input-file",   'i', &cfg.input_file,   input),
		  OPT_FILE("metadata",     'M', &cfg.metadata,     metadata),
		  OPT_FLAG("raw-binary",   'b', &cfg.raw_binary,   raw_dump),
		  OPT_FLAG("show-command", 's', &cfg.show_command, show),
		  OPT_FLAG("dry-run",      'd', &nvme_cfg.dry_run, dry_run),
		  OPT_FLAG("read",         'r', &cfg.read,         re),
		  OPT_FLAG("write",        'w', &cfg.write,        wr),
		  OPT_FLAG("latency",      'T', &cfg.latency,      latency));

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	err = validate_output_format(nvme_cfg.output_format, &flags_t);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	if (!argconfig_parse_seen(opts, "opcode")) {
		nvme_show_error("%s: opcode parameter required", acmd->name);
		return -EINVAL;
	}

	if (cfg.opcode & 0x01) {
		cfg.write = true;
		flags = O_RDONLY;
		dfd = mfd = STDIN_FILENO;
	}

	if (cfg.opcode & 0x02) {
		cfg.read = true;
		flags = O_WRONLY | O_CREAT;
		dfd = mfd = STDOUT_FILENO;
	}

	if (strlen(cfg.input_file)) {
		dfd = open(cfg.input_file, flags, mode);
		if (dfd < 0) {
			nvme_show_perror(cfg.input_file);
			return -EINVAL;
		}
	}

	if (cfg.metadata && strlen(cfg.metadata)) {
		mfd = open(cfg.metadata, flags, mode);
		if (mfd < 0) {
			nvme_show_perror(cfg.metadata);
			return -EINVAL;
		}
	}

	if (cfg.metadata_len) {
		mdata = malloc(cfg.metadata_len);
		if (!mdata)
			return -ENOMEM;

		if (cfg.write) {
			if (read(mfd, mdata, cfg.metadata_len) < 0) {
				err = -errno;
				nvme_show_perror("failed to read metadata write buffer");
				return err;
			}
		} else {
			memset(mdata, cfg.prefill, cfg.metadata_len);
		}
	}

	if (cfg.data_len) {
		data = nvme_alloc_huge(cfg.data_len, &mh);
		if (!data) {
			nvme_show_error("failed to allocate huge memory");
			return -ENOMEM;
		}

		memset(data, cfg.prefill, cfg.data_len);
		if (!cfg.read && !cfg.write) {
			nvme_show_error("data direction not given");
			return -EINVAL;
		} else if (cfg.write) {
			if (read(dfd, data, cfg.data_len) < 0) {
				err = -errno;
				nvme_show_error("failed to read write buffer %s", strerror(errno));
				return err;
			}
		}
	}

	if (cfg.show_command || nvme_cfg.dry_run) {
		printf("opcode       : %02x\n", cfg.opcode);
		printf("flags        : %02x\n", cfg.flags);
		printf("rsvd1        : %04x\n", cfg.rsvd);
		printf("nsid         : %08x\n", cfg.namespace_id);
		printf("cdw2         : %08x\n", cfg.cdw2);
		printf("cdw3         : %08x\n", cfg.cdw3);
		printf("data_len     : %08x\n", cfg.data_len);
		printf("metadata_len : %08x\n", cfg.metadata_len);
		printf("addr         : %"PRIx64"\n", (uint64_t)(uintptr_t)data);
		printf("metadata     : %"PRIx64"\n", (uint64_t)(uintptr_t)mdata);
		printf("cdw10        : %08x\n", cfg.cdw10);
		printf("cdw11        : %08x\n", cfg.cdw11);
		printf("cdw12        : %08x\n", cfg.cdw12);
		printf("cdw13        : %08x\n", cfg.cdw13);
		printf("cdw14        : %08x\n", cfg.cdw14);
		printf("cdw15        : %08x\n", cfg.cdw15);
		printf("timeout_ms   : %08x\n", nvme_cfg.timeout);
	}
	if (nvme_cfg.dry_run)
		return 0;

	gettimeofday(&start_time, NULL);

	if (admin)
		err = nvme_admin_passthru(hdl, cfg.opcode, cfg.flags,
					  cfg.rsvd,
					  cfg.namespace_id, cfg.cdw2,
					  cfg.cdw3, cfg.cdw10,
					  cfg.cdw11, cfg.cdw12, cfg.cdw13,
					  cfg.cdw14,
					  cfg.cdw15, cfg.data_len, data,
					  cfg.metadata_len,
					  mdata, nvme_cfg.timeout, &result);
	else
		err = nvme_io_passthru(hdl, cfg.opcode, cfg.flags,
				       cfg.rsvd,
				       cfg.namespace_id, cfg.cdw2, cfg.cdw3,
				       cfg.cdw10,
				       cfg.cdw11, cfg.cdw12, cfg.cdw13,
				       cfg.cdw14,
				       cfg.cdw15, cfg.data_len, data,
				       cfg.metadata_len,
				       mdata, nvme_cfg.timeout, &result);

	gettimeofday(&end_time, NULL);
	cmd_name = nvme_cmd_to_string(admin, cfg.opcode);
	if (cfg.latency)
		printf("%s Command %s latency: %llu us\n", admin ? "Admin" : "IO",
		       strcmp(cmd_name, "Unknown") ? cmd_name : "Vendor Specific",
		       elapsed_utime(start_time, end_time));

	if (err < 0) {
		nvme_show_error("%s: %s", __func__, nvme_strerror(err));
	} else if (err) {
		nvme_show_status(err);
	} else  {
		fprintf(stderr, "%s Command %s is Success and result: 0x%08x\n", admin ? "Admin" : "IO",
			strcmp(cmd_name, "Unknown") ? cmd_name : "Vendor Specific", result);
		if (cfg.read)
			passthru_print_read_output(cfg, data, dfd, mdata, mfd, err);
	}

	return err;
}

static int io_passthru(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc =
	    "Send a user-defined IO command to the specified device via IOCTL passthrough, return results.";

	return passthru(argc, argv, false, desc, acmd);
}

static int admin_passthru(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc =
	    "Send a user-defined Admin command to the specified device via IOCTL passthrough, return results.";

	return passthru(argc, argv, true, desc, acmd);
}

static int gen_hostnqn_cmd(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	char *hostnqn;

	hostnqn = nvmf_hostnqn_generate();
	if (!hostnqn) {
		nvme_show_error("\"%s\" not supported. Install lib uuid and rebuild.",
				acmd->name);
		return -ENOTSUP;
	}
	printf("%s\n", hostnqn);
	free(hostnqn);
	return 0;
}

static int show_hostnqn_cmd(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	char *hostnqn;

	hostnqn = nvmf_hostnqn_from_file();
	if (!hostnqn)
		hostnqn =  nvmf_hostnqn_generate();

	if (!hostnqn) {
		nvme_show_error("hostnqn is not available -- use nvme gen-hostnqn");
		return -ENOENT;
	}

	fprintf(stdout, "%s\n", hostnqn);
	free(hostnqn);

	return 0;
}


static int gen_dhchap_key(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc =
	    "Generate a DH-HMAC-CHAP host key usable for NVMe In-Band Authentication.";
	const char *secret =
	    "Optional secret (in hexadecimal characters) to be used to initialize the host key.";
	const char *key_len = "Length of the resulting key (32, 48, or 64 bytes).";
	const char *hmac =
	    "HMAC function to use for key transformation (0 = none, 1 = SHA-256, 2 = SHA-384, 3 = SHA-512).";
	const char *nqn = "Host NQN to use for key transformation.";

	_cleanup_free_ unsigned char *raw_secret = NULL;
	_cleanup_free_ char *hnqn = NULL;
	unsigned char key[68];
	char encoded_key[128];
	unsigned long crc = crc32(0L, NULL, 0);
	int err = 0;

	struct config {
		char		*secret;
		unsigned int	key_len;
		char		*nqn;
		unsigned int	hmac;
	};

	struct config cfg = {
		.secret		= NULL,
		.key_len	= 0,
		.nqn		= NULL,
		.hmac		= 0,
	};

	NVME_ARGS(opts,
		  OPT_STR("secret",		's', &cfg.secret,	secret),
		  OPT_UINT("key-length",	'l', &cfg.key_len,	key_len),
		  OPT_STR("nqn",		'n', &cfg.nqn,		nqn),
		  OPT_UINT("hmac",		'm', &cfg.hmac,		hmac));

	err = parse_args(argc, argv, desc, opts);
	if (err)
		return err;

	if (cfg.hmac > 3) {
		nvme_show_error("Invalid HMAC identifier %u", cfg.hmac);
		return -EINVAL;
	}
	if (cfg.hmac > 0) {
		switch (cfg.hmac) {
		case 1:
			if (!cfg.key_len) {
				cfg.key_len = 32;
			} else if (cfg.key_len != 32) {
				nvme_show_error("Invalid key length %d for SHA(256)", cfg.key_len);
				return -EINVAL;
			}
			break;
		case 2:
			if (!cfg.key_len) {
				cfg.key_len = 48;
			} else if (cfg.key_len != 48) {
				nvme_show_error("Invalid key length %d for SHA(384)", cfg.key_len);
				return -EINVAL;
			}
			break;
		case 3:
			if (!cfg.key_len) {
				cfg.key_len = 64;
			} else if (cfg.key_len != 64) {
				nvme_show_error("Invalid key length %d for SHA(512)", cfg.key_len);
				return -EINVAL;
			}
			break;
		default:
			break;
		}
	} else if (!cfg.key_len) {
		cfg.key_len = 32;
	}

	if (cfg.key_len != 32 && cfg.key_len != 48 && cfg.key_len != 64) {
		nvme_show_error("Invalid key length %u", cfg.key_len);
		return -EINVAL;
	}
	raw_secret = malloc(cfg.key_len);
	if (!raw_secret)
		return -ENOMEM;
	if (!cfg.secret) {
		if (getrandom_bytes(raw_secret, cfg.key_len) < 0)
			return -errno;
	} else {
		int secret_len = 0, i;
		unsigned int c;

		for (i = 0; i < strlen(cfg.secret); i += 2) {
			if (sscanf(&cfg.secret[i], "%02x", &c) != 1) {
				nvme_show_error("Invalid secret '%s'", cfg.secret);
				return -EINVAL;
			}
			raw_secret[secret_len++] = (unsigned char)c;
		}
		if (secret_len != cfg.key_len) {
			nvme_show_error("Invalid key length (%d bytes)", secret_len);
			return -EINVAL;
		}
	}

	if (!cfg.nqn) {
		cfg.nqn = hnqn = nvmf_hostnqn_from_file();
		if (!cfg.nqn) {
			nvme_show_error("Could not read host NQN");
			return -ENOENT;
		}
	}

	err = nvme_gen_dhchap_key(cfg.nqn, cfg.hmac, cfg.key_len, raw_secret, key);
	if (err)
		return err;

	crc = crc32(crc, key, cfg.key_len);
	key[cfg.key_len++] = crc & 0xff;
	key[cfg.key_len++] = (crc >> 8) & 0xff;
	key[cfg.key_len++] = (crc >> 16) & 0xff;
	key[cfg.key_len++] = (crc >> 24) & 0xff;

	memset(encoded_key, 0, sizeof(encoded_key));
	base64_encode(key, cfg.key_len, encoded_key);

	printf("DHHC-1:%02x:%s:\n", cfg.hmac, encoded_key);
	return 0;
}

static int check_dhchap_key(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc =
	    "Check a DH-HMAC-CHAP host key for usability for NVMe In-Band Authentication.";
	const char *key = "DH-HMAC-CHAP key (in hexadecimal characters) to be validated.";

	unsigned char decoded_key[128];
	unsigned int decoded_len;
	uint32_t crc = crc32(0L, NULL, 0);
	uint32_t key_crc;
	int err = 0, hmac;
	struct config {
		char	*key;
	};

	struct config cfg = {
		.key	= NULL,
	};

	NVME_ARGS(opts,
		  OPT_STR("key", 'k', &cfg.key, key));

	err = parse_args(argc, argv, desc, opts);
	if (err)
		return err;

	if (!cfg.key) {
		nvme_show_error("Key not specified");
		return -EINVAL;
	}

	if (sscanf(cfg.key, "DHHC-1:%02x:*s", &hmac) != 1) {
		nvme_show_error("Invalid key header '%s'", cfg.key);
		return -EINVAL;
	}
	switch (hmac) {
	case 0:
		break;
	case 1:
		if (strlen(cfg.key) != 59) {
			nvme_show_error("Invalid key length for SHA(256)");
			return -EINVAL;
		}
		break;
	case 2:
		if (strlen(cfg.key) != 83) {
			nvme_show_error("Invalid key length for SHA(384)");
			return -EINVAL;
		}
		break;
	case 3:
		if (strlen(cfg.key) != 103) {
			nvme_show_error("Invalid key length for SHA(512)");
			return -EINVAL;
		}
		break;
	default:
		nvme_show_error("Invalid HMAC identifier %d", hmac);
		return -EINVAL;
	}

	err = base64_decode(cfg.key + 10, strlen(cfg.key) - 11, decoded_key);
	if (err < 0) {
		nvme_show_error("Base64 decoding failed, error %d", err);
		return err;
	}
	decoded_len = err;
	if (decoded_len < 32) {
		nvme_show_error("Base64 decoding failed (%s, size %u)", cfg.key + 10, decoded_len);
		return -EINVAL;
	}
	decoded_len -= 4;
	if (decoded_len != 32 && decoded_len != 48 && decoded_len != 64) {
		nvme_show_error("Invalid key length %d", decoded_len);
		return -EINVAL;
	}
	crc = crc32(crc, decoded_key, decoded_len);
	key_crc = ((uint32_t)decoded_key[decoded_len]) |
		   ((uint32_t)decoded_key[decoded_len + 1] << 8) |
		   ((uint32_t)decoded_key[decoded_len + 2] << 16) |
		   ((uint32_t)decoded_key[decoded_len + 3] << 24);
	if (key_crc != crc) {
		nvme_show_error("CRC mismatch (key %08x, crc %08x)", key_crc, crc);
		return -EINVAL;
	}
	printf("Key is valid (HMAC %d, length %d, CRC %08x)\n", hmac, decoded_len, crc);
	return 0;
}

static int append_keyfile(const char *keyring, long id, const char *keyfile)
{
	_cleanup_free_ unsigned char *key_data = NULL;
	_cleanup_free_ char *exported_key = NULL;
	_cleanup_free_ char *identity = NULL;
	_cleanup_file_ FILE *fd = NULL;
	int err, ver, hmac, key_len;
	mode_t old_umask;
	long kr_id;
	char type;

	err = nvme_lookup_keyring(keyring, &kr_id);
	if (err) {
		nvme_show_error("Failed to lookup keyring '%s', %s",
				keyring, strerror(-err));
		return err;
	}

	identity = nvme_describe_key_serial(id);
	if (!identity) {
		nvme_show_error("Failed to get identity info");
		return -EINVAL;
	}

	if (sscanf(identity, "NVMe%01d%c%02d %*s", &ver, &type, &hmac) != 3) {
		nvme_show_error("Failed to parse identity\n");
		return -EINVAL;
	}

	err = nvme_read_key(kr_id, id, &key_len, &key_data);
	if (err) {
		nvme_show_error("Failed to read back derive TLS PSK, %s",
			strerror(-err));
		return err;
	}

	err = nvme_export_tls_key_versioned(ver, hmac, key_data,
					    key_len, &exported_key);
	if (err) {
		nvme_show_error("Failed to export key, %s",
			strerror(-err));
		return err;
	}

	old_umask = umask(0);

	fd = fopen(keyfile, "a");
	if (!fd) {
		nvme_show_error("Failed to open '%s', %s",
				keyfile, strerror(errno));
		err = -errno;
		goto out;
	}

	err = fprintf(fd, "%s %s\n", identity, exported_key);
	if (err < 0) {
		nvme_show_error("Failed to append key to '%', %s",
				keyfile, strerror(errno));
		err = -errno;
	} else {
		err = 0;
	}

out:
	chmod(keyfile, 0600);
	umask(old_umask);

	return err;
}

static int gen_tls_key(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc = "Generate a TLS key in NVMe PSK Interchange format.";
	const char *secret =
	    "Optional secret (in hexadecimal characters) to be used for the TLS key.";
	const char *hmac = "HMAC function to use for the retained key (1 = SHA-256, 2 = SHA-384).";
	const char *version = "TLS identity version to use (0 = NVMe TCP 1.0c, 1 = NVMe TCP 2.0";
	const char *hostnqn = "Host NQN for the retained key.";
	const char *subsysnqn = "Subsystem NQN for the retained key.";
	const char *keyring = "Keyring for the retained key.";
	const char *keytype = "Key type of the retained key.";
	const char *insert = "Insert retained key into the keyring.";
	const char *keyfile = "Update key file with the derive TLS PSK.";
	const char *compat = "Use non-RFC 8446 compliant algorithm for deriving TLS PSK for older implementations";

	_cleanup_free_ unsigned char *raw_secret = NULL;
	_cleanup_free_ char *encoded_key = NULL;
	_cleanup_free_ char *hnqn = NULL;
	int key_len = 32;
	int err;
	long tls_key;

	struct config {
		char		*keyring;
		char		*keytype;
		char		*hostnqn;
		char		*subsysnqn;
		char		*secret;
		char		*keyfile;
		unsigned char	hmac;
		unsigned char	version;
		bool		insert;
		bool		compat;
	};

	struct config cfg = {
		.keyring	= ".nvme",
		.keytype	= "psk",
		.hostnqn	= NULL,
		.subsysnqn	= NULL,
		.secret		= NULL,
		.keyfile	= NULL,
		.hmac		= 1,
		.version	= 0,
		.insert		= false,
		.compat		= false,
	};

	NVME_ARGS(opts,
		  OPT_STR("keyring",	'k', &cfg.keyring,	keyring),
		  OPT_STR("keytype",	't', &cfg.keytype,	keytype),
		  OPT_STR("hostnqn",	'n', &cfg.hostnqn,	hostnqn),
		  OPT_STR("subsysnqn",	'c', &cfg.subsysnqn,	subsysnqn),
		  OPT_STR("secret",	's', &cfg.secret,	secret),
		  OPT_STR("keyfile",	'f', &cfg.keyfile,	keyfile),
		  OPT_BYTE("hmac",	'm', &cfg.hmac,		hmac),
		  OPT_BYTE("identity",	'I', &cfg.version,	version),
		  OPT_FLAG("insert",	'i', &cfg.insert,	insert),
		  OPT_FLAG("compat",	'C', &cfg.compat,	compat));

	err = parse_args(argc, argv, desc, opts);
	if (err)
		return err;
	if (cfg.hmac < 1 || cfg.hmac > 2) {
		nvme_show_error("Invalid HMAC identifier %u", cfg.hmac);
		return -EINVAL;
	}
	if (cfg.version > 1) {
		nvme_show_error("Invalid TLS identity version %u",
				cfg.version);
		return -EINVAL;
	}
	if (cfg.insert) {
		if (!cfg.subsysnqn) {
			nvme_show_error("No subsystem NQN specified");
			return -EINVAL;
		}
		if (!cfg.hostnqn) {
			cfg.hostnqn = hnqn = nvmf_hostnqn_from_file();
			if (!cfg.hostnqn) {
				nvme_show_error("Failed to read host NQN");
				return -EINVAL;
			}
		}
	}
	if (cfg.hmac == 2)
		key_len = 48;

	raw_secret = malloc(key_len + 4);
	if (!raw_secret)
		return -ENOMEM;
	if (!cfg.secret) {
		if (getrandom_bytes(raw_secret, key_len) < 0)
			return -errno;
	} else {
		int secret_len = 0, i;
		unsigned int c;

		for (i = 0; i < strlen(cfg.secret); i += 2) {
			if (sscanf(&cfg.secret[i], "%02x", &c) != 1) {
				nvme_show_error("Invalid secret '%s'", cfg.secret);
				return -EINVAL;
			}
			if (i >= key_len * 2) {
				fprintf(stderr, "Skipping excess secret bytes\n");
				break;
			}
			raw_secret[secret_len++] = (unsigned char)c;
		}
		if (secret_len != key_len) {
			nvme_show_error("Invalid key length (%d bytes)", secret_len);
			return -EINVAL;
		}
	}

	err = nvme_export_tls_key(raw_secret, key_len, &encoded_key);
	if (err) {
		nvme_show_error("Failed to export key, %s", strerror(-err));
		return err;
	}
	printf("%s\n", encoded_key);

	if (cfg.insert) {
		if (cfg.compat)
			err = nvme_insert_tls_key_compat(cfg.keyring,
					cfg.keytype, cfg.hostnqn,
					cfg.subsysnqn, cfg.version,
					cfg.hmac, raw_secret, key_len, &tls_key);
		else
			err = nvme_insert_tls_key_versioned(cfg.keyring,
					cfg.keytype, cfg.hostnqn,
					cfg.subsysnqn, cfg.version,
					cfg.hmac, raw_secret, key_len, &tls_key);
		if (err) {
			nvme_show_error("Failed to insert key, error %d", err);
			return err;
		}

		printf("Inserted TLS key %08x\n", (unsigned int)tls_key);

		if (cfg.keyfile) {
			err = append_keyfile(cfg.keyring, tls_key, cfg.keyfile);
			if (err)
				return err;
		}
	}

	return 0;
}

static int check_tls_key(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc = "Check a TLS key for NVMe PSK Interchange format.\n";
	const char *keydata = "TLS key (in PSK Interchange format) to be validated.";
	const char *identity = "TLS identity version to use (0 = NVMe TCP 1.0c, 1 = NVMe TCP 2.0)";
	const char *hostnqn = "Host NQN for the retained key.";
	const char *subsysnqn = "Subsystem NQN for the retained key.";
	const char *keyring = "Keyring for the retained key.";
	const char *keytype = "Key type of the retained key.";
	const char *insert = "Insert retained key into the keyring.";
	const char *keyfile = "Update key file with the derive TLS PSK.";
	const char *compat = "Use non-RFC 8446 compliant algorithm for checking TLS PSK for older implementations.";

	_cleanup_free_ unsigned char *decoded_key = NULL;
	_cleanup_free_ char *hnqn = NULL;
	int decoded_len, err = 0;
	unsigned int hmac;
	long tls_key;
	struct config {
		char		*keyring;
		char		*keytype;
		char		*hostnqn;
		char		*subsysnqn;
		char		*keydata;
		char		*keyfile;
		unsigned char	identity;
		bool		insert;
		bool		compat;
	};

	struct config cfg = {
		.keyring	= ".nvme",
		.keytype	= "psk",
		.hostnqn	= NULL,
		.subsysnqn	= NULL,
		.keydata	= NULL,
		.keyfile	= NULL,
		.identity	= 0,
		.insert		= false,
		.compat		= false,
	};

	NVME_ARGS(opts,
		  OPT_STR("keyring",	'k', &cfg.keyring,	keyring),
		  OPT_STR("keytype",	't', &cfg.keytype,	keytype),
		  OPT_STR("hostnqn",	'n', &cfg.hostnqn,	hostnqn),
		  OPT_STR("subsysnqn",	'c', &cfg.subsysnqn,	subsysnqn),
		  OPT_STR("keydata",	'd', &cfg.keydata,	keydata),
		  OPT_STR("keyfile",	'f', &cfg.keyfile,	keyfile),
		  OPT_BYTE("identity",	'I', &cfg.identity,	identity),
		  OPT_FLAG("insert",	'i', &cfg.insert,	insert),
		  OPT_FLAG("compat",	'C', &cfg.compat,	compat));

	err = parse_args(argc, argv, desc, opts);
	if (err)
		return err;

	if (!cfg.keydata) {
		nvme_show_error("No key data");
		return -EINVAL;
	}
	if (cfg.identity > 1) {
		nvme_show_error("Invalid TLS identity version %u",
				cfg.identity);
		return -EINVAL;
	}

	err = nvme_import_tls_key(cfg.keydata, &decoded_len, &hmac, &decoded_key);
	if (err) {
		nvme_show_error("Key decoding failed, error %d\n", err);
		return err;
	}

	if (cfg.subsysnqn) {
		if (!cfg.hostnqn) {
			cfg.hostnqn = hnqn = nvmf_hostnqn_from_file();
			if (!cfg.hostnqn) {
				nvme_show_error("Failed to read host NQN");
				return -EINVAL;
			}
		}
	} else {
		nvme_show_error("Need to specify a subsystem NQN");
		return -EINVAL;
	}

	if (cfg.insert) {
		if (cfg.compat)
			err = nvme_insert_tls_key_compat(cfg.keyring,
					cfg.keytype, cfg.hostnqn,
					cfg.subsysnqn, cfg.identity,
					hmac, decoded_key, decoded_len,
					&tls_key);
		else
			err = nvme_insert_tls_key_versioned(cfg.keyring,
					cfg.keytype, cfg.hostnqn,
					cfg.subsysnqn, cfg.identity,
					hmac, decoded_key, decoded_len,
					&tls_key);
		if (err) {
			nvme_show_error("Failed to insert key, error %d", err);
			return err;
		}
		printf("Inserted TLS key %08x\n", (unsigned int)tls_key);

		if (cfg.keyfile) {
			err = append_keyfile(cfg.keyring, tls_key, cfg.keyfile);
			if (err)
				return err;
		}
	} else {
		_cleanup_free_ char *tls_id = NULL;

		if (cfg.compat)
			err = nvme_generate_tls_key_identity_compat(cfg.hostnqn,
					cfg.subsysnqn, cfg.identity,
					hmac, decoded_key, decoded_len,
					&tls_id);
		else
			err = nvme_generate_tls_key_identity(cfg.hostnqn,
					cfg.subsysnqn, cfg.identity,
					hmac, decoded_key, decoded_len,
					&tls_id);
		if (err) {
			nvme_show_error("Failed to generate identity, error %d",
					err);
			return err;
		}
		printf("%s\n", tls_id);
	}
	return 0;
}

static void __scan_tls_key(long keyring_id, long key_id,
			   char *desc, int desc_len, void *data)
{
	FILE *fd = data;
	_cleanup_free_ unsigned char *key_data = NULL;
	_cleanup_free_ char *encoded_key = NULL;
	int key_len;
	int ver, hmac;
	char type;
	int err;

	err = nvme_read_key(keyring_id, key_id, &key_len, &key_data);
	if (err)
		return;

	if (sscanf(desc, "NVMe%01d%c%02d %*s", &ver, &type, &hmac) != 3)
		return;

	err = nvme_export_tls_key_versioned(ver, hmac, key_data, key_len,
					    &encoded_key);
	if (err)
		return;
	fprintf(fd, "%s %s\n", desc, encoded_key);
}

static int import_key(const char *keyring, FILE *fd)
{
	long keyring_id, key;
	char tls_str[512];
	char *tls_key;
	unsigned char *psk;
	unsigned int hmac;
	int linenum = -1, key_len;
	int err;

	err = nvme_lookup_keyring(keyring, &keyring_id);
	if (err) {
		nvme_show_error("Invalid keyring '%s'", keyring);
		return err;
	}

	while (fgets(tls_str, 512, fd)) {
		linenum++;
		tls_key = strrchr(tls_str, ' ');
		if (!tls_key) {
			nvme_show_error("Parse error in line %d",
					linenum);
			continue;
		}
		*tls_key = '\0';
		tls_key++;
		tls_key[strcspn(tls_key, "\n")] = 0;
		err = nvme_import_tls_key(tls_key, &key_len, &hmac, &psk);
		if (err) {
			nvme_show_error("Failed to import key in line %d",
					linenum);
			continue;
		}
		err = nvme_update_key(keyring_id, "psk", tls_str,
				psk, key_len, &key);
		if (err)
			continue;
		free(psk);
	}

	return 0;
}


static int tls_key(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc = "Manipulation of TLS keys.\n";
	const char *keyring = "Keyring for the retained key.";
	const char *keytype = "Key type of the retained key.";
	const char *keyfile = "File for list of keys.";
	const char *import = "Import all keys into the keyring.";
	const char *export = "Export all keys from the keyring.";
	const char *revoke = "Revoke key from the keyring.";

	_cleanup_file_ FILE *fd = NULL;
	mode_t old_umask = 0;
	int cnt, err = 0;

	struct config {
		char		*keyring;
		char		*keytype;
		char		*keyfile;
		bool		import;
		bool		export;
		char		*revoke;
	};

	struct config cfg = {
		.keyring	= ".nvme",
		.keytype	= "psk",
		.keyfile	= NULL,
		.import		= false,
		.export		= false,
		.revoke		= NULL,
	};

	NVME_ARGS(opts,
		  OPT_STR("keyring",	'k', &cfg.keyring,	keyring),
		  OPT_STR("keytype",	't', &cfg.keytype,	keytype),
		  OPT_STR("keyfile",	'f', &cfg.keyfile,	keyfile),
		  OPT_FLAG("import",	'i', &cfg.import,	import),
		  OPT_FLAG("export",	'e', &cfg.export,	export),
		  OPT_STR("revoke",	'r', &cfg.revoke,	revoke));

	err = argconfig_parse(argc, argv, desc, opts);
	if (err)
		return err;

	if (cfg.keyfile) {
		const char *mode;

		if (cfg.import)
			mode = "r";
		else
			mode = "w";

		old_umask = umask(0);

		fd = fopen(cfg.keyfile, mode);
		if (!fd) {
			nvme_show_error("Cannot open keyfile %s, error %d",
					cfg.keyfile, errno);
			return -errno;
		}
	} else {
		if (cfg.import)
			fd = freopen(NULL, "r", stdin);
		else
			fd = freopen(NULL, "w", stdout);
	}

	cnt = 0;
	if (cfg.export) cnt++;
	if (cfg.import) cnt++;
	if (cfg.revoke) cnt++;

	if (cnt != 1) {
		nvme_show_error("Must specify either --import, --export or --revoke");
		return -EINVAL;
	} else if (cfg.export) {
		err = nvme_scan_tls_keys(cfg.keyring, __scan_tls_key, fd);
		if (err < 0) {
			nvme_show_error("Export of TLS keys failed with '%s'",
				nvme_strerror(err));
			return err;
		}

		if (argconfig_parse_seen(opts, "verbose"))
			printf("exporting to %s\n", cfg.keyfile);

		return 0;
	} else if (cfg.import) {
		err = import_key(cfg.keyring, fd);
		if (err) {
			nvme_show_error("Import of TLS keys failed with '%s'",
					nvme_strerror(err));
			return err;
		}

		if (argconfig_parse_seen(opts, "verbose"))
			printf("importing from %s\n", cfg.keyfile);
	} else {
		err = nvme_revoke_tls_key(cfg.keyring, cfg.keytype, cfg.revoke);
		if (err) {
			nvme_show_error("Failed to revoke key '%s'",
					nvme_strerror(err));
			return err;
		}

		if (argconfig_parse_seen(opts, "verbose"))
			printf("revoking key\n");
	}

	if (old_umask != 0 && fd) {
		umask(old_umask);
		chmod(cfg.keyfile, 0600);
	}

	return err;
}

static int show_topology_cmd(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc = "Show the topology\n";
	const char *output_format = "Output format: normal|json|binary|tabular";
	const char *ranking = "Ranking order: namespace|ctrl|multipath";
	nvme_print_flags_t flags;
	_cleanup_nvme_global_ctx_ struct nvme_global_ctx *ctx = NULL;
	char *devname = NULL;
	nvme_scan_filter_t filter = NULL;
	enum nvme_cli_topo_ranking rank;
	int err;

	struct config {
		char	*ranking;
	};

	struct config cfg = {
		.ranking	= "namespace",
	};

	NVME_ARGS(opts,
		  OPT_FMT("ranking",       'r', &cfg.ranking,       ranking));

	err = argconfig_parse(argc, argv, desc, opts);
	if (err)
		return err;

	err = validate_output_format(nvme_cfg.output_format, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	if (argconfig_parse_seen(opts, "verbose"))
		flags |= VERBOSE;

	if (!strcmp(cfg.ranking, "namespace")) {
		rank = NVME_CLI_TOPO_NAMESPACE;
	} else if (!strcmp(cfg.ranking, "ctrl")) {
		rank = NVME_CLI_TOPO_CTRL;
	} else if (!strcmp(cfg.ranking, "multipath")) {
		rank = NVME_CLI_TOPO_MULTIPATH;
	} else {
		nvme_show_error("Invalid ranking argument: %s", cfg.ranking);
		return -EINVAL;
	}

	ctx = nvme_create_global_ctx(stderr, log_level);
	if (!ctx) {
		nvme_show_error("Failed to create global context");
		return -ENOMEM;
	}

	if (optind < argc)
		devname = basename(argv[optind++]);

	if (devname) {
		int subsys_id, nsid;

		if (sscanf(devname, "nvme%dn%d", &subsys_id, &nsid) != 2) {
			nvme_show_error("Invalid device name %s\n", devname);
			return -EINVAL;
		}
		filter = nvme_match_device_filter;
	}

	err = nvme_scan_topology(ctx, filter, (void *)devname);
	if (err < 0) {
		nvme_show_error("Failed to scan topology: %s", nvme_strerror(err));
		return err;
	}

	if (flags & TABULAR)
		nvme_show_topology_tabular(ctx, flags);
	else
		nvme_show_topology(ctx, rank, flags);

	return err;
}

static int discover_cmd(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc = "Send Get Log Page request to Discovery Controller.";

	return nvmf_discover(desc, argc, argv, false);
}

static int connect_all_cmd(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc = "Discover NVMeoF subsystems and connect to them";

	return nvmf_discover(desc, argc, argv, true);
}

static int connect_cmd(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc = "Connect to NVMeoF subsystem";

	return nvmf_connect(desc, argc, argv);
}

static int disconnect_cmd(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc = "Disconnect from NVMeoF subsystem";

	return nvmf_disconnect(desc, argc, argv);
}

int disconnect_all_cmd(int argc, char **argv, struct command *acmd,
	struct plugin *plugin)
{
	const char *desc = "Disconnect from all connected NVMeoF subsystems";

	return nvmf_disconnect_all(desc, argc, argv);
}

static int config_cmd(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc = "Configuration of NVMeoF subsystems";

	return nvmf_config(desc, argc, argv);
}

static int dim_cmd(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc =
	    "Send Discovery Information Management command to a Discovery Controller (DC)";

	return nvmf_dim(desc, argc, argv);
}

static int nvme_mi(int argc, char **argv, __u8 admin_opcode, const char *desc)
{
	const char *opcode = "opcode (required)";
	const char *data_len = "data I/O length (bytes)";
	const char *nmimt = "nvme-mi message type";
	const char *nmd0 = "nvme management dword 0 value";
	const char *nmd1 = "nvme management dword 1 value";
	const char *input = "data input or output file";

	int mode = 0644;
	void *data = NULL;
	int err = 0;
	bool send;
	_cleanup_fd_ int fd = -1;
	int flags;
	_cleanup_huge_ struct nvme_mem_huge mh = { 0, };
	_cleanup_nvme_global_ctx_ struct nvme_global_ctx *ctx = NULL;
	_cleanup_nvme_transport_handle_ struct nvme_transport_handle *hdl = NULL;
	__u32 result;

	struct config {
		__u8 opcode;
		__u32 namespace_id;
		__u32 data_len;
		__u32 nmimt;
		__u32 nmd0;
		__u32 nmd1;
		char *input_file;
	};

	struct config cfg = {
		.opcode = 0,
		.namespace_id = 0,
		.data_len = 0,
		.nmimt = 0,
		.nmd0 = 0,
		.nmd1 = 0,
		.input_file = "",
	};

	NVME_ARGS(opts,
		  OPT_BYTE("opcode", 'O', &cfg.opcode, opcode),
		  OPT_UINT("namespace-id", 'n', &cfg.namespace_id, namespace_desired),
		  OPT_UINT("data-len", 'l', &cfg.data_len, data_len),
		  OPT_UINT("nmimt", 'm', &cfg.nmimt, nmimt),
		  OPT_UINT("nmd0", '0', &cfg.nmd0, nmd0),
		  OPT_UINT("nmd1", '1', &cfg.nmd1, nmd1),
		  OPT_FILE("input-file", 'i', &cfg.input_file, input));

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	if (!argconfig_parse_seen(opts, "opcode")) {
		nvme_show_error("%s: opcode parameter required", *argv);
		return -EINVAL;
	}

	if (admin_opcode == nvme_admin_nvme_mi_send) {
		flags = O_RDONLY;
		fd = STDIN_FILENO;
		send = true;
	} else {
		flags = O_WRONLY | O_CREAT;
		fd = STDOUT_FILENO;
		send = false;
	}

	if (strlen(cfg.input_file)) {
		fd = open(cfg.input_file, flags, mode);
		if (fd < 0) {
			nvme_show_perror(cfg.input_file);
			return -EINVAL;
		}
	}

	if (cfg.data_len) {
		data = nvme_alloc_huge(cfg.data_len, &mh);
		if (!data) {
			nvme_show_error("failed to allocate huge memory");
			return -ENOMEM;
		}

		if (send) {
			if (read(fd, data, cfg.data_len) < 0) {
				err = -errno;
				nvme_show_error("failed to read write buffer %s", strerror(errno));
				return err;
			}
		}
	}

	err = nvme_admin_passthru(hdl, admin_opcode, 0, 0, cfg.namespace_id, 0, 0,
				  cfg.nmimt << 11 | 4, cfg.opcode, cfg.nmd0, cfg.nmd1, 0, 0,
				  cfg.data_len, data, 0, NULL, 0, &result);
	if (err < 0) {
		nvme_show_error("nmi_recv: %s", nvme_strerror(err));
	} else if (err) {
		nvme_show_status(err);
	} else  {
		printf(
		    "%s Command is Success and result: 0x%08x (status: 0x%02x, response: 0x%06x)\n",
		    nvme_cmd_to_string(true, admin_opcode), result, result & 0xff, result >> 8);
		if (result & 0xff)
			printf("status: %s\n", nvme_mi_status_to_string(result & 0xff));
		if (!send && strlen(cfg.input_file)) {
			if (write(fd, (void *)data, cfg.data_len) < 0)
				perror("failed to write data buffer");
		} else if (data && !send && !err) {
			d((unsigned char *)data, cfg.data_len, 16, 1);
		}
	}

	return err;
}

static int nmi_recv(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc =
	    "Send a NVMe-MI Receive command to the specified device, return results.";

	return nvme_mi(argc, argv, nvme_admin_nvme_mi_recv, desc);
}

static int nmi_send(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc = "Send a NVMe-MI Send command to the specified device, return results.";

	return nvme_mi(argc, argv, nvme_admin_nvme_mi_send, desc);
}

static int get_mgmt_addr_list_log(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc = "Retrieve Management Address List Log, show it";
	nvme_print_flags_t flags;
	int err = -1;

	_cleanup_free_ struct nvme_mgmt_addr_list_log *ma_log = NULL;
	_cleanup_nvme_global_ctx_ struct nvme_global_ctx *ctx = NULL;
	_cleanup_nvme_transport_handle_ struct nvme_transport_handle *hdl = NULL;

	NVME_ARGS(opts);

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	err = validate_output_format(nvme_cfg.output_format, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	ma_log = nvme_alloc(sizeof(*ma_log));
	if (!ma_log)
		return -ENOMEM;

	err = nvme_get_log_mgmt_addr_list(hdl, ma_log, sizeof(*ma_log));
	if (!err)
		nvme_show_mgmt_addr_list_log(ma_log, flags);
	else if (err > 0)
		nvme_show_status(err);
	else
		nvme_show_perror("management address list log");

	return err;
}

static int get_rotational_media_info_log(int argc, char **argv, struct command *acmd,
					 struct plugin *plugin)
{
	const char *desc = "Retrieve Rotational Media Information Log, show it";
	nvme_print_flags_t flags;
	int err = -1;

	_cleanup_free_ struct nvme_rotational_media_info_log *info = NULL;
	_cleanup_nvme_global_ctx_ struct nvme_global_ctx *ctx = NULL;
	_cleanup_nvme_transport_handle_ struct nvme_transport_handle *hdl = NULL;

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

	err = validate_output_format(nvme_cfg.output_format, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	info = nvme_alloc(sizeof(*info));
	if (!info)
		return -ENOMEM;

	err = nvme_get_log_rotational_media_info(hdl, cfg.endgid, info, sizeof(*info));
	if (!err)
		nvme_show_rotational_media_info_log(info, flags);
	else if (err > 0)
		nvme_show_status(err);
	else
		nvme_show_perror("rotational media info log");

	return err;
}

static int get_dispersed_ns_psub(struct nvme_transport_handle *hdl, __u32 nsid,
				 struct nvme_dispersed_ns_participating_nss_log **logp)
{
	int err;
	__u64 header_len = sizeof(**logp);
	__u64 psub_list_len;
	struct nvme_dispersed_ns_participating_nss_log *log = nvme_alloc(header_len);
	struct nvme_passthru_cmd cmd;

	if (!log)
		return -ENOMEM;

	err = nvme_get_log_dispersed_ns_participating_nss(hdl, nsid, log, header_len);
	if (err)
		goto err_free;

	psub_list_len = le64_to_cpu(log->numpsub) * NVME_NQN_LENGTH;

	log = nvme_realloc(log, header_len + psub_list_len);
	if (!log) {
		err = -ENOMEM;
		goto err_free;
	}

	nvme_init_get_log_dispersed_ns_participating_nss(&cmd, nsid,
		(void *)log->participating_nss, psub_list_len);
	cmd.cdw12 = header_len & 0xffffffff;
	cmd.cdw13 = header_len >> 32;
	err = nvme_get_log(hdl, &cmd, false, NVME_LOG_PAGE_PDU_SIZE, NULL);
	if (err)
		goto err_free;

	*logp = log;
	return 0;

err_free:
	free(log);
	return err;
}

static int get_dispersed_ns_participating_nss_log(int argc, char **argv, struct command *acmd,
						  struct plugin *plugin)
{
	const char *desc = "Retrieve Dispersed Namespace Participating NVM Subsystems Log, show it";
	nvme_print_flags_t flags;
	int err;

	_cleanup_nvme_global_ctx_ struct nvme_global_ctx *ctx = NULL;
	_cleanup_nvme_transport_handle_ struct nvme_transport_handle *hdl = NULL;
	_cleanup_free_ struct nvme_dispersed_ns_participating_nss_log *log = NULL;

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

	err = validate_output_format(nvme_cfg.output_format, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	err = get_dispersed_ns_psub(hdl, cfg.namespace_id, &log);
	if (!err)
		nvme_show_dispersed_ns_psub_log(log, flags);
	else if (err > 0)
		nvme_show_status(err);
	else
		nvme_show_perror("dispersed ns participating nss log");

	return err;
}

static int get_log_offset(struct nvme_transport_handle *hdl,
			  struct nvme_get_log_args *args, __u64 *offset,
			  __u32 len, void **log)
{
	struct nvme_passthru_cmd cmd;

	args->lpo = *offset,
	args->log = *log + *offset,
	args->len = len;
	*offset += args->len;

	*log = nvme_realloc(*log, *offset);
	if (!*log)
		return -ENOMEM;

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

	return nvme_get_log(hdl, &cmd, args->rae,
			    NVME_LOG_PAGE_PDU_SIZE, args->result);
}

static int get_reachability_group_desc(struct nvme_transport_handle *hdl, struct nvme_get_log_args *args,
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
	free(log);
	*logp = NULL;
	return err;
}

static int get_reachability_groups(struct nvme_transport_handle *hdl, bool rgo, bool rae,
				   struct nvme_reachability_groups_log **logp,
				   __u64 *lenp)
{
	int err;
	struct nvme_reachability_groups_log *log;
	__u64 log_len = sizeof(*log);
	struct nvme_get_log_args args = {
		.lid = NVME_LOG_LID_REACHABILITY_GROUPS,
		.nsid = NVME_NSID_ALL,
		.lsp = rgo,
		.rae = rae,
	};

	log = nvme_alloc(log_len);
	if (!log)
		return -ENOMEM;

	err = nvme_get_log_reachability_groups(hdl, rgo, rae, log, log_len);
	if (err)
		goto err_free;

	err = get_reachability_group_desc(hdl, &args, &log_len, &log);
	if (err)
		goto err_free;

	*logp = log;
	*lenp = log_len;
	return 0;

err_free:
	free(log);
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
	_cleanup_free_ struct nvme_reachability_groups_log *log = NULL;
	_cleanup_nvme_global_ctx_ struct nvme_global_ctx *ctx = NULL;
	_cleanup_nvme_transport_handle_ struct nvme_transport_handle *hdl = NULL;

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

	err = validate_output_format(nvme_cfg.output_format, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	err = get_reachability_groups(hdl, cfg.rgo, cfg.rae, &log, &len);
	if (!err)
		nvme_show_reachability_groups_log(log, len, flags);
	else if (err > 0)
		nvme_show_status(err);
	else
		nvme_show_perror("reachability groups log");

	return err;
}

static int get_reachability_association_desc(struct nvme_transport_handle *hdl, struct nvme_get_log_args *args,
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
	free(log);
	*logp = NULL;
	return err;
}

static int get_reachability_associations(struct nvme_transport_handle *hdl, bool rao, bool rae,
					 struct nvme_reachability_associations_log **logp,
					 __u64 *lenp)
{
	int err;
	struct nvme_reachability_associations_log *log;
	__u64 log_len = sizeof(*log);
	struct nvme_get_log_args args = {
		.lid = NVME_LOG_LID_REACHABILITY_ASSOCIATIONS,
		.nsid = NVME_NSID_ALL,
		.lsp = rao,
		.rae = rae,
	};

	log = nvme_alloc(log_len);
	if (!log)
		return -ENOMEM;

	err = nvme_get_log_reachability_associations(hdl, rao, rae, log, log_len);
	if (err)
		goto err_free;

	err = get_reachability_association_desc(hdl, &args, &log_len, &log);
	if (err)
		goto err_free;

	*logp = log;
	*lenp = log_len;
	return 0;

err_free:
	free(log);
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
	_cleanup_free_ struct nvme_reachability_associations_log *log = NULL;
	_cleanup_nvme_global_ctx_ struct nvme_global_ctx *ctx = NULL;
	_cleanup_nvme_transport_handle_ struct nvme_transport_handle *hdl = NULL;

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

	err = validate_output_format(nvme_cfg.output_format, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	err = get_reachability_associations(hdl, cfg.rao, cfg.rae, &log, &len);
	if (!err)
		nvme_show_reachability_associations_log(log, len, flags);
	else if (err > 0)
		nvme_show_status(err);
	else
		nvme_show_perror("reachability associations log");

	return err;
}

static int get_host_discovery(struct nvme_transport_handle *hdl, bool allhoste, bool rae,
			      struct nvme_host_discover_log **logp)
{
	int err;
	struct nvme_host_discover_log *log;
	__u64 log_len = sizeof(*log);
	struct nvme_get_log_args args = {
		.lid = NVME_LOG_LID_HOST_DISCOVERY,
		.nsid = NVME_NSID_ALL,
		.lsp = allhoste,
		.rae = rae,
	};

	log = nvme_alloc(log_len);
	if (!log)
		return -ENOMEM;

	err = nvme_get_log_host_discovery(hdl, allhoste, rae, log, log_len);
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
	free(log);
	return err;
}

static int get_host_discovery_log(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc = "Retrieve Host Discovery Log, show it";
	const char *allhoste = "All Host Entries";
	nvme_print_flags_t flags;
	int err;
	_cleanup_free_ struct nvme_host_discover_log *log = NULL;
	_cleanup_nvme_global_ctx_ struct nvme_global_ctx *ctx = NULL;
	_cleanup_nvme_transport_handle_ struct nvme_transport_handle *hdl = NULL;

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

	err = validate_output_format(nvme_cfg.output_format, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	err = get_host_discovery(hdl, cfg.allhoste, cfg.rae, &log);
	if (!err)
		nvme_show_host_discovery_log(log, flags);
	else if (err > 0)
		nvme_show_status(err);
	else
		nvme_show_perror("host discovery log");

	return err;
}

static int get_ave_discovery(struct nvme_transport_handle *hdl, bool rae, struct nvme_ave_discover_log **logp)
{
	int err;
	struct nvme_ave_discover_log *log;
	__u64 log_len = sizeof(*log);
	struct nvme_get_log_args args = {
		.lid = NVME_LOG_LID_AVE_DISCOVERY,
		.nsid = NVME_NSID_ALL,
		.rae = rae,
	};

	log = nvme_alloc(log_len);
	if (!log)
		return -ENOMEM;

	err = nvme_get_log_ave_discovery(hdl, rae, log, log_len);
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
	free(log);
	return err;
}

static int get_ave_discovery_log(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc = "Retrieve AVE Discovery Log, show it";
	nvme_print_flags_t flags;
	int err;

	_cleanup_free_ struct nvme_ave_discover_log *log = NULL;
	_cleanup_nvme_global_ctx_ struct nvme_global_ctx *ctx = NULL;
	_cleanup_nvme_transport_handle_ struct nvme_transport_handle *hdl = NULL;

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

	err = validate_output_format(nvme_cfg.output_format, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	err = get_ave_discovery(hdl, cfg.rae, &log);
	if (!err)
		nvme_show_ave_discovery_log(log, flags);
	else if (err > 0)
		nvme_show_status(err);
	else
		nvme_show_perror("ave discovery log");

	return err;
}

static int get_pull_model_ddc_req(struct nvme_transport_handle *hdl,
				  bool rae, struct nvme_pull_model_ddc_req_log **logp)
{
	int err;
	struct nvme_pull_model_ddc_req_log *log;
	__u64 log_len = sizeof(*log);
	struct nvme_get_log_args args = {
		.lid = NVME_LOG_LID_PULL_MODEL_DDC_REQ,
		.nsid = NVME_NSID_ALL,
		.rae = rae,
	};

	log = nvme_alloc(log_len);
	if (!log)
		return -ENOMEM;

	err = nvme_get_log_pull_model_ddc_req(hdl, rae, log, log_len);
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
	free(log);
	return err;
}

static int get_pull_model_ddc_req_log(int argc, char **argv, struct command *acmd,
				      struct plugin *plugin)
{
	const char *desc = "Retrieve Pull Model DDC Request Log, show it";
	nvme_print_flags_t flags;
	int err;

	_cleanup_free_ struct nvme_pull_model_ddc_req_log *log = NULL;
	_cleanup_nvme_global_ctx_ struct nvme_global_ctx *ctx = NULL;
	_cleanup_nvme_transport_handle_ struct nvme_transport_handle *hdl = NULL;

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

	err = validate_output_format(nvme_cfg.output_format, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	err = get_pull_model_ddc_req(hdl, cfg.rae, &log);
	if (!err)
		nvme_show_pull_model_ddc_req_log(log, flags);
	else if (err > 0)
		nvme_show_status(err);
	else
		nvme_show_perror("pull model ddc req log");

	return err;
}

void register_extension(struct plugin *plugin)
{
	plugin->parent = &nvme;
	nvme.extensions->tail->next = plugin;
	nvme.extensions->tail = plugin;
}

int main(int argc, char **argv)
{
	int err;

	nvme.extensions->parent = &nvme;
	if (argc < 2) {
		general_help(&builtin, NULL);
		return 0;
	}
	setlocale(LC_ALL, "");

	err = nvme_install_sigint_handler();
	if (err)
		return err;

	err = handle_plugin(argc - 1, &argv[1], nvme.extensions);
	if (err == -ENOTTY)
		general_help(&builtin, NULL);

	return err ? 1 : 0;
}
