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
#include <fs-util.h>
#include <mmio-util.h>
#include <parse-util.h>
#include <sig-util.h>
#include <suffix-util.h>
#include <time-util.h>

#include "argconfig.h"
#include "fabrics.h"
#include "global-config.h"
#include "global-ctx.h"
#include "logging.h"
#include "nvme-cmds.h"
#include "nvme-print.h"
#include "nvme-regs.h"
#include "plugin.h"

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
	.desc = "The '<device>' may be either an NVMe controller "
		"device (ex: /dev/nvme0), an nvme namespace device "
		"(ex: /dev/nvme0n1), or a mctp address in the form "
		"mctp:<net>,<eid>[:ctrl-id]",
	.extensions = &builtin,
};

static const char *app_tag = "app tag for end-to-end PI";
static const char *app_tag_mask = "app tag mask for end-to-end PI";
static const char *block_count = "number of blocks (zeroes based) on device to access";
static const char *crkey = "current reservation key";
static const char *csi = "command set identifier";
static const char *buf_len = "buffer len (if) data is sent or received";
static const char *doper = "directive operation";
static const char *dspec_w_dtype = "directive specification associated with directive type";
static const char *dtype = "directive type";
static const char *endgid = "Endurance Group Identifier (ENDGID)";
static const char *force_unit_access = "force device to commit data before command completes";
static const char *iekey = "ignore existing res. key";
static const char *latency = "output latency statistics";
static const char *limited_retry = "limit media access attempts";
static const char *lsp = "log specific field";
static const char *mos = "management operation specific";
static const char *mo = "management operation";
static const char *namespace_desired = "desired namespace";
static const char *nssf = "NVMe Security Specific Field";
static const char *only_ctrl_dev = "Only controller device is allowed";
static const char *prinfo = "PI and check field";
static const char *rae = "Retain an Asynchronous Event";
static const char *raw_directive = "show directive in binary format";
static const char *raw_dump = "dump output in binary format";
static const char *raw_identify = "show identify in binary format";
static const char *ref_tag = "reference tag for end-to-end PI";
static const char *rtype = "reservation type";
static const char *secp = "security protocol (cf. SPC-4)";
static const char *spsp = "security-protocol-specific (cf. SPC-4)";
static const char *start_block = "64-bit LBA of first block to access";
static const char *storage_tag = "storage tag for end-to-end PI";
static const char *storage_tag_check = "This bit specifies if the Storage Tag field shall be checked as\n"
	"part of end-to-end data protection processing";
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
static const char *ish = "Ignore Shutdown (for NVMe-MI command)";

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
	VAL_BYTE("resv-nf-mask", NVME_FEAT_FID_RESV_NF_MASK),
	VAL_BYTE("resv-persist", NVME_FEAT_FID_RESV_PERSIST),
	VAL_BYTE("write-protect", NVME_FEAT_FID_WRITE_PROTECT),
	VAL_BYTE("bp-write-protect", NVME_FEAT_FID_BP_WRITE_PROTECT),
	VAL_END()
};

static int open_fallback_chardev(struct libnvme_global_ctx *ctx,
				 __u32 nsid,
				 struct libnvme_transport_handle **phdl)
{
	struct libnvme_transport_handle *hdl = *phdl;
	int err;

	if (libnvme_transport_handle_is_ctrl(hdl)) {
		__cleanup_free char *cdev = NULL;

		if (!nsid) {
			nvme_show_error("controller device not supported without --namespace-id");
			return -EINVAL;
		}

		if (asprintf(&cdev, "/dev/%sn%d",
			     libnvme_transport_handle_get_name(hdl), nsid) < 0)
			return -ENOMEM;

		libnvme_close(hdl);

		err = libnvme_open(ctx, cdev, O_RDONLY, &hdl);
		if (err) {
			*phdl = NULL;

			nvme_show_error("could not open %s", cdev);
			return err;
		}

		*phdl = hdl;
	}

	return 0;
}

static int get_supported_log_pages(int argc, char **argv, struct command *acmd,
	struct plugin *plugin)
{
	const char *desc = "Retrieve supported logs and print the table.";

	__cleanup_libnvme_free struct nvme_supported_log_pages *supports = NULL;
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

	supports = libnvme_alloc(sizeof(*supports));
	if (!supports)
		return -ENOMEM;

	nvme_init_get_log(&cmd, NVME_NSID_ALL, NVME_LOG_LID_SUPPORTED_LOG_PAGES,
		NVME_CSI_NVM, supports, sizeof(*supports));
	err = libnvme_get_log(hdl, &cmd, false, sizeof(*supports));
	if (err) {
		nvme_show_err(err, "supported log pages");
		return err;
	}

	nvme_show_supported_log(supports, libnvme_transport_handle_get_name(hdl),
				flags);

	return err;
}

static int io_mgmt_send(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc = "I/O Management Send";
	const char *data = "optional file for data (default stdin)";

	__cleanup_nvme_transport_handle struct libnvme_transport_handle *hdl = NULL;
	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	__cleanup_fd int dfd = STDIN_FILENO;
	__cleanup_libnvme_free void *buf = NULL;
	struct libnvme_passthru_cmd cmd;
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
		err = libnvme_get_nsid(hdl, &cfg.nsid);
		if (err < 0) {
			nvme_show_err(err, "get-namespace-id");
			return err;
		}
	}

	if (cfg.data_len) {
		buf = libnvme_alloc(cfg.data_len);
		if (!buf)
			return -ENOMEM;
	}

	if (cfg.file) {
		dfd = shr_open_rawdata(cfg.file, O_RDONLY);
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
	err = libnvme_exec_io_passthru(hdl, &cmd);
	if (err) {
		nvme_show_err(err, "io-mgmt-send");
		return err;
	}

	nvme_show_verbose_result("io-mgmt-send: Success, mos:%u mo:%u nsid:%d",
				 cfg.mos, cfg.mo, cfg.nsid);

	return err;
}

static int io_mgmt_recv(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc = "I/O Management Receive";
	const char *data = "optional file for data (default stdout)";

	__cleanup_nvme_transport_handle struct libnvme_transport_handle *hdl = NULL;
	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	__cleanup_libnvme_free void *buf = NULL;
	struct libnvme_passthru_cmd cmd;
	__cleanup_fd int dfd = -1;
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
		err = libnvme_get_nsid(hdl, &cfg.nsid);
		if (err < 0) {
			nvme_show_err(err, "get-namespace-id");
			return err;
		}
	}

	if (cfg.data_len) {
		buf = libnvme_alloc(cfg.data_len);
		if (!buf)
			return -ENOMEM;
	}

	nvme_init_io_mgmt_recv(&cmd, cfg.nsid, cfg.mo, cfg.mos, buf,
		cfg.data_len);
	err = libnvme_exec_io_passthru(hdl, &cmd);
	if (err) {
		nvme_show_err(err, "io-mgmt-recv");
		return err;
	}

	nvme_show_verbose_result("io-mgmt-recv: Success, mos:%u mo:%u nsid:%d",
				 cfg.mos, cfg.mo, cfg.nsid);

	if (cfg.file) {
		dfd = shr_open_rawdata(cfg.file, O_WRONLY | O_CREAT | O_TRUNC, 0644);
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

	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	__cleanup_nvme_transport_handle struct libnvme_transport_handle *hdl = NULL;
	__cleanup_libnvme_free unsigned char *log = NULL;
	struct libnvme_passthru_cmd cmd;
	int err;
	nvme_print_flags_t flags;

	struct config {
		bool	ish;
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
		.ish		= false,
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
		.xfer_len	= NVME_LOG_PAGE_PDU_SIZE,
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
		  OPT_FLAG("ish",          'I', &cfg.ish,          ish),
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

	err = validate_output_format(nvme_args.output_format, &flags);
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

	log = libnvme_alloc(cfg.log_len);
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
	if (cfg.ish) {
		if (libnvme_transport_handle_is_mi(hdl))
			nvme_init_mi_cmd_flags(&cmd, ish);
		else
			nvme_show_error("ISH is supported only for NVMe-MI");
	}
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

	err = libnvme_get_log(hdl, &cmd, cfg.rae, cfg.xfer_len);
	if (err) {
		nvme_show_err(err, "log page");
		return err;
	}

	if (!cfg.raw_binary) {
		nvme_show_result("Device:%s log-id:%d namespace-id:%#x",
		                 libnvme_transport_handle_get_name(hdl), cfg.log_id,
		                 cfg.namespace_id);
		d(log, cfg.log_len, 16, 1);
		if (nvme_args.verbose)
			nvme_show_log(libnvme_transport_handle_get_name(hdl), args.lid,
				      args.nsid, args.lsi, args.lsp, args.log, args.len,
				      VERBOSE);
	} else {
		d_raw((unsigned char *)log, cfg.log_len);
	}

	return err;
}

static bool is_ns_mgmt_support(struct libnvme_transport_handle *hdl)
{
	int err;
	struct libnvme_passthru_cmd cmd;

	__cleanup_libnvme_free struct nvme_id_ctrl *ctrl = libnvme_alloc(sizeof(*ctrl));

	if (!ctrl)
		return false;

	nvme_init_identify_ctrl(&cmd, ctrl);
	err = libnvme_exec_admin_passthru(hdl, &cmd);
	if (err)
		return false;

	return le16_to_cpu(ctrl->oacs) & NVME_CTRL_OACS_NS_MGMT;
}

static void ns_mgmt_show_status(struct libnvme_transport_handle *hdl, int err, char *cmd, __u32 nsid)
{
	if (err < 0) {
		nvme_show_error("%s: %s", cmd, libnvme_strerror(-err));
		return;
	} else if (err > 0) {
		nvme_show_status(err);
		if (!is_ns_mgmt_support(hdl))
			nvme_show_error("NS management and attachment not supported");
		return;
	}

	nvme_show_verbose_key_value(cmd, "success");
	nvme_show_verbose_key_value("nsid", "%d", nsid);
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

	__cleanup_nvme_transport_handle struct libnvme_transport_handle *hdl = NULL;
	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	struct libnvme_passthru_cmd cmd;
	nvme_print_flags_t flags;
	int err;

	struct config {
		bool	ish;
		__u32	namespace_id;
	};

	struct config cfg = {
		.ish		= false,
		.namespace_id	= 0,
	};

	NVME_ARGS(opts,
		  OPT_FLAG("ish",          'I', &cfg.ish,          ish),
		  OPT_UINT("namespace-id", 'n', &cfg.namespace_id, namespace_id));

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	err = validate_output_format(nvme_args.output_format, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	if (!cfg.namespace_id) {
		err = libnvme_get_nsid(hdl, &cfg.namespace_id);
		if (err < 0) {
			nvme_show_error("get-namespace-id: %s", libnvme_strerror(-err));
			return err;
		}
	}

	nvme_init_ns_mgmt_delete(&cmd, cfg.namespace_id);
	if (cfg.ish) {
		if (libnvme_transport_handle_is_mi(hdl))
			nvme_init_mi_cmd_flags(&cmd, ish);
		else
			nvme_show_error("ISH is supported only for NVMe-MI");
	}
	err = libnvme_exec_admin_passthru(hdl, &cmd);
	ns_mgmt_show_status(hdl, err, acmd->name, cfg.namespace_id);

	return err;
}

static int nvme_attach_ns(int argc, char **argv, int attach, const char *desc, struct command *acmd)
{
	__cleanup_nvme_transport_handle struct libnvme_transport_handle *hdl = NULL;
	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;

	__cleanup_libnvme_free struct nvme_ctrl_list *cntlist = NULL;
	__u16 list[NVME_ID_CTRL_LIST_MAX];
	struct libnvme_passthru_cmd cmd;
	nvme_print_flags_t flags;
	int err, num;

	const char *namespace_id = "namespace to attach";
	const char *cont = "optional comma-sep controller id list";

	struct config {
		bool	ish;
		__u32	nsid;
		char	*cntlist;
	};

	struct config cfg = {
		.ish		= false,
		.nsid		= 0,
		.cntlist	= "",
	};

	NVME_ARGS(opts,
		  OPT_FLAG("ish",          'I', &cfg.ish,     ish),
		  OPT_UINT("namespace-id", 'n', &cfg.nsid,    namespace_id),
		  OPT_LIST("controllers",  'c', &cfg.cntlist, cont));

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	err = validate_output_format(nvme_args.output_format, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	if (libnvme_transport_handle_is_ns(hdl)) {
		nvme_show_error("%s: a namespace device opened (dev: %s, nsid: %d)", acmd->name,
				libnvme_transport_handle_get_name(hdl), cfg.nsid);
		return -EINVAL;
	}

	if (!cfg.nsid) {
		nvme_show_error("%s: namespace-id parameter required", acmd->name);
		return -EINVAL;
	}

	num = shr_parse_csv_u16(cfg.cntlist, list, ARRAY_SIZE(list));
	if (num == -1) {
		nvme_show_error("%s: controller id list is malformed", acmd->name);
		return -EINVAL;
	}

	cntlist = libnvme_alloc(sizeof(*cntlist));
	if (!cntlist)
		return -ENOMEM;

	if (argconfig_parse_seen(opts, "controllers")) {
		nvme_init_ctrl_list(cntlist, num, list);
	} else {
		struct nvme_id_ctrl ctrl = { 0 };

		nvme_init_identify_ctrl(&cmd, &ctrl);
		err = libnvme_exec_admin_passthru(hdl, &cmd);
		if (err) {
			nvme_show_error("identify-ctrl %s", libnvme_strerror(-err));
			return err;
		}
		cntlist->num = cpu_to_le16(1);
		cntlist->identifier[0] = ctrl.cntlid;
	}

	if (attach)
		nvme_init_ns_attach_ctrls(&cmd, cfg.nsid, cntlist);
	else
		nvme_init_ns_detach_ctrls(&cmd, cfg.nsid, cntlist);

	if (cfg.ish) {
		if (libnvme_transport_handle_is_mi(hdl))
			nvme_init_mi_cmd_flags(&cmd, ish);
		else
			nvme_show_error("ISH is supported only for NVMe-MI");
	}
	err = libnvme_exec_admin_passthru(hdl, &cmd);
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

static int parse_lba_num_si(struct libnvme_transport_handle *hdl, const char *opt,
			    const char *val, __u8 flbas, __u64 *num, __u64 align)
{
	__cleanup_libnvme_free struct nvme_ns_list *ns_list = NULL;
	__cleanup_libnvme_free struct nvme_id_ctrl *ctrl = NULL;
	__cleanup_libnvme_free struct nvme_id_ns *ns = NULL;
	struct libnvme_passthru_cmd cmd;
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

	ctrl = libnvme_alloc(sizeof(*ctrl));
	if (!ctrl)
		return -ENOMEM;

	nvme_init_identify_ctrl(&cmd, ctrl);
	err = libnvme_exec_admin_passthru(hdl, &cmd);
	if (err) {
		nvme_show_err(err, "identify controller");
		return err;
	}

	ns_list = libnvme_alloc(sizeof(*ns_list));
	if (!ns_list)
		return -ENOMEM;

	if ((ctrl->oacs & 0x8) >> 3) {
		nsid = NVME_NSID_ALL;
	} else {
		nvme_init_identify_active_ns_list(&cmd, nsid - 1, ns_list);
		err = libnvme_exec_admin_passthru(hdl, &cmd);
		if (err) {
			nvme_show_err(err, "identify namespace list");
			return err;
		}
		nsid = le32_to_cpu(ns_list->ns[0]);
	}

	ns = libnvme_alloc(sizeof(*ns));
	if (!ns)
		return -ENOMEM;

	nvme_init_identify_ns(&cmd, nsid, ns);
	err = libnvme_exec_admin_passthru(hdl, &cmd);
	if (err) {
		nvme_show_err(err, "identify namespace");
		return err;
	}

	nvme_id_ns_flbas_to_lbaf_inuse(flbas, &lbaf);
	lbas = (1 << ns->lbaf[lbaf].ds) + le16_to_cpu(ns->lbaf[lbaf].ms);

	err = shr_suffix_si_parse(val, &endptr, (uint64_t *)num);
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

	__cleanup_nvme_transport_handle struct libnvme_transport_handle *hdl = NULL;
	__cleanup_libnvme_free struct nvme_ns_mgmt_host_sw_specified *data = NULL;
	__cleanup_libnvme_free struct nvme_id_ns_granularity_list *gr_list = NULL;
	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	__cleanup_libnvme_free struct nvme_id_ctrl *id = NULL;
	__cleanup_libnvme_free struct nvme_id_ns *ns = NULL;
	__u64 align_nsze = 1 << 20; /* Default 1 MiB */
	__u64 align_ncap = align_nsze;
	struct libnvme_passthru_cmd cmd;
	uint16_t phndl[128] = { 0, };
	nvme_print_flags_t flags;
	uint16_t num_phandle;
	int err = 0, i;
	__u32 nsid;

	struct config {
		bool	ish;
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
		.ish		= false,
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
		  OPT_FLAG("ish",          'I', &cfg.ish,      ish),
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

	err = validate_output_format(nvme_args.output_format, &flags);
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

		ns = libnvme_alloc(sizeof(*ns));
		if (!ns)
			return -ENOMEM;

		nvme_init_identify_ns(&cmd, NVME_NSID_ALL, ns);
		err = libnvme_exec_admin_passthru(hdl, &cmd);
		if (err) {
			if (err > 0)
				nvme_show_error("identify failed");
			nvme_show_err(err, "identify-namespace");
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
		nvme_show_error("FLBAS corresponding to block size %"PRIu64" not found",
			(uint64_t)cfg.bs);
		nvme_show_error("Please correct block size, or specify FLBAS directly");

		return -EINVAL;
	}

	id = libnvme_alloc(sizeof(*id));
	if (!id)
		return -ENOMEM;

	nvme_init_identify_ctrl(&cmd, id);
	err = libnvme_exec_admin_passthru(hdl, &cmd);
	if (err) {
		if (err > 0)
			nvme_show_error("identify controller failed");
		nvme_show_err(err, "identify-controller");
		return err;
	}

	if (id->ctratt & NVME_CTRL_CTRATT_NAMESPACE_GRANULARITY) {
		gr_list = libnvme_alloc(sizeof(*gr_list));
		if (!gr_list)
			return -ENOMEM;

		nvme_init_identify_ns_granularity(&cmd, gr_list);
		if (!libnvme_exec_admin_passthru(hdl, &cmd)) {
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

	data = libnvme_alloc(sizeof(*data));
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

	num_phandle = shr_parse_csv_ushort(cfg.phndls, phndl, ARRAY_SIZE(phndl));
	if (cfg.nphndls != num_phandle) {
		nvme_show_error("Invalid Placement handle list");
		return -EINVAL;
	}

	for (i = 0; i < num_phandle; i++)
		data->phndl[i] = cpu_to_le16(phndl[i]);

	nvme_init_ns_mgmt_create(&cmd, cfg.csi, data);
	if (cfg.ish) {
		if (libnvme_transport_handle_is_mi(hdl))
			nvme_init_mi_cmd_flags(&cmd, ish);
		else
			nvme_show_error("ISH is supported only for NVMe-MI");
	}
	err = libnvme_exec_admin_passthru(hdl, &cmd);
	nsid = cmd.result;
	ns_mgmt_show_status(hdl, err, acmd->name, nsid);

	return err;
}

static bool nvme_match_devname(char *devname, libnvme_ns_t ns)
{
	libnvme_ctrl_t c = libnvme_ns_get_ctrl(ns);

	if (!strcmp(devname, libnvme_ns_get_name(ns)) ||
	    (c && !strcmp(devname, libnvme_ctrl_get_name(c))) ||
	    !strcmp(devname, libnvme_ns_get_generic_name(ns)))
		return true;

	return false;
}

static bool nvme_match_device_filter(libnvme_subsystem_t s,
		libnvme_ctrl_t c, libnvme_ns_t ns, void *f_args)
{
	char *devname = f_args;
	libnvme_ns_t n;

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

static int handle_scan_topology_error(int err)
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

static int list_subsys(int argc, char **argv, struct command *acmd,
		struct plugin *plugin)
{
	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	nvme_print_flags_t flags;
	const char *desc = "Retrieve information for subsystems";
	libnvme_scan_filter_t filter = NULL;
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

	err = validate_output_format(nvme_args.output_format, &flags);
	if (err < 0 || (flags != JSON && flags != NORMAL)) {
		nvme_show_error("Invalid output format");
		return -EINVAL;
	}

	if (nvme_args.verbose)
		flags |= VERBOSE;

	err = nvme_create_global_ctx(&ctx);
	if (err) {
		if (devname)
			nvme_show_error("Failed to scan nvme subsystem for %s", devname);
		else
			nvme_show_error("Failed to scan nvme subsystem");
		return err;
	}

	if (devname) {
		int subsys_num;

		if (sscanf(devname, "nvme%dn%d", &subsys_num, &nsid) < 1 &&
		    sscanf(devname, "ng%dn%d", &subsys_num, &nsid) != 2) {
			nvme_show_error("Invalid device name %s", devname);
			return -EINVAL;
		}
		filter = nvme_match_device_filter;
	}

	err = libnvme_scan_topology(ctx, filter, (void *)devname);
	if (err)
		return handle_scan_topology_error(err);

	nvme_show_subsystem_list(ctx, nsid != NVME_NSID_ALL, flags);

	return 0;
}

#ifdef CONFIG_TOP
static int top(int argc, char **argv, struct command *acmd,
		struct plugin *plugin)
{
	int err;
	nvme_print_flags_t flags = 0;
	const char *desc = "show nvme top output";
	const char *delay = "refresh interval in seconds";

	struct config {
		int delay;
	};

	struct config cfg = {
		.delay = 1,
	};

	NVME_ARGS(opts,
		  OPT_INT("delay", 'd', &cfg.delay, delay));

	err = parse_args(argc, argv, desc, opts);
	if (err)
		return err;

	err = validate_output_format(nvme_args.output_format, &flags);
	if (err < 0 || flags != NORMAL) {
		nvme_show_error("Invalid output format");
		return -EINVAL;
	}

	if (cfg.delay < 1) {
		nvme_show_error("delay must be greater than or equal to 1");
		return -EINVAL;
	}

	err = shr_install_sigwinch_handler();
	if (err) {
		nvme_show_error("failed to install sig handler for SIGWINCH");
		return err;
	}

	nvme_show_top(flags, cfg.delay);

	return err;
}
#endif

static int list(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc = "Retrieve basic information for all NVMe namespaces";
	nvme_print_flags_t flags;
	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	int err = 0;

	NVME_ARGS(opts);

	err = parse_args(argc, argv, desc, opts);
	if (err)
		return err;

	err = validate_output_format(nvme_args.output_format, &flags);
	if (err < 0 || (flags != JSON && flags != NORMAL)) {
		nvme_show_error("Invalid output format");
		return -EINVAL;
	}

	if (nvme_args.verbose)
		flags |= VERBOSE;

	err = nvme_create_global_ctx(&ctx);
	if (err)
		return err;

	err = libnvme_scan_topology(ctx, NULL, NULL);
	if (err < 0)
		return handle_scan_topology_error(err);

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

	__cleanup_libnvme_free struct nvme_id_ctrl *ctrl = NULL;
	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	__cleanup_nvme_transport_handle struct libnvme_transport_handle *hdl = NULL;
	struct libnvme_passthru_cmd cmd;
	nvme_print_flags_t flags;
	int err;

	struct config {
		bool	vendor_specific;
		bool	raw_binary;
	};

	struct config cfg = {
		.vendor_specific	= false,
		.raw_binary		= false,
	};

	NVME_ARGS(opts,
		  OPT_FLAG("vendor-specific", 'V', &cfg.vendor_specific, vendor_specific),
		  OPT_FLAG("raw-binary",      'b', &cfg.raw_binary,      raw_identify));

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

	if (cfg.vendor_specific)
		flags |= VS;

	if (nvme_args.verbose)
		flags |= VERBOSE;

	ctrl = libnvme_alloc(sizeof(*ctrl));
	if (!ctrl)
		return -ENOMEM;

	nvme_init_identify_ctrl(&cmd, ctrl);
	err = libnvme_exec_admin_passthru(hdl, &cmd);
	if (err) {
		nvme_show_err(err, "identify controller");
		return err;
	}

	nvme_show_id_ctrl(ctx, hdl, ctrl, flags, vs);

	return err;
}

static int get_ns_id(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc = "Get namespace ID of a the block device.";

	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	__cleanup_nvme_transport_handle struct libnvme_transport_handle *hdl = NULL;
	unsigned int nsid;
	int err;
	nvme_print_flags_t flags;

	NVME_ARGS(opts);

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	err = validate_output_format(nvme_args.output_format, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	err = libnvme_get_nsid(hdl, &nsid);
	if (err < 0) {
		nvme_show_error("get namespace ID: %s", libnvme_strerror(-err));
		return -errno;
	}

	nvme_show_result("%s: namespace-id:%d", libnvme_transport_handle_get_name(hdl), nsid);

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

	__cleanup_nvme_transport_handle struct libnvme_transport_handle *hdl = NULL;
	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	struct libnvme_passthru_cmd cmd;
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
	err = libnvme_exec_admin_passthru(hdl, &cmd);
	if (err) {
		nvme_show_err(err, "virt-mgmt");
		return err;
	}

	nvme_show_verbose_result(
		"success, Number of Controller Resources Modified (NRM):%" PRIu64,
		(uint64_t)cmd.result);

	return err;
}

static int nvme_sleep(unsigned int seconds)
{
	shr_sigint_received = false;

	sleep(seconds);

	if (shr_sigint_received) {
		nvme_show_error("Interrupted device self-test operation by SIGINT");
		return -SIGINT;
	}

	return 0;
}

static int wait_self_test(struct libnvme_transport_handle *hdl)
{
	static const char spin[] = {'-', '\\', '|', '/' };
	__cleanup_libnvme_free struct nvme_self_test_log *log = NULL;
	__cleanup_libnvme_free struct nvme_id_ctrl *ctrl = NULL;
	struct libnvme_passthru_cmd cmd;
	int err, i = 0, p = 0, cnt = 0;
	int wthr;

	ctrl = libnvme_alloc(sizeof(*ctrl));
	if (!ctrl)
		return -ENOMEM;

	log = libnvme_alloc(sizeof(*log));
	if (!log)
		return -ENOMEM;

	nvme_init_identify_ctrl(&cmd, ctrl);
	err = libnvme_exec_admin_passthru(hdl, &cmd);
	if (err) {
		nvme_show_err(err, "identify-ctrl");
		return err;
	}

	wthr = le16_to_cpu(ctrl->edstt) * 60 / 100 + 60;

	nvme_show_result("Waiting for self test completion...");
	while (true) {
		if (nvme_is_output_format_normal()) {
			print_info("\r[%.*s%c%.*s] %3d%%", p / 2, dash, spin[i % 4], 49 - p / 2, space, p);
			fflush(stdout);
		}
		err = nvme_sleep(1);
		if (err)
			return err;

		nvme_init_get_log(&cmd, NVME_NSID_ALL, NVME_LOG_LID_DEVICE_SELF_TEST,
			NVME_CSI_NVM, log, sizeof(*log));
		err = libnvme_get_log(hdl, &cmd, false, sizeof(*log));
		if (err) {
			if (nvme_is_output_format_normal())
				print_info("\n");
			nvme_show_err(err, "self test log\n");
			return err;
		}

		if (++cnt > wthr) {
			nvme_show_error("no progress for %d seconds, stop waiting", wthr);
			return -EIO;
		}

		if (log->completion == 0 && p > 0) {
			if (nvme_is_output_format_normal())
				print_info("\r[%.*s] %3d%%\n", 50, dash, 100);
			break;
		}

		if (log->completion < p) {
			if (nvme_is_output_format_normal())
				print_info("\n");
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

static void abort_self_test(struct libnvme_transport_handle *hdl, bool ish,
			__u32 nsid)
{
	struct libnvme_passthru_cmd cmd;
	int err;

	nvme_init_dev_self_test(&cmd, nsid, NVME_DST_STC_ABORT);
	if (ish) {
		if (libnvme_transport_handle_is_mi(hdl))
			nvme_init_mi_cmd_flags(&cmd, ish);
		else
			nvme_show_error("ISH is supported only for NVMe-MI");
	}
	err = libnvme_exec_admin_passthru(hdl, &cmd);
	if (err) {
		nvme_show_err(err, "Device self-test");
		return;
	}

	nvme_show_result("Aborting device self-test operation");
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

	__cleanup_nvme_transport_handle struct libnvme_transport_handle *hdl = NULL;
	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	struct libnvme_passthru_cmd cmd;
	nvme_print_flags_t flags;
	int err;

	struct config {
		bool	ish;
		__u32	namespace_id;
		__u8	stc;
		bool	wait;
	};

	struct config cfg = {
		.ish		= false,
		.namespace_id	= NVME_NSID_ALL,
		.stc		= NVME_ST_CODE_RESERVED,
		.wait		= false,
	};

	NVME_ARGS(opts,
		  OPT_FLAG("ish",            'I', &cfg.ish,          ish),
		  OPT_UINT("namespace-id",   'n', &cfg.namespace_id, namespace_id),
		  OPT_BYTE("self-test-code", 's', &cfg.stc,          self_test_code),
		  OPT_FLAG("wait",           'w', &cfg.wait,         wait));

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	err = validate_output_format(nvme_args.output_format, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	if (cfg.stc == NVME_ST_CODE_RESERVED) {
		__cleanup_libnvme_free struct nvme_self_test_log *log = NULL;

		log = libnvme_alloc(sizeof(*log));
		if (!log)
			return -ENOMEM;

		nvme_init_get_log(&cmd, NVME_NSID_ALL, NVME_LOG_LID_DEVICE_SELF_TEST,
			NVME_CSI_NVM, log, sizeof(*log));
		err = libnvme_get_log(hdl, &cmd, false, sizeof(*log));
		if (err) {
			if (nvme_is_output_format_normal())
				print_info("\n");
			nvme_show_err(err, "self test log\n");
		}

		if (log->completion == 0) {
			nvme_show_result("no self test running");
		} else {
			if (cfg.wait)
				err = wait_self_test(hdl);
			else
				nvme_show_result("progress %d%%", log->completion);
		}

		goto check_abort;
	}

	nvme_init_dev_self_test(&cmd, cfg.namespace_id, cfg.stc);
	if (cfg.ish) {
		if (libnvme_transport_handle_is_mi(hdl))
			nvme_init_mi_cmd_flags(&cmd, ish);
		else
			nvme_show_error("ISH is supported only for NVMe-MI");
	}
	err = libnvme_exec_admin_passthru(hdl, &cmd);
	if (err) {
		nvme_show_err(err, "Device self-test");
		goto check_abort;
	}

	if (cfg.stc == NVME_ST_CODE_ABORT)
		nvme_show_result("Aborting device self-test operation");
	else if (cfg.stc == NVME_ST_CODE_EXTENDED)
		nvme_show_result("Extended Device self-test started");
	else if (cfg.stc == NVME_ST_CODE_SHORT)
		nvme_show_result("Short Device self-test started");
	else if (cfg.stc == NVME_ST_CODE_HOST_INIT)
		nvme_show_result("Host-Initiated Refresh started");

	if (cfg.wait && cfg.stc != NVME_ST_CODE_ABORT)
		err = wait_self_test(hdl);

check_abort:
	if (err == -EINTR)
		abort_self_test(hdl, cfg.ish, cfg.namespace_id);

	return err;
}

static int get_feature_id(struct libnvme_transport_handle *hdl, struct feat_cfg *cfg,
			  void **buf, __u64 *result)
{
	if (!cfg->data_len)
		libnvme_get_feature_length(cfg->feature_id, cfg->cdw11,
					NVME_DATA_TFR_CTRL_TO_HOST,	
					&cfg->data_len);

	if (cfg->feature_id == NVME_FEAT_FID_FDP_EVENTS) {
		cfg->data_len = 0xff * sizeof(__u16);
		cfg->cdw11 |= 0xff << 16;
	}

	if (NVME_CHECK(cfg->sel, GET_FEATURES_SEL, SUPPORTED))
		cfg->data_len = 0;

	if (cfg->data_len) {
		*buf = libnvme_alloc(cfg->data_len - 1);
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

static void get_feature_id_print(struct feat_cfg cfg, int err, __u64 result,
		void *buf, nvme_print_flags_t flags)
{
	int status = err > 0 ? filter_out_flags(err) : err;
	enum nvme_status_type type = NVME_STATUS_TYPE_NVME;

	if (err) {
		if (nvme_status_equals(status, type, NVME_SC_INVALID_FIELD) ||
		    nvme_status_equals(status, type, NVME_SC_INVALID_NS))
			return;
		nvme_show_err(err, "get-feature");
		return;
	}

	nvme_show_feature(cfg.feature_id, cfg.sel, result, buf, cfg.data_len,
			  flags);
}

static bool is_get_feature_result_set(enum nvme_features_id feature_id)
{
	switch (feature_id) {
	case NVME_FEAT_FID_PERF_CHARACTERISTICS:
	case NVME_FEAT_FID_HOST_ID:
		return false;
	default:
		break;
	}

	return true;
}

static int get_feature_id_changed(struct libnvme_transport_handle *hdl, struct feat_cfg cfg,
		nvme_print_flags_t flags)
{
	__cleanup_libnvme_free void *buf_def = NULL;
	__cleanup_libnvme_free void *buf = NULL;
	__u64 result_def = 0;
	__u64 result = 0;
	int err_def = 0;
	int err;

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

static int get_feature_ids(struct libnvme_transport_handle *hdl, struct feat_cfg cfg,
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
	const char *changed = "show feature changed";
	nvme_print_flags_t flags = NORMAL;

	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	__cleanup_nvme_transport_handle struct libnvme_transport_handle *hdl = NULL;
	int err;

	struct feat_cfg cfg = {
		.feature_id	= 0,
		.namespace_id	= 0,
		.sel		= NVME_GET_FEATURES_SEL_CURRENT,
		.data_len	= 0,
		.raw_binary	= false,
		.cdw11		= 0,
		.uuid_index	= 0,
	};

	NVME_ARGS(opts,
		  OPT_BYTE("feature-id",     'f', &cfg.feature_id,     feature_id, feature_name),
		  OPT_UINT("namespace-id",   'n', &cfg.namespace_id,   namespace_id_desired),
		  OPT_BYTE("sel",            's', &cfg.sel,            sel),
		  OPT_UINT("data-len",       'l', &cfg.data_len,       buf_len),
		  OPT_FLAG("raw-binary",     'b', &cfg.raw_binary,     raw),
		  OPT_UINT("cdw11",          'c', &cfg.cdw11,          cdw11),
		  OPT_BYTE("uuid-index",     'U', &cfg.uuid_index,     uuid_index_specify),
		  OPT_FLAG("changed",        'C', &cfg.changed,        changed));

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	err = validate_output_format(nvme_args.output_format, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	if (!argconfig_parse_seen(opts, "namespace-id")) {
		err = libnvme_get_nsid(hdl, &cfg.namespace_id);
		if (err < 0) {
			if (errno != ENOTTY) {
				nvme_show_error("get-namespace-id: %s", libnvme_strerror(-err));
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

	if (nvme_args.verbose)
		flags |= VERBOSE;

	err = get_feature_ids(hdl, cfg, flags);

	return err;
}

/*
 * Transfers one chunk of firmware to the device, and decodes & reports any
 * errors. Returns -1 on (fatal) error; signifying that the transfer should
 * be aborted.
 */
static int fw_download_single(struct libnvme_transport_handle *hdl, void *fw_buf,
			      bool ish, unsigned int fw_len, uint32_t offset,
			      uint32_t len, bool progress, bool ignore_ovr)
{
	const unsigned int max_retries = 3;
	struct libnvme_passthru_cmd cmd;
	bool retryable, ovr;
	int err, try;

	if (progress) {
		print_info("Firmware download: transferring 0x%08x/0x%08x bytes: %03d%%\r",
		           offset, fw_len, (int)(100 * offset / fw_len));
	}

	if (libnvme_transport_handle_is_mi(hdl))
		nvme_init_mi_cmd_flags(&cmd, ish);

	for (try = 0; try < max_retries; try++) {
		if (try > 0) {
			nvme_show_error("retrying offset %x (%u/%u)",
				offset, try, max_retries);
		}

		err = nvme_init_fw_download(&cmd, fw_buf, len, offset);
		if (err)
			return err;

		err = libnvme_exec_admin_passthru(hdl, &cmd);
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
			print_info("\n");
			fflush(stdout);
		}

		nvme_show_error("fw-download: error on offset 0x%08x/0x%08x",
			offset, fw_len);

		nvme_show_err(err, "fw-download");
		if (err > 0 && ovr) {
			/*
			 * non-ignored ovr error: print a little extra info
			 * about recovering
			 */
			nvme_show_error("Use --ignore-ovr to ignore overwrite errors");

			/*
			 * We'll just be attempting more overwrites if
			 * we retry. DNR will likely be set, but force
			 * an exit anyway.
			 */
			retryable = false;
		}

		if (!retryable)
			break;
	}

	return -1;
}

static int fw_read_full(int fd, void *buf, size_t len)
{
	size_t offset = 0;

	while (offset < len) {
		ssize_t ret = read(fd, (char *)buf + offset, len - offset);

		if (ret < 0) {
			if (errno == EINTR)
				continue;
			return -errno;
		}
		if (!ret)
			return -EIO;
		offset += ret;
	}

	return 0;
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
	const char *stream = "read firmware in transfer-sized chunks";

	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	__cleanup_nvme_transport_handle struct libnvme_transport_handle *hdl = NULL;
	__cleanup_huge struct libnvme_mem_huge mh = { 0, };
	__cleanup_libnvme_free void *stream_buf = NULL;
	__cleanup_fd int fw_fd = -1;
	unsigned int fw_size, pos;
	int err;
	struct stat sb;
	void *fw_buf;
	struct nvme_id_ctrl ctrl = { 0 };
	struct libnvme_passthru_cmd cmd;
	nvme_print_flags_t flags;

	struct config {
		char	*fw;
		bool	ish;
		__u32	xfer;
		__u32	offset;
		bool	progress;
		bool	ignore_ovr;
		bool	stream;
	};

	struct config cfg = {
		.fw         = "",
		.ish        = false,
		.xfer       = 0,
		.offset     = 0,
		.progress   = false,
		.ignore_ovr = false,
		.stream     = false,
	};

	NVME_ARGS(opts,
		  OPT_FILE("fw",         'f', &cfg.fw,         fw),
		  OPT_FLAG("ish",        'I', &cfg.ish,        ish),
		  OPT_UINT("xfer",       'x', &cfg.xfer,       xfer),
		  OPT_UINT("offset",     'O', &cfg.offset,     offset),
		  OPT_FLAG("progress",   'p', &cfg.progress,   progress),
		  OPT_FLAG("ignore-ovr", 'i', &cfg.ignore_ovr, ignore_ovr),
		  OPT_FLAG("stream",       0, &cfg.stream,      stream));

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	err = validate_output_format(nvme_args.output_format, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	fw_fd = shr_open_rawdata(cfg.fw, O_RDONLY);
	cfg.offset <<= 2;
	if (fw_fd < 0) {
		nvme_show_error("Failed to open firmware file %s: %s", cfg.fw, libnvme_strerror(errno));
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
		nvme_init_identify_ctrl(&cmd, &ctrl);
		err = libnvme_exec_admin_passthru(hdl, &cmd);
		if (err) {
			nvme_show_error("identify-ctrl: %s", libnvme_strerror(err));
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

	if (cfg.stream) {
		stream_buf = libnvme_alloc(cfg.xfer);
		fw_buf = stream_buf;
	} else {
		fw_buf = libnvme_alloc_huge(fw_size, &mh);
	}
	if (!fw_buf) {
		nvme_show_error("failed to allocate firmware buffer");
		return -ENOMEM;
	}

	if (!cfg.stream) {
		err = fw_read_full(fw_fd, fw_buf, fw_size);
		if (err) {
			nvme_show_error("read %s: %s", cfg.fw,
					libnvme_strerror(err));
			return err;
		}
	}

	if (cfg.ish && !libnvme_transport_handle_is_mi(hdl)) {
		nvme_show_error("ISH is supported only for NVMe-MI");
	}

	for (pos = 0; pos < fw_size; pos += cfg.xfer) {
		void *xfer_buf = cfg.stream ? fw_buf : fw_buf + pos;

		cfg.xfer = min(cfg.xfer, fw_size - pos);
		if (cfg.stream) {
			err = fw_read_full(fw_fd, fw_buf, cfg.xfer);
			if (err) {
				nvme_show_error("read %s: %s", cfg.fw,
						libnvme_strerror(err));
				break;
			}
		}

		err = fw_download_single(hdl, xfer_buf, cfg.ish, fw_size,
					 cfg.offset + pos, cfg.xfer,
					 cfg.progress, cfg.ignore_ovr);
		if (err)
			break;
	}

	if (!err) {
		/* end the progress output */
		if (cfg.progress)
			print_info("\n");
		nvme_show_verbose_result("Firmware download success");
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

static bool fw_commit_support_mud(struct libnvme_transport_handle *hdl)
{
	__cleanup_libnvme_free struct nvme_id_ctrl *ctrl = NULL;
	struct libnvme_passthru_cmd cmd;
	int err;

	ctrl = libnvme_alloc(sizeof(*ctrl));
	if (!ctrl)
		return false;

	nvme_init_identify_ctrl(&cmd, ctrl);
	err = libnvme_exec_admin_passthru(hdl, &cmd);

	if (err)
		nvme_show_error("identify-ctrl: %s", libnvme_strerror(err));
	else if (ctrl->frmw >> 5 & 0x1)
		return true;

	return false;
}

static void fw_commit_print_mud(bool mud_supported, __u64 result)
{
	if (!mud_supported)
		return;

	nvme_show_result("Multiple Update Detected (MUD) Value: %#" PRIx64,
		                 (uint64_t)result);

	if (result & 0x1)
		nvme_show_result("Detected an overlapping firmware/boot partition image update command "
		                 "sequence due to processing a command from an Admin SQ on a controller");

	if (result >> 1 & 0x1)
		nvme_show_result("Detected an overlapping firmware/boot partition image update command "
		                 "sequence due to processing a command from a Management Endpoint");
}

static void fw_commit_err(int err, __u8 action, __u8 slot, __u8 bpid)
{
	__u32 val;

	if (err > 0 && nvme_status_get_type(err) == NVME_STATUS_TYPE_NVME) {
		val = nvme_status_get_value(err);
		switch (val & 0x7ff) {
		case NVME_SC_FW_NEEDS_CONV_RESET:
		case NVME_SC_FW_NEEDS_SUBSYS_RESET:
		case NVME_SC_FW_NEEDS_RESET:
			print_info("Success activating firmware action:%d slot:%d",
			           action, slot);
			if (action == 6 || action == 7)
				print_info(" bpid:%d", bpid);
			print_info(", but firmware requires %s reset\n",
			           nvme_fw_status_reset_type(val));
			return;
		default:
			break;
		}
	}

	nvme_show_err(err, "fw-commit");
}

static int fw_commit(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc = "Verify downloaded firmware image and "
		"commit to specific firmware slot. Device is not automatically "
		"reset following firmware activation. A reset may be issued "
		"with an 'echo 1 > /sys/class/nvme/nvmeX/reset_controller'. "
		"Ensure nvmeX is the device you just activated before reset.";
	const char *slot = "[0-7]: firmware slot for commit action";
	const char *action = "[0-7]: commit action: 0 = replace, "
				"1 = replace and activate, 2 = set active, "
				"3 = replace and activate immediate, "
				"6 = replace boot partition, "
				"7 = activate boot partition";
	const char *bpid = "[0,1]: boot partition identifier, if applicable (default: 0)";

	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	__cleanup_nvme_transport_handle struct libnvme_transport_handle *hdl = NULL;
	struct libnvme_passthru_cmd cmd;
	int err;
	nvme_print_flags_t flags;
	bool mud_supported;

	struct config {
		bool	ish;
		__u8	slot;
		__u8	action;
		__u8	bpid;
	};

	struct config cfg = {
		.ish	= false,
		.slot	= 0,
		.action	= 0,
		.bpid	= 0,
	};

	OPT_VALS(ca) = {
		VAL_BYTE("replace", NVME_FW_COMMIT_CA_REPLACE),
		VAL_BYTE("replace-and-activate",
			 NVME_FW_COMMIT_CA_REPLACE_AND_ACTIVATE),
		VAL_BYTE("set-active", NVME_FW_COMMIT_CA_SET_ACTIVE),
		VAL_BYTE("replace-and-activate-immediate",
			 NVME_FW_COMMIT_CA_REPLACE_AND_ACTIVATE_IMMEDIATE),
		VAL_BYTE("replace-boot-partition",
			 NVME_FW_COMMIT_CA_REPLACE_BOOT_PARTITION),
		VAL_BYTE("activate-boot-partition",
			 NVME_FW_COMMIT_CA_ACTIVATE_BOOT_PARTITION),
		VAL_END()
	};

	NVME_ARGS(opts,
		  OPT_FLAG("ish",    'I', &cfg.ish,    ish),
		  OPT_BYTE("slot",   's', &cfg.slot,   slot),
		  OPT_BYTE("action", 'a', &cfg.action, action, ca),
		  OPT_BYTE("bpid",   'b', &cfg.bpid,   bpid));

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	err = validate_output_format(nvme_args.output_format, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	if (cfg.slot > 7) {
		nvme_show_error("invalid slot:%d", cfg.slot);
		return -EINVAL;
	}

	switch (cfg.action) {
	case NVME_FW_COMMIT_CA_REPLACE:
	case NVME_FW_COMMIT_CA_REPLACE_AND_ACTIVATE:
	case NVME_FW_COMMIT_CA_SET_ACTIVE:
	case NVME_FW_COMMIT_CA_REPLACE_AND_ACTIVATE_IMMEDIATE:
	case NVME_FW_COMMIT_CA_REPLACE_BOOT_PARTITION:
	case NVME_FW_COMMIT_CA_ACTIVATE_BOOT_PARTITION:
		break;
	default:
		nvme_show_error("invalid action:%d", cfg.action);
		return -EINVAL;
	}

	if (cfg.bpid > 1) {
		nvme_show_error("invalid boot partition id:%d", cfg.bpid);
		return -EINVAL;
	}

	mud_supported = fw_commit_support_mud(hdl);

	nvme_init_fw_commit(&cmd, cfg.slot, cfg.action, cfg.bpid);
	if (cfg.ish) {
		if (libnvme_transport_handle_is_mi(hdl))
			nvme_init_mi_cmd_flags(&cmd, ish);
		else
			nvme_show_error("ISH is supported only for NVMe-MI");
	}
	err = libnvme_exec_admin_passthru(hdl, &cmd);
	if (err) {
		fw_commit_err(err, cfg.action, cfg.slot, cfg.bpid);
		return err;
	}

	if (cfg.action == 6 || cfg.action == 7)
		nvme_show_verbose_result("Success committing firmware action:%d slot:%d bpid:%d",
					 cfg.action, cfg.slot, cfg.bpid);
	else
		nvme_show_verbose_result("Success committing firmware action:%d slot:%d",
					 cfg.action, cfg.slot);
	fw_commit_print_mud(mud_supported, cmd.result);

	return err;
}

static int subsystem_reset(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc = "Resets the NVMe subsystem";

	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	__cleanup_nvme_transport_handle struct libnvme_transport_handle *hdl = NULL;
	int err;

	NVME_ARGS(opts);

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	if (!libnvme_transport_handle_is_ctrl(hdl)) {
		nvme_show_error(only_ctrl_dev);
		return -EINVAL;
	}

	err = libnvme_reset_subsystem(hdl);
	if (err < 0) {
		if (errno == ENOTTY)
			nvme_show_error("Subsystem-reset: NVM Subsystem Reset not supported.");
		else
			nvme_show_error("Subsystem-reset: %s", libnvme_strerror(-err));
	} else {
		nvme_show_verbose_info("resetting subsystem through %s",
				       libnvme_transport_handle_get_name(hdl));
	}

	return err;
}

static int reset(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc = "Resets the NVMe controller\n";

	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	__cleanup_nvme_transport_handle struct libnvme_transport_handle *hdl = NULL;
	int err;

	NVME_ARGS(opts);

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	if (!libnvme_transport_handle_is_ctrl(hdl)) {
		nvme_show_error(only_ctrl_dev);
		return -EINVAL;
	}

	err = libnvme_reset_ctrl(hdl);
	if (err < 0)
		nvme_show_error("Reset: %s", libnvme_strerror(-err));
	else
		nvme_show_verbose_info("resetting controller %s",
				       libnvme_transport_handle_get_name(hdl));

	return err;
}

static int ns_rescan(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc = "Rescans the NVMe namespaces\n";

	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	__cleanup_nvme_transport_handle struct libnvme_transport_handle *hdl = NULL;
	int err;
	nvme_print_flags_t flags;

	NVME_ARGS(opts);

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	if (!libnvme_transport_handle_is_ctrl(hdl)) {
		nvme_show_error(only_ctrl_dev);
		return -EINVAL;
	}

	err = validate_output_format(nvme_args.output_format, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	err = libnvme_rescan_ns(hdl);
	if (err < 0)
		nvme_show_error("Namespace Rescan: %s\n", libnvme_strerror(-err));
	else
		nvme_show_verbose_info("rescanning namespaces through %s",
				       libnvme_transport_handle_get_name(hdl));

	return err;
}

static int wait_sanitize(struct libnvme_transport_handle *hdl)
{
	__cleanup_libnvme_free struct nvme_sanitize_log_page *log = NULL;
	static const char spin[] = {'-', '\\', '|', '/' };
	struct libnvme_passthru_cmd cmd;
	__u64 i = 0, cnt = 0, wthr = 0;
	__u32 p = 0;
	int err;

	log = libnvme_alloc(sizeof(*log));
	if (!log)
		return -ENOMEM;

	nvme_init_get_log_sanitize(&cmd, log);
	err = libnvme_get_log(hdl, &cmd, false, sizeof(*log));
	if (err) {
		nvme_show_err(err, "sanitize status log");
		return err;
	}

	switch (NVME_GET(log->scdw10, SANITIZE_CDW10_SANACT)) {
	case NVME_SANITIZE_SANACT_EXIT_FAILURE:
		break;
	case NVME_SANITIZE_SANACT_START_BLOCK_ERASE:
		if (NVME_GET(log->scdw10, SANITIZE_CDW10_NDAS))
			wthr = le32_to_cpu(log->etbend);
		else
			wthr = le32_to_cpu(log->etbe);
		break;
	case NVME_SANITIZE_SANACT_START_OVERWRITE:
		if (NVME_GET(log->scdw10, SANITIZE_CDW10_NDAS))
			wthr = le32_to_cpu(log->etond);
		else
			wthr = le32_to_cpu(log->eto);
		break;
	case NVME_SANITIZE_SANACT_START_CRYPTO_ERASE:
		if (NVME_GET(log->scdw10, SANITIZE_CDW10_NDAS))
			wthr = le32_to_cpu(log->etcend);
		else
			wthr = le32_to_cpu(log->etce);
		break;
	case NVME_SANITIZE_SANACT_EXIT_MEDIA_VERIF:
	default:
		break;
	}
	if (wthr != 0xffffffff && NVME_GET(log->scdw10, SANITIZE_CDW10_EMVS))
		wthr += le32_to_cpu(log->etpvds);

	nvme_show_result("Waiting for sanitize completion...");
	while (true) {
		if (nvme_is_output_format_normal()) {
			print_info("\r[%.*s%c%.*s] %3d%%", p * 100 / 0xffff / 2, dash,
			           spin[i % 4], 49 - p * 100 / 0xffff / 2, space,
			           p * 100 / 0xffff);
			fflush(stdout);
		}
		err = nvme_sleep(1);
		if (err)
			return err;

		nvme_init_get_log_sanitize(&cmd, log);
		err = libnvme_get_log(hdl, &cmd, false, sizeof(*log));
		if (err) {
			if (nvme_is_output_format_normal())
				print_info("\n");
			nvme_show_err(err, "sanitize status log");
			return err;
		}

		if (++cnt > wthr) {
			nvme_show_error(
			    "no progress for %"PRIu64" seconds, stop waiting",
			    wthr);
			return -EIO;
		}

		if (le16_to_cpu(log->sprog) == 0xffff) {
			if (nvme_is_output_format_normal())
				print_info("\r[%.*s] %3d%%\n", 50, dash, 100);
			break;
		}

		if (le16_to_cpu(log->sprog) < p) {
			if (nvme_is_output_format_normal())
				print_info("\n");
			nvme_show_error("progress broken");
			return -EIO;
		} else if (le16_to_cpu(log->sprog) != p) {
			p = le16_to_cpu(log->sprog);
			cnt = 0;
		}

		i++;
	}

	return 0;
}

static int check_sanitize(struct libnvme_transport_handle *hdl, bool *sanitized)
{
	__cleanup_libnvme_free struct nvme_sanitize_log_page *log = NULL;
	struct libnvme_passthru_cmd cmd;
	int err;

	log = libnvme_alloc(sizeof(*log));
	if (!log)
		return -ENOMEM;

	nvme_init_get_log_sanitize(&cmd, log);
	err = libnvme_get_log(hdl, &cmd, false, sizeof(*log));
	if (err) {
		nvme_show_err(err, "sanitize status log");
		return err;
	}

	switch (NVME_GET(le16_to_cpu(log->sstat), SANITIZE_SSTAT_STATUS)) {
	case NVME_SANITIZE_SSTAT_STATUS_NEVER_SANITIZED:
		break;
	case NVME_SANITIZE_SSTAT_STATUS_COMPLETE_SUCCESS:
		*sanitized = true;
		break;
	case NVME_SANITIZE_SSTAT_STATUS_IN_PROGRESS:
	case NVME_SANITIZE_SSTAT_STATUS_COMPLETED_FAILED:
	case NVME_SANITIZE_SSTAT_STATUS_ND_COMPLETE_SUCCESS:
	default:
		break;
	}

	return 0;
}

struct nvme_id_ctrl *identify_ctrl(struct libnvme_transport_handle *hdl)
{
	struct nvme_id_ctrl *ctrl = libnvme_alloc(sizeof(*ctrl));
	struct libnvme_passthru_cmd cmd;
	int err = 0;

	if (!ctrl) {
		errno = ENOMEM;
		return NULL;
	}

	nvme_init_identify_ctrl(&cmd, ctrl);
	err = libnvme_exec_admin_passthru(hdl, &cmd);
	if (err) {
		nvme_show_error("identify-ctrl: %s", libnvme_strerror(err));
		libnvme_free(ctrl);
		return NULL;
	}

	return ctrl;
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
	const char *wait = "Wait for the sanitize to finish";
	const char *repeat = "Repeat for the multi cycle sanitization";

	__cleanup_nvme_transport_handle struct libnvme_transport_handle *hdl = NULL;
	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	__cleanup_libnvme_free struct nvme_id_ctrl *ctrl = NULL;
	struct libnvme_passthru_cmd cmd;
	nvme_print_flags_t flags;
	int err;
	bool sanitized;

	struct config {
		bool	ish;
		bool	no_dealloc;
		bool	oipbp;
		__u8	owpass;
		bool	ause;
		__u8	sanact;
		__u32	ovrpat;
		bool	emvs;
		bool	wait;
		__u32	repeat;
	};

	struct config cfg = {
		.ish		= false,
		.no_dealloc	= false,
		.oipbp		= false,
		.owpass		= 0,
		.ause		= false,
		.sanact		= 0,
		.ovrpat		= 0,
		.emvs		= false,
		.repeat		= 1,
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
		  OPT_FLAG("ish",        'I', &cfg.ish,        ish),
		  OPT_FLAG("no-dealloc", 'd', &cfg.no_dealloc, no_dealloc_desc),
		  OPT_FLAG("oipbp",      'i', &cfg.oipbp,      oipbp_desc),
		  OPT_BYTE("owpass",     'n', &cfg.owpass,     owpass_desc),
		  OPT_FLAG("ause",       'u', &cfg.ause,       ause_desc),
		  OPT_BYTE("sanact",     'a', &cfg.sanact,     sanact_desc, sanact),
		  OPT_UINT("ovrpat",     'p', &cfg.ovrpat,     ovrpat_desc),
		  OPT_FLAG("emvs",       'e', &cfg.emvs,       emvs_desc),
		  OPT_FLAG("wait",       'w', &cfg.wait,       wait),
		  OPT_UINT("repeat",     'r', &cfg.repeat,     repeat));

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	err = validate_output_format(nvme_args.output_format, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	ctrl = identify_ctrl(hdl);
	if (!ctrl)
		return -errno;

	switch (cfg.sanact) {
	case NVME_SANITIZE_SANACT_EXIT_FAILURE:
		break;
	case NVME_SANITIZE_SANACT_START_BLOCK_ERASE:
		if (!NVME_CTRL_SANICAP_BES(le32_to_cpu(ctrl->sanicap))) {
			nvme_show_error("block erase action unsupported");
			return -EINVAL;
		}
		break;
	case NVME_SANITIZE_SANACT_START_OVERWRITE:
		if (!NVME_CTRL_SANICAP_OWS(le32_to_cpu(ctrl->sanicap))) {
			nvme_show_error("overwrite action unsupported");
			return -EINVAL;
		}
		break;
	case NVME_SANITIZE_SANACT_START_CRYPTO_ERASE:
		if (!NVME_CTRL_SANICAP_CES(le32_to_cpu(ctrl->sanicap))) {
			nvme_show_error("crypto erase action unsupported");
			return -EINVAL;
		}
		break;
	case NVME_SANITIZE_SANACT_EXIT_MEDIA_VERIF:
		break;
	default:
		nvme_show_error("Invalid Sanitize Action");
		return -EINVAL;
	}

	if (cfg.emvs && !NVME_CTRL_SANICAP_VERS(le32_to_cpu(ctrl->sanicap))) {
		nvme_show_error("media verification unsupported");
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
	if (cfg.ish) {
		if (libnvme_transport_handle_is_mi(hdl))
			nvme_init_mi_cmd_flags(&cmd, ish);
		else
			nvme_show_error("ISH is supported only for NVMe-MI");
	}

	do {
		err = libnvme_exec_admin_passthru(hdl, &cmd);
		if (err) {
			nvme_show_err(err, "sanitize");
			return err;
		}

		if (cfg.wait)
			err = wait_sanitize(hdl);

		sanitized = false;
		if (!err && --cfg.repeat)
			err = check_sanitize(hdl, &sanitized);
	} while (!err && sanitized);

	return err;
}

static int sanitize_ns_cmd(int argc, char **argv, struct command *acmd,
			   struct plugin *plugin)
{
	const char *desc = "Send a sanitize namespace command.";
	const char *emvs_desc = "Enter media verification state.";
	const char *ause_desc = "Allow unrestricted sanitize exit.";
	const char *sanact_desc = "Sanitize action: 1 = Exit failure mode,\n"
		"4 = Start a crypto erase namespace sanitize operation,\n"
		"5 = Exit media verification state";

	__cleanup_nvme_transport_handle struct libnvme_transport_handle *hdl =
		NULL;

	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	struct libnvme_passthru_cmd cmd;
	nvme_print_flags_t flags;
	int err;

	struct config {
		bool	ish;
		bool	ause;
		__u8	sanact;
		bool	emvs;
	};

	struct config cfg = {
		.ish		= false,
		.ause		= false,
		.sanact		= 0,
		.emvs		= false,
	};

	OPT_VALS(sanact) = {
		VAL_BYTE("exit-failure", NVME_SANITIZE_SANACT_EXIT_FAILURE),
		VAL_BYTE("start-crypto-erase",
			 NVME_SANITIZE_SANACT_START_CRYPTO_ERASE),
		VAL_BYTE("exit-media-verification",
			 NVME_SANITIZE_SANACT_EXIT_MEDIA_VERIF),
		VAL_END()
	};

	NVME_ARGS(opts,
		  OPT_FLAG("ish",    'I', &cfg.ish,    ish),
		  OPT_FLAG("ause",   'u', &cfg.ause,   ause_desc),
		  OPT_BYTE("sanact", 'a', &cfg.sanact, sanact_desc, sanact),
		  OPT_FLAG("emvs",   'e', &cfg.emvs,   emvs_desc));

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	err = validate_output_format(nvme_args.output_format, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	switch (cfg.sanact) {
	case NVME_SANITIZE_SANACT_EXIT_FAILURE:
	case NVME_SANITIZE_SANACT_START_CRYPTO_ERASE:
	case NVME_SANITIZE_SANACT_EXIT_MEDIA_VERIF:
		break;
	default:
		nvme_show_error("Invalid Sanitize Action");
		return -EINVAL;
	}

	if (cfg.ause) {
		if (cfg.sanact == NVME_SANITIZE_SANACT_EXIT_FAILURE) {
			nvme_show_error("SANACT is Exit Failure Mode");
			return -EINVAL;
		} else if (cfg.sanact ==
			   NVME_SANITIZE_SANACT_EXIT_MEDIA_VERIF) {
			nvme_show_error(
			    "SANACT is Exit Media Verification State");
			return -EINVAL;
		}
	}

	nvme_init_sanitize_ns(&cmd, cfg.sanact, cfg.ause, cfg.emvs);
	if (cfg.ish) {
		if (libnvme_transport_handle_is_mi(hdl))
			nvme_init_mi_cmd_flags(&cmd, ish);
		else
			nvme_show_error("ISH is supported only for NVMe-MI");
	}
	err = libnvme_exec_admin_passthru(hdl, &cmd);
	if (err) {
		nvme_show_admin_cmd_err("sanitize ns", cmd.opcode, err);
		return err;
	}

	return err;
}

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

static void show_relatives(const char *name, nvme_print_flags_t flags)
{
	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	int err;

	err = nvme_create_global_ctx(&ctx);
	if (err)
		return;

	err = libnvme_scan_topology(ctx, NULL, NULL);
	if (err < 0) {
		handle_scan_topology_error(err);
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

	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	__cleanup_nvme_transport_handle struct libnvme_transport_handle *hdl = NULL;
	__cleanup_libnvme_free struct nvme_id_ctrl *ctrl = NULL;
	__cleanup_libnvme_free struct nvme_id_ns *ns = NULL;
	nvme_print_flags_t flags = NORMAL;
	struct libnvme_passthru_cmd cmd;
	__u8 prev_lbaf = 0;
	int block_size;
	int err, i;

	struct config {
		bool	ish;
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
		.ish		= false,
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

	NVME_ARGS(opts,
		  OPT_FLAG("ish",         'I', &cfg.ish,          ish),
		  OPT_UINT("namespace-id", 'n', &cfg.namespace_id, namespace_id_desired),
		  OPT_BYTE("lbaf",         'l', &cfg.lbaf,         lbaf),
		  OPT_BYTE("ses",          's', &cfg.ses,          ses),
		  OPT_BYTE("pi",           'i', &cfg.pi,           pi),
		  OPT_BYTE("pil",          'p', &cfg.pil,          pil),
		  OPT_BYTE("ms",           'm', &cfg.mset,         mset),
		  OPT_FLAG("reset",        'r', &cfg.reset,        reset),
		  OPT_FLAG("force",          0, &cfg.force,        force),
		  OPT_SUFFIX("block-size", 'b', &cfg.bs,           bs));

	/* set default timeout for format to 60 seconds */
	nvme_args.timeout = 600000;

	err = parse_args(argc, argv, desc, opts);
	if (err)
		return err;

	err = open_exclusive(&ctx, &hdl, argc, argv, cfg.force, opts);
	if (err) {
		if (-err == EBUSY) {
			nvme_show_error("Failed to open %s.", basename(argv[optind]));
			nvme_show_error("Namespace is currently busy.");
			if (!cfg.force)
				nvme_show_error("Use the force [--force] option to ignore that.");
		} else {
			argconfig_print_help(desc, opts);
		}
		return err;
	}

	err = validate_output_format(nvme_args.output_format, &flags);
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

	ctrl = libnvme_alloc(sizeof(*ctrl));
	if (!ctrl)
		return -ENOMEM;

	nvme_init_identify_ctrl(&cmd, ctrl);
	err = libnvme_exec_admin_passthru(hdl, &cmd);
	if (err) {
		nvme_show_error("identify-ctrl: %s", libnvme_strerror(err));
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
		err = libnvme_get_nsid(hdl, &cfg.namespace_id);
		if (err < 0) {
			nvme_show_error("get-namespace-id: %s", libnvme_strerror(-err));
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
		ns = libnvme_alloc(sizeof(*ns));
		if (!ns)
			return -ENOMEM;

		nvme_init_identify_ns(&cmd, cfg.namespace_id, ns);
		err = libnvme_exec_admin_passthru(hdl, &cmd);
		if (err) {
			if (err > 0)
				nvme_show_error("identify failed");
			nvme_show_err(err, "identify-namespace");
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
				nvme_show_error(
				    "LBAF corresponding to given block size %"PRIu64" not found",
				    (uint64_t)cfg.bs);
				nvme_show_error(
					"Please correct block size, or specify LBAF directly");
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
		nvme_show_error("You are about to format %s, namespace %#x%s.",
			libnvme_transport_handle_get_name(hdl), cfg.namespace_id,
			cfg.namespace_id == NVME_NSID_ALL ? "(ALL namespaces)" : "");
		show_relatives(libnvme_transport_handle_get_name(hdl), flags);
		nvme_show_error(
			"WARNING: Format may irrevocably delete this device's data.\n"
			"You have 10 seconds to press Ctrl-C to cancel this operation.\n\n"
			"Use the force [--force] option to suppress this warning.");
		shr_sigint_received = false;
		sleep(10);
		if (shr_sigint_received)
			return -EINTR;
		nvme_show_verbose_info("Sending format operation ...");
	}

	nvme_init_format_nvm(&cmd, cfg.namespace_id, cfg.lbaf, cfg.mset,
		cfg.pi, cfg.pil, cfg.ses);
	if (cfg.ish) {
		if (libnvme_transport_handle_is_mi(hdl))
			nvme_init_mi_cmd_flags(&cmd, ish);
		else
			nvme_show_error("ISH is supported only for NVMe-MI");
	}
	err = libnvme_exec_admin_passthru(hdl, &cmd);
	if (err) {
		nvme_show_err(err, "format");
		return err;
	}

	nvme_show_verbose_result("Success formatting namespace:%x", cfg.namespace_id);
	if (libnvme_transport_handle_is_direct(hdl) && cfg.lbaf != prev_lbaf) {
		if (libnvme_transport_handle_is_ctrl(hdl)) {
			if (libnvme_rescan_ns(hdl) < 0) {
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
			err = libnvme_update_block_size(hdl, block_size);
			if (err < 0) {
				nvme_show_error(
				    "failed to set block size to %d",
				    block_size);
				return err;
			}
		}
	}
	if (libnvme_transport_handle_is_direct(hdl) && cfg.reset &&
	    libnvme_transport_handle_is_ctrl(hdl))
		libnvme_reset_ctrl(hdl);

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

	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	__cleanup_nvme_transport_handle struct libnvme_transport_handle *hdl = NULL;
	__cleanup_libnvme_free void *buf = NULL;
	__cleanup_fd int ffd = STDIN_FILENO;
	int err;
	__u64 result;
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

	err = validate_output_format(nvme_args.output_format, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	if (!argconfig_parse_seen(opts, "namespace-id")) {
		err = libnvme_get_nsid(hdl, &cfg.nsid);
		if (err < 0) {
			if (errno != ENOTTY) {
				nvme_show_error("get-namespace-id: %s", libnvme_strerror(-err));
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
		libnvme_get_feature_length(cfg.fid, cfg.value,
					 NVME_DATA_TFR_HOST_TO_CTRL,
					 &cfg.data_len);

	if (cfg.data_len) {
		buf = libnvme_alloc(cfg.data_len);
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
				ffd = shr_open_rawdata(cfg.file, O_RDONLY);

			if (ffd < 0) {
				nvme_show_error("Failed to open file %s: %s",
						cfg.file, libnvme_strerror(errno));
				return -EINVAL;
			}

			err = read(ffd, buf, cfg.data_len);
			if (err < 0) {
				nvme_show_error("failed to read data buffer from input file: %s",
						libnvme_strerror(errno));
				return -errno;
			}
		}
	}

	err = nvme_set_features(hdl, cfg.nsid, cfg.fid, cfg.sv, cfg.value, cfg.cdw12,
			0, cfg.uidx, 0, buf, cfg.data_len, &result);
	if (err) {
		nvme_show_admin_cmd_err("set-feature", nvme_admin_set_features,
					err);
		return err;
	}

	nvme_show_result("set-feature:%#0*x (%s), value:%#0*" PRIx64
	                 ", cdw12:%#0*x, save:%#x", cfg.fid ? 4 : 2, cfg.fid,
	                 nvme_feature_to_string(cfg.fid), cfg.value ? 10 : 8,
	                 (uint64_t)cfg.value, cfg.cdw12 ? 10 : 8, cfg.cdw12, cfg.sv);
	if (cfg.fid == NVME_FEAT_FID_LBA_STS_INTERVAL)
		nvme_show_lba_status_info(result);
	if (buf) {
		if (cfg.fid == NVME_FEAT_FID_LBA_RANGE)
			nvme_show_lba_range((struct nvme_lba_range_type *)buf,
					    result, 0);
		else
			d(buf, cfg.data_len, 16, 1);
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

	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	__cleanup_nvme_transport_handle struct libnvme_transport_handle *hdl = NULL;
	struct libnvme_passthru_cmd cmd;
	__cleanup_libnvme_free void *sec_buf = NULL;
	__cleanup_fd int sec_fd = -1;
	unsigned int sec_size;
	int err;
	nvme_print_flags_t flags;

	struct config {
		bool	ish;
		__u32	namespace_id;
		char	*file;
		__u8	nssf;
		__u8	secp;
		__u16	spsp;
		__u32	tl;
	};

	struct config cfg = {
		.ish		= false,
		.namespace_id	= 0,
		.file		= "",
		.nssf		= 0,
		.secp		= 0,
		.spsp		= 0,
		.tl		= 0,
	};

	NVME_ARGS(opts,
		  OPT_FLAG("ish",          'I', &cfg.ish,          ish),
		  OPT_UINT("namespace-id", 'n', &cfg.namespace_id, namespace_desired),
		  OPT_FILE("file",         'f', &cfg.file,         file),
		  OPT_BYTE("nssf",         'N', &cfg.nssf,         nssf),
		  OPT_BYTE("secp",         'p', &cfg.secp,         secp),
		  OPT_SHRT("spsp",         's', &cfg.spsp,         spsp),
		  OPT_UINT("tl",           't', &cfg.tl,           tl));

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	err = validate_output_format(nvme_args.output_format, &flags);
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
		sec_fd = shr_open_rawdata(cfg.file, O_RDONLY);
		if (sec_fd < 0) {
			nvme_show_error("Failed to open %s: %s", cfg.file, libnvme_strerror(errno));
			return -EINVAL;
		}

		err = fstat(sec_fd, &sb);
		if (err < 0) {
			nvme_show_perror("fstat");
			return err;
		}

		sec_size = cfg.tl > sb.st_size ? cfg.tl : sb.st_size;
	}

	sec_buf = libnvme_alloc(cfg.tl);
	if (!sec_buf)
		return -ENOMEM;

	err = read(sec_fd, sec_buf, sec_size);
	if (err < 0) {
		nvme_show_error("Failed to read data from security file %s with %s", cfg.file,
				libnvme_strerror(errno));
		return -errno;
	}

	nvme_init_security_send(&cmd, cfg.namespace_id, cfg.nssf, cfg.spsp,
		cfg.secp, cfg.tl, sec_buf, cfg.tl);
	if (cfg.ish) {
		if (libnvme_transport_handle_is_mi(hdl))
			nvme_init_mi_cmd_flags(&cmd, ish);
		else
			nvme_show_error("ISH is supported only for NVMe-MI");
	}
	err = libnvme_exec_admin_passthru(hdl, &cmd);
	if (err) {
		nvme_show_err(err, "security-send");
		return err;
	}

	nvme_show_verbose_result("NVME Security Send Command Success");

	return err;
}

static int dir_send(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc = "Set directive parameters of the specified directive type.";
	const char *endir = "directive enable";
	const char *ttype = "target directive type to be enabled/disabled";
	const char *input = "write/send file (default stdin)";

	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	__cleanup_nvme_transport_handle struct libnvme_transport_handle *hdl = NULL;
	__cleanup_libnvme_free void *buf = NULL;
	struct libnvme_passthru_cmd cmd;
	__u32 dw12 = 0;
	__cleanup_fd int ffd = STDIN_FILENO;
	int err;

	struct config {
		__u32	namespace_id;
		__u32	data_len;
		__u8	dtype;
		__u8	ttype;
		__u16	dspec;
		__u8	doper;
		__u16	endir;
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
		buf = libnvme_alloc(cfg.data_len);
		if (!buf)
			return -ENOMEM;
	}

	if (buf) {
		if (strlen(cfg.file)) {
			ffd = shr_open_rawdata(cfg.file, O_RDONLY);
			if (ffd <= 0) {
				nvme_show_error("Failed to open file %s: %s",
						cfg.file, libnvme_strerror(errno));
				return -EINVAL;
			}
		}
		err = read(ffd, (void *)buf, cfg.data_len);
		if (err < 0) {
			nvme_show_error(
			    "failed to read data buffer from input file %s",
			    libnvme_strerror(errno));
			return -errno;
		}
	}

	nvme_init_directive_send(&cmd, cfg.namespace_id, cfg.doper, cfg.dtype,
		cfg.dspec, buf, cfg.data_len);
	cmd.cdw12 = dw12;
	err = libnvme_exec_admin_passthru(hdl, &cmd);
	if (err) {
		nvme_show_err(err, "dir-send");
		return err;
	}

	nvme_show_result(
	    "%s: type %#x, operation %#x, spec_val %#x, nsid %#x, result %#"
	    PRIx64, __func__, cfg.dtype, cfg.doper, cfg.dspec,
	    cfg.namespace_id, (uint64_t)cmd.result);

	if (buf) {
		if (!cfg.raw_binary)
			d(buf, cfg.data_len, 16, 1);
		else
			d_raw(buf, cfg.data_len);
	}

	return err;
}

static int write_uncor(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc =
	    "The Write Uncorrectable command is used to set a range of logical blocks to invalid.";

	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	__cleanup_nvme_transport_handle struct libnvme_transport_handle *hdl = NULL;
	struct libnvme_passthru_cmd cmd;
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
		err = libnvme_get_nsid(hdl, &cfg.namespace_id);
		if (err < 0) {
			nvme_show_error("get-namespace-id: %s", libnvme_strerror(-err));
			return err;
		}
	}

	if (cfg.dtype > 0xf) {
		nvme_show_error("Invalid directive type, %x",	cfg.dtype);
		return -EINVAL;
	}

	nvme_init_write_uncorrectable(&cmd, cfg.namespace_id, cfg.start_block,
		cfg.block_count, cfg.dtype << 4, cfg.dspec);
	err = libnvme_exec_io_passthru(hdl, &cmd);
	if (err) {
		nvme_show_err(err, "write uncorrectable");
		return err;
	}

	nvme_show_verbose_result("NVME Write Uncorrectable Success");

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

static int check_lbstm_byte_granularity(__u64 lbstm, __u8 sts)
{
	__u8 nr_full_bytes = sts / 8;
	__u8 nr_rem_bits = sts % 8;
	__u8 rem_mask, byte;
	__u8 i;

	if (sts > 64)
		return -EINVAL;

	if (sts < 64)
		lbstm &= (1ULL << sts) - 1;

	for (i = 0; i < nr_full_bytes; i++) {
		byte = (lbstm >> (i * 8)) & 0xff;
		if (byte != 0x00 && byte != 0xff)
			return -EINVAL;
	}

	if (nr_rem_bits) {
		rem_mask = (1u << nr_rem_bits) - 1;
		byte = (lbstm >> (nr_full_bytes * 8)) & rem_mask;
		if (byte != 0x00 && byte != rem_mask)
			return -EINVAL;
	}

	return 0;
}

static int check_lbstm_masking_not_supported(__u64 lbstm, __u8 sts)
{
	__u64 stm_mask;

	if (sts > 64)
		return -EINVAL;

	stm_mask = (sts < 64) ? ((1ULL << sts) - 1) : ~0ULL;
	if ((lbstm & stm_mask) != stm_mask)
		return -EINVAL;

	return 0;
}

static int get_pif_sts_via_qpif(struct nvme_nvm_id_ns *nvm_ns, __u32 elbaf,
		__u8 sts, __u8 *pif)
{
	__u64 lbstm;
	int err = 0;

	*pif = NVME_NVM_ELBAF_QPIF(elbaf);

	lbstm = le64_to_cpu(nvm_ns->lbstm);
	switch (NVME_NVM_PIFA_STMLA(nvm_ns->pifa)) {
	case NVME_NVM_PIFA_BIT_GRANULARITY_MASKING:
		break;
	case NVME_NVM_PIFA_BYTE_GRANULARITY_MASKING:
		err = check_lbstm_byte_granularity(lbstm, sts);
		break;
	case NVME_NVM_PIFA_MASKING_NOT_SUPPORTED:
		err = check_lbstm_masking_not_supported(lbstm, sts);
		break;
	default:
		err = -EINVAL;
		break;
	}

	if (err)
		nvme_show_error("Logical Block Storage Tag Mask is inconsistent with the Storage Tag Masking Level Attribute");

	return err;
}

static int get_pif_sts(struct nvme_id_ns *ns, struct nvme_nvm_id_ns *nvm_ns,
		__u8 *pif, __u8 *sts)
{
	__u8 lba_index;
	__u32 elbaf;

	nvme_id_ns_flbas_to_lbaf_inuse(ns->flbas, &lba_index);
	elbaf = le32_to_cpu(nvm_ns->elbaf[lba_index]);
	*sts = NVME_NVM_ELBAF_STS(elbaf);
	*pif = NVME_NVM_ELBAF_PIF(elbaf);

	if (*pif == NVME_NVM_PIF_QTYPE && NVME_NVM_PIC_QPIFS(nvm_ns->pic))
		return get_pif_sts_via_qpif(nvm_ns, elbaf, *sts, pif);

	return 0;
}

static int get_pi_info(struct libnvme_transport_handle *hdl,
		__u32 nsid, __u8 prinfo, __u64 ilbrt, __u64 lbst,
		unsigned int *logical_block_size, __u16 *metadata_size)
{
	__cleanup_libnvme_free struct nvme_nvm_id_ns *nvm_ns = NULL;
	__cleanup_libnvme_free struct nvme_id_ns *ns = NULL;
	struct libnvme_passthru_cmd cmd;
	__u8 sts = 0, pif = 0;
	unsigned int lbs = 0;
	__u8 lba_index;
	int pi_size;
	__u16 ms;
	int err;

	ns = libnvme_alloc(sizeof(*ns));
	if (!ns)
		return -ENOMEM;

	nvme_init_identify_ns(&cmd, nsid, ns);
	err = libnvme_exec_admin_passthru(hdl, &cmd);
	if (err) {
		nvme_show_err(err, "identify namespace");
		return err;
	}

	nvme_id_ns_flbas_to_lbaf_inuse(ns->flbas, &lba_index);
	lbs = 1 << ns->lbaf[lba_index].ds;
	ms = le16_to_cpu(ns->lbaf[lba_index].ms);

	nvm_ns = libnvme_alloc(sizeof(*nvm_ns));
	if (!nvm_ns)
		return -ENOMEM;

	nvme_init_identify_csi_ns(&cmd, nsid, NVME_CSI_NVM, 0, nvm_ns);
	err = libnvme_exec_admin_passthru(hdl, &cmd);
	if (!err) {
		err = get_pif_sts(ns, nvm_ns, &pif, &sts);
		if (err)
			return err;
	} else if (!nvme_status_equals(err, NVME_STATUS_TYPE_NVME,
				       NVME_SC_INVALID_FIELD)) {
		/*
		 * Ignore the invalid field error and skip get_pif_sts().
		 * Keep the I/O commands behavior same as before.
		 * Since the error returned by drives unsupported.
		 */
		return NVME_SC_INVALID_FIELD;
	}

	pi_size = (pif == NVME_NVM_PIF_16B_GUARD) ? 8 : 16;
	if (NVME_FLBAS_META_EXT(ns->flbas)) {
		/*
		 * No meta data is transferred for PRACT=1 and MD=PI size:
		 *   5.2.2.1 Protection Information and Write Commands
		 *   5.2.2.2 Protection Information and Read Commands
		 */
		if (!((prinfo & 0x8) != 0 && ms == pi_size))
			lbs += ms;
	}

	if (invalid_tags(lbst, ilbrt, sts, pif))
		return -EINVAL;

	*logical_block_size = lbs;
	*metadata_size = ms;

	return 0;
}

static int init_pi_tags(struct libnvme_transport_handle *hdl,
	struct libnvme_passthru_cmd *cmd, __u32 nsid, __u64 ilbrt, __u64 lbst,
	__u16 lbat, __u16 lbatm)
{
	__cleanup_libnvme_free struct nvme_nvm_id_ns *nvm_ns = NULL;
	__cleanup_libnvme_free struct nvme_id_ns *ns = NULL;
	struct libnvme_passthru_cmd id_cmd;
	__u8 sts = 0, pif = 0;
	int err = 0;

	ns = libnvme_alloc(sizeof(*ns));
	if (!ns)
		return -ENOMEM;

	nvme_init_identify_ns(&id_cmd, nsid, ns);
	err = libnvme_exec_admin_passthru(hdl, &id_cmd);
	if (err) {
		nvme_show_err(err, "identify namespace");
		return err;
	}

	nvm_ns = libnvme_alloc(sizeof(*nvm_ns));
	if (!nvm_ns)
		return -ENOMEM;

	nvme_init_identify_csi_ns(&id_cmd, nsid, NVME_CSI_NVM, 0, nvm_ns);
	err = libnvme_exec_admin_passthru(hdl, &id_cmd);
	if (!err) {
		err = get_pif_sts(ns, nvm_ns, &pif, &sts);
		if (err)
			return err;
	} else if (!nvme_status_equals(err, NVME_STATUS_TYPE_NVME,
				       NVME_SC_INVALID_FIELD)) {
		/*
		 * Ignore the invalid field error and skip get_pif_sts().
		 * Keep the I/O commands behavior same as before.
		 * Since the error returned by drives unsupported.
		 */
		return NVME_SC_INVALID_FIELD;
	}

	if (invalid_tags(lbst, ilbrt, sts, pif))
		return -EINVAL;

	nvme_init_var_size_tags(cmd, pif, sts, ilbrt, lbst);
	nvme_init_app_tag(cmd, lbat, lbatm);

	return 0;
}

static int write_zeroes(int argc, char **argv,
	struct command *acmd, struct plugin *plugin)
{
	__cleanup_nvme_transport_handle struct libnvme_transport_handle *hdl = NULL;
	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	struct libnvme_passthru_cmd cmd;
	__u16 control = 0;
	int err;

	const char *desc =
	    "The Write Zeroes command is used to set a range of logical blocks to zero.";
	const char *deac =
	    "Set DEAC bit, requesting controller to deallocate specified logical blocks";
	const char *nsz = "Clear all logical blocks to zero in the entire namespace";

	struct config {
		__u32	nsid;
		__u64	start_block;
		__u16	block_count;
		__u8	dtype;
		bool	deac;
		bool	limited_retry;
		bool	force_unit_access;
		__u8	prinfo;
		__u64	ilbrt;
		__u16	lbatm;
		__u16	lbat;
		__u64	lbst;
		bool	stc;
		__u16	dspec;
		bool	nsz;
	};

	struct config cfg = {
		.nsid				= 0,
		.start_block		= 0,
		.block_count		= 0,
		.dtype				= 0,
		.deac				= false,
		.limited_retry		= false,
		.force_unit_access	= false,
		.prinfo				= 0,
		.ilbrt				= 0,
		.lbatm				= 0,
		.lbat				= 0,
		.lbst				= 0,
		.stc				= false,
		.dspec				= 0,
		.nsz				= false,
	};

	NVME_ARGS(opts,
		  OPT_UINT("namespace-id",      'n', &cfg.nsid,				 namespace_desired),
		  OPT_SUFFIX("start-block",     's', &cfg.start_block,       start_block),
		  OPT_SHRT("block-count",       'c', &cfg.block_count,       block_count),
		  OPT_BYTE("dir-type",          'T', &cfg.dtype,             dtype),
		  OPT_FLAG("deac",              'd', &cfg.deac,              deac),
		  OPT_FLAG("limited-retry",     'l', &cfg.limited_retry,     limited_retry),
		  OPT_FLAG("force-unit-access", 'f', &cfg.force_unit_access, force_unit_access),
		  OPT_BYTE("prinfo",            'p', &cfg.prinfo,            prinfo),
		  OPT_SUFFIX("ref-tag",         'r', &cfg.ilbrt,			 ref_tag),
		  OPT_SHRT("app-tag-mask",      'm', &cfg.lbatm,			 app_tag_mask),
		  OPT_SHRT("app-tag",           'a', &cfg.lbat,				 app_tag),
		  OPT_SUFFIX("storage-tag",     'S', &cfg.lbst,				 storage_tag),
		  OPT_FLAG("storage-tag-check", 'C', &cfg.stc,				 storage_tag_check),
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
	if (cfg.stc)
		control |= NVME_IO_STC;
	if (cfg.nsz)
		control |= NVME_IO_NSZ;
	control |= (cfg.dtype << 4);
	if (!cfg.nsid) {
		err = libnvme_get_nsid(hdl, &cfg.nsid);
		if (err < 0) {
			nvme_show_error("get-namespace-id: %s", libnvme_strerror(-err));
			return err;
		}
	}

	nvme_init_write_zeros(&cmd, cfg.nsid, cfg.start_block, cfg.block_count,
			      control, cfg.dspec, 0, 0);

	err = init_pi_tags(hdl, &cmd, cfg.nsid, cfg.ilbrt, cfg.lbst, cfg.lbat,
			   cfg.lbatm);
	if (err && err != NVME_SC_INVALID_FIELD)
		return err;

	err = libnvme_exec_io_passthru(hdl, &cmd);
	if (err) {
		nvme_show_err(err, "write-zeroes");
		return err;
	}

	nvme_show_verbose_result("NVME Write Zeroes Success");

	if (!cfg.nsz || !nvme_args.verbose)
		return err;

	if (cmd.result & 0x1)
		nvme_show_result(
		    "All logical blocks in the entire namespace cleared to zero");
	else
		nvme_show_result("%d logical blocks cleared to zero", cfg.block_count);

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

	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	__cleanup_nvme_transport_handle struct libnvme_transport_handle *hdl = NULL;
	__cleanup_libnvme_free struct nvme_dsm_range *dsm = NULL;
	struct libnvme_passthru_cmd cmd;
	__u32 ctx_attrs[NVME_DSM_MAX_RANGES] = {0,};
	__u32 nlbs[NVME_DSM_MAX_RANGES] = {0,};
	__u64 slbas[NVME_DSM_MAX_RANGES] = {0,};
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

	err = open_fallback_chardev(ctx, cfg.namespace_id, &hdl);
	if (err)
		return err;

	err = validate_output_format(nvme_args.output_format, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	nc = shr_parse_csv_u32(cfg.ctx_attrs, ctx_attrs, ARRAY_SIZE(ctx_attrs));
	nb = shr_parse_csv_u32(cfg.blocks, nlbs, ARRAY_SIZE(nlbs));
	ns = shr_parse_csv_u64(cfg.slbas, slbas, ARRAY_SIZE(slbas));
	if ((nb != ns) ||
	    (argconfig_parse_seen(opts, "ctx-attrs") && nb != nc)) {
		nvme_show_error("No valid range definition provided");
		return -EINVAL;
	}
	if (!nb || nb > NVME_DSM_MAX_RANGES) {
		nvme_show_error("No range definition provided");
		return -EINVAL;
	}

	if (!cfg.namespace_id) {
		err = libnvme_get_nsid(hdl, &cfg.namespace_id);
		if (err < 0) {
			nvme_show_error("get-namespace-id: %s", libnvme_strerror(-err));
			return err;
		}
	}
	if (cfg.cdw11) {
		cfg.ad = NVME_GET(cfg.cdw11, DSM_CDW11_AD);
		cfg.idw = NVME_GET(cfg.cdw11, DSM_CDW11_IDW);
		cfg.idr = NVME_GET(cfg.cdw11, DSM_CDW11_IDR);
	}

	dsm = libnvme_alloc(sizeof(*dsm) * nb);
	if (!dsm)
		return -ENOMEM;

	nvme_init_dsm_range(dsm, ctx_attrs, nlbs, slbas, nb);
	nvme_init_dsm(&cmd, cfg.namespace_id, nb, cfg.idr, cfg.idw, cfg.ad, dsm,
		      sizeof(*dsm) * nb);
	err = libnvme_exec_io_passthru(hdl, &cmd);
	if (err) {
		nvme_show_err(err, "data-set management");
		return err;
	}

	nvme_show_verbose_result("NVMe DSM: success");

	return err;
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

	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	__cleanup_nvme_transport_handle struct libnvme_transport_handle *hdl = NULL;
	__u16 nr, nb, ns, nrts, natms, nats, nids;
	struct libnvme_passthru_cmd cmd;
	__u16 nlbs[256] = { 0 };
	__u64 slbas[256] = { 0 };
	__u32 snsids[256] = { 0 };
	__u16 sopts[256] = { 0 };
	int err;

	union {
		__u32 short_pi[256];
		__u64 long_pi[256];
	} eilbrts;

	__u16 elbatms[256] = { 0 };
	__u16 elbats[256] = { 0 };

	__cleanup_libnvme_free union {
		struct nvme_copy_range_f0 f0[256];
		struct nvme_copy_range_f1 f1[256];
		struct nvme_copy_range_f2 f2[256];
		struct nvme_copy_range_f3 f3[256];
	} *copy = NULL;

	struct config {
		__u32	nsid;
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
		__u64	lbst;
		bool	stc;
	};

	struct config cfg = {
		.nsid		= 0,
		.sdlba		= 0,
		.slbas		= "",
		.nlbs		= "",
		.snsids		= "",
		.sopts		= "",
		.lr			= false,
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
		.lbst		= 0,
		.stc		= false,
	};

	NVME_ARGS(opts,
		  OPT_UINT("namespace-id",           'n', &cfg.nsid,		namespace_id_desired),
		  OPT_SUFFIX("sdlba",                'd', &cfg.sdlba,		d_sdlba),
		  OPT_LIST("slbs",                   's', &cfg.slbas,		d_slbas),
		  OPT_LIST("blocks",                 'b', &cfg.nlbs,		d_nlbs),
		  OPT_LIST("snsids",                 'N', &cfg.snsids,		d_snsids),
		  OPT_LIST("sopts",                  'O', &cfg.sopts,		d_sopts),
		  OPT_FLAG("limited-retry",          'l', &cfg.lr,			d_lr),
		  OPT_FLAG("force-unit-access",      'f', &cfg.fua,			d_fua),
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
		  OPT_BYTE("format",                 'F', &cfg.format,		d_format),
		  OPT_SUFFIX("storage-tag",			 't', &cfg.lbst,		storage_tag),
		  OPT_FLAG("storage-tag-check",		 'c', &cfg.stc,			storage_tag_check));

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	nb = shr_parse_csv_u16(cfg.nlbs, nlbs, ARRAY_SIZE(nlbs));
	ns = shr_parse_csv_u64(cfg.slbas, slbas, ARRAY_SIZE(slbas));
	nids = shr_parse_csv_u32(cfg.snsids, snsids, ARRAY_SIZE(snsids));
	shr_parse_csv_u16(cfg.sopts, sopts, ARRAY_SIZE(sopts));

	switch (cfg.format) {
	case 0:
	case 2:
		nrts = shr_parse_csv_u32(cfg.eilbrts,
			eilbrts.short_pi, ARRAY_SIZE(eilbrts.short_pi));
		break;
	case 1:
	case 3:
		nrts = shr_parse_csv_u64(cfg.eilbrts,
			eilbrts.long_pi, ARRAY_SIZE(eilbrts.long_pi));
		break;
	default:
		nvme_show_error("invalid format");
		return -EINVAL;
	}

	natms = shr_parse_csv_u16(cfg.elbatms, elbatms,
						    ARRAY_SIZE(elbatms));
	nats = shr_parse_csv_u16(cfg.elbats, elbats,
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

	if (!cfg.nsid) {
		err = libnvme_get_nsid(hdl, &cfg.nsid);
		if (err < 0) {
			nvme_show_error("get-namespace-id: %s", libnvme_strerror(-err));
			return err;
		}
	}

	copy = libnvme_alloc(sizeof(*copy));
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
		nvme_init_copy_range_f0(copy->f0, nlbs, slbas, eilbrts.short_pi,
					elbatms, elbats, nr);
		break;
	}

	nvme_init_copy(&cmd, cfg.nsid, cfg.sdlba, nr, cfg.format,
		       cfg.prinfor, cfg.prinfow, 0, cfg.dtype, cfg.stc, cfg.stc,
		       cfg.fua, cfg.lr, 0, cfg.dspec, copy->f0);
	err = init_pi_tags(hdl, &cmd, cfg.nsid, cfg.ilbrt, cfg.lbst, cfg.lbat,
		cfg.lbatm);
	if (err != 0 && err != NVME_SC_INVALID_FIELD)
		return err;
	err = libnvme_exec_io_passthru(hdl, &cmd);
	if (err) {
		nvme_show_err(err, "NVMe Copy");
		return err;
	}

	nvme_show_verbose_result("NVMe Copy: success");

	return err;
}

static int flush_cmd(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc = "Commit data and metadata associated with\n"
		"given namespaces to nonvolatile media. Applies to all commands\n"
		"finished before the flush was submitted. Additional data may also be\n"
		"flushed by the controller, from any namespace, depending on controller and\n"
		"associated namespace status.";

	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	__cleanup_nvme_transport_handle struct libnvme_transport_handle *hdl = NULL;
	struct libnvme_passthru_cmd cmd = {};
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

	err = open_fallback_chardev(ctx, cfg.namespace_id, &hdl);
	if (err)
		return err;

	if (!cfg.namespace_id) {
		err = libnvme_get_nsid(hdl, &cfg.namespace_id);
		if (err < 0) {
			nvme_show_error("get-namespace-id: %s", libnvme_strerror(-err));
			return err;
		}
	}

	cmd.opcode = nvme_cmd_flush;
	cmd.nsid = cfg.namespace_id;

	err = libnvme_exec_io_passthru(hdl, &cmd);
	if (err) {
		nvme_show_err(err, "flush");
		return err;
	}

	nvme_show_verbose_result("NVMe Flush: success");

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

	__cleanup_nvme_transport_handle struct libnvme_transport_handle *hdl = NULL;
	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	struct libnvme_passthru_cmd cmd;
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

	err = validate_output_format(nvme_args.output_format, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	if (!cfg.namespace_id) {
		err = libnvme_get_nsid(hdl, &cfg.namespace_id);
		if (err < 0) {
			nvme_show_error("get-namespace-id: %s", libnvme_strerror(-err));
			return err;
		}
	}
	if (cfg.racqa > 7) {
		nvme_show_error("invalid racqa:%d", cfg.racqa);
		return -EINVAL;
	}

	nvme_init_resv_acquire(&cmd, cfg.namespace_id, cfg.racqa, cfg.iekey,
			       false, cfg.rtype, cfg.crkey, cfg.prkey, payload);
	err = libnvme_exec_io_passthru(hdl, &cmd);
	if (err) {
		nvme_show_err(err, "reservation acquire");
		return err;
	}

	nvme_show_verbose_result("NVME Reservation Acquire success");

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

	__cleanup_nvme_transport_handle struct libnvme_transport_handle *hdl = NULL;
	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	struct libnvme_passthru_cmd cmd;
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

	err = validate_output_format(nvme_args.output_format, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	if (!cfg.namespace_id) {
		err = libnvme_get_nsid(hdl, &cfg.namespace_id);
		if (err < 0) {
			nvme_show_error("get-namespace-id: %s", libnvme_strerror(-err));
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
	err = libnvme_exec_io_passthru(hdl, &cmd);
	if (err) {
		nvme_show_err(err, "reservation register");
		return err;
	}

	nvme_show_verbose_result("NVME Reservation success");

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

	__cleanup_nvme_transport_handle struct libnvme_transport_handle *hdl = NULL;
	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	struct libnvme_passthru_cmd cmd;
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

	err = validate_output_format(nvme_args.output_format, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	if (!cfg.nsid) {
		err = libnvme_get_nsid(hdl, &cfg.nsid);
		if (err < 0) {
			nvme_show_error("get-namespace-id: %s", libnvme_strerror(-err));
			return err;
		}
	}
	if (cfg.rrela > 7) {
		nvme_show_error("invalid rrela:%d", cfg.rrela);
		return -EINVAL;
	}

	nvme_init_resv_release(&cmd, cfg.nsid, cfg.rrela, cfg.iekey, false,
		cfg.rtype, cfg.crkey, payload);
	err = libnvme_exec_io_passthru(hdl, &cmd);
	if (err) {
		nvme_show_err(err, "reservation release");
		return err;
	}

	nvme_show_verbose_result("NVME Reservation Release success");

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

	__cleanup_nvme_transport_handle struct libnvme_transport_handle *hdl = NULL;
	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	__cleanup_libnvme_free struct nvme_resv_status *status = NULL;
	__cleanup_libnvme_free struct nvme_id_ctrl *ctrl = NULL;
	struct libnvme_passthru_cmd cmd;
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

	err = validate_output_format(nvme_args.output_format, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	if (cfg.raw_binary)
		flags = BINARY;

	if (!cfg.nsid) {
		err = libnvme_get_nsid(hdl, &cfg.nsid);
		if (err < 0) {
			nvme_show_error("get-namespace-id: %s", libnvme_strerror(-err));
			return err;
		}
	}

	if (!cfg.numd || cfg.numd >= (0x1000 >> 2))
		cfg.numd = (0x1000 >> 2) - 1;
	if (cfg.numd < 3)
		cfg.numd = 3;

	size = (cfg.numd + 1) << 2;

	ctrl = libnvme_alloc(sizeof(*ctrl));
	if (!ctrl)
		return -ENOMEM;

	nvme_init_identify_ctrl(&cmd, ctrl);
	err = libnvme_exec_admin_passthru(hdl, &cmd);
	if (err) {
		nvme_show_error("identify-ctrl: %s", libnvme_strerror(err));
		return -errno;
	}

	if (ctrl->ctratt & NVME_CTRL_CTRATT_128_ID)
		cfg.eds = true;

	status = libnvme_alloc(size);
	if (!status)
		return -ENOMEM;

	nvme_init_resv_report(&cmd, cfg.nsid, cfg.eds, false, status, size);
	err = libnvme_exec_io_passthru(hdl, &cmd);
	if (err) {
		nvme_show_err(err, "reservation report");
		return err;
	}

	nvme_show_resv_report(status, size, cfg.eds, flags);

	return err;
}

static int submit_io(int opcode, char *command, const char *desc, int argc, char **argv)
{
	__cleanup_nvme_transport_handle struct libnvme_transport_handle *hdl = NULL;
	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	unsigned long long buffer_size = 0, mbuffer_size = 0;
	__cleanup_free struct nvme_nvm_id_ns *nvm_ns = NULL;
	__cleanup_huge struct libnvme_mem_huge mh = { 0, };
	__cleanup_free struct nvme_id_ns *ns = NULL;
	unsigned int logical_block_size = 0;
	struct timeval start_time, end_time;
	__cleanup_free void *mbuffer = NULL;
	__cleanup_fd int dfd = -1, mfd = -1;
	__u16 control = 0, nblocks = 0;
	struct libnvme_passthru_cmd cmd;
	__u8 sts = 0, pif = 0;
	bool pi_available;
	__u32 dsmgmt = 0;
	int mode = 0644;
	void *buffer;
	__u16 ms = 0;
	int err = 0;
	int flags;

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
	const char *force = "The \"I know what I'm doing\" flag, do not enforce exclusive access for write";

	struct config {
		__u32	nsid;
		__u64	start_block;
		__u16	block_count;
		__u16	block_size;
		__u64	data_size;
		__u64	metadata_size;
		__u64	ilbrt;
		char	*data;
		char	*metadata;
		__u8	prinfo;
		__u16	lbatm;
		__u16	lbat;
		__u64	lbst;
		bool	limited_retry;
		bool	force_unit_access;
		bool	stc;
		__u8	dtype;
		__u16	dspec;
		__u8	dsmgmt;
		bool	show;
		bool	latency;
		bool	force;
	};

	struct config cfg = {
		.nsid				= 0,
		.start_block		= 0,
		.block_count		= 0,
		.block_size			= 0,
		.data_size			= 0,
		.metadata_size		= 0,
		.ilbrt				= 0,
		.data				= "",
		.metadata			= "",
		.prinfo				= 0,
		.lbatm				= 0,
		.lbat				= 0,
		.lbst				= 0,
		.limited_retry		= false,
		.force_unit_access	= false,
		.stc				= false,
		.dtype				= 0,
		.dspec				= 0,
		.dsmgmt				= 0,
		.show				= false,
		.latency			= false,
		.force				= false,
	};

	NVME_ARGS(opts,
		  OPT_UINT("namespace-id",      'n', &cfg.nsid,				 namespace_id_desired),
		  OPT_SUFFIX("start-block",     's', &cfg.start_block,       start_block_addr),
		  OPT_SHRT("block-count",       'c', &cfg.block_count,       block_count),
		  OPT_SHRT("block-size",        'b', &cfg.block_size,        block_size),
		  OPT_SUFFIX("data-size",       'z', &cfg.data_size,         data_size),
		  OPT_SUFFIX("metadata-size",   'y', &cfg.metadata_size,     metadata_size),
		  OPT_SUFFIX("ref-tag",         'r', &cfg.ilbrt,			 ref_tag),
		  OPT_FILE("data",              'd', &cfg.data,              data),
		  OPT_FILE("metadata",          'M', &cfg.metadata,          metadata),
		  OPT_BYTE("prinfo",            'p', &cfg.prinfo,            prinfo),
		  OPT_SHRT("app-tag-mask",      'm', &cfg.lbatm,			 app_tag_mask),
		  OPT_SHRT("app-tag",           'a', &cfg.lbat,				 app_tag),
		  OPT_SUFFIX("storage-tag",     'g', &cfg.lbst,				 storage_tag),
		  OPT_FLAG("limited-retry",     'l', &cfg.limited_retry,     limited_retry_num),
		  OPT_FLAG("force-unit-access", 'f', &cfg.force_unit_access, force_unit_access),
		  OPT_FLAG("storage-tag-check", 'C', &cfg.stc,				 storage_tag_check),
		  OPT_BYTE("dir-type",          'T', &cfg.dtype,             dtype_for_write),
		  OPT_SHRT("dir-spec",          'S', &cfg.dspec,             dspec),
		  OPT_BYTE("dsm",               'D', &cfg.dsmgmt,            dsm),
		  OPT_FLAG("show-command",      'V', &cfg.show,              show),
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
		err = open_exclusive(&ctx, &hdl, argc, argv, cfg.force, opts);
		if (err) {
			if (err == -EBUSY) {
				nvme_show_error("Failed to open %s.", basename(argv[optind]));
				nvme_show_error("Namespace is currently busy.");
				if (!cfg.force)
					nvme_show_error(
						"Use the force [--force] option to ignore that.");
			} else {
				argconfig_print_help(desc, opts);
			}
			return err;
		}
	}

	if (!cfg.nsid) {
		err = libnvme_get_nsid(hdl, &cfg.nsid);
		if (err < 0) {
			nvme_show_error("get-namespace-id: %s", libnvme_strerror(-err));
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
	if (cfg.stc)
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
		flags = O_WRONLY | O_CREAT | O_TRUNC;
	}

	if (strlen(cfg.data)) {
		dfd = shr_open_rawdata(cfg.data, flags, mode);
		if (dfd < 0) {
			nvme_show_perror(cfg.data);
			return -EINVAL;
		}
	}

	if (strlen(cfg.metadata)) {
		mfd = shr_open_rawdata(cfg.metadata, flags, mode);
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
		pi_available = true;
	} else {
		err = get_pi_info(hdl, cfg.nsid, cfg.prinfo,
			cfg.ilbrt, cfg.lbst, &logical_block_size, &ms);
		pi_available = err == 0;
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

	buffer = libnvme_alloc_huge(buffer_size, &mh);
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
			nvme_show_error("failed to read data buffer from input file %s", libnvme_strerror(errno));
			return err;
		}
	}

	if ((opcode & 1) && cfg.metadata_size) {
		err = read(mfd, (void *)mbuffer, mbuffer_size);
		if (err < 0) {
			err = -errno;
			nvme_show_error("failed to read meta-data buffer from input file %s", libnvme_strerror(errno));
			return err;
		}
	}

	if (cfg.show || nvme_args.dry_run) {
		nvme_show_result("opcode       : %02x", opcode);
		nvme_show_result("nsid         : %02x", cfg.nsid);
		nvme_show_result("flags        : %02x", 0);
		nvme_show_result("control      : %04x", control);
		nvme_show_result("nblocks      : %04x", nblocks);
		nvme_show_result("metadata     : %"PRIx64, (uint64_t)(uintptr_t)mbuffer);
		nvme_show_result("addr         : %"PRIx64, (uint64_t)(uintptr_t)buffer);
		nvme_show_result("slba         : %"PRIx64, (uint64_t)cfg.start_block);
		nvme_show_result("dsmgmt       : %08x", dsmgmt);
		nvme_show_result("reftag       : %"PRIx64, (uint64_t)cfg.ilbrt);
		nvme_show_result("apptag       : %04x", cfg.lbat);
		nvme_show_result("appmask      : %04x", cfg.lbatm);
		nvme_show_result("storagetagcheck : %04x", cfg.stc);
		nvme_show_result("storagetag      : %"PRIx64, (uint64_t)cfg.lbst);
		nvme_show_result("pif             : %02x", pif);
		nvme_show_result("sts             : %02x", sts);
	}
	if (nvme_args.dry_run)
		return 0;

	nvme_init_io(&cmd, opcode, cfg.nsid, cfg.start_block, buffer,
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
	if (pi_available) {
		err = init_pi_tags(hdl, &cmd, cfg.nsid, cfg.ilbrt, cfg.lbst,
			cfg.lbat, cfg.lbatm);
		if (err)
			return err;
	}
	gettimeofday(&start_time, NULL);
	err = libnvme_exec_io_passthru(hdl, &cmd);
	gettimeofday(&end_time, NULL);
	if (cfg.latency)
		nvme_show_result(" latency: %s: %llu us", command, shr_elapsed_utime(start_time, end_time));
	if (err) {
		nvme_show_err(err, "submit-io");
		return err;
	}

	if (!(opcode & 1) && write(dfd, (void *)buffer, buffer_size) < 0) {
		nvme_show_error(
		    "write: %s: failed to write buffer to output file",
		    libnvme_strerror(errno));
		err = -EINVAL;
	} else if (!(opcode & 1) && cfg.metadata_size &&
		   write(mfd, (void *)mbuffer, mbuffer_size) < 0) {
		nvme_show_error(
		    "write: %s: failed to write meta-data buffer to output file",
		    libnvme_strerror(errno));
		err = -EINVAL;
	} else {
		nvme_show_verbose_result("%s: Success", command);
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
	__cleanup_nvme_transport_handle struct libnvme_transport_handle *hdl = NULL;
	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	struct libnvme_passthru_cmd cmd;
	__u16 control = 0;
	int err;

	const char *desc = "Verify specified logical blocks on the given device.";
	const char *force_unit_access_verify =
	    "force device to commit cached data before performing the verify operation";
	const char *storage_tag_check =
	    "This bit specifies the Storage Tag field shall be checked as part of Verify operation";

	struct config {
		__u32	nsid;
		__u64	start_block;
		__u16	block_count;
		bool	limited_retry;
		bool	force_unit_access;
		__u8	prinfo;
		__u32	ilbrt;
		__u16	lbat;
		__u16	lbatm;
		__u64	lbst;
		bool	stc;
	};

	struct config cfg = {
		.nsid				= 0,
		.start_block		= 0,
		.block_count		= 0,
		.limited_retry		= false,
		.force_unit_access	= false,
		.prinfo				= 0,
		.ilbrt				= 0,
		.lbat				= 0,
		.lbatm				= 0,
		.lbst				= 0,
		.stc				= false,
	};

	NVME_ARGS(opts,
		  OPT_UINT("namespace-id",      'n', &cfg.nsid,				 namespace_desired),
		  OPT_SUFFIX("start-block",     's', &cfg.start_block,       start_block),
		  OPT_SHRT("block-count",       'c', &cfg.block_count,       block_count),
		  OPT_FLAG("limited-retry",     'l', &cfg.limited_retry,     limited_retry),
		  OPT_FLAG("force-unit-access", 'f', &cfg.force_unit_access, force_unit_access_verify),
		  OPT_BYTE("prinfo",            'p', &cfg.prinfo,            prinfo),
		  OPT_SUFFIX("ref-tag",         'r', &cfg.ilbrt,			 ref_tag),
		  OPT_SHRT("app-tag",           'a', &cfg.lbat,				 app_tag),
		  OPT_SHRT("app-tag-mask",      'm', &cfg.lbatm,			 app_tag_mask),
		  OPT_SUFFIX("storage-tag",     'S', &cfg.lbst,				 storage_tag),
		  OPT_FLAG("storage-tag-check", 'C', &cfg.stc,				 storage_tag_check));

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	err = open_fallback_chardev(ctx, cfg.nsid, &hdl);
	if (err)
		return err;

	if (cfg.prinfo > 0xf)
		return -EINVAL;

	control |= (cfg.prinfo << 10);
	if (cfg.limited_retry)
		control |= NVME_IO_LR;
	if (cfg.force_unit_access)
		control |= NVME_IO_FUA;
	if (cfg.stc)
		control |= NVME_IO_STC;

	if (!cfg.nsid) {
		err = libnvme_get_nsid(hdl, &cfg.nsid);
		if (err < 0) {
			nvme_show_error("get-namespace-id: %s", libnvme_strerror(-err));
			return err;
		}
	}

	nvme_init_verify(&cmd, cfg.nsid, cfg.start_block,
		cfg.block_count, control, 0, NULL, 0, NULL, 0);
	err = init_pi_tags(hdl, &cmd, cfg.nsid, cfg.ilbrt, cfg.lbst,
		cfg.lbat, cfg.lbatm);
	if (err != 0 && err != NVME_SC_INVALID_FIELD)
		return err;
	err = libnvme_exec_io_passthru(hdl, &cmd);
	if (err) {
		nvme_show_err(err, "verify");
		return err;
	}

	nvme_show_verbose_result("NVME Verify Success");

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

	__cleanup_nvme_transport_handle struct libnvme_transport_handle *hdl = NULL;
	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	__cleanup_libnvme_free void *sec_buf = NULL;
	struct libnvme_passthru_cmd cmd;
	nvme_print_flags_t flags;
	int err;

	struct config {
		bool	ish;
		__u32	namespace_id;
		__u32	size;
		__u8	nssf;
		__u8	secp;
		__u16	spsp;
		__u32	al;
		bool	raw_binary;
	};

	struct config cfg = {
		.ish		= false,
		.namespace_id	= 0,
		.size		= 0,
		.nssf		= 0,
		.secp		= 0,
		.spsp		= 0,
		.al		= 0,
		.raw_binary	= false,
	};

	NVME_ARGS(opts,
		  OPT_FLAG("ish",          'I', &cfg.ish,          ish),
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

	err = validate_output_format(nvme_args.output_format, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	if (cfg.size) {
		sec_buf = libnvme_alloc(cfg.size);
		if (!sec_buf)
			return -ENOMEM;
	}

	if (cfg.ish) {
		if (libnvme_transport_handle_is_mi(hdl))
			nvme_init_mi_cmd_flags(&cmd, ish);
		else
			nvme_show_error("ISH is supported only for NVMe-MI");
	}

	nvme_init_security_receive(&cmd, cfg.namespace_id, cfg.nssf, cfg.spsp,
				   cfg.secp, cfg.al, sec_buf, cfg.size);
	err = libnvme_exec_admin_passthru(hdl, &cmd);
	if (err) {
		nvme_show_err(err, "security receive");
		return err;
	}

	nvme_show_verbose_result("NVME Security Receive Command Success");
	if (!cfg.raw_binary)
		d(sec_buf, cfg.size, 16, 1);
	else if (cfg.size)
		d_raw((unsigned char *)sec_buf, cfg.size);

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

	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	__cleanup_nvme_transport_handle struct libnvme_transport_handle *hdl = NULL;
	struct libnvme_passthru_cmd cmd;
	__cleanup_libnvme_free void *buf = NULL;
	nvme_print_flags_t flags;
	unsigned long buf_len;
	int err;

	struct config {
		bool	ish;
		__u32	namespace_id;
		__u64	slba;
		__u32	mndw;
		__u8	atype;
		__u16	rl;
	};

	struct config cfg = {
		.ish		= false,
		.namespace_id	= 0,
		.slba		= 0,
		.mndw		= 0,
		.atype		= 0,
		.rl		= 0,
	};

	NVME_ARGS(opts,
		  OPT_FLAG("ish",          'I', &cfg.ish,           ish),
		  OPT_UINT("namespace-id", 'n', &cfg.namespace_id,  namespace_desired),
		  OPT_SUFFIX("start-lba",  's', &cfg.slba,          slba),
		  OPT_UINT("max-dw",       'm', &cfg.mndw,          mndw),
		  OPT_BYTE("action",       'a', &cfg.atype,         atype),
		  OPT_SHRT("range-len",    'l', &cfg.rl,            rl));

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	err = validate_output_format(nvme_args.output_format, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	if (!cfg.atype) {
		nvme_show_error("action type (--action) has to be given");
		return -EINVAL;
	}

	buf_len = (cfg.mndw + 1) * 4;
	buf = libnvme_alloc(buf_len);
	if (!buf)
		return -ENOMEM;

	nvme_init_get_lba_status(&cmd, cfg.namespace_id, cfg.slba, cfg.mndw,
				 cfg.atype, cfg.rl, buf);
	if (cfg.ish) {
		if (libnvme_transport_handle_is_mi(hdl))
			nvme_init_mi_cmd_flags(&cmd, ish);
		else
			nvme_show_error("ISH is supported only for NVMe-MI");
	}
	err = libnvme_exec_admin_passthru(hdl, &cmd);
	if (err) {
		nvme_show_err(err, "get lba status");
		return err;
	}

	nvme_show_lba_status(buf, buf_len, flags);

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

	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	__cleanup_nvme_transport_handle struct libnvme_transport_handle *hdl = NULL;
	struct libnvme_passthru_cmd cmd;
	int err = -1;
	nvme_print_flags_t flags;

	struct config {
		bool	ish;
		__u8	operation;
		__u16	element_id;
		__u32	dw11;
		__u32	dw12;
	};

	struct config cfg = {
		.ish		= false,
		.operation	= 0xff,
		.element_id	= 0xffff,
		.dw11		= 0,
		.dw12		= 0,
	};

	NVME_ARGS(opts,
		  OPT_FLAG("ish",         'I', &cfg.ish,          ish),
		  OPT_BYTE("operation",   'O', &cfg.operation,    operation),
		  OPT_SHRT("element-id",  'i', &cfg.element_id,   element_id),
		  OPT_UINT("cap-lower",   'l', &cfg.dw11,         cap_lower),
		  OPT_UINT("cap-upper",   'u', &cfg.dw12,         cap_upper));

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	err = validate_output_format(nvme_args.output_format, &flags);
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
	if (cfg.ish) {
		if (libnvme_transport_handle_is_mi(hdl))
			nvme_init_mi_cmd_flags(&cmd, ish);
		else
			nvme_show_error("ISH is supported only for NVMe-MI");
	}
	err = libnvme_exec_admin_passthru(hdl, &cmd);
	if (err) {
		nvme_show_err(err, "capacity management");
		return err;
	}

	nvme_show_verbose_result("Capacity Management Command is Success");

	if (cfg.operation == 1)
		nvme_show_result("Created Element Identifier for Endurance Group is: %"
		                 PRIu64, (uint64_t)cmd.result);
	else if (cfg.operation == 3)
		nvme_show_result("Created Element Identifier for NVM Set is: %"
		                 PRIu64, (uint64_t)cmd.result);

	return err;
}

static int dir_receive(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc = "Read directive parameters of the specified directive type.";
	const char *nsr = "namespace stream requested";

	nvme_print_flags_t flags = NORMAL;
	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	__cleanup_nvme_transport_handle struct libnvme_transport_handle *hdl = NULL;
	__cleanup_libnvme_free void *buf = NULL;
	struct libnvme_passthru_cmd cmd;
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
	};

	struct config cfg = {
		.namespace_id	= 1,
		.data_len	= 0,
		.raw_binary	= false,
		.dtype		= 0,
		.dspec		= 0,
		.doper		= 0,
		.nsr		= 0,
	};

	NVME_ARGS(opts,
		  OPT_UINT("namespace-id",   'n', &cfg.namespace_id,   namespace_id_desired),
		  OPT_UINT("data-len",       'l', &cfg.data_len,       buf_len),
		  OPT_FLAG("raw-binary",     'b', &cfg.raw_binary,     raw_directive),
		  OPT_BYTE("dir-type",       'D', &cfg.dtype,          dtype),
		  OPT_SHRT("dir-spec",       'S', &cfg.dspec,          dspec_w_dtype),
		  OPT_BYTE("dir-oper",       'O', &cfg.doper,          doper),
		  OPT_SHRT("req-resource",   'r', &cfg.nsr,            nsr));

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	if (nvme_args.verbose)
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
		buf = libnvme_alloc(cfg.data_len);
		if (!buf)
			return -ENOMEM;
	}

	nvme_init_directive_recv(&cmd, cfg.namespace_id, cfg.doper, cfg.dtype,
		cfg.dspec, buf, cfg.data_len);
	cmd.cdw12 = dw12;
	err = libnvme_exec_admin_passthru(hdl, &cmd);
	if (err) {
		nvme_show_err(err, "dir-receive");
		return err;
	}

	nvme_directive_show(cfg.dtype, cfg.doper, cfg.dspec, cfg.namespace_id,
			    cmd.result, buf, cfg.data_len, flags);

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

	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	__cleanup_nvme_transport_handle struct libnvme_transport_handle *hdl = NULL;
	struct libnvme_passthru_cmd cmd;
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
	err = libnvme_exec_admin_passthru(hdl, &cmd);
	if (err) {
		nvme_show_err(err, "lockdown");
		return err;
	}

	nvme_show_verbose_result("Lockdown Command is Successful");

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

	__cleanup_huge struct libnvme_mem_huge mh = { 0, };
	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	__cleanup_nvme_transport_handle struct libnvme_transport_handle *hdl = NULL;
	__cleanup_fd int dfd = -1, mfd = -1;
	int flags = -1;
	int mode = 0644;
	void *data = NULL;
	__cleanup_free void *mdata = NULL;
	int err = 0;
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
		  OPT_FLAG("read",         'r', &cfg.read,         re),
		  OPT_FLAG("write",        'w', &cfg.write,        wr),
		  OPT_FLAG("latency",      'T', &cfg.latency,      latency));

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	err = validate_output_format(nvme_args.output_format, &flags_t);
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
		flags = O_WRONLY | O_CREAT | O_TRUNC;
		dfd = mfd = STDOUT_FILENO;
	}

	/*
	 * Fallback to user specified data direction in case from opcode
	 * we can't decode direction.
	 */
	if (cfg.write && flags < 0) {
		flags = O_RDONLY;
		dfd = mfd = STDIN_FILENO;
	}

	if (cfg.read && flags < 0) {
		flags = O_WRONLY | O_CREAT | O_TRUNC;
		dfd = mfd = STDOUT_FILENO;
	}
	if (strlen(cfg.input_file)) {
		if (flags < 0) {
			nvme_show_error("input file specified for opcode 0x%x "
				"without a data transfer direction",
					cfg.opcode);
			return -EINVAL;
		}
		dfd = shr_open_rawdata(cfg.input_file, flags, mode);
		if (dfd < 0) {
			nvme_show_perror(cfg.input_file);
			return -EINVAL;
		}
	}

	if (cfg.metadata && strlen(cfg.metadata)) {
		if (flags < 0) {
			nvme_show_error("metadata file specified for opcode 0x%x "
				"without a data transfer direction",
					cfg.opcode);
			return -EINVAL;
		}
		mfd = shr_open_rawdata(cfg.metadata, flags, mode);
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
		data = libnvme_alloc_huge(cfg.data_len, &mh);
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
				nvme_show_error("failed to read write buffer %s", libnvme_strerror(errno));
				return err;
			}
		}
	}

	if (cfg.show_command || nvme_args.dry_run) {
		nvme_show_result("opcode       : %02x", cfg.opcode);
		nvme_show_result("flags        : %02x", cfg.flags);
		nvme_show_result("rsvd1        : %04x", cfg.rsvd);
		nvme_show_result("nsid         : %08x", cfg.namespace_id);
		nvme_show_result("cdw2         : %08x", cfg.cdw2);
		nvme_show_result("cdw3         : %08x", cfg.cdw3);
		nvme_show_result("data_len     : %08x", cfg.data_len);
		nvme_show_result("metadata_len : %08x", cfg.metadata_len);
		nvme_show_result("addr         : %"PRIx64, (uint64_t)(uintptr_t)data);
		nvme_show_result("metadata     : %"PRIx64, (uint64_t)(uintptr_t)mdata);
		nvme_show_result("cdw10        : %08x", cfg.cdw10);
		nvme_show_result("cdw11        : %08x", cfg.cdw11);
		nvme_show_result("cdw12        : %08x", cfg.cdw12);
		nvme_show_result("cdw13        : %08x", cfg.cdw13);
		nvme_show_result("cdw14        : %08x", cfg.cdw14);
		nvme_show_result("cdw15        : %08x", cfg.cdw15);
		nvme_show_result("timeout_ms   : %08x", nvme_args.timeout);
	}
	if (nvme_args.dry_run)
		return 0;

	gettimeofday(&start_time, NULL);

	struct libnvme_passthru_cmd cmd = {
		.opcode		= cfg.opcode,
		.flags		= cfg.flags,
		.nsid		= cfg.namespace_id,
		.cdw2		= cfg.cdw2,
		.cdw3		= cfg.cdw3,
		.metadata	= (__u64)(uintptr_t)mdata,
		.addr		= (__u64)(uintptr_t)data,
		.metadata_len	= cfg.metadata_len,
		.data_len	= cfg.data_len,
		.cdw10		= cfg.cdw10,
		.cdw11		= cfg.cdw11,
		.cdw12		= cfg.cdw12,
		.cdw13		= cfg.cdw13,
		.cdw14		= cfg.cdw14,
		.cdw15		= cfg.cdw15,
		.timeout_ms 	= nvme_args.timeout,
	};
	if (admin)
		err = libnvme_exec_admin_passthru(hdl, &cmd);
	else
		err = libnvme_exec_io_passthru(hdl, &cmd);

	gettimeofday(&end_time, NULL);
	cmd_name = nvme_cmd_to_string(admin, cfg.opcode);
	if (cfg.latency)
		nvme_show_result("%s Command %s latency: %llu us", admin ? "Admin" : "IO",
		                 strcmp(cmd_name, "Unknown") ? cmd_name : "Vendor Specific",
		                 shr_elapsed_utime(start_time, end_time));

	if (err) {
		nvme_show_err(err, __func__);
		return err;
	}

	nvme_show_verbose_result("%s Command %s is Success and result: 0x%" PRIx64,
				 admin ? "Admin" : "IO",
				 strcmp(cmd_name, "Unknown") ?
				 cmd_name : "Vendor Specific", (uint64_t)cmd.result);
	if (cfg.read)
		passthru_print_read_output(cfg, data, dfd, mdata, mfd, err);

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

#ifdef CONFIG_FABRICS
static int gen_hostnqn_cmd(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc = "Generate a hostnqn";

	__cleanup_free char *hostnqn = NULL;
	int err;

	NVME_ARGS(opts);

	err = parse_args(argc, argv, desc, opts);
	if (err)
		return err;

	hostnqn = libnvmf_generate_hostnqn();
	if (!hostnqn) {
		nvme_show_error("\"%s\" not supported. Install lib uuid and rebuild.",
				acmd->name);
		return -ENOTSUP;
	}

	nvme_show_result("%s", hostnqn);

	return 0;
}

static int show_hostnqn_cmd(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc = "Show hostnqn";

	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	__cleanup_free char *hostnqn = NULL;
	int err;

	NVME_ARGS(opts);

	err = parse_args(argc, argv, desc, opts);
	if (err)
		return err;

	ctx = libnvme_create_global_ctx();
	if (!ctx)
		return -ENOMEM;

	hostnqn = libnvmf_read_hostnqn(ctx);
	if (!hostnqn)
		hostnqn =  libnvmf_generate_hostnqn();

	if (!hostnqn) {
		nvme_show_error("hostnqn is not available -- use nvme gen-hostnqn");
		return -ENOENT;
	}

	nvme_show_result("%s", hostnqn);

	return 0;
}

#endif /* CONFIG_FABRICS */

static int show_topology_cmd(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc = "Show the topology\n";
	const char *ranking = "Ranking order: namespace|ctrl|multipath";
	nvme_print_flags_t flags;
	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	char *devname = NULL;
	libnvme_scan_filter_t filter = NULL;
	enum nvme_cli_topo_ranking rank;
	int err;

#ifdef CONFIG_JSONC
	nvme_print_flags_t supported_formats = (NORMAL | JSON | TABULAR);
	const char *supported_formats_desc = "Output format: normal|json|tabular";
#else /* CONFIG_JSONC */
	nvme_print_flags_t supported_formats = (NORMAL | TABULAR);
	const char *supported_formats_desc = "Output format: normal|tabular";
#endif /* CONFIG_JSONC */

	struct config {
		char	*ranking;
	};

	struct config cfg = {
		.ranking	= "namespace",
	};

	NVME_ARGS_OUTPUT_FORMATS(opts, supported_formats, supported_formats_desc,
		  OPT_FMT("ranking",       'r', &cfg.ranking,       ranking));

	err = parse_args(argc, argv, desc, opts);
	if (err)
		return err;

	err = validate_output_format(nvme_args.output_format, &flags);
	if (err < 0) {
		nvme_show_error("Invalid output format");
		return err;
	}

	if (nvme_args.verbose)
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

	err = nvme_create_global_ctx(&ctx);
	if (err)
		return err;

	if (optind < argc)
		devname = basename(argv[optind++]);

	if (devname) {
		int subsys_id, nsid;

		if (sscanf(devname, "nvme%dn%d", &subsys_id, &nsid) < 1 &&
		    sscanf(devname, "ng%dn%d", &subsys_id, &nsid) != 2) {
			nvme_show_error("Invalid device name %s\n", devname);
			return -EINVAL;
		}
		filter = nvme_match_device_filter;
	}

	err = libnvme_scan_topology(ctx, filter, (void *)devname);
	if (err < 0)
		return handle_scan_topology_error(err);

	if (flags & TABULAR)
		nvme_show_topology_tabular(ctx, flags);
	else
		nvme_show_topology(ctx, rank, flags);

	return err;
}

#ifdef CONFIG_FABRICS
static int discover_cmd(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc = "Send Get Log Page request to Discovery Controller.";

	return fabrics_discover(desc, argc, argv, false);
}

static int connect_all_cmd(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc = "Discover NVMeoF subsystems and connect to them";

	return fabrics_discover(desc, argc, argv, true);
}

static int connect_cmd(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc = "Connect to NVMeoF subsystem";

	return fabrics_connect(desc, argc, argv);
}

static int disconnect_cmd(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc = "Disconnect from NVMeoF subsystem";

	return fabrics_disconnect(desc, argc, argv);
}

int disconnect_all_cmd(int argc, char **argv, struct command *acmd,
	struct plugin *plugin)
{
	const char *desc = "Disconnect from all connected NVMeoF subsystems";

	return fabrics_disconnect_all(desc, argc, argv);
}

static int dim_cmd(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc =
	    "Send Discovery Information Management command to a Discovery Controller (DC)";

	return fabrics_dim(desc, argc, argv);
}

#ifdef CONFIG_DEPRECATED_CMDS
static struct plugin *find_keys_plugin(void)
{
	struct plugin *keys = nvme.extensions->next;

	while (keys && (!keys->name || strcmp(keys->name, "keys")))
		keys = keys->next;

	return keys;
}

static int forward_to_keys_plugin(const char *old_name, const char *subcmd,
		int argc, char **argv)
{
	struct plugin *keys = find_keys_plugin();
	__cleanup_free char **sub_argv = NULL;

	if (!keys) {
		fprintf(stderr, "ERROR: '%s' is deprecated and requires the 'keys' plugin, which is not available in this build; use 'nvme keys %s'\n",
			old_name, subcmd);
		return -ENOTTY;
	}

	fprintf(stderr, "WARNING: '%s' is deprecated and will be removed in the next major version, use 'nvme keys %s' instead\n",
		old_name, subcmd);

	/*
	 * handle_plugin() expects argv[0] to be a throwaway name (its own
	 * global-option parsing skips it like a program name) and argv[1]
	 * to be the subcommand it dispatches on, so forwarding into the
	 * 'keys' plugin needs both slots, not just a renamed argv[0].
	 */
	sub_argv = calloc(argc + 1, sizeof(*sub_argv));
	if (!sub_argv)
		return -ENOMEM;

	sub_argv[0] = (char *)keys->name;
	sub_argv[1] = (char *)subcmd;
	memcpy(&sub_argv[2], &argv[1], (argc - 1) * sizeof(*argv));

	return handle_plugin(argc + 1, sub_argv, keys);
}

/*
 * gen-kxchap-secret dropped --nqn with the transform that used it. Take
 * it here anyway, warn, and drop it, so a 2.x command line still works.
 */
static int gen_dhchap_key(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc =
	    "Generate a KX-HMAC-CHAP secret in the DHHC-1 representation, usable for\n"
	    "NVMe In-Band Authentication.\n"
	    "Deprecated; use 'nvme keys gen-kxchap-secret' instead.";
	const char *secret =
	    "Optional secret (in hexadecimal characters) to be placed in the representation.";
	const char *key_len = "Length of the secret (32, 48, or 64 bytes).";
	const char *hmac =
	    "Hash function the consumer is to apply to the secret (0 = none, 1 = SHA-256, 2 = SHA-384, 3 = SHA-512).";
	const char *nqn =
	    "Accepted and ignored; nvme-cli 2.x keyed the transform with it.";

	char key_len_buf[16], hmac_buf[16];
	char *args[8] = { argv[0] };
	int nargs = 1, err;

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

	err = argconfig_parse(argc, argv, desc, opts);
	if (err)
		return err;

	if (argconfig_parse_seen(opts, "nqn"))
		fprintf(stderr,
			"WARNING: '--nqn' is ignored, the DHHC-1 string carries the secret itself, which no NQN takes part in deriving\n");

	if (argconfig_parse_seen(opts, "secret")) {
		args[nargs++] = "--secret";
		args[nargs++] = cfg.secret;
	}
	if (argconfig_parse_seen(opts, "key-length")) {
		snprintf(key_len_buf, sizeof(key_len_buf), "%u", cfg.key_len);
		args[nargs++] = "--secret-length";
		args[nargs++] = key_len_buf;
	}
	if (argconfig_parse_seen(opts, "hmac")) {
		snprintf(hmac_buf, sizeof(hmac_buf), "%u", cfg.hmac);
		args[nargs++] = "--hmac";
		args[nargs++] = hmac_buf;
	}

	return forward_to_keys_plugin("gen-dhchap-key", "gen-kxchap-secret", nargs, args);
}

/*
 * 2.x took the secret in --key/-k, which the command this forwards to
 * gives to --keyring. Take the 2.x option here and pass it as --keydata.
 */
static int check_dhchap_key(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc =
	    "Check a KX-HMAC-CHAP host secret for usability for NVMe In-Band Authentication.\n"
	    "Deprecated; use 'nvme keys check-kxchap-secret' instead.";
	const char *key =
	    "KX-HMAC-CHAP secret (in DHHC-1 interchange format) to be validated. Reads from stdin if not given.";

	char *args[4] = { argv[0] };
	int nargs = 1, err;

	struct config {
		char	*key;
	};

	struct config cfg = {
		.key	= NULL,
	};

	NVME_ARGS(opts,
		  OPT_STR("key", 'k', &cfg.key, key));

	err = argconfig_parse(argc, argv, desc, opts);
	if (err)
		return err;

	if (argconfig_parse_seen(opts, "key")) {
		args[nargs++] = "--keydata";
		args[nargs++] = cfg.key;
	}

	return forward_to_keys_plugin("check-dhchap-key", "check-kxchap-secret", nargs, args);
}

static int gen_tls_key(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	return forward_to_keys_plugin("gen-tls-key", "gen-tls", argc, argv);
}

static int check_tls_key(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	return forward_to_keys_plugin("check-tls-key", "check-tls", argc, argv);
}

/*
 * The old 'tls-key' command bundled import/export/revoke behind
 * -i/-e/-r mode flags sharing -k/-t/-f; the 'keys' plugin split these
 * into separate subcommands with their own option sets, so unlike the
 * other legacy aliases this one has to translate argv instead of just
 * renaming argv[0].
 */
static int tls_key(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	static const struct option opts[] = {
		{ "keyring",	required_argument,	NULL, 'k' },
		{ "keytype",	required_argument,	NULL, 't' },
		{ "keyfile",	required_argument,	NULL, 'f' },
		{ "import",	no_argument,		NULL, 'i' },
		{ "export",	no_argument,		NULL, 'e' },
		{ "revoke",	required_argument,	NULL, 'r' },
		{ NULL, 0, NULL, 0 },
	};
	__cleanup_free char *keyring_opt = NULL;
	__cleanup_free char *keytype_opt = NULL;
	__cleanup_free char *keyfile_opt = NULL;
	__cleanup_free char *identity_opt = NULL;
	__cleanup_free char **sub_argv = NULL;
	const char *keyring = NULL, *keytype = NULL, *keyfile = NULL, *revoke = NULL;
	const char *subcmd = NULL;
	struct plugin *keys;
	int nsub = 0, c;

	optind = 1;
	while ((c = getopt_long(argc, argv, "k:t:f:ier:", opts, NULL)) != -1) {
		switch (c) {
		case 'k':
			keyring = optarg;
			break;
		case 't':
			keytype = optarg;
			break;
		case 'f':
			keyfile = optarg;
			break;
		case 'i':
		case 'e':
			if (subcmd) {
				fprintf(stderr, "ERROR: only one of --import, --export, or --revoke may be given\n");
				return -EINVAL;
			}
			subcmd = c == 'i' ? "import" : "export";
			break;
		case 'r':
			if (subcmd) {
				fprintf(stderr, "ERROR: only one of --import, --export, or --revoke may be given\n");
				return -EINVAL;
			}
			subcmd = "revoke";
			revoke = optarg;
			break;
		default:
			return -EINVAL;
		}
	}

	if (!subcmd) {
		fprintf(stderr, "ERROR: 'tls-key' requires one of --import, --export, or --revoke\n");
		return -EINVAL;
	}

	keys = find_keys_plugin();
	if (!keys) {
		fprintf(stderr, "ERROR: 'tls-key' is deprecated and requires the 'keys' plugin, which is not available in this build; use 'nvme keys %s'\n",
			subcmd);
		return -ENOTTY;
	}

	sub_argv = calloc(6, sizeof(*sub_argv));
	if (!sub_argv)
		return -ENOMEM;

	sub_argv[nsub++] = (char *)keys->name;
	sub_argv[nsub++] = (char *)subcmd;

	if (keyring) {
		if (asprintf(&keyring_opt, "--keyring=%s", keyring) < 0)
			return -ENOMEM;
		sub_argv[nsub++] = keyring_opt;
	}

	if (!strcmp(subcmd, "revoke")) {
		if (keytype) {
			if (asprintf(&keytype_opt, "--keytype=%s", keytype) < 0)
				return -ENOMEM;
			sub_argv[nsub++] = keytype_opt;
		}
		if (asprintf(&identity_opt, "--identity=%s", revoke) < 0)
			return -ENOMEM;
		sub_argv[nsub++] = identity_opt;
	} else if (keyfile) {
		if (asprintf(&keyfile_opt, "--keyfile=%s", keyfile) < 0)
			return -ENOMEM;
		sub_argv[nsub++] = keyfile_opt;
	}

	fprintf(stderr, "WARNING: 'tls-key' is deprecated and will be removed in the next major version, use 'nvme keys %s' instead\n",
		subcmd);

	return handle_plugin(nsub, sub_argv, keys);
}
#endif /* CONFIG_DEPRECATED_CMDS */
#endif /* CONFIG_FABRICS */

#ifdef CONFIG_DEPRECATED_CMDS
static struct plugin *find_log_plugin(void)
{
	struct plugin *log = nvme.extensions->next;

	while (log && (!log->name || strcmp(log->name, "log")))
		log = log->next;

	return log;
}

static int forward_to_log_plugin(const char *old_name, const char *subcmd,
		int argc, char **argv)
{
	struct plugin *log = find_log_plugin();
	__cleanup_free char **sub_argv = NULL;

	if (!log) {
		fprintf(stderr, "ERROR: '%s' is deprecated and requires the 'log' plugin, which is not available in this build; use 'nvme log %s'\n",
			old_name, subcmd);
		return -ENOTTY;
	}

	fprintf(stderr, "WARNING: '%s' is deprecated and will be removed in the next major version, use 'nvme log %s' instead\n",
		old_name, subcmd);

	sub_argv = calloc(argc + 1, sizeof(*sub_argv));
	if (!sub_argv)
		return -ENOMEM;

	sub_argv[0] = (char *)log->name;
	sub_argv[1] = (char *)subcmd;
	memcpy(&sub_argv[2], &argv[1], (argc - 1) * sizeof(*argv));

	return handle_plugin(argc + 1, sub_argv, log);
}

static int get_telemetry_log(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	return forward_to_log_plugin("telemetry-log", "telemetry", argc, argv);
}

static int get_fw_log(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	return forward_to_log_plugin("fw-log", "fw", argc, argv);
}

static int get_changed_attach_ns_list_log(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	return forward_to_log_plugin("changed-ns-list-log", "changed-ns-list", argc, argv);
}

static int get_smart_log(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	return forward_to_log_plugin("smart-log", "smart", argc, argv);
}

static int get_ana_log(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	return forward_to_log_plugin("ana-log", "ana", argc, argv);
}

static int get_error_log(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	return forward_to_log_plugin("error-log", "error", argc, argv);
}

static int get_effects_log(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	return forward_to_log_plugin("effects-log", "effects", argc, argv);
}

static int get_endurance_log(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	return forward_to_log_plugin("endurance-log", "endurance", argc, argv);
}

static int get_pred_lat_per_nvmset_log(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	return forward_to_log_plugin("predictable-lat-log", "predictable-lat", argc, argv);
}

static int get_pred_lat_event_agg_log(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	return forward_to_log_plugin("pred-lat-event-agg-log", "pred-lat-event-agg", argc, argv);
}

static int get_persistent_event_log(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	return forward_to_log_plugin("persistent-event-log", "persistent-event", argc, argv);
}

static int get_endurance_event_agg_log(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	return forward_to_log_plugin("endurance-event-agg-log", "endurance-event-agg", argc, argv);
}

static int get_lba_status_log(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	return forward_to_log_plugin("lba-status-log", "lba-status", argc, argv);
}

static int get_resv_notif_log(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	return forward_to_log_plugin("resv-notif-log", "resv-notif", argc, argv);
}

static int get_boot_part_log(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	return forward_to_log_plugin("boot-part-log", "boot-part", argc, argv);
}

static int get_phy_rx_eom_log(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	return forward_to_log_plugin("phy-rx-eom-log", "phy-rx-eom", argc, argv);
}

static int self_test_log(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	return forward_to_log_plugin("self-test-log", "self-test", argc, argv);
}

static int get_fid_support_effects_log(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	return forward_to_log_plugin("fid-support-effects-log", "fid-support-effects", argc, argv);
}

static int get_mi_cmd_support_effects_log(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	return forward_to_log_plugin("mi-cmd-support-effects-log", "mi-cmd-support-effects", argc, argv);
}

static int get_media_unit_stat_log(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	return forward_to_log_plugin("media-unit-stat-log", "media-unit-stat", argc, argv);
}

static int get_supp_cap_config_log(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	return forward_to_log_plugin("supported-cap-config-log", "supported-cap-config", argc, argv);
}

static int get_mgmt_addr_list_log(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	return forward_to_log_plugin("mgmt-addr-list-log", "mgmt-addr-list", argc, argv);
}

static int get_rotational_media_info_log(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	return forward_to_log_plugin("rotational-media-info-log", "rotational-media-info", argc, argv);
}

static int get_changed_alloc_ns_list_log(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	return forward_to_log_plugin("changed-alloc-ns-list-log", "changed-alloc-ns-list", argc, argv);
}

static int get_dispersed_ns_participating_nss_log(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	return forward_to_log_plugin("dispersed-ns-participating-nss-log", "dispersed-ns-participating-nss", argc, argv);
}

static int get_reachability_groups_log(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	return forward_to_log_plugin("reachability-groups-log", "reachability-groups", argc, argv);
}

static int get_reachability_associations_log(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	return forward_to_log_plugin("reachability-associations-log", "reachability-associations", argc, argv);
}

static int get_host_discovery_log(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	return forward_to_log_plugin("host-discovery-log", "host-discovery", argc, argv);
}

static int get_ave_discovery_log(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	return forward_to_log_plugin("ave-discovery-log", "ave-discovery", argc, argv);
}

static int get_pull_model_ddc_req_log(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	return forward_to_log_plugin("pull-model-ddc-req-log", "pull-model-ddc-req", argc, argv);
}

static int get_power_measurement_log(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	return forward_to_log_plugin("power-measurement-log", "power-measurement", argc, argv);
}

static int sanitize_log(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	return forward_to_log_plugin("sanitize-log", "sanitize", argc, argv);
}

#endif /* CONFIG_DEPRECATED_CMDS */

#ifdef CONFIG_DEPRECATED_CMDS
static struct plugin *find_id_plugin(void)
{
	struct plugin *id = nvme.extensions->next;

	while (id && (!id->name || strcmp(id->name, "id")))
		id = id->next;

	return id;
}

static int forward_to_id_plugin(const char *old_name, const char *subcmd,
		int argc, char **argv)
{
	struct plugin *id = find_id_plugin();
	__cleanup_free char **sub_argv = NULL;

	if (!id) {
		fprintf(stderr, "ERROR: '%s' is deprecated and requires the 'id' plugin, which is not available in this build; use 'nvme id %s'\n",
			old_name, subcmd);
		return -ENOTTY;
	}

	fprintf(stderr, "WARNING: '%s' is deprecated and will be removed in the next major version, use 'nvme id %s' instead\n",
		old_name, subcmd);

	sub_argv = calloc(argc + 1, sizeof(*sub_argv));
	if (!sub_argv)
		return -ENOMEM;

	sub_argv[0] = (char *)id->name;
	sub_argv[1] = (char *)subcmd;
	memcpy(&sub_argv[2], &argv[1], (argc - 1) * sizeof(*argv));

	return handle_plugin(argc + 1, sub_argv, id);
}

static int id_ctrl(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	return forward_to_id_plugin("id-ctrl", "ctrl", argc, argv);
}

static int id_ns(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	return forward_to_id_plugin("id-ns", "ns", argc, argv);
}

static int id_ns_granularity(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	return forward_to_id_plugin("id-ns-granularity", "ns-granularity", argc, argv);
}

static int id_ns_lba_format(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	return forward_to_id_plugin("id-ns-lba-format", "ns-lba-format", argc, argv);
}

static int list_ns(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	return forward_to_id_plugin("list-ns", "ns-list", argc, argv);
}

static int list_ctrl(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	return forward_to_id_plugin("list-ctrl", "ctrl-list", argc, argv);
}

static int nvm_id_ctrl(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	return forward_to_id_plugin("nvm-id-ctrl", "nvm-ctrl", argc, argv);
}

static int nvm_id_ns(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	return forward_to_id_plugin("nvm-id-ns", "nvm-ns", argc, argv);
}

static int nvm_id_ns_lba_format(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	return forward_to_id_plugin("nvm-id-ns-lba-format", "nvm-ns-lba-format", argc, argv);
}

static int primary_ctrl_caps(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	return forward_to_id_plugin("primary-ctrl-caps", "primary-ctrl-caps", argc, argv);
}

static int list_secondary_ctrl(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	return forward_to_id_plugin("list-secondary", "secondary-ctrl-list", argc, argv);
}

static int cmd_set_independent_id_ns(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	return forward_to_id_plugin("cmdset-ind-id-ns", "ns-ind", argc, argv);
}

static int ns_descs(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	return forward_to_id_plugin("ns-descs", "ns-descs", argc, argv);
}

static int id_nvmset(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	return forward_to_id_plugin("id-nvmset", "nvmset", argc, argv);
}

static int id_uuid(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	return forward_to_id_plugin("id-uuid", "uuid", argc, argv);
}

static int id_iocs(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	return forward_to_id_plugin("id-iocs", "iocs", argc, argv);
}

static int id_domain(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	return forward_to_id_plugin("id-domain", "domain", argc, argv);
}

static int id_endurance_grp_list(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	return forward_to_id_plugin("list-endgrp", "endgrp-list", argc, argv);
}

#endif /* CONFIG_DEPRECATED_CMDS */

static int libnvme_mi(int argc, char **argv, __u8 admin_opcode, const char *desc)
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
	__cleanup_fd int fd = -1;
	int flags;
	__cleanup_huge struct libnvme_mem_huge mh = { 0, };
	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	__cleanup_nvme_transport_handle struct libnvme_transport_handle *hdl = NULL;
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
		flags = O_WRONLY | O_CREAT | O_TRUNC;
		fd = STDOUT_FILENO;
		send = false;
	}

	if (strlen(cfg.input_file)) {
		fd = shr_open_rawdata(cfg.input_file, flags, mode);
		if (fd < 0) {
			nvme_show_perror(cfg.input_file);
			return -EINVAL;
		}
	}

	if (cfg.data_len) {
		data = libnvme_alloc_huge(cfg.data_len, &mh);
		if (!data) {
			nvme_show_error("failed to allocate huge memory");
			return -ENOMEM;
		}

		if (send) {
			if (read(fd, data, cfg.data_len) < 0) {
				err = -errno;
				nvme_show_error("failed to read write buffer %s", libnvme_strerror(errno));
				return err;
			}
		}
	}

	struct libnvme_passthru_cmd cmd = {
		.opcode		= admin_opcode,
		.nsid		= cfg.namespace_id,
		.cdw10		= cfg.nmimt << 11 | 4,
		.cdw11		= cfg.opcode,
		.cdw12		= cfg.nmd0,
		.cdw13		= cfg.nmd1,
		.addr		= (__u64)(uintptr_t)data,
		.data_len	= cfg.data_len,
	};

	err = libnvme_exec_admin_passthru(hdl, &cmd);
	if (err) {
		nvme_show_err(err, "nmi_recv");
		return err;
	}

	result = cmd.result;
	nvme_show_verbose_result(
		"%s Command is Success and result: 0x%08x (status: 0x%02x, response: 0x%06x)",
		nvme_cmd_to_string(true, admin_opcode), result,
		result & 0xff, result >> 8);
	if (result & 0xff)
		nvme_show_verbose_result("status: %s",
					 libnvme_mi_status_to_string(result & 0xff));
	if (!send && strlen(cfg.input_file)) {
		if (write(fd, (void *)data, cfg.data_len) < 0)
			perror("failed to write data buffer");
	} else if (data && !send && !err) {
		d((unsigned char *)data, cfg.data_len, 16, 1);
	}

	return err;
}

static int nmi_recv(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc =
	    "Send a NVMe-MI Receive command to the specified device, return results.";

	return libnvme_mi(argc, argv, nvme_admin_nvme_mi_recv, desc);
}

static int nmi_send(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc = "Send a NVMe-MI Send command to the specified device, return results.";

	return libnvme_mi(argc, argv, nvme_admin_nvme_mi_send, desc);
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

#ifdef _WIN32
	/*
	 * Set stdout and stderr to binary mode to prevent Windows text-mode
	 * translation from converting LF to CRLF and corrupting binary output.
	 */
	_setmode(_fileno(stdout), O_BINARY);
	_setmode(_fileno(stderr), O_BINARY);
#endif

	nvme.extensions->parent = &nvme;
	if (argc < 2) {
		general_help(&builtin, NULL);
		return 0;
	}
	setlocale(LC_ALL, "");

	err = nvme_load_global_config();
	if (err)
		return err;

	err = shr_install_sigint_handler();
	if (err)
		return err;

	err = handle_plugin(argc, argv, nvme.extensions);
	if (err == -ENOTTY)
		general_help(&builtin, NULL);

	nvme_show_finish();

	return err ? 1 : 0;
}
