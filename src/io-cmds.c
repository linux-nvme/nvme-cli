// SPDX-License-Identifier: GPL-2.0-or-later
#include <libgen.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <ccan/endian/endian.h>
#include <ccan/minmax/minmax.h>
#include <ccan/array_size/array_size.h>
#include <cleanup.h>
#include <fs-util.h>
#include <time-util.h>
#include <parse-util.h>
#include "io-cmds.h"
#include "nvme-print.h"
#include "global-ctx.h"
#include "plugin.h"

static const char *dspec_w_dtype =
	"directive specification associated with directive type";
static const char *dtype = "directive type";
static const char *limited_retry = "limit media access attempts";
static const char *start_block = "64-bit LBA of first block to access";

const char *app_tag = "app tag for end-to-end PI";
const char *app_tag_mask = "app tag mask for end-to-end PI";
const char *block_count = "number of blocks (zeroes based) on device to access";
const char *force_unit_access =
	"force device to commit data before command completes";
const char *prinfo = "PI and check field";
const char *ref_tag = "reference tag for end-to-end PI";
const char *storage_tag = "storage tag for end-to-end PI";
const char *storage_tag_check =
	"This bit specifies if the Storage Tag field shall be checked as\n"
	"part of end-to-end data protection processing";

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

static int open_fallback_chardev(struct libnvme_global_ctx *ctx,
				 __u32 nsid,
				 struct libnvme_transport_handle **phdl)
{
	struct libnvme_transport_handle *hdl = *phdl;
	int err;

	__cleanup_free char *cdev = NULL;

	if (!libnvme_transport_handle_is_ctrl(hdl))
		return 0;

	if (!nsid) {
		nvme_show_error(
		    "controller device not supported without --namespace-id");
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

	return 0;
}

int submit_io(int opcode, char *command, const char *desc, int argc,
	      char **argv)
{
	__cleanup_nvme_transport_handle struct libnvme_transport_handle *hdl =
		NULL;
	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	unsigned long long buffer_size = 0, mbuffer_size = 0;

	__cleanup_free struct nvme_nvm_id_ns *nvm_ns = NULL;

	__cleanup_huge struct libnvme_mem_huge mh = { 0, };
	__cleanup_free struct nvme_id_ns *ns = NULL;
	unsigned int lbads = 0;
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

	const char *slba = "64-bit addr of first block to access";
	const char *lbads_desc = "if specified, logical block size in bytes;\n"
		"discovered by identify namespace otherwise";
	const char *ds = "size of data in bytes";
	const char *ms_desc = "size of metadata in bytes";
	const char *data = "data file";
	const char *md = "metadata file";
	const char *lr = "limit num. media access attempts";
	const char *show = "show command before sending";
	const char *dtype = "directive type (for write-only)";
	const char *dspec = "directive specific (for write-only)";
	const char *dsm = "dataset management attributes (lower 8 bits)";
	const char *force = "The \"I know what I'm doing\" flag,\n"
		"do not enforce exclusive access for write";

	struct config {
		__u32 nsid;
		__u64 slba;
		__u16 nlb;
		__u16 lbads;
		__u64 ds;
		__u64 ms;
		__u64 ilbrt;
		char *data;
		char *md;
		__u8 prinfo;
		__u16 lbatm;
		__u16 lbat;
		__u64 lbst;
		bool lr;
		bool fua;
		bool stc;
		__u8 dtype;
		__u16 dspec;
		__u8 dsmgmt;
		bool show;
		bool latency;
		bool force;
	};

	struct config cfg = { 0 };

	NVME_ARGS(opts,
	    OPT_UINT("namespace-id", 'n', &cfg.nsid, namespace_id_desired),
	    OPT_SUFFIX("start-block", 's', &cfg.slba, slba),
	    OPT_SHRT("block-count", 'c', &cfg.nlb, block_count),
	    OPT_SHRT("block-size", 'b', &cfg.lbads, lbads_desc),
	    OPT_SUFFIX("data-size", 'z', &cfg.ds, ds),
	    OPT_SUFFIX("metadata-size", 'y', &cfg.ms, ms_desc),
	    OPT_SUFFIX("ref-tag", 'r', &cfg.ilbrt, ref_tag),
	    OPT_FILE("data", 'd', &cfg.data, data),
	    OPT_FILE("metadata", 'M', &cfg.md, md),
	    OPT_BYTE("prinfo", 'p', &cfg.prinfo, prinfo),
	    OPT_SHRT("app-tag-mask", 'm', &cfg.lbatm, app_tag_mask),
	    OPT_SHRT("app-tag", 'a', &cfg.lbat, app_tag),
	    OPT_SUFFIX("storage-tag", 'g', &cfg.lbst, storage_tag),
	    OPT_FLAG("limited-retry", 'l', &cfg.lr, lr),
	    OPT_FLAG("force-unit-access", 'f', &cfg.fua, force_unit_access),
	    OPT_FLAG("storage-tag-check", 'C', &cfg.stc, storage_tag_check),
	    OPT_BYTE("dir-type", 'T', &cfg.dtype, dtype),
	    OPT_SHRT("dir-spec", 'S', &cfg.dspec, dspec),
	    OPT_BYTE("dsm", 'D', &cfg.dsmgmt, dsm),
	    OPT_FLAG("show-command", 'V', &cfg.show, show),
	    OPT_FLAG("latency", 't', &cfg.latency, latency),
	    OPT_FLAG("force", 0, &cfg.force, force));

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
				nvme_show_error("Failed to open %s.",
						basename(argv[optind]));
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
			nvme_show_error("get-namespace-id: %s",
					libnvme_strerror(-err));
			return err;
		}
	}

	if (cfg.prinfo > 0xf)
		return err;

	dsmgmt = cfg.dsmgmt;
	control |= (cfg.prinfo << 10);
	if (cfg.lr)
		control |= NVME_IO_LR;
	if (cfg.fua)
		control |= NVME_IO_FUA;
	if (cfg.stc)
		control |= NVME_IO_STC;
	if (cfg.dtype) {
		if (cfg.dtype > 0xf) {
			nvme_show_error("Invalid directive type, %x",
					cfg.dtype);
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

	if (cfg.data && strlen(cfg.data)) {
		dfd = shr_open_rawdata(cfg.data, flags, mode);
		if (dfd < 0) {
			nvme_show_perror(cfg.data);
			return -EINVAL;
		}
	}

	if (cfg.md && strlen(cfg.md)) {
		mfd = shr_open_rawdata(cfg.md, flags, mode);
		if (mfd < 0) {
			nvme_show_perror(cfg.md);
			return -EINVAL;
		}
	}

	if (!cfg.ds) {
		nvme_show_error("data size not provided");
		return -EINVAL;
	}

	if (cfg.lbads) {
		lbads = cfg.lbads;
		ms = cfg.ms;
		pi_available = true;
	} else {
		err = get_pi_info(hdl, cfg.nsid, cfg.prinfo,
			cfg.ilbrt, cfg.lbst, &lbads, &ms);
		pi_available = err == 0;
	}

	buffer_size = ((long long)cfg.nlb + 1) * lbads;
	if (cfg.ds < buffer_size)
		nvme_show_error(
		    "Rounding data size to fit block count (%lld bytes)",
		    buffer_size);
	else
		buffer_size = cfg.ds;

	if (argconfig_parse_seen(opts, "block-count")) {
		/* Use the value provided */
		nblocks = cfg.nlb;
	} else {
		/*
		 * Get the required block count. Note this is a zeroes based
		 * value.
		 */
		nblocks = ((buffer_size + (lbads - 1)) / lbads) - 1;

		/* Update the data size based on the required block count */
		buffer_size = ((unsigned long long)nblocks + 1) * lbads;
	}

	buffer = libnvme_alloc_huge(buffer_size, &mh);
	if (!buffer) {
		nvme_show_error("failed to allocate huge memory");
		return -ENOMEM;
	}

	if (cfg.ms) {
		mbuffer_size = ((unsigned long long)cfg.nlb + 1) * ms;
		if (ms && cfg.ms < mbuffer_size)
			nvme_show_error(
			    "Rounding metadata size to fit block count (%lld bytes)",
			    mbuffer_size);
		else
			mbuffer_size = cfg.ms;

		mbuffer = malloc(mbuffer_size);
		if (!mbuffer)
			return -ENOMEM;
		memset(mbuffer, 0, mbuffer_size);
	}

	if (opcode & 1) {
		err = read(dfd, (void *)buffer, cfg.ds);
		if (err < 0) {
			err = -errno;
			nvme_show_error(
			    "failed to read data buffer from input file %s",
			    libnvme_strerror(errno));
			return err;
		}
	}

	if ((opcode & 1) && cfg.ms) {
		err = read(mfd, (void *)mbuffer, mbuffer_size);
		if (err < 0) {
			err = -errno;
			nvme_show_error(
			    "failed to read meta-data buffer from input file %s",
			    libnvme_strerror(errno));
			return err;
		}
	}

	if (cfg.show || nvme_args.dry_run) {
		nvme_show_result("opcode       : %02x", opcode);
		nvme_show_result("nsid         : %02x", cfg.nsid);
		nvme_show_result("flags        : %02x", 0);
		nvme_show_result("control      : %04x", control);
		nvme_show_result("nblocks      : %04x", nblocks);
		nvme_show_result("metadata     : %"PRIx64,
				 (uint64_t)(uintptr_t)mbuffer);
		nvme_show_result("addr         : %"PRIx64,
				 (uint64_t)(uintptr_t)buffer);
		nvme_show_result("slba         : %"PRIx64, (uint64_t)cfg.slba);
		nvme_show_result("dsmgmt       : %08x", dsmgmt);
		nvme_show_result("reftag       : %"PRIx64, (uint64_t)cfg.ilbrt);
		nvme_show_result("apptag       : %04x", cfg.lbat);
		nvme_show_result("appmask      : %04x", cfg.lbatm);
		nvme_show_result("storagetagcheck : %04x", cfg.stc);
		nvme_show_result("storagetag      : %"PRIx64,
				 (uint64_t)cfg.lbst);
		nvme_show_result("pif             : %02x", pif);
		nvme_show_result("sts             : %02x", sts);
	}
	if (nvme_args.dry_run)
		return 0;

	nvme_init_io(&cmd, opcode, cfg.nsid, cfg.slba, buffer,
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
		nvme_show_result(" latency: %s: %llu us", command,
				 shr_elapsed_utime(start_time, end_time));
	if (err) {
		nvme_show_err(err, "submit-io");
		return err;
	}

	if (!(opcode & 1) && write(dfd, (void *)buffer, buffer_size) < 0) {
		nvme_show_error(
		    "write: %s: failed to write buffer to output file",
		    libnvme_strerror(errno));
		err = -EINVAL;
	} else if (!(opcode & 1) && cfg.ms &&
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

int write_uncor(int argc, char **argv, struct command *acmd,
		struct plugin *plugin)
{
	const char *desc = "The Write Uncorrectable command is used to\n"
			   "set a range of logical blocks to invalid.";

	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;

	__cleanup_nvme_transport_handle struct libnvme_transport_handle *hdl =
		NULL;
	struct libnvme_passthru_cmd cmd;
	int err;

	struct config {
		__u32 namespace_id;
		__u64 start_block;
		__u16 block_count;
		__u8 dtype;
		__u16 dspec;
	};

	struct config cfg = { 0 };

	NVME_ARGS(opts,
	    OPT_UINT("namespace-id", 'n', &cfg.namespace_id, namespace_desired),
	    OPT_SUFFIX("start-block", 's', &cfg.start_block, start_block),
	    OPT_SHRT("block-count", 'c', &cfg.block_count, block_count),
	    OPT_BYTE("dir-type", 'T', &cfg.dtype, dtype),
	    OPT_SHRT("dir-spec", 'S', &cfg.dspec, dspec_w_dtype));

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	if (!cfg.namespace_id) {
		err = libnvme_get_nsid(hdl, &cfg.namespace_id);
		if (err < 0) {
			nvme_show_error("get-namespace-id: %s",
					libnvme_strerror(-err));
			return err;
		}
	}

	if (cfg.dtype > 0xf) {
		nvme_show_error("Invalid directive type, %x",	cfg.dtype);
		return -EINVAL;
	}

	nvme_init_write_uncorrectable(&cmd, cfg.namespace_id, cfg.start_block,
				      cfg.block_count, cfg.dtype << 4,
				      cfg.dspec);
	err = libnvme_exec_io_passthru(hdl, &cmd);
	if (err) {
		nvme_show_err(err, "write uncorrectable");
		return err;
	}

	nvme_show_verbose_result("NVME Write Uncorrectable Success");

	return err;
}

int write_zeroes(int argc, char **argv, struct command *acmd,
		 struct plugin *plugin)
{
	__cleanup_nvme_transport_handle struct libnvme_transport_handle *hdl =
		NULL;
	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	struct libnvme_passthru_cmd cmd;
	__u16 control = 0;
	int err;

	const char *desc = "The Write Zeroes command is used to\n"
		"set a range of logical blocks to zero.";
	const char *deac = "Set DEAC bit, requesting controller to\n"
		"deallocate specified logical blocks";
	const char *nsz = "Clear all logical blocks to\n"
		"zero in the entire namespace";

	struct config {
		__u32 nsid;
		__u64 start_block;
		__u16 block_count;
		__u8 dtype;
		bool deac;
		bool limited_retry;
		bool fua;
		__u8 prinfo;
		__u64 ilbrt;
		__u16 lbatm;
		__u16 lbat;
		__u64 lbst;
		bool stc;
		__u16 dspec;
		bool nsz;
	};

	struct config cfg = { 0 };

	NVME_ARGS(opts,
	    OPT_UINT("namespace-id", 'n', &cfg.nsid, namespace_desired),
	    OPT_SUFFIX("start-block", 's', &cfg.start_block, start_block),
	    OPT_SHRT("block-count", 'c', &cfg.block_count, block_count),
	    OPT_BYTE("dir-type", 'T', &cfg.dtype, dtype),
	    OPT_FLAG("deac", 'd', &cfg.deac, deac),
	    OPT_FLAG("limited-retry", 'l', &cfg.limited_retry, limited_retry),
	    OPT_FLAG("force-unit-access", 'f', &cfg.fua, force_unit_access),
	    OPT_BYTE("prinfo", 'p', &cfg.prinfo, prinfo),
	    OPT_SUFFIX("ref-tag", 'r', &cfg.ilbrt, ref_tag),
	    OPT_SHRT("app-tag-mask", 'm', &cfg.lbatm, app_tag_mask),
	    OPT_SHRT("app-tag", 'a', &cfg.lbat, app_tag),
	    OPT_SUFFIX("storage-tag", 'S', &cfg.lbst, storage_tag),
	    OPT_FLAG("storage-tag-check", 'C', &cfg.stc, storage_tag_check),
	    OPT_SHRT("dir-spec", 'D', &cfg.dspec, dspec_w_dtype),
	    OPT_FLAG("namespace-zeroes", 'Z', &cfg.nsz, nsz));

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
	if (cfg.fua)
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
			nvme_show_error("get-namespace-id: %s",
					libnvme_strerror(-err));
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
		    "All logical blocks in the entire namespace cleared to zero"
		    );
	else
		nvme_show_result("%d logical blocks cleared to zero",
				 cfg.block_count);

	return err;
}

int dsm(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc =
	    "The Dataset Management command is used by the host to\n"
	    "indicate attributes for ranges of logical blocks.\n"
	    "This includes attributes for discarding unused blocks, data read\n"
	    "and write frequency, access size, and other information\n"
	    "that may be used to optimize performance and reliability.";
	const char *blocks =
	    "Comma separated list of the number of blocks in each range";
	const char *starting_blocks =
	    "Comma separated list of the starting block in each range";
	const char *context_attrs =
	    "Comma separated list of the context attributes in each range";
	const char *ad = "Attribute Deallocate";
	const char *idw = "Attribute Integral Dataset for Write";
	const char *idr = "Attribute Integral Dataset for Read";
	const char *cdw11 = "All the command DWORD 11 attributes.\n"
	    "Use instead of specifying individual attributes";

	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	__cleanup_nvme_transport_handle struct libnvme_transport_handle *hdl =
		NULL;
	__cleanup_libnvme_free struct nvme_dsm_range *dsm = NULL;
	struct libnvme_passthru_cmd cmd;
	__u32 ctx_attrs[NVME_DSM_MAX_RANGES] = { 0 };
	__u32 nlbs[NVME_DSM_MAX_RANGES] = { 0 };
	__u64 slbas[NVME_DSM_MAX_RANGES] = { 0 };
	nvme_print_flags_t flags;
	uint16_t nc, nb, ns;
	int err;

	struct config {
		__u32 nsid;
		char *ctx_attrs;
		char *blocks;
		char *slbas;
		bool ad;
		bool idw;
		bool idr;
		__u32 cdw11;
	};

	struct config cfg = { 0 };

	NVME_ARGS(opts,
	    OPT_UINT("namespace-id", 'n', &cfg.nsid, namespace_id_desired),
	    OPT_LIST("ctx-attrs", 'a', &cfg.ctx_attrs, context_attrs),
	    OPT_LIST("blocks", 'b', &cfg.blocks, blocks),
	    OPT_LIST("slbs", 's', &cfg.slbas, starting_blocks),
	    OPT_FLAG("ad", 'd', &cfg.ad, ad),
	    OPT_FLAG("idw", 'w', &cfg.idw, idw),
	    OPT_FLAG("idr", 'r', &cfg.idr, idr),
	    OPT_UINT("cdw11", 'c', &cfg.cdw11, cdw11));

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	err = open_fallback_chardev(ctx, cfg.nsid, &hdl);
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

	if (!cfg.nsid) {
		err = libnvme_get_nsid(hdl, &cfg.nsid);
		if (err < 0) {
			nvme_show_error("get-namespace-id: %s",
					libnvme_strerror(-err));
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
	nvme_init_dsm(&cmd, cfg.nsid, nb, cfg.idr, cfg.idw, cfg.ad, dsm,
		      sizeof(*dsm) * nb);
	err = libnvme_exec_io_passthru(hdl, &cmd);
	if (err) {
		nvme_show_err(err, "data-set management");
		return err;
	}

	nvme_show_verbose_result("NVMe DSM: success");

	return err;
}

int copy_cmd(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc = "The Copy command is used by the host to copy data\n"
	    "from one or more source logical block ranges to a\n"
	    "single consecutive destination logical block range.";
	const char *d_sdlba = "64-bit addr of first destination logical block";
	const char *d_slbas =
	    "64-bit addr of first block per range (comma-separated list)";
	const char *d_nlbs = "number of blocks per range\n"
	    "(comma-separated list, zeroes-based values)";
	const char *d_snsids =
	    "source namespace identifier per range (comma-separated list)";
	const char *d_sopts = "source options per range (comma-separated list)";
	const char *d_lr = "limited retry";
	const char *d_fua = "force unit access";
	const char *d_prinfor =
	    "protection information and check field (read part)";
	const char *d_prinfow =
	    "protection information and check field (write part)";
	const char *d_ilbrt = "initial lba reference tag (write part)";
	const char *d_eilbrts =
	    "expected lba reference tags (read part, comma-separated list)";
	const char *d_lbat = "lba application tag (write part)";
	const char *d_elbats =
	    "expected lba application tags (read part, comma-separated list)";
	const char *d_lbatm = "lba application tag mask (write part)";
	const char *d_elbatms = "expected lba application tag masks\n"
	    "(read part, comma-separated list)";
	const char *d_dtype = "directive type (write part)";
	const char *d_dspec = "directive specific (write part)";
	const char *d_format = "source range entry format";

	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	__cleanup_nvme_transport_handle struct libnvme_transport_handle *hdl =
		NULL;
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
		__u32 nsid;
		__u64 sdlba;
		char *slbas;
		char *nlbs;
		char *snsids;
		char *sopts;
		bool lr;
		bool fua;
		__u8 prinfow;
		__u8 prinfor;
		__u64 ilbrt;
		char *eilbrts;
		__u16 lbat;
		char *elbats;
		__u16 lbatm;
		char *elbatms;
		__u8 dtype;
		__u16 dspec;
		__u8 format;
		__u64 lbst;
		bool stc;
	};

	struct config cfg = { 0 };

	NVME_ARGS(opts,
	    OPT_UINT("namespace-id", 'n', &cfg.nsid, namespace_id_desired),
	    OPT_SUFFIX("sdlba", 'd', &cfg.sdlba, d_sdlba),
	    OPT_LIST("slbs", 's', &cfg.slbas, d_slbas),
	    OPT_LIST("blocks", 'b', &cfg.nlbs, d_nlbs),
	    OPT_LIST("snsids", 'N', &cfg.snsids, d_snsids),
	    OPT_LIST("sopts", 'O', &cfg.sopts, d_sopts),
	    OPT_FLAG("limited-retry", 'l', &cfg.lr, d_lr),
	    OPT_FLAG("force-unit-access", 'f', &cfg.fua, d_fua),
	    OPT_BYTE("prinfow", 'p', &cfg.prinfow, d_prinfow),
	    OPT_BYTE("prinfor", 'P', &cfg.prinfor, d_prinfor),
	    OPT_SUFFIX("ref-tag", 'r', &cfg.ilbrt, d_ilbrt),
	    OPT_LIST("expected-ref-tags", 'R', &cfg.eilbrts, d_eilbrts),
	    OPT_SHRT("app-tag", 'a', &cfg.lbat, d_lbat),
	    OPT_LIST("expected-app-tags", 'A', &cfg.elbats, d_elbats),
	    OPT_SHRT("app-tag-mask", 'm', &cfg.lbatm, d_lbatm),
	    OPT_LIST("expected-app-tag-masks", 'M', &cfg.elbatms, d_elbatms),
	    OPT_BYTE("dir-type", 'T', &cfg.dtype, d_dtype),
	    OPT_SHRT("dir-spec", 'S', &cfg.dspec, d_dspec),
	    OPT_BYTE("format", 'F', &cfg.format, d_format),
	    OPT_SUFFIX("storage-tag", 't', &cfg.lbst, storage_tag),
	    OPT_FLAG("storage-tag-check", 'c', &cfg.stc, storage_tag_check));

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
		nrts = shr_parse_csv_u32(cfg.eilbrts, eilbrts.short_pi,
					 ARRAY_SIZE(eilbrts.short_pi));
		break;
	case 1:
	case 3:
		nrts = shr_parse_csv_u64(cfg.eilbrts, eilbrts.long_pi,
					 ARRAY_SIZE(eilbrts.long_pi));
		break;
	default:
		nvme_show_error("invalid format");
		return -EINVAL;
	}

	natms = shr_parse_csv_u16(cfg.elbatms, elbatms, ARRAY_SIZE(elbatms));
	nats = shr_parse_csv_u16(cfg.elbats, elbats, ARRAY_SIZE(elbats));

	nr = max(nb, max(ns, max(nrts, max(natms, nats))));
	if (cfg.format == 2 || cfg.format == 3) {
		if (nr != nids) {
			nvme_show_error(
			    "formats 2 and 3 require source namespace ids for each source range");
			return -EINVAL;
		}
	} else if (nids) {
		nvme_show_error(
		    "formats 0 and 1 do not support cross-namespace copy");
		return -EINVAL;
	}
	if (!nr || nr > 256) {
		nvme_show_error("invalid range");
		return -EINVAL;
	}

	if (!cfg.nsid) {
		err = libnvme_get_nsid(hdl, &cfg.nsid);
		if (err < 0) {
			nvme_show_error("get-namespace-id: %s",
					libnvme_strerror(-err));
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

	nvme_init_copy(&cmd, cfg.nsid, cfg.sdlba, nr, cfg.format, cfg.prinfor,
		       cfg.prinfow, 0, cfg.dtype, cfg.stc, cfg.stc, cfg.fua,
		       cfg.lr, 0, cfg.dspec, copy->f0);
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

int flush_cmd(int argc, char **argv, struct command *acmd,
	      struct plugin *plugin)
{
	const char *desc = "Commit data and metadata associated with\n"
	    "given namespaces to nonvolatile media. Applies to all commands\n"
	    "finished before the flush was submitted. Additional data may\n"
	    "also be flushed by the controller, from any namespace, depending\n"
	    "on controller and associated namespace status.";

	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	__cleanup_nvme_transport_handle struct libnvme_transport_handle *hdl =
		NULL;
	struct libnvme_passthru_cmd cmd = { 0 };
	int err;

	struct config {
		__u32 nsid;
	};

	struct config cfg = { 0 };

	NVME_ARGS(opts,
	    OPT_UINT("namespace-id", 'n', &cfg.nsid, namespace_id_desired));

	err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts);
	if (err)
		return err;

	err = open_fallback_chardev(ctx, cfg.nsid, &hdl);
	if (err)
		return err;

	if (!cfg.nsid) {
		err = libnvme_get_nsid(hdl, &cfg.nsid);
		if (err < 0) {
			nvme_show_error("get-namespace-id: %s",
					libnvme_strerror(-err));
			return err;
		}
	}

	cmd.opcode = nvme_cmd_flush;
	cmd.nsid = cfg.nsid;

	err = libnvme_exec_io_passthru(hdl, &cmd);
	if (err) {
		nvme_show_err(err, "flush");
		return err;
	}

	nvme_show_verbose_result("NVMe Flush: success");

	return err;
}

int compare(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc = "Compare specified logical blocks on\n"
	    "device with specified data buffer; return failure if buffer\n"
	    "and block(s) are dissimilar";

	return submit_io(nvme_cmd_compare, "compare", desc, argc, argv);
}

int read_cmd(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc = "Copy specified logical blocks on the given\n"
	    "device to specified data buffer (default buffer is stdout).";

	return submit_io(nvme_cmd_read, "read", desc, argc, argv);
}

int write_cmd(int argc, char **argv, struct command *acmd,
	      struct plugin *plugin)
{
	const char *desc = "Copy from provided data buffer (default\n"
	    "buffer is stdin) to specified logical blocks on the given device.";

	return submit_io(nvme_cmd_write, "write", desc, argc, argv);
}

int verify_cmd(int argc, char **argv, struct command *acmd,
	       struct plugin *plugin)
{
	__cleanup_nvme_transport_handle struct libnvme_transport_handle *hdl =
		NULL;
	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	struct libnvme_passthru_cmd cmd;
	__u16 control = 0;
	int err;

	const char *desc =
	    "Verify specified logical blocks on the given device.";
	const char *fua = "force device to commit cached data before\n"
	    "performing the verify operation";
	const char *storage_tag_check =
	    "This bit specifies the Storage Tag field shall be checked\n"
	    "as part of Verify operation";

	struct config {
		__u32 nsid;
		__u64 start_block;
		__u16 block_count;
		bool limited_retry;
		bool fua;
		__u8 prinfo;
		__u32 ilbrt;
		__u16 lbat;
		__u16 lbatm;
		__u64 lbst;
		bool stc;
	};

	struct config cfg = { 0 };

	NVME_ARGS(opts,
	    OPT_UINT("namespace-id", 'n', &cfg.nsid, namespace_desired),
	    OPT_SUFFIX("start-block", 's', &cfg.start_block, start_block),
	    OPT_SHRT("block-count", 'c', &cfg.block_count, block_count),
	    OPT_FLAG("limited-retry", 'l', &cfg.limited_retry, limited_retry),
	    OPT_FLAG("force-unit-access", 'f', &cfg.fua, fua),
	    OPT_BYTE("prinfo", 'p', &cfg.prinfo, prinfo),
	    OPT_SUFFIX("ref-tag", 'r', &cfg.ilbrt, ref_tag),
	    OPT_SHRT("app-tag", 'a', &cfg.lbat, app_tag),
	    OPT_SHRT("app-tag-mask", 'm', &cfg.lbatm, app_tag_mask),
	    OPT_SUFFIX("storage-tag", 'S', &cfg.lbst, storage_tag),
	    OPT_FLAG("storage-tag-check", 'C', &cfg.stc, storage_tag_check));

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
	if (cfg.fua)
		control |= NVME_IO_FUA;
	if (cfg.stc)
		control |= NVME_IO_STC;

	if (!cfg.nsid) {
		err = libnvme_get_nsid(hdl, &cfg.nsid);
		if (err < 0) {
			nvme_show_error("get-namespace-id: %s",
					libnvme_strerror(-err));
			return err;
		}
	}

	nvme_init_verify(&cmd, cfg.nsid, cfg.start_block, cfg.block_count,
			 control, 0, NULL, 0, NULL, 0);
	err = init_pi_tags(hdl, &cmd, cfg.nsid, cfg.ilbrt, cfg.lbst, cfg.lbat,
			   cfg.lbatm);
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
