/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "common.h"
#include "io-cmds.h"
#include "nvme.h"
#include "nvme-cmds.h"
#include "nvme-print.h"

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
	__u8 sts = 0, pif = 0;
	unsigned int lbs = 0;
	__u8 lba_index;
	int pi_size;
	__u16 ms;
	int err;

	ns = libnvme_alloc(sizeof(*ns));
	if (!ns)
		return -ENOMEM;

	err = nvme_identify_ns(hdl, nsid, ns);
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

	err = nvme_identify_csi_ns(hdl, nsid, NVME_CSI_NVM, 0, nvm_ns);
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
	const char *force =
		"The \"I know what I'm doing\" flag, do not enforce exclusive "
		"access for write";

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
		  OPT_UINT("namespace-id",      'n', &cfg.nsid,    namespace_id_desired),
		  OPT_SUFFIX("start-block",     's', &cfg.slba,    slba),
		  OPT_SHRT("block-count",       'c', &cfg.nlb,     block_count),
		  OPT_SHRT("block-size",        'b', &cfg.lbads,   lbads_desc),
		  OPT_SUFFIX("data-size",       'z', &cfg.ds,      ds),
		  OPT_SUFFIX("metadata-size",   'y', &cfg.ms,      ms_desc),
		  OPT_SUFFIX("ref-tag",         'r', &cfg.ilbrt,   ref_tag),
		  OPT_FILE("data",              'd', &cfg.data,    data),
		  OPT_FILE("metadata",          'M', &cfg.md,      md),
		  OPT_BYTE("prinfo",            'p', &cfg.prinfo,  prinfo),
		  OPT_SHRT("app-tag-mask",      'm', &cfg.lbatm,   app_tag_mask),
		  OPT_SHRT("app-tag",           'a', &cfg.lbat,    app_tag),
		  OPT_SUFFIX("storage-tag",     'g', &cfg.lbst,    storage_tag),
		  OPT_FLAG("limited-retry",     'l', &cfg.lr,      lr),
		  OPT_FLAG("force-unit-access", 'f', &cfg.fua,     force_unit_access),
		  OPT_FLAG("storage-tag-check", 'C', &cfg.stc,     storage_tag_check),
		  OPT_BYTE("dir-type",          'T', &cfg.dtype,   dtype),
		  OPT_SHRT("dir-spec",          'S', &cfg.dspec,   dspec),
		  OPT_BYTE("dsm",               'D', &cfg.dsmgmt,  dsm),
		  OPT_FLAG("show-command",      'V', &cfg.show,    show),
		  OPT_FLAG("latency",           't', &cfg.latency, latency),
		  OPT_FLAG("force",               0, &cfg.force,   force));

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
					    "Use the force [--force] option to "
					    "ignore that.");
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

	if (strlen(cfg.data)) {
		dfd = nvme_open_rawdata(cfg.data, flags, mode);
		if (dfd < 0) {
			nvme_show_perror(cfg.data);
			return -EINVAL;
		}
	}

	if (strlen(cfg.md)) {
		mfd = nvme_open_rawdata(cfg.md, flags, mode);
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
				 elapsed_utime(start_time, end_time));
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
