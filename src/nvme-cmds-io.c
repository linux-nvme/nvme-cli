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

#include <libnvme-mi.h>
#include <libnvme.h>

#include <ccan/array_size/array_size.h>
#include <ccan/endian/endian.h>
#include <ccan/minmax/minmax.h>
#include <shared/compiler-attributes-util.h>
#include <shared/fs-util.h>
#include <shared/mmio-util.h>
#include <shared/parse-util.h>
#include <shared/sig-util.h>
#include <shared/suffix-util.h>
#include <shared/time-util.h>

#include "argconfig.h"
#include "cleanup.h"
#include "global-ctx.h"
#include "nvme-print.h"
#include "plugin.h"

static const char *app_tag = "app tag for end-to-end PI";
static const char *app_tag_mask = "app tag mask for end-to-end PI";
static const char *block_count = "number of blocks (zeroes based) on device to access";
static const char *dspec_w_dtype = "directive specification associated with directive type";
static const char *dtype = "directive type";
static const char *force_unit_access = "force device to commit data before command completes";
static const char *latency = "output latency statistics";
static const char *limited_retry = "limit media access attempts";
static const char *namespace_desired = "desired namespace";
static const char *prinfo = "PI and check field";
static const char *ref_tag = "reference tag for end-to-end PI";
static const char *start_block = "64-bit LBA of first block to access";
static const char *storage_tag = "storage tag for end-to-end PI";
static const char *storage_tag_check = "This bit specifies if the Storage Tag field shall be checked as\n"
	"part of end-to-end data protection processing";
static const char *ish = "Ignore Shutdown (for NVMe-MI command)";

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
		__u64	ilbrt;
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

static struct command dsm_cmd = {
	.name = "dsm",
	.help = "Submit a Data Set Management command, return results",
	.fn = dsm,
};

static struct command copy_cmd_cmd = {
	.name = "copy",
	.help = "Submit a Simple Copy command, return results",
	.fn = copy_cmd,
};

static struct command flush_cmd_cmd = {
	.name = "flush",
	.help = "Submit a Flush command, return results",
	.fn = flush_cmd,
};

static struct command compare_cmd = {
	.name = "compare",
	.help = "Submit a Compare command, return results",
	.fn = compare,
};

static struct command read_cmd_cmd = {
	.name = "read",
	.help = "Submit a read command, return results",
	.fn = read_cmd,
};

static struct command write_cmd_cmd = {
	.name = "write",
	.help = "Submit a write command, return results",
	.fn = write_cmd,
};

static struct command write_zeroes_cmd = {
	.name = "write-zeroes",
	.help = "Submit a write zeroes command, return results",
	.fn = write_zeroes,
};

static struct command write_uncor_cmd = {
	.name = "write-uncor",
	.help = "Submit a write uncorrectable command, return results",
	.fn = write_uncor,
};

static struct command verify_cmd_cmd = {
	.name = "verify",
	.help = "Submit a verify command, return results",
	.fn = verify_cmd,
};

static struct command get_lba_status_cmd = {
	.name = "get-lba-status",
	.help = "Submit a Get LBA Status command, return results",
	.fn = get_lba_status,
};

static struct command capacity_mgmt_cmd = {
	.name = "capacity-mgmt",
	.help = "Submit Capacity Management Command, return results",
	.fn = capacity_mgmt,
};

static struct command *commands[] = {
	&dsm_cmd,
	&copy_cmd_cmd,
	&flush_cmd_cmd,
	&compare_cmd,
	&read_cmd_cmd,
	&write_cmd_cmd,
	&write_zeroes_cmd,
	&write_uncor_cmd,
	&verify_cmd_cmd,
	&get_lba_status_cmd,
	&capacity_mgmt_cmd,
	NULL,
};

static void __shr_constructor register_group(void)
{
	plugin_add_group(&builtin, "I/O Commands", commands);
}
