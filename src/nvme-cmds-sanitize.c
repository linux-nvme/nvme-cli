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

static const char *ish = "Ignore Shutdown (for NVMe-MI command)";
static const char dash[51] = {[0 ... 49] = '=', '\0'};
static const char space[51] = {[0 ... 49] = ' ', '\0'};

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

static struct command device_self_test_cmd = {
	.name = "device-self-test",
	.help = "Perform the necessary tests to observe the performance",
	.fn = device_self_test,
};

static struct command sanitize_cmd_cmd = {
	.name = "sanitize",
	.help = "Submit a sanitize command",
	.fn = sanitize_cmd,
};

static struct command sanitize_ns_cmd_cmd = {
	.name = "sanitize-ns",
	.help = "Submit a sanitize namespace command",
	.fn = sanitize_ns_cmd,
};

static struct command *commands[] = {
	&device_self_test_cmd,
	&sanitize_cmd_cmd,
	&sanitize_ns_cmd_cmd,
	NULL,
};

static void __attribute__((constructor)) register_group(void)
{
	plugin_add_group(&builtin, "Sanitize & Self-Test", commands);
}
