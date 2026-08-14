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

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdint.h>
#include <unistd.h>

#include <sys/stat.h>

#include <libnvme.h>

#include <ccan/minmax/minmax.h>

#include <cleanup.h>
#include <shared/fs-util.h>

#include "argconfig.h"
#include "global-ctx.h"
#include "logging.h"
#include "nvme-print.h"
#include "plugin.h"

#define CREATE_CMD
#include "fw-plugin.h"

static const char *ish = "Ignore Shutdown (for NVMe-MI command)";

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
