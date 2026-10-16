// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libnvme.
 * Copyright (c) 2020 Western Digital Corporation or its affiliates.
 *
 * Authors: Keith Busch <keith.busch@wdc.com>
 * 	    Chaitanya Kulkarni <chaitanya.kulkarni@wdc.com>
 */
#include <stdint.h>
#include <string.h>

#include <libnvme.h>

#include "private.h"

void *__libnvme_submit_entry(struct libnvme_transport_handle *hdl,
		struct libnvme_passthru_cmd *cmd)
{
	return NULL;
}

void __libnvme_submit_exit(struct libnvme_transport_handle *hdl,
		struct libnvme_passthru_cmd *cmd, int err, void *user_data)
{
}

bool __libnvme_decide_retry(struct libnvme_transport_handle *hdl,
		struct libnvme_passthru_cmd *cmd, int err)
{
	return false;
}

/*
 * In dry-run mode an operation which changes the device is skipped and
 * succeeds. It only shows up in the debug log, like the passthru commands
 * which are skipped.
 */
bool __libnvme_dry_run(struct libnvme_transport_handle *hdl, const char *op)
{
	if (!hdl->ctx->dry_run)
		return false;

	libnvme_msg(hdl->ctx, LIBNVME_LOG_DEBUG, "dry-run: %s skipped\n", op);
	return true;
}

int __libnvme_exec_dry_run(struct libnvme_transport_handle *hdl,
		struct libnvme_passthru_cmd *cmd)
{
	void *user_data;

	/* The caller reads the data of a skipped read command. */
	if ((cmd->opcode & 0x3) == NVME_DATA_TFR_CTRL_TO_HOST) {
		if (cmd->addr)
			memset((void *)(uintptr_t)cmd->addr, 0, cmd->data_len);
		if (cmd->metadata)
			memset((void *)(uintptr_t)cmd->metadata, 0,
			       cmd->metadata_len);
	}

	user_data = hdl->submit_entry(hdl, cmd);
	hdl->submit_exit(hdl, cmd, 0, user_data);

	return 0;
}
