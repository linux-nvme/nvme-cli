// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libnvme.
 * Copyright (c) 2026 SUSE Software Solutions
 *
 * Authors: Daniel Wagner <dwagner@suse.de>
 */
#include <errno.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdnoreturn.h>
#include <string.h>

#include <libnvme.h>

#include "private.h"
#include "loopback.h"

static noreturn void loopback_fail(const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	vfprintf(stderr, fmt, args);
	va_end(args);
	fputc('\n', stderr);
	abort();
}

#define loopback_check(condition, fmt...) \
	((condition) || (loopback_fail(fmt), 0))

static void loopback_cmp(const void *actual, const void *expected, size_t len,
		const char *msg)
{
	if (len && memcmp(actual, expected, len) != 0)
		loopback_fail("%s", msg);
}

static int loopback_execute(struct libnvme_passthru_cmd *cmd,
		const struct libnvme_loopback_cmd *exp)
{
	void *data = (void *)(uintptr_t)cmd->addr;
	void *metadata = (void *)(uintptr_t)cmd->metadata;

	loopback_check(cmd->opcode == exp->opcode,
		"got opcode 0x%" PRIx8 ", expected 0x%" PRIx8,
		cmd->opcode, exp->opcode);
	loopback_check(cmd->flags == exp->flags,
		"got flags 0x%" PRIx8 ", expected 0x%" PRIx8,
		cmd->flags, exp->flags);
	loopback_check(cmd->nsid == exp->nsid,
		"got nsid 0x%" PRIx32 ", expected 0x%" PRIx32,
		cmd->nsid, exp->nsid);
	loopback_check(cmd->cdw2 == exp->cdw2,
		"got cdw2 0x%" PRIx32 ", expected 0x%" PRIx32,
		cmd->cdw2, exp->cdw2);
	loopback_check(cmd->cdw3 == exp->cdw3,
		"got cdw3 0x%" PRIx32 ", expected 0x%" PRIx32,
		cmd->cdw3, exp->cdw3);
	loopback_check(cmd->metadata_len == exp->metadata_len,
		"got metadata_len %" PRIu32 ", expected %" PRIu32,
		cmd->metadata_len, exp->metadata_len);
	if (cmd->metadata_len)
		loopback_cmp(metadata, exp->metadata, cmd->metadata_len,
			"incorrect metadata");
	loopback_check(cmd->data_len == exp->data_len,
		"got data_len %" PRIu32 ", expected %" PRIu32,
		cmd->data_len, exp->data_len);
	if (exp->in_data)
		loopback_cmp(data, exp->in_data, cmd->data_len,
			"incorrect data");
	loopback_check(cmd->cdw10 == exp->cdw10,
		"got cdw10 0x%" PRIx32 ", expected 0x%" PRIx32,
		cmd->cdw10, exp->cdw10);
	loopback_check(cmd->cdw11 == exp->cdw11,
		"got cdw11 0x%" PRIx32 ", expected 0x%" PRIx32,
		cmd->cdw11, exp->cdw11);
	loopback_check(cmd->cdw12 == exp->cdw12,
		"got cdw12 0x%" PRIx32 ", expected 0x%" PRIx32,
		cmd->cdw12, exp->cdw12);
	loopback_check(cmd->cdw13 == exp->cdw13,
		"got cdw13 0x%" PRIx32 ", expected 0x%" PRIx32,
		cmd->cdw13, exp->cdw13);
	loopback_check(cmd->cdw14 == exp->cdw14,
		"got cdw14 0x%" PRIx32 ", expected 0x%" PRIx32,
		cmd->cdw14, exp->cdw14);
	loopback_check(cmd->cdw15 == exp->cdw15,
		"got cdw15 0x%" PRIx32 ", expected 0x%" PRIx32,
		cmd->cdw15, exp->cdw15);
	loopback_check(cmd->timeout_ms == exp->timeout_ms,
		"got timeout_ms %" PRIu32 ", expected %" PRIu32,
		cmd->timeout_ms, exp->timeout_ms);

	cmd->result = exp->result;
	if (exp->out_data)
		memcpy(data, exp->out_data, exp->out_data_len ?: cmd->data_len);

	return exp->err;
}

static int loopback_passthru(const struct libnvme_loopback_cmd **cmds,
		size_t *remaining, const char *name,
		struct libnvme_passthru_cmd *cmd)
{
	const struct libnvme_loopback_cmd *exp;

	loopback_check(*remaining, "unexpected %s command", name);
	exp = (*cmds)++;
	(*remaining)--;

	return loopback_execute(cmd, exp);
}

int __libnvme_loopback_admin_passthru(struct libnvme_transport_handle *hdl,
		struct libnvme_passthru_cmd *cmd)
{
	return loopback_passthru(&hdl->loopback_admin_cmds,
		&hdl->loopback_admin_remaining, "admin", cmd);
}

int __libnvme_loopback_io_passthru(struct libnvme_transport_handle *hdl,
		struct libnvme_passthru_cmd *cmd)
{
	return loopback_passthru(&hdl->loopback_io_cmds,
		&hdl->loopback_io_remaining, "IO", cmd);
}

int libnvme_open_loopback(struct libnvme_global_ctx *ctx,
		struct libnvme_transport_handle **hdlp)
{
	struct libnvme_transport_handle *hdl;

	hdl = __libnvme_create_transport_handle(ctx);
	if (!hdl)
		return -ENOMEM;

	hdl->type = LIBNVME_TRANSPORT_HANDLE_TYPE_LOOPBACK;
	hdl->uring_state = LIBNVME_IO_URING_STATE_NOT_AVAILABLE;

	*hdlp = hdl;

	return 0;
}

void libnvme_loopback_set_admin_cmds(struct libnvme_transport_handle *hdl,
		const struct libnvme_loopback_cmd *cmds, size_t len)
{
	hdl->loopback_admin_cmds = cmds;
	hdl->loopback_admin_remaining = len;
}

void libnvme_loopback_set_io_cmds(struct libnvme_transport_handle *hdl,
		const struct libnvme_loopback_cmd *cmds, size_t len)
{
	hdl->loopback_io_cmds = cmds;
	hdl->loopback_io_remaining = len;
}

void libnvme_loopback_end(struct libnvme_transport_handle *hdl)
{
	loopback_check(!hdl->loopback_admin_remaining,
		"%zu admin commands not executed",
		hdl->loopback_admin_remaining);
	loopback_check(!hdl->loopback_io_remaining,
		"%zu IO commands not executed",
		hdl->loopback_io_remaining);
}
