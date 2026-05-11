// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libnvme.
 * Copyright (c) 2020 Western Digital Corporation or its affiliates.
 *
 * Authors: Keith Busch <keith.busch@wdc.com>
 *	    Chaitanya Kulkarni <chaitanya.kulkarni@wdc.com>
 *	    Daniel Wagner <dwagner@suse.de>
 */
#include <liburing.h>

#include <libnvme.h>

#include "private.h"
#include "compiler-attributes.h"

/*
 * should not exceed CAP.MQES, 16 is rational for most ssd
 */
#define NVME_URING_ENTRIES 16

int libnvme_open_uring(struct libnvme_global_ctx *ctx)
{
	struct io_uring_probe *probe;
	struct io_uring *ring;

	probe = io_uring_get_probe();
	if (!probe)
		return -ENOTSUP;

	if (!io_uring_opcode_supported(probe, IORING_OP_URING_CMD))
		return -ENOTSUP;

	ring = calloc(1, sizeof(*ring));
	if (!ring)
		return -ENOMEM;

	if (io_uring_queue_init(NVME_URING_ENTRIES, ring,
			IORING_SETUP_SQE128 | IORING_SETUP_CQE32)) {
		free(ring);
		return -errno;
	}

	ctx->ring = ring;
	return 0;
}

void libnvme_close_uring(struct libnvme_global_ctx *ctx)
{
	if (!ctx->ring)
		return;

	io_uring_queue_exit(ctx->ring);
	free(ctx->ring);
}

int __libnvme_transport_handle_open_uring(struct libnvme_transport_handle *hdl)
{
	int err;

	switch (hdl->ctx->uring_state) {
	case LIBNVME_IO_URING_STATE_NOT_AVAILABLE:
		return -ENOTSUP;
	case LIBNVME_IO_URING_STATE_AVAILABLE:
		goto uring_enabled;
	case LIBNVME_IO_URING_STATE_UNKNOWN:
		break;
	}

	err = libnvme_open_uring(hdl->ctx);
	if (err)
		return err;

uring_enabled:
	hdl->uring_enabled = true;

	return 0;
}

static int nvme_submit_uring_cmd(struct io_uring *ring, int fd,
		struct libnvme_passthru_cmd *cmd)
{
	struct io_uring_sqe *sqe;
	int ret;

	sqe = io_uring_get_sqe(ring);
	if (!sqe)
		return -1;

	memcpy(&sqe->cmd, cmd, sizeof(*cmd));

	sqe->fd = fd;
	sqe->opcode = IORING_OP_URING_CMD;
	sqe->cmd_op = LIBNVME_URING_CMD_ADMIN;

	ret = io_uring_submit(ring);
	if (ret < 0)
		return -errno;

	return 0;
}

__public int libnvme_wait_admin_passthru(struct libnvme_transport_handle *hdl)
{
	struct io_uring_cqe *cqe;
	struct io_uring *ring;
	int err;

	if (!hdl)
		return -ENODEV;

	ring = hdl->ctx->ring;

	for (int i = 0; i < hdl->ctx->ring_cmds; i++) {
		err = io_uring_wait_cqe(ring, &cqe);
		if (err < 0)
			return -errno;
		io_uring_cqe_seen(ring, cqe);
	}

	hdl->ctx->ring_cmds = 0;
	return 0;
}

int libnvme_submit_admin_passthru_async(struct libnvme_transport_handle *hdl,
		 struct libnvme_passthru_cmd *cmd)
{
	int err;

	if (hdl->ctx->ring_cmds >= NVME_URING_ENTRIES) {
		err = libnvme_wait_admin_passthru(hdl);
		if (err)
			return err;
	}

	err = nvme_submit_uring_cmd(hdl->ctx->ring, hdl->fd, cmd);
	if (err)
		return err;

	hdl->ctx->ring_cmds += 1;
	return 0;
}

__public int libnvme_wait_io_passthru(struct libnvme_transport_handle *hdl)
{
	return 0;
}
