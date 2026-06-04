// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libnvme.
 * Copyright (c) 2020 Western Digital Corporation or its affiliates.
 *
 * Authors: Keith Busch <keith.busch@wdc.com>
 *	    Chaitanya Kulkarni <chaitanya.kulkarni@wdc.com>
 *	    Daniel Wagner <dwagner@suse.de>
 */
#include <errno.h>
#include <stdlib.h>

#include <liburing.h>

#include <libnvme.h>

#include "private.h"
#include "compiler-attributes.h"

/*
 * should not exceed CAP.MQES, 16 is rational for most ssd
 */
#define NVME_URING_ENTRIES 16

struct libnvme_async_req {
	struct libnvme_passthru_cmd *cmd;
	void *cookie;
	void *user_data;
	unsigned int cmd_op;
	struct libnvme_async_req *next;
};

static int libnvme_probe_uring(void)
{
	struct io_uring_probe *probe;
	int err = 0;

	probe = io_uring_get_probe();
	if (!probe)
		return -ENOTSUP;

	if (!io_uring_opcode_supported(probe, IORING_OP_URING_CMD))
		err = -ENOTSUP;

	io_uring_free_probe(probe);
	return err;
}

int libnvme_open_uring(struct libnvme_transport_handle *hdl)
{
	struct io_uring *ring;

	if (hdl->ring)
		return 0;

	ring = calloc(1, sizeof(*ring));
	if (!ring)
		return -ENOMEM;

	if (io_uring_queue_init(NVME_URING_ENTRIES, ring,
			IORING_SETUP_SQE128 | IORING_SETUP_CQE32)) {
		free(ring);
		return -ENOTSUP;
	}

	hdl->ring = ring;
	return 0;
}

static int nvme_submit_uring_cmd(struct libnvme_transport_handle *hdl,
				 struct libnvme_async_req *req)
{
	struct io_uring_sqe *sqe;
	int ret;

	sqe = io_uring_get_sqe(hdl->ring);
	if (!sqe)
		return -EAGAIN;

	memcpy(&sqe->cmd, req->cmd, sizeof(*req->cmd));

	sqe->fd = hdl->fd;
	sqe->opcode = IORING_OP_URING_CMD;
	sqe->cmd_op = req->cmd_op;
	io_uring_sqe_set_data(sqe, req);

	ret = io_uring_submit(hdl->ring);
	if (ret < 0)
		return -errno;

	return 0;
}

static struct libnvme_async_req *nvme_dequeue_dry_run_req(
		struct libnvme_transport_handle *hdl)
{
	struct libnvme_async_req *req = hdl->dry_run_head;

	if (!req)
		return NULL;

	hdl->dry_run_head = req->next;
	if (!hdl->dry_run_head)
		hdl->dry_run_tail = NULL;

	return req;
}

void libnvme_close_uring(struct libnvme_transport_handle *hdl)
{
	struct libnvme_passthru_completion completion;

	if (!hdl->ring)
		return;

	/* Drain any pending completions */
	while (hdl->uring_pending) {
		if (libnvme_reap_passthru(hdl, &completion))
			break;
	}

	io_uring_queue_exit(hdl->ring);
	free(hdl->ring);
	hdl->ring = NULL;
	hdl->uring_pending = 0;
}

int __libnvme_transport_handle_open_uring(struct libnvme_transport_handle *hdl)
{
	int err;

	switch (hdl->uring_state) {
	case LIBNVME_IO_URING_STATE_NOT_AVAILABLE:
		return -ENOTSUP;
	case LIBNVME_IO_URING_STATE_UNKNOWN:
		err = libnvme_probe_uring();
		if (err)
			goto no_uring;
		break;
	case LIBNVME_IO_URING_STATE_AVAILABLE:
		break;
	}

	err = libnvme_open_uring(hdl);
	if (err)
		goto no_uring;

	hdl->uring_state = LIBNVME_IO_URING_STATE_AVAILABLE;

	return 0;

no_uring:
	hdl->uring_state = LIBNVME_IO_URING_STATE_NOT_AVAILABLE;
	return err;
}

static int libnvme_submit_passthru(
		struct libnvme_transport_handle *hdl,
		unsigned long ioctl_cmd,
		struct libnvme_passthru_cmd *cmd, void *cookie)
{
	struct libnvme_async_req *req;
	int err;

	if (!hdl)
		return -ENODEV;

	if (hdl->uring_state == LIBNVME_IO_URING_STATE_NOT_AVAILABLE)
		return -ENOTSUP;

	if (hdl->uring_state == LIBNVME_IO_URING_STATE_UNKNOWN) {
		err = __libnvme_transport_handle_open_uring(hdl);
		if (err)
			return err;
	}

	if (hdl->uring_pending >= NVME_URING_ENTRIES)
		return -EAGAIN;

	if (!cmd->timeout_ms && hdl->timeout)
		cmd->timeout_ms = hdl->timeout;

	req = calloc(1, sizeof(*req));
	if (!req)
		return -ENOMEM;

	req->cmd = cmd;
	req->cookie = cookie;
	req->cmd_op = ioctl_cmd;
	req->user_data = hdl->submit_entry(hdl, cmd);
	hdl->uring_pending += 1;

	if (hdl->ctx->dry_run) {
		req->next = NULL;
		if (hdl->dry_run_tail)
			hdl->dry_run_tail->next = req;
		else
			hdl->dry_run_head = req;

		hdl->dry_run_tail = req;
		return 0;
	}

	err = nvme_submit_uring_cmd(hdl, req);
	if (err) {
		hdl->uring_pending -= 1;
		hdl->submit_exit(hdl, cmd, err, req->user_data);
		free(req);
		return err;
	}

	return 0;
}

__libnvme_public int libnvme_submit_admin_passthru(
		struct libnvme_transport_handle *hdl,
		struct libnvme_passthru_cmd *cmd, void *cookie)
{
	return libnvme_submit_passthru(hdl, LIBNVME_URING_CMD_ADMIN,
		cmd, cookie);
}

__libnvme_public int libnvme_submit_io_passthru(
		struct libnvme_transport_handle *hdl,
		struct libnvme_passthru_cmd *cmd, void *cookie)
{
	return libnvme_submit_passthru(hdl, LIBNVME_URING_CMD_IO,
		cmd, cookie);
}

__libnvme_public int libnvme_reap_passthru(
		struct libnvme_transport_handle *hdl,
		struct libnvme_passthru_completion *completion)
{
	struct libnvme_async_req *req;
	struct io_uring_cqe *cqe;
	int err;

	if (!hdl)
		return -ENODEV;

	if (!completion)
		return -EINVAL;

	if (hdl->uring_state == LIBNVME_IO_URING_STATE_NOT_AVAILABLE)
		return -ENOTSUP;

	req = nvme_dequeue_dry_run_req(hdl);
	if (req) {
		err = 0;
		goto complete;
	}

	if (!hdl->uring_pending)
		return -EAGAIN;

	for (;;) {
		err = io_uring_wait_cqe(hdl->ring, &cqe);
		if (err < 0)
			return -errno;

		req = io_uring_cqe_get_data(cqe);
		err = cqe->res;
		io_uring_cqe_seen(hdl->ring, cqe);
		if (!req)
			return -EIO;

		if (err < 0 && hdl->decide_retry(hdl, req->cmd, err)) {
			err = nvme_submit_uring_cmd(hdl, req);
			if (!err)
				continue;
		}

		break;
	}

complete:
	hdl->uring_pending -= 1;
	hdl->submit_exit(hdl, req->cmd, err, req->user_data);
	completion->cmd = req->cmd;
	completion->cookie = req->cookie;
	completion->status = err;
	free(req);

	return 0;
}

__libnvme_public int libnvme_wait_passthru(
		struct libnvme_transport_handle *hdl)
{
	struct libnvme_passthru_completion completion;
	int err, ret = 0;

	if (!hdl)
		return -ENODEV;

	if (hdl->uring_state == LIBNVME_IO_URING_STATE_NOT_AVAILABLE)
		return -ENOTSUP;

	while (hdl->uring_pending) {
		err = libnvme_reap_passthru(hdl, &completion);
		if (err)
			return err;
		if (!ret && completion.status)
			ret = completion.status;
	}

	return ret;
}
