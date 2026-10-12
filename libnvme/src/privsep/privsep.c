// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libnvme.
 * Copyright (c) 2026 SUSE Software Solutions
 *
 * Authors: Daniel Wagner <dwagner@suse.de>
 */
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <shared/compiler-attributes-util.h>

#include <libnvme.h>
#include <libnvme-privsep.h>

#include "nvme/private.h"
#include "privsep-proto.h"

struct libnvme_privsep {
	int sock;
	pid_t pid;
	bool broken;
};

/* A decoded struct libnvme_privsep_resp. */
struct privsep_reply {
	int status;
	__u32 len;
	__u64 result;
};

/*
 * Sends one request and receives the response header. A failure leaves the
 * stream in an unknown state, so the channel is unusable afterwards.
 */
static int privsep_call(struct libnvme_privsep *ps, __u32 op, __u32 id,
		const void *p1, size_t l1, const void *p2, size_t l2,
		const void *p3, size_t l3, struct privsep_reply *reply)
{
	struct libnvme_privsep_req req = {
		.op = op,
		.id = id,
		.len = l1 + l2 + l3,
	};
	struct libnvme_privsep_resp resp;
	int ret;

	if (ps->broken)
		return -EPIPE;

	ret = libnvme_privsep_send(ps->sock, &req, sizeof(req));
	if (!ret && l1)
		ret = libnvme_privsep_send(ps->sock, p1, l1);
	if (!ret && l2)
		ret = libnvme_privsep_send(ps->sock, p2, l2);
	if (!ret && l3)
		ret = libnvme_privsep_send(ps->sock, p3, l3);
	if (!ret)
		ret = libnvme_privsep_recv(ps->sock, &resp, sizeof(resp));
	if (ret) {
		ps->broken = true;
		return ret;
	}

	reply->status = resp.status;
	reply->len = resp.len;
	reply->result = resp.result;

	return 0;
}

static int privsep_recv_payload(struct libnvme_privsep *ps, void *buf,
		size_t len)
{
	int ret;

	if (!len)
		return 0;

	ret = libnvme_privsep_recv(ps->sock, buf, len);
	if (ret)
		ps->broken = true;

	return ret;
}

static int privsep_check_len(struct libnvme_privsep *ps,
		struct privsep_reply *reply, size_t len)
{
	if (reply->len == len)
		return 0;

	ps->broken = true;
	return -EPROTO;
}

static void close_fds_from(int first)
{
#ifdef NVME_HAVE_CLOSE_RANGE
	if (!close_range(first, ~0U, 0))
		return;
#endif
	long max = sysconf(_SC_OPEN_MAX);
	int fd;

	if (max < 0)
		max = 65536;
	for (fd = first; fd < max; fd++)
		close(fd);
}

static int privsep_hello(struct libnvme_privsep *ps)
{
	struct privsep_reply reply;
	int ret;

	ret = privsep_call(ps, LIBNVME_PRIVSEP_OP_HELLO, 0, NULL, 0, NULL, 0,
			   NULL, 0, &reply);
	if (ret)
		return ret;
	ret = privsep_check_len(ps, &reply, 0);
	if (ret)
		return ret;
	if (reply.status)
		return reply.status < 0 ? reply.status : -EPROTO;
	if (reply.result != LIBNVME_PRIVSEP_VERSION)
		return -EPROTO;

	return 0;
}

__shr_public int libnvme_privsep_spawn(const char *helper,
		struct libnvme_privsep **psp)
{
	struct libnvme_privsep *ps;
	int sv[2];
	int ret;

	if (!helper)
		helper = LIBNVME_PRIVSEP_HELPER;

	ps = calloc(1, sizeof(*ps));
	if (!ps)
		return -ENOMEM;

	if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sv) < 0) {
		ret = -errno;
		free(ps);
		return ret;
	}

	ps->pid = fork();
	if (ps->pid < 0) {
		ret = -errno;
		close(sv[0]);
		close(sv[1]);
		free(ps);
		return ret;
	}

	if (!ps->pid) {
		/* dup2() clears FD_CLOEXEC on the new descriptor. */
		if (sv[1] == LIBNVME_PRIVSEP_FD) {
			if (fcntl(sv[1], F_SETFD, 0) < 0)
				_exit(127);
		} else if (dup2(sv[1], LIBNVME_PRIVSEP_FD) < 0) {
			_exit(127);
		}
		close_fds_from(LIBNVME_PRIVSEP_FD + 1);
		execl(helper, "nvme-privsep-helper", (char *)NULL);
		_exit(127);
	}

	close(sv[1]);
	ps->sock = sv[0];

	ret = privsep_hello(ps);
	if (ret) {
		libnvme_privsep_free(ps);
		return ret;
	}

	*psp = ps;
	return 0;
}

__shr_public void libnvme_privsep_free(struct libnvme_privsep *ps)
{
	if (!ps)
		return;

	close(ps->sock);
	while (waitpid(ps->pid, NULL, 0) < 0 && errno == EINTR)
		;
	free(ps);
}

__shr_public void libnvme_set_privsep(struct libnvme_global_ctx *ctx,
		struct libnvme_privsep *ps)
{
	ctx->privsep = ps;
}

int __libnvme_transport_handle_open_privsep(
		struct libnvme_transport_handle *hdl, const char *name,
		int flags)
{
	struct libnvme_privsep *ps = hdl->ctx->privsep;
	struct libnvme_privsep_open open_req = {
		.flags = flags,
	};
	struct libnvme_privsep_open_resp open_resp;
	struct privsep_reply reply;
	size_t len = strlen(name) + 1;
	int ret;

	if (len > LIBNVME_PRIVSEP_MAX_NAME)
		return -ENAMETOOLONG;

	hdl->type = LIBNVME_TRANSPORT_HANDLE_TYPE_PRIVSEP;
	hdl->fd = LIBNVME_INVALID_FD;
	hdl->uring_state = LIBNVME_IO_URING_STATE_NOT_AVAILABLE;

	ret = privsep_call(ps, LIBNVME_PRIVSEP_OP_OPEN, 0,
			   &open_req, sizeof(open_req), name, len, NULL, 0,
			   &reply);
	if (ret)
		return ret;
	if (reply.status) {
		ret = privsep_check_len(ps, &reply, 0);
		return ret ? ret : reply.status;
	}
	ret = privsep_check_len(ps, &reply, sizeof(open_resp));
	if (!ret)
		ret = privsep_recv_payload(ps, &open_resp, sizeof(open_resp));
	if (ret)
		return ret;

	hdl->privsep = ps;
	hdl->privsep_id = reply.result;
	hdl->stat.st_mode = open_resp.mode;

	return 0;
}

void __libnvme_transport_handle_close_privsep(
		struct libnvme_transport_handle *hdl)
{
	struct privsep_reply reply;

	if (hdl->privsep &&
	    !privsep_call(hdl->privsep, LIBNVME_PRIVSEP_OP_CLOSE,
			  hdl->privsep_id, NULL, 0, NULL, 0, NULL, 0, &reply))
		privsep_check_len(hdl->privsep, &reply, 0);

	free(hdl);
}

static int privsep_exec(struct libnvme_transport_handle *hdl, __u32 op,
		struct libnvme_passthru_cmd *cmd)
{
	struct libnvme_privsep *ps = hdl->privsep;
	void *data = (void *)(uintptr_t)cmd->addr;
	void *metadata = (void *)(uintptr_t)cmd->metadata;
	__u32 data_len = data ? cmd->data_len : 0;
	__u32 metadata_len = metadata ? cmd->metadata_len : 0;
	bool write = cmd->opcode & 1;
	struct libnvme_privsep_cmd pcmd;
	struct privsep_reply reply;
	int ret;

	if (data_len > LIBNVME_PRIVSEP_MAX_DATA ||
	    metadata_len > LIBNVME_PRIVSEP_MAX_DATA - data_len)
		return -EINVAL;

	libnvme_privsep_cmd_encode(&pcmd, cmd, data_len, metadata_len);

	if (write)
		ret = privsep_call(ps, op, hdl->privsep_id,
				   &pcmd, sizeof(pcmd), data, data_len,
				   metadata, metadata_len, &reply);
	else
		ret = privsep_call(ps, op, hdl->privsep_id,
				   &pcmd, sizeof(pcmd), NULL, 0, NULL, 0,
				   &reply);
	if (ret)
		return ret;

	ret = privsep_check_len(ps, &reply,
				write ? 0 : (size_t)data_len + metadata_len);
	if (!ret && !write) {
		ret = privsep_recv_payload(ps, data, data_len);
		if (!ret)
			ret = privsep_recv_payload(ps, metadata, metadata_len);
	}
	if (ret)
		return ret;

	cmd->result = reply.result;
	return reply.status;
}

static int privsep_passthru(struct libnvme_transport_handle *hdl, __u32 op,
		struct libnvme_passthru_cmd *cmd)
{
	void *user_data;
	int err;

	user_data = hdl->submit_entry(hdl, cmd);

	do {
		err = privsep_exec(hdl, op, cmd);
		if (err >= 0 || hdl->privsep->broken)
			break;
	} while (hdl->decide_retry(hdl, cmd, err));

	hdl->submit_exit(hdl, cmd, err, user_data);
	return err;
}

int __libnvme_privsep_admin_passthru(struct libnvme_transport_handle *hdl,
		struct libnvme_passthru_cmd *cmd)
{
	return privsep_passthru(hdl, LIBNVME_PRIVSEP_OP_ADMIN, cmd);
}

int __libnvme_privsep_io_passthru(struct libnvme_transport_handle *hdl,
		struct libnvme_passthru_cmd *cmd)
{
	return privsep_passthru(hdl, LIBNVME_PRIVSEP_OP_IO, cmd);
}
