// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libnvme.
 * Copyright (c) 2026 SUSE Software Solutions
 *
 * Authors: Daniel Wagner <dwagner@suse.de>
 *
 * nvme-privsep-helper: issues the NVMe ioctls on behalf of an unprivileged
 * libnvme process. libnvme_privsep_spawn() starts it with the socket on
 * LIBNVME_PRIVSEP_FD. The helper interprets only the request headers. It
 * never parses the data returned by a device.
 */
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/socket.h>
#include <sys/stat.h>

#include <libnvme.h>

#include "privsep/privsep-proto.h"

#define MAX_HANDLES 64

static struct libnvme_transport_handle *handles[MAX_HANDLES];

/* libnvme_open() parses the numbers as int. */
static bool parse_number(const char **p)
{
	const char *s = *p;
	long val = 0;

	if (*s < '0' || *s > '9')
		return false;
	while (*s >= '0' && *s <= '9') {
		val = val * 10 + (*s++ - '0');
		if (val > INT_MAX)
			return false;
	}
	*p = s;

	return true;
}

/*
 * Accepts nvmeX, nvmeXnY and ngXnY, with an optional /dev/ prefix, and
 * the NVME_TEST_FD names, which select the test backend of libnvme_open()
 * used by the nvme-cli test suite.
 */
static bool valid_name(const char *name)
{
	const char *p;

	if (!strcmp(name, "NVME_TEST_FD") || !strcmp(name, "NVME_TEST_FD64"))
		return true;

	if (!strncmp(name, "/dev/", 5))
		name += 5;

	if (!strncmp(name, "nvme", 4)) {
		p = name + 4;
		if (!parse_number(&p))
			return false;
		if (!*p)
			return true;
	} else if (!strncmp(name, "ng", 2)) {
		p = name + 2;
		if (!parse_number(&p))
			return false;
	} else {
		return false;
	}

	if (*p++ != 'n' || !parse_number(&p))
		return false;

	return !*p;
}

struct reply {
	int status;
	__u32 len;
	__u64 result;
	const void *payload;
	const void *payload2;	/* sent after payload */
	__u32 len2;		/* included in len */
};

/* Page aligned buffers for the kernel, as nvme-cli would pass them. */
struct xfer {
	void *data;
	void *metadata;
};

static int handle_open(struct libnvme_global_ctx *ctx, const void *payload,
		__u32 len, struct reply *reply,
		struct libnvme_privsep_open_resp *open_resp)
{
	const struct libnvme_privsep_open *req = payload;
	struct libnvme_transport_handle *hdl;
	const char *name;
	size_t name_len;
	__u32 flags;
	int i, ret;

	if (len < sizeof(*req) + 1)
		return -EINVAL;

	name = (const char *)(req + 1);
	name_len = len - sizeof(*req);
	if (name_len > LIBNVME_PRIVSEP_MAX_NAME || name[name_len - 1] ||
	    strlen(name) != name_len - 1)
		return -EINVAL;

	flags = req->flags;
	if (flags & ~(__u32)(O_ACCMODE | O_EXCL))
		return -EINVAL;

	if (!valid_name(name))
		return -EINVAL;

	for (i = 0; i < MAX_HANDLES; i++)
		if (!handles[i])
			break;
	if (i == MAX_HANDLES)
		return -EMFILE;

	ret = libnvme_open(ctx, name, flags, &hdl);
	if (ret)
		return ret;

	handles[i] = hdl;
	if (libnvme_transport_handle_is_ctrl(hdl))
		open_resp->mode = S_IFCHR;
	else if (libnvme_transport_handle_is_ns(hdl))
		open_resp->mode = S_IFBLK;
	reply->result = i + 1;
	reply->len = sizeof(*open_resp);
	reply->payload = open_resp;

	return 0;
}

static struct libnvme_transport_handle *lookup(__u32 id)
{
	if (!id || id > MAX_HANDLES)
		return NULL;

	return handles[id - 1];
}

static int handle_close(__u32 id, __u32 len)
{
	struct libnvme_transport_handle *hdl = lookup(id);

	if (!hdl || len)
		return -EINVAL;

	libnvme_close(hdl);
	handles[id - 1] = NULL;

	return 0;
}

static int handle_passthru(__u32 op, __u32 id, void *payload, __u32 len,
		struct reply *reply, struct xfer *xfer)
{
	struct libnvme_transport_handle *hdl = lookup(id);
	struct libnvme_privsep_cmd *pcmd = payload;
	struct libnvme_passthru_cmd cmd;
	size_t xfer_len;
	bool write;

	if (!hdl || len < sizeof(*pcmd))
		return -EINVAL;

	libnvme_privsep_cmd_decode(&cmd, pcmd);
	if (cmd.data_len > LIBNVME_PRIVSEP_MAX_DATA ||
	    cmd.metadata_len > LIBNVME_PRIVSEP_MAX_DATA - cmd.data_len)
		return -EINVAL;

	write = cmd.opcode & 1;
	xfer_len = (size_t)cmd.data_len + cmd.metadata_len;
	if (len != sizeof(*pcmd) + (write ? xfer_len : 0))
		return -EINVAL;

	if (cmd.data_len) {
		xfer->data = libnvme_alloc(cmd.data_len);
		if (!xfer->data)
			return -ENOMEM;
		if (write)
			memcpy(xfer->data, pcmd + 1, cmd.data_len);
		cmd.addr = (__u64)(uintptr_t)xfer->data;
	}
	if (cmd.metadata_len) {
		xfer->metadata = libnvme_alloc(cmd.metadata_len);
		if (!xfer->metadata)
			return -ENOMEM;
		if (write)
			memcpy(xfer->metadata,
			       (char *)(pcmd + 1) + cmd.data_len,
			       cmd.metadata_len);
		cmd.metadata = (__u64)(uintptr_t)xfer->metadata;
	}

	if (op == LIBNVME_PRIVSEP_OP_ADMIN)
		reply->status = libnvme_exec_admin_passthru(hdl, &cmd);
	else
		reply->status = libnvme_exec_io_passthru(hdl, &cmd);
	reply->result = cmd.result;

	if (!write) {
		reply->len = xfer_len;
		reply->payload = xfer->data;
		reply->payload2 = xfer->metadata;
		reply->len2 = cmd.metadata_len;
	}

	return 0;
}

static int handle_device_op(__u32 op, __u32 id, const void *payload,
		__u32 len, struct reply *reply)
{
	struct libnvme_transport_handle *hdl = lookup(id);
	const struct libnvme_privsep_block_size *bs = payload;
	__u32 nsid;

	if (!hdl)
		return -EINVAL;
	if (len != (op == LIBNVME_PRIVSEP_OP_UPDATE_BLOCK_SIZE ?
		    sizeof(*bs) : 0))
		return -EINVAL;

	switch (op) {
	case LIBNVME_PRIVSEP_OP_RESET_CTRL:
		reply->status = libnvme_reset_ctrl(hdl);
		break;
	case LIBNVME_PRIVSEP_OP_RESET_SUBSYSTEM:
		reply->status = libnvme_reset_subsystem(hdl);
		break;
	case LIBNVME_PRIVSEP_OP_RESCAN_NS:
		reply->status = libnvme_rescan_ns(hdl);
		break;
	case LIBNVME_PRIVSEP_OP_GET_NSID:
		reply->status = libnvme_get_nsid(hdl, &nsid);
		if (!reply->status)
			reply->result = nsid;
		break;
	case LIBNVME_PRIVSEP_OP_REREAD_PARTITIONS:
		reply->status = libnvme_reread_partitions(hdl);
		break;
	case LIBNVME_PRIVSEP_OP_UPDATE_BLOCK_SIZE:
		reply->status = libnvme_update_block_size(hdl,
							  bs->block_size);
		break;
	}

	return 0;
}

static void close_handles(void)
{
	int i;

	for (i = 0; i < MAX_HANDLES; i++) {
		libnvme_close(handles[i]);
		handles[i] = NULL;
	}
}

/* Return: 0 to continue, a negative error code to terminate the helper. */
static int serve_one(struct libnvme_global_ctx *ctx, int sock, bool *hello)
{
	struct libnvme_privsep_open_resp open_resp = {};
	struct libnvme_privsep_resp resp;
	struct libnvme_privsep_req req;
	struct reply reply = {};
	struct xfer xfer = {};
	void *payload = NULL;
	__u32 op, id, len;
	int ret;

	ret = libnvme_privsep_recv(sock, &req, sizeof(req));
	if (ret)
		return ret;

	op = req.op;
	id = req.id;
	len = req.len;

	if (len > LIBNVME_PRIVSEP_MAX_PAYLOAD)
		return -EMSGSIZE;
	if (len) {
		payload = malloc(len);
		if (!payload)
			return -ENOMEM;
		ret = libnvme_privsep_recv(sock, payload, len);
		if (ret)
			goto out;
	}

	if (!*hello && op != LIBNVME_PRIVSEP_OP_HELLO) {
		ret = -EPROTO;
		goto out;
	}

	switch (op) {
	case LIBNVME_PRIVSEP_OP_HELLO:
		*hello = true;
		reply.result = LIBNVME_PRIVSEP_VERSION;
		ret = 0;
		break;
	case LIBNVME_PRIVSEP_OP_OPEN:
		ret = handle_open(ctx, payload, len, &reply, &open_resp);
		break;
	case LIBNVME_PRIVSEP_OP_CLOSE:
		ret = handle_close(id, len);
		break;
	case LIBNVME_PRIVSEP_OP_ADMIN:
	case LIBNVME_PRIVSEP_OP_IO:
		ret = handle_passthru(op, id, payload, len, &reply, &xfer);
		break;
	case LIBNVME_PRIVSEP_OP_RESET_CTRL:
	case LIBNVME_PRIVSEP_OP_RESET_SUBSYSTEM:
	case LIBNVME_PRIVSEP_OP_RESCAN_NS:
	case LIBNVME_PRIVSEP_OP_GET_NSID:
	case LIBNVME_PRIVSEP_OP_REREAD_PARTITIONS:
	case LIBNVME_PRIVSEP_OP_UPDATE_BLOCK_SIZE:
		ret = handle_device_op(op, id, payload, len, &reply);
		break;
	default:
		ret = -EOPNOTSUPP;
		break;
	}

	if (ret)
		reply = (struct reply) { .status = ret };

	resp = (struct libnvme_privsep_resp) {
		.status = reply.status,
		.len = reply.len,
		.result = reply.result,
	};
	ret = libnvme_privsep_send(sock, &resp, sizeof(resp));
	if (!ret && reply.len > reply.len2)
		ret = libnvme_privsep_send(sock, reply.payload,
					   reply.len - reply.len2);
	if (!ret && reply.len2)
		ret = libnvme_privsep_send(sock, reply.payload2, reply.len2);

out:
	libnvme_free(xfer.data);
	libnvme_free(xfer.metadata);
	free(payload);

	return ret;
}

/* Keep device descriptors off 0-2 when the caller had them closed. */
static void open_stdio(void)
{
	int fd;

	do {
		fd = open("/dev/null", O_RDWR);
	} while (fd >= 0 && fd <= STDERR_FILENO);
	if (fd >= 0)
		close(fd);
}

int main(int argc, char **argv)
{
	struct libnvme_global_ctx *ctx;
	bool hello = false;
	struct stat st;
	int ret;

	open_stdio();

	if (argc != 1 || fstat(LIBNVME_PRIVSEP_FD, &st) ||
	    !S_ISSOCK(st.st_mode)) {
		fprintf(stderr,
			"%s: started without libnvme_privsep_spawn()\n",
			argv[0]);
		return EXIT_FAILURE;
	}

	ctx = libnvme_create_global_ctx();
	if (!ctx)
		return EXIT_FAILURE;

	do {
		ret = serve_one(ctx, LIBNVME_PRIVSEP_FD, &hello);
	} while (!ret);

	close_handles();
	libnvme_free_global_ctx(ctx);

	return ret == -EPIPE ? EXIT_SUCCESS : EXIT_FAILURE;
}
