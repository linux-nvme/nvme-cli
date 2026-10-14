/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * This file is part of libnvme.
 * Copyright (c) 2026 SUSE Software Solutions
 *
 * Authors: Daniel Wagner <dwagner@suse.de>
 */
#pragma once

#include <errno.h>
#include <stddef.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <linux/types.h>

#include <nvme/lib-types.h>

/*
 * Wire protocol between libnvme and nvme-privsep-helper.
 *
 * The protocol is an ABI between a libnvme process and the helper it
 * spawned on the same host from the same build. All fields use the host
 * byte order, errno values and open() flags. The protocol is not meant to
 * cross a host boundary. The data and metadata buffers are passed through
 * as they are.
 *
 * Every request is a struct libnvme_privsep_req followed by len payload
 * bytes. Every response is a struct libnvme_privsep_resp followed by len
 * payload bytes. The helper answers the requests in order.
 *
 * ADMIN and IO requests carry a struct libnvme_privsep_cmd. Like the
 * kernel, the opcode bit 0 selects the data direction: host to controller
 * commands send the data and metadata buffers with the request, all other
 * commands get them back with the response.
 *
 * The other per-handle ops mirror the libnvme function of the same name.
 * The helper calls the function on its handle and returns the return
 * value as status.
 *
 * SED requests carry a struct libnvme_privsep_sed. The helper issues only
 * the IOC_OPAL_* ioctls which libnvme uses. All of them pass a fixed size
 * argument to the kernel and return nothing but the status.
 */

#define LIBNVME_PRIVSEP_VERSION		1

/* File descriptor of the socket in the helper process. */
#define LIBNVME_PRIVSEP_FD		3

#define LIBNVME_PRIVSEP_MAX_NAME	64
#define LIBNVME_PRIVSEP_MAX_REGS	4096
#define LIBNVME_PRIVSEP_MAX_DATA	(8 * 1024 * 1024)
#define LIBNVME_PRIVSEP_MAX_PAYLOAD	(LIBNVME_PRIVSEP_MAX_DATA + 4096)

enum libnvme_privsep_op {
	LIBNVME_PRIVSEP_OP_HELLO	= 1,
	LIBNVME_PRIVSEP_OP_OPEN		= 2,
	LIBNVME_PRIVSEP_OP_CLOSE	= 3,
	LIBNVME_PRIVSEP_OP_ADMIN	= 4,
	LIBNVME_PRIVSEP_OP_IO		= 5,
	LIBNVME_PRIVSEP_OP_RESET_CTRL	= 6,
	LIBNVME_PRIVSEP_OP_RESET_SUBSYSTEM = 7,
	LIBNVME_PRIVSEP_OP_RESCAN_NS	= 8,
	LIBNVME_PRIVSEP_OP_GET_NSID	= 9,	/* result: nsid */
	LIBNVME_PRIVSEP_OP_REREAD_PARTITIONS = 10,
	LIBNVME_PRIVSEP_OP_UPDATE_BLOCK_SIZE = 11,
	LIBNVME_PRIVSEP_OP_READ_REGS	= 12,	/* response: the registers */
	LIBNVME_PRIVSEP_OP_WRITE_REG32	= 13,
	LIBNVME_PRIVSEP_OP_WRITE_REG64	= 14,
	LIBNVME_PRIVSEP_OP_SED		= 15,
};

struct libnvme_privsep_req {
	__u32 op;
	__u32 id;	/* helper handle id, 0 for HELLO and OPEN */
	__u32 len;
	__u32 rsvd;
};

struct libnvme_privsep_resp {
	__s32 status;	/* 0, an NVMe status or a negative errno */
	__u32 len;
	__u64 result;	/* HELLO: version, OPEN: handle id, else CQE result */
};

/* OPEN payload: followed by the NUL-terminated device name. */
struct libnvme_privsep_open {
	__u32 flags;
	__u32 rsvd;
};

/* OPEN response payload. */
struct libnvme_privsep_open_resp {
	__u32 mode;	/* S_IFCHR, S_IFBLK or 0 */
	__u32 rsvd;
};

/* UPDATE_BLOCK_SIZE payload. */
struct libnvme_privsep_block_size {
	__s32 block_size;
	__u32 rsvd;
};

/* READ_REGS, WRITE_REG32 and WRITE_REG64 payload. */
struct libnvme_privsep_reg {
	__u64 value;	/* WRITE_REG32 and WRITE_REG64 */
	__u32 offset;
	__u32 len;	/* READ_REGS, at most LIBNVME_PRIVSEP_MAX_REGS */
	__u32 mmio32;	/* WRITE_REG64 */
	__u32 rsvd;
};

/* SED payload: followed by the argument of the ioctl request. */
struct libnvme_privsep_sed {
	__u32 request;
	__u32 rsvd;
};

struct libnvme_privsep_cmd {
	__u8 opcode;
	__u8 flags;
	__u16 rsvd1;
	__u32 nsid;
	__u32 cdw2;
	__u32 cdw3;
	__u32 cdw10;
	__u32 cdw11;
	__u32 cdw12;
	__u32 cdw13;
	__u32 cdw14;
	__u32 cdw15;
	__u32 timeout_ms;
	__u32 data_len;
	__u32 metadata_len;
};

static inline void libnvme_privsep_cmd_encode(struct libnvme_privsep_cmd *w,
		const struct libnvme_passthru_cmd *cmd, __u32 data_len,
		__u32 metadata_len)
{
	*w = (struct libnvme_privsep_cmd) {
		.opcode = cmd->opcode,
		.flags = cmd->flags,
		.nsid = cmd->nsid,
		.cdw2 = cmd->cdw2,
		.cdw3 = cmd->cdw3,
		.cdw10 = cmd->cdw10,
		.cdw11 = cmd->cdw11,
		.cdw12 = cmd->cdw12,
		.cdw13 = cmd->cdw13,
		.cdw14 = cmd->cdw14,
		.cdw15 = cmd->cdw15,
		.timeout_ms = cmd->timeout_ms,
		.data_len = data_len,
		.metadata_len = metadata_len,
	};
}

/* Does not set the addr and metadata buffer pointers. */
static inline void libnvme_privsep_cmd_decode(struct libnvme_passthru_cmd *cmd,
		const struct libnvme_privsep_cmd *w)
{
	*cmd = (struct libnvme_passthru_cmd) {
		.opcode = w->opcode,
		.flags = w->flags,
		.nsid = w->nsid,
		.cdw2 = w->cdw2,
		.cdw3 = w->cdw3,
		.cdw10 = w->cdw10,
		.cdw11 = w->cdw11,
		.cdw12 = w->cdw12,
		.cdw13 = w->cdw13,
		.cdw14 = w->cdw14,
		.cdw15 = w->cdw15,
		.timeout_ms = w->timeout_ms,
		.data_len = w->data_len,
		.metadata_len = w->metadata_len,
	};
}

static inline int libnvme_privsep_send(int sock, const void *buf, size_t len)
{
	const char *p = buf;

	while (len) {
		ssize_t n = send(sock, p, len, MSG_NOSIGNAL);

		if (n < 0) {
			if (errno == EINTR)
				continue;
			return -errno;
		}
		p += n;
		len -= n;
	}

	return 0;
}

/* Return: 0 on success, -EPIPE if the peer closed the socket. */
static inline int libnvme_privsep_recv(int sock, void *buf, size_t len)
{
	char *p = buf;

	while (len) {
		ssize_t n = recv(sock, p, len, 0);

		if (n < 0) {
			if (errno == EINTR)
				continue;
			return -errno;
		}
		if (!n)
			return -EPIPE;
		p += n;
		len -= n;
	}

	return 0;
}
