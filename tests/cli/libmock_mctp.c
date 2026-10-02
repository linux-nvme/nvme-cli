// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * This file is part of nvme-cli.
 *
 * Copyright (c) 2026 Samsung Electronics Co., Ltd.
 *
 * Authors: Hyuntae Kim <h1219.kim@samsung.com>
 */

/*
 * Redirect an MCTP command socket to a Unix seqpacket peer. The real
 * libnvme MCTP transport still builds and validates the NVMe-MI messages.
 * Only the socket boundary is mocked; no libnvme API is interposed.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <dlfcn.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#ifndef AF_MCTP
#define AF_MCTP 45
#endif

static int mock_fd = -1;

int socket(int domain, int type, int protocol)
{
	int (*real_socket)(int domain, int type, int protocol) =
		dlsym(RTLD_NEXT, "socket");
	int (*real_close)(int fd) = dlsym(RTLD_NEXT, "close");
	const char *path = getenv("MOCK_MCTP_SOCK");
	struct sockaddr_un addr = { .sun_family = AF_UNIX };
	int fd, saved_errno;
	size_t path_len;

	if (domain != AF_MCTP || !path)
		return real_socket(domain, type, protocol);
	path_len = strlen(path);
	if (path_len >= sizeof(addr.sun_path)) {
		errno = ENAMETOOLONG;
		return -1;
	}
	if (mock_fd >= 0 || type != SOCK_DGRAM) {
		errno = EOPNOTSUPP;
		return -1;
	}

	fd = real_socket(AF_UNIX, SOCK_SEQPACKET, 0);
	if (fd < 0)
		return fd;
	memcpy(addr.sun_path, path, path_len + 1);
	if (connect(fd, (struct sockaddr *)&addr, sizeof(addr))) {
		saved_errno = errno;
		real_close(fd);
		errno = saved_errno;
		return -1;
	}
	mock_fd = fd;
	return fd;
}

ssize_t sendmsg(int fd, const struct msghdr *message, int flags)
{
	ssize_t (*real_sendmsg)(int fd, const struct msghdr *message,
				int flags) =
		dlsym(RTLD_NEXT, "sendmsg");
	struct msghdr msg = *message;

	if (fd == mock_fd) {
		msg.msg_name = NULL;
		msg.msg_namelen = 0;
	}
	return real_sendmsg(fd, &msg, flags);
}

ssize_t recvmsg(int fd, struct msghdr *message, int flags)
{
	ssize_t (*real_recvmsg)(int fd, struct msghdr *message, int flags) =
		dlsym(RTLD_NEXT, "recvmsg");
	struct msghdr msg = *message;
	ssize_t ret;

	if (fd == mock_fd) {
		msg.msg_name = NULL;
		msg.msg_namelen = 0;
	}
	ret = real_recvmsg(fd, &msg, flags);
	message->msg_flags = msg.msg_flags;
	message->msg_namelen = msg.msg_namelen;
	message->msg_controllen = msg.msg_controllen;
	return ret;
}

int close(int fd)
{
	int (*real_close)(int fd) = dlsym(RTLD_NEXT, "close");

	if (fd == mock_fd)
		mock_fd = -1;
	return real_close(fd);
}
