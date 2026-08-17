// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * This file is part of nvme-cli.
 *
 * Copyright (c) 2026 SUSE LLC
 *
 * Authors: Daniel Wagner <dwagner@suse.com>
 */

/*
 * LD_PRELOAD shim for the fabrics CLI tests (see nvme_fabrics_mock_test.py).
 *
 * It intercepts open()/write()/ioctl()/close() on /dev/nvme-fabrics and
 * /dev/nvme<N> so that "nvme discover"/"connect"/"connect-all" can run
 * against a fake target without a kernel nvme-fabrics module or root
 * privileges. Every intercepted write() (connect args) and ioctl() (admin
 * passthru command) is forwarded over a Unix socket to a Python-side IPC
 * server that supplies the response, so all test scenarios are steered from
 * the Python test file rather than from this shim.
 */

#undef _FILE_OFFSET_BITS
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <dlfcn.h>
#include <endian.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/types.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#include <shared/compiler-attributes-util.h>

/*
 * Mirrors struct linux_passthru_cmd32/64 in libnvme/src/nvme/private.h --
 * the layout libnvme's own ioctl() callers use -- so casting the ioctl()
 * argp we're handed back to this type lines up with the real fields.
 */
struct linux_passthru_cmd32 {
	__u8	opcode;
	__u8	flags;
	__u16	rsvd1;
	__u32	nsid;
	__u32	cdw2;
	__u32	cdw3;
	__u64	metadata;
	__u64	addr;
	__u32	metadata_len;
	__u32	data_len;
	__u32	cdw10;
	__u32	cdw11;
	__u32	cdw12;
	__u32	cdw13;
	__u32	cdw14;
	__u32	cdw15;
	__u32	timeout_ms;
	__u32	result;
};

struct linux_passthru_cmd64 {
	__u8	opcode;
	__u8	flags;
	__u16	rsvd1;
	__u32	nsid;
	__u32	cdw2;
	__u32	cdw3;
	__u64	metadata;
	__u64	addr;
	__u32	metadata_len;
	__u32	data_len;
	__u32	cdw10;
	__u32	cdw11;
	__u32	cdw12;
	__u32	cdw13;
	__u32	cdw14;
	__u32	cdw15;
	__u32	timeout_ms;
	__u32	rsvd2;
	__u64	result;
};

#define LIBNVME_IOCTL_ADMIN_CMD		_IOWR('N', 0x41, struct linux_passthru_cmd32)
#define LIBNVME_IOCTL_ADMIN64_CMD	_IOWR('N', 0x47, struct linux_passthru_cmd64)

/* Wire format shared with the Python IPC server -- keep both sides in sync. */
struct __attribute__((packed)) ipc_request {
	uint32_t type;		/* 1 == WRITE, 2 == IOCTL */
	uint32_t fd;		/* instance number for IOCTL */
	uint32_t data_len;	/* payload length (follows immediately) */
	uint32_t request;	/* ioctl request code */
	uint8_t  opcode;	/* nvme opcode */
	uint8_t  rsvd[3];
	uint32_t nsid;
	uint32_t cdw10;
	uint32_t cdw11;
	uint32_t cdw12;
	uint32_t cdw13;
	uint32_t cdw14;
	uint32_t cdw15;
	uint64_t lpo;
	uint32_t req_len;	/* command data length */
};

struct __attribute__((packed)) ipc_response {
	int32_t  status;	/* 0 for success, -1 for error */
	int32_t  errno_val;	/* errno to return on error */
	uint32_t result;	/* cmd->result */
	uint32_t data_len;	/* payload length (follows immediately) */
};

typedef int (*orig_open_t)(const char *pathname, int flags, ...);
typedef int (*orig_open64_t)(const char *pathname, int flags, ...);
typedef int (*orig_openat_t)(int dirfd, const char *pathname, int flags, ...);
typedef int (*orig_openat64_t)(int dirfd, const char *pathname, int flags, ...);
typedef ssize_t (*orig_write_t)(int fd, const void *buf, size_t count);
typedef ssize_t (*orig_read_t)(int fd, void *buf, size_t count);
typedef int (*orig_ioctl_t)(int fd, unsigned long request, ...);
typedef int (*orig_close_t)(int fd);

static orig_open_t orig_open;
static orig_open64_t orig_open64;
static orig_openat_t orig_openat;
static orig_openat64_t orig_openat64;
static orig_write_t orig_write;
static orig_read_t orig_read;
static orig_ioctl_t orig_ioctl;
static orig_close_t orig_close;

static int mock_fabrics_fd = -1;
static int mock_fabrics_manager_fd = -1;
static bool mock_debug;

#define MAX_MOCK_CTRLS 16
static struct {
	int fd;
	int instance;
} mock_ctrl_fds[MAX_MOCK_CTRLS];
static int num_mock_ctrls;

#define mock_dbg(fmt, ...) \
	do { \
		if (mock_debug) \
			fprintf(stderr, "[MOCK_DEBUG] " fmt, ##__VA_ARGS__); \
	} while (0)

static void __shr_constructor mock_init(void)
{
	mock_debug = !!getenv("MOCK_DEBUG");
	mock_dbg("libmock_fabrics loaded, sizeof(ipc_request)=%zu, sizeof(ipc_response)=%zu\n",
		 sizeof(struct ipc_request), sizeof(struct ipc_response));
}

static void init_orig_functions(void)
{
	if (orig_open)
		return;

	orig_open = (orig_open_t)dlsym(RTLD_NEXT, "open");
	orig_open64 = (orig_open64_t)dlsym(RTLD_NEXT, "open64");
	orig_openat = (orig_openat_t)dlsym(RTLD_NEXT, "openat");
	orig_openat64 = (orig_openat64_t)dlsym(RTLD_NEXT, "openat64");
	orig_write = (orig_write_t)dlsym(RTLD_NEXT, "write");
	orig_read = (orig_read_t)dlsym(RTLD_NEXT, "read");
	orig_ioctl = (orig_ioctl_t)dlsym(RTLD_NEXT, "ioctl");
	orig_close = (orig_close_t)dlsym(RTLD_NEXT, "close");
}

static int connect_ipc_socket(void)
{
	const char *sock_path = getenv("MOCK_IPC_SOCK");
	struct sockaddr_un addr;
	int fd;

	if (!sock_path) {
		mock_dbg("MOCK_IPC_SOCK env var not set!\n");
		return -1;
	}

	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd < 0) {
		mock_dbg("failed to create socket: %s\n", strerror(errno));
		return -1;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, sock_path, sizeof(addr.sun_path) - 1);
	if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		mock_dbg("connect failed to '%s': %s\n", sock_path, strerror(errno));
		orig_close(fd);
		return -1;
	}

	return fd;
}

/* Returns -2 when @pathname is not one we intercept. */
static int handle_open_intercept(const char *pathname, int flags)
{
	int instance, real_fd, sv[2];
	char *endp;

	if (!pathname)
		return -2;

	if (!strcmp(pathname, "/dev/nvme-fabrics")) {
		if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0)
			return -1;

		mock_fabrics_manager_fd = sv[0];
		mock_fabrics_fd = sv[1];

		mock_dbg("intercepted /dev/nvme-fabrics open\n");

		if ((flags & O_ACCMODE) == O_RDONLY) {
			const char *opts = getenv("MOCK_SUPPORTED_OPTIONS");

			if (!opts)
				opts = "instance,cntlid,concat,ctrl_loss_tmo,data_digest,"
				       "dhchap_ctrl_secret,dhchap_secret,disable_sqflow,"
				       "discovery,duplicate_connect,fast_io_fail_tmo,"
				       "hdr_digest,host_iface,host_traddr,hostid,hostnqn,"
				       "keep_alive_tmo,keyring,nqn,nr_io_queues,"
				       "nr_poll_queues,nr_write_queues,queue_size,"
				       "reconnect_delay,tls,tls_key,tos,traddr,transport,"
				       "trsvcid\n";
			orig_write(mock_fabrics_manager_fd, opts, strlen(opts));
			orig_close(mock_fabrics_manager_fd);
			mock_fabrics_manager_fd = -1;
		}

		return mock_fabrics_fd;
	}

	if (strncmp(pathname, "/dev/nvme", 9) ||
			pathname[9] < '0' ||
			pathname[9] > '9')
		return -2;

	instance = strtol(pathname + 9, &endp, 10);
	if (!endp || *endp != '\0')
		return -2;

	real_fd = orig_open("/dev/null", flags);
	if (real_fd >= 0) {
		if (num_mock_ctrls < MAX_MOCK_CTRLS) {
			mock_ctrl_fds[num_mock_ctrls].fd = real_fd;
			mock_ctrl_fds[num_mock_ctrls].instance = instance;
			num_mock_ctrls++;
		}
		mock_dbg("intercepted /dev/nvme%d open (mapped to fd %d)\n",
			 instance, real_fd);
	}

	return real_fd;
}

static mode_t open_mode_arg(int flags, va_list args)
{
	if (flags & (O_CREAT | O_TMPFILE))
		return va_arg(args, mode_t);

	return 0;
}

int open(const char *pathname, int flags, ...)
{
	va_list args;
	mode_t mode;
	int fd;

	init_orig_functions();
	fd = handle_open_intercept(pathname, flags);
	if (fd != -2)
		return fd;

	va_start(args, flags);
	mode = open_mode_arg(flags, args);
	va_end(args);

	return orig_open(pathname, flags, mode);
}

int open64(const char *pathname, int flags, ...)
{
	va_list args;
	mode_t mode;
	int fd;

	init_orig_functions();
	fd = handle_open_intercept(pathname, flags);
	if (fd != -2)
		return fd;

	va_start(args, flags);
	mode = open_mode_arg(flags, args);
	va_end(args);

	return orig_open64(pathname, flags, mode);
}

int openat(int dirfd, const char *pathname, int flags, ...)
{
	va_list args;
	mode_t mode;
	int fd;

	init_orig_functions();
	fd = handle_open_intercept(pathname, flags);
	if (fd != -2)
		return fd;

	va_start(args, flags);
	mode = open_mode_arg(flags, args);
	va_end(args);

	return orig_openat(dirfd, pathname, flags, mode);
}

int openat64(int dirfd, const char *pathname, int flags, ...)
{
	va_list args;
	mode_t mode;
	int fd;

	init_orig_functions();
	fd = handle_open_intercept(pathname, flags);
	if (fd != -2)
		return fd;

	va_start(args, flags);
	mode = open_mode_arg(flags, args);
	va_end(args);

	return orig_openat64(dirfd, pathname, flags, mode);
}

/*
 * With _FORTIFY_SOURCE >= 1 and optimization enabled, glibc's <fcntl.h>
 * rewrites the 2-argument form of open()/openat() (no O_CREAT, so no mode)
 * at the call site into a call to these symbols instead of open()/openat().
 * Callers built that way (e.g. the Tumbleweed release CI job, which passes
 * -D_FORTIFY_SOURCE=3 -O2) bypass our open()/openat() overrides entirely
 * unless these are intercepted too. No mode argument is needed here since
 * the 2-argument form implies O_CREAT/O_TMPFILE weren't set.
 */
int __open_2(const char *pathname, int flags)
{
	int fd;

	init_orig_functions();
	fd = handle_open_intercept(pathname, flags);
	if (fd != -2)
		return fd;

	return orig_open(pathname, flags, 0);
}

int __open64_2(const char *pathname, int flags)
{
	int fd;

	init_orig_functions();
	fd = handle_open_intercept(pathname, flags);
	if (fd != -2)
		return fd;

	return orig_open64(pathname, flags, 0);
}

int __openat_2(int dirfd, const char *pathname, int flags)
{
	int fd;

	init_orig_functions();
	fd = handle_open_intercept(pathname, flags);
	if (fd != -2)
		return fd;

	return orig_openat(dirfd, pathname, flags, 0);
}

int __openat64_2(int dirfd, const char *pathname, int flags)
{
	int fd;

	init_orig_functions();
	fd = handle_open_intercept(pathname, flags);
	if (fd != -2)
		return fd;

	return orig_openat64(dirfd, pathname, flags, 0);
}

/* read() on a stream socket may return fewer bytes than requested even
 * when more are on the way; loop until @len bytes are read, an orig_read()
 * error/EOF occurs, or a short read is treated as an error by the caller.
 * Returns true if all @len bytes were read.
 */
static bool read_full(int fd, void *buf, size_t len)
{
	size_t total_read = 0;

	while (total_read < len) {
		ssize_t n = orig_read(fd, (char *)buf + total_read,
				       len - total_read);
		if (n <= 0)
			return false;
		total_read += n;
	}

	return true;
}

/* Reads the fixed-size ipc_response header, then its variable-length
 * payload (if any) into a freshly malloc()'d buffer. Returns the payload
 * (NULL if empty or on error) and fills in @resp.
 */
static void *read_ipc_response(int ipc_fd, struct ipc_response *resp)
{
	char *payload;

	memset(resp, 0, sizeof(*resp));
	if (!read_full(ipc_fd, resp, sizeof(*resp))) {
		mock_dbg("failed to read full IPC response header\n");
		resp->status = -1;
		resp->errno_val = EIO;
		return NULL;
	}

	if (!resp->data_len)
		return NULL;

	payload = malloc(resp->data_len);
	if (!payload)
		return NULL;

	if (!read_full(ipc_fd, payload, resp->data_len)) {
		mock_dbg("failed to read full IPC response payload\n");
		free(payload);
		resp->status = -1;
		resp->errno_val = EIO;
		return NULL;
	}

	return payload;
}

ssize_t write(int fd, const void *buf, size_t count)
{
	struct ipc_response resp;
	char *resp_data;
	int ipc_fd;

	init_orig_functions();

	if (fd != mock_fabrics_fd)
		return orig_write(fd, buf, count);

	mock_dbg("intercepted connect args on fabrics fd %d\n", fd);

	ipc_fd = connect_ipc_socket();
	if (ipc_fd < 0) {
		mock_dbg("could not connect to IPC socket\n");
		return orig_write(fd, buf, count);
	}

	struct ipc_request req = {
		.type = 1, /* WRITE */
		.fd = fd,
		.data_len = count,
	};

	orig_write(ipc_fd, &req, sizeof(req));
	orig_write(ipc_fd, buf, count);

	resp_data = read_ipc_response(ipc_fd, &resp);
	mock_dbg("connect IPC response status %d, data_len %u\n",
		 resp.status, resp.data_len);

	if (resp.status == -1) {
		free(resp_data);
		orig_close(ipc_fd);
		errno = resp.errno_val;
		return -1;
	}

	if (resp_data && mock_fabrics_manager_fd >= 0)
		orig_write(mock_fabrics_manager_fd, resp_data, resp.data_len);
	free(resp_data);
	orig_close(ipc_fd);

	return count;
}

static int mock_ctrl_instance(int fd)
{
	for (int i = 0; i < num_mock_ctrls; i++)
		if (mock_ctrl_fds[i].fd == fd)
			return mock_ctrl_fds[i].instance;

	return -1;
}

static int handle_admin_ioctl(int instance, unsigned long request,
			       struct linux_passthru_cmd64 *cmd)
{
	struct ipc_response resp;
	void *resp_data;
	int ipc_fd;

	mock_dbg("ioctl intercepted on instance %d\n", instance);

	ipc_fd = connect_ipc_socket();
	if (ipc_fd < 0) {
		mock_dbg("ioctl could not connect to IPC socket\n");
		return -2;
	}

	struct ipc_request req = {
		.type = 2, /* IOCTL */
		.fd = instance, /* controller instance, not a real fd */
		.request = request,
		.opcode = cmd->opcode,
		.nsid = cmd->nsid,
		.cdw10 = cmd->cdw10,
		.cdw11 = cmd->cdw11,
		.cdw12 = cmd->cdw12,
		.cdw13 = cmd->cdw13,
		.cdw14 = cmd->cdw14,
		.cdw15 = cmd->cdw15,
		.lpo = ((uint64_t)cmd->cdw13 << 32) | cmd->cdw12,
		.req_len = cmd->data_len,
	};

	orig_write(ipc_fd, &req, sizeof(req));

	resp_data = read_ipc_response(ipc_fd, &resp);
	mock_dbg("ioctl received IPC response status %d, result %u, data_len %u\n",
		 resp.status, resp.result, resp.data_len);

	if (resp.status == -1) {
		free(resp_data);
		orig_close(ipc_fd);
		errno = resp.errno_val;
		return -1;
	}

	/*
	 * argp is only guaranteed to be a full struct linux_passthru_cmd64
	 * for the ADMIN64_CMD request; for the legacy ADMIN_CMD request it
	 * really points at the smaller struct linux_passthru_cmd32, whose
	 * result field is 4 bytes narrower and sits 4 bytes earlier. Writing
	 * through the wider cmd64 view in that case scribbles 8 bytes past
	 * the end of the caller's 32-bit struct.
	 */
	if (request == LIBNVME_IOCTL_ADMIN_CMD) {
		struct linux_passthru_cmd32 *cmd32 = (struct linux_passthru_cmd32 *)cmd;

		cmd32->result = resp.result;
	} else {
		cmd->result = resp.result;
	}

	if (resp_data) {
		if (resp.data_len > cmd->data_len) {
			mock_dbg("ioctl response data_len %u exceeds caller buffer %u, truncating\n",
				 resp.data_len, cmd->data_len);
			resp.data_len = cmd->data_len;
		}
		memcpy((void *)(uintptr_t)cmd->addr, resp_data, resp.data_len);
	}
	free(resp_data);
	orig_close(ipc_fd);

	return 0;
}

int ioctl(int fd, unsigned long request, ...)
{
	int instance = mock_ctrl_instance(fd);
	va_list args;
	void *argp;
	int ret;

	init_orig_functions();

	va_start(args, request);
	argp = va_arg(args, void *);
	va_end(args);

	if (instance >= 0 &&
	    (request == LIBNVME_IOCTL_ADMIN_CMD || request == LIBNVME_IOCTL_ADMIN64_CMD)) {
		ret = handle_admin_ioctl(instance, request, argp);
		if (ret != -2)
			return ret;
	}

	return orig_ioctl(fd, request, argp);
}

/*
 * Some libc admin-passthru call sites resolve ioctl() through this alias
 * rather than the public symbol; keep it in sync with ioctl() above so
 * those calls are intercepted too.
 */
int __ioctl(int fd, unsigned long request, ...)
{
	va_list args;
	void *argp;

	va_start(args, request);
	argp = va_arg(args, void *);
	va_end(args);

	return ioctl(fd, request, argp);
}

int close(int fd)
{
	init_orig_functions();

	if (fd == mock_fabrics_fd)
		mock_fabrics_fd = -1;
	if (fd == mock_fabrics_manager_fd)
		mock_fabrics_manager_fd = -1;

	for (int i = 0; i < num_mock_ctrls; i++) {
		if (mock_ctrl_fds[i].fd != fd)
			continue;
		for (int j = i; j < num_mock_ctrls - 1; j++)
			mock_ctrl_fds[j] = mock_ctrl_fds[j + 1];
		num_mock_ctrls--;
		break;
	}

	return orig_close(fd);
}
