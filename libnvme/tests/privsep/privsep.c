// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libnvme.
 * Copyright (c) 2026 SUSE Software Solutions
 *
 * Authors: Daniel Wagner <dwagner@suse.de>
 *
 * Runs nvme-privsep-helper with mock-ioctl preloaded. Usage:
 * test-privsep HELPER MOCK_LIBRARY
 */
#include <endian.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/wait.h>

#include <ccan/array_size/array_size.h>

#include <shared/io-util.h>

#include <libnvme.h>
#include <libnvme-privsep.h>
#ifdef TEST_SED
#include <libnvme-sed.h>
#endif

#include "../ioctl/util.h"
#include "mock.h"

static struct libnvme_global_ctx *ctx;

static void test_spawn_failure(void)
{
	struct libnvme_privsep *ps = NULL;

	check(libnvme_privsep_spawn("/nonexistent/helper", &ps) < 0,
	      "spawning a missing helper succeeded");
	check(!ps, "channel returned on failure");
}

/*
 * The helper is the only child of the calling process. The children file
 * needs CONFIG_PROC_CHILDREN; skip the check without it.
 */
static bool helper_stdio_is_null(void)
{
	char path[64], link[64];
	ssize_t len;
	FILE *f;
	int fd, pid;

	snprintf(path, sizeof(path), "/proc/self/task/%d/children", getpid());
	f = fopen(path, "r");
	if (!f)
		return true;
	if (fscanf(f, "%d", &pid) != 1)
		pid = -1;
	fclose(f);
	if (pid < 0)
		return false;

	for (fd = STDIN_FILENO; fd <= STDERR_FILENO; fd++) {
		snprintf(path, sizeof(path), "/proc/%d/fd/%d", pid, fd);
		len = readlink(path, link, sizeof(link) - 1);
		if (len < 0)
			return false;
		link[len] = '\0';
		if (strcmp(link, "/dev/null"))
			return false;
	}

	return true;
}

/* The helper must work when the caller has stdin, stdout and stderr closed. */
static void test_closed_stdio(const char *helper)
{
	struct libnvme_privsep *ps;
	bool null;
	int status;
	pid_t pid;

	pid = fork();
	check(pid >= 0, "fork");
	if (!pid) {
		close(STDIN_FILENO);
		close(STDOUT_FILENO);
		close(STDERR_FILENO);
		alarm(10);
		if (libnvme_privsep_spawn(helper, &ps))
			_exit(1);
		null = helper_stdio_is_null();
		libnvme_privsep_free(ps);
		_exit(null ? 0 : 2);
	}

	check(waitpid(pid, &status, 0) == pid, "waitpid");
	check(WIFEXITED(status) && WEXITSTATUS(status) != 1,
	      "spawn with closed stdio failed");
	check(WIFEXITED(status) && !WEXITSTATUS(status),
	      "helper stdio not on /dev/null");
}

static void test_open_invalid(void)
{
	static const char * const names[] = {
		"../etc/passwd", "/dev/sda", "nvme", "nvme0x", "nvme0n",
		"nvme-1", "ng0", "ng0n1p1", "/dev/../dev/nvme0",
		"/dev/NVME_TEST_FD", "mctp:", "", "nvme2147483648",
		"ng0n99999999999999999999",
	};
	struct libnvme_transport_handle *hdl;
	size_t i;

	for (i = 0; i < ARRAY_SIZE(names); i++) {
		/* mctp: names never reach the helper */
		if (!strcmp(names[i], "mctp:"))
			continue;
		check(libnvme_open(ctx, names[i], O_RDONLY, &hdl) == -EINVAL,
		      "invalid name '%s' accepted", names[i]);
	}

	check(libnvme_open(ctx, "NVME_TEST_FD", O_RDONLY | O_CREAT, &hdl) ==
	      -EINVAL, "O_CREAT accepted");
}

static void test_admin_read(struct libnvme_transport_handle *hdl)
{
	unsigned char data[4096];
	struct libnvme_passthru_cmd cmd = {
		.opcode = nvme_admin_identify,
		.nsid = 7,
		.cdw10 = 3,
		.addr = (__u64)(uintptr_t)data,
		.data_len = sizeof(data),
	};
	size_t i;

	memset(data, 0, sizeof(data));
	check(!libnvme_exec_admin_passthru(hdl, &cmd), "identify failed");
	check(cmd.result == 7 + 0x1000, "result %#llx",
	      (unsigned long long)cmd.result);
	for (i = 0; i < sizeof(data); i++)
		check(data[i] == ((i + 3) & 0xff), "data[%zu] = %#x", i,
		      data[i]);
}

static void test_admin_write(struct libnvme_transport_handle *hdl)
{
	unsigned char data[512];
	struct libnvme_passthru_cmd cmd = {
		.opcode = nvme_admin_set_features,
		.addr = (__u64)(uintptr_t)data,
		.data_len = sizeof(data),
	};
	__u64 sum = 0;
	size_t i;

	for (i = 0; i < sizeof(data); i++) {
		data[i] = i * 7;
		sum += data[i];
	}
	check(!libnvme_exec_admin_passthru(hdl, &cmd), "set features failed");
	check(cmd.result == sum, "result %#llx, expected %#llx",
	      (unsigned long long)cmd.result, (unsigned long long)sum);
}

static void test_io_metadata(struct libnvme_transport_handle *hdl)
{
	unsigned char data[1024], md[64];
	struct libnvme_passthru_cmd cmd = {
		.opcode = nvme_cmd_read,
		.nsid = 1,
		.addr = (__u64)(uintptr_t)data,
		.data_len = sizeof(data),
		.metadata = (__u64)(uintptr_t)md,
		.metadata_len = sizeof(md),
	};
	size_t i;

	memset(md, 0, sizeof(md));
	check(!libnvme_exec_io_passthru(hdl, &cmd), "read failed");
	for (i = 0; i < sizeof(md); i++)
		check(md[i] == 0xa5, "md[%zu] = %#x", i, md[i]);

	cmd.opcode = nvme_cmd_write;
	check(!libnvme_exec_io_passthru(hdl, &cmd), "write failed");
	check(cmd.result >= 0xa5 * sizeof(md), "metadata not sent");
}

static void test_status(struct libnvme_transport_handle *hdl)
{
	unsigned char data[16] = {};
	struct libnvme_passthru_cmd cmd = {
		.opcode = MOCK_OPC_ERROR,
		.addr = (__u64)(uintptr_t)data,
		.data_len = sizeof(data),
	};

	check(libnvme_exec_admin_passthru(hdl, &cmd) == MOCK_STATUS,
	      "NVMe status not returned");
	check(data[1] == 1, "data not returned with an NVMe status");
}

static void test_limits(struct libnvme_transport_handle *hdl)
{
	static unsigned char data[1];
	struct libnvme_passthru_cmd cmd = {
		.opcode = nvme_admin_identify,
		.addr = (__u64)(uintptr_t)data,
		.data_len = 64 * 1024 * 1024,
	};

	check(libnvme_exec_admin_passthru(hdl, &cmd) == -EINVAL,
	      "oversized transfer accepted");
}

static void test_no_fd(struct libnvme_transport_handle *hdl)
{
	check(libnvme_transport_handle_get_fd(hdl) == LIBNVME_INVALID_FD,
	      "privsep handle exposes a file descriptor");
}

static void test_device_ops(void)
{
	struct libnvme_transport_handle *c, *n;
	__u32 nsid = 0;

	check(!libnvme_open(ctx, "nvme0", O_RDONLY, &c), "open nvme0");
	check(!libnvme_open(ctx, "/dev/nvme0n1", O_RDONLY, &n),
	      "open nvme0n1");
	check(libnvme_transport_handle_is_ctrl(c), "nvme0 is no controller");
	check(libnvme_transport_handle_is_ns(n), "nvme0n1 is no namespace");

	check(!libnvme_reset_ctrl(c), "reset failed");
	check(libnvme_reset_ctrl(n) == -EINVAL, "reset on a namespace");
	check(libnvme_reset_subsystem(c) == -EBUSY,
	      "subsystem reset error not returned");
	check(!libnvme_rescan_ns(c), "rescan failed");

	check(!libnvme_get_nsid(n, &nsid), "get nsid failed");
	check(nsid == MOCK_NSID, "nsid %u", nsid);
	check(libnvme_get_nsid(c, &nsid) == -ENOTTY,
	      "nsid of a controller");

	check(!libnvme_reread_partitions(n), "reread partitions failed");
	check(libnvme_reread_partitions(c) == -EINVAL,
	      "reread partitions on a controller");
	check(!libnvme_update_block_size(n, MOCK_BLOCK_SIZE),
	      "update block size failed");
	check(libnvme_update_block_size(n, 512) == -EINVAL,
	      "invalid block size accepted");

	libnvme_close(c);
	libnvme_close(n);
}

static void test_dry_run(struct libnvme_transport_handle *hdl)
{
	unsigned char data[16] = {};
	struct libnvme_passthru_cmd cmd = {
		.opcode = nvme_admin_identify,
		.addr = (__u64)(uintptr_t)data,
		.data_len = sizeof(data),
	};

	libnvme_set_dry_run(ctx, true);
	check(!libnvme_exec_admin_passthru(hdl, &cmd), "dry-run failed");
	libnvme_set_dry_run(ctx, false);
	check(!data[1], "dry-run reached the helper");
}

static char resource0[64];

/* Fills the BAR with the dwords 0x10000000 + byte offset. */
static void create_resource0(void)
{
	__le32 bar[1024];
	size_t i;
	int fd;

	for (i = 0; i < ARRAY_SIZE(bar); i++)
		bar[i] = htole32(0x10000000 + i * 4);

	snprintf(resource0, sizeof(resource0), "/tmp/test-privsep-XXXXXX");
	fd = mkstemp(resource0);
	check(fd >= 0, "mkstemp: %m");
	check(!shr_write_all(fd, bar, sizeof(bar)), "write: %m");
	close(fd);
	check(!setenv("MOCK_RESOURCE0", resource0, 1), "setenv");
}

static __u64 bar_read(__u32 offset, size_t len)
{
	__le64 val = 0;
	int fd;

	fd = open(resource0, O_RDONLY);
	check(fd >= 0, "open: %m");
	check(pread(fd, &val, len, offset) == (ssize_t)len, "pread: %m");
	close(fd);

	return le64toh(val);
}

static void test_regs(void)
{
	struct libnvme_transport_handle *c, *n;
	__le32 regs[4];
	size_t i;

	check(!libnvme_open(ctx, "nvme0", O_RDWR, &c), "open nvme0");
	check(!libnvme_open(ctx, "nvme0n1", O_RDONLY, &n), "open nvme0n1");

	memset(regs, 0, sizeof(regs));
	check(!libnvme_read_regs(c, 0x20, regs, sizeof(regs)),
	      "read regs failed");
	for (i = 0; i < ARRAY_SIZE(regs); i++)
		check(le32toh(regs[i]) == 0x10000020 + i * 4,
		      "reg %#zx = %#x", 0x20 + i * 4, le32toh(regs[i]));

	check(!libnvme_write_reg32(c, 0x14, 0xdeadbeef),
	      "write reg32 failed");
	check(bar_read(0x14, 4) == 0xdeadbeef, "reg32 not written");
	check(bar_read(0x18, 4) == 0x10000018, "reg32 overwrote 0x18");

	check(!libnvme_write_reg64(c, 0x28, 0x1122334455667788ULL, false),
	      "write reg64 failed");
	check(bar_read(0x28, 8) == 0x1122334455667788ULL,
	      "reg64 not written");
	check(!libnvme_write_reg64(c, 0x30, 0x8877665544332211ULL, true),
	      "write reg64 as 2 x 32 bit failed");
	check(bar_read(0x30, 8) == 0x8877665544332211ULL,
	      "reg64 not written as 2 x 32 bit");

	check(libnvme_read_regs(n, 0, regs, sizeof(regs)) == -EINVAL,
	      "read regs of a namespace");
	check(libnvme_write_reg32(n, 0x14, 0) == -EINVAL,
	      "write reg32 of a namespace");

	libnvme_close(c);
	libnvme_close(n);
}

#ifdef TEST_SED
static void test_sed(void)
{
	struct libnvme_sed_key key = {
		.type = LIBNVME_SED_KEY_INCLUDED,
		.len = strlen(MOCK_SED_PASSWORD),
	};
	struct libnvme_transport_handle *c, *n;

	memcpy(key.key, MOCK_SED_PASSWORD, key.len);
	check(!libnvme_open(ctx, "nvme0", O_RDONLY, &c), "open nvme0");
	check(!libnvme_open(ctx, "nvme0n1", O_RDWR, &n), "open nvme0n1");

	check(!libnvme_sed_take_ownership(n, &key), "take ownership failed");
	check(!libnvme_sed_lock_unlock(n, &key, LIBNVME_SED_LOCK_RW),
	      "unlock failed");
	check(libnvme_sed_lock_unlock(n, &key, LIBNVME_SED_LOCK_LK) ==
	      MOCK_TCG_INVALID_PARAM, "lock state not passed");
	check(libnvme_sed_take_ownership(c, &key) == -EINVAL,
	      "take ownership of a controller");

	key.key[0] = 'P';
	check(libnvme_sed_take_ownership(n, &key) == MOCK_TCG_NOT_AUTHORIZED,
	      "TCG status not returned");

	libnvme_close(c);
	libnvme_close(n);
}
#else
static void test_sed(void)
{
}
#endif

static int retries;

static bool retry_always(struct libnvme_transport_handle *hdl,
		struct libnvme_passthru_cmd *cmd, int err)
{
	return ++retries < 100;
}

/* Run last: terminates the helper. */
static void test_retry_broken(void)
{
	struct libnvme_transport_handle *hdl;
	struct libnvme_passthru_cmd cmd = {
		.opcode = MOCK_OPC_EXIT,
	};

	check(!libnvme_open(ctx, "NVME_TEST_FD", O_RDONLY, &hdl), "open");
	libnvme_transport_handle_set_decide_retry(hdl, retry_always);
	check(libnvme_exec_admin_passthru(hdl, &cmd) < 0,
	      "command to an exited helper succeeded");
	check(!retries, "retried on a broken channel");
	libnvme_close(hdl);
}

static void test_handles(void)
{
	struct libnvme_transport_handle *a, *b;

	check(!libnvme_open(ctx, "NVME_TEST_FD", O_RDONLY, &a), "open a");
	check(!libnvme_open(ctx, "NVME_TEST_FD64", O_RDWR, &b), "open b");
	libnvme_close(a);
	test_admin_read(b);
	libnvme_close(b);
}

int main(int argc, char **argv)
{
	struct libnvme_transport_handle *hdl;
	struct libnvme_privsep *ps;

	check(argc == 3, "usage: %s HELPER MOCK_LIBRARY", argv[0]);
	check(!setenv("LD_PRELOAD", argv[2], 1), "setenv");
	create_resource0();

	test_spawn_failure();
	test_closed_stdio(argv[1]);

	check(!libnvme_privsep_spawn(argv[1], &ps), "spawn failed");
	ctx = libnvme_create_global_ctx();
	check(ctx, "create ctx");
	libnvme_set_privsep(ctx, ps);

	test_open_invalid();

	check(!libnvme_open(ctx, "NVME_TEST_FD", O_RDONLY, &hdl), "open");
	test_admin_read(hdl);
	test_admin_write(hdl);
	test_io_metadata(hdl);
	test_status(hdl);
	test_limits(hdl);
	test_no_fd(hdl);
	test_dry_run(hdl);
	libnvme_close(hdl);

	test_handles();
	test_device_ops();
	test_regs();
	test_sed();
	test_retry_broken();

	libnvme_free_global_ctx(ctx);
	libnvme_privsep_free(ps);
	unlink(resource0);
	printf("privsep tests passed\n");

	return EXIT_SUCCESS;
}
