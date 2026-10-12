// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libnvme.
 * Copyright (c) 2026 SUSE Software Solutions
 *
 * Authors: Daniel Wagner <dwagner@suse.de>
 */

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <ccan/array_size/array_size.h>
#include <ccan/endian/endian.h>

#include <libnvme.h>

#include "ioctl/util.h"

#define REG_MAP_SIZE 0x1000

static char tmpdir[32];
static char resource[PATH_MAX];

static void mkdir_p(const char *base, const char *sub)
{
	char path[PATH_MAX];
	const char *p;

	for (p = sub; (p = strchr(p, '/')); p++) {
		snprintf(path, sizeof(path), "%s/%.*s", base,
			 (int)(p - sub), sub);
		check(!mkdir(path, 0755) || errno == EEXIST,
		      "mkdir %s: %m", path);
	}
	snprintf(path, sizeof(path), "%s/%s", base, sub);
	check(!mkdir(path, 0755) || errno == EEXIST, "mkdir %s: %m", path);
}

static void setup_resource(void)
{
	long size = sysconf(_SC_PAGESIZE);
	__le32 *regs;
	int fd, i;

	snprintf(tmpdir, sizeof(tmpdir), "/tmp/libnvme-regs-XXXXXX");
	check(mkdtemp(tmpdir), "mkdtemp: %m");
	mkdir_p(tmpdir, "sys/class/nvme/NVME_TEST_FD/device");
	snprintf(resource, sizeof(resource),
		 "%s/sys/class/nvme/NVME_TEST_FD/device/resource0", tmpdir);

	regs = calloc(1, size);
	check(regs, "calloc");
	for (i = 0; i < REG_MAP_SIZE / 4; i++)
		regs[i] = cpu_to_le32(0x11220000 + i);

	fd = open(resource, O_CREAT | O_TRUNC | O_RDWR, 0600);
	check(fd >= 0, "open %s: %m", resource);
	check(write(fd, regs, size) == size, "write %s: %m", resource);
	close(fd);
	free(regs);
}

static void cleanup_resource(void)
{
	char path[PATH_MAX];
	static const char * const dirs[] = {
		"sys/class/nvme/NVME_TEST_FD/device",
		"sys/class/nvme/NVME_TEST_FD",
		"sys/class/nvme",
		"sys/class",
		"sys",
	};
	size_t i;

	unlink(resource);
	for (i = 0; i < ARRAY_SIZE(dirs); i++) {
		snprintf(path, sizeof(path), "%s/%s", tmpdir, dirs[i]);
		rmdir(path);
	}
	rmdir(tmpdir);
}

static __u32 resource_read32(__u32 offset)
{
	__le32 val;
	int fd;

	fd = open(resource, O_RDONLY);
	check(fd >= 0, "open %s: %m", resource);
	check(pread(fd, &val, sizeof(val), offset) == sizeof(val),
	      "pread %s: %m", resource);
	close(fd);

	return le32_to_cpu(val);
}

static void test_read(struct libnvme_transport_handle *hdl)
{
	__le32 buf[8];
	int i;

	check(!libnvme_read_regs(hdl, 0, buf, sizeof(buf)), "read_regs");
	for (i = 0; i < 8; i++)
		check(le32_to_cpu(buf[i]) == 0x11220000 + (__u32)i,
		      "reg %d: got %#x", i, le32_to_cpu(buf[i]));

	check(!libnvme_read_regs(hdl, NVME_REG_PMRCAP, buf, 4),
	      "read_regs PMRCAP");
	check(le32_to_cpu(buf[0]) == 0x11220000 + NVME_REG_PMRCAP / 4,
	      "PMRCAP: got %#x", le32_to_cpu(buf[0]));

	check(!libnvme_read_regs(hdl, REG_MAP_SIZE - 4, buf, 4),
	      "read_regs last dword");
}

static void test_read_invalid(struct libnvme_transport_handle *hdl)
{
	__le32 buf[2];

	check(libnvme_read_regs(hdl, 2, buf, 4) == -EINVAL,
	      "unaligned offset accepted");
	check(libnvme_read_regs(hdl, 0, buf, 6) == -EINVAL,
	      "unaligned length accepted");
	check(libnvme_read_regs(hdl, REG_MAP_SIZE - 4, buf, 8) == -EINVAL,
	      "range beyond the register map accepted");
	check(libnvme_read_regs(hdl, UINT32_MAX - 3, buf, 8) == -EINVAL,
	      "wrapping range accepted");
}

static void test_write(struct libnvme_transport_handle *hdl)
{
	check(!libnvme_write_reg32(hdl, NVME_REG_CC, 0xdeadbeef),
	      "write_reg32");
	check(resource_read32(NVME_REG_CC) == 0xdeadbeef, "CC not written");

	check(!libnvme_write_reg64(hdl, NVME_REG_ASQ, 0x0123456789abcdefULL,
				   false), "write_reg64");
	check(resource_read32(NVME_REG_ASQ) == 0x89abcdef &&
	      resource_read32(NVME_REG_ASQ + 4) == 0x01234567,
	      "ASQ not written");

	check(!libnvme_write_reg64(hdl, NVME_REG_ACQ, 0xfedcba9876543210ULL,
				   true), "write_reg64 mmio32");
	check(resource_read32(NVME_REG_ACQ) == 0x76543210 &&
	      resource_read32(NVME_REG_ACQ + 4) == 0xfedcba98,
	      "ACQ not written");

	check(libnvme_write_reg32(hdl, REG_MAP_SIZE, 0) == -EINVAL,
	      "write beyond the register map accepted");
	check(libnvme_write_reg64(hdl, REG_MAP_SIZE - 4, 0, false) == -EINVAL,
	      "64-bit write beyond the register map accepted");
	check(libnvme_write_reg64(hdl, NVME_REG_INTMS, 0, false) == -EINVAL,
	      "unaligned 64-bit write accepted");
	check(libnvme_write_reg64(hdl, NVME_REG_INTMS, 0, true) == -EINVAL,
	      "unaligned 64-bit mmio32 write accepted");
}

int main(void)
{
	struct libnvme_transport_handle *hdl;
	struct libnvme_global_ctx *ctx;

	setup_resource();

	ctx = libnvme_create_global_ctx();
	check(ctx, "create ctx");
	check(!libnvme_set_test_sysfs_dir(ctx, tmpdir), "set sysfs dir");
	check(!libnvme_open(ctx, "NVME_TEST_FD", O_RDONLY, &hdl), "open");

	test_read(hdl);
	test_read_invalid(hdl);
	test_write(hdl);

	libnvme_close(hdl);
	libnvme_free_global_ctx(ctx);
	cleanup_resource();

	return EXIT_SUCCESS;
}
