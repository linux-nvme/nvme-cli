// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 Dell Technologies Inc. or its subsidiaries.
 *
 * Authors: Martin Belanger <martin.belanger@dell.com>
 */

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <shared/io-util.h>

static bool check_ret(const char *name, int got, int want)
{
	if (got == want) {
		printf(" - %s [PASS]\n", name);
		return true;
	}

	printf(" - %s: got %d, want %d [FAIL]\n", name, got, want);
	return false;
}

static bool check_bool(const char *name, bool got)
{
	printf(" - %s [%s]\n", name, got ? "PASS" : "FAIL");
	return got;
}

static bool test_round_trip(void)
{
	static const char *path = "shr-test-io-util-file";
	static const char *msg = "some bytes written through shr_write_all";
	char readback[128] = { 0 };
	bool pass = true;
	int fd, ret;
	ssize_t n;

	printf("test_round_trip:\n");

	fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	pass &= check_bool("temp file opened for writing", fd >= 0);
	if (fd < 0)
		return pass;

	ret = shr_write_all(fd, msg, strlen(msg));
	pass &= check_ret("writes the whole buffer in one call", ret, 0);
	close(fd);

	fd = open(path, O_RDONLY);
	pass &= check_bool("temp file reopened for reading", fd >= 0);
	if (fd >= 0) {
		n = read(fd, readback, sizeof(readback) - 1);
		close(fd);
		pass &= check_bool("readback matches what was written",
				   n == (ssize_t)strlen(msg) &&
				   !strcmp(readback, msg));
	}

	unlink(path);

	return pass;
}

static bool test_zero_length(void)
{
	bool pass;

	printf("test_zero_length:\n");

	/* len == 0 must succeed without touching the fd at all. */
	pass = check_ret("zero-length write on an invalid fd still succeeds",
			  shr_write_all(-1, "x", 0), 0);

	return pass;
}

static bool test_bad_fd(void)
{
	bool pass;

	printf("test_bad_fd:\n");

	pass = check_ret("a real write on an invalid fd reports -EBADF",
			  shr_write_all(-1, "x", 1), -EBADF);

	return pass;
}

static bool test_read_all(void)
{
	static const char *path = "shr-test-io-util-read";
	static const char *msg = "0123456789abcdef";
	char buf[64];
	bool pass = true;
	int fd, ret;

	printf("test_read_all:\n");

	fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (!check_bool("temp file opened for writing", fd >= 0))
		return false;
	shr_write_all(fd, msg, strlen(msg));
	close(fd);

	/* Buffer large enough: whole content read back, NUL-terminated. */
	fd = open(path, O_RDONLY);
	if (check_bool("temp file reopened for reading", fd >= 0)) {
		memset(buf, 'x', sizeof(buf));
		ret = shr_read_all(fd, buf, sizeof(buf));
		close(fd);
		pass &= check_ret("read to EOF succeeds", ret, 0);
		pass &= check_bool("content matches", !strcmp(buf, msg));
	} else {
		pass = false;
	}

	/* Buffer too small: keeps out_len-1 bytes, still drains to EOF. */
	fd = open(path, O_RDONLY);
	if (check_bool("temp file reopened for short read", fd >= 0)) {
		ret = shr_read_all(fd, buf, 8);
		close(fd);
		pass &= check_ret("short buffer still succeeds (drains rest)",
				  ret, 0);
		pass &= check_bool("keeps exactly out_len-1 bytes",
				   strlen(buf) == 7 && !strncmp(buf, msg, 7));
	} else {
		pass = false;
	}

	/* NULL out with a non-zero length is rejected. */
	pass &= check_ret("NULL buffer with non-zero length is -EINVAL",
			  shr_read_all(-1, NULL, 8), -EINVAL);

	/* out_len == 0 keeps nothing but still drains the fd to EOF. */
	fd = open(path, O_RDONLY);
	if (check_bool("temp file reopened for zero-length read", fd >= 0)) {
		ret = shr_read_all(fd, buf, 0);
		close(fd);
		pass &= check_ret("zero-length buffer drains and succeeds",
				  ret, 0);
	} else {
		pass = false;
	}

	unlink(path);

	return pass;
}

int main(void)
{
	bool pass = true;

	pass &= test_round_trip();
	pass &= test_zero_length();
	pass &= test_bad_fd();
	pass &= test_read_all();

	fflush(stdout);
	exit(pass ? EXIT_SUCCESS : EXIT_FAILURE);
}
