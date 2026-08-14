// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of nvme-cli.
 */
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <shared/cleanup.h>
#include <shared/fs-util.h>

static bool check_bool(const char *name, bool got)
{
	printf(" - %s [%s]\n", name, got ? "PASS" : "FAIL");
	return got;
}

static int open_fd(const char *path)
{
	return open(path, O_RDONLY);
}

static bool test_cleanup_fd(void)
{
	static const char *path = "shr-test-cleanup-fd-file";
	bool pass = true;
	int saved_fd;
	FILE *f;

	printf("test_cleanup_fd:\n");

	f = fopen(path, "w");
	pass &= check_bool("temp file created", f != NULL);
	if (f)
		fclose(f);

	{
		__cleanup_fd int fd = open_fd(path);

		pass &= check_bool("fd opened successfully", fd >= 0);
		saved_fd = fd;
	}

	pass &= check_bool("fd is closed once out of scope",
			    !shr_fd_is_open(saved_fd));

	unlink(path);

	return pass;
}

static bool test_cleanup_file(void)
{
	static const char *path = "shr-test-cleanup-file-file";
	bool pass = true;
	bool no_leak = true;
	int i;

	printf("test_cleanup_file:\n");

	{
		FILE *f = fopen(path, "w");

		pass &= check_bool("temp file created", f != NULL);
		if (f)
			fclose(f);
	}

	/*
	 * If __cleanup_file failed to close the FILE* at scope exit, this
	 * loop would exhaust the fd table well before 256 iterations.
	 */
	for (i = 0; i < 256; i++) {
		__cleanup_file FILE *f = fopen(path, "r");

		if (!f) {
			no_leak = false;
			break;
		}
	}
	pass &= check_bool("no fd leak across 256 open/scope-exit cycles", no_leak);

	unlink(path);

	return pass;
}

int main(void)
{
	bool pass = true;

	pass &= test_cleanup_fd();
	pass &= test_cleanup_file();

	fflush(stdout);
	exit(pass ? EXIT_SUCCESS : EXIT_FAILURE);
}
