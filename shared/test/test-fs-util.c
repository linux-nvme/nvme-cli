// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 Dell Technologies Inc. or its subsidiaries.
 *
 * Authors: Martin Belanger <martin.belanger@dell.com>
 */

#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32)
#include <direct.h>
#define rmdir _rmdir
#else
#include <fcntl.h>
#include <unistd.h>
#endif

#include <fs-util.h>

static bool check_str(const char *name, const char *got, const char *want)
{
	bool eq = (got == want) || (got && want && !strcmp(got, want));

	if (eq) {
		printf(" - %s [PASS]\n", name);
		return true;
	}

	printf(" - %s: got \"%s\", want \"%s\" [FAIL]\n",
	       name, got ? got : "(null)", want ? want : "(null)");
	return false;
}

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

static bool test_basename(void)
{
	bool pass = true;

	printf("test_basename:\n");

	pass &= check_str("regular path", shr_basename("/a/b/c"), "c");
	pass &= check_str("no slash at all",
			   shr_basename("noslash"), "noslash");
	pass &= check_str("trailing slash → empty (unlike POSIX basename())",
			   shr_basename("/trailing/"), "");
	pass &= check_str("bare \"/\" → empty", shr_basename("/"), "");
	pass &= check_str("empty input → empty", shr_basename(""), "");

	return pass;
}

/* Prove the directory tree really exists by writing a file inside it. */
static bool dir_is_writable(const char *dir)
{
	char path[512];
	FILE *f;

	snprintf(path, sizeof(path), "%s/marker", dir);
	f = fopen(path, "w");
	if (!f)
		return false;
	fclose(f);
	remove(path);

	return true;
}

static bool test_mkdir_p(void)
{
	static const char *base = "shr-test-mkdir-p-dir";
	char deep[256];
	bool pass = true;
	int ret;

	printf("test_mkdir_p:\n");

	snprintf(deep, sizeof(deep), "%s/level1/level2", base);

	ret = shr_mkdir_p(deep, 0755);
	pass &= check_ret("creates every missing parent", ret, 0);
	pass &= check_bool("the deepest directory is real and writable",
			    dir_is_writable(deep));

	ret = shr_mkdir_p(deep, 0755);
	pass &= check_ret("re-running on an existing tree is a no-op success",
			   ret, 0);

	snprintf(deep, sizeof(deep), "%s/level1/level2/", base);
	ret = shr_mkdir_p(deep, 0755);
	pass &= check_ret("a trailing slash does not confuse it", ret, 0);

	{
		char toolong[PATH_MAX + 2];

		memset(toolong, 'a', sizeof(toolong) - 1);
		toolong[sizeof(toolong) - 1] = '\0';
		ret = shr_mkdir_p(toolong, 0755);
		pass &= check_ret("a path longer than PATH_MAX is rejected",
				  ret, -ENAMETOOLONG);
	}

	/* Clean up what we created, deepest first. */
	rmdir("shr-test-mkdir-p-dir/level1/level2");
	rmdir("shr-test-mkdir-p-dir/level1");
	rmdir("shr-test-mkdir-p-dir");

	return pass;
}

#if !defined(_WIN32)
static bool test_mkstemp(void)
{
	char template[] = "shr-test-mkstemp-XXXXXX";
	bool pass = true;
	int fd, flags;

	printf("test_mkstemp:\n");

	fd = shr_mkstemp(template);
	pass &= check_bool("returns a valid fd", fd >= 0);
	if (fd < 0)
		return pass;

	pass &= check_bool("template's X's got replaced",
			    strcmp(template, "shr-test-mkstemp-XXXXXX") != 0);

	flags = fcntl(fd, F_GETFD);
	pass &= check_bool("O_CLOEXEC is set on the returned fd",
			    flags >= 0 && (flags & FD_CLOEXEC));

	close(fd);
	unlink(template);

	return pass;
}
#endif

static bool test_fsync_dir(void)
{
	printf("test_fsync_dir:\n");

	/* Neither call has a return value to check; passing means no crash. */
	shr_fsync_dir(".");
	shr_fsync_dir("/no/such/directory/at/all");

	printf(" - fsync_dir on a real and a bogus path [PASS]\n");

	return true;
}

int main(void)
{
	bool pass = true;

	pass &= test_basename();
	pass &= test_mkdir_p();
#if !defined(_WIN32)
	pass &= test_mkstemp();
#endif
	pass &= test_fsync_dir();

	fflush(stdout);
	exit(pass ? EXIT_SUCCESS : EXIT_FAILURE);
}
