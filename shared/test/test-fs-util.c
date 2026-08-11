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
#include <fcntl.h>
#include <io.h>
#define rmdir _rmdir
#define close _close
#define unlink _unlink
#define read _read
#define write _write
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

static bool test_dirname(void)
{
	struct {
		const char *input;
		const char *expected;
	} cases[] = {
		{ "/usr/lib", "/usr" },
		{ "/usr/", "/" },
		{ "/usr", "/" },
		{ "usr", "." },
		{ "/", "/" },
		{ ".", "." },
		{ "..", "." },
		{ "", "." },
		{ "///", "/" },
		{ "/usr///lib", "/usr" },
		{ "/usr/lib/", "/usr" },
		{ NULL, "." },
	};
	bool pass = true;
	unsigned int i;

	printf("test_dirname:\n");

	for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
		char buf[256];
		char *input = NULL;
		char *res;

		if (cases[i].input) {
			strncpy(buf, cases[i].input, sizeof(buf) - 1);
			buf[sizeof(buf) - 1] = '\0';
			input = buf;
		}

		res = shr_dirname(input);

		char desc[512];
		snprintf(desc, sizeof(desc), "shr_dirname(\"%s\")", cases[i].input ? cases[i].input : "NULL");
		pass &= check_str(desc, res, cases[i].expected);
	}

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

static bool test_mkdir(void)
{
	static const char *dir = "shr-test-mkdir-dir";
	bool pass = true;
	int ret;

	printf("test_mkdir:\n");

	/* Clean up if it was left over from a previous crashed run */
	rmdir(dir);

	ret = shr_mkdir(dir, 0755);
	pass &= check_ret("creates directory", ret, 0);
	pass &= check_bool("the directory is real and writable",
			    dir_is_writable(dir));

	ret = shr_mkdir(dir, 0755);
	pass &= check_ret("re-running on an existing directory returns -EEXIST", ret, -EEXIST);

	rmdir(dir);

	return pass;
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

static bool test_mkstemp(void)
{
	char template[] = "shr-test-mkstemp-XXXXXX";
	bool pass = true;
	int fd;

	printf("test_mkstemp:\n");

	fd = shr_mkstemp(template);
	pass &= check_bool("returns a valid fd", fd >= 0);
	if (fd < 0)
		return pass;

	pass &= check_bool("template's X's got replaced",
			    strcmp(template, "shr-test-mkstemp-XXXXXX") != 0);

#if !defined(_WIN32)
	int flags = fcntl(fd, F_GETFD);
	pass &= check_bool("O_CLOEXEC is set on the returned fd",
			    flags >= 0 && (flags & FD_CLOEXEC));
#endif

	close(fd);
	unlink(template);

	return pass;
}

static bool test_mkdir_from_fname(void)
{
	static const char *base = "shr-test-mkdir-fname-dir";
	char fname[256];
	bool pass = true;
	int ret;

	printf("test_mkdir_from_fname:\n");

	snprintf(fname, sizeof(fname), "%s/level1/level2/file.txt", base);

	ret = shr_mkdir_from_fname(fname, 0755);
	pass &= check_ret("creates parent directories from filename", ret, 0);
	pass &= check_bool("the deepest parent directory is real and writable",
			    dir_is_writable("shr-test-mkdir-fname-dir/level1/level2"));

	ret = shr_mkdir_from_fname(fname, 0755);
	pass &= check_ret("re-running on an existing tree is a no-op success",
			   ret, 0);

	ret = shr_mkdir_from_fname("bare_filename.txt", 0755);
	pass &= check_ret("bare filename without directories is a no-op success",
			   ret, 0);

	{
		char toolong[PATH_MAX + 10];

		memset(toolong, 'a', sizeof(toolong) - 1);
		toolong[sizeof(toolong) - 1] = '\0';
		toolong[PATH_MAX + 2] = '/';
		ret = shr_mkdir_from_fname(toolong, 0755);
		pass &= check_ret("a parent path longer than PATH_MAX is rejected",
				  ret, -ENAMETOOLONG);
	}

	/* Clean up what we created, deepest first. */
	rmdir("shr-test-mkdir-fname-dir/level1/level2");
	rmdir("shr-test-mkdir-fname-dir/level1");
	rmdir("shr-test-mkdir-fname-dir");

	return pass;
}

static bool test_read_file(void)
{
	static const char *dir = "shr-test-read-file-dir";
	static const char *name = "data.bin";
	static const char *content = "some file content\n";
	char path[256];
	bool pass = true;
	long size = 0;
	unsigned char *buf;
	FILE *f;

	printf("test_read_file:\n");

	shr_mkdir(dir, 0755);
	snprintf(path, sizeof(path), "%s/%s", dir, name);
	f = fopen(path, "wb");
	pass &= check_bool("test file created", f != NULL);
	if (f) {
		fwrite(content, 1, strlen(content), f);
		fclose(f);
	}

	buf = shr_read_file(NULL, path, &size, 1);
	pass &= check_bool("reads a file given as a plain path", buf != NULL);
	if (buf) {
		pass &= check_bool("size matches file content",
				    (size_t)size == strlen(content));
		pass &= check_bool("content matches what was written",
				    !memcmp(buf, content, strlen(content)));
		free(buf);
	}

	buf = shr_read_file(dir, name, &size, 1);
	pass &= check_bool("reads a file given as dir + name", buf != NULL);
	if (buf) {
		pass &= check_bool("content matches when joining dir and name",
				    (size_t)size == strlen(content) &&
				    !memcmp(buf, content, strlen(content)));
		free(buf);
	}

	buf = shr_read_file(NULL, "shr-test-read-file-does-not-exist", &size, 1);
	pass &= check_bool("a missing file returns NULL", buf == NULL);

	unlink(path);
	rmdir(dir);

	return pass;
}

static bool test_fsync_dir(void)
{
	printf("test_fsync_dir:\n");

	/* Neither call has a return value to check; passing means no crash. */
	shr_fsync_dir(".");
	shr_fsync_dir("/no/such/directory/at/all");

	printf(" - fsync_dir on a real and a bogus path [PASS]\n");

	return true;
}

static bool test_dev_null(void)
{
	bool pass = true;
	int fd;

	printf("test_dev_null:\n");

	pass &= check_bool("shr_dev_null() returns a non-empty path",
			    shr_dev_null() != NULL && *shr_dev_null());

	fd = open(shr_dev_null(), O_WRONLY);
	pass &= check_bool("the returned path can be opened for writing", fd >= 0);
	if (fd >= 0)
		close(fd);

	return pass;
}

static bool test_fsync(void)
{
	static const char *name = "shr-test-fsync-file";
	bool pass = true;
	int fd, ret;

	printf("test_fsync:\n");

	fd = open(name, O_RDWR | O_CREAT | O_TRUNC, 0644);
	pass &= check_bool("test file created", fd >= 0);
	if (fd < 0)
		return pass;

	ret = shr_fsync(fd);
	pass &= check_ret("fsync of a real fd succeeds", ret, 0);

	close(fd);
	unlink(name);

	ret = shr_fsync(fd);
	pass &= check_bool("fsync of a closed fd fails", ret < 0);

	return pass;
}

static bool test_getpagesize(void)
{
	int pagesize;
	bool pass = true;

	printf("test_getpagesize:\n");

	pagesize = shr_getpagesize();
	pass &= check_bool("returns a positive value", pagesize > 0);
	pass &= check_bool("value is a power of 2",
			    pagesize > 0 && (pagesize & (pagesize - 1)) == 0);

	return pass;
}

static bool test_open_rawdata(void)
{
	static const char *name = "shr-test-open-rawdata-file";
	static const char *content = "raw data\n";
	bool pass = true;
	int fd;
	char buf[64];
	ssize_t n;

	printf("test_open_rawdata:\n");

	fd = shr_open_rawdata(name, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	pass &= check_bool("opens a new file for writing", fd >= 0);
	if (fd >= 0) {
		n = write(fd, content, strlen(content));
		pass &= check_bool("writes the expected number of bytes",
				    n == (ssize_t)strlen(content));
		close(fd);
	}

	fd = shr_open_rawdata(name, O_RDONLY);
	pass &= check_bool("reopens the file for reading", fd >= 0);
	if (fd >= 0) {
		n = read(fd, buf, sizeof(buf) - 1);
		if (n >= 0)
			buf[n] = '\0';
		pass &= check_bool("content survives the round trip",
				    n == (ssize_t)strlen(content) &&
				    !memcmp(buf, content, strlen(content)));
		close(fd);
	}

	unlink(name);

	return pass;
}

int main(void)
{
	bool pass = true;

	pass &= test_basename();
	pass &= test_dirname();
	pass &= test_mkdir();
	pass &= test_mkdir_p();
	pass &= test_mkdir_from_fname();
	pass &= test_mkstemp();
	pass &= test_read_file();
	pass &= test_fsync_dir();
	pass &= test_dev_null();
	pass &= test_fsync();
	pass &= test_getpagesize();
	pass &= test_open_rawdata();

	fflush(stdout);
	exit(pass ? EXIT_SUCCESS : EXIT_FAILURE);
}
