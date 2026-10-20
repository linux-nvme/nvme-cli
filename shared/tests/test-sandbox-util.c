// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 SUSE Software Solutions
 *
 * Authors: Daniel Wagner <dwagner@suse.de>
 */
#include <errno.h>
#include <stdint.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <sys/ioctl.h>
#include <sys/resource.h>
#ifdef __linux__
#include <sys/syscall.h>
#endif

#include <ccan/array_size/array_size.h>

#include <shared/sandbox-util.h>

static bool check_bool(const char *name, bool got)
{
	printf(" - %s [%s]\n", name, got ? "PASS" : "FAIL");
	return got;
}

/* What the functions write, handed back as the result. */
static struct {
	pid_t pid;
	int err;
	char text[16];
} out;
static int outside;

/*
 * Runs @fn with shr_sandbox_begin(), the child hands back @out.
 *
 * Return: what shr_sandbox_begin() returned, or -EPROTO for a result of
 * an unexpected size.
 */
static int run(int (*fn)(void *arg), void *arg)
{
	struct shr_sandbox_output res;
	int ret;

	memset(&out, 0, sizeof(out));
	ret = shr_sandbox_begin(&res);
	switch (ret) {
	case SHR_SANDBOX_OFF:
		fn(arg);
		break;
	case SHR_SANDBOX_CHILD:
		fn(arg);
		shr_sandbox_end(&out, sizeof(out));
	case SHR_SANDBOX_DONE:
		if (res.len == sizeof(out))
			memcpy(&out, res.buf, sizeof(out));
		else
			ret = -EPROTO;
		free(res.buf);
		break;
	}

	return ret;
}

static int fn_result(void *arg)
{
	out.pid = getpid();
	memcpy(out.text, "decoded", sizeof("decoded"));
	outside = 1;
	return 0;
}

/* The child is sandboxed already, so the code runs in it. */
static int fn_nested(void *arg)
{
	struct shr_sandbox_output res;

	out.err = shr_sandbox_begin(&res);
	return 0;
}

/* A child may hand back nothing. */
static bool run_empty(void)
{
	struct shr_sandbox_output res;
	int ret = shr_sandbox_begin(&res);

	if (ret == SHR_SANDBOX_CHILD)
		shr_sandbox_end(NULL, 0);
	free(res.buf);

	return ret == SHR_SANDBOX_DONE && !res.len;
}

static int fn_malloc(void *arg)
{
	size_t len = 4 << 20;
	char *p = malloc(len);

	if (!p)
		return -ENOMEM;
	memset(p, 0x5a, len);
	p = realloc(p, 2 * len);
	if (!p)
		return -ENOMEM;
	out.text[0] = p[len - 1];
	free(p);
	return 0;
}

/* Opening a file is not allowed. */
static int fn_open(void *arg)
{
	int fd = open("/dev/null", O_RDONLY);

	if (fd < 0)
		out.err = errno;
	else
		close(fd);
	return 0;
}

/* Descriptors other than stdio are closed in the sandbox. */
static int fn_write_fd(void *arg)
{
	if (write(*(int *)arg, "x", 1) < 0)
		out.err = errno;
	return 0;
}

/* stdio asks whether a stream is a terminal. */
static int fn_isatty(void *arg)
{
	struct winsize ws;

	out.err = isatty(STDIN_FILENO) &&
		!ioctl(STDIN_FILENO, TIOCGWINSZ, &ws) ? 0 : ENOTTY;
	return 0;
}

#ifdef __linux__
/* FIONREAD works on a pipe, so only the filter can make it fail. */
static int fn_ioctl(void *arg)
{
	int n;

	if (ioctl(STDIN_FILENO, FIONREAD, &n))
		out.err = errno;
	return 0;
}

/* Signal 0 only checks whether a signal could be sent. */
static int fn_tgkill(void *arg)
{
	pid_t pid = *(pid_t *)arg;

	if (syscall(SYS_tgkill, pid, pid, 0))
		out.err = errno;
	return 0;
}
#endif

/*
 * A child taken over could write data of its choice to the result pipe;
 * the caller must notice data beyond the result.
 */
static int fn_extra(void *arg)
{
	uint64_t len = sizeof(out);

	if (write(3, &len, sizeof(len)) < 0 ||
	    write(3, &out, sizeof(out)) < 0 ||
	    write(3, "x", 1) < 0)
		_exit(1);
	_exit(0);
}

/* ... and a length beyond what the caller takes. */
static int fn_huge(void *arg)
{
	uint64_t len = (uint64_t)1 << 40;

	if (write(3, &len, sizeof(len)) < 0)
		out.err = errno;
	_exit(0);
}

/* The child cannot read the time zone, the caller loads it. */
static int fn_localtime(void *arg)
{
	time_t t = 0;
	struct tm tm;

	strftime(out.text, sizeof(out.text), "%Z %z", localtime_r(&t, &tm));
	return 0;
}

static int fn_abort(void *arg)
{
	abort();
}

static int fn_exit(void *arg)
{
	_exit(0);
}

/* Runs @fn with @fd as stdin. */
static int run_stdin(int (*fn)(void *arg), int fd)
{
	int saved = dup(STDIN_FILENO), ret;

	dup2(fd, STDIN_FILENO);
	ret = run(fn, NULL);
	dup2(saved, STDIN_FILENO);
	close(saved);

	return ret;
}

/* A descriptor above a lowered limit, which a loop up to the limit misses */
static bool run_high_fd(int fd)
{
	struct rlimit saved, low;
	int high = 200;
	bool ret;

	if (getrlimit(RLIMIT_NOFILE, &saved) || saved.rlim_cur <= high ||
	    dup2(fd, high) != high) {
		printf(" - no descriptor above the limit [SKIP]\n");
		return true;
	}
	low = saved;
	low.rlim_cur = 64;
	ret = !setrlimit(RLIMIT_NOFILE, &low);
	ret &= check_bool("descriptors above the limit are closed",
			  run(fn_write_fd, &high) == SHR_SANDBOX_DONE &&
			  out.err == EBADF);
	setrlimit(RLIMIT_NOFILE, &saved);
	close(high);

	return ret;
}

int main(void)
{
	char zone[sizeof(out.text)];
	pid_t self = getpid();
	bool pass = true;
	time_t t = 0;
	struct tm tm;
	int fds[2], pty, ret;

	printf("shr_sandbox_begin:\n");

	pass &= check_bool("disabled: runs in process",
			   run(fn_result, NULL) == SHR_SANDBOX_OFF &&
			   out.pid == self && outside == 1);

	shr_sandbox_enable(true);
	outside = 0;
	ret = run(fn_result, NULL);
	if (ret == SHR_SANDBOX_OFF) {
		printf(" - no sandbox on this system [SKIP]\n");
		return pass ? 77 : EXIT_FAILURE;
	}
	pass &= check_bool("the code runs in a child",
			   ret == SHR_SANDBOX_DONE && out.pid != self);
	pass &= check_bool("the result is returned",
			   !strcmp(out.text, "decoded"));
	pass &= check_bool("other memory is not", outside == 0);
	pass &= check_bool("in the sandbox, the code runs in the child",
			   run(fn_nested, NULL) == SHR_SANDBOX_DONE &&
			   out.err == SHR_SANDBOX_OFF);
	pass &= check_bool("an empty result", run_empty());
	pass &= check_bool("memory can be allocated",
			   run(fn_malloc, NULL) == SHR_SANDBOX_DONE &&
			   out.text[0] == 0x5a);
	/* the time zone of the system, which only tells something if not UTC */
	run(fn_localtime, NULL);
	strftime(zone, sizeof(zone), "%Z %z", localtime_r(&t, &tm));
	if (strcmp(zone, "UTC +0000") && strcmp(zone, "GMT +0000"))
		pass &= check_bool("the time zone of the caller is used",
				   !strcmp(out.text, zone));
	else
		printf(" - the time zone is UTC [SKIP]\n");
	pass &= check_bool("files cannot be opened",
			   run(fn_open, NULL) == SHR_SANDBOX_DONE && out.err);

	if (!pipe(fds)) {
		pass &= check_bool("other descriptors are closed",
				   run(fn_write_fd, &fds[1]) ==
				   SHR_SANDBOX_DONE && out.err == EBADF);
		pass &= run_high_fd(fds[1]);
#ifdef __linux__
		pass &= check_bool("other ioctls fail with ENOTTY",
				   run_stdin(fn_ioctl, fds[0]) ==
				   SHR_SANDBOX_DONE && out.err == ENOTTY);
#endif
		close(fds[0]);
		close(fds[1]);
	}

	pty = posix_openpt(O_RDWR | O_NOCTTY);
	if (pty >= 0) {
		pass &= check_bool("terminal queries work",
				   run_stdin(fn_isatty, pty) ==
				   SHR_SANDBOX_DONE && !out.err);
		close(pty);
	} else {
		printf(" - no pty for the terminal queries [SKIP]\n");
	}

#ifdef __linux__
	pass &= check_bool("other processes cannot be signaled",
			   run(fn_tgkill, &self) == SHR_SANDBOX_DONE &&
			   out.err == EPERM);
#endif
	pass &= check_bool("data after the result fails",
			   run(fn_extra, NULL) == -EPROTO);
	pass &= check_bool("a result too large fails",
			   run(fn_huge, NULL) == -EPROTO);
	pass &= check_bool("abort() in the child fails",
			   run(fn_abort, NULL) == -EPROTO);
	pass &= check_bool("exit without a result fails",
			   run(fn_exit, NULL) == -EPROTO);

	return pass ? EXIT_SUCCESS : EXIT_FAILURE;
}
