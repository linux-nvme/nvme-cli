// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 SUSE Software Solutions
 *
 * Authors: Daniel Wagner <dwagner@suse.de>
 */
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/ioctl.h>
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

/* What the functions write, as region. */
static struct {
	pid_t pid;
	int err;
	char text[16];
} out;
static int outside;

static const struct shr_sandbox_region out_region[] = {
	{ &out, sizeof(out) },
};

static int run(int (*fn)(void *arg), void *arg)
{
	memset(&out, 0, sizeof(out));
	return shr_sandbox_run(fn, arg, out_region, ARRAY_SIZE(out_region));
}

static int fn_result(void *arg)
{
	out.pid = getpid();
	memcpy(out.text, "parsed", sizeof("parsed"));
	outside = 1;
	return 42;
}

static int fn_error(void *arg)
{
	return -EINVAL;
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
	static const char data[64];

	if (write(3, data, sizeof(data)) < 0)
		out.err = errno;
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

int main(void)
{
	pid_t self = getpid();
	bool pass = true;
	int fds[2], pty;

	printf("shr_sandbox_run:\n");

	pass &= check_bool("disabled: runs in process",
			   run(fn_result, NULL) == 42 && out.pid == self &&
			   outside == 1);

	shr_sandbox_enable(true);
	outside = 0;
	if (run(fn_result, NULL) != 42 || out.pid == self) {
		printf(" - no sandbox on this system [SKIP]\n");
		return 77;
	}
	pass &= check_bool("result and regions are returned",
			   !strcmp(out.text, "parsed"));
	pass &= check_bool("other memory is not", outside == 0);
	pass &= check_bool("error of the function is returned",
			   run(fn_error, NULL) == -EINVAL);
	pass &= check_bool("memory can be allocated",
			   !run(fn_malloc, NULL) && out.text[0] == 0x5a);
	pass &= check_bool("files cannot be opened",
			   !run(fn_open, NULL) && out.err);

	if (!pipe(fds)) {
		pass &= check_bool("other descriptors are closed",
				   !run(fn_write_fd, &fds[1]) &&
				   out.err == EBADF);
#ifdef __linux__
		pass &= check_bool("other ioctls fail with ENOTTY",
				   !run_stdin(fn_ioctl, fds[0]) &&
				   out.err == ENOTTY);
#endif
		close(fds[0]);
		close(fds[1]);
	}

	pty = posix_openpt(O_RDWR | O_NOCTTY);
	if (pty >= 0) {
		pass &= check_bool("terminal queries work",
				   !run_stdin(fn_isatty, pty) && !out.err);
		close(pty);
	} else {
		printf(" - no pty for the terminal queries [SKIP]\n");
	}

#ifdef __linux__
	pass &= check_bool("other processes cannot be signaled",
			   !run(fn_tgkill, &self) && out.err == EPERM);
#endif
	pass &= check_bool("data after the result fails",
			   run(fn_extra, NULL) == -EPROTO);
	pass &= check_bool("abort() in the child fails",
			   run(fn_abort, NULL) == -EPROTO);
	pass &= check_bool("exit without a result fails",
			   run(fn_exit, NULL) == -EPROTO);

	return pass ? EXIT_SUCCESS : EXIT_FAILURE;
}
