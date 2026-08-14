// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 Micron Technology, Inc.
 *
 * Authors: Broc Going <bgoing@micron.com>
 */
#include <errno.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <unistd.h>

#include "proc-util.h"

int shr_pipe(int fds[2])
{
	/*
	 * O_CLOEXEC so a forked child does not leak the raw pipe fds: the
	 * dup2() onto stdout/stderr in shr_spawn() clears close-on-exec on the
	 * copies it keeps, while the originals close at execv().
	 *
	 * pipe2() sets O_CLOEXEC atomically but its glibc declaration is gated
	 * behind _GNU_SOURCE; fall back to pipe() + fcntl() where _GNU_SOURCE
	 * is not defined (e.g. the musl-style CI build).
	 */
#ifdef _GNU_SOURCE
	if (pipe2(fds, O_CLOEXEC) < 0)
		return -errno;
#else
	if (pipe(fds) < 0)
		return -errno;
	if (fcntl(fds[0], F_SETFD, FD_CLOEXEC) < 0 ||
	    fcntl(fds[1], F_SETFD, FD_CLOEXEC) < 0) {
		int e = -errno;

		close(fds[0]);
		close(fds[1]);
		return e;
	}
#endif
	return 0;
}

int shr_spawn(const char *const argv[], int out_fd, int err_fd,
	      shr_proc_t *proc)
{
	pid_t pid;

	pid = fork();
	if (pid < 0)
		return -errno;

	if (pid == 0) {
		/*
		 * Abort on a failed redirect: exec'ing with the parent's
		 * unredirected stdout would leave a caller draining a pipe that
		 * never receives the child's output, blocking until exit.
		 */
		if (out_fd >= 0 && dup2(out_fd, STDOUT_FILENO) < 0)
			_exit(127);
		if (err_fd >= 0 && dup2(err_fd, STDERR_FILENO) < 0)
			_exit(127);

		execv(argv[0], (char *const *)argv);
		_exit(127); /* exec failed */
	}

	*proc = (shr_proc_t)pid;

	return 0;
}

int shr_wait_proc(shr_proc_t proc, bool *exited, int *code)
{
	int status;

	while (waitpid((pid_t)proc, &status, 0) < 0) {
		if (errno != EINTR)
			return -errno;
	}

	*exited = WIFEXITED(status);
	*code = WIFEXITED(status) ? WEXITSTATUS(status) : -1;

	return 0;
}
