/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 Micron Technology, Inc.
 *
 * Authors: Broc Going <bgoing@micron.com>
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/*
 * Create a pipe. fds[0] is the read end, fds[1] the write end. On Windows the
 * pipe is opened in binary mode (no CRLF translation).
 * Return: 0 on success, -errno otherwise.
 */
int shr_pipe(int fds[2]);

/* Opaque child handle: a pid_t on POSIX, a process HANDLE on Windows. */
typedef intptr_t shr_proc_t;

/*
 * Spawn argv[0] with arguments argv (NULL-terminated) WITHOUT a shell and
 * return immediately; the child runs concurrently. No command string is built,
 * so there is no shell to interpret metacharacters. argv[0] must be a path to
 * the executable (no PATH search), mirroring _spawnv()/execv().
 *
 * If out_fd/err_fd are >= 0, the child's stdout/stderr are redirected to them
 * (pass the same fd for both to merge, the 2>&1 equivalent; pass distinct pipes
 * to keep them separate; either may point at a real file); -1 means inherit.
 *
 * If a redirect target is a pipe, drain its read end while the child runs and
 * only THEN call shr_wait_proc(); a child that fills the pipe buffer blocks on
 * write() until the reader drains it, so waiting first would deadlock.
 *
 * On success *proc receives the child handle for shr_wait_proc().
 * Return: 0 on success, -errno if the child could not be spawned.
 */
int shr_spawn(const char *const argv[], int out_fd, int err_fd,
	      shr_proc_t *proc);

/*
 * Like shr_spawn(), but resolve argv[0] through PATH when it contains no path
 * separator, mirroring execvp()/_spawnvp(). An argv[0] that already contains a
 * path separator is used as-is (no PATH search). Because PATH search widens the
 * set of binaries that may run, prefer shr_spawn() with an absolute path when
 * the executable location is known.
 *
 * The out_fd/err_fd redirection, pipe-drain-before-wait, and *proc semantics
 * are identical to shr_spawn().
 * Return: 0 on success, -errno if the child could not be spawned.
 */
int shr_spawnp(const char *const argv[], int out_fd, int err_fd,
	       shr_proc_t *proc);

/*
 * Wait for a child from shr_spawn() and report how it ended. On success *exited
 * is set true if the child terminated normally and *code to its exit status;
 * *exited is false if it crashed or was killed by a signal.
 * Return: 0 on success, -errno if the child could not be waited for.
 */
int shr_wait_proc(shr_proc_t proc, bool *exited, int *code);
