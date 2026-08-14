// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 Micron Technology, Inc.
 *
 * Authors: Broc Going <bgoing@micron.com>
 */
#include <errno.h>
#include <fcntl.h>
#include <io.h>
#include <process.h>
#include <stdio.h>
#include <windows.h>

#include "proc-util.h"

/*
 * _dup() returns an inheritable fd, so the stdout/stderr backups would leak
 * into the child spawned with _P_NOWAIT (created before they are restored and
 * closed). Clear the inherit flag on the underlying handle so the child
 * inherits only its redirected streams.
 *
 * Note: _spawnv() passes fds 0/1/2 to the child as its standard handles via
 * the CRT startup block, regardless of the pipe's _O_NOINHERIT flag.
 * The child still receives the redirected stdout/stderr, while the raw
 * (high-numbered) pipe fds stay uninherited, which is what lets the pipe
 * reach EOF once the child exits instead of hanging the drain.
 */
static void clear_inherit(int fd)
{
	intptr_t h = _get_osfhandle(fd);

	if (h != -1)
		SetHandleInformation((HANDLE)h, HANDLE_FLAG_INHERIT, 0);
}

int shr_pipe(int fds[2])
{
	/*
	 * _O_NOINHERIT so a spawned child does not inherit the raw pipe fds:
	 * the _dup2() onto stdout/stderr in shr_spawn() gives the child only
	 * its redirected streams. Binary mode avoids CRLF translation.
	 */
	return _pipe(fds, 1 << 16, _O_BINARY | _O_NOINHERIT) ? -errno : 0;
}

int shr_spawn(const char *const argv[], int out_fd, int err_fd,
	      shr_proc_t *proc)
{
	int saved_out = -1, saved_err = -1;
	intptr_t rc = -1;
	int err = 0;

	/*
	 * Windows has no fork(): _spawnv() runs a fresh process that inherits
	 * this process's stdout/stderr. Redirect ours onto the caller's fds for
	 * the duration of the spawn, then restore them.
	 *
	 * Flush first: stdout/stderr are buffered stdio streams, and _dup2()
	 * swaps the underlying fd without touching the buffer, so any pending
	 * parent output would otherwise drain into the child's capture pipe.
	 */
	if (out_fd >= 0) {
		fflush(stdout);
		saved_out = _dup(_fileno(stdout));
		if (saved_out < 0 || _dup2(out_fd, _fileno(stdout)) < 0) {
			err = errno;
			goto restore;
		}
		clear_inherit(saved_out);
	}
	if (err_fd >= 0) {
		fflush(stderr);
		saved_err = _dup(_fileno(stderr));
		if (saved_err < 0 || _dup2(err_fd, _fileno(stderr)) < 0) {
			err = errno;
			goto restore;
		}
		clear_inherit(saved_err);
	}

	/*
	 * _P_NOWAIT so the child runs concurrently: the caller must drain a
	 * pipe target before shr_wait_proc(); waiting here would deadlock.
	 */
	rc = _spawnv(_P_NOWAIT, argv[0], argv);
	if (rc == -1)
		err = errno;

restore:
	/* Flush the child-directed streams before restoring the parent fds. */
	fflush(stdout);
	fflush(stderr);
	if (saved_out >= 0) {
		_dup2(saved_out, _fileno(stdout));
		_close(saved_out);
	}
	if (saved_err >= 0) {
		_dup2(saved_err, _fileno(stderr));
		_close(saved_err);
	}

	if (rc == -1)
		return err ? -err : -EIO;

	*proc = rc;

	return 0;
}

int shr_wait_proc(shr_proc_t proc, bool *exited, int *code)
{
	unsigned int u;
	int status;

	if (_cwait(&status, proc, 0) == -1)
		return -errno;

	/*
	 * _cwait() reports the child's exit code in status. Windows has no
	 * signals, but a crash surfaces as a Microsoft-defined error-severity
	 * NTSTATUS code in 0xC0000000-0xCFFFFFFF (e.g. 0xC0000005 access
	 * violation, 0xC00000FD stack overflow). Bound both ends so a normal
	 * exit(-1) (0xFFFFFFFF, which is above that range) is preserved as a
	 * clean exit with *code == -1 rather than misread as a crash.
	 */
	u = (unsigned int)status;
	*exited = !(u >= 0xC0000000u && u <= 0xCFFFFFFFu);
	*code = status;

	return 0;
}
