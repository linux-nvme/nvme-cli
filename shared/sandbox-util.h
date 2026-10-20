/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 SUSE Software Solutions
 *
 * Authors: Daniel Wagner <dwagner@suse.de>
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>

/*
 * Runs code which handles untrusted data, e.g. a decoder of data a device
 * returned, in a forked child process which can only allocate memory,
 * write to stdout and stderr and exit: seccomp on Linux, Capsicum on
 * FreeBSD. The child closes all other descriptors first, so it cannot
 * reach e.g. the privsep helper.
 *
 *	struct shr_sandbox_output out;
 *
 *	switch (shr_sandbox_begin(&out)) {
 *	case SHR_SANDBOX_OFF:		// no sandbox: run it here
 *		decode(data);
 *		break;
 *	case SHR_SANDBOX_CHILD:		// in the sandbox
 *		decode(data);
 *		shr_sandbox_end(result, len);
 *	case SHR_SANDBOX_DONE:		// the child ran it, out has its result
 *		use(out.buf, out.len);
 *		free(out.buf);
 *		break;
 *	default:			// the child failed, e.g. crashed
 *		...
 *	}
 *
 * The child sees the memory of the caller as it was at the fork, so it
 * can read the data without copying it. What it changes is lost, except
 * its output on stdout and stderr and the result it hands to
 * shr_sandbox_end(). The caller must treat that result as untrusted, as
 * the child may have been taken over.
 *
 * Call it only while the process runs a single thread. Keep the standard
 * descriptors open from the start of the program, e.g. on /dev/null: the
 * child keeps them, whatever a descriptor opened while one was closed
 * refers to.
 */

/*
 * shr_sandbox_enable() - Enable or disable the sandbox
 * @enable:	whether to run the code sandboxed, where supported
 *
 * Disabled by default.
 */
void shr_sandbox_enable(bool enable);

/* What shr_sandbox_begin() returns, unless it fails. */
enum shr_sandbox_where {
	SHR_SANDBOX_OFF,	/* no sandbox: run the code in process */
	SHR_SANDBOX_CHILD,	/* in the sandbox: run the code, then end */
	SHR_SANDBOX_DONE,	/* in the caller: the child ran the code */
};

/* What the child handed to shr_sandbox_end(), malloc()ed. */
struct shr_sandbox_output {
	void *buf;
	size_t len;
};

/*
 * shr_sandbox_begin() - Run the code which follows sandboxed
 * @out:	on SHR_SANDBOX_DONE, the result of the child, to free()
 *
 * Forks a child which enters the sandbox and returns SHR_SANDBOX_CHILD.
 * The child runs the code and calls shr_sandbox_end(). The caller waits
 * for the child and returns SHR_SANDBOX_DONE. Returns SHR_SANDBOX_OFF,
 * and the caller runs the code itself, when the sandbox is disabled, not
 * supported by the system, e.g. under valgrind, or when called in the
 * sandbox already.
 *
 * Return: a value of enum shr_sandbox_where, or a negative error code if
 * the child failed: it crashed, exited without shr_sandbox_end() or wrote
 * a malformed result.
 */
int shr_sandbox_begin(struct shr_sandbox_output *out);

/*
 * shr_sandbox_end() - End the child of shr_sandbox_begin()
 * @buf:	result for the caller, may be NULL
 * @len:	length of @buf, at most 64 MiB
 */
void shr_sandbox_end(const void *buf, size_t len)
	__attribute__((noreturn));
