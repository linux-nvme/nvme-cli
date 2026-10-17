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
 * Runs parsers of untrusted input in a forked child process which can
 * only allocate memory, write to stdout and stderr and exit: seccomp on
 * Linux, Capsicum on FreeBSD. The child then copies the memory the parser
 * wrote back to the same addresses in the caller, which a fork has in
 * common with the child. Without a sandbox, the parser just runs in the
 * caller. Either way, the caller sees the same result.
 *
 * Call it only while the process runs a single thread.
 */

/* Memory the parser writes and the caller keeps. */
struct shr_sandbox_region {
	void *addr;
	size_t size;
};

/*
 * shr_sandbox_enable() - Enable or disable the sandbox
 * @enable:	whether to run the parsers sandboxed, where supported
 *
 * Disabled by default.
 */
void shr_sandbox_enable(bool enable);

/*
 * shr_sandbox_run() - Run a parser sandboxed
 * @fn:		parser
 * @arg:	argument of @fn
 * @regions:	memory @fn writes, copied back from the sandbox
 * @nr:		number of @regions
 *
 * Runs @fn in process when the sandbox is disabled or not supported by
 * the system, e.g. under valgrind.
 *
 * Return: the return value of @fn, or a negative error code if the
 * sandbox failed, in which case @regions are unchanged.
 */
int shr_sandbox_run(int (*fn)(void *arg), void *arg,
		const struct shr_sandbox_region *regions, unsigned int nr);
