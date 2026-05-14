/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * This file is part of libnvme.
 * Copyright (c) 2026 Micron Technology, Inc.
 *
 * Cross-platform compatibility for signal.h.
 * Provides functionality that may be missing on some platforms.
 * Compatibility is not comprehensive. Only functionality required by
 * nvme-cli and libnvme is included.
 *
 * Authors: Brandon Busacker <bbusacker@micron.com>
 */
#pragma once

#include <signal.h>

#if defined(_WIN32)

/* signal.h POSIX compatibility - Windows doesn't have sigaction */

struct sigaction {
	void (*sa_handler)(int);
	int sa_flags;
	int sa_mask;  /* simplified - normally sigset_t */
};

static inline int sigemptyset(int *set)
{
	*set = 0;
	return 0;
}

/*
 * Simplified signal handling using Windows signal() function
 * This is sufficient for handling SIGINT with no mask or flags.
 */
static inline int sigaction(int signum, const struct sigaction *act,
			struct sigaction *oldact)
{
	(void)oldact; /* ignore old action for simplicity */
	if (act && act->sa_handler) {
		signal(signum, act->sa_handler);
		return 0;
	}
	return -1;
}

#endif
