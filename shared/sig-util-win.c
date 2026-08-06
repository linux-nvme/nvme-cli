// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of nvme-cli.
 */
#include <signal.h>
#include <errno.h>

#include "sig-util.h"

volatile sig_atomic_t shr_sigint_received;
volatile sig_atomic_t shr_sigwinch_received;

static void shr_sigint_handler(int signum)
{
	shr_sigint_received = true;
}

int shr_install_sigint_handler(void)
{
	shr_sigint_received = false;
	if (signal(SIGINT, shr_sigint_handler) == SIG_ERR)
		return -errno;
	return 0;
}

int shr_install_sigwinch_handler(void)
{
	return -ENOTSUP;
}
