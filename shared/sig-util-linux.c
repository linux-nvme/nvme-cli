// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 SUSE Software Solutions
 *
 * Authors: Daniel Wagner <dwagner@suse.de>
 */
#include <signal.h>
#include <errno.h>
#include <stddef.h>

#include "sig-util.h"

volatile sig_atomic_t shr_sigint_received;
volatile sig_atomic_t shr_sigwinch_received;

static void shr_sigint_handler(int signum)
{
	shr_sigint_received = true;
}

static void shr_sigwinch_handler(int signum)
{
	shr_sigwinch_received = true;
}

int shr_install_sigint_handler(void)
{
	struct sigaction act = {0};

	sigemptyset(&act.sa_mask);
	act.sa_handler = shr_sigint_handler;
	act.sa_flags = 0;

	shr_sigint_received = false;
	if (sigaction(SIGINT, &act, NULL) == -1)
		return -errno;

	return 0;
}

int shr_install_sigwinch_handler(void)
{
	struct sigaction act = {0};

	sigemptyset(&act.sa_mask);
	act.sa_handler = shr_sigwinch_handler;
	act.sa_flags = 0;

	shr_sigwinch_received = false;
	if (sigaction(SIGWINCH, &act, NULL) == -1)
		return -errno;

	return 0;
}
