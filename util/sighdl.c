// SPDX-License-Identifier: GPL-2.0-or-later
#include <signal.h>
#include <errno.h>
#include <stddef.h>
#include <stdio.h>

#include "sighdl.h"

bool nvme_sigint_received;
bool nvme_sigwinch_received;

static void nvme_sigint_handler(int signum)
{
	if (signum == SIGINT)
		nvme_sigint_received = true;
	else if (signum == SIGWINCH)
		nvme_sigwinch_received = true;
}

int nvme_install_sigint_handler(void)
{
	struct sigaction act;

	sigemptyset(&act.sa_mask);
	act.sa_handler = nvme_sigint_handler;
	act.sa_flags = 0;

	nvme_sigint_received = false;
	if (sigaction(SIGINT, &act, NULL) == -1)
		return -errno;

	if (sigaction(SIGWINCH, &act, NULL) == -1)
		return -errno;

	return 0;
}
