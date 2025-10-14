// SPDX-License-Identifier: GPL-2.0-only
#include <signal.h>
#include <errno.h>
#include <stddef.h>

#include "sighdl.h"

bool nvme_sigint_received;

static void nvme_sigint_handler(int signum)
{
	nvme_sigint_received = true;
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

	return 0;
}
