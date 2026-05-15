// SPDX-License-Identifier: GPL-2.0-or-later
#include <signal.h>
#include <errno.h>

#include "sighdl.h"

volatile sig_atomic_t nvme_sigint_received;

static void nvme_sigint_handler(int signum)
{
	nvme_sigint_received = true;
}

int nvme_install_sigint_handler(void)
{
	nvme_sigint_received = false;
	if (signal(SIGINT, nvme_sigint_handler) == SIG_ERR)
		return -errno;
	return 0;
}

int nvme_install_sigwinch_handler(void)
{
	return -ENOTSUP;
}
