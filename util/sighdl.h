/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef __NVME_SIGHDL
#define __NVME_SIGHDL

#include <stdbool.h>
#include <signal.h>

extern volatile sig_atomic_t nvme_sigint_received;
extern volatile sig_atomic_t nvme_sigwinch_received;

int nvme_install_sigint_handler(void);
int nvme_install_sigwinch_handler(void);

#endif // __NVME_SIGHDL
