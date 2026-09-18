// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libnvme.
 *
 * Initialize the crash handler when libnvme is loaded.
 */

#include <shared/crash-util.h>

static __attribute__((constructor)) void libnvme_init_crash_handler(void)
{
	shr_install_crash_handler();
}
