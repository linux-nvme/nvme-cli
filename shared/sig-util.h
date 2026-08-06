/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 SUSE Software Solutions
 *
 * Authors: Daniel Wagner <dwagner@suse.de>
 */
#pragma once

#include <stdbool.h>
#include <signal.h>

extern volatile sig_atomic_t shr_sigint_received;
extern volatile sig_atomic_t shr_sigwinch_received;

int shr_install_sigint_handler(void);
int shr_install_sigwinch_handler(void);
