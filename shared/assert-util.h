/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 SUSE Software Solutions
 *
 * Authors: Daniel Wagner <dwagner@suse.de>
 */
#pragma once

void shr_assert_fail(const char *file, int line, const char *cond) __attribute__((noreturn));

#define shr_assert(cond) \
	((void)((cond) || (shr_assert_fail(__FILE__, __LINE__, #cond), 0)))
