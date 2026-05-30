// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libnvme.
 * Copyright (c) 2022 Code Construct
 *
 * Common test utilities for libnvme tests. These have quite strict error
 * handling, so the general pattern is to abort/exit on error.
 */
#pragma once

#include <stdio.h>

FILE *test_setup_log(void);
void test_print_log_buf(FILE *logfd);
void test_close_log(FILE *fd);
