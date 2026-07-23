/* SPDX-License-Identifier: LGPL-2.1-or-later */
/**
 * This file is part of libnvme.
 * Copyright (c) 2026 Daniel Wagner, SUSE LLC
 */

#pragma once

#include <libnvme.h>

#define MAX_HOSTS 3

struct host_info {
	char *hostnqn;
	char *hostid;
};

extern struct host_info hosts[MAX_HOSTS];

int parse_args(struct libnvme_global_ctx *ctx, int argc, char *argv[]);
