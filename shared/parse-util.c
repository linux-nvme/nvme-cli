// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 Dell Technologies Inc. or its subsidiaries.
 *
 * Authors: Martin Belanger <martin.belanger@dell.com>
 */

#include <errno.h>
#include <string.h>
#include <strings.h>

#include <ccan/array_size/array_size.h>

#include "parse-util.h"

int parse_bool(const char *value, bool *out)
{
	static const char * const yes[] = {
		"1", "yes", "y", "true", "t", "on"
	};
	static const char * const no[] = {
		"0", "no", "n", "false", "f", "off"
	};
	size_t i;

	for (i = 0; i < ARRAY_SIZE(yes); i++) {
		if (!strcasecmp(value, yes[i])) {
			*out = true;
			return 0;
		}
	}
	for (i = 0; i < ARRAY_SIZE(no); i++) {
		if (!strcasecmp(value, no[i])) {
			*out = false;
			return 0;
		}
	}

	return -EINVAL;
}
