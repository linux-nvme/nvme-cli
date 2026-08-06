// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 Dell Technologies Inc. or its subsidiaries.
 *
 * Authors: Martin Belanger <martin.belanger@dell.com>
 */

#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include <ccan/array_size/array_size.h>

#include "parse-util.h"

int shr_parse_bool(const char *value, bool *out)
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

#define DEFINE_SHR_PARSE_CSV_FUNC(name, ret_t, ret_max)		\
int shr_parse_csv_ ## name(char *string, ret_t *val,			\
			   unsigned int max_length)			\
{									\
	int ret = 0;							\
	uintmax_t v;							\
	char *tmp;							\
	char *p;							\
									\
	if (!string || !*string)					\
		return 0;						\
									\
	tmp = strtok(string, ",");					\
									\
	while (tmp) {							\
		if (ret >= max_length)					\
			return -1;					\
									\
		errno = 0;						\
		v = strtoumax(tmp, &p, 0);				\
		if (*p != 0)						\
			return -1;					\
		if (errno == ERANGE ||					\
			v > ret_max) {					\
			fprintf(stderr, "%s out of range\n", tmp);	\
			return -1;					\
		}							\
		val[ret] = v;						\
		ret++;							\
									\
		tmp = strtok(NULL, ",");				\
	}								\
									\
	return ret;							\
}

DEFINE_SHR_PARSE_CSV_FUNC(int, int, INT_MAX)
DEFINE_SHR_PARSE_CSV_FUNC(ushort, unsigned short, UINT16_MAX)
DEFINE_SHR_PARSE_CSV_FUNC(uint, unsigned int, UINT32_MAX)
DEFINE_SHR_PARSE_CSV_FUNC(ulonglong, unsigned long long, ULLONG_MAX)
