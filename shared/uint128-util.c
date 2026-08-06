// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2022 Jeremy Kerr
 * Copyright (c) 2023 Tokunori Ikegami
 *
 * Authors: Jeremy Kerr <jk@codeconstruct.com.au>
 *          Tokunori Ikegami <ikegami.t@gmail.com>
 *          Daniel Wagner <dwagner@suse.de>
 */

#include <locale.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include <ccan/endian/endian.h>

#include "uint128-util.h"
#include "suffix-util.h"

shr_uint128_t le128_to_cpu(uint8_t *data)
{
	shr_uint128_t u;
	shr_uint128_t tmp;

	memcpy(tmp.bytes, data, 16);
	u.words[0] = le32_to_cpu(tmp.words[3]);
	u.words[1] = le32_to_cpu(tmp.words[2]);
	u.words[2] = le32_to_cpu(tmp.words[1]);
	u.words[3] = le32_to_cpu(tmp.words[0]);
	return u;
}

long double int128_to_double(uint8_t *data)
{
	long double result = 0;
	int i;

	for (i = 0; i < 16; i++) {
		result *= 256;
		result += data[15 - i];
	}
	return result;
}

long double uint128_t_to_double(shr_uint128_t data)
{
	long double result = 0;
	int i;

	for (i = 0; i < sizeof(data.words) / sizeof(*data.words); i++) {
		result *= 4294967296;
		result += data.words[i];
	}

	return result;
}

static char *uint128_to_str(shr_uint128_t val, bool l10n)
{
	static char str[60];
	int idx = 60;
	uint64_t div, rem;
	char *sep = NULL;
	int i, len = 0, cl = 0;

	if (l10n) {
		sep = localeconv()->thousands_sep;
		len = strlen(sep);
		cl = 1;
	}

	/* terminate at the end, and build up from the ones */
	str[--idx] = '\0';

	do {
		if (len && !((sizeof(str) - idx) % (3 + cl))) {
			for (i = 0; i < len; i++)
				str[--idx] = sep[len - i - 1];
		}

		rem = val.words[0];

		div = rem / 10;
		rem = ((rem - div * 10) << 32) + val.words[1];
		val.words[0] = div;

		div = rem / 10;
		rem = ((rem - div * 10) << 32) + val.words[2];
		val.words[1] = div;

		div = rem / 10;
		rem = ((rem - div * 10) << 32) + val.words[3];
		val.words[2] = div;

		div = rem / 10;
		rem = rem - div * 10;
		val.words[3] = div;

		str[--idx] = '0' + rem;
	} while (val.words[0] || val.words[1] || val.words[2] || val.words[3]);

	return str + idx;
}

char *uint128_t_to_string(shr_uint128_t val)
{
	return uint128_to_str(val, false);
}

char *uint128_t_to_l10n_string(shr_uint128_t val)
{
	return uint128_to_str(val, true);
}

char *uint128_t_to_si_string(shr_uint128_t val, uint32_t bytes_per_unit)
{
	long double bytes = uint128_t_to_double(val) * bytes_per_unit;
	static char str[40];
	const char *suffix = shr_suffix_si_get_ld(&bytes);
	int n = snprintf(str, sizeof(str), "%.2Lf %sB", bytes, suffix);

	if (n <= 0)
		return "";

	if (n >= sizeof(str))
		str[sizeof(str) - 1] = '\0';

	return str;
}
