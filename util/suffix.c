// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *
 * Copyright 2014 PMC-Sierra, Inc.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 */

/*
 *
 *   Author: Logan Gunthorpe
 *
 *   Date:   Oct 23 2014
 *
 *   Description:
 *     Functions for dealing with number suffixes
 *
 */

#include "suffix.h"
#include "common.h"

#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <math.h>
#include <float.h>
#include <limits.h>
#include <locale.h>

static struct si_suffix {
	long double magnitude;
	unsigned int exponent;
	const char *suffix;
} si_suffixes[] = {
	{1e30, 30, "Q"},
	{1e27, 27, "R"},
	{1e24, 24, "Y"},
	{1e21, 21, "Z"},
	{1e18, 18, "E"},
	{1e15, 15, "P"},
	{1e12, 12, "T"},
	{1e9, 9, "G"},
	{1e6, 6, "M"},
	{1e3, 3, "k"},
};

const char *suffix_si_get(double *value)
{
	long double value_ld = *value;
	const char *suffix = suffix_si_get_ld(&value_ld);

	*value = value_ld;

	return suffix;
}

int suffix_si_parse(const char *str, char **endptr, uint64_t *val)
{
	unsigned long long num, frac;
	char *sep, *tmp;
	int frac_len, len, i;

	num = strtoull(str, endptr, 0);
	if (str == *endptr ||
	    ((num == ULLONG_MAX) && errno == ERANGE))
		return -EINVAL;

	/* simple number, no decimal point not suffix */
	if ((*endptr)[0] == '\0') {
		*val = num;
		return 0;
	}

	/* get rid of the decimal point */
	sep = localeconv()->decimal_point;
	if (sep)
		len = strlen(sep);
	else
		len = 0;

	for (i = 0; i < len; i++) {
		if (((*endptr)[i] == '\0') || (*endptr)[i] != sep[i])
			return -EINVAL;
	}
	*endptr += len;
	tmp = *endptr;

	/* extract the digits after decimal point */
	frac = strtoull(tmp, endptr, 0);
	if (tmp == *endptr ||
	    ((frac == ULLONG_MAX) && errno == ERANGE))
		return -EINVAL;

	/* test that we have max one character as suffix */
	if ((*endptr)[0] != '\0' && (*endptr)[1] != '\0')
		return -EINVAL;

	frac_len = *endptr - tmp;

	for (i = 0; i < ARRAY_SIZE(si_suffixes); i++) {
		struct si_suffix *s = &si_suffixes[i];

		if ((*endptr)[0] != s->suffix[0])
			continue;

		/* we should check for overflow */
		for (int j = 0; j < s->exponent; j++)
			num *= 10;

		if (s->exponent > frac_len) {
			for (int j = 0; j < s->exponent - frac_len;  j++)
				frac *= 10;
		} else if (s->exponent < frac_len) {
			for (int j = 0; j < frac_len - s->exponent;  j++)
				frac /= 10;
		} else {
			frac = 0;
		}

		*val = num + frac;
		return 0;
	}

	if ((*endptr)[0] != '\0')
		return -EINVAL;

	*val = num;
	return 0;
}

const char *suffix_si_get_ld(long double *value)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(si_suffixes); i++) {
		struct si_suffix *s = &si_suffixes[i];

		if (*value >= s->magnitude) {
			*value /= s->magnitude;
			return s->suffix;
		}
	}

	return "";
}

static struct binary_suffix {
	int shift;
	const char *suffix;
} binary_suffixes[] = {
	{50, "Pi"},
	{40, "Ti"},
	{30, "Gi"},
	{20, "Mi"},
	{10, "Ki"},
};

const char *suffix_binary_get(long long *value)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(binary_suffixes); i++) {
		struct binary_suffix *s = &binary_suffixes[i];

		if (llabs(*value) >= (1LL << s->shift)) {
			*value =
			    (*value + (1LL << (s->shift - 1))) / (1LL << s->shift);
			return s->suffix;
		}
	}

	return "";
}

const char *suffix_dbinary_get(double *value)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(binary_suffixes); i++) {
		struct binary_suffix *s = &binary_suffixes[i];

		if (fabs(*value) >= (1LL << s->shift)) {
			*value = *value / (1LL << s->shift);
			return s->suffix;
		}
	}

	return "";
}

int suffix_binary_parse(const char *str, char **endptr, uint64_t *val)
{
	uint64_t ret;
	int i;

	ret = strtoull(str, endptr, 0);
	if (str == *endptr ||
	    ((ret == ULLONG_MAX) && errno == ERANGE))
		return -EINVAL;

	if (str == *endptr) {
		*val = ret;
		return 0;
	}

	/* simple number, no decimal point, no suffix */
	if ((*endptr)[0] == '\0') {
		*val = ret;
		return 0;
	}

	for (i = 0; i < ARRAY_SIZE(binary_suffixes); i++) {
		struct binary_suffix *s = &binary_suffixes[i];

		if (tolower((*endptr)[0]) == tolower(s->suffix[0]) &&
		    (s->suffix[0] != '\0' &&
		     (((*endptr)[0] != '\0' &&
		       (*endptr)[1] != '\0' &&
		       (*endptr)[2] == '\0') &&
		      (tolower((*endptr)[1]) == tolower(s->suffix[1]))))) {
			ret <<= s->shift;
			*val = ret;
			return 0;
		}
	}

	return -EINVAL;
}
