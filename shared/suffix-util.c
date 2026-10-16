// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 Tokunori Ikegami
 * Copyright (c) 2026 SUSE Software Solutions
 *
 * Authors: Daniel Wagner <dwagner@suse.de>
 *          Tokunori Ikegami <ikegami.t@gmail.com>
 */

#include <ctype.h>
#include <errno.h>
#include <float.h>
#include <limits.h>
#include <locale.h>
#include <math.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <ccan/array_size/array_size.h>

#include "suffix-util.h"

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

const char *shr_suffix_si_get(double *value)
{
	long double value_ld = *value;
	const char *suffix = shr_suffix_si_get_ld(&value_ld);

	*value = value_ld;

	return suffix;
}

/* @v * 10, false if that is larger than UINT64_MAX */
static bool mul10(uint64_t *v)
{
	if (*v > UINT64_MAX / 10)
		return false;
	*v *= 10;
	return true;
}

int shr_suffix_si_parse(const char *str, char **endptr, uint64_t *val)
{
	unsigned long long num;
	uint64_t frac = 0;
	const char *p;
	int frac_len = 0, i;

	/* strtoull() takes whitespace and a sign, a digit must lead */
	if (!isdigit((unsigned char)*str))
		return -EINVAL;

	errno = 0;
	num = strtoull(str, endptr, 0);
	if (str == *endptr || errno == ERANGE)
		return -EINVAL;
	p = *endptr;

	/* the digits after the point, which the suffix may keep */
	if (*p == '.') {
		p++;
		if (!isdigit((unsigned char)*p))
			return -EINVAL;
		for (; isdigit((unsigned char)*p); p++, frac_len++) {
			/* more digits don't fit into 64 bits, cut them off */
			if (frac_len >= 19)
				continue;
			if (!mul10(&frac))
				return -EINVAL;
			frac += *p - '0';
		}
	}
	*endptr = (char *)p;

	if (*p == '\0') {
		/* no suffix keeps no fraction */
		*val = num;
		return 0;
	}

	if (p[1] != '\0')
		return -EINVAL;

	for (i = 0; i < ARRAY_SIZE(si_suffixes); i++) {
		struct si_suffix *s = &si_suffixes[i];
		uint64_t v = num;
		int j;

		if (*p != s->suffix[0])
			continue;

		for (j = 0; j < s->exponent; j++) {
			if (!mul10(&v))
				return -EINVAL;
		}

		/* scale the fraction to the exponent, cutting off the rest */
		if (frac_len > 19)
			frac_len = 19;
		for (j = frac_len; j < (int)s->exponent; j++) {
			if (!mul10(&frac))
				return -EINVAL;
		}
		for (j = s->exponent; j < frac_len; j++)
			frac /= 10;

		if (frac > UINT64_MAX - v)
			return -EINVAL;

		*endptr = (char *)p + 1;
		*val = v + frac;
		return 0;
	}

	return -EINVAL;
}

const char *shr_suffix_si_get_ld(long double *value)
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

const char *shr_suffix_binary_get(long long *value)
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

const char *shr_suffix_dbinary_get(double *value)
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

int shr_suffix_binary_parse(const char *str, char **endptr, uint64_t *val)
{
	unsigned long long ret;
	const char *p;
	int i;

	/* strtoull() takes whitespace and a sign, a digit must lead */
	if (!isdigit((unsigned char)*str))
		return -EINVAL;

	errno = 0;
	ret = strtoull(str, endptr, 0);
	if (str == *endptr || errno == ERANGE)
		return -EINVAL;
	p = *endptr;

	/* simple number, no decimal point, no suffix */
	if (*p == '\0') {
		*val = ret;
		return 0;
	}

	/* a suffix is two characters, e.g. Ki */
	if (!p[1] || p[2])
		return -EINVAL;

	for (i = 0; i < ARRAY_SIZE(binary_suffixes); i++) {
		struct binary_suffix *s = &binary_suffixes[i];

		if (!s->suffix[0] ||
		    tolower((unsigned char)p[0]) !=
		    tolower((unsigned char)s->suffix[0]) ||
		    tolower((unsigned char)p[1]) !=
		    tolower((unsigned char)s->suffix[1]))
			continue;

		if (ret > UINT64_MAX >> s->shift)
			return -EINVAL;

		*endptr = (char *)p + 2;
		*val = ret << s->shift;
		return 0;
	}

	return -EINVAL;
}
