/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 Dell Technologies Inc. or its subsidiaries.
 *
 * Authors: Martin Belanger <martin.belanger@dell.com>
 */
#pragma once

#include <stdbool.h>
#include <stdint.h>

#include <ccan/build_assert/build_assert.h>

#ifdef NVME_HAVE_INT128
typedef unsigned __int128 uint128_t;

#define UINT128_CONST(high, low) (((uint128_t)(high) << 64) | (low))
#define UINT128_MAX UINT128_CONST(UINT64_MAX, UINT64_MAX)
#endif /* NVME_HAVE_INT128 */

/*
 * Parse a boolean string using the systemd parse_boolean() convention:
 * 1/yes/y/true/t/on, 0/no/n/false/f/off (case-insensitive).
 * Return: 0 on success (*out set), -EINVAL if value matches neither list.
 */
int shr_parse_bool(const char *value, bool *out);

/*
 * Parse the whole string @s as an unsigned number: decimal, hexadecimal
 * with a 0x prefix or octal with a leading 0, like strtoull() with base 0,
 * but no whitespace, no sign and nothing after the digits.
 * Return: 0 on success (*out set), -EINVAL if @s is no number, -ERANGE if
 * it is larger than @max.
 */
int shr_parse_u64(const char *s, uint64_t max, uint64_t *out);

/*
 * The same for a signed number, with an optional '-' in front.
 * Return: 0 on success (*out set), -EINVAL if @s is no number, -ERANGE if
 * it is outside of @min and @max.
 */
int shr_parse_s64(const char *s, int64_t min, int64_t max, int64_t *out);

/*
 * Parse the whole string @s as a finite floating point number with a '.'
 * as decimal point, whatever the locale: no whitespace, no nan or inf and
 * nothing after the number.
 * Return: 0 on success (*out set), -EINVAL if @s is no such number,
 * -ERANGE if it is too large.
 */
int shr_parse_double(const char *s, double *out);

/*
 * Parse a comma-separated list of numbers from string (modified in place by
 * strtok()) into val, up to max_length entries. Each number is parsed with
 * strtoumax() and range-checked against the destination type; an empty
 * string is a no-op success.
 * Return: the number of entries parsed, or -1 on a parse/range/overflow error.
 */
int shr_parse_csv_int(char *string, int *val, unsigned int max_length);
int shr_parse_csv_ushort(char *string, unsigned short *val, unsigned int max_length);
int shr_parse_csv_uint(char *string, unsigned int *val, unsigned int max_length);
int shr_parse_csv_ulonglong(char *string, unsigned long long *val, unsigned int max_length);
int shr_parse_csv_uchar(char *string, unsigned char *val,
			unsigned int max_length);
#ifdef NVME_HAVE_INT128
int shr_parse_csv_uint128(char *string, uint128_t *val,
			  unsigned int max_length);
#endif /* NVME_HAVE_INT128 */

/*
 * Fixed-width aliases for the parsers above, for callers whose buffer is
 * declared uint16_t/uint32_t/uint64_t or the kernel's __u16/__u32/__u64.
 * __u16 and __u32 are "unsigned short"/"unsigned int" on every
 * architecture, so those two are exact matches. __u64 is not: it's
 * "unsigned long" on some 64-bit architectures (e.g. ppc64le) and
 * "unsigned long long" on others (e.g. x86_64), and need not match
 * uint64_t either. "unsigned long long" is the one type guaranteed to be
 * exactly 64 bits everywhere, so shr_parse_csv_u64 always routes through
 * it; BUILD_ASSERT_OR_ZERO() below rejects, at compile time, a val whose
 * pointee isn't that width instead of silently mis-parsing into it.
 */
#define shr_parse_csv_u8(string, val, max_length)			\
	shr_parse_csv_uchar(string,					\
		(unsigned char *)(val) + BUILD_ASSERT_OR_ZERO(		\
			sizeof(*(val)) == sizeof(unsigned char)),	\
		max_length)

#define shr_parse_csv_u16(string, val, max_length)			\
	shr_parse_csv_ushort(string,					\
		(unsigned short *)(val) + BUILD_ASSERT_OR_ZERO(	\
			sizeof(*(val)) == sizeof(unsigned short)),	\
		max_length)

#define shr_parse_csv_u32(string, val, max_length)			\
	shr_parse_csv_uint(string,					\
		(unsigned int *)(val) + BUILD_ASSERT_OR_ZERO(		\
			sizeof(*(val)) == sizeof(unsigned int)),	\
		max_length)

#define shr_parse_csv_u64(string, val, max_length)			\
	shr_parse_csv_ulonglong(string,				\
		(unsigned long long *)(val) + BUILD_ASSERT_OR_ZERO(	\
			sizeof(*(val)) == sizeof(unsigned long long)),	\
		max_length)

#define shr_parse_csv_u128(string, val, max_length)			\
	shr_parse_csv_uint128(string,					\
		(uint128_t *)(val) + BUILD_ASSERT_OR_ZERO(		\
			sizeof(*(val)) == sizeof(uint128_t)),		\
		max_length)
