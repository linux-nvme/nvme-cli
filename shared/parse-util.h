/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 Dell Technologies Inc. or its subsidiaries.
 *
 * Authors: Martin Belanger <martin.belanger@dell.com>
 */
#pragma once

#include <stdbool.h>

#include <ccan/build_assert/build_assert.h>

/*
 * Parse a boolean string using the systemd parse_boolean() convention:
 * 1/yes/y/true/t/on, 0/no/n/false/f/off (case-insensitive).
 * Return: 0 on success (*out set), -EINVAL if value matches neither list.
 */
int shr_parse_bool(const char *value, bool *out);

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

#define shr_parse_csv_u8(string, val, max_length)			\
	shr_parse_csv_uchar(string,					\
		(unsigned char *)(val) + BUILD_ASSERT_OR_ZERO(		\
			sizeof(*(val)) == sizeof(unsigned char)),	\
		max_length)
