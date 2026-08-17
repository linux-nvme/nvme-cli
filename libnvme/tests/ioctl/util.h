/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stddef.h>
#include <stdnoreturn.h>

#include <shared/cleanup-util.h>

#if (defined(__MINGW32__) || defined(__MINGW64__)) && defined(__GNUC__)
#define __fail_format(f, a) __attribute__((format(gnu_printf, f, a)))
#else
#define __fail_format(f, a) __attribute__((format(printf, f, a)))
#endif

noreturn void fail(const char *fmt, ...) __fail_format(1, 2);

#define check(condition, fmt...) ((condition) || (fail(fmt), 0))

void cmp(const void *actual, const void *expected, size_t len, const char *msg);

void arbitrary(void *buf, size_t len);

size_t arbitrary_range(size_t max);
