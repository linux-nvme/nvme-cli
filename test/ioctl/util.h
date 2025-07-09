/* SPDX-License-Identifier: LGPL-2.1-or-later */

#ifndef _LIBNVME_TEST_IOCTL_UTIL_H
#define _LIBNVME_TEST_IOCTL_UTIL_H

#include <stddef.h>
#include <stdlib.h>
#include <stdnoreturn.h>

noreturn void fail(const char *fmt, ...) __attribute__((format(printf, 1, 2)));

#define check(condition, fmt...) ((condition) || (fail(fmt), 0))

void cmp(const void *actual, const void *expected, size_t len, const char *msg);

void arbitrary(void *buf, size_t len);

size_t arbitrary_range(size_t max);

#define __cleanup__(fn) __attribute__((cleanup(fn)))

static inline void freep(void *p)
{
	free(*(void **)p);
}
#define _cleanup_free_ __cleanup__(freep)

#endif /* #ifndef _LIBNVME_TEST_IOCTL_UTIL_H */
