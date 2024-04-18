/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _COMMON_H
#define _COMMON_H

#include <string.h>
#include <stdbool.h>

#include "ccan/endian/endian.h"

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

#define min(x, y) ((x) > (y) ? (y) : (x))
#define max(x, y) ((x) > (y) ? (x) : (y))

#ifdef __packed
#else /* __packed */
#define __packed __attribute__((__packed__))
#endif /* __packed */

static inline uint32_t mmio_read32(void *addr)
{
	leint32_t *p = addr;

	return le32_to_cpu(*p);
}

/* Access 64-bit registers as 2 32-bit; Some devices fail 64-bit MMIO. */
static inline uint64_t mmio_read64(void *addr)
{
	const volatile uint32_t *p = addr;
	uint32_t low, high;

	low = le32_to_cpu(*p);
	high = le32_to_cpu(*(p + 1));

	return ((uint64_t)high << 32) | low;
}

static inline void mmio_write32(void *addr, uint32_t value)
{
	leint32_t *p = addr;

	*p = cpu_to_le32(value);
}

/* Access 64-bit registers as 2 32-bit if write32 flag set; Some devices fail 64-bit MMIO. */
static inline void mmio_write64(void *addr, uint64_t value, bool write32)
{
	uint64_t *p = addr;

	if (write32) {
		mmio_write32(addr, value);
		mmio_write32((uint32_t *)addr + 1, value >> 32);
		return;
	}

	*p = cpu_to_le64(value);
}
#endif
