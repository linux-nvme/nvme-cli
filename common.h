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

/*
 * VMs on arm64 can only use a subset of instructions for MMIO that provide
 * the hypervisor with a complete instruction decode. Provide assembly MMIO
 * accessors to prevent the compiler from using a possibly unsupported
 * instruction.
 *
 * See kernel commit c726200dd106 ("KVM: arm/arm64: Allow reporting non-ISV
 * data aborts to userspace") for more details.
 */
#if defined(__aarch64__)
static inline leint32_t __raw_readl(const volatile leint32_t *addr)
{
	leint32_t val;

	asm volatile("ldr %w0, %1" : "=r" (val) : "Qo" (*addr));

	return val;
}

static inline void __raw_writel(volatile leint32_t *addr, leint32_t val)
{
	asm volatile("str %w0, %1" : : "r" (val), "Qo" (*addr));
}

static inline void __raw_writeq(volatile leint64_t *addr, leint64_t val)
{
	asm volatile("str %0, %1" : : "r" (val), "Qo" (*addr));
}
#else
static inline leint32_t __raw_readl(volatile leint32_t *addr)
{
	return *addr;
}

static inline void __raw_writel(volatile leint32_t *addr, leint32_t val)
{
	*addr = val;
}

static inline void __raw_writeq(volatile leint64_t *addr, leint64_t val)
{
	*addr = val;
}
#endif

static inline uint32_t mmio_read32(void *addr)
{
	return le32_to_cpu(__raw_readl(addr));
}

/* Access 64-bit registers as 2 32-bit; Some devices fail 64-bit MMIO. */
static inline uint64_t mmio_read64(void *addr)
{
	uint32_t low, high;

	low = le32_to_cpu(__raw_readl(addr));
	high = le32_to_cpu(__raw_readl(addr + sizeof(leint32_t)));

	return ((uint64_t)high << 32) | low;
}

static inline void mmio_write32(void *addr, uint32_t value)
{
	__raw_writel(addr, cpu_to_le32(value));
}

/* Access 64-bit registers as 2 32-bit if write32 flag set; Some devices fail 64-bit MMIO. */
static inline void mmio_write64(void *addr, uint64_t value, bool write32)
{
	if (write32) {
		mmio_write32(addr, value);
		mmio_write32((uint32_t *)addr + 1, value >> 32);
		return;
	}

	__raw_writeq(addr, cpu_to_le64(value));
}
#endif
