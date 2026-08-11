/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 SUSE Software Solutions
 *
 * Authors: Daniel Wagner <dwagner@suse.de>
 */
#pragma once

#include <stdbool.h>
#include <stdint.h>

#include <ccan/endian/endian.h>

/*
 * VMs on arm64 can only use a subset of instructions for MMIO that provide
 * the hypervisor with a complete instruction decode. Use assembly MMIO
 * accessors there to prevent the compiler from emitting a possibly
 * unsupported instruction.
 *
 * See kernel commit c726200dd106 ("KVM: arm/arm64: Allow reporting non-ISV
 * data aborts to userspace") for more details.
 */
#if defined(__aarch64__)
static inline leint32_t __shr_raw_readl(const volatile leint32_t *addr)
{
	leint32_t val;

	asm volatile("ldr %w0, %1" : "=r" (val) : "Qo" (*addr));

	return val;
}

static inline void __shr_raw_writel(volatile leint32_t *addr, leint32_t val)
{
	asm volatile("str %w0, %1" : : "r" (val), "Qo" (*addr));
}

static inline void __shr_raw_writeq(volatile leint64_t *addr, leint64_t val)
{
	asm volatile("str %0, %1" : : "r" (val), "Qo" (*addr));
}
#else
static inline leint32_t __shr_raw_readl(volatile leint32_t *addr)
{
	return *addr;
}

static inline void __shr_raw_writel(volatile leint32_t *addr, leint32_t val)
{
	*addr = val;
}

static inline void __shr_raw_writeq(volatile leint64_t *addr, leint64_t val)
{
	*addr = val;
}
#endif

static inline uint32_t shr_mmio_read32(void *addr)
{
	return le32_to_cpu(__shr_raw_readl(addr));
}

/* Access 64-bit registers as 2 32-bit; Some devices fail 64-bit MMIO. */
static inline uint64_t shr_mmio_read64(void *addr)
{
	uint32_t low, high;

	low = le32_to_cpu(__shr_raw_readl(addr));
	high = le32_to_cpu(__shr_raw_readl(addr + sizeof(leint32_t)));

	return ((uint64_t)high << 32) | low;
}

static inline void shr_mmio_write32(void *addr, uint32_t value)
{
	__shr_raw_writel(addr, cpu_to_le32(value));
}

/* Access 64-bit registers as 2 32-bit if write32 is set; some devices fail 64-bit MMIO. */
static inline void shr_mmio_write64(void *addr, uint64_t value, bool write32)
{
	if (write32) {
		shr_mmio_write32(addr, value);
		shr_mmio_write32((uint32_t *)addr + 1, value >> 32);
		return;
	}

	__shr_raw_writeq(addr, cpu_to_le64(value));
}
