/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * This file is part of libnvme.
 * Copyright (c) 2026 Micron Technology, Inc.
 *
 * Cross-platform compatibility for stdlib.h.
 * Provides functionality that may be missing on some platforms.
 * Compatibility is not comprehensive. Only functionality required by
 * nvme-cli and libnvme is included.
 *
 * Authors: Brandon Capener <bcapener@micron.com>
 */
#pragma once

#include <stdlib.h>

/*
 * Cross-platform compatible free for aligned memory allocations.
 * Use when posix_memalign is used to allocate memory.
 */
#if defined(_WIN32)
#define aligned_free _aligned_free
#else
#define aligned_free free
#endif

#if defined(_WIN32)

#include <errno.h>
#include <limits.h>
#include <malloc.h>

/* Aligned memory allocation function, use aligned_free to free. */
static inline int posix_memalign(void **memptr, size_t alignment, size_t size)
{
	*memptr = _aligned_malloc(size, alignment);
	return (*memptr == NULL) ? ENOMEM : 0;
}

/* reallocarray implementation for Windows */
static inline void *reallocarray(void *ptr, size_t nmemb, size_t size)
{
	size_t total_size;

	/* Check for multiplication overflow */
	if (nmemb != 0 && size > SIZE_MAX / nmemb) {
		errno = ENOMEM;
		return NULL;
	}

	total_size = nmemb * size;
	return realloc(ptr, total_size);
}

#endif
