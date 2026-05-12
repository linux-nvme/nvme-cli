// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libnvme.
 * Copyright (c) 2026 SUSE Software Solutions
 *
 * Authors: Daniel Wagner <dwagner@suse.de>
 */
#pragma once

#include <stddef.h>
#include <stdbool.h>

/**
 * libnvme_alloc() - Allocate zero-initialized memory
 * @len: Number of bytes to allocate
 *
 * Allocates @len bytes of zero-initialized memory suitable for use by
 * libnvme APIs.
 *
 * Return: Pointer to the allocated memory on success, or %NULL on failure.
 */
void *libnvme_alloc(size_t len);

/**
 * libnvme_realloc() - Resize an allocated memory buffer
 * @p:   Existing memory buffer to resize
 * @len: New size in bytes
 *
 * Resizes the memory buffer referenced by @p to @len bytes. The returned
 * buffer may be relocated. On successful expansion, any newly allocated
 * portion of the buffer is zero-initialized.
 *
 * If @p is %NULL, this function behaves like libnvme_alloc().
 *
 * Return: Pointer to the resized memory buffer on success, or %NULL on failure.
 * On failure, the original buffer referenced by @p remains valid and
 * unchanged.
 */
void *libnvme_realloc(void *p, size_t len);

/**
 * struct libnvme_mem_huge - Huge page memory allocation descriptor
 * @len:              Size of the allocated buffer in bytes
 * @libnvme_alloc:    Indicates that @p was allocated using libnvme_alloc()
 * @p:                Pointer to the allocated memory buffer
 *
 * Describes a memory buffer allocated by libnvme_alloc_huge(). The structure
 * stores allocation metadata required for proper cleanup by
 * libnvme_free_huge().
 */
struct libnvme_mem_huge {
	size_t len;
	bool libnvme_alloc;
	void *p;
};

/**
 * libnvme_alloc_huge() - Allocate a huge page-backed memory buffer
 * @len: Size of the memory buffer in bytes
 * @mh:  Huge memory allocation descriptor
 *
 * Attempts to allocate a memory buffer backed by huge pages. Allocation
 * details are stored in @mh and must later be released using
 * libnvme_free_huge().
 *
 * Return: pointer to the allocated memory buffer on success, or %NULL on
 * failure.
 */
void *libnvme_alloc_huge(size_t len, struct libnvme_mem_huge *mh);

/**
 * libnvme_free_huge() - Free a huge page-backed memory buffer
 * @mh: Huge memory allocation descriptor
 *
 * Releases resources associated with a buffer allocated by
 * libnvme_alloc_huge(). The descriptor contents are no longer valid after
 * this call.
 */
void libnvme_free_huge(struct libnvme_mem_huge *mh);
