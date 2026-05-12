// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libnvme.
 * Copyright (c) 2026 SUSE Software Solutions
 *
 * Authors: Daniel Wagner <dwagner@suse.de>
 */
#pragma once

#include <stddef.h>

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
