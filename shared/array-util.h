/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 Dell Technologies Inc. or its subsidiaries.
 *
 * Authors: Martin Belanger <martin.belanger@dell.com>
 */
#pragma once

#include <stddef.h>

/*
 * A growable array of untyped pointers, doubling capacity (starting at 8)
 * as items are appended. Neither owns nor frees the pointed-to items --
 * only the backing array itself (see ptrarray_free()).
 */
struct ptrarray {
	void **items;
	size_t len;
	size_t cap;
};

/*
 * Append item to a, growing the backing array as needed.
 *
 * To build a NULL-terminated array (e.g. to hand back to a caller that
 * expects one), append every real item, then append NULL last -- that
 * final call reserves the extra slot itself, same as any other append.
 *
 * Return: 0 on success, -ENOMEM on allocation failure.
 */
int ptrarray_append(struct ptrarray *a, void *item);

/*
 * Free the backing array only, leaving *a zeroed. Caller is responsible
 * for freeing each item first if the array owns them.
 */
void ptrarray_free(struct ptrarray *a);
