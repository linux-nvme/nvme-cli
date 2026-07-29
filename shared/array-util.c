// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 Dell Technologies Inc. or its subsidiaries.
 *
 * Authors: Martin Belanger <martin.belanger@dell.com>
 */

#include <errno.h>
#include <stdlib.h>

#include "array-util.h"

int shr_ptrarray_append(struct shr_ptrarray *a, void *item)
{
	if (a->len == a->cap) {
		size_t newcap = a->cap ? a->cap * 2 : 8;
		void **newitems = realloc(a->items, newcap * sizeof(*newitems));

		if (!newitems)
			return -ENOMEM;
		a->items = newitems;
		a->cap = newcap;
	}
	a->items[a->len++] = item;
	return 0;
}

void shr_ptrarray_free(struct shr_ptrarray *a)
{
	free(a->items);
	a->items = NULL;
	a->len = 0;
	a->cap = 0;
}
