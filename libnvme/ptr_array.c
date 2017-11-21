/*
 * Copyright (C) 2017 Red Hat, Inc.
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; If not, see <http://www.gnu.org/licenses/>.
 *
 * Author: Gris Ge <fge@redhat.com>
 */

#include <assert.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>

#include "ptr_array.h"

#define _INITIAL_ARRAY_SIZE		255

struct ptr_array {
	void **array;
	uint32_t size;
	uint32_t allocated_size;
};

static int _ptr_array_grow_if_needed(struct ptr_array *pa,
				     uint32_t expected_size)
{
	void *new_array = NULL;

	while(pa->allocated_size < expected_size) {
		new_array = (void **) realloc(pa->array,
					      sizeof(void *) *
					      pa->allocated_size * 2);
		if (new_array == NULL) {
			errno = ENOMEM;
			return ENOMEM;
		}
		pa->allocated_size *= 2;
		pa->array = new_array;
	}
	memset(pa->array + pa->size, 0,
	       sizeof(void *) * (pa->allocated_size - pa->size));
	return 0;
}

struct ptr_array *ptr_array_new(uint32_t size)
{
	struct ptr_array *pa = NULL;

	pa = (struct ptr_array *) calloc(1, sizeof(struct ptr_array));
	if (pa == NULL)
		goto nomem;

	if (size < _INITIAL_ARRAY_SIZE)
		size = _INITIAL_ARRAY_SIZE;

	pa->allocated_size = size;

	pa->array = (void **) calloc(size, sizeof(void *));
	if (pa->array == NULL) {
		free(pa);
		goto nomem;
	}
	return pa;

nomem:
	errno = ENOMEM;
	return NULL;
}

void ptr_array_update(struct ptr_array *pa, uint32_t index, void *data)
{
	assert(pa != NULL);

	if (_ptr_array_grow_if_needed(pa, index + 1) != 0)
		return;

	pa->array[index] = data;
	if (index >= pa->size)
		pa->size = index + 1;
}

int ptr_array_insert(struct ptr_array *pa, void *data)
{
	assert(pa != NULL);

	if (_ptr_array_grow_if_needed(pa, pa->size + 1) != 0)
		return errno;


	pa->array[pa->size] = data;
	pa->size++;

	return 0;
}

void ptr_array_free(struct ptr_array *pa)
{
	if (pa != NULL)
		free(pa->array);
	free(pa);
}

void *ptr_array_get(struct ptr_array *pa, uint32_t index)
{
	assert(pa != NULL);

	if (pa->size <= index)
		return NULL;

	return pa->array[index];
}

uint32_t ptr_array_size(struct ptr_array *pa)
{
	assert(pa != NULL);
	return pa->size;
}

int ptr_array_extract(struct ptr_array *pa, void ***array, uint32_t *count)
{
	assert(pa != NULL);
	assert(array != NULL);
	assert(count != NULL);

	if (pa->size == 0) {
		*array = NULL;
		*count = 0;
		return 0;
	}

	*array = (void **) calloc(pa->size, sizeof(void *));
	if (*array == NULL) {
		errno = ENOMEM;
		return ENOMEM;
	}
	*count = pa->size;
	memcpy(*array, pa->array, sizeof(void *) * pa->size);
	return 0;
}
