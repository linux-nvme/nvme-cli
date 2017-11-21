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

#ifndef _PTR_ARRAY_H_
#define _PTR_ARRAY_H_

#include <stdint.h>

#define _PTR_ARRAY_NO_PRE_ALLOCATION           0

struct ptr_array;

struct ptr_array *ptr_array_new(uint32_t size);

/*
 * The index is started at 0.
 * Grow if needed.
 * Abort by assert() if pa pointer is NULL.
 * Abort by assert() if out of index.
 */
void ptr_array_update(struct ptr_array *pa, uint32_t index, void *data);

/*
 * Grow if needed.
 * Abort by assert() if pa pointer is NULL.
 * Return ENOMEM if no memory, original pa is untouched.
 * Return 0 if no error.
 */
int ptr_array_insert(struct ptr_array *pa, void *data);

void ptr_array_free(struct ptr_array *pa);

/*
 * Abort by assert() if pa pointer is NULL.
 * Abort by assert() if out of index.
 */
void *ptr_array_get(struct ptr_array *pa, uint32_t index);

/*
 * Abort by assert() if pa pointer is NULL.
 */
uint32_t ptr_array_size(struct ptr_array *pa);

#define ptr_array_for_each(pa, i, data) \
	for (i = 0; \
	     ((pa != NULL) && (i < ptr_array_size(pa)) && \
	      ((data = ptr_array_get(pa, i)) || 1)); \
	     ++i)

/*
 * Output pointer array to fix sized array.
 * You may free the ptr_array afterwords.
 */
int ptr_array_extract(struct ptr_array *pa, void ***array, uint32_t *count);

#endif  /* End of _PTR_ARRAY_H_ */
