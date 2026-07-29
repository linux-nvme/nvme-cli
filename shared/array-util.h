/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 Dell Technologies Inc. or its subsidiaries.
 *
 * Authors: Martin Belanger <martin.belanger@dell.com>
 */
#pragma once

#include <stddef.h>

#include <ccan/build_assert/build_assert.h>

/*
 * A growable array of untyped pointers, doubling capacity (starting at 8)
 * as items are appended. Neither owns nor frees the pointed-to items --
 * only the backing array itself (see shr_ptrarray_free()).
 */
struct shr_ptrarray {
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
int shr_ptrarray_append(struct shr_ptrarray *a, void *item);

/*
 * Free the backing array only, leaving *a zeroed. Caller is responsible
 * for freeing each item first if the array owns them.
 */
void shr_ptrarray_free(struct shr_ptrarray *a);

/*
 * SHR_PTRARRAY_DEFINE(name, type) declares a type-checked growable array of
 * `type *`, built on top of struct shr_ptrarray:
 *
 *   SHR_PTRARRAY_DEFINE(tid_list, struct libnvmf_tid);
 *
 * generates:
 *
 *   struct tid_list { struct libnvmf_tid **items; size_t len, cap; };
 *   int tid_list_append(struct tid_list *a, struct libnvmf_tid *item);
 *   void tid_list_free(struct tid_list *a);
 *
 * struct name is defined here with the same field order/types as struct
 * shr_ptrarray, so name##_append()/name##_free() can reinterpret-cast between
 * the two -- one macro invocation both defines the layout and generates
 * the casts, so the two can never drift apart the way two independently
 * hand-written structs could.
 */
#define SHR_PTRARRAY_DEFINE(name, type)					\
	struct name {							\
		type **items;						\
		size_t len;						\
		size_t cap;						\
	};								\
	static inline int name##_append(struct name *a, type *item)	\
	{								\
		BUILD_ASSERT(sizeof(struct name) ==			\
			     sizeof(struct shr_ptrarray));		\
		return shr_ptrarray_append(				\
			(struct shr_ptrarray *)a, item);		\
	}								\
	static inline void name##_free(struct name *a)			\
	{								\
		shr_ptrarray_free((struct shr_ptrarray *)a);		\
	}
