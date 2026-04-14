// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef __CLEANUP_H
#define __CLEANUP_H

#include <stdlib.h>

#define __cleanup(fn) __attribute__((cleanup(fn)))

#define DECLARE_CLEANUP_FUNC(name, type) \
	void name(type *__p)

#define DEFINE_CLEANUP_FUNC(name, type, free_fn)\
DECLARE_CLEANUP_FUNC(name, type)		\
{						\
	if (*__p)				\
		free_fn(*__p);			\
}

static inline void freep(void *p)
{
	free(*(void **)p);
}
#define __cleanup_free __cleanup(freep)

#endif
