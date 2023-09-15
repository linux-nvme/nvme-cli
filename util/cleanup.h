/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef __CLEANUP_H
#define __CLEANUP_H

#include <unistd.h>
#include <stdlib.h>

#define __cleanup__(fn) __attribute__((cleanup(fn)))

#define DECLARE_CLEANUP_FUNC(name, type) \
	void name(type *__p)

#define DEFINE_CLEANUP_FUNC(name, type, free_fn)\
DECLARE_CLEANUP_FUNC(name, type)		\
{						\
	if (*__p)				\
		free_fn(*__p);			\
}

DECLARE_CLEANUP_FUNC(cleanup_charp, char *);

static inline void freep(void *p)
{
        free(*(void**) p);
}
#define _cleanup_free_ __cleanup__(freep)

static inline void close_file(int *f)
{
	if (*f >= 0)
		close(*f);
}
#define _cleanup_file_ __cleanup__(close_file)

#endif
