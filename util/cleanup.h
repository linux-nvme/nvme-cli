/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef __CLEANUP_H
#define __CLEANUP_H

#include <unistd.h>
#include <stdlib.h>

#include <libnvme.h>

#include "util/mem.h"

#define __cleanup__(fn) __attribute__((cleanup(fn)))

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
        free(*(void**) p);
}
#define _cleanup_free_ __cleanup__(freep)

#define _cleanup_huge_ __cleanup__(nvme_free_huge)

static inline void close_file(int *f)
{
	if (*f > STDERR_FILENO)
		close(*f);
}
#define _cleanup_file_ __cleanup__(close_file)

static inline void cleanup_nvme_root(nvme_root_t *r)
{
	if (r)
		nvme_free_tree(*r);
}
#define _cleanup_nvme_root_ __cleanup__(cleanup_nvme_root)

#endif
