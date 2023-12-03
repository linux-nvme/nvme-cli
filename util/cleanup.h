/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef __CLEANUP_H
#define __CLEANUP_H

#include <unistd.h>
#include <stdlib.h>

#include "util/mem.h"
#include "nvme.h"

#define __cleanup__(fn) __attribute__((cleanup(fn)))

#define DEFINE_CLEANUP_FUNC(name, type, free_fn)\
void name(type *__p)				\
{						\
	if (*__p)				\
		free_fn(*__p);			\
}

static inline void freep(void *p)
{
	free(*(void **)p);
}
#define _cleanup_free_ __cleanup__(freep)

#define _cleanup_huge_ __cleanup__(nvme_free_huge)

static inline void close_file(int *f)
{
	if (*f > STDERR_FILENO)
		close(*f);
}
#define _cleanup_file_ __cleanup__(close_file)

static inline DEFINE_CLEANUP_FUNC(
	cleanup_nvme_dev, struct nvme_dev *, dev_close)
#define _cleanup_nvme_dev_ __cleanup__(cleanup_nvme_dev)

#endif
