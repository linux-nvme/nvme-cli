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
	free(*(void **)p);
}
#define _cleanup_free_ __cleanup__(freep)

#define _cleanup_huge_ __cleanup__(nvme_free_huge)

static inline void cleanup_fd(int *fd)
{
	if (*fd > STDERR_FILENO)
		close(*fd);
}
#define _cleanup_fd_ __cleanup__(cleanup_fd)

static inline void cleanup_nvme_global_ctx(struct nvme_global_ctx **ctx)
{
	nvme_free_global_ctx(*ctx);
}
#define _cleanup_nvme_global_ctx_ __cleanup__(cleanup_nvme_global_ctx)

static inline DEFINE_CLEANUP_FUNC(cleanup_nvme_ctrl, nvme_ctrl_t, nvme_free_ctrl)
#define _cleanup_nvme_ctrl_ __cleanup__(cleanup_nvme_ctrl)

static inline void free_uri(struct nvme_fabrics_uri **uri)
{
	if (*uri)
		nvme_free_uri(*uri);
}
#define _cleanup_uri_ __cleanup__(free_uri)

static inline DEFINE_CLEANUP_FUNC(cleanup_file, FILE *, fclose)
#define _cleanup_file_ __cleanup__(cleanup_file)

#endif /* __CLEANUP_H */
