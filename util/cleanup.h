/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef __CLEANUP_H
#define __CLEANUP_H

#include <stdlib.h>
#include <unistd.h>

#include <libnvme.h>

#include "util/mem.h"

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
#define _cleanup_free_ __cleanup(freep)

#define _cleanup_huge_ __cleanup(nvme_free_huge)

static inline void cleanup_fd(int *fd)
{
	if (*fd > STDERR_FILENO)
		close(*fd);
}
#define _cleanup_fd_ __cleanup(cleanup_fd)

static inline void cleanup_nvme_global_ctx(struct libnvme_global_ctx **ctx)
{
	libnvme_free_global_ctx(*ctx);
}
#define _cleanup_nvme_global_ctx_ __cleanup(cleanup_nvme_global_ctx)

static inline DEFINE_CLEANUP_FUNC(cleanup_nvme_ctrl, libnvme_ctrl_t, libnvme_free_ctrl)
#define _cleanup_nvme_ctrl_ __cleanup(cleanup_nvme_ctrl)

#ifdef CONFIG_FABRICS
static inline void free_uri(struct libnvme_fabrics_uri **uri)
{
	if (*uri)
		libnvmf_free_uri(*uri);
}
#define _cleanup_uri_ __cleanup(free_uri)

static inline void cleanup_nvmf_context(struct libnvmf_context **fctx)
{
	libnvmf_context_free(*fctx);
}
#define _cleanup_nvmf_context_ __cleanup(cleanup_nvmf_context)
#endif

static inline DEFINE_CLEANUP_FUNC(cleanup_file, FILE *, fclose)
#define _cleanup_file_ __cleanup(cleanup_file)

#endif /* __CLEANUP_H */
