/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef __CLEANUP_H
#define __CLEANUP_H

#include <stdlib.h>
#include <unistd.h>

#include <libnvme.h>

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

static inline void libnvme_freep(void *p)
{
	libnvme_free(*(void **)p);
}
#define __cleanup_libnvme_free __cleanup(libnvme_freep)

#define __cleanup_huge __cleanup(libnvme_free_huge)

static inline void cleanup_fd(int *fd)
{
	if (*fd > STDERR_FILENO)
		close(*fd);
}
#define __cleanup_fd __cleanup(cleanup_fd)

static inline void cleanup_nvme_global_ctx(struct libnvme_global_ctx **ctx)
{
	libnvme_free_global_ctx(*ctx);
}
#define __cleanup_nvme_global_ctx __cleanup(cleanup_nvme_global_ctx)

static inline void cleanup_nvme_ctrl(libnvme_ctrl_t *__p)
{
	libnvme_free_ctrl(*__p);
}
#define __cleanup_nvme_ctrl __cleanup(cleanup_nvme_ctrl)

#ifdef CONFIG_FABRICS
static inline void free_uri(struct libnvmf_uri **uri)
{
	libnvmf_uri_free(*uri);
}
#define __cleanup_uri __cleanup(free_uri)

static inline void cleanup_nvmf_context(struct libnvmf_context **fctx)
{
	libnvmf_context_free(*fctx);
}
#define __cleanup_nvmf_context __cleanup(cleanup_nvmf_context)
#endif

static inline DEFINE_CLEANUP_FUNC(cleanup_file, FILE *, fclose)
#define __cleanup_file __cleanup(cleanup_file)

#endif /* __CLEANUP_H */
