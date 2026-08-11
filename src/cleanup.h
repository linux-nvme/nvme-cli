/* SPDX-License-Identifier: GPL-2.0-or-later */
#pragma once

#include <shared/cleanup.h>
#include <libnvme.h>

static inline void libnvme_freep(void *p)
{
	libnvme_free(*(void **)p);
}
#define __cleanup_libnvme_free __cleanup(libnvme_freep)

#define __cleanup_huge __cleanup(libnvme_free_huge)

static inline void cleanup_nvme_global_ctx(struct libnvme_global_ctx **ctx)
{
	libnvme_free_global_ctx(*ctx);
}
#define __cleanup_nvme_global_ctx __cleanup(cleanup_nvme_global_ctx)

static inline void cleanup_nvme_transport_handle(struct libnvme_transport_handle **hdl)
{
	libnvme_close(*hdl);
}
#define __cleanup_nvme_transport_handle __cleanup(cleanup_nvme_transport_handle)

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

static inline void cleanup_nvmf_tid(struct libnvmf_tid **tid)
{
	libnvmf_tid_free(*tid);
}
#define __cleanup_nvmf_tid __cleanup(cleanup_nvmf_tid)
#endif
