// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef __CLEANUP_H
#define __CLEANUP_H

#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>

#include <platform/includes.h>

#include "fabrics.h"
#include "private.h"

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

static inline void nvme_freep(void *p)
{
	__libnvme_free(*(void **)p);
}
#define _cleanup_nvme_free_ __cleanup__(nvme_freep)

static inline DEFINE_CLEANUP_FUNC(cleanup_file, FILE *, fclose)
#define __cleanup_file __cleanup(cleanup_file)

static inline DEFINE_CLEANUP_FUNC(cleanup_dir, DIR *, closedir)
#define __cleanup_dir __cleanup(cleanup_dir)

static inline void cleanup_fd(int *fd)
{
	if (*fd >= 0)
		close(*fd);
}
#define __cleanup_fd __cleanup(cleanup_fd)

static inline DEFINE_CLEANUP_FUNC(cleanup_addrinfo, struct addrinfo *, freeaddrinfo)
#define __cleanup_addrinfo __cleanup(cleanup_addrinfo)

static inline void free_uri(struct libnvme_fabrics_uri **uri)
{
	if (*uri)
		libnvmf_free_uri(*uri);
}
#define __cleanup_uri __cleanup(free_uri)

#endif
