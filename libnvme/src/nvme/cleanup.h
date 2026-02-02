// SPDX-License-Identifier: LGPL-2.1-or-later
#ifndef __CLEANUP_H
#define __CLEANUP_H

#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>

#include "platform/includes.h"  /* Platform abstraction - includes all needed headers */

#include "fabrics.h"

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

static inline DEFINE_CLEANUP_FUNC(cleanup_file, FILE *, fclose)
#define _cleanup_file_ __cleanup__(cleanup_file)

static inline DEFINE_CLEANUP_FUNC(cleanup_dir, DIR *, closedir)
#define _cleanup_dir_ __cleanup__(cleanup_dir)

static inline void cleanup_fd(int *fd)
{
	if (*fd >= 0)
		close(*fd);
}
#define _cleanup_fd_ __cleanup__(cleanup_fd)

static inline DEFINE_CLEANUP_FUNC(cleanup_addrinfo, struct addrinfo *, freeaddrinfo)
#define _cleanup_addrinfo_ __cleanup__(cleanup_addrinfo)

static inline void free_uri(struct nvme_fabrics_uri **uri)
{
	if (*uri)
		nvme_free_uri(*uri);
}
#define _cleanup_uri_ __cleanup__(free_uri)

#endif
