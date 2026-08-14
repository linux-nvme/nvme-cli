/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 Dell Technologies Inc. or its subsidiaries.
 *
 * Authors: Martin Belanger <martin.belanger@dell.com>
 */
#pragma once

#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define __cleanup(fn) __attribute__((cleanup(fn)))

#define DECLARE_CLEANUP_FUNC(name, type) \
	void name(type *__p)

#define DEFINE_CLEANUP_FUNC(name, type, free_fn)\
DECLARE_CLEANUP_FUNC(name, type)		\
{						\
	if (*__p)				\
		free_fn(*__p);			\
}

static inline void shr_freep(void *p)
{
	free(*(void **)p);
}
#define __cleanup_free __cleanup(shr_freep)

struct dirents {
	struct dirent **ents;
	int num;
};

static inline void cleanup_dirents(struct dirents *ents)
{
	while (ents->num > 0)
		free(ents->ents[--ents->num]);
	free(ents->ents);
}

#define __cleanup_dirents __cleanup(cleanup_dirents)

static inline void shr_cleanup_fd(int *fd)
{
	if (*fd > STDERR_FILENO)
		close(*fd);
}
#define __cleanup_fd __cleanup(shr_cleanup_fd)

static inline DEFINE_CLEANUP_FUNC(shr_cleanup_file, FILE *, fclose)
#define __cleanup_file __cleanup(shr_cleanup_file)
