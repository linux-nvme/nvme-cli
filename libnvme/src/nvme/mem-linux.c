/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * This file is part of libnvme.
 * Copyright (c) 2026 SUSE Software Solutions
 *
 * Authors: Daniel Wagner <dwagner@suse.de>
 */

#include <stdlib.h>
#include <unistd.h>
#include <malloc.h>

#include <ccan/minmax/minmax.h>

#include "compiler-attributes.h"
#include "mem.h"
#include "private.h"

__libnvme_public void *libnvme_alloc(size_t len)
{
	size_t _len = round_up(len, 0x1000);
	void *p;

	if (posix_memalign((void *)&p, getpagesize(), _len))
		return NULL;

	memset(p, 0, _len);
	return p;
}

__libnvme_public void *libnvme_realloc(void *p, size_t len)
{
	size_t old_len = malloc_usable_size(p);

	void *result = libnvme_alloc(len);

	if (p && result) {
		memcpy(result, p, min_t(size_t, old_len, len));
		free(p);
	}

	return result;
}
