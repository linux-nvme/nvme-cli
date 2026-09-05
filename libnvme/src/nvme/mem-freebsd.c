/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * This file is part of libnvme.
 * Copyright (c) 2026 SUSE Software Solutions
 *
 * Authors: Daniel Wagner <dwagner@suse.de>
 */

#include <malloc_np.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <ccan/minmax/minmax.h>

#include <shared/compiler-attributes-util.h>

#include "mem.h"
#include "private.h"

/*
 * FreeBSD: plain page-aligned allocations. Linux's transparent-hugepage
 * mmap/madvise flags (MAP_HUGETLB, MADV_HUGEPAGE) have no FreeBSD
 * equivalent, so libnvme_alloc_huge() always takes the small-allocation
 * posix_memalign() path regardless of size -- correct, just without the
 * performance benefit of real huge pages.
 */

__shr_public void *libnvme_alloc(size_t len)
{
	size_t _len = round_up(len, 0x1000);
	void *p;

	if (posix_memalign((void *)&p, getpagesize(), _len))
		return NULL;

	memset(p, 0, _len);
	return p;
}

__shr_public void *libnvme_realloc(void *p, size_t len)
{
	size_t old_len = malloc_usable_size(p);
	void *result = libnvme_alloc(len);

	if (p && result) {
		memcpy(result, p, min_t(size_t, old_len, len));
		free(p);
	}

	return result;
}

__shr_public void libnvme_free(void *p)
{
	free(p);
}

__shr_public void *libnvme_alloc_huge(size_t len,
		struct libnvme_mem_huge *mh)
{
	memset(mh, 0, sizeof(*mh));

	len = round_up(len, 0x1000);

	mh->p = libnvme_alloc(len);
	if (!mh->p)
		return NULL;

	mh->libnvme_alloc = true;
	mh->len = len;
	return mh->p;
}

__shr_public void libnvme_free_huge(struct libnvme_mem_huge *mh)
{
	if (!mh || mh->len == 0)
		return;

	free(mh->p);

	mh->len = 0;
	mh->p = NULL;
}
