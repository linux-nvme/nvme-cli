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
#include <stdint.h>
#include <sys/mman.h>

#include <ccan/minmax/minmax.h>

#include <shared/compiler-attributes-util.h>

#include "mem.h"
#include "private.h"

#define HUGE_MIN 0x80000

/*
 * Round @n up to the next multiple of @s, rejecting the wrap-around that the
 * round_up() macro produces for near-SIZE_MAX inputs. Returns false on
 * overflow (or @s == 0) so callers fail the allocation instead of silently
 * under-allocating and later overflowing the buffer.
 */
static bool round_up_checked(size_t n, size_t s, size_t *out)
{
	size_t rem, add;

	if (!s)
		return false;

	rem = n % s;
	if (!rem) {
		*out = n;
		return true;
	}

	add = s - rem;
	if (n > SIZE_MAX - add)
		return false;

	*out = n + add;
	return true;
}

__shr_public void *libnvme_alloc(size_t len)
{
	size_t _len;
	void *p;

	if (!round_up_checked(len, 0x1000, &_len))
		return NULL;

	if (posix_memalign(&p, getpagesize(), _len))
		return NULL;

	memset(p, 0, _len);
	return p;
}

__shr_public void *libnvme_realloc(void *p, size_t len)
{
	size_t old_len;
	void *result;

	if (!p)
		return libnvme_alloc(len);

	old_len = malloc_usable_size(p);
	result = libnvme_alloc(len);
	if (!result)
		return NULL;

	memcpy(result, p, min_t(size_t, old_len, len));
	free(p);

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

	if (!round_up_checked(len, 0x1000, &len))
		return NULL;

	/*
	 * For smaller allocation we just use posix_memalign and hope the kernel
	 * is able to convert to a contiguous memory region.
	 */
	if (len < HUGE_MIN) {
		mh->p = libnvme_alloc(len);
		if (!mh->p)
			return NULL;
		mh->libnvme_alloc = true;
		mh->len = len;
		return mh->p;
	}

	/*
	 * Larger allocation will almost certainly fail with the small
	 * allocation approach. Instead try pre-allocating memory from the
	 * HugeTLB pool.
	 *
	 * https://www.kernel.org/doc/Documentation/vm/hugetlbpage.txt
	 */
	mh->p = mmap(NULL, len, PROT_READ | PROT_WRITE,
		     MAP_ANONYMOUS | MAP_PRIVATE | MAP_HUGETLB, -1, 0);
	if (mh->p != MAP_FAILED) {
		mh->len = len;
		return mh->p;
	}

	/*
	 * And if mmap fails because the pool is empty, try to use
	 * posix_memalign/madvise as fallback with a 2MB aligmnent in order to
	 * fullfil the request. This gives the kernel a chance to try to claim
	 * some huge pages. This might still fail though.
	 */
	if (!round_up_checked(len, 0x200000, &len))
		return NULL;
	if (posix_memalign(&mh->p, 0x200000, len))
		return NULL;
	mh->libnvme_alloc = true;
	mh->len = len;

	memset(mh->p, 0, mh->len);

	/*
	 * MADV_HUGEPAGE is advisory. Keep the aligned allocation when
	 * transparent huge pages are unavailable. Let the I/O path try to map
	 * the buffer.
	 */
	madvise(mh->p, mh->len, MADV_HUGEPAGE);

	return mh->p;
}

__shr_public void libnvme_free_huge(struct libnvme_mem_huge *mh)

{
	if (!mh || mh->len == 0)
		return;

	if (mh->libnvme_alloc)
		free(mh->p);
	else
		munmap(mh->p, mh->len);

	mh->len = 0;
	mh->p = NULL;
}
