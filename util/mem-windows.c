// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libnvme.
 * Copyright (c) 2025 Micron Technology, Inc.
 *
 * Authors: Brandon Capener <bcapener@micron.com>
 */

#include <stdlib.h>
#include <malloc.h>
#include <string.h>

#include "platform/includes.h"
#include "mem.h"
#include "common.h"

#define ROUND_UP(N, S) ((((N) + (S) - 1) / (S)) * (S))
#define HUGE_MIN 0x80000 /* policy threshold when large pages unavailable */

void *nvme_alloc_huge(size_t len, struct nvme_mem_huge *mh)
{
	SIZE_T large_min = GetLargePageMinimum(); /* 0 if unsupported/unavailable */
	SIZE_T huge_min = large_min ? large_min : HUGE_MIN;
	SIZE_T page_size = getpagesize();
	SIZE_T align;

	memset(mh, 0, sizeof(*mh));

	len = ROUND_UP(len, page_size);

	/*
	 * For smaller allocations, use regular allocator.
	 */
	if (len < huge_min) {
		mh->p = nvme_alloc(len);
		if (!mh->p)
			return NULL;
		mh->posix_memalign = true;
		mh->len = len;
		return mh->p;
	}

	/*
	 * Try large pages first when available.
	 * Requires SeLockMemoryPrivilege and size multiple of large_min.
	 */
	if (large_min) {
		SIZE_T lp_len = ROUND_UP(len, large_min);

		mh->p = VirtualAlloc(NULL, lp_len,
					 MEM_COMMIT | MEM_RESERVE | MEM_LARGE_PAGES,
					 PAGE_READWRITE);
		if (mh->p != NULL) {
			mh->len = lp_len;
			mh->posix_memalign = false;
			return mh->p;
		}
	}

	/*
	 * Fallback to regular VirtualAlloc.
	 */
	mh->p = VirtualAlloc(NULL, len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (mh->p != NULL) {
		mh->len = len;
		mh->posix_memalign = false;
		return mh->p;
	}

	/*
	 * Final fallback: aligned heap allocation.
	 * Prefer large page size if known, otherwise page size.
	 */
	align = large_min ? large_min : page_size;
	len = ROUND_UP(len, align);
	if (posix_memalign(&mh->p, align, len))
		return NULL;

	mh->posix_memalign = true;
	mh->len = len;
	memset(mh->p, 0, mh->len);
	return mh->p;
}

void nvme_free_huge(struct nvme_mem_huge *mh)
{
	if (!mh || mh->len == 0)
		return;

	if (mh->posix_memalign)
		nvme_free(mh->p);
	else
		VirtualFree(mh->p, 0, MEM_RELEASE);

	mh->len = 0;
	mh->p = NULL;
}
