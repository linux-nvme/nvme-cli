/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * This file is part of libnvme.
 * Copyright (c) 2026 Micron Technology, Inc.
 *
 * Authors: Brandon Capener <bcapener@micron.com>
 */

#include <string.h>
#include <malloc.h>

#include <memoryapi.h>
#include <sysinfoapi.h>

#include "compiler-attributes.h"
#include "mem.h"
#include "private.h"

#define HUGE_MIN 0x80000 /* policy threshold when large pages unavailable */

static int getpagesize(void)
{
	SYSTEM_INFO si;

	GetSystemInfo(&si);
	return si.dwPageSize;
}

__libnvme_public void *libnvme_alloc(size_t len)
{
	size_t _len = round_up(len, 0x1000);
	void *p;

	p = _aligned_malloc(_len, getpagesize());
	if (!p)
		return NULL;

	memset(p, 0, _len);
	return p;
}

__libnvme_public void *libnvme_realloc(void *p, size_t len)
{
	size_t old_len;
	void *result;

	if (!p)
		return libnvme_alloc(len);

	old_len = _aligned_msize(p, getpagesize(), 0);
	result = libnvme_alloc(len);

	if (result) {
		memcpy(result, p, min(old_len, len));
		_aligned_free(p);
	}

	return result;
}

__libnvme_public void libnvme_free(void *p)
{
	_aligned_free(p);
}

__libnvme_public void *libnvme_alloc_huge(size_t len,
		struct libnvme_mem_huge *mh)
{
	SIZE_T large_min = GetLargePageMinimum(); /* 0 if unsupported/unavailable */
	SIZE_T huge_min = large_min ? large_min : HUGE_MIN;
	SIZE_T page_size = getpagesize();
	SIZE_T align;

	memset(mh, 0, sizeof(*mh));

	len = round_up(len, page_size);

	/*
	 * For smaller allocations, use regular allocator.
	 */
	if (len < huge_min) {
		mh->p = libnvme_alloc(len);
		if (!mh->p)
			return NULL;
		mh->libnvme_alloc = true;
		mh->len = len;
		return mh->p;
	}

	/*
	 * Try large pages first when available.
	 * Requires SeLockMemoryPrivilege and size multiple of large_min.
	 */
	if (large_min) {
		SIZE_T lp_len = round_up(len, large_min);

		mh->p = VirtualAlloc(NULL, lp_len,
					 MEM_COMMIT | MEM_RESERVE | MEM_LARGE_PAGES,
					 PAGE_READWRITE);
		if (mh->p != NULL) {
			mh->len = lp_len;
			mh->libnvme_alloc = false;
			return mh->p;
		}
	}

	/*
	 * Fallback to regular VirtualAlloc.
	 */
	mh->p = VirtualAlloc(NULL, len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (mh->p != NULL) {
		mh->len = len;
		mh->libnvme_alloc = false;
		return mh->p;
	}

	/*
	 * Final fallback: aligned heap allocation.
	 * Prefer large page size if known, otherwise page size.
	 */
	align = large_min ? large_min : page_size;
	len = round_up(len, align);
	mh->p = _aligned_malloc(len, align);
	if (mh->p == NULL)
		return NULL;

	mh->libnvme_alloc = true;
	mh->len = len;
	memset(mh->p, 0, mh->len);
	return mh->p;
}

__libnvme_public void libnvme_free_huge(struct libnvme_mem_huge *mh)
{
	if (!mh || mh->len == 0)
		return;

	if (mh->libnvme_alloc)
		_aligned_free(mh->p);
	else
		VirtualFree(mh->p, 0, MEM_RELEASE);

	mh->len = 0;
	mh->p = NULL;
}
