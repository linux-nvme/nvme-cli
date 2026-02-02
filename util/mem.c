/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <stdlib.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#ifndef _WIN32
#include <sys/mman.h>
#endif

#include "platform/includes.h"

#include "mem.h"

#include "common.h"

#define ROUND_UP(N, S) ((((N) + (S) - 1) / (S)) * (S))
#define HUGE_MIN 0x80000

void *nvme_alloc(size_t len)
{
	void *p;

	len = ROUND_UP(len, 0x1000);
	if (posix_memalign((void *)&p, getpagesize(), len))
		return NULL;

	memset(p, 0, len);
	return p;
}

void *nvme_realloc(void *p, size_t len)
{
	size_t old_len = malloc_usable_size(p);

	void *result = nvme_alloc(len);

	if (p) {
		memcpy(result, p, min(old_len, len));
		free(p);
	}

	return result;
}

void *nvme_alloc_huge(size_t len, struct nvme_mem_huge *mh)
{
	memset(mh, 0, sizeof(*mh));

	len = ROUND_UP(len, 0x1000);

	/*
	 * For smaller allocation we just use posix_memalign and hope the kernel
	 * is able to convert to a contiguous memory region.
	 */
	if (len < HUGE_MIN) {
		mh->p = nvme_alloc(len);
		if (!mh->p)
			return NULL;
		mh->posix_memalign = true;
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
	len = ROUND_UP(len, 0x200000);
	if (posix_memalign(&mh->p, 0x200000, len))
		return NULL;
	mh->posix_memalign = true;
	mh->len = len;

	memset(mh->p, 0, mh->len);

	if (madvise(mh->p, mh->len, MADV_HUGEPAGE) < 0) {
		nvme_free_huge(mh);
		return NULL;
	}

	return mh->p;
}

void nvme_free_huge(struct nvme_mem_huge *mh)

{
	if (!mh || mh->len == 0)
		return;

	if (mh->posix_memalign)
		free(mh->p);
	else
		munmap(mh->p, mh->len);

	mh->len = 0;
	mh->p = NULL;
}
