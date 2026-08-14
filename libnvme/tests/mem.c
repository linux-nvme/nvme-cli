// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * Test the ordinary-memory fallback used when huge pages are unavailable.
 */

#include <dlfcn.h>
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <sys/mman.h>
#include <unistd.h>

#include <shared/compiler-attributes.h>
#include <shared/shr-assert.h>

#include <libnvme.h>

static bool madvise_called;

typedef void *(*mmap_func_t)(void *, size_t, int, int, int, off_t);

void *mmap(void *addr, size_t length, int prot, int flags, int fd,
	   off_t offset)
{
	mmap_func_t real_mmap;

	if (flags & MAP_HUGETLB) {
		errno = EINVAL;
		return MAP_FAILED;
	}

	real_mmap = (mmap_func_t)dlsym(RTLD_NEXT, "mmap");
	shr_assert(real_mmap);

	return real_mmap(addr, length, prot, flags, fd, offset);
}

int madvise(__shr_unused void *addr, __shr_unused size_t length,
	    __shr_unused int advice)
{
	madvise_called = true;
	errno = EINVAL;
	return -1;
}

int main(void)
{
	struct libnvme_mem_huge mh = { 0 };
	unsigned char *buf;

	buf = libnvme_alloc_huge(2 * 1024 * 1024, &mh);
	shr_assert(madvise_called);
	shr_assert(buf);
	shr_assert(mh.p == buf);
	shr_assert(mh.libnvme_alloc);
	shr_assert(mh.len == 2 * 1024 * 1024);
	shr_assert(buf[0] == 0);
	shr_assert(buf[mh.len - 1] == 0);

	buf[mh.len - 1] = 0xa5;
	libnvme_free_huge(&mh);
	shr_assert(!mh.p);
	shr_assert(!mh.len);

	return 0;
}
