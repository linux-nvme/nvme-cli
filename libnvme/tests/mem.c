// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * Test the ordinary-memory fallback used when huge pages are unavailable.
 */

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <compiler-attributes.h>
#include <shr-assert.h>

#include <libnvme.h>

static bool madvise_called;

void *mmap(void *addr, size_t length, int prot, int flags, int fd,
	   off_t offset)
{
	if (flags & MAP_HUGETLB) {
		errno = EINVAL;
		return MAP_FAILED;
	}

	return (void *)syscall(SYS_mmap, addr, length, prot, flags, fd, offset);
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
