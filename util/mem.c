/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <stdlib.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>

#include "mem.h"

#include "common.h"

#define ROUND_UP(N, S) ((((N) + (S) - 1) / (S)) * (S))

void *nvme_alloc(size_t len)
{
	size_t _len = ROUND_UP(len, 0x1000);
	void *p;

	if (posix_memalign((void *)&p, getpagesize(), _len))
		return NULL;

	memset(p, 0, _len);
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

static void *__nvme_alloc_huge(size_t len, bool *huge)
{
	void *p;

	if (!posix_memalign(&p, getpagesize(), len)) {
		*huge = false;
		memset(p, 0, len);
		return p;
	}
	return NULL;
}

#define HUGE_MIN 0x80000

#ifdef CONFIG_LIBHUGETLBFS
void nvme_free_huge(void *p, bool huge)
{
	if (huge) {
		if (p)
			free_hugepage_region(p);
	} else {
		free(p);
	}
}

void *nvme_alloc_huge(size_t len, bool *huge)
{
	void *p;

	if (len < HUGE_MIN)
		return __nvme_alloc_huge(len, huge);

	p = get_hugepage_region(len, GHR_DEFAULT);
	if (!p)
		return __nvme_alloc_huge(len, huge);

	*huge = true;
	return p;
}
#else
void nvme_free_huge(void *p, bool huge)
{
	free(p);
}

void *nvme_alloc_huge(size_t len, bool *huge)
{
	return __nvme_alloc_huge(len, huge);
}
#endif

void *nvme_realloc_huge(void *p, size_t len, bool *huge)
{
	size_t old_len = malloc_usable_size(p);
	bool was_huge = *huge;

	void *result = nvme_alloc_huge(len, huge);

	if (p) {
		memcpy(result, p, min(old_len, len));
		nvme_free_huge(p, was_huge);
	}

	return result;
}
