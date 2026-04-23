/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <string.h>

#include <nvme/malloc.h>
#include <nvme/stdlib.h>
#include <nvme/unistd.h>

#include "mem.h"

#include "common.h"

#define ROUND_UP(N, S) ((((N) + (S) - 1) / (S)) * (S))

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
	if (!result)
		return NULL;

	if (p) {
		memcpy(result, p, min(old_len, len));
		nvme_free(p);
	}

	return result;
}

void nvme_free(void *p)
{
	aligned_free(p);
}
