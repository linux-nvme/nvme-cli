/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef MEM_H_
#define MEM_H_

#include <stddef.h>
#include <stdbool.h>

void *nvme_alloc(size_t len);
void *nvme_realloc(void *p, size_t len);

struct nvme_mem_huge {
	size_t len;
	bool posix_memalign; /* p has been allocated using posix_memalign */
	void *p;
};

void *nvme_alloc_huge(size_t len, struct nvme_mem_huge *mh);
void nvme_free_huge(struct nvme_mem_huge *mh);

#endif /* MEM_H_ */
