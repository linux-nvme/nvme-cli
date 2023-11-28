/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef MEM_H_
#define MEM_H_

#include <stddef.h>
#include <stdbool.h>

void *nvme_alloc(size_t len);
void *nvme_realloc(void *p, size_t len);

void *nvme_alloc_huge(size_t len, bool *huge);
void nvme_free_huge(void *p, bool huge);

#endif /* MEM_H_ */
