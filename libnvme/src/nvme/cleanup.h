// SPDX-License-Identifier: LGPL-2.1-or-later
#pragma once

#include <shared/cleanup.h>
#include <nvme/mem.h>

static inline void libnvme_freep(void *p)
{
	libnvme_free(*(void **)p);
}
#define __cleanup_libnvme_free __cleanup(libnvme_freep)
