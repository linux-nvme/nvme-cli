/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * This file is part of libnvme.
 * Copyright (c) 2026 Micron Technology, Inc.
 *
 * Authors: Brandon Capener <bcapener@micron.com>
 */

#include <string.h>
#include <errno.h>
#include <limits.h>
#include <malloc.h>

#include <io.h>
#include <sysinfoapi.h>
#include <winsock2.h>	/* for gethostname */

#include "compiler-attributes.h"
#include "mem.h"
#include "private.h"

/* unistd.h POSIX compatibility */

#define fsync _commit
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
