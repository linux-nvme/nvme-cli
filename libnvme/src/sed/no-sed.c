// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libnvme.
 * Copyright (c) 2026 SUSE Software Solutions
 *
 * Authors: Daniel Wagner <dwagner@suse.de>
 */

#include <errno.h>

#include <shared/compiler-attributes-util.h>

#include <libnvme.h>
#include <libnvme-sed.h>

__shr_public int libnvme_sed_discover(struct libnvme_transport_handle *hdl,
		void *buf, __u32 len)
{
	return -ENOTSUP;
}

__shr_public struct tcg_l0_desc *libnvme_sed_l0_next(void *buf, size_t len,
		struct tcg_l0_desc *desc)
{
	return NULL;
}

__shr_public struct tcg_l0_desc *libnvme_sed_l0_find(void *buf, size_t len,
		__u16 code)
{
	return NULL;
}
