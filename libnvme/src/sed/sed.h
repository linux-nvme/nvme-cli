/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * This file is part of libnvme.
 * Copyright (c) 2026 SUSE Software Solutions
 *
 * Authors: Daniel Wagner <dwagner@suse.de>
 */
#pragma once

#include <stddef.h>

#include <nvme/lib.h>
#include <nvme/types.h>
#include <sed/tcg-types.h>

/**
 * DOC: sed.h - TCG Storage (Self-Encrypting Drive) support
 */

/**
 * libnvme_sed_discover() - Retrieve the TCG Level 0 Discovery data
 * @hdl:	Transport handle
 * @buf:	Buffer for the Level 0 Discovery data
 * @len:	Size of @buf in bytes
 *
 * Issues a Security Receive for the Level 0 Discovery ComID. The data
 * is returned unparsed; use libnvme_sed_l0_for_each() or
 * libnvme_sed_l0_find() to walk the feature descriptors.
 *
 * Return: 0 on success, the NVMe command status if a response was
 * received (see &enum nvme_status_field) or a negative error code
 * otherwise.
 */
int libnvme_sed_discover(struct libnvme_transport_handle *hdl,
		void *buf, __u32 len);

/**
 * libnvme_sed_l0_next() - Return the next Level 0 Discovery descriptor
 * @buf:	Level 0 Discovery data
 * @len:	Size of @buf in bytes
 * @desc:	Current descriptor, or NULL to get the first descriptor
 *
 * The walk ends at the length reported in the header or at the end of
 * @buf, whichever comes first. A descriptor which does not fit
 * completely ends the walk.
 *
 * Return: Pointer to the next descriptor, or NULL if there is none.
 */
struct tcg_l0_desc *libnvme_sed_l0_next(void *buf, size_t len,
		struct tcg_l0_desc *desc);

/**
 * libnvme_sed_l0_find() - Find a Level 0 Discovery descriptor
 * @buf:	Level 0 Discovery data
 * @len:	Size of @buf in bytes
 * @code:	Feature code, see &enum tcg_l0_code
 *
 * Return: Pointer to the first descriptor with feature code @code, or
 * NULL if there is none.
 */
struct tcg_l0_desc *libnvme_sed_l0_find(void *buf, size_t len, __u16 code);

/**
 * libnvme_sed_l0_for_each() - Iterate over Level 0 Discovery descriptors
 * @desc:	&struct tcg_l0_desc pointer used as the loop cursor
 * @buf:	Level 0 Discovery data
 * @len:	Size of @buf in bytes
 */
#define libnvme_sed_l0_for_each(desc, buf, len)				\
	for (desc = libnvme_sed_l0_next(buf, len, NULL); desc;		\
	     desc = libnvme_sed_l0_next(buf, len, desc))

/**
 * libnvme_sed_l0_data() - Return the feature data of a descriptor
 * @desc:	Level 0 Discovery feature descriptor
 *
 * Return: Pointer to the feature data following the descriptor header.
 */
static inline void *libnvme_sed_l0_data(struct tcg_l0_desc *desc)
{
	return desc + 1;
}
