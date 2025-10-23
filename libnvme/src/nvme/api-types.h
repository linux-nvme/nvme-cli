// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * Types used as part of the libnvme/libnvme-mi API, rather than specified
 * by the NVM Express specification.
 *
 * These are shared across both libnvme and libnvme-mi interfaces.
 *
 * This file is part of libnvme.
 * Copyright (c) 2022 Code Construct
 *
 * Authors: Jeremy Kerr <jk@codeconstruct.com.au>
 */
#ifndef _LIBNVME_API_TYPES_H
#define _LIBNVME_API_TYPES_H

#include <stdio.h>
#include <stdbool.h>

#include <nvme/types.h>

struct nvme_global_ctx;
struct nvme_transport_handle;

/**
 * nvme_create_global_ctx() - Initialize global context object
 * @fp:		File descriptor for logging messages
 * @log_level:	Logging level to use
 *
 * Return: Initialized &struct nvme_global_ctx object
 */
struct nvme_global_ctx *nvme_create_global_ctx(FILE *fp, int log_level);

/**
 * nvme_free_global_ctx() - Free global context object
 * @ctx:	&struct nvme_global_ctx object
 *
 * Free an &struct nvme_global_ctx object and all attached objects
 */
void nvme_free_global_ctx(struct nvme_global_ctx *ctx);

/**
 * struct nvme_copy_args - Arguments for the NVMe Copy command
 * @sdlba:	Start destination LBA
 * @result:	The command completion result from CQE dword0
 * @copy:	Range description
 * @args_size:	Size of &struct nvme_copy_args
 * @timeout:	Timeout in ms
 * @nsid:	Namespace identifier
 * @ilbrt:	Initial logical block reference tag
 * @lr:		Limited retry
 * @fua:	Force unit access
 * @nr:		Number of ranges
 * @dspec:	Directive specific value
 * @lbatm:	Logical block application tag mask
 * @lbat:	Logical block application tag
 * @prinfor:	Protection information field for read
 * @prinfow:	Protection information field for write
 * @dtype:	Directive type
 * @format:	Descriptor format
 * @ilbrt_u64:	Initial logical block reference tag - 8 byte
 *              version required for enhanced protection info
 */
struct nvme_copy_args {
	__u64 sdlba;
	__u32 *result;
	struct nvme_copy_range *copy;
	int args_size;
	__u32 timeout;
	__u32 nsid;
	__u32 ilbrt;
	int lr;
	int fua;
	__u16 nr;
	__u16 dspec;
	__u16 lbatm;
	__u16 lbat;
	__u8 prinfor;
	__u8 prinfow;
	__u8 dtype;
	__u8 format;
	__u64 ilbrt_u64;
};

#endif /* _LIBNVME_API_TYPES_H */
