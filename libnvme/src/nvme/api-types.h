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

#endif /* _LIBNVME_API_TYPES_H */
