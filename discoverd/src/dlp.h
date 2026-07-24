/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 Dell Technologies Inc. or its subsidiaries.
 *
 * Authors: Martin Belanger <martin.belanger@dell.com>
 */
#pragma once

#include "ctx.h"
#include "tid.h"

/*
 * Fetch the Discovery Log Page from a connected DC and parse all entries.
 *
 * For each DLPE:
 *   subtype == NVME_NQN_NVME (I/O controller): ioc_cback is called.
 *   subtype == NVME_NQN_DISC (referral DC):    dc_cback is called.
 *   DUPRETINFO flag set: entry is skipped.
 *
 * devname: kernel device name, e.g. "nvme0".
 * dc_tid: TID of the DC (used as the cache key in the caller).
 *
 * Returns 0 on success, negative errno on failure.
 */
int dlp_fetch(struct discoverd_ctx *ctx, const char *devname,
	      const struct libnvmf_tid *dc_tid,
	      void (*ioc_cback)(const struct libnvmf_tid *t, void *user_data),
	      void (*dc_cback)(const struct libnvmf_tid *t, void *user_data),
	      void *user_data);
