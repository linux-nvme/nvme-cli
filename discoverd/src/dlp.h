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
 *   subtype == NVME_NQN_NVME (I/O controller):       ioc_callback is called.
 *   subtype == NVME_NQN_DISC (referral DC):          dc_callback is called.
 *   subtype == NVME_NQN_CURR (this DC's self entry): self_callback is called.
 *   DUPRETINFO flag set: entry is skipped.
 *
 * self_callback is called at most once, with the self entry's EPCSD bit
 * (EFLAGS bit 1). It is not called at all if the log page carries no self
 * entry; the caller must supply its own fallback for that case.
 *
 * devname: kernel device name, e.g. "nvme0".
 * dc_tid: TID of the DC (used as the cache key in the caller).
 *
 * Returns 0 on success, negative errno on failure.
 */
int dlp_fetch(struct discoverd_ctx *ctx, const char *devname,
	      const struct libnvmf_tid *dc_tid,
	      void (*ioc_callback)(const struct libnvmf_tid *t,
				   void *user_data),
	      void (*dc_callback)(const struct libnvmf_tid *t,
				 void *user_data),
	      void (*self_callback)(bool epcsd, void *user_data),
	      void *user_data);
