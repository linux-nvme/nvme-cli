/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 Dell Technologies Inc. or its subsidiaries.
 *
 * Authors: Martin Belanger <martin.belanger@dell.com>
 */
#pragma once

#include <stdbool.h>

#include <nvme/nvme-types-fabrics.h>

#include "tid.h"

struct dmn_work_pool;
struct dmn_work;

/*
 * Called from the event loop when dlp_read() ends. @ret is 0 on success, a
 * negative errno otherwise. @log is valid only during the call.
 */
typedef void (*dlp_read_callback)(int ret,
				  const struct nvmf_discovery_log *log,
				  void *user_data);

/*
 * Read the Discovery Log Page of the connected DC @devname, e.g. "nvme0".
 * The read blocks until the DC answers, so it runs in a worker of @pool,
 * with a libnvme global context of its own. @log_level is the libnvme
 * logging level of that context. *@ret, if @ret is not NULL, is valid
 * until @cb is called or the read is cancelled with dmn_work_cancel().
 *
 * Return: 0 on success, a negative errno otherwise.
 */
int dlp_read(struct dmn_work_pool *pool, const char *devname, int log_level,
	     dlp_read_callback cb, void *user_data, struct dmn_work **ret);

/*
 * Parse all the entries of a Discovery Log Page.
 *
 * For each DLPE:
 *   subtype == NVME_NQN_NVME (I/O controller):       ioc_callback is called.
 *   subtype == NVME_NQN_DISC (referral DC):          dc_callback is called.
 *   subtype == NVME_NQN_CURR (this DC's self entry): self_callback is called.
 *
 * self_callback is called once per self entry, with that entry's EPCSD bit
 * (EFLAGS bit 1); a multi-port DC may publish several. It is not called at
 * all if the log page carries no self entry; the caller must supply its own
 * fallback for that case.
 *
 * dc_callback is passed the referral entry's own EPCSD bit, i.e. this DC's
 * report of whether the referred-to DC supports persistent connections.
 * The caller can keep it as a fallback for when that DC is later connected
 * to and its own self entry turns out to be absent.
 *
 * log: a Discovery Log Page; numrec is read from its own header.
 * dc_tid: TID of the DC; the entries inherit its host-side fields.
 */
void dlp_process_log(const struct nvmf_discovery_log *log,
		     const struct libnvmf_tid *dc_tid,
		     void (*ioc_callback)(const struct libnvmf_tid *t,
					  void *user_data),
		     void (*dc_callback)(const struct libnvmf_tid *t,
					 bool epcsd, void *user_data),
		     void (*self_callback)(bool epcsd, void *user_data),
		     void *user_data);
