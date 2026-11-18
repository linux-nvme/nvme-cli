/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 SUSE LLC
 *
 * Authors: Daniel Wagner <dwagner@suse.de>
 */
#pragma once

#include <stdbool.h>

struct libnvme_global_ctx;
struct libnvmf_params;
struct libnvmf_tid;

/*
 * The connections the pre-OS environment (firmware and initrd) wanted, for
 * the OS environment: nvme-discoverd keeps them connected after the switch
 * to the real root, with these parameters and the owner "pre-os", but
 * never owns them.
 *
 * RUNDIR/nvme/pre-os.conf and its drop-ins in pre-os.conf.d/, in the
 * format of nvme-fabrics.conf(5). /run moves to the real root, so they
 * survive the switch. Under --set-options test-base-dir=DIR, DIR/pre-os.conf.
 */
const char *nvme_pre_os_conf_path(void);

/*
 * Whether this runs in the pre-OS environment and connects as its owner:
 * @owner is "pre-os" (or its old name "nbft"), and this is an initrd
 * (/etc/initrd-release, see os-release(5); under --set-options
 * test-base-dir=DIR, DIR/etc/initrd-release). nvme-discoverd reconnects
 * the pre-OS paths with the same owner from the real root, and records
 * nothing.
 */
bool nvme_pre_os_records(const char *owner);

/*
 * Record the connection @tid with @params before it is connected: a path
 * that fails to connect in the pre-OS environment is one the OS
 * environment connects later. Each host has a drop-in of its own (one
 * host per file, see nvme-fabrics.conf(5)) with all its connections;
 * recording a connection again replaces its entry.
 *
 * Return: 0 on success, negative errno otherwise.
 */
int nvme_pre_os_record(struct libnvme_global_ctx *ctx, bool is_dc,
		const struct libnvmf_tid *tid,
		const struct libnvmf_params *params);
