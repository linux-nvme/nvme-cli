/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 Dell Technologies Inc. or its subsidiaries.
 *
 * Authors: Martin Belanger <martin.belanger@dell.com>
 */
#pragma once

#include <stdbool.h>

struct libnvme_global_ctx;

/*
 * Return true if an entry of the fabrics configuration @fabrics_conf (NULL
 * for the default) has a key source other than "inline". Without such an
 * entry, import_keys() has nothing to do.
 */
bool import_needed(struct libnvme_global_ctx *ctx, const char *fabrics_conf);

/*
 * Put every TLS PSK that the fabrics configuration @fabrics_conf (NULL for
 * the default) takes from a systemd credential into its keyring. A key
 * that is already there is not written again. Any other key for the same
 * host NQN and subsystem NQN is revoked, so the kernel's lookup by NQNs
 * finds only this one.
 *
 * @creds_dir holds the encrypted credentials. systemd-creds decrypts
 * them.
 */
void import_keys(struct libnvme_global_ctx *ctx, const char *fabrics_conf,
		 const char *creds_dir);
