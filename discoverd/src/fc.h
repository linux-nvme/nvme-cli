/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 Dell Technologies Inc. or its subsidiaries.
 *
 * Authors: Martin Belanger <martin.belanger@dell.com>
 */
#pragma once

/*
 * Trigger FC-NVMe discovery by writing "add" to the FC HBA's nvme_discovery
 * sysfs node. The HBA firmware probes all reachable targets and fires
 * FC_EVENT=="nvmediscovery" uevents; events.c delivers these to the
 * fc_discovery callback.
 *
 * Idempotent: writing "add" while a probe is already in progress is
 * harmless.
 *
 * Returns 0 on success, negative errno if the sysfs node cannot be written.
 */
int fc_kickstart(void);
