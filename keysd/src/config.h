/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 Dell Technologies Inc. or its subsidiaries.
 *
 * Authors: Martin Belanger <martin.belanger@dell.com>
 */
#pragma once

/*
 * nvme-keysd's own settings. Which key belongs to which host and subsystem
 * is in the shared fabrics config, never here.
 *
 *   [Global]
 *   debug-level = info
 */
struct keysd_config {
	int debug_level; // DMN_LOG_* (see daemon-util/log.h)
};

/*
 * Load @conf_path (KEYSD_CONF_PATH if NULL). A missing file is not an
 * error: every setting keeps its default. A bad line is logged and
 * skipped. Returns NULL only on allocation failure. Free with
 * config_free().
 */
struct keysd_config *config_load(const char *conf_path);

void config_free(struct keysd_config *cfg);

#define KEYSD_CONF_PATH SYSCONFDIR "/nvme/nvme-keysd.conf"
#define KEYSD_CREDS_DIR SYSCONFDIR "/nvme/creds"
