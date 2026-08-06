/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 SUSE Software Solutions
 *
 * Authors: Daniel Wagner <dwagner@suse.de>
 */
#pragma once

#define PATH_NVME_CLI_INI SYSCONFDIR "/nvme/nvme-cli.conf"

/*
 * Load /etc/nvme/nvme-cli.conf (if present) into the global nvme_args
 * defaults. Must be called before any command-line parsing, so that an
 * explicit flag still overrides whatever the file set. A missing file
 * is not an error.
 */
int nvme_load_global_config(void);

/* Exposed for unit testing; nvme_load_global_config() is the real entry point. */
int nvme_load_global_config_from(const char *path);
