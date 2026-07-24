/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 Dell Technologies Inc. or its subsidiaries.
 *
 * Authors: Martin Belanger <martin.belanger@dell.com>
 */
#pragma once

#include <stdbool.h>

/*
 * discoverd.conf carries the daemon's own knobs only — the connections it
 * manages come from the shared fabrics config (libnvmf_config_read()), not
 * from here. Just a single [Global] section:
 *
 *   [Global]
 *   nbft = true
 *   debug-level = info
 *   fc-kickstart-interval-minutes = 0
 */
struct discoverd_config {
	bool nbft; // adopt/connect NBFT-listed controllers; default true

	/*
	 * Log threshold for discoverd and its in-process libnvme context, as
	 * a DISC_LOG_* value (see log.h); default DISC_LOG_INFO. A
	 * command-line --debug overrides this.
	 */
	int debug_level;

	/*
	 * FC kickstart interval in minutes. 0 = disabled (default), i.e.
	 * kickstart only runs at startup and on FC controller drop; N >= 1 =
	 * additionally re-issue every N minutes.
	 */
	unsigned int fc_kickstart_interval_minutes;
};

/*
 * Load discoverd's own configuration. @conf_path is discoverd.conf's path
 * (DISCOVERD_CONF_PATH if NULL). A missing file is not an error — every
 * knob keeps its default; a malformed line is logged and skipped.
 * Returns a newly allocated config (never NULL except on allocation
 * failure). Caller frees with config_free().
 */
struct discoverd_config *config_load(const char *conf_path);

void config_free(struct discoverd_config *cfg);

/*
 * Default discoverd.conf location, using the build-provided SYSCONFDIR
 * prefix. The --config command line option overrides it.
 */
#define DISCOVERD_CONF_PATH SYSCONFDIR "/nvme/discoverd.conf"
