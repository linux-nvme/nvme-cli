/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 Dell Technologies Inc. or its subsidiaries.
 *
 * Authors: Martin Belanger <martin.belanger@dell.com>
 */
#pragma once

#include <stdbool.h>
#include <stdint.h>

/*
 * nvme-discoverd's config file carries the daemon's own knobs only — the
 * connections it manages come from the shared fabrics config
 * (libnvmf_config_read()), not from here. Just a single [Global] section:
 *
 *   [Global]
 *   nbft = true
 *   debug-level = info
 *   fc-kickstart-interval-minutes = 0
 *   epcsd-poll-interval-minutes = 15
 *   dc-giveup-timeout = 72hours
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

	/*
	 * How often, in minutes, to reconnect and re-check a DC whose
	 * effective EPCSD is 0. Such a DC is disconnected between checks —
	 * it does not support persistent connections, so there is nothing
	 * to hold open. Default 15; never 0 (unlike fc_kickstart_interval,
	 * this poll is not optional).
	 */
	unsigned int epcsd_poll_interval_minutes;

	/*
	 * Microseconds a dynamically-discovered DC (found only via referral
	 * or FC kickstart, not NBFT or the fabrics config) keeps retrying a
	 * failed (re)connect before it's dropped from tracking. Default 72
	 * hours. SHR_USEC_INFINITY = never give up, same as a
	 * static/NBFT-sourced DC; 0 = give up on the first failure.
	 */
	uint64_t dc_giveup_timeout_usec;
};

/*
 * Load discoverd's own configuration. @conf_path is the config file's path
 * (DISCOVERD_CONF_PATH if NULL). A missing file is not an error — every
 * knob keeps its default; a malformed line is logged and skipped. Returns
 * a newly allocated config (never NULL except on allocation failure).
 * Caller frees with config_free().
 */
struct discoverd_config *config_load(const char *conf_path);

void config_free(struct discoverd_config *cfg);

/*
 * Default nvme-discoverd's config file location, using the build-provided
 * SYSCONFDIR prefix. The --config command line option overrides it.
 */
#define DISCOVERD_CONF_PATH SYSCONFDIR "/nvme/nvme-discoverd.conf"
