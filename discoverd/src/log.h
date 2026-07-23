/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 Dell Technologies Inc. or its subsidiaries.
 *
 * Authors: Martin Belanger <martin.belanger@dell.com>
 */
#pragma once

/*
 * Logging wrapper.
 *
 * Levels mirror libnvme's (ERR/WARN/INFO/DEBUG): a message is emitted when
 * its level is <= the configured threshold, so DEBUG turns everything on.
 * All output currently goes to the systemd journal; routing lives behind
 * this wrapper so a future change of logging backend touches only log.c.
 */
enum disc_log_level {
	DISC_LOG_ERR   = 0,
	DISC_LOG_WARN  = 1,
	DISC_LOG_INFO  = 2,
	DISC_LOG_DEBUG = 3,
};

#define DISC_DEFAULT_LOGLEVEL DISC_LOG_INFO

/* Set the current threshold (e.g. from discoverd.conf's debug-level knob). */
void log_set_level(int level);

/*
 * Emit one message at @level if it passes the threshold. Use the disc_*
 * helpers below rather than calling this directly.
 */
void log_msg(int level, const char *fmt, ...)
	__attribute__((format(printf, 2, 3)));

/*
 * INFO and higher print the message as-is (per convention, lead with the
 * TID: "<tid> | <dev> - msg" — see libnvmf_tid_str()). DEBUG additionally
 * prepends the calling function name for call tracing ("<func>() - msg");
 * __func__ keeps it from drifting out of sync.
 */
#define disc_err(fmt, ...)  log_msg(DISC_LOG_ERR,   fmt, ##__VA_ARGS__)
#define disc_warn(fmt, ...) log_msg(DISC_LOG_WARN,  fmt, ##__VA_ARGS__)
#define disc_info(fmt, ...) log_msg(DISC_LOG_INFO,  fmt, ##__VA_ARGS__)
#define disc_dbg(fmt, ...)  log_msg(DISC_LOG_DEBUG, "%s() - " fmt, __func__, ##__VA_ARGS__)
