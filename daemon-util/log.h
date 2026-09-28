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
 * Logging for the nvme-cli daemons. Messages go to the systemd journal.
 *
 * Levels mirror libnvme's (ERR/WARN/INFO/DEBUG): a message is emitted when
 * its level is <= the configured threshold, so DEBUG turns everything on.
 */
enum dmn_log_level {
	DMN_LOG_ERR   = 0,
	DMN_LOG_WARN  = 1,
	DMN_LOG_INFO  = 2,
	DMN_LOG_DEBUG = 3,
};

#define DMN_DEFAULT_LOGLEVEL DMN_LOG_INFO

void dmn_log_set_level(int level);

/*
 * Parse a level name: err, warn, info, or debug (case-insensitive).
 * Return: 0 on success (*level set), -EINVAL otherwise.
 */
int dmn_parse_log_level(const char *name, int *level);

/* Use the log_*() macros below rather than calling these directly. */
void dmn_log_msg(int level, const char *fmt, ...)
	__attribute__((format(printf, 2, 3)));

/*
 * Log only the first time this is called for a given @fired. @fired is
 * owned by the caller and must live as long as the entity the message is
 * about, e.g. a field of that entity's struct.
 */
void dmn_log_msg_once(bool *fired, int level, const char *fmt, ...)
	__attribute__((format(printf, 3, 4)));

/* DEBUG also prepends the calling function's name. */
#define log_err(fmt, ...)  dmn_log_msg(DMN_LOG_ERR,  fmt, ##__VA_ARGS__)
#define log_warn(fmt, ...) dmn_log_msg(DMN_LOG_WARN, fmt, ##__VA_ARGS__)
#define log_info(fmt, ...) dmn_log_msg(DMN_LOG_INFO, fmt, ##__VA_ARGS__)
#define log_dbg(fmt, ...)						\
	dmn_log_msg(DMN_LOG_DEBUG, "%s() - " fmt, __func__, ##__VA_ARGS__)

#define log_info_once(fired, fmt, ...)					\
	dmn_log_msg_once(fired, DMN_LOG_INFO, fmt, ##__VA_ARGS__)
