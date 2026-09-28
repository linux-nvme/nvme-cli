// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 Dell Technologies Inc. or its subsidiaries.
 *
 * Authors: Martin Belanger <martin.belanger@dell.com>
 */

#include <errno.h>
#include <stdarg.h>
#include <strings.h>
#include <syslog.h>
#include <systemd/sd-journal.h>

#include <ccan/array_size/array_size.h>

#include "log.h"

static int log_level = DMN_DEFAULT_LOGLEVEL;

static const char * const level_names[] = {
	[DMN_LOG_ERR]   = "err",
	[DMN_LOG_WARN]  = "warn",
	[DMN_LOG_INFO]  = "info",
	[DMN_LOG_DEBUG] = "debug",
};

static const int prio_map[] = {
	[DMN_LOG_ERR]   = LOG_ERR,
	[DMN_LOG_WARN]  = LOG_WARNING,
	[DMN_LOG_INFO]  = LOG_INFO,
	[DMN_LOG_DEBUG] = LOG_DEBUG,
};

void dmn_log_set_level(int level)
{
	log_level = level;
}

int dmn_parse_log_level(const char *name, int *level)
{
	size_t i;

	for (i = 0; i < ARRAY_SIZE(level_names); i++) {
		if (!strcasecmp(name, level_names[i])) {
			*level = (int)i;
			return 0;
		}
	}

	return -EINVAL;
}

static void log_vmsg(int level, const char *fmt, va_list ap)
{
	if (level > log_level)
		return;
	if (level < DMN_LOG_ERR || level > DMN_LOG_DEBUG)
		level = DMN_LOG_ERR;

	sd_journal_printv(prio_map[level], fmt, ap);
}

void dmn_log_msg(int level, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	log_vmsg(level, fmt, ap);
	va_end(ap);
}

void dmn_log_msg_once(bool *fired, int level, const char *fmt, ...)
{
	va_list ap;

	if (*fired)
		return;
	*fired = true;

	va_start(ap, fmt);
	log_vmsg(level, fmt, ap);
	va_end(ap);
}
