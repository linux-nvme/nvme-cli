// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 Dell Technologies Inc. or its subsidiaries.
 *
 * Authors: Martin Belanger <martin.belanger@dell.com>
 */

#include <stdarg.h>
#include <syslog.h>
#include <systemd/sd-journal.h>

#include "log.h"

static int log_level = DISC_DEFAULT_LOGLEVEL;

/* Map discoverd levels to syslog priorities for the journal. */
static const int prio_map[] = {
	[DISC_LOG_ERR]   = LOG_ERR,
	[DISC_LOG_WARN]  = LOG_WARNING,
	[DISC_LOG_INFO]  = LOG_INFO,
	[DISC_LOG_DEBUG] = LOG_DEBUG,
};

void log_set_level(int level)
{
	log_level = level;
}

void log_msg(int level, const char *fmt, ...)
{
	va_list ap;

	if (level > log_level)
		return;
	if (level < DISC_LOG_ERR || level > DISC_LOG_DEBUG)
		level = DISC_LOG_ERR;

	va_start(ap, fmt);
	sd_journal_printv(prio_map[level], fmt, ap);
	va_end(ap);
}
