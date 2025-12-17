// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libnvme.
 * Copyright (C) 2021 SUSE LLC
 *
 * Authors: Hannes Reinecke <hare@suse.de>
 *
 * This file implements basic logging functionality.
 */

#include <sys/types.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdbool.h>
#include <syslog.h>
#include <unistd.h>
#include <time.h>
#define LOG_FUNCNAME 1
#include "private.h"
#include "log.h"
#include "cleanup.h"

#ifndef LOG_CLOCK
#define LOG_CLOCK CLOCK_MONOTONIC
#endif

void __attribute__((format(printf, 4, 5)))
__nvme_msg(struct nvme_global_ctx *ctx, int level,
	   const char *func, const char *format, ...)
{
	struct nvme_log *l = &ctx->log;
	va_list ap;
	char pidbuf[16];
	char timebuf[32];
	static const char *const formats[] = {
		"%s%s%s",
		"%s%s%s: ",
		"%s<%s>%s ",
		"%s<%s> %s: ",
		"[%s] %s%s ",
		"[%s]%s %s: ",
		"[%s] <%s>%s ",
		"[%s] <%s> %s: ",
	};
	_cleanup_free_ char *header = NULL;
	_cleanup_free_ char *message = NULL;
	int idx = 0;

	if (level > l->level)
		return;

	if (l->timestamp) {
		struct timespec now;

		clock_gettime(LOG_CLOCK, &now);
		snprintf(timebuf, sizeof(timebuf), "%6ld.%06ld",
			 (long)now.tv_sec, now.tv_nsec / 1000);
		idx |= 1 << 2;
	} else
		*timebuf = '\0';

	if (l->pid) {
		snprintf(pidbuf, sizeof(pidbuf), "%ld", (long)getpid());
		idx |= 1 << 1;
	} else
		*pidbuf = '\0';

	if (func)
		idx |= 1 << 0;

	if (asprintf(&header, formats[idx],
		     timebuf, pidbuf, func ? func : "") == -1)
		header = NULL;

	va_start(ap, format);
	if (vasprintf(&message, format, ap) == -1)
		message = NULL;
	va_end(ap);

	dprintf(l->fd, "%s%s",
		header ? header : "<error>",
		message ? message : "<error>");
}

void nvme_init_logging(struct nvme_global_ctx *ctx, int lvl,
		bool log_pid, bool log_tstamp)
{
	ctx->log.level = lvl;
	ctx->log.pid = log_pid;
	ctx->log.timestamp = log_tstamp;
}

int nvme_get_logging_level(struct nvme_global_ctx *ctx,
		bool *log_pid, bool *log_tstamp)
{
	if (log_pid)
		*log_pid = ctx->log.pid;
	if (log_tstamp)
		*log_tstamp = ctx->log.timestamp;
	return ctx->log.level;
}
