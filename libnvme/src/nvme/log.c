// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libnvme.
 * Copyright (C) 2021 SUSE LLC
 *
 * Authors: Hannes Reinecke <hare@suse.de>
 *
 * This file implements basic logging functionality.
 */

#include <errno.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <libnvme.h>

#include "cleanup.h"
#define LOG_FUNCNAME 1
#include "private.h"
#include "compiler-attributes.h"

#ifndef LOG_CLOCK
#define LOG_CLOCK CLOCK_MONOTONIC
#endif

static ssize_t write_all(int fd, const void *buf, size_t count)
{
	const char *p = buf;
	size_t total = 0;

	while (total < count) {
		ssize_t n = write(fd, p + total, count - total);

		if (n > 0) {
			total += n;
			continue;
		}

		if (n < 0) {
			if (errno == EINTR)
				continue;

			if (errno == EAGAIN)
				continue;

			return -1;
		}

		errno = EIO;
		return -1;
	}

	return total;
}

void __attribute__((format(printf, 4, 5)))
__libnvme_msg(struct libnvme_global_ctx *ctx, int level,
	   const char *func, const char *format, ...)
{
	struct libnvme_log *l = &ctx->log;
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
	__cleanup_free char *header = NULL;
	__cleanup_free char *message = NULL;
	__cleanup_free char *log = NULL;
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

	if (asprintf(&log, "%s%s", header ? header : "<error>",
			message ? message : "<error>") == -1)
		return;

	if (write_all(l->fd, log, strlen(log)) < 0)
		perror("failed to write log entry");
}

__libnvme_public void libnvme_set_logging_level(
		struct libnvme_global_ctx *ctx, int log_level, bool log_pid,
		bool log_tstamp)
{
	ctx->log.level = log_level;
	ctx->log.pid = log_pid;
	ctx->log.timestamp = log_tstamp;
}

__libnvme_public int libnvme_get_logging_level(struct libnvme_global_ctx *ctx,
		bool *log_pid, bool *log_tstamp)
{
	if (log_pid)
		*log_pid = ctx->log.pid;
	if (log_tstamp)
		*log_tstamp = ctx->log.timestamp;
	return ctx->log.level;
}
