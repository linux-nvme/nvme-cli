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
#include <stdlib.h>
#include <stdarg.h>
#include <stdbool.h>
#include <syslog.h>
#include <unistd.h>
#include <time.h>
#include <string.h>
#define LOG_FUNCNAME 1
#include "private.h"
#include "log.h"
#include "cleanup.h"

#ifndef LOG_CLOCK
#define LOG_CLOCK CLOCK_MONOTONIC
#endif

static struct nvme_log def_log = {
	.fd = STDERR_FILENO,
	.level = DEFAULT_LOGLEVEL,
	.pid = false,
	.timestamp = false,
};

void __attribute__((format(printf, 4, 5)))
__nvme_msg(nvme_root_t r, int level,
	   const char *func, const char *format, ...)
{
	struct nvme_log *l;
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

	if (r)
		l = &r->log;
	else
		l = &def_log;

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

void nvme_init_logging(nvme_root_t r, int lvl, bool log_pid, bool log_tstamp)
{
	r->log.level = lvl;
	r->log.pid = log_pid;
	r->log.timestamp = log_tstamp;
}

int nvme_get_logging_level(nvme_root_t r, bool *log_pid, bool *log_tstamp)
{
	struct nvme_log *l;

	if (r)
		l = &r->log;
	else
		l = &def_log;

	if (log_pid)
		*log_pid = l->pid;
	if (log_tstamp)
		*log_tstamp = l->timestamp;
	return l->level;
}

void nvme_init_default_logging(FILE *fp, int level, bool log_pid, bool log_tstamp)
{
	def_log.fd = fileno(fp);
	def_log.level = level;
	def_log.pid = log_pid;
	def_log.timestamp = log_tstamp;
}

void nvme_set_root(nvme_root_t r)
{
	def_log.fd = r->log.fd;
	def_log.level = r->log.level;
	def_log.pid = r->log.pid;
	def_log.timestamp = r->log.timestamp;
}

void nvme_set_debug(bool debug)
{
	def_log.level = debug ? LOG_DEBUG : DEFAULT_LOGLEVEL;
}

bool nvme_get_debug(void)
{
	return def_log.level == LOG_DEBUG;
}
