/*
 * Copyright (C) 2021 SUSE LLC
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version
 * 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
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
#include "log.h"
#include "cleanup.h"

#ifndef LOG_CLOCK
#define LOG_CLOCK CLOCK_MONOTONIC
#endif

int nvme_log_level = DEFAULT_LOGLEVEL;
bool nvme_log_timestamp;
bool nvme_log_pid;
char *nvme_log_message = NULL;

void __attribute__((format(printf, 3, 4)))
__nvme_msg(int lvl, const char *func, const char *format, ...)
{
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
	char *header __cleanup__(cleanup_charp) = NULL;
	char *message __cleanup__(cleanup_charp) = NULL;
	int idx;

	if (nvme_log_timestamp) {
		struct timespec now;

		clock_gettime(LOG_CLOCK, &now);
		snprintf(timebuf, sizeof(timebuf), "%6ld.%06ld",
			 (long)now.tv_sec, now.tv_nsec / 1000);
	} else
		*timebuf = '\0';

	if (nvme_log_pid)
		snprintf(pidbuf, sizeof(pidbuf), "%ld", (long)getpid());
	else
		*pidbuf = '\0';

	idx = ((nvme_log_timestamp ? 1 : 0) << 2) |
		((nvme_log_pid ? 1 : 0) << 1) | (func ? 1 : 0);

	if (asprintf(&header, formats[idx], timebuf, pidbuf, func ? func : "")
	    == -1)
		header = NULL;

	va_start(ap, format);
	if (vasprintf(&message, format, ap) == -1)
		message = NULL;
	va_end(ap);

	if (nvme_log_message)
		free(nvme_log_message);
	nvme_log_message = strdup(message);

	if (lvl <= nvme_log_level)
		fprintf(stderr, "%s%s", header ? header : "<error>",
			message ? message : "<error>");

}
