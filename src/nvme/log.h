/*
 * Copyright (c) 2021 Martin Wilck, SUSE LLC
 * SPDX-License-Identifier: LGPL-2.1-or-newer
 */
#ifndef _LOG_H
#define _LOG_H

#include <syslog.h>

#ifndef MAX_LOGLEVEL
#  define MAX_LOGLEVEL LOG_DEBUG
#endif
#ifndef DEFAULT_LOGLEVEL
#  define DEFAULT_LOGLEVEL LOG_NOTICE
#endif

#if (LOG_FUNCNAME == 1)
#define __nvme_log_func __func__
#else
#define __nvme_log_func NULL
#endif

extern int nvme_log_level;
extern bool nvme_log_timestamp;
extern bool nvme_log_pid;
extern char *nvme_log_message;

void __attribute__((format(printf, 3, 4)))
__nvme_msg(int lvl, const char *func, const char *format, ...);

#define nvme_msg(lvl, format, ...)					\
	do {								\
		if ((lvl) <= MAX_LOGLEVEL)				\
			__nvme_msg(lvl, __nvme_log_func,		\
				   format, ##__VA_ARGS__);		\
	} while (0)

#endif /* _LOG_H */
