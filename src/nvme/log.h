// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * Copyright (c) 2021 Martin Wilck, SUSE LLC
 */
#ifndef _LOG_H
#define _LOG_H

#include <stdbool.h>
#include <syslog.h>

#ifndef MAX_LOGLEVEL
#  define MAX_LOGLEVEL LOG_DEBUG
#endif
#ifndef DEFAULT_LOGLEVEL
#  define DEFAULT_LOGLEVEL LOG_NOTICE
#endif

/**
 * nvme_init_logging() - initialize logging
 * @r: nvme_root_t context
 * @lvl: logging level to set
 * @log_pid: boolean to enable logging of the PID
 * @log_tstamp: boolean to enable logging of the timestamp
 *
 * Sets the default logging variables for the library.
 */
void nvme_init_logging(nvme_root_t r, int lvl, bool log_pid, bool log_tstamp);

#endif /* _LOG_H */
