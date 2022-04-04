// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * Copyright (c) 2021 Martin Wilck, SUSE LLC
 */
#ifndef _LOG_H
#define _LOG_H

#include <stdbool.h>
#include <syslog.h>

/* for nvme_root_t */
#include "tree.h"

#ifndef MAX_LOGLEVEL
#  define MAX_LOGLEVEL LOG_DEBUG
#endif
#ifndef DEFAULT_LOGLEVEL
#  define DEFAULT_LOGLEVEL LOG_NOTICE
#endif

/**
 * DOC: log.h
 *
 * logging functions
 */

/**
 * nvme_init_logging() - Initialize logging
 * @r:		nvme_root_t context
 * @lvl:	Logging level to set
 * @log_pid:	Boolean to enable logging of the PID
 * @log_tstamp:	Boolean to enable logging of the timestamp
 *
 * Sets the default logging variables for the library.
 */
void nvme_init_logging(nvme_root_t r, int lvl, bool log_pid, bool log_tstamp);

#endif /* _LOG_H */
