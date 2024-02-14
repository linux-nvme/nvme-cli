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

/**
 * nvme_get_logging_level() - Get current logging level
 * @r:		nvme_root_t context
 * @log_pid:	Pointer to store a current value of logging of
 *		the PID flag at (optional).
 * @log_tstamp:	Pointer to store a current value of logging of
 *		the timestamp flag at (optional).
 *
 * Retrieves current values of logging variables.
 *
 * Return: current log level value or DEFAULT_LOGLEVEL if not initialized.
 */
int nvme_get_logging_level(nvme_root_t r, bool *log_pid, bool *log_tstamp);

/**
 * nvme_set_root() - Set nvme_root_t context
 * @r:		nvme_root_t context
 *
 * In order to be able to log from code paths where no root object is passed in
 * via the arguments use the the default one which can be set via this call.
 * When creating a new root object with @nvme_create_root the global root object
 * will be set as well. This means the global root object is always pointing to
 * the latest created root object. Note the first @nvme_free_tree call will reset
 * the global root object.
 */
void nvme_set_root(nvme_root_t r);

/**
 * nvme_set_debug - Set NVMe command debugging output
 * @debug:	true to enable or false to disable
 *
 * Don't use it, it's debricated.
 */
void nvme_set_debug(bool debug);

/**
 * nvme_get_debug - Get NVMe command debugging output
 *
 * Don't use it, it's debricated.
 *
 * Return: false if disabled or true if enabled.
 */
bool nvme_get_debug(void);

#endif /* _LOG_H */
