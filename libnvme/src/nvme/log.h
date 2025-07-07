// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * Copyright (c) 2021 Martin Wilck, SUSE LLC
 */
#ifndef _LOG_H
#define _LOG_H

#include <stdbool.h>
#include <syslog.h>

/* for nvme_root_t */
#include <nvme/tree.h>

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
 * @ctx:	struct nvme_global_ctx object
 * @lvl:	Logging level to set
 * @log_pid:	Boolean to enable logging of the PID
 * @log_tstamp:	Boolean to enable logging of the timestamp
 *
 * Sets the default logging variables for the library.
 */
void nvme_init_logging(struct nvme_global_ctx *ctx, int lvl, bool log_pid, bool log_tstamp);

/**
 * nvme_init_default_logging() - Initialize default (fallback) logging
 * @fp:		File descriptor for logging messages
 * @lvl:	Logging level to set
 * @log_pid:	Boolean to enable logging of the PID
 * @log_tstamp:	Boolean to enable logging of the timestamp
 *
 * Sets the default logging settings for the library in case the root object
 * is absent.
 */
void nvme_init_default_logging(FILE *fp, int lvl, bool log_pid, bool log_tstamp);

/**
 * nvme_get_logging_level() - Get current logging level
 * @ctx:	struct nvme_global_ctx object
 * @log_pid:	Pointer to store a current value of logging of
 *		the PID flag at (optional).
 * @log_tstamp:	Pointer to store a current value of logging of
 *		the timestamp flag at (optional).
 *
 * Retrieves current values of logging variables.
 *
 * Return: current log level value or DEFAULT_LOGLEVEL if not initialized.
 */
int nvme_get_logging_level(struct nvme_global_ctx *ctx, bool *log_pid, bool *log_tstamp);

/**
 * nvme_set_global_ctx() - Set global context
 * @ctx:		struct nvme_global_ctx object
 *
 * In order to be able to log from code paths where no global context
 * object is passed in via the arguments use the the default one which
 * can be set via this call. When creating a new global context object
 * with @nvme_create_global_ctx the global context object will be set as
 * well. This means the global context object is always pointing to the
 * latest created global context object. Note the first
 * @nvme_free_global_ctx call will reset the global context object.
 *
 * This function is deprecated. Use nvme_init_default_logging or/and
 * nvme_init_logging instead.
 */
void nvme_set_global_ctx(struct nvme_global_ctx *ctx) __attribute__((deprecated));

/**
 * nvme_set_debug - Set NVMe command debugging output
 * @debug:	true to enable or false to disable
 *
 * This function is deprecated. Use nvme_init_default_logging instead.
 */
void nvme_set_debug(bool debug) __attribute__((deprecated));

/**
 * nvme_get_debug - Get NVMe command debugging output
 *
 * This function is deprecated. Use nvme_get_logging_level instead.
 *
 * Return: false if disabled or true if enabled.
 */
bool nvme_get_debug(void) __attribute__((deprecated));

#endif /* _LOG_H */
