/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 Dell Technologies Inc. or its subsidiaries.
 *
 * Authors: Martin Belanger <martin.belanger@dell.com>
 */
#pragma once

#include <stdbool.h>
#include <stdint.h>

#include <systemd/sd-event.h>

/*
 * Blocking work for an sd-event loop. The work runs in worker threads. Its
 * end is reported from the event loop.
 *
 * The work must not share state with the event loop while it runs, except
 * what the done callback reads after the work ended. For libnvme, this
 * means that the work uses a global context of its own.
 */
struct dmn_work_pool;
struct dmn_work;

// Runs in a worker thread.
typedef void (*dmn_work_fn)(void *data);

/*
 * Runs in the event loop when the work ended, or when it timed out. With
 * @timed_out, a worker may still run the work: read only the fields of
 * @data that the work does not write, and do not free @data.
 */
typedef void (*dmn_work_done_fn)(void *data, bool timed_out);

/*
 * Frees @data. Runs in the event loop, or in the worker thread when the
 * work ends after a timeout or a cancel.
 */
typedef void (*dmn_work_free_fn)(void *data);

/*
 * Create a pool that runs up to @max_workers works at the same time.
 * Return: 0 on success, a negative errno otherwise.
 */
int dmn_work_pool_new(sd_event *event, unsigned int max_workers,
		      struct dmn_work_pool **ret);

/*
 * Cancel all works and free @p. No done callback is called. A worker that
 * still runs a work frees it when the work returns. May be called from a
 * done callback.
 */
void dmn_work_pool_free(struct dmn_work_pool *p);

/*
 * Run @fn(@data) in a worker thread, then call @done(@data) from the event
 * loop and free @data with @free_fn. On success, the pool owns @data, even
 * if @fn never runs. A @timeout_usec of 0 means no timeout. *@ret, if @ret
 * is not NULL, is valid until @done is called or the work is cancelled.
 * Return: 0 on success, a negative errno otherwise.
 */
int dmn_work_submit(struct dmn_work_pool *p, dmn_work_fn fn,
		    dmn_work_done_fn done, dmn_work_free_fn free_fn,
		    void *data, uint64_t timeout_usec, struct dmn_work **ret);

// Cancel @w. Its done callback is not called.
void dmn_work_cancel(struct dmn_work *w);
