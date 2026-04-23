/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * This file is part of libnvme.
 * Copyright (c) 2020 Western Digital Corporation or its affiliates.
 *
 * Authors: Keith Busch <keith.busch@wdc.com>
 *	    Chaitanya Kulkarni <chaitanya.kulkarni@wdc.com>
 */
#pragma once

#include <stdbool.h>
#include <stdio.h>

#include <nvme/lib-compat.h>
#include <nvme/lib-types.h>

enum libnvme_log_level {
	LIBNVME_LOG_ERR	  = 0,
	LIBNVME_LOG_WARN  = 1,
	LIBNVME_LOG_INFO  = 2,
	LIBNVME_LOG_DEBUG = 3,
};

#define LIBNVME_DEFAULT_LOGLEVEL LIBNVME_LOG_WARN

/**
 * libnvme_create_global_ctx() - Initialize global context object
 * @fp:		File descriptor for logging messages
 * @log_level:	Logging level to use
 *
 * Return: Initialized &struct libnvme_global_ctx object
 */
struct libnvme_global_ctx *libnvme_create_global_ctx(FILE *fp, int log_level);

/**
 * libnvme_free_global_ctx() - Free global context object
 * @ctx:	&struct libnvme_global_ctx object
 *
 * Free an &struct libnvme_global_ctx object and all attached objects
 */
void libnvme_free_global_ctx(struct libnvme_global_ctx *ctx);

/**
 * libnvme_set_logging_level() - Set current logging level
 * @ctx:	struct libnvme_global_ctx object
 * @log_level:	Logging level to set
 * @log_pid:	Boolean to enable logging of the PID
 * @log_tstamp:	Boolean to enable logging of the timestamp
 *
 * Sets the current logging level for the global context.
 */
void libnvme_set_logging_level(struct libnvme_global_ctx *ctx, int log_level,
		bool log_pid, bool log_tstamp);

/**
 * libnvme_get_logging_level() - Get current logging level
 * @ctx:	struct libnvme_global_ctx object
 * @log_pid:	Pointer to store a current value of logging of
 *		the PID flag at (optional).
 * @log_tstamp:	Pointer to store a current value of logging of
 *		the timestamp flag at (optional).
 *
 * Retrieves current values of logging variables.
 *
 * Return: current log level value or LIBNVME_DEFAULT_LOGLEVEL if not initialized.
 */
int libnvme_get_logging_level(struct libnvme_global_ctx *ctx, bool *log_pid,
		bool *log_tstamp);

/**
 * libnvme_open() - Open an nvme controller or namespace device
 * @ctx:	struct libnvme_global_ctx object
 * @name:	The basename of the device to open
 * @hdl:	Transport handle to return
 *
 * This will look for the handle in /dev/ and validate the name and filetype
 * match linux conventions.
 *
 * Return: 0 on success or negative error code otherwise
 */
int libnvme_open(struct libnvme_global_ctx *ctx, const char *name,
	      struct libnvme_transport_handle **hdl);

/**
 * libnvme_close() - Close transport handle
 * @hdl:	Transport handle
 */
void libnvme_close(struct libnvme_transport_handle *hdl);

/**
 * libnvme_transport_handle_get_fd - Return file descriptor from
 * the transport handle
 * @hdl:	Transport handle
 *
 * If the device handle is for a ioctl based device,
 * libnvme_transport_handle_get_fd will return a valid file descriptor.
 *
 * Return: File descriptor for an IOCTL based transport handle,
 * otherwise LIBNVME_INVALID_FD.
 */
libnvme_fd_t libnvme_transport_handle_get_fd(struct libnvme_transport_handle *hdl);

/**
 * libnvme_transport_handle_get_name - Return name of the device
 * transport handle
 * @hdl:	Transport handle
 *
 * Return: Device file name, otherwise -1.
 */
const char *libnvme_transport_handle_get_name(
		struct libnvme_transport_handle *hdl);

/**
 * libnvme_transport_handle_is_ctrl - Check if transport handle is a
 * controller device
 * @hdl:	Transport handle
 *
 * Return: Return true if transport handle is a controller device,
 * otherwise false.
 */
bool libnvme_transport_handle_is_ctrl(struct libnvme_transport_handle *hdl);

/**
 * libnvme_transport_handle_is_direct - Check if transport handle is using IOCTL
 * interface
 * @hdl:	Transport handle
 *
 * Return: Return true if transport handle is using IOCTL interface,
 * otherwise false.
 */
bool libnvme_transport_handle_is_direct(struct libnvme_transport_handle *hdl);

/**
 * libnvme_transport_handle_is_mi - Check if transport handle is a using MI
 * interface
 * @hdl:	Transport handle
 *
 * Return: Return true if transport handle is using MI interface,
 * otherwise false.
 */
bool libnvme_transport_handle_is_mi(struct libnvme_transport_handle *hdl);

/**
 * libnvme_transport_handle_is_ns - Check if transport handle is a
 * namespace device
 * @hdl:	Transport handle
 *
 * Return: Return true if transport handle is a namespace device,
 * otherwise false.
 */
bool libnvme_transport_handle_is_ns(struct libnvme_transport_handle *hdl);

/**
 * libnvme_transport_handle_set_submit_entry() - Install a submit-entry callback
 * @hdl:	Transport handle to configure
 * @submit_entry: Callback invoked immediately before a passthrough command is
 *		submitted. The function receives the command about to be issued
 *		and may return an opaque pointer representing per-command
 *		context. This pointer is later passed unmodified to the
 *		submit-exit callback. Implementations typically use this hook
 *		for logging, tracing, or allocating per-command state.
 *
 * Installs a user-defined callback that is invoked at the moment a passthrough
 * command enters the NVMe submission path. Passing NULL removes any previously
 * installed callback.
 *
 * Return: None.
 */
void libnvme_transport_handle_set_submit_entry(
		struct libnvme_transport_handle *hdl,
		void *(*submit_entry)(struct libnvme_transport_handle *hdl,
				struct libnvme_passthru_cmd *cmd));

/**
 * libnvme_transport_handle_set_submit_exit() - Install a submit-exit callback
 * @hdl:	Transport handle to configure
 * @submit_exit: Callback invoked after a passthrough command completes. The
 *		function receives the command, the completion status @err
 *		(0 for success, a negative errno, or an NVMe status value), and
 *		the @user_data pointer returned earlier by the submit-entry
 *		callback. Implementations typically use this hook for logging,
 *		tracing, or freeing per-command state.
 *
 * Installs a callback that is invoked when a passthrough command leaves the
 * NVMe submission path. Passing NULL removes any previously installed callback.
 *
 * Return: None.
 */
void libnvme_transport_handle_set_submit_exit(
		struct libnvme_transport_handle *hdl,
		void (*submit_exit)(struct libnvme_transport_handle *hdl,
				struct libnvme_passthru_cmd *cmd,
				int err, void *user_data));

/**
 * libnvme_transport_handle_set_decide_retry() - Install a retry-decision
 * callback
 * @hdl:	Transport handle to configure
 * @decide_retry: Callback used to determine whether a passthrough command
 *		should be retried after an error. The function is called with
 *		the command that failed and the error code returned by the
 *		kernel or device. The callback should return true if the
 *		submission path should retry the command, or false if the
 *		error is final.
 *
 * Installs a user-provided callback to control retry behavior for
 * passthrough commands issued through @hdl. This allows transports or
 * higher-level logic to implement custom retry policies, such as retrying on
 * transient conditions like -EAGAIN or device-specific status codes.
 *
 * Passing NULL clears any previously installed callback and reverts to the
 * default behavior (no retries).
 *
 * Return: None.
 */
void libnvme_transport_handle_set_decide_retry(
		struct libnvme_transport_handle *hdl,
		bool (*decide_retry)(struct libnvme_transport_handle *hdl,
				struct libnvme_passthru_cmd *cmd, int err));

/**
 * libnvme_transport_handle_set_timeout() - Set the default command timeout
 * @hdl:	Transport handle to configure
 * @timeout_ms:	Timeout in milliseconds. A value of 0 means use the kernel
 *		default (NVME_DEFAULT_IOCTL_TIMEOUT).
 *
 * Sets a default timeout that is applied to every passthrough command
 * submitted through @hdl when the command's own timeout_ms field is 0.
 * Commands that set a non-zero timeout_ms override this default.
 */
void libnvme_transport_handle_set_timeout(struct libnvme_transport_handle *hdl,
		__u32 timeout_ms);

/**
 * libnvme_set_probe_enabled() - enable/disable the probe for new MI endpoints
 * @ctx:	&struct libnvme_global_ctx object
 * @enabled: whether to probe new endpoints
 *
 * Controls whether newly-created endpoints are probed for quirks on creation.
 * Defaults to enabled, which results in some initial messaging with the
 * endpoint to determine model-specific details.
 */
void libnvme_set_probe_enabled(struct libnvme_global_ctx *ctx, bool enabled);

/**
 * libnvme_set_dry_run() - Set global dry run state
 * @ctx:	struct libnvme_global_ctx object
 * @enable:	Enable/disable dry run state
 *
 * When dry_run is enabled, any IOCTL commands send via the passthru
 * interface won't be executed.
 */
void libnvme_set_dry_run(struct libnvme_global_ctx *ctx, bool enable);

/**
 * libnvme_set_ioctl_probing() - Enable/disable 64-bit IOCTL probing
 * @ctx:	struct libnvme_global_ctx object
 * @enable:	Enable/disable 64-bit IOCTL probing
 *
 * When IOCTL probing is enabled, a 64-bit IOCTL command is issued to
 * figure out if the passthru interface supports it.
 *
 * IOCTL probing is enabled per default.
 */
void libnvme_set_ioctl_probing(struct libnvme_global_ctx *ctx, bool enable);
