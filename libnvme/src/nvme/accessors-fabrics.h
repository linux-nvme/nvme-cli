/* SPDX-License-Identifier: LGPL-2.1-or-later */

/*
 * This file is part of libnvme.
 *
 * Copyright (c) 2025, Dell Technologies Inc. or its subsidiaries.
 * Authors: Martin Belanger <Martin.Belanger@dell.com>
 *
 *   ____                           _           _    ____          _
 *  / ___| ___ _ __   ___ _ __ __ _| |_ ___  __| |  / ___|___   __| | ___
 * | |  _ / _ \ '_ \ / _ \ '__/ _` | __/ _ \/ _` | | |   / _ \ / _` |/ _ \
 * | |_| |  __/ | | |  __/ | | (_| | ||  __/ (_| | | |__| (_) | (_| |  __/
 *  \____|\___|_| |_|\___|_|  \__,_|\__\___|\__,_|  \____\___/ \__,_|\___|
 *
 * Auto-generated struct member accessors (setter/getter)
 *
 * To update run: meson compile -C [BUILD-DIR] update-accessors
 * Or:            make update-accessors
 */
#ifndef _ACCESSORS_FABRICS_H_
#define _ACCESSORS_FABRICS_H_

#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>

#include <nvme/types.h>
#include <nvme/nvme-types.h>

/* Forward declarations. These are internal (opaque) structs. */
struct libnvmf_context;
struct libnvmf_tid;
struct libnvmf_discovery_args;
struct libnvmf_uri;

/****************************************************************************
 * Accessors for: struct libnvmf_context
 ****************************************************************************/

/**
 * libnvmf_context_get_transport() - Get transport.
 * @p: The &struct libnvmf_context instance to query.
 *
 * Return: The value of the transport field, or NULL if not set.
 */
const char *libnvmf_context_get_transport(const struct libnvmf_context *p);

/**
 * libnvmf_context_get_traddr() - Get traddr.
 * @p: The &struct libnvmf_context instance to query.
 *
 * Return: The value of the traddr field, or NULL if not set.
 */
const char *libnvmf_context_get_traddr(const struct libnvmf_context *p);

/**
 * libnvmf_context_get_host_traddr() - Get host_traddr.
 * @p: The &struct libnvmf_context instance to query.
 *
 * Return: The value of the host_traddr field, or NULL if not set.
 */
const char *libnvmf_context_get_host_traddr(const struct libnvmf_context *p);

/**
 * libnvmf_context_get_host_iface() - Get host_iface.
 * @p: The &struct libnvmf_context instance to query.
 *
 * Return: The value of the host_iface field, or NULL if not set.
 */
const char *libnvmf_context_get_host_iface(const struct libnvmf_context *p);

/**
 * libnvmf_context_get_trsvcid() - Get trsvcid.
 * @p: The &struct libnvmf_context instance to query.
 *
 * Return: The value of the trsvcid field, or NULL if not set.
 */
const char *libnvmf_context_get_trsvcid(const struct libnvmf_context *p);

/**
 * libnvmf_context_get_subsysnqn() - Get subsysnqn.
 * @p: The &struct libnvmf_context instance to query.
 *
 * Return: The value of the subsysnqn field, or NULL if not set.
 */
const char *libnvmf_context_get_subsysnqn(const struct libnvmf_context *p);

/**
 * libnvmf_context_set_queue_size() - Set queue_size.
 * @p: The &struct libnvmf_context instance to update.
 * @queue_size: Value to assign to the queue_size field.
 */
void libnvmf_context_set_queue_size(struct libnvmf_context *p, int queue_size);

/**
 * libnvmf_context_get_queue_size() - Get queue_size.
 * @p: The &struct libnvmf_context instance to query.
 *
 * Return: The value of the queue_size field.
 */
int libnvmf_context_get_queue_size(const struct libnvmf_context *p);

/**
 * libnvmf_context_set_nr_io_queues() - Set nr_io_queues.
 * @p: The &struct libnvmf_context instance to update.
 * @nr_io_queues: Value to assign to the nr_io_queues field.
 */
void libnvmf_context_set_nr_io_queues(
		struct libnvmf_context *p,
		int nr_io_queues);

/**
 * libnvmf_context_get_nr_io_queues() - Get nr_io_queues.
 * @p: The &struct libnvmf_context instance to query.
 *
 * Return: The value of the nr_io_queues field.
 */
int libnvmf_context_get_nr_io_queues(const struct libnvmf_context *p);

/**
 * libnvmf_context_set_reconnect_delay() - Set reconnect_delay.
 * @p: The &struct libnvmf_context instance to update.
 * @reconnect_delay: Value to assign to the reconnect_delay field.
 */
void libnvmf_context_set_reconnect_delay(
		struct libnvmf_context *p,
		int reconnect_delay);

/**
 * libnvmf_context_get_reconnect_delay() - Get reconnect_delay.
 * @p: The &struct libnvmf_context instance to query.
 *
 * Return: The value of the reconnect_delay field.
 */
int libnvmf_context_get_reconnect_delay(const struct libnvmf_context *p);

/**
 * libnvmf_context_set_ctrl_loss_tmo() - Set ctrl_loss_tmo.
 * @p: The &struct libnvmf_context instance to update.
 * @ctrl_loss_tmo: Value to assign to the ctrl_loss_tmo field.
 */
void libnvmf_context_set_ctrl_loss_tmo(
		struct libnvmf_context *p,
		int ctrl_loss_tmo);

/**
 * libnvmf_context_get_ctrl_loss_tmo() - Get ctrl_loss_tmo.
 * @p: The &struct libnvmf_context instance to query.
 *
 * Return: The value of the ctrl_loss_tmo field.
 */
int libnvmf_context_get_ctrl_loss_tmo(const struct libnvmf_context *p);

/**
 * libnvmf_context_set_fast_io_fail_tmo() - Set fast_io_fail_tmo.
 * @p: The &struct libnvmf_context instance to update.
 * @fast_io_fail_tmo: Value to assign to the fast_io_fail_tmo field.
 */
void libnvmf_context_set_fast_io_fail_tmo(
		struct libnvmf_context *p,
		int fast_io_fail_tmo);

/**
 * libnvmf_context_get_fast_io_fail_tmo() - Get fast_io_fail_tmo.
 * @p: The &struct libnvmf_context instance to query.
 *
 * Return: The value of the fast_io_fail_tmo field.
 */
int libnvmf_context_get_fast_io_fail_tmo(const struct libnvmf_context *p);

/**
 * libnvmf_context_set_keep_alive_tmo() - Set keep_alive_tmo.
 * @p: The &struct libnvmf_context instance to update.
 * @keep_alive_tmo: Value to assign to the keep_alive_tmo field.
 */
void libnvmf_context_set_keep_alive_tmo(
		struct libnvmf_context *p,
		int keep_alive_tmo);

/**
 * libnvmf_context_get_keep_alive_tmo() - Get keep_alive_tmo.
 * @p: The &struct libnvmf_context instance to query.
 *
 * Return: The value of the keep_alive_tmo field.
 */
int libnvmf_context_get_keep_alive_tmo(const struct libnvmf_context *p);

/**
 * libnvmf_context_set_nr_write_queues() - Set nr_write_queues.
 * @p: The &struct libnvmf_context instance to update.
 * @nr_write_queues: Value to assign to the nr_write_queues field.
 */
void libnvmf_context_set_nr_write_queues(
		struct libnvmf_context *p,
		int nr_write_queues);

/**
 * libnvmf_context_get_nr_write_queues() - Get nr_write_queues.
 * @p: The &struct libnvmf_context instance to query.
 *
 * Return: The value of the nr_write_queues field.
 */
int libnvmf_context_get_nr_write_queues(const struct libnvmf_context *p);

/**
 * libnvmf_context_set_nr_poll_queues() - Set nr_poll_queues.
 * @p: The &struct libnvmf_context instance to update.
 * @nr_poll_queues: Value to assign to the nr_poll_queues field.
 */
void libnvmf_context_set_nr_poll_queues(
		struct libnvmf_context *p,
		int nr_poll_queues);

/**
 * libnvmf_context_get_nr_poll_queues() - Get nr_poll_queues.
 * @p: The &struct libnvmf_context instance to query.
 *
 * Return: The value of the nr_poll_queues field.
 */
int libnvmf_context_get_nr_poll_queues(const struct libnvmf_context *p);

/**
 * libnvmf_context_set_tos() - Set tos.
 * @p: The &struct libnvmf_context instance to update.
 * @tos: Value to assign to the tos field.
 */
void libnvmf_context_set_tos(struct libnvmf_context *p, int tos);

/**
 * libnvmf_context_get_tos() - Get tos.
 * @p: The &struct libnvmf_context instance to query.
 *
 * Return: The value of the tos field.
 */
int libnvmf_context_get_tos(const struct libnvmf_context *p);

/**
 * libnvmf_context_set_keyring_id() - Set keyring_id.
 * @p: The &struct libnvmf_context instance to update.
 * @keyring_id: Value to assign to the keyring_id field.
 */
void libnvmf_context_set_keyring_id(struct libnvmf_context *p, long keyring_id);

/**
 * libnvmf_context_get_keyring_id() - Get keyring_id.
 * @p: The &struct libnvmf_context instance to query.
 *
 * Return: The value of the keyring_id field.
 */
long libnvmf_context_get_keyring_id(const struct libnvmf_context *p);

/**
 * libnvmf_context_set_tls_key_id() - Set tls_key_id.
 * @p: The &struct libnvmf_context instance to update.
 * @tls_key_id: Value to assign to the tls_key_id field.
 */
void libnvmf_context_set_tls_key_id(struct libnvmf_context *p, long tls_key_id);

/**
 * libnvmf_context_get_tls_key_id() - Get tls_key_id.
 * @p: The &struct libnvmf_context instance to query.
 *
 * Return: The value of the tls_key_id field.
 */
long libnvmf_context_get_tls_key_id(const struct libnvmf_context *p);

/**
 * libnvmf_context_set_tls_configured_key_id() - Set tls_configured_key_id.
 * @p: The &struct libnvmf_context instance to update.
 * @tls_configured_key_id: Value to assign to the tls_configured_key_id field.
 */
void libnvmf_context_set_tls_configured_key_id(
		struct libnvmf_context *p,
		long tls_configured_key_id);

/**
 * libnvmf_context_get_tls_configured_key_id() - Get tls_configured_key_id.
 * @p: The &struct libnvmf_context instance to query.
 *
 * Return: The value of the tls_configured_key_id field.
 */
long libnvmf_context_get_tls_configured_key_id(const struct libnvmf_context *p);

/**
 * libnvmf_context_set_duplicate_connect() - Set duplicate_connect.
 * @p: The &struct libnvmf_context instance to update.
 * @duplicate_connect: Value to assign to the duplicate_connect field.
 */
void libnvmf_context_set_duplicate_connect(
		struct libnvmf_context *p,
		bool duplicate_connect);

/**
 * libnvmf_context_get_duplicate_connect() - Get duplicate_connect.
 * @p: The &struct libnvmf_context instance to query.
 *
 * Return: The value of the duplicate_connect field.
 */
bool libnvmf_context_get_duplicate_connect(const struct libnvmf_context *p);

/**
 * libnvmf_context_set_disable_sqflow() - Set disable_sqflow.
 * @p: The &struct libnvmf_context instance to update.
 * @disable_sqflow: Value to assign to the disable_sqflow field.
 */
void libnvmf_context_set_disable_sqflow(
		struct libnvmf_context *p,
		bool disable_sqflow);

/**
 * libnvmf_context_get_disable_sqflow() - Get disable_sqflow.
 * @p: The &struct libnvmf_context instance to query.
 *
 * Return: The value of the disable_sqflow field.
 */
bool libnvmf_context_get_disable_sqflow(const struct libnvmf_context *p);

/**
 * libnvmf_context_set_hdr_digest() - Set hdr_digest.
 * @p: The &struct libnvmf_context instance to update.
 * @hdr_digest: Value to assign to the hdr_digest field.
 */
void libnvmf_context_set_hdr_digest(struct libnvmf_context *p, bool hdr_digest);

/**
 * libnvmf_context_get_hdr_digest() - Get hdr_digest.
 * @p: The &struct libnvmf_context instance to query.
 *
 * Return: The value of the hdr_digest field.
 */
bool libnvmf_context_get_hdr_digest(const struct libnvmf_context *p);

/**
 * libnvmf_context_set_data_digest() - Set data_digest.
 * @p: The &struct libnvmf_context instance to update.
 * @data_digest: Value to assign to the data_digest field.
 */
void libnvmf_context_set_data_digest(
		struct libnvmf_context *p,
		bool data_digest);

/**
 * libnvmf_context_get_data_digest() - Get data_digest.
 * @p: The &struct libnvmf_context instance to query.
 *
 * Return: The value of the data_digest field.
 */
bool libnvmf_context_get_data_digest(const struct libnvmf_context *p);

/**
 * libnvmf_context_set_tls() - Set tls.
 * @p: The &struct libnvmf_context instance to update.
 * @tls: Value to assign to the tls field.
 */
void libnvmf_context_set_tls(struct libnvmf_context *p, bool tls);

/**
 * libnvmf_context_get_tls() - Get tls.
 * @p: The &struct libnvmf_context instance to query.
 *
 * Return: The value of the tls field.
 */
bool libnvmf_context_get_tls(const struct libnvmf_context *p);

/**
 * libnvmf_context_set_concat() - Set concat.
 * @p: The &struct libnvmf_context instance to update.
 * @concat: Value to assign to the concat field.
 */
void libnvmf_context_set_concat(struct libnvmf_context *p, bool concat);

/**
 * libnvmf_context_get_concat() - Get concat.
 * @p: The &struct libnvmf_context instance to query.
 *
 * Return: The value of the concat field.
 */
bool libnvmf_context_get_concat(const struct libnvmf_context *p);

/**
 * libnvmf_context_set_default_max_discovery_retries() - Setter.
 * @p: The &struct libnvmf_context instance to update.
 * @default_max_discovery_retries: New value.
 */
void libnvmf_context_set_default_max_discovery_retries(
		struct libnvmf_context *p,
		int default_max_discovery_retries);

/**
 * libnvmf_context_get_default_max_discovery_retries() - Getter.
 * @p: The &struct libnvmf_context instance to query.
 *
 * Return: The value of the default_max_discovery_retries field.
 */
int libnvmf_context_get_default_max_discovery_retries(
		const struct libnvmf_context *p);

/**
 * libnvmf_context_set_default_keep_alive_timeout() - Setter.
 * @p: The &struct libnvmf_context instance to update.
 * @default_keep_alive_timeout: New value.
 */
void libnvmf_context_set_default_keep_alive_timeout(
		struct libnvmf_context *p,
		int default_keep_alive_timeout);

/**
 * libnvmf_context_get_default_keep_alive_timeout() - Getter.
 * @p: The &struct libnvmf_context instance to query.
 *
 * Return: The value of the default_keep_alive_timeout field.
 */
int libnvmf_context_get_default_keep_alive_timeout(
		const struct libnvmf_context *p);

/**
 * libnvmf_context_get_device() - Get device.
 * @p: The &struct libnvmf_context instance to query.
 *
 * Return: The value of the device field, or NULL if not set.
 */
const char *libnvmf_context_get_device(const struct libnvmf_context *p);

/**
 * libnvmf_context_set_persistent() - Set persistent.
 * @p: The &struct libnvmf_context instance to update.
 * @persistent: Value to assign to the persistent field.
 */
void libnvmf_context_set_persistent(struct libnvmf_context *p, bool persistent);

/**
 * libnvmf_context_get_persistent() - Get persistent.
 * @p: The &struct libnvmf_context instance to query.
 *
 * Return: The value of the persistent field.
 */
bool libnvmf_context_get_persistent(const struct libnvmf_context *p);

/**
 * libnvmf_context_get_devid_file() - Get devid_file.
 * @p: The &struct libnvmf_context instance to query.
 *
 * Return: The value of the devid_file field, or NULL if not set.
 */
const char *libnvmf_context_get_devid_file(const struct libnvmf_context *p);

/**
 * libnvmf_context_get_hostnqn() - Get hostnqn.
 * @p: The &struct libnvmf_context instance to query.
 *
 * Return: The value of the hostnqn field, or NULL if not set.
 */
const char *libnvmf_context_get_hostnqn(const struct libnvmf_context *p);

/**
 * libnvmf_context_get_hostid() - Get hostid.
 * @p: The &struct libnvmf_context instance to query.
 *
 * Return: The value of the hostid field, or NULL if not set.
 */
const char *libnvmf_context_get_hostid(const struct libnvmf_context *p);

/**
 * libnvmf_context_get_hostkey() - Get hostkey.
 * @p: The &struct libnvmf_context instance to query.
 *
 * Return: The value of the hostkey field, or NULL if not set.
 */
const char *libnvmf_context_get_hostkey(const struct libnvmf_context *p);

/**
 * libnvmf_context_get_ctrlkey() - Get ctrlkey.
 * @p: The &struct libnvmf_context instance to query.
 *
 * Return: The value of the ctrlkey field, or NULL if not set.
 */
const char *libnvmf_context_get_ctrlkey(const struct libnvmf_context *p);

/**
 * libnvmf_context_get_keyring() - Get keyring.
 * @p: The &struct libnvmf_context instance to query.
 *
 * Return: The value of the keyring field, or NULL if not set.
 */
const char *libnvmf_context_get_keyring(const struct libnvmf_context *p);

/**
 * libnvmf_context_get_tls_key() - Get tls_key.
 * @p: The &struct libnvmf_context instance to query.
 *
 * Return: The value of the tls_key field, or NULL if not set.
 */
const char *libnvmf_context_get_tls_key(const struct libnvmf_context *p);

/**
 * libnvmf_context_get_tls_key_identity() - Get tls_key_identity.
 * @p: The &struct libnvmf_context instance to query.
 *
 * Return: The value of the tls_key_identity field, or NULL if not set.
 */
const char *libnvmf_context_get_tls_key_identity(
		const struct libnvmf_context *p);

/****************************************************************************
 * Accessors for: struct libnvmf_tid
 ****************************************************************************/

/**
 * libnvmf_tid_new() - Allocate and initialise a libnvmf_tid object.
 * @pp: On success, *pp is set to the newly allocated object.
 *
 * Allocates a zeroed &struct libnvmf_tid on the heap.
 * The caller must release it with libnvmf_tid_free().
 *
 * Return: 0 on success, -EINVAL if @pp is NULL,
 *         -ENOMEM if allocation fails.
 */
int libnvmf_tid_new(struct libnvmf_tid **pp);

/**
 * libnvmf_tid_free() - Release a libnvmf_tid object.
 * @p: Object previously returned by libnvmf_tid_new().
 *     A NULL pointer is silently ignored.
 */
void libnvmf_tid_free(struct libnvmf_tid *p);

/**
 * libnvmf_tid_get_transport() - Get transport.
 * @p: The &struct libnvmf_tid instance to query.
 *
 * Return: The value of the transport field, or NULL if not set.
 */
const char *libnvmf_tid_get_transport(const struct libnvmf_tid *p);

/**
 * libnvmf_tid_get_traddr() - Get traddr.
 * @p: The &struct libnvmf_tid instance to query.
 *
 * Return: The value of the traddr field, or NULL if not set.
 */
const char *libnvmf_tid_get_traddr(const struct libnvmf_tid *p);

/**
 * libnvmf_tid_get_trsvcid() - Get trsvcid.
 * @p: The &struct libnvmf_tid instance to query.
 *
 * Return: The value of the trsvcid field, or NULL if not set.
 */
const char *libnvmf_tid_get_trsvcid(const struct libnvmf_tid *p);

/**
 * libnvmf_tid_get_subsysnqn() - Get subsysnqn.
 * @p: The &struct libnvmf_tid instance to query.
 *
 * Return: The value of the subsysnqn field, or NULL if not set.
 */
const char *libnvmf_tid_get_subsysnqn(const struct libnvmf_tid *p);

/**
 * libnvmf_tid_get_host_traddr() - Get host_traddr.
 * @p: The &struct libnvmf_tid instance to query.
 *
 * Return: The value of the host_traddr field, or NULL if not set.
 */
const char *libnvmf_tid_get_host_traddr(const struct libnvmf_tid *p);

/**
 * libnvmf_tid_get_host_iface() - Get host_iface.
 * @p: The &struct libnvmf_tid instance to query.
 *
 * Return: The value of the host_iface field, or NULL if not set.
 */
const char *libnvmf_tid_get_host_iface(const struct libnvmf_tid *p);

/**
 * libnvmf_tid_get_hostnqn() - Get hostnqn.
 * @p: The &struct libnvmf_tid instance to query.
 *
 * Return: The value of the hostnqn field, or NULL if not set.
 */
const char *libnvmf_tid_get_hostnqn(const struct libnvmf_tid *p);

/**
 * libnvmf_tid_get_hostid() - Get hostid.
 * @p: The &struct libnvmf_tid instance to query.
 *
 * Return: The value of the hostid field, or NULL if not set.
 */
const char *libnvmf_tid_get_hostid(const struct libnvmf_tid *p);

/****************************************************************************
 * Accessors for: struct libnvmf_discovery_args
 ****************************************************************************/

/**
 * libnvmf_discovery_args_new() - Allocate and initialise a new instance.
 * @pp: On success, *pp is set to the newly allocated object.
 *
 * Allocates a zeroed &struct libnvmf_discovery_args on the heap.
 * The caller must release it with libnvmf_discovery_args_free().
 *
 * Return: 0 on success, -EINVAL if @pp is NULL,
 *         -ENOMEM if allocation fails.
 */
int libnvmf_discovery_args_new(struct libnvmf_discovery_args **pp);

/**
 * libnvmf_discovery_args_free() - Release a libnvmf_discovery_args object.
 * @p: Object previously returned by libnvmf_discovery_args_new().
 *     A NULL pointer is silently ignored.
 */
void libnvmf_discovery_args_free(struct libnvmf_discovery_args *p);

/**
 * libnvmf_discovery_args_init_defaults() - Set fields to their defaults.
 * @p: The &struct libnvmf_discovery_args instance to initialise.
 *
 * Sets each field that carries a default annotation to its
 * compile-time default value.  Called automatically by
 * libnvmf_discovery_args_new() but may also be called directly to reset an
 * instance to its defaults without reallocating it.
 */
void libnvmf_discovery_args_init_defaults(struct libnvmf_discovery_args *p);

/**
 * libnvmf_discovery_args_set_max_retries() - Set max_retries.
 * @p: The &struct libnvmf_discovery_args instance to update.
 * @max_retries: Value to assign to the max_retries field.
 */
void libnvmf_discovery_args_set_max_retries(
		struct libnvmf_discovery_args *p,
		int max_retries);

/**
 * libnvmf_discovery_args_get_max_retries() - Get max_retries.
 * @p: The &struct libnvmf_discovery_args instance to query.
 *
 * Return: The value of the max_retries field.
 */
int libnvmf_discovery_args_get_max_retries(
		const struct libnvmf_discovery_args *p);

/**
 * libnvmf_discovery_args_set_lsp() - Set lsp.
 * @p: The &struct libnvmf_discovery_args instance to update.
 * @lsp: Value to assign to the lsp field.
 */
void libnvmf_discovery_args_set_lsp(struct libnvmf_discovery_args *p, __u8 lsp);

/**
 * libnvmf_discovery_args_get_lsp() - Get lsp.
 * @p: The &struct libnvmf_discovery_args instance to query.
 *
 * Return: The value of the lsp field.
 */
__u8 libnvmf_discovery_args_get_lsp(const struct libnvmf_discovery_args *p);

/****************************************************************************
 * Accessors for: struct libnvmf_uri
 ****************************************************************************/

/**
 * libnvmf_uri_set_scheme() - Set scheme.
 * @p: The &struct libnvmf_uri instance to update.
 * @scheme: New string; a copy is stored. Pass NULL to clear.
 */
void libnvmf_uri_set_scheme(struct libnvmf_uri *p, const char *scheme);

/**
 * libnvmf_uri_get_scheme() - Get scheme.
 * @p: The &struct libnvmf_uri instance to query.
 *
 * Return: The value of the scheme field, or NULL if not set.
 */
const char *libnvmf_uri_get_scheme(const struct libnvmf_uri *p);

/**
 * libnvmf_uri_set_protocol() - Set protocol.
 * @p: The &struct libnvmf_uri instance to update.
 * @protocol: New string; a copy is stored. Pass NULL to clear.
 */
void libnvmf_uri_set_protocol(struct libnvmf_uri *p, const char *protocol);

/**
 * libnvmf_uri_get_protocol() - Get protocol.
 * @p: The &struct libnvmf_uri instance to query.
 *
 * Return: The value of the protocol field, or NULL if not set.
 */
const char *libnvmf_uri_get_protocol(const struct libnvmf_uri *p);

/**
 * libnvmf_uri_set_userinfo() - Set userinfo.
 * @p: The &struct libnvmf_uri instance to update.
 * @userinfo: New string; a copy is stored. Pass NULL to clear.
 */
void libnvmf_uri_set_userinfo(struct libnvmf_uri *p, const char *userinfo);

/**
 * libnvmf_uri_get_userinfo() - Get userinfo.
 * @p: The &struct libnvmf_uri instance to query.
 *
 * Return: The value of the userinfo field, or NULL if not set.
 */
const char *libnvmf_uri_get_userinfo(const struct libnvmf_uri *p);

/**
 * libnvmf_uri_set_host() - Set host.
 * @p: The &struct libnvmf_uri instance to update.
 * @host: New string; a copy is stored. Pass NULL to clear.
 */
void libnvmf_uri_set_host(struct libnvmf_uri *p, const char *host);

/**
 * libnvmf_uri_get_host() - Get host.
 * @p: The &struct libnvmf_uri instance to query.
 *
 * Return: The value of the host field, or NULL if not set.
 */
const char *libnvmf_uri_get_host(const struct libnvmf_uri *p);

/**
 * libnvmf_uri_set_port() - Set port.
 * @p: The &struct libnvmf_uri instance to update.
 * @port: Value to assign to the port field.
 */
void libnvmf_uri_set_port(struct libnvmf_uri *p, int port);

/**
 * libnvmf_uri_get_port() - Get port.
 * @p: The &struct libnvmf_uri instance to query.
 *
 * Return: The value of the port field.
 */
int libnvmf_uri_get_port(const struct libnvmf_uri *p);

/**
 * libnvmf_uri_set_path_segments() - Set path_segments.
 * @p: The &struct libnvmf_uri instance to update.
 * @path_segments: New NULL-terminated string array; deep-copied.
 */
void libnvmf_uri_set_path_segments(
		struct libnvmf_uri *p,
		const char *const *path_segments);

/**
 * libnvmf_uri_get_path_segments() - Get path_segments.
 * @p: The &struct libnvmf_uri instance to query.
 *
 * Return: The value of the path_segments field.
 */
const char *const *libnvmf_uri_get_path_segments(const struct libnvmf_uri *p);

/**
 * libnvmf_uri_set_query() - Set query.
 * @p: The &struct libnvmf_uri instance to update.
 * @query: New string; a copy is stored. Pass NULL to clear.
 */
void libnvmf_uri_set_query(struct libnvmf_uri *p, const char *query);

/**
 * libnvmf_uri_get_query() - Get query.
 * @p: The &struct libnvmf_uri instance to query.
 *
 * Return: The value of the query field, or NULL if not set.
 */
const char *libnvmf_uri_get_query(const struct libnvmf_uri *p);

/**
 * libnvmf_uri_set_fragment() - Set fragment.
 * @p: The &struct libnvmf_uri instance to update.
 * @fragment: New string; a copy is stored. Pass NULL to clear.
 */
void libnvmf_uri_set_fragment(struct libnvmf_uri *p, const char *fragment);

/**
 * libnvmf_uri_get_fragment() - Get fragment.
 * @p: The &struct libnvmf_uri instance to query.
 *
 * Return: The value of the fragment field, or NULL if not set.
 */
const char *libnvmf_uri_get_fragment(const struct libnvmf_uri *p);

#endif /* _ACCESSORS_FABRICS_H_ */
