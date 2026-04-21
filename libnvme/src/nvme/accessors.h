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
#ifndef _ACCESSORS_H_
#define _ACCESSORS_H_

#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>

#include <nvme/types.h>

/* Forward declarations. These are internal (opaque) structs. */
struct libnvme_fabrics_config;
struct libnvme_path;
struct libnvme_ns;
struct libnvme_ctrl;
struct libnvme_subsystem;
struct libnvme_host;
struct libnvme_fabric_options;

/****************************************************************************
 * Accessors for: struct libnvme_fabrics_config
 ****************************************************************************/

/**
 * libnvme_fabrics_config_set_queue_size() - Set queue_size.
 * @p: The &struct libnvme_fabrics_config instance to update.
 * @queue_size: Value to assign to the queue_size field.
 */
void libnvme_fabrics_config_set_queue_size(
		struct libnvme_fabrics_config *p,
		int queue_size);

/**
 * libnvme_fabrics_config_get_queue_size() - Get queue_size.
 * @p: The &struct libnvme_fabrics_config instance to query.
 *
 * Return: The value of the queue_size field.
 */
int libnvme_fabrics_config_get_queue_size(
		const struct libnvme_fabrics_config *p);

/**
 * libnvme_fabrics_config_set_nr_io_queues() - Set nr_io_queues.
 * @p: The &struct libnvme_fabrics_config instance to update.
 * @nr_io_queues: Value to assign to the nr_io_queues field.
 */
void libnvme_fabrics_config_set_nr_io_queues(
		struct libnvme_fabrics_config *p,
		int nr_io_queues);

/**
 * libnvme_fabrics_config_get_nr_io_queues() - Get nr_io_queues.
 * @p: The &struct libnvme_fabrics_config instance to query.
 *
 * Return: The value of the nr_io_queues field.
 */
int libnvme_fabrics_config_get_nr_io_queues(
		const struct libnvme_fabrics_config *p);

/**
 * libnvme_fabrics_config_set_reconnect_delay() - Set reconnect_delay.
 * @p: The &struct libnvme_fabrics_config instance to update.
 * @reconnect_delay: Value to assign to the reconnect_delay field.
 */
void libnvme_fabrics_config_set_reconnect_delay(
		struct libnvme_fabrics_config *p,
		int reconnect_delay);

/**
 * libnvme_fabrics_config_get_reconnect_delay() - Get reconnect_delay.
 * @p: The &struct libnvme_fabrics_config instance to query.
 *
 * Return: The value of the reconnect_delay field.
 */
int libnvme_fabrics_config_get_reconnect_delay(
		const struct libnvme_fabrics_config *p);

/**
 * libnvme_fabrics_config_set_ctrl_loss_tmo() - Set ctrl_loss_tmo.
 * @p: The &struct libnvme_fabrics_config instance to update.
 * @ctrl_loss_tmo: Value to assign to the ctrl_loss_tmo field.
 */
void libnvme_fabrics_config_set_ctrl_loss_tmo(
		struct libnvme_fabrics_config *p,
		int ctrl_loss_tmo);

/**
 * libnvme_fabrics_config_get_ctrl_loss_tmo() - Get ctrl_loss_tmo.
 * @p: The &struct libnvme_fabrics_config instance to query.
 *
 * Return: The value of the ctrl_loss_tmo field.
 */
int libnvme_fabrics_config_get_ctrl_loss_tmo(
		const struct libnvme_fabrics_config *p);

/**
 * libnvme_fabrics_config_set_fast_io_fail_tmo() - Set fast_io_fail_tmo.
 * @p: The &struct libnvme_fabrics_config instance to update.
 * @fast_io_fail_tmo: Value to assign to the fast_io_fail_tmo field.
 */
void libnvme_fabrics_config_set_fast_io_fail_tmo(
		struct libnvme_fabrics_config *p,
		int fast_io_fail_tmo);

/**
 * libnvme_fabrics_config_get_fast_io_fail_tmo() - Get fast_io_fail_tmo.
 * @p: The &struct libnvme_fabrics_config instance to query.
 *
 * Return: The value of the fast_io_fail_tmo field.
 */
int libnvme_fabrics_config_get_fast_io_fail_tmo(
		const struct libnvme_fabrics_config *p);

/**
 * libnvme_fabrics_config_set_keep_alive_tmo() - Set keep_alive_tmo.
 * @p: The &struct libnvme_fabrics_config instance to update.
 * @keep_alive_tmo: Value to assign to the keep_alive_tmo field.
 */
void libnvme_fabrics_config_set_keep_alive_tmo(
		struct libnvme_fabrics_config *p,
		int keep_alive_tmo);

/**
 * libnvme_fabrics_config_get_keep_alive_tmo() - Get keep_alive_tmo.
 * @p: The &struct libnvme_fabrics_config instance to query.
 *
 * Return: The value of the keep_alive_tmo field.
 */
int libnvme_fabrics_config_get_keep_alive_tmo(
		const struct libnvme_fabrics_config *p);

/**
 * libnvme_fabrics_config_set_nr_write_queues() - Set nr_write_queues.
 * @p: The &struct libnvme_fabrics_config instance to update.
 * @nr_write_queues: Value to assign to the nr_write_queues field.
 */
void libnvme_fabrics_config_set_nr_write_queues(
		struct libnvme_fabrics_config *p,
		int nr_write_queues);

/**
 * libnvme_fabrics_config_get_nr_write_queues() - Get nr_write_queues.
 * @p: The &struct libnvme_fabrics_config instance to query.
 *
 * Return: The value of the nr_write_queues field.
 */
int libnvme_fabrics_config_get_nr_write_queues(
		const struct libnvme_fabrics_config *p);

/**
 * libnvme_fabrics_config_set_nr_poll_queues() - Set nr_poll_queues.
 * @p: The &struct libnvme_fabrics_config instance to update.
 * @nr_poll_queues: Value to assign to the nr_poll_queues field.
 */
void libnvme_fabrics_config_set_nr_poll_queues(
		struct libnvme_fabrics_config *p,
		int nr_poll_queues);

/**
 * libnvme_fabrics_config_get_nr_poll_queues() - Get nr_poll_queues.
 * @p: The &struct libnvme_fabrics_config instance to query.
 *
 * Return: The value of the nr_poll_queues field.
 */
int libnvme_fabrics_config_get_nr_poll_queues(
		const struct libnvme_fabrics_config *p);

/**
 * libnvme_fabrics_config_set_tos() - Set tos.
 * @p: The &struct libnvme_fabrics_config instance to update.
 * @tos: Value to assign to the tos field.
 */
void libnvme_fabrics_config_set_tos(struct libnvme_fabrics_config *p, int tos);

/**
 * libnvme_fabrics_config_get_tos() - Get tos.
 * @p: The &struct libnvme_fabrics_config instance to query.
 *
 * Return: The value of the tos field.
 */
int libnvme_fabrics_config_get_tos(const struct libnvme_fabrics_config *p);

/**
 * libnvme_fabrics_config_set_keyring_id() - Set keyring_id.
 * @p: The &struct libnvme_fabrics_config instance to update.
 * @keyring_id: Value to assign to the keyring_id field.
 */
void libnvme_fabrics_config_set_keyring_id(
		struct libnvme_fabrics_config *p,
		long keyring_id);

/**
 * libnvme_fabrics_config_get_keyring_id() - Get keyring_id.
 * @p: The &struct libnvme_fabrics_config instance to query.
 *
 * Return: The value of the keyring_id field.
 */
long libnvme_fabrics_config_get_keyring_id(
		const struct libnvme_fabrics_config *p);

/**
 * libnvme_fabrics_config_set_tls_key_id() - Set tls_key_id.
 * @p: The &struct libnvme_fabrics_config instance to update.
 * @tls_key_id: Value to assign to the tls_key_id field.
 */
void libnvme_fabrics_config_set_tls_key_id(
		struct libnvme_fabrics_config *p,
		long tls_key_id);

/**
 * libnvme_fabrics_config_get_tls_key_id() - Get tls_key_id.
 * @p: The &struct libnvme_fabrics_config instance to query.
 *
 * Return: The value of the tls_key_id field.
 */
long libnvme_fabrics_config_get_tls_key_id(
		const struct libnvme_fabrics_config *p);

/**
 * libnvme_fabrics_config_set_tls_configured_key_id() - Setter.
 * @p: The &struct libnvme_fabrics_config instance to update.
 * @tls_configured_key_id: Value to assign to the tls_configured_key_id field.
 */
void libnvme_fabrics_config_set_tls_configured_key_id(
		struct libnvme_fabrics_config *p,
		long tls_configured_key_id);

/**
 * libnvme_fabrics_config_get_tls_configured_key_id() - Getter.
 * @p: The &struct libnvme_fabrics_config instance to query.
 *
 * Return: The value of the tls_configured_key_id field.
 */
long libnvme_fabrics_config_get_tls_configured_key_id(
		const struct libnvme_fabrics_config *p);

/**
 * libnvme_fabrics_config_set_duplicate_connect() - Set duplicate_connect.
 * @p: The &struct libnvme_fabrics_config instance to update.
 * @duplicate_connect: Value to assign to the duplicate_connect field.
 */
void libnvme_fabrics_config_set_duplicate_connect(
		struct libnvme_fabrics_config *p,
		bool duplicate_connect);

/**
 * libnvme_fabrics_config_get_duplicate_connect() - Get duplicate_connect.
 * @p: The &struct libnvme_fabrics_config instance to query.
 *
 * Return: The value of the duplicate_connect field.
 */
bool libnvme_fabrics_config_get_duplicate_connect(
		const struct libnvme_fabrics_config *p);

/**
 * libnvme_fabrics_config_set_disable_sqflow() - Set disable_sqflow.
 * @p: The &struct libnvme_fabrics_config instance to update.
 * @disable_sqflow: Value to assign to the disable_sqflow field.
 */
void libnvme_fabrics_config_set_disable_sqflow(
		struct libnvme_fabrics_config *p,
		bool disable_sqflow);

/**
 * libnvme_fabrics_config_get_disable_sqflow() - Get disable_sqflow.
 * @p: The &struct libnvme_fabrics_config instance to query.
 *
 * Return: The value of the disable_sqflow field.
 */
bool libnvme_fabrics_config_get_disable_sqflow(
		const struct libnvme_fabrics_config *p);

/**
 * libnvme_fabrics_config_set_hdr_digest() - Set hdr_digest.
 * @p: The &struct libnvme_fabrics_config instance to update.
 * @hdr_digest: Value to assign to the hdr_digest field.
 */
void libnvme_fabrics_config_set_hdr_digest(
		struct libnvme_fabrics_config *p,
		bool hdr_digest);

/**
 * libnvme_fabrics_config_get_hdr_digest() - Get hdr_digest.
 * @p: The &struct libnvme_fabrics_config instance to query.
 *
 * Return: The value of the hdr_digest field.
 */
bool libnvme_fabrics_config_get_hdr_digest(
		const struct libnvme_fabrics_config *p);

/**
 * libnvme_fabrics_config_set_data_digest() - Set data_digest.
 * @p: The &struct libnvme_fabrics_config instance to update.
 * @data_digest: Value to assign to the data_digest field.
 */
void libnvme_fabrics_config_set_data_digest(
		struct libnvme_fabrics_config *p,
		bool data_digest);

/**
 * libnvme_fabrics_config_get_data_digest() - Get data_digest.
 * @p: The &struct libnvme_fabrics_config instance to query.
 *
 * Return: The value of the data_digest field.
 */
bool libnvme_fabrics_config_get_data_digest(
		const struct libnvme_fabrics_config *p);

/**
 * libnvme_fabrics_config_set_tls() - Set tls.
 * @p: The &struct libnvme_fabrics_config instance to update.
 * @tls: Value to assign to the tls field.
 */
void libnvme_fabrics_config_set_tls(struct libnvme_fabrics_config *p, bool tls);

/**
 * libnvme_fabrics_config_get_tls() - Get tls.
 * @p: The &struct libnvme_fabrics_config instance to query.
 *
 * Return: The value of the tls field.
 */
bool libnvme_fabrics_config_get_tls(const struct libnvme_fabrics_config *p);

/**
 * libnvme_fabrics_config_set_concat() - Set concat.
 * @p: The &struct libnvme_fabrics_config instance to update.
 * @concat: Value to assign to the concat field.
 */
void libnvme_fabrics_config_set_concat(
		struct libnvme_fabrics_config *p,
		bool concat);

/**
 * libnvme_fabrics_config_get_concat() - Get concat.
 * @p: The &struct libnvme_fabrics_config instance to query.
 *
 * Return: The value of the concat field.
 */
bool libnvme_fabrics_config_get_concat(const struct libnvme_fabrics_config *p);

/****************************************************************************
 * Accessors for: struct libnvme_path
 ****************************************************************************/

/**
 * libnvme_path_set_name() - Set name.
 * @p: The &struct libnvme_path instance to update.
 * @name: New string; a copy is stored. Pass NULL to clear.
 */
void libnvme_path_set_name(struct libnvme_path *p, const char *name);

/**
 * libnvme_path_get_name() - Get name.
 * @p: The &struct libnvme_path instance to query.
 *
 * Return: The value of the name field, or NULL if not set.
 */
const char *libnvme_path_get_name(const struct libnvme_path *p);

/**
 * libnvme_path_set_sysfs_dir() - Set sysfs_dir.
 * @p: The &struct libnvme_path instance to update.
 * @sysfs_dir: New string; a copy is stored. Pass NULL to clear.
 */
void libnvme_path_set_sysfs_dir(struct libnvme_path *p, const char *sysfs_dir);

/**
 * libnvme_path_get_sysfs_dir() - Get sysfs_dir.
 * @p: The &struct libnvme_path instance to query.
 *
 * Return: The value of the sysfs_dir field, or NULL if not set.
 */
const char *libnvme_path_get_sysfs_dir(const struct libnvme_path *p);

/**
 * libnvme_path_set_grpid() - Set grpid.
 * @p: The &struct libnvme_path instance to update.
 * @grpid: Value to assign to the grpid field.
 */
void libnvme_path_set_grpid(struct libnvme_path *p, int grpid);

/**
 * libnvme_path_get_grpid() - Get grpid.
 * @p: The &struct libnvme_path instance to query.
 *
 * Return: The value of the grpid field.
 */
int libnvme_path_get_grpid(const struct libnvme_path *p);

/****************************************************************************
 * Accessors for: struct libnvme_ns
 ****************************************************************************/

/**
 * libnvme_ns_set_nsid() - Set nsid.
 * @p: The &struct libnvme_ns instance to update.
 * @nsid: Value to assign to the nsid field.
 */
void libnvme_ns_set_nsid(struct libnvme_ns *p, __u32 nsid);

/**
 * libnvme_ns_get_nsid() - Get nsid.
 * @p: The &struct libnvme_ns instance to query.
 *
 * Return: The value of the nsid field.
 */
__u32 libnvme_ns_get_nsid(const struct libnvme_ns *p);

/**
 * libnvme_ns_set_name() - Set name.
 * @p: The &struct libnvme_ns instance to update.
 * @name: New string; a copy is stored. Pass NULL to clear.
 */
void libnvme_ns_set_name(struct libnvme_ns *p, const char *name);

/**
 * libnvme_ns_get_name() - Get name.
 * @p: The &struct libnvme_ns instance to query.
 *
 * Return: The value of the name field, or NULL if not set.
 */
const char *libnvme_ns_get_name(const struct libnvme_ns *p);

/**
 * libnvme_ns_set_sysfs_dir() - Set sysfs_dir.
 * @p: The &struct libnvme_ns instance to update.
 * @sysfs_dir: New string; a copy is stored. Pass NULL to clear.
 */
void libnvme_ns_set_sysfs_dir(struct libnvme_ns *p, const char *sysfs_dir);

/**
 * libnvme_ns_get_sysfs_dir() - Get sysfs_dir.
 * @p: The &struct libnvme_ns instance to query.
 *
 * Return: The value of the sysfs_dir field, or NULL if not set.
 */
const char *libnvme_ns_get_sysfs_dir(const struct libnvme_ns *p);

/**
 * libnvme_ns_set_lba_shift() - Set lba_shift.
 * @p: The &struct libnvme_ns instance to update.
 * @lba_shift: Value to assign to the lba_shift field.
 */
void libnvme_ns_set_lba_shift(struct libnvme_ns *p, int lba_shift);

/**
 * libnvme_ns_get_lba_shift() - Get lba_shift.
 * @p: The &struct libnvme_ns instance to query.
 *
 * Return: The value of the lba_shift field.
 */
int libnvme_ns_get_lba_shift(const struct libnvme_ns *p);

/**
 * libnvme_ns_set_lba_size() - Set lba_size.
 * @p: The &struct libnvme_ns instance to update.
 * @lba_size: Value to assign to the lba_size field.
 */
void libnvme_ns_set_lba_size(struct libnvme_ns *p, int lba_size);

/**
 * libnvme_ns_get_lba_size() - Get lba_size.
 * @p: The &struct libnvme_ns instance to query.
 *
 * Return: The value of the lba_size field.
 */
int libnvme_ns_get_lba_size(const struct libnvme_ns *p);

/**
 * libnvme_ns_set_meta_size() - Set meta_size.
 * @p: The &struct libnvme_ns instance to update.
 * @meta_size: Value to assign to the meta_size field.
 */
void libnvme_ns_set_meta_size(struct libnvme_ns *p, int meta_size);

/**
 * libnvme_ns_get_meta_size() - Get meta_size.
 * @p: The &struct libnvme_ns instance to query.
 *
 * Return: The value of the meta_size field.
 */
int libnvme_ns_get_meta_size(const struct libnvme_ns *p);

/**
 * libnvme_ns_set_lba_count() - Set lba_count.
 * @p: The &struct libnvme_ns instance to update.
 * @lba_count: Value to assign to the lba_count field.
 */
void libnvme_ns_set_lba_count(struct libnvme_ns *p, uint64_t lba_count);

/**
 * libnvme_ns_get_lba_count() - Get lba_count.
 * @p: The &struct libnvme_ns instance to query.
 *
 * Return: The value of the lba_count field.
 */
uint64_t libnvme_ns_get_lba_count(const struct libnvme_ns *p);

/**
 * libnvme_ns_set_lba_util() - Set lba_util.
 * @p: The &struct libnvme_ns instance to update.
 * @lba_util: Value to assign to the lba_util field.
 */
void libnvme_ns_set_lba_util(struct libnvme_ns *p, uint64_t lba_util);

/**
 * libnvme_ns_get_lba_util() - Get lba_util.
 * @p: The &struct libnvme_ns instance to query.
 *
 * Return: The value of the lba_util field.
 */
uint64_t libnvme_ns_get_lba_util(const struct libnvme_ns *p);

/****************************************************************************
 * Accessors for: struct libnvme_ctrl
 ****************************************************************************/

/**
 * libnvme_ctrl_get_name() - Get name.
 * @p: The &struct libnvme_ctrl instance to query.
 *
 * Return: The value of the name field, or NULL if not set.
 */
const char *libnvme_ctrl_get_name(const struct libnvme_ctrl *p);

/**
 * libnvme_ctrl_get_sysfs_dir() - Get sysfs_dir.
 * @p: The &struct libnvme_ctrl instance to query.
 *
 * Return: The value of the sysfs_dir field, or NULL if not set.
 */
const char *libnvme_ctrl_get_sysfs_dir(const struct libnvme_ctrl *p);

/**
 * libnvme_ctrl_get_firmware() - Get firmware.
 * @p: The &struct libnvme_ctrl instance to query.
 *
 * Return: The value of the firmware field, or NULL if not set.
 */
const char *libnvme_ctrl_get_firmware(const struct libnvme_ctrl *p);

/**
 * libnvme_ctrl_get_model() - Get model.
 * @p: The &struct libnvme_ctrl instance to query.
 *
 * Return: The value of the model field, or NULL if not set.
 */
const char *libnvme_ctrl_get_model(const struct libnvme_ctrl *p);

/**
 * libnvme_ctrl_get_numa_node() - Get numa_node.
 * @p: The &struct libnvme_ctrl instance to query.
 *
 * Return: The value of the numa_node field, or NULL if not set.
 */
const char *libnvme_ctrl_get_numa_node(const struct libnvme_ctrl *p);

/**
 * libnvme_ctrl_get_queue_count() - Get queue_count.
 * @p: The &struct libnvme_ctrl instance to query.
 *
 * Return: The value of the queue_count field, or NULL if not set.
 */
const char *libnvme_ctrl_get_queue_count(const struct libnvme_ctrl *p);

/**
 * libnvme_ctrl_get_serial() - Get serial.
 * @p: The &struct libnvme_ctrl instance to query.
 *
 * Return: The value of the serial field, or NULL if not set.
 */
const char *libnvme_ctrl_get_serial(const struct libnvme_ctrl *p);

/**
 * libnvme_ctrl_get_sqsize() - Get sqsize.
 * @p: The &struct libnvme_ctrl instance to query.
 *
 * Return: The value of the sqsize field, or NULL if not set.
 */
const char *libnvme_ctrl_get_sqsize(const struct libnvme_ctrl *p);

/**
 * libnvme_ctrl_get_transport() - Get transport.
 * @p: The &struct libnvme_ctrl instance to query.
 *
 * Return: The value of the transport field, or NULL if not set.
 */
const char *libnvme_ctrl_get_transport(const struct libnvme_ctrl *p);

/**
 * libnvme_ctrl_get_subsysnqn() - Get subsysnqn.
 * @p: The &struct libnvme_ctrl instance to query.
 *
 * Return: The value of the subsysnqn field, or NULL if not set.
 */
const char *libnvme_ctrl_get_subsysnqn(const struct libnvme_ctrl *p);

/**
 * libnvme_ctrl_get_traddr() - Get traddr.
 * @p: The &struct libnvme_ctrl instance to query.
 *
 * Return: The value of the traddr field, or NULL if not set.
 */
const char *libnvme_ctrl_get_traddr(const struct libnvme_ctrl *p);

/**
 * libnvme_ctrl_get_trsvcid() - Get trsvcid.
 * @p: The &struct libnvme_ctrl instance to query.
 *
 * Return: The value of the trsvcid field, or NULL if not set.
 */
const char *libnvme_ctrl_get_trsvcid(const struct libnvme_ctrl *p);

/**
 * libnvme_ctrl_set_dhchap_host_key() - Set dhchap_host_key.
 * @p: The &struct libnvme_ctrl instance to update.
 * @dhchap_host_key: New string; a copy is stored. Pass NULL to clear.
 */
void libnvme_ctrl_set_dhchap_host_key(
		struct libnvme_ctrl *p,
		const char *dhchap_host_key);

/**
 * libnvme_ctrl_get_dhchap_host_key() - Get dhchap_host_key.
 * @p: The &struct libnvme_ctrl instance to query.
 *
 * Return: The value of the dhchap_host_key field, or NULL if not set.
 */
const char *libnvme_ctrl_get_dhchap_host_key(const struct libnvme_ctrl *p);

/**
 * libnvme_ctrl_set_dhchap_ctrl_key() - Set dhchap_ctrl_key.
 * @p: The &struct libnvme_ctrl instance to update.
 * @dhchap_ctrl_key: New string; a copy is stored. Pass NULL to clear.
 */
void libnvme_ctrl_set_dhchap_ctrl_key(
		struct libnvme_ctrl *p,
		const char *dhchap_ctrl_key);

/**
 * libnvme_ctrl_get_dhchap_ctrl_key() - Get dhchap_ctrl_key.
 * @p: The &struct libnvme_ctrl instance to query.
 *
 * Return: The value of the dhchap_ctrl_key field, or NULL if not set.
 */
const char *libnvme_ctrl_get_dhchap_ctrl_key(const struct libnvme_ctrl *p);

/**
 * libnvme_ctrl_set_keyring() - Set keyring.
 * @p: The &struct libnvme_ctrl instance to update.
 * @keyring: New string; a copy is stored. Pass NULL to clear.
 */
void libnvme_ctrl_set_keyring(struct libnvme_ctrl *p, const char *keyring);

/**
 * libnvme_ctrl_get_keyring() - Get keyring.
 * @p: The &struct libnvme_ctrl instance to query.
 *
 * Return: The value of the keyring field, or NULL if not set.
 */
const char *libnvme_ctrl_get_keyring(const struct libnvme_ctrl *p);

/**
 * libnvme_ctrl_set_tls_key_identity() - Set tls_key_identity.
 * @p: The &struct libnvme_ctrl instance to update.
 * @tls_key_identity: New string; a copy is stored. Pass NULL to clear.
 */
void libnvme_ctrl_set_tls_key_identity(
		struct libnvme_ctrl *p,
		const char *tls_key_identity);

/**
 * libnvme_ctrl_get_tls_key_identity() - Get tls_key_identity.
 * @p: The &struct libnvme_ctrl instance to query.
 *
 * Return: The value of the tls_key_identity field, or NULL if not set.
 */
const char *libnvme_ctrl_get_tls_key_identity(const struct libnvme_ctrl *p);

/**
 * libnvme_ctrl_set_tls_key() - Set tls_key.
 * @p: The &struct libnvme_ctrl instance to update.
 * @tls_key: New string; a copy is stored. Pass NULL to clear.
 */
void libnvme_ctrl_set_tls_key(struct libnvme_ctrl *p, const char *tls_key);

/**
 * libnvme_ctrl_get_tls_key() - Get tls_key.
 * @p: The &struct libnvme_ctrl instance to query.
 *
 * Return: The value of the tls_key field, or NULL if not set.
 */
const char *libnvme_ctrl_get_tls_key(const struct libnvme_ctrl *p);

/**
 * libnvme_ctrl_get_cntrltype() - Get cntrltype.
 * @p: The &struct libnvme_ctrl instance to query.
 *
 * Return: The value of the cntrltype field, or NULL if not set.
 */
const char *libnvme_ctrl_get_cntrltype(const struct libnvme_ctrl *p);

/**
 * libnvme_ctrl_get_cntlid() - Get cntlid.
 * @p: The &struct libnvme_ctrl instance to query.
 *
 * Return: The value of the cntlid field, or NULL if not set.
 */
const char *libnvme_ctrl_get_cntlid(const struct libnvme_ctrl *p);

/**
 * libnvme_ctrl_get_dctype() - Get dctype.
 * @p: The &struct libnvme_ctrl instance to query.
 *
 * Return: The value of the dctype field, or NULL if not set.
 */
const char *libnvme_ctrl_get_dctype(const struct libnvme_ctrl *p);

/**
 * libnvme_ctrl_get_phy_slot() - Get phy_slot.
 * @p: The &struct libnvme_ctrl instance to query.
 *
 * Return: The value of the phy_slot field, or NULL if not set.
 */
const char *libnvme_ctrl_get_phy_slot(const struct libnvme_ctrl *p);

/**
 * libnvme_ctrl_get_host_traddr() - Get host_traddr.
 * @p: The &struct libnvme_ctrl instance to query.
 *
 * Return: The value of the host_traddr field, or NULL if not set.
 */
const char *libnvme_ctrl_get_host_traddr(const struct libnvme_ctrl *p);

/**
 * libnvme_ctrl_get_host_iface() - Get host_iface.
 * @p: The &struct libnvme_ctrl instance to query.
 *
 * Return: The value of the host_iface field, or NULL if not set.
 */
const char *libnvme_ctrl_get_host_iface(const struct libnvme_ctrl *p);

/**
 * libnvme_ctrl_set_discovery_ctrl() - Set discovery_ctrl.
 * @p: The &struct libnvme_ctrl instance to update.
 * @discovery_ctrl: Value to assign to the discovery_ctrl field.
 */
void libnvme_ctrl_set_discovery_ctrl(
		struct libnvme_ctrl *p,
		bool discovery_ctrl);

/**
 * libnvme_ctrl_get_discovery_ctrl() - Get discovery_ctrl.
 * @p: The &struct libnvme_ctrl instance to query.
 *
 * Return: The value of the discovery_ctrl field.
 */
bool libnvme_ctrl_get_discovery_ctrl(const struct libnvme_ctrl *p);

/**
 * libnvme_ctrl_set_unique_discovery_ctrl() - Set unique_discovery_ctrl.
 * @p: The &struct libnvme_ctrl instance to update.
 * @unique_discovery_ctrl: Value to assign to the unique_discovery_ctrl field.
 */
void libnvme_ctrl_set_unique_discovery_ctrl(
		struct libnvme_ctrl *p,
		bool unique_discovery_ctrl);

/**
 * libnvme_ctrl_get_unique_discovery_ctrl() - Get unique_discovery_ctrl.
 * @p: The &struct libnvme_ctrl instance to query.
 *
 * Return: The value of the unique_discovery_ctrl field.
 */
bool libnvme_ctrl_get_unique_discovery_ctrl(const struct libnvme_ctrl *p);

/**
 * libnvme_ctrl_set_discovered() - Set discovered.
 * @p: The &struct libnvme_ctrl instance to update.
 * @discovered: Value to assign to the discovered field.
 */
void libnvme_ctrl_set_discovered(struct libnvme_ctrl *p, bool discovered);

/**
 * libnvme_ctrl_get_discovered() - Get discovered.
 * @p: The &struct libnvme_ctrl instance to query.
 *
 * Return: The value of the discovered field.
 */
bool libnvme_ctrl_get_discovered(const struct libnvme_ctrl *p);

/**
 * libnvme_ctrl_set_persistent() - Set persistent.
 * @p: The &struct libnvme_ctrl instance to update.
 * @persistent: Value to assign to the persistent field.
 */
void libnvme_ctrl_set_persistent(struct libnvme_ctrl *p, bool persistent);

/**
 * libnvme_ctrl_get_persistent() - Get persistent.
 * @p: The &struct libnvme_ctrl instance to query.
 *
 * Return: The value of the persistent field.
 */
bool libnvme_ctrl_get_persistent(const struct libnvme_ctrl *p);

/****************************************************************************
 * Accessors for: struct libnvme_subsystem
 ****************************************************************************/

/**
 * libnvme_subsystem_get_name() - Get name.
 * @p: The &struct libnvme_subsystem instance to query.
 *
 * Return: The value of the name field, or NULL if not set.
 */
const char *libnvme_subsystem_get_name(const struct libnvme_subsystem *p);

/**
 * libnvme_subsystem_get_sysfs_dir() - Get sysfs_dir.
 * @p: The &struct libnvme_subsystem instance to query.
 *
 * Return: The value of the sysfs_dir field, or NULL if not set.
 */
const char *libnvme_subsystem_get_sysfs_dir(const struct libnvme_subsystem *p);

/**
 * libnvme_subsystem_get_subsysnqn() - Get subsysnqn.
 * @p: The &struct libnvme_subsystem instance to query.
 *
 * Return: The value of the subsysnqn field, or NULL if not set.
 */
const char *libnvme_subsystem_get_subsysnqn(const struct libnvme_subsystem *p);

/**
 * libnvme_subsystem_get_model() - Get model.
 * @p: The &struct libnvme_subsystem instance to query.
 *
 * Return: The value of the model field, or NULL if not set.
 */
const char *libnvme_subsystem_get_model(const struct libnvme_subsystem *p);

/**
 * libnvme_subsystem_get_serial() - Get serial.
 * @p: The &struct libnvme_subsystem instance to query.
 *
 * Return: The value of the serial field, or NULL if not set.
 */
const char *libnvme_subsystem_get_serial(const struct libnvme_subsystem *p);

/**
 * libnvme_subsystem_get_firmware() - Get firmware.
 * @p: The &struct libnvme_subsystem instance to query.
 *
 * Return: The value of the firmware field, or NULL if not set.
 */
const char *libnvme_subsystem_get_firmware(const struct libnvme_subsystem *p);

/**
 * libnvme_subsystem_get_subsystype() - Get subsystype.
 * @p: The &struct libnvme_subsystem instance to query.
 *
 * Return: The value of the subsystype field, or NULL if not set.
 */
const char *libnvme_subsystem_get_subsystype(const struct libnvme_subsystem *p);

/**
 * libnvme_subsystem_set_application() - Set application.
 * @p: The &struct libnvme_subsystem instance to update.
 * @application: New string; a copy is stored. Pass NULL to clear.
 */
void libnvme_subsystem_set_application(
		struct libnvme_subsystem *p,
		const char *application);

/**
 * libnvme_subsystem_get_application() - Get application.
 * @p: The &struct libnvme_subsystem instance to query.
 *
 * Return: The value of the application field, or NULL if not set.
 */
const char *libnvme_subsystem_get_application(
		const struct libnvme_subsystem *p);

/****************************************************************************
 * Accessors for: struct libnvme_host
 ****************************************************************************/

/**
 * libnvme_host_get_hostnqn() - Get hostnqn.
 * @p: The &struct libnvme_host instance to query.
 *
 * Return: The value of the hostnqn field, or NULL if not set.
 */
const char *libnvme_host_get_hostnqn(const struct libnvme_host *p);

/**
 * libnvme_host_get_hostid() - Get hostid.
 * @p: The &struct libnvme_host instance to query.
 *
 * Return: The value of the hostid field, or NULL if not set.
 */
const char *libnvme_host_get_hostid(const struct libnvme_host *p);

/**
 * libnvme_host_set_dhchap_host_key() - Set dhchap_host_key.
 * @p: The &struct libnvme_host instance to update.
 * @dhchap_host_key: New string; a copy is stored. Pass NULL to clear.
 */
void libnvme_host_set_dhchap_host_key(
		struct libnvme_host *p,
		const char *dhchap_host_key);

/**
 * libnvme_host_get_dhchap_host_key() - Get dhchap_host_key.
 * @p: The &struct libnvme_host instance to query.
 *
 * Return: The value of the dhchap_host_key field, or NULL if not set.
 */
const char *libnvme_host_get_dhchap_host_key(const struct libnvme_host *p);

/**
 * libnvme_host_set_hostsymname() - Set hostsymname.
 * @p: The &struct libnvme_host instance to update.
 * @hostsymname: New string; a copy is stored. Pass NULL to clear.
 */
void libnvme_host_set_hostsymname(
		struct libnvme_host *p,
		const char *hostsymname);

/**
 * libnvme_host_get_hostsymname() - Get hostsymname.
 * @p: The &struct libnvme_host instance to query.
 *
 * Return: The value of the hostsymname field, or NULL if not set.
 */
const char *libnvme_host_get_hostsymname(const struct libnvme_host *p);

/**
 * libnvme_host_set_pdc_enabled_valid() - Set pdc_enabled_valid.
 * @p: The &struct libnvme_host instance to update.
 * @pdc_enabled_valid: Value to assign to the pdc_enabled_valid field.
 */
void libnvme_host_set_pdc_enabled_valid(
		struct libnvme_host *p,
		bool pdc_enabled_valid);

/**
 * libnvme_host_get_pdc_enabled_valid() - Get pdc_enabled_valid.
 * @p: The &struct libnvme_host instance to query.
 *
 * Return: The value of the pdc_enabled_valid field.
 */
bool libnvme_host_get_pdc_enabled_valid(const struct libnvme_host *p);

/****************************************************************************
 * Accessors for: struct libnvme_fabric_options
 ****************************************************************************/

/**
 * libnvme_fabric_options_set_cntlid() - Set cntlid.
 * @p: The &struct libnvme_fabric_options instance to update.
 * @cntlid: Value to assign to the cntlid field.
 */
void libnvme_fabric_options_set_cntlid(
		struct libnvme_fabric_options *p,
		bool cntlid);

/**
 * libnvme_fabric_options_get_cntlid() - Get cntlid.
 * @p: The &struct libnvme_fabric_options instance to query.
 *
 * Return: The value of the cntlid field.
 */
bool libnvme_fabric_options_get_cntlid(const struct libnvme_fabric_options *p);

/**
 * libnvme_fabric_options_set_concat() - Set concat.
 * @p: The &struct libnvme_fabric_options instance to update.
 * @concat: Value to assign to the concat field.
 */
void libnvme_fabric_options_set_concat(
		struct libnvme_fabric_options *p,
		bool concat);

/**
 * libnvme_fabric_options_get_concat() - Get concat.
 * @p: The &struct libnvme_fabric_options instance to query.
 *
 * Return: The value of the concat field.
 */
bool libnvme_fabric_options_get_concat(const struct libnvme_fabric_options *p);

/**
 * libnvme_fabric_options_set_ctrl_loss_tmo() - Set ctrl_loss_tmo.
 * @p: The &struct libnvme_fabric_options instance to update.
 * @ctrl_loss_tmo: Value to assign to the ctrl_loss_tmo field.
 */
void libnvme_fabric_options_set_ctrl_loss_tmo(
		struct libnvme_fabric_options *p,
		bool ctrl_loss_tmo);

/**
 * libnvme_fabric_options_get_ctrl_loss_tmo() - Get ctrl_loss_tmo.
 * @p: The &struct libnvme_fabric_options instance to query.
 *
 * Return: The value of the ctrl_loss_tmo field.
 */
bool libnvme_fabric_options_get_ctrl_loss_tmo(
		const struct libnvme_fabric_options *p);

/**
 * libnvme_fabric_options_set_data_digest() - Set data_digest.
 * @p: The &struct libnvme_fabric_options instance to update.
 * @data_digest: Value to assign to the data_digest field.
 */
void libnvme_fabric_options_set_data_digest(
		struct libnvme_fabric_options *p,
		bool data_digest);

/**
 * libnvme_fabric_options_get_data_digest() - Get data_digest.
 * @p: The &struct libnvme_fabric_options instance to query.
 *
 * Return: The value of the data_digest field.
 */
bool libnvme_fabric_options_get_data_digest(
		const struct libnvme_fabric_options *p);

/**
 * libnvme_fabric_options_set_dhchap_ctrl_secret() - Set dhchap_ctrl_secret.
 * @p: The &struct libnvme_fabric_options instance to update.
 * @dhchap_ctrl_secret: Value to assign to the dhchap_ctrl_secret field.
 */
void libnvme_fabric_options_set_dhchap_ctrl_secret(
		struct libnvme_fabric_options *p,
		bool dhchap_ctrl_secret);

/**
 * libnvme_fabric_options_get_dhchap_ctrl_secret() - Get dhchap_ctrl_secret.
 * @p: The &struct libnvme_fabric_options instance to query.
 *
 * Return: The value of the dhchap_ctrl_secret field.
 */
bool libnvme_fabric_options_get_dhchap_ctrl_secret(
		const struct libnvme_fabric_options *p);

/**
 * libnvme_fabric_options_set_dhchap_secret() - Set dhchap_secret.
 * @p: The &struct libnvme_fabric_options instance to update.
 * @dhchap_secret: Value to assign to the dhchap_secret field.
 */
void libnvme_fabric_options_set_dhchap_secret(
		struct libnvme_fabric_options *p,
		bool dhchap_secret);

/**
 * libnvme_fabric_options_get_dhchap_secret() - Get dhchap_secret.
 * @p: The &struct libnvme_fabric_options instance to query.
 *
 * Return: The value of the dhchap_secret field.
 */
bool libnvme_fabric_options_get_dhchap_secret(
		const struct libnvme_fabric_options *p);

/**
 * libnvme_fabric_options_set_disable_sqflow() - Set disable_sqflow.
 * @p: The &struct libnvme_fabric_options instance to update.
 * @disable_sqflow: Value to assign to the disable_sqflow field.
 */
void libnvme_fabric_options_set_disable_sqflow(
		struct libnvme_fabric_options *p,
		bool disable_sqflow);

/**
 * libnvme_fabric_options_get_disable_sqflow() - Get disable_sqflow.
 * @p: The &struct libnvme_fabric_options instance to query.
 *
 * Return: The value of the disable_sqflow field.
 */
bool libnvme_fabric_options_get_disable_sqflow(
		const struct libnvme_fabric_options *p);

/**
 * libnvme_fabric_options_set_discovery() - Set discovery.
 * @p: The &struct libnvme_fabric_options instance to update.
 * @discovery: Value to assign to the discovery field.
 */
void libnvme_fabric_options_set_discovery(
		struct libnvme_fabric_options *p,
		bool discovery);

/**
 * libnvme_fabric_options_get_discovery() - Get discovery.
 * @p: The &struct libnvme_fabric_options instance to query.
 *
 * Return: The value of the discovery field.
 */
bool libnvme_fabric_options_get_discovery(
		const struct libnvme_fabric_options *p);

/**
 * libnvme_fabric_options_set_duplicate_connect() - Set duplicate_connect.
 * @p: The &struct libnvme_fabric_options instance to update.
 * @duplicate_connect: Value to assign to the duplicate_connect field.
 */
void libnvme_fabric_options_set_duplicate_connect(
		struct libnvme_fabric_options *p,
		bool duplicate_connect);

/**
 * libnvme_fabric_options_get_duplicate_connect() - Get duplicate_connect.
 * @p: The &struct libnvme_fabric_options instance to query.
 *
 * Return: The value of the duplicate_connect field.
 */
bool libnvme_fabric_options_get_duplicate_connect(
		const struct libnvme_fabric_options *p);

/**
 * libnvme_fabric_options_set_fast_io_fail_tmo() - Set fast_io_fail_tmo.
 * @p: The &struct libnvme_fabric_options instance to update.
 * @fast_io_fail_tmo: Value to assign to the fast_io_fail_tmo field.
 */
void libnvme_fabric_options_set_fast_io_fail_tmo(
		struct libnvme_fabric_options *p,
		bool fast_io_fail_tmo);

/**
 * libnvme_fabric_options_get_fast_io_fail_tmo() - Get fast_io_fail_tmo.
 * @p: The &struct libnvme_fabric_options instance to query.
 *
 * Return: The value of the fast_io_fail_tmo field.
 */
bool libnvme_fabric_options_get_fast_io_fail_tmo(
		const struct libnvme_fabric_options *p);

/**
 * libnvme_fabric_options_set_hdr_digest() - Set hdr_digest.
 * @p: The &struct libnvme_fabric_options instance to update.
 * @hdr_digest: Value to assign to the hdr_digest field.
 */
void libnvme_fabric_options_set_hdr_digest(
		struct libnvme_fabric_options *p,
		bool hdr_digest);

/**
 * libnvme_fabric_options_get_hdr_digest() - Get hdr_digest.
 * @p: The &struct libnvme_fabric_options instance to query.
 *
 * Return: The value of the hdr_digest field.
 */
bool libnvme_fabric_options_get_hdr_digest(
		const struct libnvme_fabric_options *p);

/**
 * libnvme_fabric_options_set_host_iface() - Set host_iface.
 * @p: The &struct libnvme_fabric_options instance to update.
 * @host_iface: Value to assign to the host_iface field.
 */
void libnvme_fabric_options_set_host_iface(
		struct libnvme_fabric_options *p,
		bool host_iface);

/**
 * libnvme_fabric_options_get_host_iface() - Get host_iface.
 * @p: The &struct libnvme_fabric_options instance to query.
 *
 * Return: The value of the host_iface field.
 */
bool libnvme_fabric_options_get_host_iface(
		const struct libnvme_fabric_options *p);

/**
 * libnvme_fabric_options_set_host_traddr() - Set host_traddr.
 * @p: The &struct libnvme_fabric_options instance to update.
 * @host_traddr: Value to assign to the host_traddr field.
 */
void libnvme_fabric_options_set_host_traddr(
		struct libnvme_fabric_options *p,
		bool host_traddr);

/**
 * libnvme_fabric_options_get_host_traddr() - Get host_traddr.
 * @p: The &struct libnvme_fabric_options instance to query.
 *
 * Return: The value of the host_traddr field.
 */
bool libnvme_fabric_options_get_host_traddr(
		const struct libnvme_fabric_options *p);

/**
 * libnvme_fabric_options_set_hostid() - Set hostid.
 * @p: The &struct libnvme_fabric_options instance to update.
 * @hostid: Value to assign to the hostid field.
 */
void libnvme_fabric_options_set_hostid(
		struct libnvme_fabric_options *p,
		bool hostid);

/**
 * libnvme_fabric_options_get_hostid() - Get hostid.
 * @p: The &struct libnvme_fabric_options instance to query.
 *
 * Return: The value of the hostid field.
 */
bool libnvme_fabric_options_get_hostid(const struct libnvme_fabric_options *p);

/**
 * libnvme_fabric_options_set_hostnqn() - Set hostnqn.
 * @p: The &struct libnvme_fabric_options instance to update.
 * @hostnqn: Value to assign to the hostnqn field.
 */
void libnvme_fabric_options_set_hostnqn(
		struct libnvme_fabric_options *p,
		bool hostnqn);

/**
 * libnvme_fabric_options_get_hostnqn() - Get hostnqn.
 * @p: The &struct libnvme_fabric_options instance to query.
 *
 * Return: The value of the hostnqn field.
 */
bool libnvme_fabric_options_get_hostnqn(const struct libnvme_fabric_options *p);

/**
 * libnvme_fabric_options_set_instance() - Set instance.
 * @p: The &struct libnvme_fabric_options instance to update.
 * @instance: Value to assign to the instance field.
 */
void libnvme_fabric_options_set_instance(
		struct libnvme_fabric_options *p,
		bool instance);

/**
 * libnvme_fabric_options_get_instance() - Get instance.
 * @p: The &struct libnvme_fabric_options instance to query.
 *
 * Return: The value of the instance field.
 */
bool libnvme_fabric_options_get_instance(
		const struct libnvme_fabric_options *p);

/**
 * libnvme_fabric_options_set_keep_alive_tmo() - Set keep_alive_tmo.
 * @p: The &struct libnvme_fabric_options instance to update.
 * @keep_alive_tmo: Value to assign to the keep_alive_tmo field.
 */
void libnvme_fabric_options_set_keep_alive_tmo(
		struct libnvme_fabric_options *p,
		bool keep_alive_tmo);

/**
 * libnvme_fabric_options_get_keep_alive_tmo() - Get keep_alive_tmo.
 * @p: The &struct libnvme_fabric_options instance to query.
 *
 * Return: The value of the keep_alive_tmo field.
 */
bool libnvme_fabric_options_get_keep_alive_tmo(
		const struct libnvme_fabric_options *p);

/**
 * libnvme_fabric_options_set_keyring() - Set keyring.
 * @p: The &struct libnvme_fabric_options instance to update.
 * @keyring: Value to assign to the keyring field.
 */
void libnvme_fabric_options_set_keyring(
		struct libnvme_fabric_options *p,
		bool keyring);

/**
 * libnvme_fabric_options_get_keyring() - Get keyring.
 * @p: The &struct libnvme_fabric_options instance to query.
 *
 * Return: The value of the keyring field.
 */
bool libnvme_fabric_options_get_keyring(const struct libnvme_fabric_options *p);

/**
 * libnvme_fabric_options_set_nqn() - Set nqn.
 * @p: The &struct libnvme_fabric_options instance to update.
 * @nqn: Value to assign to the nqn field.
 */
void libnvme_fabric_options_set_nqn(struct libnvme_fabric_options *p, bool nqn);

/**
 * libnvme_fabric_options_get_nqn() - Get nqn.
 * @p: The &struct libnvme_fabric_options instance to query.
 *
 * Return: The value of the nqn field.
 */
bool libnvme_fabric_options_get_nqn(const struct libnvme_fabric_options *p);

/**
 * libnvme_fabric_options_set_nr_io_queues() - Set nr_io_queues.
 * @p: The &struct libnvme_fabric_options instance to update.
 * @nr_io_queues: Value to assign to the nr_io_queues field.
 */
void libnvme_fabric_options_set_nr_io_queues(
		struct libnvme_fabric_options *p,
		bool nr_io_queues);

/**
 * libnvme_fabric_options_get_nr_io_queues() - Get nr_io_queues.
 * @p: The &struct libnvme_fabric_options instance to query.
 *
 * Return: The value of the nr_io_queues field.
 */
bool libnvme_fabric_options_get_nr_io_queues(
		const struct libnvme_fabric_options *p);

/**
 * libnvme_fabric_options_set_nr_poll_queues() - Set nr_poll_queues.
 * @p: The &struct libnvme_fabric_options instance to update.
 * @nr_poll_queues: Value to assign to the nr_poll_queues field.
 */
void libnvme_fabric_options_set_nr_poll_queues(
		struct libnvme_fabric_options *p,
		bool nr_poll_queues);

/**
 * libnvme_fabric_options_get_nr_poll_queues() - Get nr_poll_queues.
 * @p: The &struct libnvme_fabric_options instance to query.
 *
 * Return: The value of the nr_poll_queues field.
 */
bool libnvme_fabric_options_get_nr_poll_queues(
		const struct libnvme_fabric_options *p);

/**
 * libnvme_fabric_options_set_nr_write_queues() - Set nr_write_queues.
 * @p: The &struct libnvme_fabric_options instance to update.
 * @nr_write_queues: Value to assign to the nr_write_queues field.
 */
void libnvme_fabric_options_set_nr_write_queues(
		struct libnvme_fabric_options *p,
		bool nr_write_queues);

/**
 * libnvme_fabric_options_get_nr_write_queues() - Get nr_write_queues.
 * @p: The &struct libnvme_fabric_options instance to query.
 *
 * Return: The value of the nr_write_queues field.
 */
bool libnvme_fabric_options_get_nr_write_queues(
		const struct libnvme_fabric_options *p);

/**
 * libnvme_fabric_options_set_queue_size() - Set queue_size.
 * @p: The &struct libnvme_fabric_options instance to update.
 * @queue_size: Value to assign to the queue_size field.
 */
void libnvme_fabric_options_set_queue_size(
		struct libnvme_fabric_options *p,
		bool queue_size);

/**
 * libnvme_fabric_options_get_queue_size() - Get queue_size.
 * @p: The &struct libnvme_fabric_options instance to query.
 *
 * Return: The value of the queue_size field.
 */
bool libnvme_fabric_options_get_queue_size(
		const struct libnvme_fabric_options *p);

/**
 * libnvme_fabric_options_set_reconnect_delay() - Set reconnect_delay.
 * @p: The &struct libnvme_fabric_options instance to update.
 * @reconnect_delay: Value to assign to the reconnect_delay field.
 */
void libnvme_fabric_options_set_reconnect_delay(
		struct libnvme_fabric_options *p,
		bool reconnect_delay);

/**
 * libnvme_fabric_options_get_reconnect_delay() - Get reconnect_delay.
 * @p: The &struct libnvme_fabric_options instance to query.
 *
 * Return: The value of the reconnect_delay field.
 */
bool libnvme_fabric_options_get_reconnect_delay(
		const struct libnvme_fabric_options *p);

/**
 * libnvme_fabric_options_set_tls() - Set tls.
 * @p: The &struct libnvme_fabric_options instance to update.
 * @tls: Value to assign to the tls field.
 */
void libnvme_fabric_options_set_tls(struct libnvme_fabric_options *p, bool tls);

/**
 * libnvme_fabric_options_get_tls() - Get tls.
 * @p: The &struct libnvme_fabric_options instance to query.
 *
 * Return: The value of the tls field.
 */
bool libnvme_fabric_options_get_tls(const struct libnvme_fabric_options *p);

/**
 * libnvme_fabric_options_set_tls_key() - Set tls_key.
 * @p: The &struct libnvme_fabric_options instance to update.
 * @tls_key: Value to assign to the tls_key field.
 */
void libnvme_fabric_options_set_tls_key(
		struct libnvme_fabric_options *p,
		bool tls_key);

/**
 * libnvme_fabric_options_get_tls_key() - Get tls_key.
 * @p: The &struct libnvme_fabric_options instance to query.
 *
 * Return: The value of the tls_key field.
 */
bool libnvme_fabric_options_get_tls_key(const struct libnvme_fabric_options *p);

/**
 * libnvme_fabric_options_set_tos() - Set tos.
 * @p: The &struct libnvme_fabric_options instance to update.
 * @tos: Value to assign to the tos field.
 */
void libnvme_fabric_options_set_tos(struct libnvme_fabric_options *p, bool tos);

/**
 * libnvme_fabric_options_get_tos() - Get tos.
 * @p: The &struct libnvme_fabric_options instance to query.
 *
 * Return: The value of the tos field.
 */
bool libnvme_fabric_options_get_tos(const struct libnvme_fabric_options *p);

/**
 * libnvme_fabric_options_set_traddr() - Set traddr.
 * @p: The &struct libnvme_fabric_options instance to update.
 * @traddr: Value to assign to the traddr field.
 */
void libnvme_fabric_options_set_traddr(
		struct libnvme_fabric_options *p,
		bool traddr);

/**
 * libnvme_fabric_options_get_traddr() - Get traddr.
 * @p: The &struct libnvme_fabric_options instance to query.
 *
 * Return: The value of the traddr field.
 */
bool libnvme_fabric_options_get_traddr(const struct libnvme_fabric_options *p);

/**
 * libnvme_fabric_options_set_transport() - Set transport.
 * @p: The &struct libnvme_fabric_options instance to update.
 * @transport: Value to assign to the transport field.
 */
void libnvme_fabric_options_set_transport(
		struct libnvme_fabric_options *p,
		bool transport);

/**
 * libnvme_fabric_options_get_transport() - Get transport.
 * @p: The &struct libnvme_fabric_options instance to query.
 *
 * Return: The value of the transport field.
 */
bool libnvme_fabric_options_get_transport(
		const struct libnvme_fabric_options *p);

/**
 * libnvme_fabric_options_set_trsvcid() - Set trsvcid.
 * @p: The &struct libnvme_fabric_options instance to update.
 * @trsvcid: Value to assign to the trsvcid field.
 */
void libnvme_fabric_options_set_trsvcid(
		struct libnvme_fabric_options *p,
		bool trsvcid);

/**
 * libnvme_fabric_options_get_trsvcid() - Get trsvcid.
 * @p: The &struct libnvme_fabric_options instance to query.
 *
 * Return: The value of the trsvcid field.
 */
bool libnvme_fabric_options_get_trsvcid(const struct libnvme_fabric_options *p);

#endif /* _ACCESSORS_H_ */
