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

#pragma once

/* Opaque: defined only in the generated ns-sysfs.c. No
 * other file may see its layout -- every field is reachable
 * only through the accessors below.
 */
struct libnvme_ns_sysfs;

/* Internal: allocate/reset/free the opaque struct. Not part
 * of the public API, not listed in any .ld.
 */
struct libnvme_ns_sysfs *libnvme_ns_sysfs_alloc(void);
void libnvme_ns_sysfs_reset(
		struct libnvme_ns_sysfs *sysfs);
void libnvme_ns_sysfs_free(
		struct libnvme_ns_sysfs *sysfs);

/**
 * libnvme_ns_get_lba_size() - Get lba_size.
 * @p: The &struct libnvme_ns instance to query.
 * @lba_size: Where to store the value on success.
 * @dflt: Value to store in @lba_size on failure.
 *
 * Return: 0 on success, -ENOENT if the attribute does not
 *	   exist, or a negative errno on failure.
 */
int libnvme_ns_get_lba_size(
		const struct libnvme_ns *p,
		int *lba_size,
		int dflt);

/**
 * libnvme_ns_get_lba_shift() - Get lba_shift.
 * @p: The &struct libnvme_ns instance to query.
 * @lba_shift: Where to store the value on success.
 * @dflt: Value to store in @lba_shift on failure.
 *
 * Return: 0 on success, -ENOENT if the attribute does not
 *	   exist, or a negative errno on failure.
 */
int libnvme_ns_get_lba_shift(
		const struct libnvme_ns *p,
		int *lba_shift,
		int dflt);

/**
 * libnvme_ns_get_lba_count() - Get lba_count.
 * @p: The &struct libnvme_ns instance to query.
 * @lba_count: Where to store the value on success.
 * @dflt: Value to store in @lba_count on failure.
 *
 * Return: 0 on success, -ENOENT if the attribute does not
 *	   exist, or a negative errno on failure.
 */
int libnvme_ns_get_lba_count(
		const struct libnvme_ns *p,
		uint64_t *lba_count,
		uint64_t dflt);

/**
 * libnvme_ns_get_lba_util() - Get lba_util.
 * @p: The &struct libnvme_ns instance to query.
 * @lba_util: Where to store the value on success.
 * @dflt: Value to store in @lba_util on failure.
 *
 * Return: 0 on success, -ENOENT if the attribute does not
 *	   exist, or a negative errno on failure.
 */
int libnvme_ns_get_lba_util(
		const struct libnvme_ns *p,
		uint64_t *lba_util,
		uint64_t dflt);

/**
 * libnvme_ns_get_meta_size() - Get meta_size.
 * @p: The &struct libnvme_ns instance to query.
 * @meta_size: Where to store the value on success.
 * @dflt: Value to store in @meta_size on failure.
 *
 * Return: 0 on success, -ENOENT if the attribute does not
 *	   exist, or a negative errno on failure.
 */
int libnvme_ns_get_meta_size(
		const struct libnvme_ns *p,
		int *meta_size,
		int dflt);

/**
 * libnvme_ns_get_csi() - Get csi.
 * @p: The &struct libnvme_ns instance to query.
 * @csi: Where to store the value on success.
 * @dflt: Value to store in @csi on failure.
 *
 * Return: 0 on success, -ENOENT if the attribute does not
 *	   exist, or a negative errno on failure.
 */
int libnvme_ns_get_csi(
		const struct libnvme_ns *p,
		enum nvme_csi *csi,
		enum nvme_csi dflt);

/**
 * libnvme_ns_get_command_retry_count() - Get command_retry_count.
 * @p: The &struct libnvme_ns instance to query.
 * @command_retry_count: Where to store the value on success.
 * @dflt: Value to store in @command_retry_count on failure.
 *
 * Return: 0 on success, -ENOENT if the attribute does not
 *	   exist, or a negative errno on failure.
 */
int libnvme_ns_get_command_retry_count(
		const struct libnvme_ns *p,
		long *command_retry_count,
		long dflt);

/**
 * libnvme_ns_get_command_error_count() - Get command_error_count.
 * @p: The &struct libnvme_ns instance to query.
 * @command_error_count: Where to store the value on success.
 * @dflt: Value to store in @command_error_count on failure.
 *
 * Return: 0 on success, -ENOENT if the attribute does not
 *	   exist, or a negative errno on failure.
 */
int libnvme_ns_get_command_error_count(
		const struct libnvme_ns *p,
		long *command_error_count,
		long dflt);

/**
 * libnvme_ns_get_io_requeue_no_usable_path_count() - Getter.
 * @p: The &struct libnvme_ns instance to query.
 * @io_requeue_no_usable_path_count: Where to store the value on success.
 * @dflt: Value to store in @io_requeue_no_usable_path_count on failure.
 *
 * Return: 0 on success, -ENOENT if the attribute does not
 *	   exist, or a negative errno on failure.
 */
int libnvme_ns_get_io_requeue_no_usable_path_count(
		const struct libnvme_ns *p,
		long *io_requeue_no_usable_path_count,
		long dflt);

/**
 * libnvme_ns_get_io_fail_no_available_path_count() - Getter.
 * @p: The &struct libnvme_ns instance to query.
 * @io_fail_no_available_path_count: Where to store the value on success.
 * @dflt: Value to store in @io_fail_no_available_path_count on failure.
 *
 * Return: 0 on success, -ENOENT if the attribute does not
 *	   exist, or a negative errno on failure.
 */
int libnvme_ns_get_io_fail_no_available_path_count(
		const struct libnvme_ns *p,
		long *io_fail_no_available_path_count,
		long dflt);

