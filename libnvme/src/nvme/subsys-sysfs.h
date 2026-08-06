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

/* Opaque: defined only in the generated subsys-sysfs.c. No
 * other file may see its layout -- every field is reachable
 * only through the accessors below.
 */
struct libnvme_subsystem_sysfs;

/* Internal: allocate/reset/free the opaque struct. Not part
 * of the public API, not listed in any .ld.
 */
struct libnvme_subsystem_sysfs *libnvme_subsystem_sysfs_alloc(void);
void libnvme_subsystem_sysfs_reset(
		struct libnvme_subsystem_sysfs *sysfs);
void libnvme_subsystem_sysfs_free(
		struct libnvme_subsystem_sysfs *sysfs);

/**
 * libnvme_subsystem_set_model() - Set model.
 * @p: The &struct libnvme_subsystem instance to update.
 * @model: New string; a copy is stored. Pass NULL to clear.
 */
void libnvme_subsystem_set_model(
		struct libnvme_subsystem *p,
		const char *model);

/**
 * libnvme_subsystem_get_model() - Get model.
 * @p: The &struct libnvme_subsystem instance to query.
 * @model: Where to store the value on success.
 * @dflt: Value to store in @model on failure.
 *
 * Return: 0 on success, -ENOENT if the attribute does not
 *	   exist, or a negative errno on failure.
 */
int libnvme_subsystem_get_model(
		const struct libnvme_subsystem *p,
		const char **model,
		const char *dflt);

/**
 * libnvme_subsystem_set_serial() - Set serial.
 * @p: The &struct libnvme_subsystem instance to update.
 * @serial: New string; a copy is stored. Pass NULL to clear.
 */
void libnvme_subsystem_set_serial(
		struct libnvme_subsystem *p,
		const char *serial);

/**
 * libnvme_subsystem_get_serial() - Get serial.
 * @p: The &struct libnvme_subsystem instance to query.
 * @serial: Where to store the value on success.
 * @dflt: Value to store in @serial on failure.
 *
 * Return: 0 on success, -ENOENT if the attribute does not
 *	   exist, or a negative errno on failure.
 */
int libnvme_subsystem_get_serial(
		const struct libnvme_subsystem *p,
		const char **serial,
		const char *dflt);

/**
 * libnvme_subsystem_set_firmware() - Set firmware.
 * @p: The &struct libnvme_subsystem instance to update.
 * @firmware: New string; a copy is stored. Pass NULL to clear.
 */
void libnvme_subsystem_set_firmware(
		struct libnvme_subsystem *p,
		const char *firmware);

/**
 * libnvme_subsystem_get_firmware() - Get firmware.
 * @p: The &struct libnvme_subsystem instance to query.
 * @firmware: Where to store the value on success.
 * @dflt: Value to store in @firmware on failure.
 *
 * Return: 0 on success, -ENOENT if the attribute does not
 *	   exist, or a negative errno on failure.
 */
int libnvme_subsystem_get_firmware(
		const struct libnvme_subsystem *p,
		const char **firmware,
		const char *dflt);

/**
 * libnvme_subsystem_get_iopolicy() - Get iopolicy.
 * @p: The &struct libnvme_subsystem instance to query.
 * @iopolicy: Where to store the value on success.
 * @dflt: Value to store in @iopolicy on failure.
 *
 * Return: 0 on success, -ENOENT if the attribute does not
 *	   exist, or a negative errno on failure.
 */
int libnvme_subsystem_get_iopolicy(
		const struct libnvme_subsystem *p,
		const char **iopolicy,
		const char *dflt);

