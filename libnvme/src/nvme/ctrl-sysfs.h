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

/* Opaque: defined only in the generated ctrl-sysfs.c. No
 * other file may see its layout -- every field is reachable
 * only through the accessors below.
 */
struct libnvme_ctrl_sysfs;

/* Internal: allocate/reset/free the opaque struct. Not part
 * of the public API, not listed in any .ld.
 */
struct libnvme_ctrl_sysfs *libnvme_ctrl_sysfs_alloc(void);
void libnvme_ctrl_sysfs_reset(
		struct libnvme_ctrl_sysfs *sysfs);
void libnvme_ctrl_sysfs_free(
		struct libnvme_ctrl_sysfs *sysfs);

/* Internal: loader callbacks, one per group above. Each
 * fills every member of its group in a single call, returning
 * 0 on success or a negative errno. Defined in whichever
 * hand-written ctrl-sysfs-custom-*.c matches the build (see
 * that file's own #ifdef/#include selection).
 */
int libnvme_ctrl_load_identity(struct libnvme_ctrl *c);
int libnvme_ctrl_load_phy_slot(struct libnvme_ctrl *c);
int libnvmf_ctrl_load_fabrics_attrs(struct libnvme_ctrl *c);

/**
 * libnvme_ctrl_get_numa_node() - Get numa_node.
 * @p: The &struct libnvme_ctrl instance to query.
 * @numa_node: Where to store the value on success.
 * @dflt: Value to store in @numa_node on failure.
 *
 * Return: 0 on success, -ENOENT if the attribute does not
 *	   exist, or a negative errno on failure.
 */
int libnvme_ctrl_get_numa_node(
		const struct libnvme_ctrl *p,
		const char **numa_node,
		const char *dflt);

/**
 * libnvme_ctrl_get_queue_count() - Get queue_count.
 * @p: The &struct libnvme_ctrl instance to query.
 * @queue_count: Where to store the value on success.
 * @dflt: Value to store in @queue_count on failure.
 *
 * Return: 0 on success, -ENOENT if the attribute does not
 *	   exist, or a negative errno on failure.
 */
int libnvme_ctrl_get_queue_count(
		const struct libnvme_ctrl *p,
		const char **queue_count,
		const char *dflt);

/**
 * libnvme_ctrl_get_sqsize() - Get sqsize.
 * @p: The &struct libnvme_ctrl instance to query.
 * @sqsize: Where to store the value on success.
 * @dflt: Value to store in @sqsize on failure.
 *
 * Return: 0 on success, -ENOENT if the attribute does not
 *	   exist, or a negative errno on failure.
 */
int libnvme_ctrl_get_sqsize(
		const struct libnvme_ctrl *p,
		const char **sqsize,
		const char *dflt);

/**
 * libnvme_ctrl_get_command_error_count() - Get command_error_count.
 * @p: The &struct libnvme_ctrl instance to query.
 * @command_error_count: Where to store the value on success.
 * @dflt: Value to store in @command_error_count on failure.
 *
 * Return: 0 on success, -ENOENT if the attribute does not
 *	   exist, or a negative errno on failure.
 */
int libnvme_ctrl_get_command_error_count(
		const struct libnvme_ctrl *p,
		long *command_error_count,
		long dflt);

/**
 * libnvme_ctrl_get_reset_count() - Get reset_count.
 * @p: The &struct libnvme_ctrl instance to query.
 * @reset_count: Where to store the value on success.
 * @dflt: Value to store in @reset_count on failure.
 *
 * Return: 0 on success, -ENOENT if the attribute does not
 *	   exist, or a negative errno on failure.
 */
int libnvme_ctrl_get_reset_count(
		const struct libnvme_ctrl *p,
		long *reset_count,
		long dflt);

/**
 * libnvme_ctrl_get_reconnect_count() - Get reconnect_count.
 * @p: The &struct libnvme_ctrl instance to query.
 * @reconnect_count: Where to store the value on success.
 * @dflt: Value to store in @reconnect_count on failure.
 *
 * Return: 0 on success, -ENOENT if the attribute does not
 *	   exist, or a negative errno on failure.
 */
int libnvme_ctrl_get_reconnect_count(
		const struct libnvme_ctrl *p,
		long *reconnect_count,
		long dflt);

/**
 * libnvme_ctrl_set_firmware() - Set firmware.
 * @p: The &struct libnvme_ctrl instance to update.
 * @firmware: New string; a copy is stored. Pass NULL to clear.
 */
void libnvme_ctrl_set_firmware(struct libnvme_ctrl *p, const char *firmware);

/**
 * libnvme_ctrl_get_firmware() - Get firmware.
 * @p: The &struct libnvme_ctrl instance to query.
 * @firmware: Where to store the value on success.
 * @dflt: Value to store in @firmware on failure.
 *
 * Return: 0 on success, -ENOENT if the attribute does not
 *	   exist, or a negative errno on failure.
 */
int libnvme_ctrl_get_firmware(
		const struct libnvme_ctrl *p,
		const char **firmware,
		const char *dflt);

/**
 * libnvme_ctrl_set_model() - Set model.
 * @p: The &struct libnvme_ctrl instance to update.
 * @model: New string; a copy is stored. Pass NULL to clear.
 */
void libnvme_ctrl_set_model(struct libnvme_ctrl *p, const char *model);

/**
 * libnvme_ctrl_get_model() - Get model.
 * @p: The &struct libnvme_ctrl instance to query.
 * @model: Where to store the value on success.
 * @dflt: Value to store in @model on failure.
 *
 * Return: 0 on success, -ENOENT if the attribute does not
 *	   exist, or a negative errno on failure.
 */
int libnvme_ctrl_get_model(
		const struct libnvme_ctrl *p,
		const char **model,
		const char *dflt);

/**
 * libnvme_ctrl_set_serial() - Set serial.
 * @p: The &struct libnvme_ctrl instance to update.
 * @serial: New string; a copy is stored. Pass NULL to clear.
 */
void libnvme_ctrl_set_serial(struct libnvme_ctrl *p, const char *serial);

/**
 * libnvme_ctrl_get_serial() - Get serial.
 * @p: The &struct libnvme_ctrl instance to query.
 * @serial: Where to store the value on success.
 * @dflt: Value to store in @serial on failure.
 *
 * Return: 0 on success, -ENOENT if the attribute does not
 *	   exist, or a negative errno on failure.
 */
int libnvme_ctrl_get_serial(
		const struct libnvme_ctrl *p,
		const char **serial,
		const char *dflt);

/**
 * libnvme_ctrl_set_cntrltype() - Set cntrltype.
 * @p: The &struct libnvme_ctrl instance to update.
 * @cntrltype: New string; a copy is stored. Pass NULL to clear.
 */
void libnvme_ctrl_set_cntrltype(struct libnvme_ctrl *p, const char *cntrltype);

/**
 * libnvme_ctrl_get_cntrltype() - Get cntrltype.
 * @p: The &struct libnvme_ctrl instance to query.
 * @cntrltype: Where to store the value on success.
 * @dflt: Value to store in @cntrltype on failure.
 *
 * Return: 0 on success, -ENOENT if the attribute does not
 *	   exist, or a negative errno on failure.
 */
int libnvme_ctrl_get_cntrltype(
		const struct libnvme_ctrl *p,
		const char **cntrltype,
		const char *dflt);

/**
 * libnvme_ctrl_set_cntlid() - Set cntlid.
 * @p: The &struct libnvme_ctrl instance to update.
 * @cntlid: New string; a copy is stored. Pass NULL to clear.
 */
void libnvme_ctrl_set_cntlid(struct libnvme_ctrl *p, const char *cntlid);

/**
 * libnvme_ctrl_get_cntlid() - Get cntlid.
 * @p: The &struct libnvme_ctrl instance to query.
 * @cntlid: Where to store the value on success.
 * @dflt: Value to store in @cntlid on failure.
 *
 * Return: 0 on success, -ENOENT if the attribute does not
 *	   exist, or a negative errno on failure.
 */
int libnvme_ctrl_get_cntlid(
		const struct libnvme_ctrl *p,
		const char **cntlid,
		const char *dflt);

/**
 * libnvme_ctrl_set_dctype() - Set dctype.
 * @p: The &struct libnvme_ctrl instance to update.
 * @dctype: New string; a copy is stored. Pass NULL to clear.
 */
void libnvme_ctrl_set_dctype(struct libnvme_ctrl *p, const char *dctype);

/**
 * libnvme_ctrl_get_dctype() - Get dctype.
 * @p: The &struct libnvme_ctrl instance to query.
 * @dctype: Where to store the value on success.
 * @dflt: Value to store in @dctype on failure.
 *
 * Return: 0 on success, -ENOENT if the attribute does not
 *	   exist, or a negative errno on failure.
 */
int libnvme_ctrl_get_dctype(
		const struct libnvme_ctrl *p,
		const char **dctype,
		const char *dflt);

/**
 * libnvme_ctrl_get_phy_slot() - Get phy_slot.
 * @p: The &struct libnvme_ctrl instance to query.
 * @phy_slot: Where to store the value on success.
 * @dflt: Value to store in @phy_slot on failure.
 *
 * Return: 0 on success, -ENOENT if the attribute does not
 *	   exist, or a negative errno on failure.
 */
int libnvme_ctrl_get_phy_slot(
		const struct libnvme_ctrl *p,
		const char **phy_slot,
		const char *dflt);

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
 * @dhchap_host_key: Where to store the value on success.
 * @dflt: Value to store in @dhchap_host_key on failure.
 *
 * Return: 0 on success, -ENOENT if the attribute does not
 *	   exist, or a negative errno on failure.
 */
int libnvme_ctrl_get_dhchap_host_key(
		const struct libnvme_ctrl *p,
		const char **dhchap_host_key,
		const char *dflt);

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
 * @dhchap_ctrl_key: Where to store the value on success.
 * @dflt: Value to store in @dhchap_ctrl_key on failure.
 *
 * Return: 0 on success, -ENOENT if the attribute does not
 *	   exist, or a negative errno on failure.
 */
int libnvme_ctrl_get_dhchap_ctrl_key(
		const struct libnvme_ctrl *p,
		const char **dhchap_ctrl_key,
		const char *dflt);

/**
 * libnvme_ctrl_set_keyring() - Set keyring.
 * @p: The &struct libnvme_ctrl instance to update.
 * @keyring: New string; a copy is stored. Pass NULL to clear.
 */
void libnvme_ctrl_set_keyring(struct libnvme_ctrl *p, const char *keyring);

/**
 * libnvme_ctrl_get_keyring() - Get keyring.
 * @p: The &struct libnvme_ctrl instance to query.
 * @keyring: Where to store the value on success.
 * @dflt: Value to store in @keyring on failure.
 *
 * Return: 0 on success, -ENOENT if the attribute does not
 *	   exist, or a negative errno on failure.
 */
int libnvme_ctrl_get_keyring(
		const struct libnvme_ctrl *p,
		const char **keyring,
		const char *dflt);

