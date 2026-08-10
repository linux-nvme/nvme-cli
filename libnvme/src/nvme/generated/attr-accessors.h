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

/* Opaque: defined only in the generated attr-accessors.c. No
 * other file may see its layout -- every field is reachable
 * only through the accessors below.
 */
struct libnvme_ctrl_attrs;

/* Internal: allocate/reset/free the opaque struct. Not part
 * of the public API, not listed in any .ld.
 */
struct libnvme_ctrl_attrs *libnvme_ctrl_attrs_alloc(void);
void libnvme_ctrl_attrs_reset(
		struct libnvme_ctrl_attrs *attrs);
void libnvme_ctrl_attrs_free(
		struct libnvme_ctrl_attrs *attrs);

/* Internal: loader callbacks, one per group above. Each
 * fills every member of its group in a single call,
 * returning 0 on success or a negative errno. Defined in
 * whichever hand-written attr-accessors-custom-*.c matches
 * the build (see that file's own #ifdef/#include selection).
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


/* Opaque: defined only in the generated attr-accessors.c. No
 * other file may see its layout -- every field is reachable
 * only through the accessors below.
 */
struct libnvme_path_attrs;

/* Internal: allocate/reset/free the opaque struct. Not part
 * of the public API, not listed in any .ld.
 */
struct libnvme_path_attrs *libnvme_path_attrs_alloc(void);
void libnvme_path_attrs_reset(
		struct libnvme_path_attrs *attrs);
void libnvme_path_attrs_free(
		struct libnvme_path_attrs *attrs);

/**
 * libnvme_path_get_ana_state() - Get ana_state.
 * @p: The &struct libnvme_path instance to query.
 * @ana_state: Where to store the value on success.
 * @dflt: Value to store in @ana_state on failure.
 *
 * Return: 0 on success, -ENOENT if the attribute does not
 *	   exist, or a negative errno on failure.
 */
int libnvme_path_get_ana_state(
		const struct libnvme_path *p,
		const char **ana_state,
		const char *dflt);

/**
 * libnvme_path_get_numa_nodes() - Get numa_nodes.
 * @p: The &struct libnvme_path instance to query.
 * @numa_nodes: Where to store the value on success.
 * @dflt: Value to store in @numa_nodes on failure.
 *
 * Return: 0 on success, -ENOENT if the attribute does not
 *	   exist, or a negative errno on failure.
 */
int libnvme_path_get_numa_nodes(
		const struct libnvme_path *p,
		const char **numa_nodes,
		const char *dflt);

/**
 * libnvme_path_get_grpid() - Get grpid.
 * @p: The &struct libnvme_path instance to query.
 * @grpid: Where to store the value on success.
 * @dflt: Value to store in @grpid on failure.
 *
 * Return: 0 on success, -ENOENT if the attribute does not
 *	   exist, or a negative errno on failure.
 */
int libnvme_path_get_grpid(const struct libnvme_path *p, int *grpid, int dflt);

/**
 * libnvme_path_get_queue_depth() - Get queue_depth.
 * @p: The &struct libnvme_path instance to query.
 * @queue_depth: Where to store the value on success.
 * @dflt: Value to store in @queue_depth on failure.
 *
 * Return: 0 on success, -ENOENT if the attribute does not
 *	   exist, or a negative errno on failure.
 */
int libnvme_path_get_queue_depth(
		const struct libnvme_path *p,
		int *queue_depth,
		int dflt);

/**
 * libnvme_path_get_multipath_failover_count() - Get multipath_failover_count.
 * @p: The &struct libnvme_path instance to query.
 * @multipath_failover_count: Where to store the value on success.
 * @dflt: Value to store in @multipath_failover_count on failure.
 *
 * Return: 0 on success, -ENOENT if the attribute does not
 *	   exist, or a negative errno on failure.
 */
int libnvme_path_get_multipath_failover_count(
		const struct libnvme_path *p,
		long *multipath_failover_count,
		long dflt);

/**
 * libnvme_path_get_command_retry_count() - Get command_retry_count.
 * @p: The &struct libnvme_path instance to query.
 * @command_retry_count: Where to store the value on success.
 * @dflt: Value to store in @command_retry_count on failure.
 *
 * Return: 0 on success, -ENOENT if the attribute does not
 *	   exist, or a negative errno on failure.
 */
int libnvme_path_get_command_retry_count(
		const struct libnvme_path *p,
		long *command_retry_count,
		long dflt);

/**
 * libnvme_path_get_command_error_count() - Get command_error_count.
 * @p: The &struct libnvme_path instance to query.
 * @command_error_count: Where to store the value on success.
 * @dflt: Value to store in @command_error_count on failure.
 *
 * Return: 0 on success, -ENOENT if the attribute does not
 *	   exist, or a negative errno on failure.
 */
int libnvme_path_get_command_error_count(
		const struct libnvme_path *p,
		long *command_error_count,
		long dflt);


/* Opaque: defined only in the generated attr-accessors.c. No
 * other file may see its layout -- every field is reachable
 * only through the accessors below.
 */
struct libnvme_ns_attrs;

/* Internal: allocate/reset/free the opaque struct. Not part
 * of the public API, not listed in any .ld.
 */
struct libnvme_ns_attrs *libnvme_ns_attrs_alloc(void);
void libnvme_ns_attrs_reset(
		struct libnvme_ns_attrs *attrs);
void libnvme_ns_attrs_free(
		struct libnvme_ns_attrs *attrs);

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
 * libnvme_ns_get_eui64() - Get eui64.
 * @p: The &struct libnvme_ns instance to query.
 * @eui64: Where to store the value on success.
 * @dflt: Value to store in @eui64 on failure.
 *
 * Return: 0 on success, -ENOENT if the attribute does not
 *	   exist, or a negative errno on failure.
 */
int libnvme_ns_get_eui64(
		const struct libnvme_ns *p,
		const uint8_t **eui64,
		const uint8_t *dflt);

/**
 * libnvme_ns_get_nguid() - Get nguid.
 * @p: The &struct libnvme_ns instance to query.
 * @nguid: Where to store the value on success.
 * @dflt: Value to store in @nguid on failure.
 *
 * Return: 0 on success, -ENOENT if the attribute does not
 *	   exist, or a negative errno on failure.
 */
int libnvme_ns_get_nguid(
		const struct libnvme_ns *p,
		const uint8_t **nguid,
		const uint8_t *dflt);

/**
 * libnvme_ns_get_uuid() - Get uuid.
 * @p: The &struct libnvme_ns instance to query.
 * @uuid: Where to store the value on success.
 * @dflt: Value to store in @uuid on failure.
 *
 * Return: 0 on success, -ENOENT if the attribute does not
 *	   exist, or a negative errno on failure.
 */
int libnvme_ns_get_uuid(
		const struct libnvme_ns *p,
		const unsigned char **uuid,
		const unsigned char *dflt);

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


/* Opaque: defined only in the generated attr-accessors.c. No
 * other file may see its layout -- every field is reachable
 * only through the accessors below.
 */
struct libnvme_subsystem_attrs;

/* Internal: allocate/reset/free the opaque struct. Not part
 * of the public API, not listed in any .ld.
 */
struct libnvme_subsystem_attrs *libnvme_subsystem_attrs_alloc(void);
void libnvme_subsystem_attrs_reset(
		struct libnvme_subsystem_attrs *attrs);
void libnvme_subsystem_attrs_free(
		struct libnvme_subsystem_attrs *attrs);

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


