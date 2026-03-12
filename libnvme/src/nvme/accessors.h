/* SPDX-License-Identifier: LGPL-2.1-or-later */

/**
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
 */
#ifndef _ACCESSORS_H_
#define _ACCESSORS_H_

#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <linux/types.h> /* __u32, __u64, etc. */

/* Forward declarations. These are internal (opaque) structs. */
struct nvme_path;
struct nvme_ns;
struct nvme_ctrl;
struct nvme_subsystem;
struct nvme_host;
struct nvme_fabric_options;

/****************************************************************************
 * Accessors for: struct nvme_path
 ****************************************************************************/

/**
 * nvme_path_set_name() - Set name.
 * @p: The &struct nvme_path instance to update.
 * @name: New string; a copy is stored. Pass NULL to clear.
 */
void nvme_path_set_name(struct nvme_path *p, const char *name);

/**
 * nvme_path_get_name() - Get name.
 * @p: The &struct nvme_path instance to query.
 *
 * Return: The value of the name field, or NULL if not set.
 */
const char *nvme_path_get_name(const struct nvme_path *p);

/**
 * nvme_path_set_sysfs_dir() - Set sysfs_dir.
 * @p: The &struct nvme_path instance to update.
 * @sysfs_dir: New string; a copy is stored. Pass NULL to clear.
 */
void nvme_path_set_sysfs_dir(struct nvme_path *p, const char *sysfs_dir);

/**
 * nvme_path_get_sysfs_dir() - Get sysfs_dir.
 * @p: The &struct nvme_path instance to query.
 *
 * Return: The value of the sysfs_dir field, or NULL if not set.
 */
const char *nvme_path_get_sysfs_dir(const struct nvme_path *p);

/**
 * nvme_path_set_ana_state() - Set ana_state.
 * @p: The &struct nvme_path instance to update.
 * @ana_state: New string; a copy is stored. Pass NULL to clear.
 */
void nvme_path_set_ana_state(struct nvme_path *p, const char *ana_state);

/**
 * nvme_path_get_ana_state() - Get ana_state.
 * @p: The &struct nvme_path instance to query.
 *
 * Return: The value of the ana_state field, or NULL if not set.
 */
const char *nvme_path_get_ana_state(const struct nvme_path *p);

/**
 * nvme_path_set_numa_nodes() - Set numa_nodes.
 * @p: The &struct nvme_path instance to update.
 * @numa_nodes: New string; a copy is stored. Pass NULL to clear.
 */
void nvme_path_set_numa_nodes(struct nvme_path *p, const char *numa_nodes);

/**
 * nvme_path_get_numa_nodes() - Get numa_nodes.
 * @p: The &struct nvme_path instance to query.
 *
 * Return: The value of the numa_nodes field, or NULL if not set.
 */
const char *nvme_path_get_numa_nodes(const struct nvme_path *p);

/**
 * nvme_path_set_grpid() - Set grpid.
 * @p: The &struct nvme_path instance to update.
 * @grpid: Value to assign to the grpid field.
 */
void nvme_path_set_grpid(struct nvme_path *p, int grpid);

/**
 * nvme_path_get_grpid() - Get grpid.
 * @p: The &struct nvme_path instance to query.
 *
 * Return: The value of the grpid field.
 */
int nvme_path_get_grpid(const struct nvme_path *p);

/****************************************************************************
 * Accessors for: struct nvme_ns
 ****************************************************************************/

/**
 * nvme_ns_set_nsid() - Set nsid.
 * @p: The &struct nvme_ns instance to update.
 * @nsid: Value to assign to the nsid field.
 */
void nvme_ns_set_nsid(struct nvme_ns *p, __u32 nsid);

/**
 * nvme_ns_get_nsid() - Get nsid.
 * @p: The &struct nvme_ns instance to query.
 *
 * Return: The value of the nsid field.
 */
__u32 nvme_ns_get_nsid(const struct nvme_ns *p);

/**
 * nvme_ns_set_name() - Set name.
 * @p: The &struct nvme_ns instance to update.
 * @name: New string; a copy is stored. Pass NULL to clear.
 */
void nvme_ns_set_name(struct nvme_ns *p, const char *name);

/**
 * nvme_ns_get_name() - Get name.
 * @p: The &struct nvme_ns instance to query.
 *
 * Return: The value of the name field, or NULL if not set.
 */
const char *nvme_ns_get_name(const struct nvme_ns *p);

/**
 * nvme_ns_set_sysfs_dir() - Set sysfs_dir.
 * @p: The &struct nvme_ns instance to update.
 * @sysfs_dir: New string; a copy is stored. Pass NULL to clear.
 */
void nvme_ns_set_sysfs_dir(struct nvme_ns *p, const char *sysfs_dir);

/**
 * nvme_ns_get_sysfs_dir() - Get sysfs_dir.
 * @p: The &struct nvme_ns instance to query.
 *
 * Return: The value of the sysfs_dir field, or NULL if not set.
 */
const char *nvme_ns_get_sysfs_dir(const struct nvme_ns *p);

/**
 * nvme_ns_set_lba_shift() - Set lba_shift.
 * @p: The &struct nvme_ns instance to update.
 * @lba_shift: Value to assign to the lba_shift field.
 */
void nvme_ns_set_lba_shift(struct nvme_ns *p, int lba_shift);

/**
 * nvme_ns_get_lba_shift() - Get lba_shift.
 * @p: The &struct nvme_ns instance to query.
 *
 * Return: The value of the lba_shift field.
 */
int nvme_ns_get_lba_shift(const struct nvme_ns *p);

/**
 * nvme_ns_set_lba_size() - Set lba_size.
 * @p: The &struct nvme_ns instance to update.
 * @lba_size: Value to assign to the lba_size field.
 */
void nvme_ns_set_lba_size(struct nvme_ns *p, int lba_size);

/**
 * nvme_ns_get_lba_size() - Get lba_size.
 * @p: The &struct nvme_ns instance to query.
 *
 * Return: The value of the lba_size field.
 */
int nvme_ns_get_lba_size(const struct nvme_ns *p);

/**
 * nvme_ns_set_meta_size() - Set meta_size.
 * @p: The &struct nvme_ns instance to update.
 * @meta_size: Value to assign to the meta_size field.
 */
void nvme_ns_set_meta_size(struct nvme_ns *p, int meta_size);

/**
 * nvme_ns_get_meta_size() - Get meta_size.
 * @p: The &struct nvme_ns instance to query.
 *
 * Return: The value of the meta_size field.
 */
int nvme_ns_get_meta_size(const struct nvme_ns *p);

/**
 * nvme_ns_set_lba_count() - Set lba_count.
 * @p: The &struct nvme_ns instance to update.
 * @lba_count: Value to assign to the lba_count field.
 */
void nvme_ns_set_lba_count(struct nvme_ns *p, uint64_t lba_count);

/**
 * nvme_ns_get_lba_count() - Get lba_count.
 * @p: The &struct nvme_ns instance to query.
 *
 * Return: The value of the lba_count field.
 */
uint64_t nvme_ns_get_lba_count(const struct nvme_ns *p);

/**
 * nvme_ns_set_lba_util() - Set lba_util.
 * @p: The &struct nvme_ns instance to update.
 * @lba_util: Value to assign to the lba_util field.
 */
void nvme_ns_set_lba_util(struct nvme_ns *p, uint64_t lba_util);

/**
 * nvme_ns_get_lba_util() - Get lba_util.
 * @p: The &struct nvme_ns instance to query.
 *
 * Return: The value of the lba_util field.
 */
uint64_t nvme_ns_get_lba_util(const struct nvme_ns *p);

/****************************************************************************
 * Accessors for: struct nvme_ctrl
 ****************************************************************************/

/**
 * nvme_ctrl_set_name() - Set name.
 * @p: The &struct nvme_ctrl instance to update.
 * @name: New string; a copy is stored. Pass NULL to clear.
 */
void nvme_ctrl_set_name(struct nvme_ctrl *p, const char *name);

/**
 * nvme_ctrl_get_name() - Get name.
 * @p: The &struct nvme_ctrl instance to query.
 *
 * Return: The value of the name field, or NULL if not set.
 */
const char *nvme_ctrl_get_name(const struct nvme_ctrl *p);

/**
 * nvme_ctrl_set_sysfs_dir() - Set sysfs_dir.
 * @p: The &struct nvme_ctrl instance to update.
 * @sysfs_dir: New string; a copy is stored. Pass NULL to clear.
 */
void nvme_ctrl_set_sysfs_dir(struct nvme_ctrl *p, const char *sysfs_dir);

/**
 * nvme_ctrl_get_sysfs_dir() - Get sysfs_dir.
 * @p: The &struct nvme_ctrl instance to query.
 *
 * Return: The value of the sysfs_dir field, or NULL if not set.
 */
const char *nvme_ctrl_get_sysfs_dir(const struct nvme_ctrl *p);

/**
 * nvme_ctrl_set_firmware() - Set firmware.
 * @p: The &struct nvme_ctrl instance to update.
 * @firmware: New string; a copy is stored. Pass NULL to clear.
 */
void nvme_ctrl_set_firmware(struct nvme_ctrl *p, const char *firmware);

/**
 * nvme_ctrl_get_firmware() - Get firmware.
 * @p: The &struct nvme_ctrl instance to query.
 *
 * Return: The value of the firmware field, or NULL if not set.
 */
const char *nvme_ctrl_get_firmware(const struct nvme_ctrl *p);

/**
 * nvme_ctrl_set_model() - Set model.
 * @p: The &struct nvme_ctrl instance to update.
 * @model: New string; a copy is stored. Pass NULL to clear.
 */
void nvme_ctrl_set_model(struct nvme_ctrl *p, const char *model);

/**
 * nvme_ctrl_get_model() - Get model.
 * @p: The &struct nvme_ctrl instance to query.
 *
 * Return: The value of the model field, or NULL if not set.
 */
const char *nvme_ctrl_get_model(const struct nvme_ctrl *p);

/**
 * nvme_ctrl_set_numa_node() - Set numa_node.
 * @p: The &struct nvme_ctrl instance to update.
 * @numa_node: New string; a copy is stored. Pass NULL to clear.
 */
void nvme_ctrl_set_numa_node(struct nvme_ctrl *p, const char *numa_node);

/**
 * nvme_ctrl_get_numa_node() - Get numa_node.
 * @p: The &struct nvme_ctrl instance to query.
 *
 * Return: The value of the numa_node field, or NULL if not set.
 */
const char *nvme_ctrl_get_numa_node(const struct nvme_ctrl *p);

/**
 * nvme_ctrl_set_queue_count() - Set queue_count.
 * @p: The &struct nvme_ctrl instance to update.
 * @queue_count: New string; a copy is stored. Pass NULL to clear.
 */
void nvme_ctrl_set_queue_count(struct nvme_ctrl *p, const char *queue_count);

/**
 * nvme_ctrl_get_queue_count() - Get queue_count.
 * @p: The &struct nvme_ctrl instance to query.
 *
 * Return: The value of the queue_count field, or NULL if not set.
 */
const char *nvme_ctrl_get_queue_count(const struct nvme_ctrl *p);

/**
 * nvme_ctrl_set_serial() - Set serial.
 * @p: The &struct nvme_ctrl instance to update.
 * @serial: New string; a copy is stored. Pass NULL to clear.
 */
void nvme_ctrl_set_serial(struct nvme_ctrl *p, const char *serial);

/**
 * nvme_ctrl_get_serial() - Get serial.
 * @p: The &struct nvme_ctrl instance to query.
 *
 * Return: The value of the serial field, or NULL if not set.
 */
const char *nvme_ctrl_get_serial(const struct nvme_ctrl *p);

/**
 * nvme_ctrl_set_sqsize() - Set sqsize.
 * @p: The &struct nvme_ctrl instance to update.
 * @sqsize: New string; a copy is stored. Pass NULL to clear.
 */
void nvme_ctrl_set_sqsize(struct nvme_ctrl *p, const char *sqsize);

/**
 * nvme_ctrl_get_sqsize() - Get sqsize.
 * @p: The &struct nvme_ctrl instance to query.
 *
 * Return: The value of the sqsize field, or NULL if not set.
 */
const char *nvme_ctrl_get_sqsize(const struct nvme_ctrl *p);

/**
 * nvme_ctrl_set_transport() - Set transport.
 * @p: The &struct nvme_ctrl instance to update.
 * @transport: New string; a copy is stored. Pass NULL to clear.
 */
void nvme_ctrl_set_transport(struct nvme_ctrl *p, const char *transport);

/**
 * nvme_ctrl_get_transport() - Get transport.
 * @p: The &struct nvme_ctrl instance to query.
 *
 * Return: The value of the transport field, or NULL if not set.
 */
const char *nvme_ctrl_get_transport(const struct nvme_ctrl *p);

/**
 * nvme_ctrl_set_traddr() - Set traddr.
 * @p: The &struct nvme_ctrl instance to update.
 * @traddr: New string; a copy is stored. Pass NULL to clear.
 */
void nvme_ctrl_set_traddr(struct nvme_ctrl *p, const char *traddr);

/**
 * nvme_ctrl_get_traddr() - Get traddr.
 * @p: The &struct nvme_ctrl instance to query.
 *
 * Return: The value of the traddr field, or NULL if not set.
 */
const char *nvme_ctrl_get_traddr(const struct nvme_ctrl *p);

/**
 * nvme_ctrl_set_trsvcid() - Set trsvcid.
 * @p: The &struct nvme_ctrl instance to update.
 * @trsvcid: New string; a copy is stored. Pass NULL to clear.
 */
void nvme_ctrl_set_trsvcid(struct nvme_ctrl *p, const char *trsvcid);

/**
 * nvme_ctrl_get_trsvcid() - Get trsvcid.
 * @p: The &struct nvme_ctrl instance to query.
 *
 * Return: The value of the trsvcid field, or NULL if not set.
 */
const char *nvme_ctrl_get_trsvcid(const struct nvme_ctrl *p);

/**
 * nvme_ctrl_set_dhchap_key() - Set dhchap_key.
 * @p: The &struct nvme_ctrl instance to update.
 * @dhchap_key: New string; a copy is stored. Pass NULL to clear.
 */
void nvme_ctrl_set_dhchap_key(struct nvme_ctrl *p, const char *dhchap_key);

/**
 * nvme_ctrl_get_dhchap_key() - Get dhchap_key.
 * @p: The &struct nvme_ctrl instance to query.
 *
 * Return: The value of the dhchap_key field, or NULL if not set.
 */
const char *nvme_ctrl_get_dhchap_key(const struct nvme_ctrl *p);

/**
 * nvme_ctrl_set_dhchap_ctrl_key() - Set dhchap_ctrl_key.
 * @p: The &struct nvme_ctrl instance to update.
 * @dhchap_ctrl_key: New string; a copy is stored. Pass NULL to clear.
 */
void nvme_ctrl_set_dhchap_ctrl_key(
		struct nvme_ctrl *p,
		const char *dhchap_ctrl_key);

/**
 * nvme_ctrl_get_dhchap_ctrl_key() - Get dhchap_ctrl_key.
 * @p: The &struct nvme_ctrl instance to query.
 *
 * Return: The value of the dhchap_ctrl_key field, or NULL if not set.
 */
const char *nvme_ctrl_get_dhchap_ctrl_key(const struct nvme_ctrl *p);

/**
 * nvme_ctrl_set_keyring() - Set keyring.
 * @p: The &struct nvme_ctrl instance to update.
 * @keyring: New string; a copy is stored. Pass NULL to clear.
 */
void nvme_ctrl_set_keyring(struct nvme_ctrl *p, const char *keyring);

/**
 * nvme_ctrl_get_keyring() - Get keyring.
 * @p: The &struct nvme_ctrl instance to query.
 *
 * Return: The value of the keyring field, or NULL if not set.
 */
const char *nvme_ctrl_get_keyring(const struct nvme_ctrl *p);

/**
 * nvme_ctrl_set_tls_key_identity() - Set tls_key_identity.
 * @p: The &struct nvme_ctrl instance to update.
 * @tls_key_identity: New string; a copy is stored. Pass NULL to clear.
 */
void nvme_ctrl_set_tls_key_identity(
		struct nvme_ctrl *p,
		const char *tls_key_identity);

/**
 * nvme_ctrl_get_tls_key_identity() - Get tls_key_identity.
 * @p: The &struct nvme_ctrl instance to query.
 *
 * Return: The value of the tls_key_identity field, or NULL if not set.
 */
const char *nvme_ctrl_get_tls_key_identity(const struct nvme_ctrl *p);

/**
 * nvme_ctrl_set_tls_key() - Set tls_key.
 * @p: The &struct nvme_ctrl instance to update.
 * @tls_key: New string; a copy is stored. Pass NULL to clear.
 */
void nvme_ctrl_set_tls_key(struct nvme_ctrl *p, const char *tls_key);

/**
 * nvme_ctrl_get_tls_key() - Get tls_key.
 * @p: The &struct nvme_ctrl instance to query.
 *
 * Return: The value of the tls_key field, or NULL if not set.
 */
const char *nvme_ctrl_get_tls_key(const struct nvme_ctrl *p);

/**
 * nvme_ctrl_set_cntrltype() - Set cntrltype.
 * @p: The &struct nvme_ctrl instance to update.
 * @cntrltype: New string; a copy is stored. Pass NULL to clear.
 */
void nvme_ctrl_set_cntrltype(struct nvme_ctrl *p, const char *cntrltype);

/**
 * nvme_ctrl_get_cntrltype() - Get cntrltype.
 * @p: The &struct nvme_ctrl instance to query.
 *
 * Return: The value of the cntrltype field, or NULL if not set.
 */
const char *nvme_ctrl_get_cntrltype(const struct nvme_ctrl *p);

/**
 * nvme_ctrl_set_cntlid() - Set cntlid.
 * @p: The &struct nvme_ctrl instance to update.
 * @cntlid: New string; a copy is stored. Pass NULL to clear.
 */
void nvme_ctrl_set_cntlid(struct nvme_ctrl *p, const char *cntlid);

/**
 * nvme_ctrl_get_cntlid() - Get cntlid.
 * @p: The &struct nvme_ctrl instance to query.
 *
 * Return: The value of the cntlid field, or NULL if not set.
 */
const char *nvme_ctrl_get_cntlid(const struct nvme_ctrl *p);

/**
 * nvme_ctrl_set_dctype() - Set dctype.
 * @p: The &struct nvme_ctrl instance to update.
 * @dctype: New string; a copy is stored. Pass NULL to clear.
 */
void nvme_ctrl_set_dctype(struct nvme_ctrl *p, const char *dctype);

/**
 * nvme_ctrl_get_dctype() - Get dctype.
 * @p: The &struct nvme_ctrl instance to query.
 *
 * Return: The value of the dctype field, or NULL if not set.
 */
const char *nvme_ctrl_get_dctype(const struct nvme_ctrl *p);

/**
 * nvme_ctrl_set_host_traddr() - Set host_traddr.
 * @p: The &struct nvme_ctrl instance to update.
 * @host_traddr: New string; a copy is stored. Pass NULL to clear.
 */
void nvme_ctrl_set_host_traddr(struct nvme_ctrl *p, const char *host_traddr);

/**
 * nvme_ctrl_get_host_traddr() - Get host_traddr.
 * @p: The &struct nvme_ctrl instance to query.
 *
 * Return: The value of the host_traddr field, or NULL if not set.
 */
const char *nvme_ctrl_get_host_traddr(const struct nvme_ctrl *p);

/**
 * nvme_ctrl_set_host_iface() - Set host_iface.
 * @p: The &struct nvme_ctrl instance to update.
 * @host_iface: New string; a copy is stored. Pass NULL to clear.
 */
void nvme_ctrl_set_host_iface(struct nvme_ctrl *p, const char *host_iface);

/**
 * nvme_ctrl_get_host_iface() - Get host_iface.
 * @p: The &struct nvme_ctrl instance to query.
 *
 * Return: The value of the host_iface field, or NULL if not set.
 */
const char *nvme_ctrl_get_host_iface(const struct nvme_ctrl *p);

/**
 * nvme_ctrl_set_discovery_ctrl() - Set discovery_ctrl.
 * @p: The &struct nvme_ctrl instance to update.
 * @discovery_ctrl: Value to assign to the discovery_ctrl field.
 */
void nvme_ctrl_set_discovery_ctrl(struct nvme_ctrl *p, bool discovery_ctrl);

/**
 * nvme_ctrl_get_discovery_ctrl() - Get discovery_ctrl.
 * @p: The &struct nvme_ctrl instance to query.
 *
 * Return: The value of the discovery_ctrl field.
 */
bool nvme_ctrl_get_discovery_ctrl(const struct nvme_ctrl *p);

/**
 * nvme_ctrl_set_unique_discovery_ctrl() - Set unique_discovery_ctrl.
 * @p: The &struct nvme_ctrl instance to update.
 * @unique_discovery_ctrl: Value to assign to the unique_discovery_ctrl field.
 */
void nvme_ctrl_set_unique_discovery_ctrl(
		struct nvme_ctrl *p,
		bool unique_discovery_ctrl);

/**
 * nvme_ctrl_get_unique_discovery_ctrl() - Get unique_discovery_ctrl.
 * @p: The &struct nvme_ctrl instance to query.
 *
 * Return: The value of the unique_discovery_ctrl field.
 */
bool nvme_ctrl_get_unique_discovery_ctrl(const struct nvme_ctrl *p);

/**
 * nvme_ctrl_set_discovered() - Set discovered.
 * @p: The &struct nvme_ctrl instance to update.
 * @discovered: Value to assign to the discovered field.
 */
void nvme_ctrl_set_discovered(struct nvme_ctrl *p, bool discovered);

/**
 * nvme_ctrl_get_discovered() - Get discovered.
 * @p: The &struct nvme_ctrl instance to query.
 *
 * Return: The value of the discovered field.
 */
bool nvme_ctrl_get_discovered(const struct nvme_ctrl *p);

/**
 * nvme_ctrl_set_persistent() - Set persistent.
 * @p: The &struct nvme_ctrl instance to update.
 * @persistent: Value to assign to the persistent field.
 */
void nvme_ctrl_set_persistent(struct nvme_ctrl *p, bool persistent);

/**
 * nvme_ctrl_get_persistent() - Get persistent.
 * @p: The &struct nvme_ctrl instance to query.
 *
 * Return: The value of the persistent field.
 */
bool nvme_ctrl_get_persistent(const struct nvme_ctrl *p);

/****************************************************************************
 * Accessors for: struct nvme_subsystem
 ****************************************************************************/

/**
 * nvme_subsystem_set_name() - Set name.
 * @p: The &struct nvme_subsystem instance to update.
 * @name: New string; a copy is stored. Pass NULL to clear.
 */
void nvme_subsystem_set_name(struct nvme_subsystem *p, const char *name);

/**
 * nvme_subsystem_get_name() - Get name.
 * @p: The &struct nvme_subsystem instance to query.
 *
 * Return: The value of the name field, or NULL if not set.
 */
const char *nvme_subsystem_get_name(const struct nvme_subsystem *p);

/**
 * nvme_subsystem_set_sysfs_dir() - Set sysfs_dir.
 * @p: The &struct nvme_subsystem instance to update.
 * @sysfs_dir: New string; a copy is stored. Pass NULL to clear.
 */
void nvme_subsystem_set_sysfs_dir(
		struct nvme_subsystem *p,
		const char *sysfs_dir);

/**
 * nvme_subsystem_get_sysfs_dir() - Get sysfs_dir.
 * @p: The &struct nvme_subsystem instance to query.
 *
 * Return: The value of the sysfs_dir field, or NULL if not set.
 */
const char *nvme_subsystem_get_sysfs_dir(const struct nvme_subsystem *p);

/**
 * nvme_subsystem_set_subsysnqn() - Set subsysnqn.
 * @p: The &struct nvme_subsystem instance to update.
 * @subsysnqn: New string; a copy is stored. Pass NULL to clear.
 */
void nvme_subsystem_set_subsysnqn(
		struct nvme_subsystem *p,
		const char *subsysnqn);

/**
 * nvme_subsystem_get_subsysnqn() - Get subsysnqn.
 * @p: The &struct nvme_subsystem instance to query.
 *
 * Return: The value of the subsysnqn field, or NULL if not set.
 */
const char *nvme_subsystem_get_subsysnqn(const struct nvme_subsystem *p);

/**
 * nvme_subsystem_set_model() - Set model.
 * @p: The &struct nvme_subsystem instance to update.
 * @model: New string; a copy is stored. Pass NULL to clear.
 */
void nvme_subsystem_set_model(struct nvme_subsystem *p, const char *model);

/**
 * nvme_subsystem_get_model() - Get model.
 * @p: The &struct nvme_subsystem instance to query.
 *
 * Return: The value of the model field, or NULL if not set.
 */
const char *nvme_subsystem_get_model(const struct nvme_subsystem *p);

/**
 * nvme_subsystem_set_serial() - Set serial.
 * @p: The &struct nvme_subsystem instance to update.
 * @serial: New string; a copy is stored. Pass NULL to clear.
 */
void nvme_subsystem_set_serial(struct nvme_subsystem *p, const char *serial);

/**
 * nvme_subsystem_get_serial() - Get serial.
 * @p: The &struct nvme_subsystem instance to query.
 *
 * Return: The value of the serial field, or NULL if not set.
 */
const char *nvme_subsystem_get_serial(const struct nvme_subsystem *p);

/**
 * nvme_subsystem_set_firmware() - Set firmware.
 * @p: The &struct nvme_subsystem instance to update.
 * @firmware: New string; a copy is stored. Pass NULL to clear.
 */
void nvme_subsystem_set_firmware(
		struct nvme_subsystem *p,
		const char *firmware);

/**
 * nvme_subsystem_get_firmware() - Get firmware.
 * @p: The &struct nvme_subsystem instance to query.
 *
 * Return: The value of the firmware field, or NULL if not set.
 */
const char *nvme_subsystem_get_firmware(const struct nvme_subsystem *p);

/**
 * nvme_subsystem_set_subsystype() - Set subsystype.
 * @p: The &struct nvme_subsystem instance to update.
 * @subsystype: New string; a copy is stored. Pass NULL to clear.
 */
void nvme_subsystem_set_subsystype(
		struct nvme_subsystem *p,
		const char *subsystype);

/**
 * nvme_subsystem_get_subsystype() - Get subsystype.
 * @p: The &struct nvme_subsystem instance to query.
 *
 * Return: The value of the subsystype field, or NULL if not set.
 */
const char *nvme_subsystem_get_subsystype(const struct nvme_subsystem *p);

/**
 * nvme_subsystem_set_application() - Set application.
 * @p: The &struct nvme_subsystem instance to update.
 * @application: New string; a copy is stored. Pass NULL to clear.
 */
void nvme_subsystem_set_application(
		struct nvme_subsystem *p,
		const char *application);

/**
 * nvme_subsystem_get_application() - Get application.
 * @p: The &struct nvme_subsystem instance to query.
 *
 * Return: The value of the application field, or NULL if not set.
 */
const char *nvme_subsystem_get_application(const struct nvme_subsystem *p);

/**
 * nvme_subsystem_set_iopolicy() - Set iopolicy.
 * @p: The &struct nvme_subsystem instance to update.
 * @iopolicy: New string; a copy is stored. Pass NULL to clear.
 */
void nvme_subsystem_set_iopolicy(
		struct nvme_subsystem *p,
		const char *iopolicy);

/**
 * nvme_subsystem_get_iopolicy() - Get iopolicy.
 * @p: The &struct nvme_subsystem instance to query.
 *
 * Return: The value of the iopolicy field, or NULL if not set.
 */
const char *nvme_subsystem_get_iopolicy(const struct nvme_subsystem *p);

/****************************************************************************
 * Accessors for: struct nvme_host
 ****************************************************************************/

/**
 * nvme_host_set_hostnqn() - Set hostnqn.
 * @p: The &struct nvme_host instance to update.
 * @hostnqn: New string; a copy is stored. Pass NULL to clear.
 */
void nvme_host_set_hostnqn(struct nvme_host *p, const char *hostnqn);

/**
 * nvme_host_get_hostnqn() - Get hostnqn.
 * @p: The &struct nvme_host instance to query.
 *
 * Return: The value of the hostnqn field, or NULL if not set.
 */
const char *nvme_host_get_hostnqn(const struct nvme_host *p);

/**
 * nvme_host_set_hostid() - Set hostid.
 * @p: The &struct nvme_host instance to update.
 * @hostid: New string; a copy is stored. Pass NULL to clear.
 */
void nvme_host_set_hostid(struct nvme_host *p, const char *hostid);

/**
 * nvme_host_get_hostid() - Get hostid.
 * @p: The &struct nvme_host instance to query.
 *
 * Return: The value of the hostid field, or NULL if not set.
 */
const char *nvme_host_get_hostid(const struct nvme_host *p);

/**
 * nvme_host_set_dhchap_key() - Set dhchap_key.
 * @p: The &struct nvme_host instance to update.
 * @dhchap_key: New string; a copy is stored. Pass NULL to clear.
 */
void nvme_host_set_dhchap_key(struct nvme_host *p, const char *dhchap_key);

/**
 * nvme_host_get_dhchap_key() - Get dhchap_key.
 * @p: The &struct nvme_host instance to query.
 *
 * Return: The value of the dhchap_key field, or NULL if not set.
 */
const char *nvme_host_get_dhchap_key(const struct nvme_host *p);

/**
 * nvme_host_set_hostsymname() - Set hostsymname.
 * @p: The &struct nvme_host instance to update.
 * @hostsymname: New string; a copy is stored. Pass NULL to clear.
 */
void nvme_host_set_hostsymname(struct nvme_host *p, const char *hostsymname);

/**
 * nvme_host_get_hostsymname() - Get hostsymname.
 * @p: The &struct nvme_host instance to query.
 *
 * Return: The value of the hostsymname field, or NULL if not set.
 */
const char *nvme_host_get_hostsymname(const struct nvme_host *p);

/**
 * nvme_host_set_pdc_enabled_valid() - Set pdc_enabled_valid.
 * @p: The &struct nvme_host instance to update.
 * @pdc_enabled_valid: Value to assign to the pdc_enabled_valid field.
 */
void nvme_host_set_pdc_enabled_valid(
		struct nvme_host *p,
		bool pdc_enabled_valid);

/**
 * nvme_host_get_pdc_enabled_valid() - Get pdc_enabled_valid.
 * @p: The &struct nvme_host instance to query.
 *
 * Return: The value of the pdc_enabled_valid field.
 */
bool nvme_host_get_pdc_enabled_valid(const struct nvme_host *p);

/****************************************************************************
 * Accessors for: struct nvme_fabric_options
 ****************************************************************************/

/**
 * nvme_fabric_options_set_cntlid() - Set cntlid.
 * @p: The &struct nvme_fabric_options instance to update.
 * @cntlid: Value to assign to the cntlid field.
 */
void nvme_fabric_options_set_cntlid(struct nvme_fabric_options *p, bool cntlid);

/**
 * nvme_fabric_options_get_cntlid() - Get cntlid.
 * @p: The &struct nvme_fabric_options instance to query.
 *
 * Return: The value of the cntlid field.
 */
bool nvme_fabric_options_get_cntlid(const struct nvme_fabric_options *p);

/**
 * nvme_fabric_options_set_concat() - Set concat.
 * @p: The &struct nvme_fabric_options instance to update.
 * @concat: Value to assign to the concat field.
 */
void nvme_fabric_options_set_concat(struct nvme_fabric_options *p, bool concat);

/**
 * nvme_fabric_options_get_concat() - Get concat.
 * @p: The &struct nvme_fabric_options instance to query.
 *
 * Return: The value of the concat field.
 */
bool nvme_fabric_options_get_concat(const struct nvme_fabric_options *p);

/**
 * nvme_fabric_options_set_ctrl_loss_tmo() - Set ctrl_loss_tmo.
 * @p: The &struct nvme_fabric_options instance to update.
 * @ctrl_loss_tmo: Value to assign to the ctrl_loss_tmo field.
 */
void nvme_fabric_options_set_ctrl_loss_tmo(
		struct nvme_fabric_options *p,
		bool ctrl_loss_tmo);

/**
 * nvme_fabric_options_get_ctrl_loss_tmo() - Get ctrl_loss_tmo.
 * @p: The &struct nvme_fabric_options instance to query.
 *
 * Return: The value of the ctrl_loss_tmo field.
 */
bool nvme_fabric_options_get_ctrl_loss_tmo(const struct nvme_fabric_options *p);

/**
 * nvme_fabric_options_set_data_digest() - Set data_digest.
 * @p: The &struct nvme_fabric_options instance to update.
 * @data_digest: Value to assign to the data_digest field.
 */
void nvme_fabric_options_set_data_digest(
		struct nvme_fabric_options *p,
		bool data_digest);

/**
 * nvme_fabric_options_get_data_digest() - Get data_digest.
 * @p: The &struct nvme_fabric_options instance to query.
 *
 * Return: The value of the data_digest field.
 */
bool nvme_fabric_options_get_data_digest(const struct nvme_fabric_options *p);

/**
 * nvme_fabric_options_set_dhchap_ctrl_secret() - Set dhchap_ctrl_secret.
 * @p: The &struct nvme_fabric_options instance to update.
 * @dhchap_ctrl_secret: Value to assign to the dhchap_ctrl_secret field.
 */
void nvme_fabric_options_set_dhchap_ctrl_secret(
		struct nvme_fabric_options *p,
		bool dhchap_ctrl_secret);

/**
 * nvme_fabric_options_get_dhchap_ctrl_secret() - Get dhchap_ctrl_secret.
 * @p: The &struct nvme_fabric_options instance to query.
 *
 * Return: The value of the dhchap_ctrl_secret field.
 */
bool nvme_fabric_options_get_dhchap_ctrl_secret(
		const struct nvme_fabric_options *p);

/**
 * nvme_fabric_options_set_dhchap_secret() - Set dhchap_secret.
 * @p: The &struct nvme_fabric_options instance to update.
 * @dhchap_secret: Value to assign to the dhchap_secret field.
 */
void nvme_fabric_options_set_dhchap_secret(
		struct nvme_fabric_options *p,
		bool dhchap_secret);

/**
 * nvme_fabric_options_get_dhchap_secret() - Get dhchap_secret.
 * @p: The &struct nvme_fabric_options instance to query.
 *
 * Return: The value of the dhchap_secret field.
 */
bool nvme_fabric_options_get_dhchap_secret(const struct nvme_fabric_options *p);

/**
 * nvme_fabric_options_set_disable_sqflow() - Set disable_sqflow.
 * @p: The &struct nvme_fabric_options instance to update.
 * @disable_sqflow: Value to assign to the disable_sqflow field.
 */
void nvme_fabric_options_set_disable_sqflow(
		struct nvme_fabric_options *p,
		bool disable_sqflow);

/**
 * nvme_fabric_options_get_disable_sqflow() - Get disable_sqflow.
 * @p: The &struct nvme_fabric_options instance to query.
 *
 * Return: The value of the disable_sqflow field.
 */
bool nvme_fabric_options_get_disable_sqflow(
		const struct nvme_fabric_options *p);

/**
 * nvme_fabric_options_set_discovery() - Set discovery.
 * @p: The &struct nvme_fabric_options instance to update.
 * @discovery: Value to assign to the discovery field.
 */
void nvme_fabric_options_set_discovery(
		struct nvme_fabric_options *p,
		bool discovery);

/**
 * nvme_fabric_options_get_discovery() - Get discovery.
 * @p: The &struct nvme_fabric_options instance to query.
 *
 * Return: The value of the discovery field.
 */
bool nvme_fabric_options_get_discovery(const struct nvme_fabric_options *p);

/**
 * nvme_fabric_options_set_duplicate_connect() - Set duplicate_connect.
 * @p: The &struct nvme_fabric_options instance to update.
 * @duplicate_connect: Value to assign to the duplicate_connect field.
 */
void nvme_fabric_options_set_duplicate_connect(
		struct nvme_fabric_options *p,
		bool duplicate_connect);

/**
 * nvme_fabric_options_get_duplicate_connect() - Get duplicate_connect.
 * @p: The &struct nvme_fabric_options instance to query.
 *
 * Return: The value of the duplicate_connect field.
 */
bool nvme_fabric_options_get_duplicate_connect(
		const struct nvme_fabric_options *p);

/**
 * nvme_fabric_options_set_fast_io_fail_tmo() - Set fast_io_fail_tmo.
 * @p: The &struct nvme_fabric_options instance to update.
 * @fast_io_fail_tmo: Value to assign to the fast_io_fail_tmo field.
 */
void nvme_fabric_options_set_fast_io_fail_tmo(
		struct nvme_fabric_options *p,
		bool fast_io_fail_tmo);

/**
 * nvme_fabric_options_get_fast_io_fail_tmo() - Get fast_io_fail_tmo.
 * @p: The &struct nvme_fabric_options instance to query.
 *
 * Return: The value of the fast_io_fail_tmo field.
 */
bool nvme_fabric_options_get_fast_io_fail_tmo(
		const struct nvme_fabric_options *p);

/**
 * nvme_fabric_options_set_hdr_digest() - Set hdr_digest.
 * @p: The &struct nvme_fabric_options instance to update.
 * @hdr_digest: Value to assign to the hdr_digest field.
 */
void nvme_fabric_options_set_hdr_digest(
		struct nvme_fabric_options *p,
		bool hdr_digest);

/**
 * nvme_fabric_options_get_hdr_digest() - Get hdr_digest.
 * @p: The &struct nvme_fabric_options instance to query.
 *
 * Return: The value of the hdr_digest field.
 */
bool nvme_fabric_options_get_hdr_digest(const struct nvme_fabric_options *p);

/**
 * nvme_fabric_options_set_host_iface() - Set host_iface.
 * @p: The &struct nvme_fabric_options instance to update.
 * @host_iface: Value to assign to the host_iface field.
 */
void nvme_fabric_options_set_host_iface(
		struct nvme_fabric_options *p,
		bool host_iface);

/**
 * nvme_fabric_options_get_host_iface() - Get host_iface.
 * @p: The &struct nvme_fabric_options instance to query.
 *
 * Return: The value of the host_iface field.
 */
bool nvme_fabric_options_get_host_iface(const struct nvme_fabric_options *p);

/**
 * nvme_fabric_options_set_host_traddr() - Set host_traddr.
 * @p: The &struct nvme_fabric_options instance to update.
 * @host_traddr: Value to assign to the host_traddr field.
 */
void nvme_fabric_options_set_host_traddr(
		struct nvme_fabric_options *p,
		bool host_traddr);

/**
 * nvme_fabric_options_get_host_traddr() - Get host_traddr.
 * @p: The &struct nvme_fabric_options instance to query.
 *
 * Return: The value of the host_traddr field.
 */
bool nvme_fabric_options_get_host_traddr(const struct nvme_fabric_options *p);

/**
 * nvme_fabric_options_set_hostid() - Set hostid.
 * @p: The &struct nvme_fabric_options instance to update.
 * @hostid: Value to assign to the hostid field.
 */
void nvme_fabric_options_set_hostid(struct nvme_fabric_options *p, bool hostid);

/**
 * nvme_fabric_options_get_hostid() - Get hostid.
 * @p: The &struct nvme_fabric_options instance to query.
 *
 * Return: The value of the hostid field.
 */
bool nvme_fabric_options_get_hostid(const struct nvme_fabric_options *p);

/**
 * nvme_fabric_options_set_hostnqn() - Set hostnqn.
 * @p: The &struct nvme_fabric_options instance to update.
 * @hostnqn: Value to assign to the hostnqn field.
 */
void nvme_fabric_options_set_hostnqn(
		struct nvme_fabric_options *p,
		bool hostnqn);

/**
 * nvme_fabric_options_get_hostnqn() - Get hostnqn.
 * @p: The &struct nvme_fabric_options instance to query.
 *
 * Return: The value of the hostnqn field.
 */
bool nvme_fabric_options_get_hostnqn(const struct nvme_fabric_options *p);

/**
 * nvme_fabric_options_set_instance() - Set instance.
 * @p: The &struct nvme_fabric_options instance to update.
 * @instance: Value to assign to the instance field.
 */
void nvme_fabric_options_set_instance(
		struct nvme_fabric_options *p,
		bool instance);

/**
 * nvme_fabric_options_get_instance() - Get instance.
 * @p: The &struct nvme_fabric_options instance to query.
 *
 * Return: The value of the instance field.
 */
bool nvme_fabric_options_get_instance(const struct nvme_fabric_options *p);

/**
 * nvme_fabric_options_set_keep_alive_tmo() - Set keep_alive_tmo.
 * @p: The &struct nvme_fabric_options instance to update.
 * @keep_alive_tmo: Value to assign to the keep_alive_tmo field.
 */
void nvme_fabric_options_set_keep_alive_tmo(
		struct nvme_fabric_options *p,
		bool keep_alive_tmo);

/**
 * nvme_fabric_options_get_keep_alive_tmo() - Get keep_alive_tmo.
 * @p: The &struct nvme_fabric_options instance to query.
 *
 * Return: The value of the keep_alive_tmo field.
 */
bool nvme_fabric_options_get_keep_alive_tmo(
		const struct nvme_fabric_options *p);

/**
 * nvme_fabric_options_set_keyring() - Set keyring.
 * @p: The &struct nvme_fabric_options instance to update.
 * @keyring: Value to assign to the keyring field.
 */
void nvme_fabric_options_set_keyring(
		struct nvme_fabric_options *p,
		bool keyring);

/**
 * nvme_fabric_options_get_keyring() - Get keyring.
 * @p: The &struct nvme_fabric_options instance to query.
 *
 * Return: The value of the keyring field.
 */
bool nvme_fabric_options_get_keyring(const struct nvme_fabric_options *p);

/**
 * nvme_fabric_options_set_nqn() - Set nqn.
 * @p: The &struct nvme_fabric_options instance to update.
 * @nqn: Value to assign to the nqn field.
 */
void nvme_fabric_options_set_nqn(struct nvme_fabric_options *p, bool nqn);

/**
 * nvme_fabric_options_get_nqn() - Get nqn.
 * @p: The &struct nvme_fabric_options instance to query.
 *
 * Return: The value of the nqn field.
 */
bool nvme_fabric_options_get_nqn(const struct nvme_fabric_options *p);

/**
 * nvme_fabric_options_set_nr_io_queues() - Set nr_io_queues.
 * @p: The &struct nvme_fabric_options instance to update.
 * @nr_io_queues: Value to assign to the nr_io_queues field.
 */
void nvme_fabric_options_set_nr_io_queues(
		struct nvme_fabric_options *p,
		bool nr_io_queues);

/**
 * nvme_fabric_options_get_nr_io_queues() - Get nr_io_queues.
 * @p: The &struct nvme_fabric_options instance to query.
 *
 * Return: The value of the nr_io_queues field.
 */
bool nvme_fabric_options_get_nr_io_queues(const struct nvme_fabric_options *p);

/**
 * nvme_fabric_options_set_nr_poll_queues() - Set nr_poll_queues.
 * @p: The &struct nvme_fabric_options instance to update.
 * @nr_poll_queues: Value to assign to the nr_poll_queues field.
 */
void nvme_fabric_options_set_nr_poll_queues(
		struct nvme_fabric_options *p,
		bool nr_poll_queues);

/**
 * nvme_fabric_options_get_nr_poll_queues() - Get nr_poll_queues.
 * @p: The &struct nvme_fabric_options instance to query.
 *
 * Return: The value of the nr_poll_queues field.
 */
bool nvme_fabric_options_get_nr_poll_queues(
		const struct nvme_fabric_options *p);

/**
 * nvme_fabric_options_set_nr_write_queues() - Set nr_write_queues.
 * @p: The &struct nvme_fabric_options instance to update.
 * @nr_write_queues: Value to assign to the nr_write_queues field.
 */
void nvme_fabric_options_set_nr_write_queues(
		struct nvme_fabric_options *p,
		bool nr_write_queues);

/**
 * nvme_fabric_options_get_nr_write_queues() - Get nr_write_queues.
 * @p: The &struct nvme_fabric_options instance to query.
 *
 * Return: The value of the nr_write_queues field.
 */
bool nvme_fabric_options_get_nr_write_queues(
		const struct nvme_fabric_options *p);

/**
 * nvme_fabric_options_set_queue_size() - Set queue_size.
 * @p: The &struct nvme_fabric_options instance to update.
 * @queue_size: Value to assign to the queue_size field.
 */
void nvme_fabric_options_set_queue_size(
		struct nvme_fabric_options *p,
		bool queue_size);

/**
 * nvme_fabric_options_get_queue_size() - Get queue_size.
 * @p: The &struct nvme_fabric_options instance to query.
 *
 * Return: The value of the queue_size field.
 */
bool nvme_fabric_options_get_queue_size(const struct nvme_fabric_options *p);

/**
 * nvme_fabric_options_set_reconnect_delay() - Set reconnect_delay.
 * @p: The &struct nvme_fabric_options instance to update.
 * @reconnect_delay: Value to assign to the reconnect_delay field.
 */
void nvme_fabric_options_set_reconnect_delay(
		struct nvme_fabric_options *p,
		bool reconnect_delay);

/**
 * nvme_fabric_options_get_reconnect_delay() - Get reconnect_delay.
 * @p: The &struct nvme_fabric_options instance to query.
 *
 * Return: The value of the reconnect_delay field.
 */
bool nvme_fabric_options_get_reconnect_delay(
		const struct nvme_fabric_options *p);

/**
 * nvme_fabric_options_set_tls() - Set tls.
 * @p: The &struct nvme_fabric_options instance to update.
 * @tls: Value to assign to the tls field.
 */
void nvme_fabric_options_set_tls(struct nvme_fabric_options *p, bool tls);

/**
 * nvme_fabric_options_get_tls() - Get tls.
 * @p: The &struct nvme_fabric_options instance to query.
 *
 * Return: The value of the tls field.
 */
bool nvme_fabric_options_get_tls(const struct nvme_fabric_options *p);

/**
 * nvme_fabric_options_set_tls_key() - Set tls_key.
 * @p: The &struct nvme_fabric_options instance to update.
 * @tls_key: Value to assign to the tls_key field.
 */
void nvme_fabric_options_set_tls_key(
		struct nvme_fabric_options *p,
		bool tls_key);

/**
 * nvme_fabric_options_get_tls_key() - Get tls_key.
 * @p: The &struct nvme_fabric_options instance to query.
 *
 * Return: The value of the tls_key field.
 */
bool nvme_fabric_options_get_tls_key(const struct nvme_fabric_options *p);

/**
 * nvme_fabric_options_set_tos() - Set tos.
 * @p: The &struct nvme_fabric_options instance to update.
 * @tos: Value to assign to the tos field.
 */
void nvme_fabric_options_set_tos(struct nvme_fabric_options *p, bool tos);

/**
 * nvme_fabric_options_get_tos() - Get tos.
 * @p: The &struct nvme_fabric_options instance to query.
 *
 * Return: The value of the tos field.
 */
bool nvme_fabric_options_get_tos(const struct nvme_fabric_options *p);

/**
 * nvme_fabric_options_set_traddr() - Set traddr.
 * @p: The &struct nvme_fabric_options instance to update.
 * @traddr: Value to assign to the traddr field.
 */
void nvme_fabric_options_set_traddr(struct nvme_fabric_options *p, bool traddr);

/**
 * nvme_fabric_options_get_traddr() - Get traddr.
 * @p: The &struct nvme_fabric_options instance to query.
 *
 * Return: The value of the traddr field.
 */
bool nvme_fabric_options_get_traddr(const struct nvme_fabric_options *p);

/**
 * nvme_fabric_options_set_transport() - Set transport.
 * @p: The &struct nvme_fabric_options instance to update.
 * @transport: Value to assign to the transport field.
 */
void nvme_fabric_options_set_transport(
		struct nvme_fabric_options *p,
		bool transport);

/**
 * nvme_fabric_options_get_transport() - Get transport.
 * @p: The &struct nvme_fabric_options instance to query.
 *
 * Return: The value of the transport field.
 */
bool nvme_fabric_options_get_transport(const struct nvme_fabric_options *p);

/**
 * nvme_fabric_options_set_trsvcid() - Set trsvcid.
 * @p: The &struct nvme_fabric_options instance to update.
 * @trsvcid: Value to assign to the trsvcid field.
 */
void nvme_fabric_options_set_trsvcid(
		struct nvme_fabric_options *p,
		bool trsvcid);

/**
 * nvme_fabric_options_get_trsvcid() - Get trsvcid.
 * @p: The &struct nvme_fabric_options instance to query.
 *
 * Return: The value of the trsvcid field.
 */
bool nvme_fabric_options_get_trsvcid(const struct nvme_fabric_options *p);

#endif /* _ACCESSORS_H_ */
