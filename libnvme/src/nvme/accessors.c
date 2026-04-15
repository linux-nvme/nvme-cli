// SPDX-License-Identifier: LGPL-2.1-or-later

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
 *
 * To update run: meson compile -C [BUILD-DIR] update-accessors
 * Or:            make update-accessors
 */
#include <stdlib.h>
#include <string.h>
#include "accessors.h"

#include "private.h"
#include "compiler-attributes.h"

/****************************************************************************
 * Accessors for: struct libnvme_fabrics_config
 ****************************************************************************/

__public void libnvme_fabrics_config_set_queue_size(
		struct libnvme_fabrics_config *p,
		int queue_size)
{
	p->queue_size = queue_size;
}

__public int libnvme_fabrics_config_get_queue_size(
		const struct libnvme_fabrics_config *p)
{
	return p->queue_size;
}

__public void libnvme_fabrics_config_set_nr_io_queues(
		struct libnvme_fabrics_config *p,
		int nr_io_queues)
{
	p->nr_io_queues = nr_io_queues;
}

__public int libnvme_fabrics_config_get_nr_io_queues(
		const struct libnvme_fabrics_config *p)
{
	return p->nr_io_queues;
}

__public void libnvme_fabrics_config_set_reconnect_delay(
		struct libnvme_fabrics_config *p,
		int reconnect_delay)
{
	p->reconnect_delay = reconnect_delay;
}

__public int libnvme_fabrics_config_get_reconnect_delay(
		const struct libnvme_fabrics_config *p)
{
	return p->reconnect_delay;
}

__public void libnvme_fabrics_config_set_ctrl_loss_tmo(
		struct libnvme_fabrics_config *p,
		int ctrl_loss_tmo)
{
	p->ctrl_loss_tmo = ctrl_loss_tmo;
}

__public int libnvme_fabrics_config_get_ctrl_loss_tmo(
		const struct libnvme_fabrics_config *p)
{
	return p->ctrl_loss_tmo;
}

__public void libnvme_fabrics_config_set_fast_io_fail_tmo(
		struct libnvme_fabrics_config *p,
		int fast_io_fail_tmo)
{
	p->fast_io_fail_tmo = fast_io_fail_tmo;
}

__public int libnvme_fabrics_config_get_fast_io_fail_tmo(
		const struct libnvme_fabrics_config *p)
{
	return p->fast_io_fail_tmo;
}

__public void libnvme_fabrics_config_set_keep_alive_tmo(
		struct libnvme_fabrics_config *p,
		int keep_alive_tmo)
{
	p->keep_alive_tmo = keep_alive_tmo;
}

__public int libnvme_fabrics_config_get_keep_alive_tmo(
		const struct libnvme_fabrics_config *p)
{
	return p->keep_alive_tmo;
}

__public void libnvme_fabrics_config_set_nr_write_queues(
		struct libnvme_fabrics_config *p,
		int nr_write_queues)
{
	p->nr_write_queues = nr_write_queues;
}

__public int libnvme_fabrics_config_get_nr_write_queues(
		const struct libnvme_fabrics_config *p)
{
	return p->nr_write_queues;
}

__public void libnvme_fabrics_config_set_nr_poll_queues(
		struct libnvme_fabrics_config *p,
		int nr_poll_queues)
{
	p->nr_poll_queues = nr_poll_queues;
}

__public int libnvme_fabrics_config_get_nr_poll_queues(
		const struct libnvme_fabrics_config *p)
{
	return p->nr_poll_queues;
}

__public void libnvme_fabrics_config_set_tos(
		struct libnvme_fabrics_config *p,
		int tos)
{
	p->tos = tos;
}

__public int libnvme_fabrics_config_get_tos(
		const struct libnvme_fabrics_config *p)
{
	return p->tos;
}

__public void libnvme_fabrics_config_set_keyring_id(
		struct libnvme_fabrics_config *p,
		long keyring_id)
{
	p->keyring_id = keyring_id;
}

__public long libnvme_fabrics_config_get_keyring_id(
		const struct libnvme_fabrics_config *p)
{
	return p->keyring_id;
}

__public void libnvme_fabrics_config_set_tls_key_id(
		struct libnvme_fabrics_config *p,
		long tls_key_id)
{
	p->tls_key_id = tls_key_id;
}

__public long libnvme_fabrics_config_get_tls_key_id(
		const struct libnvme_fabrics_config *p)
{
	return p->tls_key_id;
}

__public void libnvme_fabrics_config_set_tls_configured_key_id(
		struct libnvme_fabrics_config *p,
		long tls_configured_key_id)
{
	p->tls_configured_key_id = tls_configured_key_id;
}

__public long libnvme_fabrics_config_get_tls_configured_key_id(
		const struct libnvme_fabrics_config *p)
{
	return p->tls_configured_key_id;
}

__public void libnvme_fabrics_config_set_duplicate_connect(
		struct libnvme_fabrics_config *p,
		bool duplicate_connect)
{
	p->duplicate_connect = duplicate_connect;
}

__public bool libnvme_fabrics_config_get_duplicate_connect(
		const struct libnvme_fabrics_config *p)
{
	return p->duplicate_connect;
}

__public void libnvme_fabrics_config_set_disable_sqflow(
		struct libnvme_fabrics_config *p,
		bool disable_sqflow)
{
	p->disable_sqflow = disable_sqflow;
}

__public bool libnvme_fabrics_config_get_disable_sqflow(
		const struct libnvme_fabrics_config *p)
{
	return p->disable_sqflow;
}

__public void libnvme_fabrics_config_set_hdr_digest(
		struct libnvme_fabrics_config *p,
		bool hdr_digest)
{
	p->hdr_digest = hdr_digest;
}

__public bool libnvme_fabrics_config_get_hdr_digest(
		const struct libnvme_fabrics_config *p)
{
	return p->hdr_digest;
}

__public void libnvme_fabrics_config_set_data_digest(
		struct libnvme_fabrics_config *p,
		bool data_digest)
{
	p->data_digest = data_digest;
}

__public bool libnvme_fabrics_config_get_data_digest(
		const struct libnvme_fabrics_config *p)
{
	return p->data_digest;
}

__public void libnvme_fabrics_config_set_tls(
		struct libnvme_fabrics_config *p,
		bool tls)
{
	p->tls = tls;
}

__public bool libnvme_fabrics_config_get_tls(
		const struct libnvme_fabrics_config *p)
{
	return p->tls;
}

__public void libnvme_fabrics_config_set_concat(
		struct libnvme_fabrics_config *p,
		bool concat)
{
	p->concat = concat;
}

__public bool libnvme_fabrics_config_get_concat(
		const struct libnvme_fabrics_config *p)
{
	return p->concat;
}

/****************************************************************************
 * Accessors for: struct libnvme_path
 ****************************************************************************/

__public void libnvme_path_set_name(struct libnvme_path *p, const char *name)
{
	free(p->name);
	p->name = name ? strdup(name) : NULL;
}

__public const char *libnvme_path_get_name(const struct libnvme_path *p)
{
	return p->name;
}

__public void libnvme_path_set_sysfs_dir(
		struct libnvme_path *p,
		const char *sysfs_dir)
{
	free(p->sysfs_dir);
	p->sysfs_dir = sysfs_dir ? strdup(sysfs_dir) : NULL;
}

__public const char *libnvme_path_get_sysfs_dir(const struct libnvme_path *p)
{
	return p->sysfs_dir;
}

__public void libnvme_path_set_ana_state(
		struct libnvme_path *p,
		const char *ana_state)
{
	free(p->ana_state);
	p->ana_state = ana_state ? strdup(ana_state) : NULL;
}

__public const char *libnvme_path_get_ana_state(const struct libnvme_path *p)
{
	return p->ana_state;
}

__public void libnvme_path_set_numa_nodes(
		struct libnvme_path *p,
		const char *numa_nodes)
{
	free(p->numa_nodes);
	p->numa_nodes = numa_nodes ? strdup(numa_nodes) : NULL;
}

__public const char *libnvme_path_get_numa_nodes(const struct libnvme_path *p)
{
	return p->numa_nodes;
}

__public void libnvme_path_set_grpid(struct libnvme_path *p, int grpid)
{
	p->grpid = grpid;
}

__public int libnvme_path_get_grpid(const struct libnvme_path *p)
{
	return p->grpid;
}

/****************************************************************************
 * Accessors for: struct libnvme_ns
 ****************************************************************************/

__public void libnvme_ns_set_nsid(struct libnvme_ns *p, __u32 nsid)
{
	p->nsid = nsid;
}

__public __u32 libnvme_ns_get_nsid(const struct libnvme_ns *p)
{
	return p->nsid;
}

__public void libnvme_ns_set_name(struct libnvme_ns *p, const char *name)
{
	free(p->name);
	p->name = name ? strdup(name) : NULL;
}

__public const char *libnvme_ns_get_name(const struct libnvme_ns *p)
{
	return p->name;
}

__public void libnvme_ns_set_sysfs_dir(
		struct libnvme_ns *p,
		const char *sysfs_dir)
{
	free(p->sysfs_dir);
	p->sysfs_dir = sysfs_dir ? strdup(sysfs_dir) : NULL;
}

__public const char *libnvme_ns_get_sysfs_dir(const struct libnvme_ns *p)
{
	return p->sysfs_dir;
}

__public void libnvme_ns_set_lba_shift(struct libnvme_ns *p, int lba_shift)
{
	p->lba_shift = lba_shift;
}

__public int libnvme_ns_get_lba_shift(const struct libnvme_ns *p)
{
	return p->lba_shift;
}

__public void libnvme_ns_set_lba_size(struct libnvme_ns *p, int lba_size)
{
	p->lba_size = lba_size;
}

__public int libnvme_ns_get_lba_size(const struct libnvme_ns *p)
{
	return p->lba_size;
}

__public void libnvme_ns_set_meta_size(struct libnvme_ns *p, int meta_size)
{
	p->meta_size = meta_size;
}

__public int libnvme_ns_get_meta_size(const struct libnvme_ns *p)
{
	return p->meta_size;
}

__public void libnvme_ns_set_lba_count(struct libnvme_ns *p, uint64_t lba_count)
{
	p->lba_count = lba_count;
}

__public uint64_t libnvme_ns_get_lba_count(const struct libnvme_ns *p)
{
	return p->lba_count;
}

__public void libnvme_ns_set_lba_util(struct libnvme_ns *p, uint64_t lba_util)
{
	p->lba_util = lba_util;
}

__public uint64_t libnvme_ns_get_lba_util(const struct libnvme_ns *p)
{
	return p->lba_util;
}

/****************************************************************************
 * Accessors for: struct libnvme_ctrl
 ****************************************************************************/

__public const char *libnvme_ctrl_get_name(const struct libnvme_ctrl *p)
{
	return p->name;
}

__public const char *libnvme_ctrl_get_sysfs_dir(const struct libnvme_ctrl *p)
{
	return p->sysfs_dir;
}

__public const char *libnvme_ctrl_get_firmware(const struct libnvme_ctrl *p)
{
	return p->firmware;
}

__public const char *libnvme_ctrl_get_model(const struct libnvme_ctrl *p)
{
	return p->model;
}

__public const char *libnvme_ctrl_get_numa_node(const struct libnvme_ctrl *p)
{
	return p->numa_node;
}

__public const char *libnvme_ctrl_get_queue_count(const struct libnvme_ctrl *p)
{
	return p->queue_count;
}

__public const char *libnvme_ctrl_get_serial(const struct libnvme_ctrl *p)
{
	return p->serial;
}

__public const char *libnvme_ctrl_get_sqsize(const struct libnvme_ctrl *p)
{
	return p->sqsize;
}

__public const char *libnvme_ctrl_get_transport(const struct libnvme_ctrl *p)
{
	return p->transport;
}

__public const char *libnvme_ctrl_get_subsysnqn(const struct libnvme_ctrl *p)
{
	return p->subsysnqn;
}

__public const char *libnvme_ctrl_get_traddr(const struct libnvme_ctrl *p)
{
	return p->traddr;
}

__public const char *libnvme_ctrl_get_trsvcid(const struct libnvme_ctrl *p)
{
	return p->trsvcid;
}

__public void libnvme_ctrl_set_dhchap_host_key(
		struct libnvme_ctrl *p,
		const char *dhchap_host_key)
{
	free(p->dhchap_host_key);
	p->dhchap_host_key = dhchap_host_key ? strdup(dhchap_host_key) : NULL;
}

__public const char *libnvme_ctrl_get_dhchap_host_key(
		const struct libnvme_ctrl *p)
{
	return p->dhchap_host_key;
}

__public void libnvme_ctrl_set_dhchap_ctrl_key(
		struct libnvme_ctrl *p,
		const char *dhchap_ctrl_key)
{
	free(p->dhchap_ctrl_key);
	p->dhchap_ctrl_key = dhchap_ctrl_key ? strdup(dhchap_ctrl_key) : NULL;
}

__public const char *libnvme_ctrl_get_dhchap_ctrl_key(
		const struct libnvme_ctrl *p)
{
	return p->dhchap_ctrl_key;
}

__public void libnvme_ctrl_set_keyring(
		struct libnvme_ctrl *p,
		const char *keyring)
{
	free(p->keyring);
	p->keyring = keyring ? strdup(keyring) : NULL;
}

__public const char *libnvme_ctrl_get_keyring(const struct libnvme_ctrl *p)
{
	return p->keyring;
}

__public void libnvme_ctrl_set_tls_key_identity(
		struct libnvme_ctrl *p,
		const char *tls_key_identity)
{
	free(p->tls_key_identity);
	p->tls_key_identity =
		tls_key_identity ? strdup(tls_key_identity) : NULL;
}

__public const char *libnvme_ctrl_get_tls_key_identity(
		const struct libnvme_ctrl *p)
{
	return p->tls_key_identity;
}

__public void libnvme_ctrl_set_tls_key(
		struct libnvme_ctrl *p,
		const char *tls_key)
{
	free(p->tls_key);
	p->tls_key = tls_key ? strdup(tls_key) : NULL;
}

__public const char *libnvme_ctrl_get_tls_key(const struct libnvme_ctrl *p)
{
	return p->tls_key;
}

__public const char *libnvme_ctrl_get_cntrltype(const struct libnvme_ctrl *p)
{
	return p->cntrltype;
}

__public const char *libnvme_ctrl_get_cntlid(const struct libnvme_ctrl *p)
{
	return p->cntlid;
}

__public const char *libnvme_ctrl_get_dctype(const struct libnvme_ctrl *p)
{
	return p->dctype;
}

__public const char *libnvme_ctrl_get_phy_slot(const struct libnvme_ctrl *p)
{
	return p->phy_slot;
}

__public const char *libnvme_ctrl_get_host_traddr(const struct libnvme_ctrl *p)
{
	return p->host_traddr;
}

__public const char *libnvme_ctrl_get_host_iface(const struct libnvme_ctrl *p)
{
	return p->host_iface;
}

__public void libnvme_ctrl_set_discovery_ctrl(
		struct libnvme_ctrl *p,
		bool discovery_ctrl)
{
	p->discovery_ctrl = discovery_ctrl;
}

__public bool libnvme_ctrl_get_discovery_ctrl(const struct libnvme_ctrl *p)
{
	return p->discovery_ctrl;
}

__public void libnvme_ctrl_set_unique_discovery_ctrl(
		struct libnvme_ctrl *p,
		bool unique_discovery_ctrl)
{
	p->unique_discovery_ctrl = unique_discovery_ctrl;
}

__public bool libnvme_ctrl_get_unique_discovery_ctrl(
		const struct libnvme_ctrl *p)
{
	return p->unique_discovery_ctrl;
}

__public void libnvme_ctrl_set_discovered(
		struct libnvme_ctrl *p,
		bool discovered)
{
	p->discovered = discovered;
}

__public bool libnvme_ctrl_get_discovered(const struct libnvme_ctrl *p)
{
	return p->discovered;
}

__public void libnvme_ctrl_set_persistent(
		struct libnvme_ctrl *p,
		bool persistent)
{
	p->persistent = persistent;
}

__public bool libnvme_ctrl_get_persistent(const struct libnvme_ctrl *p)
{
	return p->persistent;
}

/****************************************************************************
 * Accessors for: struct libnvme_subsystem
 ****************************************************************************/

__public const char *libnvme_subsystem_get_name(
		const struct libnvme_subsystem *p)
{
	return p->name;
}

__public const char *libnvme_subsystem_get_sysfs_dir(
		const struct libnvme_subsystem *p)
{
	return p->sysfs_dir;
}

__public const char *libnvme_subsystem_get_subsysnqn(
		const struct libnvme_subsystem *p)
{
	return p->subsysnqn;
}

__public const char *libnvme_subsystem_get_model(
		const struct libnvme_subsystem *p)
{
	return p->model;
}

__public const char *libnvme_subsystem_get_serial(
		const struct libnvme_subsystem *p)
{
	return p->serial;
}

__public const char *libnvme_subsystem_get_firmware(
		const struct libnvme_subsystem *p)
{
	return p->firmware;
}

__public const char *libnvme_subsystem_get_subsystype(
		const struct libnvme_subsystem *p)
{
	return p->subsystype;
}

__public void libnvme_subsystem_set_application(
		struct libnvme_subsystem *p,
		const char *application)
{
	free(p->application);
	p->application = application ? strdup(application) : NULL;
}

__public const char *libnvme_subsystem_get_application(
		const struct libnvme_subsystem *p)
{
	return p->application;
}

__public void libnvme_subsystem_set_iopolicy(
		struct libnvme_subsystem *p,
		const char *iopolicy)
{
	free(p->iopolicy);
	p->iopolicy = iopolicy ? strdup(iopolicy) : NULL;
}

__public const char *libnvme_subsystem_get_iopolicy(
		const struct libnvme_subsystem *p)
{
	return p->iopolicy;
}

/****************************************************************************
 * Accessors for: struct libnvme_host
 ****************************************************************************/

__public const char *libnvme_host_get_hostnqn(const struct libnvme_host *p)
{
	return p->hostnqn;
}

__public const char *libnvme_host_get_hostid(const struct libnvme_host *p)
{
	return p->hostid;
}

__public void libnvme_host_set_dhchap_host_key(
		struct libnvme_host *p,
		const char *dhchap_host_key)
{
	free(p->dhchap_host_key);
	p->dhchap_host_key = dhchap_host_key ? strdup(dhchap_host_key) : NULL;
}

__public const char *libnvme_host_get_dhchap_host_key(
		const struct libnvme_host *p)
{
	return p->dhchap_host_key;
}

__public void libnvme_host_set_hostsymname(
		struct libnvme_host *p,
		const char *hostsymname)
{
	free(p->hostsymname);
	p->hostsymname = hostsymname ? strdup(hostsymname) : NULL;
}

__public const char *libnvme_host_get_hostsymname(const struct libnvme_host *p)
{
	return p->hostsymname;
}

__public void libnvme_host_set_pdc_enabled_valid(
		struct libnvme_host *p,
		bool pdc_enabled_valid)
{
	p->pdc_enabled_valid = pdc_enabled_valid;
}

__public bool libnvme_host_get_pdc_enabled_valid(const struct libnvme_host *p)
{
	return p->pdc_enabled_valid;
}

/****************************************************************************
 * Accessors for: struct libnvme_fabric_options
 ****************************************************************************/

__public void libnvme_fabric_options_set_cntlid(
		struct libnvme_fabric_options *p,
		bool cntlid)
{
	p->cntlid = cntlid;
}

__public bool libnvme_fabric_options_get_cntlid(
		const struct libnvme_fabric_options *p)
{
	return p->cntlid;
}

__public void libnvme_fabric_options_set_concat(
		struct libnvme_fabric_options *p,
		bool concat)
{
	p->concat = concat;
}

__public bool libnvme_fabric_options_get_concat(
		const struct libnvme_fabric_options *p)
{
	return p->concat;
}

__public void libnvme_fabric_options_set_ctrl_loss_tmo(
		struct libnvme_fabric_options *p,
		bool ctrl_loss_tmo)
{
	p->ctrl_loss_tmo = ctrl_loss_tmo;
}

__public bool libnvme_fabric_options_get_ctrl_loss_tmo(
		const struct libnvme_fabric_options *p)
{
	return p->ctrl_loss_tmo;
}

__public void libnvme_fabric_options_set_data_digest(
		struct libnvme_fabric_options *p,
		bool data_digest)
{
	p->data_digest = data_digest;
}

__public bool libnvme_fabric_options_get_data_digest(
		const struct libnvme_fabric_options *p)
{
	return p->data_digest;
}

__public void libnvme_fabric_options_set_dhchap_ctrl_secret(
		struct libnvme_fabric_options *p,
		bool dhchap_ctrl_secret)
{
	p->dhchap_ctrl_secret = dhchap_ctrl_secret;
}

__public bool libnvme_fabric_options_get_dhchap_ctrl_secret(
		const struct libnvme_fabric_options *p)
{
	return p->dhchap_ctrl_secret;
}

__public void libnvme_fabric_options_set_dhchap_secret(
		struct libnvme_fabric_options *p,
		bool dhchap_secret)
{
	p->dhchap_secret = dhchap_secret;
}

__public bool libnvme_fabric_options_get_dhchap_secret(
		const struct libnvme_fabric_options *p)
{
	return p->dhchap_secret;
}

__public void libnvme_fabric_options_set_disable_sqflow(
		struct libnvme_fabric_options *p,
		bool disable_sqflow)
{
	p->disable_sqflow = disable_sqflow;
}

__public bool libnvme_fabric_options_get_disable_sqflow(
		const struct libnvme_fabric_options *p)
{
	return p->disable_sqflow;
}

__public void libnvme_fabric_options_set_discovery(
		struct libnvme_fabric_options *p,
		bool discovery)
{
	p->discovery = discovery;
}

__public bool libnvme_fabric_options_get_discovery(
		const struct libnvme_fabric_options *p)
{
	return p->discovery;
}

__public void libnvme_fabric_options_set_duplicate_connect(
		struct libnvme_fabric_options *p,
		bool duplicate_connect)
{
	p->duplicate_connect = duplicate_connect;
}

__public bool libnvme_fabric_options_get_duplicate_connect(
		const struct libnvme_fabric_options *p)
{
	return p->duplicate_connect;
}

__public void libnvme_fabric_options_set_fast_io_fail_tmo(
		struct libnvme_fabric_options *p,
		bool fast_io_fail_tmo)
{
	p->fast_io_fail_tmo = fast_io_fail_tmo;
}

__public bool libnvme_fabric_options_get_fast_io_fail_tmo(
		const struct libnvme_fabric_options *p)
{
	return p->fast_io_fail_tmo;
}

__public void libnvme_fabric_options_set_hdr_digest(
		struct libnvme_fabric_options *p,
		bool hdr_digest)
{
	p->hdr_digest = hdr_digest;
}

__public bool libnvme_fabric_options_get_hdr_digest(
		const struct libnvme_fabric_options *p)
{
	return p->hdr_digest;
}

__public void libnvme_fabric_options_set_host_iface(
		struct libnvme_fabric_options *p,
		bool host_iface)
{
	p->host_iface = host_iface;
}

__public bool libnvme_fabric_options_get_host_iface(
		const struct libnvme_fabric_options *p)
{
	return p->host_iface;
}

__public void libnvme_fabric_options_set_host_traddr(
		struct libnvme_fabric_options *p,
		bool host_traddr)
{
	p->host_traddr = host_traddr;
}

__public bool libnvme_fabric_options_get_host_traddr(
		const struct libnvme_fabric_options *p)
{
	return p->host_traddr;
}

__public void libnvme_fabric_options_set_hostid(
		struct libnvme_fabric_options *p,
		bool hostid)
{
	p->hostid = hostid;
}

__public bool libnvme_fabric_options_get_hostid(
		const struct libnvme_fabric_options *p)
{
	return p->hostid;
}

__public void libnvme_fabric_options_set_hostnqn(
		struct libnvme_fabric_options *p,
		bool hostnqn)
{
	p->hostnqn = hostnqn;
}

__public bool libnvme_fabric_options_get_hostnqn(
		const struct libnvme_fabric_options *p)
{
	return p->hostnqn;
}

__public void libnvme_fabric_options_set_instance(
		struct libnvme_fabric_options *p,
		bool instance)
{
	p->instance = instance;
}

__public bool libnvme_fabric_options_get_instance(
		const struct libnvme_fabric_options *p)
{
	return p->instance;
}

__public void libnvme_fabric_options_set_keep_alive_tmo(
		struct libnvme_fabric_options *p,
		bool keep_alive_tmo)
{
	p->keep_alive_tmo = keep_alive_tmo;
}

__public bool libnvme_fabric_options_get_keep_alive_tmo(
		const struct libnvme_fabric_options *p)
{
	return p->keep_alive_tmo;
}

__public void libnvme_fabric_options_set_keyring(
		struct libnvme_fabric_options *p,
		bool keyring)
{
	p->keyring = keyring;
}

__public bool libnvme_fabric_options_get_keyring(
		const struct libnvme_fabric_options *p)
{
	return p->keyring;
}

__public void libnvme_fabric_options_set_nqn(
		struct libnvme_fabric_options *p,
		bool nqn)
{
	p->nqn = nqn;
}

__public bool libnvme_fabric_options_get_nqn(
		const struct libnvme_fabric_options *p)
{
	return p->nqn;
}

__public void libnvme_fabric_options_set_nr_io_queues(
		struct libnvme_fabric_options *p,
		bool nr_io_queues)
{
	p->nr_io_queues = nr_io_queues;
}

__public bool libnvme_fabric_options_get_nr_io_queues(
		const struct libnvme_fabric_options *p)
{
	return p->nr_io_queues;
}

__public void libnvme_fabric_options_set_nr_poll_queues(
		struct libnvme_fabric_options *p,
		bool nr_poll_queues)
{
	p->nr_poll_queues = nr_poll_queues;
}

__public bool libnvme_fabric_options_get_nr_poll_queues(
		const struct libnvme_fabric_options *p)
{
	return p->nr_poll_queues;
}

__public void libnvme_fabric_options_set_nr_write_queues(
		struct libnvme_fabric_options *p,
		bool nr_write_queues)
{
	p->nr_write_queues = nr_write_queues;
}

__public bool libnvme_fabric_options_get_nr_write_queues(
		const struct libnvme_fabric_options *p)
{
	return p->nr_write_queues;
}

__public void libnvme_fabric_options_set_queue_size(
		struct libnvme_fabric_options *p,
		bool queue_size)
{
	p->queue_size = queue_size;
}

__public bool libnvme_fabric_options_get_queue_size(
		const struct libnvme_fabric_options *p)
{
	return p->queue_size;
}

__public void libnvme_fabric_options_set_reconnect_delay(
		struct libnvme_fabric_options *p,
		bool reconnect_delay)
{
	p->reconnect_delay = reconnect_delay;
}

__public bool libnvme_fabric_options_get_reconnect_delay(
		const struct libnvme_fabric_options *p)
{
	return p->reconnect_delay;
}

__public void libnvme_fabric_options_set_tls(
		struct libnvme_fabric_options *p,
		bool tls)
{
	p->tls = tls;
}

__public bool libnvme_fabric_options_get_tls(
		const struct libnvme_fabric_options *p)
{
	return p->tls;
}

__public void libnvme_fabric_options_set_tls_key(
		struct libnvme_fabric_options *p,
		bool tls_key)
{
	p->tls_key = tls_key;
}

__public bool libnvme_fabric_options_get_tls_key(
		const struct libnvme_fabric_options *p)
{
	return p->tls_key;
}

__public void libnvme_fabric_options_set_tos(
		struct libnvme_fabric_options *p,
		bool tos)
{
	p->tos = tos;
}

__public bool libnvme_fabric_options_get_tos(
		const struct libnvme_fabric_options *p)
{
	return p->tos;
}

__public void libnvme_fabric_options_set_traddr(
		struct libnvme_fabric_options *p,
		bool traddr)
{
	p->traddr = traddr;
}

__public bool libnvme_fabric_options_get_traddr(
		const struct libnvme_fabric_options *p)
{
	return p->traddr;
}

__public void libnvme_fabric_options_set_transport(
		struct libnvme_fabric_options *p,
		bool transport)
{
	p->transport = transport;
}

__public bool libnvme_fabric_options_get_transport(
		const struct libnvme_fabric_options *p)
{
	return p->transport;
}

__public void libnvme_fabric_options_set_trsvcid(
		struct libnvme_fabric_options *p,
		bool trsvcid)
{
	p->trsvcid = trsvcid;
}

__public bool libnvme_fabric_options_get_trsvcid(
		const struct libnvme_fabric_options *p)
{
	return p->trsvcid;
}

