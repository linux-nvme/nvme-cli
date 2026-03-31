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
#include "compiler_attributes.h"

/****************************************************************************
 * Accessors for: struct nvme_path
 ****************************************************************************/

__public void nvme_path_set_name(struct nvme_path *p, const char *name)
{
	free(p->name);
	p->name = name ? strdup(name) : NULL;
}

__public const char *nvme_path_get_name(const struct nvme_path *p)
{
	return p->name;
}

__public void nvme_path_set_sysfs_dir(
		struct nvme_path *p,
		const char *sysfs_dir)
{
	free(p->sysfs_dir);
	p->sysfs_dir = sysfs_dir ? strdup(sysfs_dir) : NULL;
}

__public const char *nvme_path_get_sysfs_dir(const struct nvme_path *p)
{
	return p->sysfs_dir;
}

__public void nvme_path_set_ana_state(
		struct nvme_path *p,
		const char *ana_state)
{
	free(p->ana_state);
	p->ana_state = ana_state ? strdup(ana_state) : NULL;
}

__public const char *nvme_path_get_ana_state(const struct nvme_path *p)
{
	return p->ana_state;
}

__public void nvme_path_set_numa_nodes(
		struct nvme_path *p,
		const char *numa_nodes)
{
	free(p->numa_nodes);
	p->numa_nodes = numa_nodes ? strdup(numa_nodes) : NULL;
}

__public const char *nvme_path_get_numa_nodes(const struct nvme_path *p)
{
	return p->numa_nodes;
}

__public void nvme_path_set_grpid(struct nvme_path *p, int grpid)
{
	p->grpid = grpid;
}

__public int nvme_path_get_grpid(const struct nvme_path *p)
{
	return p->grpid;
}

/****************************************************************************
 * Accessors for: struct nvme_ns
 ****************************************************************************/

__public void nvme_ns_set_nsid(struct nvme_ns *p, __u32 nsid)
{
	p->nsid = nsid;
}

__public __u32 nvme_ns_get_nsid(const struct nvme_ns *p)
{
	return p->nsid;
}

__public void nvme_ns_set_name(struct nvme_ns *p, const char *name)
{
	free(p->name);
	p->name = name ? strdup(name) : NULL;
}

__public const char *nvme_ns_get_name(const struct nvme_ns *p)
{
	return p->name;
}

__public void nvme_ns_set_sysfs_dir(struct nvme_ns *p, const char *sysfs_dir)
{
	free(p->sysfs_dir);
	p->sysfs_dir = sysfs_dir ? strdup(sysfs_dir) : NULL;
}

__public const char *nvme_ns_get_sysfs_dir(const struct nvme_ns *p)
{
	return p->sysfs_dir;
}

__public void nvme_ns_set_lba_shift(struct nvme_ns *p, int lba_shift)
{
	p->lba_shift = lba_shift;
}

__public int nvme_ns_get_lba_shift(const struct nvme_ns *p)
{
	return p->lba_shift;
}

__public void nvme_ns_set_lba_size(struct nvme_ns *p, int lba_size)
{
	p->lba_size = lba_size;
}

__public int nvme_ns_get_lba_size(const struct nvme_ns *p)
{
	return p->lba_size;
}

__public void nvme_ns_set_meta_size(struct nvme_ns *p, int meta_size)
{
	p->meta_size = meta_size;
}

__public int nvme_ns_get_meta_size(const struct nvme_ns *p)
{
	return p->meta_size;
}

__public void nvme_ns_set_lba_count(struct nvme_ns *p, uint64_t lba_count)
{
	p->lba_count = lba_count;
}

__public uint64_t nvme_ns_get_lba_count(const struct nvme_ns *p)
{
	return p->lba_count;
}

__public void nvme_ns_set_lba_util(struct nvme_ns *p, uint64_t lba_util)
{
	p->lba_util = lba_util;
}

__public uint64_t nvme_ns_get_lba_util(const struct nvme_ns *p)
{
	return p->lba_util;
}

/****************************************************************************
 * Accessors for: struct nvme_ctrl
 ****************************************************************************/

__public const char *nvme_ctrl_get_name(const struct nvme_ctrl *p)
{
	return p->name;
}

__public const char *nvme_ctrl_get_sysfs_dir(const struct nvme_ctrl *p)
{
	return p->sysfs_dir;
}

__public const char *nvme_ctrl_get_firmware(const struct nvme_ctrl *p)
{
	return p->firmware;
}

__public const char *nvme_ctrl_get_model(const struct nvme_ctrl *p)
{
	return p->model;
}

__public const char *nvme_ctrl_get_numa_node(const struct nvme_ctrl *p)
{
	return p->numa_node;
}

__public const char *nvme_ctrl_get_queue_count(const struct nvme_ctrl *p)
{
	return p->queue_count;
}

__public const char *nvme_ctrl_get_serial(const struct nvme_ctrl *p)
{
	return p->serial;
}

__public const char *nvme_ctrl_get_sqsize(const struct nvme_ctrl *p)
{
	return p->sqsize;
}

__public const char *nvme_ctrl_get_transport(const struct nvme_ctrl *p)
{
	return p->transport;
}

__public const char *nvme_ctrl_get_subsysnqn(const struct nvme_ctrl *p)
{
	return p->subsysnqn;
}

__public const char *nvme_ctrl_get_traddr(const struct nvme_ctrl *p)
{
	return p->traddr;
}

__public const char *nvme_ctrl_get_trsvcid(const struct nvme_ctrl *p)
{
	return p->trsvcid;
}

__public void nvme_ctrl_set_dhchap_host_key(
		struct nvme_ctrl *p,
		const char *dhchap_host_key)
{
	free(p->dhchap_host_key);
	p->dhchap_host_key = dhchap_host_key ? strdup(dhchap_host_key) : NULL;
}

__public const char *nvme_ctrl_get_dhchap_host_key(const struct nvme_ctrl *p)
{
	return p->dhchap_host_key;
}

__public void nvme_ctrl_set_dhchap_ctrl_key(
		struct nvme_ctrl *p,
		const char *dhchap_ctrl_key)
{
	free(p->dhchap_ctrl_key);
	p->dhchap_ctrl_key = dhchap_ctrl_key ? strdup(dhchap_ctrl_key) : NULL;
}

__public const char *nvme_ctrl_get_dhchap_ctrl_key(const struct nvme_ctrl *p)
{
	return p->dhchap_ctrl_key;
}

__public void nvme_ctrl_set_keyring(struct nvme_ctrl *p, const char *keyring)
{
	free(p->keyring);
	p->keyring = keyring ? strdup(keyring) : NULL;
}

__public const char *nvme_ctrl_get_keyring(const struct nvme_ctrl *p)
{
	return p->keyring;
}

__public void nvme_ctrl_set_tls_key_identity(
		struct nvme_ctrl *p,
		const char *tls_key_identity)
{
	free(p->tls_key_identity);
	p->tls_key_identity =
		tls_key_identity ? strdup(tls_key_identity) : NULL;
}

__public const char *nvme_ctrl_get_tls_key_identity(const struct nvme_ctrl *p)
{
	return p->tls_key_identity;
}

__public void nvme_ctrl_set_tls_key(struct nvme_ctrl *p, const char *tls_key)
{
	free(p->tls_key);
	p->tls_key = tls_key ? strdup(tls_key) : NULL;
}

__public const char *nvme_ctrl_get_tls_key(const struct nvme_ctrl *p)
{
	return p->tls_key;
}

__public const char *nvme_ctrl_get_cntrltype(const struct nvme_ctrl *p)
{
	return p->cntrltype;
}

__public const char *nvme_ctrl_get_cntlid(const struct nvme_ctrl *p)
{
	return p->cntlid;
}

__public const char *nvme_ctrl_get_dctype(const struct nvme_ctrl *p)
{
	return p->dctype;
}

__public const char *nvme_ctrl_get_phy_slot(const struct nvme_ctrl *p)
{
	return p->phy_slot;
}

__public const char *nvme_ctrl_get_host_traddr(const struct nvme_ctrl *p)
{
	return p->host_traddr;
}

__public const char *nvme_ctrl_get_host_iface(const struct nvme_ctrl *p)
{
	return p->host_iface;
}

__public void nvme_ctrl_set_discovery_ctrl(
		struct nvme_ctrl *p,
		bool discovery_ctrl)
{
	p->discovery_ctrl = discovery_ctrl;
}

__public bool nvme_ctrl_get_discovery_ctrl(const struct nvme_ctrl *p)
{
	return p->discovery_ctrl;
}

__public void nvme_ctrl_set_unique_discovery_ctrl(
		struct nvme_ctrl *p,
		bool unique_discovery_ctrl)
{
	p->unique_discovery_ctrl = unique_discovery_ctrl;
}

__public bool nvme_ctrl_get_unique_discovery_ctrl(const struct nvme_ctrl *p)
{
	return p->unique_discovery_ctrl;
}

__public void nvme_ctrl_set_discovered(struct nvme_ctrl *p, bool discovered)
{
	p->discovered = discovered;
}

__public bool nvme_ctrl_get_discovered(const struct nvme_ctrl *p)
{
	return p->discovered;
}

__public void nvme_ctrl_set_persistent(struct nvme_ctrl *p, bool persistent)
{
	p->persistent = persistent;
}

__public bool nvme_ctrl_get_persistent(const struct nvme_ctrl *p)
{
	return p->persistent;
}

/****************************************************************************
 * Accessors for: struct nvme_subsystem
 ****************************************************************************/

__public const char *nvme_subsystem_get_name(const struct nvme_subsystem *p)
{
	return p->name;
}

__public const char *nvme_subsystem_get_sysfs_dir(
		const struct nvme_subsystem *p)
{
	return p->sysfs_dir;
}

__public const char *nvme_subsystem_get_subsysnqn(
		const struct nvme_subsystem *p)
{
	return p->subsysnqn;
}

__public const char *nvme_subsystem_get_model(const struct nvme_subsystem *p)
{
	return p->model;
}

__public const char *nvme_subsystem_get_serial(const struct nvme_subsystem *p)
{
	return p->serial;
}

__public const char *nvme_subsystem_get_firmware(const struct nvme_subsystem *p)
{
	return p->firmware;
}

__public const char *nvme_subsystem_get_subsystype(
		const struct nvme_subsystem *p)
{
	return p->subsystype;
}

__public void nvme_subsystem_set_application(
		struct nvme_subsystem *p,
		const char *application)
{
	free(p->application);
	p->application = application ? strdup(application) : NULL;
}

__public const char *nvme_subsystem_get_application(
		const struct nvme_subsystem *p)
{
	return p->application;
}

__public void nvme_subsystem_set_iopolicy(
		struct nvme_subsystem *p,
		const char *iopolicy)
{
	free(p->iopolicy);
	p->iopolicy = iopolicy ? strdup(iopolicy) : NULL;
}

__public const char *nvme_subsystem_get_iopolicy(const struct nvme_subsystem *p)
{
	return p->iopolicy;
}

/****************************************************************************
 * Accessors for: struct nvme_host
 ****************************************************************************/

__public const char *nvme_host_get_hostnqn(const struct nvme_host *p)
{
	return p->hostnqn;
}

__public void nvme_host_set_dhchap_host_key(
		struct nvme_host *p,
		const char *dhchap_host_key)
{
	free(p->dhchap_host_key);
	p->dhchap_host_key = dhchap_host_key ? strdup(dhchap_host_key) : NULL;
}

__public const char *nvme_host_get_dhchap_host_key(const struct nvme_host *p)
{
	return p->dhchap_host_key;
}

__public void nvme_host_set_hostsymname(
		struct nvme_host *p,
		const char *hostsymname)
{
	free(p->hostsymname);
	p->hostsymname = hostsymname ? strdup(hostsymname) : NULL;
}

__public const char *nvme_host_get_hostsymname(const struct nvme_host *p)
{
	return p->hostsymname;
}

__public void nvme_host_set_pdc_enabled_valid(
		struct nvme_host *p,
		bool pdc_enabled_valid)
{
	p->pdc_enabled_valid = pdc_enabled_valid;
}

__public bool nvme_host_get_pdc_enabled_valid(const struct nvme_host *p)
{
	return p->pdc_enabled_valid;
}

/****************************************************************************
 * Accessors for: struct nvme_fabric_options
 ****************************************************************************/

__public void nvme_fabric_options_set_cntlid(
		struct nvme_fabric_options *p,
		bool cntlid)
{
	p->cntlid = cntlid;
}

__public bool nvme_fabric_options_get_cntlid(
		const struct nvme_fabric_options *p)
{
	return p->cntlid;
}

__public void nvme_fabric_options_set_concat(
		struct nvme_fabric_options *p,
		bool concat)
{
	p->concat = concat;
}

__public bool nvme_fabric_options_get_concat(
		const struct nvme_fabric_options *p)
{
	return p->concat;
}

__public void nvme_fabric_options_set_ctrl_loss_tmo(
		struct nvme_fabric_options *p,
		bool ctrl_loss_tmo)
{
	p->ctrl_loss_tmo = ctrl_loss_tmo;
}

__public bool nvme_fabric_options_get_ctrl_loss_tmo(
		const struct nvme_fabric_options *p)
{
	return p->ctrl_loss_tmo;
}

__public void nvme_fabric_options_set_data_digest(
		struct nvme_fabric_options *p,
		bool data_digest)
{
	p->data_digest = data_digest;
}

__public bool nvme_fabric_options_get_data_digest(
		const struct nvme_fabric_options *p)
{
	return p->data_digest;
}

__public void nvme_fabric_options_set_dhchap_ctrl_secret(
		struct nvme_fabric_options *p,
		bool dhchap_ctrl_secret)
{
	p->dhchap_ctrl_secret = dhchap_ctrl_secret;
}

__public bool nvme_fabric_options_get_dhchap_ctrl_secret(
		const struct nvme_fabric_options *p)
{
	return p->dhchap_ctrl_secret;
}

__public void nvme_fabric_options_set_dhchap_secret(
		struct nvme_fabric_options *p,
		bool dhchap_secret)
{
	p->dhchap_secret = dhchap_secret;
}

__public bool nvme_fabric_options_get_dhchap_secret(
		const struct nvme_fabric_options *p)
{
	return p->dhchap_secret;
}

__public void nvme_fabric_options_set_disable_sqflow(
		struct nvme_fabric_options *p,
		bool disable_sqflow)
{
	p->disable_sqflow = disable_sqflow;
}

__public bool nvme_fabric_options_get_disable_sqflow(
		const struct nvme_fabric_options *p)
{
	return p->disable_sqflow;
}

__public void nvme_fabric_options_set_discovery(
		struct nvme_fabric_options *p,
		bool discovery)
{
	p->discovery = discovery;
}

__public bool nvme_fabric_options_get_discovery(
		const struct nvme_fabric_options *p)
{
	return p->discovery;
}

__public void nvme_fabric_options_set_duplicate_connect(
		struct nvme_fabric_options *p,
		bool duplicate_connect)
{
	p->duplicate_connect = duplicate_connect;
}

__public bool nvme_fabric_options_get_duplicate_connect(
		const struct nvme_fabric_options *p)
{
	return p->duplicate_connect;
}

__public void nvme_fabric_options_set_fast_io_fail_tmo(
		struct nvme_fabric_options *p,
		bool fast_io_fail_tmo)
{
	p->fast_io_fail_tmo = fast_io_fail_tmo;
}

__public bool nvme_fabric_options_get_fast_io_fail_tmo(
		const struct nvme_fabric_options *p)
{
	return p->fast_io_fail_tmo;
}

__public void nvme_fabric_options_set_hdr_digest(
		struct nvme_fabric_options *p,
		bool hdr_digest)
{
	p->hdr_digest = hdr_digest;
}

__public bool nvme_fabric_options_get_hdr_digest(
		const struct nvme_fabric_options *p)
{
	return p->hdr_digest;
}

__public void nvme_fabric_options_set_host_iface(
		struct nvme_fabric_options *p,
		bool host_iface)
{
	p->host_iface = host_iface;
}

__public bool nvme_fabric_options_get_host_iface(
		const struct nvme_fabric_options *p)
{
	return p->host_iface;
}

__public void nvme_fabric_options_set_host_traddr(
		struct nvme_fabric_options *p,
		bool host_traddr)
{
	p->host_traddr = host_traddr;
}

__public bool nvme_fabric_options_get_host_traddr(
		const struct nvme_fabric_options *p)
{
	return p->host_traddr;
}

__public void nvme_fabric_options_set_hostnqn(
		struct nvme_fabric_options *p,
		bool hostnqn)
{
	p->hostnqn = hostnqn;
}

__public bool nvme_fabric_options_get_hostnqn(
		const struct nvme_fabric_options *p)
{
	return p->hostnqn;
}

__public void nvme_fabric_options_set_instance(
		struct nvme_fabric_options *p,
		bool instance)
{
	p->instance = instance;
}

__public bool nvme_fabric_options_get_instance(
		const struct nvme_fabric_options *p)
{
	return p->instance;
}

__public void nvme_fabric_options_set_keep_alive_tmo(
		struct nvme_fabric_options *p,
		bool keep_alive_tmo)
{
	p->keep_alive_tmo = keep_alive_tmo;
}

__public bool nvme_fabric_options_get_keep_alive_tmo(
		const struct nvme_fabric_options *p)
{
	return p->keep_alive_tmo;
}

__public void nvme_fabric_options_set_keyring(
		struct nvme_fabric_options *p,
		bool keyring)
{
	p->keyring = keyring;
}

__public bool nvme_fabric_options_get_keyring(
		const struct nvme_fabric_options *p)
{
	return p->keyring;
}

__public void nvme_fabric_options_set_nqn(
		struct nvme_fabric_options *p,
		bool nqn)
{
	p->nqn = nqn;
}

__public bool nvme_fabric_options_get_nqn(const struct nvme_fabric_options *p)
{
	return p->nqn;
}

__public void nvme_fabric_options_set_nr_io_queues(
		struct nvme_fabric_options *p,
		bool nr_io_queues)
{
	p->nr_io_queues = nr_io_queues;
}

__public bool nvme_fabric_options_get_nr_io_queues(
		const struct nvme_fabric_options *p)
{
	return p->nr_io_queues;
}

__public void nvme_fabric_options_set_nr_poll_queues(
		struct nvme_fabric_options *p,
		bool nr_poll_queues)
{
	p->nr_poll_queues = nr_poll_queues;
}

__public bool nvme_fabric_options_get_nr_poll_queues(
		const struct nvme_fabric_options *p)
{
	return p->nr_poll_queues;
}

__public void nvme_fabric_options_set_nr_write_queues(
		struct nvme_fabric_options *p,
		bool nr_write_queues)
{
	p->nr_write_queues = nr_write_queues;
}

__public bool nvme_fabric_options_get_nr_write_queues(
		const struct nvme_fabric_options *p)
{
	return p->nr_write_queues;
}

__public void nvme_fabric_options_set_queue_size(
		struct nvme_fabric_options *p,
		bool queue_size)
{
	p->queue_size = queue_size;
}

__public bool nvme_fabric_options_get_queue_size(
		const struct nvme_fabric_options *p)
{
	return p->queue_size;
}

__public void nvme_fabric_options_set_reconnect_delay(
		struct nvme_fabric_options *p,
		bool reconnect_delay)
{
	p->reconnect_delay = reconnect_delay;
}

__public bool nvme_fabric_options_get_reconnect_delay(
		const struct nvme_fabric_options *p)
{
	return p->reconnect_delay;
}

__public void nvme_fabric_options_set_tls(
		struct nvme_fabric_options *p,
		bool tls)
{
	p->tls = tls;
}

__public bool nvme_fabric_options_get_tls(const struct nvme_fabric_options *p)
{
	return p->tls;
}

__public void nvme_fabric_options_set_tls_key(
		struct nvme_fabric_options *p,
		bool tls_key)
{
	p->tls_key = tls_key;
}

__public bool nvme_fabric_options_get_tls_key(
		const struct nvme_fabric_options *p)
{
	return p->tls_key;
}

__public void nvme_fabric_options_set_tos(
		struct nvme_fabric_options *p,
		bool tos)
{
	p->tos = tos;
}

__public bool nvme_fabric_options_get_tos(const struct nvme_fabric_options *p)
{
	return p->tos;
}

__public void nvme_fabric_options_set_traddr(
		struct nvme_fabric_options *p,
		bool traddr)
{
	p->traddr = traddr;
}

__public bool nvme_fabric_options_get_traddr(
		const struct nvme_fabric_options *p)
{
	return p->traddr;
}

__public void nvme_fabric_options_set_transport(
		struct nvme_fabric_options *p,
		bool transport)
{
	p->transport = transport;
}

__public bool nvme_fabric_options_get_transport(
		const struct nvme_fabric_options *p)
{
	return p->transport;
}

__public void nvme_fabric_options_set_trsvcid(
		struct nvme_fabric_options *p,
		bool trsvcid)
{
	p->trsvcid = trsvcid;
}

__public bool nvme_fabric_options_get_trsvcid(
		const struct nvme_fabric_options *p)
{
	return p->trsvcid;
}

