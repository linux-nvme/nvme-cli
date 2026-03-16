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

/****************************************************************************
 * Accessors for: struct nvme_path
 ****************************************************************************/

void nvme_path_set_name(struct nvme_path *p, const char *name)
{
	free(p->name);
	p->name = name ? strdup(name) : NULL;
}

const char *nvme_path_get_name(const struct nvme_path *p)
{
	return p->name;
}

void nvme_path_set_sysfs_dir(struct nvme_path *p, const char *sysfs_dir)
{
	free(p->sysfs_dir);
	p->sysfs_dir = sysfs_dir ? strdup(sysfs_dir) : NULL;
}

const char *nvme_path_get_sysfs_dir(const struct nvme_path *p)
{
	return p->sysfs_dir;
}

void nvme_path_set_ana_state(struct nvme_path *p, const char *ana_state)
{
	free(p->ana_state);
	p->ana_state = ana_state ? strdup(ana_state) : NULL;
}

const char *nvme_path_get_ana_state(const struct nvme_path *p)
{
	return p->ana_state;
}

void nvme_path_set_numa_nodes(struct nvme_path *p, const char *numa_nodes)
{
	free(p->numa_nodes);
	p->numa_nodes = numa_nodes ? strdup(numa_nodes) : NULL;
}

const char *nvme_path_get_numa_nodes(const struct nvme_path *p)
{
	return p->numa_nodes;
}

void nvme_path_set_grpid(struct nvme_path *p, int grpid)
{
	p->grpid = grpid;
}

int nvme_path_get_grpid(const struct nvme_path *p)
{
	return p->grpid;
}

/****************************************************************************
 * Accessors for: struct nvme_ns
 ****************************************************************************/

void nvme_ns_set_nsid(struct nvme_ns *p, __u32 nsid)
{
	p->nsid = nsid;
}

__u32 nvme_ns_get_nsid(const struct nvme_ns *p)
{
	return p->nsid;
}

void nvme_ns_set_name(struct nvme_ns *p, const char *name)
{
	free(p->name);
	p->name = name ? strdup(name) : NULL;
}

const char *nvme_ns_get_name(const struct nvme_ns *p)
{
	return p->name;
}

void nvme_ns_set_sysfs_dir(struct nvme_ns *p, const char *sysfs_dir)
{
	free(p->sysfs_dir);
	p->sysfs_dir = sysfs_dir ? strdup(sysfs_dir) : NULL;
}

const char *nvme_ns_get_sysfs_dir(const struct nvme_ns *p)
{
	return p->sysfs_dir;
}

void nvme_ns_set_lba_shift(struct nvme_ns *p, int lba_shift)
{
	p->lba_shift = lba_shift;
}

int nvme_ns_get_lba_shift(const struct nvme_ns *p)
{
	return p->lba_shift;
}

void nvme_ns_set_lba_size(struct nvme_ns *p, int lba_size)
{
	p->lba_size = lba_size;
}

int nvme_ns_get_lba_size(const struct nvme_ns *p)
{
	return p->lba_size;
}

void nvme_ns_set_meta_size(struct nvme_ns *p, int meta_size)
{
	p->meta_size = meta_size;
}

int nvme_ns_get_meta_size(const struct nvme_ns *p)
{
	return p->meta_size;
}

void nvme_ns_set_lba_count(struct nvme_ns *p, uint64_t lba_count)
{
	p->lba_count = lba_count;
}

uint64_t nvme_ns_get_lba_count(const struct nvme_ns *p)
{
	return p->lba_count;
}

void nvme_ns_set_lba_util(struct nvme_ns *p, uint64_t lba_util)
{
	p->lba_util = lba_util;
}

uint64_t nvme_ns_get_lba_util(const struct nvme_ns *p)
{
	return p->lba_util;
}

/****************************************************************************
 * Accessors for: struct nvme_ctrl
 ****************************************************************************/

void nvme_ctrl_set_name(struct nvme_ctrl *p, const char *name)
{
	free(p->name);
	p->name = name ? strdup(name) : NULL;
}

const char *nvme_ctrl_get_name(const struct nvme_ctrl *p)
{
	return p->name;
}

void nvme_ctrl_set_sysfs_dir(struct nvme_ctrl *p, const char *sysfs_dir)
{
	free(p->sysfs_dir);
	p->sysfs_dir = sysfs_dir ? strdup(sysfs_dir) : NULL;
}

const char *nvme_ctrl_get_sysfs_dir(const struct nvme_ctrl *p)
{
	return p->sysfs_dir;
}

void nvme_ctrl_set_firmware(struct nvme_ctrl *p, const char *firmware)
{
	free(p->firmware);
	p->firmware = firmware ? strdup(firmware) : NULL;
}

const char *nvme_ctrl_get_firmware(const struct nvme_ctrl *p)
{
	return p->firmware;
}

void nvme_ctrl_set_model(struct nvme_ctrl *p, const char *model)
{
	free(p->model);
	p->model = model ? strdup(model) : NULL;
}

const char *nvme_ctrl_get_model(const struct nvme_ctrl *p)
{
	return p->model;
}

void nvme_ctrl_set_numa_node(struct nvme_ctrl *p, const char *numa_node)
{
	free(p->numa_node);
	p->numa_node = numa_node ? strdup(numa_node) : NULL;
}

const char *nvme_ctrl_get_numa_node(const struct nvme_ctrl *p)
{
	return p->numa_node;
}

void nvme_ctrl_set_queue_count(struct nvme_ctrl *p, const char *queue_count)
{
	free(p->queue_count);
	p->queue_count = queue_count ? strdup(queue_count) : NULL;
}

const char *nvme_ctrl_get_queue_count(const struct nvme_ctrl *p)
{
	return p->queue_count;
}

void nvme_ctrl_set_serial(struct nvme_ctrl *p, const char *serial)
{
	free(p->serial);
	p->serial = serial ? strdup(serial) : NULL;
}

const char *nvme_ctrl_get_serial(const struct nvme_ctrl *p)
{
	return p->serial;
}

void nvme_ctrl_set_sqsize(struct nvme_ctrl *p, const char *sqsize)
{
	free(p->sqsize);
	p->sqsize = sqsize ? strdup(sqsize) : NULL;
}

const char *nvme_ctrl_get_sqsize(const struct nvme_ctrl *p)
{
	return p->sqsize;
}

void nvme_ctrl_set_transport(struct nvme_ctrl *p, const char *transport)
{
	free(p->transport);
	p->transport = transport ? strdup(transport) : NULL;
}

const char *nvme_ctrl_get_transport(const struct nvme_ctrl *p)
{
	return p->transport;
}

void nvme_ctrl_set_traddr(struct nvme_ctrl *p, const char *traddr)
{
	free(p->traddr);
	p->traddr = traddr ? strdup(traddr) : NULL;
}

const char *nvme_ctrl_get_traddr(const struct nvme_ctrl *p)
{
	return p->traddr;
}

void nvme_ctrl_set_trsvcid(struct nvme_ctrl *p, const char *trsvcid)
{
	free(p->trsvcid);
	p->trsvcid = trsvcid ? strdup(trsvcid) : NULL;
}

const char *nvme_ctrl_get_trsvcid(const struct nvme_ctrl *p)
{
	return p->trsvcid;
}

void nvme_ctrl_set_dhchap_host_key(
		struct nvme_ctrl *p,
		const char *dhchap_host_key)
{
	free(p->dhchap_host_key);
	p->dhchap_host_key = dhchap_host_key ? strdup(dhchap_host_key) : NULL;
}

const char *nvme_ctrl_get_dhchap_host_key(const struct nvme_ctrl *p)
{
	return p->dhchap_host_key;
}

void nvme_ctrl_set_dhchap_ctrl_key(
		struct nvme_ctrl *p,
		const char *dhchap_ctrl_key)
{
	free(p->dhchap_ctrl_key);
	p->dhchap_ctrl_key = dhchap_ctrl_key ? strdup(dhchap_ctrl_key) : NULL;
}

const char *nvme_ctrl_get_dhchap_ctrl_key(const struct nvme_ctrl *p)
{
	return p->dhchap_ctrl_key;
}

void nvme_ctrl_set_keyring(struct nvme_ctrl *p, const char *keyring)
{
	free(p->keyring);
	p->keyring = keyring ? strdup(keyring) : NULL;
}

const char *nvme_ctrl_get_keyring(const struct nvme_ctrl *p)
{
	return p->keyring;
}

void nvme_ctrl_set_tls_key_identity(
		struct nvme_ctrl *p,
		const char *tls_key_identity)
{
	free(p->tls_key_identity);
	p->tls_key_identity =
		tls_key_identity ? strdup(tls_key_identity) : NULL;
}

const char *nvme_ctrl_get_tls_key_identity(const struct nvme_ctrl *p)
{
	return p->tls_key_identity;
}

void nvme_ctrl_set_tls_key(struct nvme_ctrl *p, const char *tls_key)
{
	free(p->tls_key);
	p->tls_key = tls_key ? strdup(tls_key) : NULL;
}

const char *nvme_ctrl_get_tls_key(const struct nvme_ctrl *p)
{
	return p->tls_key;
}

void nvme_ctrl_set_cntrltype(struct nvme_ctrl *p, const char *cntrltype)
{
	free(p->cntrltype);
	p->cntrltype = cntrltype ? strdup(cntrltype) : NULL;
}

const char *nvme_ctrl_get_cntrltype(const struct nvme_ctrl *p)
{
	return p->cntrltype;
}

void nvme_ctrl_set_cntlid(struct nvme_ctrl *p, const char *cntlid)
{
	free(p->cntlid);
	p->cntlid = cntlid ? strdup(cntlid) : NULL;
}

const char *nvme_ctrl_get_cntlid(const struct nvme_ctrl *p)
{
	return p->cntlid;
}

void nvme_ctrl_set_dctype(struct nvme_ctrl *p, const char *dctype)
{
	free(p->dctype);
	p->dctype = dctype ? strdup(dctype) : NULL;
}

const char *nvme_ctrl_get_dctype(const struct nvme_ctrl *p)
{
	return p->dctype;
}

void nvme_ctrl_set_host_traddr(struct nvme_ctrl *p, const char *host_traddr)
{
	free(p->host_traddr);
	p->host_traddr = host_traddr ? strdup(host_traddr) : NULL;
}

const char *nvme_ctrl_get_host_traddr(const struct nvme_ctrl *p)
{
	return p->host_traddr;
}

void nvme_ctrl_set_host_iface(struct nvme_ctrl *p, const char *host_iface)
{
	free(p->host_iface);
	p->host_iface = host_iface ? strdup(host_iface) : NULL;
}

const char *nvme_ctrl_get_host_iface(const struct nvme_ctrl *p)
{
	return p->host_iface;
}

void nvme_ctrl_set_discovery_ctrl(struct nvme_ctrl *p, bool discovery_ctrl)
{
	p->discovery_ctrl = discovery_ctrl;
}

bool nvme_ctrl_get_discovery_ctrl(const struct nvme_ctrl *p)
{
	return p->discovery_ctrl;
}

void nvme_ctrl_set_unique_discovery_ctrl(
		struct nvme_ctrl *p,
		bool unique_discovery_ctrl)
{
	p->unique_discovery_ctrl = unique_discovery_ctrl;
}

bool nvme_ctrl_get_unique_discovery_ctrl(const struct nvme_ctrl *p)
{
	return p->unique_discovery_ctrl;
}

void nvme_ctrl_set_discovered(struct nvme_ctrl *p, bool discovered)
{
	p->discovered = discovered;
}

bool nvme_ctrl_get_discovered(const struct nvme_ctrl *p)
{
	return p->discovered;
}

void nvme_ctrl_set_persistent(struct nvme_ctrl *p, bool persistent)
{
	p->persistent = persistent;
}

bool nvme_ctrl_get_persistent(const struct nvme_ctrl *p)
{
	return p->persistent;
}

/****************************************************************************
 * Accessors for: struct nvme_subsystem
 ****************************************************************************/

void nvme_subsystem_set_name(struct nvme_subsystem *p, const char *name)
{
	free(p->name);
	p->name = name ? strdup(name) : NULL;
}

const char *nvme_subsystem_get_name(const struct nvme_subsystem *p)
{
	return p->name;
}

void nvme_subsystem_set_sysfs_dir(
		struct nvme_subsystem *p,
		const char *sysfs_dir)
{
	free(p->sysfs_dir);
	p->sysfs_dir = sysfs_dir ? strdup(sysfs_dir) : NULL;
}

const char *nvme_subsystem_get_sysfs_dir(const struct nvme_subsystem *p)
{
	return p->sysfs_dir;
}

void nvme_subsystem_set_subsysnqn(
		struct nvme_subsystem *p,
		const char *subsysnqn)
{
	free(p->subsysnqn);
	p->subsysnqn = subsysnqn ? strdup(subsysnqn) : NULL;
}

const char *nvme_subsystem_get_subsysnqn(const struct nvme_subsystem *p)
{
	return p->subsysnqn;
}

void nvme_subsystem_set_model(struct nvme_subsystem *p, const char *model)
{
	free(p->model);
	p->model = model ? strdup(model) : NULL;
}

const char *nvme_subsystem_get_model(const struct nvme_subsystem *p)
{
	return p->model;
}

void nvme_subsystem_set_serial(struct nvme_subsystem *p, const char *serial)
{
	free(p->serial);
	p->serial = serial ? strdup(serial) : NULL;
}

const char *nvme_subsystem_get_serial(const struct nvme_subsystem *p)
{
	return p->serial;
}

void nvme_subsystem_set_firmware(struct nvme_subsystem *p, const char *firmware)
{
	free(p->firmware);
	p->firmware = firmware ? strdup(firmware) : NULL;
}

const char *nvme_subsystem_get_firmware(const struct nvme_subsystem *p)
{
	return p->firmware;
}

void nvme_subsystem_set_subsystype(
		struct nvme_subsystem *p,
		const char *subsystype)
{
	free(p->subsystype);
	p->subsystype = subsystype ? strdup(subsystype) : NULL;
}

const char *nvme_subsystem_get_subsystype(const struct nvme_subsystem *p)
{
	return p->subsystype;
}

void nvme_subsystem_set_application(
		struct nvme_subsystem *p,
		const char *application)
{
	free(p->application);
	p->application = application ? strdup(application) : NULL;
}

const char *nvme_subsystem_get_application(const struct nvme_subsystem *p)
{
	return p->application;
}

void nvme_subsystem_set_iopolicy(struct nvme_subsystem *p, const char *iopolicy)
{
	free(p->iopolicy);
	p->iopolicy = iopolicy ? strdup(iopolicy) : NULL;
}

const char *nvme_subsystem_get_iopolicy(const struct nvme_subsystem *p)
{
	return p->iopolicy;
}

/****************************************************************************
 * Accessors for: struct nvme_host
 ****************************************************************************/

void nvme_host_set_hostnqn(struct nvme_host *p, const char *hostnqn)
{
	free(p->hostnqn);
	p->hostnqn = hostnqn ? strdup(hostnqn) : NULL;
}

const char *nvme_host_get_hostnqn(const struct nvme_host *p)
{
	return p->hostnqn;
}

void nvme_host_set_hostid(struct nvme_host *p, const char *hostid)
{
	free(p->hostid);
	p->hostid = hostid ? strdup(hostid) : NULL;
}

const char *nvme_host_get_hostid(const struct nvme_host *p)
{
	return p->hostid;
}

void nvme_host_set_dhchap_host_key(
		struct nvme_host *p,
		const char *dhchap_host_key)
{
	free(p->dhchap_host_key);
	p->dhchap_host_key = dhchap_host_key ? strdup(dhchap_host_key) : NULL;
}

const char *nvme_host_get_dhchap_host_key(const struct nvme_host *p)
{
	return p->dhchap_host_key;
}

void nvme_host_set_hostsymname(struct nvme_host *p, const char *hostsymname)
{
	free(p->hostsymname);
	p->hostsymname = hostsymname ? strdup(hostsymname) : NULL;
}

const char *nvme_host_get_hostsymname(const struct nvme_host *p)
{
	return p->hostsymname;
}

void nvme_host_set_pdc_enabled_valid(
		struct nvme_host *p,
		bool pdc_enabled_valid)
{
	p->pdc_enabled_valid = pdc_enabled_valid;
}

bool nvme_host_get_pdc_enabled_valid(const struct nvme_host *p)
{
	return p->pdc_enabled_valid;
}

/****************************************************************************
 * Accessors for: struct nvme_fabric_options
 ****************************************************************************/

void nvme_fabric_options_set_cntlid(struct nvme_fabric_options *p, bool cntlid)
{
	p->cntlid = cntlid;
}

bool nvme_fabric_options_get_cntlid(const struct nvme_fabric_options *p)
{
	return p->cntlid;
}

void nvme_fabric_options_set_concat(struct nvme_fabric_options *p, bool concat)
{
	p->concat = concat;
}

bool nvme_fabric_options_get_concat(const struct nvme_fabric_options *p)
{
	return p->concat;
}

void nvme_fabric_options_set_ctrl_loss_tmo(
		struct nvme_fabric_options *p,
		bool ctrl_loss_tmo)
{
	p->ctrl_loss_tmo = ctrl_loss_tmo;
}

bool nvme_fabric_options_get_ctrl_loss_tmo(const struct nvme_fabric_options *p)
{
	return p->ctrl_loss_tmo;
}

void nvme_fabric_options_set_data_digest(
		struct nvme_fabric_options *p,
		bool data_digest)
{
	p->data_digest = data_digest;
}

bool nvme_fabric_options_get_data_digest(const struct nvme_fabric_options *p)
{
	return p->data_digest;
}

void nvme_fabric_options_set_dhchap_ctrl_secret(
		struct nvme_fabric_options *p,
		bool dhchap_ctrl_secret)
{
	p->dhchap_ctrl_secret = dhchap_ctrl_secret;
}

bool nvme_fabric_options_get_dhchap_ctrl_secret(
		const struct nvme_fabric_options *p)
{
	return p->dhchap_ctrl_secret;
}

void nvme_fabric_options_set_dhchap_secret(
		struct nvme_fabric_options *p,
		bool dhchap_secret)
{
	p->dhchap_secret = dhchap_secret;
}

bool nvme_fabric_options_get_dhchap_secret(const struct nvme_fabric_options *p)
{
	return p->dhchap_secret;
}

void nvme_fabric_options_set_disable_sqflow(
		struct nvme_fabric_options *p,
		bool disable_sqflow)
{
	p->disable_sqflow = disable_sqflow;
}

bool nvme_fabric_options_get_disable_sqflow(const struct nvme_fabric_options *p)
{
	return p->disable_sqflow;
}

void nvme_fabric_options_set_discovery(
		struct nvme_fabric_options *p,
		bool discovery)
{
	p->discovery = discovery;
}

bool nvme_fabric_options_get_discovery(const struct nvme_fabric_options *p)
{
	return p->discovery;
}

void nvme_fabric_options_set_duplicate_connect(
		struct nvme_fabric_options *p,
		bool duplicate_connect)
{
	p->duplicate_connect = duplicate_connect;
}

bool nvme_fabric_options_get_duplicate_connect(
		const struct nvme_fabric_options *p)
{
	return p->duplicate_connect;
}

void nvme_fabric_options_set_fast_io_fail_tmo(
		struct nvme_fabric_options *p,
		bool fast_io_fail_tmo)
{
	p->fast_io_fail_tmo = fast_io_fail_tmo;
}

bool nvme_fabric_options_get_fast_io_fail_tmo(
		const struct nvme_fabric_options *p)
{
	return p->fast_io_fail_tmo;
}

void nvme_fabric_options_set_hdr_digest(
		struct nvme_fabric_options *p,
		bool hdr_digest)
{
	p->hdr_digest = hdr_digest;
}

bool nvme_fabric_options_get_hdr_digest(const struct nvme_fabric_options *p)
{
	return p->hdr_digest;
}

void nvme_fabric_options_set_host_iface(
		struct nvme_fabric_options *p,
		bool host_iface)
{
	p->host_iface = host_iface;
}

bool nvme_fabric_options_get_host_iface(const struct nvme_fabric_options *p)
{
	return p->host_iface;
}

void nvme_fabric_options_set_host_traddr(
		struct nvme_fabric_options *p,
		bool host_traddr)
{
	p->host_traddr = host_traddr;
}

bool nvme_fabric_options_get_host_traddr(const struct nvme_fabric_options *p)
{
	return p->host_traddr;
}

void nvme_fabric_options_set_hostid(struct nvme_fabric_options *p, bool hostid)
{
	p->hostid = hostid;
}

bool nvme_fabric_options_get_hostid(const struct nvme_fabric_options *p)
{
	return p->hostid;
}

void nvme_fabric_options_set_hostnqn(
		struct nvme_fabric_options *p,
		bool hostnqn)
{
	p->hostnqn = hostnqn;
}

bool nvme_fabric_options_get_hostnqn(const struct nvme_fabric_options *p)
{
	return p->hostnqn;
}

void nvme_fabric_options_set_instance(
		struct nvme_fabric_options *p,
		bool instance)
{
	p->instance = instance;
}

bool nvme_fabric_options_get_instance(const struct nvme_fabric_options *p)
{
	return p->instance;
}

void nvme_fabric_options_set_keep_alive_tmo(
		struct nvme_fabric_options *p,
		bool keep_alive_tmo)
{
	p->keep_alive_tmo = keep_alive_tmo;
}

bool nvme_fabric_options_get_keep_alive_tmo(const struct nvme_fabric_options *p)
{
	return p->keep_alive_tmo;
}

void nvme_fabric_options_set_keyring(
		struct nvme_fabric_options *p,
		bool keyring)
{
	p->keyring = keyring;
}

bool nvme_fabric_options_get_keyring(const struct nvme_fabric_options *p)
{
	return p->keyring;
}

void nvme_fabric_options_set_nqn(struct nvme_fabric_options *p, bool nqn)
{
	p->nqn = nqn;
}

bool nvme_fabric_options_get_nqn(const struct nvme_fabric_options *p)
{
	return p->nqn;
}

void nvme_fabric_options_set_nr_io_queues(
		struct nvme_fabric_options *p,
		bool nr_io_queues)
{
	p->nr_io_queues = nr_io_queues;
}

bool nvme_fabric_options_get_nr_io_queues(const struct nvme_fabric_options *p)
{
	return p->nr_io_queues;
}

void nvme_fabric_options_set_nr_poll_queues(
		struct nvme_fabric_options *p,
		bool nr_poll_queues)
{
	p->nr_poll_queues = nr_poll_queues;
}

bool nvme_fabric_options_get_nr_poll_queues(const struct nvme_fabric_options *p)
{
	return p->nr_poll_queues;
}

void nvme_fabric_options_set_nr_write_queues(
		struct nvme_fabric_options *p,
		bool nr_write_queues)
{
	p->nr_write_queues = nr_write_queues;
}

bool nvme_fabric_options_get_nr_write_queues(
		const struct nvme_fabric_options *p)
{
	return p->nr_write_queues;
}

void nvme_fabric_options_set_queue_size(
		struct nvme_fabric_options *p,
		bool queue_size)
{
	p->queue_size = queue_size;
}

bool nvme_fabric_options_get_queue_size(const struct nvme_fabric_options *p)
{
	return p->queue_size;
}

void nvme_fabric_options_set_reconnect_delay(
		struct nvme_fabric_options *p,
		bool reconnect_delay)
{
	p->reconnect_delay = reconnect_delay;
}

bool nvme_fabric_options_get_reconnect_delay(
		const struct nvme_fabric_options *p)
{
	return p->reconnect_delay;
}

void nvme_fabric_options_set_tls(struct nvme_fabric_options *p, bool tls)
{
	p->tls = tls;
}

bool nvme_fabric_options_get_tls(const struct nvme_fabric_options *p)
{
	return p->tls;
}

void nvme_fabric_options_set_tls_key(
		struct nvme_fabric_options *p,
		bool tls_key)
{
	p->tls_key = tls_key;
}

bool nvme_fabric_options_get_tls_key(const struct nvme_fabric_options *p)
{
	return p->tls_key;
}

void nvme_fabric_options_set_tos(struct nvme_fabric_options *p, bool tos)
{
	p->tos = tos;
}

bool nvme_fabric_options_get_tos(const struct nvme_fabric_options *p)
{
	return p->tos;
}

void nvme_fabric_options_set_traddr(struct nvme_fabric_options *p, bool traddr)
{
	p->traddr = traddr;
}

bool nvme_fabric_options_get_traddr(const struct nvme_fabric_options *p)
{
	return p->traddr;
}

void nvme_fabric_options_set_transport(
		struct nvme_fabric_options *p,
		bool transport)
{
	p->transport = transport;
}

bool nvme_fabric_options_get_transport(const struct nvme_fabric_options *p)
{
	return p->transport;
}

void nvme_fabric_options_set_trsvcid(
		struct nvme_fabric_options *p,
		bool trsvcid)
{
	p->trsvcid = trsvcid;
}

bool nvme_fabric_options_get_trsvcid(const struct nvme_fabric_options *p)
{
	return p->trsvcid;
}

