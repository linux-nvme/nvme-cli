// SPDX-License-Identifier: LGPL-2.1-or-later

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
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <compiler-attributes.h>

#include "accessors.h"

#include "private.h"

/****************************************************************************
 * Accessors for: struct libnvme_path
 ****************************************************************************/

__shr_public void libnvme_path_set_name(
		struct libnvme_path *p,
		const char *name)
{
	free(p->name);
	p->name = name ? strdup(name) : NULL;
}

__shr_public const char *libnvme_path_get_name(const struct libnvme_path *p)
{
	return p->name;
}

__shr_public void libnvme_path_set_sysfs_dir(
		struct libnvme_path *p,
		const char *sysfs_dir)
{
	free(p->sysfs_dir);
	p->sysfs_dir = sysfs_dir ? strdup(sysfs_dir) : NULL;
}

__shr_public const char *libnvme_path_get_sysfs_dir(
		const struct libnvme_path *p)
{
	return p->sysfs_dir;
}

/****************************************************************************
 * Accessors for: struct libnvme_ns
 ****************************************************************************/

__shr_public void libnvme_ns_set_nsid(struct libnvme_ns *p, __u32 nsid)
{
	p->nsid = nsid;
}

__shr_public __u32 libnvme_ns_get_nsid(const struct libnvme_ns *p)
{
	return p->nsid;
}

__shr_public const char *libnvme_ns_get_name(const struct libnvme_ns *p)
{
	return p->name;
}

__shr_public const char *libnvme_ns_get_generic_name(const struct libnvme_ns *p)
{
	return p->generic_name;
}

__shr_public void libnvme_ns_set_sysfs_dir(
		struct libnvme_ns *p,
		const char *sysfs_dir)
{
	free(p->sysfs_dir);
	p->sysfs_dir = sysfs_dir ? strdup(sysfs_dir) : NULL;
}

__shr_public const char *libnvme_ns_get_sysfs_dir(const struct libnvme_ns *p)
{
	return p->sysfs_dir;
}

/****************************************************************************
 * Accessors for: struct libnvme_ctrl
 ****************************************************************************/

__shr_public const char *libnvme_ctrl_get_name(const struct libnvme_ctrl *p)
{
	return p->name;
}

__shr_public const char *libnvme_ctrl_get_sysfs_dir(
		const struct libnvme_ctrl *p)
{
	return p->sysfs_dir;
}

__shr_public const char *libnvme_ctrl_get_address(const struct libnvme_ctrl *p)
{
	return p->address;
}

__shr_public const char *libnvme_ctrl_get_transport(
		const struct libnvme_ctrl *p)
{
	return p->transport;
}

__shr_public const char *libnvme_ctrl_get_subsysnqn(
		const struct libnvme_ctrl *p)
{
	return p->subsysnqn;
}

__shr_public const char *libnvme_ctrl_get_traddr(const struct libnvme_ctrl *p)
{
	return p->traddr;
}

__shr_public const char *libnvme_ctrl_get_trsvcid(const struct libnvme_ctrl *p)
{
	return p->trsvcid;
}

__shr_public void libnvme_ctrl_set_tls_key_identity(
		struct libnvme_ctrl *p,
		const char *tls_key_identity)
{
	free(p->tls_key_identity);
	p->tls_key_identity =
		tls_key_identity ? strdup(tls_key_identity) : NULL;
}

__shr_public const char *libnvme_ctrl_get_tls_key_identity(
		const struct libnvme_ctrl *p)
{
	return p->tls_key_identity;
}

__shr_public void libnvme_ctrl_set_tls_key(
		struct libnvme_ctrl *p,
		const char *tls_key)
{
	free(p->tls_key);
	p->tls_key = tls_key ? strdup(tls_key) : NULL;
}

__shr_public const char *libnvme_ctrl_get_tls_key(const struct libnvme_ctrl *p)
{
	return p->tls_key;
}

__shr_public const char *libnvme_ctrl_get_host_traddr(
		const struct libnvme_ctrl *p)
{
	return p->host_traddr;
}

__shr_public const char *libnvme_ctrl_get_host_iface(
		const struct libnvme_ctrl *p)
{
	return p->host_iface;
}

__shr_public void libnvme_ctrl_set_discovery_ctrl(
		struct libnvme_ctrl *p,
		bool discovery_ctrl)
{
	p->discovery_ctrl = discovery_ctrl;
}

__shr_public bool libnvme_ctrl_get_discovery_ctrl(const struct libnvme_ctrl *p)
{
	return p->discovery_ctrl;
}

__shr_public void libnvme_ctrl_set_unique_discovery_ctrl(
		struct libnvme_ctrl *p,
		bool unique_discovery_ctrl)
{
	p->unique_discovery_ctrl = unique_discovery_ctrl;
}

__shr_public bool libnvme_ctrl_get_unique_discovery_ctrl(
		const struct libnvme_ctrl *p)
{
	return p->unique_discovery_ctrl;
}

__shr_public void libnvme_ctrl_set_discovered(
		struct libnvme_ctrl *p,
		bool discovered)
{
	p->discovered = discovered;
}

__shr_public bool libnvme_ctrl_get_discovered(const struct libnvme_ctrl *p)
{
	return p->discovered;
}

__shr_public void libnvme_ctrl_set_persistent(
		struct libnvme_ctrl *p,
		bool persistent)
{
	p->persistent = persistent;
}

__shr_public bool libnvme_ctrl_get_persistent(const struct libnvme_ctrl *p)
{
	return p->persistent;
}

__shr_public int libnvme_ctrl_get_queue_size(const struct libnvme_ctrl *p)
{
	return p->cfg.queue_size;
}

__shr_public int libnvme_ctrl_get_nr_io_queues(const struct libnvme_ctrl *p)
{
	return p->cfg.nr_io_queues;
}

__shr_public int libnvme_ctrl_get_reconnect_delay(const struct libnvme_ctrl *p)
{
	return p->cfg.reconnect_delay;
}

__shr_public int libnvme_ctrl_get_ctrl_loss_tmo(const struct libnvme_ctrl *p)
{
	return p->cfg.ctrl_loss_tmo;
}

__shr_public int libnvme_ctrl_get_fast_io_fail_tmo(const struct libnvme_ctrl *p)
{
	return p->cfg.fast_io_fail_tmo;
}

__shr_public int libnvme_ctrl_get_keep_alive_tmo(const struct libnvme_ctrl *p)
{
	return p->cfg.keep_alive_tmo;
}

__shr_public int libnvme_ctrl_get_nr_write_queues(const struct libnvme_ctrl *p)
{
	return p->cfg.nr_write_queues;
}

__shr_public int libnvme_ctrl_get_nr_poll_queues(const struct libnvme_ctrl *p)
{
	return p->cfg.nr_poll_queues;
}

__shr_public int libnvme_ctrl_get_tos(const struct libnvme_ctrl *p)
{
	return p->cfg.tos;
}

__shr_public long libnvme_ctrl_get_keyring_id(const struct libnvme_ctrl *p)
{
	return p->cfg.keyring_id;
}

__shr_public long libnvme_ctrl_get_tls_key_id(const struct libnvme_ctrl *p)
{
	return p->cfg.tls_key_id;
}

__shr_public long libnvme_ctrl_get_tls_configured_key_id(
		const struct libnvme_ctrl *p)
{
	return p->cfg.tls_configured_key_id;
}

__shr_public bool libnvme_ctrl_get_duplicate_connect(
		const struct libnvme_ctrl *p)
{
	return p->cfg.duplicate_connect;
}

__shr_public bool libnvme_ctrl_get_disable_sqflow(const struct libnvme_ctrl *p)
{
	return p->cfg.disable_sqflow;
}

__shr_public bool libnvme_ctrl_get_hdr_digest(const struct libnvme_ctrl *p)
{
	return p->cfg.hdr_digest;
}

__shr_public bool libnvme_ctrl_get_data_digest(const struct libnvme_ctrl *p)
{
	return p->cfg.data_digest;
}

__shr_public bool libnvme_ctrl_get_tls(const struct libnvme_ctrl *p)
{
	return p->cfg.tls;
}

__shr_public bool libnvme_ctrl_get_concat(const struct libnvme_ctrl *p)
{
	return p->cfg.concat;
}

/****************************************************************************
 * Accessors for: struct libnvme_subsystem
 ****************************************************************************/

__shr_public const char *libnvme_subsystem_get_name(
		const struct libnvme_subsystem *p)
{
	return p->name;
}

__shr_public const char *libnvme_subsystem_get_sysfs_dir(
		const struct libnvme_subsystem *p)
{
	return p->sysfs_dir;
}

__shr_public const char *libnvme_subsystem_get_subsysnqn(
		const struct libnvme_subsystem *p)
{
	return p->subsysnqn;
}

__shr_public const char *libnvme_subsystem_get_model(
		const struct libnvme_subsystem *p)
{
	return p->model;
}

__shr_public const char *libnvme_subsystem_get_serial(
		const struct libnvme_subsystem *p)
{
	return p->serial;
}

__shr_public const char *libnvme_subsystem_get_firmware(
		const struct libnvme_subsystem *p)
{
	return p->firmware;
}

__shr_public const char *libnvme_subsystem_get_subsystype(
		const struct libnvme_subsystem *p)
{
	return p->subsystype;
}

/****************************************************************************
 * Accessors for: struct libnvme_host
 ****************************************************************************/

__shr_public const char *libnvme_host_get_hostnqn(const struct libnvme_host *p)
{
	return p->hostnqn;
}

__shr_public const char *libnvme_host_get_hostid(const struct libnvme_host *p)
{
	return p->hostid;
}

__shr_public void libnvme_host_set_dhchap_host_key(
		struct libnvme_host *p,
		const char *dhchap_host_key)
{
	free(p->dhchap_host_key);
	p->dhchap_host_key = dhchap_host_key ? strdup(dhchap_host_key) : NULL;
}

__shr_public const char *libnvme_host_get_dhchap_host_key(
		const struct libnvme_host *p)
{
	return p->dhchap_host_key;
}

__shr_public void libnvme_host_set_hostsymname(
		struct libnvme_host *p,
		const char *hostsymname)
{
	free(p->hostsymname);
	p->hostsymname = hostsymname ? strdup(hostsymname) : NULL;
}

__shr_public const char *libnvme_host_get_hostsymname(
		const struct libnvme_host *p)
{
	return p->hostsymname;
}

/****************************************************************************
 * Accessors for: struct libnvme_fabric_options
 ****************************************************************************/

__shr_public void libnvme_fabric_options_set_cntlid(
		struct libnvme_fabric_options *p,
		bool cntlid)
{
	p->cntlid = cntlid;
}

__shr_public bool libnvme_fabric_options_get_cntlid(
		const struct libnvme_fabric_options *p)
{
	return p->cntlid;
}

__shr_public void libnvme_fabric_options_set_concat(
		struct libnvme_fabric_options *p,
		bool concat)
{
	p->concat = concat;
}

__shr_public bool libnvme_fabric_options_get_concat(
		const struct libnvme_fabric_options *p)
{
	return p->concat;
}

__shr_public void libnvme_fabric_options_set_ctrl_loss_tmo(
		struct libnvme_fabric_options *p,
		bool ctrl_loss_tmo)
{
	p->ctrl_loss_tmo = ctrl_loss_tmo;
}

__shr_public bool libnvme_fabric_options_get_ctrl_loss_tmo(
		const struct libnvme_fabric_options *p)
{
	return p->ctrl_loss_tmo;
}

__shr_public void libnvme_fabric_options_set_data_digest(
		struct libnvme_fabric_options *p,
		bool data_digest)
{
	p->data_digest = data_digest;
}

__shr_public bool libnvme_fabric_options_get_data_digest(
		const struct libnvme_fabric_options *p)
{
	return p->data_digest;
}

__shr_public void libnvme_fabric_options_set_dhchap_ctrl_secret(
		struct libnvme_fabric_options *p,
		bool dhchap_ctrl_secret)
{
	p->dhchap_ctrl_secret = dhchap_ctrl_secret;
}

__shr_public bool libnvme_fabric_options_get_dhchap_ctrl_secret(
		const struct libnvme_fabric_options *p)
{
	return p->dhchap_ctrl_secret;
}

__shr_public void libnvme_fabric_options_set_dhchap_secret(
		struct libnvme_fabric_options *p,
		bool dhchap_secret)
{
	p->dhchap_secret = dhchap_secret;
}

__shr_public bool libnvme_fabric_options_get_dhchap_secret(
		const struct libnvme_fabric_options *p)
{
	return p->dhchap_secret;
}

__shr_public void libnvme_fabric_options_set_disable_sqflow(
		struct libnvme_fabric_options *p,
		bool disable_sqflow)
{
	p->disable_sqflow = disable_sqflow;
}

__shr_public bool libnvme_fabric_options_get_disable_sqflow(
		const struct libnvme_fabric_options *p)
{
	return p->disable_sqflow;
}

__shr_public void libnvme_fabric_options_set_discovery(
		struct libnvme_fabric_options *p,
		bool discovery)
{
	p->discovery = discovery;
}

__shr_public bool libnvme_fabric_options_get_discovery(
		const struct libnvme_fabric_options *p)
{
	return p->discovery;
}

__shr_public void libnvme_fabric_options_set_duplicate_connect(
		struct libnvme_fabric_options *p,
		bool duplicate_connect)
{
	p->duplicate_connect = duplicate_connect;
}

__shr_public bool libnvme_fabric_options_get_duplicate_connect(
		const struct libnvme_fabric_options *p)
{
	return p->duplicate_connect;
}

__shr_public void libnvme_fabric_options_set_fast_io_fail_tmo(
		struct libnvme_fabric_options *p,
		bool fast_io_fail_tmo)
{
	p->fast_io_fail_tmo = fast_io_fail_tmo;
}

__shr_public bool libnvme_fabric_options_get_fast_io_fail_tmo(
		const struct libnvme_fabric_options *p)
{
	return p->fast_io_fail_tmo;
}

__shr_public void libnvme_fabric_options_set_hdr_digest(
		struct libnvme_fabric_options *p,
		bool hdr_digest)
{
	p->hdr_digest = hdr_digest;
}

__shr_public bool libnvme_fabric_options_get_hdr_digest(
		const struct libnvme_fabric_options *p)
{
	return p->hdr_digest;
}

__shr_public void libnvme_fabric_options_set_host_iface(
		struct libnvme_fabric_options *p,
		bool host_iface)
{
	p->host_iface = host_iface;
}

__shr_public bool libnvme_fabric_options_get_host_iface(
		const struct libnvme_fabric_options *p)
{
	return p->host_iface;
}

__shr_public void libnvme_fabric_options_set_host_traddr(
		struct libnvme_fabric_options *p,
		bool host_traddr)
{
	p->host_traddr = host_traddr;
}

__shr_public bool libnvme_fabric_options_get_host_traddr(
		const struct libnvme_fabric_options *p)
{
	return p->host_traddr;
}

__shr_public void libnvme_fabric_options_set_hostid(
		struct libnvme_fabric_options *p,
		bool hostid)
{
	p->hostid = hostid;
}

__shr_public bool libnvme_fabric_options_get_hostid(
		const struct libnvme_fabric_options *p)
{
	return p->hostid;
}

__shr_public void libnvme_fabric_options_set_hostnqn(
		struct libnvme_fabric_options *p,
		bool hostnqn)
{
	p->hostnqn = hostnqn;
}

__shr_public bool libnvme_fabric_options_get_hostnqn(
		const struct libnvme_fabric_options *p)
{
	return p->hostnqn;
}

__shr_public void libnvme_fabric_options_set_instance(
		struct libnvme_fabric_options *p,
		bool instance)
{
	p->instance = instance;
}

__shr_public bool libnvme_fabric_options_get_instance(
		const struct libnvme_fabric_options *p)
{
	return p->instance;
}

__shr_public void libnvme_fabric_options_set_keep_alive_tmo(
		struct libnvme_fabric_options *p,
		bool keep_alive_tmo)
{
	p->keep_alive_tmo = keep_alive_tmo;
}

__shr_public bool libnvme_fabric_options_get_keep_alive_tmo(
		const struct libnvme_fabric_options *p)
{
	return p->keep_alive_tmo;
}

__shr_public void libnvme_fabric_options_set_keyring(
		struct libnvme_fabric_options *p,
		bool keyring)
{
	p->keyring = keyring;
}

__shr_public bool libnvme_fabric_options_get_keyring(
		const struct libnvme_fabric_options *p)
{
	return p->keyring;
}

__shr_public void libnvme_fabric_options_set_nqn(
		struct libnvme_fabric_options *p,
		bool nqn)
{
	p->nqn = nqn;
}

__shr_public bool libnvme_fabric_options_get_nqn(
		const struct libnvme_fabric_options *p)
{
	return p->nqn;
}

__shr_public void libnvme_fabric_options_set_nr_io_queues(
		struct libnvme_fabric_options *p,
		bool nr_io_queues)
{
	p->nr_io_queues = nr_io_queues;
}

__shr_public bool libnvme_fabric_options_get_nr_io_queues(
		const struct libnvme_fabric_options *p)
{
	return p->nr_io_queues;
}

__shr_public void libnvme_fabric_options_set_nr_poll_queues(
		struct libnvme_fabric_options *p,
		bool nr_poll_queues)
{
	p->nr_poll_queues = nr_poll_queues;
}

__shr_public bool libnvme_fabric_options_get_nr_poll_queues(
		const struct libnvme_fabric_options *p)
{
	return p->nr_poll_queues;
}

__shr_public void libnvme_fabric_options_set_nr_write_queues(
		struct libnvme_fabric_options *p,
		bool nr_write_queues)
{
	p->nr_write_queues = nr_write_queues;
}

__shr_public bool libnvme_fabric_options_get_nr_write_queues(
		const struct libnvme_fabric_options *p)
{
	return p->nr_write_queues;
}

__shr_public void libnvme_fabric_options_set_queue_size(
		struct libnvme_fabric_options *p,
		bool queue_size)
{
	p->queue_size = queue_size;
}

__shr_public bool libnvme_fabric_options_get_queue_size(
		const struct libnvme_fabric_options *p)
{
	return p->queue_size;
}

__shr_public void libnvme_fabric_options_set_reconnect_delay(
		struct libnvme_fabric_options *p,
		bool reconnect_delay)
{
	p->reconnect_delay = reconnect_delay;
}

__shr_public bool libnvme_fabric_options_get_reconnect_delay(
		const struct libnvme_fabric_options *p)
{
	return p->reconnect_delay;
}

__shr_public void libnvme_fabric_options_set_tls(
		struct libnvme_fabric_options *p,
		bool tls)
{
	p->tls = tls;
}

__shr_public bool libnvme_fabric_options_get_tls(
		const struct libnvme_fabric_options *p)
{
	return p->tls;
}

__shr_public void libnvme_fabric_options_set_tls_key(
		struct libnvme_fabric_options *p,
		bool tls_key)
{
	p->tls_key = tls_key;
}

__shr_public bool libnvme_fabric_options_get_tls_key(
		const struct libnvme_fabric_options *p)
{
	return p->tls_key;
}

__shr_public void libnvme_fabric_options_set_tos(
		struct libnvme_fabric_options *p,
		bool tos)
{
	p->tos = tos;
}

__shr_public bool libnvme_fabric_options_get_tos(
		const struct libnvme_fabric_options *p)
{
	return p->tos;
}

__shr_public void libnvme_fabric_options_set_traddr(
		struct libnvme_fabric_options *p,
		bool traddr)
{
	p->traddr = traddr;
}

__shr_public bool libnvme_fabric_options_get_traddr(
		const struct libnvme_fabric_options *p)
{
	return p->traddr;
}

__shr_public void libnvme_fabric_options_set_transport(
		struct libnvme_fabric_options *p,
		bool transport)
{
	p->transport = transport;
}

__shr_public bool libnvme_fabric_options_get_transport(
		const struct libnvme_fabric_options *p)
{
	return p->transport;
}

__shr_public void libnvme_fabric_options_set_trsvcid(
		struct libnvme_fabric_options *p,
		bool trsvcid)
{
	p->trsvcid = trsvcid;
}

__shr_public bool libnvme_fabric_options_get_trsvcid(
		const struct libnvme_fabric_options *p)
{
	return p->trsvcid;
}

/****************************************************************************
 * Accessors for: struct libnvme_global_ctx
 ****************************************************************************/

__shr_public void libnvme_set_dry_run(
		struct libnvme_global_ctx *p,
		bool dry_run)
{
	p->dry_run = dry_run;
}

__shr_public bool libnvme_get_dry_run(const struct libnvme_global_ctx *p)
{
	return p->dry_run;
}

__shr_public void libnvme_set_force_4k(
		struct libnvme_global_ctx *p,
		bool force_4k)
{
	p->force_4k = force_4k;
}

__shr_public bool libnvme_get_force_4k(const struct libnvme_global_ctx *p)
{
	return p->force_4k;
}

__shr_public void libnvme_set_mi_probe_enabled(
		struct libnvme_global_ctx *p,
		bool mi_probe_enabled)
{
	p->mi_probe_enabled = mi_probe_enabled;
}

__shr_public bool libnvme_get_mi_probe_enabled(
		const struct libnvme_global_ctx *p)
{
	return p->mi_probe_enabled;
}

__shr_public void libnvme_set_ioctl_probing(
		struct libnvme_global_ctx *p,
		bool ioctl_probing)
{
	p->ioctl_probing = ioctl_probing;
}

__shr_public bool libnvme_get_ioctl_probing(const struct libnvme_global_ctx *p)
{
	return p->ioctl_probing;
}

__shr_public void libnvme_set_hostnqn(
		struct libnvme_global_ctx *p,
		const char *hostnqn)
{
	free(p->hostnqn);
	p->hostnqn = hostnqn ? strdup(hostnqn) : NULL;
}

__shr_public void libnvme_set_hostid(
		struct libnvme_global_ctx *p,
		const char *hostid)
{
	free(p->hostid);
	p->hostid = hostid ? strdup(hostid) : NULL;
}

