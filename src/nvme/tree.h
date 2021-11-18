// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libnvme.
 * Copyright (c) 2020 Western Digital Corporation or its affiliates.
 *
 * Authors: Keith Busch <keith.busch@wdc.com>
 * 	    Chaitanya Kulkarni <chaitanya.kulkarni@wdc.com>
 */

#ifndef _LIBNVME_TREE_H
#define _LIBNVME_TREE_H

#include <stdbool.h>
#include <stddef.h>

#include <sys/types.h>
#ifdef CONFIG_LIBUUID
#include <uuid/uuid.h>
#endif
#include "ioctl.h"
#include "util.h"

/**
 *
 */
typedef struct nvme_ns *nvme_ns_t;

/**
 *
 */
typedef struct nvme_path *nvme_path_t;

/**
 *
 */
typedef struct nvme_ctrl *nvme_ctrl_t;

/**
 *
 */
typedef struct nvme_subsystem *nvme_subsystem_t;

/**
 *
 */
typedef struct nvme_host *nvme_host_t;

/**
 *
 */
typedef struct nvme_root *nvme_root_t;

/**
 *
 */
typedef bool (*nvme_scan_filter_t)(nvme_subsystem_t);

/**
 * nvme_first_host() -
 * @r:
 *
 * Return: 
 */
nvme_host_t nvme_first_host(nvme_root_t r);

/**
 * nvme_next_host() -
 * @r:
 * @h:
 *
 * Return: 
 */
nvme_host_t nvme_next_host(nvme_root_t r, nvme_host_t h);

/**
 * nvme_host_get_root() -
 * @h:
 *
 * Return:
 */
nvme_root_t nvme_host_get_root(nvme_host_t h);

/**
 * nvme_lookup_host() -
 * @r:
 *
 * Return: 
 */
nvme_host_t nvme_lookup_host(nvme_root_t r, const char *hostnqn,
			     const char *hostid);

/**
 * nvme_host_get_hostnqn() -
 * @h:
 *
 * Return: 
 */
const char *nvme_host_get_hostnqn(nvme_host_t h);

/**
 * nvme_host_get_hostid() -
 * @h:
 *
 * Return: 
 */
const char *nvme_host_get_hostid(nvme_host_t h);

/**
 * nvme_host_get_dhchap_key() - return host key
 * @h: Host for which the key should be returned
 *
 * Return: DH-HMAC-CHAP host key or NULL if not set
 */
const char *nvme_host_get_dhchap_key(nvme_host_t h);

/**
 * nvme_host_set_dhchap_key() - set host key
 * @h: Host for which the key should be set
 * @key: DH-HMAC-CHAP Key to set or NULL to clear existing key
 */
void nvme_host_set_dhchap_key(nvme_host_t h, const char *key);

/**
 * nvme_default_host() -
 * @r:
 *
 * Return:
 */
nvme_host_t nvme_default_host(nvme_root_t r);

/**
 * nvme_first_subsystem() -
 * @h:
 *
 * Return: 
 */
nvme_subsystem_t nvme_first_subsystem(nvme_host_t h);

/**
 * nvme_next_subsystem() -
 * @h:
 * @s:
 *
 * Return: 
 */
nvme_subsystem_t nvme_next_subsystem(nvme_host_t h, nvme_subsystem_t s);

/**
 * nvme_lookup_subsystem() -
 * @h:
 * @name:
 * @subsysnqn:
 *
 * Return: 
 */
nvme_subsystem_t nvme_lookup_subsystem(struct nvme_host *h,
				       const char *name,
				       const char *subsysnqn);

/**
 * nvme_free_subsystem() -
 * @s:
 */
void nvme_free_subsystem(struct nvme_subsystem *s);

/**
 * nvme_subsystem_get_host() -
 * @s:
 *
 * Return: 
 */
nvme_host_t nvme_subsystem_get_host(nvme_subsystem_t s);

/**
 * nvme_ctrl_first_ns() -
 * @c:
 *
 * Return: 
 */
nvme_ns_t nvme_ctrl_first_ns(nvme_ctrl_t c);

/**
 * nvme_ctrl_next_ns() -
 * @c:
 * @n:
 *
 * Return: 
 */
nvme_ns_t nvme_ctrl_next_ns(nvme_ctrl_t c, nvme_ns_t n);

/**
 * nvme_ctrl_first_path() -
 * @c:
 *
 * Return: 
 */
nvme_path_t nvme_ctrl_first_path(nvme_ctrl_t c);

/**
 * nvme_ctrl_next_path() -
 * @c:
 * @p:
 *
 * Return: 
 */
nvme_path_t nvme_ctrl_next_path(nvme_ctrl_t c, nvme_path_t p);

/**
 * nvme_subsystem_first_ctrl() -
 * @s:
 *
 * Return: 
 */
nvme_ctrl_t nvme_subsystem_first_ctrl(nvme_subsystem_t s);

/**
 * nvme_subsystem_next_ctrl() -
 * @s:
 * @c:
 *
 * Return: 
 */
nvme_ctrl_t nvme_subsystem_next_ctrl(nvme_subsystem_t s, nvme_ctrl_t c);

/**
 * nvme_lookup_ctrl() -
 * @s:
 * @transport:
 * @traddr:
 * @host_traddr:
 * @host_iface:
 * @trsvcid:
 *
 * Return: 
 */
nvme_ctrl_t nvme_lookup_ctrl(nvme_subsystem_t s, const char *transport,
			     const char *traddr, const char *host_traddr,
			     const char *host_iface, const char *trsvcid);


/**
 * nvme_create_ctrl() -
 * @subsysnqn:
 * @transport:
 * @traddr:
 * @host_traddr:
 * @host_iface:
 * @trsvcid:
 *
 * Return: 
 */
nvme_ctrl_t nvme_create_ctrl(const char *subsysnqn, const char *transport,
			     const char *traddr, const char *host_traddr,
			     const char *host_iface, const char *trsvcid);


/**
 * nvme_subsystem_first_ns() -
 * @s:
 *
 * Return: 
 */
nvme_ns_t nvme_subsystem_first_ns(nvme_subsystem_t s);

/**
 * nvme_subsystem_next_ns() -
 * @s:
 * @n:
 *
 * Return: 
 */
nvme_ns_t nvme_subsystem_next_ns(nvme_subsystem_t s, nvme_ns_t n);

/**
 * nvme_for_each_host_safe()
 */
#define nvme_for_each_host_safe(r, h, _h)		\
	for (h = nvme_first_host(r),			\
	     _h = nvme_next_host(r, h);			\
             h != NULL; 				\
	     h = _h, _h = nvme_next_host(r, h))

/**
 * nvme_for_each_host()
 */
#define nvme_for_each_host(r, h)			\
	for (h = nvme_first_host(r); h != NULL; 	\
	     h = nvme_next_host(r, h))

/**
 * nvme_for_each_subsystem_safe()
 */
#define nvme_for_each_subsystem_safe(h, s, _s)			\
	for (s = nvme_first_subsystem(h), 			\
             _s = nvme_next_subsystem(h, s); 			\
             s != NULL; 					\
	     s = _s, _s = nvme_next_subsystem(h, s))

/**
 * nvme_for_each_subsystem()
 */
#define nvme_for_each_subsystem(h, s)				\
	for (s = nvme_first_subsystem(h); s != NULL; 		\
		s = nvme_next_subsystem(h, s))

/**
 * nvme_subsystem_for_each_ctrl_safe()
 */
#define nvme_subsystem_for_each_ctrl_safe(s, c, _c)		\
	for (c = nvme_subsystem_first_ctrl(s), 			\
             _c = nvme_subsystem_next_ctrl(s, c); 		\
             c != NULL; 					\
	     c = _c, _c = nvme_subsystem_next_ctrl(s, c))

/**
 * nvme_subsystem_for_each_ctrl()
 */
#define nvme_subsystem_for_each_ctrl(s, c)			\
	for (c = nvme_subsystem_first_ctrl(s); c != NULL; 	\
		c = nvme_subsystem_next_ctrl(s, c))

/**
 * nvme_ctrl_for_each_ns_safe()
 */
#define nvme_ctrl_for_each_ns_safe(c, n, _n)			\
	for (n = nvme_ctrl_first_ns(c), 			\
             _n = nvme_ctrl_next_ns(c, n); 			\
             n != NULL; 					\
	     n = _n, _n = nvme_ctrl_next_ns(c, n))

/**
 * nvme_ctrl_for_each_ns()
 */
#define nvme_ctrl_for_each_ns(c, n)				\
	for (n = nvme_ctrl_first_ns(c); n != NULL; 		\
		n = nvme_ctrl_next_ns(c, n))

/**
 * nvme_ctrl_for_each_path_safe()
 */
#define nvme_ctrl_for_each_path_safe(c, p, _p)			\
	for (p = nvme_ctrl_first_path(c), 			\
             _p = nvme_ctrl_next_path(c, p); 			\
             p != NULL; 					\
	     p = _p, _p = nvme_ctrl_next_path(c, p))

/**
 * nvme_ctrl_for_each_path()
 */
#define nvme_ctrl_for_each_path(c, p)				\
	for (p = nvme_ctrl_first_path(c); p != NULL; 		\
		p = nvme_ctrl_next_path(c, p))

/**
 * nvme_subsystem_for_each_ns_safe()
 */
#define nvme_subsystem_for_each_ns_safe(s, n, _n)		\
	for (n = nvme_subsystem_first_ns(s), 			\
             _n = nvme_subsystem_next_ns(s, n); 		\
             n != NULL; 					\
	     n = _n, _n = nvme_subsystem_next_ns(s, n))

/**
 * nvme_subsystem_for_each_ns()
 */
#define nvme_subsystem_for_each_ns(s, n)			\
	for (n = nvme_subsystem_first_ns(s); n != NULL; 	\
		n = nvme_subsystem_next_ns(s, n))

/**
 * nvme_ns_get_fd() -
 * @n:
 *
 * Return: 
 */
int nvme_ns_get_fd(nvme_ns_t n);

/**
 * nvme_ns_get_nsid() -
 * @n:
 *
 * Return: 
 */
int nvme_ns_get_nsid(nvme_ns_t n);

/**
 * nvme_ns_get_lba_size() -
 * @n:
 *
 * Return: 
 */
int nvme_ns_get_lba_size(nvme_ns_t n);

/**
 * nvme_ns_get_meta_size() -
 * @n:
 *
 * Return:
 */
int nvme_ns_get_meta_size(nvme_ns_t n);

/**
 * nvme_ns_get_lba_count() -
 * @n:
 *
 * Return: 
 */
uint64_t nvme_ns_get_lba_count(nvme_ns_t n);

/**
 * nvme_ns_get_lba_util() -
 * @n:
 *
 * Return: 
 */
uint64_t nvme_ns_get_lba_util(nvme_ns_t n);

/**
 * nvme_ns_get_csi() -
 * @n:
 *
 * Return: The namespace's command set identifier in use
 */
enum nvme_csi nvme_ns_get_csi(nvme_ns_t n);

/**
 * nvme_ns_get_eui64() -
 * @n:
 *
 * Returns a pointer to the 64-bit eui
 */
const uint8_t *nvme_ns_get_eui64(nvme_ns_t n);

/**
 * nvme_ns_get_nguid() -
 * @n:
 *
 * Returns a pointer to the 128-bit nguid
 */
const uint8_t *nvme_ns_get_nguid(nvme_ns_t n);

/**
 * nvme_ns_get_uuid() -
 * @n:
 * @out:
 *
 * Copies the namespace's uuid to the destination buffer
 */
#ifdef CONFIG_LIBUUID
void nvme_ns_get_uuid(nvme_ns_t n, uuid_t out);
#else
void nvme_ns_get_uuid(nvme_ns_t n, uint8_t *out);
#endif
/**
 * nvme_ns_get_sysfs_dir() -
 * @n:
 *
 * Return: 
 */
const char *nvme_ns_get_sysfs_dir(nvme_ns_t n);

/**
 * nvme_ns_get_name() -
 * @n:
 *
 * Return: 
 */
const char *nvme_ns_get_name(nvme_ns_t n);

/**
 * nvme_ns_get_generic_name() - Returns name of generic namesapce chardev.
 * @n: Namespace instance
 *
 * Return: Name of generic namespace chardev
 */
const char *nvme_ns_get_generic_name(nvme_ns_t n);

/**
 * nvme_ns_get_firmware() -
 * @n:
 *
 * Return: 
 */
const char *nvme_ns_get_firmware(nvme_ns_t n);

/**
 * nvme_ns_get_serial() -
 * @n:
 *
 * Return: 
 */
const char *nvme_ns_get_serial(nvme_ns_t n);

/**
 * nvme_ns_get_model() -
 * @n:
 *
 * Return: 
 */
const char *nvme_ns_get_model(nvme_ns_t n);

/**
 * nvme_ns_get_subsystem() -
 * @n:
 *
 * Return: 
 */
nvme_subsystem_t nvme_ns_get_subsystem(nvme_ns_t n);

/**
 * nvme_ns_get_ctrl() -
 * @n:
 *
 * Return: 
 */
nvme_ctrl_t nvme_ns_get_ctrl(nvme_ns_t n);

/**
 * nvme_free_ns() -
 * @ns:
 */
void nvme_free_ns(struct nvme_ns *n);

/**
 * nvme_ns_read() -
 * @n:
 * @buf:
 * @offset:
 * @count:
 *
 * Return: 
 */
int nvme_ns_read(nvme_ns_t n, void *buf, off_t offset, size_t count);

/**
 * nvme_ns_write() -
 * @n:
 * @buf:
 * @offset:
 * @count:
 *
 * Return: 
 */
int nvme_ns_write(nvme_ns_t n, void *buf, off_t offset, size_t count);

/**
 * nvme_ns_verify() -
 * @n:
 * @offset:
 * @count:
 *
 * Return: 
 */
int nvme_ns_verify(nvme_ns_t n, off_t offset, size_t count);

/**
 * nvme_ns_compare() -
 * @n:
 * @buf:
 * @offset:
 * @count:
 *
 * Return: 
 */
int nvme_ns_compare(nvme_ns_t n, void *buf, off_t offset, size_t count);

/**
 * nvme_ns_write_zeros() -
 * @n:
 * @offset:
 * @count:
 *
 * Return: 
 */
int nvme_ns_write_zeros(nvme_ns_t n, off_t offset, size_t count);

/**
 * nvme_ns_write_uncorrectable() -
 * @n:
 * @offset:
 * @count:
 *
 * Return: 
 */
int nvme_ns_write_uncorrectable(nvme_ns_t n, off_t offset, size_t count);

/**
 * nvme_ns_flush() -
 * @n:
 *
 * Return: 
 */
int nvme_ns_flush(nvme_ns_t n);

/**
 * nvme_ns_identify() -
 * @n:
 * @ns:
 *
 * Return: 
 */
int nvme_ns_identify(nvme_ns_t n, struct nvme_id_ns *ns);

/**
 * nvme_ns_identify_descs() -
 * @n:
 * @descs:
 *
 * Return: 
 */
int nvme_ns_identify_descs(nvme_ns_t n, struct nvme_ns_id_desc *descs);

/**
 * nvme_path_get_name() -
 * @p:
 *
 * Return: 
 */
const char *nvme_path_get_name(nvme_path_t p);

/**
 * nvme_path_get_sysfs_dir() -
 * @p:
 *
 * Return: 
 */
const char *nvme_path_get_sysfs_dir(nvme_path_t p);

/**
 * nvme_path_get_ana_state() -
 * @p:
 *
 * Return: 
 */
const char *nvme_path_get_ana_state(nvme_path_t p);

/**
 * nvme_path_get_subsystem() -
 * @p:
 *
 * Return: 
 */
nvme_ctrl_t nvme_path_get_subsystem(nvme_path_t p);

/**
 * nvme_path_get_ns() -
 * @p:
 *
 * Return: 
 */
nvme_ns_t nvme_path_get_ns(nvme_path_t p);

/**
 * nvme_ctrl_get_fd() -
 * @c:
 *
 * Return: 
 */
int nvme_ctrl_get_fd(nvme_ctrl_t c);

/**
 * nvme_ctrl_get_name() -
 * @c:
 *
 * Return: 
 */
const char *nvme_ctrl_get_name(nvme_ctrl_t c);

/**
 * nvme_ctrl_get_sysfs_dir() -
 * @c:
 *
 * Return: 
 */
const char *nvme_ctrl_get_sysfs_dir(nvme_ctrl_t c);

/**
 * nvme_ctrl_get_address() -
 * @c:
 *
 * Return: 
 */
const char *nvme_ctrl_get_address(nvme_ctrl_t c);

/**
 * nvme_ctrl_get_firmware() -
 * @c:
 *
 * Return: 
 */
const char *nvme_ctrl_get_firmware(nvme_ctrl_t c);

/**
 * nvme_ctrl_get_model() -
 * @c:
 *
 * Return: 
 */
const char *nvme_ctrl_get_model(nvme_ctrl_t c);

/**
 * nvme_ctrl_get_state() -
 * @c:
 *
 * Return: 
 */
const char *nvme_ctrl_get_state(nvme_ctrl_t c);

/**
 * nvme_ctrl_get_numa_node() -
 * @c:
 *
 * Return: 
 */
const char *nvme_ctrl_get_numa_node(nvme_ctrl_t c);

/**
 * nvme_ctrl_get_queue_count() -
 * @c:
 *
 * Return: 
 */
const char *nvme_ctrl_get_queue_count(nvme_ctrl_t c);

/**
 * nvme_ctrl_get_serial() -
 * @c:
 *
 * Return: 
 */
const char *nvme_ctrl_get_serial(nvme_ctrl_t c);

/**
 * nvme_ctrl_get_sqsize() -
 * @c:
 *
 * Return: 
 */
const char *nvme_ctrl_get_sqsize(nvme_ctrl_t c);

/**
 * nvme_ctrl_get_transport() -
 * @c:
 *
 * Return: 
 */
const char *nvme_ctrl_get_transport(nvme_ctrl_t c);

/**
 * nvme_ctrl_get_subsysnqn() -
 * @c:
 *
 * Return: 
 */
const char *nvme_ctrl_get_subsysnqn(nvme_ctrl_t c);

/**
 * nvme_ctrl_get_subsystem() -
 * @c:
 *
 * Return: 
 */
nvme_subsystem_t nvme_ctrl_get_subsystem(nvme_ctrl_t c);

/**
 * nvme_ctrl_get_traddr() -
 * @c:
 *
 * Return:
 */
const char *nvme_ctrl_get_traddr(nvme_ctrl_t c);

/**
 * nvme_ctrl_get_trsvcid() -
 * @c:
 *
 * Return:
 */
const char *nvme_ctrl_get_trsvcid(nvme_ctrl_t c);

/**
 * nvme_ctrl_get_host_traddr() -
 * @c:
 *
 * Return:
 */
const char *nvme_ctrl_get_host_traddr(nvme_ctrl_t c);

/**
 * nvme_ctrl_get_host_iface() -
 * @c:
 *
 * Return:
 */
const char *nvme_ctrl_get_host_iface(nvme_ctrl_t c);

/**
 * nvme_ctrl_get_dhchap_key() - return controller key
 * @c: controller for which the key should be returned
 *
 * Return: DH-HMAC-CHAP controller key or NULL if not set
 */
const char *nvme_ctrl_get_dhchap_key(nvme_ctrl_t c);

/**
 * nvme_ctrl_set_dhchap_key() - set controller key
 * @c: Controller for which the key should be set
 * @key: DH-HMAC-CHAP Key to set or NULL to clear existing key
 */
void nvme_ctrl_set_dhchap_key(nvme_ctrl_t c, const char *key);

/**
 * nvme_ctrl_get_config() -
 * @c:
 *
 * Return:
 */
struct nvme_fabrics_config *nvme_ctrl_get_config(nvme_ctrl_t c);

/**
 * nvme_ctrl_set_discovered() -
 * @c:
 * @discovered:
 *
 * Return:
 */
void nvme_ctrl_set_discovered(nvme_ctrl_t c, bool discovered);

/**
 * nvme_ctrl_is_discovered() -
 * @c:
 *
 * Return:
 */
bool nvme_ctrl_is_discovered(nvme_ctrl_t c);

/**
 * nvme_ctrl_set_persistent() -
 * @c:
 * @persistent:
 *
 * Return:
 */
void nvme_ctrl_set_persistent(nvme_ctrl_t c, bool persistent);

/**
 * nvme_ctrl_is_persistent() -
 * @c:
 *
 * Return:
 */
bool nvme_ctrl_is_persistent(nvme_ctrl_t c);

/**
 * nvme_ctrl_set_discovery_ctrl() - Set the 'discovery_ctrl' flag
 * @c: Controller to be modified
 * @discovery: value of the discovery_ctrl flag
 *
 * Sets the 'discovery_ctrl' flag in @c to specify whether
 * @c connects to a discovery subsystem.
 *
 */
void nvme_ctrl_set_discovery_ctrl(nvme_ctrl_t c, bool discovery);

/**
 * nvme_ctrl_is_discovery_ctrl() - Check the 'discovery_ctrl' flag
 * @c: Controller to be checked
 *
 * Returns the value of the 'discovery_ctrl' flag which specifies whether
 * @c connects to a discovery subsystem.
 *
 * Return: value of the 'discover_ctrl' flag
 */
bool nvme_ctrl_is_discovery_ctrl(nvme_ctrl_t c);

/**
 * nvme_ctrl_disable_sqflow() -
 * @c:
 * @disable_sqflow:
 *
 * Return:
 */
void nvme_ctrl_disable_sqflow(nvme_ctrl_t c, bool disable_sqflow);

/**
 * nvme_ctrl_identify() -
 * @c:
 * @id:
 *
 * Return: 
 */
int nvme_ctrl_identify(nvme_ctrl_t c, struct nvme_id_ctrl *id);

/**
 * nvme_disconnect_ctrl() -
 * @c:
 *
 * Return: 
 */
int nvme_disconnect_ctrl(nvme_ctrl_t c);

/**
 * nvme_scan_ctrl() -
 * @name:
 *
 * Return: 
 */
nvme_ctrl_t nvme_scan_ctrl(nvme_root_t r, const char *name);

/**
 * @c:
 *
 */
void nvme_rescan_ctrl(nvme_ctrl_t c);

/**
 * nvme_init_ctrl() - Initialize control for an existing nvme device.
 * @h: host
 * @c: ctrl
 * @instance: Instance number (e.g. 1 for nvme1)
 *
 * Return: The ioctl() return code. Typically 0 on success.
 */
int nvme_init_ctrl(nvme_host_t h, nvme_ctrl_t c, int instance);

/**
 * nvme_free_ctrl() -
 * @c:
 */
void nvme_free_ctrl(struct nvme_ctrl *c);

/**
 * nvme_unlink_ctrl() -
 * @c:
 */
void nvme_unlink_ctrl(struct nvme_ctrl *c);

/**
 * nvme_subsystem_get_nqn() -
 * @s:
 *
 * Return: 
 */
const char *nvme_subsystem_get_nqn(nvme_subsystem_t s);

/**
 * nvme_subsystem_get_sysfs_dir() -
 * @s:
 *
 * Return: 
 */
const char *nvme_subsystem_get_sysfs_dir(nvme_subsystem_t s);

/**
 * nvme_subsystem_get_name() -
 * @s:
 *
 * Return: 
 */
const char *nvme_subsystem_get_name(nvme_subsystem_t s);

/**
 * nvme_subsystem_get_type() - Returns the type of a subsystem
 * @s: Subsystem
 *
 * Returns the subsystem type of @s.
 *
 * Return: 'nvm' or 'discovery'
 */
const char *nvme_subsystem_get_type(nvme_subsystem_t s);

/**
 * nvme_scan_filter() -
 * @f:
 *
 * Return: 
 */
nvme_root_t nvme_scan_filter(nvme_scan_filter_t f);

/**
 * nvme_host_get_hostnqn() -
 * @h:
 *
 * Return: 
 */
const char *nvme_host_get_hostnqn(nvme_host_t h);

/**
 * nvme_host_get_hostid() -
 * @h:
 *
 * Return: 
 */
const char *nvme_host_get_hostid(nvme_host_t h);

/**
 * nvme_default_host() -
 * @root:
 *
 * Return:
 */
nvme_host_t nvme_default_host(nvme_root_t r);

/**
 * nvme_free_host() -
 * @r:
 */
void nvme_free_host(nvme_host_t h);

/**
 * nvme_scan() -
 * @config_file:
 *
 * Return: 
 */
nvme_root_t nvme_scan(const char *config_file);

/**
 * nvme_refresh_topology() -
 * @r:
 */
void nvme_refresh_topology(nvme_root_t r);

/**
 * nvme_reset_topology() -
 * @r:
 */
void nvme_reset_topology(nvme_root_t r);

/**
 * nvme_update_config() -
 * @r:
 *
 * Return:
 */
int nvme_update_config(nvme_root_t r);

/**
 * nvme_dump_config() -
 * @r:
 *
 * Return:
 */
int nvme_dump_config(nvme_root_t r);

/**
 * nvme_free_tree() -
 * @r:
 */
void nvme_free_tree(nvme_root_t r);

/**
 * nvme_get_attr() -
 * @dir:
 * @attr:
 *
 * Return: 
 */
char *nvme_get_attr(const char *dir, const char *attr);

/**
 * nvme_get_subsys_attr() -
 * @s:
 * @attr:
 *
 * Return: 
 */
char *nvme_get_subsys_attr(nvme_subsystem_t s, const char *attr);

/**
 * nvme_get_ctrl_attr() -
 * @c:
 * @attr:
 *
 * Return: 
 */
char *nvme_get_ctrl_attr(nvme_ctrl_t c, const char *attr);

/**
 * nvme_get_ns_attr() -
 * @n:
 * @attr:
 *
 * Return: 
 */
char *nvme_get_ns_attr(nvme_ns_t n, const char *attr);

nvme_ns_t nvme_subsystem_lookup_namespace(struct nvme_subsystem *s,
					  __u32 nsid);
/**
 * nvme_get_path_attr() -
 * @p:
 * @attr:
 *
 * Return: 
 */
char *nvme_get_path_attr(nvme_path_t p, const char *attr);

nvme_ns_t nvme_scan_namespace(const char *name);

#endif /* _LIBNVME_TREE_H */
