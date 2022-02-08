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

#include <stdio.h>
#include <stdbool.h>
#include <stddef.h>

#include <sys/types.h>
#include <uuid/uuid.h>

#include "ioctl.h"
#include "util.h"

/**
 * DOC: tree.h
 *
 * libnvme tree object interface
 */

typedef struct nvme_ns *nvme_ns_t;
typedef struct nvme_path *nvme_path_t;
typedef struct nvme_ctrl *nvme_ctrl_t;
typedef struct nvme_subsystem *nvme_subsystem_t;
typedef struct nvme_host *nvme_host_t;
typedef struct nvme_root *nvme_root_t;

typedef bool (*nvme_scan_filter_t)(nvme_subsystem_t);

/**
 * nvme_create_root() - Initialize root object
 * @fp: filedescriptor for logging messages
 * @log_level: logging level to use
 *
 * Return: initialized nvme_root_t object
 */
nvme_root_t nvme_create_root(FILE *fp, int log_level);

/**
 * nvme_free_tree() - Free root object
 * @r: nvme_root_t object
 *
 * Free an nvme_root_t object and all attached objects
 */
void nvme_free_tree(nvme_root_t r);

/**
 * nvme_first_host() - Start host iterator
 * @r: nvme_root_t object
 *
 * Return: first nvme_host_t object in an iterator
 */
nvme_host_t nvme_first_host(nvme_root_t r);

/**
 * nvme_next_host() - Next host iterator
 * @r: nvme_root_t object
 * @h: previous nvme_host_t iterator
 *
 * Return: next nvme_host_t object in an iterator
 */
nvme_host_t nvme_next_host(nvme_root_t r, nvme_host_t h);

/**
 * nvme_host_get_root() - Returns nvme_root_t object
 * @h: host
 *
 * Return: nvme_root_t object from @h
 */
nvme_root_t nvme_host_get_root(nvme_host_t h);

/**
 * nvme_lookup_host() - Lookup nvme_host_t object
 * @r: nvme_root_t object
 * @hostnqn: Host NQN
 * @hostid: Host ID
 *
 * Lookup a nvme_host_t object based on @hostnqn and @hostid
 * or create one if not found.
 *
 * Return: nvme_host_t object
 */
nvme_host_t nvme_lookup_host(nvme_root_t r, const char *hostnqn,
			     const char *hostid);

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
 * nvme_default_host() - Initializes the default host
 * @r: nvme_root_t object
 *
 * Initializes the default host object based on the values in
 * /etc/nvme/hostnqn and /etc/nvme/hostid and attaches it to @r.
 *
 * Return: nvme_host_t object
 */
nvme_host_t nvme_default_host(nvme_root_t r);

/**
 * nvme_first_subsystem() - Start subsystem iterator
 * @h: nvme_host_t object
 *
 * Return: first nvme_subsystem_t object in an iterator
 */
nvme_subsystem_t nvme_first_subsystem(nvme_host_t h);

/**
 * nvme_next_subsystem() - Next subsystem iterator
 * @h: nvme_host_t object
 * @s: previous nvme_subsystem_t iterator
 *
 * Return: next nvme_subsystem_t object in an iterator
 */
nvme_subsystem_t nvme_next_subsystem(nvme_host_t h, nvme_subsystem_t s);

/**
 * nvme_lookup_subsystem() - Lookup nvme_subsystem_t object
 * @h: nvme_host_t object
 * @name: Name of the subsystem (may be NULL)
 * @subsysnqn: Subsystem NQN
 *
 * Lookup a nvme_subsystem_t object in @h base on @name (if present)
 * and @subsystemnqn or create one if not found.
 *
 * Return: nvme_subsystme_t object
 */
nvme_subsystem_t nvme_lookup_subsystem(struct nvme_host *h,
				       const char *name,
				       const char *subsysnqn);

/**
 * nvme_free_subsystem() - Free a subsystem
 * @s: subsystem
 *
 * Frees @s and all related objects.
 */
void nvme_free_subsystem(struct nvme_subsystem *s);

/**
 * nvme_subsystem_get_host() - Returns nvme_host_t object
 * @s: subsystem
 *
 * Return: nvme_host_t object from @s
 */
nvme_host_t nvme_subsystem_get_host(nvme_subsystem_t s);

/**
 * nvme_ctrl_first_ns() - Start namespace iterator
 * @c: nvme_ctrl_t object
 *
 * Return: first nvme_ns_t object of an @c iterator
 */
nvme_ns_t nvme_ctrl_first_ns(nvme_ctrl_t c);

/**
 * nvme_ctrl_next_ns() - Next namespace iterator
 * @c: nvme_ctrl_t object
 * @n: previous nvme_ns_t iterator
 *
 * Return: next nvme_ns_t object of an @c iterator
 */
nvme_ns_t nvme_ctrl_next_ns(nvme_ctrl_t c, nvme_ns_t n);

/**
 * nvme_ctrl_first_path() - Start path iterator
 * @c: nvme_ctrl_t object
 *
 * Return: First nvme_path_t object of an @c iterator
 */
nvme_path_t nvme_ctrl_first_path(nvme_ctrl_t c);

/**
 * nvme_ctrl_next_path() - Next path iterator
 * @c: nvme_ctrl_t object
 * @p: previous nvme_path_t object of an @c iterator
 *
 * Return: 
 */
nvme_path_t nvme_ctrl_next_path(nvme_ctrl_t c, nvme_path_t p);

/**
 * nvme_subsystem_first_ctrl() - First ctrl iterator
 * @s: nvme_subsystem_t object
 *
 * Return: First nvme_ctrl_t object of an @s iterator
 */
nvme_ctrl_t nvme_subsystem_first_ctrl(nvme_subsystem_t s);

/**
 * nvme_subsystem_next_ctrl() - Next ctrl iterator
 * @s: nvme_subsystem_t object
 * @c: previous nvme_ctrl_t object of an @s iterator
 *
 * Return: next nvme_ctrl_t object of an @s iterator
 */
nvme_ctrl_t nvme_subsystem_next_ctrl(nvme_subsystem_t s, nvme_ctrl_t c);

/**
 * nvme_lookup_ctrl() - Lookup nvme_ctrl_t object
 * @s: nvme_subsystem_t object
 * @transport: transport name
 * @traddr: transport address
 * @host_traddr: host transport address
 * @host_iface: host interface name
 * @trsvcid: transport service identifier
 * @p: previous nvme_ctrl_t object
 *
 * Lookup a nvme_ctrl_t object in @s based on @transport, @traddr,
 * @host_traddr, @host_iface, and @trsvcid. @transport must be specified,
 * other fields may be required depending on the transport. A new
 * object is created if none is found. If @p is specified the lookup
 * will start at @p instead of the first controller.
 *
 * Return: nvme_ctrl_t object
 */
nvme_ctrl_t nvme_lookup_ctrl(nvme_subsystem_t s, const char *transport,
			     const char *traddr, const char *host_traddr,
			     const char *host_iface, const char *trsvcid,
			     nvme_ctrl_t p);


/**
 * nvme_create_ctrl() - Allocate an unconnected NVMe controller
 * @r: NVMe root element
 * @subsysnqn: Subsystem NQN
 * @transport: Transport type
 * @traddr: Transport address
 * @host_traddr: Host transport address
 * @host_iface: Host interface name
 * @trsvcid: Transport service ID
 *
 * Creates an unconnected nvme_ctrl_t object to be used for
 * nvme_add_ctrl().
 *
 * Return: nvme_ctrl_t object
 */
nvme_ctrl_t nvme_create_ctrl(nvme_root_t r,
			     const char *subsysnqn, const char *transport,
			     const char *traddr, const char *host_traddr,
			     const char *host_iface, const char *trsvcid);


/**
 * nvme_subsystem_first_ns() - Start namespace iterator
 * @s: nvme_subsystem_t object
 *
 * Return: First nvme_ns_t object of an @s iterator
 */
nvme_ns_t nvme_subsystem_first_ns(nvme_subsystem_t s);

/**
 * nvme_subsystem_next_ns() - Next namespace iterator
 * @s: nvme_subsystem_t object
 * @n: previous nvme_ns_t iterator
 *
 * Return: Next nvme_ns_t object of an @s iterator
 */
nvme_ns_t nvme_subsystem_next_ns(nvme_subsystem_t s, nvme_ns_t n);

/**
 * nvme_for_each_host_safe() - Traverse host list
 * @r: nvme_root_t object
 * @h: nvme_host_t object
 * @_h: temporary nvme_host_t object
 */
#define nvme_for_each_host_safe(r, h, _h)		\
	for (h = nvme_first_host(r),			\
	     _h = nvme_next_host(r, h);			\
             h != NULL; 				\
	     h = _h, _h = nvme_next_host(r, h))

/**
 * nvme_for_each_host() - Traverse host list
 * @r: nvme_root_t object
 * @h: nvme_host_t object
 */
#define nvme_for_each_host(r, h)			\
	for (h = nvme_first_host(r); h != NULL; 	\
	     h = nvme_next_host(r, h))

/**
 * nvme_for_each_subsystem_safe() - Traverse subsystems
 * @h: nvme_host_t object
 * @s: nvme_subsystem_t object
 * @_s: temporary nvme_subsystem_t object
 */
#define nvme_for_each_subsystem_safe(h, s, _s)			\
	for (s = nvme_first_subsystem(h), 			\
             _s = nvme_next_subsystem(h, s); 			\
             s != NULL; 					\
	     s = _s, _s = nvme_next_subsystem(h, s))

/**
 * nvme_for_each_subsystem() - Traverse subsystems
 * @h: nvme_host_t object
 * @s: nvme_subsystem_t object
 */
#define nvme_for_each_subsystem(h, s)				\
	for (s = nvme_first_subsystem(h); s != NULL; 		\
		s = nvme_next_subsystem(h, s))

/**
 * nvme_subsystem_for_each_ctrl_safe() - Traverse controllers
 * @s: nvme_subsystem_t object
 * @c: nvme_ctrl_t object
 * @_c: temporary nvme_ctrl_t object
 */
#define nvme_subsystem_for_each_ctrl_safe(s, c, _c)		\
	for (c = nvme_subsystem_first_ctrl(s), 			\
             _c = nvme_subsystem_next_ctrl(s, c); 		\
             c != NULL; 					\
	     c = _c, _c = nvme_subsystem_next_ctrl(s, c))

/**
 * nvme_subsystem_for_each_ctrl() - traverse controllers
 * @s: nvme_subsystem_t object
 * @c: nvme_ctrl_t object
 */
#define nvme_subsystem_for_each_ctrl(s, c)			\
	for (c = nvme_subsystem_first_ctrl(s); c != NULL; 	\
		c = nvme_subsystem_next_ctrl(s, c))

/**
 * nvme_ctrl_for_each_ns_safe() - traverse namespaces
 * @c: nvme_ctrl_t object
 * @n: nvme_ns_t object
 * @_n: temporary nvme_ns_t object
 */
#define nvme_ctrl_for_each_ns_safe(c, n, _n)			\
	for (n = nvme_ctrl_first_ns(c), 			\
             _n = nvme_ctrl_next_ns(c, n); 			\
             n != NULL; 					\
	     n = _n, _n = nvme_ctrl_next_ns(c, n))

/**
 * nvme_ctrl_for_each_ns() - traverse namespaces
 * @c: nvme_ctrl_t object
 * @n: nvme_ns_t object
 */
#define nvme_ctrl_for_each_ns(c, n)				\
	for (n = nvme_ctrl_first_ns(c); n != NULL; 		\
		n = nvme_ctrl_next_ns(c, n))

/**
 * nvme_ctrl_for_each_path_safe() - Traverse paths
 * @c: nvme_ctrl_t object
 * @p: nvme_path_t object
 * @_p: temporary nvme_path_t object
 */
#define nvme_ctrl_for_each_path_safe(c, p, _p)			\
	for (p = nvme_ctrl_first_path(c), 			\
             _p = nvme_ctrl_next_path(c, p); 			\
             p != NULL; 					\
	     p = _p, _p = nvme_ctrl_next_path(c, p))

/**
 * nvme_ctrl_for_each_path() - Traverse paths
 * @c: nvme_ctrl_t object
 * @p: nvme_path_t object
 */
#define nvme_ctrl_for_each_path(c, p)				\
	for (p = nvme_ctrl_first_path(c); p != NULL; 		\
		p = nvme_ctrl_next_path(c, p))

/**
 * nvme_subsystem_for_each_ns_safe() - Traverse namespaces
 * @s: nvme_subsystem_t object
 * @n: nvme_ns_t object
 * @_n: temporary nvme_ns_t object
 */
#define nvme_subsystem_for_each_ns_safe(s, n, _n)		\
	for (n = nvme_subsystem_first_ns(s), 			\
             _n = nvme_subsystem_next_ns(s, n); 		\
             n != NULL; 					\
	     n = _n, _n = nvme_subsystem_next_ns(s, n))

/**
 * nvme_subsystem_for_each_ns() - Traverse namespaces
 * @s: nvme_subsystem_t object
 * @n: nvme_ns_t object
 */
#define nvme_subsystem_for_each_ns(s, n)			\
	for (n = nvme_subsystem_first_ns(s); n != NULL; 	\
		n = nvme_subsystem_next_ns(s, n))

/**
 * nvme_ns_get_fd() - Get associated filedescriptor
 * @n: nvme_ns_t object
 *
 * Return: Filedescriptor associated with @n or -1
 */
int nvme_ns_get_fd(nvme_ns_t n);

/**
 * nvme_ns_get_nsid() - NSID of an nvme_ns_t object
 * @n: nvme_ns_t object
 *
 * Return: NSID of @n
 */
int nvme_ns_get_nsid(nvme_ns_t n);

/**
 * nvme_ns_get_lba_size() - LBA size of an nvme_ns_t object
 * @n: nvme_ns_t object
 *
 * Return: LBA size of @n
 */
int nvme_ns_get_lba_size(nvme_ns_t n);

/**
 * nvme_ns_get_meta_size() - Metadata size of an nvme_ns_t object
 * @n: nvme_ns_t object
 *
 * Return: Metadata size of @n
 */
int nvme_ns_get_meta_size(nvme_ns_t n);

/**
 * nvme_ns_get_lba_count() - LBA count of an nvme_ns_t object
 * @n: nvme_ns_t object
 *
 * Return: LBA count of @n
 */
uint64_t nvme_ns_get_lba_count(nvme_ns_t n);

/**
 * nvme_ns_get_lba_util() - LBA utilisation of an nvme_ns_t object
 * @n: nvme_ns_t object
 *
 * Return: LBA utilisation of @n
 */
uint64_t nvme_ns_get_lba_util(nvme_ns_t n);

/**
 * nvme_ns_get_csi() - Command set identifier of an nvme_ns_t object
 * @n: nvme_ns_t object
 *
 * Return: The namespace's command set identifier in use
 */
enum nvme_csi nvme_ns_get_csi(nvme_ns_t n);

/**
 * nvme_ns_get_eui64() - 64-bit eui of an nvme_ns_t object
 * @n: nvme_ns_t object
 *
 * Returns a pointer to the 64-bit eui
 */
const uint8_t *nvme_ns_get_eui64(nvme_ns_t n);

/**
 * nvme_ns_get_nguid() - 128-bit nguid of an nvme_ns_t object
 * @n: nvme_ns_t object
 *
 * Returns a pointer to the 128-bit nguid
 */
const uint8_t *nvme_ns_get_nguid(nvme_ns_t n);

/**
 * nvme_ns_get_uuid() - UUID of an nvme_ns_t object
 * @n: nvme_ns_t object
 * @out: buffer for the UUID
 *
 * Copies the namespace's uuid into @out
 */
void nvme_ns_get_uuid(nvme_ns_t n, uuid_t out);

/**
 * nvme_ns_get_sysfs_dir() - sysfs directory of an nvme_ns_t object
 * @n: nvme_ns_t object
 *
 * Return: sysfs directory name of @n
 */
const char *nvme_ns_get_sysfs_dir(nvme_ns_t n);

/**
 * nvme_ns_get_name() - sysfs name of an nvme_ns_t object
 * @n: nvme_ns_t object
 *
 * Return: sysfs name of @n
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
 * nvme_ns_get_firmware() - Firmware string of an nvme_ns_t object
 * @n: nvme_ns_t object
 *
 * Return: Firmware string of @n
 */
const char *nvme_ns_get_firmware(nvme_ns_t n);

/**
 * nvme_ns_get_serial() - Serial number of an nvme_ns_t object
 * @n: nvme_ns_t object
 *
 * Return: Serial number string of @n
 */
const char *nvme_ns_get_serial(nvme_ns_t n);

/**
 * nvme_ns_get_model() - Model of an nvme_ns_t object
 * @n: nvme_ns_t object
 *
 * Return: Model string of @n
 */
const char *nvme_ns_get_model(nvme_ns_t n);

/**
 * nvme_ns_get_subsystem() - nvme_subsystem_t of an nvme_ns_t object
 * @n: nvme_ns_t object
 *
 * Return: nvme_subsystem_t object of @n
 */
nvme_subsystem_t nvme_ns_get_subsystem(nvme_ns_t n);

/**
 * nvme_ns_get_ctrl() - nvme_ctrl_t of an nvme_ns_t object
 * @n: nvme_ns_t object
 *
 * nvme_ctrl_t object may be NULL for a multipathed namespace
 *
 * Return: nvme_ctrl_t object of @n if present
 */
nvme_ctrl_t nvme_ns_get_ctrl(nvme_ns_t n);

/**
 * nvme_free_ns() - free an nvme_ns_t object
 * @n: nvme_ns_t object
 */
void nvme_free_ns(struct nvme_ns *n);

/**
 * nvme_ns_read() - Read from a namespace
 * @n: nvme_ns_t object
 * @buf: buffer into which the data will be transferred
 * @offset: LBA offset of @n
 * @count: Number of sectors in @buf
 *
 * Return: Number of sectors read or -1 on error.
 */
int nvme_ns_read(nvme_ns_t n, void *buf, off_t offset, size_t count);

/**
 * nvme_ns_write() - Write to a namespace
 * @n: nvme_ns_t object
 * @buf: buffer with data to be written
 * @offset: LBA offset of @n
 * @count: Number of sectors in @buf
 *
 * Return: Number of sectors written or -1 on error
 */
int nvme_ns_write(nvme_ns_t n, void *buf, off_t offset, size_t count);

/**
 * nvme_ns_verify() - Verify data on a namespace
 * @n: nvme_ns_t object
 * @offset: LBA offset of @n
 * @count: Number of sectors to be verified
 *
 * Return: Number of sectors verified
 */
int nvme_ns_verify(nvme_ns_t n, off_t offset, size_t count);

/**
 * nvme_ns_compare() - Compare data on a namespace
 * @n: nvme_ns_t object
 * @buf: buffer with data to be compared
 * @offset: LBA offset of @n
 * @count: Number of sectors in @buf
 *
 * Return: Number of sectors compared
 */
int nvme_ns_compare(nvme_ns_t n, void *buf, off_t offset, size_t count);

/**
 * nvme_ns_write_zeros() - Write zeros to a namespace
 * @n: nvme_ns_t object
 * @offset: LBA offset in @n
 * @count: Number of sectors to be written
 *
 * Return: Number of sectors written
 */
int nvme_ns_write_zeros(nvme_ns_t n, off_t offset, size_t count);

/**
 * nvme_ns_write_uncorrectable() - Issus a 'write uncorrectable' command
 * @n: nvme_ns_t object
 * @offset: LBA offset in @n
 * @count: Number of sectors to be written
 *
 * Return: Number of sectors written
 */
int nvme_ns_write_uncorrectable(nvme_ns_t n, off_t offset, size_t count);

/**
 * nvme_ns_flush() - Flush data to a namespace
 * @n: nvme_ns_t object
 *
 * Return: 0 on success, -1 on error.
 */
int nvme_ns_flush(nvme_ns_t n);

/**
 * nvme_ns_identify() - Issue an 'identify namespace' command
 * @n: nvme_ns_t object
 * @ns: nvme_id_ns buffer
 *
 * Writes the data returned by the 'identify namespace' command
 * into @ns.
 *
 * Return: 0 on success, -1 on error.
 */
int nvme_ns_identify(nvme_ns_t n, struct nvme_id_ns *ns);

/**
 * nvme_ns_identify_descs() - Issue an 'identify descriptors' command
 * @n: nvme_ns_t object
 * @descs: list of identify descriptors
 *
 * Writes the data returned by the 'identify descriptors' command
 * into @descs.
 *
 * Return: 0 on success, -1 on error.
 */
int nvme_ns_identify_descs(nvme_ns_t n, struct nvme_ns_id_desc *descs);

/**
 * nvme_path_get_name() - sysfs name of an nvme_path_t object
 * @p: nvme_path_t object
 *
 * Return: sysfs name of @p
 */
const char *nvme_path_get_name(nvme_path_t p);

/**
 * nvme_path_get_sysfs_dir() - sysfs directory of an nvme_path_t object
 * @p: nvme_path_t object
 *
 * Return: sysfs directory of @p
 */
const char *nvme_path_get_sysfs_dir(nvme_path_t p);

/**
 * nvme_path_get_ana_state() - ANA state of an nvme_path_t object
 * @p: nvme_path_t object
 *
 * Return: ANA (Asynchronous Namespace Access) state of @p
 */
const char *nvme_path_get_ana_state(nvme_path_t p);

/**
 * nvme_path_get_ctrl() - parent controller of an nvme_path_t object
 * @p: nvme_path_t object
 *
 * Return: parent controller if present
 */
nvme_ctrl_t nvme_path_get_ctrl(nvme_path_t p);

/**
 * nvme_path_get_ns() - parent namespace of an nvme_path_t object
 * @p: nvme_path_t object
 *
 * Return: parent namespace if present
 */
nvme_ns_t nvme_path_get_ns(nvme_path_t p);

/**
 * nvme_ctrl_get_fd() - Get associated filedescriptor
 * @c: nvme_ctrl_t object
 *
 * Return: Filedescriptor associated with @c or -1
 */
int nvme_ctrl_get_fd(nvme_ctrl_t c);

/**
 * nvme_ctrl_get_name() - sysfs name of an nvme_ctrl_t object
 * @c: nvme_ctrl_t object
 *
 * Return: sysfs name of @c
 */
const char *nvme_ctrl_get_name(nvme_ctrl_t c);

/**
 * nvme_ctrl_get_sysfs_dir() - sysfs directory of an nvme_ctrl_t object
 * @c: nvme_ctrl_t object
 *
 * Return: sysfs directory name of @c
 */
const char *nvme_ctrl_get_sysfs_dir(nvme_ctrl_t c);

/**
 * nvme_ctrl_get_address() - Address string of an nvme_ctrl_t
 * @c: nvme_ctrl_t object
 *
 * Return: NVMe-over-Fabrics address string of @c or empty string
 * of no address is present.
 */
const char *nvme_ctrl_get_address(nvme_ctrl_t c);

/**
 * nvme_ctrl_get_firmware() - Firmware string of an nvme_ctrl_t object
 * @c: nvme_ctrl_t object
 *
 * Return: Firmware string of @c
 */
const char *nvme_ctrl_get_firmware(nvme_ctrl_t c);

/**
 * nvme_ctrl_get_model() - Model of an nvme_ctrl_t object
 * @c: nvme_ctrl_t object
 *
 * Return: Model string of @c
 */
const char *nvme_ctrl_get_model(nvme_ctrl_t c);

/**
 * nvme_ctrl_get_state() - Running state of an nvme_ctrl_t object
 * @c: nvme_ctrl_t object
 *
 * Return: string indicating the running state of @c
 */
const char *nvme_ctrl_get_state(nvme_ctrl_t c);

/**
 * nvme_ctrl_get_numa_node() - NUMA node of an nvme_ctrl_t object
 * @c: nvme_ctrl_t object
 *
 * Return: string indicating the NUMA node
 */
const char *nvme_ctrl_get_numa_node(nvme_ctrl_t c);

/**
 * nvme_ctrl_get_queue_count() - Queue count of an nvme_ctrl_t object
 * @c: nvme_ctrl_t object
 *
 * Return: Queue count of @c
 */
const char *nvme_ctrl_get_queue_count(nvme_ctrl_t c);

/**
 * nvme_ctrl_get_serial() - Serial number of an nvme_ctrl_t object
 * @c: nvme_ctrl_t object
 *
 * Return: Serial number string of @c
 */
const char *nvme_ctrl_get_serial(nvme_ctrl_t c);

/**
 * nvme_ctrl_get_sqsize() - SQ size of an nvme_ctrl_t object
 * @c: nvme_ctrl_t object
 *
 * Return: SQ size (as string) of @c
 */
const char *nvme_ctrl_get_sqsize(nvme_ctrl_t c);

/**
 * nvme_ctrl_get_transport() - Transport type of an nvme_ctrl_t object
 * @c: nvme_ctrl_t object
 *
 * Return: Transport type of @c
 */
const char *nvme_ctrl_get_transport(nvme_ctrl_t c);

/**
 * nvme_ctrl_get_subsysnqn() - Subsystem NQN of an nvme_ctrl_t object
 * @c: nvme_ctrl_t object
 *
 * Return: Subsystem NQN of @c
 */
const char *nvme_ctrl_get_subsysnqn(nvme_ctrl_t c);

/**
 * nvme_ctrl_get_subsystem() - Parent subsystem of an nvme_ctrl_t object
 * @c: nvme_ctrl_t object
 *
 * Return: Parent nvme_subsystem_t object
 */
nvme_subsystem_t nvme_ctrl_get_subsystem(nvme_ctrl_t c);

/**
 * nvme_ctrl_get_traddr() - Transport address of an nvme_ctrl_t object
 * @c: nvme_ctrl_t object
 *
 * Return: Transport address of @c
 */
const char *nvme_ctrl_get_traddr(nvme_ctrl_t c);

/**
 * nvme_ctrl_get_trsvcid() - Transport service identifier of an nvme_ctrl_t object
 * @c: nvme_ctrl_t object
 *
 * Return: Transport service identifier of @c (if present)
 */
const char *nvme_ctrl_get_trsvcid(nvme_ctrl_t c);

/**
 * nvme_ctrl_get_host_traddr() - Host transport address of an nvme_ctrl_t object
 * @c: nvme_ctrl_t object
 *
 * Return: Host transport address of @c (if present)
 */
const char *nvme_ctrl_get_host_traddr(nvme_ctrl_t c);

/**
 * nvme_ctrl_get_host_iface() - Host interface name of an nvme_ctrl_t object
 * @c: nvme_ctrl_t object
 *
 * Return: Host interface name of @c (if present)
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
 * nvme_ctrl_get_config() - Fabrics configuration of an nvme_ctrl_t object
 * @c: nvme_ctrl_t object
 *
 * Return: Fabrics configuration of @c
 */
struct nvme_fabrics_config *nvme_ctrl_get_config(nvme_ctrl_t c);

/**
 * nvme_ctrl_set_discovered() - Set the 'discovered' flag
 * @c: nvme_ctrl_t object
 * @discovered: value of the 'discovered' flag
 *
 * Set the 'discovered' flag of @c to @discovered
 */
void nvme_ctrl_set_discovered(nvme_ctrl_t c, bool discovered);

/**
 * nvme_ctrl_is_discovered() - Returns the value of the 'discovered' flag
 * @c: nvme_ctrl_t object
 *
 * Return: Value of the 'discovered' flag of @c
 */
bool nvme_ctrl_is_discovered(nvme_ctrl_t c);

/**
 * nvme_ctrl_set_persistent() - Set the 'persistent' flag
 * @c: nvme_ctrl_t object
 * @persistent: value of the 'persistent' flag
 *
 * Set the 'persistent' flag of @c to @persistent
 */
void nvme_ctrl_set_persistent(nvme_ctrl_t c, bool persistent);

/**
 * nvme_ctrl_is_persistent() - Returns the value of the 'persistent' flag
 * @c: nvme_ctrl_t object
 *
 * Return: Value of the 'persistent' flag of @c
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
 * nvme_ctrl_identify() - Issues an 'identify controller' command
 * @c: nvme_ctrl_t object
 * @id: identify controller data structure
 *
 * Issues an 'identify controller' command to @c and copies the
 * data into @id.
 *
 * Return: 0 on success or -1 on failure.
 */
int nvme_ctrl_identify(nvme_ctrl_t c, struct nvme_id_ctrl *id);

/**
 * nvme_disconnect_ctrl() - Disconnect a controller
 * @c: nvme_ctrl_t object
 *
 * Issues a 'disconnect' fabrics command to @c
 *
 * Return: 0 on success, -1 on failure.
 */
int nvme_disconnect_ctrl(nvme_ctrl_t c);

/**
 * nvme_scan_ctrl() - Scan on a controller
 * @r: nvme_root_t object
 * @name: name of the controller
 *
 * Scans a controller with sysfs name @name and add it to @r.
 *
 * Return: nvme_ctrl_t object
 */
nvme_ctrl_t nvme_scan_ctrl(nvme_root_t r, const char *name);

/**
 * nvme_rescan_ctrl() - Rescan an existing nvme_ctrl_t object
 * @c: nvme_ctrl_t object
 */
void nvme_rescan_ctrl(nvme_ctrl_t c);

/**
 * nvme_init_ctrl() - Initialize nvme_ctrl_t object for an existing nvme controller.
 * @h: nvme_host_t object
 * @c: nvme_ctrl_t object
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
 * nvme_subsystem_get_sysfs_dir() - sysfs directory of an nvme_subsystem_t object
 * @s: nvme_subsystem_t object
 *
 * Return: sysfs directory name of @s
 */
const char *nvme_subsystem_get_sysfs_dir(nvme_subsystem_t s);

/**
 * nvme_subsystem_get_name() - sysfs name of an nvme_subsystem_t object
 * @s: nvme_subsystem_t object
 *
 * Return: sysfs name of @s
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
 * nvme_scan_topology() - Scan NVMe topology and apply filter
 * @r: nvme_root_t object
 * @f: filter to apply
 *
 * Scans the NVMe topology and filters out the resulting elements
 * by applying @f.
 *
 * Return: Number of elements scanned
 */
int nvme_scan_topology(nvme_root_t r, nvme_scan_filter_t f);

/**
 * nvme_host_get_hostnqn() - Host NQN of an nvme_host_t object
 * @h: nvme_host_t object
 *
 * Return: Host NQN of @h
 */
const char *nvme_host_get_hostnqn(nvme_host_t h);

/**
 * nvme_host_get_hostid() - Host ID of an nvme_host_t object
 * @h: nvme_host_t object
 *
 * Return: Host ID of @h
 */
const char *nvme_host_get_hostid(nvme_host_t h);

/**
 * nvme_free_host() - Free nvme_host_t object
 * @h: nvme_host_t object
 */
void nvme_free_host(nvme_host_t h);

/**
 * nvme_scan() - Scan NVMe topology
 * @config_file: configuration file
 *
 * Return: nvme_root_t object of found elements
 */
nvme_root_t nvme_scan(const char *config_file);

/**
 * nvme_read_config() - Read NVMe json configuration file
 * @r: nvme_root_t object
 * @config_file: json configuration file
 *
 * Read in the contents of @config_file and merge them with
 * the elements in @r.
 *
 * Returns: 0 on success, -1 on failure with errno set.
 */
int nvme_read_config(nvme_root_t r, const char *config_file);

/**
 * nvme_refresh_topology() - refresh nvme_root_t object contents
 * @r: nvme_root_t object
 *
 * Removes all elements in @r and rescans the existing topology.
 */
void nvme_refresh_topology(nvme_root_t r);

/**
 * nvme_update_config() - Update JSON configuration
 * @r: nvme_root_t object
 *
 * Updates the JSON configuration file with the contents of @r.
 *
 * Return: 0 on success, -1 on failure.
 */
int nvme_update_config(nvme_root_t r);

/**
 * nvme_dump_config() - Print the JSON configuration
 * @r: nvme_root_t object
 *
 * Prints the current contents of the JSON configuration
 * file to stdout.
 *
 * Return: 0 on success, -1 on failure.
 */
int nvme_dump_config(nvme_root_t r);

/**
 * nvme_get_attr() - Read sysfs attribute
 * @d: sysfs directory
 * @attr: sysfs attribute name
 *
 * Return: string with the contents of @attr
 */
char *nvme_get_attr(const char *d, const char *attr);

/**
 * nvme_get_subsys_attr() - Read subsystem sysfs attribute
 * @s: nvme_subsystem_t object
 * @attr: sysfs attribute name
 *
 * Return: string with the contents of @attr
 */
char *nvme_get_subsys_attr(nvme_subsystem_t s, const char *attr);

/**
 * nvme_get_ctrl_attr() - Read controller sysfs attribute
 * @c: nvme_ctrl_t object
 * @attr: sysfs attribute name
 *
 * Return: string with the contents of @attr
 */
char *nvme_get_ctrl_attr(nvme_ctrl_t c, const char *attr);

/**
 * nvme_get_ns_attr() - Read namespace sysfs attribute
 * @n: nvme_ns_t object
 * @attr: sysfs attribute name
 *
 * Return: string with the contents of @attr
 */
char *nvme_get_ns_attr(nvme_ns_t n, const char *attr);

/**
 * nvme_subsystem_lookup_namespace() - lookup namespace by NSID
 * @s: nvme_subsystem_t object
 * @nsid: namespace id
 *
 * Return: nvme_ns_t of the namespace with id @nsid in subsystem @s
 */
nvme_ns_t nvme_subsystem_lookup_namespace(struct nvme_subsystem *s,
					  __u32 nsid);

/**
 * nvme_get_path_attr() - Read path sysfs attribute
 * @p: nvme_path_t object
 * @attr: sysfs attribute name
 *
 * Return:  string with the contents of @attr
 */
char *nvme_get_path_attr(nvme_path_t p, const char *attr);

/**
 * nvme_scan_namespace() - scan namespace based on sysfs name
 * @name: sysfs name of the namespace to scan
 *
 * Return: nvme_ns_t object or NULL if not found.
 */
nvme_ns_t nvme_scan_namespace(const char *name);

#endif /* _LIBNVME_TREE_H */
