// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libnvme.
 * Copyright (c) 2020 Western Digital Corporation or its affiliates.
 *
 * Authors: Keith Busch <keith.busch@wdc.com>
 *	    Chaitanya Kulkarni <chaitanya.kulkarni@wdc.com>
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>

#include <nvme/lib-types.h>
#include <nvme/nvme-types.h>

/**
 * DOC: tree.h
 *
 * libnvme tree object interface
 */

typedef struct libnvme_ns *libnvme_ns_t;
typedef struct libnvme_ns_head *libnvme_ns_head_t;
typedef struct libnvme_path *libnvme_path_t;
typedef struct libnvme_stat *libnvme_stat_t;
typedef struct libnvme_ctrl *libnvme_ctrl_t;
typedef struct libnvme_subsystem *libnvme_subsystem_t;
typedef struct libnvme_host *libnvme_host_t;

typedef bool (*libnvme_scan_filter_t)(libnvme_subsystem_t, libnvme_ctrl_t,
				   libnvme_ns_t, void *);

/**
 * libnvme_set_application - Specify managing application
 * @ctx:	struct libnvme_global_ctx object
 * @a:	Application string
 *
 * Sets the managing application string for @r.
 */
void libnvme_set_application(struct libnvme_global_ctx *ctx, const char *a);

/**
 * libnvme_get_application - Get managing application
 * @ctx:	struct libnvme_global_ctx object
 *
 * Returns the managing application string for @r or NULL if not set.
 */
const char *libnvme_get_application(struct libnvme_global_ctx *ctx);

/**
 * libnvme_skip_namespaces - Skip namespace scanning
 * @ctx:	struct libnvme_global_ctx object
 *
 * Sets a flag to skip namespaces during scanning.
 */
void libnvme_skip_namespaces(struct libnvme_global_ctx *ctx);

/**
 * libnvme_release_fds - Close all opened file descriptors in the tree
 * @ctx:	struct libnvme_global_ctx object
 *
 * Controller and Namespace objects cache the file descriptors
 * of opened nvme devices. This API can be used to close and
 * clear all cached fds in the tree.
 *
 */
void libnvme_release_fds(struct libnvme_global_ctx *ctx);

/**
 * libnvme_first_host() - Start host iterator
 * @ctx:	struct libnvme_global_ctx object
 *
 * Return: First &libnvme_host_t object in an iterator
 */
libnvme_host_t libnvme_first_host(struct libnvme_global_ctx *ctx);

/**
 * libnvme_next_host() - Next host iterator
 * @ctx:	struct libnvme_global_ctx object
 * @h:	Previous &libnvme_host_t iterator
 *
 * Return: Next &libnvme_host_t object in an iterator
 */
libnvme_host_t libnvme_next_host(struct libnvme_global_ctx *ctx,
		libnvme_host_t h);

/**
 * libnvme_host_get_global_ctx() - Returns libnvme_global_ctx object
 * @h:	&libnvme_host_t object
 *
 * Return: &struct libnvme_global_ctx object from @h
 */
struct libnvme_global_ctx *libnvme_host_get_global_ctx(libnvme_host_t h);

/**
 * libnvme_host_set_pdc_enabled() - Set Persistent Discovery Controller flag
 * @h:		Host for which the falg should be set
 * @enabled:	The bool to set the enabled flag
 *
 * When libnvme_host_set_pdc_enabled() is not used to set the PDC flag,
 * libnvme_host_is_pdc_enabled() will return the default value which was
 * passed into the function and not the undefined flag value.
 */
void libnvme_host_set_pdc_enabled(libnvme_host_t h, bool enabled);

/**
 * libnvme_host_is_pdc_enabled() - Is Persistenct Discovery Controller enabled
 * @h: 		Host which to check if PDC is enabled
 * @fallback:	The fallback default value of the flag when
 * 		@libnvme_host_set_pdc_enabled has not be used
 * 		to set the flag.
 *
 * Return: true if PDC is enabled for @h, else false
 */
bool libnvme_host_is_pdc_enabled(libnvme_host_t h, bool fallback);

/**
 * libnvme_get_host() - Returns a host object
 * @ctx:	struct libnvme_global_ctx object
 * @hostnqn:	Host NQN (optional)
 * @hostid:	Host ID (optional)
 * @h:		&libnvme_host_t object to return
 *
 * Returns a host object based on the hostnqn/hostid values or the default if
 * hostnqn/hostid are NULL.
 *
 * Return: 0 on success or negative error code otherwise
 */
int libnvme_get_host(struct libnvme_global_ctx *ctx, const char *hostnqn,
		const char *hostid, libnvme_host_t *h);

/**
 * libnvme_host_get_ids - Retrieve host ids from various sources
 *
 * @ctx:		struct libnvme_global_ctx object
 * @hostnqn_arg:	Input hostnqn (command line) argument
 * @hostid_arg:		Input hostid (command line) argument
 * @hostnqn:		Output hostnqn
 * @hostid:		Output hostid
 *
 * libnvme_host_get_ids figures out which hostnqn/hostid is to be used.
 * There are several sources where this information can be retrieved.
 *
 * The order is:
 *
 *  - Start with informartion from DMI or device-tree
 *  - Override hostnqn and hostid from /etc/nvme files
 *  - Override hostnqn or hostid with values from JSON
 *    configuration file. The first host entry in the file is
 *    considered the default host.
 *  - Override hostnqn or hostid with values from the command line
 *    (@hostnqn_arg, @hostid_arg).
 *
 *  If the IDs are still NULL after the lookup algorithm, the function
 *  will generate random IDs.
 *
 *  The function also verifies that hostnqn and hostid matches. The Linux
 *  NVMe implementation expects a 1:1 matching between the IDs.
 *
 *  Return: 0 on success (@hostnqn and @hostid contain valid strings
 *  which the caller needs to free), or negative error code otherwise.
 */
int libnvme_host_get_ids(struct libnvme_global_ctx *ctx,
		      const char *hostnqn_arg, const char *hostid_arg,
		      char **hostnqn, char **hostid);

/**
 * libnvme_first_subsystem() - Start subsystem iterator
 * @h:	&libnvme_host_t object
 *
 * Return: first &libnvme_subsystem_t object in an iterator
 */
libnvme_subsystem_t libnvme_first_subsystem(libnvme_host_t h);

/**
 * libnvme_next_subsystem() - Next subsystem iterator
 * @h:	&libnvme_host_t object
 * @s:	Previous &libnvme_subsystem_t iterator
 *
 * Return: next &libnvme_subsystem_t object in an iterator
 */
libnvme_subsystem_t libnvme_next_subsystem(libnvme_host_t h,
		libnvme_subsystem_t s);

/**
 * libnvme_get_subsystem() - Returns libnvme_subsystem_t object
 * @ctx:	struct libnvme_global_ctx object
 * @h:		&libnvme_host_t object
 * @name:	Name of the subsystem (may be NULL)
 * @subsysnqn:	Subsystem NQN
 * @s: 		libnvme_subsystem_t object
 *
 * Returns an &libnvme_subsystem_t object in @h base on @name (if present)
 * and @subsysnqn or create one if not found.
 *
 */
int libnvme_get_subsystem(struct libnvme_global_ctx *ctx,
		struct libnvme_host *h, const char *name,
		const char *subsysnqn, struct libnvme_subsystem **s);

/**
 * libnvme_free_subsystem() - Free a subsystem
 * @s:	subsystem
 *
 * Frees @s and all related objects.
 */
void libnvme_free_subsystem(struct libnvme_subsystem *s);

/**
 * libnvme_subsystem_get_host() - Returns libnvme_host_t object
 * @s:	subsystem
 *
 * Return: &libnvme_host_t object from @s
 */
libnvme_host_t libnvme_subsystem_get_host(libnvme_subsystem_t s);

/**
 * libnvme_subsystem_get_iopolicy() - Get subsystem iopolicy name
 * @s:	subsystem
 *
 * Return: The iopolicy configured in subsystem @s
 */
char *libnvme_subsystem_get_iopolicy(libnvme_subsystem_t s);

/**
 * libnvme_ctrl_first_ns() - Start namespace iterator
 * @c:	Controller instance
 *
 * Return: First &libnvme_ns_t object of an @c iterator
 */
libnvme_ns_t libnvme_ctrl_first_ns(libnvme_ctrl_t c);

/**
 * libnvme_ctrl_next_ns() - Next namespace iterator
 * @c:	Controller instance
 * @n:	Previous libnvme_ns_t iterator
 *
 * Return: Next libnvme_ns_t object of an @c iterator
 */
libnvme_ns_t libnvme_ctrl_next_ns(libnvme_ctrl_t c, libnvme_ns_t n);

/**
 * libnvme_ctrl_first_path() - Start path iterator
 * @c:	Controller instance
 *
 * Return: First &libnvme_path_t object of an @c iterator
 */
libnvme_path_t libnvme_ctrl_first_path(libnvme_ctrl_t c);

/**
 * libnvme_ctrl_next_path() - Next path iterator
 * @c:	Controller instance
 * @p:	Previous &libnvme_path_t object of an @c iterator
 *
 * Return: Next &libnvme_path_t object of an @c iterator
 */
libnvme_path_t libnvme_ctrl_next_path(libnvme_ctrl_t c, libnvme_path_t p);

/**
 * libnvme_subsystem_first_ctrl() - First ctrl iterator
 * @s:	&libnvme_subsystem_t object
 *
 * Return: First controller of an @s iterator
 */
libnvme_ctrl_t libnvme_subsystem_first_ctrl(libnvme_subsystem_t s);

/**
 * libnvme_subsystem_next_ctrl() - Next ctrl iterator
 * @s:	&libnvme_subsystem_t object
 * @c:	Previous controller instance of an @s iterator
 *
 * Return: Next controller of an @s iterator
 */
libnvme_ctrl_t libnvme_subsystem_next_ctrl(libnvme_subsystem_t s,
		libnvme_ctrl_t c);

/**
 * libnvme_namespace_first_path() - Start path iterator
 * @ns:	Namespace instance
 *
 * Return: First &libnvme_path_t object of an @ns iterator
 */
libnvme_path_t libnvme_namespace_first_path(libnvme_ns_t ns);

/**
 * libnvme_namespace_next_path() - Next path iterator
 * @ns:	Namespace instance
 * @p:	Previous &libnvme_path_t object of an @ns iterator
 *
 * Return: Next &libnvme_path_t object of an @ns iterator
 */
libnvme_path_t libnvme_namespace_next_path(libnvme_ns_t ns, libnvme_path_t p);

/**
 * libnvme_ctrl_match_config() - Check if ctrl @c matches config params
 * @c:			An existing controller instance
 * @transport:		Transport name
 * @traddr:		Transport address
 * @trsvcid:		Transport service identifier
 * @subsysnqn:		Subsystem NQN
 * @host_traddr:	Host transport address
 * @host_iface:		Host interface name
 *
 * Check that controller @c matches parameters: @transport, @traddr,
 * @trsvcid, @subsysnqn, @host_traddr, and @host_iface. Parameters set
 * to NULL will be ignored.
 *
 * Return: true if there's a match, false otherwise.
 */
bool libnvme_ctrl_match_config(struct libnvme_ctrl *c, const char *transport,
			    const char *traddr, const char *trsvcid,
			    const char *subsysnqn, const char *host_traddr,
			    const char *host_iface);

/**
 * libnvme_subsystem_first_ns() - Start namespace iterator
 * @s:	&libnvme_subsystem_t object
 *
 * Return: First &libnvme_ns_t object of an @s iterator
 */
libnvme_ns_t libnvme_subsystem_first_ns(libnvme_subsystem_t s);

/**
 * libnvme_subsystem_next_ns() - Next namespace iterator
 * @s:	&libnvme_subsystem_t object
 * @n:	Previous &libnvme_ns_t iterator
 *
 * Return: Next &libnvme_ns_t object of an @s iterator
 */
libnvme_ns_t libnvme_subsystem_next_ns(libnvme_subsystem_t s, libnvme_ns_t n);

/**
 * libnvme_for_each_host_safe() - Traverse host list
 * @r:	&libnvme_root_t object
 * @h:	&libnvme_host_t object
 * @_h:	Temporary &libnvme_host_t object
 */
#define libnvme_for_each_host_safe(r, h, _h)		\
	for (h = libnvme_first_host(r),			\
	     _h = libnvme_next_host(r, h);		\
	     h != NULL;					\
	     h = _h, _h = libnvme_next_host(r, h))

/**
 * libnvme_for_each_host() - Traverse host list
 * @r:	&libnvme_root_t object
 * @h:	&libnvme_host_t object
 */
#define libnvme_for_each_host(r, h)			\
	for (h = libnvme_first_host(r); h != NULL;	\
	     h = libnvme_next_host(r, h))

/**
 * libnvme_for_each_subsystem_safe() - Traverse subsystems
 * @h:	&libnvme_host_t object
 * @s:	&libnvme_subsystem_t object
 * @_s:	Temporary &libnvme_subsystem_t object
 */
#define libnvme_for_each_subsystem_safe(h, s, _s)		\
	for (s = libnvme_first_subsystem(h),			\
	     _s = libnvme_next_subsystem(h, s);			\
	     s != NULL;						\
	     s = _s, _s = libnvme_next_subsystem(h, s))

/**
 * libnvme_for_each_subsystem() - Traverse subsystems
 * @h:	&libnvme_host_t object
 * @s:	&libnvme_subsystem_t object
 */
#define libnvme_for_each_subsystem(h, s)			\
	for (s = libnvme_first_subsystem(h); s != NULL;		\
		s = libnvme_next_subsystem(h, s))

/**
 * libnvme_subsystem_for_each_ctrl_safe() - Traverse controllers
 * @s:	&libnvme_subsystem_t object
 * @c:	Controller instance
 * @_c:	A &libnvme_ctrl_t_node to use as temporary storage
 */
#define libnvme_subsystem_for_each_ctrl_safe(s, c, _c)		\
	for (c = libnvme_subsystem_first_ctrl(s),		\
	     _c = libnvme_subsystem_next_ctrl(s, c);		\
	     c != NULL;						\
	     c = _c, _c = libnvme_subsystem_next_ctrl(s, c))

/**
 * libnvme_subsystem_for_each_ctrl() - Traverse controllers
 * @s:	&libnvme_subsystem_t object
 * @c:	Controller instance
 */
#define libnvme_subsystem_for_each_ctrl(s, c)			\
	for (c = libnvme_subsystem_first_ctrl(s); c != NULL;	\
		c = libnvme_subsystem_next_ctrl(s, c))

/**
 * libnvme_ctrl_for_each_ns_safe() - Traverse namespaces
 * @c:	Controller instance
 * @n:	&libnvme_ns_t object
 * @_n:	A &libnvme_ns_t_node to use as temporary storage
 */
#define libnvme_ctrl_for_each_ns_safe(c, n, _n)			\
	for (n = libnvme_ctrl_first_ns(c),			\
	     _n = libnvme_ctrl_next_ns(c, n);			\
	     n != NULL;						\
	     n = _n, _n = libnvme_ctrl_next_ns(c, n))

/**
 * libnvme_ctrl_for_each_ns() - Traverse namespaces
 * @c:	Controller instance
 * @n:	&libnvme_ns_t object
 */
#define libnvme_ctrl_for_each_ns(c, n)				\
	for (n = libnvme_ctrl_first_ns(c); n != NULL;		\
		n = libnvme_ctrl_next_ns(c, n))

/**
 * libnvme_ctrl_for_each_path_safe() - Traverse paths
 * @c:	Controller instance
 * @p:	&libnvme_path_t object
 * @_p:	A &libnvme_path_t_node to use as temporary storage
 */
#define libnvme_ctrl_for_each_path_safe(c, p, _p)		\
	for (p = libnvme_ctrl_first_path(c),			\
	     _p = libnvme_ctrl_next_path(c, p);			\
	     p != NULL;						\
	     p = _p, _p = libnvme_ctrl_next_path(c, p))

/**
 * libnvme_ctrl_for_each_path() - Traverse paths
 * @c:	Controller instance
 * @p:	&libnvme_path_t object
 */
#define libnvme_ctrl_for_each_path(c, p)			\
	for (p = libnvme_ctrl_first_path(c); p != NULL;		\
		p = libnvme_ctrl_next_path(c, p))

/**
 * libnvme_subsystem_for_each_ns_safe() - Traverse namespaces
 * @s:	&libnvme_subsystem_t object
 * @n:	&libnvme_ns_t object
 * @_n:	A &libnvme_ns_t_node to use as temporary storage
 */
#define libnvme_subsystem_for_each_ns_safe(s, n, _n)		\
	for (n = libnvme_subsystem_first_ns(s),			\
	     _n = libnvme_subsystem_next_ns(s, n);		\
	     n != NULL;						\
	     n = _n, _n = libnvme_subsystem_next_ns(s, n))

/**
 * libnvme_subsystem_for_each_ns() - Traverse namespaces
 * @s:	&libnvme_subsystem_t object
 * @n:	&libnvme_ns_t object
 */
#define libnvme_subsystem_for_each_ns(s, n)			\
	for (n = libnvme_subsystem_first_ns(s); n != NULL;	\
		n = libnvme_subsystem_next_ns(s, n))

/**
 * libnvme_namespace_for_each_path_safe() - Traverse paths
 * @n:	Namespace instance
 * @p:	&libnvme_path_t object
 * @_p:	A &libnvme_path_t_node to use as temporary storage
 */
#define libnvme_namespace_for_each_path_safe(n, p, _p)		\
	for (p = libnvme_namespace_first_path(n),		\
	     _p = libnvme_namespace_next_path(n, p);		\
	     p != NULL;						\
	     p = _p, _p = libnvme_namespace_next_path(n, p))

/**
 * libnvme_namespace_for_each_path() - Traverse paths
 * @n:	Namespace instance
 * @p:	&libnvme_path_t object
 */
#define libnvme_namespace_for_each_path(n, p)			\
	for (p = libnvme_namespace_first_path(n); p != NULL;	\
		p = libnvme_namespace_next_path(n, p))

/**
 * libnvme_ns_get_csi() - Command set identifier of a namespace
 * @n:	Namespace instance
 *
 * Return: The namespace's command set identifier in use
 */
enum nvme_csi libnvme_ns_get_csi(libnvme_ns_t n);

/**
 * libnvme_ns_get_eui64() - 64-bit eui of a namespace
 * @n:	Namespace instance
 *
 * Return: A pointer to the 64-bit eui
 */
const uint8_t *libnvme_ns_get_eui64(libnvme_ns_t n);

/**
 * libnvme_ns_get_nguid() - 128-bit nguid of a namespace
 * @n:	Namespace instance
 *
 * Return: A pointer to the 128-bit nguid
 */
const uint8_t *libnvme_ns_get_nguid(libnvme_ns_t n);

/**
 * libnvme_ns_get_uuid() - UUID of a namespace
 * @n:		Namespace instance
 * @out:	buffer for the UUID
 *
 * Copies the namespace's uuid into @out
 */
void libnvme_ns_get_uuid(libnvme_ns_t n, unsigned char out[NVME_UUID_LEN]);

/**
 * libnvme_ns_get_generic_name() - Returns name of generic namespace chardev.
 * @n:	Namespace instance
 *
 * Return: Name of generic namespace chardev
 */
const char *libnvme_ns_get_generic_name(libnvme_ns_t n);

/**
 * libnvme_ns_get_firmware() - Firmware string of a namespace
 * @n:	Namespace instance
 *
 * Return: Firmware string of @n
 */
const char *libnvme_ns_get_firmware(libnvme_ns_t n);

/**
 * libnvme_ns_get_serial() - Serial number of a namespace
 * @n:	Namespace instance
 *
 * Return: Serial number string of @n
 */
const char *libnvme_ns_get_serial(libnvme_ns_t n);

/**
 * libnvme_ns_get_model() - Model of a namespace
 * @n:	Namespace instance
 *
 * Return: Model string of @n
 */
const char *libnvme_ns_get_model(libnvme_ns_t n);

/**
 * libnvme_ns_get_subsystem() - &libnvme_subsystem_t of a namespace
 * @n:	Namespace instance
 *
 * Return: libnvme_subsystem_t object of @n
 */
libnvme_subsystem_t libnvme_ns_get_subsystem(libnvme_ns_t n);

/**
 * libnvme_ns_get_ctrl() - &libnvme_ctrl_t of a namespace
 * @n:	Namespace instance
 *
 * libnvme_ctrl_t object may be NULL for a multipathed namespace
 *
 * Return: libnvme_ctrl_t object of @n if present
 */
libnvme_ctrl_t libnvme_ns_get_ctrl(libnvme_ns_t n);

/**
 * libnvme_free_ns() - Free a namespace object
 * @n:	Namespace instance
 */
void libnvme_free_ns(struct libnvme_ns *n);

/**
 * libnvme_ns_read() - Read from a namespace
 * @n:		Namespace instance
 * @buf:	Buffer into which the data will be transferred
 * @offset:	LBA offset of @n
 * @count:	Number of sectors in @buf
 *
 * Return: Number of sectors read or -1 on error.
 */
int libnvme_ns_read(libnvme_ns_t n, void *buf, off_t offset, size_t count);

/**
 * libnvme_ns_write() - Write to a namespace
 * @n:		Namespace instance
 * @buf:	Buffer with data to be written
 * @offset:	LBA offset of @n
 * @count:	Number of sectors in @buf
 *
 * Return: Number of sectors written or -1 on error
 */
int libnvme_ns_write(libnvme_ns_t n, void *buf, off_t offset, size_t count);

/**
 * libnvme_ns_verify() - Verify data on a namespace
 * @n:		Namespace instance
 * @offset:	LBA offset of @n
 * @count:	Number of sectors to be verified
 *
 * Return: Number of sectors verified
 */
int libnvme_ns_verify(libnvme_ns_t n, off_t offset, size_t count);

/**
 * libnvme_ns_compare() - Compare data on a namespace
 * @n:		Namespace instance
 * @buf:	Buffer with data to be compared
 * @offset:	LBA offset of @n
 * @count:	Number of sectors in @buf
 *
 * Return: Number of sectors compared
 */
int libnvme_ns_compare(libnvme_ns_t n, void *buf, off_t offset, size_t count);

/**
 * libnvme_ns_write_zeros() - Write zeros to a namespace
 * @n:		Namespace instance
 * @offset:	LBA offset in @n
 * @count:	Number of sectors to be written
 *
 * Return: Number of sectors written
 */
int libnvme_ns_write_zeros(libnvme_ns_t n, off_t offset, size_t count);

/**
 * libnvme_ns_write_uncorrectable() - Issus a 'write uncorrectable' command
 * @n:		Namespace instance
 * @offset:	LBA offset in @n
 * @count:	Number of sectors to be written
 *
 * Return: Number of sectors written
 */
int libnvme_ns_write_uncorrectable(libnvme_ns_t n, off_t offset, size_t count);

/**
 * libnvme_ns_flush() - Flush data to a namespace
 * @n:	Namespace instance
 *
 * Return: 0 on success, -1 on error.
 */
int libnvme_ns_flush(libnvme_ns_t n);

/**
 * libnvme_ns_identify() - Issue an 'identify namespace' command
 * @n:	Namespace instance
 * @ns:	&nvme_id_ns buffer
 *
 * Writes the data returned by the 'identify namespace' command
 * into @ns.
 *
 * Return: 0 on success, -1 on error.
 */
int libnvme_ns_identify(libnvme_ns_t n, struct nvme_id_ns *ns);

/**
 * libnvme_ns_identify_descs() - Issue an 'identify descriptors' command
 * @n:		Namespace instance
 * @descs:	List of identify descriptors
 *
 * Writes the data returned by the 'identify descriptors' command
 * into @descs.
 *
 * Return: 0 on success, -1 on error.
 */
int libnvme_ns_identify_descs(libnvme_ns_t n, struct nvme_ns_id_desc *descs);

/**
 * libnvme_path_get_queue_depth() - Queue depth of an libnvme_path_t object
 * @p: &libnvme_path_t object
 *
 * Return: Queue depth of @p
 */
int libnvme_path_get_queue_depth(libnvme_path_t p);

/**
 * libnvme_path_get_ana_state() - ANA state of an nvme_path_t object
 * @p: &libnvme_path_t object
 *
 * Return: ANA state of @p
 */
char *libnvme_path_get_ana_state(libnvme_path_t p);

/**
 * libnvme_path_get_numa_nodes() - Numa nodes of an nvme_path_t object
 * @p: &libnvme_path_t object
 *
 * Return: Numa nodes of @p
 */
char *libnvme_path_get_numa_nodes(libnvme_path_t p);

/**
 * libnvme_path_get_multipath_failover_count() - Get multipath failover count
 * @p: &libnvme_path_t object
 *
 * Return: Number of times I/Os have to be failed over to another active path
 * from path @p maybe due to any transient error observed on path @p
 */
long libnvme_path_get_multipath_failover_count(libnvme_path_t p);

/**
 * libnvme_path_get_command_retry_count() - Get command retry count
 * @p: &libnvme_path_t object
 *
 * Return: Number of times any command issued to the namespace represented by
 * path @p has to be retried
 */
long libnvme_path_get_command_retry_count(libnvme_path_t p);

/**
 * libnvme_path_get_command_error_count() - Get command error count
 * @p: &libnvme_path_t object
 *
 * Return: Number of times command issued to the namespace represented by path
 * @p returns non-zero status or error
 */
long libnvme_path_get_command_error_count(libnvme_path_t p);

/**
 * libnvme_path_get_ctrl() - Parent controller of an libnvme_path_t object
 * @p:	&libnvme_path_t object
 *
 * Return: Parent controller if present
 */
libnvme_ctrl_t libnvme_path_get_ctrl(libnvme_path_t p);

/**
 * libnvme_path_get_ns() - Parent namespace of an libnvme_path_t object
 * @p:	&libnvme_path_t object
 *
 * Return: Parent namespace if present
 */
libnvme_ns_t libnvme_path_get_ns(libnvme_path_t p);

/**
 * libnvme_path_reset_stat() - Resets namespace path nvme stat
 * @p:	&libnvme_path_t object
 */
void libnvme_path_reset_stat(libnvme_path_t p);

/**
 * libnvme_path_update_stat() - Update stat of an nvme_path_t object
 * @p:		&libnvme_path_t object
 * @diffstat:	If set to true then getters return the diff stat otherwise
 *		return the current absolute stat
 *
 * Return:	0 on success, -1 on error
 */
int libnvme_path_update_stat(libnvme_path_t p, bool diffstat);

/**
 * libnvme_path_get_read_ios() - Calculate and return read IOs
 * @p:		&libnvme_path_t object
 *
 * Return:	Num of read IOs processed between two stat samples
 */
unsigned long libnvme_path_get_read_ios(libnvme_path_t p);

/**
 * libnvme_path_get_write_ios() - Get write I/Os
 * @p:		&libnvme_path_t object
 *
 * Return:	Num of write I/Os processed between two stat samples
 */
unsigned long libnvme_path_get_write_ios(libnvme_path_t p);

/**
 * libnvme_path_get_read_ticks() - Get read I/O ticks
 * @p:		&libnvme_path_t object
 *
 * Return:	Time, in milliseconds, sepnt processing read I/O requests
 *		between two stat samples
 */
unsigned int libnvme_path_get_read_ticks(libnvme_path_t p);

/**
 * libnvme_path_get_read_sectors() - Get read I/O sectors
 * @p:		&libnvme_path_t object
 *
 * Return:	Number of sectors read from the device between two stat samples
 */
unsigned long long libnvme_path_get_read_sectors(libnvme_path_t p);

/**
 * libnvme_path_get_write_sectors() - Get write I/O sectors
 * @p:		&libnvme_path_t object
 *
 * Return:	Num of sectors written to the device between two stat samples
 */
unsigned long long libnvme_path_get_write_sectors(libnvme_path_t p);

/**
 * libnvme_path_get_write_ticks() - Get write I/O ticks
 * @p:		&libnvme_path_t object
 *
 * Return:	Time, in milliseconds, sepnt processing write I/O requests
 *		between two stat samples
 */
unsigned int libnvme_path_get_write_ticks(libnvme_path_t p);

/**
 * libnvme_path_get_stat_interval() - Get interval between two stat samples
 * @p:		&libnvme_path_t object
 *
 * Return:	Interval, in milliseconds between collection of two consecutive
 *		stat samples
 */
double libnvme_path_get_stat_interval(libnvme_path_t p);

/**
 * libnvme_path_get_io_ticks() - Get I/O ticks
 * @p:		&libnvme_path_t object
 *
 * Return:	Time consumed, in milliseconds, processing I/O requests between
 *		two stat samples
 */
unsigned int libnvme_path_get_io_ticks(libnvme_path_t p);

/**
 * libnvme_path_get_inflights() - Inflight IOs for nvme_path_t object
 * @p:		&libnvme_path_t object
 *
 * Return:	Inflight number of IOs
 */
unsigned int libnvme_path_get_inflights(libnvme_path_t p);

/**
 * libnvme_ctrl_get_transport_handle() - Get associated transport handle
 * @c:	Controller instance
 *
 * libnvme will open() the device (if not already opened) and keep an
 * internal copy of the link handle. Following calls to this API retrieve
 * the internal cached copy of the link handle. The file will remain
 * opened and the handle will remain cached until the controller object
 * is deleted or libnvme_ctrl_release_transport_handle() is called.
 *
 * Return: Link handle associated with @c or NULL
 */
struct libnvme_transport_handle *
libnvme_ctrl_get_transport_handle(libnvme_ctrl_t c);

/**
 * libnvme_ctrl_release_transport_handle() - Free transport handle
 * from controller object
 * @c:	Controller instance
 *
 */
void libnvme_ctrl_release_transport_handle(libnvme_ctrl_t c);

/**
 * libnvme_ctrl_get_src_addr() - Extract src_addr from the c->address string
 * @c:	Controller instance
 * @src_addr: Where to copy the src_addr. Size must be at least
 *            INET6_ADDRSTRLEN.
 * @src_addr_len: Length of the buffer @src_addr.
 *
 * Return: Pointer to @src_addr on success. NULL on failure to extract the
 * src_addr.
 */
char *libnvme_ctrl_get_src_addr(libnvme_ctrl_t c, char *src_addr,
		size_t src_addr_len);

/**
 * libnvme_ctrl_get_state() - Running state of a controller
 * @c:	Controller instance
 *
 * Return: String indicating the running state of @c
 */
const char *libnvme_ctrl_get_state(libnvme_ctrl_t c);

/**
 * libnvme_ctrl_get_subsystem() - Parent subsystem of a controller
 * @c:	Controller instance
 *
 * Return: Parent libnvme_subsystem_t object
 */
libnvme_subsystem_t libnvme_ctrl_get_subsystem(libnvme_ctrl_t c);

/**
 * libnvme_ns_head_get_sysfs_dir() - sysfs dir of namespave head
 * @head: namespace head instance
 *
 * Returns: sysfs directory name of @head
 */
const char *libnvme_ns_head_get_sysfs_dir(libnvme_ns_head_t head);

/**
 * libnvme_ns_update_stat() - update the nvme namespace stat
 * @n:		&libnvme_ns_t object
 * @diffstat:	If set to true then getters return the diff stat otherwise
 *		return the current absolute stat
 *
 * Returns:	0 on success, -1 on error
 */
int libnvme_ns_update_stat(libnvme_ns_t n, bool diffstat);

/**
 * libnvme_ns_reset_stat() - Resets nvme namespace stat
 * @n:	&libnvme_ns_t object
 *
 */
void libnvme_ns_reset_stat(libnvme_ns_t n);

/**
 * libnvme_ns_get_inflights() - Inflight IOs for nvme_ns_t object
 * @n:		&libnvme_ns_t object
 *
 * Return:	Inflight number of IOs
 */
unsigned int libnvme_ns_get_inflights(libnvme_ns_t n);

/**
 * libnvme_ns_get_io_ticks() - Get IO ticks
 * @n:		&libnvme_ns_t object
 *
 * Return:	Time consumed, in milliseconds, processing I/O requests between
 *		two stat samples
 */
unsigned int libnvme_ns_get_io_ticks(libnvme_ns_t n);

/**
 * libnvme_ns_get_read_ticks() - Get read I/O ticks
 * @n:		&libnvme_ns_t object
 *
 * Return:	Time, in milliseconds, sepnt processing read I/O requests
 *		between two stat samples
 */
unsigned int libnvme_ns_get_read_ticks(libnvme_ns_t n);

/**
 * libnvme_ns_get_write_ticks() - Get write I/O ticks
 * @n:		&libnvme_ns_t object
 *
 * Return:	Time, in milliseconds, sepnt processing write I/O requests
 *		between two stat samples
 */
unsigned int libnvme_ns_get_write_ticks(libnvme_ns_t n);

/**
 * libnvme_ns_get_stat_interval() - Get interval between two stat samples
 * @n:		&libnvme_ns_t object
 *
 * Return:	Interval, in milliseconds, between collection of two consecutive
 *		stat samples
 */
double libnvme_ns_get_stat_interval(libnvme_ns_t n);

/**
 * libnvme_ns_get_read_ios() - Get num of read I/Os
 * @n:		&libnvme_ns_t object
 *
 * Return:	Num of read IOs processed between two stat samples
 */
unsigned long libnvme_ns_get_read_ios(libnvme_ns_t n);

/**
 * libnvme_ns_get_write_ios() - Get num of write I/Os
 * @n:		&libnvme_ns_t object
 *
 * Return:	Num of write IOs processed between two consecutive stat samples
 */
unsigned long libnvme_ns_get_write_ios(libnvme_ns_t n);

/**
 * libnvme_ns_get_read_sectors() - Get num of read sectors
 * @n:		&libnvme_ns_t object
 *
 * Return:	Num of sectors read from the device between two stat samples
 */
unsigned long long libnvme_ns_get_read_sectors(libnvme_ns_t n);

/**
 * libnvme_ns_get_write_sectors() - Get num of write sectors
 * @n:		&libnvme_ns_t object
 *
 * Return:	Num of sectors written to the device between two stat samples
 */
unsigned long long libnvme_ns_get_write_sectors(libnvme_ns_t n);

/**
 * libnvme_ctrl_identify() - Issues an 'identify controller' command
 * @c:	Controller instance
 * @id:	Identify controller data structure
 *
 * Issues an 'identify controller' command to @c and copies the
 * data into @id.
 *
 * Return: 0 on success or -1 on failure.
 */
int libnvme_ctrl_identify(libnvme_ctrl_t c, struct nvme_id_ctrl *id);

/**
 * libnvme_scan_ctrl() - Scan on a controller
 * @ctx:	struct libnvme_global_ctx object
 * @name:	Name of the controller
 * @c:		@libnvme_ctrl_t object to return
 *
 * Scans a controller with sysfs name @name and add it to @r.
 *
 * Return: 0 on success or negative error code otherwise
 */
int libnvme_scan_ctrl(struct libnvme_global_ctx *ctx, const char *name,
		libnvme_ctrl_t *c);

/**
 * libnvme_rescan_ctrl() - Rescan an existing controller
 * @c:	Controller instance
 */
void libnvme_rescan_ctrl(libnvme_ctrl_t c);

/**
 * libnvme_init_ctrl() - Initialize libnvme_ctrl_t object for an existing
 * controller.
 * @h:		libnvme_host_t object
 * @c:		libnvme_ctrl_t object
 * @instance:	Instance number (e.g. 1 for nvme1)
 *
 * Return: 0 on success or negative error code otherwise
 */
int libnvme_init_ctrl(libnvme_host_t h, libnvme_ctrl_t c, int instance);

/**
 * libnvme_free_ctrl() - Free controller
 * @c:	Controller instance
 */
void libnvme_free_ctrl(struct libnvme_ctrl *c);

/**
 * libnvme_unlink_ctrl() - Unlink controller
 * @c:	Controller instance
 */
void libnvme_unlink_ctrl(struct libnvme_ctrl *c);

/**
 * libnvme_scan_topology() - Scan NVMe topology and apply filter
 * @ctx:    struct libnvme_global_ctx object
 * @f:	    filter to apply
 * @f_args: user-specified argument to @f
 *
 * Scans the NVMe topology and filters out the resulting elements
 * by applying @f.
 *
 * Return: 0 on success, or negative error code otherwise.
 */
int libnvme_scan_topology(struct libnvme_global_ctx *ctx,
		libnvme_scan_filter_t f, void *f_args);

/**
 * libnvme_host_release_fds() - Close all opened file descriptors under host
 * @h:	libnvme_host_t object
 *
 * Controller and Namespace objects cache the file descriptors
 * of opened nvme devices. This API can be used to close and
 * clear all cached fds under this host.
 */
void libnvme_host_release_fds(struct libnvme_host *h);

/**
 * libnvme_free_host() - Free libnvme_host_t object
 * @h:	libnvme_host_t object
 */
void libnvme_free_host(libnvme_host_t h);

/**
 * libnvme_read_config() - Read NVMe JSON configuration file
 * @ctx:		&struct libnvme_global_ctx object
 * @config_file:	JSON configuration file
 *
 * Read in the contents of @config_file and merge them with
 * the elements in @r.
 *
 * Return: 0 on success or negative error code otherwise
 */
int libnvme_read_config(struct libnvme_global_ctx *ctx,
		const char *config_file);

/**
 * libnvme_refresh_topology() - Refresh libnvme_root_t object contents
 * @ctx:		&struct libnvme_global_ctx object
 *
 * Removes all elements in @r and rescans the existing topology.
 */
void libnvme_refresh_topology(struct libnvme_global_ctx *ctx);

/**
 * libnvme_dump_config() - Print the JSON configuration
 * @ctx:		&struct libnvme_global_ctx object
 * @fd:			File descriptor to write the JSON configuration.
 *
 * Writes the current contents of the JSON configuration
 * to the file descriptor fd.
 *
 * Return: 0 on success, or negative error code otherwise.
 */
int libnvme_dump_config(struct libnvme_global_ctx *ctx, int fd);

/**
 * libnvme_dump_tree() - Dump internal object tree
 * @ctx:		&struct libnvme_global_ctx object
 *
 * Prints the internal object tree in JSON format
 * to stdout.
 *
 * Return: 0 on success or negative error code otherwise
 */
int libnvme_dump_tree(struct libnvme_global_ctx *ctx);

/**
 * libnvme_get_attr() - Read sysfs attribute
 * @d:		sysfs directory
 * @attr:	sysfs attribute name
 *
 * Return: String with the contents of @attr or %NULL in case of an empty
 *         value or error.
 */
char *libnvme_get_attr(const char *d, const char *attr);

/**
 * libnvme_get_subsys_attr() - Read subsystem sysfs attribute
 * @s:		libnvme_subsystem_t object
 * @attr:	sysfs attribute name
 *
 * Return: String with the contents of @attr or %NULL in case of an empty
 *	   value or error.
 */
char *libnvme_get_subsys_attr(libnvme_subsystem_t s, const char *attr);

/**
 * libnvme_get_ctrl_attr() - Read controller sysfs attribute
 * @c:		Controller instance
 * @attr:	sysfs attribute name
 *
 * Return: String with the contents of @attr or %NULL in case of an empty value
 *	   or in case of an error.
 */
char *libnvme_get_ctrl_attr(libnvme_ctrl_t c, const char *attr);

/**
 * libnvme_get_ns_attr() - Read namespace sysfs attribute
 * @n:		libnvme_ns_t object
 * @attr:	sysfs attribute name
 *
 * Return: String with the contents of @attr or %NULL in case of an empty value
 *	   or in case of an error.
 */
char *libnvme_get_ns_attr(libnvme_ns_t n, const char *attr);

/**
 * libnvme_subsystem_lookup_namespace() - lookup namespace by NSID
 * @s:		libnvme_subsystem_t object
 * @nsid:	Namespace id
 *
 * Return: libnvme_ns_t of the namespace with id @nsid in subsystem @s
 */
libnvme_ns_t libnvme_subsystem_lookup_namespace(struct libnvme_subsystem *s,
					  __u32 nsid);

/**
 * libnvme_subsystem_release_fds() - Close all opened fds under subsystem
 * @s:		libnvme_subsystem_t object
 *
 * Controller and Namespace objects cache the file descriptors
 * of opened nvme devices. This API can be used to close and
 * clear all cached fds under this subsystem.
 *
 */
void libnvme_subsystem_release_fds(struct libnvme_subsystem *s);


/**
 * libnvme_get_path_attr() - Read path sysfs attribute
 * @p:		libnvme_path_t object
 * @attr:	sysfs attribute name
 *
 * Return: String with the contents of @attr or %NULL in case of an empty value
 *	   or in case of an error.
 */
char *libnvme_get_path_attr(libnvme_path_t p, const char *attr);

/**
 * libnvme_scan_namespace() - scan namespace based on sysfs name
 * @ctx:	&struct libnvme_global_ctx object
 * @name:	sysfs name of the namespace to scan
 * @ns:		&libnvme_ns_t object to return
 *
 * Return: 0 on success or negative error code otherwise
 */
int libnvme_scan_namespace(struct libnvme_global_ctx *ctx, const char *name,
		libnvme_ns_t *ns);
