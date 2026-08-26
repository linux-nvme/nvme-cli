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

struct libnvme_host;
struct libnvme_subsystem;
struct libnvme_ctrl;
struct libnvme_ns;
struct libnvme_ns_head;
struct libnvme_path;

typedef bool (*libnvme_scan_filter_t)(struct libnvme_subsystem *, struct libnvme_ctrl *,
				   struct libnvme_ns *, void *);

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
 * Return: First &struct libnvme_host object in an iterator
 */
struct libnvme_host *libnvme_first_host(struct libnvme_global_ctx *ctx);

/**
 * libnvme_next_host() - Next host iterator
 * @ctx:	struct libnvme_global_ctx object
 * @h:	Previous &struct libnvme_host iterator
 *
 * Return: Next &struct libnvme_host object in an iterator
 */
struct libnvme_host *libnvme_next_host(struct libnvme_global_ctx *ctx,
		struct libnvme_host *h);

/**
 * libnvme_host_get_global_ctx() - Returns libnvme_global_ctx object
 * @h:	&struct libnvme_host object
 *
 * Return: &struct libnvme_global_ctx object from @h
 */
struct libnvme_global_ctx *libnvme_host_get_global_ctx(struct libnvme_host *h);

/**
 * libnvme_get_host() - Returns a host object
 * @ctx:	struct libnvme_global_ctx object
 * @hostnqn:	Host NQN (optional)
 * @hostid:	Host ID (optional)
 * @h:		&struct libnvme_host object to return
 *
 * Returns a host object based on the hostnqn/hostid values or the default if
 * hostnqn/hostid are NULL.
 *
 * Return: 0 on success, negative error code otherwise.
 */
int libnvme_get_host(struct libnvme_global_ctx *ctx, const char *hostnqn,
		const char *hostid, struct libnvme_host **h);

/**
 * libnvme_first_subsystem() - Start subsystem iterator
 * @h:	&struct libnvme_host object
 *
 * Return: first &struct libnvme_subsystem object in an iterator
 */
struct libnvme_subsystem *libnvme_first_subsystem(struct libnvme_host *h);

/**
 * libnvme_next_subsystem() - Next subsystem iterator
 * @h:	&struct libnvme_host object
 * @s:	Previous &struct libnvme_subsystem iterator
 *
 * Return: next &struct libnvme_subsystem object in an iterator
 */
struct libnvme_subsystem *libnvme_next_subsystem(struct libnvme_host *h,
		struct libnvme_subsystem *s);

/**
 * libnvme_get_subsystem() - Returns struct libnvme_subsystem object
 * @ctx:	struct libnvme_global_ctx object
 * @h:		&struct libnvme_host object
 * @name:	Name of the subsystem (may be NULL)
 * @subsysnqn:	Subsystem NQN
 * @s: 		struct libnvme_subsystem object
 *
 * Returns an &struct libnvme_subsystem object in @h base on @name (if present)
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
 * libnvme_subsystem_get_host() - Returns struct libnvme_host object
 * @s:	subsystem
 *
 * Return: &struct libnvme_host object from @s
 */
struct libnvme_host *libnvme_subsystem_get_host(struct libnvme_subsystem *s);

/**
 * libnvme_ctrl_first_ns() - Start namespace iterator
 * @c:	Controller instance
 *
 * Return: First &struct libnvme_ns object of an @c iterator
 */
struct libnvme_ns *libnvme_ctrl_first_ns(struct libnvme_ctrl *c);

/**
 * libnvme_ctrl_next_ns() - Next namespace iterator
 * @c:	Controller instance
 * @n:	Previous struct libnvme_ns iterator
 *
 * Return: Next struct libnvme_ns object of an @c iterator
 */
struct libnvme_ns *libnvme_ctrl_next_ns(struct libnvme_ctrl *c, struct libnvme_ns *n);

/**
 * libnvme_ctrl_first_path() - Start path iterator
 * @c:	Controller instance
 *
 * Return: First &struct libnvme_path object of an @c iterator
 */
struct libnvme_path *libnvme_ctrl_first_path(struct libnvme_ctrl *c);

/**
 * libnvme_ctrl_next_path() - Next path iterator
 * @c:	Controller instance
 * @p:	Previous &struct libnvme_path object of an @c iterator
 *
 * Return: Next &struct libnvme_path object of an @c iterator
 */
struct libnvme_path *libnvme_ctrl_next_path(struct libnvme_ctrl *c, struct libnvme_path *p);

/**
 * libnvme_subsystem_first_ctrl() - First ctrl iterator
 * @s:	&struct libnvme_subsystem object
 *
 * Return: First controller of an @s iterator
 */
struct libnvme_ctrl *libnvme_subsystem_first_ctrl(struct libnvme_subsystem *s);

/**
 * libnvme_subsystem_next_ctrl() - Next ctrl iterator
 * @s:	&struct libnvme_subsystem object
 * @c:	Previous controller instance of an @s iterator
 *
 * Return: Next controller of an @s iterator
 */
struct libnvme_ctrl *libnvme_subsystem_next_ctrl(struct libnvme_subsystem *s,
		struct libnvme_ctrl *c);

/**
 * libnvme_namespace_first_path() - Start path iterator
 * @ns:	Namespace instance
 *
 * Return: First &struct libnvme_path object of an @ns iterator
 */
struct libnvme_path *libnvme_namespace_first_path(struct libnvme_ns *ns);

/**
 * libnvme_namespace_next_path() - Next path iterator
 * @ns:	Namespace instance
 * @p:	Previous &struct libnvme_path object of an @ns iterator
 *
 * Return: Next &struct libnvme_path object of an @ns iterator
 */
struct libnvme_path *libnvme_namespace_next_path(struct libnvme_ns *ns, struct libnvme_path *p);

/**
 * libnvme_subsystem_first_ns() - Start namespace iterator
 * @s:	&struct libnvme_subsystem object
 *
 * Return: First &struct libnvme_ns object of an @s iterator
 */
struct libnvme_ns *libnvme_subsystem_first_ns(struct libnvme_subsystem *s);

/**
 * libnvme_subsystem_next_ns() - Next namespace iterator
 * @s:	&struct libnvme_subsystem object
 * @n:	Previous &struct libnvme_ns iterator
 *
 * Return: Next &struct libnvme_ns object of an @s iterator
 */
struct libnvme_ns *libnvme_subsystem_next_ns(struct libnvme_subsystem *s, struct libnvme_ns *n);

/**
 * libnvme_for_each_host_safe() - Traverse host list
 * @r:	&libnvme_root_t object
 * @h:	&struct libnvme_host object
 * @_h:	Temporary &struct libnvme_host object
 */
#define libnvme_for_each_host_safe(r, h, _h)		\
	for (h = libnvme_first_host(r),			\
	     _h = libnvme_next_host(r, h);		\
	     h != NULL;					\
	     h = _h, _h = libnvme_next_host(r, h))

/**
 * libnvme_for_each_host() - Traverse host list
 * @r:	&libnvme_root_t object
 * @h:	&struct libnvme_host object
 */
#define libnvme_for_each_host(r, h)			\
	for (h = libnvme_first_host(r); h != NULL;	\
	     h = libnvme_next_host(r, h))

/**
 * libnvme_for_each_subsystem_safe() - Traverse subsystems
 * @h:	&struct libnvme_host object
 * @s:	&struct libnvme_subsystem object
 * @_s:	Temporary &struct libnvme_subsystem object
 */
#define libnvme_for_each_subsystem_safe(h, s, _s)		\
	for (s = libnvme_first_subsystem(h),			\
	     _s = libnvme_next_subsystem(h, s);			\
	     s != NULL;						\
	     s = _s, _s = libnvme_next_subsystem(h, s))

/**
 * libnvme_for_each_subsystem() - Traverse subsystems
 * @h:	&struct libnvme_host object
 * @s:	&struct libnvme_subsystem object
 */
#define libnvme_for_each_subsystem(h, s)			\
	for (s = libnvme_first_subsystem(h); s != NULL;		\
		s = libnvme_next_subsystem(h, s))

/**
 * libnvme_subsystem_for_each_ctrl_safe() - Traverse controllers
 * @s:	&struct libnvme_subsystem object
 * @c:	Controller instance
 * @_c:	A &struct libnvme_ctrl node to use as temporary storage
 */
#define libnvme_subsystem_for_each_ctrl_safe(s, c, _c)		\
	for (c = libnvme_subsystem_first_ctrl(s),		\
	     _c = libnvme_subsystem_next_ctrl(s, c);		\
	     c != NULL;						\
	     c = _c, _c = libnvme_subsystem_next_ctrl(s, c))

/**
 * libnvme_subsystem_for_each_ctrl() - Traverse controllers
 * @s:	&struct libnvme_subsystem object
 * @c:	Controller instance
 */
#define libnvme_subsystem_for_each_ctrl(s, c)			\
	for (c = libnvme_subsystem_first_ctrl(s); c != NULL;	\
		c = libnvme_subsystem_next_ctrl(s, c))

/**
 * libnvme_ctrl_for_each_ns_safe() - Traverse namespaces
 * @c:	Controller instance
 * @n:	&struct libnvme_ns object
 * @_n:	A &struct libnvme_ns node to use as temporary storage
 */
#define libnvme_ctrl_for_each_ns_safe(c, n, _n)			\
	for (n = libnvme_ctrl_first_ns(c),			\
	     _n = libnvme_ctrl_next_ns(c, n);			\
	     n != NULL;						\
	     n = _n, _n = libnvme_ctrl_next_ns(c, n))

/**
 * libnvme_ctrl_for_each_ns() - Traverse namespaces
 * @c:	Controller instance
 * @n:	&struct libnvme_ns object
 */
#define libnvme_ctrl_for_each_ns(c, n)				\
	for (n = libnvme_ctrl_first_ns(c); n != NULL;		\
		n = libnvme_ctrl_next_ns(c, n))

/**
 * libnvme_ctrl_for_each_path_safe() - Traverse paths
 * @c:	Controller instance
 * @p:	&struct libnvme_path object
 * @_p:	A &struct libnvme_path node to use as temporary storage
 */
#define libnvme_ctrl_for_each_path_safe(c, p, _p)		\
	for (p = libnvme_ctrl_first_path(c),			\
	     _p = libnvme_ctrl_next_path(c, p);			\
	     p != NULL;						\
	     p = _p, _p = libnvme_ctrl_next_path(c, p))

/**
 * libnvme_ctrl_for_each_path() - Traverse paths
 * @c:	Controller instance
 * @p:	&struct libnvme_path object
 */
#define libnvme_ctrl_for_each_path(c, p)			\
	for (p = libnvme_ctrl_first_path(c); p != NULL;		\
		p = libnvme_ctrl_next_path(c, p))

/**
 * libnvme_subsystem_for_each_ns_safe() - Traverse namespaces
 * @s:	&struct libnvme_subsystem object
 * @n:	&struct libnvme_ns object
 * @_n:	A &struct libnvme_ns node to use as temporary storage
 */
#define libnvme_subsystem_for_each_ns_safe(s, n, _n)		\
	for (n = libnvme_subsystem_first_ns(s),			\
	     _n = libnvme_subsystem_next_ns(s, n);		\
	     n != NULL;						\
	     n = _n, _n = libnvme_subsystem_next_ns(s, n))

/**
 * libnvme_subsystem_for_each_ns() - Traverse namespaces
 * @s:	&struct libnvme_subsystem object
 * @n:	&struct libnvme_ns object
 */
#define libnvme_subsystem_for_each_ns(s, n)			\
	for (n = libnvme_subsystem_first_ns(s); n != NULL;	\
		n = libnvme_subsystem_next_ns(s, n))

/**
 * libnvme_namespace_for_each_path_safe() - Traverse paths
 * @n:	Namespace instance
 * @p:	&struct libnvme_path object
 * @_p:	A &struct libnvme_path node to use as temporary storage
 */
#define libnvme_namespace_for_each_path_safe(n, p, _p)		\
	for (p = libnvme_namespace_first_path(n),		\
	     _p = libnvme_namespace_next_path(n, p);		\
	     p != NULL;						\
	     p = _p, _p = libnvme_namespace_next_path(n, p))

/**
 * libnvme_namespace_for_each_path() - Traverse paths
 * @n:	Namespace instance
 * @p:	&struct libnvme_path object
 */
#define libnvme_namespace_for_each_path(n, p)			\
	for (p = libnvme_namespace_first_path(n); p != NULL;	\
		p = libnvme_namespace_next_path(n, p))

/**
 * libnvme_ns_get_firmware() - Firmware string of a namespace
 * @n:	Namespace instance
 *
 * Return: Firmware string of @n
 */
const char *libnvme_ns_get_firmware(struct libnvme_ns *n);

/**
 * libnvme_ns_get_serial() - Serial number of a namespace
 * @n:	Namespace instance
 *
 * Return: Serial number string of @n
 */
const char *libnvme_ns_get_serial(struct libnvme_ns *n);

/**
 * libnvme_ns_get_model() - Model of a namespace
 * @n:	Namespace instance
 *
 * Return: Model string of @n
 */
const char *libnvme_ns_get_model(struct libnvme_ns *n);

/**
 * libnvme_ns_get_subsystem() - &struct libnvme_subsystem of a namespace
 * @n:	Namespace instance
 *
 * Return: struct libnvme_subsystem object of @n
 */
struct libnvme_subsystem *libnvme_ns_get_subsystem(struct libnvme_ns *n);

/**
 * libnvme_ns_get_ctrl() - &struct libnvme_ctrl of a namespace
 * @n:	Namespace instance
 *
 * struct libnvme_ctrl object may be NULL for a multipathed namespace
 *
 * Return: struct libnvme_ctrl object of @n if present
 */
struct libnvme_ctrl *libnvme_ns_get_ctrl(struct libnvme_ns *n);

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
int libnvme_ns_read(struct libnvme_ns *n, void *buf, off_t offset, size_t count);

/**
 * libnvme_ns_write() - Write to a namespace
 * @n:		Namespace instance
 * @buf:	Buffer with data to be written
 * @offset:	LBA offset of @n
 * @count:	Number of sectors in @buf
 *
 * Return: Number of sectors written or -1 on error
 */
int libnvme_ns_write(struct libnvme_ns *n, void *buf, off_t offset, size_t count);

/**
 * libnvme_ns_verify() - Verify data on a namespace
 * @n:		Namespace instance
 * @offset:	LBA offset of @n
 * @count:	Number of sectors to be verified
 *
 * Return: Number of sectors verified
 */
int libnvme_ns_verify(struct libnvme_ns *n, off_t offset, size_t count);

/**
 * libnvme_ns_compare() - Compare data on a namespace
 * @n:		Namespace instance
 * @buf:	Buffer with data to be compared
 * @offset:	LBA offset of @n
 * @count:	Number of sectors in @buf
 *
 * Return: Number of sectors compared
 */
int libnvme_ns_compare(struct libnvme_ns *n, void *buf, off_t offset, size_t count);

/**
 * libnvme_ns_write_zeros() - Write zeros to a namespace
 * @n:		Namespace instance
 * @offset:	LBA offset in @n
 * @count:	Number of sectors to be written
 *
 * Return: Number of sectors written
 */
int libnvme_ns_write_zeros(struct libnvme_ns *n, off_t offset, size_t count);

/**
 * libnvme_ns_write_uncorrectable() - Issus a 'write uncorrectable' command
 * @n:		Namespace instance
 * @offset:	LBA offset in @n
 * @count:	Number of sectors to be written
 *
 * Return: Number of sectors written
 */
int libnvme_ns_write_uncorrectable(struct libnvme_ns *n, off_t offset, size_t count);

/**
 * libnvme_ns_flush() - Flush data to a namespace
 * @n:	Namespace instance
 *
 * Return: 0 on success, negative error code otherwise.
 */
int libnvme_ns_flush(struct libnvme_ns *n);

/**
 * libnvme_ns_identify() - Issue an 'identify namespace' command
 * @n:	Namespace instance
 * @ns:	&nvme_id_ns buffer
 *
 * Writes the data returned by the 'identify namespace' command
 * into @ns.
 *
 * Return: 0 on success, negative error code otherwise.
 */
int libnvme_ns_identify(struct libnvme_ns *n, struct nvme_id_ns *ns);

/**
 * libnvme_ns_identify_descs() - Issue an 'identify descriptors' command
 * @n:		Namespace instance
 * @descs:	List of identify descriptors
 *
 * Writes the data returned by the 'identify descriptors' command
 * into @descs.
 *
 * Return: 0 on success, negative error code otherwise.
 */
int libnvme_ns_identify_descs(struct libnvme_ns *n, struct nvme_ns_id_desc *descs);

/**
 * libnvme_path_get_ctrl() - Parent controller of an struct libnvme_path object
 * @p:	&struct libnvme_path object
 *
 * Return: Parent controller if present
 */
struct libnvme_ctrl *libnvme_path_get_ctrl(struct libnvme_path *p);

/**
 * libnvme_path_get_ns() - Parent namespace of an struct libnvme_path object
 * @p:	&struct libnvme_path object
 *
 * Return: Parent namespace if present
 */
struct libnvme_ns *libnvme_path_get_ns(struct libnvme_path *p);

/**
 * libnvme_path_reset_stat() - Resets namespace path nvme stat
 * @p:	&struct libnvme_path object
 */
void libnvme_path_reset_stat(struct libnvme_path *p);

/**
 * libnvme_path_update_stat() - Update stat of an nvme_path_t object
 * @p:		&struct libnvme_path object
 * @diffstat:	If set to true then getters return the diff stat otherwise
 *		return the current absolute stat
 *
 * Return: 0 on success, negative error code otherwise.
 */
int libnvme_path_update_stat(struct libnvme_path *p, bool diffstat);

/**
 * libnvme_path_get_read_ios() - Calculate and return read IOs
 * @p:		&struct libnvme_path object
 *
 * Return:	Num of read IOs processed between two stat samples
 */
unsigned long libnvme_path_get_read_ios(struct libnvme_path *p);

/**
 * libnvme_path_get_write_ios() - Get write I/Os
 * @p:		&struct libnvme_path object
 *
 * Return:	Num of write I/Os processed between two stat samples
 */
unsigned long libnvme_path_get_write_ios(struct libnvme_path *p);

/**
 * libnvme_path_get_read_ticks() - Get read I/O ticks
 * @p:		&struct libnvme_path object
 *
 * Return:	Time, in milliseconds, sepnt processing read I/O requests
 *		between two stat samples
 */
unsigned int libnvme_path_get_read_ticks(struct libnvme_path *p);

/**
 * libnvme_path_get_read_sectors() - Get read I/O sectors
 * @p:		&struct libnvme_path object
 *
 * Return:	Number of sectors read from the device between two stat samples
 */
unsigned long long libnvme_path_get_read_sectors(struct libnvme_path *p);

/**
 * libnvme_path_get_write_sectors() - Get write I/O sectors
 * @p:		&struct libnvme_path object
 *
 * Return:	Num of sectors written to the device between two stat samples
 */
unsigned long long libnvme_path_get_write_sectors(struct libnvme_path *p);

/**
 * libnvme_path_get_write_ticks() - Get write I/O ticks
 * @p:		&struct libnvme_path object
 *
 * Return:	Time, in milliseconds, sepnt processing write I/O requests
 *		between two stat samples
 */
unsigned int libnvme_path_get_write_ticks(struct libnvme_path *p);

/**
 * libnvme_path_get_stat_interval() - Get interval between two stat samples
 * @p:		&struct libnvme_path object
 *
 * Return:	Interval, in milliseconds between collection of two consecutive
 *		stat samples
 */
double libnvme_path_get_stat_interval(struct libnvme_path *p);

/**
 * libnvme_path_get_io_ticks() - Get I/O ticks
 * @p:		&struct libnvme_path object
 *
 * Return:	Time consumed, in milliseconds, processing I/O requests between
 *		two stat samples
 */
unsigned int libnvme_path_get_io_ticks(struct libnvme_path *p);

/**
 * libnvme_path_get_inflights() - Inflight IOs for nvme_path_t object
 * @p:		&struct libnvme_path object
 *
 * Return:	Inflight number of IOs
 */
unsigned int libnvme_path_get_inflights(struct libnvme_path *p);

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
libnvme_ctrl_get_transport_handle(struct libnvme_ctrl *c);

/**
 * libnvme_ctrl_release_transport_handle() - Free transport handle
 * from controller object
 * @c:	Controller instance
 *
 */
void libnvme_ctrl_release_transport_handle(struct libnvme_ctrl *c);

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
char *libnvme_ctrl_get_src_addr(struct libnvme_ctrl *c, char *src_addr,
		size_t src_addr_len);

/**
 * libnvme_ctrl_get_state() - Running state of a controller
 * @c:	Controller instance
 *
 * Return: String indicating the running state of @c
 */
const char *libnvme_ctrl_get_state(struct libnvme_ctrl *c);

/**
 * libnvme_transport_is_fabric() - True for a fabrics transport string
 * @transport:	Transport name, e.g. "tcp", "pcie"
 *
 * A transport is either local (pcie, apple-nvme) or NVMe-over-Fabrics
 * (tcp, rdma, fc, loop). Use this when only the transport string is
 * available, e.g. before a controller exists to ask
 * libnvme_ctrl_is_transport_fabric() instead.
 *
 * Return: true if @transport is a fabrics transport, false if local.
 */
bool libnvme_transport_is_fabric(const char *transport);

/**
 * libnvme_ctrl_is_transport_fabric() - True for a fabrics transport
 * @c:	Controller instance
 *
 * A controller is reachable either over a local transport (pcie,
 * apple-nvme) or over NVMe-over-Fabrics (tcp, rdma, fc, loop).
 *
 * Return: true if @c uses a fabrics transport, false if local.
 */
bool libnvme_ctrl_is_transport_fabric(struct libnvme_ctrl *c);

/**
 * libnvme_ctrl_owner() - Registered orchestrator owner of a controller
 * @c:	Controller instance
 *
 * Looks up the controller's "owner" entry in the ownership registry.  In a
 * build without fabrics support this always returns NULL.
 *
 * Return: a newly allocated owner string (the caller frees), or NULL if the
 * controller is unowned, local (non-fabrics), or the registry is unreadable.
 */
char *libnvme_ctrl_owner(struct libnvme_ctrl *c);

/**
 * libnvme_ctrl_get_subsystem() - Parent subsystem of a controller
 * @c:	Controller instance
 *
 * Return: Parent struct libnvme_subsystem object
 */
struct libnvme_subsystem *libnvme_ctrl_get_subsystem(struct libnvme_ctrl *c);

/**
 * libnvme_ns_head_get_sysfs_dir() - sysfs dir of namespave head
 * @head: namespace head instance
 *
 * Return: sysfs directory name of @head
 */
const char *libnvme_ns_head_get_sysfs_dir(struct libnvme_ns_head *head);

/**
 * libnvme_ns_update_stat() - update the nvme namespace stat
 * @n:		&struct libnvme_ns object
 * @diffstat:	If set to true then getters return the diff stat otherwise
 *		return the current absolute stat
 *
 * Return: 0 on success, negative error code otherwise.
 */
int libnvme_ns_update_stat(struct libnvme_ns *n, bool diffstat);

/**
 * libnvme_ns_reset_stat() - Resets nvme namespace stat
 * @n:	&struct libnvme_ns object
 *
 */
void libnvme_ns_reset_stat(struct libnvme_ns *n);

/**
 * libnvme_ns_get_inflights() - Inflight IOs for nvme_ns_t object
 * @n:		&struct libnvme_ns object
 *
 * Return:	Inflight number of IOs
 */
unsigned int libnvme_ns_get_inflights(struct libnvme_ns *n);

/**
 * libnvme_ns_get_io_ticks() - Get IO ticks
 * @n:		&struct libnvme_ns object
 *
 * Return:	Time consumed, in milliseconds, processing I/O requests between
 *		two stat samples
 */
unsigned int libnvme_ns_get_io_ticks(struct libnvme_ns *n);

/**
 * libnvme_ns_get_read_ticks() - Get read I/O ticks
 * @n:		&struct libnvme_ns object
 *
 * Return:	Time, in milliseconds, sepnt processing read I/O requests
 *		between two stat samples
 */
unsigned int libnvme_ns_get_read_ticks(struct libnvme_ns *n);

/**
 * libnvme_ns_get_write_ticks() - Get write I/O ticks
 * @n:		&struct libnvme_ns object
 *
 * Return:	Time, in milliseconds, sepnt processing write I/O requests
 *		between two stat samples
 */
unsigned int libnvme_ns_get_write_ticks(struct libnvme_ns *n);

/**
 * libnvme_ns_get_stat_interval() - Get interval between two stat samples
 * @n:		&struct libnvme_ns object
 *
 * Return:	Interval, in milliseconds, between collection of two consecutive
 *		stat samples
 */
double libnvme_ns_get_stat_interval(struct libnvme_ns *n);

/**
 * libnvme_ns_get_read_ios() - Get num of read I/Os
 * @n:		&struct libnvme_ns object
 *
 * Return:	Num of read IOs processed between two stat samples
 */
unsigned long libnvme_ns_get_read_ios(struct libnvme_ns *n);

/**
 * libnvme_ns_get_write_ios() - Get num of write I/Os
 * @n:		&struct libnvme_ns object
 *
 * Return:	Num of write IOs processed between two consecutive stat samples
 */
unsigned long libnvme_ns_get_write_ios(struct libnvme_ns *n);

/**
 * libnvme_ns_get_read_sectors() - Get num of read sectors
 * @n:		&struct libnvme_ns object
 *
 * Return:	Num of sectors read from the device between two stat samples
 */
unsigned long long libnvme_ns_get_read_sectors(struct libnvme_ns *n);

/**
 * libnvme_ns_get_write_sectors() - Get num of write sectors
 * @n:		&struct libnvme_ns object
 *
 * Return:	Num of sectors written to the device between two stat samples
 */
unsigned long long libnvme_ns_get_write_sectors(struct libnvme_ns *n);

/**
 * libnvme_ctrl_identify() - Issues an 'identify controller' command
 * @c:	Controller instance
 * @id:	Identify controller data structure
 *
 * Issues an 'identify controller' command to @c and copies the
 * data into @id.
 *
 * Return: 0 on success, negative error code otherwise.
 */
int libnvme_ctrl_identify(struct libnvme_ctrl *c, struct nvme_id_ctrl *id);

/**
 * libnvme_scan_ctrl() - Scan on a controller
 * @ctx:	struct libnvme_global_ctx object
 * @name:	Name of the controller
 * @c:		@struct libnvme_ctrl object to return
 *
 * Scans a controller with sysfs name @name and add it to @r.
 *
 * Return: 0 on success, negative error code otherwise.
 */
int libnvme_scan_ctrl(struct libnvme_global_ctx *ctx, const char *name,
		struct libnvme_ctrl **c);

/**
 * libnvme_rescan_ctrl() - Rescan an existing controller
 * @c:	Controller instance
 */
void libnvme_rescan_ctrl(struct libnvme_ctrl *c);

/**
 * libnvme_init_ctrl() - Initialize struct libnvme_ctrl object for an existing
 * controller.
 * @h:		struct libnvme_host object
 * @c:		struct libnvme_ctrl object
 * @instance:	Instance number (e.g. 1 for nvme1)
 *
 * Return: 0 on success, negative error code otherwise.
 */
int libnvme_init_ctrl(struct libnvme_host *h, struct libnvme_ctrl *c, int instance);

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
 * Return: 0 on success, negative error code otherwise.
 */
int libnvme_scan_topology(struct libnvme_global_ctx *ctx,
		libnvme_scan_filter_t f, void *f_args);

/**
 * libnvme_host_release_fds() - Close all opened file descriptors under host
 * @h:	struct libnvme_host object
 *
 * Controller and Namespace objects cache the file descriptors
 * of opened nvme devices. This API can be used to close and
 * clear all cached fds under this host.
 */
void libnvme_host_release_fds(struct libnvme_host *h);

/**
 * libnvme_free_host() - Free struct libnvme_host object
 * @h:	struct libnvme_host object
 */
void libnvme_free_host(struct libnvme_host *h);

/**
 * libnvme_refresh_topology() - Refresh libnvme_root_t object contents
 * @ctx:		&struct libnvme_global_ctx object
 *
 * Removes all elements in @r and rescans the existing topology.
 *
 * Returns: 0 on success, negative error code otherwise.
 */
int libnvme_refresh_topology(struct libnvme_global_ctx *ctx);

/**
 * libnvme_get_attr() - Read sysfs attribute
 * @d:		sysfs directory
 * @attr:	sysfs attribute name
 *
 * Return: A newly allocated string with the contents of @attr (the caller
 *         frees), or %NULL in case of an empty value or error.
 */
char *libnvme_get_attr(const char *d, const char *attr);

/**
 * libnvme_get_subsys_attr() - Read subsystem sysfs attribute
 * @s:		struct libnvme_subsystem object
 * @attr:	sysfs attribute name
 *
 * Return: A newly allocated string with the contents of @attr (the caller
 *	   frees), or %NULL in case of an empty value or error.
 */
char *libnvme_get_subsys_attr(struct libnvme_subsystem *s, const char *attr);

/**
 * libnvme_get_ctrl_attr() - Read controller sysfs attribute
 * @c:		Controller instance
 * @attr:	sysfs attribute name
 *
 * Return: A newly allocated string with the contents of @attr (the caller
 *	   frees), or %NULL in case of an empty value or error.
 */
char *libnvme_get_ctrl_attr(struct libnvme_ctrl *c, const char *attr);

/**
 * libnvme_get_ns_attr() - Read namespace sysfs attribute
 * @n:		struct libnvme_ns object
 * @attr:	sysfs attribute name
 *
 * Return: A newly allocated string with the contents of @attr (the caller
 *	   frees), or %NULL in case of an empty value or error.
 */
char *libnvme_get_ns_attr(struct libnvme_ns *n, const char *attr);

/**
 * libnvme_subsystem_lookup_namespace() - lookup namespace by NSID
 * @s:		struct libnvme_subsystem object
 * @nsid:	Namespace id
 *
 * Return: struct libnvme_ns of the namespace with id @nsid in subsystem @s
 */
struct libnvme_ns *libnvme_subsystem_lookup_namespace(struct libnvme_subsystem *s,
					  __u32 nsid);

/**
 * libnvme_subsystem_release_fds() - Close all opened fds under subsystem
 * @s:		struct libnvme_subsystem object
 *
 * Controller and Namespace objects cache the file descriptors
 * of opened nvme devices. This API can be used to close and
 * clear all cached fds under this subsystem.
 *
 */
void libnvme_subsystem_release_fds(struct libnvme_subsystem *s);


/**
 * libnvme_get_path_attr() - Read path sysfs attribute
 * @p:		struct libnvme_path object
 * @attr:	sysfs attribute name
 *
 * Return: A newly allocated string with the contents of @attr (the caller
 *	   frees), or %NULL in case of an empty value or error.
 */
char *libnvme_get_path_attr(struct libnvme_path *p, const char *attr);

/**
 * libnvme_scan_namespace() - scan namespace based on sysfs name
 * @ctx:	&struct libnvme_global_ctx object
 * @name:	sysfs name of the namespace to scan
 * @ns:		&struct libnvme_ns object to return
 *
 * Return: 0 on success, negative error code otherwise.
 */
int libnvme_scan_namespace(struct libnvme_global_ctx *ctx, const char *name,
		struct libnvme_ns **ns);
