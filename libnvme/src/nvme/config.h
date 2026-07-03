/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * This file is part of libnvme.
 * Copyright (c) 2026, Dell Technologies Inc. or its subsidiaries.
 *
 * Authors: Martin Belanger <Martin.Belanger@dell.com>
 */
#pragma once

#include <stdbool.h>

struct libnvme_global_ctx;
struct libnvmf_tid;

/**
 * DOC: config.h
 *
 * NVMe-oF connection configuration.
 *
 * The configuration consists of a main INI file and optional .conf drop-ins
 * under <file>.d/. At load time, these inputs are resolved into a flat list
 * of connections. Each connection contains the complete role, addressing,
 * identity, and parameter set after all defaults and overrides have been
 * applied.
 *
 * Files, sections, and drop-ins are internal representation details and are
 * not exposed through this API.
 *
 * The configuration API is read-only. It provides access to resolved
 * connection data but does not provide setters.
 *
 * Connection configuration support is available only when NVMe-oF fabrics
 * support is enabled.
 */

/**
 * struct libnvmf_config - a resolved connection configuration.
 *
 * Opaque handle owning the resolved connection list.  Obtained from
 * libnvmf_config_read(), released with libnvmf_config_free().
 */
struct libnvmf_config;

/**
 * struct libnvmf_config_conn - one resolved connection.
 *
 * Opaque; one future "nvme connect".  Only valid while the owning
 * struct libnvmf_config is alive.
 */
struct libnvmf_config_conn;

/**
 * struct libnvmf_params - a resolved connection-parameter set.
 *
 * Opaque map of connection parameters, keyed by the configuration key
 * names (which are the "nvme connect" long-option names).  Each parameter
 * is either absent (unset: the kernel default applies), the empty string
 * (an explicit reset to the kernel default), or a value string.
 */
struct libnvmf_params;

/**
 * libnvmf_config_read() - read and resolve a connection configuration.
 * @ctx:  libnvme global context
 * @file: main configuration file, or NULL for the default
 *        (/etc/nvme/nvme-fabrics.conf).  The drop-in directory is always
 *        derived from the file name: the .conf files under <file>.d/.
 * @out:  the resolved configuration on success; NULL on error
 *
 * Reads the main file (if it exists) and the drop-ins (if the directory
 * exists) and resolves them into the flat connection list.  An absent
 * configuration is valid and yields an empty list.  Any validation error
 * in any file fails the read as a unit; diagnostics carry file:line and
 * are reported through @ctx.
 *
 * Return: 0 on success (*@out is the resolved configuration), negative
 * errno otherwise (*@out is NULL).
 */
int libnvmf_config_read(struct libnvme_global_ctx *ctx, const char *file,
		struct libnvmf_config **out);

/**
 * libnvmf_config_free() - release a resolved configuration.
 * @config: configuration to free; NULL is a no-op.
 *
 * Invalidates every connection and parameter set obtained from @config.
 */
void libnvmf_config_free(struct libnvmf_config *config);

/**
 * libnvmf_config_validate() - dry-run a connection configuration.
 * @ctx:  libnvme global context
 * @file: main configuration file, or NULL for the default.
 *
 * Reads and resolves like libnvmf_config_read(), reporting every
 * diagnostic through @ctx, without handing back a configuration.
 *
 * Return: 0 when the configuration is valid (including absent),
 * negative errno otherwise.
 */
int libnvmf_config_validate(struct libnvme_global_ctx *ctx, const char *file);

/**
 * libnvmf_config_conn_for_each() - iterate over the resolved connections.
 * @config:    the resolved configuration
 * @callback:  called once per connection, in file order (main file first,
 *             then the drop-ins in sorted order)
 * @user_data: caller context passed to @callback
 */
void libnvmf_config_conn_for_each(const struct libnvmf_config *config,
		void (*callback)(const struct libnvmf_config_conn *conn,
				 void *user_data),
		void *user_data);

/**
 * libnvmf_config_conn_is_dc() - is this connection a discovery controller?
 * @conn: the resolved connection
 *
 * Return: true for a discovery controller, false for an I/O controller.
 */
bool libnvmf_config_conn_is_dc(const struct libnvmf_config_conn *conn);

/**
 * libnvmf_config_conn_get_transport() - a connection's transport.
 * @conn: the resolved connection
 *
 * Addressing is exposed as raw strings, not a TID: the configuration is a
 * human interface and traddr/host-traddr may legitimately name a host,
 * while TID construction rejects one.  Resolve first, then build a TID
 * with libnvmf_tid_from_fields() + libnvmf_tid_set_identity().
 *
 * Return: borrowed string, valid while the owning configuration is alive.
 */
const char *libnvmf_config_conn_get_transport(
		const struct libnvmf_config_conn *conn);

/**
 * libnvmf_config_conn_get_traddr() - a connection's transport address.
 * @conn: the resolved connection
 *
 * May be a hostname; see libnvmf_config_conn_get_transport().
 *
 * Return: borrowed string, valid while the owning configuration is alive.
 */
const char *libnvmf_config_conn_get_traddr(
		const struct libnvmf_config_conn *conn);

/**
 * libnvmf_config_conn_get_trsvcid() - a connection's transport service ID.
 * @conn: the resolved connection
 *
 * Return: borrowed string, or NULL when unset (the transport default
 * applies).
 */
const char *libnvmf_config_conn_get_trsvcid(
		const struct libnvmf_config_conn *conn);

/**
 * libnvmf_config_conn_get_subsysnqn() - a connection's subsystem NQN.
 * @conn: the resolved connection
 *
 * Return: borrowed string; the well-known discovery NQN for a discovery
 * controller with no explicit nqn.
 */
const char *libnvmf_config_conn_get_subsysnqn(
		const struct libnvmf_config_conn *conn);

/**
 * libnvmf_config_conn_get_host_traddr() - a connection's host transport
 * address.
 * @conn: the resolved connection
 *
 * May be a hostname; see libnvmf_config_conn_get_transport().
 *
 * Return: borrowed string, or NULL when the path left it unset.
 */
const char *libnvmf_config_conn_get_host_traddr(
		const struct libnvmf_config_conn *conn);

/**
 * libnvmf_config_conn_get_host_iface() - a connection's host interface
 * binding.
 * @conn: the resolved connection
 *
 * Return: borrowed string, or NULL when the path left it unset.
 */
const char *libnvmf_config_conn_get_host_iface(
		const struct libnvmf_config_conn *conn);

/**
 * libnvmf_config_conn_get_hostnqn() - a connection's host NQN.
 * @conn: the resolved connection
 *
 * Return: borrowed string, or NULL when the configuration leaves the host
 * identity to the system default (the connect path applies its usual
 * /etc/nvme/hostnqn fallback).
 */
const char *libnvmf_config_conn_get_hostnqn(
		const struct libnvmf_config_conn *conn);

/**
 * libnvmf_config_conn_get_hostid() - a connection's host identifier.
 * @conn: the resolved connection
 *
 * Return: borrowed string, or NULL when the configuration leaves the host
 * identity to the system default (the connect path applies its usual
 * hostid fallback).
 */
const char *libnvmf_config_conn_get_hostid(
		const struct libnvmf_config_conn *conn);

/**
 * libnvmf_config_conn_get_params() - a connection's resolved parameters.
 * @conn: the resolved connection
 *
 * Every cascade level is already merged; what remains unset is a "use the
 * kernel default".
 *
 * Return: borrowed pointer, valid while the owning configuration is alive.
 */
const struct libnvmf_params *libnvmf_config_conn_get_params(
		const struct libnvmf_config_conn *conn);

/**
 * libnvmf_config_conn_get_hostsymname() - the persona's symbolic name.
 * @conn: the resolved connection
 *
 * Return: borrowed string, or NULL when the persona has none.
 */
const char *libnvmf_config_conn_get_hostsymname(
		const struct libnvmf_config_conn *conn);

/**
 * libnvmf_config_conn_get_source() - the file a connection came from.
 * @conn: the resolved connection
 *
 * Provenance for diagnostics and "config show" style output.
 *
 * Return: borrowed string; the originating file's path.
 */
const char *libnvmf_config_conn_get_source(
		const struct libnvmf_config_conn *conn);

/**
 * libnvmf_config_resolve_discovered() - parameters for a controller that is
 * not in the configuration.
 * @config: the resolved configuration
 * @via_dc: the DC connection the controller was discovered through, or NULL
 *          for a controller with no configured origin (e.g. an
 *          mDNS-discovered DC)
 * @is_dc:  true for a discovered discovery controller (a referral), false
 *          for a discovered I/O controller
 *
 * A controller learned at runtime -- from a discovery log page, an AEN, or
 * mDNS -- has no section in the configuration, but still draws parameters
 * from it: the defaults of the file scope it was discovered through, or the
 * top-level scope when it has no configured origin.  The four combinations:
 *
 *   (via_dc = DC,   is_dc = true)   a referral: a DC discovered via a DC;
 *                                   draws that DC's DC-defaults scope
 *   (via_dc = DC,   is_dc = false)  a DLP-discovered IOC; draws that DC's
 *                                   IOC-defaults scope
 *   (via_dc = NULL, is_dc = true)   a DC with no configured origin (e.g.
 *                                   mDNS); draws the top-level DC scope
 *   (via_dc = NULL, is_dc = false)  an IOC with no configured origin;
 *                                   draws the top-level IOC scope
 *
 * Return: borrowed parameter set, valid while @config is alive.  @via_dc must
 * be a connection of @config; an I/O-controller @via_dc yields NULL.  Passing
 * a connection that does not belong to @config is undefined.
 */
const struct libnvmf_params *libnvmf_config_resolve_discovered(
		const struct libnvmf_config *config,
		const struct libnvmf_config_conn *via_dc,
		bool is_dc);

/**
 * libnvmf_connect_args_emit() - render a connection as "nvme connect"
 * options.
 * @tid:       addressing + identity, or NULL to emit the parameters only
 * @params:    connection parameters, or NULL to emit the TID only
 * @callback:  called once per formatted option, e.g. "--transport=tcp";
 *             the string is only valid for the duration of the call
 * @user_data: caller context passed to @callback
 *
 * Emits the TID's set fields first, in fixed order (--transport, --traddr,
 * --trsvcid, --nqn, --host-traddr, --host-iface, --hostnqn, --hostid),
 * then the parameters in their iteration order.  Unset and reset
 * parameters are skipped so the kernel default applies; a boolean
 * parameter is emitted as a bare "--flag" when true and skipped when
 * false.  Consumer-private options are the caller's to append.
 *
 * This is the consumption path for the resolved configuration: each
 * connection becomes the option list of one "nvme connect" invocation.
 * It also renders a connection as a human-readable, copy-pasteable
 * command line for "config show" style output.
 *
 * Return: 0 on success, -EINVAL when @callback is NULL, -ENOMEM when
 * formatting an option fails (the emission stops there).
 */
int libnvmf_connect_args_emit(const struct libnvmf_tid *tid,
		const struct libnvmf_params *params,
		void (*callback)(const char *arg, void *user_data),
		void *user_data);

/**
 * struct libnvmf_config_emitter - Configuration emitter.
 *
 * Opaque type used to build and write an NVMe Fabrics configuration.
 */
struct libnvmf_config_emitter;

/**
 * libnvmf_config_emit_new() - Create a configuration emitter.
 * @ctx: libnvme global context. Must not be NULL.
 *
 * Return: A new emitter on success, or NULL on failure.
 * Free the emitter with libnvmf_config_emit_free().
 */
struct libnvmf_config_emitter *libnvmf_config_emit_new(
		struct libnvme_global_ctx *ctx);

/**
 * libnvmf_config_emit_free() - Free a configuration emitter.
 * @emitter: Emitter to free. NULL is ignored.
 */
void libnvmf_config_emit_free(struct libnvmf_config_emitter *emitter);

/**
 * libnvmf_config_emit_add() - Add a connection to a configuration emitter.
 * @emitter:     Configuration emitter.
 * @is_dc:       Discovery controller if true, I/O controller if false.
 * @transport:   Transport type. Required.
 * @traddr:      Transport address. Required. Written verbatim, even if a
 *               hostname; resolution happens at connect time, not here.
 * @trsvcid:     Transport service ID, or NULL.
 * @subsysnqn:   Subsystem NQN. Required unless @is_dc is true.
 * @host_traddr: Host transport address, or NULL.
 * @host_iface:  Host interface, or NULL.
 * @hostnqn:     Host NQN, or NULL.
 * @hostid:      Host identifier, or NULL.
 * @params:      Connection parameters, or NULL.
 * @hostsymname: Host symbolic name, or NULL.
 *
 * The parameter set is copied by the emitter.
 *
 * Return:
 * * 0 on success.
 * * -EINVAL if a required parameter is missing or if @hostsymname
 *   conflicts with an existing persona.
 * * -ENOMEM if memory allocation fails.
 */
int libnvmf_config_emit_add(struct libnvmf_config_emitter *emitter,
		bool is_dc, const char *transport, const char *traddr,
		const char *trsvcid, const char *subsysnqn,
		const char *host_traddr, const char *host_iface,
		const char *hostnqn, const char *hostid,
		const struct libnvmf_params *params, const char *hostsymname);

/**
 * libnvmf_config_emit_install() - Write a configuration to disk.
 * @emitter: Configuration emitter.
 * @file:  Destination configuration file, or NULL to use the default
 *         configuration file.
 * @force: Overwrite an existing configuration if true.
 *
 * The default persona is written to the main configuration file. Each
 * named persona is written to a separate drop-in file.
 *
 * The generated configuration is validated by reading it back through the
 * standard parser before it is installed. Files are written atomically
 * (temporary file followed by rename). If any step fails, no configuration
 * is installed.
 *
 * Return:
 * * 0 on success.
 * * -EEXIST if a configuration already exists and @force is false.
 * * -EINVAL if @emitter is NULL.
 * * A negative errno value on other failures.
 */
int libnvmf_config_emit_install(struct libnvmf_config_emitter *emitter,
		const char *file, bool force);

/**
 * libnvmf_params_new() - Create a connection parameter set.
 *
 * Return: A new parameter set on success, or NULL on failure.
 * Free the parameter set with libnvmf_params_free().
 */
struct libnvmf_params *libnvmf_params_new(void);

/**
 * libnvmf_params_free() - Free a connection parameter set.
 * @params: Parameter set to free. NULL is ignored.
 *
 * Only free a set obtained from libnvmf_params_new(); never call this on
 * a set borrowed from a configuration.
 */
void libnvmf_params_free(struct libnvmf_params *params);

/**
 * libnvmf_params_set() - Set a connection parameter.
 * @params: Caller-owned parameter set.
 * @key:   Parameter name.
 * @value: Parameter value as a string. An empty string restores the
 *         kernel default for the parameter.
 *
 * If the parameter already exists, its value is replaced.
 *
 * Return:
 * * 0 on success.
 * * -EINVAL if @key is unknown, is not a connection parameter,
 *   or if @value is invalid for the parameter type.
 * * -ENOMEM if memory allocation fails.
 */
int libnvmf_params_set(struct libnvmf_params *params, const char *key,
		const char *value);

/**
 * libnvmf_params_get() - look up one connection parameter.
 * @params: a resolved parameter set
 * @key:    the configuration key name (the "nvme connect" long-option name,
 *          e.g. "ctrl-loss-tmo")
 *
 * Return: NULL when @key is unset (the kernel default applies), the empty
 * string for an explicit reset to the kernel default, the value string
 * otherwise.  Borrowed; valid while the owning configuration is alive.
 */
const char *libnvmf_params_get(const struct libnvmf_params *params,
		const char *key);

/**
 * libnvmf_params_for_each() - iterate over set connection parameters.
 * @params:    a resolved parameter set
 * @callback:  called once per key in first-insertion order; @value is the
 *             empty string for an explicit reset, never NULL
 * @user_data: caller context passed to @callback
 */
void libnvmf_params_for_each(const struct libnvmf_params *params,
		void (*callback)(const char *key, const char *value,
				 void *user_data),
		void *user_data);
