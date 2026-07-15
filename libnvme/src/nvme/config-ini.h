/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * This file is part of libnvme.
 * Copyright (c) 2026, Dell Technologies Inc. or its subsidiaries.
 *
 * Authors: Martin Belanger <Martin.Belanger@dell.com>
 */
#pragma once

#include <stdbool.h>

#include <ccan/list/list.h>

#include <nvme/config.h>

#define CONFIG_MAIN_PATH SYSCONFDIR "/nvme/nvme-fabrics.conf"

/*
 * Internal building blocks for the INI connection configuration:
 * the connection-parameter store that tracks unset, reset, and explicit
 * values, and the table of recognized keys.
 */

/*
 * Stores connection parameters used during configuration cascading.
 * Each cascadeable parameter has one of three states:
 *
 *   key absent      -> unset: inherit from the next cascade level;
 *   value == ""     -> reset: stop inheriting and use the kernel default;
 *   value == "..."  -> set to the specified value.
 *
 * Values are stored as strings from the configuration file. They are
 * validated when added (libnvmf_key_check_value) and interpreted when
 * emitted. Iteration order follows the order in which keys were inserted.
 * The store itself is public (new/set/get/for_each/free live in
 * <nvme/config.h>); only the whole-store operations below stay internal.
 */
struct libnvmf_params *libnvmf_params_dup(const struct libnvmf_params *p);

/* Overlay @src onto @dst: every key present in @src wins. */
int libnvmf_params_merge(struct libnvmf_params *dst,
		const struct libnvmf_params *src);

/*
 * The recognized configuration keys.  The key class encodes where a key may
 * appear; the type drives value validation.
 */
enum libnvmf_key_type {
	LIBNVMF_KEY_STRING,
	LIBNVMF_KEY_INT,
	LIBNVMF_KEY_BOOL
};

/* See the keys[] table in config-ini.c for each key's class. */
enum libnvmf_key_class {
	LIBNVMF_KEY_TUNABLE,	/* any section; per-path override allowed */
	LIBNVMF_KEY_SECURITY,	/* any section; NEVER on a controller= line */
	LIBNVMF_KEY_IDENTITY,	/* [Host] only: hostnqn, hostid, hostsymname */
	LIBNVMF_KEY_NQN,	/* endpoint sections only: nqn */
	LIBNVMF_KEY_CONTROLLER,	/* endpoint sections only: ctrl (repeatable) */
};

struct libnvmf_key {
	const char *name;
	enum libnvmf_key_type type;
	enum libnvmf_key_class class;
};

/* Return the table entry for @name, or NULL for an unknown key. */
const struct libnvmf_key *libnvmf_key_lookup(const char *name);

/*
 * Validate @value against @key's type.  An empty value (the reset form) is
 * always valid.  Returns 0 or -EINVAL.
 */
int libnvmf_key_check_value(const struct libnvmf_key *key, const char *value);

/* The boolean spellings the config format accepts (case-insensitive). */
int libnvmf_parse_bool(const char *value, bool *out);

/*
 * Raw configuration model for a single parsed file.
 *
 * The parser records the file contents without applying precedence or
 * inheritance rules. The resolver combines the main file and any drop-ins
 * to produce the resolved connection list.
 *
 * This is an internal type. Its members are not part of the public API.
 */

struct libnvme_global_ctx;

/*
 * Raw configuration model for one parsed configuration file.
 *
 * Used for both the main configuration file and individual drop-in files.
 */
struct libnvmf_conf_file {
	char *path;			/* provenance, diagnostics */
	struct libnvmf_params *dc_defaults;
	struct libnvmf_params *ioc_defaults;
	bool has_host;			/* file carries a [Host] section */
	char *hostnqn;
	char *hostid;
	char *hostsymname;
	struct libnvmf_params *host_params;  /* [Host] non-identity keys */
	struct list_head endpoints;	/* libnvmf_conf_endpoint, file order */
};

/* One [Discovery Controller] or [Subsystem] section, identified by is_dc. */
struct libnvmf_conf_endpoint {
	struct list_node entry;
	bool is_dc;
	char *nqn;			/* NULL on a DC = well-known NQN */
	struct libnvmf_params *params;	/* section keys incl. security */
	struct list_head paths;		/* struct libnvmf_conf_path */
	unsigned int line;
};

/* One controller= line: one path to an endpoint. */
struct libnvmf_conf_path {
	struct list_node entry;
	char *transport;
	char *traddr;
	char *trsvcid;
	char *host_traddr;
	char *host_iface;
	/* per-path tunables; never security */
	struct libnvmf_params *overrides;
	unsigned int line;
};

/*
 * Parse one file into its raw configuration model.
 *
 * Structural errors, such as keys in invalid sections, invalid values, or
 * malformed controller= lines, cause the entire file to fail parsing.
 *
 * On success, the output file pointer is initialized.
 *
 * Returns:
 *   0 on success;
 *   a negative error code on failure.
 */
int libnvmf_conf_file_parse(
		struct libnvme_global_ctx *ctx,
		const char *path, struct libnvmf_conf_file **file);
void libnvmf_conf_file_free(struct libnvmf_conf_file *f);

/*
 * Resolved configuration.
 *
 * Contains the flat list of connections produced from the configuration
 * files after all precedence rules have been applied. Consumers see only
 * resolved connections; files and sections remain internal.
 *
 * These are the definitions behind the opaque public types declared in
 * <nvme/config.h>. Their members are not part of the public API.
 */
struct libnvmf_config_conn {
	struct list_node entry;
	bool is_dc;
	char *transport;
	char *traddr;
	char *trsvcid;
	char *host_traddr;
	char *host_iface;
	char *subsysnqn;
	char *hostnqn;
	char *hostid;
	struct libnvmf_params *params;
	char *hostsymname; /* Discovery Information Entry (DIE) symbolic name */
	char *source;      /* originating file */
	unsigned int line; /* its controller= line */
	/*
	 * DC only: the resolved defaults for controllers *discovered* via this
	 * DC (referral DCs / DLP IOCs), i.e. its file scope minus any endpoint
	 * level.
	 */
	struct libnvmf_params *dlp_dc_params;
	struct libnvmf_params *dlp_ioc_params;
};

struct libnvmf_config {
	/* Main file's connections first, then the sorted drop-ins'. */
	struct list_head conns;		/* struct libnvmf_config_conn */
	/*
	 * Top-level scope defaults for discovered controllers with no
	 * via-DC (an mDNS-found DC).
	 */
	struct libnvmf_params *top_dc_params;
	struct libnvmf_params *top_ioc_params;
};

/*
 * Load and resolve the configuration file at @path and any drop-in files
 * under <path>.d.
 *
 * A missing configuration file or drop-in directory is not an error; in that
 * case an empty configuration is returned.  A fatal validation or parsing
 * error in any file fails the load as a unit, leaving *@out NULL.
 *
 * The public libnvmf_config_read()/libnvmf_config_validate() wrap this with
 * the default-path handling; libnvmf_config_free() releases the result.
 *
 * Returns 0 on success, a negative error code on failure.
 */
int libnvmf_config_load(struct libnvme_global_ctx *ctx, const char *path,
		struct libnvmf_config **out);

/* The scandir() filter selecting *.conf drop-ins. */
struct dirent;
int libnvmf_conf_dropin_filter(const struct dirent *d);
