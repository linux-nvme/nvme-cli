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

/*
 * Internal building blocks for the INI connection config
 * (libnvme/design/CONFIG.md): the connection-parameter bag with its
 * three-state values, and the table of recognized keys.
 */

/*
 * A connection-parameter bag.  Every cascade-able parameter is in one of
 * three states, which is what makes the precedence cascade and the
 * reset-to-kernel-default form ("key =") expressible:
 *
 *   key absent      ->  unset: inherit from the next cascade level;
 *   value == ""     ->  reset: stop inheriting, let the kernel default apply;
 *   value == "..."  ->  set to that value.
 *
 * Values are kept as the strings the file spelled; they are validated on the
 * way in (libnvmf_key_check_value) and interpreted on the way out (the
 * emitter).  Iteration preserves first-insertion order.
 */
struct libnvmf_params;

struct libnvmf_params *libnvmf_params_new(void);
struct libnvmf_params *libnvmf_params_dup(const struct libnvmf_params *p);
void libnvmf_params_free(struct libnvmf_params *p);

/* Set @key to @value (replacing an earlier value); "" records a reset. */
int libnvmf_params_set(struct libnvmf_params *p, const char *key,
		const char *value);

/* NULL = unset; "" = reset; anything else = the set value. */
const char *libnvmf_params_get(const struct libnvmf_params *p,
		const char *key);

/* Overlay @src onto @dst: every key present in @src wins. */
int libnvmf_params_merge(struct libnvmf_params *dst,
		const struct libnvmf_params *src);

typedef void (*libnvmf_params_fn)(const char *key, const char *value,
		void *user_data);
void libnvmf_params_for_each(const struct libnvmf_params *p,
		libnvmf_params_fn callback, void *user_data);

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
 * The raw model of ONE parsed file -- sections and lines faithfully
 * recorded, nothing resolved.  The cascade resolver (which merges the
 * top-level file with the drop-ins and expands endpoints into connections)
 * consumes a list of these.  Struct members are open because this is an
 * internal type; nothing here crosses the public API boundary.
 */

struct libnvme_global_ctx;

/*
 * One parsed file -- the top-level nvme-fabrics.conf or one drop-in under
 * nvme-fabrics.conf.d/; both use this same representation.
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

/* One controller= line: one path to an endpoint (see CONFIG.md Multipath). */
struct libnvmf_conf_path {
	struct list_node entry;
	/*
	 * Addressing as the file spelled it: traddr/host_traddr are raw
	 * strings, not a TID (see libnvme/design/TID.md for why).
	 * subsysnqn and the host identity are filled in at resolve time.
	 */
	char *transport;
	char *traddr;
	char *trsvcid;
	char *host_traddr;
	char *host_iface;
	/* per-path tunables; never security */
	struct libnvmf_params *overrides;
	unsigned int line;	/* for diagnostics */
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
