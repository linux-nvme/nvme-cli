/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * This file is part of libnvme.
 * Copyright (c) 2026, Dell Technologies Inc. or its subsidiaries.
 *
 * Authors: Martin Belanger <Martin.Belanger@dell.com>
 */
#pragma once

#include <stdbool.h>

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
