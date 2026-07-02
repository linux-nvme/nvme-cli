// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libnvme.
 * Copyright (c) 2026, Dell Technologies Inc. or its subsidiaries.
 *
 * Authors: Martin Belanger <Martin.Belanger@dell.com>
 */

/*
 * Building blocks for the INI connection config -- see config-ini.h for the
 * contracts and libnvme/design/CONFIG.md for the format they implement.
 */

#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include <ccan/array_size/array_size.h>
#include <ccan/list/list.h>

#include "config-ini.h"

/*
 * The recognized keys.  One row per key the format accepts; the CLI option
 * name is the only spelling (CONFIG.md "Parser conventions").  See
 * enum libnvmf_key_class for what the third column means.
 */
static const struct libnvmf_key keys[] = {
	/* connection tunables; only class overridable per controller= line */
	{ "nr-io-queues",		LIBNVMF_KEY_INT,	LIBNVMF_KEY_TUNABLE },
	{ "nr-write-queues",		LIBNVMF_KEY_INT,	LIBNVMF_KEY_TUNABLE },
	{ "nr-poll-queues",		LIBNVMF_KEY_INT,	LIBNVMF_KEY_TUNABLE },
	{ "queue-size",			LIBNVMF_KEY_INT,	LIBNVMF_KEY_TUNABLE },
	{ "keep-alive-tmo",		LIBNVMF_KEY_INT,	LIBNVMF_KEY_TUNABLE },
	{ "reconnect-delay",		LIBNVMF_KEY_INT,	LIBNVMF_KEY_TUNABLE },
	{ "ctrl-loss-tmo",		LIBNVMF_KEY_INT,	LIBNVMF_KEY_TUNABLE },
	{ "fast-io-fail-tmo",		LIBNVMF_KEY_INT,	LIBNVMF_KEY_TUNABLE },
	{ "tos",			LIBNVMF_KEY_INT,	LIBNVMF_KEY_TUNABLE },
	{ "duplicate-connect",		LIBNVMF_KEY_BOOL,	LIBNVMF_KEY_TUNABLE },
	{ "disable-sqflow",		LIBNVMF_KEY_BOOL,	LIBNVMF_KEY_TUNABLE },
	{ "hdr-digest",			LIBNVMF_KEY_BOOL,	LIBNVMF_KEY_TUNABLE },
	{ "data-digest",		LIBNVMF_KEY_BOOL,	LIBNVMF_KEY_TUNABLE },

	/* security -- bound to (hostnqn, subsysnqn); never per-path */
	{ "tls",			LIBNVMF_KEY_BOOL,	LIBNVMF_KEY_SECURITY },
	{ "concat",			LIBNVMF_KEY_BOOL,	LIBNVMF_KEY_SECURITY },
	{ "tls-key",			LIBNVMF_KEY_STRING,	LIBNVMF_KEY_SECURITY },
	{ "tls-key-identity",		LIBNVMF_KEY_STRING,	LIBNVMF_KEY_SECURITY },
	{ "keyring",			LIBNVMF_KEY_STRING,	LIBNVMF_KEY_SECURITY },
	{ "dhchap-secret",		LIBNVMF_KEY_STRING,	LIBNVMF_KEY_SECURITY },
	{ "dhchap-ctrl-secret",		LIBNVMF_KEY_STRING,	LIBNVMF_KEY_SECURITY },

	/* host identity -- [Host] only */
	{ "hostnqn",			LIBNVMF_KEY_STRING,	LIBNVMF_KEY_IDENTITY },
	{ "hostid",			LIBNVMF_KEY_STRING,	LIBNVMF_KEY_IDENTITY },
	{ "hostsymname",		LIBNVMF_KEY_STRING,	LIBNVMF_KEY_IDENTITY },

	/* endpoint sections only */
	{ "nqn",			LIBNVMF_KEY_STRING,	LIBNVMF_KEY_NQN },
	{ "controller",			LIBNVMF_KEY_STRING,	LIBNVMF_KEY_CONTROLLER },
};

const struct libnvmf_key *libnvmf_key_lookup(const char *name)
{
	size_t i;

	if (!name)
		return NULL;
	for (i = 0; i < ARRAY_SIZE(keys); i++) {
		if (!strcmp(keys[i].name, name))
			return &keys[i];
	}

	return NULL;
}

int libnvmf_parse_bool(const char *value, bool *out)
{
	static const char * const yes[] = {
		"1", "yes", "y", "true", "t", "on"
	};
	static const char * const no[] = {
		"0", "no", "n", "false", "f", "off"
	};
	size_t i;

	if (!value || !out)
		return -EINVAL;

	for (i = 0; i < ARRAY_SIZE(yes); i++) {
		if (!strcasecmp(value, yes[i])) {
			*out = true;
			return 0;
		}
	}
	for (i = 0; i < ARRAY_SIZE(no); i++) {
		if (!strcasecmp(value, no[i])) {
			*out = false;
			return 0;
		}
	}

	return -EINVAL;
}

static int check_int(const char *value)
{
	char *end;
	long v;

	errno = 0;
	v = strtol(value, &end, 0);
	if (errno || *end || end == value || v < INT_MIN || v > INT_MAX)
		return -EINVAL;

	return 0;
}

int libnvmf_key_check_value(const struct libnvmf_key *key, const char *value)
{
	bool b;

	if (!key || !value)
		return -EINVAL;

	/* The reset form ("key =") is valid for every key. */
	if (!*value)
		return 0;

	switch (key->type) {
	case LIBNVMF_KEY_INT:
		return check_int(value);
	case LIBNVMF_KEY_BOOL:
		return libnvmf_parse_bool(value, &b);
	case LIBNVMF_KEY_STRING:
		return 0;
	}

	return -EINVAL;
}

struct kv {
	struct list_node entry;
	char *key;
	char *value;
};

/*
 * One member on purpose: this is the public opaque type (config.h), kept a
 * distinct struct so ccan/list stays an internal implementation choice
 * rather than leaking into the ABI.
 */
struct libnvmf_params {
	struct list_head list;
};

struct libnvmf_params *libnvmf_params_new(void)
{
	struct libnvmf_params *p = calloc(1, sizeof(*p));

	if (!p)
		return NULL;
	list_head_init(&p->list);

	return p;
}

void libnvmf_params_free(struct libnvmf_params *p)
{
	struct kv *e, *next;

	if (!p)
		return;
	list_for_each_safe(&p->list, e, next, entry) {
		free(e->key);
		free(e->value);
		free(e);
	}
	free(p);
}

static struct kv *kv_find(const struct libnvmf_params *p, const char *key)
{
	struct kv *e;

	list_for_each(&p->list, e, entry) {
		if (!strcmp(e->key, key))
			return e;
	}

	return NULL;
}

/* Allocate a new entry for @key, taking ownership of @value, and append it. */
static int kv_append(struct libnvmf_params *p, const char *key, char *value)
{
	struct kv *e = calloc(1, sizeof(*e));

	if (!e)
		return -ENOMEM;
	e->key = strdup(key);
	if (!e->key) {
		free(e);
		return -ENOMEM;
	}
	e->value = value;
	list_add_tail(&p->list, &e->entry);

	return 0;
}

int libnvmf_params_set(struct libnvmf_params *p, const char *key,
		const char *value)
{
	struct kv *e;
	char *copy;

	if (!p || !key || !value)
		return -EINVAL;

	copy = strdup(value);
	if (!copy)
		return -ENOMEM;

	e = kv_find(p, key);
	if (e) {
		free(e->value);
		e->value = copy;
		return 0;
	}

	if (kv_append(p, key, copy)) {
		free(copy);
		return -ENOMEM;
	}

	return 0;
}

__libnvme_public const char *libnvmf_params_get(const struct libnvmf_params *p,
		const char *key)
{
	struct kv *e;

	if (!p || !key)
		return NULL;
	e = kv_find(p, key);

	return e ? e->value : NULL;
}

int libnvmf_params_merge(struct libnvmf_params *dst,
		const struct libnvmf_params *src)
{
	struct kv *e;
	int ret;

	if (!dst || !src)
		return -EINVAL;

	list_for_each(&src->list, e, entry) {
		ret = libnvmf_params_set(dst, e->key, e->value);
		if (ret)
			return ret;
	}

	return 0;
}

struct libnvmf_params *libnvmf_params_dup(const struct libnvmf_params *p)
{
	struct libnvmf_params *copy;

	if (!p)
		return NULL;
	copy = libnvmf_params_new();
	if (!copy)
		return NULL;
	if (libnvmf_params_merge(copy, p)) {
		libnvmf_params_free(copy);
		return NULL;
	}

	return copy;
}

__libnvme_public void libnvmf_params_for_each(const struct libnvmf_params *p,
		void (*callback)(const char *key, const char *value,
				 void *user_data),
		void *user_data)
{
	struct kv *e;

	if (!p || !callback)
		return;
	list_for_each(&p->list, e, entry)
		callback(e->key, e->value, user_data);
}
