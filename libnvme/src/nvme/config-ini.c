// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libnvme.
 * Copyright (c) 2026, Dell Technologies Inc. or its subsidiaries.
 *
 * Authors: Martin Belanger <Martin.Belanger@dell.com>
 */

/*
 * Building blocks for the INI configuration parser.
 */

#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include <ccan/array_size/array_size.h>
#include <ccan/list/list.h>

#include "compiler-attributes.h"
#include "config-ini.h"
#include "ini.h"
#include "lib.h"
#include "private-fabrics.h"
#include "util.h"

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

enum sect {
	SECT_NONE,	/* before the first section header */
	SECT_IGNORED,	/* an unknown section, reserved for the future */
	SECT_DC_DEFAULTS,
	SECT_IOC_DEFAULTS,
	SECT_HOST,
	SECT_DC,
	SECT_SUBSYS,
};

struct conf_parse {
	struct libnvme_global_ctx *ctx;
	const char *path;
	struct libnvmf_conf_file *f;
	enum sect sect;
	struct libnvmf_conf_endpoint *ep; /* current, when sect is DC/SUBSYS */
	int err;
};

#define conf_err(pc, line, fmt, ...) do {				\
	libnvme_msg((pc)->ctx, LIBNVME_LOG_ERR, "%s:%u: " fmt "\n",	\
		    (pc)->path, line, ##__VA_ARGS__);			\
	(pc)->err = -EINVAL;						\
} while (0)

#define conf_warn(pc, line, fmt, ...)					\
	libnvme_msg((pc)->ctx, LIBNVME_LOG_WARN, "%s:%u: " fmt "\n",	\
		    (pc)->path, line, ##__VA_ARGS__)

static void free_path(struct libnvmf_conf_path *p)
{
	if (!p)
		return;
	free(p->transport);
	free(p->traddr);
	free(p->trsvcid);
	free(p->host_traddr);
	free(p->host_iface);
	libnvmf_params_free(p->overrides);
	free(p);
}

static void free_paths(struct list_head *paths)
{
	struct libnvmf_conf_path *p, *next;

	list_for_each_safe(paths, p, next, entry)
		free_path(p);
}

void libnvmf_conf_file_free(struct libnvmf_conf_file *f)
{
	struct libnvmf_conf_endpoint *e, *next;

	if (!f)
		return;
	list_for_each_safe(&f->endpoints, e, next, entry) {
		free(e->nqn);
		libnvmf_params_free(e->params);
		free_paths(&e->paths);
		free(e);
	}
	libnvmf_params_free(f->dc_defaults);
	libnvmf_params_free(f->ioc_defaults);
	libnvmf_params_free(f->host_params);
	free(f->hostnqn);
	free(f->hostid);
	free(f->hostsymname);
	free(f->path);
	free(f);
}

static int new_endpoint(struct conf_parse *pc, bool is_dc, unsigned int line)
{
	struct libnvmf_conf_endpoint *ep;

	ep = calloc(1, sizeof(*ep));
	if (!ep)
		return -ENOMEM;
	ep->is_dc = is_dc;
	ep->line = line;
	ep->params = libnvmf_params_new();
	if (!ep->params) {
		free(ep);
		return -ENOMEM;
	}
	list_head_init(&ep->paths);

	list_add_tail(&pc->f->endpoints, &ep->entry);
	pc->ep = ep;

	return 0;
}

static int enter_section(struct conf_parse *pc, const char *name,
			 unsigned int line)
{
	struct libnvmf_conf_file *f = pc->f;

	pc->ep = NULL;

	if (!strcmp(name, "Discovery Controller Defaults")) {
		if (f->dc_defaults)
			conf_warn(pc, line, "repeated [%s] section", name);
		else
			f->dc_defaults = libnvmf_params_new();
		pc->sect = f->dc_defaults ? SECT_DC_DEFAULTS : SECT_IGNORED;
		return f->dc_defaults ? 0 : -ENOMEM;
	}
	if (!strcmp(name, "I/O Controller Defaults")) {
		if (f->ioc_defaults)
			conf_warn(pc, line, "repeated [%s] section", name);
		else
			f->ioc_defaults = libnvmf_params_new();
		pc->sect = f->ioc_defaults ? SECT_IOC_DEFAULTS :
					     SECT_IGNORED;
		return f->ioc_defaults ? 0 : -ENOMEM;
	}
	if (!strcmp(name, "Host")) {
		/* Hard singleton: personas never merge (CONFIG.md). */
		if (f->has_host) {
			conf_err(pc, line,
				 "second [Host] section; one persona, one file");
			return -EINVAL;
		}
		f->has_host = true;
		f->host_params = libnvmf_params_new();
		if (!f->host_params)
			return -ENOMEM;
		pc->sect = SECT_HOST;
		return 0;
	}
	if (!strcmp(name, "Discovery Controller")) {
		pc->sect = SECT_DC;
		return new_endpoint(pc, true, line);
	}
	if (!strcmp(name, "Subsystem")) {
		pc->sect = SECT_SUBSYS;
		return new_endpoint(pc, false, line);
	}

	conf_warn(pc, line, "unknown section [%s] ignored", name);
	pc->sect = SECT_IGNORED;

	return 0;
}

struct path_addr {
	const char *transport;
	const char *traddr;
	const char *trsvcid;
	const char *host_traddr;
	const char *host_iface;
};

static const char **addr_slot(struct path_addr *a, const char *key)
{
	if (!strcmp(key, "transport"))
		return &a->transport;
	if (!strcmp(key, "traddr"))
		return &a->traddr;
	if (!strcmp(key, "trsvcid"))
		return &a->trsvcid;
	if (!strcmp(key, "host-traddr"))
		return &a->host_traddr;
	if (!strcmp(key, "host-iface"))
		return &a->host_iface;

	return NULL;
}

/*
 * Parse one "controller =" value.
 *
 * Addressing keys are stored as raw path addressing fields. Tunable keys are
 * stored as per-path overrides.
 *
 * Unknown keys are rejected intentionally. A misspelled addressing option
 * must not silently result in a different connection.
 *
 * The parser accepts hostnames in addressing fields, so it tokenizes the
 * value directly instead of constructing a TID here. TID construction is
 * performed later by the consumer.
 */
static int add_path(struct conf_parse *pc, char *value, unsigned int line)
{
	struct libnvmf_conf_path *path;
	struct path_addr addr = { 0 };
	struct libnvmf_params *overrides;
	char *save = NULL, *tok;
	int ret = -EINVAL;

	overrides = libnvmf_params_new();
	if (!overrides)
		return -ENOMEM;

	for (tok = strtok_r(value, ";", &save); tok;
	     tok = strtok_r(NULL, ";", &save)) {
		const struct libnvmf_key *k;
		const char **slot;
		char *eq, *key, *val;

		key = libnvmf_trim(tok);
		if (!*key)
			continue; /* ";;" and a trailing ';' are benign */
		eq = strchr(key, '=');
		if (!eq || eq == key) {
			conf_err(pc, line, "malformed token \"%s\"", key);
			goto fail;
		}
		*eq = '\0';
		key = libnvmf_trim(key);
		val = libnvmf_trim(eq + 1);

		slot = addr_slot(&addr, key);
		if (slot) {
			if (!*val) {
				conf_err(pc, line, "empty %s", key);
				goto fail;
			}
			if (*slot) {
				conf_err(pc, line, "repeated %s", key);
				goto fail;
			}
			*slot = val;
			continue;
		}

		k = libnvmf_key_lookup(key);
		if (!k) {
			conf_err(pc, line,
				 "unknown key \"%s\" on a controller line",
				 key);
			goto fail;
		}
		switch (k->class) {
		case LIBNVMF_KEY_TUNABLE:
			if (libnvmf_key_check_value(k, val)) {
				conf_err(pc, line, "invalid %s value \"%s\"",
					 key, val);
				goto fail;
			}
			if (libnvmf_params_set(overrides, key, val)) {
				ret = -ENOMEM;
				goto fail;
			}
			break;
		case LIBNVMF_KEY_SECURITY:
			conf_err(pc, line,
				 "%s is bound to the (hostnqn, subsysnqn) pair; set it on the section, not per path",
				 key);
			goto fail;
		default:
			conf_err(pc, line, "%s does not belong on a controller line",
				 key);
			goto fail;
		}
	}

	if (!addr.transport || !addr.traddr) {
		conf_err(pc, line,
			 "controller line needs transport and traddr");
		goto fail;
	}

	path = calloc(1, sizeof(*path));
	if (!path) {
		ret = -ENOMEM;
		goto fail;
	}
	path->transport = xstrdup(addr.transport);
	path->traddr = xstrdup(addr.traddr);
	path->trsvcid = xstrdup(addr.trsvcid);
	path->host_traddr = xstrdup(addr.host_traddr);
	path->host_iface = xstrdup(addr.host_iface);
	if (!path->transport || !path->traddr ||
	    (addr.trsvcid && !path->trsvcid) ||
	    (addr.host_traddr && !path->host_traddr) ||
	    (addr.host_iface && !path->host_iface)) {
		free_path(path);
		ret = -ENOMEM;
		goto fail;
	}
	path->overrides = overrides;
	path->line = line;

	list_add_tail(&pc->ep->paths, &path->entry);

	return 0;

fail:
	libnvmf_params_free(overrides);
	return ret;
}

/*
 * Validate the basic NQN syntax defined by the NVMe Base specification,
 * section 4.7.
 *
 * The expected format starts with "nqn.", followed by a four-digit year,
 * a two-digit month (01-12), and a non-empty suffix after the domain
 * separator.
 *
 * Examples of valid NQNs:
 *
 *   nqn.2014-08.org.nvmexpress
 *   nqn.2014-08.org.example:subsystem1
 *
 * This function checks only the structural format. It does not validate the
 * reverse domain name, domain ownership, or uniqueness requirements.
 */
static bool nqn_valid(const char *nqn)
{
	size_t len = strlen(nqn);
	const char *p = nqn + 4;
	int month;

	if (!len || len > NVMF_NQN_SIZE || strncmp(nqn, "nqn.", 4))
		return false;
	if (!isdigit((unsigned char)p[0]) || !isdigit((unsigned char)p[1]) ||
	    !isdigit((unsigned char)p[2]) || !isdigit((unsigned char)p[3]) ||
	    p[4] != '-' || !isdigit((unsigned char)p[5]) ||
	    !isdigit((unsigned char)p[6]) || p[7] != '.' || !p[8])
		return false;

	month = (p[5] - '0') * 10 + (p[6] - '0');
	if (month < 1 || month > 12)
		return false;

	for (p = nqn; *p; p++) {
		if ((unsigned char)*p < 0x21 || (unsigned char)*p > 0x7e)
			return false;
	}

	return true;
}

/*
 * Validate the HostID syntax defined by the NVMe Base specification,
 * section 5.2.26.1.32.2.
 *
 * A HostID is a 128-bit value represented as a UUID string. The all-zero UUID
 * is not a valid HostID because it does not identify a host.
 */
static bool hostid_valid(const char *hostid)
{
	unsigned char uuid[NVME_UUID_LEN];
	int i;

	if (libnvme_uuid_from_string(hostid, uuid))
		return false;
	for (i = 0; i < NVME_UUID_LEN; i++) {
		if (uuid[i])
			return true;
	}

	return false;
}

static int set_identity(struct conf_parse *pc, char **field, const char *value)
{
	free(*field);
	*field = xstrdup(value);

	return *field ? 0 : -ENOMEM;
}

/* A "key = value" line, routed by the current section. */
static int conf_kv(struct conf_parse *pc, const char *key, char *value,
		   unsigned int line)
{
	const struct libnvmf_key *k;
	struct libnvmf_params *dest = NULL;

	if (pc->sect == SECT_IGNORED)
		return 0;
	if (pc->sect == SECT_NONE) {
		conf_err(pc, line, "\"%s\" before any section", key);
		return -EINVAL;
	}

	k = libnvmf_key_lookup(key);
	if (!k) {
		conf_warn(pc, line, "unknown key \"%s\" ignored", key);
		return 0;
	}

	switch (k->class) {
	case LIBNVMF_KEY_CONTROLLER:
		if (pc->sect != SECT_DC && pc->sect != SECT_SUBSYS)
			break;
		return add_path(pc, value, line);
	case LIBNVMF_KEY_NQN:
		if (pc->sect != SECT_DC && pc->sect != SECT_SUBSYS)
			break;
		if (!*value) {
			conf_err(pc, line, "empty nqn");
			return -EINVAL;
		}
		if (!nqn_valid(value)) {
			conf_err(pc, line, "\"%s\" is not a valid NQN", value);
			return -EINVAL;
		}
		return set_identity(pc, &pc->ep->nqn, value);
	case LIBNVMF_KEY_IDENTITY:
		if (pc->sect != SECT_HOST)
			break;
		if (!strcmp(key, "hostnqn")) {
			if (*value && !nqn_valid(value)) {
				conf_err(pc, line,
					 "hostnqn \"%s\" is not a valid NQN",
					 value);
				return -EINVAL;
			}
			return set_identity(pc, &pc->f->hostnqn, value);
		}
		if (!strcmp(key, "hostid")) {
			if (*value && !hostid_valid(value)) {
				conf_err(pc, line,
					 "hostid \"%s\" is not a valid, non-zero 128-bit UUID",
					 value);
				return -EINVAL;
			}
			return set_identity(pc, &pc->f->hostid, value);
		}
		return set_identity(pc, &pc->f->hostsymname, value);
	case LIBNVMF_KEY_TUNABLE:
	case LIBNVMF_KEY_SECURITY:
		if (libnvmf_key_check_value(k, value)) {
			conf_err(pc, line, "invalid %s value \"%s\"", key,
				 value);
			return -EINVAL;
		}
		switch (pc->sect) {
		case SECT_DC_DEFAULTS:
			dest = pc->f->dc_defaults;
			break;
		case SECT_IOC_DEFAULTS:
			dest = pc->f->ioc_defaults;
			break;
		case SECT_HOST:
			dest = pc->f->host_params;
			break;
		case SECT_DC:
		case SECT_SUBSYS:
			dest = pc->ep->params;
			break;
		default:
			break;
		}
		return libnvmf_params_set(dest, key, value);
	}

	conf_err(pc, line, "\"%s\" is not valid in this section", key);

	return -EINVAL;
}

static int conf_event(enum libnvmf_ini_event event, const char *section,
		      const char *key, const char *value, unsigned int line,
		      void *user_data)
{
	struct conf_parse *pc = user_data;

	switch (event) {
	case LIBNVMF_INI_SECTION:
		return enter_section(pc, key, line);
	case LIBNVMF_INI_KV:
		return conf_kv(pc, key, (char *)value, line);
	case LIBNVMF_INI_JUNK:
		conf_err(pc, line, "malformed line \"%s\"", key);
		return -EINVAL;
	}

	return -EINVAL;
}

int libnvmf_conf_file_parse(struct libnvme_global_ctx *ctx, const char *path,
		struct libnvmf_conf_file **file)
{
	struct libnvmf_conf_endpoint *ep;
	struct conf_parse pc = { .ctx = ctx, .path = path };
	int ret;

	if (!file)
		return -EINVAL;
	*file = NULL;

	if (!ctx || !path)
		return -EINVAL;

	pc.f = calloc(1, sizeof(*pc.f));
	if (!pc.f)
		goto nomem;
	list_head_init(&pc.f->endpoints);
	pc.f->path = xstrdup(path);
	if (!pc.f->path)
		goto nomem;

	ret = libnvmf_ini_parse_file(ctx, path, conf_event, &pc);
	if (ret) {
		if (pc.err)
			ret = pc.err;
		goto fail;
	}

	ret = -EINVAL;
	list_for_each(&pc.f->endpoints, ep, entry) {
		if (!ep->is_dc && !ep->nqn) {
			conf_err(&pc, ep->line, "[Subsystem] without an nqn");
			goto fail;
		}
	}

	*file = pc.f;

	return 0;

nomem:
	ret = -ENOMEM;
fail:
	libnvmf_conf_file_free(pc.f);

	return ret;
}
