// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 Dell Technologies Inc. or its subsidiaries.
 *
 * Authors: Martin Belanger <martin.belanger@dell.com>
 */

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <ccan/str/str.h>
#include <daemon-util/log.h>
#include <shared/ini-util.h>
#include <shared/string-util.h>
#include <shared/time-util.h>

#include "config.h"

#define KMIP_SECTION "kmip:"
#define KMIP_TIMEOUT_MAX_MS (10 * 60 * 1000)

static void config_set_defaults(struct keysd_config *cfg)
{
	cfg->debug_level = DMN_DEFAULT_LOGLEVEL;
}

static void apply_global_key(struct keysd_config *cfg, const char *key,
			     const char *val, const char *conf_path,
			     unsigned int lineno)
{
	int r;

	if (streq(key, "debug-level")) {
		r = dmn_parse_log_level(val, &cfg->debug_level);
	} else {
		log_warn("%s:%u: unknown key '%s', ignored", conf_path,
			 lineno, key);
		return;
	}

	if (r < 0)
		log_warn("%s:%u: invalid value for '%s', ignored", conf_path,
			 lineno, key);
}

/* A name in a section header or a file name: no '/', no leading '.'. */
static bool name_valid(const char *name)
{
	return name[0] && name[0] != '.' && !strchr(name, '/') &&
	       !strpbrk(name, " \t");
}

static int parse_port(const char *val)
{
	unsigned long port;
	char *end;

	errno = 0;
	port = strtoul(val, &end, 10);
	if (errno || end == val || *end || !port || port > 65535)
		return -EINVAL;

	return 0;
}

static int parse_timeout(const char *val, unsigned int *timeout_ms)
{
	uint64_t usec;
	int r;

	r = shr_parse_time(val, &usec, SHR_USEC_PER_SEC);
	if (r)
		return r;
	if (usec < SHR_USEC_PER_MSEC ||
	    usec / SHR_USEC_PER_MSEC > KMIP_TIMEOUT_MAX_MS)
		return -ERANGE;
	*timeout_ms = usec / SHR_USEC_PER_MSEC;

	return 0;
}

/* Add @server to the servers of @kms. A duplicate is ignored. */
static int add_server(struct keysd_kmip *kms, const char *server)
{
	char **servers;
	size_t i;

	for (i = 0; i < kms->nr_servers; i++)
		if (streq(kms->servers[i], server))
			return 0;

	servers = realloc(kms->servers,
			  (kms->nr_servers + 1) * sizeof(*servers));
	if (!servers)
		return -ENOMEM;
	kms->servers = servers;

	servers[kms->nr_servers] = strdup(server);
	if (!servers[kms->nr_servers])
		return -ENOMEM;
	kms->nr_servers++;

	return 0;
}

/* Replace the string in @field with a copy of @val. */
static int set_str(char **field, const char *val)
{
	char *s = strdup(val);

	if (!s)
		return -ENOMEM;
	free(*field);
	*field = s;

	return 0;
}

static int apply_kmip_key(struct keysd_kmip *kms, const char *key,
			  const char *val, const char *conf_path,
			  unsigned int lineno)
{
	int r = -EINVAL;

	if (streq(key, "server")) {
		if (val[0] && !strpbrk(val, " \t"))
			r = add_server(kms, val);
	} else if (streq(key, "port")) {
		r = parse_port(val);
		if (!r)
			r = set_str(&kms->port, val);
	} else if (streq(key, "ca")) {
		if (val[0] == '/')
			r = set_str(&kms->ca, val);
	} else if (streq(key, "client-cert")) {
		if (val[0] == '/')
			r = set_str(&kms->client_cert, val);
	} else if (streq(key, "client-key")) {
		if (name_valid(val))
			r = set_str(&kms->client_key, val);
	} else if (streq(key, "timeout")) {
		r = parse_timeout(val, &kms->timeout_ms);
	} else {
		log_warn("%s:%u: unknown key '%s', ignored", conf_path,
			 lineno, key);
		return 0;
	}

	if (r == -ENOMEM)
		return r;
	if (r < 0)
		log_warn("%s:%u: invalid value for '%s', ignored", conf_path,
			 lineno, key);

	return 0;
}

static void kmip_free(struct keysd_kmip *kms)
{
	size_t i;

	for (i = 0; i < kms->nr_servers; i++)
		free(kms->servers[i]);
	free(kms->servers);
	free(kms->name);
	free(kms->port);
	free(kms->ca);
	free(kms->client_cert);
	free(kms->client_key);
}

const struct keysd_kmip *config_find_kmip(const struct keysd_config *cfg,
		const char *name)
{
	size_t i;

	for (i = 0; i < cfg->nr_kmip; i++)
		if (streq(cfg->kmip[i].name, name))
			return &cfg->kmip[i];

	return NULL;
}

/*
 * Start the [kmip:<name>] section of the KMS @name. Returns the new entry,
 * or NULL if the section is ignored. Sets *@r to -ENOMEM on allocation
 * failure.
 */
static struct keysd_kmip *add_kmip(struct keysd_config *cfg,
				   const char *name, const char *conf_path,
				   unsigned int lineno, int *r)
{
	struct keysd_kmip *kmip, *kms;

	if (!name_valid(name)) {
		log_warn("%s:%u: invalid KMS name '%s', section ignored",
			 conf_path, lineno, name);
		return NULL;
	}
	if (config_find_kmip(cfg, name)) {
		log_warn("%s:%u: KMS '%s' already defined, section ignored",
			 conf_path, lineno, name);
		return NULL;
	}

	kmip = realloc(cfg->kmip, (cfg->nr_kmip + 1) * sizeof(*kmip));
	if (!kmip) {
		*r = -ENOMEM;
		return NULL;
	}
	cfg->kmip = kmip;

	kms = &cfg->kmip[cfg->nr_kmip];
	memset(kms, 0, sizeof(*kms));
	kms->timeout_ms = KEYSD_KMIP_TIMEOUT_MS;
	kms->name = strdup(name);
	kms->port = strdup(KEYSD_KMIP_PORT);
	if (!kms->name || !kms->port) {
		kmip_free(kms);
		*r = -ENOMEM;
		return NULL;
	}
	cfg->nr_kmip++;

	return kms;
}

/* Drop the KMSes that miss a setting. */
static void check_kmip(struct keysd_config *cfg, const char *conf_path)
{
	struct keysd_kmip *kms;
	const char *err;
	size_t i = 0;

	while (i < cfg->nr_kmip) {
		kms = &cfg->kmip[i];
		err = NULL;
		if (!kms->nr_servers)
			err = "no server";
		else if (!kms->client_cert != !kms->client_key)
			err = "client-cert and client-key go together";

		if (!err) {
			i++;
			continue;
		}

		log_warn("%s: KMS '%s': %s, ignored", conf_path,
			 kms->name, err);
		kmip_free(kms);
		memmove(kms, kms + 1, (cfg->nr_kmip - i - 1) * sizeof(*kms));
		cfg->nr_kmip--;
	}
}

struct config_parse_ctx {
	struct keysd_config *cfg;
	const char *conf_path;
	struct keysd_kmip *kms;	// the current [kmip:<name>] section
};

static int config_event(enum shr_ini_event event, const char *section,
			const char *key, const char *value,
			unsigned int line, void *user_data)
{
	struct config_parse_ctx *pc = user_data;
	const char *name;
	int r = 0;

	switch (event) {
	case SHR_INI_SECTION:
		pc->kms = NULL;
		name = shr_startswith(key, KMIP_SECTION);
		if (name)
			pc->kms = add_kmip(pc->cfg, name, pc->conf_path, line,
					   &r);
		else if (!streq(key, "Global"))
			log_warn("%s:%u: unknown section '%s', ignored",
				 pc->conf_path, line, key);
		break;
	case SHR_INI_KV:
		if (pc->kms)
			r = apply_kmip_key(pc->kms, key, value, pc->conf_path,
					   line);
		else if (section && streq(section, "Global"))
			apply_global_key(pc->cfg, key, value, pc->conf_path,
					 line);
		else if (!section)
			log_warn("%s:%u: key outside a section, ignored",
				 pc->conf_path, line);
		// Else the section is ignored, and was reported.
		break;
	case SHR_INI_JUNK:
		log_warn("%s:%u: malformed line, ignored", pc->conf_path,
			 line);
		break;
	}

	return r;
}

struct keysd_config *config_load(const char *conf_path)
{
	struct config_parse_ctx pc = {};
	struct keysd_config *cfg;
	int ret;

	cfg = calloc(1, sizeof(*cfg));
	if (!cfg)
		return NULL;
	config_set_defaults(cfg);

	if (!conf_path)
		conf_path = KEYSD_CONF_PATH;

	pc.cfg = cfg;
	pc.conf_path = conf_path;

	ret = shr_ini_parse_file(conf_path, config_event, &pc);
	if (ret == -ENOMEM) {
		config_free(cfg);
		return NULL;
	}
	if (ret && ret != -ENOENT)
		log_warn("%s: %s, using defaults", conf_path, strerror(-ret));

	check_kmip(cfg, conf_path);

	return cfg;
}

void config_free(struct keysd_config *cfg)
{
	size_t i;

	if (!cfg)
		return;

	for (i = 0; i < cfg->nr_kmip; i++)
		kmip_free(&cfg->kmip[i]);
	free(cfg->kmip);
	free(cfg);
}
