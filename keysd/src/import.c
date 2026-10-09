// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 Dell Technologies Inc. or its subsidiaries.
 *
 * Authors: Martin Belanger <martin.belanger@dell.com>
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <ccan/str/str.h>
#include <daemon-util/log.h>
#include <nvme/config.h>
#include <nvme/crypto.h>
#include <nvme/fabrics.h>
#include <shared/cleanup-util.h>

#include "creds.h"
#include "import.h"

struct import_ctx {
	struct libnvme_global_ctx *ctx;
	const char *creds_dir;
	char *default_hostnqn; // system identity, for entries without one
	bool default_read;     // default_hostnqn was looked up
	char **done;           // "<hostnqn> <subsysnqn>" already handled
	size_t n_done;
};

/* Look up the system host NQN only when an entry needs it. */
static const char *default_hostnqn(struct import_ctx *ic)
{
	__cleanup_free char *hostid = NULL;
	int r;

	if (ic->default_read)
		return ic->default_hostnqn;

	ic->default_read = true;
	r = libnvmf_host_get_ids(ic->ctx, NULL, NULL, &ic->default_hostnqn,
				 &hostid);
	if (r < 0)
		log_warn("no default host NQN: %s", strerror(-r));

	return ic->default_hostnqn;
}

/*
 * Every path of a subsystem is a connection of its own, with the same
 * key. Return true the first time a (hostnqn, subsysnqn) pair is seen.
 */
static bool first_time(struct import_ctx *ic, const char *hostnqn,
		       const char *subsysnqn)
{
	char *pair, **p;
	size_t i;

	if (asprintf(&pair, "%s %s", hostnqn, subsysnqn) < 0)
		return true;

	for (i = 0; i < ic->n_done; i++) {
		if (streq(ic->done[i], pair)) {
			free(pair);
			return false;
		}
	}

	p = realloc(ic->done, (ic->n_done + 1) * sizeof(*p));
	if (!p) {
		free(pair);
		return true;
	}
	ic->done = p;
	ic->done[ic->n_done++] = pair;

	return true;
}

static const char *param(const struct libnvmf_params *params, const char *key)
{
	const char *value = libnvmf_params_get(params, key);

	return (value && *value) ? value : NULL;
}

/* A credential name is a file name in the credential directory. */
static bool cred_name_valid(const char *name)
{
	return name[0] != '.' && !strchr(name, '/');
}

/*
 * Large enough for a PSK in the interchange format: a 48-byte key plus
 * its CRC is 72 characters in base64, plus the 17-character framing.
 */
#define CRED_MAX 128

static void free_secret(void *p, size_t len)
{
	if (!p)
		return;
	explicit_bzero(p, len);
	free(p);
}

struct revoke_ctx {
	const char *hostnqn;
	const char *subsysnqn;
	const char *keep; // identity of the key to keep
	char **identities;
	size_t n;
	int err;
};

/*
 * A PSK description is "NVMe<v><R|G><hmac> <hostnqn> <subsysnqn>", and
 * version 1 adds " <digest>". Collect every other key for the same pair.
 */
static void collect_other_key(struct libnvme_global_ctx *ctx
				      __attribute__((unused)),
			      long keyring __attribute__((unused)),
			      long key __attribute__((unused)),
			      char *desc, int desc_len __attribute__((unused)),
			      void *data)
{
	struct revoke_ctx *rc = data;
	__cleanup_free char *copy = NULL;
	char *save, *host, *subsys, **p;

	if (rc->err || streq(desc, rc->keep))
		return;

	copy = strdup(desc);
	if (!copy) {
		rc->err = -ENOMEM;
		return;
	}
	if (!strtok_r(copy, " ", &save))
		return;
	host = strtok_r(NULL, " ", &save);
	subsys = strtok_r(NULL, " ", &save);
	if (!host || !subsys || !streq(host, rc->hostnqn) ||
	    !streq(subsys, rc->subsysnqn))
		return;

	p = realloc(rc->identities, (rc->n + 1) * sizeof(*p));
	if (!p) {
		rc->err = -ENOMEM;
		return;
	}
	rc->identities = p;
	rc->identities[rc->n] = strdup(desc);
	if (!rc->identities[rc->n]) {
		rc->err = -ENOMEM;
		return;
	}
	rc->n++;
}

static void revoke_other_keys(struct libnvme_global_ctx *ctx,
			      const char *source, const char *keyring,
			      const char *hostnqn, const char *subsysnqn,
			      const char *keep)
{
	struct revoke_ctx rc = {
		.hostnqn = hostnqn,
		.subsysnqn = subsysnqn,
		.keep = keep,
	};
	size_t i;
	int r;

	// Revoke after the scan, not while it walks the keyring.
	r = libnvmf_scan_tls_keys(ctx, keyring, collect_other_key, &rc);
	log_dbg("scanned %d keys, %zu to revoke", r, rc.n);
	if (r < 0 || rc.err)
		log_err("%s: %s: cannot scan the keyring: %s", source,
			subsysnqn, strerror(-(r < 0 ? r : rc.err)));

	for (i = 0; i < rc.n; i++) {
		r = libnvmf_revoke_tls_key(ctx, keyring, "psk",
					   rc.identities[i]);
		if (r < 0)
			log_err("cannot revoke '%s': %s", rc.identities[i],
				strerror(-r));
		else
			log_info("revoked '%s'", rc.identities[i]);
		free(rc.identities[i]);
	}
	free(rc.identities);
}

static int import_one(struct import_ctx *ic, const char *source,
		      const char *keyring, const char *hostnqn,
		      const char *subsysnqn, const char *name)
{
	__cleanup_free char *identity = NULL;
	__cleanup_free char *error = NULL;
	enum libnvmf_hmac_alg hmac;
	unsigned char version;
	unsigned char *psk = NULL;
	char encoded[CRED_MAX + 1];
	size_t psk_len = 0;
	long keyring_id, key;
	int r;

	if (!cred_name_valid(name)) {
		log_err("%s: %s: invalid credential name '%s'", source,
			subsysnqn, name);
		return -EINVAL;
	}

	r = creds_decrypt(ic->creds_dir, name, encoded, sizeof(encoded),
			  &error);
	if (r < 0) {
		explicit_bzero(encoded, sizeof(encoded));
		log_err("%s: %s: cannot decrypt credential '%s': %s", source,
			subsysnqn, name, error ?: strerror(-r));
		return r;
	}

	r = libnvmf_import_tls_key_versioned(ic->ctx, encoded, &version,
					     &hmac, &psk_len, &psk);
	explicit_bzero(encoded, sizeof(encoded));
	if (r < 0) {
		log_err("%s: %s: credential '%s' is not a valid PSK: %s",
			source, subsysnqn, name, strerror(-r));
		return r;
	}

	r = libnvmf_generate_tls_key_identity(ic->ctx, hostnqn, subsysnqn,
					      version, hmac, psk, psk_len,
					      &identity);
	if (r < 0) {
		log_err("%s: %s: cannot derive the PSK identity: %s", source,
			subsysnqn, strerror(-r));
		goto out;
	}

	r = libnvmf_lookup_keyring(ic->ctx, keyring, &keyring_id);
	if (!r)
		r = libnvmf_set_keyring(ic->ctx, keyring_id);
	if (r < 0) {
		log_err("%s: %s: keyring '%s' not available: %s", source,
			subsysnqn, keyring ?: ".nvme", strerror(-r));
		goto out;
	}

	// The identity ends with a digest of the PSK: same identity, same key.
	r = libnvmf_lookup_key(ic->ctx, "psk", identity, &key);
	if (!r) {
		log_dbg("'%s' already present", identity);
	} else {
		log_dbg("'%s' not found: %s", identity, strerror(-r));
		r = libnvmf_insert_tls_key_versioned(ic->ctx, keyring, "psk",
						     hostnqn, subsysnqn,
						     version, hmac, psk,
						     psk_len, &key);
		if (r < 0) {
			log_err("%s: %s: cannot insert the PSK: %s", source,
				subsysnqn, strerror(-r));
			goto out;
		}
		log_info("imported '%s' from credential '%s'", identity,
			 name);
	}

	revoke_other_keys(ic->ctx, source, keyring, hostnqn, subsysnqn,
			  identity);

out:
	free_secret(psk, psk_len);

	return r;
}

static void import_conn(const struct libnvmf_config_conn *conn,
			void *user_data)
{
	struct import_ctx *ic = user_data;
	const struct libnvmf_params *params;
	const char *source, *src, *name, *hostnqn, *subsysnqn;

	params = libnvmf_config_conn_get_params(conn);
	src = param(params, "key-source");
	if (!src || streq(src, "inline"))
		return;

	source = libnvmf_config_conn_get_source(conn);
	subsysnqn = libnvmf_config_conn_get_subsysnqn(conn);
	hostnqn = libnvmf_config_conn_get_hostnqn(conn) ?: default_hostnqn(ic);
	if (!hostnqn) {
		log_warn("%s: %s: no host NQN, skipped", source, subsysnqn);
		return;
	}
	if (!first_time(ic, hostnqn, subsysnqn))
		return;

	if (!streq(src, "systemd-creds")) {
		log_warn("%s: %s: key-source '%s' is not supported, skipped",
			 source, subsysnqn, src);
		return;
	}

	name = param(params, "tls-key");
	if (!name) {
		log_warn("%s: %s: key-source is systemd-creds but tls-key is not set, skipped",
			 source, subsysnqn);
		return;
	}

	import_one(ic, source, param(params, "keyring"), hostnqn, subsysnqn,
		   name);
}

static void find_key_source(const struct libnvmf_config_conn *conn,
			    void *user_data)
{
	const char *src;
	bool *found = user_data;

	src = param(libnvmf_config_conn_get_params(conn), "key-source");
	if (src && !streq(src, "inline"))
		*found = true;
}

bool import_needed(struct libnvme_global_ctx *ctx, const char *fabrics_conf)
{
	struct libnvmf_config *cfg;
	bool found = false;
	int r;

	r = libnvmf_config_read(ctx, fabrics_conf, &cfg);
	if (r < 0) {
		log_err("cannot read the fabrics configuration: %s",
			strerror(-r));
		return false;
	}

	libnvmf_config_conn_for_each(cfg, find_key_source, &found);
	libnvmf_config_free(cfg);

	return found;
}

void import_keys(struct libnvme_global_ctx *ctx, const char *fabrics_conf,
		 const char *creds_dir)
{
	struct import_ctx ic = {
		.ctx = ctx,
		.creds_dir = creds_dir,
	};
	struct libnvmf_config *cfg;
	size_t i;
	int r;

	r = libnvmf_config_read(ctx, fabrics_conf, &cfg);
	if (r < 0) {
		log_err("cannot read the fabrics configuration: %s",
			strerror(-r));
		return;
	}

	libnvmf_config_conn_for_each(cfg, import_conn, &ic);

	for (i = 0; i < ic.n_done; i++)
		free(ic.done[i]);
	free(ic.done);
	free(ic.default_hostnqn);
	libnvmf_config_free(cfg);
}
