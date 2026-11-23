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

#include <keyutils.h>

#include <ccan/str/str.h>
#include <daemon-util/log.h>
#include <nvme/config.h>
#include <nvme/crypto.h>
#include <nvme/fabrics.h>
#include <shared/cleanup-util.h>
#include <shared/string-util.h>

#include "config.h"
#include "creds.h"
#include "import.h"

struct import_ctx {
	struct libnvme_global_ctx *ctx;
	const char *creds_dir;
	const struct keysd_config *cfg;
	struct kmip_job *jobs;
	size_t n_jobs;
	char *default_hostnqn; // system identity, for entries without one
	bool default_read;     // default_hostnqn was looked up
	char **done;           // "<hostnqn> <subsysnqn>" already handled
	size_t n_done;
	bool no_dhchap;        // the kernel has no "dhchap" key type
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

/* Return true the first time @id is seen. Takes @id. */
static bool first_time_id(struct import_ctx *ic, char *id)
{
	char **p;
	size_t i;

	for (i = 0; i < ic->n_done; i++) {
		if (streq(ic->done[i], id)) {
			free(id);
			return false;
		}
	}

	p = realloc(ic->done, (ic->n_done + 1) * sizeof(*p));
	if (!p) {
		free(id);
		return true;
	}
	ic->done = p;
	ic->done[ic->n_done++] = id;

	return true;
}

/*
 * Every path of a subsystem is a connection of its own, with the same
 * key. Return true the first time a (hostnqn, subsysnqn) pair is seen.
 */
static bool first_time(struct import_ctx *ic, const char *hostnqn,
		       const char *subsysnqn)
{
	char *pair;

	if (asprintf(&pair, "%s %s", hostnqn, subsysnqn) < 0)
		return true;

	return first_time_id(ic, pair);
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

/*
 * Put the PSK @encoded, in the interchange format, in @keyring for
 * @hostnqn and @subsysnqn. @origin says where the PSK comes from, for the
 * log.
 */
static int import_psk(struct import_ctx *ic, const char *source,
		      const char *keyring, const char *hostnqn,
		      const char *subsysnqn, const char *origin,
		      const char *encoded)
{
	__cleanup_free char *identity = NULL;
	enum libnvmf_hmac_alg hmac;
	unsigned char version;
	unsigned char *psk = NULL;
	size_t psk_len = 0;
	long keyring_id, key;
	int r;

	r = libnvmf_import_tls_key_versioned(ic->ctx, encoded, &version,
					     &hmac, &psk_len, &psk);
	if (r < 0) {
		log_err("%s: %s: %s is not a valid PSK: %s", source,
			subsysnqn, origin, strerror(-r));
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
		log_info("imported '%s' from %s", identity, origin);
	}

	revoke_other_keys(ic->ctx, source, keyring, hostnqn, subsysnqn,
			  identity);

out:
	free_secret(psk, psk_len);

	return r;
}

static int import_cred(struct import_ctx *ic, const char *source,
		       const char *keyring, const char *hostnqn,
		       const char *subsysnqn, const char *name)
{
	__cleanup_free char *origin = NULL;
	__cleanup_free char *error = NULL;
	char encoded[CRED_MAX + 1];
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

	if (asprintf(&origin, "credential '%s'", name) < 0)
		r = -ENOMEM;
	else
		r = import_psk(ic, source, keyring, hostnqn, subsysnqn, origin,
			       encoded);
	explicit_bzero(encoded, sizeof(encoded));

	return r;
}

/*
 * The key description is the credential name. The connection passes it
 * as the KX-HMAC-CHAP secret, and the kernel looks it up in the keyring.
 * The kernel options are separated by commas.
 */
static bool kxchap_name_valid(const char *name)
{
	return cred_name_valid(name) && !strpbrk(name, ", \t\n");
}

/*
 * Return true the first time the KX-HMAC-CHAP key @name of @keyring is
 * seen, if it can be imported.
 */
static bool kxchap_first_time(struct import_ctx *ic, const char *source,
			      const char *keyring, const char *subsysnqn,
			      const char *name)
{
	char *id;

	if (ic->no_dhchap)
		return false;

	if (!kxchap_name_valid(name)) {
		log_err("%s: %s: invalid KX-HMAC-CHAP key name '%s'", source,
			subsysnqn, name);
		return false;
	}

	if (asprintf(&id, "dhchap %s %s", keyring ?: ".nvme", name) < 0)
		return true;

	return first_time_id(ic, id);
}

/*
 * Put the KX-HMAC-CHAP secret @secret in @keyring, as a "dhchap" key with
 * the description @name. A key with the same description is replaced in
 * the keyring, not revoked: a controller that uses it keeps it until it
 * authenticates again. @origin says where the secret comes from, for the
 * log.
 */
static int import_kxchap(struct import_ctx *ic, const char *source,
			 const char *keyring, const char *subsysnqn,
			 const char *name, const char *origin,
			 const char *secret)
{
	long keyring_id, key;
	int r;

	if (ic->no_dhchap)
		return -ENODEV;

	r = libnvmf_lookup_keyring(ic->ctx, keyring, &keyring_id);
	if (!r)
		r = libnvmf_set_keyring(ic->ctx, keyring_id);
	if (r < 0) {
		log_err("%s: %s: keyring '%s' not available: %s", source,
			subsysnqn, keyring ?: ".nvme", strerror(-r));
		return r;
	}

	key = add_key("dhchap", name, secret, strlen(secret), keyring_id);
	if (key < 0 && errno == ENODEV) {
		ic->no_dhchap = true;
		log_warn("the kernel does not support KX-HMAC-CHAP keys in the keyring, kxchap-secret-source skipped");
		return -ENODEV;
	}
	if (key < 0) {
		r = -errno;
		log_err("%s: %s: cannot import %s: %s", source, subsysnqn,
			origin, strerror(-r));
		return r;
	}
	log_info("imported KX-HMAC-CHAP key '%s' (%08lx) from %s", name, key,
		 origin);

	return 0;
}

static int import_kxchap_cred(struct import_ctx *ic, const char *source,
			      const char *keyring, const char *subsysnqn,
			      const char *name)
{
	__cleanup_free char *origin = NULL;
	__cleanup_free char *error = NULL;
	char secret[CRED_MAX + 1];
	int r;

	r = creds_decrypt(ic->creds_dir, name, secret, sizeof(secret),
			  &error);
	if (r < 0) {
		explicit_bzero(secret, sizeof(secret));
		log_err("%s: %s: cannot decrypt credential '%s': %s", source,
			subsysnqn, name, error ?: strerror(-r));
		return r;
	}

	if (asprintf(&origin, "credential '%s'", name) < 0)
		r = -ENOMEM;
	else
		r = import_kxchap(ic, source, keyring, subsysnqn, name, origin,
				  secret);
	explicit_bzero(secret, sizeof(secret));

	return r;
}

static void free_job(struct kmip_job *job)
{
	free(job->source);
	free(job->keyring);
	free(job->hostnqn);
	free(job->subsysnqn);
	free(job->name);
}

/* Find the KMS of "kmip:<name>", or of "kmip" when there is only one. */
static const struct keysd_kmip *find_kms(struct import_ctx *ic,
		const char *source, const char *subsysnqn, const char *key,
		const char *src)
{
	const char *name = shr_startswith(src, "kmip:");
	const struct keysd_kmip *kms;

	if (!name) {
		if (ic->cfg->nr_kmip == 1)
			return &ic->cfg->kmip[0];
		if (ic->cfg->nr_kmip)
			log_err("%s: %s: several KMSes: use %s = kmip:<name>",
				source, subsysnqn, key);
		else
			log_err("%s: %s: %s is kmip but no KMS is configured, skipped",
				source, subsysnqn, key);
		return NULL;
	}

	kms = config_find_kmip(ic->cfg, name);
	if (!kms)
		log_err("%s: %s: KMS '%s' is not configured", source,
			subsysnqn, name);

	return kms;
}

/* Collect a key to get from a KMS. @key is the key source entry. */
static void add_kmip_job(struct import_ctx *ic, const char *source,
			 const char *keyring, const char *hostnqn,
			 const char *subsysnqn, const char *key,
			 const char *src, const char *name, bool kxchap)
{
	const struct keysd_kmip *kms;
	struct kmip_job *jobs, *job;

#ifndef CONFIG_KMIP
	log_warn("%s: %s: this build does not support %s '%s', skipped",
		 source, subsysnqn, key, src);
	return;
#endif

	kms = find_kms(ic, source, subsysnqn, key, src);
	if (!kms)
		return;

	jobs = realloc(ic->jobs, (ic->n_jobs + 1) * sizeof(*jobs));
	if (!jobs) {
		log_err("%s: %s: out of memory", source, subsysnqn);
		return;
	}
	ic->jobs = jobs;

	job = &ic->jobs[ic->n_jobs];
	job->kms = kms;
	job->kxchap = kxchap;
	job->source = strdup(source);
	job->keyring = shr_xstrdup(keyring);
	job->hostnqn = strdup(hostnqn);
	job->subsysnqn = strdup(subsysnqn);
	job->name = strdup(name);
	if (!job->source || (keyring && !job->keyring) || !job->hostnqn ||
	    !job->subsysnqn || !job->name) {
		log_err("%s: %s: out of memory", source, subsysnqn);
		free_job(job);
		return;
	}
	ic->n_jobs++;
}

int import_kmip_key(struct import_ctx *ic, const struct kmip_job *job,
		const char *encoded)
{
	__cleanup_free char *origin = NULL;

	if (asprintf(&origin, "KMS '%s', key '%s'", job->kms->name,
		     job->name) < 0)
		return -ENOMEM;

	if (job->kxchap)
		return import_kxchap(ic, job->source, job->keyring,
				     job->subsysnqn, job->name, origin,
				     encoded);

	return import_psk(ic, job->source, job->keyring, job->hostnqn,
			  job->subsysnqn, origin, encoded);
}

/* Import the KX-HMAC-CHAP secret @name, or collect it for a KMS. */
static void import_kxchap_entry(struct import_ctx *ic, const char *source,
				const char *keyring, const char *hostnqn,
				const char *subsysnqn, const char *src,
				const char *name)
{
	if (!kxchap_first_time(ic, source, keyring, subsysnqn, name))
		return;

	if (streq(src, "systemd-creds"))
		import_kxchap_cred(ic, source, keyring, subsysnqn, name);
	else
		add_kmip_job(ic, source, keyring, hostnqn, subsysnqn,
			     "kxchap-secret-source", src, name, true);
}

static void import_conn_kxchap(struct import_ctx *ic,
			       const struct libnvmf_config_conn *conn)
{
	const struct libnvmf_params *params;
	const char *source, *src, *subsysnqn, *hostnqn, *keyring, *name;

	params = libnvmf_config_conn_get_params(conn);
	src = param(params, "kxchap-secret-source");
	if (!src || streq(src, "inline"))
		return;

	source = libnvmf_config_conn_get_source(conn);
	subsysnqn = libnvmf_config_conn_get_subsysnqn(conn);
	if (!streq(src, "systemd-creds") && !streq(src, "kmip") &&
	    !shr_startswith(src, "kmip:")) {
		log_warn("%s: %s: kxchap-secret-source '%s' is not supported, skipped",
			 source, subsysnqn, src);
		return;
	}

	name = param(params, "kxchap-secret");
	if (!name) {
		log_warn("%s: %s: kxchap-secret-source is %s but kxchap-secret is not set, skipped",
			 source, subsysnqn, src);
		return;
	}

	hostnqn = libnvmf_config_conn_get_hostnqn(conn) ?: "";
	keyring = param(params, "keyring");
	import_kxchap_entry(ic, source, keyring, hostnqn, subsysnqn, src,
			    name);

	name = param(params, "kxchap-ctrl-secret");
	if (name)
		import_kxchap_entry(ic, source, keyring, hostnqn, subsysnqn,
				    src, name);
}

static void import_conn(const struct libnvmf_config_conn *conn,
			void *user_data)
{
	struct import_ctx *ic = user_data;
	const struct libnvmf_params *params;
	const char *source, *src, *name, *hostnqn, *subsysnqn;

	import_conn_kxchap(ic, conn);

	params = libnvmf_config_conn_get_params(conn);
	src = param(params, "tls-key-source");
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

	name = param(params, "tls-key");
	if (!name) {
		log_warn("%s: %s: tls-key-source is %s but tls-key is not set, skipped",
			 source, subsysnqn, src);
		return;
	}

	if (streq(src, "kmip") || shr_startswith(src, "kmip:"))
		add_kmip_job(ic, source, param(params, "keyring"), hostnqn,
			     subsysnqn, "tls-key-source", src, name, false);
	else if (streq(src, "systemd-creds"))
		import_cred(ic, source, param(params, "keyring"), hostnqn,
			    subsysnqn, name);
	else
		log_warn("%s: %s: tls-key-source '%s' is not supported, skipped",
			 source, subsysnqn, src);
}

static bool key_source_set(const struct libnvmf_params *params,
			   const char *key)
{
	const char *src = param(params, key);

	return src && !streq(src, "inline");
}

static void find_key_source(const struct libnvmf_config_conn *conn,
			    void *user_data)
{
	const struct libnvmf_params *params;
	bool *found = user_data;

	params = libnvmf_config_conn_get_params(conn);
	if (key_source_set(params, "tls-key-source") ||
	    key_source_set(params, "kxchap-secret-source"))
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

struct import_ctx *import_new(struct libnvme_global_ctx *ctx,
		const char *creds_dir, const struct keysd_config *cfg)
{
	struct import_ctx *ic;

	ic = calloc(1, sizeof(*ic));
	if (!ic)
		return NULL;
	ic->ctx = ctx;
	ic->creds_dir = creds_dir;
	ic->cfg = cfg;

	return ic;
}

void import_free(struct import_ctx *ic)
{
	size_t i;

	if (!ic)
		return;

	for (i = 0; i < ic->n_jobs; i++)
		free_job(&ic->jobs[i]);
	free(ic->jobs);
	for (i = 0; i < ic->n_done; i++)
		free(ic->done[i]);
	free(ic->done);
	free(ic->default_hostnqn);
	free(ic);
}

void import_keys(struct import_ctx *ic, const char *fabrics_conf)
{
	struct libnvmf_config *cfg;
	int r;

	r = libnvmf_config_read(ic->ctx, fabrics_conf, &cfg);
	if (r < 0) {
		log_err("cannot read the fabrics configuration: %s",
			strerror(-r));
		return;
	}

	libnvmf_config_conn_for_each(cfg, import_conn, ic);
	libnvmf_config_free(cfg);
}

size_t import_kmip_jobs(struct import_ctx *ic, const struct kmip_job **jobs)
{
	*jobs = ic->jobs;

	return ic->n_jobs;
}
