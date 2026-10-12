// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 Dell Technologies Inc. or its subsidiaries.
 *
 * Authors: Martin Belanger <martin.belanger@dell.com>
 */

#include <errno.h>
#include <netdb.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/socket.h>

#include <daemon-util/log.h>
#include <daemon-util/resolve.h>
#include <nvme/crypto.h>

#include "config.h"
#include "kmip.h"
#include "kmip-psk.h"
#include "kmip-tls.h"

/* Locate and Get responses are small. */
#define KMIP_MSG_MAX	16384

/* Large enough for an interchange string in Secret Data. */
#define KMIP_KEY_MAX	256

static void free_secret(void *p, size_t len)
{
	if (!p)
		return;
	explicit_bzero(p, len);
	free(p);
}

static int psk_from_secret_data(struct libnvme_global_ctx *ctx,
		const uint8_t *data, size_t len, char psk[KMIP_PSK_MAX])
{
	enum libnvmf_hmac_alg hmac;
	unsigned char version;
	unsigned char *key;
	size_t key_len;
	int ret;

	// A trailing newline is common in a key file.
	while (len && (data[len - 1] == '\n' || data[len - 1] == '\r'))
		len--;
	if (!len || len >= KMIP_PSK_MAX || memchr(data, '\0', len))
		return -EMEDIUMTYPE;
	memcpy(psk, data, len);
	psk[len] = '\0';

	ret = libnvmf_import_tls_key_versioned(ctx, psk, &version, &hmac,
					       &key_len, &key);
	if (ret) {
		explicit_bzero(psk, KMIP_PSK_MAX);
		return -EMEDIUMTYPE;
	}
	free_secret(key, key_len);

	return 0;
}

static int psk_from_symmetric_key(struct libnvme_global_ctx *ctx,
		const uint8_t *data, size_t len, char psk[KMIP_PSK_MAX])
{
	char *encoded;
	size_t n;
	int ret;

	if (len != 32 && len != 48)
		return -EMEDIUMTYPE;

	ret = libnvmf_export_tls_key(ctx, data, len, &encoded);
	if (ret)
		return ret;

	n = strlen(encoded);
	if (n < KMIP_PSK_MAX)
		memcpy(psk, encoded, n + 1);
	free_secret(encoded, n);

	return n < KMIP_PSK_MAX ? 0 : -EMEDIUMTYPE;
}

int kmip_psk_from_object(struct libnvme_global_ctx *ctx, uint32_t obj_type,
		const uint8_t *data, size_t len, char psk[KMIP_PSK_MAX])
{
	switch (obj_type) {
	case KMIP_OBJ_SECRET_DATA:
		return psk_from_secret_data(ctx, data, len, psk);
	case KMIP_OBJ_SYMMETRIC_KEY:
		return psk_from_symmetric_key(ctx, data, len, psk);
	default:
		return -EMEDIUMTYPE;
	}
}

static void log_kms_failure(const char *server, const char *op,
		const struct kmip_result *res)
{
	log_err("KMIP %s: %s failed: status %u, reason %u%s%s", server, op,
		res->status, res->reason, res->message[0] ? ": " : "",
		res->message);
}

/* Send the request in @req and read the response into @resp. */
static int exchange(struct kmip_tls *t, struct ttlv_buf *req, uint8_t *resp,
		size_t *len)
{
	int ret;

	ret = kmip_tls_exchange(t, req->data, req->len, resp, KMIP_MSG_MAX,
				len);
	ttlv_buf_free(req);
	ttlv_buf_init(req);

	return ret;
}

/* Get the key from one server of @kms, at the addresses @addrs. */
static int get_from_server(struct libnvme_global_ctx *ctx,
		const struct keysd_kmip *kms, const char *server,
		const struct addrinfo *addrs, int timeout_ms,
		const char *key_path, const char *name, char psk[KMIP_PSK_MAX])
{
	const struct kmip_tls_cfg cfg = {
		.server = server,
		.addrs = addrs,
		.ca = kms->ca,
		.cert = kms->client_cert,
		.key = key_path,
		.timeout_ms = timeout_ms,
	};
	const struct kmip_version *v = &kmip_v1_4;
	uint8_t *resp, key[KMIP_KEY_MAX];
	struct kmip_tls *t = NULL;
	struct kmip_result res;
	struct ttlv_buf req;
	size_t len, key_len;
	uint32_t obj_type;
	char uid[128];
	int ret;

	resp = malloc(KMIP_MSG_MAX);
	if (!resp)
		return -ENOMEM;
	ttlv_buf_init(&req);

	ret = kmip_tls_connect(&cfg, &t);
	if (ret)
		goto out;

	ret = kmip_build_locate(&req, v, name, KMIP_STATE_ACTIVE);
	if (!ret)
		ret = exchange(t, &req, resp, &len);
	if (!ret)
		ret = kmip_parse_locate(resp, len, v, uid, sizeof(uid), &res);
	if (ret == -EREMOTEIO)
		log_kms_failure(server, "Locate", &res);
	if (ret)
		goto out;

	ret = kmip_build_get(&req, v, uid);
	if (!ret)
		ret = exchange(t, &req, resp, &len);
	if (!ret)
		ret = kmip_parse_get(resp, len, v, &obj_type, key, sizeof(key),
				     &key_len, &res);
	if (ret == -EREMOTEIO)
		log_kms_failure(server, "Get", &res);
	if (ret == -EOPNOTSUPP)
		ret = -EMEDIUMTYPE;
	if (ret)
		goto out;

	ret = kmip_psk_from_object(ctx, obj_type, key, key_len, psk);

out:
	kmip_tls_close(t);
	ttlv_buf_free(&req);
	explicit_bzero(key, sizeof(key));
	free_secret(resp, KMIP_MSG_MAX);

	return ret;
}

/* The answer does not depend on the server: the servers hold the same keys. */
static bool final_error(int err)
{
	return err == -ENOENT || err == -ENOTUNIQ || err == -EMEDIUMTYPE ||
	       err == -ENOMEM;
}

struct kmip_get {
	struct dmn_resolver *resolver;
	struct libnvme_global_ctx *ctx;
	const struct keysd_kmip *kms;
	struct dmn_resolve_query *query;
	char *key_path;
	char *name;
	size_t first;
	size_t n;		// servers tried
	int64_t deadline;	// of the current server, CLOCK_MONOTONIC in ms
	int ret;
	kmip_psk_callback done;
	void *user_data;
};

static int64_t now_ms(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);

	return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static size_t server_index(const struct kmip_get *g)
{
	return (g->first + g->n) % g->kms->nr_servers;
}

static void get_free(struct kmip_get *g)
{
	free(g->key_path);
	free(g->name);
	free(g);
}

static void on_resolved(int gai, const struct addrinfo *res,
		void *user_data);

/*
 * Start the lookup of the next server. Return: 0 if on_resolved() will be
 * called, or the error of the last server when no server is left.
 */
static int next_server(struct kmip_get *g)
{
	static const struct addrinfo hints = { .ai_socktype = SOCK_STREAM };
	const struct keysd_kmip *kms = g->kms;
	const char *server;
	int ret;

	for (; g->n < kms->nr_servers; g->n++) {
		server = kms->servers[server_index(g)];
		g->deadline = now_ms() + kms->timeout_ms;
		ret = dmn_resolve(g->resolver, server, kms->port, &hints,
				  kms->timeout_ms * 1000ULL, on_resolved, g,
				  &g->query);
		if (!ret)
			return 0;
		log_err("KMIP %s: cannot resolve: %s", server, strerror(-ret));
		g->ret = ret;
	}

	return g->ret;
}

static void on_resolved(int gai, const struct addrinfo *res,
		void *user_data)
{
	struct kmip_get *g = user_data;
	const char *server = g->kms->servers[server_index(g)];
	char psk[KMIP_PSK_MAX] = "";
	int err = errno;	// for EAI_SYSTEM
	int64_t left;
	int ret;

	g->query = NULL;
	left = g->deadline - now_ms();
	if (gai == EAI_SYSTEM) {
		ret = err ? -err : -EHOSTUNREACH;
		log_err("KMIP %s: name lookup: %s", server, strerror(-ret));
	} else if (gai) {
		log_err("KMIP %s: %s", server, gai_strerror(gai));
		ret = -EHOSTUNREACH;
	} else if (left <= 0) {
		log_err("KMIP %s: %s", server, strerror(ETIMEDOUT));
		ret = -ETIMEDOUT;
	} else {
		ret = get_from_server(g->ctx, g->kms, server, res, (int)left,
				      g->key_path, g->name, psk);
	}

	g->ret = ret;
	if (ret && !final_error(ret)) {
		g->n++;
		ret = next_server(g);
		if (!ret)
			return;
	}

	g->done(ret, psk, server_index(g), g->user_data);
	explicit_bzero(psk, sizeof(psk));
	get_free(g);
}

int kmip_get_psk(struct dmn_resolver *resolver,
		struct libnvme_global_ctx *ctx, const struct keysd_kmip *kms,
		size_t first, const char *key_path, const char *name,
		kmip_psk_callback done, void *user_data, struct kmip_get **ret)
{
	struct kmip_get *g;
	int err;

	if (!kms->nr_servers)
		return -EHOSTUNREACH;

	g = calloc(1, sizeof(*g));
	if (!g)
		return -ENOMEM;
	g->name = strdup(name);
	g->key_path = key_path ? strdup(key_path) : NULL;
	if (!g->name || (key_path && !g->key_path)) {
		get_free(g);
		return -ENOMEM;
	}
	g->resolver = resolver;
	g->ctx = ctx;
	g->kms = kms;
	g->first = first < kms->nr_servers ? first : 0;
	g->ret = -EHOSTUNREACH;
	g->done = done;
	g->user_data = user_data;

	err = next_server(g);
	if (err) {
		get_free(g);
		return err;
	}
	if (ret)
		*ret = g;

	return 0;
}

void kmip_get_cancel(struct kmip_get *g)
{
	if (!g)
		return;

	dmn_resolve_cancel(g->query);
	get_free(g);
}
