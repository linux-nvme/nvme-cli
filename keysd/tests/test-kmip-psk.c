// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 Dell Technologies Inc. or its subsidiaries.
 *
 * Authors: Martin Belanger <martin.belanger@dell.com>
 */

#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <daemon-util/resolve.h>
#include <nvme/crypto.h>
#include <nvme/lib.h>

#include "config.h"
#include "kmip.h"
#include "kmip-psk.h"
#include "kmip-responses.h"
#include "tls-server.h"

static struct libnvme_global_ctx *ctx;

// A PSK in the interchange format, made from @raw32.
static char *encoded;
static uint8_t raw32[32], raw48[48];

static bool check(bool cond, const char *what)
{
	printf(" - %s [%s]\n", what, cond ? "PASS" : "FAIL");
	return cond;
}

static int from_object(uint32_t type, const void *data, size_t len,
		char psk[KMIP_PSK_MAX])
{
	return kmip_psk_from_object(ctx, type, data, len, psk);
}

static bool test_psk_from_object(void)
{
	char psk[KMIP_PSK_MAX], text[KMIP_PSK_MAX + 8];
	bool pass = true;

	printf("test_psk_from_object:\n");

	pass &= check(!from_object(KMIP_OBJ_SYMMETRIC_KEY, raw32, 32, psk) &&
		      !strcmp(psk, encoded),
		      "32-byte Symmetric Key");
	pass &= check(!from_object(KMIP_OBJ_SYMMETRIC_KEY, raw48, 48, psk) &&
		      !strncmp(psk, "NVMeTLSkey-1:02:", 16),
		      "48-byte Symmetric Key uses SHA-384");
	pass &= check(from_object(KMIP_OBJ_SYMMETRIC_KEY, raw48, 40, psk) ==
		      -EMEDIUMTYPE,
		      "40-byte Symmetric Key");

	pass &= check(!from_object(KMIP_OBJ_SECRET_DATA, encoded,
				   strlen(encoded), psk) &&
		      !strcmp(psk, encoded),
		      "Secret Data");
	snprintf(text, sizeof(text), "%s\n", encoded);
	pass &= check(!from_object(KMIP_OBJ_SECRET_DATA, text, strlen(text),
				   psk) &&
		      !strcmp(psk, encoded),
		      "Secret Data with a newline");
	pass &= check(from_object(KMIP_OBJ_SECRET_DATA, "secret", 6, psk) ==
		      -EMEDIUMTYPE,
		      "Secret Data that is not a PSK");
	pass &= check(from_object(KMIP_OBJ_SECRET_DATA, encoded,
				  strlen(encoded) + 1, psk) == -EMEDIUMTYPE,
		      "Secret Data with a NUL");
	pass &= check(from_object(KMIP_OBJ_SECRET_DATA, "", 0, psk) ==
		      -EMEDIUMTYPE,
		      "empty Secret Data");
	pass &= check(from_object(0x01, raw32, 32, psk) == -EMEDIUMTYPE,
		      "a Certificate");

	return pass;
}

/* What the KMIP server sends. */
enum scenario {
	SC_SYMMETRIC_KEY,
	SC_SECRET_DATA,
	SC_NO_MATCH,
	SC_TWO_MATCHES,
	SC_LOCATE_FAILS,
	SC_SHORT_KEY,
	SC_OPAQUE_OBJECT,
};

static void send_buf(SSL *ssl, struct ttlv_buf *b)
{
	size_t n;

	SSL_write_ex(ssl, b->data, b->len, &n);
	ttlv_buf_free(b);
}

static uint32_t request_op(const uint8_t *buf, size_t len)
{
	struct ttlv_reader r, msg, item;
	struct ttlv_item it;
	uint32_t op = 0;

	ttlv_reader_init(&r, buf, len);
	if (ttlv_find(&r, KMIP_TAG_REQUEST_MESSAGE, &it) == 1 &&
	    !ttlv_open(&it, &msg) &&
	    ttlv_find(&msg, KMIP_TAG_BATCH_ITEM, &it) == 1 &&
	    !ttlv_open(&it, &item) &&
	    ttlv_find(&item, KMIP_TAG_OPERATION, &it) == 1)
		ttlv_get_enum(&it, &op);

	return op;
}

static void answer_locate(SSL *ssl, enum scenario sc)
{
	struct ttlv_buf b;

	switch (sc) {
	case SC_NO_MATCH:
		locate_response(&b, 0);
		break;
	case SC_TWO_MATCHES:
		locate_response(&b, 2);
		break;
	case SC_LOCATE_FAILS:
		begin_response(&b, 1, KMIP_OP_LOCATE, 1);	// Failed
		ttlv_add_enum(&b, KMIP_TAG_RESULT_REASON, 1);	// Not Found
		ttlv_add_text(&b, KMIP_TAG_RESULT_MESSAGE, "test");
		end_response(&b);
		break;
	default:
		locate_response(&b, 1);
		break;
	}
	send_buf(ssl, &b);
}

static void answer_get(SSL *ssl, enum scenario sc)
{
	struct ttlv_buf b;

	switch (sc) {
	case SC_SECRET_DATA:
		get_response(&b, KMIP_OBJ_SECRET_DATA, KMIP_TAG_SECRET_DATA,
			     KMIP_KEY_FORMAT_OPAQUE, encoded, strlen(encoded));
		break;
	case SC_SHORT_KEY:
		get_response(&b, KMIP_OBJ_SYMMETRIC_KEY, KMIP_TAG_SYMMETRIC_KEY,
			     KMIP_KEY_FORMAT_RAW, raw32, 16);
		break;
	case SC_OPAQUE_OBJECT:
		// Opaque Object (0x08): not a key object.
		get_response(&b, 0x08, 0x420089, KMIP_KEY_FORMAT_OPAQUE,
			     raw32, 32);
		break;
	default:
		get_response(&b, KMIP_OBJ_SYMMETRIC_KEY, KMIP_TAG_SYMMETRIC_KEY,
			     KMIP_KEY_FORMAT_RAW, raw32, 32);
		break;
	}
	send_buf(ssl, &b);
}

static void serve(SSL *ssl, void *arg)
{
	enum scenario sc = *(enum scenario *)arg;
	uint8_t buf[1024];
	size_t len;

	while (tls_read_msg(ssl, buf, sizeof(buf), &len)) {
		switch (request_op(buf, len)) {
		case KMIP_OP_LOCATE:
			answer_locate(ssl, sc);
			break;
		case KMIP_OP_GET:
			answer_get(ssl, sc);
			break;
		default:
			return;
		}
	}
}

// The test server listens on 127.0.0.1. Nothing listens on 127.0.0.2.
#define LIVE "server = 127.0.0.1\n"
#define DEAD "server = 127.0.0.2\n"

/* Load a [kmip:test] section with the "server = ..." lines @servers. */
static struct keysd_config *load_kms(const char *servers, const char *port)
{
	char path[] = "/tmp/nvme-keysd-kmip-XXXXXX";
	struct keysd_config *cfg;
	char *ca, *text = NULL;
	int fd, len = -1;

	ca = realpath(ca_pem, NULL);
	fd = mkstemp(path);
	if (ca && fd >= 0)
		len = asprintf(&text, "[kmip:test]\n%sport = %s\nca = %s\n",
			       servers, port, ca);
	if (len < 0 || write(fd, text, len) != len) {
		fprintf(stderr, "cannot write the config\n");
		exit(EXIT_FAILURE);
	}
	close(fd);

	cfg = config_load(path);
	unlink(path);
	free(text);
	free(ca);

	return cfg;
}

/*
 * Get a key from a KMS with the servers @servers, starting with the one
 * at index @first. The server at index @expect must answer.
 */
// The name lookup of SLOW_NAME takes longer than the KMS timeout.
#define SLOW_NAME	"slow.invalid"
#define SLOW_MS		3000

static dmn_getaddrinfo_fn lookup_fn;

static int slow_lookup(const char *host, const char *service,
		       const struct addrinfo *hints, struct addrinfo **res)
{
	if (!strcmp(host, SLOW_NAME)) {
		usleep(SLOW_MS * 1000);
		return EAI_AGAIN;
	}

	return getaddrinfo(host, service, hints, res);
}

struct get_result {
	bool done;
	int ret;
	size_t server;
	char *psk;
};

static void on_psk(int ret, const char *psk, size_t server, void *user_data)
{
	struct get_result *res = user_data;

	res->done = true;
	res->ret = ret;
	res->server = server;
	if (!ret)
		snprintf(res->psk, KMIP_PSK_MAX, "%s", psk);
}

/* Run kmip_get_psk() on an event loop of its own, until it is done. */
static int get_psk_sync(const struct keysd_kmip *kms, size_t first,
		char psk[KMIP_PSK_MAX], size_t *server)
{
	struct get_result res = { .psk = psk };
	struct dmn_resolver *resolver = NULL;
	sd_event *event = NULL;
	int ret;

	ret = sd_event_new(&event);
	if (!ret)
		ret = dmn_resolver_new(event, 8, &resolver);
	if (!ret && lookup_fn)
		dmn_resolver_set_lookup(resolver, lookup_fn);
	if (!ret)
		ret = kmip_get_psk(resolver, ctx, kms, first, NULL, "key1",
				   on_psk, &res, NULL);
	while (!ret && !res.done)
		sd_event_run(event, UINT64_MAX);
	if (!ret)
		ret = res.ret;
	*server = res.server;

	dmn_resolver_free(resolver);
	sd_event_unref(event);

	return ret;
}

static int get_psk_from(enum scenario sc, const char *servers, size_t first,
		size_t expect, char psk[KMIP_PSK_MAX])
{
	struct tls_server srv = {
		.cert = certs.srv_ip,
		.serve = serve,
		.arg = &sc,
	};
	const struct keysd_kmip *kms;
	struct keysd_config *cfg;
	size_t server = 0;
	char port[8];
	pid_t pid;
	int ret;

	pid = tls_server_start(&srv, port, sizeof(port));
	if (pid < 0)
		return -EIO;

	cfg = load_kms(servers, port);
	kms = cfg ? config_find_kmip(cfg, "test") : NULL;
	ret = kms ? get_psk_sync(kms, first, psk, &server) : -EINVAL;
	if (!ret && server != expect)
		ret = -EIO;
	config_free(cfg);
	tls_server_stop(pid);

	return ret;
}

static int get_psk(enum scenario sc, char psk[KMIP_PSK_MAX])
{
	return get_psk_from(sc, LIVE, 0, 0, psk);
}

static bool test_get_psk(void)
{
	char psk[KMIP_PSK_MAX];
	bool pass = true;

	printf("test_get_psk:\n");

	pass &= check(!get_psk(SC_SYMMETRIC_KEY, psk) && !strcmp(psk, encoded),
		      "Symmetric Key");
	pass &= check(!get_psk(SC_SECRET_DATA, psk) && !strcmp(psk, encoded),
		      "Secret Data");
	pass &= check(get_psk(SC_NO_MATCH, psk) == -ENOENT, "no match");
	pass &= check(get_psk(SC_TWO_MATCHES, psk) == -ENOTUNIQ,
		      "two matches");
	pass &= check(get_psk(SC_LOCATE_FAILS, psk) == -EREMOTEIO,
		      "Locate fails");
	pass &= check(get_psk(SC_SHORT_KEY, psk) == -EMEDIUMTYPE,
		      "16-byte key");
	pass &= check(get_psk(SC_OPAQUE_OBJECT, psk) == -EMEDIUMTYPE,
		      "Opaque Object");

	return pass;
}

static bool test_failover(void)
{
	char psk[KMIP_PSK_MAX];
	bool pass = true;

	printf("test_failover:\n");

	pass &= check(!get_psk_from(SC_SYMMETRIC_KEY, DEAD LIVE, 0, 1, psk) &&
		      !strcmp(psk, encoded),
		      "second server answers");
	pass &= check(!get_psk_from(SC_SYMMETRIC_KEY, DEAD LIVE, 1, 1, psk),
		      "start with the second server");
	pass &= check(!get_psk_from(SC_SYMMETRIC_KEY, LIVE DEAD, 1, 0, psk),
		      "wrap around to the first server");
	pass &= check(!get_psk_from(SC_SYMMETRIC_KEY, LIVE, 5, 0, psk),
		      "invalid first server");
	pass &= check(get_psk_from(SC_NO_MATCH, LIVE DEAD, 0, 0, psk) ==
		      -ENOENT,
		      "no match is final");
	pass &= check(get_psk_from(SC_LOCATE_FAILS, LIVE DEAD, 0, 0, psk) ==
		      -ECONNREFUSED,
		      "server error tries the next server");
	pass &= check(get_psk_from(SC_SYMMETRIC_KEY, DEAD, 0, 0, psk) ==
		      -ECONNREFUSED,
		      "no server answers");

	return pass;
}

static int64_t now_ms(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);

	return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static bool test_lookup_timeout(void)
{
	char psk[KMIP_PSK_MAX];
	bool pass = true;
	int64_t t0;
	int ret;

	printf("test_lookup_timeout:\n");

	lookup_fn = slow_lookup;
	t0 = now_ms();
	ret = get_psk_from(SC_SYMMETRIC_KEY,
			   "server = " SLOW_NAME "\ntimeout = 1s\n" LIVE,
			   0, 1, psk);
	pass &= check(!ret && !strcmp(psk, encoded),
		      "second server answers");
	pass &= check(now_ms() - t0 < SLOW_MS,
		      "without waiting for the first name lookup");

	ret = get_psk_from(SC_SYMMETRIC_KEY,
			   "server = " SLOW_NAME "\ntimeout = 1s\n",
			   0, 0, psk);
	pass &= check(ret == -ETIMEDOUT, "the only server times out");
	lookup_fn = NULL;

	// Let the workers in slow_lookup() end before the next test.
	usleep(SLOW_MS * 1000);

	return pass;
}

int main(void)
{
	bool pass = true;
	size_t i;

	signal(SIGPIPE, SIG_IGN);

	for (i = 0; i < sizeof(raw48); i++)
		raw48[i] = i;
	memcpy(raw32, raw48, sizeof(raw32));

	ctx = libnvme_create_global_ctx();
	pass &= check(ctx && !libnvmf_export_tls_key(ctx, raw32, 32, &encoded),
		      "PSK setup");
	pass &= check(tls_test_setup(), "TLS test setup");

	pass &= test_psk_from_object();
	pass &= test_get_psk();
	pass &= test_failover();
	pass &= test_lookup_timeout();

	tls_test_cleanup();
	free(encoded);
	libnvme_free_global_ctx(ctx);

	fflush(stdout);
	exit(pass ? EXIT_SUCCESS : EXIT_FAILURE);
}
