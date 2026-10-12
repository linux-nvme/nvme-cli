// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 Dell Technologies Inc. or its subsidiaries.
 *
 * Authors: Martin Belanger <martin.belanger@dell.com>
 */

#include <errno.h>
#include <netdb.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <sys/socket.h>

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#include <daemon-util/log.h>

#include "kmip.h"
#include "kmip-tls.h"

#define KMIP_CONNECT_TIMEOUT_MS 3000

struct kmip_tls {
	SSL_CTX *ctx;
	SSL *ssl;
	int fd;
	int64_t deadline;	// CLOCK_MONOTONIC, in ms
	char *server;
};

static int64_t now_ms(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);

	return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/* Wait until @fd is ready for @events. */
static int wait_fd(int fd, short events, int64_t deadline)
{
	struct pollfd pfd = { .fd = fd, .events = events };
	int64_t left;
	int ret;

	for (;;) {
		left = deadline - now_ms();
		if (left <= 0)
			return -ETIMEDOUT;

		ret = poll(&pfd, 1, (int)left);
		if (ret > 0)
			return 0;
		if (!ret)
			return -ETIMEDOUT;
		if (errno != EINTR)
			return -errno;
	}
}

/*
 * Log the OpenSSL error for -EPROTO, else @err. A system error, such as a
 * missing file, says more than the OpenSSL errors that follow it.
 */
static void log_failure(const char *server, const char *what, int err)
{
	unsigned long e, last = 0;
	char buf[256];

	if (err == -EPROTO) {
		while ((e = ERR_get_error())) {
			if (ERR_SYSTEM_ERROR(e)) {
				err = -ERR_GET_REASON(e);
				last = 0;
				break;
			}
			last = e;
		}
		ERR_clear_error();
	}

	if (last) {
		ERR_error_string_n(last, buf, sizeof(buf));
		log_err("KMIP %s: %s: %s", server, what, buf);
	} else {
		log_err("KMIP %s: %s: %s", server, what, strerror(-err));
	}
}

static int connect_addr(const struct addrinfo *ai, int64_t deadline)
{
	socklen_t len = sizeof(int);
	int fd, err, ret;

	fd = socket(ai->ai_family,
		    ai->ai_socktype | SOCK_NONBLOCK | SOCK_CLOEXEC,
		    ai->ai_protocol);
	if (fd < 0)
		return -errno;

	if (connect(fd, ai->ai_addr, ai->ai_addrlen) && errno != EINPROGRESS) {
		ret = -errno;
		goto err;
	}

	ret = wait_fd(fd, POLLOUT, deadline);
	if (ret)
		goto err;

	if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len)) {
		ret = -errno;
		goto err;
	}
	if (err) {
		ret = -err;
		goto err;
	}

	return fd;

err:
	close(fd);

	return ret;
}

/*
 * Try each address of the server until one connects. A host that does not
 * answer fails after KMIP_CONNECT_TIMEOUT_MS, so the caller can try the
 * next server early.
 */
static int tcp_connect(const struct kmip_tls_cfg *cfg, int64_t deadline)
{
	const struct addrinfo *ai;
	int fd = -EHOSTUNREACH;
	int64_t limit;

	for (ai = cfg->addrs; ai; ai = ai->ai_next) {
		limit = now_ms() + KMIP_CONNECT_TIMEOUT_MS;
		fd = connect_addr(ai, limit < deadline ? limit : deadline);
		if (fd >= 0 || now_ms() >= deadline)
			break;
	}

	if (fd < 0)
		log_failure(cfg->server, "connect", fd);

	return fd;
}

static int setup_ctx(struct kmip_tls *t, const struct kmip_tls_cfg *cfg)
{
	int ok;

	t->ctx = SSL_CTX_new(TLS_client_method());
	if (!t->ctx)
		return -ENOMEM;

	if (!SSL_CTX_set_min_proto_version(t->ctx, TLS1_2_VERSION))
		return -EPROTO;
	// The responses hold keys: clear the TLS buffers after use.
	SSL_CTX_set_options(t->ctx, SSL_OP_CLEANSE_PLAINTEXT);
	SSL_CTX_set_verify(t->ctx, SSL_VERIFY_PEER, NULL);

	if (cfg->ca)
		ok = SSL_CTX_load_verify_file(t->ctx, cfg->ca);
	else
		ok = SSL_CTX_set_default_verify_paths(t->ctx);
	if (!ok) {
		log_failure(cfg->server, cfg->ca ? cfg->ca : "system CAs",
			    -EPROTO);
		return -EINVAL;
	}

	if (!cfg->cert != !cfg->key) {
		log_err("KMIP %s: client certificate and key go together",
			cfg->server);
		return -EINVAL;
	}
	if (!cfg->cert)
		return 0;

	if (!SSL_CTX_use_certificate_chain_file(t->ctx, cfg->cert)) {
		log_failure(cfg->server, cfg->cert, -EPROTO);
		return -EINVAL;
	}
	if (!SSL_CTX_use_PrivateKey_file(t->ctx, cfg->key, SSL_FILETYPE_PEM) ||
	    !SSL_CTX_check_private_key(t->ctx)) {
		log_failure(cfg->server, "client key", -EPROTO);
		return -EINVAL;
	}

	return 0;
}

/* Check the server certificate against @server: an IP address or a name. */
static int set_peer_name(SSL *ssl, const char *server)
{
	unsigned char addr[sizeof(struct in6_addr)];

	if (inet_pton(AF_INET, server, addr) == 1 ||
	    inet_pton(AF_INET6, server, addr) == 1) {
		if (!X509_VERIFY_PARAM_set1_ip_asc(SSL_get0_param(ssl), server))
			return -EINVAL;
		return 0;
	}

	if (!SSL_set_tlsext_host_name(ssl, server) ||
	    !SSL_set1_host(ssl, server))
		return -EINVAL;

	return 0;
}

/* Wait as OpenSSL asks after a call on @t->ssl that returned @ret. */
static int ssl_wait(struct kmip_tls *t, int ret)
{
	switch (SSL_get_error(t->ssl, ret)) {
	case SSL_ERROR_WANT_READ:
		return wait_fd(t->fd, POLLIN, t->deadline);
	case SSL_ERROR_WANT_WRITE:
		return wait_fd(t->fd, POLLOUT, t->deadline);
	case SSL_ERROR_ZERO_RETURN:
		return -ECONNRESET;
	case SSL_ERROR_SYSCALL:
		return errno ? -errno : -ECONNRESET;
	default:
		return -EPROTO;
	}
}

static int tls_handshake(struct kmip_tls *t)
{
	long v;
	int ret;

	do {
		ERR_clear_error();
		errno = 0;
		ret = SSL_connect(t->ssl);
		if (ret == 1)
			return 0;
		ret = ssl_wait(t, ret);
	} while (!ret);

	v = SSL_get_verify_result(t->ssl);
	if (v != X509_V_OK) {
		log_err("KMIP %s: server certificate: %s", t->server,
			X509_verify_cert_error_string(v));
		return -EKEYREJECTED;
	}
	log_failure(t->server, "TLS handshake", ret);

	return ret;
}

int kmip_tls_connect(const struct kmip_tls_cfg *cfg, struct kmip_tls **out)
{
	struct kmip_tls *t;
	int ret;

	t = calloc(1, sizeof(*t));
	if (!t)
		return -ENOMEM;
	t->fd = -1;

	t->server = strdup(cfg->server);
	if (!t->server) {
		ret = -ENOMEM;
		goto err;
	}

	ret = setup_ctx(t, cfg);
	if (ret)
		goto err;

	t->deadline = now_ms() + cfg->timeout_ms;
	ret = tcp_connect(cfg, t->deadline);
	if (ret < 0)
		goto err;
	t->fd = ret;

	t->ssl = SSL_new(t->ctx);
	if (!t->ssl || !SSL_set_fd(t->ssl, t->fd)) {
		ret = -ENOMEM;
		goto err;
	}

	ret = set_peer_name(t->ssl, cfg->server);
	if (ret)
		goto err;

	ret = tls_handshake(t);
	if (ret)
		goto err;

	*out = t;

	return 0;

err:
	kmip_tls_close(t);

	return ret;
}

static int tls_write(struct kmip_tls *t, const void *buf, size_t len)
{
	const uint8_t *p = buf;
	size_t n;
	int ret;

	while (len) {
		ERR_clear_error();
		errno = 0;
		ret = SSL_write_ex(t->ssl, p, len, &n);
		if (ret == 1) {
			p += n;
			len -= n;
			continue;
		}

		ret = ssl_wait(t, ret);
		if (ret)
			return ret;
	}

	return 0;
}

static int tls_read(void *arg, void *buf, size_t len)
{
	struct kmip_tls *t = arg;
	uint8_t *p = buf;
	size_t n;
	int ret;

	while (len) {
		ERR_clear_error();
		errno = 0;
		ret = SSL_read_ex(t->ssl, p, len, &n);
		if (ret == 1) {
			p += n;
			len -= n;
			continue;
		}

		ret = ssl_wait(t, ret);
		if (ret)
			return ret;
	}

	return 0;
}

int kmip_tls_exchange(struct kmip_tls *t, const void *req, size_t req_len,
		uint8_t *resp, size_t size, size_t *resp_len)
{
	int ret;

	ret = tls_write(t, req, req_len);
	if (ret) {
		log_failure(t->server, "send", ret);
		return ret;
	}

	ret = kmip_read_msg(tls_read, t, resp, size, resp_len);
	if (ret)
		log_failure(t->server, "receive", ret);

	return ret;
}

void kmip_tls_close(struct kmip_tls *t)
{
	if (!t)
		return;

	// Send close_notify, but do not wait for the answer.
	if (t->ssl && SSL_is_init_finished(t->ssl))
		SSL_shutdown(t->ssl);
	SSL_free(t->ssl);
	SSL_CTX_free(t->ctx);
	if (t->fd >= 0)
		close(t->fd);
	free(t->server);
	free(t);
}

static uint32_t get_be32(const uint8_t *p)
{
	return (uint32_t)p[0] << 24 | p[1] << 16 | p[2] << 8 | p[3];
}

int kmip_read_msg(kmip_read_fn rd, void *arg, uint8_t *buf, size_t size,
		size_t *len)
{
	uint32_t tag_type, body;
	int ret;

	if (size < TTLV_HDR_LEN)
		return -EMSGSIZE;

	ret = rd(arg, buf, TTLV_HDR_LEN);
	if (ret)
		return ret;

	// A structure's length is a multiple of 8 (KMIP 1.4, section 9.1.1.3).
	tag_type = get_be32(buf);
	body = get_be32(buf + 4);
	if (tag_type != (KMIP_TAG_RESPONSE_MESSAGE << 8 | TTLV_STRUCTURE) ||
	    body % 8)
		return -EBADMSG;
	if (body > size - TTLV_HDR_LEN)
		return -EMSGSIZE;

	ret = rd(arg, buf + TTLV_HDR_LEN, body);
	if (ret)
		return ret;
	*len = TTLV_HDR_LEN + body;

	return 0;
}
