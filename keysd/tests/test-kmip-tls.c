// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 Dell Technologies Inc. or its subsidiaries.
 *
 * Authors: Martin Belanger <martin.belanger@dell.com>
 */

#include <errno.h>
#include <netdb.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/socket.h>

#include "kmip.h"
#include "kmip-tls.h"
#include "tls-server.h"

static bool check(bool cond, const char *what)
{
	printf(" - %s [%s]\n", what, cond ? "PASS" : "FAIL");
	return cond;
}

static int fd_read(void *arg, void *buf, size_t len)
{
	int fd = *(int *)arg;
	uint8_t *p = buf;
	ssize_t n;

	while (len) {
		n = read(fd, p, len);
		if (n < 0 && errno == EINTR)
			continue;
		if (n < 0)
			return -errno;
		if (!n)
			return -ECONNRESET;
		p += n;
		len -= n;
	}

	return 0;
}

static void put_hdr(uint8_t *p, uint32_t tag, uint8_t type, uint32_t len)
{
	uint32_t w[2] = { tag << 8 | type, len };
	int i;

	for (i = 0; i < 8; i++)
		p[i] = w[i / 4] >> (24 - 8 * (i % 4));
}

/*
 * Write a header with @tag, @type and @len, then @body_len bytes of body,
 * and read it back with a buffer of @size bytes.
 */
static int read_back(uint32_t tag, uint8_t type, uint32_t len,
		size_t body_len, size_t size, size_t *msg_len)
{
	uint8_t msg[64], buf[64];
	int sv[2], ret;

	memset(msg, 0xa5, sizeof(msg));
	put_hdr(msg, tag, type, len);

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv))
		return -errno;
	if (write(sv[1], msg, TTLV_HDR_LEN + body_len) < 0) {
		ret = -errno;
		goto out;
	}
	shutdown(sv[1], SHUT_WR);

	ret = kmip_read_msg(fd_read, &sv[0], buf, size, msg_len);
	if (!ret && memcmp(buf, msg, *msg_len))
		ret = -EIO;

out:
	close(sv[0]);
	close(sv[1]);

	return ret;
}

static bool test_read_msg(void)
{
	bool pass = true;
	size_t len = 0;

	printf("test_read_msg:\n");

	pass &= check(!read_back(KMIP_TAG_RESPONSE_MESSAGE, TTLV_STRUCTURE,
				 16, 16, 64, &len) && len == 24,
		      "message read");
	pass &= check(!read_back(KMIP_TAG_RESPONSE_MESSAGE, TTLV_STRUCTURE,
				 16, 16, 24, &len) && len == 24,
		      "message fills the buffer");
	pass &= check(read_back(KMIP_TAG_RESPONSE_MESSAGE, TTLV_STRUCTURE,
				16, 16, 23, &len) == -EMSGSIZE,
		      "message too large");
	pass &= check(read_back(KMIP_TAG_RESPONSE_MESSAGE, TTLV_STRUCTURE,
				16, 0, 4, &len) == -EMSGSIZE,
		      "buffer smaller than a header");
	pass &= check(read_back(KMIP_TAG_REQUEST_MESSAGE, TTLV_STRUCTURE,
				16, 16, 64, &len) == -EBADMSG,
		      "not a Response Message");
	pass &= check(read_back(KMIP_TAG_RESPONSE_MESSAGE, TTLV_INTEGER,
				16, 16, 64, &len) == -EBADMSG,
		      "not a structure");
	pass &= check(read_back(KMIP_TAG_RESPONSE_MESSAGE, TTLV_STRUCTURE,
				12, 16, 64, &len) == -EBADMSG,
		      "length not a multiple of 8");
	pass &= check(read_back(KMIP_TAG_RESPONSE_MESSAGE, TTLV_STRUCTURE,
				16, 8, 64, &len) == -ECONNRESET,
		      "connection closed in the body");
	pass &= check(read_back(KMIP_TAG_RESPONSE_MESSAGE, TTLV_STRUCTURE,
				16, 0, 64, &len) == -ECONNRESET,
		      "connection closed after the header");

	return pass;
}

/* Resolve @host and @port, as nvme-keysd-kmip does before the connect. */
static struct addrinfo *resolve(const char *host, const char *port)
{
	struct addrinfo hints = { .ai_socktype = SOCK_STREAM };
	struct addrinfo *res = NULL;

	if (getaddrinfo(host, port, &hints, &res)) {
		fprintf(stderr, "cannot look up %s\n", host);
		exit(EXIT_FAILURE);
	}

	return res;
}

static int try_connect(const char *port)
{
	struct kmip_tls_cfg cfg = {
		.server = "127.0.0.1",
		.timeout_ms = 200,
	};
	struct addrinfo *addrs = resolve(cfg.server, port);
	struct kmip_tls *t;
	int ret;

	cfg.addrs = addrs;
	ret = kmip_tls_connect(&cfg, &t);
	if (!ret)
		kmip_tls_close(t);
	freeaddrinfo(addrs);

	return ret;
}

static bool test_connect(void)
{
	bool pass = true;
	char port[8];
	int fd;

	printf("test_connect:\n");

	// Nothing listens on the port.
	fd = bind_loopback(port, sizeof(port));
	pass &= check(fd >= 0 && try_connect(port) == -ECONNREFUSED,
		      "connection refused");
	if (fd >= 0)
		close(fd);

	// The kernel accepts the connection, but no server answers.
	fd = bind_loopback(port, sizeof(port));
	pass &= check(fd >= 0 && !listen(fd, 1) &&
		      try_connect(port) == -ETIMEDOUT,
		      "TLS handshake times out");
	if (fd >= 0)
		close(fd);

	return pass;
}

/*
 * The TLS tests send @request to a server in a child process. The server
 * answers with @response.
 */

enum srv_mode {
	SRV_ANSWER,	// send the response
	SRV_HALF,	// send half of the response and close
	SRV_SILENT,	// read the request and never answer
};

// A Request and a Response Message with Batch Count 1.
static uint8_t request[24];
static uint8_t response[24];

static void serve(SSL *ssl, void *arg)
{
	enum srv_mode mode = *(enum srv_mode *)arg;
	uint8_t req[sizeof(request)];
	size_t n;

	if (!tls_read_msg(ssl, req, sizeof(req), &n))
		return;

	switch (mode) {
	case SRV_ANSWER:
		SSL_write_ex(ssl, response, sizeof(response), &n);
		break;
	case SRV_HALF:
		SSL_write_ex(ssl, response, sizeof(response) / 2, &n);
		break;
	case SRV_SILENT:
		pause();
		break;
	}
}

/*
 * Start a server with @srv, connect to it with @cfg and send a request.
 * The response must fit in @size bytes and match @response.
 */
static int run(const struct tls_server *srv, struct kmip_tls_cfg *cfg,
		size_t size)
{
	uint8_t resp[64];
	struct addrinfo *addrs;
	struct kmip_tls *t;
	size_t len = 0;
	char port[8];
	pid_t pid;
	int ret;

	pid = tls_server_start(srv, port, sizeof(port));
	if (pid < 0)
		return -EIO;

	addrs = resolve(cfg->server, port);
	cfg->addrs = addrs;
	ret = kmip_tls_connect(cfg, &t);
	if (!ret) {
		ret = kmip_tls_exchange(t, request, sizeof(request), resp,
					size, &len);
		if (!ret && (len != sizeof(response) ||
			     memcmp(resp, response, len)))
			ret = -EIO;
		kmip_tls_close(t);
	}
	freeaddrinfo(addrs);

	tls_server_stop(pid);

	return ret;
}

static bool test_tls(void)
{
	enum srv_mode mode = SRV_ANSWER;
	struct tls_server srv = {
		.cert = certs.srv_ip,
		.serve = serve,
		.arg = &mode,
	};
	struct kmip_tls_cfg cfg = {
		.server = "127.0.0.1",
		.ca = ca_pem,
		.timeout_ms = 5000,
	};
	bool pass = true;
	int ret;

	printf("test_tls:\n");

	pass &= check(!run(&srv, &cfg, 64), "exchange with an IP address");
	pass &= check(run(&srv, &cfg, 16) == -EMSGSIZE,
		      "response too large");

	cfg.server = "localhost";
	srv.cert = certs.srv_name;
	pass &= check(!run(&srv, &cfg, 64), "exchange with a host name");

	cfg.server = "127.0.0.1";
	srv.cert = certs.srv_wrong;
	pass &= check(run(&srv, &cfg, 64) == -EKEYREJECTED,
		      "server certificate for another name");

	srv.cert = certs.srv_ip;
	cfg.ca = other_ca_pem;
	pass &= check(run(&srv, &cfg, 64) == -EKEYREJECTED,
		      "server certificate from another CA");
	cfg.ca = ca_pem;

	srv.client_ca = certs.ca;
	ret = run(&srv, &cfg, 64);
	pass &= check(ret && ret != -EIO, "client certificate missing");
	cfg.cert = client_pem;
	cfg.key = client_key_pem;
	pass &= check(!run(&srv, &cfg, 64),
		      "exchange with a client certificate");
	srv.client_ca = NULL;

	mode = SRV_HALF;
	pass &= check(run(&srv, &cfg, 64) == -ECONNRESET,
		      "server closes in the response");

	mode = SRV_SILENT;
	cfg.timeout_ms = 300;
	pass &= check(run(&srv, &cfg, 64) == -ETIMEDOUT,
		      "server does not answer");

	return pass;
}

static int try_setup(const char *ca, const char *cert, const char *key)
{
	struct kmip_tls_cfg cfg = {
		.server = "127.0.0.1",
		.ca = ca,
		.cert = cert,
		.key = key,
		.timeout_ms = 300,
	};
	struct addrinfo *addrs = resolve(cfg.server, "1");
	struct kmip_tls *t;
	int ret;

	cfg.addrs = addrs;
	ret = kmip_tls_connect(&cfg, &t);
	if (!ret)
		kmip_tls_close(t);
	freeaddrinfo(addrs);

	return ret;
}

static bool test_setup(void)
{
	bool pass = true;

	printf("test_setup:\n");

	pass &= check(try_setup("/nonexistent/ca.pem", NULL, NULL) == -EINVAL,
		      "CA file missing");
	pass &= check(try_setup(ca_pem, client_pem, NULL) == -EINVAL,
		      "client certificate without a key");
	pass &= check(try_setup(ca_pem, client_pem, wrong_key_pem) == -EINVAL,
		      "client key does not match the certificate");

	return pass;
}

int main(void)
{
	bool pass = true;

	signal(SIGPIPE, SIG_IGN);

	pass &= test_read_msg();
	pass &= test_connect();

	put_hdr(request, KMIP_TAG_REQUEST_MESSAGE, TTLV_STRUCTURE, 16);
	put_hdr(request + 8, KMIP_TAG_BATCH_COUNT, TTLV_INTEGER, 4);
	request[19] = 1;
	put_hdr(response, KMIP_TAG_RESPONSE_MESSAGE, TTLV_STRUCTURE, 16);
	put_hdr(response + 8, KMIP_TAG_BATCH_COUNT, TTLV_INTEGER, 4);
	response[19] = 1;

	pass &= check(tls_test_setup(), "TLS test setup");
	pass &= test_tls();
	pass &= test_setup();
	tls_test_cleanup();

	fflush(stdout);
	exit(pass ? EXIT_SUCCESS : EXIT_FAILURE);
}
