// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 Dell Technologies Inc. or its subsidiaries.
 *
 * Authors: Martin Belanger <martin.belanger@dell.com>
 */

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/wait.h>

#include <openssl/pem.h>
#include <openssl/x509v3.h>

#include "tls-server.h"

static struct {
	EVP_PKEY *ca;
	EVP_PKEY *other_ca;
	EVP_PKEY *srv;
	EVP_PKEY *client;
	X509 *other_ca_cert;
	X509 *client_cert;
} priv;

struct tls_test_certs certs;

static char dir[32];
char ca_pem[64], other_ca_pem[64], client_pem[64], client_key_pem[64];
char wrong_key_pem[64];

static bool add_ext(X509 *x, X509V3_CTX *ctx, int nid, const char *value)
{
	X509_EXTENSION *ext;
	bool ok;

	ext = X509V3_EXT_conf_nid(NULL, ctx, nid, value);
	if (!ext)
		return false;
	ok = X509_add_ext(x, ext, -1);
	X509_EXTENSION_free(ext);

	return ok;
}

/* Make a certificate for @key, signed by @issuer. A NULL @issuer makes a CA. */
static X509 *make_cert(EVP_PKEY *key, const char *cn, const char *san,
		X509 *issuer, EVP_PKEY *issuer_key)
{
	static long serial = 1;
	X509V3_CTX ctx;
	X509 *x;

	x = X509_new();
	if (!x)
		return NULL;

	X509_set_version(x, 2);		// X.509 v3
	ASN1_INTEGER_set(X509_get_serialNumber(x), serial++);
	X509_gmtime_adj(X509_getm_notBefore(x), -60);
	X509_gmtime_adj(X509_getm_notAfter(x), 3600);
	X509_set_pubkey(x, key);
	X509_NAME_add_entry_by_txt(X509_get_subject_name(x), "CN",
				   MBSTRING_ASC, (const unsigned char *)cn,
				   -1, -1, 0);
	X509_set_issuer_name(x, X509_get_subject_name(issuer ? issuer : x));

	X509V3_set_ctx(&ctx, issuer ? issuer : x, x, NULL, NULL, 0);
	if (!add_ext(x, &ctx, NID_basic_constraints,
		     issuer ? "CA:FALSE" : "critical,CA:TRUE") ||
	    (!issuer && !add_ext(x, &ctx, NID_key_usage,
				 "critical,keyCertSign")) ||
	    (san && !add_ext(x, &ctx, NID_subject_alt_name, san)) ||
	    !X509_sign(x, issuer ? issuer_key : key, EVP_sha256())) {
		X509_free(x);
		return NULL;
	}

	return x;
}

static bool write_pem(char *path, size_t size, const char *name, X509 *x,
		EVP_PKEY *key)
{
	FILE *f;
	bool ok;

	snprintf(path, size, "%s/%s", dir, name);
	f = fopen(path, "w");
	if (!f)
		return false;
	if (x)
		ok = PEM_write_X509(f, x);
	else
		ok = PEM_write_PrivateKey(f, key, NULL, NULL, 0, NULL, NULL);

	return !fclose(f) && ok;
}

bool tls_test_setup(void)
{
	priv.ca = EVP_PKEY_Q_keygen(NULL, NULL, "EC", "P-256");
	priv.other_ca = EVP_PKEY_Q_keygen(NULL, NULL, "EC", "P-256");
	priv.srv = EVP_PKEY_Q_keygen(NULL, NULL, "EC", "P-256");
	priv.client = EVP_PKEY_Q_keygen(NULL, NULL, "EC", "P-256");
	if (!priv.ca || !priv.other_ca || !priv.srv || !priv.client)
		return false;

	certs.ca = make_cert(priv.ca, "test CA", NULL, NULL, NULL);
	priv.other_ca_cert = make_cert(priv.other_ca, "other CA", NULL, NULL,
				       NULL);
	certs.srv_ip = make_cert(priv.srv, "kms", "IP:127.0.0.1", certs.ca,
				 priv.ca);
	certs.srv_name = make_cert(priv.srv, "kms", "DNS:localhost", certs.ca,
				   priv.ca);
	certs.srv_wrong = make_cert(priv.srv, "kms", "DNS:kms.example",
				    certs.ca, priv.ca);
	priv.client_cert = make_cert(priv.client, "host", NULL, certs.ca,
				     priv.ca);
	if (!certs.ca || !priv.other_ca_cert || !certs.srv_ip ||
	    !certs.srv_name || !certs.srv_wrong || !priv.client_cert)
		return false;

	snprintf(dir, sizeof(dir), "test-kmip-tls-XXXXXX");

	return mkdtemp(dir) &&
	       write_pem(ca_pem, sizeof(ca_pem), "ca.pem", certs.ca, NULL) &&
	       write_pem(other_ca_pem, sizeof(other_ca_pem), "other-ca.pem",
			 priv.other_ca_cert, NULL) &&
	       write_pem(client_pem, sizeof(client_pem), "client.pem",
			 priv.client_cert, NULL) &&
	       write_pem(client_key_pem, sizeof(client_key_pem), "client.key",
			 NULL, priv.client) &&
	       write_pem(wrong_key_pem, sizeof(wrong_key_pem), "wrong.key",
			 NULL, priv.srv);
}

static void free_certs(void)
{
	X509_free(certs.ca);
	X509_free(priv.other_ca_cert);
	X509_free(certs.srv_ip);
	X509_free(certs.srv_name);
	X509_free(certs.srv_wrong);
	X509_free(priv.client_cert);
	EVP_PKEY_free(priv.ca);
	EVP_PKEY_free(priv.other_ca);
	EVP_PKEY_free(priv.srv);
	EVP_PKEY_free(priv.client);
}

void tls_test_cleanup(void)
{
	unlink(ca_pem);
	unlink(other_ca_pem);
	unlink(client_pem);
	unlink(client_key_pem);
	unlink(wrong_key_pem);
	rmdir(dir);
	free_certs();
}

int bind_loopback(char *port, size_t size)
{
	struct sockaddr_in sin = {
		.sin_family = AF_INET,
		.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
	};
	socklen_t len = sizeof(sin);
	int fd;

	fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0)
		return -1;
	if (bind(fd, (struct sockaddr *)&sin, sizeof(sin)) ||
	    getsockname(fd, (struct sockaddr *)&sin, &len)) {
		close(fd);
		return -1;
	}
	snprintf(port, size, "%u", ntohs(sin.sin_port));

	return fd;
}

static bool ssl_read_all(SSL *ssl, uint8_t *p, size_t len)
{
	size_t n;

	while (len) {
		if (SSL_read_ex(ssl, p, len, &n) != 1)
			return false;
		p += n;
		len -= n;
	}

	return true;
}

bool tls_read_msg(SSL *ssl, uint8_t *buf, size_t size, size_t *len)
{
	uint32_t body;

	if (size < 8 || !ssl_read_all(ssl, buf, 8))
		return false;

	body = (uint32_t)buf[4] << 24 | buf[5] << 16 | buf[6] << 8 | buf[7];
	if (body > size - 8 || !ssl_read_all(ssl, buf + 8, body))
		return false;
	*len = 8 + body;

	return true;
}

/* Serve one connection on @lfd. Runs in the child process. */
static int serve(int lfd, const struct tls_server *srv)
{
	SSL_CTX *ctx;
	SSL *ssl = NULL;
	int fd = -1, ret = 1;

	ctx = SSL_CTX_new(TLS_server_method());
	if (!ctx || !SSL_CTX_use_certificate(ctx, srv->cert) ||
	    !SSL_CTX_use_PrivateKey(ctx, priv.srv))
		goto out;
	if (srv->client_ca) {
		X509_STORE_add_cert(SSL_CTX_get_cert_store(ctx),
				    srv->client_ca);
		SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER |
				   SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
	}

	fd = accept(lfd, NULL, NULL);
	ssl = SSL_new(ctx);
	if (fd < 0 || !ssl || !SSL_set_fd(ssl, fd) || SSL_accept(ssl) != 1)
		goto out;

	srv->serve(ssl, srv->arg);
	SSL_shutdown(ssl);
	ret = 0;

out:
	SSL_free(ssl);
	SSL_CTX_free(ctx);
	if (fd >= 0)
		close(fd);
	close(lfd);
	free_certs();

	return ret;
}

pid_t tls_server_start(const struct tls_server *srv, char *port,
		size_t size)
{
	pid_t pid;
	int lfd;

	lfd = bind_loopback(port, size);
	if (lfd < 0)
		return -1;
	if (listen(lfd, 1)) {
		close(lfd);
		return -1;
	}

	pid = fork();
	if (!pid)
		_exit(serve(lfd, srv));
	close(lfd);

	return pid;
}

void tls_server_stop(pid_t pid)
{
	if (pid <= 0)
		return;
	kill(pid, SIGKILL);
	waitpid(pid, NULL, 0);
}
