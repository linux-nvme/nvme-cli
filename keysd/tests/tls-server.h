/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 Dell Technologies Inc. or its subsidiaries.
 *
 * Authors: Martin Belanger <martin.belanger@dell.com>
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#include <openssl/ssl.h>

/*
 * A TLS server for the tests. It runs in a child process and uses
 * certificates that tls_test_setup() generates.
 */

struct tls_test_certs {
	X509 *ca;
	// Server certificates, signed by @ca
	X509 *srv_ip;		// for 127.0.0.1
	X509 *srv_name;		// for localhost
	X509 *srv_wrong;	// for kms.example
};

extern struct tls_test_certs certs;

// PEM files: the test CA, another CA, the client certificate and key,
// and a key that does not match the client certificate.
extern char ca_pem[], other_ca_pem[], client_pem[], client_key_pem[];
extern char wrong_key_pem[];

bool tls_test_setup(void);
void tls_test_cleanup(void);

/* Bind a TCP socket on the loopback address and return its port. */
int bind_loopback(char *port, size_t size);

struct tls_server {
	X509 *cert;
	X509 *client_ca;	// require a client certificate from this CA
	void (*serve)(SSL *ssl, void *arg);	// runs in the child
	void *arg;
};

/* Start @srv on a loopback port. Returns the child's pid, or -1. */
pid_t tls_server_start(const struct tls_server *srv, char *port,
		size_t size);
void tls_server_stop(pid_t pid);

/* Read one TTLV message. Returns false on error or end of connection. */
bool tls_read_msg(SSL *ssl, uint8_t *buf, size_t size, size_t *len);
