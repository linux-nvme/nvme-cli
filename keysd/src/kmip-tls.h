/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 Dell Technologies Inc. or its subsidiaries.
 *
 * Authors: Martin Belanger <martin.belanger@dell.com>
 */
#pragma once

#include <stddef.h>
#include <stdint.h>

/*
 * KMIP over TLS. The client sends a request and reads the response, with
 * a size limit. All errors are logged. A write to a closed connection
 * raises SIGPIPE, so the caller ignores SIGPIPE.
 */

struct addrinfo;

struct kmip_tls_cfg {
	const char *server;	// host name or IP address
	const struct addrinfo *addrs;	// @server, resolved, with the port
	const char *ca;		// PEM file; NULL for the system CAs
	const char *cert;	// PEM file of the client certificate, or NULL
	const char *key;	// PEM file of the client private key, or NULL
	int timeout_ms;		// for the connect, handshake and exchange
};

struct kmip_tls;

/*
 * Connect to the first address of @cfg->addrs that answers, and do the TLS
 * handshake. Each TCP connect fails after 3 seconds at most. The server
 * certificate must be valid for @cfg->server. Returns 0 or a negative errno:
 * -EINVAL if a PEM file cannot be loaded, -ETIMEDOUT, -ECONNREFUSED or
 * another connect error, -EKEYREJECTED if the server certificate is not
 * valid, -EPROTO for another TLS error.
 */
int kmip_tls_connect(const struct kmip_tls_cfg *cfg, struct kmip_tls **out);

/*
 * Send @req and read the response into @resp. Returns 0 or a negative
 * errno: -ETIMEDOUT, -ECONNRESET, -EPROTO, or an error of kmip_read_msg().
 * The caller clears @resp if it holds a secret.
 */
int kmip_tls_exchange(struct kmip_tls *t, const void *req, size_t req_len,
		uint8_t *resp, size_t size, size_t *resp_len);

void kmip_tls_close(struct kmip_tls *t);

/* Read exactly @len bytes. Returns 0 or a negative errno. */
typedef int (*kmip_read_fn)(void *arg, void *buf, size_t len);

/*
 * Read one Response Message with @rd into @buf. Returns 0 or a negative
 * errno: -EBADMSG if the header is not a Response Message, -EMSGSIZE if
 * the message does not fit in @size bytes, or an error of @rd.
 */
int kmip_read_msg(kmip_read_fn rd, void *arg, uint8_t *buf, size_t size,
		size_t *len);
