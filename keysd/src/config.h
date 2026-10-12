/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 Dell Technologies Inc. or its subsidiaries.
 *
 * Authors: Martin Belanger <martin.belanger@dell.com>
 */
#pragma once

#include <stddef.h>

/*
 * nvme-keysd's own settings. Which key belongs to which host and subsystem
 * is in the shared fabrics config, never here.
 *
 *   [Global]
 *   debug-level = info
 *
 *   [kmip:my-kms]
 *   server = kms1.example.com
 *   server = kms2.example.com
 *   port = 5696
 *   ca = /etc/nvme/kmip/ca.pem
 *   client-cert = /etc/nvme/kmip/client.pem
 *   client-key = my-client-key
 *   timeout = 10
 */

/*
 * A KMS, from a [kmip:<name>] section. Its servers hold the same keys:
 * they are nodes of one cluster.
 */
struct keysd_kmip {
	char *name;
	char **servers;		// host names or IP addresses, in file order
	size_t nr_servers;
	char *port;
	char *ca;		// NULL: the system CAs
	char *client_cert;	// NULL: no client certificate
	char *client_key;	// file in KEYSD_KMIP_CREDS_DIR
	unsigned int timeout_ms;
};

struct keysd_config {
	int debug_level; // DMN_LOG_* (see daemon-util/log.h)
	struct keysd_kmip *kmip; // in the order of the file
	size_t nr_kmip;
};

/*
 * Load @conf_path (KEYSD_CONF_PATH if NULL). A missing file is not an
 * error: every setting keeps its default. A bad line is logged and
 * skipped. Returns NULL only on allocation failure. Free with
 * config_free().
 */
struct keysd_config *config_load(const char *conf_path);

void config_free(struct keysd_config *cfg);

/* Return the KMS named @name, or NULL. */
const struct keysd_kmip *config_find_kmip(const struct keysd_config *cfg,
		const char *name);

#define KEYSD_CONF_PATH SYSCONFDIR "/nvme/nvme-keysd.conf"
#define KEYSD_CREDS_DIR SYSCONFDIR "/nvme/creds"
#define KEYSD_KMIP_CREDS_DIR KEYSD_CREDS_DIR "/kmip"
#define KEYSD_KMIP_PORT "5696"
#define KEYSD_KMIP_TIMEOUT_MS 10000
