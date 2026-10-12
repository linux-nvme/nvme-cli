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

struct import_ctx;
struct keysd_config;
struct keysd_kmip;
struct libnvme_global_ctx;

/* A key that nvme-keysd gets from a KMS. */
struct kmip_job {
	char *source;		// the configuration file, for the log
	char *keyring;		// NULL: .nvme
	char *hostnqn;
	char *subsysnqn;
	char *name;		// the KMIP Name, from tls-key
	const struct keysd_kmip *kms;
};

/*
 * Return true if an entry of the fabrics configuration @fabrics_conf (NULL
 * for the default) has a key source other than "inline". Without such an
 * entry, import_keys() has nothing to do.
 */
bool import_needed(struct libnvme_global_ctx *ctx, const char *fabrics_conf);

/*
 * @creds_dir holds the encrypted credentials. systemd-creds decrypts
 * them. @cfg holds the KMSes. Free with import_free().
 */
struct import_ctx *import_new(struct libnvme_global_ctx *ctx,
		const char *creds_dir, const struct keysd_config *cfg);
void import_free(struct import_ctx *ic);

/*
 * Put every TLS PSK that the fabrics configuration @fabrics_conf (NULL for
 * the default) takes from a systemd credential into its keyring. A key
 * that is already there is not written again. Any other key for the same
 * host NQN and subsystem NQN is revoked, so the kernel's lookup by NQNs
 * finds only this one.
 *
 * The keys that come from a KMS are only collected: see
 * import_kmip_jobs().
 */
void import_keys(struct import_ctx *ic, const char *fabrics_conf);

/* Return the keys to get from a KMS, in @jobs. */
size_t import_kmip_jobs(struct import_ctx *ic, const struct kmip_job **jobs);

/*
 * Put the PSK @encoded, in the interchange format, from the KMS of @job
 * into its keyring, as import_keys() does. Returns 0 or a negative errno.
 */
int import_kmip_psk(struct import_ctx *ic, const struct kmip_job *job,
		const char *encoded);
