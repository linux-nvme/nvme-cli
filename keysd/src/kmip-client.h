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

#include <systemd/sd-event.h>

struct kmip_job;

/*
 * Gets keys from the KMSes through nvme-keysd-kmip, on an sd-event loop.
 * Each KMS gets one request at a time, and the KMSes are asked in
 * parallel. A key that cannot be imported is asked for again later.
 */
struct kmip_client;

/*
 * Put the PSK @encoded of @job in the keyring. Returns 0 or a negative
 * errno.
 */
typedef int (*kmip_import_fn)(const struct kmip_job *job, const char *encoded,
		void *arg);

struct kmip_client_cfg {
	const char *address;	// Varlink socket of nvme-keysd-kmip
	uint64_t retry_usec;	// first retry delay, doubled up to retry_max
	uint64_t retry_max_usec;
	kmip_import_fn import;
	void *arg;		// for @import
};

/*
 * Start getting the keys @jobs. @jobs and @cfg must stay valid until
 * kmip_client_free().
 */
int kmip_client_new(sd_event *event, const struct kmip_client_cfg *cfg,
		const struct kmip_job *jobs, size_t nr_jobs,
		struct kmip_client **out);

/* Return the number of keys not imported yet. */
size_t kmip_client_pending(const struct kmip_client *c);

void kmip_client_free(struct kmip_client *c);
