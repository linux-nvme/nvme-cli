/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * This file is part of libnvme.
 * Copyright (c) 2026, Dell Technologies Inc. or its subsidiaries.
 *
 * Authors: Martin Belanger <Martin.Belanger@dell.com>
 */
#pragma once

#include <nvme/fabrics.h>
#include <nvme/tree.h>

#include "nvme/private.h"

struct libnvmf_context {
	struct libnvme_global_ctx *ctx;

	/* common callbacks */
	bool (*decide_retry)(struct libnvmf_context *fctx, int err,
			void *user_data);
	void (*connected)(struct libnvmf_context *fctx, struct libnvme_ctrl *c,
			void *user_data);
	void (*already_connected)(struct libnvmf_context *fctx,
			struct libnvme_host *host, const char *subsysnqn,
			const char *transport, const char *traddr,
			const char *trsvcid, void *user_data);

	/* discovery callbacks */
	void (*discovery_log)(struct libnvmf_context *fctx,
			bool connect,
			struct nvmf_discovery_log *log,
			uint64_t numrec, void *user_data);
	int (*parser_init)(struct libnvmf_context *fctx,
			void *user_data);
	void (*parser_cleanup)(struct libnvmf_context *fctx,
			void *user_data);
	int (*parser_next_line)(struct libnvmf_context *fctx,
			void *user_data);

	/* discovery defaults */
	int default_max_discovery_retries;
	int default_keep_alive_timeout;

	/* common fabrics configuraiton */
	const char *device;
	bool persistent;
	struct libnvme_fabrics_config cfg;

	/* connection configuration */
	const char *subsysnqn;
	const char *transport;
	const char *traddr;
	const char *trsvcid;
	const char *host_traddr;
	const char *host_iface;

	/* host configuration */
	const char *hostnqn;
	const char *hostid;

	/* authentication and transport encryption configuration */
	const char *hostkey;
	const char *ctrlkey;
	const char *keyring;
	char *tls_key;
	const char *tls_key_identity;

	void *user_data;
};


/**
 * NVMe-oF private struct definitions.
 *
 * Structs in this file are NVMe-oF-specific (fabrics layer). They are kept
 * separate from private.h so that PCIe-only builds can exclude this entire
 * file and its generated accessors (accessors-fabrics.{h,c}) along with the
 * rest of the fabrics layer.
 */

struct libnvmf_discovery_args { /*!generate-accessors*/
	int max_retries;
	__u8 lsp;
};

bool traddr_is_hostname(struct libnvme_global_ctx *ctx,
		const char *transport, const char *traddr);

void libnvmf_default_config(struct libnvme_fabrics_config *cfg);
