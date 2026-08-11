/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 SUSE Software Solutions
 *
 * Authors: Daniel Wagner <dwagner@suse.de>
 */
#pragma once

struct libnvme_global_ctx;
struct libnvme_transport_handle;
struct argconfig_commandline_options;

void put_transport_handle(struct libnvme_transport_handle *hdl);

/*
 * nvme_create_global_ctx_hostnqn() - Create context and resolve host identity
 * @ctx: output global context
 * @hostnqn_arg: optional hostnqn override
 * @hostid_arg: optional hostid override
 * @hostnqn: optional output resolved hostnqn (caller owns/frees when provided)
 * @hostid: optional output resolved hostid (caller owns/frees when provided)
 *
 * Creates a global context, applies --set-options, resolves hostnqn/hostid
 * via libnvmf_host_get_ids(), and stores the resolved values in the context.
 * This function has to be called after @parse_args.
 */
int nvme_create_global_ctx_hostnqn(struct libnvme_global_ctx **ctx,
		const char *hostnqn_arg, const char *hostid_arg,
		char **hostnqn, char **hostid);

int nvme_create_global_ctx(struct libnvme_global_ctx **ctx);

/*
 * parse_and_open - parses arguments and opens the NVMe device, populating @ctx, @hdl
 */
int parse_and_open(struct libnvme_global_ctx **ctx,
		struct libnvme_transport_handle **hdl, int argc, char **argv,
		const char *desc, struct argconfig_commandline_options *clo);

int open_exclusive(struct libnvme_global_ctx **ctx,
		struct libnvme_transport_handle **hdl, int argc, char **argv,
		int ignore_exclusive, struct argconfig_commandline_options *opts);
