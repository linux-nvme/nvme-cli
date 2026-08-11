/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Definitions for the NVM Express interface
 * Copyright (c) 2011-2014, Intel Corporation.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 */
#pragma once

#include <dirent.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <sys/stat.h>
#include <sys/time.h>

#include "args.h"
#include "plugin.h"
#include "nvme-json.h"
#include "argconfig.h"
#include "cleanup.h"

enum nvme_cli_topo_ranking {
	NVME_CLI_TOPO_NAMESPACE,
	NVME_CLI_TOPO_CTRL,
	NVME_CLI_TOPO_MULTIPATH,
};

#define SYS_NVME "/sys/class/nvme"

static inline bool nvme_is_multipath(libnvme_subsystem_t s)
{
	libnvme_ns_t n;
	libnvme_path_t p;

	libnvme_subsystem_for_each_ns(s, n)
		libnvme_namespace_for_each_path(n, p)
			return true;

	return false;
}

static inline bool subsystem_iopolicy_filter(const char *name, void *arg)
{
	libnvme_subsystem_t s = arg;
	const char *iopolicy;

	libnvme_subsystem_get_iopolicy(s, &iopolicy, "");

	if (!strcmp(iopolicy, "queue-depth")) {
		/* exclude "Nodes" for iopolicy queue-depth */
		if (!strcmp(name, "Nodes"))
			return false;
	} else if (!strcmp(iopolicy, "numa")) {
		/* exclude "Qdepth" for iopolicy numa */
		if (!strcmp(name, "Qdepth"))
			return false;
	} else { /* round-robin */
		/* exclude "Nodes" and "Qdepth" for iopolicy round-robin */
		if (!strcmp(name, "Nodes") || !strcmp(name, "Qdepth"))
			return false;
	}

	return true;
}

void register_extension(struct plugin *plugin);

/*
 * parse_and_open - parses arguments and opens the NVMe device, populating @ctx, @hdl
 */
int parse_and_open(struct libnvme_global_ctx **ctx,
		struct libnvme_transport_handle **hdl, int argc, char **argv,
		const char *desc, struct argconfig_commandline_options *clo);

void put_transport_handle(struct libnvme_transport_handle *hdl);

// TODO: unsure if we need a double ptr here
static inline DEFINE_CLEANUP_FUNC(cleanup_nvme_transport_handle,
	struct libnvme_transport_handle *, put_transport_handle)
#define __cleanup_nvme_transport_handle __cleanup(cleanup_nvme_transport_handle)

extern const char *uuid_index;
extern const char *namespace_id_desired;

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

int parse_args(int argc, char *argv[], const char *desc,
	       struct argconfig_commandline_options *opts);
int validate_output_format(const char *format, nvme_print_flags_t *flags);
bool nvme_is_output_format_json(void);
int __id_ctrl(int argc, char **argv, struct command *acmd,
	struct plugin *plugin, void (*vs)(uint8_t *vs, struct json_object *root));

const char *libnvme_strerror(int errnum);

unsigned long long elapsed_utime(struct timeval start_time,
					struct timeval end_time);

/* nvme-print.c */
const char *nvme_select_to_string(int sel);

void d(unsigned char *buf, int len, int width, int group);
void d_raw(unsigned char *buf, unsigned len);

int get_reg_size(int offset);
bool nvme_is_ctrl_reg(int offset);
