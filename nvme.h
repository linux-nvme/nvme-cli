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

#ifndef _NVME_H
#define _NVME_H

#include <dirent.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <endian.h>
#include <sys/time.h>
#include <sys/stat.h>

#include <libnvme-mi.h>

#include "plugin.h"
#include "util/json.h"
#include "util/mem.h"
#include "util/argconfig.h"
#include "util/cleanup.h"
#include "util/types.h"

enum nvme_print_flags {
	NORMAL		= 0,
	VERBOSE		= 1 << 0,	/* verbosely decode complex values for humans */
	JSON		= 1 << 1,	/* display in json format */
	VS		= 1 << 2,	/* hex dump vendor specific data areas */
	BINARY		= 1 << 3,	/* binary dump raw bytes */
	TABULAR		= 1 << 4,	/* prints aligned columns for easy reading */
};

typedef uint32_t nvme_print_flags_t;

enum nvme_cli_topo_ranking {
	NVME_CLI_TOPO_NAMESPACE,
	NVME_CLI_TOPO_CTRL,
	NVME_CLI_TOPO_MULTIPATH,
};

#define SYS_NVME "/sys/class/nvme"

struct nvme_args {
	char *output_format;
	int verbose;
	__u32 timeout;
	bool dry_run;
	bool no_retries;
	bool no_ioctl_probing;
	unsigned int output_format_ver;
};

/*
 * the ordering of the arguments matters, as the argument parser uses the first match, thus any
 * command which defines -t shorthand will match first.
 */
#define NVME_ARGS(n, ...)                                                              \
	struct argconfig_commandline_options n[] = {                                   \
		OPT_INCR("verbose",      'v', &nvme_args.verbose,       verbose),      \
		OPT_FMT("output-format", 'o', &nvme_args.output_format, output_format), \
		##__VA_ARGS__,                                                         \
		OPT_UINT("timeout",      't', &nvme_args.timeout,       timeout),      \
		OPT_FLAG("dry-run",        0, &nvme_args.dry_run,       dry_run),      \
		OPT_FLAG("no-retries",     0, &nvme_args.no_retries,                   \
			 "disable retry logic on errors"),                             \
		OPT_FLAG("no-ioctl-probing", 0, &nvme_args.no_ioctl_probing,           \
			 "disable 64-bit IOCTL support probing"),                      \
		OPT_UINT("output-format-version", 0, &nvme_args.output_format_ver,     \
			 "output format version: 1|2"),                                \
		OPT_END()                                                              \
	}

static inline bool nvme_is_multipath(nvme_subsystem_t s)
{
	nvme_ns_t n;
	nvme_path_t p;

	nvme_subsystem_for_each_ns(s, n)
		nvme_namespace_for_each_path(n, p)
			return true;

	return false;
}

void register_extension(struct plugin *plugin);

/*
 * parse_and_open - parses arguments and opens the NVMe device, populating @ctx, @hdl
 */
int parse_and_open(struct nvme_global_ctx **ctx,
		struct nvme_transport_handle **hdl, int argc, char **argv,
		const char *desc, struct argconfig_commandline_options *clo);

// TODO: unsure if we need a double ptr here
static inline DEFINE_CLEANUP_FUNC(
	cleanup_nvme_transport_handle, struct nvme_transport_handle *, nvme_close)
#define _cleanup_nvme_transport_handle_ __cleanup__(cleanup_nvme_transport_handle)

extern const char *output_format;
extern const char *timeout;
extern const char *verbose;
extern const char *dry_run;
extern const char *uuid_index;
extern struct nvme_args nvme_args;

int validate_output_format(const char *format, nvme_print_flags_t *flags);
bool nvme_is_output_format_json(void);
int __id_ctrl(int argc, char **argv, struct command *acmd,
	struct plugin *plugin, void (*vs)(uint8_t *vs, struct json_object *root));

const char *nvme_strerror(int errnum);

unsigned long long elapsed_utime(struct timeval start_time,
					struct timeval end_time);

/* nvme-print.c */
const char *nvme_select_to_string(int sel);

void d(unsigned char *buf, int len, int width, int group);
void d_raw(unsigned char *buf, unsigned len);

int get_reg_size(int offset);
bool nvme_is_ctrl_reg(int offset);

static inline int nvme_get_nsid_log(struct nvme_transport_handle *hdl,
				    __u32 nsid, bool rae,
				    enum nvme_cmd_get_log_lid lid,
				    void *log, __u32 len)
{
	struct nvme_passthru_cmd cmd;

	nvme_init_get_log(&cmd, nsid, lid, NVME_CSI_NVM, log, len);

	return nvme_get_log(hdl, &cmd, rae, NVME_LOG_PAGE_PDU_SIZE);
}
#endif /* _NVME_H */
