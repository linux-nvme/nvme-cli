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
};

typedef uint32_t nvme_print_flags_t;

enum nvme_cli_topo_ranking {
	NVME_CLI_TOPO_NAMESPACE,
	NVME_CLI_TOPO_CTRL,
};

#define SYS_NVME "/sys/class/nvme"

enum nvme_dev_type {
	NVME_DEV_DIRECT,
	NVME_DEV_MI,
};

struct nvme_dev {
	enum nvme_dev_type type;
	union {
		struct {
			int fd;
			struct stat stat;
		} direct;
		struct {
			nvme_root_t root;
			nvme_mi_ep_t ep;
			nvme_mi_ctrl_t ctrl;
		} mi;
	};

	const char *name;
};

#define dev_fd(d) __dev_fd(d, __func__, __LINE__)

struct nvme_config {
	char *output_format;
	int verbose;
	__u32 timeout;
	bool dry_run;
	bool no_retries;
	unsigned int output_format_ver;
};

/*
 * the ordering of the arguments matters, as the argument parser uses the first match, thus any
 * command which defines -t shorthand will match first.
 */
#define NVME_ARGS(n, ...)                                                              \
	struct argconfig_commandline_options n[] = {                                   \
		OPT_INCR("verbose",      'v', &nvme_cfg.verbose,       verbose),       \
		OPT_FMT("output-format", 'o', &nvme_cfg.output_format, output_format), \
		##__VA_ARGS__,                                                         \
		OPT_UINT("timeout",      't', &nvme_cfg.timeout,       timeout),       \
		OPT_FLAG("dry-run",        0, &nvme_cfg.dry_run,       dry_run),       \
		OPT_FLAG("no-retries",     0, &nvme_cfg.no_retries,                    \
			 "disable retry logic on errors\n"),                           \
		OPT_UINT("output-format-version", 0, &nvme_cfg.output_format_ver,      \
			 "output format version: 1|2"),                                \
		OPT_END()                                                              \
	}

static inline int __dev_fd(struct nvme_dev *dev, const char *func, int line)
{
	if (dev->type != NVME_DEV_DIRECT) {
		fprintf(stderr,
			"warning: %s:%d not a direct transport!\n",
			func, line);
		return -1;
	}
	return dev->direct.fd;
}

static inline nvme_mi_ep_t dev_mi_ep(struct nvme_dev *dev)
{
	if (dev->type != NVME_DEV_MI) {
		fprintf(stderr,
			"warning: not a MI transport!\n");
		return NULL;
	}
	return dev->mi.ep;
}

void register_extension(struct plugin *plugin);

/*
 * parse_and_open - parses arguments and opens the NVMe device, populating @dev
 */
int parse_and_open(struct nvme_dev **dev, int argc, char **argv, const char *desc,
	struct argconfig_commandline_options *clo);

void dev_close(struct nvme_dev *dev);

static inline DEFINE_CLEANUP_FUNC(
	cleanup_nvme_dev, struct nvme_dev *, dev_close)
#define _cleanup_nvme_dev_ __cleanup__(cleanup_nvme_dev)

extern const char *output_format;
extern const char *timeout;
extern const char *verbose;
extern const char *dry_run;
extern struct nvme_config nvme_cfg;

int validate_output_format(const char *format, nvme_print_flags_t *flags);
bool nvme_is_output_format_json(void);
int __id_ctrl(int argc, char **argv, struct command *cmd,
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
#endif /* _NVME_H */
