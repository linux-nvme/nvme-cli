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
#include "util/argconfig.h"

enum nvme_print_flags {
	NORMAL	= 0,
	VERBOSE	= 1 << 0,	/* verbosely decode complex values for humans */
	JSON	= 1 << 1,	/* display in json format */
	VS	= 1 << 2,	/* hex dump vendor specific data areas */
	BINARY	= 1 << 3,	/* binary dump raw bytes */
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
	const struct argconfig_commandline_options *clo);

void dev_close(struct nvme_dev *dev);

extern const char *output_format;

enum nvme_print_flags validate_output_format(const char *format);
int __id_ctrl(int argc, char **argv, struct command *cmd,
	struct plugin *plugin, void (*vs)(uint8_t *vs, struct json_object *root));

extern int current_index;
void *nvme_alloc(size_t len, bool *huge);
void nvme_free(void *p, bool huge);
const char *nvme_strerror(int errnum);

unsigned long long elapsed_utime(struct timeval start_time,
					struct timeval end_time);

static inline void nvme_strip_spaces(char *s, int l)
{
        while (l && (s[l] == '\0' || s[l] == ' '))
                s[l--] = '\0';
}

/* nvme-print.c */
const char *nvme_select_to_string(int sel);

void d(unsigned char *buf, int len, int width, int group);
void d_raw(unsigned char *buf, unsigned len);
uint64_t int48_to_long(uint8_t *data);

int map_log_level(int verbose, bool quiet);
#endif /* _NVME_H */
