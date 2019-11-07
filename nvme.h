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
#include <endian.h>

#include "plugin.h"
#include "util/json.h"
#include "util/argconfig.h"
#include "linux/nvme.h"

enum nvme_print_flags {
	NORMAL	= 0,
	VERBOSE	= 1 << 0,	/* verbosely decode complex values for humans */
	JSON	= 1 << 1,	/* display in json format */
	VS	= 1 << 2,	/* hex dump vendor specific data areas */
	BINARY	= 1 << 3,	/* binary dump raw bytes */
};


struct nvme_subsystem;
struct nvme_ctrl;

struct nvme_namespace {
	char *name;
	struct nvme_ctrl *ctrl;

	unsigned nsid;
	struct nvme_id_ns ns;
};

struct nvme_ctrl {
	char *name;
	struct nvme_subsystem *subsys;

	char *address;
	char *transport;
	char *state;

	struct nvme_id_ctrl id;

	int    nr_namespaces;
	struct nvme_namespace *namespaces;
};

struct nvme_subsystem {
	char *name;
	char *subsysnqn;

	int    nr_ctrls;
	struct nvme_ctrl *ctrls;

	int    nr_namespaces;
	struct nvme_namespace *namespaces;
};

struct nvme_topology {
	int    nr_subsystems;
	struct nvme_subsystem *subsystems;
};

struct ctrl_list_item {
	char *name;
	char *address;
	char *transport;
	char *state;
	char *ana_state;
	char *subsysnqn;
	char *traddr;
	char *trsvcid;
	char *host_traddr;
};

struct subsys_list_item {
	char *name;
	char *subsysnqn;
	int nctrls;
	struct ctrl_list_item *ctrls;
};

struct connect_args {
	char *subsysnqn;
	char *transport;
	char *traddr;
	char *trsvcid;
	char *host_traddr;
};

#define SYS_NVME		"/sys/class/nvme"

bool ctrl_matches_connectargs(char *name, struct connect_args *args);
char *find_ctrl_with_connectargs(struct connect_args *args);
char *__parse_connect_arg(char *conargs, const char delim, const char *fieldnm);

extern const char *conarg_nqn;
extern const char *conarg_transport;
extern const char *conarg_traddr;
extern const char *conarg_trsvcid;
extern const char *conarg_host_traddr;
extern const char *dev;
extern const char *subsys_dir;

void register_extension(struct plugin *plugin);

int parse_and_open(int argc, char **argv, const char *desc,
	const struct argconfig_commandline_options *clo);

extern const char *devicename;

int __id_ctrl(int argc, char **argv, struct command *cmd, struct plugin *plugin, void (*vs)(__u8 *vs, struct json_object *root));
enum nvme_print_flags validate_output_format(char *format);

int get_nvme_ctrl_info(char *name, char *path, struct ctrl_list_item *ctrl,
			__u32 nsid);
struct subsys_list_item *get_subsys_list(int *subcnt, char *subsysnqn, __u32 nsid);
void free_subsys_list(struct subsys_list_item *slist, int n);
char *nvme_char_from_block(char *block);
int get_nsid(int fd);
void free_ctrl_list_item(struct ctrl_list_item *ctrls);
void *mmap_registers(const char *dev);

extern int current_index;
int scan_namespace_filter(const struct dirent *d);
int scan_ctrl_paths_filter(const struct dirent *d);
int scan_ctrls_filter(const struct dirent *d);
int scan_subsys_filter(const struct dirent *d);
int scan_dev_filter(const struct dirent *d);

int scan_subsystems(struct nvme_topology *t);
void free_topology(struct nvme_topology *t);
char *get_nvme_subsnqn(char *path);

#endif /* _NVME_H */
