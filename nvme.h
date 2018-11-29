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

#include <stdbool.h>
#include <stdint.h>
#include <endian.h>
#include "plugin.h"
#include "json.h"

#define unlikely(x) x

#ifdef LIBUUID
#include <uuid/uuid.h>
#else
typedef struct {
	uint8_t b[16];
} uuid_t;
#endif

#include "linux/nvme.h"

struct nvme_effects_log_page {
	__le32 acs[256];
	__le32 iocs[256];
	__u8   resv[2048];
};

struct nvme_error_log_page {
	__u64	error_count;
	__u16	sqid;
	__u16	cmdid;
	__u16	status_field;
	__u16	parm_error_location;
	__u64	lba;
	__u32	nsid;
	__u8	vs;
	__u8	resv[3];
	__u64	cs;
	__u8	resv2[24];
};

struct nvme_firmware_log_page {
	__u8	afi;
	__u8	resv[7];
	__u64	frs[7];
	__u8	resv2[448];
};

/* idle and active power scales occupy the last 2 bits of the field */
#define POWER_SCALE(s) ((s) >> 6)

struct nvme_host_mem_buffer {
	__u32			hsize;
	__u32			hmdlal;
	__u32			hmdlau;
	__u32			hmdlec;
	__u8			rsvd16[4080];
};

struct nvme_auto_pst {
	__u32	data;
	__u32	rsvd32;
};

struct nvme_timestamp {
	__u8 timestamp[6];
	__u8 attr;
	__u8 rsvd;
};

struct nvme_controller_list {
	__le16 num;
	__le16 identifier[];
};

struct nvme_bar_cap {
	__u16	mqes;
	__u8	ams_cqr;
	__u8	to;
	__u16	bps_css_nssrs_dstrd;
	__u8	mpsmax_mpsmin;
	__u8	reserved;
};

#ifdef __CHECKER__
#define __force       __attribute__((force))
#else
#define __force
#endif

#define cpu_to_le16(x) \
	((__force __le16)htole16(x))
#define cpu_to_le32(x) \
	((__force __le32)htole32(x))
#define cpu_to_le64(x) \
	((__force __le64)htole64(x))

#define le16_to_cpu(x) \
	le16toh((__force __u16)(x))
#define le32_to_cpu(x) \
	le32toh((__force __u32)(x))
#define le64_to_cpu(x) \
	le64toh((__force __u64)(x))

#define MAX_LIST_ITEMS 256
struct list_item {
	char                node[1024];
	struct nvme_id_ctrl ctrl;
	int                 nsid;
	struct nvme_id_ns   ns;
	unsigned            block;
};

struct ctrl_list_item {
	char *name;
	char *address;
	char *transport;
	char *state;
	char *ana_state;
};

struct subsys_list_item {
	char *name;
	char *subsysnqn;
	int nctrls;
	struct ctrl_list_item *ctrls;
};

enum {
	NORMAL,
	JSON,
	BINARY,
};

void register_extension(struct plugin *plugin);

#include "argconfig.h"
int parse_and_open(int argc, char **argv, const char *desc,
	const struct argconfig_commandline_options *clo, void *cfg, size_t size);

extern const char *devicename;

int __id_ctrl(int argc, char **argv, struct command *cmd, struct plugin *plugin, void (*vs)(__u8 *vs, struct json_object *root));
int	validate_output_format(char *format);

struct subsys_list_item *get_subsys_list(int *subcnt, char *subsysnqn, __u32 nsid);
void free_subsys_list(struct subsys_list_item *slist, int n);
char *nvme_char_from_block(char *block);
#endif /* _NVME_H */
