/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (c) 2024
 */
#include "cmd.h"
#include "common.h"
#include "ocp-nvme.h"

#ifndef OCP_HARDWARE_COMPONENT_LOG_H
#define OCP_HARDWARE_COMPONENT_LOG_H

#define HWCOMP_RSVD2_LEN 14
#define HWCOMP_SIZE_LEN 16
#define HWCOMP_RSVD48_LEN 16

struct __packed hwcomp_desc {
	__le64 date_lot_size;
	__le64 add_info_size;
	__le32 id;
	__le64 mfg;
	__le64 rev;
	__le64 mfg_code;
};

struct __packed hwcomp_log {
	__le16 ver;
	__u8 rsvd2[HWCOMP_RSVD2_LEN];
	__u8 guid[GUID_LEN];
	__u8 size[HWCOMP_SIZE_LEN];
	__u8 rsvd48[HWCOMP_RSVD48_LEN];
	struct hwcomp_desc *desc;
};

struct hwcomp_desc_entry {
	struct hwcomp_desc *desc;
	__u64 date_lot_size;
	__u8 *date_lot_code;
	__u64 add_info_size;
	__u8 *add_info;
	__u64 desc_size;
};

enum hwcomp_id {
	HWCOMP_ID_RSVD,
	HWCOMP_ID_ASIC,
	HWCOMP_ID_NAND,
	HWCOMP_ID_DRAM,
	HWCOMP_ID_PMIC,
	HWCOMP_ID_PCB,
	HWCOMP_ID_CAP,
	HWCOMP_ID_REG,
	HWCOMP_ID_CASE,
	HWCOMP_ID_SN,
	HWCOMP_ID_COUNTRY,
	HWCOMP_ID_HW_REV,
	HWCOMP_ID_BORN_ON_DATE,
	HWCOMP_ID_VENDOR = 0x8000,
	HWCOMP_ID_MAX = 0xffff,
};

int ocp_hwcomp_log(int argc, char **argv, struct command *acmd, struct plugin *plugin);
const char *hwcomp_id_to_string(__u32 id);

#endif /* OCP_HARDWARE_COMPONENT_LOG_H */
