/* SPDX-License-Identifier: GPL-2.0-or-later */
#pragma once

#include <stddef.h>
#include <stdint.h>

#include "types.h"

#define MB_SMART_LOG_ADD_SIZE 512

struct __attribute__((packed)) raw_array {
	__le16 r0;
	__le16 r2;
	__le16 r4;
};

struct __attribute__((packed)) raw_array1 {
	__le32 r0;
	__le16 r4;
};

struct __attribute__((packed)) smart_log_add_item_12 {
	uint8_t id;
	uint8_t rsvd1[2];
	uint8_t norm;
	uint8_t rsvd11;
	union {
		struct raw_array ra;
		struct raw_array1 ra1;
		uint8_t raw[6];
	};
	uint8_t rsvd2;
};

struct __attribute__((packed)) smart_log_add_item_10 {
	uint8_t id;
	uint8_t norm;
	union {
		struct raw_array ra;
		struct raw_array1 ra1;
		uint8_t raw[6];
	};
	uint8_t rsvd8[2];
};

struct __attribute__((packed)) smart_log_add {
	uint8_t raw[MB_SMART_LOG_ADD_SIZE];
};

struct command;
struct plugin;

int mb_smart_log_add_x(int argc, char **argv, struct command *acmd,
		       struct plugin *plugin);
size_t mb_smart_log_add_item_count(uint8_t version);
const char *mb_smart_log_add_attr_name(uint8_t version, uint8_t id);
void mb_smart_log_add_print(const struct smart_log_add *log,
			    const char *devname);
