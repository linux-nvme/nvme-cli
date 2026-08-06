/* SPDX-License-Identifier: GPL-2.0-or-later */
#pragma once

/* type conversion helpers */

#include <stdint.h>

#include <libnvme.h>

#define STR_LEN 100

const char *util_uuid_to_string(unsigned char uuid[NVME_UUID_LEN]);
const char *util_fw_to_string(char *c);

