/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * This file is part of nvme-cli.
 */
#pragma once

/* Byte length of a binary UUID. */
#define SHR_UUID_LEN 16

/* Length of a canonical UUID string, including the trailing '\0'. */
#define SHR_UUID_LEN_STRING 37

const char *shr_uuid_to_string(unsigned char uuid[SHR_UUID_LEN]);
const char *shr_fw_to_string(char *c);
