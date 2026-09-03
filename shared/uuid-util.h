/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * This file is part of nvme-cli.
 */
#pragma once

#include <stdbool.h>

/* Byte length of a binary UUID. */
#define SHR_UUID_LEN 16

/* Length of a canonical UUID string, including the trailing '\0'. */
#define SHR_UUID_LEN_STRING 37

/*
 * Check that @str is a canonical UUID string, as in
 * "11111111-2222-3333-4444-555555555555": 32 hexadecimal digits in
 * 8-4-4-4-12 groups separated by dashes. Case is not significant.
 *
 * Return: true if @str is a canonical UUID string.
 */
bool shr_uuid_str_valid(const char *str);

const char *shr_uuid_to_string(unsigned char uuid[SHR_UUID_LEN]);
const char *shr_fw_to_string(char *c);
