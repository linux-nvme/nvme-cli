/* SPDX-License-Identifier: GPL-2.0-or-later */

#ifndef crc32_H
#define crc32_H

#include <stdint.h>
#include <stddef.h>

uint32_t crc32(uint32_t crc, unsigned char *buf, size_t len);

#endif
