/* SPDX-License-Identifier: GPL-2.0-or-later */
#pragma once

#include <stddef.h>
#include <stdint.h>

uint32_t crc32(uint32_t crc, unsigned char *buf, size_t len);
