/* SPDX-License-Identifier: LicenseRef-Gary-S-Brown-CRC32 */
/*
 * This file is part of libnvme.
 */
#pragma once

#include <stddef.h>
#include <stdint.h>

uint32_t crc32(uint32_t crc, const void *buf, size_t len);
