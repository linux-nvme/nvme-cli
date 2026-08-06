// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2025 Tokunori Ikegami
 *
 * Authors: Tokunori Ikegami <ikegami.t@gmail.com>
 *          Daniel Wagner <dwagner@suse.de>
 */

#include <limits.h>

#include "int-util.h"

static uint64_t int_to_long(int bits, const uint8_t *data)
{
	int i;
	uint64_t result = 0;
	int bytes = (bits + CHAR_BIT - 1) / CHAR_BIT;

	for (i = 0; i < bytes; i++) {
		result <<= CHAR_BIT;
		result += data[bytes - 1 - i];
	}

	return result;
}

uint64_t int48_to_long(const uint8_t *data)
{
	return int_to_long(48, data);
}

uint64_t int56_to_long(const uint8_t *data)
{
	return int_to_long(56, data);
}
