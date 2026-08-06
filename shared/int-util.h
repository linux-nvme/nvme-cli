/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2025 Tokunori Ikegami
 *
 * Authors: Tokunori Ikegami <ikegami.t@gmail.com>
 *          Daniel Wagner <dwagner@suse.de>
 */
#pragma once

#include <stdint.h>

/* Decode a 48-bit little-endian unsigned integer. */
uint64_t int48_to_long(const uint8_t *data);

/* Decode a 56-bit little-endian unsigned integer. */
uint64_t int56_to_long(const uint8_t *data);
