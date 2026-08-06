/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2022 Jeremy Kerr
 * Copyright (c) 2023 Tokunori Ikegami
 *
 * Authors: Jeremy Kerr <jk@codeconstruct.com.au>
 *          Tokunori Ikegami <ikegami.t@gmail.com>
 *          Daniel Wagner <dwagner@suse.de>
 */
#pragma once

#include <stdint.h>

/* uint128_t is not always available, define our own. */
union shr_uint128 {
	uint8_t  bytes[16];
	uint32_t words[4]; /* [0] is most significant word */
};

typedef union shr_uint128 shr_uint128_t;

/* Convert a 16-byte little-endian buffer into a shr_uint128_t. */
shr_uint128_t le128_to_cpu(uint8_t *data);

/* Convert a 16-byte little-endian buffer directly into a long double. */
long double int128_to_double(uint8_t *data);

long double uint128_t_to_double(shr_uint128_t data);
char *uint128_t_to_string(shr_uint128_t val);
char *uint128_t_to_l10n_string(shr_uint128_t val);
char *uint128_t_to_si_string(shr_uint128_t val, uint32_t bytes_per_unit);
