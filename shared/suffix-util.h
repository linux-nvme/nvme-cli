/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 Tokunori Ikegami
 * Copyright (c) 2026 SUSE Software Solutions
 *
 * Authors: Daniel Wagner <dwagner@suse.de>
 *          Tokunori Ikegami <ikegami.t@gmail.com>
 */
#pragma once

#include <inttypes.h>
#include <stdbool.h>

/*
 * Divide *value by the largest SI suffix (k, M, G, ...) it exceeds, returning
 * that suffix.
 */
const char *shr_suffix_si_get(double *value);

/*
 * Parse a decimal number optionally followed by a single SI suffix
 * (k, M, G,  ...) into *val.
 */
int shr_suffix_si_parse(const char *str, char **endptr, uint64_t *val);

/* Same as shr_suffix_si_get(), but for a long double value. */
const char *shr_suffix_si_get_ld(long double *value);

/*
 * Divide *value by the largest binary suffix (Ki, Mi, Gi, ...) it exceeds,
 * returning that suffix.
*/
const char *shr_suffix_binary_get(long long *value);

/* Same as shr_suffix_binary_get(), but for a double value. */
const char *shr_suffix_dbinary_get(double *value);

/*
 * Parse a decimal number optionally followed by a single binary suffix
 * (Ki, Mi, Gi, ...) into *val.
 */
int shr_suffix_binary_parse(const char *str, char **endptr, uint64_t *val);
