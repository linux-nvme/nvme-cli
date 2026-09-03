/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 Dell Technologies Inc. or its subsidiaries.
 *
 * Authors: Martin Belanger <martin.belanger@dell.com>
 */
#pragma once

#include <stdbool.h>

/* Maximum length of an NQN, excluding the terminating '\0'. */
#define SHR_NQN_MAX_LEN 223

/*
 * Check @nqn against the NVMe Qualified Name rules of the NVMe Base
 * Specification, section 4.7: at most SHR_NQN_MAX_LEN bytes, an "nqn."
 * prefix, a "yyyy-mm" date code and a non-empty remainder. A name using
 * the UUID format must carry a canonical UUID.
 *
 * The prohibition on "org.nvmexpress" as a format 1 reverse domain is not
 * enforced, because names of that shape are widely deployed as host NQNs.
 *
 * Return: true if @nqn is usable as an NQN.
 */
bool shr_nqn_valid(const char *nqn);
