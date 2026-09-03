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
 * prefix, a "yyyy-mm" date code whose month is 01 to 12, and a non-empty
 * remainder. A name using the UUID format must carry a canonical UUID.
 *
 * Two deliberate departures from section 4.7:
 *
 * The prohibition on "org.nvmexpress" as a format 1 reverse domain is not
 * enforced, because names of that shape are widely deployed as host NQNs.
 *
 * Section 4.7 permits any UTF-8 string, but this check accepts printable
 * ASCII only, excluding the space. Every NQN in practice is built from a
 * reverse domain name and a vendor string, both ASCII, so the restriction
 * costs nothing and catches a truncated read or trailing whitespace.
 *
 * Return: true if @nqn is usable as an NQN.
 */
bool shr_nqn_valid(const char *nqn);

/*
 * Check @hostid as an NVMe Host Identifier: a canonical UUID string that is
 * not all zeros. The Base Specification, section 5.2.26.1.32.2, gives the
 * all-zero value no meaning, so it cannot identify a host.
 *
 * Return: true if @hostid is usable as a host identifier.
 */
bool shr_hostid_valid(const char *hostid);
