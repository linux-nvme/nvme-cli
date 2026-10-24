// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 SUSE LLC
 *
 * Authors: Daniel Wagner <dwagner@suse.de>
 */
#include <inttypes.h>
#include <stdio.h>

#include "bitfields.h"

int bitfield_str(const struct bitfield *f, uint64_t value, char *buf,
		 size_t len)
{
	uint64_t v = bitfield_get(f, value);

	switch (f->fmt) {
	case BF_DEC:
		return snprintf(buf, len, "%" PRIu64, v);
	case BF_DEC1:
		return snprintf(buf, len, "%" PRIu64, v + 1);
	case BF_HEX:
		return snprintf(buf, len, "%#" PRIx64, v);
	case BF_ADDR:
		return snprintf(buf, len, "%#" PRIx64, v << f->shift);
	case BF_YESNO:
		return snprintf(buf, len, "%s", v ? "Yes" : "No");
	case BF_SUPPORTED:
		return snprintf(buf, len, "%s",
				v ? "Supported" : "Not Supported");
	case BF_ENABLED:
		return snprintf(buf, len, "%s", v ? "Enabled" : "Disabled");
	case BF_STR:
		return snprintf(buf, len, "%s",
				v < f->nr_strs && f->strs[v] ?
				f->strs[v] : "Reserved");
	case BF_POW2:
		if (f->arg + v >= 64)
			return snprintf(buf, len, "2^%" PRIu64 " bytes",
					f->arg + v);
		return snprintf(buf, len, "%" PRIu64 " bytes",
				UINT64_C(1) << (f->arg + v));
	case BF_MS500:
		return snprintf(buf, len, "%" PRIu64 " ms", v * 500);
	}

	return snprintf(buf, len, "%#" PRIx64, v);
}
