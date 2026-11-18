// SPDX-License-Identifier: GPL-2.0-or-later
#include <ccan/array_size/array_size.h>
#include <ccan/str/str.h>
#include <shared/hex-util.h>
#include <shared/string-util.h>

#include "cleanup.h"
#include "nvme-print.h"
#include "nvme-print-stdout.h"

struct shr_table *stdout_id_ctrl_rpmbs_table(__le32 ctrl_rpmbs)
{
	struct shr_table *t;
	__u32 rpmbs = le32_to_cpu(ctrl_rpmbs);
	__u32 asz = (rpmbs & 0xFF000000) >> 24;
	__u32 tsz = (rpmbs & 0xFF0000) >> 16;
	__u32 rsvd = (rpmbs & 0xFFC0) >> 6;
	__u32 auth = (rpmbs & 0x38) >> 3;
	__u32 rpmb = rpmbs & 0x7;

	t = stdout_bits_table_create();
	if (!t)
		return NULL;

	stdout_bits_add(t, "[31:24]", asz, "Access Size");
	stdout_bits_add(t, "[23:16]", tsz, "Total Size");
	if (rsvd)
		stdout_bits_add(t, "[15:6]", rsvd, "Reserved");
	stdout_bits_add(t, "[5:3]", auth, "Authentication Method");
	stdout_bits_add(t, "[2:0]", rpmb, "Number of RPMB Units");

	return t;
}

void stdout_id_ctrl_rpmbs(__le32 ctrl_rpmbs)
{
	stdout_kv_table_finish(stdout_id_ctrl_rpmbs_table(ctrl_rpmbs),
				"id-ctrl-rpmbs");
	printf("\n");
}
