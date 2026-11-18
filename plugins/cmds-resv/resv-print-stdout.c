// SPDX-License-Identifier: GPL-2.0-or-later

#include <inttypes.h>
#include <stdio.h>

#include <libnvme.h>

#include <ccan/endian/endian.h>
#include <shared/hex-util.h>
#include <shared/table-util.h>

#include "nvme-print.h"
#include "nvme-print-stdout.h"
#include "resv-print.h"

static void stdout_resv_report(struct nvme_resv_status *status, int bytes,
			       bool eds)
{
	struct shr_table *t;
	int i, regstrnt, entries;
	char hex[33];

	regstrnt = status->regstrnt[0] | (status->regstrnt[1] << 8);

	printf("\nNVME Reservation status:\n\n");

	t = stdout_kv_table_create();
	if (!t)
		return;

	stdout_kv_add(t, "gen", "%u", le32_to_cpu(status->gen));
	stdout_kv_add(t, "rtype", "%d", status->rtype);
	stdout_kv_add(t, "regstrnt", "%d", regstrnt);
	stdout_kv_add(t, "ptpls", "%d", status->ptpls);

	stdout_kv_table_finish(t, "resv-report");

	/* check Extended Data Structure bit */
	if (!eds) {
		/*
		 * if status buffer was too small, don't loop past the end of
		 * the buffer
		 */
		entries = (bytes - 24) / 24;
		if (entries < regstrnt)
			regstrnt = entries;

		for (i = 0; i < regstrnt; i++) {
			struct nvme_registrant *reg = &status->registrant_ds[i];

			printf("registrant[%d] :\n", i);

			t = stdout_kv_table_create();
			if (!t)
				return;
			shr_table_set_indent(t, 2);

			stdout_kv_add(t, "cntlid", "%x",
				      le16_to_cpu(reg->cntlid));
			stdout_kv_add(t, "rcsts", "%x", reg->rcsts);
			stdout_kv_add(t, "hostid", "%"PRIx64,
				      le64_to_cpu(reg->hostid));
			stdout_kv_add(t, "rkey", "%"PRIx64,
				      le64_to_cpu(reg->rkey));

			stdout_kv_table_finish(t, "registrant");
		}
	} else {
		/*
		 * if status buffer was too small, don't loop past the end of
		 * the buffer
		 */
		entries = (bytes - 64) / 64;
		if (entries < regstrnt)
			regstrnt = entries;

		for (i = 0; i < regstrnt; i++) {
			struct nvme_registrant_ext *reg =
				&status->registrant_eds[i];

			printf("registrantext[%d] :\n", i);

			t = stdout_kv_table_create();
			if (!t)
				return;
			shr_table_set_indent(t, 2);

			stdout_kv_add(t, "cntlid", "%x",
				      le16_to_cpu(reg->cntlid));
			stdout_kv_add(t, "rcsts", "%x", reg->rcsts);
			stdout_kv_add(t, "rkey", "%"PRIx64,
				      le64_to_cpu(reg->rkey));

			shr_bin_to_hex(hex, sizeof(hex), reg->hostid,
				       sizeof(reg->hostid), 0);
			stdout_kv_add(t, "hostid", "%s", hex);

			stdout_kv_table_finish(t, "registrant");
		}
	}
	printf("\n");
}

static struct resv_print_ops resv_stdout_print_ops = {
	.resv_report	= stdout_resv_report,
};

struct resv_print_ops *resv_get_stdout_print_ops(nvme_print_flags_t flags)
{
	resv_stdout_print_ops.flags = flags;
	return &resv_stdout_print_ops;
}
