// SPDX-License-Identifier: GPL-2.0-or-later

#include <inttypes.h>

#include <libnvme.h>

#include <ccan/array_size/array_size.h>
#include <ccan/endian/endian.h>
#include <shared/string-util.h>
#include <shared/table-util.h>

#include "nvme-print.h"
#include "nvme-print-stdout.h"
#include "zns-print.h"

/* stdout_print_ops is already taken by the core table */
static struct zns_print_ops stdout_ops;

static void stdout_zns_id_ctrl(struct nvme_zns_id_ctrl *ctrl)
{
	struct shr_table *t;

	printf("NVMe ZNS Identify Controller:\n");

	t = stdout_kv_table_create();
	if (!t)
		return;

	stdout_kv_add(t, "zasl", "%u", ctrl->zasl);

	stdout_kv_table_finish(t, "zns-id-ctrl");
}

static struct shr_table *show_nvme_id_ns_zoned_zoc_table(__le16 ns_zoc)
{
	struct shr_table *t;
	__u16 zoc = le16_to_cpu(ns_zoc);
	__u8 rsvd = (zoc & 0xfffc) >> 2;
	__u8 ze = (zoc & 0x2) >> 1;
	__u8 vzc = zoc & 0x1;

	t = stdout_bits_table_create();
	if (!t)
		return NULL;

	if (rsvd)
		stdout_bits_add(t, "[15:2]", rsvd, "Reserved");
	stdout_bits_add(t, "[1:1]", ze, "Zone Active Excursions: %s",
			 ze ? "Yes (Host support required)" : "No");
	stdout_bits_add(t, "[0:0]", vzc, "Variable Zone Capacity: %s",
			 vzc ? "Yes (Host support required)" : "No");

	return t;
}

static struct shr_table *show_nvme_id_ns_zoned_ozcs_table(__le16 ns_ozcs)
{
	struct shr_table *t;
	__u16 ozcs = le16_to_cpu(ns_ozcs);
	__u8 rsvd = (ozcs & 0xfffc) >> 2;
	__u8 razb = ozcs & 0x1;
	__u8 zrwasup = (ozcs & 0x2) >> 1;

	t = stdout_bits_table_create();
	if (!t)
		return NULL;

	if (rsvd)
		stdout_bits_add(t, "[15:1]", rsvd, "Reserved");
	stdout_bits_add(t, "[0:0]", razb, "Read Across Zone Boundaries: %s",
			 razb ? "Yes" : "No");
	stdout_bits_add(t, "[1:1]", zrwasup, "Zone Random Write Area: %s",
			 zrwasup ? "Yes" : "No");

	return t;
}

static void stdout_zns_id_ns_recommended_limit(struct shr_table *t,
		const char *name, __le32 ns_rl, bool verbose)
{
	unsigned int recommended_limit = le32_to_cpu(ns_rl);

	if (!recommended_limit && verbose)
		stdout_kv_add(t, name, "%s", "Not Reported");
	else
		stdout_kv_add(t, name, "%u", recommended_limit);
}

static struct shr_table *stdout_zns_id_ns_zrwacap_table(__u8 zrwacap)
{
	struct shr_table *t;
	__u8 rsvd = (zrwacap & 0xfe) >> 1;
	__u8 expflushsup = zrwacap & 0x1;

	t = stdout_bits_table_create();
	if (!t)
		return NULL;

	if (rsvd)
		stdout_bits_add(t, "[7:1]", rsvd, "Reserved");
	stdout_bits_add(t, "[0:0]", expflushsup,
			 "Explicit ZRWA Flush Operations: %s",
			 expflushsup ? "Yes" : "No");

	return t;
}

static void stdout_zns_id_ns(struct nvme_zns_id_ns *ns,
			     struct nvme_id_ns *id_ns)
{
	bool verbose = stdout_ops.flags & VERBOSE;
	bool vs = stdout_ops.flags & VS;
	struct shr_table *t;
	uint8_t lbaf;
	int i, row;

	nvme_id_ns_flbas_to_lbaf_inuse(id_ns->flbas, &lbaf);

	printf("ZNS Command Set Identify Namespace:\n");

	t = stdout_kv_table_create();
	if (!t)
		return;

	if (verbose) {
		row = stdout_kv_add(t, "zoc",
				     "%u\tZone Operation Characteristics",
				     le16_to_cpu(ns->zoc));
		shr_table_set_row_subtable(t, row,
				show_nvme_id_ns_zoned_zoc_table(ns->zoc));
	} else {
		stdout_kv_add(t, "zoc", "%u", le16_to_cpu(ns->zoc));
	}

	if (verbose) {
		row = stdout_kv_add(t, "ozcs",
				     "%u\tOptional Zoned Command Support",
				     le16_to_cpu(ns->ozcs));
		shr_table_set_row_subtable(t, row,
				show_nvme_id_ns_zoned_ozcs_table(ns->ozcs));
	} else {
		stdout_kv_add(t, "ozcs", "%u", le16_to_cpu(ns->ozcs));
	}

	if (verbose) {
		if (ns->mar == 0xffffffff)
			stdout_kv_add(t, "mar", "%s",
				      "No Active Resource Limit");
		else
			stdout_kv_add(t, "mar", "%u\tActive Resources",
				      le32_to_cpu(ns->mar) + 1);
	} else {
		stdout_kv_add(t, "mar", "%#x", le32_to_cpu(ns->mar));
	}

	if (verbose) {
		if (ns->mor == 0xffffffff)
			stdout_kv_add(t, "mor", "%s",
				      "No Open Resource Limit");
		else
			stdout_kv_add(t, "mor", "%u\tOpen Resources",
				      le32_to_cpu(ns->mor) + 1);
	} else {
		stdout_kv_add(t, "mor", "%#x", le32_to_cpu(ns->mor));
	}

	stdout_zns_id_ns_recommended_limit(t, "rrl", ns->rrl, verbose);
	stdout_zns_id_ns_recommended_limit(t, "frl", ns->frl, verbose);
	stdout_zns_id_ns_recommended_limit(t, "rrl1", ns->rrl1, verbose);
	stdout_zns_id_ns_recommended_limit(t, "rrl2", ns->rrl2, verbose);
	stdout_zns_id_ns_recommended_limit(t, "rrl3", ns->rrl3, verbose);
	stdout_zns_id_ns_recommended_limit(t, "frl1", ns->frl1, verbose);
	stdout_zns_id_ns_recommended_limit(t, "frl2", ns->frl2, verbose);
	stdout_zns_id_ns_recommended_limit(t, "frl3", ns->frl3, verbose);

	stdout_kv_add(t, "numzrwa", "%#x", le32_to_cpu(ns->numzrwa));
	stdout_kv_add(t, "zrwafg", "%u", le16_to_cpu(ns->zrwafg));
	stdout_kv_add(t, "zrwasz", "%u", le16_to_cpu(ns->zrwasz));

	if (verbose) {
		row = stdout_kv_add(t, "zrwacap",
				     "%u\tZone Random Write Area Capability",
				     ns->zrwacap);
		shr_table_set_row_subtable(t, row,
				stdout_zns_id_ns_zrwacap_table(ns->zrwacap));
	} else {
		stdout_kv_add(t, "zrwacap", "%u", ns->zrwacap);
	}

	stdout_kv_table_finish(t, "zns-id-ns");

	for (i = 0; i <= id_ns->nlbaf && i < ARRAY_SIZE(ns->lbafe); i++) {
		if (verbose)
			printf("LBA Format Extension %2d : Zone Size: %#"PRIx64
			       " LBAs - Zone Descriptor Extension Size: %-1d bytes%s\n",
			       i, le64_to_cpu(ns->lbafe[i].zsze),
			       ns->lbafe[i].zdes << 6,
			       i == lbaf ? " (in use)" : "");
		else
			printf("lbafe %2d: zsze:%#"PRIx64" zdes:%u%s\n", i,
			       (uint64_t)le64_to_cpu(ns->lbafe[i].zsze),
			       ns->lbafe[i].zdes, i == lbaf ? " (in use)" : "");
	}

	if (vs) {
		printf("vs[]    :\n");
		d(ns->vs, sizeof(ns->vs), 16, 1);
	}
}

static void stdout_zns_changed(struct nvme_zns_changed_zone_log *log)
{
	struct shr_table *t;
	uint16_t nrzid;
	int i;

	nrzid = le16_to_cpu(log->nrzid);
	printf("NVMe Changed Zone List:\n");

	if (nrzid == 0xFFFF) {
		printf(
			"Too many zones have changed to fit into the log. Use report zones for changes.\n");
		return;
	}

	t = stdout_kv_table_create();
	if (!t)
		return;

	stdout_kv_add(t, "nrzid", "%u", nrzid);
	for (i = 0; i < nrzid && i < ARRAY_SIZE(log->zid); i++) {
		char name[16];

		snprintf(name, sizeof(name), "zid %03d", i);
		stdout_kv_add(t, name, "%"PRIu64,
			      (uint64_t)le64_to_cpu(log->zid[i]));
	}

	stdout_kv_table_finish(t, "zns-changed-zone-log");
}

static void stdout_zns_start_zone_list(__u64 nr_zones,
				       struct json_object **zone_list)
{
	printf("nr_zones: %"PRIu64"\n", (uint64_t)le64_to_cpu(nr_zones));
}

static void stdout_zns_report_zone_attrs_decoded(char *buf, size_t len,
		__u8 za, __u8 zai)
{
	const char * const recommended_limit[4] = {"", "1", "2", "3"};
	size_t n = 0;

	shr_snprintf_append(buf, len, &n, "%sValid",
			    za & NVME_ZNS_ZA_ZDEV ? "" : "Not ");

	if (za & NVME_ZNS_ZA_RZR)
		shr_snprintf_append(buf, len, &n,
				    ", Reset Recommended (Limit %s)",
				    recommended_limit[NVME_ZNS_ZAI_RZRTL(zai)]);

	if (za & NVME_ZNS_ZA_FZR)
		shr_snprintf_append(buf, len, &n,
				    ", Finish Recommended (Limit %s)",
				    recommended_limit[NVME_ZNS_ZAI_FZRTL(zai)]);

	if (za & NVME_ZNS_ZA_ZFC)
		shr_snprintf_append(buf, len, &n, ", Finished by Controller");
}

static struct nvme_zns_desc *stdout_zns_report_zones_desc(void *report,
		__u8 ext_size, int i)
{
	struct nvme_zone_report *r = report;

	return (struct nvme_zns_desc *)(report + sizeof(*r) +
			i * (sizeof(struct nvme_zns_desc) + ext_size));
}

static void stdout_zns_report_zones(void *report, __u32 descs,
				    __u8 ext_size, __u32 report_size,
				    struct json_object *zone_list)
{
	struct shr_table_column columns_verbose[] = {
		{ "SLBA",          LEFT, AUTO_WIDTH },
		{ "WP",            LEFT, AUTO_WIDTH },
		{ "Cap",           LEFT, AUTO_WIDTH },
		{ "State",         LEFT, AUTO_WIDTH },
		{ "Type",          LEFT, AUTO_WIDTH },
		{ "Attrs",         LEFT, AUTO_WIDTH },
		{ "AttrsInfo",     LEFT, AUTO_WIDTH },
		{ "Attrs Decoded", LEFT, AUTO_WIDTH },
	};
	struct shr_table_column columns[] = {
		{ "SLBA",      LEFT, AUTO_WIDTH },
		{ "WP",        LEFT, AUTO_WIDTH },
		{ "Cap",       LEFT, AUTO_WIDTH },
		{ "State",     LEFT, AUTO_WIDTH },
		{ "Type",      LEFT, AUTO_WIDTH },
		{ "Attrs",     LEFT, AUTO_WIDTH },
		{ "AttrsInfo", LEFT, AUTO_WIDTH },
	};
	struct nvme_zone_report *r = report;
	struct nvme_zns_desc *desc;
	struct shr_table *t;
	int i, row, verbose = stdout_ops.flags & VERBOSE;
	__u64 nr_zones = le64_to_cpu(r->nr_zones);

	if (nr_zones < descs)
		descs = nr_zones;

	if (verbose)
		t = shr_table_init_with_columns(columns_verbose,
						 ARRAY_SIZE(columns_verbose));
	else
		t = shr_table_init_with_columns(columns, ARRAY_SIZE(columns));
	if (!t)
		return;

	for (i = 0; i < descs; i++) {
		char slba[24], wp[24], cap[24], attrs[8], attrsinfo[8];
		int col = 0;

		desc = stdout_zns_report_zones_desc(report, ext_size, i);
		row = shr_table_get_row_id(t);

		snprintf(slba, sizeof(slba), "%#"PRIx64,
			 (uint64_t)le64_to_cpu(desc->zslba));
		snprintf(wp, sizeof(wp), "%#"PRIx64,
			 (uint64_t)le64_to_cpu(desc->wp));
		snprintf(cap, sizeof(cap), "%#"PRIx64,
			 (uint64_t)le64_to_cpu(desc->zcap));
		snprintf(attrs, sizeof(attrs), "%#x", desc->za);
		snprintf(attrsinfo, sizeof(attrsinfo), "%#x", desc->zai);

		shr_table_set_value_str(t, col++, row, slba, LEFT);
		shr_table_set_value_str(t, col++, row, wp, LEFT);
		shr_table_set_value_str(t, col++, row, cap, LEFT);

		if (verbose) {
			const char *state = zns_zone_state_to_string(
			    NVME_ZNS_DESC_ZS(desc->zs));
			const char *type = zns_zone_type_to_string(desc->zt);

			shr_table_set_value_str(t, col++, row, state, LEFT);
			shr_table_set_value_str(t, col++, row, type, LEFT);
		} else {
			char state[8], type[8];

			snprintf(state, sizeof(state), "%#x", desc->zs);
			snprintf(type, sizeof(type), "%#x", desc->zt);

			shr_table_set_value_str(t, col++, row, state, LEFT);
			shr_table_set_value_str(t, col++, row, type, LEFT);
		}

		shr_table_set_value_str(t, col++, row, attrs, LEFT);
		shr_table_set_value_str(t, col++, row, attrsinfo, LEFT);

		if (verbose) {
			char decoded[128];

			stdout_zns_report_zone_attrs_decoded(decoded,
					sizeof(decoded), desc->za, desc->zai);
			shr_table_set_value_str(t, col++, row, decoded, LEFT);
		}

		shr_table_add_row(t, row);
	}

	shr_table_print_header(stdout, t);

	for (i = 0; i < descs; i++) {
		desc = stdout_zns_report_zones_desc(report, ext_size, i);

		shr_table_print_row(stdout, t, i);

		if (ext_size && (desc->za & NVME_ZNS_ZA_ZDEV)) {
			printf("Extension Data: ");
			d((unsigned char *)desc + sizeof(*desc), ext_size, 16,
			  1);
			printf("..\n");
		}
	}

	shr_table_free(t);
}

static struct zns_print_ops stdout_ops = {
	.id_ctrl		= stdout_zns_id_ctrl,
	.id_ns			= stdout_zns_id_ns,
	.changed_zone_log	= stdout_zns_changed,
	.start_zone_list	= stdout_zns_start_zone_list,
	.report_zones		= stdout_zns_report_zones,
	.finish_zone_list	= NULL,
};

struct zns_print_ops *zns_get_stdout_print_ops(nvme_print_flags_t flags)
{
	stdout_ops.flags = flags;
	return &stdout_ops;
}
