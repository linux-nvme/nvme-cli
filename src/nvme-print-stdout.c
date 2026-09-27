// SPDX-License-Identifier: GPL-2.0-or-later
#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>

#ifdef CONFIG_FABRICS
#include <arpa/inet.h>
#include <sys/socket.h>
#endif

#include <libnvme-mi.h>
#include <libnvme.h>

#include <ccan/array_size/array_size.h>
#include <ccan/endian/endian.h>
#include <ccan/hash/hash.h>
#include <ccan/htable/htable.h>
#include <ccan/htable/htable_type.h>
#include <ccan/minmax/minmax.h>
#include <ccan/strset/strset.h>
#include <shared/int-util.h>
#include <shared/mmio-util.h>
#include <shared/suffix-util.h>
#include <shared/table-util.h>
#include <shared/uint128-util.h>
#include <shared/uuid-util.h>
#include <shared/string-util.h>

#include "cleanup.h"
#include "logging.h"
#include "nvme-print.h"
#include "nvme-print-stdout.h"

enum simple_list_col {
	SIMPLE_LIST_COL_NODE,
	SIMPLE_LIST_COL_GENERIC,
	SIMPLE_LIST_COL_SN,
	SIMPLE_LIST_COL_MODEL,
	SIMPLE_LIST_COL_NS,
	SIMPLE_LIST_COL_USAGE,
	SIMPLE_LIST_COL_FORMAT,
	SIMPLE_LIST_COL_FW_REV,
};

const char dash[100] = {[0 ... 99] = '-'};

struct print_ops stdout_print_ops;

static const char *subsys_key(const struct libnvme_subsystem *s)
{
	return libnvme_subsystem_get_name((struct libnvme_subsystem *)s);
}

static const char *ctrl_key(const struct libnvme_ctrl *c)
{
	return libnvme_ctrl_get_name((struct libnvme_ctrl *)c);
}

static const char *ns_key(const struct libnvme_ns *n)
{
	return libnvme_ns_get_name((struct libnvme_ns *)n);
}

static bool subsys_cmp(const struct libnvme_subsystem *s, const char *name)
{
	return !strcmp(libnvme_subsystem_get_name((struct libnvme_subsystem *)s), name);
}

static bool ctrl_cmp(const struct libnvme_ctrl *c, const char *name)
{
	return !strcmp(libnvme_ctrl_get_name((struct libnvme_ctrl *)c), name);
}

static bool ns_cmp(const struct libnvme_ns *n, const char *name)
{
	return !strcmp(libnvme_ns_get_name((struct libnvme_ns *)n), name);
}

HTABLE_DEFINE_TYPE(struct libnvme_subsystem, subsys_key, hash_string,
		   subsys_cmp, htable_subsys);
HTABLE_DEFINE_TYPE(struct libnvme_ctrl, ctrl_key, hash_string,
		   ctrl_cmp, htable_ctrl);
HTABLE_DEFINE_TYPE(struct libnvme_ns, ns_key, hash_string,
		   ns_cmp, htable_ns);

static void htable_ctrl_add_unique(struct htable_ctrl *ht, struct libnvme_ctrl *c)
{
	if (htable_ctrl_get(ht, libnvme_ctrl_get_name(c)))
		return;

	htable_ctrl_add(ht, c);
}

static void htable_ns_add_unique(struct htable_ns *ht, struct libnvme_ns *n)
{
	struct htable_ns_iter it;
	struct libnvme_ns *_n;

	/*
	 * Test if namespace pointer is already in the hash, and thus avoid
	 * inserting severaltimes the same pointer.
	 */
	for (_n = htable_ns_getfirst(ht, libnvme_ns_get_name(n), &it);
	     _n;
	     _n = htable_ns_getnext(ht, libnvme_ns_get_name(n), &it)) {
		if (_n == n)
			return;
	}
	htable_ns_add(ht, n);
}

/*
 * Device names share a common textual prefix (e.g. "nvme", "nvme0n")
 * followed by an integer index, so a plain byte-wise comparison would
 * order "nvme10" before "nvme2". Walk both strings together and,
 * whenever a run of digits begins in both, compare the runs by
 * numeric value; otherwise fall back to byte comparison.
 */
static int name_natcmp(const char *sa, const char *sb)
{
	while (*sa && *sb) {
		if (isdigit((unsigned char)*sa) && isdigit((unsigned char)*sb)) {
			char *enda, *endb;
			unsigned long va = strtoul(sa, &enda, 10);
			unsigned long vb = strtoul(sb, &endb, 10);

			if (va != vb)
				return va < vb ? -1 : 1;

			sa = enda;
			sb = endb;
			continue;
		}

		if (*sa != *sb)
			return (unsigned char)*sa - (unsigned char)*sb;

		sa++;
		sb++;
	}

	return (unsigned char)*sa - (unsigned char)*sb;
}

static int name_natcmp_qsort(const void *a, const void *b)
{
	return name_natcmp(*(const char * const *)a, *(const char * const *)b);
}

struct name_collector {
	const char **names;
	size_t count;
	size_t capacity;
};

static bool name_collect(const char *name, void *arg)
{
	struct name_collector *nc = arg;

	if (nc->count == nc->capacity) {
		const char **tmp;

		nc->capacity = nc->capacity ? nc->capacity * 2 : 16;
		tmp = realloc(nc->names, nc->capacity * sizeof(*nc->names));
		if (!tmp)
			return false;
		nc->names = tmp;
	}

	nc->names[nc->count++] = name;

	return true;
}

/*
 * Like strset_iterate(), but visits members in natural (numeric-aware)
 * order instead of the strset's underlying byte-lexicographic trie
 * order, so e.g. "nvme2" sorts before "nvme10".
 */
#define strset_iterate_sorted(set, handle, arg)			\
	strset_iterate_sorted_((set), typesafe_cb_preargs(bool, void *, \
						   (handle), (arg),	\
						   const char *),	\
			(arg))

static void strset_iterate_sorted_(const struct strset *set,
				    bool (*handle)(const char *, void *),
				    const void *data)
{
	struct name_collector nc = { 0 };
	size_t i;

	strset_iterate_(set, name_collect, &nc);
	qsort(nc.names, nc.count, sizeof(*nc.names), name_natcmp_qsort);

	for (i = 0; i < nc.count; i++) {
		if (!handle(nc.names[i], (void *)data))
			break;
	}

	free(nc.names);
}

struct nvme_resources {
	struct libnvme_global_ctx *ctx;

	struct htable_subsys ht_s;
	struct htable_ctrl ht_c;
	struct htable_ns ht_n;
	struct strset subsystems;
	struct strset ctrls;
	struct strset namespaces;
};

struct nvme_resources_table {
	struct nvme_resources *res;
	struct shr_table *t;
};

static int nvme_resources_init(struct libnvme_global_ctx *ctx, struct nvme_resources *res)
{
	struct libnvme_host *h;
	struct libnvme_subsystem *s;
	struct libnvme_ctrl *c;
	struct libnvme_ns *n;
	struct libnvme_path *p;

	res->ctx = ctx;
	htable_subsys_init(&res->ht_s);
	htable_ctrl_init(&res->ht_c);
	htable_ns_init(&res->ht_n);
	strset_init(&res->subsystems);
	strset_init(&res->ctrls);
	strset_init(&res->namespaces);

	libnvme_for_each_host(ctx, h) {
		libnvme_for_each_subsystem(h, s) {
			htable_subsys_add(&res->ht_s, s);
			strset_add(&res->subsystems, libnvme_subsystem_get_name(s));

			libnvme_subsystem_for_each_ctrl(s, c) {
				htable_ctrl_add_unique(&res->ht_c, c);
				strset_add(&res->ctrls, libnvme_ctrl_get_name(c));

				libnvme_ctrl_for_each_ns(c, n) {
					htable_ns_add_unique(&res->ht_n, n);
					strset_add(&res->namespaces, libnvme_ns_get_name(n));
				}

				libnvme_ctrl_for_each_path(c, p) {
					n = libnvme_path_get_ns(p);
					if (n) {
						htable_ns_add_unique(&res->ht_n, n);
						strset_add(&res->namespaces, libnvme_ns_get_name(n));
					}
				}
			}

			libnvme_subsystem_for_each_ns(s, n) {
				htable_ns_add_unique(&res->ht_n, n);
				strset_add(&res->namespaces, libnvme_ns_get_name(n));
			}
		}
	}

	return 0;
}

static void nvme_resources_free(struct nvme_resources *res)
{
	strset_clear(&res->namespaces);
	strset_clear(&res->ctrls);
	strset_clear(&res->subsystems);
	htable_ns_clear(&res->ht_n);
	htable_ctrl_clear(&res->ht_c);
	htable_subsys_clear(&res->ht_s);
}

static void stdout_kv_render(FILE *stream, struct shr_table *t);

static void stdout_fdp_ruh_status(struct nvme_fdp_ruh_status *status,
				  size_t len)
{
	uint16_t nruhsd = le16_to_cpu(status->nruhsd);
	struct shr_table *t;

	for (unsigned int i = 0; i < nruhsd; i++) {
		struct nvme_fdp_ruh_status_desc *ruhs = &status->ruhss[i];

		t = stdout_kv_table_create();
		if (!t)
			return;

		shr_table_set_indent(t, 2);

		stdout_kv_add(t, "Placement Identifier (PID)", "%"PRIu16,
			      le16_to_cpu(ruhs->pid));
		stdout_kv_add(t, "Reclaim Unit Handle Identifier", "%"PRIu16,
			      le16_to_cpu(ruhs->ruhid));
		stdout_kv_add(t,
			      "Estimated Active Reclaim Unit Time Remaining (EARUTR)",
			      "%"PRIu32, le32_to_cpu(ruhs->earutr));
		stdout_kv_add(t, "Reclaim Unit Available Media Writes (RUAMW)",
			      "%"PRIu64, le64_to_cpu(ruhs->ruamw));

		stdout_kv_table_finish(t, "fdp-ruh-status");

		printf("\n");
	}
}

static unsigned int stdout_subsystem_multipath(struct libnvme_subsystem *s)
{
	struct libnvme_ns *n;
	struct libnvme_path *p;
	unsigned int i = 0;

	n = libnvme_subsystem_first_ns(s);
	if (!n)
		return 0;

	libnvme_namespace_for_each_path(n, p) {
		struct libnvme_ctrl *c = libnvme_path_get_ctrl(p);
		const char *ana_state;

		libnvme_path_get_ana_state(p, &ana_state, "");

		printf(" +- %s %s %s %s %s\n",
			libnvme_ctrl_get_name(c),
			libnvme_ctrl_get_transport(c),
			libnvme_ctrl_get_traddr(c),
			libnvme_ctrl_get_state(c),
			ana_state);
		i++;
	}

	return i;
}

static void stdout_subsystem_ctrls(struct libnvme_subsystem *s)
{
	struct libnvme_ctrl *c;

	libnvme_subsystem_for_each_ctrl(s, c) {
		printf(" +- %s %s %s %s\n",
			libnvme_ctrl_get_name(c),
			libnvme_ctrl_get_transport(c),
			libnvme_ctrl_get_traddr(c),
			libnvme_ctrl_get_state(c));
	}
}

static void stdout_subsys_config(struct libnvme_subsystem *s,
				 bool show_iopolicy)
{
	int len = strlen(libnvme_subsystem_get_name(s));

	printf("%s - NQN=%s\n", libnvme_subsystem_get_name(s),
	       libnvme_subsystem_get_subsysnqn(s));
	printf("%*s   hostnqn=%s\n", len, " ",
	       libnvme_host_get_hostnqn(libnvme_subsystem_get_host(s)));
	if (show_iopolicy) {
		const char *iopolicy;

		libnvme_subsystem_get_iopolicy(s, &iopolicy, "");
		printf("%*s   iopolicy=%s\n", len, " ", iopolicy);
	}

	if (stdout_print_ops.flags & VERBOSE) {
		const char *model;
		const char *serial;
		const char *firmware;

		libnvme_subsystem_get_model(s, &model, "undefined");
		libnvme_subsystem_get_serial(s, &serial, "");
		libnvme_subsystem_get_firmware(s, &firmware, "");

		printf("%*s   model=%s\n", len, " ", model);
		printf("%*s   serial=%s\n", len, " ", serial);
		printf("%*s   firmware=%s\n", len, " ", firmware);
		printf("%*s   type=%s\n", len, " ",
			libnvme_subsystem_get_subsystype(s));
	}
}

static void stdout_subsystem(struct libnvme_global_ctx *ctx, bool show_ana)
{
	struct libnvme_host *h;
	bool first = true;

	libnvme_for_each_host(ctx, h) {
		struct libnvme_subsystem *s;

		libnvme_for_each_subsystem(h, s) {
			bool no_ctrl = true;
			struct libnvme_ctrl *c;

			libnvme_subsystem_for_each_ctrl(s, c)
				no_ctrl = false;
			if (no_ctrl)
				continue;

			if (!first)
				printf("\n");
			first = false;

			stdout_subsys_config(s,
					stdout_print_ops.flags & VERBOSE);
			printf("\\\n");

			if (!show_ana || !stdout_subsystem_multipath(s))
				stdout_subsystem_ctrls(s);
		}
	}
}

static void stdout_subsystem_list(struct libnvme_global_ctx *ctx, bool show_ana)
{
	stdout_subsystem(ctx, show_ana);
}

/*
 * Shared by stdout_kv_add() and stdout_prop_cap_add(): adds one row (name,
 * ':', the vasprintf()'d value) to @t and returns its row id. The ':' is its
 * own column so it lines up across a table and its subtables even where two
 * other columns need a plain space instead.
 */
static int stdout_kv_addv(struct shr_table *t, const char *name,
		const char *fmt, va_list ap)
{
	__cleanup_free char *value = NULL;
	int row;

	if (vasprintf(&value, fmt, ap) < 0)
		value = NULL;

	row = shr_table_get_row_id(t);

	shr_table_set_value_str(t, 0, row, name, LEFT);
	shr_table_set_value_str(t, 1, row, ":", LEFT);
	shr_table_set_value_str(t, 2, row, value ?: "", LEFT);
	shr_table_add_row(t, row);

	return row;
}

int stdout_kv_add(struct shr_table *t, const char *name,
		const char *fmt, ...)
{
	va_list ap;
	int row;

	va_start(ap, fmt);
	row = stdout_kv_addv(t, name, fmt, ap);
	va_end(ap);

	return row;
}

/*
 * Adds one row to a "name : value" table the same way stdout_kv_add() does,
 * but builds the name from the shared prop_cap[][2] name/symbol table (see
 * nvme-print.c) instead of taking it as a plain string -- for a property
 * this file shares with the other print backends (JSON, binary).
 */
static int stdout_prop_cap_add(struct shr_table *t, enum prop_cap fld,
		const char *fmt, ...)
{
	__cleanup_free char *name = NULL;
	va_list ap;
	int row;

	if (prop_cap[fld][0][0]) {
		if (asprintf(&name, "%s (%s)", prop_cap[fld][0],
			     prop_cap[fld][1]) < 0)
			name = NULL;
	}

	va_start(ap, fmt);
	row = stdout_kv_addv(t, name ?: "", fmt, ap);
	va_end(ap);

	return row;
}

/* Creates the 3-column "name : value" table stdout_kv_add() populates. */
struct shr_table *stdout_kv_table_create(void)
{
	struct shr_table_column columns[] = {
		{ "", LEFT, AUTO_WIDTH },
		{ "", LEFT, AUTO_WIDTH },
		{ "", LEFT, AUTO_WIDTH },
	};
	struct shr_table *t = shr_table_init_with_columns(columns, 3);

	if (!t)
		return NULL;

	shr_table_set_no_header(t, true);

	return t;
}

/*
 * Shared by stdout_bits_add() and stdout_bits_add_str(): adds one row to a
 * 4-column "bits : value description" table, with a constant gutter before
 * the description, independent of the value column's own width.
 */
static void stdout_bits_add_strv(struct shr_table *t, const char *bits,
		const char *value, const char *desc_fmt, va_list ap)
{
	__cleanup_free char *desc_raw = NULL;
	__cleanup_free char *desc = NULL;
	int row;

	if (vasprintf(&desc_raw, desc_fmt, ap) < 0)
		desc_raw = NULL;

	if (asprintf(&desc, "  %s", desc_raw ?: "") < 0)
		desc = NULL;

	row = shr_table_get_row_id(t);

	shr_table_set_value_str(t, 0, row, bits, RIGHT);
	shr_table_set_value_str(t, 1, row, ":", LEFT);
	shr_table_set_value_str(t, 2, row, value ?: "", LEFT);
	shr_table_set_value_str(t, 3, row, desc ?: "", LEFT);
	shr_table_add_row(t, row);
}

/*
 * Adds one row to a 4-column "bits : value description" table, using a
 * caller-formatted value string instead of an unsigned int -- for a value
 * that isn't a small bitfield (e.g. a 128-bit capacity).
 */
void stdout_bits_add_str(struct shr_table *t, const char *bits,
		const char *value, const char *desc_fmt, ...)
{
	va_list ap;

	va_start(ap, desc_fmt);
	stdout_bits_add_strv(t, bits, value, desc_fmt, ap);
	va_end(ap);
}

/*
 * Adds one row to a 4-column "bits : value description" table, one row per
 * bit-field. @desc_fmt works like printf(), matching the "%sSupported"
 * pattern the decode descriptions use.
 */
void stdout_bits_add(struct shr_table *t, const char *bits,
		unsigned int val, const char *desc_fmt, ...)
{
	__cleanup_free char *value = NULL;
	va_list ap;

	if (asprintf(&value, "%#x", val) < 0)
		value = NULL;

	va_start(ap, desc_fmt);
	stdout_bits_add_strv(t, bits, value ?: "", desc_fmt, ap);
	va_end(ap);
}

/*
 * Creates the 4-column table a bit-decode builder (e.g.
 * stdout_id_ctrl_cmic_table()) returns.
 */
struct shr_table *stdout_bits_table_create(void)
{
	struct shr_table_column columns[] = {
		{ "", RIGHT, AUTO_WIDTH },
		{ "", LEFT, AUTO_WIDTH },
		{ "", RIGHT, AUTO_WIDTH },
		{ "", LEFT, AUTO_WIDTH },
	};
	struct shr_table *t = shr_table_init_with_columns(columns, 4);

	if (!t)
		return NULL;

	shr_table_set_no_header(t, true);
	shr_table_set_indent(t, 2);

	return t;
}

/*
 * Prints every row of @t, and, for a row with a nested bit-decode table
 * attached, that table right after it. Aligns column 0 (name/bits) across
 * @t and every subtable, and column 2 (value) across the subtables
 * themselves, so both the ':' and the description start at the same
 * column everywhere.
 */
static void stdout_kv_render(FILE *stream, struct shr_table *t)
{
	int row;
	struct shr_table *sub;

	shr_table_align_column(t, 0, 0);
	shr_table_align_subtable_column(t, 2);

	for (row = 0; row < t->num_rows; row++) {
		shr_table_print_row(stream, t, row);
		sub = shr_table_get_row_subtable(t, row);
		if (sub) {
			shr_table_print_stream(stream, sub);
			fprintf(stream, "\n");
		}
	}
}

/*
 * Renders @t to stdout, or reports the build error to stderr naming
 * @what, then frees @t either way. Common tail for every kv table
 * built via stdout_kv_table_create()/stdout_kv_add().
 */
void stdout_kv_table_finish(struct shr_table *t, const char *what)
{
	if (shr_table_has_error(t))
		fprintf(stderr, "Failed to build %s table\n", what);
	else
		stdout_kv_render(stdout, t);
	shr_table_free(t);
}

static struct shr_table *stdout_registers_cap_table(uint64_t cap)
{
	struct shr_table *t;

	t = stdout_kv_table_create();
	if (!t)
		return NULL;

	stdout_prop_cap_add(t, PROP_CAP_NSSES, "%s",
			     nvme_support_str(NVME_CAP_NSSES(cap)));
	stdout_prop_cap_add(t, PROP_CAP_CRWMS, "%s",
			     nvme_support_str(NVME_CAP_CRMS(cap) &
					       NVME_CAP_CRWMS));
	stdout_prop_cap_add(t, PROP_CAP_CRIMS, "%s",
			     nvme_support_str(NVME_CAP_CRMS(cap) &
					       NVME_CAP_CRIMS));
	stdout_prop_cap_add(t, PROP_CAP_NSSS, "%s",
			     nvme_support_str(NVME_CAP_NSSS(cap)));
	stdout_prop_cap_add(t, PROP_CAP_PMRS,
			     "The Persistent Memory Region is %s",
			     nvme_support_str(NVME_CAP_PMRS(cap)));
	stdout_prop_cap_add(t, PROP_CAP_MPSMAX, "%u bytes",
			     1 << (12 + NVME_CAP_MPSMAX(cap)));
	stdout_prop_cap_add(t, PROP_CAP_MPSMIN, "%u bytes",
			     1 << (12 + NVME_CAP_MPSMIN(cap)));
	stdout_prop_cap_add(t, PROP_CAP_CPS, "%s",
			     prop_cap_cps_str(NVME_CAP_CPS(cap)));
	stdout_prop_cap_add(t, PROP_CAP_BPS, "%s",
			     nvme_yes_str(NVME_CAP_BPS(cap)));
	stdout_prop_cap_add(t, PROP_CAP_CSS, "NVM command set is %s",
			     nvme_support_str(NVME_CAP_CSS(cap) &
					       NVME_CAP_CSS_NVM));
	stdout_prop_cap_add(t, PROP_CAP_NONE,
			     "One or more I/O Command Sets are %s",
			     nvme_support_str(NVME_CAP_CSS(cap) &
					       NVME_CAP_CSS_CSI));
	stdout_prop_cap_add(t, PROP_CAP_NONE, "%s",
			     NVME_CAP_CSS(cap) & NVME_CAP_CSS_ADMIN ?
			     "Only Admin Command Set Supported" :
			     "I/O Command Set is Supported");
	stdout_prop_cap_add(t, PROP_CAP_NSSRS, "%s",
			     nvme_yes_str(NVME_CAP_NSSRS(cap)));
	stdout_prop_cap_add(t, PROP_CAP_DSTRD, "%u bytes",
			     1 << (2 + NVME_CAP_DSTRD(cap)));
	stdout_prop_cap_add(t, PROP_CAP_TO, "%"PRIu64" ms",
			     MS500_TO_MS(NVME_CAP_TO(cap)));
	stdout_prop_cap_add(t, PROP_CAP_AMS,
			     "Weighted Round Robin with Urgent Priority Class is %s",
			     nvme_support_str(NVME_CAP_AMS(cap) &
					       NVME_CAP_AMS_WRR));
	stdout_prop_cap_add(t, PROP_CAP_NONE, "Vendor Specific is %s",
			     nvme_support_str(NVME_CAP_AMS(cap) &
					       NVME_CAP_AMS_VS));
	stdout_prop_cap_add(t, PROP_CAP_CQR, "%s",
			     nvme_yes_str(NVME_CAP_CQR(cap)));
	stdout_prop_cap_add(t, PROP_CAP_MQES, "%"PRIu64,
			     NVME_CAP_MQES(cap) + 1);

	return t;
}

static struct shr_table *stdout_registers_version_table(__u32 vs)
{
	struct shr_table *t;

	t = stdout_kv_table_create();
	if (!t)
		return NULL;

	stdout_kv_add(t, "", "NVMe specification %d.%d.%d", NVME_MAJOR(vs),
		      NVME_MINOR(vs), NVME_TERTIARY(vs));

	return t;
}

static const char *stdout_registers_cc_ams_str(__u8 ams)
{
	switch (ams) {
	case NVME_CC_AMS_RR:
		return "Round Robin";
	case NVME_CC_AMS_WRRU:
		return "Weighted Round Robin with Urgent Priority Class";
	case NVME_CC_AMS_VS:
		return "Vendor Specific";
	default:
		return "Reserved";
	}
}

static const char *stdout_registers_cc_shn_str(__u8 shn)
{
	switch (shn) {
	case NVME_CC_SHN_NONE:
		return "No notification; no effect";
	case NVME_CC_SHN_NORMAL:
		return "Normal shutdown notification";
	case NVME_CC_SHN_ABRUPT:
		return "Abrupt shutdown notification";
	default:
		return "Reserved";
	}
}

static struct shr_table *stdout_registers_cc_table(__u32 cc)
{
	struct shr_table *t;

	t = stdout_kv_table_create();
	if (!t)
		return NULL;

	stdout_kv_add(t, "Controller Ready Independent of Media Enable (CRIME)",
		      "%s", NVME_CC_CRIME(cc) ? "Enabled" : "Disabled");
	stdout_kv_add(t, "I/O Completion Queue Entry Size (IOCQES)", "%u bytes",
		      POWER_OF_TWO(NVME_CC_IOCQES(cc)));
	stdout_kv_add(t, "I/O Submission Queue Entry Size (IOSQES)", "%u bytes",
		      POWER_OF_TWO(NVME_CC_IOSQES(cc)));
	stdout_kv_add(t, "Shutdown Notification (SHN)", "%s",
		      stdout_registers_cc_shn_str(NVME_CC_SHN(cc)));
	stdout_kv_add(t, "Arbitration Mechanism Selected (AMS)", "%s",
		      stdout_registers_cc_ams_str(NVME_CC_AMS(cc)));
	stdout_kv_add(t, "Memory Page Size (MPS)", "%u bytes",
		      POWER_OF_TWO(12 + NVME_CC_MPS(cc)));
	stdout_kv_add(t, "I/O Command Set Selected (CSS)", "%s",
		      NVME_CC_CSS(cc) == NVME_CC_CSS_NVM ? "NVM Command Set" :
		      NVME_CC_CSS(cc) == NVME_CC_CSS_CSI ?
		      "All supported I/O Command Sets" :
		      NVME_CC_CSS(cc) == NVME_CC_CSS_ADMIN ?
		      "Admin Command Set only" : "Reserved");
	stdout_kv_add(t, "Enable (EN)", "%s", NVME_CC_EN(cc) ? "Yes" : "No");

	return t;
}

static const char *stdout_registers_csts_shst_str(__u8 shst)
{
	switch (shst) {
	case NVME_CSTS_SHST_NORMAL:
		return "Normal operation (no shutdown has been requested)";
	case NVME_CSTS_SHST_OCCUR:
		return "Shutdown processing occurring";
	case NVME_CSTS_SHST_CMPLT:
		return "Shutdown processing complete";
	default:
		return "Reserved";
	}
}

static struct shr_table *stdout_registers_csts_table(__u32 csts)
{
	struct shr_table *t;

	t = stdout_kv_table_create();
	if (!t)
		return NULL;

	stdout_kv_add(t, "Shutdown Type (ST)", "%s",
		      NVME_CSTS_ST(csts) ? "Subsystem" : "Controller");
	stdout_kv_add(t, "Processing Paused (PP)", "%s",
		      NVME_CSTS_PP(csts) ? "Yes" : "No");
	stdout_kv_add(t, "NVM Subsystem Reset Occurred (NSSRO)", "%s",
		      NVME_CSTS_NSSRO(csts) ? "Yes" : "No");
	stdout_kv_add(t, "Shutdown Status (SHST)", "%s",
		      stdout_registers_csts_shst_str(NVME_CSTS_SHST(csts)));
	stdout_kv_add(t, "Controller Fatal Status (CFS)", "%s",
		      NVME_CSTS_CFS(csts) ? "True" : "False");
	stdout_kv_add(t, "Ready (RDY)", "%s",
		      NVME_CSTS_RDY(csts) ? "Yes" : "No");

	return t;
}

static struct shr_table *stdout_registers_nssd_table(__u32 nssd)
{
	struct shr_table *t;

	t = stdout_kv_table_create();
	if (!t)
		return NULL;

	stdout_kv_add(t, "NVM Subsystem Shutdown Control (NSSC)", "%#x", nssd);

	return t;
}

static struct shr_table *stdout_registers_crto_table(__u32 crto)
{
	struct shr_table *t;

	t = stdout_kv_table_create();
	if (!t)
		return NULL;

	stdout_kv_add(t, "CRIMT", "%d secs", NVME_CRTO_CRIMT(crto) / 2);
	stdout_kv_add(t, "CRWMT", "%d secs", NVME_CRTO_CRWMT(crto) / 2);

	return t;
}

static struct shr_table *stdout_registers_aqa_table(__u32 aqa)
{
	struct shr_table *t;

	t = stdout_kv_table_create();
	if (!t)
		return NULL;

	stdout_kv_add(t, "Admin Completion Queue Size (ACQS)", "%u",
		      NVME_AQA_ACQS(aqa) + 1);
	stdout_kv_add(t, "Admin Submission Queue Size (ASQS)", "%u",
		      NVME_AQA_ASQS(aqa) + 1);

	return t;
}

static struct shr_table *stdout_registers_asq_table(uint64_t asq)
{
	struct shr_table *t;

	t = stdout_kv_table_create();
	if (!t)
		return NULL;

	stdout_kv_add(t, "Admin Submission Queue Base (ASQB)", "%"PRIx64,
		      (uint64_t)NVME_ASQ_ASQB(asq));

	return t;
}

static struct shr_table *stdout_registers_acq_table(uint64_t acq)
{
	struct shr_table *t;

	t = stdout_kv_table_create();
	if (!t)
		return NULL;

	stdout_kv_add(t, "Admin Completion Queue Base (ACQB)", "%"PRIx64,
		      (uint64_t)NVME_ACQ_ACQB(acq));

	return t;
}

static struct shr_table *
stdout_registers_cmbloc_table(__u32 cmbloc, bool support)
{
	static const char * const enforced[] = { "Enforced", "Not Enforced" };
	struct shr_table *t;

	t = stdout_kv_table_create();
	if (!t)
		return NULL;

	if (!support) {
		stdout_kv_add(t, "", "%s",
			      "Controller Memory Buffer feature is not supported");
		return t;
	}

	stdout_kv_add(t, "Offset (OFST)", "%#x (See cmbsz.szu for granularity)",
		      NVME_CMBLOC_OFST(cmbloc));
	stdout_kv_add(t, "CMB Queue Dword Alignment (CQDA)", "%d",
		      NVME_CMBLOC_CQDA(cmbloc));
	stdout_kv_add(t, "CMB Data Metadata Mixed Memory Support (CDMMMS)",
		      "%s", enforced[NVME_CMBLOC_CDMMMS(cmbloc)]);
	stdout_kv_add(t,
		      "CMB Data Pointer and Command Independent Locations Support (CDPCILS)",
		      "%s", enforced[NVME_CMBLOC_CDPCILS(cmbloc)]);
	stdout_kv_add(t, "CMB Data Pointer Mixed Locations Support (CDPMLS)",
		      "%s", enforced[NVME_CMBLOC_CDPLMS(cmbloc)]);
	stdout_kv_add(t, "CMB Queue Physically Discontiguous Support (CQPDS)",
		      "%s", enforced[NVME_CMBLOC_CQPDS(cmbloc)]);
	stdout_kv_add(t, "CMB Queue Mixed Memory Support (CQMMS)", "%s",
		      enforced[NVME_CMBLOC_CQMMS(cmbloc)]);
	stdout_kv_add(t, "Base Indicator Register (BIR)", "%#x",
		      NVME_CMBLOC_BIR(cmbloc));

	return t;
}

static struct shr_table *stdout_registers_cmbsz_table(__u32 cmbsz)
{
	struct shr_table *t;

	t = stdout_kv_table_create();
	if (!t)
		return NULL;

	if (!cmbsz) {
		stdout_kv_add(t, "", "%s",
			      "Controller Memory Buffer feature is not supported");
		return t;
	}

	stdout_kv_add(t, "Size (SZ)", "%u", NVME_CMBSZ_SZ(cmbsz));
	stdout_kv_add(t, "Size Units (SZU)", "%s",
		      nvme_register_szu_to_string(NVME_CMBSZ_SZU(cmbsz)));
	stdout_kv_add(t, "Write Data Support (WDS)",
		      "Write Data and metadata transfer in Controller Memory Buffer is %s",
		      NVME_CMBSZ_WDS(cmbsz) ? "Supported" : "Not supported");
	stdout_kv_add(t, "Read Data Support (RDS)",
		      "Read Data and metadata transfer in Controller Memory Buffer is %s",
		      NVME_CMBSZ_RDS(cmbsz) ? "Supported" : "Not supported");
	stdout_kv_add(t, "PRP SGL List Support (LISTS)",
		      "PRP/SG Lists in Controller Memory Buffer is %s",
		      NVME_CMBSZ_LISTS(cmbsz) ? "Supported" : "Not supported");
	stdout_kv_add(t, "Completion Queue Support (CQS)",
		      "Admin and I/O Completion Queues in Controller Memory Buffer is %s",
		      NVME_CMBSZ_CQS(cmbsz) ? "Supported" : "Not supported");
	stdout_kv_add(t, "Submission Queue Support (SQS)",
		      "Admin and I/O Submission Queues in Controller Memory Buffer is %s",
		      NVME_CMBSZ_SQS(cmbsz) ? "Supported" : "Not supported");

	return t;
}

static const char *stdout_registers_bpinfo_brs_str(__u8 brs)
{
	switch (brs) {
	case 0:
		return "No Boot Partition read operation requested";
	case 1:
		return "Boot Partition read in progress";
	case 2:
		return "Boot Partition read completed successfully";
	case 3:
		return "Error completing Boot Partition read";
	default:
		return "Invalid";
	}
}

static struct shr_table *stdout_registers_bpinfo_table(__u32 bpinfo)
{
	struct shr_table *t;

	t = stdout_kv_table_create();
	if (!t)
		return NULL;

	stdout_kv_add(t, "Active Boot Partition ID (ABPID)", "%u",
		      NVME_BPINFO_ABPID(bpinfo));
	stdout_kv_add(t, "Boot Read Status (BRS)", "%s",
		      stdout_registers_bpinfo_brs_str(NVME_BPINFO_BRS(bpinfo)));
	stdout_kv_add(t, "Boot Partition Size (BPSZ)", "%u",
		      NVME_BPINFO_BPSZ(bpinfo));

	return t;
}

static struct shr_table *stdout_registers_bprsel_table(__u32 bprsel)
{
	struct shr_table *t;

	t = stdout_kv_table_create();
	if (!t)
		return NULL;

	stdout_kv_add(t, "Boot Partition Identifier (BPID)", "%u",
		      NVME_BPRSEL_BPID(bprsel));
	stdout_kv_add(t, "Boot Partition Read Offset (BPROF)", "%x",
		      NVME_BPRSEL_BPROF(bprsel));
	stdout_kv_add(t, "Boot Partition Read Size (BPRSZ)", "%x",
		      NVME_BPRSEL_BPRSZ(bprsel));

	return t;
}

static struct shr_table *stdout_registers_bpmbl_table(uint64_t bpmbl)
{
	struct shr_table *t;

	t = stdout_kv_table_create();
	if (!t)
		return NULL;

	stdout_kv_add(t, "Boot Partition Memory Buffer Base Address (BMBBA)",
		      "%"PRIx64, (uint64_t)NVME_BPMBL_BMBBA(bpmbl));

	return t;
}

static struct shr_table *stdout_registers_cmbmsc_table(uint64_t cmbmsc)
{
	struct shr_table *t;

	t = stdout_kv_table_create();
	if (!t)
		return NULL;

	stdout_kv_add(t, "Controller Base Address (CBA)", "%"PRIx64,
		      (uint64_t)NVME_CMBMSC_CBA(cmbmsc));
	stdout_kv_add(t, "Controller Memory Space Enable (CMSE)", "%"PRIx64,
		      NVME_CMBMSC_CMSE(cmbmsc));
	stdout_kv_add(t, "Capabilities Registers Enabled (CRE)",
		      "CMBLOC and CMBSZ registers are %senabled",
		      NVME_CMBMSC_CRE(cmbmsc) ? "" : "NOT ");

	return t;
}

static struct shr_table *stdout_registers_cmbsts_table(__u32 cmbsts)
{
	struct shr_table *t;

	t = stdout_kv_table_create();
	if (!t)
		return NULL;

	stdout_kv_add(t, "Controller Base Address Invalid (CBAI)", "%x",
		      NVME_CMBSTS_CBAI(cmbsts));

	return t;
}

static struct shr_table *stdout_registers_cmbebs_table(__u32 cmbebs)
{
	struct shr_table *t;

	t = stdout_kv_table_create();
	if (!t)
		return NULL;

	stdout_kv_add(t, "CMB Elasticity Buffer Size Base (CMBWBZ)", "%#x",
		      NVME_CMBEBS_CMBWBZ(cmbebs));
	stdout_kv_add(t, "Read Bypass Behavior",
		      "memory reads not conflicting with memory writes in the CMB Elasticity Buffer %s bypass those memory writes",
		      NVME_CMBEBS_RBB(cmbebs) ? "SHALL" : "MAY");
	stdout_kv_add(t, "CMB Elasticity Buffer Size Units (CMBSZU)", "%s",
		      nvme_register_unit_to_string(NVME_CMBEBS_CMBSZU(cmbebs)));

	return t;
}

static struct shr_table *stdout_registers_cmbswtp_table(__u32 cmbswtp)
{
	struct shr_table *t;

	t = stdout_kv_table_create();
	if (!t)
		return NULL;

	stdout_kv_add(t, "CMB Sustained Write Throughput (CMBSWTV)", "%#x",
		      NVME_CMBSWTP_CMBSWTV(cmbswtp));
	stdout_kv_add(t, "CMB Sustained Write Throughput Units (CMBSWTU)",
		      "%s/second",
		      nvme_register_unit_to_string(
				      NVME_CMBSWTP_CMBSWTU(cmbswtp)));

	return t;
}

static struct shr_table *stdout_registers_pmrcap_table(__u32 pmrcap)
{
	struct shr_table *t;

	t = stdout_kv_table_create();
	if (!t)
		return NULL;

	stdout_kv_add(t, "Controller Memory Space Supported (CMSS)",
		      "Referencing PMR with host supplied addresses is %sSupported",
		      NVME_PMRCAP_CMSS(pmrcap) ? "" : "Not ");
	stdout_kv_add(t, "Persistent Memory Region Timeout (PMRTO)", "%x",
		      NVME_PMRCAP_PMRTO(pmrcap));
	stdout_kv_add(t,
		      "Persistent Memory Region Write Barrier Mechanisms (PMRWBM)",
		      "%x", NVME_PMRCAP_PMRWBM(pmrcap));
	stdout_kv_add(t, "Persistent Memory Region Time Units (PMRTU)",
		      "PMR time unit is %s",
		      NVME_PMRCAP_PMRTU(pmrcap) ? "minutes" :
		      "500 milliseconds");
	stdout_kv_add(t, "Base Indicator Register (BIR)", "%x",
		      NVME_PMRCAP_BIR(pmrcap));
	stdout_kv_add(t, "Write Data Support (WDS)",
		      "Write data to the PMR is %ssupported",
		      NVME_PMRCAP_WDS(pmrcap) ? "" : "not ");
	stdout_kv_add(t, "Read Data Support (RDS)",
		      "Read data from the PMR is %ssupported",
		      NVME_PMRCAP_RDS(pmrcap) ? "" : "not ");

	return t;
}

static struct shr_table *stdout_registers_pmrctl_table(__u32 pmrctl)
{
	struct shr_table *t;

	t = stdout_kv_table_create();
	if (!t)
		return NULL;

	stdout_kv_add(t, "Enable (EN)", "PMR is %s",
		      NVME_PMRCTL_EN(pmrctl) ? "READY" : "Disabled");

	return t;
}

static struct shr_table *stdout_registers_pmrsts_table(__u32 pmrsts, bool ready)
{
	struct shr_table *t;

	t = stdout_kv_table_create();
	if (!t)
		return NULL;

	stdout_kv_add(t, "Controller Base Address Invalid (CBAI)", "%x",
		      NVME_PMRSTS_CBAI(pmrsts));
	stdout_kv_add(t, "Health Status (HSTS)", "%s",
		      nvme_register_pmr_hsts_to_string(
				      NVME_PMRSTS_HSTS(pmrsts)));
	stdout_kv_add(t, "Not Ready (NRDY)",
		      "The Persistent Memory Region is %s to process PCI Express memory read and write requests",
		      !NVME_PMRSTS_NRDY(pmrsts) && ready ?
		      "READY" : "Not Ready");
	stdout_kv_add(t, "Error (ERR)", "%x", NVME_PMRSTS_ERR(pmrsts));

	return t;
}

static struct shr_table *stdout_registers_pmrebs_table(__u32 pmrebs)
{
	struct shr_table *t;

	t = stdout_kv_table_create();
	if (!t)
		return NULL;

	stdout_kv_add(t, "PMR Elasticity Buffer Size Base (PMRWBZ)", "%x",
		      NVME_PMREBS_PMRWBZ(pmrebs));
	stdout_kv_add(t, "Read Bypass Behavior",
		      "memory reads not conflicting with memory writes in the PMR Elasticity Buffer %s bypass those memory writes",
		      NVME_PMREBS_RBB(pmrebs) ? "SHALL" : "MAY");
	stdout_kv_add(t, "PMR Elasticity Buffer Size Units (PMRSZU)", "%s",
		      nvme_register_unit_to_string(NVME_PMREBS_PMRSZU(pmrebs)));

	return t;
}

static struct shr_table *stdout_registers_pmrswtp_table(__u32 pmrswtp)
{
	struct shr_table *t;

	t = stdout_kv_table_create();
	if (!t)
		return NULL;

	stdout_kv_add(t, "PMR Sustained Write Throughput (PMRSWTV)", "%x",
		      NVME_PMRSWTP_PMRSWTV(pmrswtp));
	stdout_kv_add(t, "PMR Sustained Write Throughput Units (PMRSWTU)",
		      "%s/second",
		      nvme_register_unit_to_string(
				      NVME_PMRSWTP_PMRSWTU(pmrswtp)));

	return t;
}

static struct shr_table *stdout_registers_pmrmscl_table(uint32_t pmrmscl)
{
	struct shr_table *t;

	t = stdout_kv_table_create();
	if (!t)
		return NULL;

	stdout_kv_add(t, "Controller Base Address (CBA)", "%#x",
		      (uint32_t)NVME_PMRMSC_CBA(pmrmscl));
	stdout_kv_add(t, "Controller Memory Space Enable (CMSE)", "%#x",
		      NVME_PMRMSC_CMSE(pmrmscl));

	return t;
}

static struct shr_table *stdout_registers_pmrmscu_table(uint32_t pmrmscu)
{
	struct shr_table *t;

	t = stdout_kv_table_create();
	if (!t)
		return NULL;

	stdout_kv_add(t, "Controller Base Address (CBA)", "%#x", pmrmscu);

	return t;
}

static struct shr_table *stdout_ctrl_register_verbose_table(int offset,
		uint64_t value, bool support)
{
	struct shr_table *t;

	switch (offset) {
	case NVME_REG_CAP:
		return stdout_registers_cap_table(value);
	case NVME_REG_VS:
		return stdout_registers_version_table(value);
	case NVME_REG_INTMS:
		t = stdout_kv_table_create();
		if (!t)
			return NULL;
		stdout_kv_add(t, "Interrupt Vector Mask Set (IVMS)", "%#"PRIx64,
			      value);
		return t;
	case NVME_REG_INTMC:
		t = stdout_kv_table_create();
		if (!t)
			return NULL;
		stdout_kv_add(t, "Interrupt Vector Mask Clear (IVMC)",
			      "%#"PRIx64, value);
		return t;
	case NVME_REG_CC:
		return stdout_registers_cc_table(value);
	case NVME_REG_CSTS:
		return stdout_registers_csts_table(value);
	case NVME_REG_NSSR:
		t = stdout_kv_table_create();
		if (!t)
			return NULL;
		stdout_kv_add(t, "NVM Subsystem Reset Control (NSSRC)",
			      "%"PRIu64, value);
		return t;
	case NVME_REG_AQA:
		return stdout_registers_aqa_table(value);
	case NVME_REG_ASQ:
		return stdout_registers_asq_table(value);
	case NVME_REG_ACQ:
		return stdout_registers_acq_table(value);
	case NVME_REG_CMBLOC:
		return stdout_registers_cmbloc_table(value, support);
	case NVME_REG_CMBSZ:
		return stdout_registers_cmbsz_table(value);
	case NVME_REG_BPINFO:
		return stdout_registers_bpinfo_table(value);
	case NVME_REG_BPRSEL:
		return stdout_registers_bprsel_table(value);
	case NVME_REG_BPMBL:
		return stdout_registers_bpmbl_table(value);
	case NVME_REG_CMBMSC:
		return stdout_registers_cmbmsc_table(value);
	case NVME_REG_CMBSTS:
		return stdout_registers_cmbsts_table(value);
	case NVME_REG_CMBEBS:
		return stdout_registers_cmbebs_table(value);
	case NVME_REG_CMBSWTP:
		return stdout_registers_cmbswtp_table(value);
	case NVME_REG_NSSD:
		return stdout_registers_nssd_table(value);
	case NVME_REG_CRTO:
		return stdout_registers_crto_table(value);
	case NVME_REG_PMRCAP:
		return stdout_registers_pmrcap_table(value);
	case NVME_REG_PMRCTL:
		return stdout_registers_pmrctl_table(value);
	case NVME_REG_PMRSTS:
		return stdout_registers_pmrsts_table(value, support);
	case NVME_REG_PMREBS:
		return stdout_registers_pmrebs_table(value);
	case NVME_REG_PMRSWTP:
		return stdout_registers_pmrswtp_table(value);
	case NVME_REG_PMRMSCL:
		return stdout_registers_pmrmscl_table(value);
	case NVME_REG_PMRMSCU:
		return stdout_registers_pmrmscu_table(value);
	default:
		t = stdout_kv_table_create();
		if (!t)
			return NULL;
		stdout_kv_add(t, "",
			      "unknown register: %#04x (%s), value: %#"PRIx64,
			      offset, nvme_register_to_string(offset), value);
		return t;
	}
}

static void stdout_ctrl_register_common(int offset, uint64_t value,
					bool fabrics)
{
	bool verbose = !!(stdout_print_ops.flags & VERBOSE);
	const char *name = nvme_register_to_string(offset);
	const char *type = fabrics ? "property" : "register";
	struct shr_table *t;
	int row;

	t = stdout_kv_table_create();
	if (!t)
		return;

	if (verbose) {
		row = stdout_kv_add(t, name, "%#"PRIx64, value);
		shr_table_set_row_subtable(t, row,
				stdout_ctrl_register_verbose_table(offset,
								    value,
								    true));
	} else {
		stdout_kv_add(t, type, "%#04x (%s), value: %#"PRIx64, offset,
			      name, value);
	}

	stdout_kv_table_finish(t, "register");
}

static void stdout_ctrl_register(int offset, uint64_t value)
{
	stdout_ctrl_register_common(offset, value, false);
}

static void stdout_ctrl_register_support(struct shr_table *t, void *bar,
		bool fabrics, int offset, bool verbose, bool support)
{
	uint64_t value = nvme_is_64bit_reg(offset) ?
		shr_mmio_read64(bar + offset) : shr_mmio_read32(bar + offset);
	int row;

	if (fabrics && value == -1)
		return;

	row = stdout_kv_add(t, nvme_register_symbol_to_string(offset),
			     "%#"PRIx64, value);
	if (verbose)
		shr_table_set_row_subtable(t, row,
				stdout_ctrl_register_verbose_table(offset,
								    value,
								    support));
}

void stdout_ctrl_registers(void *bar, bool fabrics)
{
	uint32_t value;
	bool verbose = !!(stdout_print_ops.flags & VERBOSE);
	struct shr_table *t;
	int offset;
	bool support;

	t = stdout_kv_table_create();
	if (!t)
		return;

	for (offset = NVME_REG_CAP; offset <= NVME_REG_PMRMSCU;
	     offset += get_reg_size(offset)) {
		if (!nvme_is_ctrl_reg(offset) ||
		    (fabrics && !nvme_is_fabrics_reg(offset)))
			continue;
		switch (offset) {
		case NVME_REG_CMBLOC:
			value = shr_mmio_read32(bar + NVME_REG_CMBSZ);
			support = nvme_registers_cmbloc_support(value);
			break;
		case NVME_REG_PMRSTS:
			value = shr_mmio_read32(bar + NVME_REG_PMRCTL);
			support = nvme_registers_pmrctl_ready(value);
			break;
		default:
			support = true;
			break;
		}
		stdout_ctrl_register_support(t, bar, fabrics, offset, verbose,
					      support);
	}

	stdout_kv_table_finish(t, "registers");
}

static void stdout_single_property(int offset, uint64_t value)
{
	stdout_ctrl_register_common(offset, value, true);
}

static void stdout_status(int status)
{
	int val;
	int type;

	/*
	 * Callers should be checking for negative values first, but provide a
	 * sensible fallback anyway
	 */
	if (status < 0) {
		fprintf(stderr, "Error: %s\n", libnvme_strerror(-status));
		return;
	}

	val = nvme_status_get_value(status);
	type = nvme_status_get_type(status);

	switch (type) {
	case NVME_STATUS_TYPE_NVME:
		fprintf(stderr, "NVMe status: %s(%#x)\n",
			libnvme_status_to_string(val, false), val);
		break;
#ifdef CONFIG_MI
	case NVME_STATUS_TYPE_MI:
		fprintf(stderr, "NVMe-MI status: %s(%#x)\n",
			libnvme_mi_status_to_string(val), val);
		break;
#endif
	default:
		fprintf(stderr, "Unknown status type %d, value %#x\n", type,
			val);
		break;
	}
}

static void stdout_opcode_status(int status, bool admin, __u8 opcode)
{
	int val = nvme_status_get_value(status);
	int type = nvme_status_get_type(status);

	if (status >= 0 && type == NVME_STATUS_TYPE_NVME) {
		fprintf(stderr, "NVMe status: %s(0x%x)\n",
			libnvme_opcode_status_to_string(val, admin, opcode),
			val);
		return;
	}

	stdout_status(status);
}

static void stdout_error_status(int status, const char *msg, va_list ap)
{
	vfprintf(stderr, msg, ap);
	fprintf(stderr, ": ");
	stdout_status(status);
}

char *stdout_power_and_scale_str(__u16 power, __u8 scale)
{
	char *s = NULL;

	switch (scale & 0x3) {
	case NVME_PSD_PS_NOT_REPORTED:
		if (asprintf(&s, "-") < 0)
			s = NULL;
		break;
	case NVME_PSD_PS_100_MICRO_WATT:
		if (asprintf(&s, "%01u.%04uW",
			     power / 10000, power % 10000) < 0)
			s = NULL;
		break;
	case NVME_PSD_PS_10_MILLI_WATT:
		if (asprintf(&s, "%01u.%02uW", power / 100, power % 100) < 0)
			s = NULL;
		break;
	default:
		if (asprintf(&s, "reserved") < 0)
			s = NULL;
		break;
	}

	return s;
}

static void stdout_list_ns(struct nvme_ns_list *ns_list)
{
	int i, verbose = stdout_print_ops.flags & VERBOSE;

	printf("NVME Namespace List:\n");

	if (verbose) {
		struct shr_table *t;

		t = stdout_kv_table_create();
		if (!t)
			return;

		for (i = 0; i < 1024; i++) {
			char name[24];

			if (!ns_list->ns[i])
				continue;

			snprintf(name, sizeof(name), "Identifier %4u", i);
			stdout_kv_add(t, name, "NSID %#x",
				      le32_to_cpu(ns_list->ns[i]));
		}

		stdout_kv_table_finish(t, "list-ns");
	} else {
		struct shr_table_column columns[] = {
			{ "Index", RIGHT, AUTO_WIDTH },
			{ "NSID",  LEFT,  AUTO_WIDTH },
		};
		struct shr_table *t;
		bool has_entries = false;

		t = shr_table_init_with_columns(columns, ARRAY_SIZE(columns));
		if (!t)
			return;

		for (i = 0; i < 1024; i++) {
			char id[16];
			int row;

			if (!ns_list->ns[i])
				continue;

			has_entries = true;
			row = shr_table_get_row_id(t);
			snprintf(id, sizeof(id), "%#x",
				 le32_to_cpu(ns_list->ns[i]));
			shr_table_set_value_int(t, 0, row, i, RIGHT);
			shr_table_set_value_str(t, 1, row, id, LEFT);
			shr_table_add_row(t, row);
		}

		if (has_entries)
			shr_table_print(t);
		shr_table_free(t);
	}
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
	int n;

	n = snprintf(buf, len, "%sValid", za & NVME_ZNS_ZA_ZDEV ? "" : "Not ");

	if (za & NVME_ZNS_ZA_RZR)
		n += snprintf(buf + n, len - n,
			      ", Reset Recommended (Limit %s)",
			      recommended_limit[(zai&0xd)>>2]);

	if (za & NVME_ZNS_ZA_FZR)
		n += snprintf(buf + n, len - n,
			      ", Finish Recommended (Limit %s)",
			      recommended_limit[zai&0x3]);

	if (za & NVME_ZNS_ZA_ZFC)
		snprintf(buf + n, len - n, ", Finished by Controller");
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
	int i, row, verbose = stdout_print_ops.flags & VERBOSE;
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
			const char *state =
				nvme_zone_state_to_string(desc->zs >> 4);
			const char *type = nvme_zone_type_to_string(desc->zt);

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

static void stdout_list_ctrl(struct nvme_ctrl_list *ctrl_list)
{
	struct shr_table_column columns[] = {
		{ "Index",         RIGHT, AUTO_WIDTH },
		{ "Controller ID", LEFT,  AUTO_WIDTH },
	};
	__u16 num = le16_to_cpu(ctrl_list->num);
	struct shr_table *t;
	int i, row, n = min(num, 2047);

	t = stdout_kv_table_create();
	if (!t)
		return;

	stdout_kv_add(t, "num of ctrls present", "%u", num);

	stdout_kv_table_finish(t, "list-ctrl");

	if (!n)
		return;

	t = shr_table_init_with_columns(columns, ARRAY_SIZE(columns));
	if (!t)
		return;

	for (i = 0; i < n; i++) {
		char id[16];

		row = shr_table_get_row_id(t);
		snprintf(id, sizeof(id), "%#x",
			 le16_to_cpu(ctrl_list->identifier[i]));
		shr_table_set_value_int(t, 0, row, i, RIGHT);
		shr_table_set_value_str(t, 1, row, id, LEFT);
		shr_table_add_row(t, row);
	}

	shr_table_print(t);
	shr_table_free(t);
}

static struct shr_table *stdout_primary_ctrl_caps_crt_table(__u8 crt)
{
	struct shr_table *t;
	__u8 rsvd = (crt & 0xFC) >> 2;
	__u8 vi = (crt & 0x2) >> 1;
	__u8 vq = crt & 0x1;

	t = stdout_bits_table_create();
	if (!t)
		return NULL;

	if (rsvd)
		stdout_bits_add(t, "[7:2]", rsvd, "Reserved");
	stdout_bits_add(t, "[1:1]", vi, "VI Resources are %ssupported",
			 vi ? "" : "not ");
	stdout_bits_add(t, "[0:0]", vq, "VQ Resources are %ssupported",
			 vq ? "" : "not ");

	return t;
}

static void stdout_primary_ctrl_cap(const struct nvme_primary_ctrl_cap *caps)
{
	bool verbose = stdout_print_ops.flags & VERBOSE;
	struct shr_table *t;
	int row;

	printf("NVME Identify Primary Controller Capabilities:\n");

	t = stdout_kv_table_create();
	if (!t)
		return;

	stdout_kv_add(t, "cntlid", "%#x", le16_to_cpu(caps->cntlid));
	stdout_kv_add(t, "portid", "%#x", le16_to_cpu(caps->portid));

	row = stdout_kv_add(t, "crt", "%#x", caps->crt);
	if (verbose)
		shr_table_set_row_subtable(t, row,
				stdout_primary_ctrl_caps_crt_table(caps->crt));

	stdout_kv_add(t, "vqfrt", "%u", le32_to_cpu(caps->vqfrt));
	stdout_kv_add(t, "vqrfa", "%u", le32_to_cpu(caps->vqrfa));
	stdout_kv_add(t, "vqrfap", "%d", le16_to_cpu(caps->vqrfap));
	stdout_kv_add(t, "vqprt", "%d", le16_to_cpu(caps->vqprt));
	stdout_kv_add(t, "vqfrsm", "%d", le16_to_cpu(caps->vqfrsm));
	stdout_kv_add(t, "vqgran", "%d", le16_to_cpu(caps->vqgran));
	stdout_kv_add(t, "vifrt", "%u", le32_to_cpu(caps->vifrt));
	stdout_kv_add(t, "virfa", "%u", le32_to_cpu(caps->virfa));
	stdout_kv_add(t, "virfap", "%d", le16_to_cpu(caps->virfap));
	stdout_kv_add(t, "viprt", "%d", le16_to_cpu(caps->viprt));
	stdout_kv_add(t, "vifrsm", "%d", le16_to_cpu(caps->vifrsm));
	stdout_kv_add(t, "vigran", "%d", le16_to_cpu(caps->vigran));

	stdout_kv_table_finish(t, "primary-ctrl-cap");
}

static void stdout_list_secondary_ctrl(
	const struct nvme_secondary_ctrl_list *sc_list, __u32 count)
{
	const struct nvme_secondary_ctrl *sc_entry =
		&sc_list->sc_entry[0];
	static const char * const state_desc[] = { "Offline", "Online" };

	__u16 num = sc_list->num;
	__u32 entries = min(num, count);
	struct shr_table *t;
	int i;

	printf("Identify Secondary Controller List:\n");

	t = stdout_kv_table_create();
	if (!t)
		return;

	stdout_kv_add(t, "Number of Identifiers (NUMID)", "%d", num);

	stdout_kv_table_finish(t, "secondary-ctrl-list");

	for (i = 0; i < entries; i++) {
		printf("   SCEntry[%-3d]:\n", i);
		printf("................\n");

		t = stdout_kv_table_create();
		if (!t)
			return;

		shr_table_set_indent(t, 2);

		stdout_kv_add(t, "Secondary Controller Identifier (SCID)",
			      "%#.04x", le16_to_cpu(sc_entry[i].scid));
		stdout_kv_add(t, "Primary Controller Identifier (PCID)",
			      "%#.04x", le16_to_cpu(sc_entry[i].pcid));
		stdout_kv_add(t, "Secondary Controller State (SCS)",
			      "%#.04x (%s)", sc_entry[i].scs,
			      state_desc[sc_entry[i].scs & 0x1]);
		stdout_kv_add(t, "Virtual Function Number (VFN)",
			      "%#.04x", le16_to_cpu(sc_entry[i].vfn));
		stdout_kv_add(t, "Num VQ Flex Resources Assigned (NVQ)",
			      "%#.04x", le16_to_cpu(sc_entry[i].nvq));
		stdout_kv_add(t, "Num VI Flex Resources Assigned (NVI)",
			      "%#.04x", le16_to_cpu(sc_entry[i].nvi));

		stdout_kv_table_finish(t, "secondary-ctrl-list");
	}
}

static void stdout_endurance_group_list(
	struct nvme_id_endurance_group_list *endgrp_list)
{
	struct shr_table_column columns[] = {
		{ "Index",               RIGHT, AUTO_WIDTH },
		{ "Endurance Group ID",  LEFT,  AUTO_WIDTH },
	};
	__u16 num = le16_to_cpu(endgrp_list->num);
	struct shr_table *t;
	int i, row, n = min(num, 2047);

	t = stdout_kv_table_create();
	if (!t)
		return;

	stdout_kv_add(t, "num of endurance group ids", "%u", num);

	stdout_kv_table_finish(t, "endurance-group-list");

	if (!n)
		return;

	t = shr_table_init_with_columns(columns, ARRAY_SIZE(columns));
	if (!t)
		return;

	for (i = 0; i < n; i++) {
		char id[16];

		row = shr_table_get_row_id(t);
		snprintf(id, sizeof(id), "%#x",
			 le16_to_cpu(endgrp_list->identifier[i]));
		shr_table_set_value_int(t, 0, row, i, RIGHT);
		shr_table_set_value_str(t, 1, row, id, LEFT);
		shr_table_add_row(t, row);
	}

	shr_table_print(t);
	shr_table_free(t);
}

static void stdout_resv_report(struct nvme_resv_status *status, int bytes,
			       bool eds)
{
	struct shr_table *t;
	int i, j, regstrnt, entries;
	char hex[33], *hp;

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

			hp = hex;
			for (j = 0; j < 16; j++)
				hp += sprintf(hp, "%02x", reg->hostid[j]);
			stdout_kv_add(t, "hostid", "%s", hex);

			stdout_kv_table_finish(t, "registrant");
		}
	}
	printf("\n");
}

static void stdout_select_result(enum nvme_features_id fid, __u64 result)
{
	struct shr_table *t;

	t = stdout_kv_table_create();
	if (!t)
		return;

	if (result & 0x1)
		stdout_kv_add(t, "", "Feature is saveable");
	if (result & 0x2)
		stdout_kv_add(t, "", "Feature is per-namespace");
	if (result & 0x4)
		stdout_kv_add(t, "", "Feature is changeable");

	stdout_kv_table_finish(t, "select-result");
}

static void stdout_lba_range(struct nvme_lba_range_type *lbrt, int nr_ranges)
{
	int i, j;

	for (i = 0; i <= nr_ranges; i++) {
		struct nvme_lba_range_type_entry *e = &lbrt->entry[i];
		struct shr_table *t;
		char guid[2 * ARRAY_SIZE(e->guid) + 1];
		char *p = guid;

		t = stdout_kv_table_create();
		if (!t)
			return;

		shr_table_set_indent(t, 1);

		stdout_kv_add(t, "type", "%#x - %s", e->type,
			      nvme_feature_lba_type_to_string(e->type));
		const char *overwrite_str =
			NVME_LBART_ATTRB_LBARO(e->attributes) ?
			"LBA range may be overwritten" :
			"LBA range should not be overwritten";
		const char *hidden_str = NVME_LBART_ATTRB_HLBAR(e->attributes) ?
			"LBA range should be hidden from the OS/EFI/BIOS" :
			"LBA range should be visible from the OS/EFI/BIOS";

		stdout_kv_add(t, "attributes", "%#x - %s, %s", e->attributes,
			      overwrite_str, hidden_str);
		stdout_kv_add(t, "slba", "%#"PRIx64, le64_to_cpu(e->slba));
		stdout_kv_add(t, "nlb", "%#"PRIx64, le64_to_cpu(e->nlb));

		for (j = 0; j < ARRAY_SIZE(e->guid); j++)
			p += sprintf(p, "%02x", e->guid[j]);
		stdout_kv_add(t, "guid", "%s", guid);

		stdout_kv_table_finish(t, "lba-range");
	}
}

static void stdout_auto_pst(struct nvme_feat_auto_pst *apst)
{
	int i;
	__u64 value;

	printf("\tAuto PST Entries");
	printf("\t.................\n");
	for (i = 0; i < ARRAY_SIZE(apst->apst_entry); i++) {
		struct shr_table *t;

		value = le64_to_cpu(apst->apst_entry[i]);

		printf("\tEntry[%2d]\n", i);
		printf("\t.................\n");

		t = stdout_kv_table_create();
		if (!t)
			return;

		shr_table_set_indent(t, 2);
		stdout_kv_add(t, "Idle Time Prior to Transition (ITPT)",
			      "%u ms",
			      (__u32)NVME_GET(value, APST_ENTRY_ITPT));
		stdout_kv_add(t, "Idle Transition Power State (ITPS)", "%u",
			      (__u32)NVME_GET(value, APST_ENTRY_ITPS));

		stdout_kv_table_finish(t, "auto-pst");

		printf("\t.................\n");
	}
}

const char *stdout_format_timestamp(__u8 *timestamp_bytes)
{
	static char buf[STR_LEN];
	uint64_t ts_ms = int48_to_long(timestamp_bytes);

	snprintf(buf, sizeof(buf), "%"PRIu64" (%s)", ts_ms,
		nvme_format_timestamp(timestamp_bytes));

	return buf;
}

static struct shr_table *stdout_timestamp_attr_table(__u8 attr)
{
	struct shr_table *t;
	__u8 to = NVME_TIMESTAMP_ATTR_TO(attr);
	__u8 sync = NVME_TIMESTAMP_ATTR_SYNC(attr);

	t = stdout_bits_table_create();
	if (!t)
		return NULL;

	stdout_bits_add(t, "[3:1]", to, "%s",
			nvme_format_timestamp_origin(attr));
	stdout_bits_add(t, "[0:0]", sync, "%s",
			nvme_format_timestamp_sync(attr));

	return t;
}

static void stdout_timestamp(struct nvme_timestamp *ts)
{
	struct shr_table *t;
	int row;

	t = stdout_kv_table_create();
	if (!t)
		return;

	stdout_kv_add(t, "Timestamp", "%s",
		      stdout_format_timestamp(ts->timestamp));

	row = stdout_kv_add(t, "Attributes", "%#x", ts->attr);
	shr_table_set_row_subtable(t, row,
				    stdout_timestamp_attr_table(ts->attr));

	stdout_kv_table_finish(t, "timestamp");
}

static void stdout_host_mem_buffer(struct nvme_host_mem_buf_attrs *hmb)
{
	struct shr_table *t;

	t = stdout_kv_table_create();
	if (!t)
		return;

	stdout_kv_add(t, "Host Memory Descriptor List Entry Count (HMDLEC)",
		      "%u", le32_to_cpu(hmb->hmdlec));
	stdout_kv_add(t, "Host Memory Descriptor List Address (HMDLAU)",
		      "%#x", le32_to_cpu(hmb->hmdlau));
	stdout_kv_add(t, "Host Memory Descriptor List Address (HMDLAL)",
		      "%#x", le32_to_cpu(hmb->hmdlal));
	stdout_kv_add(t, "Host Memory Buffer Size (HSIZE)", "%u",
		      le32_to_cpu(hmb->hsize));

	stdout_kv_table_finish(t, "host-mem-buffer");
}

static void stdout_directive_show_fields(__u8 dtype, __u8 doper,
					 unsigned int result, unsigned char *buf)
{
	__u8 *field = buf;
	int count, i;
	struct shr_table *t;

	switch (dtype) {
	case NVME_DIRECTIVE_DTYPE_IDENTIFY:
		switch (doper) {
		case NVME_DIRECTIVE_RECEIVE_IDENTIFY_DOPER_PARAM:
			printf("\tDirective support\n");

			t = stdout_kv_table_create();
			if (!t)
				return;

			shr_table_set_indent(t, 2);
			stdout_kv_add(t, "Identify Directive", "%s",
				      (*field & 0x1) ?
				      "supported" : "not supported");
			stdout_kv_add(t, "Stream Directive", "%s",
				      (*field & 0x2) ?
				      "supported" : "not supported");
			stdout_kv_add(t, "Data Placement Directive", "%s",
				      (*field & 0x4) ?
				      "supported" : "not supported");

			stdout_kv_table_finish(t, "directive-show");

			printf("\tDirective enabled\n");

			t = stdout_kv_table_create();
			if (!t)
				return;

			shr_table_set_indent(t, 2);
			stdout_kv_add(t, "Identify Directive", "%s",
				      (*(field + 32) & 0x1) ?
				      "enabled" : "disabled");
			stdout_kv_add(t, "Stream Directive", "%s",
				      (*(field + 32) & 0x2) ?
				      "enabled" : "disabled");
			stdout_kv_add(t, "Data Placement Directive", "%s",
				      (*(field + 32) & 0x4) ?
				      "enabled" : "disabled");

			stdout_kv_table_finish(t, "directive-show");

			printf("\tDirective Persistent Across Controller Level Resets\n");

			t = stdout_kv_table_create();
			if (!t)
				return;

			shr_table_set_indent(t, 2);
			stdout_kv_add(t, "Identify Directive", "%s",
				      (*(field + 64) & 0x1) ?
				      "enabled" : "disabled");
			stdout_kv_add(t, "Stream Directive", "%s",
				      (*(field + 64) & 0x2) ?
				      "enabled" : "disabled");
			stdout_kv_add(t, "Data Placement Directive", "%s",
				      (*(field + 64) & 0x4) ?
				      "enabled" : "disabled");

			stdout_kv_table_finish(t, "directive-show");
			break;
		default:
			fprintf(stderr,
				"invalid directive operations for Identify Directives\n");
			break;
		}
		break;
	case NVME_DIRECTIVE_DTYPE_STREAMS:
		switch (doper) {
		case NVME_DIRECTIVE_RECEIVE_STREAMS_DOPER_PARAM:
			t = stdout_kv_table_create();
			if (!t)
				return;

			stdout_kv_add(t, "Max Streams Limit (MSL)", "%u",
				      *(__u16 *)field);
			stdout_kv_add(t,
				      "NVM Subsystem Streams Available (NSSA)",
				      "%u", *(__u16 *)(field + 2));
			stdout_kv_add(t,
				      "NVM Subsystem Streams Open (NSSO)",
				      "%u", *(__u16 *)(field + 4));
			stdout_kv_add(t,
				      "NVM Subsystem Stream Capability (NSSC)",
				      "%u", *(__u16 *)(field + 6));
			stdout_kv_add(t,
				      "Stream Write Size (in unit of LB size) (SWS)",
				      "%u", *(__u32 *)(field + 16));
			stdout_kv_add(t,
				      "Stream Granularity Size (in unit of SWS) (SGS)",
				      "%u", *(__u16 *)(field + 20));
			stdout_kv_add(t,
				      "Namespace Streams Allocated (NSA)",
				      "%u", *(__u16 *)(field + 22));
			stdout_kv_add(t, "Namespace Streams Open (NSO)", "%u",
				      *(__u16 *)(field + 24));

			stdout_kv_table_finish(t, "directive-show");
			break;
		case NVME_DIRECTIVE_RECEIVE_STREAMS_DOPER_STATUS:
			count = *(__u16 *)field;

			t = stdout_kv_table_create();
			if (!t)
				return;

			stdout_kv_add(t, "Open Stream Count", "%u",
				      *(__u16 *)field);
			for (i = 0; i < count; i++) {
				char name[32];

				snprintf(name, sizeof(name),
					 "Stream Identifier %.6u", i + 1);
				stdout_kv_add(t, name, "%u",
					      *(__u16 *)(field +
							 (i + 1) * 2));
			}

			stdout_kv_table_finish(t, "directive-show");
			break;
		case NVME_DIRECTIVE_RECEIVE_STREAMS_DOPER_RESOURCE:
			t = stdout_kv_table_create();
			if (!t)
				return;

			stdout_kv_add(t, "Namespace Streams Allocated (NSA)",
				      "%u", result & 0xffff);

			stdout_kv_table_finish(t, "directive-show");
			break;
		default:
			fprintf(stderr,
				"invalid directive operations for Streams Directives\n");
			break;
		}
		break;
	default:
		fprintf(stderr, "invalid directive type\n");
		break;
	}
}

static void stdout_directive_show(__u8 type, __u8 oper, __u16 spec, __u32 nsid, __u64 result,
				  void *buf, __u32 len)
{
	printf("dir-receive: type:%#x operation:%#x spec:%#x nsid:%#x result:%#"PRIx64"\n",
		type, oper, spec, nsid, (uint64_t)result);
	if (stdout_print_ops.flags & VERBOSE)
		stdout_directive_show_fields(type, oper, result, buf);
	else if (buf)
		d(buf, len, 16, 1);
}

static void stdout_lba_status_info(__u64 result)
{
	struct shr_table *t;

	t = stdout_kv_table_create();
	if (!t)
		return;

	shr_table_set_indent(t, 1);

	stdout_kv_add(t, "LBA Status Information Poll Interval (LSIPI)",
		      "%u", (__u32)NVME_FEAT_LBAS_LSIPI(result));
	stdout_kv_add(t, "LBA Status Information Report Interval (LSIRI)",
		      "%u", (__u32)NVME_FEAT_LBAS_LSIRI(result));

	stdout_kv_table_finish(t, "lba-status-info");
}

static bool line_equal(unsigned char *buf, int len, int width, int offset)
{
	if (!offset || len < offset + width ||
	    log_level >= LIBNVME_LOG_DEBUG_VERBOSE)
		return false;

	return !memcmp(buf + offset - width, buf + offset, width);
}

void stdout_d(unsigned char *buf, int len, int width, int group)
{
	int i, offset = 0;
	char ascii[32 + 1] = { 0 };
	bool omitting = false;

	assert(width < sizeof(ascii));

	printf("     ");

	for (i = 0; i <= 15; i++)
		printf("%3x", i);

	for (i = 0; i < len; i++) {
		if (!(i % width)) {
			if (line_equal(buf, len, width, offset)) {
				if (!omitting) {
					omitting = true;
					printf("\n*");
				}
				offset += width;
				continue;
			} else if (omitting) {
				omitting = false;
			}
			printf("\n%04x:", offset);
		}
		if (omitting)
			continue;
		if (i % group)
			printf("%02x", buf[i]);
		else
			printf(" %02x", buf[i]);
		ascii[i % width] = (buf[i] >= '!' && buf[i] <= '~') ? buf[i] : '.';
		if (!((i + 1) % width)) {
			printf(" \"%.*s\"", width, ascii);
			offset += width;
			memset(ascii, 0, sizeof(ascii));
		}
	}
	if (omitting)
		printf("\n%04x:\n", offset);

	if (strlen(ascii)) {
		unsigned int b = width - (i % width);

		printf(" %*s \"%.*s\"", 2 * b + b / group + (b % group ? 1 : 0), "", width, ascii);
	}

	printf("\n");
}

static void stdout_plm_config(struct nvme_plm_config *plmcfg)
{
	struct shr_table *t;

	t = stdout_kv_table_create();
	if (!t)
		return;

	stdout_kv_add(t, "Enable Event", "%04x", le16_to_cpu(plmcfg->ee));
	stdout_kv_add(t, "DTWIN Reads Threshold", "%"PRIu64,
		      le64_to_cpu(plmcfg->dtwinrt));
	stdout_kv_add(t, "DTWIN Writes Threshold", "%"PRIu64,
		      le64_to_cpu(plmcfg->dtwinwt));
	stdout_kv_add(t, "DTWIN Time Threshold", "%"PRIu64,
		      le64_to_cpu(plmcfg->dtwintt));

	stdout_kv_table_finish(t, "plm-config");
}

static void stdout_rate_limiting_data(struct nvme_rate_limiting_data *rld)
{
	__u16 rlc = le16_to_cpu(rld->rlc);
	__u16 rlm = NVME_RATE_LIMITING_RLC_RLM(rlc);
	struct shr_table *t;

	t = stdout_kv_table_create();
	if (!t)
		return;

	stdout_kv_add(t, "Rate Limiting Enable (RLE)", "%s",
		      NVME_RATE_LIMITING_RLC_RLE(rlc) ? "Enabled" : "Disabled");
	stdout_kv_add(t, "Rate Limiting Mode (RLM)", "%u - %s", rlm,
		      rlm == NVME_RATE_LIMITING_MODE_SOFT_LIMIT ? "Soft Limit" :
		      rlm == NVME_RATE_LIMITING_MODE_HARD_LIMIT ?
		      "Hard Limit" : "Reserved");
	stdout_kv_add(t, "Bandwidth Scale Factor (BWSF)", "%u", rld->bwsf);
	stdout_kv_add(t, "Total Bandwidth Value (TBWV)", "%"PRIu64,
		      le64_to_cpu(rld->tbwv));
	stdout_kv_add(t, "Write Bandwidth Value (WBWV)", "%"PRIu64,
		      le64_to_cpu(rld->wbwv));
	stdout_kv_add(t, "Total IOPS (TIOPS)", "%u", le32_to_cpu(rld->tiops));
	stdout_kv_add(t, "Write IOPS (WIOPS)", "%u", le32_to_cpu(rld->wiops));
	stdout_kv_add(t, "Read IOPS Ratio (RIOPSR)", "%u", rld->riopsr);
	stdout_kv_add(t, "Write IOPS Ratio (WIOPSR)", "%u", rld->wiopsr);
	stdout_kv_add(t, "Read Bandwidth Ratio (RBWR)", "%u", rld->rbwr);
	stdout_kv_add(t, "Write Bandwidth Ratio (WBWR)", "%u", rld->wbwr);

	stdout_kv_table_finish(t, "rate-limiting-data");
}

static void stdout_feat_perfc_std(struct nvme_std_perf_attr *data)
{
	struct shr_table *t;

	t = stdout_kv_table_create();
	if (!t)
		return;

	stdout_kv_add(t, "random 4 kib average read latency (R4KARL)",
		      "%s (0x%02x)",
		      nvme_feature_perfc_r4karl_to_string(data->r4karl),
		      data->r4karl);

	stdout_kv_table_finish(t, "feat-perfc-std");
}

static void stdout_feat_perfc_id_list(struct nvme_perf_attr_id_list *data)
{
	int i;
	int attri_vs;
	struct shr_table *t;

	t = stdout_kv_table_create();
	if (!t)
		return;

	stdout_kv_add(t, "attribute type (ATTRTYP)", "%s (0x%02x)",
		      nvme_feature_perfc_attrtyp_to_string(data->attrtyp),
		      data->attrtyp);
	stdout_kv_add(t,
		      "maximum saveable vendor specific performance attributes (MSVSPA)",
		      "%d", data->msvspa);
	stdout_kv_add(t,
		      "unused saveable vendor specific performance attributes (USVSPA)",
		      "%d", data->usvspa);

	stdout_kv_table_finish(t, "feat-perfc-id-list");

	printf("performance attribute identifier list\n");

	t = stdout_kv_table_create();
	if (!t)
		return;

	for (i = 0; i < ARRAY_SIZE(data->id_list); i++) {
		char name[48];

		attri_vs = i + NVME_FEAT_PERFC_ATTRI_VS_MIN;
		snprintf(name, sizeof(name),
			 "performance attribute %02xh identifier (PA%02XHI)",
			 attri_vs, attri_vs);
		stdout_kv_add(t, name, "%s",
			      shr_uuid_to_string(data->id_list[i].id));
	}

	stdout_kv_table_finish(t, "feat-perfc-id-list");
}

static void stdout_feat_perfc_vs(struct nvme_vs_perf_attr *data)
{
	struct shr_table *t;

	t = stdout_kv_table_create();
	if (!t)
		return;

	stdout_kv_add(t, "performance attribute identifier (PAID)", "%s",
		      shr_uuid_to_string(data->paid));
	stdout_kv_add(t, "attribute length (ATTRL)", "%u", data->attrl);

	stdout_kv_table_finish(t, "feat-perfc-vs");

	printf("vendor specific (VS):\n");
	d((unsigned char *)data->vs, data->attrl, 16, 1);
}

static void stdout_feat_perfc(unsigned int result,
			      struct nvme_perf_characteristics *data)
{
	__u8 attri;
	bool rvspa;
	struct shr_table *t;

	nvme_feature_decode_perf_characteristics(result, &attri, &rvspa);

	t = stdout_kv_table_create();
	if (!t)
		return;

	stdout_kv_add(t, "attribute index (ATTRI)", "%s (0x%02x)",
		      nvme_feature_perfc_attri_to_string(attri), attri);

	stdout_kv_table_finish(t, "feat-perfc");

	switch (attri) {
	case NVME_FEAT_PERFC_ATTRI_STD:
		stdout_feat_perfc_std(data->std_perf);
		break;
	case NVME_FEAT_PERFC_ATTRI_ID_LIST:
		stdout_feat_perfc_id_list(data->id_list);
		break;
	case NVME_FEAT_PERFC_ATTRI_VS_MIN ... NVME_FEAT_PERFC_ATTRI_VS_MAX:
		stdout_feat_perfc_vs(data->vs_perf);
		break;
	default:
		break;
	}
}

static void stdout_host_metadata(enum nvme_features_id fid,
				 struct nvme_host_metadata *data)
{
	struct nvme_metadata_element_desc *desc = &data->descs[0];
	int i;
	char val[4096];
	__u16 len;
	struct shr_table *t;

	t = stdout_kv_table_create();
	if (!t)
		return;

	stdout_kv_add(t, "Num Metadata Element Descriptors", "%d", data->ndesc);

	stdout_kv_table_finish(t, "host-metadata");

	for (i = 0; i < data->ndesc; i++) {
		len = le16_to_cpu(desc->len);
		strncpy(val, (char *)desc->val, min(sizeof(val) - 1, len));

		printf("\tElement[%-3d]:\n", i);

		t = stdout_kv_table_create();
		if (!t)
			return;

		shr_table_set_indent(t, 2);
		stdout_kv_add(t, "Type", "%#02x (%s)", desc->type,
			      nvme_host_metadata_type_to_string(fid,
								 desc->type));
		stdout_kv_add(t, "Revision", "%d", desc->rev);
		stdout_kv_add(t, "Length", "%d", len);
		stdout_kv_add(t, "Value", "%s", val);

		stdout_kv_table_finish(t, "host-metadata");

		desc = (struct nvme_metadata_element_desc *)&desc->val[desc->len];
	}
}

static void stdout_feat_host_id(unsigned int result, unsigned char *hostid)
{
	bool exhid;
	struct shr_table *t;

	if (!hostid)
		return;

	nvme_feature_decode_host_id(result, &exhid);

	t = stdout_kv_table_create();
	if (!t)
		return;

	if (exhid)
		stdout_kv_add(t, "Host Identifier (HOSTID)", "%s",
			      uint128_t_to_l10n_string(le128_to_cpu(hostid)));
	else
		stdout_kv_add(t, "Host Identifier (HOSTID)", "%"PRIu64,
			      le64_to_cpu(*(__le64 *)hostid));

	stdout_kv_table_finish(t, "feat-host-id");
}

static void stdout_feature_show(enum nvme_features_id fid, int sel,
				unsigned int result, void *buf, __u32 data_len)
{
	printf("get-feature:%#0*x (%s), %s value:%#0*x\n", fid ? 4 : 2, fid,
	       nvme_feature_to_string(fid), nvme_select_to_string(sel), result ? 10 : 8, result);

	if (NVME_CHECK(sel, GET_FEATURES_SEL, SUPPORTED))
		stdout_select_result(fid, result);
	else if (stdout_print_ops.flags & VERBOSE)
		stdout_feature_show_fields(fid, result, buf);
	else if (buf)
		d(buf, data_len, 16, 1);
}

void stdout_feature_show_fields(enum nvme_features_id fid, unsigned int result,
				unsigned char *buf)
{
	const char *async = "Send async event";
	const char *no_async = "Do not send async event";
	struct shr_table *t;
	__u8 field;

	switch (fid) {
	case NVME_FEAT_FID_ARBITRATION:
		t = stdout_kv_table_create();
		if (!t)
			return;

		stdout_kv_add(t, "High Priority Weight (HPW)", "%u",
			      NVME_FEAT_ARB_HPW(result) + 1);
		stdout_kv_add(t, "Medium Priority Weight (MPW)", "%u",
			      NVME_FEAT_ARB_MPW(result) + 1);
		stdout_kv_add(t, "Low Priority Weight (LPW)", "%u",
			      NVME_FEAT_ARB_LPW(result) + 1);
		if (NVME_FEAT_ARB_BURST(result) == NVME_FEAT_ARBITRATION_BURST_MASK)
			stdout_kv_add(t, "Arbitration Burst (AB)", "No limit");
		else
			stdout_kv_add(t, "Arbitration Burst (AB)", "%u",
				      1 << NVME_FEAT_ARB_BURST(result));

		stdout_kv_table_finish(t, "feature-show-fields");
		break;
	case NVME_FEAT_FID_POWER_MGMT:
		t = stdout_kv_table_create();
		if (!t)
			return;

		field = NVME_FEAT_PM_WH(result);
		stdout_kv_add(t, "Workload Hint (WH)", "%u - %s", field,
			      nvme_feature_wl_hints_to_string(field));
		stdout_kv_add(t, "Power State (PS)", "%u",
			      NVME_FEAT_PM_PS(result));
		field = NVME_FEAT_PM_IIELL(result);
		if (field)
			stdout_kv_add(t, "Idle I/O Exit Latency Limit (IIELL)",
				      "%uus", field * 100);
		else
			stdout_kv_add(t, "Idle I/O Exit Latency Limit (IIELL)",
				      "disabled");

		stdout_kv_table_finish(t, "feature-show-fields");
		break;
	case NVME_FEAT_FID_LBA_RANGE:
		field = NVME_FEAT_LBAR_NR(result);

		t = stdout_kv_table_create();
		if (!t)
			return;

		stdout_kv_add(t, "Number of LBA Ranges (NUM)", "%u", field + 1);

		stdout_kv_table_finish(t, "feature-show-fields");

		if (buf)
			stdout_lba_range((struct nvme_lba_range_type *)buf, field);
		break;
	case NVME_FEAT_FID_TEMP_THRESH:
		t = stdout_kv_table_create();
		if (!t)
			return;

		field = NVME_FEAT_TT_TMPTHH(result);
		stdout_kv_add(t, "Temperature Threshold Hysteresis (TMPTHH)",
			      "%s (%u K, %s)", nvme_degrees_string(field),
			      field, nvme_degrees_fahrenheit_string(field));
		field = NVME_FEAT_TT_THSEL(result);
		stdout_kv_add(t, "Threshold Type Select (THSEL)", "%u - %s",
			      field, nvme_feature_temp_type_to_string(field));
		field = NVME_FEAT_TT_TMPSEL(result);
		stdout_kv_add(t, "Threshold Temperature Select (TMPSEL)",
			      "%u - %s", field,
			      nvme_feature_temp_sel_to_string(field));
		field = NVME_FEAT_TT_TMPTH(result);
		stdout_kv_add(t, "Temperature Threshold (TMPTH)",
			      "%s (%u K, %s)",
			      nvme_degrees_string(field), field,
			      nvme_degrees_fahrenheit_string(field));

		stdout_kv_table_finish(t, "feature-show-fields");
		break;
	case NVME_FEAT_FID_ERR_RECOVERY:
		t = stdout_kv_table_create();
		if (!t)
			return;

		stdout_kv_add(t,
			      "Deallocated or Unwritten Logical Block Error Enable (DULBE)",
			      "%s",
			      NVME_FEAT_ER_DULBE(result) ?
			      "Enabled" : "Disabled");
		stdout_kv_add(t, "Time Limited Error Recovery (TLER)", "%u ms",
			      NVME_FEAT_ER_TLER(result) * 100);

		stdout_kv_table_finish(t, "feature-show-fields");
		break;
	case NVME_FEAT_FID_VOLATILE_WC:
		t = stdout_kv_table_create();
		if (!t)
			return;

		stdout_kv_add(t, "Volatile Write Cache Enable (WCE)", "%s",
			      NVME_FEAT_VWC_WCE(result) ?
			      "Enabled" : "Disabled");

		stdout_kv_table_finish(t, "feature-show-fields");
		break;
	case NVME_FEAT_FID_NUM_QUEUES:
		t = stdout_kv_table_create();
		if (!t)
			return;

		stdout_kv_add(t,
			      "Number of IO Completion Queues Allocated (NCQA)",
			      "%u", NVME_FEAT_NRQS_NCQR(result) + 1);
		stdout_kv_add(t,
			      "Number of IO Submission Queues Allocated (NSQA)",
			      "%u", NVME_FEAT_NRQS_NSQR(result) + 1);

		stdout_kv_table_finish(t, "feature-show-fields");
		break;
	case NVME_FEAT_FID_IRQ_COALESCE:
		t = stdout_kv_table_create();
		if (!t)
			return;

		stdout_kv_add(t, "Aggregation Time (TIME)", "%u usec",
			      NVME_FEAT_IRQC_TIME(result) * 100);
		stdout_kv_add(t, "Aggregation Threshold (THR)", "%u",
			      NVME_FEAT_IRQC_THR(result) + 1);

		stdout_kv_table_finish(t, "feature-show-fields");
		break;
	case NVME_FEAT_FID_IRQ_CONFIG:
		t = stdout_kv_table_create();
		if (!t)
			return;

		stdout_kv_add(t, "Coalescing Disable (CD)", "%s",
			      NVME_FEAT_ICFG_CD(result) ? "True" : "False");
		stdout_kv_add(t, "Interrupt Vector (IV)", "%u",
			      NVME_FEAT_ICFG_IV(result));

		stdout_kv_table_finish(t, "feature-show-fields");
		break;
	case NVME_FEAT_FID_WRITE_ATOMIC:
		t = stdout_kv_table_create();
		if (!t)
			return;

		stdout_kv_add(t, "Disable Normal (DN)", "%s",
			      NVME_FEAT_WA_DN(result) ? "True" : "False");

		stdout_kv_table_finish(t, "feature-show-fields");
		break;
	case NVME_FEAT_FID_ASYNC_EVENT:
		t = stdout_kv_table_create();
		if (!t)
			return;

		stdout_kv_add(t, feat_ae_dlpcn, "%s",
			      NVME_FEAT_AE_DLPCN(result) ? async : no_async);
		stdout_kv_add(t, feat_ae_hdlpcn, "%s",
			      NVME_FEAT_AE_HDLPCN(result) ? async : no_async);
		stdout_kv_add(t, feat_ae_adlpcn, "%s",
			      NVME_FEAT_AE_ADLPCN(result) ? async : no_async);
		stdout_kv_add(t, feat_ae_pmdrlpcn, "%s",
			      NVME_FEAT_AE_PMDRLPCN(result) ? async : no_async);
		stdout_kv_add(t, feat_ae_zdcn, "%s",
			      NVME_FEAT_AE_ZDCN(result) ? async : no_async);
		stdout_kv_add(t, feat_ae_rlccn, "%s",
			      NVME_FEAT_AE_RLCCN(result) ? async : no_async);
		stdout_kv_add(t, feat_ae_lhcn, "%s",
			      NVME_FEAT_AE_LHCN(result) ? async : no_async);
		stdout_kv_add(t, feat_ae_ccrcn, "%s",
			      NVME_FEAT_AE_CCRCN(result) ? async : no_async);
		stdout_kv_add(t, feat_ae_ansan, "%s",
			      NVME_FEAT_AE_ANSAN(result) ? async : no_async);
		stdout_kv_add(t, feat_ae_rgrp0, "%s",
			      NVME_FEAT_AE_RGRP0(result) ? async : no_async);
		stdout_kv_add(t, feat_ae_rassn, "%s",
			      NVME_FEAT_AE_RASSN(result) ? async : no_async);
		stdout_kv_add(t, feat_ae_tthry, "%s",
			      NVME_FEAT_AE_TTHRY(result) ? async : no_async);
		stdout_kv_add(t, feat_ae_nnsshdn, "%s",
			      NVME_FEAT_AE_NNSSHDN(result) ? async : no_async);
		stdout_kv_add(t, feat_ae_ega, "%s",
			      NVME_FEAT_AE_EGA(result) ? async : no_async);
		stdout_kv_add(t, feat_ae_lbas, "%s",
			      NVME_FEAT_AE_LBAS(result) ? async : no_async);
		stdout_kv_add(t, feat_ae_pla, "%s",
			      NVME_FEAT_AE_PLA(result) ? async : no_async);
		stdout_kv_add(t, feat_ae_ana, "%s",
			      NVME_FEAT_AE_ANA(result) ? async : no_async);
		stdout_kv_add(t, feat_ae_telem, "%s",
			      NVME_FEAT_AE_TELEM(result) ? async : no_async);
		stdout_kv_add(t, feat_ae_fw, "%s",
			      NVME_FEAT_AE_FW(result) ? async : no_async);
		stdout_kv_add(t, feat_ae_nan, "%s",
			      NVME_FEAT_AE_NAN(result) ? async : no_async);
		stdout_kv_add(t, feat_ae_smart, "%s",
			      NVME_FEAT_AE_SMART(result) ? async : no_async);

		stdout_kv_table_finish(t, "feature-show-fields");
		break;
	case NVME_FEAT_FID_AUTO_PST:
		t = stdout_kv_table_create();
		if (!t)
			return;

		stdout_kv_add(t,
			      "Autonomous Power State Transition Enable (APSTE)",
			      "%s",
			      NVME_FEAT_APST_APSTE(result) ?
			      "Enabled" : "Disabled");

		stdout_kv_table_finish(t, "feature-show-fields");

		if (buf)
			stdout_auto_pst((struct nvme_feat_auto_pst *)buf);
		break;
	case NVME_FEAT_FID_HOST_MEM_BUF:
		t = stdout_kv_table_create();
		if (!t)
			return;

		stdout_kv_add(t, "Enable Host Memory (EHM)", "%s",
			      NVME_FEAT_HMEM_EHM(result) ?
			      "Enabled" : "Disabled");
		stdout_kv_add(t,
			      "Host Memory Non-operational Access Restriction Enable (HMNARE)",
			      "%s", (result & 0x00000004) ? "True" : "False");
		stdout_kv_add(t,
			      "Host Memory Non-operational Access Restricted (HMNAR)",
			      "%s", (result & 0x00000008) ? "True" : "False");

		stdout_kv_table_finish(t, "feature-show-fields");

		if (buf)
			stdout_host_mem_buffer((struct nvme_host_mem_buf_attrs *)buf);
		break;
	case NVME_FEAT_FID_TIMESTAMP:
		if (buf)
			stdout_timestamp((struct nvme_timestamp *)buf);
		break;
	case NVME_FEAT_FID_KATO:
		t = stdout_kv_table_create();
		if (!t)
			return;

		stdout_kv_add(t, "Keep Alive Timeout (KATO) in milliseconds",
			      "%u", result);

		stdout_kv_table_finish(t, "feature-show-fields");
		break;
	case NVME_FEAT_FID_HCTM:
		t = stdout_kv_table_create();
		if (!t)
			return;

		field = NVME_FEAT_HCTM_TMT1(result);
		stdout_kv_add(t, "Thermal Management Temperature 1 (TMT1)",
			      "%u K (%s, %s)", field,
			      nvme_degrees_string(field),
			      nvme_degrees_fahrenheit_string(field));
		field = NVME_FEAT_HCTM_TMT2(result);
		stdout_kv_add(t, "Thermal Management Temperature 2 (TMT2)",
			      "%u K (%s, %s)", field,
			      nvme_degrees_string(field),
			      nvme_degrees_fahrenheit_string(field));

		stdout_kv_table_finish(t, "feature-show-fields");
		break;
	case NVME_FEAT_FID_NOPSC:
		t = stdout_kv_table_create();
		if (!t)
			return;

		stdout_kv_add(t,
			      "Non-Operational Power State Permissive Mode Enable (NOPPME)",
			      "%s",
			      NVME_FEAT_NOPS_NOPPME(result) ? "True" : "False");

		stdout_kv_table_finish(t, "feature-show-fields");
		break;
	case NVME_FEAT_FID_RRL:
		t = stdout_kv_table_create();
		if (!t)
			return;

		stdout_kv_add(t, "Read Recovery Level (RRL)", "%u",
			      NVME_FEAT_RRL_RRL(result));

		stdout_kv_table_finish(t, "feature-show-fields");
		break;
	case NVME_FEAT_FID_PLM_CONFIG:
		t = stdout_kv_table_create();
		if (!t)
			return;

		stdout_kv_add(t, "Predictable Latency Window Enabled", "%s",
			      NVME_FEAT_PLM_LPE(result) ? "True" : "False");

		stdout_kv_table_finish(t, "feature-show-fields");

		if (buf)
			stdout_plm_config((struct nvme_plm_config *)buf);
		break;
	case NVME_FEAT_FID_PLM_WINDOW:
		t = stdout_kv_table_create();
		if (!t)
			return;

		stdout_kv_add(t, "Window Select", "%s",
			      nvme_plm_window_to_string(result));

		stdout_kv_table_finish(t, "feature-show-fields");
		break;
	case NVME_FEAT_FID_LBA_STS_INTERVAL:
		stdout_lba_status_info(result);
		break;
	case NVME_FEAT_FID_HOST_BEHAVIOR:
		if (buf) {
			struct nvme_feat_host_behavior *hb =
				(struct nvme_feat_host_behavior *)buf;

			t = stdout_kv_table_create();
			if (!t)
				return;

			stdout_kv_add(t, "Advanced Command Retry Enable (ACRE)",
				      "%s", hb->acre ? "True" : "False");
			stdout_kv_add(t,
				      "Extended Telemetry Data Area 4 Supported (ETDAS)",
				      "%s", hb->etdas ? "True" : "False");
			stdout_kv_add(t, "LBA Format Extension Enable (LBAFEE)",
				      "%s", hb->lbafee ? "True" : "False");
			stdout_kv_add(t,
				      "Host Dispersed Namespace Support (HDISNS)",
				      "%s",
				      hb->hdisns ? "Enabled" : "Disabled");
			stdout_kv_add(t,
				      "Copy Descriptor Format 2h Enabled (CDF2E)",
				      "%s",
				      hb->cdfe & (1 << 2) ? "True" : "False");
			stdout_kv_add(t,
				      "Copy Descriptor Format 3h Enabled (CDF3E)",
				      "%s",
				      hb->cdfe & (1 << 3) ? "True" : "False");
			stdout_kv_add(t,
				      "Copy Descriptor Format 4h Enabled (CDF4E)",
				      "%s",
				      hb->cdfe & (1 << 4) ? "True" : "False");

			stdout_kv_table_finish(t, "feature-show-fields");
		}
		break;
	case NVME_FEAT_FID_SANITIZE:
		t = stdout_kv_table_create();
		if (!t)
			return;

		stdout_kv_add(t, "No-Deallocate Response Mode (NODRM)", "%u",
			      NVME_FEAT_SC_NODRM(result));

		stdout_kv_table_finish(t, "feature-show-fields");
		break;
	case NVME_FEAT_FID_ENDURANCE_EVT_CFG:
		t = stdout_kv_table_create();
		if (!t)
			return;

		stdout_kv_add(t, "Endurance Group Identifier (ENDGID)", "%u",
			      NVME_FEAT_EG_ENDGID(result));
		stdout_kv_add(t, "Endurance Group Critical Warnings", "%u",
			      NVME_FEAT_EG_EGCW(result));

		stdout_kv_table_finish(t, "feature-show-fields");
		break;
	case NVME_FEAT_FID_IOCS_PROFILE:
		t = stdout_kv_table_create();
		if (!t)
			return;

		stdout_kv_add(t, "I/O Command Set Profile", "%s",
			      result & 0x1 ? "True" : "False");

		stdout_kv_table_finish(t, "feature-show-fields");
		break;
	case NVME_FEAT_FID_SPINUP_CONTROL:
		t = stdout_kv_table_create();
		if (!t)
			return;

		stdout_kv_add(t, "Spinup control feature Enabled", "%s",
			      (result & 1) ? "True" : "False");

		stdout_kv_table_finish(t, "feature-show-fields");
		break;
	case NVME_FEAT_FID_POWER_LOSS_SIGNAL:
		t = stdout_kv_table_create();
		if (!t)
			return;

		stdout_kv_add(t, "Power Loss Signaling Mode (PLSM)", "%s",
			      nvme_pls_mode_to_string(
					NVME_GET(result, FEAT_PLS_MODE)));

		stdout_kv_table_finish(t, "feature-show-fields");
		break;
	case NVME_FEAT_FID_PERF_CHARACTERISTICS:
		stdout_feat_perfc(result,
				  (struct nvme_perf_characteristics *)buf);
		break;
	case NVME_FEAT_FID_ENH_CTRL_METADATA:
	case NVME_FEAT_FID_CTRL_METADATA:
	case NVME_FEAT_FID_NS_METADATA:
		if (buf)
			stdout_host_metadata(fid, (struct nvme_host_metadata *)buf);
		break;
	case NVME_FEAT_FID_SW_PROGRESS:
		t = stdout_kv_table_create();
		if (!t)
			return;

		stdout_kv_add(t, "Pre-boot Software Load Count (PBSLC)", "%u",
			      NVME_FEAT_SPM_PBSLC(result));

		stdout_kv_table_finish(t, "feature-show-fields");
		break;
	case NVME_FEAT_FID_HOST_ID:
		stdout_feat_host_id(result, buf);
		break;
	case NVME_FEAT_FID_RESV_NF_MASK:
		t = stdout_kv_table_create();
		if (!t)
			return;

		stdout_kv_add(t,
			      "Mask Reservation Preempted Notification (RESPRE)",
			      "%s",
			      NVME_FEAT_RM_RESPRE(result) ? "True" : "False");
		stdout_kv_add(t,
			      "Mask Reservation Released Notification (RESREL)",
			      "%s",
			      NVME_FEAT_RM_RESREL(result) ? "True" : "False");
		stdout_kv_add(t,
			      "Mask Registration Preempted Notification (REGPRE)",
			      "%s",
			      NVME_FEAT_RM_REGPRE(result) ? "True" : "False");

		stdout_kv_table_finish(t, "feature-show-fields");
		break;
	case NVME_FEAT_FID_RESV_PERSIST:
		t = stdout_kv_table_create();
		if (!t)
			return;

		stdout_kv_add(t, "Persist Through Power Loss (PTPL)", "%s",
			      NVME_FEAT_RP_PTPL(result) ? "True" : "False");

		stdout_kv_table_finish(t, "feature-show-fields");
		break;
	case NVME_FEAT_FID_WRITE_PROTECT:
		t = stdout_kv_table_create();
		if (!t)
			return;

		stdout_kv_add(t, "Namespace Write Protect", "%s",
			      nvme_ns_wp_cfg_to_string(result));

		stdout_kv_table_finish(t, "feature-show-fields");
		break;
	case NVME_FEAT_FID_FDP:
		t = stdout_kv_table_create();
		if (!t)
			return;

		stdout_kv_add(t, "Flexible Direct Placement Enable (FDPE)",
			      "%s", NVME_FEAT_FDPE(result) ? "Yes" : "No");
		stdout_kv_add(t,
			      "Flexible Direct Placement Configuration Index",
			      "%u", NVME_FEAT_FDPCIDX(result));

		stdout_kv_table_finish(t, "feature-show-fields");
		break;
	case NVME_FEAT_FID_FDP_EVENTS:
		t = stdout_kv_table_create();
		if (!t)
			return;

		for (unsigned int i = 0; i < result; i++) {
			struct nvme_fdp_supported_event_desc *d;

			d = &((struct nvme_fdp_supported_event_desc *)buf)[i];

			stdout_kv_add(t, nvme_fdp_event_to_string(d->evt),
				      "%sEnabled", d->evta & 0x1 ? "" : "Not ");
		}

		stdout_kv_table_finish(t, "feature-show-fields");
		break;
	case NVME_FEAT_FID_BP_WRITE_PROTECT:
		t = stdout_kv_table_create();
		if (!t)
			return;

		field = NVME_FEAT_BPWPC_BP1WPS(result);
		stdout_kv_add(t,
			      "Boot Partition 1 Write Protection State (BP1WPS)",
			      "%s", nvme_bpwps_to_string(field));
		field = NVME_FEAT_BPWPC_BP0WPS(result);
		stdout_kv_add(t,
			      "Boot Partition 0 Write Protection State (BP0WPS)",
			      "%s", nvme_bpwps_to_string(field));

		stdout_kv_table_finish(t, "feature-show-fields");
		break;
	case NVME_FEAT_FID_POWER_LIMIT: {
		__cleanup_free char *power_str = NULL;

		t = stdout_kv_table_create();
		if (!t)
			return;

		field = NVME_FEAT_POWER_LIMIT_PLS(result);
		power_str = stdout_power_and_scale_str(
				NVME_FEAT_POWER_LIMIT_PLV(result), field);
		stdout_kv_add(t, "Power Limit Scale (PLS)", "%u - %s", field,
			      nvme_feature_power_limit_scale_to_string(field));
		stdout_kv_add(t, "Power Limit Value (PLV)", "%u",
			      NVME_FEAT_POWER_LIMIT_PLV(result));
		stdout_kv_add(t, "Power Limit", "%s", power_str);

		stdout_kv_table_finish(t, "feature-show-fields");
		break;
	}
	case NVME_FEAT_FID_POWER_THRESH: {
		__cleanup_free char *power_str = NULL;

		t = stdout_kv_table_create();
		if (!t)
			return;

		field = NVME_FEAT_POWER_THRESH_EPT(result);
		stdout_kv_add(t, "Enable Power Threshold (EPT)", "%u - %s",
			      field, field ? "Enabled" : "Disabled");
		field = NVME_FEAT_POWER_THRESH_PMTS(result);
		stdout_kv_add(t, "Power Measurement Type Select (PMTS)",
			      "%u - %s", field,
			      nvme_power_measurement_type_to_string(field));
		field = NVME_FEAT_POWER_THRESH_PTS(result);
		power_str = stdout_power_and_scale_str(
				NVME_FEAT_POWER_THRESH_PTV(result), field);
		stdout_kv_add(t, "Power Threshold Scale (PTS)", "%u - %s",
			      field,
			      nvme_feature_power_limit_scale_to_string(field));
		stdout_kv_add(t, "Power Threshold Value (PTV)", "%u",
			      NVME_FEAT_POWER_THRESH_PTV(result));
		stdout_kv_add(t, "Power Threshold", "%s", power_str);

		stdout_kv_table_finish(t, "feature-show-fields");
		break;
	}
	case NVME_FEAT_FID_POWER_MEASUREMENT:
		t = stdout_kv_table_create();
		if (!t)
			return;

		field = NVME_FEAT_POWER_MEAS_ACT(result);
		stdout_kv_add(t, "Action (ACT)", "%u - %s", field,
			      nvme_power_measurement_action_to_string(field));
		field = NVME_FEAT_POWER_MEAS_PMTS(result);
		stdout_kv_add(t, "Power Measurement Type Select (PMTS)",
			      "%u - %s", field,
			      nvme_power_measurement_type_to_string(field));
		stdout_kv_add(t, "Stop Measurement Time (SMT)", "%u",
			      NVME_FEAT_POWER_MEAS_SMT(result));

		stdout_kv_table_finish(t, "feature-show-fields");
		break;
	case NVME_FEAT_FID_VOLTAGE_THRESHOLD:
		t = stdout_kv_table_create();
		if (!t)
			return;

		field = NVME_FEAT_VOLTAGE_THRESHOLD_VSENS(result);
		stdout_kv_add(t, "Voltage Sensor Select (VSENS)", "%u", field);
		stdout_kv_add(t, "Enable Voltage Threshold (EVT)", "%u - %s",
			      !!(result & NVME_FEAT_VOLTAGE_THRESHOLD_EVT),
			      result & NVME_FEAT_VOLTAGE_THRESHOLD_EVT ?
			      "Enabled" : "Disabled");
		stdout_kv_add(t, "Overvoltage Threshold (OVT)", "%u",
			      NVME_FEAT_VOLTAGE_THRESHOLD_OVT(result));
		stdout_kv_add(t, "Undervoltage Threshold (UVT)", "%u",
			      NVME_FEAT_VOLTAGE_THRESHOLD_UVT(result));

		stdout_kv_table_finish(t, "feature-show-fields");
		break;
	case NVME_FEAT_FID_VOLTAGE_MEASUREMENT:
		t = stdout_kv_table_create();
		if (!t)
			return;

		field = NVME_FEAT_VOLTAGE_MEASUREMENT_ACT(result);
		stdout_kv_add(t, "Action (ACT)", "%u", field);

		stdout_kv_table_finish(t, "feature-show-fields");
		break;
	case NVME_FEAT_FID_RATE_LIMITING:
		if (buf)
			stdout_rate_limiting_data((struct nvme_rate_limiting_data *)buf);
		break;
	default:
		break;
	}
}

static void stdout_lba_status(struct nvme_lba_status *list,
			      unsigned long len)
{
	struct shr_table_column columns[] = {
		{ "DSLBA",  LEFT, AUTO_WIDTH },
		{ "NLB",    LEFT, AUTO_WIDTH },
		{ "Status", LEFT, AUTO_WIDTH },
	};
	struct shr_table *t;
	__u32 nlsd = le32_to_cpu(list->nlsd);
	int idx, row;

	t = stdout_kv_table_create();
	if (!t)
		return;

	stdout_kv_add(t, "Number of LBA Status Descriptors(NLSD)", "%"PRIu32,
		      nlsd);
	stdout_kv_add(t, "Completion Condition(CMPC)", "%u", list->cmpc);

	stdout_kv_table_finish(t, "lba-status");

	switch (list->cmpc) {
	case NVME_LBA_STATUS_CMPC_NO_CMPC:
		printf("\tNo indication of the completion condition\n");
		break;
	case NVME_LBA_STATUS_CMPC_INCOMPLETE:
		printf("\tCompleted transferring the amount of data specified in the\n"\
			"\tMNDW field. But, additional LBA Status Descriptor Entries are\n"\
			"\tavailable to transfer or scan did not complete (if ATYPE = 10h)\n");
		break;
	case NVME_LBA_STATUS_CMPC_COMPLETE:
		printf("\tCompleted the specified action over the number of LBAs specified\n"\
			"\tin the Range Length field and transferred all available LBA Status\n"\
			"\tDescriptor Entries\n");
		break;
	default:
		break;
	}

	if (!nlsd)
		return;

	t = shr_table_init_with_columns(columns, ARRAY_SIZE(columns));
	if (!t)
		return;

	for (idx = 0; idx < nlsd; idx++) {
		struct nvme_lba_status_desc *e = &list->descs[idx];
		char dslba[24], nlb[16], status[8];

		snprintf(dslba, sizeof(dslba), "%#016"PRIx64,
			 le64_to_cpu(e->dslba));
		snprintf(nlb, sizeof(nlb), "%#08x", le32_to_cpu(e->nlb));
		snprintf(status, sizeof(status), "%#02x", e->status);

		row = shr_table_get_row_id(t);
		shr_table_set_value_str(t, 0, row, dslba, LEFT);
		shr_table_set_value_str(t, 1, row, nlb, LEFT);
		shr_table_set_value_str(t, 2, row, status, LEFT);
		shr_table_add_row(t, row);
	}

	shr_table_print(t);
	shr_table_free(t);
}

static void stdout_dev_full_path(struct libnvme_ns *n, char *path, size_t len)
{
	struct stat st;

	snprintf(path, len, "%s", libnvme_ns_get_name(n));
	if (strncmp(path, "/dev/spdk/", 10) == 0 && stat(path, &st) == 0)
		return;

	snprintf(path, len, "/dev/%s", libnvme_ns_get_name(n));
	if (stat(path, &st) == 0)
		return;

	/*
	 * We could start trying to search for it but let's make
	 * it simple and just don't show the path at all.
	 */
	snprintf(path, len, "%s", libnvme_ns_get_name(n));
}

static void stdout_generic_full_path(struct libnvme_ns *n, char *path, size_t len)
{
	int head_instance;
	int instance;
	struct stat st;

	/*
	 * There is no block devices for SPDK, point generic path to existing
	 * chardevice.
	 */
	snprintf(path, len, "%s", libnvme_ns_get_name(n));
	if (strncmp(path, "/dev/spdk/", 10) == 0 && stat(path, &st) == 0)
		return;

	if (sscanf(libnvme_ns_get_name(n), "nvme%dn%d", &instance, &head_instance) != 2)
		return;

	snprintf(path, len, "/dev/ng%dn%d", instance, head_instance);

	if (stat(path, &st) == 0)
		return;

	/*
	 * We could start trying to search for it but let's make
	 * it simple and just don't show the path at all.
	 */
	snprintf(path, len, "%s", libnvme_ns_get_generic_name(n));
}

static void list_item(struct libnvme_ns *n, struct shr_table *t)
{
	char usage[128] = { 0 }, format[128] = { 0 };
	char devname[128] = { 0 }; char genname[128] = { 0 };
	int lba_size, meta_size;
	uint64_t lba_count, lba_util;
	long long lba;
	double nsze, nuse;
	const char *s_suffix, *u_suffix, *l_suffix;
	char ns[STR_LEN];
	int row;

	libnvme_ns_get_lba_size(n, &lba_size, 0);
	libnvme_ns_get_lba_count(n, &lba_count, 0);
	libnvme_ns_get_lba_util(n, &lba_util, 0);
	libnvme_ns_get_meta_size(n, &meta_size, 0);

	lba = lba_size;
	nsze = lba_count * lba;
	nuse = lba_util * lba;

	s_suffix = shr_suffix_si_get(&nsze);
	u_suffix = shr_suffix_si_get(&nuse);
	l_suffix = shr_suffix_binary_get(&lba);

	snprintf(usage, sizeof(usage), "%6.2f %2sB / %6.2f %2sB", nuse,
		u_suffix, nsze, s_suffix);
	snprintf(format, sizeof(format), "%3.0f %2sB + %2d B", (double)lba,
		l_suffix, meta_size);

	stdout_dev_full_path(n, devname, sizeof(devname));
	stdout_generic_full_path(n, genname, sizeof(genname));

	row = shr_table_get_row_id(t);
	if (row < 0) {
		printf("Failed to add row\n");
		return;
	}
	if (shr_table_set_value_str(t, SIMPLE_LIST_COL_NODE, row, devname, LEFT)) {
		printf("Failed to set node value\n");
		return;
	}
	if (shr_table_set_value_str(t, SIMPLE_LIST_COL_GENERIC, row, genname, LEFT)) {
		printf("Failed to set generic value\n");
		return;
	}
	if (shr_table_set_value_str(t, SIMPLE_LIST_COL_SN, row, libnvme_ns_get_serial(n), LEFT)) {
		printf("Failed to set sn value\n");
		return;
	}
	if (shr_table_set_value_str(t, SIMPLE_LIST_COL_MODEL, row, libnvme_ns_get_model(n), LEFT)) {
		printf("Failed to set model value\n");
		return;
	}
	if (!sprintf(ns, "0x%x", libnvme_ns_get_nsid(n))) {
		printf("Failed to output ns string\n");
		return;
	}
	if (shr_table_set_value_str(t, SIMPLE_LIST_COL_NS, row, ns, LEFT)) {
		printf("Failed to set ns value\n");
		return;
	}
	if (shr_table_set_value_str(t, SIMPLE_LIST_COL_USAGE, row, usage, LEFT)) {
		printf("Failed to set usage value\n");
		return;
	}
	if (shr_table_set_value_str(t, SIMPLE_LIST_COL_FORMAT, row, format, LEFT)) {
		printf("Failed to set format value\n");
		return;
	}
	if (shr_table_set_value_str(t, SIMPLE_LIST_COL_FW_REV, row, libnvme_ns_get_firmware(n), LEFT)) {
		printf("Failed to set fw rev value\n");
		return;
	}
	shr_table_add_row(t, row);
}

static void stdout_list_item(struct libnvme_ns *n, struct shr_table *t)
{
	list_item(n, t);
}

static void stdout_list_item_table(struct libnvme_ns *n, struct shr_table *t)
{
	list_item(n, t);
}

static bool stdout_simple_ns(const char *name, void *arg)
{
	struct nvme_resources_table *rst_t = arg;
	struct nvme_resources *res = rst_t->res;
	struct libnvme_ns *n;

	n = htable_ns_get(&res->ht_n, name);
	stdout_list_item_table(n, rst_t->t);

	return true;
}

static void stdout_simple_list(struct libnvme_global_ctx *ctx)
{
	struct nvme_resources res;
	struct shr_table_column columns[] = {
		{ "Node", LEFT, 21 },
		{ "Generic", LEFT, 21 },
		{ "SN", LEFT, 20 },
		{ "Model", LEFT, 40 },
		{ "Namespace", LEFT, 10 },
		{ "Usage", LEFT, 26 },
		{ "Format", LEFT, 16 },
		{ "FW Rev", LEFT, 8 },
	};
	struct shr_table *t = shr_table_init_with_columns(columns, ARRAY_SIZE(columns));
	struct nvme_resources_table res_t = { &res, t };

	if (!t) {
		printf("Failed to init table\n");
		return;
	}

	nvme_resources_init(ctx, &res);

	strset_iterate_sorted(&res.namespaces, stdout_simple_ns, &res_t);

	shr_table_print(t);

	nvme_resources_free(&res);
	shr_table_free(t);
}

static void stdout_ns_details(struct libnvme_ns *n)
{
	char usage[128] = { 0 }, format[128] = { 0 }, usage_binary[128] = { 0 };
	char devname[128] = { 0 }, genname[128] = { 0 };
	int lba_size, meta_size;
	uint64_t lba_count, lba_util;
	long long lba;
	double nsze, nuse;
	double nsze_binary, nuse_binary;
	const char *s_suffix, *u_suffix, *l_suffix;
	const char *s_suffix_binary, *u_suffix_binary;

	libnvme_ns_get_lba_size(n, &lba_size, 0);
	libnvme_ns_get_lba_count(n, &lba_count, 0);
	libnvme_ns_get_lba_util(n, &lba_util, 0);
	libnvme_ns_get_meta_size(n, &meta_size, 0);

	lba = lba_size;
	nsze = lba_count * lba;
	nuse = lba_util * lba;
	nsze_binary = nsze;
	nuse_binary = nuse;

	s_suffix = shr_suffix_si_get(&nsze);
	u_suffix = shr_suffix_si_get(&nuse);
	l_suffix = shr_suffix_binary_get(&lba);

	sprintf(usage, "%6.2f %1sB / %6.2f %1sB", nuse, u_suffix, nsze, s_suffix);
	sprintf(format, "%3.0f %2sB + %2d B", (double)lba, l_suffix, meta_size);

	s_suffix_binary = shr_suffix_dbinary_get(&nsze_binary);
	u_suffix_binary = shr_suffix_dbinary_get(&nuse_binary);
	sprintf(usage_binary, "(%7.2f %2sB / %7.2f %2sB)", nuse_binary, u_suffix_binary,
		nsze_binary, s_suffix_binary);

	nvme_dev_full_path(n, devname, sizeof(devname));
	nvme_generic_full_path(n, genname, sizeof(genname));

	printf("%-17s %-20s %#-10x %-21s %-25s %-16s ", devname,
		genname, libnvme_ns_get_nsid(n), usage, usage_binary, format);
}

static bool stdout_detailed_name(const char *name, void *arg)
{
	bool *first = arg;

	printf("%s%s", *first ? "" : ", ", name);
	*first = false;

	return true;
}

static bool stdout_detailed_subsys(const char *name, void *arg)
{
	struct nvme_resources *res = arg;
	struct htable_subsys_iter it;
	struct strset ctrls;
	struct libnvme_subsystem *s;
	struct libnvme_ctrl *c;
	bool first;

	strset_init(&ctrls);
	first = true;
	for (s = htable_subsys_getfirst(&res->ht_s, name, &it);
	     s;
	     s = htable_subsys_getnext(&res->ht_s, name, &it)) {
		if (first) {
			printf("%-16s %-96s ", name,
			       libnvme_subsystem_get_subsysnqn(s));
			first = false;
		}

		libnvme_subsystem_for_each_ctrl(s, c)
			strset_add(&ctrls, libnvme_ctrl_get_name(c));
	}

	first = true;
	strset_iterate_sorted(&ctrls, stdout_detailed_name, &first);
	strset_clear(&ctrls);
	printf("\n");

	return true;
}

static bool stdout_detailed_ctrl(const char *name, void *arg)
{
	struct nvme_resources *res = arg;
	struct strset namespaces;
	struct libnvme_ctrl *c;
	struct libnvme_path *p;
	struct libnvme_ns *n;
	bool first;

	c = htable_ctrl_get(&res->ht_c, name);
	assert(c);

	{
		const char *tr = libnvme_ctrl_get_transport(c);
		__cleanup_free char *reg_owner = libnvme_ctrl_owner(c);
		const char *slot;
		const char *cntlid;
		const char *serial;
		const char *model;
		const char *firmware;
		const char *owner_str;

		libnvme_ctrl_get_phy_slot(c, &slot, NULL);
		libnvme_ctrl_get_cntlid(c, &cntlid, "");
		libnvme_ctrl_get_serial(c, &serial, "");
		libnvme_ctrl_get_model(c, &model, "");
		libnvme_ctrl_get_firmware(c, &firmware, "");

		if (!libnvme_ctrl_is_transport_fabric(c))
			owner_str = "kernel";
		else
			owner_str = reg_owner ? reg_owner : "-";

		printf("%-16s %-12s %-6s %-20s %-40s %-8s %-6s %-14s %-6s %-12s ",
		       libnvme_ctrl_get_name(c),
		       owner_str,
		       cntlid,
		       serial,
		       model,
		       firmware,
		       tr,
		       libnvme_ctrl_get_address(c),
		       slot ? slot : "",
		       libnvme_subsystem_get_name(libnvme_ctrl_get_subsystem(c)));
	}

	strset_init(&namespaces);

	libnvme_ctrl_for_each_ns(c, n)
		strset_add(&namespaces, libnvme_ns_get_name(n));
	libnvme_ctrl_for_each_path(c, p) {
		n = libnvme_path_get_ns(p);
		if (!n)
			continue;
		strset_add(&namespaces, libnvme_ns_get_name(n));
	}

	first = true;
	strset_iterate_sorted(&namespaces, stdout_detailed_name, &first);
	strset_clear(&namespaces);

	printf("\n");

	return true;
}

static bool stdout_detailed_ns(const char *name, void *arg)
{
	struct nvme_resources *res = arg;
	struct htable_ns_iter it;
	struct strset ctrls;
	struct libnvme_ctrl *c;
	struct libnvme_path *p;
	struct libnvme_ns *n;
	bool first;

	strset_init(&ctrls);
	first = true;
	for (n = htable_ns_getfirst(&res->ht_n, name, &it);
	     n;
	     n = htable_ns_getnext(&res->ht_n, name, &it)) {
		if (first) {
			stdout_ns_details(n);
			first = false;
		}

		if (libnvme_ns_get_ctrl(n)) {
			printf("%s\n", libnvme_ctrl_get_name(libnvme_ns_get_ctrl(n)));
			return true;
		}

		libnvme_namespace_for_each_path(n, p) {
			c = libnvme_path_get_ctrl(p);
			strset_add(&ctrls, libnvme_ctrl_get_name(c));
		}
	}

	first = true;
	strset_iterate_sorted(&ctrls, stdout_detailed_name, &first);
	strset_clear(&ctrls);

	printf("\n");
	return true;
}

static void stdout_detailed_list(struct libnvme_global_ctx *ctx)
{
	struct nvme_resources res;

	nvme_resources_init(ctx, &res);

	printf("%-16s %-96s %-.16s\n", "Subsystem", "Subsystem-NQN", "Controllers");
	printf("%-.16s %-.96s %-.16s\n", dash, dash, dash);
	strset_iterate_sorted(&res.subsystems, stdout_detailed_subsys, &res);
	printf("\n");

	printf("%-16s %-12s %-6s %-20s %-40s %-8s %-6s %-14s %-6s %-12s %-16s\n",
		"Device", "Orchestrator", "Cntlid", "SN", "MN", "FR", "TxPort",
		"Address", "Slot", "Subsystem", "Namespaces");
	printf("%-.16s %-.12s %-.6s %-.20s %-.40s %-.8s %-.6s %-.14s %-.6s %-.12s %-.16s\n",
		dash, dash, dash, dash, dash, dash, dash, dash, dash, dash, dash);
	strset_iterate_sorted(&res.ctrls, stdout_detailed_ctrl, &res);
	printf("\n");

	printf("%-17s %-20s %-10s %-49s %-16s %-16s\n", "Device", "Generic",
		"NSID", "Usage", "Format", "Controllers");
	printf("%-.17s %-.20s %-.10s %-.49s %-.16s %-.16s\n", dash, dash, dash,
		dash, dash, dash);
	strset_iterate_sorted(&res.namespaces, stdout_detailed_ns, &res);

	nvme_resources_free(&res);
}

static void stdout_list_items(struct libnvme_global_ctx *ctx)
{
	if (stdout_print_ops.flags & VERBOSE)
		stdout_detailed_list(ctx);
	else
		stdout_simple_list(ctx);
}

static int subsystem_topology_multipath_add_row(struct shr_table *t,
		const char *iopolicy, const char *nshead,
		const char *nsid, const char *nspath,
		const char *anastate, const char *iopolicy_info,
		const char *ctrl, const char *trtype,
		const char *address, const char *state)
{
	int row;
	int col = -1;

	row = shr_table_get_row_id(t);
	if (row < 0) {
		nvme_show_error("Failed to add subsys topology multipath row");
		return row;
	}

	shr_table_set_value_str(t, ++col, row, nshead, CENTERED);
	shr_table_set_value_str(t, ++col, row, nsid, CENTERED);
	shr_table_set_value_str(t, ++col, row, nspath, CENTERED);
	shr_table_set_value_str(t, ++col, row, anastate, CENTERED);
	if (!strcmp(iopolicy, "numa") || !strcmp(iopolicy, "queue-depth"))
		shr_table_set_value_str(t, ++col, row, iopolicy_info, CENTERED);
	shr_table_set_value_str(t, ++col, row, ctrl, CENTERED);
	shr_table_set_value_str(t, ++col, row, trtype, CENTERED);
	shr_table_set_value_str(t, ++col, row, address, CENTERED);
	shr_table_set_value_str(t, ++col, row, state, CENTERED);

	shr_table_add_row(t, row);

	return 0;
}

static void stdout_tabular_subsystem_topology_multipath(struct libnvme_subsystem *s)
{
	struct libnvme_ns *n;
	struct libnvme_path *p;
	struct libnvme_ctrl *c;
	bool first;
	char nshead[32], nsid[32];
	char iopolicy_info[256];
	int ret, num_path;
	struct shr_table *t;
	const char *iopolicy;
	struct shr_table_column columns[] = {
		{"NSHead",     LEFT, AUTO_WIDTH},
		{"NSID",       LEFT, AUTO_WIDTH},
		{"NSPath",     LEFT, AUTO_WIDTH},
		{"ANAState",   LEFT, AUTO_WIDTH},
		{"Nodes",      LEFT, AUTO_WIDTH},
		{"Qdepth",     LEFT, AUTO_WIDTH},
		{"Controller", LEFT, AUTO_WIDTH},
		{"TrType",     LEFT, AUTO_WIDTH},
		{"Address",    LEFT, AUTO_WIDTH},
		{"State",      LEFT, AUTO_WIDTH},
	};

	t = shr_table_create();
	if (!t) {
		nvme_show_error("Failed to init subsys topology multipath table");
		return;
	}

	if (shr_table_add_columns_filter(t, columns, ARRAY_SIZE(columns),
			subsystem_iopolicy_filter, (void *)s) < 0) {
		nvme_show_error("Failed to add subsys topology multipath columns");
		goto free_tbl;
	}

	libnvme_subsystem_get_iopolicy(s, &iopolicy, "");

	libnvme_subsystem_for_each_ns(s, n) {
		first = true;
		libnvme_namespace_for_each_path(n, p) {
			const char *ana_state;
			int queue_depth;
			const char *numa_nodes;

			c = libnvme_path_get_ctrl(p);
			libnvme_path_get_ana_state(p, &ana_state, "");

			/*
			 * For the first row we print actual NSHead name,
			 * however, for the subsequent rows we print "arrow"
			 * ("-->") symbol for NSHead. This "arrow" style makes
			 * it visually obvious that susequenet entries (if
			 * present) are a path under the first NSHead.
			 */
			if (first) {
				snprintf(nshead, sizeof(nshead), "%s",
						libnvme_ns_get_name(n));
				first = false;
			} else
				snprintf(nshead, sizeof(nshead), "%s", "-->");

			snprintf(nsid, sizeof(nsid), "%u", libnvme_ns_get_nsid(n));

			if (!strcmp(iopolicy, "numa")) {
				libnvme_path_get_numa_nodes(p, &numa_nodes, "");
				snprintf(iopolicy_info, sizeof(iopolicy_info),
					"%s", numa_nodes);
			} else if (!strcmp(iopolicy, "queue-depth")) {
				libnvme_path_get_queue_depth(p, &queue_depth,
							      0);
				snprintf(iopolicy_info, sizeof(iopolicy_info),
					"%d", queue_depth);
			} else {
				snprintf(iopolicy_info, sizeof(iopolicy_info), "--");
			}

			ret = subsystem_topology_multipath_add_row(t,
						    iopolicy,
						    nshead,
						    nsid,
						    libnvme_path_get_name(p),
						    ana_state,
						    iopolicy_info,
						    libnvme_ctrl_get_name(c),
						    libnvme_ctrl_get_transport(c),
						    libnvme_ctrl_get_address(c),
						    libnvme_ctrl_get_state(c));
			if (ret < 0)
				goto free_tbl;
		}
	}

	/*
	 * Next we print controller in the subsystem which may not have any
	 * nvme path associated to it.
	 */
	libnvme_subsystem_for_each_ctrl(s, c) {
		num_path = 0;
		libnvme_ctrl_for_each_path(c, p)
			num_path++;

		if (!num_path) {
			ret = subsystem_topology_multipath_add_row(t,
					iopolicy,
					"--", /* NSHead */
					"--", /* NSID */
					"--", /* NSPath */
					"--", /* ANAState */
					"--", /* Nodes/Qdepth */
					libnvme_ctrl_get_name(c),
					libnvme_ctrl_get_transport(c),
					libnvme_ctrl_get_address(c),
					libnvme_ctrl_get_state(c));
			if (ret < 0)
				goto free_tbl;
		}
	}

	shr_table_print(t);
free_tbl:
	shr_table_free(t);
}

static void stdout_subsystem_topology_multipath(struct libnvme_subsystem *s,
						     enum nvme_cli_topo_ranking ranking)
{
	struct libnvme_ns *n;
	struct libnvme_path *p;
	struct libnvme_ctrl *c;
	const char *iopolicy;

	libnvme_subsystem_get_iopolicy(s, &iopolicy, "");

	if (ranking == NVME_CLI_TOPO_NAMESPACE) {
		libnvme_subsystem_for_each_ns(s, n) {
			if (!libnvme_namespace_first_path(n))
				continue;

			printf(" +- ns %d\n", libnvme_ns_get_nsid(n));
			printf(" \\\n");

			libnvme_namespace_for_each_path(n, p) {
				const char *ana_state;

				c = libnvme_path_get_ctrl(p);
				libnvme_path_get_ana_state(p, &ana_state, "");

				printf("  +- %s %s %s %s %s\n",
				       libnvme_ctrl_get_name(c),
				       libnvme_ctrl_get_transport(c),
				       libnvme_ctrl_get_address(c),
				       libnvme_ctrl_get_state(c),
				       ana_state);
			}
		}
	} else if (ranking == NVME_CLI_TOPO_CTRL) {
		/* NVME_CLI_TOPO_CTRL */
		libnvme_subsystem_for_each_ctrl(s, c) {
			printf(" +- %s %s %s\n",
			       libnvme_ctrl_get_name(c),
			       libnvme_ctrl_get_transport(c),
			       libnvme_ctrl_get_address(c));
			printf(" \\\n");

			libnvme_subsystem_for_each_ns(s, n) {
				libnvme_namespace_for_each_path(n, p) {
					const char *ana_state;

					if (libnvme_path_get_ctrl(p) != c)
						continue;

					libnvme_path_get_ana_state(p,
							&ana_state, "");
					printf("  +- ns %d %s %s\n",
					       libnvme_ns_get_nsid(n),
					       libnvme_ctrl_get_state(c),
					       ana_state);
				}
			}
		}
	} else {
		/* NVME_CLI_TOPO_MULTIPATH */
		libnvme_subsystem_for_each_ns(s, n) {
			printf(" +- %s (ns %d)\n",
					libnvme_ns_get_name(n),
					libnvme_ns_get_nsid(n));
			printf(" \\\n");
			libnvme_namespace_for_each_path(n, p) {
				const char *ana_state;

				c = libnvme_path_get_ctrl(p);
				libnvme_path_get_ana_state(p, &ana_state, "");

				if (!strcmp(iopolicy, "numa")) {
					const char *numa_nodes;

					/*
					 * For iopolicy numa, exclude printing
					 * qdepth.
					 */
					libnvme_path_get_numa_nodes(p,
							&numa_nodes, "");
					printf("  +- %s %s %s %s %s %s %s\n",
						libnvme_path_get_name(p),
						ana_state,
						numa_nodes,
						libnvme_ctrl_get_name(c),
						libnvme_ctrl_get_transport(c),
						libnvme_ctrl_get_address(c),
						libnvme_ctrl_get_state(c));

				} else if (!strcmp(iopolicy, "queue-depth")) {
					int queue_depth;

					/*
					 * For iopolicy queue-depth, exclude
					 * printing numa nodes.
					 */
					libnvme_path_get_queue_depth(p,
							&queue_depth, 0);
					printf("  +- %s %s %d %s %s %s %s\n",
						libnvme_path_get_name(p),
						ana_state,
						queue_depth,
						libnvme_ctrl_get_name(c),
						libnvme_ctrl_get_transport(c),
						libnvme_ctrl_get_address(c),
						libnvme_ctrl_get_state(c));

				} else { /* round-robin */
					/*
					 * For iopolicy round-robin, exclude
					 * printing numa nodes and qdepth.
					 */
					printf("  +- %s %s %s %s %s %s\n",
						libnvme_path_get_name(p),
						ana_state,
						libnvme_ctrl_get_name(c),
						libnvme_ctrl_get_transport(c),
						libnvme_ctrl_get_address(c),
						libnvme_ctrl_get_state(c));
				}
			}
		}
	}
}

static int subsystem_topology_add_row(struct shr_table *t,
		const char *ns, const char *nsid, const char *ctrl,
		const char *trtype, const char *address, const char *state)
{
	int row = shr_table_get_row_id(t);
	if (row < 0) {
		nvme_show_error("Failed to add subsys topology row");
		return row;
	}

	shr_table_set_value_str(t, 0, row, ns, CENTERED);
	shr_table_set_value_str(t, 1, row, nsid, CENTERED);
	shr_table_set_value_str(t, 2, row, ctrl, CENTERED);
	shr_table_set_value_str(t, 3, row, trtype, CENTERED);
	shr_table_set_value_str(t, 4, row, address, CENTERED);
	shr_table_set_value_str(t, 5, row, state, CENTERED);

	shr_table_add_row(t, row);

	return 0;
}

static void stdout_tabular_subsystem_topology(struct libnvme_subsystem *s)
{
	struct libnvme_ctrl *c;
	struct libnvme_ns *n;
	int ret, num_ns;
	struct shr_table *t;
	struct shr_table_column columns[] = {
		{"Namespace",  LEFT, AUTO_WIDTH},
		{"NSID",       LEFT, AUTO_WIDTH},
		{"Controller", LEFT, AUTO_WIDTH},
		{"Trtype",     LEFT, AUTO_WIDTH},
		{"Address",    LEFT, AUTO_WIDTH},
		{"State",      LEFT, AUTO_WIDTH},
	};

	t = shr_table_create();
	if (!t) {
		nvme_show_error("Failed to init subsys topology table");
		return;
	}

	if (shr_table_add_columns(t, columns, ARRAY_SIZE(columns)) < 0) {
		nvme_show_error("Failed to add subsys topology columns");
		goto free_tbl;
	}

	libnvme_subsystem_for_each_ctrl(s, c) {
		num_ns = 0;

		libnvme_ctrl_for_each_ns(c, n)
			num_ns++;

		if (!num_ns) {
			ret = subsystem_topology_add_row(t,
					"--",	/* Namespace */
					"--",	/* NSID */
					libnvme_ctrl_get_name(c),
					libnvme_ctrl_get_transport(c),
					libnvme_ctrl_get_address(c),
					libnvme_ctrl_get_state(c));
			if (ret < 0)
				goto free_tbl;
		} else {
			libnvme_ctrl_for_each_ns(c, n) {
				char nsid[32];

				snprintf(nsid, sizeof(nsid), "%u",
						libnvme_ns_get_nsid(n));

				ret = subsystem_topology_add_row(t,
						libnvme_ns_get_name(n),
						(const char *)nsid,
						libnvme_ctrl_get_name(c),
						libnvme_ctrl_get_transport(c),
						libnvme_ctrl_get_address(c),
						libnvme_ctrl_get_state(c));
				if (ret < 0)
					goto free_tbl;
			}
		}
	}
	shr_table_print(t);
free_tbl:
	shr_table_free(t);
}

static void stdout_subsystem_topology(struct libnvme_subsystem *s,
					   enum nvme_cli_topo_ranking ranking)
{
	struct libnvme_ctrl *c;
	struct libnvme_ns *n;

	if (ranking == NVME_CLI_TOPO_NAMESPACE) {
		libnvme_subsystem_for_each_ctrl(s, c) {
			libnvme_ctrl_for_each_ns(c, n) {
				printf(" +- ns %d\n", libnvme_ns_get_nsid(n));
				printf(" \\\n");
				printf("  +- %s %s %s %s\n",
				       libnvme_ctrl_get_name(c),
				       libnvme_ctrl_get_transport(c),
				       libnvme_ctrl_get_address(c),
				       libnvme_ctrl_get_state(c));
			}
		}
	} else if (ranking == NVME_CLI_TOPO_CTRL) {
		/* NVME_CLI_TOPO_CTRL */
		libnvme_subsystem_for_each_ctrl(s, c) {
			printf(" +- %s %s %s\n",
			       libnvme_ctrl_get_name(c),
			       libnvme_ctrl_get_transport(c),
			       libnvme_ctrl_get_address(c));
			printf(" \\\n");
			libnvme_ctrl_for_each_ns(c, n) {
				printf("  +- ns %d %s\n",
				       libnvme_ns_get_nsid(n),
				       libnvme_ctrl_get_state(c));
			}
		}
	} else {
		/* NVME_CLI_TOPO_MULTIPATH */
		libnvme_subsystem_for_each_ctrl(s, c) {
			libnvme_ctrl_for_each_ns(c, n) {
				c = libnvme_ns_get_ctrl(n);

				printf(" +- %s (ns %d)\n",
						libnvme_ns_get_name(n),
						libnvme_ns_get_nsid(n));
				printf(" \\\n");
				printf("  +- %s %s %s %s\n",
						libnvme_ctrl_get_name(c),
						libnvme_ctrl_get_transport(c),
						libnvme_ctrl_get_address(c),
						libnvme_ctrl_get_state(c));
			}
		}
	}
}

static void stdout_topology_tabular(struct libnvme_global_ctx *ctx)
{
	struct libnvme_host *h;
	struct libnvme_subsystem *s;
	bool first = true;

	libnvme_for_each_host(ctx, h) {
		libnvme_for_each_subsystem(h, s) {
			bool no_ctrl = true;
			struct libnvme_ctrl *c;

			libnvme_subsystem_for_each_ctrl(s, c)
				no_ctrl = false;

			if (no_ctrl)
				continue;

			if (!first)
				printf("\n");
			first = false;

			stdout_subsys_config(s, true);
			printf("\n");

			if (nvme_is_multipath(s))
				stdout_tabular_subsystem_topology_multipath(s);
			else
				stdout_tabular_subsystem_topology(s);
		}
	}
}

static void stdout_simple_topology(struct libnvme_global_ctx *ctx,
				   enum nvme_cli_topo_ranking ranking)
{
	struct libnvme_host *h;
	struct libnvme_subsystem *s;
	bool first = true;

	libnvme_for_each_host(ctx, h) {
		libnvme_for_each_subsystem(h, s) {
			bool no_ctrl = true;
			struct libnvme_ctrl *c;

			libnvme_subsystem_for_each_ctrl(s, c)
				no_ctrl = false;

			if (no_ctrl)
				continue;

			if (!first)
				printf("\n");
			first = false;

			stdout_subsys_config(s, true);
			printf("\\\n");

			if (nvme_is_multipath(s))
				stdout_subsystem_topology_multipath(s, ranking);
			else
				stdout_subsystem_topology(s, ranking);
		}
	}
}

static void stdout_topology_namespace(struct libnvme_global_ctx *ctx)
{
	stdout_simple_topology(ctx, NVME_CLI_TOPO_NAMESPACE);
}

static void stdout_topology_ctrl(struct libnvme_global_ctx *ctx)
{
	stdout_simple_topology(ctx, NVME_CLI_TOPO_CTRL);
}

static void stdout_topology_multipath(struct libnvme_global_ctx *ctx)
{
	stdout_simple_topology(ctx, NVME_CLI_TOPO_MULTIPATH);
}

static void stdout_message(bool error, const char *msg, va_list ap)
{
	vfprintf(error ? stderr : stdout, msg, ap);

	fprintf(error ? stderr : stdout, "\n");
}

static void stdout_perror(const char *msg, va_list ap)
{
	__cleanup_free char *error = NULL;

	if (vasprintf(&error, msg, ap) < 0)
		error = NULL;

	perror(error ? error : alloc_error);
}

static void stdout_key_value(const char *key, const char *val, va_list ap)
{
	__cleanup_free char *value = NULL;

	if (vasprintf(&value, val, ap) < 0)
		value = NULL;

	printf("%s: %s\n", key, value ? value : alloc_error);
}

#ifdef CONFIG_FABRICS
/*
 * libnvmf_connect_args_emit() callback for "nvme config show": print each
 * formatted "--option=value" straight to stdout as part of the running
 * "nvme connect" line.
 */
static void stdout_print_conn_arg(const char *arg, void *user_data)
{
	printf(" %s", arg);
}

static void stdout_print_conn_field(const char *name, const char *value)
{
	if (value)
		printf(" --%s=%s", name, value);
}

/*
 * libnvmf_config_conn_for_each() callback for "nvme config show": render
 * one resolved connection as its equivalent "nvme connect" command line.
 *
 * Identity is deliberately left unresolved here (unlike build_conn_tid()'s
 * connect-time callers): a persona with no hostnqn/hostid falls back to the
 * system default at connect time, not parse time, so showing the concrete
 * value here would suggest a fixed identity the config doesn't actually pin.
 *
 * Addressing is not resolved either, and no TID is built for a hostname:
 * "show" must never touch the network, and a hostname traddr is legitimate
 * INI content a TID (numeric-only) can't represent. The canonicalized TID
 * rendering is used when the address is already numeric; a raw hostname
 * falls back to printing the field as configured.
 */
static void stdout_print_conn(const struct libnvmf_config_conn *conn,
			       void *user_data)
{
	bool is_dc = libnvmf_config_conn_is_dc(conn);
	const char *hostnqn = libnvmf_config_conn_get_hostnqn(conn);
	const char *hostid = libnvmf_config_conn_get_hostid(conn);
	const struct libnvmf_params *params =
		libnvmf_config_conn_get_params(conn);
	__cleanup_nvmf_tid struct libnvmf_tid *tid = NULL;

	printf("# %s: %s\n", libnvmf_config_conn_get_source(conn),
		is_dc ? "Discovery Controller" : "I/O Controller");

	libnvmf_tid_from_fields(
			libnvmf_config_conn_get_transport(conn),
			libnvmf_config_conn_get_traddr(conn),
			libnvmf_config_conn_get_trsvcid(conn),
			libnvmf_config_conn_get_subsysnqn(conn),
			libnvmf_config_conn_get_host_traddr(conn),
			libnvmf_config_conn_get_host_iface(conn),
			hostnqn, hostid, &tid);

	/*
	 * A DC entry is consumed via libnvmf_discover() (log in, fetch the
	 * discovery log, connect everything returned) -- "nvme connect-all"
	 * is its real equivalent, not a bare "nvme connect" (which would
	 * only open the admin queue, matching just the niche "connect -J"
	 * mode instead of the primary discover/connect-all consumption
	 * path this command documents).
	 */
	printf("nvme %s", is_dc ? "connect-all" : "connect");
	if (tid) {
		libnvmf_connect_args_emit(tid, params, stdout_print_conn_arg,
					   NULL);
	} else {
		const char *transport = libnvmf_config_conn_get_transport(conn);
		const char *traddr = libnvmf_config_conn_get_traddr(conn);
		const char *trsvcid = libnvmf_config_conn_get_trsvcid(conn);
		const char *subsysnqn = libnvmf_config_conn_get_subsysnqn(conn);
		const char *host_traddr =
			libnvmf_config_conn_get_host_traddr(conn);
		const char *host_iface =
			libnvmf_config_conn_get_host_iface(conn);

		stdout_print_conn_field("transport", transport);
		stdout_print_conn_field("traddr", traddr);
		stdout_print_conn_field("trsvcid", trsvcid);
		stdout_print_conn_field("nqn", subsysnqn);
		stdout_print_conn_field("host-traddr", host_traddr);
		stdout_print_conn_field("host-iface", host_iface);
		stdout_print_conn_field("hostnqn", hostnqn);
		stdout_print_conn_field("hostid", hostid);
		libnvmf_connect_args_emit(NULL, params, stdout_print_conn_arg,
					   NULL);
	}
	printf("\n");
	if (!hostnqn || !hostid)
		printf("    (hostnqn/hostid: system default)\n");
	printf("\n");
}

static void stdout_config_conn_list(struct libnvmf_config *config)
{
	libnvmf_config_conn_for_each(config, stdout_print_conn, NULL);
}
#else /* CONFIG_FABRICS */
static void stdout_config_conn_list(struct libnvmf_config *config) {}
#endif /* CONFIG_FABRICS */

static void stdout_connect_msg(struct libnvme_ctrl *c)
{
	printf("connecting to device: %s\n", libnvme_ctrl_get_name(c));
}

static void stdout_relatives(struct libnvme_global_ctx *ctx, const char *name)
{
	struct nvme_resources res;
	struct htable_ns_iter it;
	bool block = true;
	bool first = true;
	struct libnvme_ctrl *c;
	struct libnvme_path *p;
	struct libnvme_ns *n;
	int nsid;
	int ret;
	int id;

	ret = sscanf(name, "nvme%dn%d", &id, &nsid);

	switch (ret) {
	case 1:
		block = false;
		break;
	case 2:
		break;
	default:
		return;
	}

	nvme_resources_init(ctx, &res);

	if (block) {
		fprintf(stderr, "Namespace %s has parent controller(s):", name);
		for (n = htable_ns_getfirst(&res.ht_n, name, &it); n;
		     n = htable_ns_getnext(&res.ht_n, name, &it)) {
			if (libnvme_ns_get_ctrl(n)) {
				fprintf(stderr, "%s", libnvme_ctrl_get_name(libnvme_ns_get_ctrl(n)));
				break;
			}
			libnvme_namespace_for_each_path(n, p) {
				c = libnvme_path_get_ctrl(p);
				fprintf(stderr, "%s%s", first ? "" : ", ", libnvme_ctrl_get_name(c));
				if (first)
					first = false;
			}
		}
		fprintf(stderr, "\n\n");
	} else {
		c = htable_ctrl_get(&res.ht_c, name);
		if (c) {
			fprintf(stderr, "Controller %s has child namespace(s):", name);
			libnvme_ctrl_for_each_ns(c, n) {
				fprintf(stderr, "%s%s", first ? "" : ", ", libnvme_ns_get_name(n));
				if (first)
					first = false;
			}
			fprintf(stderr, "\n\n");
		}
	}

	nvme_resources_free(&res);
}

struct print_ops stdout_print_ops = {
	/* libnvme types.h print functions */
	.ana_log			= stdout_ana_log,
	.boot_part_log			= stdout_boot_part_log,
	.phy_rx_eom_log			= stdout_phy_rx_eom_log,
	.ctrl_list			= stdout_list_ctrl,
	.ctrl_registers			= stdout_ctrl_registers,
	.ctrl_register			= stdout_ctrl_register,
	.directive			= stdout_directive_show,
	.discovery_log			= stdout_discovery_log,
	.effects_log_list		= stdout_effects_log_pages,
	.endurance_group_event_agg_log	= stdout_endurance_group_event_agg_log,
	.endurance_group_list		= stdout_endurance_group_list,
	.endurance_log			= stdout_endurance_log,
	.error_log			= stdout_error_log,
	.fdp_config_log			= stdout_fdp_configs,
	.fdp_event_log			= stdout_fdp_events,
	.fdp_ruh_status			= stdout_fdp_ruh_status,
	.fdp_stats_log			= stdout_fdp_stats,
	.fdp_usage_log			= stdout_fdp_usage,
	.fid_supported_effects_log	= stdout_fid_support_effects_log,
	.fw_log				= stdout_fw_log,
	.id_ctrl			= stdout_id_ctrl,
	.id_ctrl_nvm			= stdout_id_ctrl_nvm,
	.id_domain_list			= stdout_id_domain_list,
	.id_independent_id_ns		= stdout_cmd_set_independent_id_ns,
	.id_iocs			= stdout_id_iocs,
	.id_ns				= stdout_id_ns,
	.id_ns_descs			= stdout_id_ns_descs,
	.id_ns_granularity_list		= stdout_id_ns_granularity_list,
	.id_nvmset_list			= stdout_id_nvmset,
	.id_uuid_list			= stdout_id_uuid_list,
	.lba_status			= stdout_lba_status,
	.lba_status_log			= stdout_lba_status_log,
	.media_unit_stat_log		= stdout_media_unit_stat_log,
	.mi_cmd_support_effects_log	= stdout_mi_cmd_support_effects_log,
	.ns_list			= stdout_list_ns,
	.ns_list_log			= stdout_changed_ns_list_log,
	.nvm_id_ns			= stdout_nvm_id_ns,
	.persistent_event_log		= stdout_persistent_event_log,
	.predictable_latency_event_agg_log = stdout_predictable_latency_event_agg_log,
	.predictable_latency_per_nvmset	= stdout_predictable_latency_per_nvmset,
	.primary_ctrl_cap		= stdout_primary_ctrl_cap,
	.relatives			= stdout_relatives,
	.resv_notification_log		= stdout_resv_notif_log,
	.resv_report			= stdout_resv_report,
	.sanitize_log_page		= stdout_sanitize_log,
	.secondary_ctrl_list		= stdout_list_secondary_ctrl,
	.select_result			= stdout_select_result,
	.self_test_log			= stdout_self_test_log,
	.single_property		= stdout_single_property,
	.smart_log			= stdout_smart_log,
	.supported_cap_config_list_log	= stdout_supported_cap_config_log,
	.supported_log_pages		= stdout_supported_log,
	.zns_start_zone_list		= stdout_zns_start_zone_list,
	.zns_changed_zone_log		= stdout_zns_changed,
	.zns_finish_zone_list		= NULL,
	.zns_id_ctrl			= stdout_zns_id_ctrl,
	.zns_id_ns			= stdout_zns_id_ns,
	.zns_report_zones		= stdout_zns_report_zones,
	.show_feature			= stdout_feature_show,
	.show_feature_fields		= stdout_feature_show_fields,
	.id_ctrl_rpmbs			= stdout_id_ctrl_rpmbs,
	.lba_range			= stdout_lba_range,
	.lba_status_info		= stdout_lba_status_info,
	.d				= stdout_d,
	.show_init			= NULL,
	.show_finish			= NULL,
	.mgmt_addr_list_log		= stdout_mgmt_addr_list_log,
	.rotational_media_info_log	= stdout_rotational_media_info_log,
	.dispersed_ns_psub_log		= stdout_dispersed_ns_psub_log,
	.reachability_groups_log	= stdout_reachability_groups_log,
	.reachability_associations_log	= stdout_reachability_associations_log,
	.host_discovery_log		= stdout_host_discovery_log,
	.ave_discovery_log		= stdout_ave_discovery_log,
	.pull_model_ddc_req_log		= stdout_pull_model_ddc_req_log,
	.power_meas_log			= stdout_power_meas_log,

	/* libnvme tree print functions */
	.list_item			= stdout_list_item,
	.list_items			= stdout_list_items,
	.print_nvme_subsystem_list	= stdout_subsystem_list,
	.topology_ctrl			= stdout_topology_ctrl,
	.topology_namespace		= stdout_topology_namespace,
	.topology_multipath		= stdout_topology_multipath,
	.topology_tabular		= stdout_topology_tabular,

	/* config show */
	.config_conn_list		= stdout_config_conn_list,

	/* nvme top */
#ifdef CONFIG_TOP
	.top				= stdout_top,
#else
	.top				= NULL,
#endif

	/* status and error messages */
	.connect_msg			= stdout_connect_msg,
	.show_message			= stdout_message,
	.show_perror			= stdout_perror,
	.show_status			= stdout_status,
	.show_opcode_status		= stdout_opcode_status,
	.show_error_status		= stdout_error_status,
	.show_key_value			= stdout_key_value,
};

struct print_ops *nvme_get_stdout_print_ops(nvme_print_flags_t flags)
{
	stdout_print_ops.flags = flags;
	return &stdout_print_ops;
}

void print_array(char *name, __u8 *data, int size)
{
	int i;

	if (!name || !data || !size)
		return;

	printf("%s: 0x", name);
	for (i = 0; i < size; i++)
		printf("%02X", data[size - i - 1]);
	printf("\n");
}
