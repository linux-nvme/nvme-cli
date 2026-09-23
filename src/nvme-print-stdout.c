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

static const uint8_t zero_uuid[16] = { 0 };
static const uint8_t invalid_uuid[16] = {[0 ... 15] = 0xff };
static const char dash[100] = {[0 ... 99] = '-'};

static struct print_ops stdout_print_ops;

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

static void stdout_feature_show_fields(enum nvme_features_id fid,
				       unsigned int result,
				       unsigned char *buf);
static void stdout_smart_log(struct nvme_smart_log *smart, unsigned int nsid, const char *devname);
static struct shr_table *stdout_kv_table_create(void);
static int stdout_kv_add(struct shr_table *t, const char *name,
		const char *fmt, ...);
static void stdout_kv_render(FILE *stream, struct shr_table *t);
static void stdout_kv_table_finish(struct shr_table *t, const char *what);
static struct shr_table *stdout_bits_table_create(void);
static void stdout_bits_add(struct shr_table *t, const char *bits,
		unsigned int val, const char *desc_fmt, ...);

static void stdout_predictable_latency_per_nvmset(
		struct nvme_nvmset_predictable_lat_log *plpns_log,
		__u16 nvmset_id, const char *devname)
{
	struct shr_table *t;

	printf("Predictable Latency Per NVM Set Log for device: %s\n",
		devname);
	printf("Predictable Latency Per NVM Set Log for NVM Set ID: %u\n",
		le16_to_cpu(nvmset_id));

	t = stdout_kv_table_create();
	if (!t)
		return;

	stdout_kv_add(t, "Status", "%u", plpns_log->status);
	stdout_kv_add(t, "Event Type", "%u",
		      le16_to_cpu(plpns_log->event_type));
	stdout_kv_add(t, "DTWIN Reads Typical", "%"PRIu64,
		      le64_to_cpu(plpns_log->dtwin_rt));
	stdout_kv_add(t, "DTWIN Writes Typical", "%"PRIu64,
		      le64_to_cpu(plpns_log->dtwin_wt));
	stdout_kv_add(t, "DTWIN Time Maximum", "%"PRIu64,
		      le64_to_cpu(plpns_log->dtwin_tmax));
	stdout_kv_add(t, "NDWIN Time Minimum High", "%"PRIu64,
		      le64_to_cpu(plpns_log->ndwin_tmin_hi));
	stdout_kv_add(t, "NDWIN Time Minimum Low", "%"PRIu64,
		      le64_to_cpu(plpns_log->ndwin_tmin_lo));
	stdout_kv_add(t, "DTWIN Reads Estimate", "%"PRIu64,
		      le64_to_cpu(plpns_log->dtwin_re));
	stdout_kv_add(t, "DTWIN Writes Estimate", "%"PRIu64,
		      le64_to_cpu(plpns_log->dtwin_we));
	stdout_kv_add(t, "DTWIN Time Estimate", "%"PRIu64,
		      le64_to_cpu(plpns_log->dtwin_te));

	stdout_kv_table_finish(t, "predictable-latency-nvmset");
	printf("\n\n");
}

static void stdout_predictable_latency_event_agg_log(
		struct nvme_aggregate_predictable_lat_event *pea_log,
		__u64 log_entries, __u32 size, const char *devname)
{
	__u64 num_iter;
	__u64 num_entries;
	struct shr_table *t;

	num_entries = le64_to_cpu(pea_log->num_entries);
	printf("Predictable Latency Event Aggregate Log for device: %s\n", devname);

	t = stdout_kv_table_create();
	if (!t)
		return;

	stdout_kv_add(t, "Number of Entries Available", "%"PRIu64,
		      (uint64_t)num_entries);

	num_iter = min(num_entries, log_entries);
	for (int i = 0; i < num_iter; i++) {
		char name[24];

		snprintf(name, sizeof(name), "Entry[%d]", i + 1);
		stdout_kv_add(t, name, "%u", le16_to_cpu(pea_log->entries[i]));
	}

	stdout_kv_table_finish(t, "predictable-latency-event-agg");
}

static struct shr_table *
stdout_persistent_event_log_rci_table(__le32 pel_header_rci)
{
	struct shr_table *t;
	__u32 rci = le32_to_cpu(pel_header_rci);
	__u32 rsvd19 = NVME_PEL_RCI_RSVD(rci);
	__u8 rce = NVME_PEL_RCI_RCE(rci);
	__u8 rcpit = NVME_PEL_RCI_RCPIT(rci);
	__u16 rcpid = NVME_PEL_RCI_RCPID(rci);

	t = stdout_bits_table_create();
	if (!t)
		return NULL;

	if (rsvd19)
		stdout_bits_add(t, "[31:19]", rsvd19, "Reserved");
	stdout_bits_add(t, "[18:18]", rce, "Reporting Context %sExists",
			rce ? "" : "Not ");
	stdout_bits_add(t, "[17:16]", rcpit,
			"Reporting Context Port Identifier Type: %s",
			nvme_pel_rci_rcpit_to_string(rcpit));
	stdout_bits_add(t, "[15:0]", rcpid,
			"Reporting Context Port Identifier");

	return t;
}

static struct shr_table *stdout_persistent_event_entry_ehai_table(__u8 ehai)
{
	struct shr_table *t;
	__u8 rsvd1 = NVME_PEL_EHAI_RSVD(ehai);
	__u8 pit = NVME_PEL_EHAI_PIT(ehai);

	t = stdout_bits_table_create();
	if (!t)
		return NULL;

	stdout_bits_add(t, "[7:2]", rsvd1, "Reserved");
	stdout_bits_add(t, "[1:0]", pit, "%s",
			 nvme_pel_ehai_pit_to_string(pit));

	return t;
}

static void stdout_add_bitmap(int i, __u8 seb)
{
	for (int bit = 0; bit < CHAR_BIT; bit++) {
		if (nvme_pel_event_to_string(bit + i * CHAR_BIT)) {
			if ((seb >> bit) & 0x1)
				printf("	Support %s\n",
				       nvme_pel_event_to_string(bit + i * CHAR_BIT));
		}
	}
}

static void stdout_persistent_event_log_fdp_events(unsigned int cdw11, unsigned int cdw12,
						   unsigned char *buf)
{
	unsigned int num = NVME_GET(cdw11, FEAT_FDPE_NOET);
	struct shr_table *t;

	t = stdout_kv_table_create();
	if (!t)
		return;

	for (unsigned int i = 0; i < num; i++)
		stdout_kv_add(t, nvme_fdp_event_to_string(buf[i]), "%sEnabled",
			      NVME_GET(cdw12, FDP_SUPP_EVENT_ENABLED) ?
			      "" : "Not ");

	stdout_kv_table_finish(t, "pel-fdp-events");
}

void nvme_show_pel_header(struct nvme_persistent_event_log *pevent_log_head,
			   int human)
{
	struct nvme_persistent_event_log *hdr = pevent_log_head;
	struct shr_table *t;
	int row;

	t = stdout_kv_table_create();
	if (!t)
		return;

	stdout_kv_add(t, "Log Identifier", "%u", hdr->lid);
	stdout_kv_add(t, "Total Number of Events", "%u",
		      le32_to_cpu(hdr->tnev));
	stdout_kv_add(t, "Total Log Length", "%"PRIu64,
		      le64_to_cpu(hdr->tll));
	stdout_kv_add(t, "Log Revision", "%u", hdr->rv);
	stdout_kv_add(t, "Log Header Length", "%u", hdr->lhl);
	stdout_kv_add(t, "Timestamp", "%"PRIu64, le64_to_cpu(hdr->ts));
	stdout_kv_add(t, "Power On Hours (POH)", "%s",
		      uint128_t_to_l10n_string(le128_to_cpu(hdr->poh)));
	stdout_kv_add(t, "Power Cycle Count", "%"PRIu64,
		      le64_to_cpu(hdr->pcc));
	stdout_kv_add(t, "PCI Vendor ID (VID)", "%u",
		      le16_to_cpu(hdr->vid));
	stdout_kv_add(t, "PCI Subsystem Vendor ID (SSVID)", "%u",
		      le16_to_cpu(hdr->ssvid));
	stdout_kv_add(t, "Serial Number (SN)", "%-.*s",
		      (int)sizeof(hdr->sn), hdr->sn);
	stdout_kv_add(t, "Model Number (MN)", "%-.*s",
		      (int)sizeof(hdr->mn), hdr->mn);
	stdout_kv_add(t, "NVM Subsystem NVMe Qualified Name (SUBNQN)", "%-.*s",
		      (int)sizeof(hdr->subnqn), hdr->subnqn);
	stdout_kv_add(t, "Generation Number", "%u",
		      le16_to_cpu(hdr->gen_number));
	row = stdout_kv_add(t, "Reporting Context Information (RCI)", "%u",
			     le32_to_cpu(hdr->rci));
	if (human)
		shr_table_set_row_subtable(t, row,
			stdout_persistent_event_log_rci_table(hdr->rci));

	stdout_kv_table_finish(t, "persistent-event-log header");

	printf("Supported Events Bitmap:\n");
	for (int i = 0; i < 32; i++) {
		if (!hdr->seb[i])
			continue;
		stdout_add_bitmap(i, hdr->seb[i]);
	}
}

void nvme_show_pel_event_header(int i,
				 struct nvme_persistent_event_entry *hdr,
				 int human)
{
	struct shr_table *t;
	__u16 vsil = le16_to_cpu(hdr->vsil);
	int row;

	t = stdout_kv_table_create();
	if (!t)
		return;

	stdout_kv_add(t, "Event Number", "%u", i);
	stdout_kv_add(t, "Event Type", "%s",
		      nvme_pel_event_to_string(hdr->etype));
	stdout_kv_add(t, "Event Type Revision", "%u", hdr->etype_rev);
	stdout_kv_add(t, "Event Header Length", "%u", hdr->ehl);
	row = stdout_kv_add(t, "Event Header Additional Info", "%u",
			     hdr->ehai);
	if (human)
		shr_table_set_row_subtable(t, row,
			stdout_persistent_event_entry_ehai_table(hdr->ehai));
	stdout_kv_add(t, "Controller Identifier", "%u",
		      le16_to_cpu(hdr->cntlid));
	stdout_kv_add(t, "Event Timestamp", "%"PRIu64,
		      le64_to_cpu(hdr->ets));
	stdout_kv_add(t, "Port Identifier", "%u",
		      le16_to_cpu(hdr->pelpid));
	stdout_kv_add(t, "Vendor Specific Information Length", "%u", vsil);
	stdout_kv_add(t, "Event Length", "%u", le16_to_cpu(hdr->el));

	stdout_kv_table_finish(t, "persistent-event-entry-header");

	if (vsil) {
		printf("Vendor Specific Information:\n");
		d((void *)hdr + 1, vsil, 16, 1);
	}
}

void nvme_show_pel_smart_health_event(void *pevent_log_info, __u32 offset,
				      const char *devname)
{
	struct nvme_smart_log *smart_event = pevent_log_info + offset;

	printf("Smart Health Event Entry:\n");
	stdout_smart_log(smart_event, NVME_NSID_ALL, devname);
}

void nvme_show_pel_fw_commit_event(void *pevent_log_info, __u32 offset)
{
	struct nvme_fw_commit_event *fw_commit_event = pevent_log_info + offset;
	struct shr_table *t;

	printf("FW Commit Event Entry:\n");

	t = stdout_kv_table_create();
	if (!t)
		return;

	stdout_kv_add(t, "Old Firmware Revision", "%"PRIu64" (%s)",
		      le64_to_cpu(fw_commit_event->old_fw_rev),
		      shr_fw_to_string((char *)&fw_commit_event->old_fw_rev));
	stdout_kv_add(t, "New Firmware Revision", "%"PRIu64" (%s)",
		      le64_to_cpu(fw_commit_event->new_fw_rev),
		      shr_fw_to_string((char *)&fw_commit_event->new_fw_rev));
	stdout_kv_add(t, "FW Commit Action", "%u",
		      fw_commit_event->fw_commit_action);
	stdout_kv_add(t, "FW Slot", "%u", fw_commit_event->fw_slot);
	stdout_kv_add(t, "Status Code Type for Firmware Commit Command", "%u",
		      fw_commit_event->sct_fw);
	stdout_kv_add(t, "Status Returned for Firmware Commit Command", "%u",
		      fw_commit_event->sc_fw);
	stdout_kv_add(t, "Vendor Assigned Firmware Commit Result Code", "%u",
		      le16_to_cpu(fw_commit_event->vndr_assign_fw_commit_rc));

	stdout_kv_table_finish(t, "pel-fw-commit-event");
}

void nvme_show_pel_timestamp_event(void *pevent_log_info, __u32 offset)
{
	struct nvme_time_stamp_change_event *ts_change_event = pevent_log_info + offset;
	struct shr_table *t;

	printf("Time Stamp Change Event Entry:\n");

	t = stdout_kv_table_create();
	if (!t)
		return;

	stdout_kv_add(t, "Previous Timestamp", "%"PRIu64,
		      le64_to_cpu(ts_change_event->previous_timestamp));
	stdout_kv_add(t, "Milliseconds Since Reset", "%"PRIu64,
		      le64_to_cpu(ts_change_event->ml_secs_since_reset));

	stdout_kv_table_finish(t, "pel-timestamp-event");
}

void nvme_show_pel_power_on_reset_event(void *pevent_log_info, __u32 offset,
					struct nvme_persistent_event_entry *pevent_entry_head)
{
	__u64 *fw_rev;
	__u32 por_info_len = le16_to_cpu(pevent_entry_head->el) -
			     le16_to_cpu(pevent_entry_head->vsil) - sizeof(*fw_rev);
	struct nvme_power_on_reset_info_list *por_event;
	__u32 por_info_list = por_info_len / sizeof(*por_event);
	struct shr_table *t;

	printf("Power On Reset Event Entry:\n");
	fw_rev = pevent_log_info + offset;

	t = stdout_kv_table_create();
	if (!t)
		return;

	stdout_kv_add(t, "Firmware Revision", "%"PRIu64" (%s)",
		      le64_to_cpu(*fw_rev), shr_fw_to_string((char *)fw_rev));

	stdout_kv_table_finish(t, "pel-power-on-reset-event");

	printf("Reset Information List:\n");

	for (int i = 0; i < por_info_list; i++) {
		por_event = pevent_log_info + offset + sizeof(*fw_rev) + i * sizeof(*por_event);

		t = stdout_kv_table_create();
		if (!t)
			return;

		stdout_kv_add(t, "Controller ID", "%u",
			      le16_to_cpu(por_event->cid));
		stdout_kv_add(t, "Firmware Activation", "%u",
			      por_event->fw_act);
		stdout_kv_add(t, "Operation in Progress", "%u",
			      por_event->op_in_prog);
		stdout_kv_add(t, "Controller Power Cycle", "%u",
			      le32_to_cpu(por_event->ctrl_power_cycle));
		stdout_kv_add(t, "Power on milliseconds", "%"PRIu64,
			      le64_to_cpu(por_event->power_on_ml_seconds));
		stdout_kv_add(t, "Controller Timestamp", "%"PRIu64,
			      le64_to_cpu(por_event->ctrl_time_stamp));

		stdout_kv_table_finish(t, "pel-power-on-reset-event");
	}
}

void nvme_show_pel_nss_hw_error_event(void *pevent_log_info, __u32 offset)
{
	struct nvme_nss_hw_err_event *nss_hw_err_event = pevent_log_info + offset;
	__u16 code = le16_to_cpu(nss_hw_err_event->nss_hw_err_event_code);
	struct shr_table *t;

	t = stdout_kv_table_create();
	if (!t)
		return;

	stdout_kv_add(t, "NVM Subsystem Hardware Error Event Code Entry",
		      "%u, %s", code, nvme_nss_hw_error_to_string(code));

	stdout_kv_table_finish(t, "pel-nss-hw-error-event");
}

void nvme_show_pel_change_ns_event(void *pevent_log_info, __u32 offset)
{
	struct nvme_change_ns_event *ns_event = pevent_log_info + offset;
	struct shr_table *t;

	printf("Change Namespace Event Entry:\n");

	t = stdout_kv_table_create();
	if (!t)
		return;

	stdout_kv_add(t, "Namespace Management CDW10", "%u",
		      le32_to_cpu(ns_event->nsmgt_cdw10));
	stdout_kv_add(t, "Namespace Size", "%"PRIu64,
		      le64_to_cpu(ns_event->nsze));
	stdout_kv_add(t, "Namespace Capacity", "%"PRIu64,
		      le64_to_cpu(ns_event->nscap));
	stdout_kv_add(t, "Formatted LBA Size", "%u", ns_event->flbas);
	stdout_kv_add(t, "End-to-end Data Protection Type Settings", "%u",
		      ns_event->dps);
	stdout_kv_add(t,
		      "Namespace Multi-path I/O and Namespace Sharing Capabilities",
		      "%u", ns_event->nmic);
	stdout_kv_add(t, "ANA Group Identifier", "%u",
		      le32_to_cpu(ns_event->ana_grp_id));
	stdout_kv_add(t, "NVM Set Identifier", "%u",
		      le16_to_cpu(ns_event->nvmset_id));
	stdout_kv_add(t, "Namespace ID", "%u", le32_to_cpu(ns_event->nsid));

	stdout_kv_table_finish(t, "pel-change-ns-event");
}

void nvme_show_pel_format_start_event(void *pevent_log_info, __u32 offset)
{
	struct nvme_format_nvm_start_event *format_start_event = pevent_log_info + offset;
	struct shr_table *t;

	printf("Format NVM Start Event Entry:\n");

	t = stdout_kv_table_create();
	if (!t)
		return;

	stdout_kv_add(t, "Namespace Identifier", "%u",
		      le32_to_cpu(format_start_event->nsid));
	stdout_kv_add(t, "Format NVM Attributes", "%u",
		      format_start_event->fna);
	stdout_kv_add(t, "Format NVM CDW10", "%u",
		      le32_to_cpu(format_start_event->format_nvm_cdw10));

	stdout_kv_table_finish(t, "pel-format-start-event");
}

void nvme_show_pel_format_completion_event(void *pevent_log_info, __u32 offset)
{
	struct nvme_format_nvm_compln_event *format_cmpln_event = pevent_log_info + offset;
	struct shr_table *t;

	printf("Format NVM Completion Event Entry:\n");

	t = stdout_kv_table_create();
	if (!t)
		return;

	stdout_kv_add(t, "Namespace Identifier", "%u",
		      le32_to_cpu(format_cmpln_event->nsid));
	stdout_kv_add(t, "Smallest Format Progress Indicator", "%u",
		      format_cmpln_event->smallest_fpi);
	stdout_kv_add(t, "Format NVM Status", "%u",
		      format_cmpln_event->format_nvm_status);
	stdout_kv_add(t, "Completion Information", "%u",
		      le16_to_cpu(format_cmpln_event->compln_info));
	stdout_kv_add(t, "Status Field", "%u",
		      le32_to_cpu(format_cmpln_event->status_field));

	stdout_kv_table_finish(t, "pel-format-completion-event");
}

void nvme_show_pel_sanitize_start_event(void *pevent_log_info, __u32 offset)
{
	struct nvme_sanitize_start_event *sanitize_start_event = pevent_log_info + offset;
	struct shr_table *t;

	printf("Sanitize Start Event Entry:\n");

	t = stdout_kv_table_create();
	if (!t)
		return;

	stdout_kv_add(t, "SANICAP", "%u", sanitize_start_event->sani_cap);
	stdout_kv_add(t, "Sanitize CDW10", "%u",
		      le32_to_cpu(sanitize_start_event->sani_cdw10));
	stdout_kv_add(t, "Sanitize CDW11", "%u",
		      le32_to_cpu(sanitize_start_event->sani_cdw11));

	stdout_kv_table_finish(t, "pel-sanitize-start-event");
}

void nvme_show_pel_sanitize_completion_event(void *pevent_log_info, __u32 offset)
{
	struct nvme_sanitize_compln_event *sanitize_cmpln_event = pevent_log_info + offset;
	struct shr_table *t;

	printf("Sanitize Completion Event Entry:\n");

	t = stdout_kv_table_create();
	if (!t)
		return;

	stdout_kv_add(t, "Sanitize Progress", "%u",
		      le16_to_cpu(sanitize_cmpln_event->sani_prog));
	stdout_kv_add(t, "Sanitize Status", "%u",
		      le16_to_cpu(sanitize_cmpln_event->sani_status));
	stdout_kv_add(t, "Completion Information", "%u",
		      le16_to_cpu(sanitize_cmpln_event->cmpln_info));

	stdout_kv_table_finish(t, "pel-sanitize-completion-event");
}

void nvme_show_pel_set_feature_event(void *pevent_log_info, __u32 offset)
{
	int fid, cdw11, cdw12, dword_cnt;
	unsigned char *mem_buf;
	struct nvme_set_feature_event *set_feat_event = pevent_log_info + offset;
	struct shr_table *t;

	printf("Set Feature Event Entry:\n");
	dword_cnt = NVME_SET_FEAT_EVENT_DW_COUNT(set_feat_event->layout);
	fid = NVME_GET(le32_to_cpu(set_feat_event->cdw_mem[0]), SET_FEATURES_CDW10_FID);
	cdw11 = le32_to_cpu(set_feat_event->cdw_mem[1]);

	t = stdout_kv_table_create();
	if (!t)
		return;

	stdout_kv_add(t, "Set Feature ID", "0x%02x (%s), value: 0x%08x", fid,
		      nvme_feature_to_string(fid), cdw11);

	stdout_kv_table_finish(t, "pel-set-feature-event");

	if (!NVME_SET_FEAT_EVENT_MB_COUNT(set_feat_event->layout))
		return;

	mem_buf = (unsigned char *)set_feat_event + 4 + dword_cnt * 4;
	if (fid == NVME_FEAT_FID_FDP_EVENTS) {
		cdw12 = le32_to_cpu(set_feat_event->cdw_mem[2]);
		stdout_persistent_event_log_fdp_events(cdw11, cdw12, mem_buf);
	} else {
		stdout_feature_show_fields(fid, cdw11, mem_buf);
	}
}

void nvme_show_pel_thermal_excursion_event(void *pevent_log_info, __u32 offset)
{
	struct nvme_thermal_exc_event *thermal_exc_event = pevent_log_info + offset;
	struct shr_table *t;

	printf("Thermal Excursion Event Entry:\n");

	t = stdout_kv_table_create();
	if (!t)
		return;

	stdout_kv_add(t, "Over Temperature", "%u",
		      thermal_exc_event->over_temp);
	stdout_kv_add(t, "Threshold", "%u", thermal_exc_event->threshold);

	stdout_kv_table_finish(t, "pel-thermal-excursion-event");
}

static void pel_vs_event_data(void *vsed, __u8 vsedt, __u16 vsedl)
{
	struct shr_table *t;

	printf("Vendor Specific Event Data:\n");
	switch (vsedt) {
	case NVME_PEL_VSEDT_EVENT_NAME:
		t = stdout_kv_table_create();
		if (!t)
			return;

		stdout_kv_add(t, "Event Name for Vendor Specific Event Code",
			      "%.*s", vsedl, (char *)vsed);

		stdout_kv_table_finish(t, "pel-vs-event-data");
		break;
	case NVME_PEL_VSEDT_ASCII_STRING:
		t = stdout_kv_table_create();
		if (!t)
			return;

		stdout_kv_add(t, "ASCII String Data", "%.*s", vsedl,
			      (char *)vsed);

		stdout_kv_table_finish(t, "pel-vs-event-data");
		break;
	case NVME_PEL_VSEDT_BINARY:
		printf("Binary Data:\n");
		d(vsed, vsedl, 16, 1);
		break;
	case NVME_PEL_VSEDT_SIGNED_INT:
		t = stdout_kv_table_create();
		if (!t)
			return;

		stdout_kv_add(t, "Signed Integer Data", "%"PRId64,
			      (int64_t)le64_to_cpu(*(__le64 *)vsed));

		stdout_kv_table_finish(t, "pel-vs-event-data");
		break;
	default:
		printf("Reserved data type. As Binary:\n");
		d(vsed, vsedl, 16, 1);
	}
}

void nvme_show_pel_vendor_specific_event(void *pevent_log_info, __u32 offset,
					 __u32 event_data_len)
{
	__u32 progress = 0;
	__u16 vsedl;
	int i;
	struct nvme_vs_event_desc *vs_desc;
	struct shr_table *t;

	printf("Vendor Specific Event Entry:\n");
	for (i = 0; progress < event_data_len; i++) {
		vs_desc = pevent_log_info + offset + progress;
		vsedl = le16_to_cpu(vs_desc->vsedl);

		printf("Vendor Specific Event Descriptor %u:\n", i);

		t = stdout_kv_table_create();
		if (!t)
			return;

		stdout_kv_add(t, "Vendor Specific Event Code", "%u",
			      le16_to_cpu(vs_desc->vsec));
		stdout_kv_add(t, "Vendor Specific Event Data Type", "%u",
			      vs_desc->vsedt);
		stdout_kv_add(t, "Vendor Specific Event UIndex", "%u",
			      vs_desc->uidx);
		stdout_kv_add(t, "Vendor Specific Event Data Length", "%u",
			      vsedl);

		stdout_kv_table_finish(t, "pel-vendor-specific-event");

		if (vsedl)
			pel_vs_event_data(vs_desc + 1, vs_desc->vsedt,
					  vsedl);
		progress += sizeof(*vs_desc) + vsedl;
	}
}

static void stdout_persistent_event_log(void *pevent_log_info, __u8 action, __u32 size,
					const char *devname)
{
	struct nvme_persistent_event_log *pevent_log_head;
	__u32 offset = sizeof(*pevent_log_head);
	__u16 vsil, el;
	struct nvme_persistent_event_entry *pevent_entry_head;
	int human = stdout_print_ops.flags & VERBOSE;
	struct shr_table *t;

	t = stdout_kv_table_create();
	if (!t)
		return;

	stdout_kv_add(t, "Persistent Event Log for device", "%s", devname);
	stdout_kv_add(t, "Action for Persistent Event Log", "%u", action);

	stdout_kv_table_finish(t, "persistent-event-log");

	if (size < offset) {
		printf("No log data can be shown with this log len at least " \
		       "512 bytes is required or can be 0 to read the complete " \
		       "log page after context established\n");
		return;
	}

	pevent_log_head = pevent_log_info;

	nvme_show_pel_header(pevent_log_head, human);

	printf("\n");
	printf("\nPersistent Event Entries:\n");
	for (int i = 0; i < le32_to_cpu(pevent_log_head->tnev); i++) {
		if (offset + sizeof(*pevent_entry_head) >= size)
			break;

		pevent_entry_head = pevent_log_info + offset;
		vsil = le16_to_cpu(pevent_entry_head->vsil);
		el = le16_to_cpu(pevent_entry_head->el);

		if ((offset + pevent_entry_head->ehl + 3 + el) >= size)
			break;

		nvme_show_pel_event_header(i, pevent_entry_head, human);

		offset += pevent_entry_head->ehl + vsil + 3;

		switch (pevent_entry_head->etype) {
		case NVME_PEL_SMART_HEALTH_EVENT:
			nvme_show_pel_smart_health_event(pevent_log_info,
							 offset, devname);
			break;
		case NVME_PEL_FW_COMMIT_EVENT:
			nvme_show_pel_fw_commit_event(pevent_log_info, offset);
			break;
		case NVME_PEL_TIMESTAMP_EVENT:
			nvme_show_pel_timestamp_event(pevent_log_info, offset);
			break;
		case NVME_PEL_POWER_ON_RESET_EVENT:
			nvme_show_pel_power_on_reset_event(pevent_log_info,
							   offset,
							   pevent_entry_head);
			break;
		case NVME_PEL_NSS_HW_ERROR_EVENT:
			nvme_show_pel_nss_hw_error_event(pevent_log_info,
							 offset);
			break;
		case NVME_PEL_CHANGE_NS_EVENT:
			nvme_show_pel_change_ns_event(pevent_log_info, offset);
			break;
		case NVME_PEL_FORMAT_START_EVENT:
			nvme_show_pel_format_start_event(pevent_log_info,
							 offset);
			break;
		case NVME_PEL_FORMAT_COMPLETION_EVENT:
			nvme_show_pel_format_completion_event(pevent_log_info,
							      offset);
			break;
		case NVME_PEL_SANITIZE_START_EVENT:
			nvme_show_pel_sanitize_start_event(pevent_log_info,
							   offset);
			break;
		case NVME_PEL_SANITIZE_COMPLETION_EVENT:
			nvme_show_pel_sanitize_completion_event(pevent_log_info,
								offset);
			break;
		case NVME_PEL_SET_FEATURE_EVENT:
			nvme_show_pel_set_feature_event(pevent_log_info,
							offset);
			break;
		case NVME_PEL_TELEMETRY_CRT:
			d(pevent_log_info + offset, 512, 16, 1);
			break;
		case NVME_PEL_THERMAL_EXCURSION_EVENT:
			nvme_show_pel_thermal_excursion_event(pevent_log_info,
							      offset);
			break;
		case NVME_PEL_SANITIZE_MEDIA_VERIF_EVENT:
			printf("Sanitize Media Verification Event\n");
			break;
		case NVME_PEL_VENDOR_SPECIFIC_EVENT:
			nvme_show_pel_vendor_specific_event(pevent_log_info,
							    offset, el - vsil);
			break;
		default:
			printf("Reserved Event\n\n");
			break;
		}
		offset += el;
		printf("\n");
	}
}

static void stdout_endurance_group_event_agg_log(
		struct nvme_aggregate_endurance_group_event *endurance_log,
		__u64 log_entries, __u32 size, const char *devname)
{
	struct shr_table *t;

	printf("Endurance Group Event Aggregate Log for device: %s\n", devname);

	t = stdout_kv_table_create();
	if (!t)
		return;

	stdout_kv_add(t, "Number of Entries Available", "%"PRIu64,
		      le64_to_cpu(endurance_log->num_entries));

	for (int i = 0; i < log_entries; i++) {
		char name[24];

		snprintf(name, sizeof(name), "Entry[%d]", i + 1);
		stdout_kv_add(t, name, "%u",
			      le16_to_cpu(endurance_log->entries[i]));
	}

	stdout_kv_table_finish(t, "endurance-group-event-agg");
}

static void stdout_lba_status_log(void *lba_status, __u32 size,
				  const char *devname)
{
	struct nvme_lba_status_log *hdr;
	struct nvme_lbas_ns_element *ns_element;
	struct nvme_lba_rd *range_desc;
	int offset = sizeof(*hdr);
	__u32 num_lba_desc, num_elements;
	struct shr_table *t;

	hdr = lba_status;
	printf("LBA Status Log for device: %s\n", devname);

	t = stdout_kv_table_create();
	if (!t)
		return;

	stdout_kv_add(t, "LBA Status Log Page Length", "%"PRIu32,
		      le32_to_cpu(hdr->lslplen));
	num_elements = le32_to_cpu(hdr->nlslne);
	stdout_kv_add(t, "Number of LBA Status Log Namespace Elements",
		      "%"PRIu32, num_elements);
	stdout_kv_add(t, "Estimate of Unrecoverable Logical Blocks", "%"PRIu32,
		      le32_to_cpu(hdr->estulb));
	stdout_kv_add(t, "LBA Status Generation Counter", "%"PRIu16,
		      le16_to_cpu(hdr->lsgc));
	stdout_kv_table_finish(t, "lba-status-log");

	for (int ele = 0; ele < num_elements; ele++) {
		ns_element = lba_status + offset;
		num_lba_desc = le32_to_cpu(ns_element->nlrd);

		t = stdout_kv_table_create();
		if (!t)
			return;

		stdout_kv_add(t, "Namespace Element Identifier", "%"PRIu32,
			      le32_to_cpu(ns_element->neid));
		stdout_kv_add(t, "Number of LBA Range Descriptors", "%"PRIu32,
			      num_lba_desc);
		stdout_kv_add(t, "Recommended Action Type", "%u",
			      ns_element->ratype);

		stdout_kv_table_finish(t, "lba-status-log");

		offset += sizeof(*ns_element);
		if (num_lba_desc != 0xffffffff) {
			t = stdout_kv_table_create();
			if (!t)
				return;

			for (int i = 0; i < num_lba_desc; i++) {
				char name[24];

				range_desc = lba_status + offset;
				snprintf(name, sizeof(name), "RSLBA[%d]", i);
				stdout_kv_add(t, name, "%"PRIu64,
					      le64_to_cpu(range_desc->rslba));
				snprintf(name, sizeof(name), "RNLB[%d]", i);
				stdout_kv_add(t, name, "%"PRIu32,
					      le32_to_cpu(range_desc->rnlb));
				offset += sizeof(*range_desc);
			}

			stdout_kv_table_finish(t, "lba-status-log");
		} else {
			printf("Number of LBA Range Descriptors (NLRD) set to %#x for "\
				"NS element %d\n", num_lba_desc, ele);
		}
	}
}

static void stdout_resv_notif_log(struct nvme_resv_notification_log *resv,
				  const char *devname)
{
	struct shr_table *t;

	printf("Reservation Notif Log for device: %s\n", devname);

	t = stdout_kv_table_create();
	if (!t)
		return;

	stdout_kv_add(t, "Log Page Count", "%"PRIx64, le64_to_cpu(resv->lpc));
	stdout_kv_add(t, "Resv Notif Log Page Type", "%u (%s)", resv->rnlpt,
		      nvme_resv_notif_to_string(resv->rnlpt));
	stdout_kv_add(t, "Num of Available Log Pages", "%u", resv->nalp);
	stdout_kv_add(t, "Namespace ID", "%"PRIx32, le32_to_cpu(resv->nsid));

	stdout_kv_table_finish(t, "resv-notif-log");
}

static struct shr_table *
stdout_fid_support_effects_log_human_table(__u32 fid_support)
{
	struct shr_table *t;
	__u8 fsupp = !!(fid_support & NVME_FID_SUPPORTED_EFFECTS_FSUPP);
	__u8 udcc = !!(fid_support & NVME_FID_SUPPORTED_EFFECTS_UDCC);
	__u8 ncc = !!(fid_support & NVME_FID_SUPPORTED_EFFECTS_NCC);
	__u8 nic = !!(fid_support & NVME_FID_SUPPORTED_EFFECTS_NIC);
	__u8 ccc = !!(fid_support & NVME_FID_SUPPORTED_EFFECTS_CCC);
	__u8 uss = !!(fid_support & NVME_FID_SUPPORTED_EFFECTS_UUID_SEL);
	__u16 fsp = NVME_GET(fid_support, FID_SUPPORTED_EFFECTS_SCOPE);
	__u8 ns_scope = !!(fsp & NVME_FID_SUPPORTED_EFFECTS_SCOPE_NS);
	__u8 ctrl_scope = !!(fsp & NVME_FID_SUPPORTED_EFFECTS_SCOPE_CTRL);
	__u8 nvmset_scope = !!(fsp & NVME_FID_SUPPORTED_EFFECTS_SCOPE_NVM_SET);
	__u8 endgrp_scope = !!(fsp & NVME_FID_SUPPORTED_EFFECTS_SCOPE_ENDGRP);
	__u8 domain_scope = !!(fsp & NVME_FID_SUPPORTED_EFFECTS_SCOPE_DOMAIN);
	__u8 nss_scope = !!(fsp & NVME_FID_SUPPORTED_EFFECTS_SCOPE_NSS);

	t = stdout_bits_table_create();
	if (!t)
		return NULL;

	stdout_bits_add(t, "[0:0]", fsupp, "Command %sSupported",
			fsupp ? "" : "Not ");
	stdout_bits_add(t, "[1:1]", udcc, "Logical Block Content %sChanged",
			udcc ? "" : "Not ");
	stdout_bits_add(t, "[2:2]", ncc, "Namespace Capabilities %sChanged",
			ncc ? "" : "Not ");
	stdout_bits_add(t, "[3:3]", nic, "Namespace Inventory %sChanged",
			nic ? "" : "Not ");
	stdout_bits_add(t, "[4:4]", ccc, "Controller Capabilities %sChanged",
			ccc ? "" : "Not ");
	stdout_bits_add(t, "[19:19]", uss, "UUID Selection %sSupported",
			uss ? "" : "Not ");
	stdout_bits_add(t, "[20:20]", ns_scope, "Namespace Scope %sIndicated",
			ns_scope ? "" : "Not ");
	stdout_bits_add(t, "[21:21]", ctrl_scope,
			"Controller Scope %sIndicated",
			ctrl_scope ? "" : "Not ");
	stdout_bits_add(t, "[22:22]", nvmset_scope, "NVM Set Scope %sIndicated",
			nvmset_scope ? "" : "Not ");
	stdout_bits_add(t, "[23:23]", endgrp_scope,
			"Endurance Group Scope %sIndicated",
			endgrp_scope ? "" : "Not ");
	stdout_bits_add(t, "[24:24]", domain_scope, "Domain Scope %sIndicated",
			domain_scope ? "" : "Not ");
	stdout_bits_add(t, "[25:25]", nss_scope,
			"NVM Subsystem Scope %sIndicated",
			nss_scope ? "" : "Not ");

	return t;
}

static void stdout_fid_support_effects_log(struct nvme_fid_supported_effects_log *fid_log,
					   const char *devname)
{
	struct shr_table *t;
	__u32 fid_effect;
	int i, row, human = stdout_print_ops.flags & VERBOSE;

	printf("FID Supports Effects Log for device: %s\n", devname);
	printf("Admin Command Set\n");

	t = stdout_kv_table_create();
	if (!t)
		return;

	for (i = 0; i < 256; i++) {
		char name[48];

		fid_effect = le32_to_cpu(fid_log->fid_support[i]);
		if (!(fid_effect & NVME_FID_SUPPORTED_EFFECTS_FSUPP))
			continue;

		snprintf(name, sizeof(name), "FID %02x -> Support Effects Log",
			 i);
		row = stdout_kv_add(t, name, "%08x", fid_effect);
		if (human)
			shr_table_set_row_subtable(t, row,
				stdout_fid_support_effects_log_human_table(
					fid_effect));
	}

	stdout_kv_table_finish(t, "fid-support-effects-log");
}

static struct shr_table *
stdout_mi_cmd_support_effects_log_human_table(__u32 mi_cmd_support)
{
	struct shr_table *t;
	__u8 csupp = !!(mi_cmd_support & NVME_MI_CMD_SUPPORTED_EFFECTS_CSUPP);
	__u8 udcc = !!(mi_cmd_support & NVME_MI_CMD_SUPPORTED_EFFECTS_UDCC);
	__u8 ncc = !!(mi_cmd_support & NVME_MI_CMD_SUPPORTED_EFFECTS_NCC);
	__u8 nic = !!(mi_cmd_support & NVME_MI_CMD_SUPPORTED_EFFECTS_NIC);
	__u8 ccc = !!(mi_cmd_support & NVME_MI_CMD_SUPPORTED_EFFECTS_CCC);
	__u16 csp = NVME_GET(mi_cmd_support, MI_CMD_SUPPORTED_EFFECTS_SCOPE);
	__u8 ns_scope = !!(csp & NVME_MI_CMD_SUPPORTED_EFFECTS_SCOPE_NS);
	__u8 ctrl_scope = !!(csp & NVME_MI_CMD_SUPPORTED_EFFECTS_SCOPE_CTRL);
	__u8 nvmset_scope =
		!!(csp & NVME_MI_CMD_SUPPORTED_EFFECTS_SCOPE_NVM_SET);
	__u8 endgrp_scope =
		!!(csp & NVME_MI_CMD_SUPPORTED_EFFECTS_SCOPE_ENDGRP);
	__u8 domain_scope =
		!!(csp & NVME_MI_CMD_SUPPORTED_EFFECTS_SCOPE_DOMAIN);
	__u8 nss_scope = !!(csp & NVME_MI_CMD_SUPPORTED_EFFECTS_SCOPE_NSS);

	t = stdout_bits_table_create();
	if (!t)
		return NULL;

	stdout_bits_add(t, "[0:0]", csupp, "Command %sSupported",
			csupp ? "" : "Not ");
	stdout_bits_add(t, "[1:1]", udcc, "Logical Block Content %sChanged",
			udcc ? "" : "Not ");
	stdout_bits_add(t, "[2:2]", ncc, "Namespace Capabilities %sChanged",
			ncc ? "" : "Not ");
	stdout_bits_add(t, "[3:3]", nic, "Namespace Inventory %sChanged",
			nic ? "" : "Not ");
	stdout_bits_add(t, "[4:4]", ccc, "Controller Capabilities %sChanged",
			ccc ? "" : "Not ");
	stdout_bits_add(t, "[20:20]", ns_scope, "Namespace Scope %sIndicated",
			ns_scope ? "" : "Not ");
	stdout_bits_add(t, "[21:21]", ctrl_scope,
			"Controller Scope %sIndicated",
			ctrl_scope ? "" : "Not ");
	stdout_bits_add(t, "[22:22]", nvmset_scope, "NVM Set Scope %sIndicated",
			nvmset_scope ? "" : "Not ");
	stdout_bits_add(t, "[23:23]", endgrp_scope,
			"Endurance Group Scope %sIndicated",
			endgrp_scope ? "" : "Not ");
	stdout_bits_add(t, "[24:24]", domain_scope, "Domain Scope %sIndicated",
			domain_scope ? "" : "Not ");
	stdout_bits_add(t, "[25:25]", nss_scope,
			"NVM Subsystem Scope %sIndicated",
			nss_scope ? "" : "Not ");

	return t;
}

static void stdout_mi_cmd_support_effects_log(struct nvme_mi_cmd_supported_effects_log *mi_cmd_log,
					      const char *devname)
{
	struct shr_table *t;
	__u32 mi_cmd_effect;
	int i, row, human = stdout_print_ops.flags & VERBOSE;

	printf("MI Commands Support Effects Log for device: %s\n", devname);
	printf("Admin Command Set\n");

	t = stdout_kv_table_create();
	if (!t)
		return;

	for (i = 0; i < NVME_LOG_MI_CMD_SUPPORTED_EFFECTS_MAX; i++) {
		char name[48];

		mi_cmd_effect = le32_to_cpu(mi_cmd_log->mi_cmd_support[i]);
		if (!(mi_cmd_effect & NVME_MI_CMD_SUPPORTED_EFFECTS_CSUPP))
			continue;

		snprintf(name, sizeof(name),
			 "MI CMD %02x -> Support Effects Log", i);
		row = stdout_kv_add(t, name, "%08x", mi_cmd_effect);
		if (human)
			shr_table_set_row_subtable(t, row,
				stdout_mi_cmd_support_effects_log_human_table(
					mi_cmd_effect));
	}

	stdout_kv_table_finish(t, "mi-cmd-support-effects-log");
}

static void stdout_boot_part_log(void *bp_log, const char *devname,
				 __u32 size)
{
	struct nvme_boot_partition *hdr = bp_log;
	struct shr_table *t;

	printf("Boot Partition Log for device: %s\n", devname);

	t = stdout_kv_table_create();
	if (!t)
		return;

	stdout_kv_add(t, "Log ID", "%u", hdr->lid);
	stdout_kv_add(t, "Boot Partition Size", "%u KiB",
		      NVME_BOOT_PARTITION_INFO_BPSZ(le32_to_cpu(hdr->bpinfo)));
	stdout_kv_add(t, "Active BPID", "%u",
		      NVME_BOOT_PARTITION_INFO_ABPID(le32_to_cpu(hdr->bpinfo)));

	stdout_kv_table_finish(t, "boot-part-log");
}

static const char *eomip_to_string(__u8 eomip)
{
	const char *string;

	switch (eomip) {
	case NVME_PHY_RX_EOM_NOT_STARTED:
		string = "Not Started";
		break;
	case NVME_PHY_RX_EOM_IN_PROGRESS:
		string = "In Progress";
		break;
	case NVME_PHY_RX_EOM_COMPLETED:
		string = "Completed";
		break;
	default:
		string = "Unknown";
		break;
	}
	return string;
}

static struct shr_table *stdout_phy_rx_eom_odp_table(uint8_t odp)
{
	struct shr_table *t;
	__u8 rsvd = NVME_EOM_ODP_RSVD(odp);
	__u8 edfp = NVME_EOM_ODP_EDFP(odp);
	__u8 pefp = NVME_EOM_ODP_PEFP(odp);

	t = stdout_bits_table_create();
	if (!t)
		return NULL;

	if (rsvd)
		stdout_bits_add(t, "[7:2]", rsvd, "Reserved");
	stdout_bits_add(t, "[1:1]", edfp, "Eye Data Field %sPresent",
			edfp ? "" : "Not ");
	stdout_bits_add(t, "[0:0]", pefp, "Printable Eye Field %sPresent",
			pefp ? "" : "Not ");

	return t;
}

static void stdout_eom_printable_eye(struct nvme_eom_lane_desc *lane)
{
	char *eye = (char *)lane->eye_desc;
	size_t nrows = le16_to_cpu(lane->nrows);
	size_t ncols = le16_to_cpu(lane->ncols);
	size_t i, j;

	printf("Printable Eye:\n");
	for (i = 0; i < nrows; i++) {
		for (j = 0; j < ncols; j++)
			printf("%c", eye[i * ncols + j]);
		printf("\n");
	}
}

static void stdout_phy_rx_eom_descs(struct nvme_phy_rx_eom_log *log, size_t len)
{
	struct eom_desc_iter it;
	struct nvme_eom_lane_desc *desc;

	eom_desc_iter_init(&it, log, len);

	while ((desc = eom_desc_iter_next(&it))) {
		unsigned char *vsdata;
		uint16_t vsdatalen;
		struct shr_table *t;

		t = stdout_kv_table_create();
		if (!t)
			return;

		stdout_kv_add(t, "Measurement Status", "%s",
			      desc->mstatus ? "Successful" : "Not Successful");
		stdout_kv_add(t, "Lane", "%u", desc->lane);
		stdout_kv_add(t, "Eye", "%u", desc->eye);
		stdout_kv_add(t, "Top", "%u", le16_to_cpu(desc->top));
		stdout_kv_add(t, "Bottom", "%u", le16_to_cpu(desc->bottom));
		stdout_kv_add(t, "Left", "%u", le16_to_cpu(desc->left));
		stdout_kv_add(t, "Right", "%u", le16_to_cpu(desc->right));
		stdout_kv_add(t, "Number of Rows", "%u",
			      le16_to_cpu(desc->nrows));
		stdout_kv_add(t, "Number of Columns", "%u",
			      le16_to_cpu(desc->ncols));
		stdout_kv_add(t, "Eye Data Length", "%u", desc->edlen);

		stdout_kv_table_finish(t, "phy-rx-eom-descs");

		vsdata = eom_desc_iter_vsdata(&it, desc, &vsdatalen);
		if (!vsdata)
			continue;

		if (NVME_EOM_ODP_PEFP(log->odp))
			stdout_eom_printable_eye(desc);

		/* Eye Data field is vendor specific */
		if (vsdatalen == 0)
			continue;

		printf("Eye Data:\n");
		d(vsdata, vsdatalen, 16, 1);
		printf("\n");
	}
}

static void stdout_phy_rx_eom_log(struct nvme_phy_rx_eom_log *log, __u16 controller, size_t len)
{
	int human = stdout_print_ops.flags & VERBOSE;
	struct shr_table *t;
	int row;

	if (len < sizeof(*log))
		return;

	printf("Physical Interface Receiver Eye Opening Measurement Log for controller ID: %u\n", controller);

	t = stdout_kv_table_create();
	if (!t)
		return;

	stdout_kv_add(t, "Log ID", "%u", log->lid);
	stdout_kv_add(t, "EOM In Progress", "%s", eomip_to_string(log->eomip));
	stdout_kv_add(t, "Header Size", "%u", le16_to_cpu(log->hsize));
	stdout_kv_add(t, "Result Size", "%u", le32_to_cpu(log->rsize));
	stdout_kv_add(t, "EOM Data Generation Number", "%u", log->eomdgn);
	stdout_kv_add(t, "Log Revision", "%u", log->lr);
	row = stdout_kv_add(t, "Optional Data Present", "%u", log->odp);
	if (human)
		shr_table_set_row_subtable(t, row,
			stdout_phy_rx_eom_odp_table(log->odp));
	stdout_kv_add(t, "Lanes", "%u", log->lanes);
	stdout_kv_add(t, "Eyes Per Lane", "%u", log->epl);
	stdout_kv_add(t, "Log Specific Parameter Field Copy", "%u", log->lspfc);
	stdout_kv_add(t, "Link Information", "%u", log->li);
	stdout_kv_add(t, "Log Specific Identifier Copy", "%u",
		      le16_to_cpu(log->lsic));
	stdout_kv_add(t, "Descriptor Size", "%u", le32_to_cpu(log->dsize));
	stdout_kv_add(t, "Number of Descriptors", "%u", le16_to_cpu(log->nd));
	stdout_kv_add(t, "Maximum Top Bottom", "%u", le16_to_cpu(log->maxtb));
	stdout_kv_add(t, "Maximum Left Right", "%u", le16_to_cpu(log->maxlr));
	stdout_kv_add(t, "Estimated Time for Good Quality", "%u",
		      le16_to_cpu(log->etgood));
	stdout_kv_add(t, "Estimated Time for Better Quality", "%u",
		      le16_to_cpu(log->etbetter));
	stdout_kv_add(t, "Estimated Time for Best Quality", "%u",
		      le16_to_cpu(log->etbest));

	stdout_kv_table_finish(t, "phy-rx-eom-log");

	if (log->eomip == NVME_PHY_RX_EOM_COMPLETED)
		stdout_phy_rx_eom_descs(log, len);
}

static void stdout_media_unit_stat_log(struct nvme_media_unit_stat_log *mus_log)
{
	int i;
	int nmu = le16_to_cpu(mus_log->nmu);
	struct shr_table *t;

	t = stdout_kv_table_create();
	if (!t)
		return;

	stdout_kv_add(t, "Number of Media Unit Status Descriptors", "%u", nmu);
	stdout_kv_add(t, "Number of Channels", "%u",
		      le16_to_cpu(mus_log->cchans));
	stdout_kv_add(t, "Selected Configuration", "%u",
		      le16_to_cpu(mus_log->sel_config));

	stdout_kv_table_finish(t, "media-unit-stat-log");

	for (i = 0; i < nmu; i++) {
		printf("Media Unit Status Descriptor: %u\n", i);

		t = stdout_kv_table_create();
		if (!t)
			return;

		stdout_kv_add(t, "Media Unit Identifier", "%u",
			      le16_to_cpu(mus_log->mus_desc[i].muid));
		stdout_kv_add(t, "Domain Identifier", "%u",
			      le16_to_cpu(mus_log->mus_desc[i].domainid));
		stdout_kv_add(t, "Endurance Group Identifier", "%u",
			      le16_to_cpu(mus_log->mus_desc[i].endgid));
		stdout_kv_add(t, "NVM Set Identifier", "%u",
			      le16_to_cpu(mus_log->mus_desc[i].nvmsetid));
		stdout_kv_add(t, "Capacity Adjustment Factor", "%u",
			      le16_to_cpu(mus_log->mus_desc[i].cap_adj_fctr));
		stdout_kv_add(t, "Available Spare", "%u",
			      mus_log->mus_desc[i].avl_spare);
		stdout_kv_add(t, "Percentage Used", "%u",
			      mus_log->mus_desc[i].percent_used);
		stdout_kv_add(t, "Number of Channels", "%u",
			      mus_log->mus_desc[i].mucs);
		stdout_kv_add(t, "Channel Identifiers Offset", "%u",
			      mus_log->mus_desc[i].cio);

		stdout_kv_table_finish(t, "media-unit-stat-log");
	}
}

static struct shr_table *stdout_fdp_config_fdpa_table(uint8_t fdpa)
{
	struct shr_table *t;
	__u8 valid = NVME_GET(fdpa, FDP_CONFIG_FDPA_VALID);
	__u8 rsvd = (fdpa >> 5) & 0x3;
	__u8 fdpvwc = NVME_GET(fdpa, FDP_CONFIG_FDPA_FDPVWC);
	__u8 rgif = NVME_GET(fdpa, FDP_CONFIG_FDPA_RGIF);

	t = stdout_bits_table_create();
	if (!t)
		return NULL;

	stdout_bits_add(t, "[7:7]", valid, "FDP Configuration %sValid",
			valid ? "" : "Not ");
	if (rsvd)
		stdout_bits_add(t, "[6:5]", rsvd, "Reserved");
	stdout_bits_add(t, "[4:4]", fdpvwc,
			"FDP Volatile Write Cache %sPresent",
			fdpvwc ? "" : "Not ");
	stdout_bits_add(t, "[3:0]", rgif, "Reclaim Group Identifier Format");

	return t;
}

static struct shr_table *stdout_fdp_config_ruh_list_table(
		struct nvme_fdp_config_desc *config, uint16_t nruh)
{
	struct shr_table *t;

	t = stdout_kv_table_create();
	if (!t)
		return NULL;

	shr_table_set_indent(t, 2);

	for (int j = 0; j < nruh; j++) {
		struct nvme_fdp_ruh_desc *ruh = &config->ruhs[j];
		const char *ruht_str;
		char name[16];

		if (ruh->ruht == NVME_FDP_RUHT_INITIALLY_ISOLATED)
			ruht_str = "Initially Isolated";
		else
			ruht_str = "Persistently Isolated";

		snprintf(name, sizeof(name), "[%d]", j);
		stdout_kv_add(t, name, "%s", ruht_str);
	}

	return t;
}

static void stdout_fdp_configs(struct nvme_fdp_config_log *log, size_t len)
{
	unsigned char *p, *end;
	int human = stdout_print_ops.flags & VERBOSE;
	uint16_t n;
	struct shr_table *t;
	int row;

	if (len < sizeof(*log))
		return;

	p = (unsigned char *)log->configs;
	end = (unsigned char *)log + len;
	n = le16_to_cpu(log->n) + 1;

	for (int i = 0; i < n; i++) {
		struct nvme_fdp_config_desc *config = (struct nvme_fdp_config_desc *)p;
		uint16_t size, nruh, max_nruh;

		if (!shr_buf_has_room(p, end, sizeof(*config)))
			break;

		t = stdout_kv_table_create();
		if (!t)
			return;

		row = stdout_kv_add(t, "FDP Attributes", "%#x", config->fdpa);
		if (human)
			shr_table_set_row_subtable(t, row,
				stdout_fdp_config_fdpa_table(config->fdpa));

		stdout_kv_add(t, "Vendor Specific Size", "%u", config->vss);
		stdout_kv_add(t, "Number of Reclaim Groups", "%"PRIu32,
			      le32_to_cpu(config->nrg));
		stdout_kv_add(t, "Number of Reclaim Unit Handles", "%"PRIu16,
			      le16_to_cpu(config->nruh));
		stdout_kv_add(t, "Number of Namespaces Supported", "%"PRIu32,
			      le32_to_cpu(config->nnss));
		stdout_kv_add(t, "Reclaim Unit Nominal Size", "%"PRIu64,
			      le64_to_cpu(config->runs));
		stdout_kv_add(t, "Estimated Reclaim Unit Time Limit", "%"PRIu32,
			      le32_to_cpu(config->erutl));

		size = le16_to_cpu(config->size);
		if (size < sizeof(*config) || !shr_buf_has_room(p, end, size)) {
			stdout_kv_table_finish(t, "fdp-configs");
			break;
		}

		nruh = le16_to_cpu(config->nruh);
		max_nruh = (size - sizeof(*config)) / sizeof(struct nvme_fdp_ruh_desc);
		if (nruh > max_nruh)
			nruh = max_nruh;

		if (nruh) {
			row = stdout_kv_add(t, "Reclaim Unit Handle List", "");
			shr_table_set_row_subtable(t, row,
				stdout_fdp_config_ruh_list_table(config, nruh));
		}

		stdout_kv_table_finish(t, "fdp-configs");

		p += size;
	}
}

static void stdout_fdp_usage(struct nvme_fdp_ruhu_log *log, size_t len)
{
	uint16_t nruh = le16_to_cpu(log->nruh);
	struct shr_table *t;

	t = stdout_kv_table_create();
	if (!t)
		return;

	for (int i = 0; i < nruh; i++) {
		struct nvme_fdp_ruhu_desc *ruhu = &log->ruhus[i];
		const char *ruha_str;
		char name[40];

		switch (ruhu->ruha) {
		case 0x0:
			ruha_str = "Unused";
			break;
		case 0x1:
			ruha_str = "Host Specified";
			break;
		case 0x2:
			ruha_str = "Controller Specified";
			break;
		default:
			ruha_str = "Unknown";
			break;
		}

		snprintf(name, sizeof(name),
			 "Reclaim Unit Handle %d Attributes", i);
		stdout_kv_add(t, name, "%#"PRIx8" (%s)", ruhu->ruha, ruha_str);
	}

	stdout_kv_table_finish(t, "fdp-usage");
}

static void stdout_fdp_stats(struct nvme_fdp_stats_log *log)
{
	struct shr_table *t;

	t = stdout_kv_table_create();
	if (!t)
		return;

	stdout_kv_add(t, "Host Bytes with Metadata Written (HBMW)", "%s",
		      uint128_t_to_l10n_string(le128_to_cpu(log->hbmw)));
	stdout_kv_add(t, "Media Bytes with Metadata Written (MBMW)", "%s",
		      uint128_t_to_l10n_string(le128_to_cpu(log->mbmw)));
	stdout_kv_add(t, "Media Bytes Erased (MBE)", "%s",
		      uint128_t_to_l10n_string(le128_to_cpu(log->mbe)));

	stdout_kv_table_finish(t, "fdp-stats");
}

static void stdout_fdp_events(struct nvme_fdp_events_log *log)
{
	struct tm *tm;
	char buffer[320];
	time_t ts;
	uint32_t n = le32_to_cpu(log->n);
	struct shr_table *t;

	for (unsigned int i = 0; i < n; i++) {
		struct nvme_fdp_event *event = &log->events[i];

		ts = int48_to_long(event->ts.timestamp) / 1000;
		tm = localtime(&ts);

		printf("Event[%u]\n", i);

		t = stdout_kv_table_create();
		if (!t)
			return;

		shr_table_set_indent(t, 2);

		stdout_kv_add(t, "Event Type", "%#"PRIx8" (%s)", event->type,
			      nvme_fdp_event_to_string(event->type));
		stdout_kv_add(t, "Event Timestamp", "%"PRIu64" (%s)",
			      int48_to_long(event->ts.timestamp),
			      strftime(buffer, sizeof(buffer), "%c %Z", tm) ?
			      buffer : "-");

		if (event->flags & NVME_FDP_EVENT_F_PIV)
			stdout_kv_add(t, "Placement Identifier (PID)",
				      "%#"PRIx16, le16_to_cpu(event->pid));

		if (event->flags & NVME_FDP_EVENT_F_NSIDV)
			stdout_kv_add(t, "Namespace Identifier (NSID)",
				      "%"PRIu32, le32_to_cpu(event->nsid));

		if (event->type == NVME_FDP_EVENT_REALLOC) {
			struct nvme_fdp_event_realloc *mr;

			mr = (struct nvme_fdp_event_realloc *)&event->type_specific;

			stdout_kv_add(t, "Number of LBAs Moved (NLBAM)",
				      "%"PRIu16, le16_to_cpu(mr->nlbam));

			if (mr->flags & NVME_FDP_EVENT_REALLOC_F_LBAV)
				stdout_kv_add(t, "Logical Block Address (LBA)",
					      "%#"PRIx64,
					      le64_to_cpu(mr->lba));
		}

		if (event->flags & NVME_FDP_EVENT_F_LV) {
			stdout_kv_add(t, "Reclaim Group Identifier", "%"PRIu16,
				      le16_to_cpu(event->rgid));
			stdout_kv_add(t, "Reclaim Unit Handle Identifier",
				      "%"PRIu8, event->ruhid);
		}

		stdout_kv_table_finish(t, "fdp-events");

		printf("\n");
	}
}

static void stdout_fdp_ruh_status(struct nvme_fdp_ruh_status *status, size_t len)
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

static void stdout_supported_cap_config_add_channels(struct shr_table *t,
		struct nvme_end_grp_chan_desc *chan_desc)
{
	int egchans = le16_to_cpu(chan_desc->egchans);

	stdout_kv_add(t, "Number of Channels", "%u", egchans);

	for (int l = 0; l < egchans; l++) {
		struct nvme_channel_config_desc *chd =
			&chan_desc->chan_config_desc[l];
		int chmus = le16_to_cpu(chd->chmus);

		stdout_kv_add(t, "Channel Identifier", "%u",
			      le16_to_cpu(chd->chanid));
		stdout_kv_add(t, "Number of Channel Media Units", "%u", chmus);

		for (int m = 0; m < chmus; m++) {
			struct nvme_media_unit_config_desc *mu =
				&chd->mu_config_desc[m];

			stdout_kv_add(t, "Media Unit Identifier", "%u",
				      le16_to_cpu(mu->muid));
			stdout_kv_add(t, "Media Unit Descriptor Length", "%u",
				      le16_to_cpu(mu->mudl));
		}
	}
}

static void stdout_supported_cap_config_add_egcd(struct shr_table *t,
		struct nvme_supported_cap_config_list_log *cap, int i)
{
	struct nvme_end_grp_chan_desc *chan_desc;
	int egcn = le16_to_cpu(cap->cap_config_desc[i].egcn);

	stdout_kv_add(t, "Number of Endurance Group Configuration Descriptors",
		      "%u", egcn);

	for (int j = 0; j < egcn; j++) {
		struct nvme_end_grp_config_desc *egcd =
			&cap->cap_config_desc[i].egcd[j];
		int egsets = le16_to_cpu(egcd->egsets);

		stdout_kv_add(t, "Endurance Group Identifier", "%u",
			      le16_to_cpu(egcd->endgid));
		stdout_kv_add(t, "Capacity Adjustment Factor", "%u",
			      le16_to_cpu(egcd->cap_adj_factor));
		stdout_kv_add(t, "Total Endurance Group Capacity", "%s",
			      uint128_t_to_l10n_string(
				      le128_to_cpu(egcd->tegcap)));
		stdout_kv_add(t, "Spare Endurance Group Capacity", "%s",
			      uint128_t_to_l10n_string(
				      le128_to_cpu(egcd->segcap)));
		stdout_kv_add(t, "Endurance Estimate", "%s",
			      uint128_t_to_l10n_string(
				      le128_to_cpu(egcd->end_est)));
		stdout_kv_add(t, "Number of NVM Sets", "%u", egsets);

		for (int k = 0; k < egsets; k++) {
			char name[32];

			snprintf(name, sizeof(name),
				 "NVM Set %d Identifier", i);
			stdout_kv_add(t, name, "%u",
				      le16_to_cpu(egcd->nvmsetid[k]));
		}

		chan_desc = (struct nvme_end_grp_chan_desc *)
			&egcd->nvmsetid[egsets];
		stdout_supported_cap_config_add_channels(t, chan_desc);
	}
}

static void stdout_supported_cap_config_log(
		struct nvme_supported_cap_config_list_log *cap)
{
	int sccn = cap->sccn;
	struct shr_table *t;

	t = stdout_kv_table_create();
	if (!t)
		return;

	stdout_kv_add(t, "Number of Supported Capacity Configurations", "%u",
		      sccn);

	stdout_kv_table_finish(t, "supported-cap-config");

	for (int i = 0; i < sccn; i++) {
		printf("Capacity Configuration Descriptor: %u\n", i);

		t = stdout_kv_table_create();
		if (!t)
			return;

		stdout_kv_add(t, "Capacity Configuration Identifier", "%u",
			      le16_to_cpu(
				      cap->cap_config_desc[i].cap_config_id));
		stdout_kv_add(t, "Domain Identifier", "%u",
			      le16_to_cpu(cap->cap_config_desc[i].domainid));

		stdout_supported_cap_config_add_egcd(t, cap, i);

		stdout_kv_table_finish(t, "supported-cap-config");
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

static void stdout_subsys_config(struct libnvme_subsystem *s, bool show_iopolicy)
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

static int stdout_kv_add(struct shr_table *t, const char *name,
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
static struct shr_table *stdout_kv_table_create(void)
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
static void stdout_bits_add_str(struct shr_table *t, const char *bits,
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
static void stdout_bits_add(struct shr_table *t, const char *bits,
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
static struct shr_table *stdout_bits_table_create(void)
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
static void stdout_kv_table_finish(struct shr_table *t, const char *what)
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

static struct shr_table *stdout_ctrl_register_human_table(int offset,
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

static void stdout_ctrl_register_common(int offset, uint64_t value, bool fabrics)
{
	bool human = !!(stdout_print_ops.flags & VERBOSE);
	const char *name = nvme_register_to_string(offset);
	const char *type = fabrics ? "property" : "register";
	struct shr_table *t;
	int row;

	t = stdout_kv_table_create();
	if (!t)
		return;

	if (human) {
		row = stdout_kv_add(t, name, "%#"PRIx64, value);
		shr_table_set_row_subtable(t, row,
				stdout_ctrl_register_human_table(offset, value,
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
		bool fabrics, int offset, bool human, bool support)
{
	uint64_t value = nvme_is_64bit_reg(offset) ? shr_mmio_read64(bar + offset) :
	    shr_mmio_read32(bar + offset);
	int row;

	if (fabrics && value == -1)
		return;

	row = stdout_kv_add(t, nvme_register_symbol_to_string(offset),
			     "%#"PRIx64, value);
	if (human)
		shr_table_set_row_subtable(t, row,
				stdout_ctrl_register_human_table(offset, value,
								  support));
}

void stdout_ctrl_registers(void *bar, bool fabrics)
{
	uint32_t value;
	bool human = !!(stdout_print_ops.flags & VERBOSE);
	struct shr_table *t;
	int offset;
	bool support;

	t = stdout_kv_table_create();
	if (!t)
		return;

	for (offset = NVME_REG_CAP; offset <= NVME_REG_PMRMSCU; offset += get_reg_size(offset)) {
		if (!nvme_is_ctrl_reg(offset) || (fabrics && !nvme_is_fabrics_reg(offset)))
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
		stdout_ctrl_register_support(t, bar, fabrics, offset, human,
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
			libnvme_opcode_status_to_string(val, admin, opcode), val);
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

static struct shr_table *stdout_id_ctrl_cmic_table(__u8 cmic)
{
	struct shr_table *t;
	__u8 rsvd = NVME_CMIC_MULTI_RSVD(cmic);
	__u8 ana = NVME_CMIC_MULTI_ANA(cmic);
	__u8 sriov = NVME_CMIC_MULTI_SRIOV(cmic);
	__u8 mctl = NVME_CMIC_MULTI_CTRL(cmic);
	__u8 mp = NVME_CMIC_MULTI_PORT(cmic);

	t = stdout_bits_table_create();
	if (!t)
		return NULL;

	if (rsvd)
		stdout_bits_add(t, "[7:4]", rsvd, "Reserved");
	stdout_bits_add(t, "[3:3]", ana,
			 ana ? "ANA supported" : "ANA not supported");
	stdout_bits_add(t, "[2:2]", sriov, sriov ? "SR-IOV" : "PCI");
	stdout_bits_add(t, "[1:1]", mctl,
			 mctl ? "Multi Controller" : "Single Controller");
	stdout_bits_add(t, "[0:0]", mp, mp ? "Multi Port" : "Single Port");

	return t;
}

static struct shr_table *stdout_id_ctrl_oaes_table(__le32 ctrl_oaes)
{
	struct shr_table *t;
	__u32 oaes = le32_to_cpu(ctrl_oaes);
	__u32 dlpcn = NVME_CTRL_OAES_DLPCN(oaes);
	__u32 rsvd28 = (oaes & 0x70000000) >> 28;
	__u32 zdcn = NVME_CTRL_OAES_ZDCN(oaes);
	__u32 rsvd23 = (oaes >> 23) & 0xf;
	__u32 rlcc = NVME_CTRL_OAES_RLCC(oaes);
	__u32 rsvd20 = (oaes >> 20) & 0x3;
	__u32 ansan = NVME_CTRL_OAES_ANSAN(oaes);
	__u32 rsvd18 = (oaes >> 18) & 0x1;
	__u32 rgcns = NVME_CTRL_OAES_RGCNS(oaes);
	__u32 tthr = NVME_CTRL_OAES_TTHR(oaes);
	__u32 normal_shn = NVME_CTRL_OAES_NNVMSS(oaes);
	__u32 egealpcn = NVME_CTRL_OAES_EGEALPCN(oaes);
	__u32 lbasin = NVME_CTRL_OAES_LBASIAN(oaes);
	__u32 plealcn = NVME_CTRL_OAES_PLEALCN(oaes);
	__u32 anacn = NVME_CTRL_OAES_ANACN(oaes);
	__u32 rsvd10 = (oaes >> 10) & 0x1;
	__u32 fan = NVME_CTRL_OAES_FAN(oaes);
	__u32 nace = NVME_CTRL_OAES_NSAN(oaes);
	__u32 rsvd0 = oaes & 0xFF;

	t = stdout_bits_table_create();
	if (!t)
		return NULL;

	stdout_bits_add(t, "[31:31]", dlpcn,
			"Discovery Log Change Notice %sSupported",
			dlpcn ? "" : "Not ");
	if (rsvd28)
		stdout_bits_add(t, "[30:28]", rsvd28, "Reserved");
	stdout_bits_add(t, "[27:27]", zdcn,
			"Zone Descriptor Changed Notices %sSupported",
			zdcn ? "" : "Not ");
	if (rsvd23)
		stdout_bits_add(t, "[26:23]", rsvd23, "Reserved");
	stdout_bits_add(t, "[22:22]", rlcc,
			"Rate Limiting Configuration Change Notices %sSupported",
			rlcc ? "" : "Not ");
	if (rsvd20)
		stdout_bits_add(t, "[21:20]", rsvd20, "Reserved");
	stdout_bits_add(t, "[19:19]", ansan,
			"Allocated Namespace Attribute Notices %sSupported",
			ansan ? "" : "Not ");
	if (rsvd18)
		stdout_bits_add(t, "[18:18]", rsvd18, "Reserved");
	stdout_bits_add(t, "[17:17]", rgcns,
			"Reachability Groups Change Notices %sSupported",
			rgcns ? "" : "Not ");
	stdout_bits_add(t, "[16:16]", tthr,
			"Temperature Threshold Hysteresis Recovery %sSupported",
			tthr ? "" : "Not ");
	stdout_bits_add(t, "[15:15]", normal_shn,
			"Normal NSS Shutdown Event %sSupported",
			normal_shn ? "" : "Not ");
	stdout_bits_add(t, "[14:14]", egealpcn,
			"Endurance Group Event Aggregate Log Page Change Notice %sSupported",
			egealpcn ? "" : "Not ");
	stdout_bits_add(t, "[13:13]", lbasin,
			"LBA Status Information Notices %sSupported",
			lbasin ? "" : "Not ");
	stdout_bits_add(t, "[12:12]", plealcn,
			"Predictable Latency Event Aggregate Log Change Notices %sSupported",
			plealcn ? "" : "Not ");
	stdout_bits_add(t, "[11:11]", anacn,
			"Asymmetric Namespace Access Change Notices %sSupported",
			anacn ? "" : "Not ");
	if (rsvd10)
		stdout_bits_add(t, "[10:10]", rsvd10, "Reserved");
	stdout_bits_add(t, "[9:9]", fan,
			"Firmware Activation Notices %sSupported",
			fan ? "" : "Not ");
	stdout_bits_add(t, "[8:8]", nace,
			"Attached Namespace Attribute Changed Event %sSupported",
			nace ? "" : "Not ");
	if (rsvd0)
		stdout_bits_add(t, "[7:0]", rsvd0, "Reserved");

	return t;
}

static struct shr_table *stdout_id_ctrl_ctratt_table(__le32 ctrl_ctratt)
{
	struct shr_table *t;
	__u32 ctratt = le32_to_cpu(ctrl_ctratt);
	__u32 rsvd25 = (ctratt >> 25);
	__u32 iiellss = NVME_CTRL_CTRATT_IIELLSS(ctratt);
	__u32 vms = NVME_CTRL_CTRATT_VMS(ctratt);
	__u32 pms = NVME_CTRL_CTRATT_PMS(ctratt);
	__u32 pls = NVME_CTRL_CTRATT_PLS(ctratt);
	__u32 fdps = NVME_CTRL_CTRATT_FDPS(ctratt);
	__u32 rhii = NVME_CTRL_CTRATT_RHII(ctratt);
	__u32 hmbr = NVME_CTRL_CTRATT_HMBR(ctratt);
	__u32 mem = NVME_CTRL_CTRATT_MEM(ctratt);
	__u32 elbas = NVME_CTRL_CTRATT_ELBAS(ctratt);
	__u32 dnvms = NVME_CTRL_CTRATT_DNVMS(ctratt);
	__u32 deg = NVME_CTRL_CTRATT_DEG(ctratt);
	__u32 vcm = NVME_CTRL_CTRATT_VCM(ctratt);
	__u32 fcm = NVME_CTRL_CTRATT_FCM(ctratt);
	__u32 mds = NVME_CTRL_CTRATT_MDS(ctratt);
	__u32 ulist = NVME_CTRL_CTRATT_ULIST(ctratt);
	__u32 sqa = NVME_CTRL_CTRATT_SQA(ctratt);
	__u32 ng = NVME_CTRL_CTRATT_NG(ctratt);
	__u32 tbkas = NVME_CTRL_CTRATT_TBKAS(ctratt);
	__u32 plm = NVME_CTRL_CTRATT_PLM(ctratt);
	__u32 egs = NVME_CTRL_CTRATT_EGS(ctratt);
	__u32 rrlvls = NVME_CTRL_CTRATT_RRLVLS(ctratt);
	__u32 nsets = NVME_CTRL_CTRATT_NSETS(ctratt);
	__u32 nopspm = NVME_CTRL_CTRATT_NOPSPM(ctratt);
	__u32 hids = NVME_CTRL_CTRATT_HIDS(ctratt);

	t = stdout_bits_table_create();
	if (!t)
		return NULL;

	if (rsvd25)
		stdout_bits_add(t, "[31:25]", rsvd25, "Reserved");
	stdout_bits_add(t, "[24:23]", iiellss, "Idle I/O Exit Latency Limit %s",
			 !iiellss ? "Not Supported" :
			 iiellss == NVME_CTRL_CTRATT_IIELLSS_POWER_STATE ?
			 "Supported (Power state)" :
			 iiellss == NVME_CTRL_CTRATT_IIELLSS_GLOBAL ?
			 "Supported (Global)" : "Reserved");
	stdout_bits_add(t, "[22:22]", vms, "Voltage Measurement %sSupported",
			 vms ? "" : "Not ");
	stdout_bits_add(t, "[21:21]", pms, "Power Measurement %sSupported",
			 pms ? "" : "Not ");
	stdout_bits_add(t, "[20:20]", pls, "Power Limit %sSupported",
			 pls ? "" : "Not ");
	stdout_bits_add(t, "[19:19]", fdps,
			 "Flexible Data Placement %sSupported",
			 fdps ? "" : "Not ");
	stdout_bits_add(t, "[18:18]", rhii,
			 "Reservations and Host Identifier Interaction %sSupported",
			 rhii ? "" : "Not ");
	stdout_bits_add(t, "[17:17]", hmbr,
			 "HMB Restrict Non-Operational Power State Access %sSupported",
			 hmbr ? "" : "Not ");
	stdout_bits_add(t, "[16:16]", mem,
			 "MDTS and Size Limits Exclude Metadata %sSupported",
			 mem ? "" : "Not ");
	stdout_bits_add(t, "[15:15]", elbas, "Extended LBA Formats %sSupported",
			 elbas ? "" : "Not ");
	stdout_bits_add(t, "[14:14]", dnvms, "Delete NVM Set %sSupported",
			 dnvms ? "" : "Not ");
	stdout_bits_add(t, "[13:13]", deg, "Delete Endurance Group %sSupported",
			 deg ? "" : "Not ");
	stdout_bits_add(t, "[12:12]", vcm,
			 "Variable Capacity Management %sSupported",
			 vcm ? "" : "Not ");
	stdout_bits_add(t, "[11:11]", fcm,
			 "Fixed Capacity Management %sSupported",
			 fcm ? "" : "Not ");
	stdout_bits_add(t, "[10:10]", mds, "Multi Domain Subsystem %sSupported",
			 mds ? "" : "Not ");
	stdout_bits_add(t, "[9:9]", ulist, "UUID List %sSupported",
			 ulist ? "" : "Not ");
	stdout_bits_add(t, "[8:8]", sqa, "SQ Associations %sSupported",
			 sqa ? "" : "Not ");
	stdout_bits_add(t, "[7:7]", ng, "Namespace Granularity %sSupported",
			 ng ? "" : "Not ");
	stdout_bits_add(t, "[6:6]", tbkas,
			 "Traffic Based Keep Alive %sSupported",
			 tbkas ? "" : "Not ");
	stdout_bits_add(t, "[5:5]", plm, "Predictable Latency Mode %sSupported",
			 plm ? "" : "Not ");
	stdout_bits_add(t, "[4:4]", egs, "Endurance Groups %sSupported",
			 egs ? "" : "Not ");
	stdout_bits_add(t, "[3:3]", rrlvls, "Read Recovery Levels %sSupported",
			 rrlvls ? "" : "Not ");
	stdout_bits_add(t, "[2:2]", nsets, "NVM Sets %sSupported",
			 nsets ? "" : "Not ");
	stdout_bits_add(t, "[1:1]", nopspm,
			 "Non-Operational Power State Permissive %sSupported",
			 nopspm ? "" : "Not ");
	stdout_bits_add(t, "[0:0]", hids, "128-bit Host Identifier %sSupported",
			 hids ? "" : "Not ");

	return t;
}

static struct shr_table *stdout_id_ctrl_bpcap_table(__u8 ctrl_bpcap)
{
	struct shr_table *t;
	__u8 rsvd3 = (ctrl_bpcap >> 3);
	__u8 sfbpwps = NVME_GET(ctrl_bpcap, CTRL_BACAP_SFBPWPS);
	__u8 rpmbbpwps = NVME_GET(ctrl_bpcap, CTRL_BACAP_RPMBBPWPS);
	static const char * const rpmbbpwps_def[] = {
		"Support Not Specified",
		"Not Supported",
		"Supported"
	};

	t = stdout_bits_table_create();
	if (!t)
		return NULL;

	if (rsvd3)
		stdout_bits_add(t, "[7:3]", rsvd3, "Reserved");
	stdout_bits_add(t, "[2:2]", sfbpwps,
			 "Set Features Boot Partition Write Protection %sSupported",
			 sfbpwps ? "" : "Not ");
	stdout_bits_add(t, "[1:0]", rpmbbpwps,
			 "RPMB Boot Partition Write Protection %s",
			 rpmbbpwps_def[rpmbbpwps]);

	return t;
}

static struct shr_table *stdout_id_ctrl_chsi_table(__u8 ctrl_chsi)
{
	struct shr_table *t;
	__u8 rsvd1 = (ctrl_chsi >> 1);
	__u8 chs = NVME_CTRL_CHSI_CHS(ctrl_chsi);

	t = stdout_bits_table_create();
	if (!t)
		return NULL;

	if (rsvd1)
		stdout_bits_add(t, "[7:1]", rsvd1, "Reserved");
	stdout_bits_add(t, "[0:0]", chs,
			 "CXL HDM %sSupported", chs ? "" : "Not ");

	return t;
}

static struct shr_table *stdout_id_ctrl_rmdca_table(__u8 ctrl_rmdca)
{
	struct shr_table *t;
	__u8 rsvd3 = (ctrl_rmdca >> 3);
	__u8 rdccs = NVME_CTRL_RMDCA_RDCCS(ctrl_rmdca);
	__u8 rdncs = NVME_CTRL_RMDCA_RDNCS(ctrl_rmdca);
	__u8 rdscs = NVME_CTRL_RMDCA_RDSCS(ctrl_rmdca);

	t = stdout_bits_table_create();
	if (!t)
		return NULL;

	if (rsvd3)
		stdout_bits_add(t, "[7:3]", rsvd3, "Reserved");
	stdout_bits_add(t, "[2:2]", rdccs,
			 "Restore Default Capacity Management Configuration %sSupported",
			 rdccs ? "" : "Not ");
	stdout_bits_add(t, "[1:1]", rdncs,
			 "Restore Default Namespace Configuration %sSupported",
			 rdncs ? "" : "Not ");
	stdout_bits_add(t, "[0:0]", rdscs,
			 "Restore Default NVM Subsystem Configuration %sSupported",
			 rdscs ? "" : "Not ");

	return t;
}

static struct shr_table *stdout_id_ctrl_plsi_table(__u8 ctrl_plsi)
{
	struct shr_table *t;
	__u8 rsvd2 = (ctrl_plsi >> 2);
	__u8 plsfq = NVME_GET(ctrl_plsi, CTRL_PLSI_PLSFQ);
	__u8 plsepf = NVME_GET(ctrl_plsi, CTRL_PLSI_PLSEPF);

	t = stdout_bits_table_create();
	if (!t)
		return NULL;

	if (rsvd2)
		stdout_bits_add(t, "[7:2]", rsvd2, "Reserved");
	stdout_bits_add(t, "[1:1]", plsfq,
			 "Power Loss Signaling with Forced Quiescence %sSupported",
			 plsfq ? "" : "Not ");
	stdout_bits_add(t, "[0:0]", plsepf,
			 "Power Loss Signaling with Emergency Power Fail %sSupported",
			 plsepf ? "" : "Not ");

	return t;
}

static struct shr_table *stdout_id_ctrl_crcap_table(__u8 ctrl_crcap)
{
	struct shr_table *t;
	__u8 rsvd2 = (ctrl_crcap >> 2);
	__u8 rgidc = NVME_GET(ctrl_crcap, CTRL_CRCAP_RGIDC);
	__u8 rrsup = NVME_GET(ctrl_crcap, CTRL_CRCAP_RRSUP);

	t = stdout_bits_table_create();
	if (!t)
		return NULL;

	if (rsvd2)
		stdout_bits_add(t, "[7:2]", rsvd2, "Reserved");
	stdout_bits_add(t, "[1:1]", rgidc,
			 "RGRPID %s while the namespace is attached to any controller.",
			 rgidc ? "does not change" : "may change");
	stdout_bits_add(t, "[0:0]", rrsup, "Reachability Reporting %sSupported",
			 rrsup ? "" : "Not ");

	return t;
}

static struct shr_table *stdout_id_ctrl_cntrltype_table(__u8 cntrltype)
{
	struct shr_table *t;
	__u8 rsvd = (cntrltype & 0xFC) >> 2;
	__u8 cntrl = cntrltype & 0x3;

	static const char * const type[] = {
		"Controller type not reported",
		"I/O Controller",
		"Discovery Controller",
		"Administrative Controller"
	};

	t = stdout_bits_table_create();
	if (!t)
		return NULL;

	stdout_bits_add(t, "[7:2]", rsvd, "Reserved");
	stdout_bits_add(t, "[1:0]", cntrltype, "%s", type[cntrl]);

	return t;
}

static struct shr_table *stdout_id_ctrl_nvmsr_table(__u8 nvmsr)
{
	struct shr_table *t;
	__u8 rsvd = (nvmsr >> 2) & 0xfc;
	__u8 nvmee = NVME_CTRL_NVMSR_NVMEE(nvmsr);
	__u8 nvmesd = NVME_CTRL_NVMSR_NVMESD(nvmsr);

	t = stdout_bits_table_create();
	if (!t)
		return NULL;

	if (rsvd)
		stdout_bits_add(t, "[7:2]", rsvd, "Reserved");
	stdout_bits_add(t, "[1:1]", nvmee,
			 "NVM subsystem %spart of an Enclosure",
			 nvmee ? "" : "Not ");
	stdout_bits_add(t, "[0:0]", nvmesd,
			 "NVM subsystem %spart of a Storage Device",
			 nvmesd ? "" : "Not ");

	return t;
}

static struct shr_table *stdout_id_ctrl_vwci_table(__u8 vwci)
{
	struct shr_table *t;
	__u8 vwcrv = NVME_CTRL_VWCI_VWCRV(vwci);
	__u8 vwcr = NVME_CTRL_VWCI_VWCR(vwci);

	t = stdout_bits_table_create();
	if (!t)
		return NULL;

	stdout_bits_add(t, "[7:7]", vwcrv,
			 "VPD Write Cycles Remaining field is %svalid.",
			 vwcrv ? "" : "Not ");
	stdout_bits_add(t, "[6:0]", vwcr, "VPD Write Cycles Remaining");

	return t;
}

static struct shr_table *stdout_id_ctrl_mec_table(__u8 mec)
{
	struct shr_table *t;
	__u8 rsvd = (mec >> 2) & 0xfc;
	__u8 pcieme = (mec >> 1) & 0x1;
	__u8 smbusme = mec & 0x1;

	t = stdout_bits_table_create();
	if (!t)
		return NULL;

	if (rsvd)
		stdout_bits_add(t, "[7:2]", rsvd, "Reserved");
	stdout_bits_add(t, "[1:1]", pcieme,
			 "NVM subsystem %scontains a Management Endpoint on a PCIe port",
			 pcieme ? "" : "Not ");
	stdout_bits_add(t, "[0:0]", smbusme,
			 "NVM subsystem %scontains a Management Endpoint on an SMBus/I2C port",
			 smbusme ? "" : "Not ");

	return t;
}

static struct shr_table *stdout_id_ctrl_oacs_table(__le16 ctrl_oacs)
{
	struct shr_table *t;
	__u16 oacs = le16_to_cpu(ctrl_oacs);
	__u16 rsvd = (oacs & 0xC000) >> 14;
	__u16 rsvd12 = (oacs & 0x1000) >> 12;
	__u16 ccfls = NVME_CTRL_OACS_CCFLS(oacs);
	__u16 hmlms = NVME_CTRL_OACS_HMLMS(oacs);
	__u16 lock = NVME_CTRL_OACS_CFLS(oacs);
	__u16 glbas = NVME_CTRL_OACS_GLSS(oacs);
	__u16 dbc = NVME_CTRL_OACS_DBCS(oacs);
	__u16 vir = NVME_CTRL_OACS_VMS_M(oacs);
	__u16 nmi = NVME_CTRL_OACS_NSRS(oacs);
	__u16 dir = NVME_CTRL_OACS_DIRS(oacs);
	__u16 sft = NVME_CTRL_OACS_DSTS(oacs);
	__u16 nsm = NVME_CTRL_OACS_NMS_M(oacs);
	__u16 fwc = NVME_CTRL_OACS_FWDS(oacs);
	__u16 fmt = NVME_CTRL_OACS_FNVMS(oacs);
	__u16 sec = NVME_CTRL_OACS_SSRS(oacs);

	t = stdout_bits_table_create();
	if (!t)
		return NULL;

	if (rsvd)
		stdout_bits_add(t, "[15:14]", rsvd, "Reserved");
	stdout_bits_add(t, "[13:13]", ccfls,
			 "Ctrl-scoped Command/Feature Lockdown %sSupported",
			 ccfls ? "" : "Not ");
	if (rsvd12)
		stdout_bits_add(t, "[12:12]", rsvd12, "Reserved");
	stdout_bits_add(t, "[11:11]", hmlms,
			 "Host Managed Live Migration %sSupported",
			 hmlms ? "" : "Not ");
	stdout_bits_add(t, "[10:10]", lock,
			 "Lockdown Command and Feature %sSupported",
			 lock ? "" : "Not ");
	stdout_bits_add(t, "[9:9]", glbas,
			 "Get LBA Status Capability %sSupported",
			 glbas ? "" : "Not ");
	stdout_bits_add(t, "[8:8]", dbc, "Doorbell Buffer Config %sSupported",
			 dbc ? "" : "Not ");
	stdout_bits_add(t, "[7:7]", vir,
			 "Virtualization Management %sSupported",
			 vir ? "" : "Not ");
	stdout_bits_add(t, "[6:6]", nmi, "NVMe-MI Send and Receive %sSupported",
			 nmi ? "" : "Not ");
	stdout_bits_add(t, "[5:5]", dir, "Directives %sSupported",
			 dir ? "" : "Not ");
	stdout_bits_add(t, "[4:4]", sft, "Device Self-test %sSupported",
			 sft ? "" : "Not ");
	stdout_bits_add(t, "[3:3]", nsm,
			 "NS Management and Attachment %sSupported",
			 nsm ? "" : "Not ");
	stdout_bits_add(t, "[2:2]", fwc, "FW Commit and Download %sSupported",
			 fwc ? "" : "Not ");
	stdout_bits_add(t, "[1:1]", fmt, "Format NVM %sSupported",
			 fmt ? "" : "Not ");
	stdout_bits_add(t, "[0:0]", sec,
			 "Security Send and Receive %sSupported",
			 sec ? "" : "Not ");

	return t;
}

static struct shr_table *stdout_id_ctrl_frmw_table(__u8 frmw)
{
	struct shr_table *t;
	__u8 rsvd = (frmw & 0xC0) >> 6;
	__u8 smud = (frmw >> 5) & 0x1;
	__u8 fawr = (frmw & 0x10) >> 4;
	__u8 nfws = (frmw & 0xE) >> 1;
	__u8 s1ro = frmw & 0x1;

	t = stdout_bits_table_create();
	if (!t)
		return NULL;

	if (rsvd)
		stdout_bits_add(t, "[7:6]", rsvd, "Reserved");
	stdout_bits_add(t, "[5:5]", smud,
			 "Multiple FW or Boot Update Detection %sSupported",
			 smud ? "" : "Not ");
	stdout_bits_add(t, "[4:4]", fawr,
			 "Firmware Activate Without Reset %sSupported",
			 fawr ? "" : "Not ");
	stdout_bits_add(t, "[3:1]", nfws, "Number of Firmware Slots");
	stdout_bits_add(t, "[0:0]", s1ro, "Firmware Slot 1 Read%s",
			 s1ro ? "-Only" : "/Write");

	return t;
}

static struct shr_table *stdout_id_ctrl_lpa_table(__u8 lpa)
{
	struct shr_table *t;
	__u8 rsvd = (lpa & 0x80) >> 7;
	__u8 tel = (lpa >> 6) & 0x1;
	__u8 lid_sup = (lpa >> 5) & 0x1;
	__u8 persevnt = (lpa & 0x10) >> 4;
	__u8 telem = (lpa & 0x8) >> 3;
	__u8 ed = (lpa & 0x4) >> 2;
	__u8 celp = (lpa & 0x2) >> 1;
	__u8 smlp = lpa & 0x1;

	t = stdout_bits_table_create();
	if (!t)
		return NULL;

	if (rsvd)
		stdout_bits_add(t, "[7:7]", rsvd, "Reserved");
	stdout_bits_add(t, "[6:6]", tel,
			 "Telemetry Log Data Area 4 %sSupported",
			 tel ? "" : "Not ");
	stdout_bits_add(t, "[5:5]", lid_sup,
			 "LID 0x0, Scope of each command in LID 0x5, 0x12, 0x13 %sSupported",
			 lid_sup ? "" : "Not ");
	stdout_bits_add(t, "[4:4]", persevnt,
			 "Persistent Event log %sSupported",
			 persevnt ? "" : "Not ");
	stdout_bits_add(t, "[3:3]", telem,
			 "Telemetry host/controller initiated log page %sSupported",
			 telem ? "" : "Not ");
	stdout_bits_add(t, "[2:2]", ed,
			 "Extended data for Get Log Page %sSupported",
			 ed ? "" : "Not ");
	stdout_bits_add(t, "[1:1]", celp,
			 "Command Effects Log Page %sSupported",
			 celp ? "" : "Not ");
	stdout_bits_add(t, "[0:0]", smlp,
			 "SMART/Health Log Page per NS %sSupported",
			 smlp ? "" : "Not ");

	return t;
}

static struct shr_table *stdout_id_ctrl_elpe_table(__u8 elpe)
{
	struct shr_table *t;

	t = stdout_bits_table_create();
	if (!t)
		return NULL;

	stdout_bits_add(t, "[7:0]", elpe,
			 "Error Log Page Entries (ELPE), 0's based");

	return t;
}

static struct shr_table *stdout_id_ctrl_npss_table(__u8 npss)
{
	struct shr_table *t;

	t = stdout_bits_table_create();
	if (!t)
		return NULL;

	stdout_bits_add(t, "[7:0]", npss,
			 "Number of Power States Support (NPSS), 0's based");

	return t;
}

static struct shr_table *stdout_id_ctrl_avscc_table(__u8 avscc)
{
	struct shr_table *t;
	__u8 rsvd = (avscc & 0xFE) >> 1;
	__u8 fmt = avscc & 0x1;

	t = stdout_bits_table_create();
	if (!t)
		return NULL;

	if (rsvd)
		stdout_bits_add(t, "[7:1]", rsvd, "Reserved");
	stdout_bits_add(t, "[0:0]", fmt,
			 "Admin Vendor Specific Commands uses %s Format",
			 fmt ? "NVMe" : "Vendor Specific");

	return t;
}

static struct shr_table *stdout_id_ctrl_apsta_table(__u8 apsta)
{
	struct shr_table *t;
	__u8 rsvd = (apsta & 0xFE) >> 1;
	__u8 apst = apsta & 0x1;

	t = stdout_bits_table_create();
	if (!t)
		return NULL;

	if (rsvd)
		stdout_bits_add(t, "[7:1]", rsvd, "Reserved");
	stdout_bits_add(t, "[0:0]", apst,
			 "Autonomous Power State Transitions %sSupported",
			 apst ? "" : "Not ");

	return t;
}

static struct shr_table *stdout_id_ctrl_wctemp_table(__le16 wctemp)
{
	struct shr_table *t;
	__u16 val = le16_to_cpu(wctemp);

	t = stdout_bits_table_create();
	if (!t)
		return NULL;

	stdout_bits_add(t, "[15:0]", val,
			 "%s (%u K, %s) Warning Composite Temperature Threshold (WCTEMP)",
			 nvme_degrees_string(val), val,
			 nvme_degrees_fahrenheit_string(val));

	return t;
}

static struct shr_table *stdout_id_ctrl_cctemp_table(__le16 cctemp)
{
	struct shr_table *t;
	__u16 val = le16_to_cpu(cctemp);

	t = stdout_bits_table_create();
	if (!t)
		return NULL;

	stdout_bits_add(t, "[15:0]", val,
			 "%s (%u K, %s) Critical Composite Temperature Threshold (CCTEMP)",
			 nvme_degrees_string(val), val,
			 nvme_degrees_fahrenheit_string(val));

	return t;
}

static struct shr_table *stdout_id_ctrl_tnvmcap_table(__u8 *tnvmcap)
{
	struct shr_table *t;

	t = stdout_bits_table_create();
	if (!t)
		return NULL;

	stdout_bits_add_str(t, "[127:0]",
			     uint128_t_to_l10n_string(le128_to_cpu(tnvmcap)),
			     "Total NVM Capacity (TNVMCAP)");

	return t;
}

static struct shr_table *stdout_id_ctrl_unvmcap_table(__u8 *unvmcap)
{
	struct shr_table *t;

	t = stdout_bits_table_create();
	if (!t)
		return NULL;

	stdout_bits_add_str(t, "[127:0]",
			     uint128_t_to_l10n_string(le128_to_cpu(unvmcap)),
			     "Unallocated NVM Capacity (UNVMCAP)");

	return t;
}

void stdout_id_ctrl_rpmbs(__le32 ctrl_rpmbs)
{
	__u32 rpmbs = le32_to_cpu(ctrl_rpmbs);
	__u32 asz = (rpmbs & 0xFF000000) >> 24;
	__u32 tsz = (rpmbs & 0xFF0000) >> 16;
	__u32 rsvd = (rpmbs & 0xFFC0) >> 6;
	__u32 auth = (rpmbs & 0x38) >> 3;
	__u32 rpmb = rpmbs & 0x7;

	printf(" [31:24]: %#x\tAccess Size\n", asz);
	printf(" [23:16]: %#x\tTotal Size\n", tsz);
	if (rsvd)
		printf(" [15:6] : %#x\tReserved\n", rsvd);
	printf("  [5:3] : %#x\tAuthentication Method\n", auth);
	printf("  [2:0] : %#x\tNumber of RPMB Units\n", rpmb);
	printf("\n");
}

static struct shr_table *stdout_id_ctrl_rpmbs_table(__le32 ctrl_rpmbs)
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

static struct shr_table *stdout_id_ctrl_dsto_table(__u8 dsto)
{
	struct shr_table *t;
	__u8 rsvd2 = (dsto & 0xfc) >> 2;
	__u8 hirs = NVME_CTRL_DSTO_HIRS(dsto);
	__u8 sdso = NVME_CTRL_DSTO_SDSO(dsto);

	t = stdout_bits_table_create();
	if (!t)
		return NULL;

	if (rsvd2)
		stdout_bits_add(t, "[7:2]", rsvd2, "Reserved");
	stdout_bits_add(t, "[1:1]", hirs,
			 "Host-Initiated Refresh capability %sSupported",
			 hirs ? "" : "Not ");
	stdout_bits_add(t, "[0:0]", sdso, "NVM subsystem supports %s at a time",
			 sdso ?
			 "only one device self-test operation in progress" :
			 "one device self-test operation per controller");

	return t;
}

static struct shr_table *stdout_id_ctrl_hctma_table(__le16 ctrl_hctma)
{
	struct shr_table *t;
	__u16 hctma = le16_to_cpu(ctrl_hctma);
	__u16 rsvd = (hctma & 0xFFFE) >> 1;
	__u16 hctm = hctma & 0x1;

	t = stdout_bits_table_create();
	if (!t)
		return NULL;

	if (rsvd)
		stdout_bits_add(t, "[15:1]", rsvd, "Reserved");
	stdout_bits_add(t, "[0:0]", hctm,
			 "Host Controlled Thermal Management %sSupported",
			 hctm ? "" : "Not ");

	return t;
}

static struct shr_table *stdout_id_ctrl_mntmt_table(__le16 mntmt_le)
{
	struct shr_table *t;
	__u16 mntmt = le16_to_cpu(mntmt_le);

	t = stdout_bits_table_create();
	if (!t)
		return NULL;

	stdout_bits_add(t, "[15:0]", mntmt,
			 "%s (%u K, %s) Minimum Thermal Management Temperature (MNTMT)",
			 nvme_degrees_string(mntmt), mntmt,
			 nvme_degrees_fahrenheit_string(mntmt));

	return t;
}

static struct shr_table *stdout_id_ctrl_mxtmt_table(__le16 mxtmt_le)
{
	struct shr_table *t;
	__u16 mxtmt = le16_to_cpu(mxtmt_le);

	t = stdout_bits_table_create();
	if (!t)
		return NULL;

	stdout_bits_add(t, "[15:0]", mxtmt,
			 "%s (%u K, %s) Maximum Thermal Management Temperature (MXTMT)",
			 nvme_degrees_string(mxtmt), mxtmt,
			 nvme_degrees_fahrenheit_string(mxtmt));

	return t;
}

static struct shr_table *stdout_id_ctrl_sanicap_table(__le32 ctrl_sanicap)
{
	struct shr_table *t;
	__u32 sanicap = le32_to_cpu(ctrl_sanicap);
	__u32 rsvd6 = (sanicap & 0x1FFFFFC0) >> 6;
	__u32 sprrs = NVME_CTRL_SANICAP_SPRRS(sanicap);
	__u32 vers = NVME_CTRL_SANICAP_NVERS(sanicap);
	__u32 ows = NVME_CTRL_SANICAP_OWS(sanicap);
	__u32 bes = NVME_CTRL_SANICAP_BES(sanicap);
	__u32 ces = NVME_CTRL_SANICAP_CES(sanicap);
	__u32 ndi = NVME_CTRL_SANICAP_NDI(sanicap);
	__u32 nodmmas = NVME_CTRL_SANICAP_NODMMAS(sanicap);

	static const char * const modifies_media[] = {
		"Additional media modification after sanitize operation completes successfully is not defined",
		"Media is not additionally modified after sanitize operation completes successfully",
		"Media is additionally modified after sanitize operation completes successfully",
		"Reserved"
	};

	t = stdout_bits_table_create();
	if (!t)
		return NULL;

	stdout_bits_add(t, "[31:30]", nodmmas, "%s", modifies_media[nodmmas]);
	stdout_bits_add(t, "[29:29]", ndi,
			 "No-Deallocate After Sanitize bit in Sanitize command %sSupported",
			 ndi ? "Not " : "");
	if (rsvd6)
		stdout_bits_add(t, "[28:6]", rsvd6, "Reserved");
	stdout_bits_add(t, "[5:5]", sprrs,
			 "Sanitize Purge Request and Reporting %sSupported",
			 sprrs ? "" : "Not ");
	stdout_bits_add(t, "[3:3]", vers,
			 "Media Verification and Post-Verification Deallocation state %sSupported",
			 vers ? "" : "Not ");
	stdout_bits_add(t, "[2:2]", ows,
			 "Overwrite Sanitize Operation %sSupported",
			 ows ? "" : "Not ");
	stdout_bits_add(t, "[1:1]", bes,
			 "Block Erase Sanitize Operation %sSupported",
			 bes ? "" : "Not ");
	stdout_bits_add(t, "[0:0]", ces,
			 "Crypto Erase Sanitize Operation %sSupported",
			 ces ? "" : "Not ");

	return t;
}

static struct shr_table *stdout_id_ctrl_anacap_table(__u8 anacap)
{
	struct shr_table *t;
	__u8 nz = (anacap & 0x80) >> 7;
	__u8 grpid_static = (anacap & 0x40) >> 6;
	__u8 rsvd = (anacap & 0x20) >> 5;
	__u8 ana_change = (anacap & 0x10) >> 4;
	__u8 ana_persist_loss = (anacap & 0x08) >> 3;
	__u8 ana_inaccessible = (anacap & 0x04) >> 2;
	__u8 ana_nonopt = (anacap & 0x02) >> 1;
	__u8 ana_opt = (anacap & 0x01);

	t = stdout_bits_table_create();
	if (!t)
		return NULL;

	stdout_bits_add(t, "[7:7]", nz, "Non-zero group ID %sSupported",
			 nz ? "" : "Not ");
	stdout_bits_add(t, "[6:6]", grpid_static, "Group ID does %schange",
			 grpid_static ? "not " : "");
	if (rsvd)
		stdout_bits_add(t, "[5:5]", rsvd, "Reserved");
	stdout_bits_add(t, "[4:4]", ana_change, "ANA Change state %sSupported",
			 ana_change ? "" : "Not ");
	stdout_bits_add(t, "[3:3]", ana_persist_loss,
			 "ANA Persistent Loss state %sSupported",
			 ana_persist_loss ? "" : "Not ");
	stdout_bits_add(t, "[2:2]", ana_inaccessible,
			 "ANA Inaccessible state %sSupported",
			 ana_inaccessible ? "" : "Not ");
	stdout_bits_add(t, "[1:1]", ana_nonopt,
			 "ANA Non-optimized state %sSupported",
			 ana_nonopt ? "" : "Not ");
	stdout_bits_add(t, "[0:0]", ana_opt, "ANA Optimized state %sSupported",
			 ana_opt ? "" : "Not ");

	return t;
}

static struct shr_table *stdout_id_ctrl_kpioc_table(__u8 ctrl_kpioc)
{
	struct shr_table *t;
	__u8 rsvd2 = (ctrl_kpioc >> 2);
	__u8 kpiosc = NVME_CTRL_KPIOC_KPIOSC(ctrl_kpioc);
	__u8 kpios = NVME_CTRL_KPIOC_KPIOS(ctrl_kpioc);

	t = stdout_bits_table_create();
	if (!t)
		return NULL;

	if (rsvd2)
		stdout_bits_add(t, "[7:2]", rsvd2, "Reserved");
	stdout_bits_add(t, "[1:1]", kpiosc,
			 "Key Per I/O capability %s to all namespaces",
			 kpiosc ? "applies" : "Not apply");
	stdout_bits_add(t, "[0:0]", kpios, "Key Per I/O capability %sSupported",
			 kpios ? "" : "Not ");

	return t;
}

static struct shr_table *stdout_id_ctrl_tmpthha_table(__u8 tmpthha)
{
	struct shr_table *t;
	__u8 rsvd3 = (tmpthha & 0xf8) >> 3;
	__u8 tmpthmh = tmpthha & 0x7;

	t = stdout_bits_table_create();
	if (!t)
		return NULL;

	if (rsvd3)
		stdout_bits_add(t, "[7:3]", rsvd3, "Reserved");
	stdout_bits_add(t, "[2:0]", tmpthmh,
			 "Temperature Threshold Maximum Hysteresis");

	return t;
}

static struct shr_table *stdout_id_ctrl_mupa_table(__u8 mupa)
{
	struct shr_table *t;
	__u8 mups = NVME_CTRL_MUPA_MUPS(mupa);

	t = stdout_bits_table_create();
	if (!t)
		return NULL;

	stdout_bits_add(t, "[1:0]", mups, "Maximum Unlimited Power Scale (%s)",
			 nvme_feature_power_limit_scale_to_string(mups));

	return t;
}

static struct shr_table *stdout_id_ctrl_cdpa_table(__le16 ctrl_cdpa)
{
	struct shr_table *t;
	__u16 cdpa = le16_to_cpu(ctrl_cdpa);
	__u16 rsvd1 = (cdpa >> 1);
	bool hmac_sha_384 = !!(cdpa & NVME_CTRL_CDPA_HMAC_SHA_384);

	t = stdout_bits_table_create();
	if (!t)
		return NULL;

	if (rsvd1)
		stdout_bits_add(t, "[15:1]", rsvd1, "Reserved");
	stdout_bits_add(t, "[0:0]", hmac_sha_384, "HMAC-SHA-384 %sSupported",
			 hmac_sha_384 ? "" : "Not ");

	return t;
}

static struct shr_table *stdout_id_ctrl_ipmsr_table(__le16 ctrl_ipmsr)
{
	struct shr_table *t;
	__u16 ipmsr = le16_to_cpu(ctrl_ipmsr);
	__u16 srs = NVME_CTRL_IPMSR_SRS(ipmsr);
	__u16 srv = NVME_CTRL_IPMSR_SRV(ipmsr);

	t = stdout_bits_table_create();
	if (!t)
		return NULL;

	stdout_bits_add(t, "[15:8]", srs, "Sample Rate Scale (%s)",
			 nvme_ipmsr_srs_to_string(srs));
	stdout_bits_add(t, "[7:0]", srv, "Sample Rate Value");

	return t;
}

static struct shr_table *stdout_id_ctrl_ensa_table(__u8 ensa)
{
	struct shr_table *t;
	bool ensms = !!NVME_CTRL_ENSA_ENSMS(ensa);
	bool ensts = !!NVME_CTRL_ENSA_ENSTS(ensa);

	t = stdout_bits_table_create();
	if (!t)
		return NULL;

	stdout_bits_add(t, "[1:1]", ensms,
			 "Exported NVM Subsystem Support Migration %s",
			 nvme_support_str(ensms));
	stdout_bits_add(t, "[0:0]", ensts,
			 "Exported NVM Subsystem Template %s",
			 nvme_support_str(ensts));

	return t;
}

static struct shr_table *stdout_id_ctrl_endsfs_table(__u8 endsfs)
{
	struct shr_table *t;
	bool enf1 = !!NVME_CTRL_ENDSFS_ENF1(endsfs);
	bool enf0 = !!NVME_CTRL_ENDSFS_ENF0(endsfs);

	t = stdout_bits_table_create();
	if (!t)
		return NULL;

	stdout_bits_add(t, "[1:1]", enf1, "Exported Namespace Format 1 %s",
			 nvme_support_str(enf1));
	stdout_bits_add(t, "[0:0]", enf0, "Exported Namespace Format 0 %s",
			 nvme_support_str(enf0));

	return t;
}

static struct shr_table *stdout_id_ctrl_vsen_table(__le32 ctrl_vsen)
{
	struct shr_table *t;
	__u32 vsen = le32_to_cpu(ctrl_vsen);

	t = stdout_bits_table_create();
	if (!t)
		return NULL;

	if (!vsen) {
		int row = shr_table_get_row_id(t);

		shr_table_set_value_str(t, 0, row, "", RIGHT);
		shr_table_set_value_str(t, 1, row, "", LEFT);
		shr_table_set_value_str(t, 2, row, "", RIGHT);
		shr_table_set_value_str(t, 3, row,
					 "Voltage sensor not supported", LEFT);
		shr_table_add_row(t, row);

		return t;
	}

	stdout_bits_add(t, "[31:24]", NVME_CTRL_VSEN_VSRS(vsen),
			 "Voltage Sample Rate Scale");
	stdout_bits_add(t, "[23:16]", NVME_CTRL_VSEN_VSRV(vsen),
			 "Voltage Sample Rate Value");
	stdout_bits_add(t, "[15:14]", NVME_CTRL_VSEN_VOLSS(vsen),
			 "Voltage Sample Scale");
	stdout_bits_add(t, "[13:12]", NVME_CTRL_VSEN_PISL(vsen),
			 "Power Input Supply Label");
	stdout_bits_add(t, "[11:0]", NVME_CTRL_VSEN_PISV(vsen),
			 "Power Input Supply Value (%g V)",
			 NVME_CTRL_VSEN_PISV(vsen) * 0.05);

	return t;
}

static struct shr_table *stdout_id_ctrl_sqes_table(__u8 sqes)
{
	struct shr_table *t;
	__u8 msqes = (sqes & 0xF0) >> 4;
	__u8 rsqes = sqes & 0xF;

	t = stdout_bits_table_create();
	if (!t)
		return NULL;

	stdout_bits_add(t, "[7:4]", msqes,
			 "Max SQ Entry Size (%d)", 1 << msqes);
	stdout_bits_add(t, "[3:0]", rsqes,
			 "Min SQ Entry Size (%d)", 1 << rsqes);

	return t;
}

static struct shr_table *stdout_id_ctrl_cqes_table(__u8 cqes)
{
	struct shr_table *t;
	__u8 mcqes = (cqes & 0xF0) >> 4;
	__u8 rcqes = cqes & 0xF;

	t = stdout_bits_table_create();
	if (!t)
		return NULL;

	stdout_bits_add(t, "[7:4]", mcqes,
			 "Max CQ Entry Size (%d)", 1 << mcqes);
	stdout_bits_add(t, "[3:0]", rcqes,
			 "Min CQ Entry Size (%d)", 1 << rcqes);

	return t;
}

static struct shr_table *stdout_id_ctrl_oncs_table(__le16 ctrl_oncs)
{
	struct shr_table *t;
	__u16 oncs = le16_to_cpu(ctrl_oncs);
	__u16 rsvd13 = oncs >> 13;
	bool nszs = !!(oncs & NVME_CTRL_ONCS_NAMESPACE_ZEROES);
	bool maxwzd = !!(oncs & NVME_CTRL_ONCS_WRITE_ZEROES_DEALLOCATE);
	bool nvmafc  = !!(oncs & NVME_CTRL_ONCS_ALL_FAST_COPY);
	bool nvmcsa  = !!(oncs & NVME_CTRL_ONCS_COPY_SINGLE_ATOMICITY);
	bool nvmcpys = !!(oncs & NVME_CTRL_ONCS_COPY);
	bool nvmvfys = !!(oncs & NVME_CTRL_ONCS_VERIFY);
	bool tss = !!(oncs & NVME_CTRL_ONCS_TIMESTAMP);
	bool reservs = !!(oncs & NVME_CTRL_ONCS_RESERVATIONS);
	bool ssfs = !!(oncs & NVME_CTRL_ONCS_SAVE_FEATURES);
	bool nvmwzsv = !!(oncs & NVME_CTRL_ONCS_WRITE_ZEROES);
	bool nvmdsmsv = !!(oncs & NVME_CTRL_ONCS_DSM);
	bool nvmwusv = !!(oncs & NVME_CTRL_ONCS_WRITE_UNCORRECTABLE);
	bool nvmcmps  = !!(oncs & NVME_CTRL_ONCS_COMPARE);

	t = stdout_bits_table_create();
	if (!t)
		return NULL;

	if (rsvd13)
		stdout_bits_add(t, "[15:13]", rsvd13, "Reserved");
	stdout_bits_add(t, "[12:12]", nszs, "Namespace Zeroes %sSupported",
			 nszs ? "" : "Not ");
	stdout_bits_add(t, "[11:11]", maxwzd,
			 "Maximum Write Zeroes with Deallocate %sSupported",
			 maxwzd ? "" : "Not ");
	stdout_bits_add(t, "[10:10]", nvmafc, "All Fast Copy %sSupported",
			 nvmafc ? "" : "Not ");
	stdout_bits_add(t, "[9:9]", nvmcsa, "Copy Single Atomicity %sSupported",
			 nvmcsa ? "" : "Not ");
	stdout_bits_add(t, "[8:8]", nvmcpys, "Copy %sSupported",
			 nvmcpys ? "" : "Not ");
	stdout_bits_add(t, "[7:7]", nvmvfys, "Verify %sSupported",
			 nvmvfys ? "" : "Not ");
	stdout_bits_add(t, "[6:6]", tss, "Timestamp %sSupported",
			 tss ? "" : "Not ");
	stdout_bits_add(t, "[5:5]", reservs, "Reservations %sSupported",
			 reservs ? "" : "Not ");
	stdout_bits_add(t, "[4:4]", ssfs, "Save and Select %sSupported",
			 ssfs ? "" : "Not ");
	stdout_bits_add(t, "[3:3]", nvmwzsv, "Write Zeroes Support Variants");
	stdout_bits_add(t, "[2:2]", nvmdsmsv,
			 "Dataset Management Support Variants");
	stdout_bits_add(t, "[1:1]", nvmwusv,
			 "Write Uncorrectable Support Variants");
	stdout_bits_add(t, "[0:0]", nvmcmps, "Compare Command %sSupported",
			 nvmcmps ? "" : "Not ");

	return t;
}

static struct shr_table *stdout_id_ctrl_fuses_table(__le16 ctrl_fuses)
{
	struct shr_table *t;
	__u16 fuses = le16_to_cpu(ctrl_fuses);
	__u16 rsvd = (fuses & 0xFE) >> 1;
	__u16 cmpw = fuses & 0x1;

	t = stdout_bits_table_create();
	if (!t)
		return NULL;

	if (rsvd)
		stdout_bits_add(t, "[15:1]", rsvd, "Reserved");
	stdout_bits_add(t, "[0:0]", cmpw, "Fused Compare and Write %sSupported",
			 cmpw ? "" : "Not ");

	return t;
}

static struct shr_table *stdout_id_ctrl_fna_table(__u8 fna)
{
	struct shr_table *t;
	__u8 rsvd = (fna & 0xF0) >> 4;
	__u8 bcnsid = NVME_CTRL_FNA_NSID_ALL_F(fna);
	__u8 cese = NVME_CTRL_FNA_CES(fna);
	__u8 cens = NVME_CTRL_FNA_SEC_ALL_NS(fna);
	__u8 fmns = NVME_CTRL_FNA_FMT_ALL_NS(fna);

	t = stdout_bits_table_create();
	if (!t)
		return NULL;

	if (rsvd)
		stdout_bits_add(t, "[7:4]", rsvd, "Reserved");
	stdout_bits_add(t, "[3:3]", bcnsid,
			 "Format NVM Broadcast NSID (FFFFFFFFh) %sSupported",
			 bcnsid ? "Not " : "");
	stdout_bits_add(t, "[2:2]", cese,
			 "Crypto Erase %sSupported as part of Secure Erase",
			 cese ? "" : "Not ");
	stdout_bits_add(t, "[1:1]", cens,
			 "Crypto Erase Applies to %s Namespace(s)",
			 cens ? "All" : "Single");
	stdout_bits_add(t, "[0:0]", fmns, "Format Applies to %s Namespace(s)",
			 fmns ? "All" : "Single");

	return t;
}

static struct shr_table *stdout_id_ctrl_vwc_table(__u8 vwc)
{
	struct shr_table *t;
	__u8 rsvd = (vwc & 0xF8) >> 3;
	__u8 flush = (vwc & 0x6) >> 1;
	__u8 vwcp = vwc & 0x1;

	static const char * const flush_behavior[] = {
		"Support for the NSID field set to FFFFFFFFh is not indicated",
		"Reserved",
		"The Flush command does not support NSID set to FFFFFFFFh",
		"The Flush command supports NSID set to FFFFFFFFh"
	};

	t = stdout_bits_table_create();
	if (!t)
		return NULL;

	if (rsvd)
		stdout_bits_add(t, "[7:3]", rsvd, "Reserved");
	stdout_bits_add(t, "[2:1]", flush, "%s", flush_behavior[flush]);
	stdout_bits_add(t, "[0:0]", vwcp, "Volatile Write Cache %sPresent",
			 vwcp ? "" : "Not ");

	return t;
}

static struct shr_table *stdout_id_ctrl_icsvscc_table(__u8 icsvscc)
{
	struct shr_table *t;
	__u8 rsvd = (icsvscc & 0xFE) >> 1;
	__u8 fmt = icsvscc & 0x1;

	t = stdout_bits_table_create();
	if (!t)
		return NULL;

	if (rsvd)
		stdout_bits_add(t, "[7:1]", rsvd, "Reserved");
	stdout_bits_add(t, "[0:0]", fmt,
			 "NVM Vendor Specific Commands uses %s Format",
			 fmt ? "NVMe" : "Vendor Specific");

	return t;
}

static struct shr_table *stdout_id_ctrl_nwpc_table(__u8 nwpc)
{
	struct shr_table *t;
	__u8 no_wp_wp = (nwpc & 0x01);
	__u8 wp_power_cycle = (nwpc & 0x02) >> 1;
	__u8 wp_permanent = (nwpc & 0x04) >> 2;
	__u8 rsvd = (nwpc & 0xF8) >> 3;

	t = stdout_bits_table_create();
	if (!t)
		return NULL;

	if (rsvd)
		stdout_bits_add(t, "[7:3]", rsvd, "Reserved");
	stdout_bits_add(t, "[2:2]", wp_permanent,
			 "Permanent Write Protect %sSupported",
			 wp_permanent ? "" : "Not ");
	stdout_bits_add(t, "[1:1]", wp_power_cycle,
			 "Write Protect Until Power Supply %sSupported",
			 wp_power_cycle ? "" : "Not ");
	stdout_bits_add(t, "[0:0]", no_wp_wp,
			 "No Write Protect and Write Protect Namespace %sSupported",
			 no_wp_wp ? "" : "Not ");

	return t;
}

static struct shr_table *stdout_id_ctrl_ocfs_table(__le16 ctrl_ocfs)
{
	struct shr_table *t;
	__u16 ocfs = le16_to_cpu(ctrl_ocfs);
	__u16 rsvd = ocfs >> 4;
	int copy_fmt;

	t = stdout_bits_table_create();
	if (!t)
		return NULL;

	if (rsvd)
		stdout_bits_add(t, "[15:4]", rsvd, "Reserved");

	for (copy_fmt = 3; copy_fmt >= 0; copy_fmt--) {
		__u8 supported = ocfs >> copy_fmt & 1;
		__cleanup_free char *bits = NULL;
		__cleanup_free char *desc = NULL;

		if (asprintf(&bits, "[%d:%d]", copy_fmt, copy_fmt) < 0)
			bits = NULL;
		if (asprintf(&desc, "Controller Copy Format %xh %sSupported",
			     copy_fmt, supported ? "" : "Not ") < 0)
			desc = NULL;

		stdout_bits_add(t, bits ?: "", supported, desc ?: "");
	}

	return t;
}

static struct shr_table *stdout_id_ctrl_sgls_table(__le32 ctrl_sgls)
{
	struct shr_table *t;
	__u32 sgls = le32_to_cpu(ctrl_sgls);
	__u32 rsvd0 = (sgls & 0xFFC00000) >> 22;
	__u32 trsdbd = (sgls & 0x200000) >> 21;
	__u32 aofdsl = (sgls & 0x100000) >> 20;
	__u32 mpcsd = (sgls & 0x80000) >> 19;
	__u32 sglltb = (sgls & 0x40000) >> 18;
	__u32 bacmdb = (sgls & 0x20000) >> 17;
	__u32 bbs = (sgls & 0x10000) >> 16;
	__u32 sdt = (sgls >> 8) & 0xff;
	__u32 rsvd1 = (sgls & 0xF8) >> 3;
	__u32 key = (sgls & 0x4) >> 2;
	__u32 sglsp = sgls & 0x3;

	t = stdout_bits_table_create();
	if (!t)
		return NULL;

	if (rsvd0)
		stdout_bits_add(t, "[31:22]", rsvd0, "Reserved");
	if (sglsp || (!sglsp && trsdbd))
		stdout_bits_add(t, "[21:21]", trsdbd,
				 "Transport SGL Data Block Descriptor %sSupported",
				 trsdbd ? "" : "Not ");
	if (sglsp || (!sglsp && aofdsl))
		stdout_bits_add(t, "[20:20]", aofdsl,
				 "Address Offsets %sSupported",
				 aofdsl ? "" : "Not ");
	if (sglsp || (!sglsp && mpcsd))
		stdout_bits_add(t, "[19:19]", mpcsd,
				 "Metadata Pointer Containing SGL Descriptor is %sSupported",
				 mpcsd ? "" : "Not ");
	if (sglsp || (!sglsp && sglltb))
		stdout_bits_add(t, "[18:18]", sglltb,
				 "SGL Length Larger than Buffer %sSupported",
				 sglltb ? "" : "Not ");
	if (sglsp || (!sglsp && bacmdb))
		stdout_bits_add(t, "[17:17]", bacmdb,
				 "Byte-Aligned Contig. MD Buffer %sSupported",
				 bacmdb ? "" : "Not ");
	if (sglsp || (!sglsp && bbs))
		stdout_bits_add(t, "[16:16]", bbs, "SGL Bit-Bucket %sSupported",
				 bbs ? "" : "Not ");
	stdout_bits_add(t, "[15:8]", sdt, "SGL Descriptor Threshold");
	if (rsvd1)
		stdout_bits_add(t, "[7:3]", rsvd1, "Reserved");
	if (sglsp || (!sglsp && key))
		stdout_bits_add(t, "[2:2]", key,
				 "Keyed SGL Data Block descriptor %sSupported",
				 key ? "" : "Not ");
	if (sglsp == 0x3)
		stdout_bits_add(t, "[1:0]", sglsp, "Reserved");
	else if (sglsp == 0x2)
		stdout_bits_add(t, "[1:0]", sglsp,
				 "Scatter-Gather Lists Supported. Dword alignment required.");
	else if (sglsp == 0x1)
		stdout_bits_add(t, "[1:0]", sglsp,
				 "Scatter-Gather Lists Supported. No Dword alignment required.");
	else
		stdout_bits_add(t, "[1:0]", sglsp,
				 "Scatter-Gather Lists Not Supported");

	return t;
}

static struct shr_table *stdout_id_ctrl_trattr_table(__u8 ctrl_trattr)
{
	struct shr_table *t;
	__u8 rsvd3 = (ctrl_trattr >> 3);
	__u8 mrtll = NVME_CTRL_TRATTR_MRTLL(ctrl_trattr);
	__u8 tudcs = NVME_CTRL_TRATTR_TUDCS(ctrl_trattr);
	__u8 thmcs = NVME_CTRL_TRATTR_THMCS(ctrl_trattr);

	t = stdout_bits_table_create();
	if (!t)
		return NULL;

	if (rsvd3)
		stdout_bits_add(t, "[7:3]", rsvd3, "Reserved");
	stdout_bits_add(t, "[2:2]", mrtll,
			 "Memory Range Tracking Length Limit");
	stdout_bits_add(t, "[1:1]", tudcs,
			 "Tracking User Data Changes %sSupported",
			 tudcs ? "" : "Not ");
	stdout_bits_add(t, "[0:0]", thmcs,
			 "Track Host Memory Changes %sSupported",
			 thmcs ? "" : "Not ");

	return t;
}

static struct shr_table *stdout_id_ctrl_fcatt_table(__u8 fcatt)
{
	struct shr_table *t;
	__u8 rsvd = (fcatt & 0xFE) >> 1;
	__u8 scm = fcatt & 0x1;

	t = stdout_bits_table_create();
	if (!t)
		return NULL;

	if (rsvd)
		stdout_bits_add(t, "[7:1]", rsvd, "Reserved");
	stdout_bits_add(t, "[0:0]", scm, "%s Controller Model",
			 scm ? "Static" : "Dynamic");

	return t;
}

static struct shr_table *stdout_id_ctrl_ofcs_table(__le16 ofcs_le)
{
	struct shr_table *t;
	__u16 ofcs = le16_to_cpu(ofcs_le);
	__u16 rsvd = (ofcs & 0xfffe) >> 1;
	__u8 disconn = ofcs & 0x1;

	t = stdout_bits_table_create();
	if (!t)
		return NULL;

	if (rsvd)
		stdout_bits_add(t, "[15:1]", rsvd, "Reserved");
	stdout_bits_add(t, "[0:0]", disconn, "Disconnect command %s Supported",
			 disconn ? "" : "Not");

	return t;
}

static struct shr_table *stdout_id_ctrl_dctype_table(__u8 dctype)
{
	struct shr_table *t;
	__u8 rsvd = (dctype & 0xFC) >> 2;
	__u8 dctype_val = dctype & 0x3;
	char *dctype_str;

	t = stdout_bits_table_create();
	if (!t)
		return NULL;

	if (rsvd)
		stdout_bits_add(t, "[7:3]", rsvd, "Reserved");
	if (dctype_val == NVME_CTRL_DCTYPE_CDC)
		dctype_str = "CDC";
	else if (dctype_val == NVME_CTRL_DCTYPE_DDC)
		dctype_str = "DDC";
	else
		dctype_str = "not reported";

	stdout_bits_add(t, "[0:2]", dctype_val, "Discovery Controller Type: %s",
			 dctype_str);

	return t;
}

static struct shr_table *stdout_id_ns_nsfeat_table(__u8 nsfeat)
{
	struct shr_table *t;
	__u8 optrperf = (nsfeat & 0x80) >> 7;
	__u8 mam = (nsfeat & 0x40) >> 6;
	__u8 optperf = (nsfeat & 0x30) >> 4;
	__u8 uidreuse = (nsfeat & 0x8) >> 3;
	__u8 dulbe = (nsfeat & 0x4) >> 2;
	__u8 na = (nsfeat & 0x2) >> 1;
	__u8 thin = nsfeat & 0x1;

	t = stdout_bits_table_create();
	if (!t)
		return NULL;

	stdout_bits_add(t, "[7:7]", optrperf,
			 "NPRG, NPRA and NORS are %sSupported",
			 optrperf ? "" : "Not ");
	stdout_bits_add(t, "[6:6]", mam,
			 "%s Atomicity Mode applies to write operations",
			 mam ? "Multiple" : "Single");
	stdout_bits_add(t, "[5:4]", optperf,
			 "NPWG, NPWA, %s%sNPDA, and NOWS are %sSupported",
			 ((optperf & 0x1) || (!optperf)) ? "NPDG, " : "",
			 ((optperf & 0x2) || (!optperf)) ? "NPDGL, " : "",
			 optperf ? "" : "Not ");
	stdout_bits_add(t, "[3:3]", uidreuse,
			 "NGUID and EUI64 fields if non-zero, %sReused",
			 uidreuse ? "Never " : "");
	stdout_bits_add(t, "[2:2]", dulbe,
			 "Deallocated or Unwritten Logical Block error %sSupported",
			 dulbe ? "" : "Not ");
	stdout_bits_add(t, "[1:1]", na, "Namespace uses %s",
			 na ? "NAWUN, NAWUPF, and NACWU" :
			 "AWUN, AWUPF, and ACWU");
	stdout_bits_add(t, "[0:0]", thin, "Thin Provisioning %sSupported",
			 thin ? "" : "Not ");

	return t;
}

static struct shr_table *stdout_id_ns_flbas_table(__u8 flbas)
{
	struct shr_table *t;
	__u8 rsvd = (flbas & 0x80) >> 7;
	__u8 msb2_lbaf = NVME_FLBAS_HIGHER(flbas);
	__u8 mdedata = NVME_FLBAS_META_EXT(flbas);
	__u8 lsb4_lbaf = NVME_FLBAS_LOWER(flbas);

	t = stdout_bits_table_create();
	if (!t)
		return NULL;

	if (rsvd)
		stdout_bits_add(t, "[7:7]", rsvd, "Reserved");
	stdout_bits_add(t, "[6:5]", msb2_lbaf,
			 "Most significant 2 bits of Current LBA Format Selected");
	stdout_bits_add(t, "[4:4]", mdedata, "Metadata Transferred %s",
			 mdedata ? "at End of Data LBA" :
			 "in Separate Contiguous Buffer");
	stdout_bits_add(t, "[3:0]", lsb4_lbaf,
			 "Least significant 4 bits of Current LBA Format Selected");

	return t;
}

static struct shr_table *stdout_id_ns_mc_table(__u8 mc)
{
	struct shr_table *t;
	__u8 rsvd = (mc & 0xFC) >> 2;
	__u8 mdp = (mc & 0x2) >> 1;
	__u8 extdlba = mc & 0x1;

	t = stdout_bits_table_create();
	if (!t)
		return NULL;

	if (rsvd)
		stdout_bits_add(t, "[7:2]", rsvd, "Reserved");
	stdout_bits_add(t, "[1:1]", mdp, "Metadata Pointer %sSupported",
			 mdp ? "" : "Not ");
	stdout_bits_add(t, "[0:0]", extdlba,
			 "Metadata as Part of Extended Data LBA %sSupported",
			 extdlba ? "" : "Not ");

	return t;
}

static struct shr_table *stdout_id_ns_dpc_table(__u8 dpc)
{
	struct shr_table *t;
	__u8 rsvd = (dpc & 0xE0) >> 5;
	__u8 pil8 = (dpc & 0x10) >> 4;
	__u8 pif8 = (dpc & 0x8) >> 3;
	__u8 pit3 = (dpc & 0x4) >> 2;
	__u8 pit2 = (dpc & 0x2) >> 1;
	__u8 pit1 = dpc & 0x1;

	t = stdout_bits_table_create();
	if (!t)
		return NULL;

	if (rsvd)
		stdout_bits_add(t, "[7:5]", rsvd, "Reserved");
	stdout_bits_add(t, "[4:4]", pil8,
			 "Protection Information Transferred as Last Bytes of Metadata %sSupported",
			 pil8 ? "" : "Not ");
	stdout_bits_add(t, "[3:3]", pif8,
			 "Protection Information Transferred as First Bytes of Metadata %sSupported",
			 pif8 ? "" : "Not ");
	stdout_bits_add(t, "[2:2]", pit3,
			 "Protection Information Type 3 %sSupported",
			 pit3 ? "" : "Not ");
	stdout_bits_add(t, "[1:1]", pit2,
			 "Protection Information Type 2 %sSupported",
			 pit2 ? "" : "Not ");
	stdout_bits_add(t, "[0:0]", pit1,
			 "Protection Information Type 1 %sSupported",
			 pit1 ? "" : "Not ");

	return t;
}

static struct shr_table *stdout_id_ns_dps_table(__u8 dps)
{
	struct shr_table *t;
	__u8 rsvd = (dps & 0xF0) >> 4;
	__u8 pif8 = NVME_NS_DPS_PI_FIRST(dps);
	__u8 pit = NVME_NS_DPS_PI(dps);

	t = stdout_bits_table_create();
	if (!t)
		return NULL;

	if (rsvd)
		stdout_bits_add(t, "[7:4]", rsvd, "Reserved");
	stdout_bits_add(t, "[3:3]", pif8,
			 "Protection Information is Transferred as %s Bytes of Metadata",
			 pif8 ? "First" : "Last");
	stdout_bits_add(t, "[2:0]", pit, "Protection Information %s",
			 pit == 3 ? "Type 3 Enabled" :
			 pit == 2 ? "Type 2 Enabled" :
			 pit == 1 ? "Type 1 Enabled" :
			 pit == 0 ? "Disabled" : "Reserved Enabled");

	return t;
}

static struct shr_table *stdout_id_ns_nmic_table(__u8 nmic)
{
	struct shr_table *t;
	__u8 rsvd = (nmic & 0xfc) >> 2;
	__u8 disns = (nmic & 0x2) >> 1;
	__u8 shrns = nmic & 0x1;

	t = stdout_bits_table_create();
	if (!t)
		return NULL;

	if (rsvd)
		stdout_bits_add(t, "[7:2]", rsvd, "Reserved");
	stdout_bits_add(t, "[1:1]", disns,
			 "Namespace is %sa Dispersed Namespace",
			 disns ? "" : "Not ");
	stdout_bits_add(t, "[0:0]", shrns, "Namespace Multipath %sCapable",
			 shrns ? "" : "Not ");

	return t;
}

static struct shr_table *stdout_id_ns_rescap_table(__u8 rescap)
{
	struct shr_table *t;
	__u8 iekr = (rescap & 0x80) >> 7;
	__u8 eaar = (rescap & 0x40) >> 6;
	__u8 wear = (rescap & 0x20) >> 5;
	__u8 earo = (rescap & 0x10) >> 4;
	__u8 wero = (rescap & 0x8) >> 3;
	__u8 ea = (rescap & 0x4) >> 2;
	__u8 we = (rescap & 0x2) >> 1;
	__u8 ptpl = rescap & 0x1;

	t = stdout_bits_table_create();
	if (!t)
		return NULL;

	stdout_bits_add(t, "[7:7]", iekr,
			 "Ignore Existing Key - Used as defined in revision %s",
			 iekr ? "1.3 or later" : "1.2.1 or earlier");
	stdout_bits_add(t, "[6:6]", eaar,
			 "Exclusive Access - All Registrants %sSupported",
			 eaar ? "" : "Not ");
	stdout_bits_add(t, "[5:5]", wear,
			 "Write Exclusive - All Registrants %sSupported",
			 wear ? "" : "Not ");
	stdout_bits_add(t, "[4:4]", earo,
			 "Exclusive Access - Registrants Only %sSupported",
			 earo ? "" : "Not ");
	stdout_bits_add(t, "[3:3]", wero,
			 "Write Exclusive - Registrants Only %sSupported",
			 wero ? "" : "Not ");
	stdout_bits_add(t, "[2:2]", ea, "Exclusive Access %sSupported",
			 ea ? "" : "Not ");
	stdout_bits_add(t, "[1:1]", we, "Write Exclusive %sSupported",
			 we ? "" : "Not ");
	stdout_bits_add(t, "[0:0]", ptpl,
			 "Persist Through Power Loss %sSupported",
			 ptpl ? "" : "Not ");

	return t;
}

static struct shr_table *stdout_id_ns_fpi_table(__u8 fpi)
{
	struct shr_table *t;
	__u8 fpis = (fpi & 0x80) >> 7;
	__u8 fpii = fpi & 0x7F;

	t = stdout_bits_table_create();
	if (!t)
		return NULL;

	stdout_bits_add(t, "[7:7]", fpis,
			 "Format Progress Indicator %sSupported",
			 fpis ? "" : "Not ");
	if (fpis || (!fpis && fpii))
		stdout_bits_add(t, "[6:0]", fpii,
				 "Format Progress Indicator (Remaining %d%%)",
				 fpii);

	return t;
}

static struct shr_table *stdout_id_ns_nsattr_table(__u8 nsattr)
{
	struct shr_table *t;
	__u8 rsvd = (nsattr & 0xFE) >> 1;
	__u8 write_protected = nsattr & 0x1;

	t = stdout_bits_table_create();
	if (!t)
		return NULL;

	if (rsvd)
		stdout_bits_add(t, "[7:1]", rsvd, "Reserved");
	stdout_bits_add(t, "[0:0]", write_protected,
			 "Namespace %sWrite Protected",
			 write_protected ? "" : "Not ");

	return t;
}

static struct shr_table *stdout_id_ns_dlfeat_table(__u8 dlfeat)
{
	struct shr_table *t;
	__u8 rsvd = (dlfeat & 0xE0) >> 5;
	__u8 guard = (dlfeat & 0x10) >> 4;
	__u8 dwz = (dlfeat & 0x8) >> 3;
	__u8 val = dlfeat & 0x7;

	t = stdout_bits_table_create();
	if (!t)
		return NULL;

	if (rsvd)
		stdout_bits_add(t, "[7:5]", rsvd, "Reserved");
	stdout_bits_add(t, "[4:4]", guard,
			 "Guard Field of Deallocated Logical Blocks is set to %s",
			 guard ? "CRC of The Value Read" : "0xFFFF");
	stdout_bits_add(t, "[3:3]", dwz,
			 "Deallocate Bit in the Write Zeroes Command is %sSupported",
			 dwz ? "" : "Not ");
	stdout_bits_add(t, "[2:0]", val,
			 "Bytes Read From a Deallocated Logical Block and its Metadata are %s",
			 val == 2 ? "0xFF" :
			 val == 1 ? "0x00" :
			 val == 0 ? "Not Reported" : "Reserved Value");

	return t;
}

static struct shr_table *stdout_id_ns_kpios_table(__u8 kpios)
{
	struct shr_table *t;
	__u8 rsvd = (kpios & 0xfc) >> 2;
	__u8 kpiosns = (kpios & 0x2) >> 1;
	__u8 kpioens = kpios & 0x1;

	t = stdout_bits_table_create();
	if (!t)
		return NULL;

	if (rsvd)
		stdout_bits_add(t, "[7:2]", rsvd, "Reserved");
	stdout_bits_add(t, "[1:1]", kpiosns,
			 "Key Per I/O Capability %sSupported",
			 kpiosns ? "" : "Not ");
	stdout_bits_add(t, "[0:0]", kpioens, "Key Per I/O Capability %s",
			 kpioens ? "Enabled" : "Disabled");

	return t;
}

static void stdout_id_ns(struct nvme_id_ns *ns, unsigned int nsid,
			 unsigned int lba_index, bool cap_only)
{
	bool human = stdout_print_ops.flags & VERBOSE;
	int vs = stdout_print_ops.flags & VS;
	struct shr_table *t;
	char *in_use = "(in use)";
	char nguid_buf[2 * sizeof(ns->nguid) + 1], *nguid = nguid_buf;
	char eui64_buf[2 * sizeof(ns->eui64) + 1], *eui64 = eui64_buf;
	__u8 flbas;
	int row, i;

	t = stdout_kv_table_create();
	if (!t)
		return;

	if (!cap_only) {
		printf("NVME Identify Namespace %d:\n", nsid);

		if (human) {
			stdout_kv_add(t, "nsze",
				"%#"PRIx64"\tTotal size in logical blocks",
				le64_to_cpu(ns->nsze));
			stdout_kv_add(t, "ncap",
				"%#"PRIx64"\tMaximum size in logical blocks",
				le64_to_cpu(ns->ncap));
			stdout_kv_add(t, "nuse",
				"%#"PRIx64"\tCurrent size in logical blocks",
				le64_to_cpu(ns->nuse));
		} else {
			stdout_kv_add(t, "nsze", "%#"PRIx64,
				      le64_to_cpu(ns->nsze));
			stdout_kv_add(t, "ncap", "%#"PRIx64,
				      le64_to_cpu(ns->ncap));
			stdout_kv_add(t, "nuse", "%#"PRIx64,
				      le64_to_cpu(ns->nuse));
		}

		row = stdout_kv_add(t, "nsfeat", "%#x", ns->nsfeat);
		if (human)
			shr_table_set_row_subtable(t, row,
					stdout_id_ns_nsfeat_table(ns->nsfeat));
	} else
		printf("NVMe Identify Namespace for LBA format[%d]:\n", lba_index);

	stdout_kv_add(t, "nlbaf", "%d", ns->nlbaf);
	if (!cap_only) {
		row = stdout_kv_add(t, "flbas", "%#x", ns->flbas);
		if (human)
			shr_table_set_row_subtable(t, row,
					stdout_id_ns_flbas_table(ns->flbas));
	} else
		in_use = "";

	row = stdout_kv_add(t, "mc", "%#x", ns->mc);
	if (human)
		shr_table_set_row_subtable(t, row,
				stdout_id_ns_mc_table(ns->mc));

	row = stdout_kv_add(t, "dpc", "%#x", ns->dpc);
	if (human)
		shr_table_set_row_subtable(t, row,
				stdout_id_ns_dpc_table(ns->dpc));

	if (!cap_only) {
		row = stdout_kv_add(t, "dps", "%#x", ns->dps);
		if (human)
			shr_table_set_row_subtable(t, row,
					stdout_id_ns_dps_table(ns->dps));

		row = stdout_kv_add(t, "nmic", "%#x", ns->nmic);
		if (human)
			shr_table_set_row_subtable(t, row,
					stdout_id_ns_nmic_table(ns->nmic));

		row = stdout_kv_add(t, "rescap", "%#x", ns->rescap);
		if (human)
			shr_table_set_row_subtable(t, row,
					stdout_id_ns_rescap_table(ns->rescap));

		row = stdout_kv_add(t, "fpi", "%#x", ns->fpi);
		if (human)
			shr_table_set_row_subtable(t, row,
					stdout_id_ns_fpi_table(ns->fpi));

		row = stdout_kv_add(t, "dlfeat", "%d", ns->dlfeat);
		if (human)
			shr_table_set_row_subtable(t, row,
					stdout_id_ns_dlfeat_table(ns->dlfeat));

		stdout_kv_add(t, "nawun", "%d", le16_to_cpu(ns->nawun));
		stdout_kv_add(t, "nawupf", "%d", le16_to_cpu(ns->nawupf));
		stdout_kv_add(t, "nacwu", "%d", le16_to_cpu(ns->nacwu));
		stdout_kv_add(t, "nabsn", "%d", le16_to_cpu(ns->nabsn));
		stdout_kv_add(t, "nabo", "%d", le16_to_cpu(ns->nabo));
		stdout_kv_add(t, "nabspf", "%d", le16_to_cpu(ns->nabspf));
		stdout_kv_add(t, "noiob", "%d", le16_to_cpu(ns->noiob));
		stdout_kv_add(t, "nvmcap", "%s",
			      uint128_t_to_l10n_string(
					      le128_to_cpu(ns->nvmcap)));
		if (ns->nsfeat & 0x30) {
			stdout_kv_add(t, "npwg", "%u", le16_to_cpu(ns->npwg));
			stdout_kv_add(t, "npwa", "%u", le16_to_cpu(ns->npwa));
			if (ns->nsfeat & 0x10)
				stdout_kv_add(t, "npdg", "%u",
					      le16_to_cpu(ns->npdg));
			stdout_kv_add(t, "npda", "%u", le16_to_cpu(ns->npda));
			stdout_kv_add(t, "nows", "%u", le16_to_cpu(ns->nows));
		}
		stdout_kv_add(t, "mssrl", "%u", le16_to_cpu(ns->mssrl));
		stdout_kv_add(t, "mcl", "%u", le32_to_cpu(ns->mcl));
		stdout_kv_add(t, "msrc", "%u", ns->msrc);

		row = stdout_kv_add(t, "kpios", "%u", ns->kpios);
		if (human)
			shr_table_set_row_subtable(t, row,
					stdout_id_ns_kpios_table(ns->kpios));
	}

	stdout_kv_add(t, "nulbaf", "%u", ns->nulbaf);
	if (!cap_only) {
		stdout_kv_add(t, "kpiodaag", "%u", le32_to_cpu(ns->kpiodaag));
		stdout_kv_add(t, "anagrpid", "%u", le32_to_cpu(ns->anagrpid));

		row = stdout_kv_add(t, "nsattr", "%u", ns->nsattr);
		if (human)
			shr_table_set_row_subtable(t, row,
					stdout_id_ns_nsattr_table(ns->nsattr));

		stdout_kv_add(t, "nvmsetid", "%d", le16_to_cpu(ns->nvmsetid));
		stdout_kv_add(t, "endgid", "%d", le16_to_cpu(ns->endgid));

		for (i = 0; i < (int)sizeof(ns->nguid); i++)
			nguid += sprintf(nguid, "%02x", ns->nguid[i]);
		stdout_kv_add(t, "nguid", "%s", nguid_buf);

		for (i = 0; i < (int)sizeof(ns->eui64); i++)
			eui64 += sprintf(eui64, "%02x", ns->eui64[i]);
		stdout_kv_add(t, "eui64", "%s", eui64_buf);
	}

	stdout_kv_table_finish(t, "identify-namespace");

	nvme_id_ns_flbas_to_lbaf_inuse(ns->flbas, &flbas);
	for (i = 0; i <= ns->nlbaf + ns->nulbaf; i++) {
		if (human)
			printf("LBA Format %2d : Metadata Size: %-3d bytes - "
				"Data Size: %-2d bytes - Relative Performance: %#x %s %s\n",
				i, le16_to_cpu(ns->lbaf[i].ms),
				1 << ns->lbaf[i].ds, ns->lbaf[i].rp,
				ns->lbaf[i].rp == 3 ? "Degraded" :
					ns->lbaf[i].rp == 2 ? "Good" :
					ns->lbaf[i].rp == 1 ? "Better" : "Best",
					i == flbas ? in_use : "");
		else
			printf("lbaf %2d : ms:%-3d lbads:%-2d rp:%#x %s\n", i,
				le16_to_cpu(ns->lbaf[i].ms), ns->lbaf[i].ds,
				ns->lbaf[i].rp,	i == flbas ? in_use : "");
	}

	if (vs && !cap_only) {
		printf("vs[]:\n");
		d(ns->vs, sizeof(ns->vs), 16, 1);
	}
}

static struct shr_table *
stdout_cmd_set_independent_id_ns_nsfeat_table(__u8 nsfeat)
{
	struct shr_table *t;
	__u8 rsvd6 = (nsfeat & 0xE0) >> 6;
	__u8 vwcnp = (nsfeat & 0x20) >> 5;
	__u8 rmedia = (nsfeat & 0x10) >> 4;
	__u8 uidreuse = (nsfeat & 0x8) >> 3;
	__u8 rsvd0 = (nsfeat & 0x7);

	t = stdout_bits_table_create();
	if (!t)
		return NULL;

	if (rsvd6)
		stdout_bits_add(t, "[7:6]", rsvd6, "Reserved");
	stdout_bits_add(t, "[5:5]", vwcnp,
			 "Volatile Write Cache is %sPresent",
			 vwcnp ? "" : "Not ");
	stdout_bits_add(t, "[4:4]", rmedia,
			 "Namespace %sstore data on rotational media",
			 rmedia ? "" : "does not ");
	stdout_bits_add(t, "[3:3]", uidreuse,
			 "NGUID and EUI64 fields if non-zero, %sReused",
			 uidreuse ? "Never " : "");
	if (rsvd0)
		stdout_bits_add(t, "[2:0]", rsvd0, "Reserved");

	return t;
}

static struct shr_table *
stdout_cmd_set_independent_id_ns_nstat_table(__u8 nstat)
{
	struct shr_table *t;
	__u8 rsvd3 = (nstat & 0xf8) >> 3;
	__u8 ioi = (nstat & 0x6) >> 1;
	__u8 nrdy = nstat & 0x1;

	static const char * const ioi_string[] = {
		"I/O performance degradation is not reported",
		"Reserved",
		"I/O performance is not currently degraded",
		"I/O performance is currently degraded"
	};

	t = stdout_bits_table_create();
	if (!t)
		return NULL;

	if (rsvd3)
		stdout_bits_add(t, "[7:3]", rsvd3, "Reserved");
	stdout_bits_add(t, "[2:1]", ioi, "%s", ioi_string[ioi]);
	stdout_bits_add(t, "[0:0]", nrdy, "Name space is %sready",
			 nrdy ? "" : "not ");

	return t;
}

static void stdout_cmd_set_independent_id_ns(struct nvme_id_independent_id_ns *ns,
					     unsigned int nsid)
{
	bool human = stdout_print_ops.flags & VERBOSE;
	struct shr_table *t;
	int row;

	printf("NVME Identify Command Set Independent Namespace %d:\n", nsid);

	t = stdout_kv_table_create();
	if (!t)
		return;

	row = stdout_kv_add(t, "nsfeat", "%#x", ns->nsfeat);
	if (human)
		shr_table_set_row_subtable(t, row,
				stdout_cmd_set_independent_id_ns_nsfeat_table(
						ns->nsfeat));

	row = stdout_kv_add(t, "nmic", "%#x", ns->nmic);
	if (human)
		shr_table_set_row_subtable(t, row,
				stdout_id_ns_nmic_table(ns->nmic));

	row = stdout_kv_add(t, "rescap", "%#x", ns->rescap);
	if (human)
		shr_table_set_row_subtable(t, row,
				stdout_id_ns_rescap_table(ns->rescap));

	row = stdout_kv_add(t, "fpi", "%#x", ns->fpi);
	if (human)
		shr_table_set_row_subtable(t, row,
				stdout_id_ns_fpi_table(ns->fpi));

	stdout_kv_add(t, "anagrpid", "%u", le32_to_cpu(ns->anagrpid));

	row = stdout_kv_add(t, "nsattr", "%u", ns->nsattr);
	if (human)
		shr_table_set_row_subtable(t, row,
				stdout_id_ns_nsattr_table(ns->nsattr));

	stdout_kv_add(t, "nvmsetid", "%d", le16_to_cpu(ns->nvmsetid));
	stdout_kv_add(t, "endgid", "%d", le16_to_cpu(ns->endgid));

	row = stdout_kv_add(t, "nstat", "%#x", ns->nstat);
	if (human)
		shr_table_set_row_subtable(t, row,
				stdout_cmd_set_independent_id_ns_nstat_table(
						ns->nstat));

	row = stdout_kv_add(t, "kpios", "%#x", ns->kpios);
	if (human)
		shr_table_set_row_subtable(t, row,
				stdout_id_ns_kpios_table(ns->kpios));

	stdout_kv_add(t, "maxkt", "%#x", le16_to_cpu(ns->maxkt));
	stdout_kv_add(t, "rgrpid", "%#x", le32_to_cpu(ns->rgrpid));

	stdout_kv_table_finish(t, "id-independent-id-ns");
}

static void stdout_id_ns_descs(void *data, unsigned int nsid)
{
	int pos, len = 0;
	int i, verbose = stdout_print_ops.flags & VERBOSE;
	__u8 uuid[NVME_UUID_LEN];
	char uuid_str[NVME_UUID_LEN_STRING];
	__u8 eui64[8];
	__u8 nguid[16];
	__u8 csi;
	struct shr_table *t;
	char hex[NVME_UUID_LEN * 2 + 1], *hp;

	printf("NVME Namespace Identification Descriptors NS %d:\n", nsid);

	t = stdout_kv_table_create();
	if (!t)
		return;

	for (pos = 0; pos < NVME_IDENTIFY_DATA_SIZE; pos += len) {
		struct nvme_ns_id_desc *cur = data + pos;

		if (cur->nidl == 0)
			break;

		if (verbose) {
			stdout_kv_add(t, "loc", "%d", pos);
			stdout_kv_add(t, "nidt", "%d", (int)cur->nidt);
			stdout_kv_add(t, "nidl", "%d", (int)cur->nidl);
		}

		switch (cur->nidt) {
		case NVME_NIDT_EUI64:
			memcpy(eui64, data + pos + sizeof(*cur), sizeof(eui64));
			if (verbose)
				stdout_kv_add(t, "type", "%s", "eui64");
			hp = hex;
			for (i = 0; i < 8; i++)
				hp += sprintf(hp, "%02x", eui64[i]);
			stdout_kv_add(t, "eui64", "%s", hex);
			len = sizeof(eui64);
			break;
		case NVME_NIDT_NGUID:
			memcpy(nguid, data + pos + sizeof(*cur), sizeof(nguid));
			if (verbose)
				stdout_kv_add(t, "type", "%s", "nguid");
			hp = hex;
			for (i = 0; i < 16; i++)
				hp += sprintf(hp, "%02x", nguid[i]);
			stdout_kv_add(t, "nguid", "%s", hex);
			len = sizeof(nguid);
			break;
		case NVME_NIDT_UUID:
			memcpy(uuid, data + pos + sizeof(*cur), 16);
			libnvme_uuid_to_string(uuid, uuid_str);
			if (verbose)
				stdout_kv_add(t, "type", "%s", "uuid");
			stdout_kv_add(t, "uuid", "%s", uuid_str);
			len = sizeof(uuid);
			break;
		case NVME_NIDT_CSI:
			memcpy(&csi, data + pos + sizeof(*cur), 1);
			if (verbose)
				stdout_kv_add(t, "type", "%s", "csi");
			stdout_kv_add(t, "csi", "%#x", csi);
			len += sizeof(csi);
			break;
		default:
			/* Skip unknown types */
			len = cur->nidl;
			break;
		}

		len += sizeof(*cur);
	}

	stdout_kv_table_finish(t, "id-ns-descs");
}

static char *stdout_power_and_scale_str(__u16 power, __u8 scale)
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

static char *stdout_psd_workload_str(__u8 apw)
{
	const char *s;

	switch (apw & 0x7) {
	case NVME_PSD_WORKLOAD_NP:
		s = "-";
		break;
	case 1:
		s = "1MiB 32 RW, 30s idle";
		break;
	case 2:
		s = "80K 128KiB SW";
		break;
	default:
		s = "reserved";
		break;
	}

	return strdup(s);
}

/*
 * Multiplies @time by @ts's scale up front -- e.g. "60us" (6 counts of 10
 * microseconds each) rather than leaving that math to the reader. @ts values
 * beyond the scale table are reserved.
 */
static char *stdout_psd_time_str(__u8 time, __u8 ts)
{
	static const struct {
		unsigned int mult;
		const char *unit;
	} scale[] = {
		{ 1, "us" }, { 10, "us" }, { 100, "us" },
		{ 1, "ms" }, { 10, "ms" }, { 100, "ms" },
		{ 1, "s" }, { 10, "s" }, { 100, "s" },
		{ 1000, "s" }, { 10000, "s" }, { 100000, "s" },
		{ 1000000, "s" },
	};
	char *s = NULL;

	switch (time) {
	case 0:
		if (asprintf(&s, "-") < 0)
			s = NULL;
		break;
	case 1 ... 99:
		if (ts >= ARRAY_SIZE(scale)) {
			if (asprintf(&s, "reserved") < 0)
				s = NULL;
		} else if (asprintf(&s, "%u%s", time * scale[ts].mult,
				    scale[ts].unit) < 0) {
			s = NULL;
		}
		break;
	default:
		if (asprintf(&s, "reserved") < 0)
			s = NULL;
		break;
	}

	return s;
}

/*
 * One row per power state, one column per sub-field -- unlike the bit-decode
 * subtables, which are one row per bit range -- since every power state
 * repeats the same fixed set of fields: a real table, not a "name : value"
 * list. Attached unconditionally, not just under -v.
 */
static struct shr_table *stdout_id_ctrl_ps_table(struct nvme_id_ctrl *ctrl)
{
	/*
	 * no_widen on "ps" and "state": columns 0 and 2 are what
	 * shr_table_align_column() widens to line up the outer table's
	 * "name :" and the bits subtables' "value" column, and this table
	 * happens to have its own columns at those same indices -- which do
	 * not mean the same thing, so they must opt out.
	 */
	struct shr_table_column columns[] = {
		{ "ps", RIGHT, AUTO_WIDTH, .no_widen = true },
		{ "mp", RIGHT, AUTO_WIDTH },
		{ "state", LEFT, AUTO_WIDTH, .no_widen = true },
		{ "enlat", RIGHT, AUTO_WIDTH },
		{ "exlat", RIGHT, AUTO_WIDTH },
		{ "rrt", RIGHT, AUTO_WIDTH },
		{ "rrl", RIGHT, AUTO_WIDTH },
		{ "rwt", RIGHT, AUTO_WIDTH },
		{ "rwl", RIGHT, AUTO_WIDTH },
		{ "idle_power", RIGHT, AUTO_WIDTH },
		{ "active_power", RIGHT, AUTO_WIDTH },
		{ "workload", LEFT, AUTO_WIDTH },
		{ "epfrt", LEFT, AUTO_WIDTH },
		{ "fqvt", LEFT, AUTO_WIDTH },
		{ "epfvt", LEFT, AUTO_WIDTH },
		{ "miiell", RIGHT, AUTO_WIDTH },
	};
	struct shr_table *t;
	bool iiellss = NVME_CTRL_CTRATT_IIELLSS(le32_to_cpu(ctrl->ctratt));
	int i;

	t = shr_table_init_with_columns(columns, ARRAY_SIZE(columns));
	if (!t)
		return NULL;

	for (i = 0; i <= ctrl->npss; i++) {
		struct nvme_id_psd *psd = &ctrl->psd[i];
		__u16 max_power = le16_to_cpu(psd->mp);
		__cleanup_free char *mp = NULL;
		__cleanup_free char *idle_power = NULL;
		__cleanup_free char *active_power = NULL;
		__cleanup_free char *workload = NULL;
		__cleanup_free char *epfrt = NULL;
		__cleanup_free char *fqvt = NULL;
		__cleanup_free char *epfvt = NULL;
		__cleanup_free char *miiell = NULL;
		int row = shr_table_get_row_id(t);

		if (psd->flags & NVME_PSD_FLAGS_MXPS) {
			if (asprintf(&mp, "%01u.%04uW",
				     max_power / 10000, max_power % 10000) < 0)
				mp = NULL;
		} else {
			if (asprintf(&mp, "%01u.%02uW",
				     max_power / 100, max_power % 100) < 0)
				mp = NULL;
		}

		idle_power = stdout_power_and_scale_str(
				le16_to_cpu(psd->idlp),
				nvme_psd_power_scale(psd->ips));
		active_power = stdout_power_and_scale_str(
				le16_to_cpu(psd->actp),
				nvme_psd_power_scale(psd->apws));
		workload = stdout_psd_workload_str(psd->apws);
		epfrt = stdout_psd_time_str(psd->epfrt, psd->epfr_fqv_ts & 0xf);
		fqvt = stdout_psd_time_str(psd->fqvt, psd->epfr_fqv_ts >> 4);
		epfvt = stdout_psd_time_str(psd->epfvt, psd->epfvts & 0xf);

		if (iiellss) {
			__u16 miiell_val = le16_to_cpu(psd->miiell);

			if (miiell_val) {
				if (asprintf(&miiell, "%uus",
					     miiell_val * 100) < 0)
					miiell = NULL;
			} else {
				if (asprintf(&miiell, "none") < 0)
					miiell = NULL;
			}
		}

		shr_table_set_value_int(t, 0, row, i, RIGHT);
		shr_table_set_value_str(t, 1, row, mp ?: "-", RIGHT);
		shr_table_set_value_str(t, 2, row,
				psd->flags & NVME_PSD_FLAGS_NOPS ?
				"non-operational" : "operational",
				LEFT);
		shr_table_set_value_unsigned(t, 3, row,
					      le32_to_cpu(psd->enlat), RIGHT);
		shr_table_set_value_unsigned(t, 4, row,
					      le32_to_cpu(psd->exlat), RIGHT);
		shr_table_set_value_unsigned(t, 5, row, psd->rrt, RIGHT);
		shr_table_set_value_unsigned(t, 6, row, psd->rrl, RIGHT);
		shr_table_set_value_unsigned(t, 7, row, psd->rwt, RIGHT);
		shr_table_set_value_unsigned(t, 8, row, psd->rwl, RIGHT);
		shr_table_set_value_str(t, 9, row, idle_power ?: "-", RIGHT);
		shr_table_set_value_str(t, 10, row, active_power ?: "-", RIGHT);
		shr_table_set_value_str(t, 11, row, workload ?: "-", LEFT);
		shr_table_set_value_str(t, 12, row, epfrt ?: "-", LEFT);
		shr_table_set_value_str(t, 13, row, fqvt ?: "-", LEFT);
		shr_table_set_value_str(t, 14, row, epfvt ?: "-", LEFT);
		shr_table_set_value_str(t, 15, row, miiell ?: "-", RIGHT);

		shr_table_add_row(t, row);
	}

	return t;
}

static void stdout_id_ctrl(struct nvme_id_ctrl *ctrl, const char *product_name,
			   void (*vendor_show)(__u8 *vs, struct json_object *root))
{
	bool verbose = stdout_print_ops.flags & VERBOSE;
	bool vs = stdout_print_ops.flags & VS;
	struct shr_table *t;
	int row;

	if (verbose && product_name)
		printf("%s\n\n", product_name);
	printf("NVME Identify Controller:\n");

	t = stdout_kv_table_create();
	if (!t)
		return;

	stdout_kv_add(t, "vid", "%#x", le16_to_cpu(ctrl->vid));
	stdout_kv_add(t, "ssvid", "%#x", le16_to_cpu(ctrl->ssvid));
	stdout_kv_add(t, "sn", "%-.*s", (int)sizeof(ctrl->sn), ctrl->sn);
	stdout_kv_add(t, "mn", "%-.*s", (int)sizeof(ctrl->mn), ctrl->mn);
	stdout_kv_add(t, "fr", "%-.*s", (int)sizeof(ctrl->fr), ctrl->fr);
	stdout_kv_add(t, "rab", "%d", ctrl->rab);
	stdout_kv_add(t, "ieee", "%02x%02x%02x",
		      ctrl->ieee[2], ctrl->ieee[1], ctrl->ieee[0]);

	row = stdout_kv_add(t, "cmic", "%#x", ctrl->cmic);
	if (verbose)
		shr_table_set_row_subtable(t, row,
				stdout_id_ctrl_cmic_table(ctrl->cmic));

	stdout_kv_add(t, "mdts", "%d", ctrl->mdts);
	stdout_kv_add(t, "cntlid", "%#x", le16_to_cpu(ctrl->cntlid));
	stdout_kv_add(t, "ver", "%#x", le32_to_cpu(ctrl->ver));
	stdout_kv_add(t, "rtd3r", "%#x", le32_to_cpu(ctrl->rtd3r));
	stdout_kv_add(t, "rtd3e", "%#x", le32_to_cpu(ctrl->rtd3e));

	row = stdout_kv_add(t, "oaes", "%#x", le32_to_cpu(ctrl->oaes));
	if (verbose)
		shr_table_set_row_subtable(t, row,
				stdout_id_ctrl_oaes_table(ctrl->oaes));

	row = stdout_kv_add(t, "ctratt", "%#x", le32_to_cpu(ctrl->ctratt));
	if (verbose)
		shr_table_set_row_subtable(t, row,
				stdout_id_ctrl_ctratt_table(ctrl->ctratt));

	stdout_kv_add(t, "rrls", "%#x", le16_to_cpu(ctrl->rrls));

	row = stdout_kv_add(t, "bpcap", "%#x", le16_to_cpu(ctrl->bpcap));
	if (verbose)
		shr_table_set_row_subtable(t, row,
				stdout_id_ctrl_bpcap_table(ctrl->bpcap));

	row = stdout_kv_add(t, "chsi", "%#x", ctrl->chsi);
	if (verbose)
		shr_table_set_row_subtable(t, row,
				stdout_id_ctrl_chsi_table(ctrl->chsi));

	stdout_kv_add(t, "nssl", "%#x", le32_to_cpu(ctrl->nssl));

	row = stdout_kv_add(t, "plsi", "%u", ctrl->plsi);
	if (verbose)
		shr_table_set_row_subtable(t, row,
				stdout_id_ctrl_plsi_table(ctrl->plsi));

	row = stdout_kv_add(t, "cntrltype", "%d", ctrl->cntrltype);
	if (verbose)
		shr_table_set_row_subtable(t, row,
			stdout_id_ctrl_cntrltype_table(ctrl->cntrltype));

	stdout_kv_add(t, "fguid", "%s", shr_uuid_to_string(ctrl->fguid));
	stdout_kv_add(t, "crdt1", "%u", le16_to_cpu(ctrl->crdt1));
	stdout_kv_add(t, "crdt2", "%u", le16_to_cpu(ctrl->crdt2));
	stdout_kv_add(t, "crdt3", "%u", le16_to_cpu(ctrl->crdt3));

	row = stdout_kv_add(t, "crcap", "%u", ctrl->crcap);
	if (verbose)
		shr_table_set_row_subtable(t, row,
				stdout_id_ctrl_crcap_table(ctrl->crcap));

	stdout_kv_add(t, "ciu", "%u", ctrl->ciu);
	stdout_kv_add(t, "cirn", "%"PRIu64,
		      le64_to_cpu(*(__le64 *)ctrl->cirn));

	row = stdout_kv_add(t, "nvmsr", "%u", ctrl->nvmsr);
	if (verbose)
		shr_table_set_row_subtable(t, row,
				stdout_id_ctrl_nvmsr_table(ctrl->nvmsr));

	row = stdout_kv_add(t, "vwci", "%u", ctrl->vwci);
	if (verbose)
		shr_table_set_row_subtable(t, row,
				stdout_id_ctrl_vwci_table(ctrl->vwci));

	row = stdout_kv_add(t, "mec", "%u", ctrl->mec);
	if (verbose)
		shr_table_set_row_subtable(t, row,
				stdout_id_ctrl_mec_table(ctrl->mec));

	row = stdout_kv_add(t, "oacs", "%#x", le16_to_cpu(ctrl->oacs));
	if (verbose)
		shr_table_set_row_subtable(t, row,
				stdout_id_ctrl_oacs_table(ctrl->oacs));

	stdout_kv_add(t, "acl", "%d", ctrl->acl);
	stdout_kv_add(t, "aerl", "%d", ctrl->aerl);

	row = stdout_kv_add(t, "frmw", "%#x", ctrl->frmw);
	if (verbose)
		shr_table_set_row_subtable(t, row,
				stdout_id_ctrl_frmw_table(ctrl->frmw));

	row = stdout_kv_add(t, "lpa", "%#x", ctrl->lpa);
	if (verbose)
		shr_table_set_row_subtable(t, row,
				stdout_id_ctrl_lpa_table(ctrl->lpa));

	row = stdout_kv_add(t, "elpe", "%d", ctrl->elpe);
	if (verbose)
		shr_table_set_row_subtable(t, row,
				stdout_id_ctrl_elpe_table(ctrl->elpe));

	row = stdout_kv_add(t, "npss", "%d", ctrl->npss);
	if (verbose)
		shr_table_set_row_subtable(t, row,
				stdout_id_ctrl_npss_table(ctrl->npss));

	row = stdout_kv_add(t, "avscc", "%#x", ctrl->avscc);
	if (verbose)
		shr_table_set_row_subtable(t, row,
				stdout_id_ctrl_avscc_table(ctrl->avscc));

	row = stdout_kv_add(t, "apsta", "%#x", ctrl->apsta);
	if (verbose)
		shr_table_set_row_subtable(t, row,
				stdout_id_ctrl_apsta_table(ctrl->apsta));

	row = stdout_kv_add(t, "wctemp", "%d", le16_to_cpu(ctrl->wctemp));
	if (verbose)
		shr_table_set_row_subtable(t, row,
				stdout_id_ctrl_wctemp_table(ctrl->wctemp));

	row = stdout_kv_add(t, "cctemp", "%d", le16_to_cpu(ctrl->cctemp));
	if (verbose)
		shr_table_set_row_subtable(t, row,
				stdout_id_ctrl_cctemp_table(ctrl->cctemp));

	stdout_kv_add(t, "mtfa", "%d", le16_to_cpu(ctrl->mtfa));
	stdout_kv_add(t, "hmpre", "%u", le32_to_cpu(ctrl->hmpre));
	stdout_kv_add(t, "hmmin", "%u", le32_to_cpu(ctrl->hmmin));

	row = stdout_kv_add(t, "tnvmcap", "%s",
			     uint128_t_to_l10n_string(
					le128_to_cpu(ctrl->tnvmcap)));
	if (verbose)
		shr_table_set_row_subtable(t, row,
			stdout_id_ctrl_tnvmcap_table(ctrl->tnvmcap));

	row = stdout_kv_add(t, "unvmcap", "%s",
			     uint128_t_to_l10n_string(
					le128_to_cpu(ctrl->unvmcap)));
	if (verbose)
		shr_table_set_row_subtable(t, row,
			stdout_id_ctrl_unvmcap_table(ctrl->unvmcap));

	row = stdout_kv_add(t, "rpmbs", "%#x", le32_to_cpu(ctrl->rpmbs));
	if (verbose)
		shr_table_set_row_subtable(t, row,
				stdout_id_ctrl_rpmbs_table(ctrl->rpmbs));

	stdout_kv_add(t, "edstt", "%d", le16_to_cpu(ctrl->edstt));

	row = stdout_kv_add(t, "dsto", "%d", ctrl->dsto);
	if (verbose)
		shr_table_set_row_subtable(t, row,
				stdout_id_ctrl_dsto_table(ctrl->dsto));

	stdout_kv_add(t, "fwug", "%d", ctrl->fwug);
	stdout_kv_add(t, "kas", "%d", le16_to_cpu(ctrl->kas));

	row = stdout_kv_add(t, "hctma", "%#x", le16_to_cpu(ctrl->hctma));
	if (verbose)
		shr_table_set_row_subtable(t, row,
				stdout_id_ctrl_hctma_table(ctrl->hctma));

	row = stdout_kv_add(t, "mntmt", "%d", le16_to_cpu(ctrl->mntmt));
	if (verbose)
		shr_table_set_row_subtable(t, row,
				stdout_id_ctrl_mntmt_table(ctrl->mntmt));

	row = stdout_kv_add(t, "mxtmt", "%d", le16_to_cpu(ctrl->mxtmt));
	if (verbose)
		shr_table_set_row_subtable(t, row,
				stdout_id_ctrl_mxtmt_table(ctrl->mxtmt));

	row = stdout_kv_add(t, "sanicap", "%#x", le32_to_cpu(ctrl->sanicap));
	if (verbose)
		shr_table_set_row_subtable(t, row,
				stdout_id_ctrl_sanicap_table(ctrl->sanicap));

	stdout_kv_add(t, "hmminds", "%u", le32_to_cpu(ctrl->hmminds));
	stdout_kv_add(t, "hmmaxd", "%d", le16_to_cpu(ctrl->hmmaxd));
	stdout_kv_add(t, "nsetidmax", "%d", le16_to_cpu(ctrl->nsetidmax));
	stdout_kv_add(t, "endgidmax", "%d", le16_to_cpu(ctrl->endgidmax));
	stdout_kv_add(t, "anatt", "%d", ctrl->anatt);

	row = stdout_kv_add(t, "anacap", "%d", ctrl->anacap);
	if (verbose)
		shr_table_set_row_subtable(t, row,
				stdout_id_ctrl_anacap_table(ctrl->anacap));

	stdout_kv_add(t, "anagrpmax", "%u", ctrl->anagrpmax);
	stdout_kv_add(t, "nanagrpid", "%u", le32_to_cpu(ctrl->nanagrpid));
	stdout_kv_add(t, "pels", "%u", le32_to_cpu(ctrl->pels));
	stdout_kv_add(t, "domainid", "%d", le16_to_cpu(ctrl->domainid));

	row = stdout_kv_add(t, "kpioc", "%u", ctrl->kpioc);
	if (verbose)
		shr_table_set_row_subtable(t, row,
				stdout_id_ctrl_kpioc_table(ctrl->kpioc));

	stdout_kv_add(t, "mptfawr", "%d", le16_to_cpu(ctrl->mptfawr));

	row = stdout_kv_add(t, "rmdca", "%#x", ctrl->rmdca);
	if (verbose)
		shr_table_set_row_subtable(t, row,
				stdout_id_ctrl_rmdca_table(ctrl->rmdca));

	stdout_kv_add(t, "megcap", "%s",
		      uint128_t_to_l10n_string(le128_to_cpu(ctrl->megcap)));

	row = stdout_kv_add(t, "tmpthha", "%#x", ctrl->tmpthha);
	if (verbose)
		shr_table_set_row_subtable(t, row,
				stdout_id_ctrl_tmpthha_table(ctrl->tmpthha));

	row = stdout_kv_add(t, "mupa", "%#x", ctrl->mupa);
	if (verbose)
		shr_table_set_row_subtable(t, row,
				stdout_id_ctrl_mupa_table(ctrl->mupa));

	stdout_kv_add(t, "cqt", "%d", le16_to_cpu(ctrl->cqt));

	row = stdout_kv_add(t, "cdpa", "%d", le16_to_cpu(ctrl->cdpa));
	if (verbose)
		shr_table_set_row_subtable(t, row,
				stdout_id_ctrl_cdpa_table(ctrl->cdpa));

	stdout_kv_add(t, "mup", "%d", le16_to_cpu(ctrl->mup));

	row = stdout_kv_add(t, "ipmsr", "%#x", le16_to_cpu(ctrl->ipmsr));
	if (verbose)
		shr_table_set_row_subtable(t, row,
				stdout_id_ctrl_ipmsr_table(ctrl->ipmsr));

	stdout_kv_add(t, "msmt", "%#x", le16_to_cpu(ctrl->msmt));
	stdout_kv_add(t, "mnens", "%u", le16_to_cpu(ctrl->mnens));
	stdout_kv_add(t, "mnecpens", "%u", le16_to_cpu(ctrl->mnecpens));
	stdout_kv_add(t, "mensnn", "%u", le32_to_cpu(ctrl->mensnn));

	row = stdout_kv_add(t, "ensa", "%#x", ctrl->ensa);
	if (verbose)
		shr_table_set_row_subtable(t, row,
				stdout_id_ctrl_ensa_table(ctrl->ensa));

	row = stdout_kv_add(t, "endsfs", "%#x", ctrl->endsfs);
	if (verbose)
		shr_table_set_row_subtable(t, row,
				stdout_id_ctrl_endsfs_table(ctrl->endsfs));

	if (NVME_CTRL_CTRATT_VMS(le32_to_cpu(ctrl->ctratt))) {
		row = stdout_kv_add(t, "vsen1", "%#x",
				    le32_to_cpu(ctrl->vsen1));
		if (verbose)
			shr_table_set_row_subtable(t, row,
					stdout_id_ctrl_vsen_table(ctrl->vsen1));

		row = stdout_kv_add(t, "vsen2", "%#x",
				    le32_to_cpu(ctrl->vsen2));
		if (verbose)
			shr_table_set_row_subtable(t, row,
					stdout_id_ctrl_vsen_table(ctrl->vsen2));

		row = stdout_kv_add(t, "vsen3", "%#x",
				    le32_to_cpu(ctrl->vsen3));
		if (verbose)
			shr_table_set_row_subtable(t, row,
					stdout_id_ctrl_vsen_table(ctrl->vsen3));

		row = stdout_kv_add(t, "vsen4", "%#x",
				    le32_to_cpu(ctrl->vsen4));
		if (verbose)
			shr_table_set_row_subtable(t, row,
					stdout_id_ctrl_vsen_table(ctrl->vsen4));

		stdout_kv_add(t, "msvmt", "%u", le16_to_cpu(ctrl->msvmt));
	}

	row = stdout_kv_add(t, "sqes", "%#x", ctrl->sqes);
	if (verbose)
		shr_table_set_row_subtable(t, row,
				stdout_id_ctrl_sqes_table(ctrl->sqes));

	row = stdout_kv_add(t, "cqes", "%#x", ctrl->cqes);
	if (verbose)
		shr_table_set_row_subtable(t, row,
				stdout_id_ctrl_cqes_table(ctrl->cqes));

	stdout_kv_add(t, "maxcmd", "%d", le16_to_cpu(ctrl->maxcmd));
	stdout_kv_add(t, "nn", "%u", le32_to_cpu(ctrl->nn));

	row = stdout_kv_add(t, "oncs", "%#x", le16_to_cpu(ctrl->oncs));
	if (verbose)
		shr_table_set_row_subtable(t, row,
				stdout_id_ctrl_oncs_table(ctrl->oncs));

	row = stdout_kv_add(t, "fuses", "%#x", le16_to_cpu(ctrl->fuses));
	if (verbose)
		shr_table_set_row_subtable(t, row,
				stdout_id_ctrl_fuses_table(ctrl->fuses));

	row = stdout_kv_add(t, "fna", "%#x", ctrl->fna);
	if (verbose)
		shr_table_set_row_subtable(t, row,
				stdout_id_ctrl_fna_table(ctrl->fna));

	row = stdout_kv_add(t, "vwc", "%#x", ctrl->vwc);
	if (verbose)
		shr_table_set_row_subtable(t, row,
				stdout_id_ctrl_vwc_table(ctrl->vwc));

	stdout_kv_add(t, "awun", "%d", le16_to_cpu(ctrl->awun));
	stdout_kv_add(t, "awupf", "%d", le16_to_cpu(ctrl->awupf));

	row = stdout_kv_add(t, "icsvscc", "%d", ctrl->icsvscc);
	if (verbose)
		shr_table_set_row_subtable(t, row,
				stdout_id_ctrl_icsvscc_table(ctrl->icsvscc));

	row = stdout_kv_add(t, "nwpc", "%d", ctrl->nwpc);
	if (verbose)
		shr_table_set_row_subtable(t, row,
				stdout_id_ctrl_nwpc_table(ctrl->nwpc));

	stdout_kv_add(t, "acwu", "%d", le16_to_cpu(ctrl->acwu));

	row = stdout_kv_add(t, "ocfs", "%#x", le16_to_cpu(ctrl->ocfs));
	if (verbose)
		shr_table_set_row_subtable(t, row,
				stdout_id_ctrl_ocfs_table(ctrl->ocfs));

	row = stdout_kv_add(t, "sgls", "%#x", le32_to_cpu(ctrl->sgls));
	if (verbose)
		shr_table_set_row_subtable(t, row,
				stdout_id_ctrl_sgls_table(ctrl->sgls));

	stdout_kv_add(t, "mnan", "%u", le32_to_cpu(ctrl->mnan));
	stdout_kv_add(t, "maxdna", "%s",
		      uint128_t_to_l10n_string(le128_to_cpu(ctrl->maxdna)));
	stdout_kv_add(t, "maxcna", "%u", le32_to_cpu(ctrl->maxcna));
	stdout_kv_add(t, "oaqd", "%u", le32_to_cpu(ctrl->oaqd));
	stdout_kv_add(t, "rhiri", "%d", ctrl->rhiri);
	stdout_kv_add(t, "hirt", "%d", ctrl->hirt);
	stdout_kv_add(t, "cmmrtd", "%d", le16_to_cpu(ctrl->cmmrtd));
	stdout_kv_add(t, "nmmrtd", "%d", le16_to_cpu(ctrl->nmmrtd));
	stdout_kv_add(t, "minmrtg", "%d", ctrl->minmrtg);
	stdout_kv_add(t, "maxmrtg", "%d", ctrl->maxmrtg);

	row = stdout_kv_add(t, "trattr", "%d", ctrl->trattr);
	if (verbose)
		shr_table_set_row_subtable(t, row,
				stdout_id_ctrl_trattr_table(ctrl->trattr));

	stdout_kv_add(t, "mcudmq", "%d", le16_to_cpu(ctrl->mcudmq));
	stdout_kv_add(t, "mnsudmq", "%d", le16_to_cpu(ctrl->mnsudmq));
	stdout_kv_add(t, "mcmr", "%d", le16_to_cpu(ctrl->mcmr));
	stdout_kv_add(t, "nmcmr", "%d", le16_to_cpu(ctrl->nmcmr));
	stdout_kv_add(t, "mcdqpc", "%d", le16_to_cpu(ctrl->mcdqpc));
	stdout_kv_add(t, "subnqn", "%-.*s",
		      (int)sizeof(ctrl->subnqn), ctrl->subnqn);
	stdout_kv_add(t, "ioccsz", "%u", le32_to_cpu(ctrl->ioccsz));
	stdout_kv_add(t, "iorcsz", "%u", le32_to_cpu(ctrl->iorcsz));
	stdout_kv_add(t, "icdoff", "%d", le16_to_cpu(ctrl->icdoff));

	row = stdout_kv_add(t, "fcatt", "%#x", ctrl->fcatt);
	if (verbose)
		shr_table_set_row_subtable(t, row,
				stdout_id_ctrl_fcatt_table(ctrl->fcatt));

	stdout_kv_add(t, "msdbd", "%d", ctrl->msdbd);

	row = stdout_kv_add(t, "ofcs", "%d", le16_to_cpu(ctrl->ofcs));
	if (verbose)
		shr_table_set_row_subtable(t, row,
				stdout_id_ctrl_ofcs_table(ctrl->ofcs));

	row = stdout_kv_add(t, "dctype", "%d", ctrl->dctype);
	if (verbose)
		shr_table_set_row_subtable(t, row,
				stdout_id_ctrl_dctype_table(ctrl->dctype));

	stdout_kv_add(t, "ccrl", "%d", ctrl->ccrl);

	row = stdout_kv_add(t, "ps", "%d states", ctrl->npss + 1);
	/* Unlike the fields above, shown regardless of @verbose. */
	shr_table_set_row_subtable(t, row, stdout_id_ctrl_ps_table(ctrl));

	stdout_kv_table_finish(t, "identify-controller");

	if (vendor_show)
		vendor_show(ctrl->vs, NULL);
	else if (vs) {
		printf("vs[]:\n");
		d(ctrl->vs, sizeof(ctrl->vs), 16, 1);
	}
}

static struct shr_table *stdout_id_ctrl_nvm_kpiocap_table(__u8 kpiocap)
{
	struct shr_table *t;
	__u8 rsvd2 = (kpiocap & 0xfc) >> 2;
	__u8 kpiosc = NVME_CTRL_KPIOC_KPIOSC(kpiocap);
	__u8 kpios = NVME_CTRL_KPIOC_KPIOS(kpiocap);

	t = stdout_bits_table_create();
	if (!t)
		return NULL;

	if (rsvd2)
		stdout_bits_add(t, "[7:2]", rsvd2, "Reserved");
	stdout_bits_add(t, "[1:1]", kpiosc,
			 "Key Per I/O capability enabled and disabled %s in the NVM subsystem",
			 kpiosc ? "all namespaces" : "each namespace");
	stdout_bits_add(t, "[0:0]", kpios, "Key Per I/O capability %sSupported",
			 kpios ? "" : "Not ");

	return t;
}

static struct shr_table *stdout_id_ctrl_nvm_aocs_table(__u16 aocs)
{
	struct shr_table *t;
	__u16 rsvd = (aocs & 0xfffe) >> 1;
	__u8 ralbas = aocs & 0x1;

	t = stdout_bits_table_create();
	if (!t)
		return NULL;

	if (rsvd)
		stdout_bits_add(t, "[15:1]", rsvd, "Reserved");
	stdout_bits_add(t, "[0:0]", ralbas,
			 "Reporting Allocated LBA %sSupported",
			 ralbas ? "" : "Not ");

	return t;
}

static const char *stdout_id_ctrl_nvm_lbamqf_str(__u8 lbamqf)
{
	switch (lbamqf) {
	case NVME_ID_CTRL_NVM_LBAMQF_TYPE_0:
		return "LBA Migration Queue Entry Type 0";
	case NVME_ID_CTRL_NVM_LBAMQF_VENDOR_MIN ... NVME_ID_CTRL_NVM_LBAMQF_VENDOR_MAX:
		return "Vendor Specific";
	default:
		return "Reserved";
	}
}

static void stdout_id_ctrl_nvm(struct nvme_id_ctrl_nvm *ctrl_nvm)
{
	bool verbose = stdout_print_ops.flags & VERBOSE;
	struct shr_table *t;
	__u32 ver;
	int row;

	printf("NVMe Identify Controller NVM:\n");

	t = stdout_kv_table_create();
	if (!t)
		return;

	stdout_kv_add(t, "vsl", "%u", ctrl_nvm->vsl);
	stdout_kv_add(t, "wzsl", "%u", ctrl_nvm->wzsl);
	stdout_kv_add(t, "wusl", "%u", ctrl_nvm->wusl);
	stdout_kv_add(t, "dmrl", "%u", ctrl_nvm->dmrl);
	stdout_kv_add(t, "dmrsl", "%u", le32_to_cpu(ctrl_nvm->dmrsl));
	stdout_kv_add(t, "dmsl", "%"PRIu64, le64_to_cpu(ctrl_nvm->dmsl));

	row = stdout_kv_add(t, "kpiocap", "%u", ctrl_nvm->kpiocap);
	if (verbose)
		shr_table_set_row_subtable(t, row,
				stdout_id_ctrl_nvm_kpiocap_table(
						ctrl_nvm->kpiocap));

	stdout_kv_add(t, "wzdsl", "%u", ctrl_nvm->wzdsl);

	row = stdout_kv_add(t, "aocs", "%u", le16_to_cpu(ctrl_nvm->aocs));
	if (verbose)
		shr_table_set_row_subtable(t, row,
				stdout_id_ctrl_nvm_aocs_table(
						le16_to_cpu(ctrl_nvm->aocs)));

	ver = le32_to_cpu(ctrl_nvm->ver);
	if (verbose)
		stdout_kv_add(t, "ver",
			      "0x%x\tNVM command set specification: %d.%d.%d",
			      ver, NVME_MAJOR(ver), NVME_MINOR(ver),
			      NVME_TERTIARY(ver));
	else
		stdout_kv_add(t, "ver", "0x%x", ver);

	if (verbose)
		stdout_kv_add(t, "lbamqf", "%u\t0x%x: %s", ctrl_nvm->lbamqf,
			      ctrl_nvm->lbamqf,
			      stdout_id_ctrl_nvm_lbamqf_str(ctrl_nvm->lbamqf));
	else
		stdout_kv_add(t, "lbamqf", "%u", ctrl_nvm->lbamqf);

	stdout_kv_table_finish(t, "id-ctrl-nvm");
}

static struct shr_table *stdout_nvm_id_ns_pic_table(__u8 pic)
{
	struct shr_table *t;
	__u8 rsvd = (pic & 0xF0) >> 4;
	__u8 qpifs = (pic & 0x8) >> 3;
	__u8 stcrs = (pic & 0x4) >> 2;
	__u8 pic_16bpistm = (pic & 0x2) >> 1;
	__u8 pic_16bpists = pic & 0x1;

	t = stdout_bits_table_create();
	if (!t)
		return NULL;

	if (rsvd)
		stdout_bits_add(t, "[7:4]", rsvd, "Reserved");
	stdout_bits_add(t, "[3:3]", qpifs,
			 "Qualified Protection Information Format %sSupported",
			 qpifs ? "" : "Not ");
	stdout_bits_add(t, "[2:2]", stcrs,
			 "Storage Tag Check Read %sSupported",
			 stcrs ? "" : "Not ");
	stdout_bits_add(t, "[1:1]", pic_16bpistm,
			 "16b Guard Protection Information Storage Tag Mask");
	stdout_bits_add(t, "[0:0]", pic_16bpists,
			 "16b Guard Protection Information Storage Tag %sSupported",
			 pic_16bpists ? "" : "Not ");

	return t;
}

static struct shr_table *stdout_nvm_id_ns_pifa_table(__u8 pifa)
{
	struct shr_table *t;
	__u8 rsvd = (pifa & 0xF8) >> 3;
	__u8 stmla = pifa & 0x7;

	t = stdout_bits_table_create();
	if (!t)
		return NULL;

	if (rsvd)
		stdout_bits_add(t, "[7:3]", rsvd, "Reserved");
	stdout_bits_add(t, "[2:0]", stmla,
			 "Storage Tag Masking Level Attribute : %s",
			 stmla == 0 ? "Bit Granularity Masking" :
			 stmla == 1 ? "Byte Granularity Masking" :
			 stmla == 2 ? "Masking Not Supported" : "Reserved");

	return t;
}

static char *pif_to_string(__u8 pif, bool qpifs, bool pif_field)
{
	switch (pif) {
	case NVME_NVM_PIF_16B_GUARD:
		return "16b Guard";
	case NVME_NVM_PIF_32B_GUARD:
		return "32b Guard";
	case NVME_NVM_PIF_64B_GUARD:
		return "64b Guard";
	case NVME_NVM_PIF_QTYPE:
		if (pif_field && qpifs)
			return "Qualified Type";
	default:
		return "Reserved";
	}
}

static void stdout_nvm_id_ns(struct nvme_nvm_id_ns *nvm_ns, unsigned int nsid,
			     struct nvme_id_ns *ns, unsigned int lba_index,
			     bool cap_only)
{
	bool verbose = stdout_print_ops.flags & VERBOSE;
	bool qpifs = (nvm_ns->pic & 0x8) >> 3;
	struct shr_table *t;
	__u32 elbaf;
	__u8 lbaf;
	int pif, sts, qpif;
	char *in_use = "(in use)";
	int i, row;

	nvme_id_ns_flbas_to_lbaf_inuse(ns->flbas, &lbaf);

	t = stdout_kv_table_create();
	if (!t)
		return;

	if (!cap_only) {
		printf("NVMe NVM Identify Namespace %d:\n", nsid);
		stdout_kv_add(t, "lbstm", "%#"PRIx64,
			      le64_to_cpu(nvm_ns->lbstm));
	} else {
		printf("NVMe NVM Identify Namespace for LBA format[%d]:\n",
		       lba_index);
		in_use = "";
	}

	row = stdout_kv_add(t, "pic", "%#x", nvm_ns->pic);
	if (verbose)
		shr_table_set_row_subtable(t, row,
				stdout_nvm_id_ns_pic_table(nvm_ns->pic));

	row = stdout_kv_add(t, "pifa", "%#x", nvm_ns->pifa);
	if (verbose)
		shr_table_set_row_subtable(t, row,
				stdout_nvm_id_ns_pifa_table(nvm_ns->pifa));

	stdout_kv_table_finish(t, "nvm-id-ns");

	for (i = 0; i <= ns->nlbaf + ns->nulbaf; i++) {
		elbaf = le32_to_cpu(nvm_ns->elbaf[i]);
		qpif = (elbaf >> 9) & 0xF;
		pif = (elbaf >> 7) & 0x3;
		sts = elbaf & 0x7f;
		if (verbose)
			printf("Extended LBA Format %2d : Qualified Protection Information Format: "
				"%s(%d) - Protection Information Format: %s(%d) - Storage Tag Size "
				"(MSB): %-2d %s\n", i, pif_to_string(qpif, qpifs, false), qpif,
				pif_to_string(pif, qpifs, true), pif, sts, i == lbaf ? in_use : "");
		else
			printf("elbaf %2d : qpif:%d pif:%d sts:%-2d %s\n", i,
				qpif, pif, sts, i == lbaf ? in_use : "");
	}

	t = stdout_kv_table_create();
	if (!t)
		return;

	if (ns->nsfeat & 0x20)
		stdout_kv_add(t, "npdgl", "%#x", le32_to_cpu(nvm_ns->npdgl));

	stdout_kv_add(t, "nprg", "%#x", le32_to_cpu(nvm_ns->nprg));
	stdout_kv_add(t, "npra", "%#x", le32_to_cpu(nvm_ns->npra));
	stdout_kv_add(t, "nors", "%#x", le32_to_cpu(nvm_ns->nors));
	stdout_kv_add(t, "npdal", "%#x", le32_to_cpu(nvm_ns->npdal));
	stdout_kv_add(t, "lbapss", "%#x", le32_to_cpu(nvm_ns->lbapss));
	stdout_kv_add(t, "tlbaag", "%#x", le32_to_cpu(nvm_ns->tlbaag));

	stdout_kv_table_finish(t, "nvm-id-ns");
}

static void stdout_zns_id_ctrl(struct nvme_zns_id_ctrl *ctrl)
{
	printf("NVMe ZNS Identify Controller:\n");
	printf("zasl    : %u\n", ctrl->zasl);
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
		const char *name, __le32 ns_rl, bool human)
{
	unsigned int recommended_limit = le32_to_cpu(ns_rl);

	if (!recommended_limit && human)
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
	bool human = stdout_print_ops.flags & VERBOSE;
	bool vs = stdout_print_ops.flags & VS;
	struct shr_table *t;
	uint8_t lbaf;
	int i, row;

	nvme_id_ns_flbas_to_lbaf_inuse(id_ns->flbas, &lbaf);

	printf("ZNS Command Set Identify Namespace:\n");

	t = stdout_kv_table_create();
	if (!t)
		return;

	if (human) {
		row = stdout_kv_add(t, "zoc",
				     "%u\tZone Operation Characteristics",
				     le16_to_cpu(ns->zoc));
		shr_table_set_row_subtable(t, row,
				show_nvme_id_ns_zoned_zoc_table(ns->zoc));
	} else {
		stdout_kv_add(t, "zoc", "%u", le16_to_cpu(ns->zoc));
	}

	if (human) {
		row = stdout_kv_add(t, "ozcs",
				     "%u\tOptional Zoned Command Support",
				     le16_to_cpu(ns->ozcs));
		shr_table_set_row_subtable(t, row,
				show_nvme_id_ns_zoned_ozcs_table(ns->ozcs));
	} else {
		stdout_kv_add(t, "ozcs", "%u", le16_to_cpu(ns->ozcs));
	}

	if (human) {
		if (ns->mar == 0xffffffff)
			stdout_kv_add(t, "mar", "%s",
				      "No Active Resource Limit");
		else
			stdout_kv_add(t, "mar", "%u\tActive Resources",
				      le32_to_cpu(ns->mar) + 1);
	} else {
		stdout_kv_add(t, "mar", "%#x", le32_to_cpu(ns->mar));
	}

	if (human) {
		if (ns->mor == 0xffffffff)
			stdout_kv_add(t, "mor", "%s",
				      "No Open Resource Limit");
		else
			stdout_kv_add(t, "mor", "%u\tOpen Resources",
				      le32_to_cpu(ns->mor) + 1);
	} else {
		stdout_kv_add(t, "mor", "%#x", le32_to_cpu(ns->mor));
	}

	stdout_zns_id_ns_recommended_limit(t, "rrl", ns->rrl, human);
	stdout_zns_id_ns_recommended_limit(t, "frl", ns->frl, human);
	stdout_zns_id_ns_recommended_limit(t, "rrl1", ns->rrl1, human);
	stdout_zns_id_ns_recommended_limit(t, "rrl2", ns->rrl2, human);
	stdout_zns_id_ns_recommended_limit(t, "rrl3", ns->rrl3, human);
	stdout_zns_id_ns_recommended_limit(t, "frl1", ns->frl1, human);
	stdout_zns_id_ns_recommended_limit(t, "frl2", ns->frl2, human);
	stdout_zns_id_ns_recommended_limit(t, "frl3", ns->frl3, human);

	stdout_kv_add(t, "numzrwa", "%#x", le32_to_cpu(ns->numzrwa));
	stdout_kv_add(t, "zrwafg", "%u", le16_to_cpu(ns->zrwafg));
	stdout_kv_add(t, "zrwasz", "%u", le16_to_cpu(ns->zrwasz));

	if (human) {
		row = stdout_kv_add(t, "zrwacap",
				     "%u\tZone Random Write Area Capability",
				     ns->zrwacap);
		shr_table_set_row_subtable(t, row,
				stdout_zns_id_ns_zrwacap_table(ns->zrwacap));
	} else {
		stdout_kv_add(t, "zrwacap", "%u", ns->zrwacap);
	}

	stdout_kv_table_finish(t, "zns-id-ns");

	for (i = 0; i <= id_ns->nlbaf; i++) {
		if (human)
			printf("LBA Format Extension %2d : Zone Size: %#"PRIx64" LBAs - "
					"Zone Descriptor Extension Size: %-1d bytes%s\n",
				i, le64_to_cpu(ns->lbafe[i].zsze), ns->lbafe[i].zdes << 6,
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

static void stdout_zns_start_zone_list(__u64 nr_zones, struct json_object **zone_list)
{
	printf("nr_zones: %"PRIu64"\n", (uint64_t)le64_to_cpu(nr_zones));
}

static void stdout_zns_changed(struct nvme_zns_changed_zone_log *log)
{
	struct shr_table *t;
	uint16_t nrzid;
	int i;

	nrzid = le16_to_cpu(log->nrzid);
	printf("NVMe Changed Zone List:\n");

	if (nrzid == 0xFFFF) {
		printf("Too many zones have changed to fit into the log. Use report zones for changes.\n");
		return;
	}

	t = stdout_kv_table_create();
	if (!t)
		return;

	stdout_kv_add(t, "nrzid", "%u", nrzid);
	for (i = 0; i < nrzid; i++) {
		char name[16];

		snprintf(name, sizeof(name), "zid %03d", i);
		stdout_kv_add(t, name, "%"PRIu64,
			      (uint64_t)le64_to_cpu(log->zid[i]));
	}

	stdout_kv_table_finish(t, "zns-changed-zone-log");
}

static void stdout_zns_report_zone_attributes(__u8 za, __u8 zai)
{
	const char * const recommended_limit[4] = {"", "1", "2", "3"};

	printf("Attrs: Zone Descriptor Extension is %sVaild\n",
	       za & NVME_ZNS_ZA_ZDEV ? "" : "Not ");

	if (za & NVME_ZNS_ZA_RZR)
		printf("       Reset Zone Recommended with Reset Recommended Limit%s\n",
		       recommended_limit[(zai&0xd)>>2]);

	if (za & NVME_ZNS_ZA_FZR)
		printf("       Finish Zone Recommended with Finish Recommended Limit%s\n",
		       recommended_limit[zai&0x3]);

	if (za & NVME_ZNS_ZA_ZFC)
		printf("       Zone Finished by Controller\n");
}

static void stdout_zns_report_zones(void *report, __u32 descs,
				    __u8 ext_size, __u32 report_size,
				    struct json_object *zone_list)
{
	struct nvme_zone_report *r = report;
	struct nvme_zns_desc *desc;
	int i, verbose = stdout_print_ops.flags & VERBOSE;
	__u64 nr_zones = le64_to_cpu(r->nr_zones);

	if (nr_zones < descs)
		descs = nr_zones;

	for (i = 0; i < descs; i++) {
		desc = (struct nvme_zns_desc *)
			(report + sizeof(*r) + i * (sizeof(*desc) + ext_size));
		if (verbose) {
			printf("SLBA: %#-10"PRIx64" WP: %#-10"PRIx64" Cap: %#-10"PRIx64" State: %-12s Type: %-14s\n",
				(uint64_t)le64_to_cpu(desc->zslba), (uint64_t)le64_to_cpu(desc->wp),
				(uint64_t)le64_to_cpu(desc->zcap), nvme_zone_state_to_string(desc->zs >> 4),
				nvme_zone_type_to_string(desc->zt));
			stdout_zns_report_zone_attributes(desc->za, desc->zai);
		} else {
			printf("SLBA: %#-10"PRIx64" WP: %#-10"PRIx64" Cap: %#-10"PRIx64" State: %#-4x Type: %#-4x Attrs: %#-4x AttrsInfo: %#-4x\n",
				(uint64_t)le64_to_cpu(desc->zslba), (uint64_t)le64_to_cpu(desc->wp),
				(uint64_t)le64_to_cpu(desc->zcap), desc->zs, desc->zt,
				desc->za, desc->zai);
		}

		if (ext_size && (desc->za & NVME_ZNS_ZA_ZDEV)) {
			printf("Extension Data: ");
			d((unsigned char *)desc + sizeof(*desc), ext_size, 16, 1);
			printf("..\n");
		}
	}
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

static void stdout_id_nvmset(struct nvme_id_nvmset_list *nvmset,
			     unsigned int nvmset_id)
{
	struct shr_table *t;
	int i;

	printf("NVME Identify NVM Set List %d:\n", nvmset_id);

	t = stdout_kv_table_create();
	if (!t)
		return;

	stdout_kv_add(t, "nid", "%d", nvmset->nid);

	stdout_kv_table_finish(t, "id-nvmset");

	printf(".................\n");
	for (i = 0; i < nvmset->nid; i++) {
		printf(" NVM Set Attribute Entry[%2d]\n", i);
		printf(".................\n");

		t = stdout_kv_table_create();
		if (!t)
			return;

		stdout_kv_add(t, "nvmset_id", "%d",
			      le16_to_cpu(nvmset->ent[i].nvmsetid));
		stdout_kv_add(t, "endurance_group_id", "%d",
			      le16_to_cpu(nvmset->ent[i].endgid));
		stdout_kv_add(t, "random_4k_read_typical", "%u",
			      le32_to_cpu(nvmset->ent[i].rr4kt));
		stdout_kv_add(t, "optimal_write_size", "%u",
			      le32_to_cpu(nvmset->ent[i].ows));
		stdout_kv_add(t, "total_nvmset_cap", "%s",
			      uint128_t_to_l10n_string(le128_to_cpu(
					nvmset->ent[i].tnvmsetcap)));
		stdout_kv_add(t, "unalloc_nvmset_cap", "%s",
			      uint128_t_to_l10n_string(le128_to_cpu(
					nvmset->ent[i].unvmsetcap)));

		stdout_kv_table_finish(t, "nvm-set-attribute");

		printf(".................\n");
	}
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
	bool human = stdout_print_ops.flags & VERBOSE;
	struct shr_table *t;
	int row;

	printf("NVME Identify Primary Controller Capabilities:\n");

	t = stdout_kv_table_create();
	if (!t)
		return;

	stdout_kv_add(t, "cntlid", "%#x", le16_to_cpu(caps->cntlid));
	stdout_kv_add(t, "portid", "%#x", le16_to_cpu(caps->portid));

	row = stdout_kv_add(t, "crt", "%#x", caps->crt);
	if (human)
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

static void stdout_list_secondary_ctrl(const struct nvme_secondary_ctrl_list *sc_list,
				       __u32 count)
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

static void stdout_id_ns_granularity_list(const struct nvme_id_ns_granularity_list *glist)
{
	struct shr_table *t;
	int i;

	printf("Identify Namespace Granularity List:\n");

	t = stdout_kv_table_create();
	if (!t)
		return;

	stdout_kv_add(t, "Namespace Granularity Attributes (ATTR)",
		      "%#x", glist->attributes);
	stdout_kv_add(t, "Number of Descriptors (NUMD)",
		      "%d", glist->num_descriptors);

	stdout_kv_table_finish(t, "id-ns-granularity-list");

	/* Number of Descriptors is a 0's based value */
	for (i = 0; i <= glist->num_descriptors; i++) {
		printf("\n     Entry[%2d] :\n", i);
		printf("................\n");

		t = stdout_kv_table_create();
		if (!t)
			return;

		shr_table_set_indent(t, 2);

		stdout_kv_add(t, "Namespace Size Granularity (NSG)",
			      "%#"PRIx64,
			      le64_to_cpu(glist->entry[i].nszegran));
		stdout_kv_add(t, "Namespace Capacity Granularity (NCG)",
			      "%#"PRIx64,
			      le64_to_cpu(glist->entry[i].ncapgran));

		stdout_kv_table_finish(t, "id-ns-granularity-list");
	}
}

static void stdout_id_uuid_list(const struct nvme_id_uuid_list *uuid_list)
{
	bool human = stdout_print_ops.flags & VERBOSE;
	struct shr_table *t;
	int i;

	printf("NVME Identify UUID:\n");

	for (i = 0; i < NVME_ID_UUID_LIST_MAX; i++) {
		__u8 uuid[NVME_UUID_LEN];
		char *association = "";
		uint8_t identifier_association = uuid_list->entry[i].header & 0x3;
		/* The list is terminated by a zero UUID value */
		if (memcmp(uuid_list->entry[i].uuid, zero_uuid, NVME_UUID_LEN) == 0)
			break;
		memcpy(&uuid, uuid_list->entry[i].uuid, NVME_UUID_LEN);
		if (human) {
			switch (identifier_association) {
			case 0x0:
				association = "No association reported";
				break;
			case 0x1:
				association = "associated with PCI Vendor ID";
				break;
			case 0x2:
				association = "associated with PCI Subsystem Vendor ID";
				break;
			default:
				association = "Reserved";
				break;
			}
		}

		printf(" Entry[%3d]\n", i + 1);
		printf(".................\n");

		t = stdout_kv_table_create();
		if (!t)
			return;

		stdout_kv_add(t, "association", "%#x %s",
			      identifier_association, association);

		if (memcmp(uuid_list->entry[i].uuid, invalid_uuid,
			   sizeof(zero_uuid)) == 0)
			stdout_kv_add(t, "UUID", "%s (Invalid UUID)",
				      shr_uuid_to_string(uuid));
		else
			stdout_kv_add(t, "UUID", "%s",
				      shr_uuid_to_string(uuid));

		stdout_kv_table_finish(t, "id-uuid-list");

		printf(".................\n");
	}
}

static void stdout_id_domain_list(struct nvme_id_domain_list *id_dom)
{
	struct shr_table *t;
	int i;

	t = stdout_kv_table_create();
	if (!t)
		return;

	stdout_kv_add(t, "Number of Domain Entries", "%u", id_dom->num);

	for (i = 0; i < id_dom->num; i++) {
		struct nvme_id_domain_attr *attr = &id_dom->domain_attr[i];
		char name[64];

		snprintf(name, sizeof(name), "Domain Id for Attr Entry[%u]", i);
		stdout_kv_add(t, name, "%u", le16_to_cpu(attr->dom_id));

		snprintf(name, sizeof(name),
			 "Domain Capacity for Attr Entry[%u]", i);
		stdout_kv_add(t, name, "%s", uint128_t_to_l10n_string(
			      le128_to_cpu(attr->dom_cap)));

		snprintf(name, sizeof(name),
			 "Unallocated Domain Capacity for Attr Entry[%u]", i);
		stdout_kv_add(t, name, "%s", uint128_t_to_l10n_string(
			      le128_to_cpu(attr->unalloc_dom_cap)));

		snprintf(name, sizeof(name),
			 "Max Endurance Group Domain Capacity for Attr Entry[%u]",
			 i);
		stdout_kv_add(t, name, "%s", uint128_t_to_l10n_string(
			      le128_to_cpu(attr->max_egrp_dom_cap)));
	}

	stdout_kv_table_finish(t, "id-domain-list");
}

static void stdout_endurance_group_list(struct nvme_id_endurance_group_list *endgrp_list)
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

static struct shr_table *stdout_id_iocs_iocsc_table(__u64 iocsc)
{
	struct shr_table *t;
	__u8 cpncs = NVME_GET(iocsc, IOCS_IOCSC_CPNCS);
	__u8 slmcs = NVME_GET(iocsc, IOCS_IOCSC_SLMCS);
	__u8 znscs = NVME_GET(iocsc, IOCS_IOCSC_ZNSCS);
	__u8 kvcs = NVME_GET(iocsc, IOCS_IOCSC_KVCS);
	__u8 nvmcs = NVME_GET(iocsc, IOCS_IOCSC_NVMCS);

	t = stdout_bits_table_create();
	if (!t)
		return NULL;

	stdout_bits_add(t, "[4:4]", cpncs,
			"Computational Programs Namespace Command Set %sSelected",
			cpncs ? "" : "Not ");
	stdout_bits_add(t, "[3:3]", slmcs,
			"Subsystem Local Memory Command Set %sSelected",
			slmcs ? "" : "Not ");
	stdout_bits_add(t, "[2:2]", znscs,
			"Zoned Namespace Command Set %sSelected",
			znscs ? "" : "Not ");
	stdout_bits_add(t, "[1:1]", kvcs, "Key Value Command Set %sSelected",
			kvcs ? "" : "Not ");
	stdout_bits_add(t, "[0:0]", nvmcs, "NVM Command Set %sSelected",
			nvmcs ? "" : "Not ");

	return t;
}

static void stdout_id_iocs(struct nvme_id_iocs *iocs)
{
	bool human = stdout_print_ops.flags & VERBOSE;
	struct shr_table *t;
	int row;
	__u16 i;

	t = stdout_kv_table_create();
	if (!t)
		return;

	for (i = 0; i < ARRAY_SIZE(iocs->iocsc); i++) {
		char name[48];
		__u64 iocsc;

		if (!iocs->iocsc[i])
			continue;

		iocsc = le64_to_cpu(iocs->iocsc[i]);
		snprintf(name, sizeof(name), "I/O Command Set Combination[%u]",
			 i);
		row = stdout_kv_add(t, name, "%"PRIx64, iocsc);
		if (human)
			shr_table_set_row_subtable(t, row,
				stdout_id_iocs_iocsc_table(iocsc));
	}

	stdout_kv_table_finish(t, "id-iocs");
}

static void stdout_error_log(struct nvme_error_log_page *err_log, int entries,
			     const char *devname,
			     struct nvme_error_log_filter *flt)
{
	int filtered = 0;
	int i;
	__u16 status;
	__u16 sts;
	struct shr_table *t;

	printf("Error Log Entries for device:%s entries:%d\n", devname,
	       entries);
	printf(".................\n");
	for (i = 0; i < entries; i++) {
		if (nvme_is_error_log_filter(&err_log[i], flt)) {
			filtered++;
			continue;
		}

		sts = le16_to_cpu(err_log[i].status_field);
		status = NVME_ERR_SF_STATUS_FIELD(sts);

		printf(" Entry[%2d]\n", i);
		printf(".................\n");

		t = stdout_kv_table_create();
		if (!t)
			return;

		stdout_kv_add(t, "error_count", "%"PRIu64,
			      le64_to_cpu(err_log[i].error_count));
		stdout_kv_add(t, "sqid", "%d", le16_to_cpu(err_log[i].sqid));
		stdout_kv_add(t, "cmdid", "%#x",
			      le16_to_cpu(err_log[i].cmdid));
		stdout_kv_add(t, "status_field", "%#x (%s)", status,
			      libnvme_status_to_string(status, false));
		stdout_kv_add(t, "phase_tag", "%#x",
			      NVME_ERR_SF_PHASE_TAG(sts));
		stdout_kv_add(t, "parm_err_loc", "%#x",
			      le16_to_cpu(err_log[i].parm_error_location));
		stdout_kv_add(t, "lba", "%#"PRIx64,
			      le64_to_cpu(err_log[i].lba));
		stdout_kv_add(t, "nsid", "%#x", le32_to_cpu(err_log[i].nsid));
		stdout_kv_add(t, "vs", "%d", err_log[i].vs);
		stdout_kv_add(t, "trtype", "%#x (%s)", err_log[i].trtype,
			      nvme_trtype_to_string(err_log[i].trtype));
		stdout_kv_add(t, "csi", "%d", err_log[i].csi);
		stdout_kv_add(t, "opcode", "%#x", err_log[i].opcode);
		stdout_kv_add(t, "cs", "%#"PRIx64, le64_to_cpu(err_log[i].cs));
		stdout_kv_add(t, "trtype_spec_info", "%#x",
			      le16_to_cpu(err_log[i].trtype_spec_info));
		stdout_kv_add(t, "log_page_version", "%d",
			      err_log[i].log_page_version);

		stdout_kv_table_finish(t, "error-log");

		printf(".................\n");
	}

	if (entries == filtered)
		printf("all entries filtered\n");
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
		/* if status buffer was too small, don't loop past the end of the buffer */
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

static void stdout_fw_log(struct nvme_firmware_slot *fw_log,
			  const char *devname)
{
	struct shr_table *t;
	__le64 *frs;
	char name[8];
	int i;

	printf("Firmware Log for device:%s\n", devname);

	t = stdout_kv_table_create();
	if (!t)
		return;

	stdout_kv_add(t, "afi", "%#x", fw_log->afi);
	for (i = 0; i < 7; i++) {
		if (fw_log->frs[i][0]) {
			frs = (__le64 *)&fw_log->frs[i];
			snprintf(name, sizeof(name), "frs%d", i + 1);
			stdout_kv_add(t, name, "%#016"PRIx64" (%s)",
				      le64_to_cpu(*frs),
				      shr_fw_to_string(fw_log->frs[i]));
		}
	}

	stdout_kv_table_finish(t, "fw-log");
}

static void stdout_changed_ns_list_log(struct nvme_ns_list *log, const char *devname, bool alloc)
{
	__u32 nsid;
	int i;

	if (log->ns[0] != cpu_to_le32(NVME_NSID_ALL)) {
		for (i = 0; i < NVME_ID_NS_LIST_MAX; i++) {
			nsid = le32_to_cpu(log->ns[i]);
			if (nsid == 0) {
				printf("no ns changed\n");
				break;
			}

			printf("[%4u]:%#x\n", i, nsid);
		}
	} else
		printf("more than %d ns changed\n",
			NVME_ID_NS_LIST_MAX);
}

static void stdout_effects_log_human(__u32 effect)
{
	const char *set = "+";
	const char *clr = "-";

	printf("  CSUPP+");
	printf("  LBCC%s", (effect & NVME_CMD_EFFECTS_LBCC) ? set : clr);
	printf("  NCC%s", (effect & NVME_CMD_EFFECTS_NCC) ? set : clr);
	printf("  NIC%s", (effect & NVME_CMD_EFFECTS_NIC) ? set : clr);
	printf("  CCC%s", (effect & NVME_CMD_EFFECTS_CCC) ? set : clr);
	printf("  USS%s", (effect & NVME_CMD_EFFECTS_UUID_SEL) ? set : clr);

	switch (NVME_CMD_EFFECTS_CSER(effect)) {
	case 0:
		printf("  No CSER defined\n");
		break;
	case 1:
		printf("  No admin command for any namespace\n");
		break;
	default:
		printf("  Reserved CSER\n");
	}

	switch (NVME_CMD_EFFECTS_CSE(effect)) {
	case 0:
		printf("  No command restriction\n");
		break;
	case 1:
		printf("  No other command for same namespace\n");
		break;
	case 2:
		printf("  No other command for any namespace\n");
		break;
	default:
		printf("  Reserved CSE\n");
	}
}

static void stdout_effects_entry(int admin, int index,
				 __le32 entry, unsigned int human)
{
	__u32 effect;
	char *format_string;

	format_string = admin ? "ACS%-6d[%-32s] %08x" : "IOCS%-5d[%-32s] %08x";

	effect = le32_to_cpu(entry);
	if (effect & NVME_CMD_EFFECTS_CSUPP) {
		printf(format_string, index, nvme_cmd_to_string(admin, index),
		       effect);
		if (human)
			stdout_effects_log_human(effect);
		else
			printf("\n");
	}
}

static void stdout_effects_log_segment(int admin, int a, int b,
				       struct nvme_cmd_effects_log *effects,
				       char *header, int human)
{
	bool printed_header = false;

	for (int i = a; i < b; i++) {
		__le32 entry;
		__u32 effect;

		entry = admin ? effects->acs[i] : effects->iocs[i];
		effect = le32_to_cpu(entry);

		if (!(effect & NVME_CMD_EFFECTS_CSUPP))
			continue;

		if (!printed_header && header) {
			printf("%s\n", header);
			printed_header = true;
		}

		stdout_effects_entry(admin, i, entry, human);
	}

	if (printed_header)
		printf("\n");
}

static void stdout_effects_log_page(enum nvme_csi csi,
				    struct nvme_cmd_effects_log *effects)
{
	int human = stdout_print_ops.flags & VERBOSE;

	switch (csi) {
	case NVME_CSI_NVM:
		printf("NVM Command Set Log Page\n");
		printf("%-.80s\n", dash);
		break;
	case NVME_CSI_KV:
		printf("KV Command Set Log Page\n");
		printf("%-.80s\n", dash);
		break;
	case NVME_CSI_ZNS:
		printf("ZNS Command Set Log Page\n");
		printf("%-.80s\n", dash);
		break;
	default:
		printf("Unknown Command Set Log Page\n");
		printf("%-.80s\n", dash);
		break;
	}

	stdout_effects_log_segment(1, 0, 0xbf, effects, "Admin Commands", human);
	stdout_effects_log_segment(1, 0xc0, 0xff, effects, "Vendor Specific Admin Commands", human);
	stdout_effects_log_segment(0, 0, 0x80, effects, "I/O Commands", human);
	stdout_effects_log_segment(0, 0x80, 0x100, effects, "Vendor Specific I/O Commands", human);
}

static void stdout_effects_log_pages(struct list_head *list)
{
	nvme_effects_log_node_t *node = NULL;

	list_for_each(list, node, node) {
		stdout_effects_log_page(node->csi, &node->effects);
	}
}

static struct shr_table *stdout_support_log_human_table(__u32 support, __u8 lid)
{
	struct shr_table *t;
	__u16 lidsp = support >> 16;

	t = stdout_bits_table_create();
	if (!t)
		return NULL;

	stdout_bits_add(t, "[0:0]", support & 0x1, "LSUPP is %sSupported",
			(support & 0x1) ? "" : "Not ");
	stdout_bits_add(t, "[1:1]", (support >> 0x1) & 0x1,
			"IOS is %sSupported",
			((support >> 0x1) & 0x1) ? "" : "Not ");

	switch (lid) {
	case NVME_LOG_LID_TELEMETRY_HOST:
		stdout_bits_add(t, "[16:16]", lidsp & 0x1,
				"Maximum Created Data Area is %sSupported",
				(lidsp & 0x1) ? "" : "Not ");
		break;
	case NVME_LOG_LID_PERSISTENT_EVENT:
		stdout_bits_add(t, "[16:16]", lidsp & 0x1,
				"Establish Context and Read 512 Bytes of Header is %sSupported",
				(lidsp & 0x1) ? "" : "Not ");
		break;
	case NVME_LOG_LID_DISCOVERY:
		stdout_bits_add(t, "[16:16]", lidsp & 0x1,
				"Extended Discovery Log Page Entry is %sSupported",
				(lidsp & 0x1) ? "" : "Not ");
		stdout_bits_add(t, "[17:17]", (lidsp >> 1) & 0x1,
				"Port Local Entries Only is %sSupported",
				((lidsp >> 1) & 0x1) ? "" : "Not ");
		stdout_bits_add(t, "[18:18]", (lidsp >> 2) & 0x1,
				"All NVM Subsystem Entries is %sSupported",
				((lidsp >> 2) & 0x1) ? "" : "Not ");
		break;
	case NVME_LOG_LID_HOST_DISCOVERY:
		stdout_bits_add(t, "[16:16]", lidsp & 0x1,
				"All Host Entries is %sSupported",
				(lidsp & 0x1) ? "" : "Not ");
		break;
	default:
		break;
	}

	return t;
}

static void stdout_supported_log(struct nvme_supported_log_pages *support_log,
				 const char *devname)
{
	int lid, human = stdout_print_ops.flags & VERBOSE;
	__u32 support = 0;
	struct shr_table *t;

	printf("Support Log Pages Details for %s:\n", devname);

	t = stdout_kv_table_create();
	if (!t)
		return;

	for (lid = 0; lid < 256; lid++) {
		support = le32_to_cpu(support_log->lid_support[lid]);
		if (support & 0x1) {
			char name[16];
			int row;

			snprintf(name, sizeof(name), "LID %#x", lid);
			row = stdout_kv_add(t, name, "%s",
					     nvme_log_to_string(lid));
			if (human)
				shr_table_set_row_subtable(t, row,
					stdout_support_log_human_table(
						support, lid));
		}
	}

	stdout_kv_table_finish(t, "supported-log");
}

static void stdout_endurance_log(struct nvme_endurance_group_log *el,
				 __u16 group_id, const char *devname)
{
	struct shr_table *t;

	printf("Endurance Group Log for NVME device:%s Group ID:%x\n", devname, group_id);

	t = stdout_kv_table_create();
	if (!t)
		return;

	stdout_kv_add(t, "critical_warning", "%u", el->critical_warning);
	stdout_kv_add(t, "endurance_group_features", "%u",
		      el->endurance_group_features);
	stdout_kv_add(t, "avl_spare", "%u", el->avl_spare);
	stdout_kv_add(t, "avl_spare_threshold", "%u", el->avl_spare_threshold);
	stdout_kv_add(t, "percent_used", "%u%%", el->percent_used);
	stdout_kv_add(t, "domain_identifier", "%u", el->domain_identifier);
	stdout_kv_add(t, "endurance_estimate", "%s",
		      uint128_t_to_l10n_string(
			      le128_to_cpu(el->endurance_estimate)));
	stdout_kv_add(t, "data_units_read", "%s",
		      uint128_t_to_l10n_string(
			      le128_to_cpu(el->data_units_read)));
	stdout_kv_add(t, "data_units_written", "%s",
		      uint128_t_to_l10n_string(
			      le128_to_cpu(el->data_units_written)));
	stdout_kv_add(t, "media_units_written", "%s",
		      uint128_t_to_l10n_string(
			      le128_to_cpu(el->media_units_written)));
	stdout_kv_add(t, "host_read_cmds", "%s",
		      uint128_t_to_l10n_string(
			      le128_to_cpu(el->host_read_cmds)));
	stdout_kv_add(t, "host_write_cmds", "%s",
		      uint128_t_to_l10n_string(
			      le128_to_cpu(el->host_write_cmds)));
	stdout_kv_add(t, "media_data_integrity_err", "%s",
		      uint128_t_to_l10n_string(
			      le128_to_cpu(el->media_data_integrity_err)));
	stdout_kv_add(t, "num_err_info_log_entries", "%s",
		      uint128_t_to_l10n_string(
			      le128_to_cpu(el->num_err_info_log_entries)));
	stdout_kv_add(t, "total_end_grp_cap", "%s",
		      uint128_t_to_l10n_string(
			      le128_to_cpu(el->total_end_grp_cap)));
	stdout_kv_add(t, "unalloc_end_grp_cap", "%s",
		      uint128_t_to_l10n_string(
			      le128_to_cpu(el->unalloc_end_grp_cap)));

	stdout_kv_table_finish(t, "endurance-log");
}

static struct shr_table *stdout_smart_log_critical_warning_table(__u8 cw)
{
	struct shr_table *t;

	t = stdout_bits_table_create();
	if (!t)
		return NULL;

	stdout_bits_add(t, "[6:6]", NVME_SMART_CW_IPS(cw),
			 "Indeterminate Personality");
	stdout_bits_add(t, "[5:5]", NVME_SMART_CW_PMRRO(cw),
			 "Persistent Mem. RO");
	stdout_bits_add(t, "[4:4]", NVME_SMART_CW_VMBF(cw),
			 "Volatile mem. backup failed");
	stdout_bits_add(t, "[3:3]", NVME_SMART_CW_AMRO(cw), "Read-only");
	stdout_bits_add(t, "[2:2]", NVME_SMART_CW_NDR(cw),
			 "NVM subsystem Reliability");
	stdout_bits_add(t, "[1:1]", NVME_SMART_CW_TTC(cw), "Temp. Threshold");
	stdout_bits_add(t, "[0:0]", NVME_SMART_CW_ASCBT(cw), "Available Spare");

	return t;
}

static struct shr_table *stdout_smart_log_informative_warning_table(__u8 iw)
{
	struct shr_table *t;

	t = stdout_bits_table_create();
	if (!t)
		return NULL;

	stdout_bits_add(t, "[0:0]", !!(iw & NVME_SMART_INFW_VLTHW),
			 "Voltage Log Threshold Warning");

	return t;
}

static void stdout_smart_log(struct nvme_smart_log *smart, unsigned int nsid, const char *devname)
{
	__cleanup_free char *ipm_str = NULL;
	__u16 temperature = smart->temperature[1] << 8 | smart->temperature[0];
	__u32 ipm = le32_to_cpu(smart->interval_power_measurement);
	bool human = stdout_print_ops.flags & VERBOSE;
	struct shr_table *t;
	char name[32];
	int i, row;

	printf("Smart Log for NVME device:%s namespace-id:%x\n", devname, nsid);

	t = stdout_kv_table_create();
	if (!t)
		return;

	row = stdout_kv_add(t, "critical_warning", "%#x",
			     smart->critical_warning);
	if (human)
		shr_table_set_row_subtable(t, row,
				stdout_smart_log_critical_warning_table(
						smart->critical_warning));

	stdout_kv_add(t, "temperature", "%s (%u K, %s)",
		      nvme_degrees_string(temperature), temperature,
		      nvme_degrees_fahrenheit_string(temperature));
	stdout_kv_add(t, "available_spare", "%u%%", smart->avail_spare);
	stdout_kv_add(t, "available_spare_threshold", "%u%%",
		      smart->spare_thresh);
	stdout_kv_add(t, "percentage_used", "%u%%", smart->percent_used);
	stdout_kv_add(t, "endurance group critical warning summary", "%#x",
		      smart->endu_grp_crit_warn_sumry);

	row = stdout_kv_add(t, "informative warning", "%#x",
			     smart->informative_warning);
	if (human)
		shr_table_set_row_subtable(t, row,
				stdout_smart_log_informative_warning_table(
						smart->informative_warning));

	stdout_kv_add(t, "Data Units Read", "%s (%s)",
		      uint128_t_to_l10n_string(
				      le128_to_cpu(smart->data_units_read)),
		      uint128_t_to_si_string(
				      le128_to_cpu(smart->data_units_read),
				      1000 * 512));
	stdout_kv_add(t, "Data Units Written", "%s (%s)",
		      uint128_t_to_l10n_string(
				      le128_to_cpu(smart->data_units_written)),
		      uint128_t_to_si_string(
				      le128_to_cpu(smart->data_units_written),
				      1000 * 512));
	stdout_kv_add(t, "host_read_commands", "%s",
		      uint128_t_to_l10n_string(
				      le128_to_cpu(smart->host_reads)));
	stdout_kv_add(t, "host_write_commands", "%s",
		      uint128_t_to_l10n_string(
				      le128_to_cpu(smart->host_writes)));
	stdout_kv_add(t, "controller_busy_time", "%s",
		      uint128_t_to_l10n_string(
				      le128_to_cpu(smart->ctrl_busy_time)));
	stdout_kv_add(t, "power_cycles", "%s",
		      uint128_t_to_l10n_string(
				      le128_to_cpu(smart->power_cycles)));
	stdout_kv_add(t, "power_on_hours", "%s",
		      uint128_t_to_l10n_string(
				      le128_to_cpu(smart->power_on_hours)));
	stdout_kv_add(t, "unsafe_shutdowns", "%s",
		      uint128_t_to_l10n_string(
				      le128_to_cpu(smart->unsafe_shutdowns)));
	stdout_kv_add(t, "media_errors", "%s",
		      uint128_t_to_l10n_string(
				      le128_to_cpu(smart->media_errors)));
	stdout_kv_add(t, "num_err_log_entries", "%s",
		      uint128_t_to_l10n_string(
			      le128_to_cpu(smart->num_err_log_entries)));
	stdout_kv_add(t, "Warning Temperature Time", "%u",
		      le32_to_cpu(smart->warning_temp_time));
	stdout_kv_add(t, "Critical Composite Temperature Time", "%u",
		      le32_to_cpu(smart->critical_comp_time));

	for (i = 0; i < ARRAY_SIZE(smart->temp_sensor); i++) {
		temperature = le16_to_cpu(smart->temp_sensor[i]);
		if (!temperature)
			continue;
		snprintf(name, sizeof(name), "Temperature Sensor %d", i + 1);
		stdout_kv_add(t, name, "%s (%u K, %s)",
			      nvme_degrees_string(temperature), temperature,
			      nvme_degrees_fahrenheit_string(temperature));
	}

	stdout_kv_add(t, "Thermal Management T1 Trans Count", "%u",
		      le32_to_cpu(smart->thm_temp1_trans_count));
	stdout_kv_add(t, "Thermal Management T2 Trans Count", "%u",
		      le32_to_cpu(smart->thm_temp2_trans_count));
	stdout_kv_add(t, "Thermal Management T1 Total Time", "%u",
		      le32_to_cpu(smart->thm_temp1_total_time));
	stdout_kv_add(t, "Thermal Management T2 Total Time", "%u",
		      le32_to_cpu(smart->thm_temp2_total_time));
	stdout_kv_add(t, "Operational Lifetime Energy Consumed", "%"PRIu64,
		      le64_to_cpu(smart->op_lifetime_energy_consumed));
	stdout_kv_add(t, "Interval Power Measurement Type", "%s",
		      nvme_power_measurement_type_to_string(
				      (ipm >> 20) & 0x3f));

	ipm_str = stdout_power_and_scale_str(ipm & 0xffff, (ipm >> 16) & 0x3);
	stdout_kv_add(t, "Interval Power Measurement", "%s", ipm_str ?: "-");

	stdout_kv_table_finish(t, "smart-log");
}

static void stdout_ana_log(struct nvme_ana_log *ana_log, const char *devname,
			   size_t len)
{
	size_t offset = sizeof(struct nvme_ana_log);
	struct nvme_ana_log *hdr = ana_log;
	struct nvme_ana_group_desc *desc;
	size_t nsid_buf_size;
	void *base = ana_log;
	__u32 nr_nsids;
	struct shr_table *t;
	int i, j;

	printf("Asymmetric Namespace Access Log for NVMe device: %s\n",
			devname);
	printf("ANA LOG HEADER :-\n");

	t = stdout_kv_table_create();
	if (!t)
		return;

	stdout_kv_add(t, "chgcnt", "%"PRIu64, le64_to_cpu(hdr->chgcnt));
	stdout_kv_add(t, "ngrps", "%u", le16_to_cpu(hdr->ngrps));

	stdout_kv_table_finish(t, "ana-log header");

	printf("ANA Log Desc :-\n");

	for (i = 0; i < le16_to_cpu(ana_log->ngrps); i++) {
		if (offset > len || len - offset < sizeof(*desc))
			return;
		desc = base + offset;
		nr_nsids = le32_to_cpu(desc->nnsids);
		nsid_buf_size = (size_t)nr_nsids * sizeof(__le32);
		if (len - offset - sizeof(*desc) < nsid_buf_size)
			return;

		offset += sizeof(*desc);

		t = stdout_kv_table_create();
		if (!t)
			return;

		stdout_kv_add(t, "grpid", "%u", le32_to_cpu(desc->grpid));
		stdout_kv_add(t, "nnsids", "%u", le32_to_cpu(desc->nnsids));
		stdout_kv_add(t, "chgcnt", "%"PRIu64,
			      le64_to_cpu(desc->chgcnt));
		stdout_kv_add(t, "state", "%s",
			      nvme_ana_state_to_string(desc->state));
		for (j = 0; j < nr_nsids; j++)
			stdout_kv_add(t, "nsid", "%u",
				      le32_to_cpu(desc->nsids[j]));

		stdout_kv_table_finish(t, "ana-log group");

		printf("\n");
		offset += nsid_buf_size;
	}
}

static void stdout_self_test_result(struct nvme_st_result *res)
{
	static const char * const test_res[] = {
		"Operation completed without error",
		"Operation was aborted by a Device Self-test command",
		"Operation was aborted by a Controller Level Reset",
		"Operation was aborted due to a removal of a namespace from the namespace inventory",
		"Operation was aborted due to the processing of a Format NVM command",
		"A fatal error or unknown test error occurred while the controller was executing the"\
			" device self-test operation and the operation did not complete",
		"Operation completed with a segment that failed and the segment that failed is not known",
		"Operation completed with one or more failed segments and the first segment that failed "\
			"is indicated in the SegmentNumber field",
		"Operation was aborted for unknown reason",
		"Operation was aborted due to a sanitize operation",
		"Reserved",
		[NVME_ST_RESULT_NOT_USED] = "Entry not used (does not contain a result)",
	};
	static const char * const code_desc[] = {
		[NVME_ST_CODE_SHORT] = "Short device self-test operation",
		[NVME_ST_CODE_EXTENDED] = "Extended device self-test operation",
		[NVME_ST_CODE_HOST_INIT] = "Host-Initiated Refresh operation",
		[NVME_ST_CODE_VS] = "Vendor specific",
	};
	bool verbose = stdout_print_ops.flags & VERBOSE;
	struct shr_table *t;
	__u8 op, code;

	t = stdout_kv_table_create();
	if (!t)
		return;
	shr_table_set_indent(t, 2);

	op = res->dsts & NVME_ST_RESULT_MASK;
	if (verbose)
		stdout_kv_add(t, "Operation Result", "%#x %s", op,
			      (op < ARRAY_SIZE(test_res) && test_res[op]) ?
			      test_res[op] :
			      test_res[ARRAY_SIZE(test_res) - 1]);
	else
		stdout_kv_add(t, "Operation Result", "%#x", op);

	if (op != NVME_ST_RESULT_NOT_USED) {
		code = res->dsts >> NVME_ST_CODE_SHIFT;
		if (verbose)
			stdout_kv_add(t, "Self Test Code", "%x %s", code,
				      code < ARRAY_SIZE(code_desc) &&
				      code_desc[code] ?
				      code_desc[code] : "Reserved");
		else
			stdout_kv_add(t, "Self Test Code", "%x", code);

		if (op == NVME_ST_RESULT_KNOWN_SEG_FAIL)
			stdout_kv_add(t, "Segment Number", "%#x", res->seg);

		stdout_kv_add(t, "Valid Diagnostic Information", "%#x",
			      res->vdi);
		stdout_kv_add(t, "Power on hours (POH)", "%#"PRIx64,
			      (uint64_t)le64_to_cpu(res->poh));

		if (res->vdi & NVME_ST_VALID_DIAG_INFO_NSID)
			stdout_kv_add(t, "Namespace Identifier", "%#x",
				      le32_to_cpu(res->nsid));
		if (res->vdi & NVME_ST_VALID_DIAG_INFO_FLBA)
			stdout_kv_add(t, "Failing LBA", "%#"PRIx64,
				      (uint64_t)le64_to_cpu(res->flba));
		if (res->vdi & NVME_ST_VALID_DIAG_INFO_SCT)
			stdout_kv_add(t, "Status Code Type", "%#x", res->sct);
		if (res->vdi & NVME_ST_VALID_DIAG_INFO_SC) {
			if (verbose)
				stdout_kv_add(t, "Status Code", "%#x %s",
					      res->sc,
					      libnvme_status_to_string(
						(res->sct & 7) << 8 | res->sc,
						false));
			else
				stdout_kv_add(t, "Status Code", "%#x",
					      res->sc);
		}
		stdout_kv_add(t, "Vendor Specific", "%#x %#x",
			      res->vs[0], res->vs[1]);
	}

	stdout_kv_table_finish(t, "self-test-result");
}

static void stdout_self_test_log(struct nvme_self_test_log *self_test,
				 __u8 dst_entries, __u32 size,
				 const char *devname)
{
	struct shr_table *t;
	__u8 num_entries;
	int i;

	printf("Device Self Test Log for NVME device:%s\n", devname);

	t = stdout_kv_table_create();
	if (!t)
		return;

	stdout_kv_add(t, "Current operation", "%#x",
		      self_test->current_operation);
	stdout_kv_add(t, "Current Completion", "%u%%", self_test->completion);

	stdout_kv_table_finish(t, "self-test-log");

	num_entries = min(dst_entries, NVME_LOG_ST_MAX_RESULTS);
	for (i = 0; i < num_entries; i++) {
		printf("Self Test Result[%d]:\n", i);
		stdout_self_test_result(&self_test->result[i]);
	}
}

static struct shr_table *stdout_sanitize_log_sstat_table(__u16 status)
{
	struct shr_table *t;
	const char *str = nvme_sstat_status_to_string(status);
	__u16 gde, mvcncld, prgd;

	t = stdout_bits_table_create();
	if (!t)
		return NULL;

	stdout_bits_add(t, "[2:0]", NVME_GET(status, SANITIZE_SSTAT_STATUS),
			"Sanitize Operation Status: %s", str);
	stdout_bits_add(t, "[7:3]",
			NVME_GET(status, SANITIZE_SSTAT_COMPLETED_PASSES),
			"Overwrite Passes Completed");

	gde = NVME_GET(status, SANITIZE_SSTAT_GLOBAL_DATA_ERASED);
	if (gde)
		str = "No user data has been written in the NVM subsystem and"
		       " no PMR has been enabled in the NVM subsystem";
	else
		str = "User data has been written in the NVM subsystem or"
		       " PMR has been enabled in the NVM subsystem";
	stdout_bits_add(t, "[8:8]", gde, "Global Data Erased: %s", str);

	mvcncld = NVME_GET(status, SANITIZE_SSTAT_MVCNCLD);
	stdout_bits_add(t, "[9:9]", mvcncld, "Media Verification %scanceled",
			mvcncld ? "" : "Not ");

	prgd = NVME_GET(status, SANITIZE_SSTAT_PRGD);
	stdout_bits_add(t, "[11:11]", prgd, "%sPurged", prgd ? "" : "Not ");

	return t;
}

static struct shr_table *stdout_sanitize_log_ssi_table(__u8 ssi, __u16 status)
{
	struct shr_table *t;
	__u8 sans, fails;

	t = stdout_bits_table_create();
	if (!t)
		return NULL;

	sans = NVME_GET(ssi, SANITIZE_SSI_SANS);
	stdout_bits_add(t, "[3:0]", sans, "Sanitize State: %s",
			nvme_ssi_state_to_string(sans));

	if (status == NVME_SANITIZE_SSTAT_STATUS_COMPLETED_FAILED) {
		fails = NVME_GET(ssi, SANITIZE_SSI_FAILS);
		stdout_bits_add(t, "[7:4]", fails, "Failure State: %s",
				nvme_ssi_state_to_string(fails));
	}

	return t;
}

static int stdout_estimate_sanitize_time_add(struct shr_table *t,
		const char *name, uint32_t value)
{
	const char *note;

	note = value == 0xffffffff ? " (No time period reported)" : "";
	return stdout_kv_add(t, name, "%u%s", value, note);
}

static void stdout_sanitize_log(struct nvme_sanitize_log_page *sanitize,
				const char *devname)
{
	__cleanup_free char *sprog_val = NULL;
	struct shr_table *t;
	int human = stdout_print_ops.flags & VERBOSE;
	__u16 sstat = le16_to_cpu(sanitize->sstat);
	__u16 status = sstat & NVME_SANITIZE_SSTAT_STATUS_MASK;
	double percent;
	int row;

	if (human && status == NVME_SANITIZE_SSTAT_STATUS_IN_PROGRESS) {
		percent = ((double)le16_to_cpu(sanitize->sprog) * 100) /
			  0x10000;

		if (asprintf(&sprog_val, "%u  (%f%%)",
			     le16_to_cpu(sanitize->sprog), percent) < 0)
			sprog_val = NULL;
	}

	t = stdout_kv_table_create();
	if (!t)
		return;

	if (sprog_val)
		stdout_kv_add(t, "Sanitize Progress (SPROG)", "%s", sprog_val);
	else
		stdout_kv_add(t, "Sanitize Progress (SPROG)", "%u",
			      le16_to_cpu(sanitize->sprog));

	row = stdout_kv_add(t, "Sanitize Status (SSTAT)", "%#x", sstat);
	if (human)
		shr_table_set_row_subtable(t, row,
			stdout_sanitize_log_sstat_table(sstat));

	stdout_kv_add(t, "Sanitize Command Dword 10 Information (SCDW10)",
		      "%#x", le32_to_cpu(sanitize->scdw10));
	stdout_estimate_sanitize_time_add(t, "Estimated Time For Overwrite",
					   le32_to_cpu(sanitize->eto));
	stdout_estimate_sanitize_time_add(t, "Estimated Time For Block Erase",
					   le32_to_cpu(sanitize->etbe));
	stdout_estimate_sanitize_time_add(t, "Estimated Time For Crypto Erase",
					   le32_to_cpu(sanitize->etce));
	stdout_estimate_sanitize_time_add(t,
		"Estimated Time For Overwrite (No-Deallocate)",
		le32_to_cpu(sanitize->etond));
	stdout_estimate_sanitize_time_add(t,
		"Estimated Time For Block Erase (No-Deallocate)",
		le32_to_cpu(sanitize->etbend));
	stdout_estimate_sanitize_time_add(t,
		"Estimated Time For Crypto Erase (No-Deallocate)",
		le32_to_cpu(sanitize->etcend));
	stdout_estimate_sanitize_time_add(t,
		"Estimated Time For Post-Verification Deallocation",
		le32_to_cpu(sanitize->etpvds));

	row = stdout_kv_add(t, "Sanitize State Information (SSI)", "%#x",
			     sanitize->ssi);
	if (human)
		shr_table_set_row_subtable(t, row,
			stdout_sanitize_log_ssi_table(sanitize->ssi, status));

	stdout_kv_table_finish(t, "sanitize-log");
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

static const char *stdout_format_timestamp(__u8 *timestamp_bytes)
{
	static char buf[STR_LEN];
	uint64_t ts_ms = int48_to_long(timestamp_bytes);

	snprintf(buf, sizeof(buf), "%"PRIu64" (%s)", ts_ms,
		nvme_format_timestamp(timestamp_bytes));

	return buf;
}

static void stdout_timestamp(struct nvme_timestamp *ts)
{
	printf("\tThe timestamp is : %s\n", stdout_format_timestamp(ts->timestamp));
	printf("\t%s\n", nvme_format_timestamp_origin(ts->attr));
	printf("\t%s\n", nvme_format_timestamp_sync(ts->attr));
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

static void stdout_feature_show_fields(enum nvme_features_id fid,
				       unsigned int result,
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
static void stdout_discovery_log(const struct nvmf_discovery_log *log,
				  int numrec)
{
	int i;

	printf("\nDiscovery Log Number of Records %d, Generation counter %"PRIu64"\n",
	       numrec, le64_to_cpu(log->genctr));

	for (i = 0; i < numrec; i++) {
		const struct nvmf_disc_log_entry *e = &log->entries[i];

		/*
		 * e->trsvcid/subnqn/traddr are fixed-width fields off the
		 * wire, space-padded per the spec, and not guaranteed
		 * NUL-terminated by a non-compliant DC. shr_buf2str() bounds
		 * the read to the field's own size and strips the padding.
		 */
		__cleanup_free char *trsvcid = NULL;
		__cleanup_free char *subnqn = NULL;
		__cleanup_free char *traddr = NULL;
		struct shr_table *t;

		trsvcid = shr_buf2str(e->trsvcid, sizeof(e->trsvcid));
		subnqn = shr_buf2str(e->subnqn, sizeof(e->subnqn));
		traddr = shr_buf2str(e->traddr, sizeof(e->traddr));

		printf("=====Discovery Log Entry %d======\n", i);

		t = stdout_kv_table_create();
		if (!t)
			return;

		stdout_kv_add(t, "trtype", "%s", libnvmf_trtype_str(e->trtype));
		stdout_kv_add(t, "adrfam", "%s",
			      e->traddr[0] ?
			      libnvmf_adrfam_str(e->adrfam) : "");
		stdout_kv_add(t, "subtype", "%s",
			      libnvmf_subtype_str(e->subtype));
		stdout_kv_add(t, "treq", "%s", libnvmf_treq_str(e->treq));
		stdout_kv_add(t, "portid", "%d", le16_to_cpu(e->portid));
		stdout_kv_add(t, "trsvcid", "%s", trsvcid);
		stdout_kv_add(t, "subnqn", "%s", subnqn);
		stdout_kv_add(t, "traddr", "%s", traddr);
		stdout_kv_add(t, "eflags", "%s",
			      libnvmf_eflags_str(le16_to_cpu(e->eflags)));

		switch (e->trtype) {
		case NVMF_TRTYPE_RDMA:
			stdout_kv_add(t, "rdma_prtype", "%s",
				      libnvmf_prtype_str(e->tsas.rdma.prtype));
			stdout_kv_add(t, "rdma_qptype", "%s",
				      libnvmf_qptype_str(e->tsas.rdma.qptype));
			stdout_kv_add(t, "rdma_cms", "%s",
				      libnvmf_cms_str(e->tsas.rdma.cms));
			stdout_kv_add(t, "rdma_pkey", "%#04x",
				      le16_to_cpu(e->tsas.rdma.pkey));
			break;
		case NVMF_TRTYPE_TCP:
			stdout_kv_add(t, "sectype", "%s",
				      libnvmf_sectype_str(e->tsas.tcp.sectype));
			break;
		}

		stdout_kv_table_finish(t, "discovery-log");
	}
}
#else
static void stdout_discovery_log(const struct nvmf_discovery_log *log,
				  int numrec)
{
}
#endif

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
#else
static void stdout_config_conn_list(struct libnvmf_config *config) {}
#endif

static void stdout_connect_msg(struct libnvme_ctrl *c)
{
	printf("connecting to device: %s\n", libnvme_ctrl_get_name(c));
}

static void stdout_mgmt_addr_list_log(struct nvme_mgmt_addr_list_log *ma_list)
{
	struct shr_table *t;
	bool reserved = true;
	int i;

	printf("Management Address List:\n");

	t = stdout_kv_table_create();
	if (!t)
		return;

	for (i = 0; i < ARRAY_SIZE(ma_list->mad); i++) {
		char name[16];

		switch (ma_list->mad[i].mat) {
		case 1:
		case 2:
			snprintf(name, sizeof(name), "Descriptor %d", i);
			stdout_kv_add(t, name, "Type: %d (%s), Address: %s",
				      ma_list->mad[i].mat,
				      ma_list->mad[i].mat == 1 ?
				      "NVM subsystem management agent" :
				      "fabric interface manager",
				      ma_list->mad[i].madrs);
			reserved = false;
			break;
		case 0xff:
			goto out;
		default:
			break;
		}
	}
out:
	if (reserved) {
		printf("All management address descriptors reserved\n");
		shr_table_free(t);
		return;
	}

	stdout_kv_table_finish(t, "mgmt-addr-list");
}

static void stdout_rotational_media_info_log(struct nvme_rotational_media_info_log *info)
{
	struct shr_table *t;

	t = stdout_kv_table_create();
	if (!t)
		return;

	stdout_kv_add(t, "endgid", "%u", le16_to_cpu(info->endgid));
	stdout_kv_add(t, "numa", "%u", le16_to_cpu(info->numa));
	stdout_kv_add(t, "nrs", "%u", le16_to_cpu(info->nrs));
	stdout_kv_add(t, "spinc", "%u", le32_to_cpu(info->spinc));
	stdout_kv_add(t, "fspinc", "%u", le32_to_cpu(info->fspinc));
	stdout_kv_add(t, "ldc", "%u", le32_to_cpu(info->ldc));
	stdout_kv_add(t, "fldc", "%u", le32_to_cpu(info->fldc));

	stdout_kv_table_finish(t, "rotational-media-info");
}

static void stdout_dispersed_ns_psub_log(struct nvme_dispersed_ns_participating_nss_log *log)
{
	__u64 numpsub = le64_to_cpu(log->numpsub);
	struct shr_table *t;
	__u64 i;

	t = stdout_kv_table_create();
	if (!t)
		return;

	stdout_kv_add(t, "genctr", "%"PRIu64, le64_to_cpu(log->genctr));
	stdout_kv_add(t, "numpsub", "%"PRIu64, (uint64_t)numpsub);

	for (i = 0; i < numpsub; i++) {
		char name[40];

		snprintf(name, sizeof(name), "participating_nss %"PRIu64,
			 (uint64_t)i);
		stdout_kv_add(t, name, "%-.*s", NVME_NQN_LENGTH,
			      &log->participating_nss[i * NVME_NQN_LENGTH]);
	}

	stdout_kv_table_finish(t, "dispersed-ns-psub");
}

static void stdout_reachability_groups_log(struct nvme_reachability_groups_log *log, __u64 len)
{
	struct shr_table *t;
	__u16 i;
	__u32 j;

	print_debug("len: %"PRIu64"\n", (uint64_t)len);

	t = stdout_kv_table_create();
	if (!t)
		return;

	stdout_kv_add(t, "chngc", "%"PRIu64, le64_to_cpu(log->chngc));
	stdout_kv_add(t, "nrgd", "%u", le16_to_cpu(log->nrgd));

	for (i = 0; i < le16_to_cpu(log->nrgd); i++) {
		stdout_kv_add(t, "rgid", "%u", le32_to_cpu(log->rgd[i].rgid));
		stdout_kv_add(t, "nnid", "%u", le32_to_cpu(log->rgd[i].nnid));
		stdout_kv_add(t, "chngc", "%"PRIu64,
			      le64_to_cpu(log->rgd[i].chngc));
		for (j = 0; j < le32_to_cpu(log->rgd[i].nnid); j++) {
			char name[16];

			snprintf(name, sizeof(name), "nsid%u", j);
			stdout_kv_add(t, name, "%u",
				      le32_to_cpu(log->rgd[i].nsid[j]));
		}
	}

	stdout_kv_table_finish(t, "reachability-groups");
}

static void stdout_reachability_associations_log(struct nvme_reachability_associations_log *log,
						 __u64 len)
{
	struct shr_table *t;
	__u16 i;
	__u32 j;

	print_debug("len: %"PRIu64"\n", (uint64_t)len);

	t = stdout_kv_table_create();
	if (!t)
		return;

	stdout_kv_add(t, "chngc", "%"PRIu64, le64_to_cpu(log->chngc));
	stdout_kv_add(t, "nrad", "%u", le16_to_cpu(log->nrad));

	for (i = 0; i < le16_to_cpu(log->nrad); i++) {
		stdout_kv_add(t, "rasid", "%u", le32_to_cpu(log->rad[i].rasid));
		stdout_kv_add(t, "nrid", "%u", le32_to_cpu(log->rad[i].nrid));
		stdout_kv_add(t, "chngc", "%"PRIu64,
			      le64_to_cpu(log->rad[i].chngc));
		stdout_kv_add(t, "rac", "%u", log->rad[i].rac);
		for (j = 0; j < le32_to_cpu(log->rad[i].nrid); j++) {
			char name[16];

			snprintf(name, sizeof(name), "rgid%u", j);
			stdout_kv_add(t, name, "%u",
				      le32_to_cpu(log->rad[i].rgid[j]));
		}
	}

	stdout_kv_table_finish(t, "reachability-associations");
}

#ifdef CONFIG_FABRICS
static void stdout_host_discovery_log(struct nvme_host_discovery_log *log)
{
	__u32 i;
	__u16 j;
	struct nvme_host_ext_discovery_log *hedlpe;
	struct nvmf_ext_attr *exat;
	__u32 thdlpl = le32_to_cpu(log->thdlpl);
	__u32 tel;
	__u16 numexat;
	int n = 0;
	struct shr_table *t;

	t = stdout_kv_table_create();
	if (!t)
		return;

	stdout_kv_add(t, "genctr", "%"PRIu64, le64_to_cpu(log->genctr));
	stdout_kv_add(t, "numrec", "%"PRIu64, le64_to_cpu(log->numrec));
	stdout_kv_add(t, "recfmt", "%u", le16_to_cpu(log->recfmt));
	stdout_kv_add(t, "hdlpf", "%02x", log->hdlpf);
	stdout_kv_add(t, "thdlpl", "%u", thdlpl);

	stdout_kv_table_finish(t, "host-discovery-log");

	for (i = sizeof(*log); i < le32_to_cpu(log->thdlpl); i += tel) {
		printf("hedlpe: %d\n", n++);
		hedlpe = (void *)log + i;
		tel = le32_to_cpu(hedlpe->tel);
		numexat = le16_to_cpu(hedlpe->numexat);

		t = stdout_kv_table_create();
		if (!t)
			return;

		stdout_kv_add(t, "trtype", "%s",
			      libnvmf_trtype_str(hedlpe->trtype));
		stdout_kv_add(t, "adrfam", "%s",
			      strlen(hedlpe->traddr) ?
			      libnvmf_adrfam_str(hedlpe->adrfam) : "");
		stdout_kv_add(t, "eflags", "%s",
			      libnvmf_eflags_str(le16_to_cpu(hedlpe->eflags)));
		stdout_kv_add(t, "hostnqn", "%s", hedlpe->hostnqn);
		stdout_kv_add(t, "traddr", "%s", hedlpe->traddr);
		switch (hedlpe->trtype) {
		case NVMF_TRTYPE_RDMA:
			stdout_kv_add(t, "tsas.prtype", "%s",
				      libnvmf_prtype_str(
						hedlpe->tsas.rdma.prtype));
			stdout_kv_add(t, "tsas.qptype", "%s",
				      libnvmf_qptype_str(
						hedlpe->tsas.rdma.qptype));
			stdout_kv_add(t, "tsas.cms", "%s",
				      libnvmf_cms_str(hedlpe->tsas.rdma.cms));
			stdout_kv_add(t, "tsas.pkey", "0x%04x",
				      le16_to_cpu(hedlpe->tsas.rdma.pkey));
			break;
		case NVMF_TRTYPE_TCP:
			stdout_kv_add(t, "tsas.sectype", "%s",
				      libnvmf_sectype_str(
						hedlpe->tsas.tcp.sectype));
			break;
		default:
			stdout_kv_add(t, "tsas.common", "");
			break;
		}
		stdout_kv_add(t, "tel", "%u", tel);
		stdout_kv_add(t, "numexat", "%u", numexat);

		stdout_kv_table_finish(t, "host-discovery-log");

		if (hedlpe->trtype != NVMF_TRTYPE_RDMA &&
		    hedlpe->trtype != NVMF_TRTYPE_TCP)
			d((unsigned char *)hedlpe->tsas.common,
			  sizeof(hedlpe->tsas.common), 16, 1);

		exat = hedlpe->exat;
		for (j = 0; j < numexat; j++) {
			printf("exat: %d\n", j);

			t = stdout_kv_table_create();
			if (!t)
				return;

			stdout_kv_add(t, "exattype", "%u",
				      le16_to_cpu(exat->exattype));
			stdout_kv_add(t, "exatlen", "%u",
				      le16_to_cpu(exat->exatlen));

			stdout_kv_table_finish(t, "host-discovery-log");

			printf("exatval:\n");
			d((unsigned char *)exat->exatval,
			  le16_to_cpu(exat->exatlen), 16, 1);
			exat = libnvmf_exat_ptr_next(exat);
		}
	}
}

static void stdout_kv_add_traddr(struct shr_table *t, const char *field,
				 __u8 adrfam, __u8 *traddr)
{
	char dst[INET6_ADDRSTRLEN];
	socklen_t size;
	int af;

	if (adrfam == NVMF_ADDR_FAMILY_IP4) {
		af = AF_INET;
		size = INET_ADDRSTRLEN;
	} else if (adrfam == NVMF_ADDR_FAMILY_IP6) {
		af = AF_INET6;
		size = INET6_ADDRSTRLEN;
	} else {
		stdout_kv_add(t, field, "<invalid>");
		return;
	}

	if (inet_ntop(af, traddr, dst, size))
		stdout_kv_add(t, field, "%s", dst);
}

static void stdout_ave_discovery_log(struct nvme_ave_discovery_log *log)
{
	__u32 i;
	__u8 j;
	struct nvme_ave_discovery_log_entry *adlpe;
	struct nvme_ave_tr_record *atr;
	__u32 tadlpl = le32_to_cpu(log->tadlpl);
	__u32 tel;
	__u8 numatr;
	int n = 0;
	struct shr_table *t;

	t = stdout_kv_table_create();
	if (!t)
		return;

	stdout_kv_add(t, "genctr", "%"PRIu64, le64_to_cpu(log->genctr));
	stdout_kv_add(t, "numrec", "%"PRIu64, le64_to_cpu(log->numrec));
	stdout_kv_add(t, "recfmt", "%u", le16_to_cpu(log->recfmt));
	stdout_kv_add(t, "tadlpl", "%u", tadlpl);

	stdout_kv_table_finish(t, "ave-discovery-log");

	for (i = sizeof(*log); i < le32_to_cpu(log->tadlpl); i += tel) {
		printf("adlpe: %d\n", n++);
		adlpe = (void *)log + i;
		tel = le32_to_cpu(adlpe->tel);
		numatr = adlpe->numatr;

		t = stdout_kv_table_create();
		if (!t)
			return;

		stdout_kv_add(t, "tel", "%u", tel);
		stdout_kv_add(t, "avenqn", "%s", adlpe->avenqn);
		stdout_kv_add(t, "numatr", "%u", numatr);

		stdout_kv_table_finish(t, "ave-discovery-log");

		atr = adlpe->atr;
		for (j = 0; j < numatr; j++) {
			printf("atr: %d\n", j);

			t = stdout_kv_table_create();
			if (!t)
				return;

			stdout_kv_add(t, "aveadrfam", "%s",
				      libnvmf_adrfam_str(atr->aveadrfam));
			stdout_kv_add(t, "avetrsvcid", "%u",
				      le16_to_cpu(atr->avetrsvcid));
			stdout_kv_add_traddr(t, "avetraddr", atr->aveadrfam,
					     atr->avetraddr);

			stdout_kv_table_finish(t, "ave-discovery-log");

			atr++;
		}
	}
}
#else
static void stdout_host_discovery_log(struct nvme_host_discovery_log *log) {}
static void stdout_ave_discovery_log(struct nvme_ave_discovery_log *log) {}
#endif

static void stdout_pull_model_ddc_req_log(struct nvme_pull_model_ddc_req_log *log)
{
	__u32 tpdrpl = le32_to_cpu(log->tpdrpl);
	__u32 osp_len = tpdrpl - offsetof(struct nvme_pull_model_ddc_req_log, osp);
	struct shr_table *t;

	t = stdout_kv_table_create();
	if (!t)
		return;

	stdout_kv_add(t, "ori", "%u", log->ori);
	stdout_kv_add(t, "tpdrpl", "%u", tpdrpl);

	stdout_kv_table_finish(t, "pull-model-ddc-req");

	printf("osp:\n");
	d((unsigned char *)log->osp, osp_len, 16, 1);
}

static struct shr_table *stdout_power_meas_log_pma_table(__u16 pma)
{
	struct shr_table *t;
	__u8 pmt = NVME_GET(pma, PMA_PMT);

	t = stdout_bits_table_create();
	if (!t)
		return NULL;

	stdout_bits_add(t, "[0:0]", NVME_GET(pma, PMA_PME),
			"Power Measurement Enable");
	stdout_bits_add(t, "[1:1]", NVME_GET(pma, PMA_NCPDF),
			"Non-Contiguous Power Data Flag");
	stdout_bits_add(t, "[2:2]", NVME_GET(pma, PMA_EPF),
			"Estimated Power Flag");
	stdout_bits_add(t, "[3:3]", NVME_GET(pma, PMA_MIPWRTS),
			"Maximum Interval Power Timestamp Support");
	stdout_bits_add(t, "[4:4]", NVME_GET(pma, PMA_PHDO),
			"Power Histogram Descriptor Overflow");
	stdout_bits_add(t, "[15:12]", pmt, "%s",
			nvme_power_measurement_type_to_string(pmt));

	return t;
}

static struct shr_table *stdout_power_meas_log_ts_table(__u8 attr)
{
	struct shr_table *t;

	t = stdout_bits_table_create();
	if (!t)
		return NULL;

	stdout_bits_add(t, "[3:1]", NVME_TIMESTAMP_ATTR_TO(attr), "%s",
			nvme_format_timestamp_origin(attr));
	stdout_bits_add(t, "[0:0]", NVME_TIMESTAMP_ATTR_SYNC(attr), "%s",
			nvme_format_timestamp_sync(attr));

	return t;
}

static void stdout_power_meas_log(struct nvme_power_meas_log *log, __u32 size)
{
	__u16 nphd = le16_to_cpu(log->nphd);
	__u16 pma = le16_to_cpu(log->pma);
	__u32 aipwr = le32_to_cpu(log->aipwr);
	__u32 mipwr = le32_to_cpu(log->mipwr);
	__cleanup_free char *aipwr_str = NULL;
	__cleanup_free char *mipwr_str = NULL;
	bool verbose = stdout_print_ops.flags & VERBOSE;
	struct shr_table *t;
	__u16 i;
	int row;

	printf("Power Measurement Log\n");

	t = stdout_kv_table_create();
	if (!t)
		return;

	stdout_kv_add(t, "Version", "%u", log->ver);
	stdout_kv_add(t, "Power Measurement Generation Number", "%u",
		      log->pmgn);
	row = stdout_kv_add(t, "Power Measurement Attributes", "%#06x", pma);
	if (verbose)
		shr_table_set_row_subtable(t, row,
			stdout_power_meas_log_pma_table(pma));

	stdout_kv_add(t, "Size (bytes)", "%u", le32_to_cpu(log->sze));
	stdout_kv_add(t, "Power Measurement Count", "%u",
		      le32_to_cpu(log->pmc));
	stdout_kv_add(t, "Number of Power Histogram Descriptors", "%u", nphd);
	stdout_kv_add(t, "Stop Measurement Time Remaining (minutes)", "%u",
		      le16_to_cpu(log->smtr));
	row = stdout_kv_add(t, "Stop Measurement Timestamp", "%s",
			     stdout_format_timestamp(log->smts.timestamp));
	if (verbose)
		shr_table_set_row_subtable(t, row,
			stdout_power_meas_log_ts_table(log->smts.attr));

	stdout_kv_add(t, "Power Histogram Descriptor Size (bytes)", "%u",
		      le16_to_cpu(log->phds));
	stdout_kv_add(t, "Power Histogram Bin Size (mW)", "%u",
		      le16_to_cpu(log->phbs));
	stdout_kv_add(t, "Number of Power Histogram Descriptors Supported",
		      "%u", le16_to_cpu(log->nphds));
	stdout_kv_add(t, "Vendor Specific Size (bytes)", "%u",
		      le16_to_cpu(log->vss));
	stdout_kv_add(t, "Power Histogram Descriptor Overflow Count", "%u",
		      le32_to_cpu(log->phdoc));

	aipwr_str = stdout_power_and_scale_str(aipwr & 0xffff,
						(aipwr >> 16) & 0x3);
	stdout_kv_add(t, "Average Interval Power", "%s", aipwr_str ?: "-");
	mipwr_str = stdout_power_and_scale_str(mipwr & 0xffff,
						(mipwr >> 16) & 0x3);
	stdout_kv_add(t, "Maximum Interval Power", "%s", mipwr_str ?: "-");

	row = stdout_kv_add(t, "Maximum Interval Power Timestamp", "%s",
			     stdout_format_timestamp(log->mipwrt.timestamp));
	if (verbose)
		shr_table_set_row_subtable(t, row,
			stdout_power_meas_log_ts_table(log->mipwrt.attr));

	stdout_kv_add(t, "Interval Power Percent Error", "%u", log->ipwrpe);

	stdout_kv_table_finish(t, "power-meas-log");

	if (verbose) {
		for (i = 0; i < nphd; i++) {
			__u32 phblt = le32_to_cpu(log->descs[i].phblt);
			__cleanup_free char *phblt_str = NULL;

			printf("Power Histogram Descriptor [%u]:\n", i);

			t = stdout_kv_table_create();
			if (!t)
				return;

			shr_table_set_indent(t, 2);

			stdout_kv_add(t, "Power Histogram Bin Count", "%u",
				      le32_to_cpu(log->descs[i].phbc));
			phblt_str = stdout_power_and_scale_str(
				phblt & 0xffff, (phblt >> 16) & 0x3);
			stdout_kv_add(t, "Power Histogram Bin Lower Threshold",
				      "%s",
				      phblt_str ?: "-");

			stdout_kv_table_finish(t, "power-meas-log");
		}
	}
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

static struct print_ops stdout_print_ops = {
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
