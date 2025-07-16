// SPDX-License-Identifier: GPL-2.0-or-later
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <ccan/ccan/strset/strset.h>
#include <ccan/ccan/htable/htable_type.h>
#include <ccan/ccan/htable/htable.h>
#include <ccan/ccan/hash/hash.h>

#include "nvme.h"
#include "libnvme.h"
#include "nvme-print.h"
#include "nvme-models.h"
#include "util/suffix.h"
#include "util/types.h"
#include "logging.h"
#include "common.h"

static const uint8_t zero_uuid[16] = { 0 };
static const uint8_t invalid_uuid[16] = {[0 ... 15] = 0xff };
static const char dash[100] = {[0 ... 99] = '-'};

static struct print_ops stdout_print_ops;

static const char *subsys_key(const struct nvme_subsystem *s)
{
	return nvme_subsystem_get_name((nvme_subsystem_t)s);
}

static const char *ctrl_key(const struct nvme_ctrl *c)
{
	return nvme_ctrl_get_name((nvme_ctrl_t)c);
}

static const char *ns_key(const struct nvme_ns *n)
{
	return nvme_ns_get_name((nvme_ns_t)n);
}

static bool subsys_cmp(const struct nvme_subsystem *s, const char *name)
{
	return !strcmp(nvme_subsystem_get_name((nvme_subsystem_t)s), name);
}

static bool ctrl_cmp(const struct nvme_ctrl *c, const char *name)
{
	return !strcmp(nvme_ctrl_get_name((nvme_ctrl_t)c), name);
}

static bool ns_cmp(const struct nvme_ns *n, const char *name)
{
	return !strcmp(nvme_ns_get_name((nvme_ns_t)n), name);
}

HTABLE_DEFINE_TYPE(struct nvme_subsystem, subsys_key, hash_string,
		   subsys_cmp, htable_subsys);
HTABLE_DEFINE_TYPE(struct nvme_ctrl, ctrl_key, hash_string,
		   ctrl_cmp, htable_ctrl);
HTABLE_DEFINE_TYPE(struct nvme_ns, ns_key, hash_string,
		   ns_cmp, htable_ns);

static void htable_ctrl_add_unique(struct htable_ctrl *ht, nvme_ctrl_t c)
{
	if (htable_ctrl_get(ht, nvme_ctrl_get_name(c)))
		return;

	htable_ctrl_add(ht, c);
}

static void htable_ns_add_unique(struct htable_ns *ht, nvme_ns_t n)
{
	struct htable_ns_iter it;
	nvme_ns_t _n;

	/*
	 * Test if namespace pointer is already in the hash, and thus avoid
	 * inserting severaltimes the same pointer.
	 */
	for (_n = htable_ns_getfirst(ht, nvme_ns_get_name(n), &it);
	     _n;
	     _n = htable_ns_getnext(ht, nvme_ns_get_name(n), &it)) {
		if (_n == n)
			return;
	}
	htable_ns_add(ht, n);
}

struct nvme_resources {
	nvme_root_t r;

	struct htable_subsys ht_s;
	struct htable_ctrl ht_c;
	struct htable_ns ht_n;
	struct strset subsystems;
	struct strset ctrls;
	struct strset namespaces;
};

static int nvme_resources_init(nvme_root_t r, struct nvme_resources *res)
{
	nvme_host_t h;
	nvme_subsystem_t s;
	nvme_ctrl_t c;
	nvme_ns_t n;
	nvme_path_t p;

	res->r = r;
	htable_subsys_init(&res->ht_s);
	htable_ctrl_init(&res->ht_c);
	htable_ns_init(&res->ht_n);
	strset_init(&res->subsystems);
	strset_init(&res->ctrls);
	strset_init(&res->namespaces);

	nvme_for_each_host(r, h) {
		nvme_for_each_subsystem(h, s) {
			htable_subsys_add(&res->ht_s, s);
			strset_add(&res->subsystems, nvme_subsystem_get_name(s));

			nvme_subsystem_for_each_ctrl(s, c) {
				htable_ctrl_add_unique(&res->ht_c, c);
				strset_add(&res->ctrls, nvme_ctrl_get_name(c));

				nvme_ctrl_for_each_ns(c, n) {
					htable_ns_add_unique(&res->ht_n, n);
					strset_add(&res->namespaces, nvme_ns_get_name(n));
				}

				nvme_ctrl_for_each_path(c, p) {
					n = nvme_path_get_ns(p);
					if (n) {
						htable_ns_add_unique(&res->ht_n, n);
						strset_add(&res->namespaces, nvme_ns_get_name(n));
					}
				}
			}

			nvme_subsystem_for_each_ns(s, n) {
				htable_ns_add_unique(&res->ht_n, n);
				strset_add(&res->namespaces, nvme_ns_get_name(n));
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

static void stdout_predictable_latency_per_nvmset(
		struct nvme_nvmset_predictable_lat_log *plpns_log,
		__u16 nvmset_id, const char *devname)
{
	printf("Predictable Latency Per NVM Set Log for device: %s\n",
		devname);
	printf("Predictable Latency Per NVM Set Log for NVM Set ID: %u\n",
		le16_to_cpu(nvmset_id));
	printf("Status: %u\n", plpns_log->status);
	printf("Event Type: %u\n",
		le16_to_cpu(plpns_log->event_type));
	printf("DTWIN Reads Typical: %"PRIu64"\n",
		le64_to_cpu(plpns_log->dtwin_rt));
	printf("DTWIN Writes Typical: %"PRIu64"\n",
		le64_to_cpu(plpns_log->dtwin_wt));
	printf("DTWIN Time Maximum: %"PRIu64"\n",
		le64_to_cpu(plpns_log->dtwin_tmax));
	printf("NDWIN Time Minimum High: %"PRIu64"\n",
		le64_to_cpu(plpns_log->ndwin_tmin_hi));
	printf("NDWIN Time Minimum Low: %"PRIu64"\n",
		le64_to_cpu(plpns_log->ndwin_tmin_lo));
	printf("DTWIN Reads Estimate: %"PRIu64"\n",
		le64_to_cpu(plpns_log->dtwin_re));
	printf("DTWIN Writes Estimate: %"PRIu64"\n",
		le64_to_cpu(plpns_log->dtwin_we));
	printf("DTWIN Time Estimate: %"PRIu64"\n\n\n",
		le64_to_cpu(plpns_log->dtwin_te));
}

static void stdout_predictable_latency_event_agg_log(
		struct nvme_aggregate_predictable_lat_event *pea_log,
		__u64 log_entries, __u32 size, const char *devname)
{
	__u64 num_iter;
	__u64 num_entries;

	num_entries = le64_to_cpu(pea_log->num_entries);
	printf("Predictable Latency Event Aggregate Log for device: %s\n", devname);

	printf("Number of Entries Available: %"PRIu64"\n", (uint64_t)num_entries);

	num_iter = min(num_entries, log_entries);
	for (int i = 0; i < num_iter; i++)
		printf("Entry[%d]: %u\n", i + 1, le16_to_cpu(pea_log->entries[i]));
}

static void stdout_persistent_event_log_rci(__le32 pel_header_rci)
{
	__u32 rci = le32_to_cpu(pel_header_rci);
	__u32 rsvd19 = NVME_PEL_RCI_RSVD(rci);
	__u8 rce = NVME_PEL_RCI_RCE(rci);
	__u8 rcpit = NVME_PEL_RCI_RCPIT(rci);
	__u16 rcpid = NVME_PEL_RCI_RCPID(rci);

	if (rsvd19)
		printf("  [31:19] : %#x\tReserved\n", rsvd19);
	printf("\tReporting Context Exists (RCE): %s(%u)\n", rce ? "true" : "false", rce);
	printf("\tReporting Context Port Identifier Type (RCPIT): %u(%s)\n", rcpit,
	       nvme_pel_rci_rcpit_to_string(rcpit));
	printf("\tReporting Context Port Identifier (RCPID): %#x\n\n", rcpid);
}

static void stdout_persistent_event_entry_ehai(__u8 ehai)
{
	__u8 rsvd1 = NVME_PEL_EHAI_RSVD(ehai);
	__u8 pit = NVME_PEL_EHAI_PIT(ehai);

	printf("  [7:2] : %#x\tReserved\n", rsvd1);
	printf("\tPort Identifier Type (PIT): %u(%s)\n", pit, nvme_pel_ehai_pit_to_string(pit));
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

	for (unsigned int i = 0; i < num; i++) {
		printf("\t%-53s: %sEnabled\n", nvme_fdp_event_to_string(buf[i]),
		       NVME_GET(cdw12, FDP_SUPP_EVENT_ENABLED) ? "" : "Not ");
	}
}

static void pel_header(struct nvme_persistent_event_log *pevent_log_head, int human)
{
	printf("Log Identifier: %u\n", pevent_log_head->lid);
	printf("Total Number of Events: %u\n", le32_to_cpu(pevent_log_head->tnev));
	printf("Total Log Length : %"PRIu64"\n", le64_to_cpu(pevent_log_head->tll));
	printf("Log Revision: %u\n", pevent_log_head->rv);
	printf("Log Header Length: %u\n", pevent_log_head->lhl);
	printf("Timestamp: %"PRIu64"\n", le64_to_cpu(pevent_log_head->ts));
	printf("Power On Hours (POH): %s",
	       uint128_t_to_l10n_string(le128_to_cpu(pevent_log_head->poh)));
	printf("Power Cycle Count: %"PRIu64"\n", le64_to_cpu(pevent_log_head->pcc));
	printf("PCI Vendor ID (VID): %u\n", le16_to_cpu(pevent_log_head->vid));
	printf("PCI Subsystem Vendor ID (SSVID): %u\n", le16_to_cpu(pevent_log_head->ssvid));
	printf("Serial Number (SN): %-.*s\n", (int)sizeof(pevent_log_head->sn),
	       pevent_log_head->sn);
	printf("Model Number (MN): %-.*s\n", (int)sizeof(pevent_log_head->mn), pevent_log_head->mn);
	printf("NVM Subsystem NVMe Qualified Name (SUBNQN): %-.*s\n",
	       (int)sizeof(pevent_log_head->subnqn), pevent_log_head->subnqn);
	printf("Generation Number: %u\n", le16_to_cpu(pevent_log_head->gen_number));
	printf("Reporting Context Information (RCI): %u\n", le32_to_cpu(pevent_log_head->rci));

	if (human)
		stdout_persistent_event_log_rci(pevent_log_head->rci);

	printf("Supported Events Bitmap:\n");
	for (int i = 0; i < 32; i++) {
		if (!pevent_log_head->seb[i])
			continue;
		stdout_add_bitmap(i, pevent_log_head->seb[i]);
	}
}

static void pel_event_header(int i, struct nvme_persistent_event_entry *pevent_entry_head,
			     int human)
{
	printf("Event Number: %u\n", i);
	printf("Event Type: %s\n", nvme_pel_event_to_string(pevent_entry_head->etype));
	printf("Event Type Revision: %u\n", pevent_entry_head->etype_rev);
	printf("Event Header Length: %u\n", pevent_entry_head->ehl);
	printf("Event Header Additional Info: %u\n", pevent_entry_head->ehai);

	if (human)
		stdout_persistent_event_entry_ehai(pevent_entry_head->ehai);

	printf("Controller Identifier: %u\n", le16_to_cpu(pevent_entry_head->cntlid));
	printf("Event Timestamp: %"PRIu64"\n", le64_to_cpu(pevent_entry_head->ets));
	printf("Port Identifier: %u\n", le16_to_cpu(pevent_entry_head->pelpid));
	printf("Vendor Specific Information Length: %u\n", le16_to_cpu(pevent_entry_head->vsil));
	printf("Event Length: %u\n", le16_to_cpu(pevent_entry_head->el));
}

static void pel_smart_health_event(void *pevent_log_info, __u32 offset, const char *devname)
{
	struct nvme_smart_log *smart_event = pevent_log_info + offset;

	printf("Smart Health Event Entry:\n");
	stdout_smart_log(smart_event, NVME_NSID_ALL, devname);
}

static void pel_fw_commit_event(void *pevent_log_info, __u32 offset)
{
	struct nvme_fw_commit_event *fw_commit_event = pevent_log_info + offset;

	printf("FW Commit Event Entry:\n");
	printf("Old Firmware Revision: %"PRIu64" (%s)\n", le64_to_cpu(fw_commit_event->old_fw_rev),
	       util_fw_to_string((char *)&fw_commit_event->old_fw_rev));
	printf("New Firmware Revision: %"PRIu64" (%s)\n", le64_to_cpu(fw_commit_event->new_fw_rev),
	       util_fw_to_string((char *)&fw_commit_event->new_fw_rev));
	printf("FW Commit Action: %u\n", fw_commit_event->fw_commit_action);
	printf("FW Slot: %u\n", fw_commit_event->fw_slot);
	printf("Status Code Type for Firmware Commit Command: %u\n", fw_commit_event->sct_fw);
	printf("Status Returned for Firmware Commit Command: %u\n", fw_commit_event->sc_fw);
	printf("Vendor Assigned Firmware Commit Result Code: %u\n",
	       le16_to_cpu(fw_commit_event->vndr_assign_fw_commit_rc));
}

static void pel_timestamp_event(void *pevent_log_info, __u32 offset)
{
	struct nvme_time_stamp_change_event *ts_change_event = pevent_log_info + offset;

	printf("Time Stamp Change Event Entry:\n");
	printf("Previous Timestamp: %"PRIu64"\n", le64_to_cpu(ts_change_event->previous_timestamp));
	printf("Milliseconds Since Reset: %"PRIu64"\n",
	       le64_to_cpu(ts_change_event->ml_secs_since_reset));
}

static void pel_power_on_reset_event(void *pevent_log_info, __u32 offset,
				     struct nvme_persistent_event_entry *pevent_entry_head)
{
	__u64 *fw_rev;
	__u32 por_info_len = le16_to_cpu(pevent_entry_head->el) -
			     le16_to_cpu(pevent_entry_head->vsil) - sizeof(*fw_rev);
	struct nvme_power_on_reset_info_list *por_event;
	__u32 por_info_list = por_info_len / sizeof(*por_event);

	printf("Power On Reset Event Entry:\n");
	fw_rev = pevent_log_info + offset;
	printf("Firmware Revision: %"PRIu64" (%s)\n", le64_to_cpu(*fw_rev),
	       util_fw_to_string((char *)fw_rev));
	printf("Reset Information List:\n");

	for (int i = 0; i < por_info_list; i++) {
		por_event = pevent_log_info + offset + sizeof(*fw_rev) + i * sizeof(*por_event);
		printf("Controller ID: %u\n", le16_to_cpu(por_event->cid));
		printf("Firmware Activation: %u\n", por_event->fw_act);
		printf("Operation in Progress: %u\n", por_event->op_in_prog);
		printf("Controller Power Cycle: %u\n", le32_to_cpu(por_event->ctrl_power_cycle));
		printf("Power on milliseconds: %"PRIu64"\n",
		       le64_to_cpu(por_event->power_on_ml_seconds));
		printf("Controller Timestamp: %"PRIu64"\n",
		       le64_to_cpu(por_event->ctrl_time_stamp));
	}
}

static void pel_nss_hw_error_event(void *pevent_log_info, __u32 offset)
{
	struct nvme_nss_hw_err_event *nss_hw_err_event = pevent_log_info + offset;

	printf("NVM Subsystem Hardware Error Event Code Entry: %u, %s\n",
	       le16_to_cpu(nss_hw_err_event->nss_hw_err_event_code),
	       nvme_nss_hw_error_to_string(nss_hw_err_event->nss_hw_err_event_code));
}

static void pel_change_ns_event(void *pevent_log_info, __u32 offset)
{
	struct nvme_change_ns_event *ns_event = pevent_log_info + offset;

	printf("Change Namespace Event Entry:\n");
	printf("Namespace Management CDW10: %u\n", le32_to_cpu(ns_event->nsmgt_cdw10));
	printf("Namespace Size: %"PRIu64"\n", le64_to_cpu(ns_event->nsze));
	printf("Namespace Capacity: %"PRIu64"\n", le64_to_cpu(ns_event->nscap));
	printf("Formatted LBA Size: %u\n", ns_event->flbas);
	printf("End-to-end Data Protection Type Settings: %u\n", ns_event->dps);
	printf("Namespace Multi-path I/O and Namespace Sharing Capabilities: %u\n", ns_event->nmic);
	printf("ANA Group Identifier: %u\n", le32_to_cpu(ns_event->ana_grp_id));
	printf("NVM Set Identifier: %u\n", le16_to_cpu(ns_event->nvmset_id));
	printf("Namespace ID: %u\n", le32_to_cpu(ns_event->nsid));
}

static void pel_format_start_event(void *pevent_log_info, __u32 offset)
{
	struct nvme_format_nvm_start_event *format_start_event = pevent_log_info + offset;

	printf("Format NVM Start Event Entry:\n");
	printf("Namespace Identifier: %u\n", le32_to_cpu(format_start_event->nsid));
	printf("Format NVM Attributes: %u\n", format_start_event->fna);
	printf("Format NVM CDW10: %u\n", le32_to_cpu(format_start_event->format_nvm_cdw10));
}

static void pel_format_completion_event(void *pevent_log_info, __u32 offset)
{
	struct nvme_format_nvm_compln_event *format_cmpln_event = pevent_log_info + offset;

	printf("Format NVM Completion Event Entry:\n");
	printf("Namespace Identifier: %u\n", le32_to_cpu(format_cmpln_event->nsid));
	printf("Smallest Format Progress Indicator: %u\n", format_cmpln_event->smallest_fpi);
	printf("Format NVM Status: %u\n", format_cmpln_event->format_nvm_status);
	printf("Completion Information: %u\n", le16_to_cpu(format_cmpln_event->compln_info));
	printf("Status Field: %u\n", le32_to_cpu(format_cmpln_event->status_field));
}

static void pel_sanitize_start_event(void *pevent_log_info, __u32 offset)
{
	struct nvme_sanitize_start_event *sanitize_start_event = pevent_log_info + offset;

	printf("Sanitize Start Event Entry:\n");
	printf("SANICAP: %u\n", sanitize_start_event->sani_cap);
	printf("Sanitize CDW10: %u\n", le32_to_cpu(sanitize_start_event->sani_cdw10));
	printf("Sanitize CDW11: %u\n", le32_to_cpu(sanitize_start_event->sani_cdw11));
}

static void pel_sanitize_completion_event(void *pevent_log_info, __u32 offset)
{
	struct nvme_sanitize_compln_event *sanitize_cmpln_event = pevent_log_info + offset;

	printf("Sanitize Completion Event Entry:\n");
	printf("Sanitize Progress: %u\n", le16_to_cpu(sanitize_cmpln_event->sani_prog));
	printf("Sanitize Status: %u\n", le16_to_cpu(sanitize_cmpln_event->sani_status));
	printf("Completion Information: %u\n", le16_to_cpu(sanitize_cmpln_event->cmpln_info));
}

static void pel_set_feature_event(void *pevent_log_info, __u32 offset)
{
	int fid, cdw11, cdw12, dword_cnt;
	unsigned char *mem_buf;
	struct nvme_set_feature_event *set_feat_event = pevent_log_info + offset;

	printf("Set Feature Event Entry:\n");
	dword_cnt = NVME_SET_FEAT_EVENT_DW_COUNT(set_feat_event->layout);
	fid = NVME_GET(le32_to_cpu(set_feat_event->cdw_mem[0]), FEATURES_CDW10_FID);
	cdw11 = le32_to_cpu(set_feat_event->cdw_mem[1]);

	printf("Set Feature ID: 0x%02x (%s), value: 0x%08x\n", fid, nvme_feature_to_string(fid),
	       cdw11);

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

static void pel_thermal_excursion_event(void *pevent_log_info, __u32 offset)
{
	struct nvme_thermal_exc_event *thermal_exc_event = pevent_log_info + offset;

	printf("Thermal Excursion Event Entry:\n");
	printf("Over Temperature: %u\n", thermal_exc_event->over_temp);
	printf("Threshold: %u\n", thermal_exc_event->threshold);
}

static void stdout_persistent_event_log(void *pevent_log_info, __u8 action, __u32 size,
					const char *devname)
{
	struct nvme_persistent_event_log *pevent_log_head;
	__u32 offset = sizeof(*pevent_log_head);
	struct nvme_persistent_event_entry *pevent_entry_head;
	int human = stdout_print_ops.flags & VERBOSE;

	printf("Persistent Event Log for device: %s\n", devname);
	printf("Action for Persistent Event Log: %u\n", action);

	if (size < offset) {
		printf("No log data can be shown with this log len at least " \
		       "512 bytes is required or can be 0 to read the complete " \
		       "log page after context established\n");
		return;
	}

	pevent_log_head = pevent_log_info;

	pel_header(pevent_log_head, human);

	printf("\n");
	printf("\nPersistent Event Entries:\n");
	for (int i = 0; i < le32_to_cpu(pevent_log_head->tnev); i++) {
		if (offset + sizeof(*pevent_entry_head) >= size)
			break;

		pevent_entry_head = pevent_log_info + offset;

		if ((offset + pevent_entry_head->ehl + 3 +
			le16_to_cpu(pevent_entry_head->el)) >= size)
			break;

		pel_event_header(i, pevent_entry_head, human);

		offset += pevent_entry_head->ehl + 3;

		switch (pevent_entry_head->etype) {
		case NVME_PEL_SMART_HEALTH_EVENT:
			pel_smart_health_event(pevent_log_info, offset, devname);
			break;
		case NVME_PEL_FW_COMMIT_EVENT:
			pel_fw_commit_event(pevent_log_info, offset);
			break;
		case NVME_PEL_TIMESTAMP_EVENT:
			pel_timestamp_event(pevent_log_info, offset);
			break;
		case NVME_PEL_POWER_ON_RESET_EVENT:
			pel_power_on_reset_event(pevent_log_info, offset, pevent_entry_head);
			break;
		case NVME_PEL_NSS_HW_ERROR_EVENT:
			pel_nss_hw_error_event(pevent_log_info, offset);
			break;
		case NVME_PEL_CHANGE_NS_EVENT:
			pel_change_ns_event(pevent_log_info, offset);
			break;
		case NVME_PEL_FORMAT_START_EVENT:
			pel_format_start_event(pevent_log_info, offset);
			break;
		case NVME_PEL_FORMAT_COMPLETION_EVENT:
			pel_format_completion_event(pevent_log_info, offset);
			break;
		case NVME_PEL_SANITIZE_START_EVENT:
			pel_sanitize_start_event(pevent_log_info, offset);
			break;
		case NVME_PEL_SANITIZE_COMPLETION_EVENT:
			pel_sanitize_completion_event(pevent_log_info, offset);
			break;
		case NVME_PEL_SET_FEATURE_EVENT:
			pel_set_feature_event(pevent_log_info, offset);
			break;
		case NVME_PEL_TELEMETRY_CRT:
			d(pevent_log_info + offset, 512, 16, 1);
			break;
		case NVME_PEL_THERMAL_EXCURSION_EVENT:
			pel_thermal_excursion_event(pevent_log_info, offset);
			break;
		case NVME_PEL_SANITIZE_MEDIA_VERIF_EVENT:
			printf("Sanitize Media Verification Event\n");
			break;
		default:
			printf("Reserved Event\n\n");
			break;
		}
		offset += le16_to_cpu(pevent_entry_head->el);
		printf("\n");
	}
}

static void stdout_endurance_group_event_agg_log(
		struct nvme_aggregate_endurance_group_event *endurance_log,
		__u64 log_entries, __u32 size, const char *devname)
{
	printf("Endurance Group Event Aggregate Log for device: %s\n", devname);

	printf("Number of Entries Available: %"PRIu64"\n",
		le64_to_cpu(endurance_log->num_entries));

	for (int i = 0; i < log_entries; i++) {
		printf("Entry[%d]: %u\n", i + 1,
			le16_to_cpu(endurance_log->entries[i]));
	}
}

static void stdout_lba_status_log(void *lba_status, __u32 size,
				  const char *devname)
{
	struct nvme_lba_status_log *hdr;
	struct nvme_lbas_ns_element *ns_element;
	struct nvme_lba_rd *range_desc;
	int offset = sizeof(*hdr);
	__u32 num_lba_desc, num_elements;

	hdr = lba_status;
	printf("LBA Status Log for device: %s\n", devname);
	printf("LBA Status Log Page Length: %"PRIu32"\n",
		le32_to_cpu(hdr->lslplen));
	num_elements = le32_to_cpu(hdr->nlslne);
	printf("Number of LBA Status Log Namespace Elements: %"PRIu32"\n",
		num_elements);
	printf("Estimate of Unrecoverable Logical Blocks: %"PRIu32"\n",
		le32_to_cpu(hdr->estulb));
	printf("LBA Status Generation Counter: %"PRIu16"\n", le16_to_cpu(hdr->lsgc));
	for (int ele = 0; ele < num_elements; ele++) {
		ns_element = lba_status + offset;
		printf("Namespace Element Identifier: %"PRIu32"\n",
			le32_to_cpu(ns_element->neid));
		num_lba_desc = le32_to_cpu(ns_element->nlrd);
		printf("Number of LBA Range Descriptors: %"PRIu32"\n", num_lba_desc);
		printf("Recommended Action Type: %u\n", ns_element->ratype);

		offset += sizeof(*ns_element);
		if (num_lba_desc != 0xffffffff) {
			for (int i = 0; i < num_lba_desc; i++) {
				range_desc = lba_status + offset;
				printf("RSLBA[%d]: %"PRIu64"\n", i,
					le64_to_cpu(range_desc->rslba));
				printf("RNLB[%d]: %"PRIu32"\n", i,
					le32_to_cpu(range_desc->rnlb));
				offset += sizeof(*range_desc);
			}
		} else {
			printf("Number of LBA Range Descriptors (NLRD) set to %#x for "\
				"NS element %d\n", num_lba_desc, ele);
		}
	}
}

static void stdout_resv_notif_log(struct nvme_resv_notification_log *resv,
				  const char *devname)
{
	printf("Reservation Notif Log for device: %s\n", devname);
	printf("Log Page Count				: %"PRIx64"\n",
		le64_to_cpu(resv->lpc));
	printf("Resv Notif Log Page Type	: %u (%s)\n",
		resv->rnlpt,
		nvme_resv_notif_to_string(resv->rnlpt));
	printf("Num of Available Log Pages	: %u\n", resv->nalp);
	printf("Namespace ID:				: %"PRIx32"\n",
		le32_to_cpu(resv->nsid));
}

static void stdout_fid_support_effects_log_human(__u32 fid_support)
{
	const char *set = "+";
	const char *clr = "-";
	__u16 fsp;

	printf("  FSUPP+");
	printf("  UDCC%s", (fid_support & NVME_FID_SUPPORTED_EFFECTS_UDCC) ? set : clr);
	printf("  NCC%s", (fid_support & NVME_FID_SUPPORTED_EFFECTS_NCC) ? set : clr);
	printf("  NIC%s", (fid_support & NVME_FID_SUPPORTED_EFFECTS_NIC) ? set : clr);
	printf("  CCC%s", (fid_support & NVME_FID_SUPPORTED_EFFECTS_CCC) ? set : clr);
	printf("  USS%s", (fid_support & NVME_FID_SUPPORTED_EFFECTS_UUID_SEL) ? set : clr);

	fsp = NVME_GET(fid_support, FID_SUPPORTED_EFFECTS_SCOPE);

	printf("  NAMESPACE SCOPE%s", (fsp & NVME_FID_SUPPORTED_EFFECTS_SCOPE_NS) ? set : clr);
	printf("  CONTROLLER SCOPE%s", (fsp & NVME_FID_SUPPORTED_EFFECTS_SCOPE_CTRL) ? set : clr);
	printf("  NVM SET SCOPE%s", (fsp & NVME_FID_SUPPORTED_EFFECTS_SCOPE_NVM_SET) ? set : clr);
	printf("  ENDURANCE GROUP SCOPE%s", (fsp & NVME_FID_SUPPORTED_EFFECTS_SCOPE_ENDGRP) ? set : clr);
	printf("  DOMAIN SCOPE%s", (fsp & NVME_FID_SUPPORTED_EFFECTS_SCOPE_DOMAIN) ? set : clr);
	printf("  NVM Subsystem SCOPE%s", (fsp & NVME_FID_SUPPORTED_EFFECTS_SCOPE_NSS) ? set : clr);
}

static void stdout_fid_support_effects_log(struct nvme_fid_supported_effects_log *fid_log,
					   const char *devname)
{
	__u32 fid_effect;
	int i, human = stdout_print_ops.flags & VERBOSE;

	printf("FID Supports Effects Log for device: %s\n", devname);
	printf("Admin Command Set\n");
	for (i = 0; i < 256; i++) {
		fid_effect = le32_to_cpu(fid_log->fid_support[i]);
		if (fid_effect & NVME_FID_SUPPORTED_EFFECTS_FSUPP) {
			printf("FID %02x -> Support Effects Log: %08x", i,
				fid_effect);
			if (human)
				stdout_fid_support_effects_log_human(fid_effect);
			printf("\n");
		}
	}
}

static void stdout_mi_cmd_support_effects_log_human(__u32 mi_cmd_support)
{
	const char *set = "+";
	const char *clr = "-";
	__u16 csp;

	printf("  CSUPP+");
	printf("  UDCC%s", (mi_cmd_support & NVME_MI_CMD_SUPPORTED_EFFECTS_UDCC) ? set : clr);
	printf("  NCC%s", (mi_cmd_support & NVME_MI_CMD_SUPPORTED_EFFECTS_NCC) ? set : clr);
	printf("  NIC%s", (mi_cmd_support & NVME_MI_CMD_SUPPORTED_EFFECTS_NIC) ? set : clr);
	printf("  CCC%s", (mi_cmd_support & NVME_MI_CMD_SUPPORTED_EFFECTS_CCC) ? set : clr);

	csp = NVME_GET(mi_cmd_support, MI_CMD_SUPPORTED_EFFECTS_SCOPE);

	printf("  NAMESPACE SCOPE%s", (csp & NVME_MI_CMD_SUPPORTED_EFFECTS_SCOPE_NS) ? set : clr);
	printf("  CONTROLLER SCOPE%s", (csp & NVME_MI_CMD_SUPPORTED_EFFECTS_SCOPE_CTRL) ? set : clr);
	printf("  NVM SET SCOPE%s", (csp & NVME_MI_CMD_SUPPORTED_EFFECTS_SCOPE_NVM_SET) ? set : clr);
	printf("  ENDURANCE GROUP SCOPE%s", (csp & NVME_MI_CMD_SUPPORTED_EFFECTS_SCOPE_ENDGRP) ? set : clr);
	printf("  DOMAIN SCOPE%s", (csp & NVME_MI_CMD_SUPPORTED_EFFECTS_SCOPE_DOMAIN) ? set : clr);
	printf("  NVM Subsystem SCOPE%s", (csp & NVME_MI_CMD_SUPPORTED_EFFECTS_SCOPE_NSS) ? set : clr);
}

static void stdout_mi_cmd_support_effects_log(struct nvme_mi_cmd_supported_effects_log *mi_cmd_log,
					      const char *devname)
{
	__u32 mi_cmd_effect;
	int i, human = stdout_print_ops.flags & VERBOSE;

	printf("MI Commands Support Effects Log for device: %s\n", devname);
	printf("Admin Command Set\n");
	for (i = 0; i < NVME_LOG_MI_CMD_SUPPORTED_EFFECTS_MAX; i++) {
		mi_cmd_effect = le32_to_cpu(mi_cmd_log->mi_cmd_support[i]);
		if (mi_cmd_effect & NVME_MI_CMD_SUPPORTED_EFFECTS_CSUPP) {
			printf("MI CMD %02x -> Support Effects Log: %08x", i,
					mi_cmd_effect);
			if (human)
				stdout_mi_cmd_support_effects_log_human(mi_cmd_effect);
			printf("\n");
		}
	}
}

static void stdout_boot_part_log(void *bp_log, const char *devname,
				 __u32 size)
{
	struct nvme_boot_partition *hdr = bp_log;

	printf("Boot Partition Log for device: %s\n", devname);
	printf("Log ID: %u\n", hdr->lid);
	printf("Boot Partition Size: %u KiB\n",
	       NVME_BOOT_PARTITION_INFO_BPSZ(le32_to_cpu(hdr->bpinfo)));
	printf("Active BPID: %u\n", NVME_BOOT_PARTITION_INFO_ABPID(le32_to_cpu(hdr->bpinfo)));
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

static void stdout_phy_rx_eom_odp(uint8_t odp)
{
	__u8 rsvd = NVME_EOM_ODP_RSVD(odp);
	__u8 edfp = NVME_EOM_ODP_EDFP(odp);
	__u8 pefp = NVME_EOM_ODP_PEFP(odp);

	if (rsvd)
		printf("  [7:2] : %#x\tReserved\n", rsvd);
	printf("  [1:1] : %#x\tEye Data Field %sPresent\n",
		edfp, edfp ? "" : "Not ");
	printf("  [0:0] : %#x\tPrintable Eye Field %sPresent\n",
		pefp, pefp ? "" : "Not ");
}

static void stdout_eom_printable_eye(struct nvme_eom_lane_desc *lane)
{
	char *eye = (char *)lane->eye_desc;
	int i, j;

	printf("Printable Eye:\n");
	for (i = 0; i < le16_to_cpu(lane->nrows); i++) {
		for (j = 0; j < le16_to_cpu(lane->ncols); j++)
			printf("%c", eye[i * le16_to_cpu(lane->ncols) + j]);
		printf("\n");
	}
}

static void stdout_phy_rx_eom_descs(struct nvme_phy_rx_eom_log *log)
{
	void *p = log->descs;
	int i;

	for (i = 0; i < log->nd; i++) {
		struct nvme_eom_lane_desc *desc = p;
		unsigned char *vsdata = NULL;
		unsigned int vsdataoffset = 0;
		uint16_t nrows, ncols, edlen;

		nrows = le16_to_cpu(desc->nrows);
		ncols = le16_to_cpu(desc->ncols);
		edlen = le16_to_cpu(desc->edlen);

		printf("Measurement Status: %s\n",
			desc->mstatus ? "Successful" : "Not Successful");
		printf("Lane: %u\n", desc->lane);
		printf("Eye: %u\n", desc->eye);
		printf("Top: %u\n", le16_to_cpu(desc->top));
		printf("Bottom: %u\n", le16_to_cpu(desc->bottom));
		printf("Left: %u\n", le16_to_cpu(desc->left));
		printf("Right: %u\n", le16_to_cpu(desc->right));
		printf("Number of Rows: %u\n", nrows);
		printf("Number of Columns: %u\n", ncols);
		printf("Eye Data Length: %u\n", desc->edlen);

		if (NVME_EOM_ODP_PEFP(log->odp))
			stdout_eom_printable_eye(desc);

		/* Eye Data field is vendor specific */
		if (edlen == 0)
			continue;

		vsdataoffset = (nrows * ncols) + sizeof(struct nvme_eom_lane_desc);
		vsdata = (unsigned char *)((unsigned char *)desc + vsdataoffset);
		printf("Eye Data:\n");
		d(vsdata, edlen, 16, 1);
		printf("\n");

		p += log->dsize;
	}
}

static void stdout_phy_rx_eom_log(struct nvme_phy_rx_eom_log *log, __u16 controller)
{
	int human = stdout_print_ops.flags & VERBOSE;

	printf("Physical Interface Receiver Eye Opening Measurement Log for controller ID: %u\n", controller);
	printf("Log ID: %u\n", log->lid);
	printf("EOM In Progress: %s\n", eomip_to_string(log->eomip));
	printf("Header Size: %u\n", le16_to_cpu(log->hsize));
	printf("Result Size: %u\n", le32_to_cpu(log->rsize));
	printf("EOM Data Generation Number: %u\n", log->eomdgn);
	printf("Log Revision: %u\n", log->lr);
	printf("Optional Data Present: %u\n", log->odp);
	if (human)
		stdout_phy_rx_eom_odp(log->odp);
	printf("Lanes: %u\n", log->lanes);
	printf("Eyes Per Lane: %u\n", log->epl);
	printf("Log Specific Parameter Field Copy: %u\n", log->lspfc);
	printf("Link Information: %u\n", log->li);
	printf("Log Specific Identifier Copy: %u\n", le16_to_cpu(log->lsic));
	printf("Descriptor Size: %u\n", le32_to_cpu(log->dsize));
	printf("Number of Descriptors: %u\n", le16_to_cpu(log->nd));
	printf("Maximum Top Bottom: %u\n", le16_to_cpu(log->maxtb));
	printf("Maximum Left Right: %u\n", le16_to_cpu(log->maxlr));
	printf("Estimated Time for Good Quality: %u\n", le16_to_cpu(log->etgood));
	printf("Estimated Time for Better Quality: %u\n", le16_to_cpu(log->etbetter));
	printf("Estimated Time for Best Quality: %u\n", le16_to_cpu(log->etbest));

	if (log->eomip == NVME_PHY_RX_EOM_COMPLETED)
		stdout_phy_rx_eom_descs(log);
}

static void stdout_media_unit_stat_log(struct nvme_media_unit_stat_log *mus_log)
{
	int i;
	int nmu = le16_to_cpu(mus_log->nmu);

	printf("Number of Media Unit Status Descriptors: %u\n", nmu);
	printf("Number of Channels: %u\n", le16_to_cpu(mus_log->cchans));
	printf("Selected Configuration: %u\n", le16_to_cpu(mus_log->sel_config));
	for (i = 0; i < nmu; i++) {
		printf("Media Unit Status Descriptor: %u\n", i);
		printf("Media Unit Identifier: %u\n",
			le16_to_cpu(mus_log->mus_desc[i].muid));
		printf("Domain Identifier: %u\n",
			le16_to_cpu(mus_log->mus_desc[i].domainid));
		printf("Endurance Group Identifier: %u\n",
			le16_to_cpu(mus_log->mus_desc[i].endgid));
		printf("NVM Set Identifier: %u\n",
			le16_to_cpu(mus_log->mus_desc[i].nvmsetid));
		printf("Capacity Adjustment Factor: %u\n",
			le16_to_cpu(mus_log->mus_desc[i].cap_adj_fctr));
		printf("Available Spare: %u\n", mus_log->mus_desc[i].avl_spare);
		printf("Percentage Used: %u\n", mus_log->mus_desc[i].percent_used);
		printf("Number of Channels: %u\n", mus_log->mus_desc[i].mucs);
		printf("Channel Identifiers Offset: %u\n", mus_log->mus_desc[i].cio);
	}
}

static void stdout_fdp_config_fdpa(uint8_t fdpa)
{
	__u8 valid = NVME_GET(fdpa, FDP_CONFIG_FDPA_VALID);
	__u8 rsvd = (fdpa >> 5) & 0x3;
	__u8 fdpvwc = NVME_GET(fdpa, FDP_CONFIG_FDPA_FDPVWC);
	__u8 rgif = NVME_GET(fdpa, FDP_CONFIG_FDPA_RGIF);

	printf("  [7:7] : %#x\tFDP Configuration %sValid\n",
		valid, valid ? "" : "Not ");
	if (rsvd)
		printf("  [6:5] : %#x\tReserved\n", rsvd);
	printf("  [4:4] : %#x\tFDP Volatile Write Cache %sPresent\n",
		fdpvwc, fdpvwc ? "" : "Not ");
	printf("  [3:0] : %#x\tReclaim Group Identifier Format\n", rgif);
}

static void stdout_fdp_configs(struct nvme_fdp_config_log *log, size_t len)
{
	void *p = log->configs;
	int human = stdout_print_ops.flags & VERBOSE;
	uint16_t n;

	n = le16_to_cpu(log->n) + 1;

	for (int i = 0; i < n; i++) {
		struct nvme_fdp_config_desc *config = p;

		printf("FDP Attributes: %#x\n", config->fdpa);
		if (human)
			stdout_fdp_config_fdpa(config->fdpa);

		printf("Vendor Specific Size: %u\n", config->vss);
		printf("Number of Reclaim Groups: %"PRIu32"\n", le32_to_cpu(config->nrg));
		printf("Number of Reclaim Unit Handles: %"PRIu16"\n", le16_to_cpu(config->nruh));
		printf("Number of Namespaces Supported: %"PRIu32"\n", le32_to_cpu(config->nnss));
		printf("Reclaim Unit Nominal Size: %"PRIu64"\n", le64_to_cpu(config->runs));
		printf("Estimated Reclaim Unit Time Limit: %"PRIu32"\n", le32_to_cpu(config->erutl));

		printf("Reclaim Unit Handle List:\n");
		for (int j = 0; j < le16_to_cpu(config->nruh); j++) {
			struct nvme_fdp_ruh_desc *ruh = &config->ruhs[j];

			printf("  [%d]: %s\n", j, ruh->ruht == NVME_FDP_RUHT_INITIALLY_ISOLATED ? "Initially Isolated" : "Persistently Isolated");
		}

		p += config->size;
	}
}

static void stdout_fdp_usage(struct nvme_fdp_ruhu_log *log, size_t len)
{
	uint16_t nruh = le16_to_cpu(log->nruh);

	for (int i = 0; i < nruh; i++) {
		struct nvme_fdp_ruhu_desc *ruhu = &log->ruhus[i];

		printf("Reclaim Unit Handle %d Attributes: %#"PRIx8" (%s)\n", i, ruhu->ruha,
				ruhu->ruha == 0x0 ? "Unused" : (
				ruhu->ruha == 0x1 ? "Host Specified" : (
				ruhu->ruha == 0x2 ? "Controller Specified" : "Unknown")));
	}
}

static void stdout_fdp_stats(struct nvme_fdp_stats_log *log)
{
	printf("Host Bytes with Metadata Written (HBMW): %s\n",
		uint128_t_to_l10n_string(le128_to_cpu(log->hbmw)));
	printf("Media Bytes with Metadata Written (MBMW): %s\n",
		uint128_t_to_l10n_string(le128_to_cpu(log->mbmw)));
	printf("Media Bytes Erased (MBE): %s\n",
		uint128_t_to_l10n_string(le128_to_cpu(log->mbe)));
}

static void stdout_fdp_events(struct nvme_fdp_events_log *log)
{
	struct tm *tm;
	char buffer[320];
	time_t ts;
	uint32_t n = le32_to_cpu(log->n);

	for (unsigned int i = 0; i < n; i++) {
		struct nvme_fdp_event *event = &log->events[i];

		ts = int48_to_long(event->ts.timestamp) / 1000;
		tm = localtime(&ts);

		printf("Event[%u]\n", i);
		printf("  Event Type: %#"PRIx8" (%s)\n", event->type,
		       nvme_fdp_event_to_string(event->type));
		printf("  Event Timestamp: %"PRIu64" (%s)\n", int48_to_long(event->ts.timestamp),
			strftime(buffer, sizeof(buffer), "%c %Z", tm) ? buffer : "-");

		if (event->flags & NVME_FDP_EVENT_F_PIV)
			printf("  Placement Identifier (PID): %#"PRIx16"\n",
			       le16_to_cpu(event->pid));

		if (event->flags & NVME_FDP_EVENT_F_NSIDV)
			printf("  Namespace Identifier (NSID): %"PRIu32"\n", le32_to_cpu(event->nsid));

		if (event->type == NVME_FDP_EVENT_REALLOC) {
			struct nvme_fdp_event_realloc *mr;

			mr = (struct nvme_fdp_event_realloc *)&event->type_specific;

			printf("  Number of LBAs Moved (NLBAM): %"PRIu16"\n", le16_to_cpu(mr->nlbam));

			if (mr->flags & NVME_FDP_EVENT_REALLOC_F_LBAV)
				printf("  Logical Block Address (LBA): %#"PRIx64"\n",
				       le64_to_cpu(mr->lba));
		}

		if (event->flags & NVME_FDP_EVENT_F_LV) {
			printf("  Reclaim Group Identifier: %"PRIu16"\n", le16_to_cpu(event->rgid));
			printf("  Reclaim Unit Handle Identifier %"PRIu8"\n", event->ruhid);
		}

		printf("\n");
	}
}

static void stdout_fdp_ruh_status(struct nvme_fdp_ruh_status *status, size_t len)
{
	uint16_t nruhsd = le16_to_cpu(status->nruhsd);

	for (unsigned int i = 0; i < nruhsd; i++) {
		struct nvme_fdp_ruh_status_desc *ruhs = &status->ruhss[i];

		printf("Placement Identifier %"PRIu16"; Reclaim Unit Handle Identifier %"PRIu16"\n",
				le16_to_cpu(ruhs->pid), le16_to_cpu(ruhs->ruhid));
		printf("  Estimated Active Reclaim Unit Time Remaining (EARUTR): %"PRIu32"\n",
				le32_to_cpu(ruhs->earutr));
		printf("  Reclaim Unit Available Media Writes (RUAMW): %"PRIu64"\n",
				le64_to_cpu(ruhs->ruamw));

		printf("\n");
	}
}

static void stdout_supported_cap_config_log(struct nvme_supported_cap_config_list_log *cap)
{
	struct nvme_end_grp_chan_desc *chan_desc;
	int i, j, k, l, m, sccn, egcn, egsets, egchans, chmus;

	sccn = cap->sccn;
	printf("Number of Supported Capacity Configurations: %u\n", sccn);
	for (i = 0; i < sccn; i++) {
		printf("Capacity Configuration Descriptor: %u\n", i);
		printf("Capacity Configuration Identifier: %u\n",
			le16_to_cpu(cap->cap_config_desc[i].cap_config_id));
		printf("Domain Identifier: %u\n",
			le16_to_cpu(cap->cap_config_desc[i].domainid));
		egcn = le16_to_cpu(cap->cap_config_desc[i].egcn);
		printf("Number of Endurance Group Configuration Descriptors: %u\n", egcn);
		for (j = 0; j < egcn; j++) {
			printf("Endurance Group Identifier: %u\n",
				le16_to_cpu(cap->cap_config_desc[i].egcd[j].endgid));
			printf("Capacity Adjustment Factor: %u\n",
				le16_to_cpu(cap->cap_config_desc[i].egcd[j].cap_adj_factor));
			printf("Total Endurance Group Capacity: %s\n",
				uint128_t_to_l10n_string(le128_to_cpu(
					cap->cap_config_desc[i].egcd[j].tegcap)));
			printf("Spare Endurance Group Capacity: %s\n",
				uint128_t_to_l10n_string(le128_to_cpu(
					cap->cap_config_desc[i].egcd[j].segcap)));
			printf("Endurance Estimate: %s\n",
				uint128_t_to_l10n_string(le128_to_cpu(
					cap->cap_config_desc[i].egcd[j].end_est)));
			egsets = le16_to_cpu(cap->cap_config_desc[i].egcd[j].egsets);
			printf("Number of NVM Sets: %u\n", egsets);
			for (k = 0; k < egsets; k++)
				printf("NVM Set %d Identifier: %u\n", i,
				       le16_to_cpu(cap->cap_config_desc[i].egcd[j].nvmsetid[k]));

			chan_desc = (struct nvme_end_grp_chan_desc *)
			    &cap->cap_config_desc[i].egcd[j].nvmsetid[egsets];
			egchans = le16_to_cpu(chan_desc->egchans);
			printf("Number of Channels: %u\n", egchans);
			for (l = 0; l < egchans; l++) {
				printf("Channel Identifier: %u\n",
					le16_to_cpu(chan_desc->chan_config_desc[l].chanid));
				chmus = le16_to_cpu(chan_desc->chan_config_desc[l].chmus);
				printf("Number of Channel Media Units: %u\n", chmus);
				for (m = 0; m < chmus; m++) {
					printf("Media Unit Identifier: %u\n",
						le16_to_cpu(chan_desc->chan_config_desc[l].mu_config_desc[m].muid));
					printf("Media Unit Descriptor Length: %u\n",
						le16_to_cpu(chan_desc->chan_config_desc[l].mu_config_desc[m].mudl));
				}
			}
		}
	}
}

static unsigned int stdout_subsystem_multipath(nvme_subsystem_t s)
{
	nvme_ns_t n;
	nvme_path_t p;
	unsigned int i = 0;

	n = nvme_subsystem_first_ns(s);
	if (!n)
		return 0;

	nvme_namespace_for_each_path(n, p) {
		nvme_ctrl_t c = nvme_path_get_ctrl(p);
		const char *ana_state = ana_state = nvme_path_get_ana_state(p);

		printf(" +- %s %s %s %s %s\n",
			nvme_ctrl_get_name(c),
			nvme_ctrl_get_transport(c),
			nvme_ctrl_get_address(c),
			nvme_ctrl_get_state(c),
			ana_state);
		i++;
	}

	return i;
}

static void stdout_subsystem_ctrls(nvme_subsystem_t s)
{
	nvme_ctrl_t c;

	nvme_subsystem_for_each_ctrl(s, c) {
		printf(" +- %s %s %s %s\n",
			nvme_ctrl_get_name(c),
			nvme_ctrl_get_transport(c),
			nvme_ctrl_get_address(c),
			nvme_ctrl_get_state(c));
	}
}

static void stdout_subsys_config(nvme_subsystem_t s)
{
	int len = strlen(nvme_subsystem_get_name(s));

	printf("%s - NQN=%s\n", nvme_subsystem_get_name(s),
	       nvme_subsystem_get_nqn(s));
	printf("%*s   hostnqn=%s\n", len, " ",
	       nvme_host_get_hostnqn(nvme_subsystem_get_host(s)));

	if (stdout_print_ops.flags & VERBOSE) {
		printf("%*s   model=%s\n", len, " ",
			nvme_subsystem_get_model(s));
		printf("%*s   serial=%s\n", len, " ",
			nvme_subsystem_get_serial(s));
		printf("%*s   firmware=%s\n", len, " ",
			nvme_subsystem_get_fw_rev(s));
		printf("%*s   iopolicy=%s\n", len, " ",
			nvme_subsystem_get_iopolicy(s));
		printf("%*s   type=%s\n", len, " ",
			nvme_subsystem_get_type(s));
	}
}

static void stdout_subsystem(nvme_root_t r, bool show_ana)
{
	nvme_host_t h;
	bool first = true;

	nvme_for_each_host(r, h) {
		nvme_subsystem_t s;

		nvme_for_each_subsystem(h, s) {
			bool no_ctrl = true;
			nvme_ctrl_t c;

			nvme_subsystem_for_each_ctrl(s, c)
				no_ctrl = false;
			if (no_ctrl)
				continue;

			if (!first)
				printf("\n");
			first = false;

			stdout_subsys_config(s);
			printf("\\\n");

			if (!show_ana || !stdout_subsystem_multipath(s))
				stdout_subsystem_ctrls(s);
		}
	}
}

static void stdout_subsystem_list(nvme_root_t r, bool show_ana)
{
	stdout_subsystem(r, show_ana);
}

static void stdout_registers_cap(struct nvme_bar_cap *cap)
{
	printf("\tNVM Subsystem Shutdown Enhancements Supported (NSSES): %s\n",
		cap->nsses ? "Supported" : "Not Supported");
	printf("\tController Ready With Media Support (CRWMS): %s\n",
	       cap->crwms ? "Supported" : "Not Supported");
	printf("\tController Ready Independent of Media Support (CRIMS): %s\n",
	       cap->crims ? "Supported" : "Not Supported");
	printf("\tNVM Subsystem Shutdown Supported   (NSSS): %s\n", cap->nsss ? "Supported" : "Not Supported");
	printf("\tController Memory Buffer Supported (CMBS): The Controller Memory Buffer is %s\n",
	       cap->cmbs ? "Supported" : "Not Supported");
	printf("\tPersistent Memory Region Supported (PMRS): The Persistent Memory Region is %s\n",
	       cap->pmrs ? "Supported" : "Not Supported");
	printf("\tMemory Page Size Maximum         (MPSMAX): %u bytes\n", 1 << (12 + cap->mpsmax));
	printf("\tMemory Page Size Minimum         (MPSMIN): %u bytes\n", 1 << (12 + cap->mpsmin));
	printf("\tController Power Scope              (CPS): %s\n",
	       !cap->cps ? "Not Reported" : cap->cps == 1 ? "Controller scope" :
	       cap->cps == 2 ? "Domain scope" : "NVM subsystem scope");
	printf("\tBoot Partition Support              (BPS): %s\n", cap->bps ? "Yes" : "No");
	printf("\tCommand Sets Supported              (CSS): NVM command set is %s\n",
	       cap->css & 0x01 ? "Supported" : "Not Supported");
	printf("\t                                           One or more I/O Command Sets are %s\n",
	       cap->css & 0x40 ? "Supported" : "Not Supported");
	printf("\t                                           %s\n",
	       cap->css & 0x80 ? "Only Admin Command Set Supported" : "I/O Command Set is Supported");
	printf("\tNVM Subsystem Reset Supported     (NSSRS): %s\n", cap->nssrs ? "Yes" : "No");
	printf("\tDoorbell Stride                   (DSTRD): %u bytes\n", 1 << (2 + cap->dstrd));
	printf("\tTimeout                              (TO): %u ms\n", cap->to * 500);
	printf("\tArbitration Mechanism Supported     (AMS): Weighted Round Robin with Urgent Priority Class is %s\n",
	       cap->ams & 0x01 ? "Supported" : "Not supported");
	printf("\tContiguous Queues Required          (CQR): %s\n", cap->cqr ? "Yes" : "No");
	printf("\tMaximum Queue Entries Supported    (MQES): %u\n\n", cap->mqes + 1);
}

static void stdout_registers_version(__u32 vs)
{
	printf("\tNVMe specification %d.%d.%d\n\n", NVME_MAJOR(vs), NVME_MINOR(vs),
	       NVME_TERTIARY(vs));
}

static void stdout_registers_cc_ams(__u8 ams)
{
	printf("\tArbitration Mechanism Selected     (AMS): ");
	switch (ams) {
	case NVME_CC_AMS_RR:
		printf("Round Robin\n");
		break;
	case NVME_CC_AMS_WRRU:
		printf("Weighted Round Robin with Urgent Priority Class\n");
		break;
	case NVME_CC_AMS_VS:
		printf("Vendor Specific\n");
		break;
	default:
		printf("Reserved\n");
		break;
	}
}

static void stdout_registers_cc_shn(__u8 shn)
{
	printf("\tShutdown Notification              (SHN): ");
	switch (shn) {
	case NVME_CC_SHN_NONE:
		printf("No notification; no effect\n");
		break;
	case NVME_CC_SHN_NORMAL:
		printf("Normal shutdown notification\n");
		break;
	case NVME_CC_SHN_ABRUPT:
		printf("Abrupt shutdown notification\n");
		break;
	default:
		printf("Reserved\n");
		break;
	}
}

static void stdout_registers_cc(__u32 cc)
{
	printf("\tController Ready Independent of Media Enable (CRIME): %s\n",
		NVME_CC_CRIME(cc) ? "Enabled" : "Disabled");

	printf("\tI/O Completion Queue Entry Size (IOCQES): %u bytes\n",
	       POWER_OF_TWO(NVME_CC_IOCQES(cc)));
	printf("\tI/O Submission Queue Entry Size (IOSQES): %u bytes\n",
	       POWER_OF_TWO(NVME_CC_IOSQES(cc)));
	stdout_registers_cc_shn(NVME_CC_SHN(cc));
	stdout_registers_cc_ams(NVME_CC_AMS(cc));
	printf("\tMemory Page Size                   (MPS): %u bytes\n",
	       POWER_OF_TWO(12 + NVME_CC_MPS(cc)));
	printf("\tI/O Command Set Selected           (CSS): %s\n",
	       NVME_CC_CSS(cc) == NVME_CC_CSS_NVM ? "NVM Command Set" :
	       NVME_CC_CSS(cc) == NVME_CC_CSS_CSI ? "All supported I/O Command Sets" :
	       NVME_CC_CSS(cc) == NVME_CC_CSS_ADMIN ? "Admin Command Set only" : "Reserved");
	printf("\tEnable                              (EN): %s\n\n", NVME_CC_EN(cc) ? "Yes" : "No");
}

static void stdout_registers_csts_shst(__u8 shst)
{
	printf("\tShutdown Status               (SHST): ");
	switch (shst) {
	case NVME_CSTS_SHST_NORMAL:
		printf("Normal operation (no shutdown has been requested)\n");
		break;
	case NVME_CSTS_SHST_OCCUR:
		printf("Shutdown processing occurring\n");
		break;
	case NVME_CSTS_SHST_CMPLT:
		printf("Shutdown processing complete\n");
		break;
	default:
		printf("Reserved\n");
		break;
	}
}

static void stdout_registers_csts(__u32 csts)
{
	printf("\tShutdown Type                   (ST): %s\n",
	       NVME_CSTS_ST(csts) ? "Subsystem" : "Controller");
	printf("\tProcessing Paused               (PP): %s\n", NVME_CSTS_PP(csts) ? "Yes" : "No");
	printf("\tNVM Subsystem Reset Occurred (NSSRO): %s\n",
	       NVME_CSTS_NSSRO(csts) ? "Yes" : "No");
	stdout_registers_csts_shst(NVME_CSTS_SHST(csts));
	printf("\tController Fatal Status        (CFS): %s\n",
	       NVME_CSTS_CFS(csts) ? "True" : "False");
	printf("\tReady                          (RDY): %s\n\n",
	       NVME_CSTS_RDY(csts) ? "Yes" : "No");
}

static void stdout_registers_nssd(__u32 nssd)
{
	printf("\tNVM Subsystem Shutdown Control (NSSC): %#x\n\n", nssd);
}

static void stdout_registers_crto(__u32 crto)
{
	printf("\tCRIMT                               : %d secs\n", NVME_CRTO_CRIMT(crto) / 2);
	printf("\tCRWMT                               : %d secs\n", NVME_CRTO_CRWMT(crto) / 2);
}

static void stdout_registers_aqa(__u32 aqa)
{
	printf("\tAdmin Completion Queue Size (ACQS): %u\n", NVME_AQA_ACQS(aqa) + 1);
	printf("\tAdmin Submission Queue Size (ASQS): %u\n\n", NVME_AQA_ASQS(aqa) + 1);
}

static void stdout_registers_asq(uint64_t asq)
{
	printf("\tAdmin Submission Queue Base (ASQB): %"PRIx64"\n", (uint64_t)NVME_ASQ_ASQB(asq));
}

static void stdout_registers_acq(uint64_t acq)
{
	printf("\tAdmin Completion Queue Base (ACQB): %"PRIx64"\n", (uint64_t)NVME_ACQ_ACQB(acq));
}

static void stdout_registers_cmbloc(__u32 cmbloc, bool support)
{
	static const char * const enforced[] = { "Enforced", "Not Enforced" };

	if (!support) {
		printf("\tController Memory Buffer feature is not supported\n\n");
		return;
	}

	printf("\tOffset                                                        (OFST): ");
	printf("%#x (See cmbsz.szu for granularity)\n", NVME_CMBLOC_OFST(cmbloc));

	printf("\tCMB Queue Dword Alignment                                     (CQDA): %d\n",
	       NVME_CMBLOC_CQDA(cmbloc));

	printf("\tCMB Data Metadata Mixed Memory Support                      (CDMMMS): %s\n",
	       enforced[NVME_CMBLOC_CDMMMS(cmbloc)]);

	printf("\tCMB Data Pointer and Command Independent Locations Support (CDPCILS): %s\n",
	       enforced[NVME_CMBLOC_CDPCILS(cmbloc)]);

	printf("\tCMB Data Pointer Mixed Locations Support                    (CDPMLS): %s\n",
	       enforced[NVME_CMBLOC_CDPLMS(cmbloc)]);

	printf("\tCMB Queue Physically Discontiguous Support                   (CQPDS): %s\n",
	       enforced[NVME_CMBLOC_CQPDS(cmbloc)]);

	printf("\tCMB Queue Mixed Memory Support                               (CQMMS): %s\n",
	       enforced[NVME_CMBLOC_CQMMS(cmbloc)]);

	printf("\tBase Indicator Register                                        (BIR): %#x\n\n",
	       NVME_CMBLOC_BIR(cmbloc));
}

static void stdout_registers_cmbsz(__u32 cmbsz)
{
	if (!cmbsz) {
		printf("\tController Memory Buffer feature is not supported\n\n");
		return;
	}

	printf("\tSize                      (SZ): %u\n", NVME_CMBSZ_SZ(cmbsz));
	printf("\tSize Units               (SZU): %s\n",
	       nvme_register_szu_to_string(NVME_CMBSZ_SZU(cmbsz)));
	printf("\tWrite Data Support       (WDS): Write Data and metadata transfer in Controller Memory Buffer is %s\n",
	       NVME_CMBSZ_WDS(cmbsz) ? "Supported" : "Not supported");
	printf("\tRead Data Support        (RDS): Read Data and metadata transfer in Controller Memory Buffer is %s\n",
	       NVME_CMBSZ_RDS(cmbsz) ? "Supported" : "Not supported");
	printf("\tPRP SGL List Support   (LISTS): PRP/SG Lists in Controller Memory Buffer is %s\n",
	       NVME_CMBSZ_LISTS(cmbsz) ? "Supported" : "Not supported");
	printf("\tCompletion Queue Support (CQS): Admin and I/O Completion Queues in Controller Memory Buffer is %s\n",
	       NVME_CMBSZ_CQS(cmbsz) ? "Supported" : "Not supported");
	printf("\tSubmission Queue Support (SQS): Admin and I/O Submission Queues in Controller Memory Buffer is %s\n\n",
	       NVME_CMBSZ_SQS(cmbsz) ? "Supported" : "Not supported");
}

static void stdout_registers_bpinfo_brs(__u8 brs)
{
	printf("\tBoot Read Status                (BRS): ");
	switch (brs) {
	case 0:
		printf("No Boot Partition read operation requested\n");
		break;
	case 1:
		printf("Boot Partition read in progress\n");
		break;
	case 2:
		printf("Boot Partition read completed successfully\n");
		break;
	case 3:
		printf("Error completing Boot Partition read\n");
		break;
	default:
		printf("Invalid\n");
		break;
	}
}

static void stdout_registers_bpinfo(__u32 bpinfo)
{
	printf("\tActive Boot Partition ID      (ABPID): %u\n", NVME_BPINFO_ABPID(bpinfo));
	stdout_registers_bpinfo_brs(NVME_BPINFO_BRS(bpinfo));
	printf("\tBoot Partition Size            (BPSZ): %u\n", NVME_BPINFO_BPSZ(bpinfo));
}

static void stdout_registers_bprsel(__u32 bprsel)
{
	printf("\tBoot Partition Identifier      (BPID): %u\n", NVME_BPRSEL_BPID(bprsel));
	printf("\tBoot Partition Read Offset    (BPROF): %x\n", NVME_BPRSEL_BPROF(bprsel));
	printf("\tBoot Partition Read Size      (BPRSZ): %x\n", NVME_BPRSEL_BPRSZ(bprsel));
}

static void stdout_registers_bpmbl(uint64_t bpmbl)
{
	printf("\tBoot Partition Memory Buffer Base Address (BMBBA): %"PRIx64"\n",
	       (uint64_t)NVME_BPMBL_BMBBA(bpmbl));
}

static void stdout_registers_cmbmsc(uint64_t cmbmsc)
{
	printf("\tController Base Address         (CBA): %" PRIx64 "\n",
	       (uint64_t)NVME_CMBMSC_CBA(cmbmsc));
	printf("\tController Memory Space Enable (CMSE): %" PRIx64 "\n", NVME_CMBMSC_CMSE(cmbmsc));
	printf("\tCapabilities Registers Enabled  (CRE): ");
	printf("CMBLOC and CMBSZ registers are %senabled\n\n",
	       NVME_CMBMSC_CRE(cmbmsc) ? "" : "NOT ");
}

static void stdout_registers_cmbsts(__u32 cmbsts)
{
	printf("\tController Base Address Invalid (CBAI): %x\n\n", NVME_CMBSTS_CBAI(cmbsts));
}

static void stdout_registers_cmbebs(__u32 cmbebs)
{
	printf("\tCMB Elasticity Buffer Size Base  (CMBWBZ): %#x\n", NVME_CMBEBS_CMBWBZ(cmbebs));
	printf("\tRead Bypass Behavior                     : ");
	printf("memory reads not conflicting with memory writes in the CMB Elasticity Buffer ");
	printf("%s bypass those memory writes\n", NVME_CMBEBS_RBB(cmbebs) ? "SHALL" : "MAY");
	printf("\tCMB Elasticity Buffer Size Units (CMBSZU): %s\n\n",
	       nvme_register_unit_to_string(NVME_CMBEBS_CMBSZU(cmbebs)));
}

static void stdout_registers_cmbswtp(__u32 cmbswtp)
{
	printf("\tCMB Sustained Write Throughput       (CMBSWTV): %#x\n",
	       NVME_CMBSWTP_CMBSWTV(cmbswtp));
	printf("\tCMB Sustained Write Throughput Units (CMBSWTU): %s/second\n\n",
	       nvme_register_unit_to_string(NVME_CMBSWTP_CMBSWTU(cmbswtp)));
}

static void stdout_registers_pmrcap(__u32 pmrcap)
{
	printf("\tController Memory Space Supported                   (CMSS): ");
	printf("Referencing PMR with host supplied addresses is %sSupported\n",
	       NVME_PMRCAP_CMSS(pmrcap) ? "" : "Not ");
	printf("\tPersistent Memory Region Timeout                   (PMRTO): %x\n",
	       NVME_PMRCAP_PMRTO(pmrcap));
	printf("\tPersistent Memory Region Write Barrier Mechanisms (PMRWBM): %x\n",
	       NVME_PMRCAP_PMRWBM(pmrcap));
	printf("\tPersistent Memory Region Time Units                (PMRTU): ");
	printf("PMR time unit is %s\n", NVME_PMRCAP_PMRTU(pmrcap) ? "minutes" : "500 milliseconds");
	printf("\tBase Indicator Register                              (BIR): %x\n",
	       NVME_PMRCAP_BIR(pmrcap));
	printf("\tWrite Data Support                                   (WDS): ");
	printf("Write data to the PMR is %ssupported\n", NVME_PMRCAP_WDS(pmrcap) ? "" : "not ");
	printf("\tRead Data Support                                    (RDS): ");
	printf("Read data from the PMR is %ssupported\n", NVME_PMRCAP_RDS(pmrcap) ? "" : "not ");
}

static void stdout_registers_pmrctl(__u32 pmrctl)
{
	printf("\tEnable (EN): PMR is %s\n", NVME_PMRCTL_EN(pmrctl) ? "READY" : "Disabled");
}

static void stdout_registers_pmrsts(__u32 pmrsts, bool ready)
{
	printf("\tController Base Address Invalid (CBAI): %x\n", NVME_PMRSTS_CBAI(pmrsts));
	printf("\tHealth Status                   (HSTS): %s\n",
	       nvme_register_pmr_hsts_to_string(NVME_PMRSTS_HSTS(pmrsts)));
	printf("\tNot Ready                       (NRDY): ");
	printf("The Persistent Memory Region is %s to process ",
	       !NVME_PMRSTS_NRDY(pmrsts) && ready ? "READY" : "Not Ready");
	printf("PCI Express memory read and write requests\n");
	printf("\tError                            (ERR): %x\n", NVME_PMRSTS_ERR(pmrsts));
}

static void stdout_registers_pmrebs(__u32 pmrebs)
{
	printf("\tPMR Elasticity Buffer Size Base  (PMRWBZ): %x\n", NVME_PMREBS_PMRWBZ(pmrebs));
	printf("\tRead Bypass Behavior                     : ");
	printf("memory reads not conflicting with memory writes ");
	printf("in the PMR Elasticity Buffer %s bypass those memory writes\n",
	       NVME_PMREBS_RBB(pmrebs) ? "SHALL" : "MAY");
	printf("\tPMR Elasticity Buffer Size Units (PMRSZU): %s\n",
	       nvme_register_unit_to_string(NVME_PMREBS_PMRSZU(pmrebs)));
}

static void stdout_registers_pmrswtp(__u32 pmrswtp)
{
	printf("\tPMR Sustained Write Throughput       (PMRSWTV): %x\n",
	       NVME_PMRSWTP_PMRSWTV(pmrswtp));
	printf("\tPMR Sustained Write Throughput Units (PMRSWTU): %s/second\n",
	       nvme_register_unit_to_string(NVME_PMRSWTP_PMRSWTU(pmrswtp)));
}

static void stdout_registers_pmrmscl(uint32_t pmrmscl)
{
	printf("\tController Base Address         (CBA): %#x\n",
	       (uint32_t)NVME_PMRMSC_CBA(pmrmscl));
	printf("\tController Memory Space Enable (CMSE): %#x\n\n", NVME_PMRMSC_CMSE(pmrmscl));
}

static void stdout_registers_pmrmscu(uint32_t pmrmscu)
{
	printf("\tController Base Address         (CBA): %#x\n",
		pmrmscu);
}

static void stdout_ctrl_register_human(int offset, uint64_t value, bool support)
{
	switch (offset) {
	case NVME_REG_CAP:
		stdout_registers_cap((struct nvme_bar_cap *)&value);
		break;
	case NVME_REG_VS:
		stdout_registers_version(value);
		break;
	case NVME_REG_INTMS:
		printf("\tInterrupt Vector Mask Set (IVMS): %#"PRIx64"\n\n", value);
		break;
	case NVME_REG_INTMC:
		printf("\tInterrupt Vector Mask Clear (IVMC): %#"PRIx64"\n\n", value);
		break;
	case NVME_REG_CC:
		stdout_registers_cc(value);
		break;
	case NVME_REG_CSTS:
		stdout_registers_csts(value);
		break;
	case NVME_REG_NSSR:
		printf("\tNVM Subsystem Reset Control (NSSRC): %"PRIu64"\n\n", value);
		break;
	case NVME_REG_AQA:
		stdout_registers_aqa(value);
		break;
	case NVME_REG_ASQ:
		stdout_registers_asq(value);
		break;
	case NVME_REG_ACQ:
		stdout_registers_acq(value);
		break;
	case NVME_REG_CMBLOC:
		stdout_registers_cmbloc(value, support);
		break;
	case NVME_REG_CMBSZ:
		stdout_registers_cmbsz(value);
		break;
	case NVME_REG_BPINFO:
		stdout_registers_bpinfo(value);
		break;
	case NVME_REG_BPRSEL:
		stdout_registers_bprsel(value);
		break;
	case NVME_REG_BPMBL:
		stdout_registers_bpmbl(value);
		break;
	case NVME_REG_CMBMSC:
		stdout_registers_cmbmsc(value);
		break;
	case NVME_REG_CMBSTS:
		stdout_registers_cmbsts(value);
		break;
	case NVME_REG_CMBEBS:
		stdout_registers_cmbebs(value);
		break;
	case NVME_REG_CMBSWTP:
		stdout_registers_cmbswtp(value);
		break;
	case NVME_REG_NSSD:
		stdout_registers_nssd(value);
		break;
	case NVME_REG_CRTO:
		stdout_registers_crto(value);
		break;
	case NVME_REG_PMRCAP:
		stdout_registers_pmrcap(value);
		break;
	case NVME_REG_PMRCTL:
		stdout_registers_pmrctl(value);
		break;
	case NVME_REG_PMRSTS:
		stdout_registers_pmrsts(value, support);
		break;
	case NVME_REG_PMREBS:
		stdout_registers_pmrebs(value);
		break;
	case NVME_REG_PMRSWTP:
		stdout_registers_pmrswtp(value);
		break;
	case NVME_REG_PMRMSCL:
		stdout_registers_pmrmscl(value);
		break;
	case NVME_REG_PMRMSCU:
		stdout_registers_pmrmscu(value);
		break;
	default:
		printf("unknown register: %#04x (%s), value: %#"PRIx64"\n",
		       offset, nvme_register_to_string(offset), value);
		break;
	}
}

static void stdout_ctrl_register_common(int offset, uint64_t value, bool fabrics)
{
	bool human = !!(stdout_print_ops.flags & VERBOSE);
	const char *name = nvme_register_to_string(offset);
	const char *type = fabrics ? "property" : "register";

	if (human) {
		printf("%s: %#"PRIx64"\n", name, value);
		stdout_ctrl_register_human(offset, value, true);
		return;
	}

	printf("%s: %#04x (%s), value: %#"PRIx64"\n", type, offset,
	       name, value);
}

static void stdout_ctrl_register(int offset, uint64_t value)
{
	stdout_ctrl_register_common(offset, value, false);
}

static void stdout_ctrl_register_support(void *bar, bool fabrics, int offset, bool human,
					 bool support)
{
	uint64_t value = nvme_is_64bit_reg(offset) ? mmio_read64(bar + offset) :
	    mmio_read32(bar + offset);

	if (fabrics && value == -1)
		return;

	printf("%-8s: ", nvme_register_symbol_to_string(offset));

	printf("%#"PRIx64"\n", value);

	if (human)
		stdout_ctrl_register_human(offset, value, support);
}

void stdout_ctrl_registers(void *bar, bool fabrics)
{
	uint32_t value;
	bool human = !!(stdout_print_ops.flags & VERBOSE);
	int offset;
	bool support;

	for (offset = NVME_REG_CAP; offset <= NVME_REG_PMRMSCU; offset += get_reg_size(offset)) {
		if (!nvme_is_ctrl_reg(offset) || (fabrics && !nvme_is_fabrics_reg(offset)))
			continue;
		switch (offset) {
		case NVME_REG_CMBLOC:
			value = mmio_read32(bar + NVME_REG_CMBSZ);
			support = nvme_registers_cmbloc_support(value);
			break;
		case NVME_REG_PMRSTS:
			value = mmio_read32(bar + NVME_REG_PMRCTL);
			support = nvme_registers_pmrctl_ready(value);
			break;
		default:
			support = true;
			break;
		}
		stdout_ctrl_register_support(bar, fabrics, offset, human, support);
	}
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
		fprintf(stderr, "Error: %s\n", nvme_strerror(errno));
		return;
	}

	val = nvme_status_get_value(status);
	type = nvme_status_get_type(status);

	switch (type) {
	case NVME_STATUS_TYPE_NVME:
		fprintf(stderr, "NVMe status: %s(%#x)\n",
			nvme_status_to_string(val, false), val);
		break;
	case NVME_STATUS_TYPE_MI:
		fprintf(stderr, "NVMe-MI status: %s(%#x)\n",
			nvme_mi_status_to_string(val), val);
		break;
	default:
		fprintf(stderr, "Unknown status type %d, value %#x\n", type,
			val);
		break;
	}
}

static void stdout_error_status(int status, const char *msg, va_list ap)
{
	vfprintf(stderr, msg, ap);
	fprintf(stderr, ": ");
	stdout_status(status);
}

static void stdout_id_ctrl_cmic(__u8 cmic)
{
	__u8 rsvd = NVME_CMIC_MULTI_RSVD(cmic);
	__u8 ana = NVME_CMIC_MULTI_ANA(cmic);
	__u8 sriov = NVME_CMIC_MULTI_SRIOV(cmic);
	__u8 mctl = NVME_CMIC_MULTI_CTRL(cmic);
	__u8 mp = NVME_CMIC_MULTI_PORT(cmic);

	if (rsvd)
		printf("  [7:4] : %#x\tReserved\n", rsvd);
	printf("  [3:3] : %#x\tANA %ssupported\n", ana, ana ? "" : "not ");
	printf("  [2:2] : %#x\t%s\n", sriov, sriov ? "SR-IOV" : "PCI");
	printf("  [1:1] : %#x\t%s Controller\n", mctl, mctl ? "Multi" : "Single");
	printf("  [0:0] : %#x\t%s Port\n", mp, mp ? "Multi" : "Single");
	printf("\n");
}

static void stdout_id_ctrl_oaes(__le32 ctrl_oaes)
{
	__u32 oaes = le32_to_cpu(ctrl_oaes);
	__u32 dlpcn = (oaes & NVME_CTRL_OAES_DL) >> 31;
	__u32 rsvd28 = (oaes & 0x70000000) >> 28;
	__u32 zdcn = (oaes & NVME_CTRL_OAES_ZD) >> 27;
	__u32 rsvd20 = (oaes & 0x7fe0000) >> 20;
	__u32 ansan = (oaes & NVME_CTRL_OAES_ANSAN) >> 19;
	__u32 rsvd18 = (oaes >> 18) & 0x1;
	__u32 rgcns = (oaes & NVME_CTRL_OAES_RGCNS) >> 17;
	__u32 tthr = (oaes & NVME_CTRL_OAES_TTH) >> 16;
	__u32 normal_shn = (oaes & NVME_CTRL_OAES_NS) >> 15;
	__u32 egealpcn = (oaes & NVME_CTRL_OAES_EGE) >> 14;
	__u32 lbasin = (oaes & NVME_CTRL_OAES_LBAS) >> 13;
	__u32 plealcn = (oaes & NVME_CTRL_OAES_PLEA) >> 12;
	__u32 anacn = (oaes & NVME_CTRL_OAES_ANA) >> 11;
	__u32 rsvd10 = (oaes >> 10) & 0x1;
	__u32 fan = (oaes & NVME_CTRL_OAES_FA) >> 9;
	__u32 nace = (oaes & NVME_CTRL_OAES_NA) >> 8;
	__u32 rsvd0 = oaes & 0xFF;

	printf("  [31:31] : %#x\tDiscovery Log Change Notice %sSupported\n",
			dlpcn, dlpcn ? "" : "Not ");
	if (rsvd28)
		printf("  [30:28] : %#x\tReserved\n", rsvd28);
	printf("  [27:27] : %#x\tZone Descriptor Changed Notices %sSupported\n",
			zdcn, zdcn ? "" : "Not ");
	if (rsvd20)
		printf("  [26:20] : %#x\tReserved\n", rsvd20);
	printf("  [19:19] : %#x\tAllocated Namespace Attribute Notices %sSupported\n",
			ansan, ansan ? "" : "Not ");
	if (rsvd18)
		printf("  [18:18] : %#x\tReserved\n", rsvd18);
	printf("  [17:17] : %#x\tReachability Groups Change Notices %sSupported\n",
			rgcns, rgcns ? "" : "Not ");
	printf("  [16:16] : %#x\tTemperature Threshold Hysteresis Recovery %sSupported\n",
		tthr, tthr ? "" : "Not ");
	printf("  [15:15] : %#x\tNormal NSS Shutdown Event %sSupported\n",
			normal_shn, normal_shn ? "" : "Not ");
	printf("  [14:14] : %#x\tEndurance Group Event Aggregate Log Page"\
			" Change Notice %sSupported\n",
			egealpcn, egealpcn ? "" : "Not ");
	printf("  [13:13] : %#x\tLBA Status Information Notices %sSupported\n",
			lbasin, lbasin ? "" : "Not ");
	printf("  [12:12] : %#x\tPredictable Latency Event Aggregate Log Change"\
			" Notices %sSupported\n",
			plealcn, plealcn ? "" : "Not ");
	printf("  [11:11] : %#x\tAsymmetric Namespace Access Change Notices"\
			" %sSupported\n", anacn, anacn ? "" : "Not ");
	if (rsvd10)
		printf("  [10:10] : %#x\tReserved\n", rsvd10);
	printf("  [9:9] : %#x\tFirmware Activation Notices %sSupported\n",
		fan, fan ? "" : "Not ");
	printf("  [8:8] : %#x\tNamespace Attribute Changed Event %sSupported\n",
		nace, nace ? "" : "Not ");
	if (rsvd0)
		printf("  [7:0] : %#x\tReserved\n", rsvd0);
	printf("\n");
}

static void stdout_id_ctrl_ctratt(__le32 ctrl_ctratt)
{
	__u32 ctratt = le32_to_cpu(ctrl_ctratt);
	__u32 rsvd20 = (ctratt >> 20);
	__u32 fdps = (ctratt & NVME_CTRL_CTRATT_FDPS) >> 19;
	__u32 rhii = (ctratt & NVME_CTRL_CTRATT_RHII) >> 18;
	__u32 hmbr = (ctratt & NVME_CTRL_CTRATT_HMBR) >> 17;
	__u32 mem = (ctratt & NVME_CTRL_CTRATT_MEM) >> 16;
	__u32 elbas = (ctratt & NVME_CTRL_CTRATT_ELBAS) >> 15;
	__u32 dnvms = (ctratt & NVME_CTRL_CTRATT_DEL_NVM_SETS) >> 14;
	__u32 deg = (ctratt & NVME_CTRL_CTRATT_DEL_ENDURANCE_GROUPS) >> 13;
	__u32 vcm = (ctratt & NVME_CTRL_CTRATT_VARIABLE_CAP) >> 12;
	__u32 fcm = (ctratt & NVME_CTRL_CTRATT_FIXED_CAP) >> 11;
	__u32 mds = (ctratt & NVME_CTRL_CTRATT_MDS) >> 10;
	__u32 ulist = (ctratt & NVME_CTRL_CTRATT_UUID_LIST) >> 9;
	__u32 sqa = (ctratt & NVME_CTRL_CTRATT_SQ_ASSOCIATIONS) >> 8;
	__u32 ng = (ctratt & NVME_CTRL_CTRATT_NAMESPACE_GRANULARITY) >> 7;
	__u32 tbkas = (ctratt & NVME_CTRL_CTRATT_TBKAS) >> 6;
	__u32 plm = (ctratt & NVME_CTRL_CTRATT_PREDICTABLE_LAT) >> 5;
	__u32 egs = (ctratt & NVME_CTRL_CTRATT_ENDURANCE_GROUPS) >> 4;
	__u32 rrlvls = (ctratt & NVME_CTRL_CTRATT_READ_RECV_LVLS) >> 3;
	__u32 nsets = (ctratt & NVME_CTRL_CTRATT_NVM_SETS) >> 2;
	__u32 nopspm = (ctratt & NVME_CTRL_CTRATT_NON_OP_PSP) >> 1;
	__u32 hids = (ctratt & NVME_CTRL_CTRATT_128_ID) >> 0;

	if (rsvd20)
		printf(" [31:20] : %#x\tReserved\n", rsvd20);
	printf("  [19:19] : %#x\tFlexible Data Placement %sSupported\n",
		fdps, fdps ? "" : "Not ");
	printf("  [18:18] : %#x\tReservations and Host Identifier Interaction %sSupported\n",
		rhii, rhii ? "" : "Not ");
	printf("  [17:17] : %#x\tHMB Restrict Non-Operational Power State Access %sSupported\n",
		hmbr, hmbr ? "" : "Not ");
	printf("  [16:16] : %#x\tMDTS and Size Limits Exclude Metadata %sSupported\n",
		mem, mem ? "" : "Not ");
	printf("  [15:15] : %#x\tExtended LBA Formats %sSupported\n",
		elbas, elbas ? "" : "Not ");
	printf("  [14:14] : %#x\tDelete NVM Set %sSupported\n",
		dnvms, dnvms ? "" : "Not ");
	printf("  [13:13] : %#x\tDelete Endurance Group %sSupported\n",
		deg, deg ? "" : "Not ");
	printf("  [12:12] : %#x\tVariable Capacity Management %sSupported\n",
		vcm, vcm ? "" : "Not ");
	printf("  [11:11] : %#x\tFixed Capacity Management %sSupported\n",
		fcm, fcm ? "" : "Not ");
	printf("  [10:10] : %#x\tMulti Domain Subsystem %sSupported\n",
		mds, mds ? "" : "Not ");
	printf("  [9:9] : %#x\tUUID List %sSupported\n",
		ulist, ulist ? "" : "Not ");
	printf("  [8:8] : %#x\tSQ Associations %sSupported\n",
		sqa, sqa ? "" : "Not ");
	printf("  [7:7] : %#x\tNamespace Granularity %sSupported\n",
		ng, ng ? "" : "Not ");
	printf("  [6:6] : %#x\tTraffic Based Keep Alive %sSupported\n",
		tbkas, tbkas ? "" : "Not ");
	printf("  [5:5] : %#x\tPredictable Latency Mode %sSupported\n",
		plm, plm ? "" : "Not ");
	printf("  [4:4] : %#x\tEndurance Groups %sSupported\n",
		egs, egs ? "" : "Not ");
	printf("  [3:3] : %#x\tRead Recovery Levels %sSupported\n",
		rrlvls, rrlvls ? "" : "Not ");
	printf("  [2:2] : %#x\tNVM Sets %sSupported\n",
		nsets, nsets ? "" : "Not ");
	printf("  [1:1] : %#x\tNon-Operational Power State Permissive %sSupported\n",
		nopspm, nopspm ? "" : "Not ");
	printf("  [0:0] : %#x\t128-bit Host Identifier %sSupported\n",
		hids, hids ? "" : "Not ");
	printf("\n");
}

static void stdout_id_ctrl_bpcap(__u8 ctrl_bpcap)
{
	__u8 rsvd3 = (ctrl_bpcap >> 3);
	__u8 sfbpwps = NVME_GET(ctrl_bpcap, CTRL_BACAP_SFBPWPS);
	__u8 rpmbbpwps = NVME_GET(ctrl_bpcap, CTRL_BACAP_RPMBBPWPS);
	static const char * const rpmbbpwps_def[] = {
		"Support Not Specified",
		"Not Supported",
		"Supported"
	};

	if (rsvd3)
		printf(" [7:3] : %#x\tReserved\n", rsvd3);

	printf("  [2:2] : %#x\tSet Features Boot Partition Write Protection %sSupported\n",
		sfbpwps, sfbpwps ? "" : "Not ");
	printf("  [1:0] : %#x\tRPMB Boot Partition Write Protection %s\n",
		rpmbbpwps, rpmbbpwps_def[rpmbbpwps]);
	printf("\n");
}

static void stdout_id_ctrl_plsi(__u8 ctrl_plsi)
{
	__u8 rsvd2 = (ctrl_plsi >> 2);
	__u8 plsfq = NVME_GET(ctrl_plsi, CTRL_PLSI_PLSFQ);
	__u8 plsepf = NVME_GET(ctrl_plsi, CTRL_PLSI_PLSEPF);

	if (rsvd2)
		printf(" [7:2] : %#x\tReserved\n", rsvd2);

	printf("  [1:1] : %#x\tPower Loss Signaling with Forced Quiescence %sSupported\n",
		plsfq, plsfq ? "" : "Not ");
	printf("  [0:0] : %#x\tPower Loss Signaling with Emergency Power Fail %sSupported\n",
		plsepf, plsepf ? "" : "Not ");
	printf("\n");
}

static void stdout_id_ctrl_crcap(__u8 ctrl_crcap)
{
	__u8 rsvd2 = (ctrl_crcap >> 2);
	__u8 rgidc = NVME_GET(ctrl_crcap, CTRL_CRCAP_RGIDC);
	__u8 rrsup = NVME_GET(ctrl_crcap, CTRL_CRCAP_RRSUP);

	if (rsvd2)
		printf(" [7:2] : %#x\tReserved\n", rsvd2);

	printf("  [1:1] : %#x\tRGRPID %s while the namespace is attached to any controller.\n",
		rgidc, rgidc ? "does not change" : "may change");
	printf("  [0:0] : %#x\tReachability Reporting %sSupported\n",
		rrsup, rrsup ? "" : "Not ");
	printf("\n");
}

static void stdout_id_ctrl_cntrltype(__u8 cntrltype)
{
	__u8 rsvd = (cntrltype & 0xFC) >> 2;
	__u8 cntrl = cntrltype & 0x3;

	static const char * const type[] = {
		"Controller type not reported",
		"I/O Controller",
		"Discovery Controller",
		"Administrative Controller"
	};

	printf("  [7:2] : %#x\tReserved\n", rsvd);
	printf("  [1:0] : %#x\t%s\n", cntrltype, type[cntrl]);
}

static void stdout_id_ctrl_nvmsr(__u8 nvmsr)
{
	__u8 rsvd = (nvmsr >> 2) & 0xfc;
	__u8 nvmee = (nvmsr >> 1) & 0x1;
	__u8 nvmesd = nvmsr & 0x1;

	if (rsvd)
		printf(" [7:2] : %#x\tReserved\n", rsvd);
	printf("  [1:1] : %#x\tNVM subsystem %spart of an Enclosure\n",
		nvmee, nvmee ? "" : "Not ");
	printf("  [0:0] : %#x\tNVM subsystem %spart of a Storage Device\n",
		nvmesd, nvmesd ? "" : "Not ");
	printf("\n");
}

static void stdout_id_ctrl_vwci(__u8 vwci)
{
	__u8 vwcrv = (vwci >> 7) & 0x1;
	__u8 vwcr = vwci & 0xfe;

	printf("  [7:7] : %#x\tVPD Write Cycles Remaining field is %svalid.\n",
		vwcrv, vwcrv ? "" : "Not ");
	printf("  [6:0] : %#x\tVPD Write Cycles Remaining\n", vwcr);
	printf("\n");

}

static void stdout_id_ctrl_mec(__u8 mec)
{
	__u8 rsvd = (mec >> 2) & 0xfc;
	__u8 pcieme = (mec >> 1) & 0x1;
	__u8 smbusme = mec & 0x1;

	if (rsvd)
		printf(" [7:2] : %#x\tReserved\n", rsvd);
	printf("  [1:1] : %#x\tNVM subsystem %scontains a Management Endpoint"\
		" on a PCIe port\n", pcieme, pcieme ? "" : "Not ");
	printf("  [0:0] : %#x\tNVM subsystem %scontains a Management Endpoint"\
		" on an SMBus/I2C port\n", smbusme, smbusme ? "" : "Not ");
	printf("\n");

}

static void stdout_id_ctrl_oacs(__le16 ctrl_oacs)
{
	__u16 oacs = le16_to_cpu(ctrl_oacs);
	__u16 rsvd = (oacs & 0xF000) >> 12;
	__u16 hmlms = (oacs & 0x800) >> 11;
	__u16 lock = (oacs & NVME_CTRL_OACS_CMD_FEAT_LD) >> 10;
	__u16 glbas = (oacs & NVME_CTRL_OACS_LBA_STATUS) >> 9;
	__u16 dbc = (oacs & NVME_CTRL_OACS_DBBUF_CFG) >> 8;
	__u16 vir = (oacs & NVME_CTRL_OACS_VIRT_MGMT) >> 7;
	__u16 nmi = (oacs & NVME_CTRL_OACS_NVME_MI) >> 6;
	__u16 dir = (oacs & NVME_CTRL_OACS_DIRECTIVES) >> 5;
	__u16 sft = (oacs & NVME_CTRL_OACS_SELF_TEST) >> 4;
	__u16 nsm = (oacs & NVME_CTRL_OACS_NS_MGMT) >> 3;
	__u16 fwc = (oacs & NVME_CTRL_OACS_FW) >> 2;
	__u16 fmt = (oacs & NVME_CTRL_OACS_FORMAT) >> 1;
	__u16 sec = oacs & NVME_CTRL_OACS_SECURITY;

	if (rsvd)
		printf(" [15:12] : %#x\tReserved\n", rsvd);
	printf("  [11:11] : %#x\tHost Managed Live Migration %sSupported\n",
		hmlms, hmlms ? "" : "Not ");
	printf("  [10:10] : %#x\tLockdown Command and Feature %sSupported\n",
		lock, lock ? "" : "Not ");
	printf("  [9:9] : %#x\tGet LBA Status Capability %sSupported\n",
		glbas, glbas ? "" : "Not ");
	printf("  [8:8] : %#x\tDoorbell Buffer Config %sSupported\n",
		dbc, dbc ? "" : "Not ");
	printf("  [7:7] : %#x\tVirtualization Management %sSupported\n",
		vir, vir ? "" : "Not ");
	printf("  [6:6] : %#x\tNVMe-MI Send and Receive %sSupported\n",
		nmi, nmi ? "" : "Not ");
	printf("  [5:5] : %#x\tDirectives %sSupported\n",
		dir, dir ? "" : "Not ");
	printf("  [4:4] : %#x\tDevice Self-test %sSupported\n",
		sft, sft ? "" : "Not ");
	printf("  [3:3] : %#x\tNS Management and Attachment %sSupported\n",
		nsm, nsm ? "" : "Not ");
	printf("  [2:2] : %#x\tFW Commit and Download %sSupported\n",
		fwc, fwc ? "" : "Not ");
	printf("  [1:1] : %#x\tFormat NVM %sSupported\n",
		fmt, fmt ? "" : "Not ");
	printf("  [0:0] : %#x\tSecurity Send and Receive %sSupported\n",
		sec, sec ? "" : "Not ");
	printf("\n");
}

static void stdout_id_ctrl_frmw(__u8 frmw)
{
	__u8 rsvd = (frmw & 0xC0) >> 6;
	__u8 smud = (frmw >> 5) & 0x1;
	__u8 fawr = (frmw & 0x10) >> 4;
	__u8 nfws = (frmw & 0xE) >> 1;
	__u8 s1ro = frmw & 0x1;

	if (rsvd)
		printf("  [7:6] : %#x\tReserved\n", rsvd);
	printf("  [5:5] : %#x\tMultiple FW or Boot Update Detection %sSupported\n",
		smud, smud ? "" : "Not ");
	printf("  [4:4] : %#x\tFirmware Activate Without Reset %sSupported\n",
		fawr, fawr ? "" : "Not ");
	printf("  [3:1] : %#x\tNumber of Firmware Slots\n", nfws);
	printf("  [0:0] : %#x\tFirmware Slot 1 Read%s\n",
		s1ro, s1ro ? "-Only" : "/Write");
	printf("\n");
}

static void stdout_id_ctrl_lpa(__u8 lpa)
{
	__u8 rsvd = (lpa & 0x80) >> 7;
	__u8 tel = (lpa >> 6) & 0x1;
	__u8 lid_sup = (lpa >> 5) & 0x1;
	__u8 persevnt = (lpa & 0x10) >> 4;
	__u8 telem = (lpa & 0x8) >> 3;
	__u8 ed = (lpa & 0x4) >> 2;
	__u8 celp = (lpa & 0x2) >> 1;
	__u8 smlp = lpa & 0x1;

	if (rsvd)
		printf("  [7:7] : %#x\tReserved\n", rsvd);
	printf("  [6:6] : %#x\tTelemetry Log Data Area 4 %sSupported\n",
			tel, tel ? "" : "Not ");
	printf("  [5:5] : %#x\tLID 0x0, Scope of each command in LID 0x5, "\
			"0x12, 0x13 %sSupported\n", lid_sup, lid_sup ? "" : "Not ");
	printf("  [4:4] : %#x\tPersistent Event log %sSupported\n",
			persevnt, persevnt ? "" : "Not ");
	printf("  [3:3] : %#x\tTelemetry host/controller initiated log page %sSupported\n",
	       telem, telem ? "" : "Not ");
	printf("  [2:2] : %#x\tExtended data for Get Log Page %sSupported\n",
		ed, ed ? "" : "Not ");
	printf("  [1:1] : %#x\tCommand Effects Log Page %sSupported\n",
		celp, celp ? "" : "Not ");
	printf("  [0:0] : %#x\tSMART/Health Log Page per NS %sSupported\n",
		smlp, smlp ? "" : "Not ");
	printf("\n");
}

static void stdout_id_ctrl_elpe(__u8 elpe)
{
	printf("  [7:0] : %d (0's based)\tError Log Page Entries (ELPE)\n",
	       elpe);
	printf("\n");
}

static void stdout_id_ctrl_npss(__u8 npss)
{
	printf("  [7:0] : %d (0's based)\tNumber of Power States Support (NPSS)\n",
	       npss);
	printf("\n");
}

static void stdout_id_ctrl_avscc(__u8 avscc)
{
	__u8 rsvd = (avscc & 0xFE) >> 1;
	__u8 fmt = avscc & 0x1;

	if (rsvd)
		printf("  [7:1] : %#x\tReserved\n", rsvd);
	printf("  [0:0] : %#x\tAdmin Vendor Specific Commands uses %s Format\n",
		fmt, fmt ? "NVMe" : "Vendor Specific");
	printf("\n");
}

static void stdout_id_ctrl_apsta(__u8 apsta)
{
	__u8 rsvd = (apsta & 0xFE) >> 1;
	__u8 apst = apsta & 0x1;

	if (rsvd)
		printf("  [7:1] : %#x\tReserved\n", rsvd);
	printf("  [0:0] : %#x\tAutonomous Power State Transitions %sSupported\n",
		apst, apst ? "" : "Not ");
	printf("\n");
}

static void stdout_id_ctrl_wctemp(__le16 wctemp)
{
	printf(" [15:0] : %s (%u K)\tWarning Composite Temperature Threshold (WCTEMP)\n",
	       nvme_degrees_string(le16_to_cpu(wctemp)), le16_to_cpu(wctemp));
	printf("\n");
}

static void stdout_id_ctrl_cctemp(__le16 cctemp)
{
	printf(" [15:0] : %s (%u K)\tCritical Composite Temperature Threshold (CCTEMP)\n",
	       nvme_degrees_string(le16_to_cpu(cctemp)), le16_to_cpu(cctemp));
	printf("\n");
}

static void stdout_id_ctrl_tnvmcap(__u8 *tnvmcap)
{
	printf("[127:0] : %s\n", uint128_t_to_l10n_string(le128_to_cpu(tnvmcap)));
	printf("\tTotal NVM Capacity (TNVMCAP)\n\n");
}

static void stdout_id_ctrl_unvmcap(__u8 *unvmcap)
{
	printf("[127:0] : %s\n", uint128_t_to_l10n_string(le128_to_cpu(unvmcap)));
	printf("\tUnallocated NVM Capacity (UNVMCAP)\n\n");
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

static void stdout_id_ctrl_dsto(__u8 dsto)
{
	__u8 rsvd2 = (dsto & 0xfc) >> 2;
	__u8 hirs = (dsto & 0x2) >> 1;
	__u8 sdso = dsto & 0x1;

	if (rsvd2)
		printf("  [7:2] : %#x\tReserved\n", rsvd2);
	printf("  [1:1] : %#x\tHost-Initiated Refresh capability %sSupported\n",
		hirs, hirs ? "" : "Not ");
	printf("  [0:0] : %#x\tNVM subsystem supports %s at a time\n", sdso,
		sdso ? "only one device self-test operation in progress" :
		"one device self-test operation per controller");
	printf("\n");
}

static void stdout_id_ctrl_hctma(__le16 ctrl_hctma)
{
	__u16 hctma = le16_to_cpu(ctrl_hctma);
	__u16 rsvd = (hctma & 0xFFFE) >> 1;
	__u16 hctm = hctma & 0x1;

	if (rsvd)
		printf(" [15:1] : %#x\tReserved\n", rsvd);
	printf("  [0:0] : %#x\tHost Controlled Thermal Management %sSupported\n",
		hctm, hctm ? "" : "Not ");
	printf("\n");
}

static void stdout_id_ctrl_mntmt(__le16 mntmt)
{
	printf(" [15:0] : %s (%u K)\tMinimum Thermal Management Temperature (MNTMT)\n",
	       nvme_degrees_string(le16_to_cpu(mntmt)), le16_to_cpu(mntmt));
	printf("\n");
}

static void stdout_id_ctrl_mxtmt(__le16 mxtmt)
{
	printf(" [15:0] : %s (%u K)\tMaximum Thermal Management Temperature (MXTMT)\n",
	       nvme_degrees_string(le16_to_cpu(mxtmt)), le16_to_cpu(mxtmt));
	printf("\n");
}

static void stdout_id_ctrl_sanicap(__le32 ctrl_sanicap)
{
	__u32 sanicap = le32_to_cpu(ctrl_sanicap);
	__u32 rsvd4 = (sanicap & 0x1FFFFFF0) >> 4;
	__u32 vers = (sanicap & 0x8) >> 3;
	__u32 ows = (sanicap & 0x4) >> 2;
	__u32 bes = (sanicap & 0x2) >> 1;
	__u32 ces = sanicap & 0x1;
	__u32 ndi = (sanicap & 0x20000000) >> 29;
	__u32 nodmmas = (sanicap & 0xC0000000) >> 30;

	static const char * const modifies_media[] = {
		"Additional media modification after sanitize operation completes successfully is not defined",
		"Media is not additionally modified after sanitize operation completes successfully",
		"Media is additionally modified after sanitize operation completes successfully",
		"Reserved"
	};

	printf("  [31:30] : %#x\t%s\n", nodmmas, modifies_media[nodmmas]);
	printf("  [29:29] : %#x\tNo-Deallocate After Sanitize bit in Sanitize command %sSupported\n",
		ndi, ndi ? "Not " : "");
	if (rsvd4)
		printf("  [28:4] : %#x\tReserved\n", rsvd4);
	printf("  [3:3] : %#x\tMedia Verification and Post-Verification Deallocation state %sSupported\n",
		vers, vers ? "" : "Not ");
	printf("  [2:2] : %#x\tOverwrite Sanitize Operation %sSupported\n",
		ows, ows ? "" : "Not ");
	printf("  [1:1] : %#x\tBlock Erase Sanitize Operation %sSupported\n",
		bes, bes ? "" : "Not ");
	printf("  [0:0] : %#x\tCrypto Erase Sanitize Operation %sSupported\n",
		ces, ces ? "" : "Not ");
	printf("\n");
}

static void stdout_id_ctrl_anacap(__u8 anacap)
{
	__u8 nz = (anacap & 0x80) >> 7;
	__u8 grpid_static = (anacap & 0x40) >> 6;
	__u8 rsvd = (anacap & 0x20) >> 5;
	__u8 ana_change = (anacap & 0x10) >> 4;
	__u8 ana_persist_loss = (anacap & 0x08) >> 3;
	__u8 ana_inaccessible = (anacap & 0x04) >> 2;
	__u8 ana_nonopt = (anacap & 0x02) >> 1;
	__u8 ana_opt = (anacap & 0x01);

	printf("  [7:7] : %#x\tNon-zero group ID %sSupported\n",
			nz, nz ? "" : "Not ");
	printf("  [6:6] : %#x\tGroup ID does %schange\n",
			grpid_static, grpid_static ? "not " : "");
	if (rsvd)
		printf(" [5:5] : %#x\tReserved\n", rsvd);
	printf("  [4:4] : %#x\tANA Change state %sSupported\n",
			ana_change, ana_change ? "" : "Not ");
	printf("  [3:3] : %#x\tANA Persistent Loss state %sSupported\n",
			ana_persist_loss, ana_persist_loss ? "" : "Not ");
	printf("  [2:2] : %#x\tANA Inaccessible state %sSupported\n",
			ana_inaccessible, ana_inaccessible ? "" : "Not ");
	printf("  [1:1] : %#x\tANA Non-optimized state %sSupported\n",
			ana_nonopt, ana_nonopt ? "" : "Not ");
	printf("  [0:0] : %#x\tANA Optimized state %sSupported\n",
			ana_opt, ana_opt ? "" : "Not ");
	printf("\n");
}

static void stdout_id_ctrl_kpioc(__u8 ctrl_kpioc)
{
	__u8 rsvd2 = (ctrl_kpioc >> 2);
	__u8 kpiosc = NVME_GET(ctrl_kpioc, CTRL_KPIOC_KPIOSC);
	__u8 kpios = NVME_GET(ctrl_kpioc, CTRL_KPIOC_KPIOS);

	if (rsvd2)
		printf(" [7:2] : %#x\tReserved\n", rsvd2);

	printf("  [1:1] : %#x\tKey Per I/O capability %s to all namespaces\n",
		kpiosc, kpiosc ? "applies" : "Not apply");
	printf("  [0:0] : %#x\tKey Per I/O capability %sSupported\n",
		kpios, kpios ? "" : "Not ");
	printf("\n");
}

static void stdout_id_ctrl_tmpthha(__u8 tmpthha)
{
	__u8 rsvd3 = (tmpthha & 0xf8) >> 3;
	__u8 tmpthmh = tmpthha & 0x7;

	if (rsvd3)
		printf("  [7:3] : %#x\tReserved\n", rsvd3);
	printf("  [2:0] : %#x\tTemperature Threshold Maximum Hysteresis\n",
		tmpthmh);
	printf("\n");
}

static void stdout_id_ctrl_sqes(__u8 sqes)
{
	__u8 msqes = (sqes & 0xF0) >> 4;
	__u8 rsqes = sqes & 0xF;

	printf("  [7:4] : %#x\tMax SQ Entry Size (%d)\n", msqes, 1 << msqes);
	printf("  [3:0] : %#x\tMin SQ Entry Size (%d)\n", rsqes, 1 << rsqes);
	printf("\n");
}

static void stdout_id_ctrl_cqes(__u8 cqes)
{
	__u8 mcqes = (cqes & 0xF0) >> 4;
	__u8 rcqes = cqes & 0xF;

	printf("  [7:4] : %#x\tMax CQ Entry Size (%d)\n", mcqes, 1 << mcqes);
	printf("  [3:0] : %#x\tMin CQ Entry Size (%d)\n", rcqes, 1 << rcqes);
	printf("\n");
}

static void stdout_id_ctrl_oncs(__le16 ctrl_oncs)
{
	__u16 oncs = le16_to_cpu(ctrl_oncs);
	__u16 rsvd13 = oncs >> 13;
	bool nszs = !!(oncs & NVME_CTRL_ONCS_NAMESPACE_ZEROES);
	bool maxwzd = !!(oncs & NVME_CTRL_ONCS_WRITE_ZEROES_DEALLOCATE);
	bool afc  = !!(oncs & NVME_CTRL_ONCS_ALL_FAST_COPY);
	bool csa  = !!(oncs & NVME_CTRL_ONCS_COPY_SINGLE_ATOMICITY);
	bool copy = !!(oncs & NVME_CTRL_ONCS_COPY);
	bool vrfy = !!(oncs & NVME_CTRL_ONCS_VERIFY);
	bool tmst = !!(oncs & NVME_CTRL_ONCS_TIMESTAMP);
	bool resv = !!(oncs & NVME_CTRL_ONCS_RESERVATIONS);
	bool save = !!(oncs & NVME_CTRL_ONCS_SAVE_FEATURES);
	bool wzro = !!(oncs & NVME_CTRL_ONCS_WRITE_ZEROES);
	bool dsms = !!(oncs & NVME_CTRL_ONCS_DSM);
	bool wunc = !!(oncs & NVME_CTRL_ONCS_WRITE_UNCORRECTABLE);
	bool cmp  = !!(oncs & NVME_CTRL_ONCS_COMPARE);

	if (rsvd13)
		printf("  [15:13] : %#x\tReserved\n", rsvd13);
	printf("  [12:12] : %#x\tNamespace Zeroes %sSupported\n",
		nszs, nszs ? "" : "Not ");
	printf("  [11:11] : %#x\tMaximum Write Zeroes with Deallocate %sSupported\n",
		maxwzd, maxwzd ? "" : "Not ");
	printf("  [10:10] : %#x\tAll Fast Copy %sSupported\n",
		afc, afc ? "" : "Not ");
	printf("  [9:9] : %#x\tCopy Single Atomicity %sSupported\n",
		csa, csa ? "" : "Not ");
	printf("  [8:8] : %#x\tCopy %sSupported\n",
		copy, copy ? "" : "Not ");
	printf("  [7:7] : %#x\tVerify %sSupported\n",
		vrfy, vrfy ? "" : "Not ");
	printf("  [6:6] : %#x\tTimestamp %sSupported\n",
		tmst, tmst ? "" : "Not ");
	printf("  [5:5] : %#x\tReservations %sSupported\n",
		resv, resv ? "" : "Not ");
	printf("  [4:4] : %#x\tSave and Select %sSupported\n",
		save, save ? "" : "Not ");
	printf("  [3:3] : %#x\tWrite Zeroes %sSupported\n",
		wzro, wzro ? "" : "Not ");
	printf("  [2:2] : %#x\tData Set Management %sSupported\n",
		dsms, dsms ? "" : "Not ");
	printf("  [1:1] : %#x\tWrite Uncorrectable %sSupported\n",
		wunc, wunc ? "" : "Not ");
	printf("  [0:0] : %#x\tCompare %sSupported\n",
		cmp, cmp ? "" : "Not ");
	printf("\n");
}

static void stdout_id_ctrl_fuses(__le16 ctrl_fuses)
{
	__u16 fuses = le16_to_cpu(ctrl_fuses);
	__u16 rsvd = (fuses & 0xFE) >> 1;
	__u16 cmpw = fuses & 0x1;

	if (rsvd)
		printf(" [15:1] : %#x\tReserved\n", rsvd);
	printf("  [0:0] : %#x\tFused Compare and Write %sSupported\n",
		cmpw, cmpw ? "" : "Not ");
	printf("\n");
}

static void stdout_id_ctrl_fna(__u8 fna)
{
	__u8 rsvd = (fna & 0xF0) >> 4;
	__u8 bcnsid = (fna & NVME_CTRL_FNA_NSID_FFFFFFFF) >> 3;
	__u8 cese = (fna & NVME_CTRL_FNA_CRYPTO_ERASE) >> 2;
	__u8 cens = (fna & NVME_CTRL_FNA_SEC_ALL_NAMESPACES) >> 1;
	__u8 fmns = fna & NVME_CTRL_FNA_FMT_ALL_NAMESPACES;

	if (rsvd)
		printf("  [7:4] : %#x\tReserved\n", rsvd);
	printf("  [3:3] : %#x\tFormat NVM Broadcast NSID (FFFFFFFFh) %sSupported\n",
		bcnsid, bcnsid ? "Not " : "");
	printf("  [2:2] : %#x\tCrypto Erase %sSupported as part of Secure Erase\n",
		cese, cese ? "" : "Not ");
	printf("  [1:1] : %#x\tCrypto Erase Applies to %s Namespace(s)\n",
		cens, cens ? "All" : "Single");
	printf("  [0:0] : %#x\tFormat Applies to %s Namespace(s)\n",
		fmns, fmns ? "All" : "Single");
	printf("\n");
}

static void stdout_id_ctrl_vwc(__u8 vwc)
{
	__u8 rsvd = (vwc & 0xF8) >> 3;
	__u8 flush = (vwc & 0x6) >> 1;
	__u8 vwcp = vwc & 0x1;

	static const char * const flush_behavior[] = {
		"Support for the NSID field set to FFFFFFFFh is not indicated",
		"Reserved",
		"The Flush command does not support NSID set to FFFFFFFFh",
		"The Flush command supports NSID set to FFFFFFFFh"
	};

	if (rsvd)
		printf("  [7:3] : %#x\tReserved\n", rsvd);
	printf("  [2:1] : %#x\t%s\n", flush, flush_behavior[flush]);
	printf("  [0:0] : %#x\tVolatile Write Cache %sPresent\n", vwcp, vwcp ? "" : "Not ");
	printf("\n");
}

static void stdout_id_ctrl_icsvscc(__u8 icsvscc)
{
	__u8 rsvd = (icsvscc & 0xFE) >> 1;
	__u8 fmt = icsvscc & 0x1;

	if (rsvd)
		printf("  [7:1] : %#x\tReserved\n", rsvd);
	printf("  [0:0] : %#x\tNVM Vendor Specific Commands uses %s Format\n",
		fmt, fmt ? "NVMe" : "Vendor Specific");
	printf("\n");
}

static void stdout_id_ctrl_nwpc(__u8 nwpc)
{
	__u8 no_wp_wp = (nwpc & 0x01);
	__u8 wp_power_cycle = (nwpc & 0x02) >> 1;
	__u8 wp_permanent = (nwpc & 0x04) >> 2;
	__u8 rsvd = (nwpc & 0xF8) >> 3;

	if (rsvd)
		printf("  [7:3] : %#x\tReserved\n", rsvd);

	printf("  [2:2] : %#x\tPermanent Write Protect %sSupported\n",
		wp_permanent, wp_permanent ? "" : "Not ");
	printf("  [1:1] : %#x\tWrite Protect Until Power Supply %sSupported\n",
		wp_power_cycle, wp_power_cycle ? "" : "Not ");
	printf("  [0:0] : %#x\tNo Write Protect and Write Protect Namespace %sSupported\n",
		no_wp_wp, no_wp_wp ? "" : "Not ");
	printf("\n");
}

static void stdout_id_ctrl_ocfs(__le16 ctrl_ocfs)
{
	__u16 ocfs = le16_to_cpu(ctrl_ocfs);
	__u16 rsvd = ocfs >> 4;
	__u8 copy_fmt_supported;
	int copy_fmt;

	if (rsvd)
		printf("  [15:4] : %#x\tReserved\n", rsvd);
	for (copy_fmt = 3; copy_fmt >= 0; copy_fmt--) {
		copy_fmt_supported = ocfs >> copy_fmt & 1;
		printf("  [%d:%d] : %#x\tController Copy Format %xh %sSupported\n", copy_fmt,
		       copy_fmt, copy_fmt_supported, copy_fmt, copy_fmt_supported ? "" : "Not ");
	}
	printf("\n");
}

static void stdout_id_ctrl_sgls(__le32 ctrl_sgls)
{
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

	if (rsvd0)
		printf(" [31:22]: %#x\tReserved\n", rsvd0);
	if (sglsp || (!sglsp && trsdbd))
		printf(" [21:21]: %#x\tTransport SGL Data Block Descriptor %sSupported\n",
			trsdbd, trsdbd ? "" : "Not ");
	if (sglsp || (!sglsp && aofdsl))
		printf(" [20:20]: %#x\tAddress Offsets %sSupported\n",
			aofdsl, aofdsl ? "" : "Not ");
	if (sglsp || (!sglsp && mpcsd))
		printf(" [19:19]: %#x\tMetadata Pointer Containing "
			"SGL Descriptor is %sSupported\n",
			mpcsd, mpcsd ? "" : "Not ");
	if (sglsp || (!sglsp && sglltb))
		printf(" [18:18]: %#x\tSGL Length Larger than Buffer %sSupported\n",
			sglltb, sglltb ? "" : "Not ");
	if (sglsp || (!sglsp && bacmdb))
		printf(" [17:17]: %#x\tByte-Aligned Contig. MD Buffer %sSupported\n",
			bacmdb, bacmdb ? "" : "Not ");
	if (sglsp || (!sglsp && bbs))
		printf(" [16:16]: %#x\tSGL Bit-Bucket %sSupported\n",
			bbs, bbs ? "" : "Not ");
	printf(" [15:8] : %#x\tSGL Descriptor Threshold\n", sdt);
	if (rsvd1)
		printf(" [7:3] : %#x\tReserved\n", rsvd1);
	if (sglsp || (!sglsp && key))
		printf("  [2:2] : %#x\tKeyed SGL Data Block descriptor %sSupported\n",
			key, key ? "" : "Not ");
	if (sglsp == 0x3)
		printf("  [1:0] : %#x\tReserved\n", sglsp);
	else if (sglsp == 0x2)
		printf("  [1:0] : %#x\tScatter-Gather Lists Supported."
			" Dword alignment required.\n", sglsp);
	else if (sglsp == 0x1)
		printf("  [1:0] : %#x\tScatter-Gather Lists Supported."
			" No Dword alignment required.\n", sglsp);
	else
		printf(" [1:0]  : %#x\tScatter-Gather Lists Not Supported\n", sglsp);
	printf("\n");
}

static void stdout_id_ctrl_trattr(__u8 ctrl_trattr)
{
	__u8 rsvd3 = (ctrl_trattr >> 3);
	__u8 mrtll = NVME_GET(ctrl_trattr, CTRL_TRATTR_MRTLL);
	__u8 tudcs = NVME_GET(ctrl_trattr, CTRL_TRATTR_TUDCS);
	__u8 thmcs = NVME_GET(ctrl_trattr, CTRL_TRATTR_THMCS);

	if (rsvd3)
		printf(" [7:3] : %#x\tReserved\n", rsvd3);

	printf("  [2:2] : %#x\tMemory Range Tracking Length Limit\n", mrtll);
	printf("  [1:1] : %#x\tTracking User Data Changes %sSupported\n",
		tudcs, tudcs ? "" : "Not ");
	printf("  [0:0] : %#x\tTrack Host Memory Changes %sSupported\n",
		thmcs, thmcs ? "" : "Not ");
	printf("\n");
}

static void stdout_id_ctrl_fcatt(__u8 fcatt)
{
	__u8 rsvd = (fcatt & 0xFE) >> 1;
	__u8 scm = fcatt & 0x1;

	if (rsvd)
		printf("  [7:1] : %#x\tReserved\n", rsvd);
	printf("  [0:0] : %#x\t%s Controller Model\n",
		scm, scm ? "Static" : "Dynamic");
	printf("\n");
}

static void stdout_id_ctrl_ofcs(__le16 ofcs)
{
	__u16 rsvd = (ofcs & 0xfffe) >> 1;
	__u8 disconn = ofcs & 0x1;

	if (rsvd)
		printf("  [15:1] : %#x\tReserved\n", rsvd);
	printf("  [0:0] : %#x\tDisconnect command %s Supported\n",
		disconn, disconn ? "" : "Not");
	printf("\n");

}

static void stdout_id_ns_size(uint64_t nsze, uint64_t ncap, uint64_t nuse)
{
	printf("nsze    : %#"PRIx64"\tTotal size in logical blocks\n",
			le64_to_cpu(nsze));
	printf("ncap    : %#"PRIx64"\tMaximum size in logical blocks\n",
			le64_to_cpu(ncap));
	printf("nuse    : %#"PRIx64"\tCurrent size in logical blocks\n",
			le64_to_cpu(nuse));
}

static void stdout_id_ns_nsfeat(__u8 nsfeat)
{
	__u8 optrperf = (nsfeat & 0x80) >> 7;
	__u8 mam = (nsfeat & 0x40) >> 6;
	__u8 optperf = (nsfeat & 0x30) >> 4;
	__u8 uidreuse = (nsfeat & 0x8) >> 3;
	__u8 dulbe = (nsfeat & 0x4) >> 2;
	__u8 na = (nsfeat & 0x2) >> 1;
	__u8 thin = nsfeat & 0x1;

	printf("  [7:7] : %#x\tNPRG, NPRA and NORS are %sSupported\n",
		optrperf, optrperf ? "" : "Not ");
	printf("  [6:6] : %#x\t%s Atomicity Mode applies to write operations\n",
		mam, mam ? "Multiple" : "Single");
	printf("  [5:4] : %#x\tNPWG, NPWA, %s%sNPDA, and NOWS are %sSupported\n",
		optperf, ((optperf & 0x1) || (!optperf)) ? "NPDG, " : "",
		((optperf & 0x2) || (!optperf)) ? "NPDGL, " : "", optperf ? "" : "Not ");
	printf("  [3:3] : %#x\tNGUID and EUI64 fields if non-zero, %sReused\n",
		uidreuse, uidreuse ? "Never " : "");
	printf("  [2:2] : %#x\tDeallocated or Unwritten Logical Block error %sSupported\n",
		dulbe, dulbe ? "" : "Not ");
	printf("  [1:1] : %#x\tNamespace uses %s\n",
		na, na ? "NAWUN, NAWUPF, and NACWU" : "AWUN, AWUPF, and ACWU");
	printf("  [0:0] : %#x\tThin Provisioning %sSupported\n",
		thin, thin ? "" : "Not ");
	printf("\n");
}

static void stdout_id_ns_flbas(__u8 flbas)
{
	__u8 rsvd = (flbas & 0x80) >> 7;
	__u8 msb2_lbaf = (flbas & NVME_NS_FLBAS_HIGHER_MASK) >> 5;
	__u8 mdedata = (flbas & 0x10) >> 4;
	__u8 lsb4_lbaf = flbas & NVME_NS_FLBAS_LOWER_MASK;

	if (rsvd)
		printf("  [7:7] : %#x\tReserved\n", rsvd);
	printf("  [6:5] : %#x\tMost significant 2 bits of Current LBA Format Selected\n",
		msb2_lbaf);
	printf("  [4:4] : %#x\tMetadata Transferred %s\n",
		mdedata, mdedata ? "at End of Data LBA" : "in Separate Contiguous Buffer");
	printf("  [3:0] : %#x\tLeast significant 4 bits of Current LBA Format Selected\n",
		lsb4_lbaf);
	printf("\n");
}

static void stdout_id_ns_mc(__u8 mc)
{
	__u8 rsvd = (mc & 0xFC) >> 2;
	__u8 mdp = (mc & 0x2) >> 1;
	__u8 extdlba = mc & 0x1;

	if (rsvd)
		printf("  [7:2] : %#x\tReserved\n", rsvd);
	printf("  [1:1] : %#x\tMetadata Pointer %sSupported\n",
		mdp, mdp ? "" : "Not ");
	printf("  [0:0] : %#x\tMetadata as Part of Extended Data LBA %sSupported\n",
		extdlba, extdlba ? "" : "Not ");
	printf("\n");
}

static void stdout_id_ns_dpc(__u8 dpc)
{
	__u8 rsvd = (dpc & 0xE0) >> 5;
	__u8 pil8 = (dpc & 0x10) >> 4;
	__u8 pif8 = (dpc & 0x8) >> 3;
	__u8 pit3 = (dpc & 0x4) >> 2;
	__u8 pit2 = (dpc & 0x2) >> 1;
	__u8 pit1 = dpc & 0x1;

	if (rsvd)
		printf("  [7:5] : %#x\tReserved\n", rsvd);
	printf("  [4:4] : %#x\tProtection Information Transferred as Last Bytes of Metadata %sSupported\n",
		pil8, pil8 ? "" : "Not ");
	printf("  [3:3] : %#x\tProtection Information Transferred as First Bytes of Metadata %sSupported\n",
		pif8, pif8 ? "" : "Not ");
	printf("  [2:2] : %#x\tProtection Information Type 3 %sSupported\n",
		pit3, pit3 ? "" : "Not ");
	printf("  [1:1] : %#x\tProtection Information Type 2 %sSupported\n",
		pit2, pit2 ? "" : "Not ");
	printf("  [0:0] : %#x\tProtection Information Type 1 %sSupported\n",
		pit1, pit1 ? "" : "Not ");
	printf("\n");
}

static void stdout_id_ns_dps(__u8 dps)
{
	__u8 rsvd = (dps & 0xF0) >> 4;
	__u8 pif8 = (dps & 0x8) >> 3;
	__u8 pit = dps & 0x7;

	if (rsvd)
		printf("  [7:4] : %#x\tReserved\n", rsvd);
	printf("  [3:3] : %#x\tProtection Information is Transferred as %s Bytes of Metadata\n",
		pif8, pif8 ? "First" : "Last");
	printf("  [2:0] : %#x\tProtection Information %s\n", pit,
		pit == 3 ? "Type 3 Enabled" :
		pit == 2 ? "Type 2 Enabled" :
		pit == 1 ? "Type 1 Enabled" :
		pit == 0 ? "Disabled" : "Reserved Enabled");
	printf("\n");
}

static void stdout_id_ns_nmic(__u8 nmic)
{
	__u8 rsvd = (nmic & 0xfc) >> 2;
	__u8 disns = (nmic & 0x2) >> 1;
	__u8 shrns = nmic & 0x1;

	if (rsvd)
		printf("  [7:2] : %#x\tReserved\n", rsvd);
	printf("  [1:1] : %#x\tNamespace is %sa Dispersed Namespace\n",
		disns, disns ? "" : "Not ");
	printf("  [0:0] : %#x\tNamespace Multipath %sCapable\n",
		shrns, shrns ? "" : "Not ");
	printf("\n");
}

static void stdout_id_ns_rescap(__u8 rescap)
{
	__u8 iekr = (rescap & 0x80) >> 7;
	__u8 eaar = (rescap & 0x40) >> 6;
	__u8 wear = (rescap & 0x20) >> 5;
	__u8 earo = (rescap & 0x10) >> 4;
	__u8 wero = (rescap & 0x8) >> 3;
	__u8 ea = (rescap & 0x4) >> 2;
	__u8 we = (rescap & 0x2) >> 1;
	__u8 ptpl = rescap & 0x1;

	printf("  [7:7] : %#x\tIgnore Existing Key - Used as defined in revision %s\n",
		iekr, iekr ? "1.3 or later" : "1.2.1 or earlier");
	printf("  [6:6] : %#x\tExclusive Access - All Registrants %sSupported\n",
		eaar, eaar ? "" : "Not ");
	printf("  [5:5] : %#x\tWrite Exclusive - All Registrants %sSupported\n",
		wear, wear ? "" : "Not ");
	printf("  [4:4] : %#x\tExclusive Access - Registrants Only %sSupported\n",
		earo, earo ? "" : "Not ");
	printf("  [3:3] : %#x\tWrite Exclusive - Registrants Only %sSupported\n",
		wero, wero ? "" : "Not ");
	printf("  [2:2] : %#x\tExclusive Access %sSupported\n",
		ea, ea ? "" : "Not ");
	printf("  [1:1] : %#x\tWrite Exclusive %sSupported\n",
		we, we ? "" : "Not ");
	printf("  [0:0] : %#x\tPersist Through Power Loss %sSupported\n",
		ptpl, ptpl ? "" : "Not ");
	printf("\n");
}

static void stdout_id_ns_fpi(__u8 fpi)
{
	__u8 fpis = (fpi & 0x80) >> 7;
	__u8 fpii = fpi & 0x7F;

	printf("  [7:7] : %#x\tFormat Progress Indicator %sSupported\n",
		fpis, fpis ? "" : "Not ");
	if (fpis || (!fpis && fpii))
		printf("  [6:0] : %#x\tFormat Progress Indicator (Remaining %d%%)\n",
		fpii, fpii);
	printf("\n");
}

static void stdout_id_ns_nsattr(__u8 nsattr)
{
	__u8 rsvd = (nsattr & 0xFE) >> 1;
	__u8 write_protected = nsattr & 0x1;

	if (rsvd)
		printf("  [7:1] : %#x\tReserved\n", rsvd);
	printf("  [0:0] : %#x\tNamespace %sWrite Protected\n",
			write_protected, write_protected ? "" : "Not ");
	printf("\n");
}

static void stdout_id_ns_dlfeat(__u8 dlfeat)
{
	__u8 rsvd = (dlfeat & 0xE0) >> 5;
	__u8 guard = (dlfeat & 0x10) >> 4;
	__u8 dwz = (dlfeat & 0x8) >> 3;
	__u8 val = dlfeat & 0x7;

	if (rsvd)
		printf("  [7:5] : %#x\tReserved\n", rsvd);
	printf("  [4:4] : %#x\tGuard Field of Deallocated Logical Blocks is set to %s\n",
		guard, guard ? "CRC of The Value Read" : "0xFFFF");
	printf("  [3:3] : %#x\tDeallocate Bit in the Write Zeroes Command is %sSupported\n",
		dwz, dwz ? "" : "Not ");
	printf("  [2:0] : %#x\tBytes Read From a Deallocated Logical Block and its Metadata are %s\n",
		val, val == 2 ? "0xFF" :
			val == 1 ? "0x00" :
			val == 0 ? "Not Reported" : "Reserved Value");
	printf("\n");
}

static void stdout_id_ns_kpios(__u8 kpios)
{
	__u8 rsvd = (kpios & 0xfc) >> 2;
	__u8 kpiosns = (kpios & 0x2) >> 1;
	__u8 kpioens = kpios & 0x1;

	if (rsvd)
		printf("  [7:2] : %#x\tReserved\n", rsvd);
	printf("  [1:1] : %#x\tKey Per I/O Capability %sSupported\n",
		kpiosns, kpiosns ? "" : "Not ");
	printf("  [0:0] : %#x\tKey Per I/O Capability %s\n", kpioens,
		kpioens ? "Enabled" : "Disabled");
	printf("\n");
}

static void stdout_id_ns(struct nvme_id_ns *ns, unsigned int nsid,
			 unsigned int lba_index, bool cap_only)
{
	bool human = stdout_print_ops.flags & VERBOSE;
	int vs = stdout_print_ops.flags & VS;
	int i;
	__u8 flbas;
	char *in_use = "(in use)";

	if (!cap_only) {
		printf("NVME Identify Namespace %d:\n", nsid);

		if (human)
			stdout_id_ns_size(ns->nsze, ns->ncap, ns->nuse);
		else {
			printf("nsze    : %#"PRIx64"\n", le64_to_cpu(ns->nsze));
			printf("ncap    : %#"PRIx64"\n", le64_to_cpu(ns->ncap));
			printf("nuse    : %#"PRIx64"\n", le64_to_cpu(ns->nuse));
		}

		printf("nsfeat  : %#x\n", ns->nsfeat);
		if (human)
			stdout_id_ns_nsfeat(ns->nsfeat);
	} else
		printf("NVMe Identify Namespace for LBA format[%d]:\n", lba_index);

	printf("nlbaf   : %d\n", ns->nlbaf);
	if (!cap_only) {
		printf("flbas   : %#x\n", ns->flbas);
		if (human)
			stdout_id_ns_flbas(ns->flbas);
	} else
		in_use = "";

	printf("mc      : %#x\n", ns->mc);
	if (human)
		stdout_id_ns_mc(ns->mc);
	printf("dpc     : %#x\n", ns->dpc);
	if (human)
		stdout_id_ns_dpc(ns->dpc);
	if (!cap_only) {
		printf("dps     : %#x\n", ns->dps);
		if (human)
			stdout_id_ns_dps(ns->dps);
		printf("nmic    : %#x\n", ns->nmic);
		if (human)
			stdout_id_ns_nmic(ns->nmic);
		printf("rescap  : %#x\n", ns->rescap);
		if (human)
			stdout_id_ns_rescap(ns->rescap);
		printf("fpi     : %#x\n", ns->fpi);
		if (human)
			stdout_id_ns_fpi(ns->fpi);
		printf("dlfeat  : %d\n", ns->dlfeat);
		if (human)
			stdout_id_ns_dlfeat(ns->dlfeat);
		printf("nawun   : %d\n", le16_to_cpu(ns->nawun));
		printf("nawupf  : %d\n", le16_to_cpu(ns->nawupf));
		printf("nacwu   : %d\n", le16_to_cpu(ns->nacwu));
		printf("nabsn   : %d\n", le16_to_cpu(ns->nabsn));
		printf("nabo    : %d\n", le16_to_cpu(ns->nabo));
		printf("nabspf  : %d\n", le16_to_cpu(ns->nabspf));
		printf("noiob   : %d\n", le16_to_cpu(ns->noiob));
		printf("nvmcap  : %s\n",
			uint128_t_to_l10n_string(le128_to_cpu(ns->nvmcap)));
		if (ns->nsfeat & 0x30) {
			printf("npwg    : %u\n", le16_to_cpu(ns->npwg));
			printf("npwa    : %u\n", le16_to_cpu(ns->npwa));
			if (ns->nsfeat & 0x10)
				printf("npdg    : %u\n", le16_to_cpu(ns->npdg));
			printf("npda    : %u\n", le16_to_cpu(ns->npda));
			printf("nows    : %u\n", le16_to_cpu(ns->nows));
		}
		printf("mssrl   : %u\n", le16_to_cpu(ns->mssrl));
		printf("mcl     : %u\n", le32_to_cpu(ns->mcl));
		printf("msrc    : %u\n", ns->msrc);
		printf("kpios   : %u\n", ns->kpios);
		if (human)
			stdout_id_ns_kpios(ns->kpios);
	}
	printf("nulbaf  : %u\n", ns->nulbaf);
	if (!cap_only) {
		printf("kpiodaag: %u\n", le32_to_cpu(ns->kpiodaag));
		printf("anagrpid: %u\n", le32_to_cpu(ns->anagrpid));
		printf("nsattr	: %u\n", ns->nsattr);
		if (human)
			stdout_id_ns_nsattr(ns->nsattr);
		printf("nvmsetid: %d\n", le16_to_cpu(ns->nvmsetid));
		printf("endgid  : %d\n", le16_to_cpu(ns->endgid));

		printf("nguid   : ");
		for (i = 0; i < 16; i++)
			printf("%02x", ns->nguid[i]);
		printf("\n");

		printf("eui64   : ");
		for (i = 0; i < 8; i++)
			printf("%02x", ns->eui64[i]);
		printf("\n");
	}

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

static void stdout_cmd_set_independent_id_ns_nsfeat(__u8 nsfeat)
{
	__u8 rsvd6 = (nsfeat & 0xE0) >> 6;
	__u8 vwcnp = (nsfeat & 0x20) >> 5;
	__u8 rmedia = (nsfeat & 0x10) >> 4;
	__u8 uidreuse = (nsfeat & 0x8) >> 3;
	__u8 rsvd0 = (nsfeat & 0x7);

	if (rsvd6)
		printf("  [7:6] : %#x\tReserved\n", rsvd6);
	printf("  [5:5] : %#x\tVolatile Write Cache is %sPresent\n",
		vwcnp, vwcnp ? "" : "Not ");
	printf("  [4:4] : %#x\tNamespace %sstore data on rotational media\n",
		rmedia, rmedia ? "" : "does not ");
	printf("  [3:3] : %#x\tNGUID and EUI64 fields if non-zero, %sReused\n",
		uidreuse, uidreuse ? "Never " : "");
	if (rsvd0)
		printf("  [2:0] : %#x\tReserved\n", rsvd0);
	printf("\n");
}

static void stdout_cmd_set_independent_id_ns_nstat(__u8 nstat)
{
	__u8 rsvd3 = (nstat & 0xf8) >> 3;
	__u8 ioi = (nstat & 0x6) >> 1;
	__u8 nrdy = nstat & 0x1;

	static const char * const ioi_string[] = {
		"I/O performance degradation is not reported",
		"Reserved",
		"I/O performance is not currently degraded",
		"I/O performance is currently degraded"
	};

	if (rsvd3)
		printf("  [7:3] : %#x\tReserved\n", rsvd3);
	printf("  [2:1] : %#x\t%s\n", ioi, ioi_string[ioi]);
	printf("  [0:0] : %#x\tName space is %sready\n",
		nrdy, nrdy ? "" : "not ");
	printf("\n");
}

static void stdout_cmd_set_independent_id_ns(struct nvme_id_independent_id_ns *ns,
					     unsigned int nsid)
{
	int human = stdout_print_ops.flags & VERBOSE;

	printf("NVME Identify Command Set Independent Namespace %d:\n", nsid);
	printf("nsfeat  : %#x\n", ns->nsfeat);
	if (human)
		stdout_cmd_set_independent_id_ns_nsfeat(ns->nsfeat);
	printf("nmic    : %#x\n", ns->nmic);
	if (human)
		stdout_id_ns_nmic(ns->nmic);
	printf("rescap  : %#x\n", ns->rescap);
	if (human)
		stdout_id_ns_rescap(ns->rescap);
	printf("fpi     : %#x\n", ns->fpi);
	if (human)
		stdout_id_ns_fpi(ns->fpi);
	printf("anagrpid: %u\n", le32_to_cpu(ns->anagrpid));
	printf("nsattr	: %u\n", ns->nsattr);
	if (human)
		stdout_id_ns_nsattr(ns->nsattr);
	printf("nvmsetid: %d\n", le16_to_cpu(ns->nvmsetid));
	printf("endgid  : %d\n", le16_to_cpu(ns->endgid));

	printf("nstat   : %#x\n", ns->nstat);
	if (human)
		stdout_cmd_set_independent_id_ns_nstat(ns->nstat);
	printf("kpios   : %#x\n", ns->kpios);
	if (human)
		stdout_id_ns_kpios(ns->kpios);
	printf("maxkt   : %#x\n", le16_to_cpu(ns->maxkt));
	printf("rgrpid  : %#x\n", le32_to_cpu(ns->rgrpid));
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

	printf("NVME Namespace Identification Descriptors NS %d:\n", nsid);
	for (pos = 0; pos < NVME_IDENTIFY_DATA_SIZE; pos += len) {
		struct nvme_ns_id_desc *cur = data + pos;

		if (cur->nidl == 0)
			break;

		if (verbose) {
			printf("loc     : %d\n", pos);
			printf("nidt    : %d\n", (int)cur->nidt);
			printf("nidl    : %d\n", (int)cur->nidl);
		}

		switch (cur->nidt) {
		case NVME_NIDT_EUI64:
			memcpy(eui64, data + pos + sizeof(*cur), sizeof(eui64));
			if (verbose)
				printf("type    : eui64\n");
			printf("eui64   : ");
			for (i = 0; i < 8; i++)
				printf("%02x", eui64[i]);
			printf("\n");
			len = sizeof(eui64);
			break;
		case NVME_NIDT_NGUID:
			memcpy(nguid, data + pos + sizeof(*cur), sizeof(nguid));
			if (verbose)
				printf("type    : nguid\n");
			printf("nguid   : ");
			for (i = 0; i < 16; i++)
				printf("%02x", nguid[i]);
			printf("\n");
			len = sizeof(nguid);
			break;
		case NVME_NIDT_UUID:
			memcpy(uuid, data + pos + sizeof(*cur), 16);
			nvme_uuid_to_string(uuid, uuid_str);
			if (verbose)
				printf("type    : uuid\n");
			printf("uuid    : %s\n", uuid_str);
			len = sizeof(uuid);
			break;
		case NVME_NIDT_CSI:
			memcpy(&csi, data + pos + sizeof(*cur), 1);
			if (verbose)
				printf("type    : csi\n");
			printf("csi     : %#x\n", csi);
			len += sizeof(csi);
			break;
		default:
			/* Skip unknown types */
			len = cur->nidl;
			break;
		}

		len += sizeof(*cur);
	}
}

static void print_psd_workload(__u8 apw)
{
	switch (apw & 0x7) {
	case NVME_PSD_WORKLOAD_NP:
		/* Unknown or not provided */
		printf("-");
		break;
	case 1:
		/* Extended idle period with burst of random write */
		printf("1MiB 32 RW, 30s idle");
		break;
	case 2:
		/* Heavy sequential writes */
		printf("80K 128KiB SW");
		break;
	default:
		printf("reserved");
		break;
	}
}

static void print_ps_power_and_scale(__le16 ctr_power, __u8 scale)
{
	__u16 power = le16_to_cpu(ctr_power);

	switch (scale & 0x3) {
	case NVME_PSD_PS_NOT_REPORTED:
		/* Not reported for this power state */
		printf("-");
		break;
	case NVME_PSD_PS_100_MICRO_WATT:
		/* Units of 0.0001W */
		printf("%01u.%04uW", power / 10000, power % 10000);
		break;
	case NVME_PSD_PS_10_MILLI_WATT:
		/* Units of 0.01W */
		printf("%01u.%02uW", power / 100, power % 100);
		break;
	default:
		printf("reserved");
		break;
	}
}

static void print_psd_time(const char *desc, __u8 time, __u8 ts)
{
	int width = 12 + strlen(desc);
	char value[STR_LEN] = { 0 };

	switch (time) {
	case 0:
		snprintf(value, sizeof(value), "-");
		break;
	case 1 ... 99:
		snprintf(value, sizeof(value), "%d (unit: %s)", time,
			 nvme_time_scale_to_string(ts));
		break;
	default:
		snprintf(value, sizeof(value), "reserved");
		break;
	}

	printf("%*s: %s\n", width, desc, value);
}

static void stdout_id_ctrl_power(struct nvme_id_ctrl *ctrl)
{
	int i;

	for (i = 0; i <= ctrl->npss; i++) {
		__u16 max_power = le16_to_cpu(ctrl->psd[i].mp);

		printf("ps   %4d : mp:", i);

		if (ctrl->psd[i].flags & NVME_PSD_FLAGS_MXPS)
			printf("%01u.%04uW ", max_power / 10000, max_power % 10000);
		else
			printf("%01u.%02uW ", max_power / 100, max_power % 100);

		if (ctrl->psd[i].flags & NVME_PSD_FLAGS_NOPS)
			printf("non-");

		printf("operational enlat:%d exlat:%d rrt:%d rrl:%d\n"
			"            rwt:%d rwl:%d idle_power:",
			le32_to_cpu(ctrl->psd[i].enlat),
			le32_to_cpu(ctrl->psd[i].exlat),
			ctrl->psd[i].rrt, ctrl->psd[i].rrl,
			ctrl->psd[i].rwt, ctrl->psd[i].rwl);
		print_ps_power_and_scale(ctrl->psd[i].idlp,
				 nvme_psd_power_scale(ctrl->psd[i].ips));
		printf(" active_power:");
		print_ps_power_and_scale(ctrl->psd[i].actp,
				 nvme_psd_power_scale(ctrl->psd[i].apws));
		printf("\n            active_power_workload:");
		print_psd_workload(ctrl->psd[i].apws);
		printf("\n");
		print_psd_time("emergency power fail recovery time", ctrl->psd[i].epfrt,
			       ctrl->psd[i].epfr_fqv_ts & 0xf);
		print_psd_time("forced quiescence vault time", ctrl->psd[i].fqvt,
			       ctrl->psd[i].epfr_fqv_ts >> 4);
		print_psd_time("emergency power fail vault time", ctrl->psd[i].epfvt,
			       ctrl->psd[i].epfvts & 0xf);
	}
}

static void stdout_id_ctrl(struct nvme_id_ctrl *ctrl,
			   void (*vendor_show)(__u8 *vs, struct json_object *root))
{
	bool human = stdout_print_ops.flags & VERBOSE, vs = stdout_print_ops.flags & VS;

	printf("NVME Identify Controller:\n");
	printf("vid       : %#x\n", le16_to_cpu(ctrl->vid));
	printf("ssvid     : %#x\n", le16_to_cpu(ctrl->ssvid));
	printf("sn        : %-.*s\n", (int)sizeof(ctrl->sn), ctrl->sn);
	printf("mn        : %-.*s\n", (int)sizeof(ctrl->mn), ctrl->mn);
	printf("fr        : %-.*s\n", (int)sizeof(ctrl->fr), ctrl->fr);
	printf("rab       : %d\n", ctrl->rab);
	printf("ieee      : %02x%02x%02x\n",
		ctrl->ieee[2], ctrl->ieee[1], ctrl->ieee[0]);
	printf("cmic      : %#x\n", ctrl->cmic);
	if (human)
		stdout_id_ctrl_cmic(ctrl->cmic);
	printf("mdts      : %d\n", ctrl->mdts);
	printf("cntlid    : %#x\n", le16_to_cpu(ctrl->cntlid));
	printf("ver       : %#x\n", le32_to_cpu(ctrl->ver));
	printf("rtd3r     : %#x\n", le32_to_cpu(ctrl->rtd3r));
	printf("rtd3e     : %#x\n", le32_to_cpu(ctrl->rtd3e));
	printf("oaes      : %#x\n", le32_to_cpu(ctrl->oaes));
	if (human)
		stdout_id_ctrl_oaes(ctrl->oaes);
	printf("ctratt    : %#x\n", le32_to_cpu(ctrl->ctratt));
	if (human)
		stdout_id_ctrl_ctratt(ctrl->ctratt);
	printf("rrls      : %#x\n", le16_to_cpu(ctrl->rrls));
	printf("bpcap     : %#x\n", le16_to_cpu(ctrl->bpcap));
	if (human)
		stdout_id_ctrl_bpcap(ctrl->bpcap);
	printf("nssl      : %#x\n", le32_to_cpu(ctrl->nssl));
	printf("plsi      : %u\n", ctrl->plsi);
	if (human)
		stdout_id_ctrl_plsi(ctrl->plsi);
	printf("cntrltype : %d\n", ctrl->cntrltype);
	if (human)
		stdout_id_ctrl_cntrltype(ctrl->cntrltype);
	printf("fguid     : %s\n", util_uuid_to_string(ctrl->fguid));
	printf("crdt1     : %u\n", le16_to_cpu(ctrl->crdt1));
	printf("crdt2     : %u\n", le16_to_cpu(ctrl->crdt2));
	printf("crdt3     : %u\n", le16_to_cpu(ctrl->crdt3));
	printf("crcap     : %u\n", ctrl->crcap);
	if (human)
		stdout_id_ctrl_crcap(ctrl->crcap);
	printf("nvmsr     : %u\n", ctrl->nvmsr);
	if (human)
		stdout_id_ctrl_nvmsr(ctrl->nvmsr);
	printf("vwci      : %u\n", ctrl->vwci);
	if (human)
		stdout_id_ctrl_vwci(ctrl->vwci);
	printf("mec       : %u\n", ctrl->mec);
	if (human)
		stdout_id_ctrl_mec(ctrl->mec);

	printf("oacs      : %#x\n", le16_to_cpu(ctrl->oacs));
	if (human)
		stdout_id_ctrl_oacs(ctrl->oacs);
	printf("acl       : %d\n", ctrl->acl);
	printf("aerl      : %d\n", ctrl->aerl);
	printf("frmw      : %#x\n", ctrl->frmw);
	if (human)
		stdout_id_ctrl_frmw(ctrl->frmw);
	printf("lpa       : %#x\n", ctrl->lpa);
	if (human)
		stdout_id_ctrl_lpa(ctrl->lpa);
	printf("elpe      : %d\n", ctrl->elpe);
	if (human)
		stdout_id_ctrl_elpe(ctrl->elpe);
	printf("npss      : %d\n", ctrl->npss);
	if (human)
		stdout_id_ctrl_npss(ctrl->npss);
	printf("avscc     : %#x\n", ctrl->avscc);
	if (human)
		stdout_id_ctrl_avscc(ctrl->avscc);
	printf("apsta     : %#x\n", ctrl->apsta);
	if (human)
		stdout_id_ctrl_apsta(ctrl->apsta);
	printf("wctemp    : %d\n", le16_to_cpu(ctrl->wctemp));
	if (human)
		stdout_id_ctrl_wctemp(ctrl->wctemp);
	printf("cctemp    : %d\n", le16_to_cpu(ctrl->cctemp));
	if (human)
		stdout_id_ctrl_cctemp(ctrl->cctemp);
	printf("mtfa      : %d\n", le16_to_cpu(ctrl->mtfa));
	printf("hmpre     : %u\n", le32_to_cpu(ctrl->hmpre));
	printf("hmmin     : %u\n", le32_to_cpu(ctrl->hmmin));
	printf("tnvmcap   : %s\n",
		uint128_t_to_l10n_string(le128_to_cpu(ctrl->tnvmcap)));
	if (human)
		stdout_id_ctrl_tnvmcap(ctrl->tnvmcap);
	printf("unvmcap   : %s\n",
		uint128_t_to_l10n_string(le128_to_cpu(ctrl->unvmcap)));
	if (human)
		stdout_id_ctrl_unvmcap(ctrl->unvmcap);
	printf("rpmbs     : %#x\n", le32_to_cpu(ctrl->rpmbs));
	if (human)
		stdout_id_ctrl_rpmbs(ctrl->rpmbs);
	printf("edstt     : %d\n", le16_to_cpu(ctrl->edstt));
	printf("dsto      : %d\n", ctrl->dsto);
	if (human)
		stdout_id_ctrl_dsto(ctrl->dsto);
	printf("fwug      : %d\n", ctrl->fwug);
	printf("kas       : %d\n", le16_to_cpu(ctrl->kas));
	printf("hctma     : %#x\n", le16_to_cpu(ctrl->hctma));
	if (human)
		stdout_id_ctrl_hctma(ctrl->hctma);
	printf("mntmt     : %d\n", le16_to_cpu(ctrl->mntmt));
	if (human)
		stdout_id_ctrl_mntmt(ctrl->mntmt);
	printf("mxtmt     : %d\n", le16_to_cpu(ctrl->mxtmt));
	if (human)
		stdout_id_ctrl_mxtmt(ctrl->mxtmt);
	printf("sanicap   : %#x\n", le32_to_cpu(ctrl->sanicap));
	if (human)
		stdout_id_ctrl_sanicap(ctrl->sanicap);
	printf("hmminds   : %u\n", le32_to_cpu(ctrl->hmminds));
	printf("hmmaxd    : %d\n", le16_to_cpu(ctrl->hmmaxd));
	printf("nsetidmax : %d\n", le16_to_cpu(ctrl->nsetidmax));
	printf("endgidmax : %d\n", le16_to_cpu(ctrl->endgidmax));
	printf("anatt     : %d\n", ctrl->anatt);
	printf("anacap    : %d\n", ctrl->anacap);
	if (human)
		stdout_id_ctrl_anacap(ctrl->anacap);
	printf("anagrpmax : %u\n", ctrl->anagrpmax);
	printf("nanagrpid : %u\n", le32_to_cpu(ctrl->nanagrpid));
	printf("pels      : %u\n", le32_to_cpu(ctrl->pels));
	printf("domainid  : %d\n", le16_to_cpu(ctrl->domainid));
	printf("kpioc     : %u\n", ctrl->kpioc);
	if (human)
		stdout_id_ctrl_kpioc(ctrl->kpioc);
	printf("mptfawr   : %d\n", le16_to_cpu(ctrl->mptfawr));
	printf("megcap    : %s\n",
		uint128_t_to_l10n_string(le128_to_cpu(ctrl->megcap)));
	printf("tmpthha   : %#x\n", ctrl->tmpthha);
	if (human)
		stdout_id_ctrl_tmpthha(ctrl->tmpthha);
	printf("cqt       : %d\n", le16_to_cpu(ctrl->cqt));
	printf("sqes      : %#x\n", ctrl->sqes);
	if (human)
		stdout_id_ctrl_sqes(ctrl->sqes);
	printf("cqes      : %#x\n", ctrl->cqes);
	if (human)
		stdout_id_ctrl_cqes(ctrl->cqes);
	printf("maxcmd    : %d\n", le16_to_cpu(ctrl->maxcmd));
	printf("nn        : %u\n", le32_to_cpu(ctrl->nn));
	printf("oncs      : %#x\n", le16_to_cpu(ctrl->oncs));
	if (human)
		stdout_id_ctrl_oncs(ctrl->oncs);
	printf("fuses     : %#x\n", le16_to_cpu(ctrl->fuses));
	if (human)
		stdout_id_ctrl_fuses(ctrl->fuses);
	printf("fna       : %#x\n", ctrl->fna);
	if (human)
		stdout_id_ctrl_fna(ctrl->fna);
	printf("vwc       : %#x\n", ctrl->vwc);
	if (human)
		stdout_id_ctrl_vwc(ctrl->vwc);
	printf("awun      : %d\n", le16_to_cpu(ctrl->awun));
	printf("awupf     : %d\n", le16_to_cpu(ctrl->awupf));
	printf("icsvscc   : %d\n", ctrl->icsvscc);
	if (human)
		stdout_id_ctrl_icsvscc(ctrl->icsvscc);
	printf("nwpc      : %d\n", ctrl->nwpc);
	if (human)
		stdout_id_ctrl_nwpc(ctrl->nwpc);
	printf("acwu      : %d\n", le16_to_cpu(ctrl->acwu));
	printf("ocfs      : %#x\n", le16_to_cpu(ctrl->ocfs));
	if (human)
		stdout_id_ctrl_ocfs(ctrl->ocfs);
	printf("sgls      : %#x\n", le32_to_cpu(ctrl->sgls));
	if (human)
		stdout_id_ctrl_sgls(ctrl->sgls);
	printf("mnan      : %u\n", le32_to_cpu(ctrl->mnan));
	printf("maxdna    : %s\n",
		uint128_t_to_l10n_string(le128_to_cpu(ctrl->maxdna)));
	printf("maxcna    : %u\n", le32_to_cpu(ctrl->maxcna));
	printf("oaqd      : %u\n", le32_to_cpu(ctrl->oaqd));
	printf("rhiri     : %d\n", ctrl->rhiri);
	printf("hirt      : %d\n", ctrl->hirt);
	printf("cmmrtd    : %d\n", le16_to_cpu(ctrl->cmmrtd));
	printf("nmmrtd    : %d\n", le16_to_cpu(ctrl->nmmrtd));
	printf("minmrtg   : %d\n", ctrl->minmrtg);
	printf("maxmrtg   : %d\n", ctrl->maxmrtg);
	printf("trattr    : %d\n", ctrl->trattr);
	if (human)
		stdout_id_ctrl_trattr(ctrl->trattr);
	printf("mcudmq    : %d\n", le16_to_cpu(ctrl->mcudmq));
	printf("mnsudmq   : %d\n", le16_to_cpu(ctrl->mnsudmq));
	printf("mcmr      : %d\n", le16_to_cpu(ctrl->mcmr));
	printf("nmcmr     : %d\n", le16_to_cpu(ctrl->nmcmr));
	printf("mcdqpc    : %d\n", le16_to_cpu(ctrl->mcdqpc));
	printf("subnqn    : %-.*s\n", (int)sizeof(ctrl->subnqn), ctrl->subnqn);
	printf("ioccsz    : %u\n", le32_to_cpu(ctrl->ioccsz));
	printf("iorcsz    : %u\n", le32_to_cpu(ctrl->iorcsz));
	printf("icdoff    : %d\n", le16_to_cpu(ctrl->icdoff));
	printf("fcatt     : %#x\n", ctrl->fcatt);
	if (human)
		stdout_id_ctrl_fcatt(ctrl->fcatt);
	printf("msdbd     : %d\n", ctrl->msdbd);
	printf("ofcs      : %d\n", le16_to_cpu(ctrl->ofcs));
	if (human)
		stdout_id_ctrl_ofcs(ctrl->ofcs);

	stdout_id_ctrl_power(ctrl);
	if (vendor_show)
		vendor_show(ctrl->vs, NULL);
	else if (vs) {
		printf("vs[]:\n");
		d(ctrl->vs, sizeof(ctrl->vs), 16, 1);
	}
}

static void stdout_id_ctrl_nvm_kpiocap(__u8 kpiocap)
{
	__u8 rsvd2 = (kpiocap & 0xfc) >> 2;
	__u8 kpiosc = (kpiocap & 0x2) >> 1;
	__u8 kpios = kpiocap & 0x1;

	if (rsvd2)
		printf("  [7:2] : %#x\tReserved\n", rsvd2);
	printf("  [1:1] : %#x\tKey Per I/O capability enabled and disabled %s in the"
		"NVM subsystem\n", kpiosc, kpiosc ? "all namespaces" : "each namespace");
	printf("  [0:0] : %#x\tKey Per I/O capability %sSupported\n", kpios,
		kpios ? "" : "Not ");
}

static void stdout_id_ctrl_nvm_aocs(__u16 aocs)
{
	__u16 rsvd = (aocs & 0xfffe) >> 1;
	__u8 ralbas = aocs & 0x1;

	if (rsvd)
		printf("  [15:1] : %#x\tReserved\n", rsvd);
	printf("  [0:0] : %#x\tReporting Allocated LBA %sSupported\n", ralbas,
		ralbas ? "" : "Not ");
	printf("\n");
}

static void stdout_id_ctrl_nvm_ver(__u32 ver)
{
	printf("  NVM command set specification: %d.%d.%d\n\n", NVME_MAJOR(ver), NVME_MINOR(ver),
	       NVME_TERTIARY(ver));
}

static void stdout_id_ctrl_nvm_lbamqf(__u8 lbamqf)
{
	printf("  0x%x: ", lbamqf);

	switch (lbamqf) {
	case NVME_ID_CTRL_NVM_LBAMQF_TYPE_0:
		printf("LBA Migration Queue Entry Type 0\n\n");
		break;
	case NVME_ID_CTRL_NVM_LBAMQF_VENDOR_MIN ... NVME_ID_CTRL_NVM_LBAMQF_VENDOR_MAX:
		printf("Vendor Specific\n\n");
		break;
	default:
		printf("Reserved\n\n");
		break;
	}
}

static void stdout_id_ctrl_nvm(struct nvme_id_ctrl_nvm *ctrl_nvm)
{
	int verbose = stdout_print_ops.flags & VERBOSE;

	printf("NVMe Identify Controller NVM:\n");
	printf("vsl    : %u\n", ctrl_nvm->vsl);
	printf("wzsl   : %u\n", ctrl_nvm->wzsl);
	printf("wusl   : %u\n", ctrl_nvm->wusl);
	printf("dmrl   : %u\n", ctrl_nvm->dmrl);
	printf("dmrsl  : %u\n", le32_to_cpu(ctrl_nvm->dmrsl));
	printf("dmsl   : %"PRIu64"\n", le64_to_cpu(ctrl_nvm->dmsl));
	printf("kpiocap: %u\n", ctrl_nvm->kpiocap);
	if (verbose)
		stdout_id_ctrl_nvm_kpiocap(ctrl_nvm->kpiocap);
	printf("wzdsl  : %u\n", ctrl_nvm->wzdsl);
	printf("aocs   : %u\n", le16_to_cpu(ctrl_nvm->aocs));
	if (verbose)
		stdout_id_ctrl_nvm_aocs(le16_to_cpu(ctrl_nvm->aocs));
	printf("ver    : 0x%x\n", le32_to_cpu(ctrl_nvm->ver));
	if (verbose)
		stdout_id_ctrl_nvm_ver(le32_to_cpu(ctrl_nvm->ver));
	printf("lbamqf : %u\n", ctrl_nvm->lbamqf);
	if (verbose)
		stdout_id_ctrl_nvm_lbamqf(ctrl_nvm->lbamqf);
}

static void stdout_nvm_id_ns_pic(__u8 pic)
{
	__u8 rsvd = (pic & 0xF0) >> 4;
	__u8 qpifs = (pic & 0x8) >> 3;
	__u8 stcrs = (pic & 0x4) >> 2;
	__u8 pic_16bpistm = (pic & 0x2) >> 1;
	__u8 pic_16bpists = pic & 0x1;

	if (rsvd)
		printf("  [7:4] : %#x\tReserved\n", rsvd);
	printf("  [3:3] : %#x\tQualified Protection Information Format %sSupported\n",
		qpifs, qpifs ? "" : "Not ");
	printf("  [2:2] : %#x\tStorage Tag Check Read %sSupported\n",
		stcrs, stcrs ? "" : "Not ");
	printf("  [1:1] : %#x\t16b Guard Protection Information Storage Tag Mask\n",
		pic_16bpistm);
	printf("  [0:0] : %#x\t16b Guard Protection Information Storage Tag %sSupported\n",
		pic_16bpists, pic_16bpists ? "" : "Not ");
	printf("\n");
}

static void stdout_nvm_id_ns_pifa(__u8 pifa)
{
	__u8 rsvd = (pifa & 0xF8) >> 3;
	__u8 stmla = pifa & 0x7;

	if (rsvd)
		printf("  [7:3] : %#x\tReserved\n", rsvd);
	printf("  [2:0] : %#x\tStorage Tag Masking Level Attribute : %s\n", stmla,
		stmla == 0 ? "Bit Granularity Masking" :
		stmla == 1 ? "Byte Granularity Masking" :
		stmla == 2 ? "Masking Not Supported" : "Reserved");
	printf("\n");
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
	int i, verbose = stdout_print_ops.flags & VERBOSE;
	bool qpifs = (nvm_ns->pic & 0x8) >> 3;
	__u32 elbaf;
	__u8 lbaf;
	int pif, sts, qpif;
	char *in_use = "(in use)";

	nvme_id_ns_flbas_to_lbaf_inuse(ns->flbas, &lbaf);

	if (!cap_only) {
		printf("NVMe NVM Identify Namespace %d:\n", nsid);
		printf("lbstm : %#"PRIx64"\n", le64_to_cpu(nvm_ns->lbstm));
	} else {
		printf("NVMe NVM Identify Namespace for LBA format[%d]:\n", lba_index);
		in_use = "";
	}
	printf("pic   : %#x\n", nvm_ns->pic);
	if (verbose)
		stdout_nvm_id_ns_pic(nvm_ns->pic);
	printf("pifa  : %#x\n", nvm_ns->pifa);
	if (verbose)
		stdout_nvm_id_ns_pifa(nvm_ns->pifa);

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
	if (ns->nsfeat & 0x20)
		printf("npdgl : %#x\n", le32_to_cpu(nvm_ns->npdgl));

	printf("nprg  : %#x\n", le32_to_cpu(nvm_ns->nprg));
	printf("npra  : %#x\n", le32_to_cpu(nvm_ns->npra));
	printf("nors  : %#x\n", le32_to_cpu(nvm_ns->nors));
	printf("npdal : %#x\n", le32_to_cpu(nvm_ns->npdal));
	printf("lbapss: %#x\n", le32_to_cpu(nvm_ns->lbapss));
	printf("tlbaag: %#x\n", le32_to_cpu(nvm_ns->tlbaag));
}

static void stdout_zns_id_ctrl(struct nvme_zns_id_ctrl *ctrl)
{
	printf("NVMe ZNS Identify Controller:\n");
	printf("zasl    : %u\n", ctrl->zasl);
}

static void show_nvme_id_ns_zoned_zoc(__le16 ns_zoc)
{
	__u16 zoc = le16_to_cpu(ns_zoc);
	__u8 rsvd = (zoc & 0xfffc) >> 2;
	__u8 ze = (zoc & 0x2) >> 1;
	__u8 vzc = zoc & 0x1;

	if (rsvd)
		printf(" [15:2] : %#x\tReserved\n", rsvd);
	printf("  [1:1] : %#x\t  Zone Active Excursions: %s\n",
		ze, ze ? "Yes (Host support required)" : "No");
	printf("  [0:0] : %#x\t  Variable Zone Capacity: %s\n",
		vzc, vzc ? "Yes (Host support required)" : "No");
	printf("\n");
}

static void show_nvme_id_ns_zoned_ozcs(__le16 ns_ozcs)
{
	__u16 ozcs = le16_to_cpu(ns_ozcs);
	__u8 rsvd = (ozcs & 0xfffc) >> 2;
	__u8 razb = ozcs & 0x1;
	__u8 zrwasup = (ozcs & 0x2) >> 1;

	if (rsvd)
		printf(" [15:1] : %#x\tReserved\n", rsvd);
	printf("  [0:0] : %#x\t  Read Across Zone Boundaries: %s\n",
		razb, razb ? "Yes" : "No");
	printf("  [1:1] : %#x\t  Zone Random Write Area: %s\n", zrwasup,
				zrwasup ? "Yes" : "No");
}

static void stdout_zns_id_ns_recommended_limit(__le32 ns_rl, int human,
					       const char *target_limit)
{
	unsigned int recommended_limit = le32_to_cpu(ns_rl);

	if (!recommended_limit && human)
		printf("%s    : Not Reported\n", target_limit);
	else
		printf("%s    : %u\n", target_limit, recommended_limit);
}

static void stdout_zns_id_ns_zrwacap(__u8 zrwacap)
{
	__u8 rsvd = (zrwacap & 0xfe) >> 1;
	__u8 expflushsup = zrwacap & 0x1;

	if (rsvd)
		printf(" [7:1] : %#x\tReserved\n", rsvd);
	printf("  [0:0] : %#x\t  Explicit ZRWA Flush Operations: %s\n",
		expflushsup, expflushsup ? "Yes" : "No");
}

static void stdout_zns_id_ns(struct nvme_zns_id_ns *ns,
			     struct nvme_id_ns *id_ns)
{
	int human = stdout_print_ops.flags & VERBOSE, vs = stdout_print_ops.flags & VS;
	uint8_t lbaf;
	int i;

	nvme_id_ns_flbas_to_lbaf_inuse(id_ns->flbas, &lbaf);

	printf("ZNS Command Set Identify Namespace:\n");

	if (human) {
		printf("zoc     : %u\tZone Operation Characteristics\n", le16_to_cpu(ns->zoc));
		show_nvme_id_ns_zoned_zoc(ns->zoc);
	} else {
		printf("zoc     : %u\n", le16_to_cpu(ns->zoc));
	}

	if (human) {
		printf("ozcs    : %u\tOptional Zoned Command Support\n", le16_to_cpu(ns->ozcs));
		show_nvme_id_ns_zoned_ozcs(ns->ozcs);
	} else {
		printf("ozcs    : %u\n", le16_to_cpu(ns->ozcs));
	}

	if (human) {
		if (ns->mar == 0xffffffff)
			printf("mar     : No Active Resource Limit\n");
		else
			printf("mar     : %u\tActive Resources\n", le32_to_cpu(ns->mar) + 1);
	} else {
		printf("mar     : %#x\n", le32_to_cpu(ns->mar));
	}

	if (human) {
		if (ns->mor == 0xffffffff)
			printf("mor     : No Open Resource Limit\n");
		else
			printf("mor     : %u\tOpen Resources\n", le32_to_cpu(ns->mor) + 1);
	} else {
		printf("mor     : %#x\n", le32_to_cpu(ns->mor));
	}

	stdout_zns_id_ns_recommended_limit(ns->rrl,  human, "rrl ");
	stdout_zns_id_ns_recommended_limit(ns->frl,  human, "frl ");
	stdout_zns_id_ns_recommended_limit(ns->rrl1, human, "rrl1");
	stdout_zns_id_ns_recommended_limit(ns->rrl2, human, "rrl2");
	stdout_zns_id_ns_recommended_limit(ns->rrl3, human, "rrl3");
	stdout_zns_id_ns_recommended_limit(ns->frl1,  human, "frl1");
	stdout_zns_id_ns_recommended_limit(ns->frl2,  human, "frl2");
	stdout_zns_id_ns_recommended_limit(ns->frl3,  human, "frl3");

	printf("numzrwa : %#x\n", le32_to_cpu(ns->numzrwa));
	printf("zrwafg  : %u\n", le16_to_cpu(ns->zrwafg));
	printf("zrwasz  : %u\n", le16_to_cpu(ns->zrwasz));
	if (human) {
		printf("zrwacap : %u\tZone Random Write Area Capability\n", ns->zrwacap);
		stdout_zns_id_ns_zrwacap(ns->zrwacap);
	} else {
		printf("zrwacap : %u\n", ns->zrwacap);
	}

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
	for (i = 0; i < 1024; i++) {
		if (ns_list->ns[i]) {
			if (verbose)
				printf("Identifier %4u: NSID %#x\n",
						i, le32_to_cpu(ns_list->ns[i]));
			else
				printf("[%4u]:%#x\n",
						i, le32_to_cpu(ns_list->ns[i]));
		}
	}
}

static void stdout_zns_start_zone_list(__u64 nr_zones, struct json_object **zone_list)
{
	printf("nr_zones: %"PRIu64"\n", (uint64_t)le64_to_cpu(nr_zones));
}

static void stdout_zns_changed(struct nvme_zns_changed_zone_log *log)
{
	uint16_t nrzid;
	int i;

	nrzid = le16_to_cpu(log->nrzid);
	printf("NVMe Changed Zone List:\n");

	if (nrzid == 0xFFFF) {
		printf("Too many zones have changed to fit into the log. Use report zones for changes.\n");
		return;
	}

	printf("nrzid:  %u\n", nrzid);
	for (i = 0; i < nrzid; i++)
		printf("zid %03d: %"PRIu64"\n", i, (uint64_t)le64_to_cpu(log->zid[i]));
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
	__u16 num = le16_to_cpu(ctrl_list->num);
	int i;

	printf("num of ctrls present: %u\n", num);
	for (i = 0; i < min(num, 2047); i++)
		printf("[%4u]:%#x\n", i, le16_to_cpu(ctrl_list->identifier[i]));
}

static void stdout_id_nvmset(struct nvme_id_nvmset_list *nvmset,
			     unsigned int nvmset_id)
{
	int i;

	printf("NVME Identify NVM Set List %d:\n", nvmset_id);
	printf("nid     : %d\n", nvmset->nid);
	printf(".................\n");
	for (i = 0; i < nvmset->nid; i++) {
		printf(" NVM Set Attribute Entry[%2d]\n", i);
		printf(".................\n");
		printf("nvmset_id               : %d\n",
			le16_to_cpu(nvmset->ent[i].endgid));
		printf("endurance_group_id      : %d\n",
			le16_to_cpu(nvmset->ent[i].endgid));
		printf("random_4k_read_typical  : %u\n",
			le32_to_cpu(nvmset->ent[i].rr4kt));
		printf("optimal_write_size      : %u\n",
			le32_to_cpu(nvmset->ent[i].ows));
		printf("total_nvmset_cap        : %s\n",
			uint128_t_to_l10n_string(
				le128_to_cpu(nvmset->ent[i].tnvmsetcap)));
		printf("unalloc_nvmset_cap      : %s\n",
			uint128_t_to_l10n_string(
				le128_to_cpu(nvmset->ent[i].unvmsetcap)));
		printf(".................\n");
	}
}

static void stdout_primary_ctrl_caps_crt(__u8 crt)
{
	__u8 rsvd = (crt & 0xFC) >> 2;
	__u8 vi = (crt & 0x2) >> 1;
	__u8 vq = crt & 0x1;

	if (rsvd)
		printf("  [7:2] : %#x\tReserved\n", rsvd);
	printf("  [1:1] %#x\tVI Resources are %ssupported\n", vi, vi ? "" : "not ");
	printf("  [0:0] %#x\tVQ Resources are %ssupported\n", vq, vq ? "" : "not ");
}

static void stdout_primary_ctrl_cap(const struct nvme_primary_ctrl_cap *caps)
{
	int human = stdout_print_ops.flags & VERBOSE;

	printf("NVME Identify Primary Controller Capabilities:\n");
	printf("cntlid    : %#x\n", le16_to_cpu(caps->cntlid));
	printf("portid    : %#x\n", le16_to_cpu(caps->portid));
	printf("crt       : %#x\n", caps->crt);
	if (human)
		stdout_primary_ctrl_caps_crt(caps->crt);
	printf("vqfrt     : %u\n", le32_to_cpu(caps->vqfrt));
	printf("vqrfa     : %u\n", le32_to_cpu(caps->vqrfa));
	printf("vqrfap    : %d\n", le16_to_cpu(caps->vqrfap));
	printf("vqprt     : %d\n", le16_to_cpu(caps->vqprt));
	printf("vqfrsm    : %d\n", le16_to_cpu(caps->vqfrsm));
	printf("vqgran    : %d\n", le16_to_cpu(caps->vqgran));
	printf("vifrt     : %u\n", le32_to_cpu(caps->vifrt));
	printf("virfa     : %u\n", le32_to_cpu(caps->virfa));
	printf("virfap    : %d\n", le16_to_cpu(caps->virfap));
	printf("viprt     : %d\n", le16_to_cpu(caps->viprt));
	printf("vifrsm    : %d\n", le16_to_cpu(caps->vifrsm));
	printf("vigran    : %d\n", le16_to_cpu(caps->vigran));
}

static void stdout_list_secondary_ctrl(const struct nvme_secondary_ctrl_list *sc_list,
				       __u32 count)
{
	const struct nvme_secondary_ctrl *sc_entry =
		&sc_list->sc_entry[0];
	static const char * const state_desc[] = { "Offline", "Online" };

	__u16 num = sc_list->num;
	__u32 entries = min(num, count);
	int i;

	printf("Identify Secondary Controller List:\n");
	printf("   NUMID       : Number of Identifiers           : %d\n", num);

	for (i = 0; i < entries; i++) {
		printf("   SCEntry[%-3d]:\n", i);
		printf("................\n");
		printf("     SCID      : Secondary Controller Identifier : %#.04x\n",
				le16_to_cpu(sc_entry[i].scid));
		printf("     PCID      : Primary Controller Identifier   : %#.04x\n",
				le16_to_cpu(sc_entry[i].pcid));
		printf("     SCS       : Secondary Controller State      : %#.04x (%s)\n",
				sc_entry[i].scs,
				state_desc[sc_entry[i].scs & 0x1]);
		printf("     VFN       : Virtual Function Number         : %#.04x\n",
				le16_to_cpu(sc_entry[i].vfn));
		printf("     NVQ       : Num VQ Flex Resources Assigned  : %#.04x\n",
				le16_to_cpu(sc_entry[i].nvq));
		printf("     NVI       : Num VI Flex Resources Assigned  : %#.04x\n",
				le16_to_cpu(sc_entry[i].nvi));
	}
}

static void stdout_id_ns_granularity_list(const struct nvme_id_ns_granularity_list *glist)
{
	int i;

	printf("Identify Namespace Granularity List:\n");
	printf("   ATTR        : Namespace Granularity Attributes: %#x\n",
		glist->attributes);
	printf("   NUMD        : Number of Descriptors           : %d\n",
		glist->num_descriptors);

	/* Number of Descriptors is a 0's based value */
	for (i = 0; i <= glist->num_descriptors; i++) {
		printf("\n     Entry[%2d] :\n", i);
		printf("................\n");
		printf("     NSG       : Namespace Size Granularity     : %#"PRIx64"\n",
			le64_to_cpu(glist->entry[i].nszegran));
		printf("     NCG       : Namespace Capacity Granularity : %#"PRIx64"\n",
			le64_to_cpu(glist->entry[i].ncapgran));
	}
}

static void stdout_id_uuid_list(const struct nvme_id_uuid_list *uuid_list)
{
	int i, human = stdout_print_ops.flags & VERBOSE;

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
		printf(" Entry[%3d]\n", i+1);
		printf(".................\n");
		printf("association  : %#x %s\n", identifier_association, association);
		printf("UUID         : %s", util_uuid_to_string(uuid));
		if (memcmp(uuid_list->entry[i].uuid, invalid_uuid,
			   sizeof(zero_uuid)) == 0)
			printf(" (Invalid UUID)");
		printf("\n.................\n");
	}
}

static void stdout_id_domain_list(struct nvme_id_domain_list *id_dom)
{
	int i;

	printf("Number of Domain Entries: %u\n", id_dom->num);
	for (i = 0; i < id_dom->num; i++) {
		printf("Domain Id for Attr Entry[%u]: %u\n", i,
			le16_to_cpu(id_dom->domain_attr[i].dom_id));
		printf("Domain Capacity for Attr Entry[%u]: %s\n", i,
			uint128_t_to_l10n_string(
				le128_to_cpu(id_dom->domain_attr[i].dom_cap)));
		printf("Unallocated Domain Capacity for Attr Entry[%u]: %s\n", i,
			uint128_t_to_l10n_string(
				le128_to_cpu(id_dom->domain_attr[i].unalloc_dom_cap)));
		printf("Max Endurance Group Domain Capacity for Attr Entry[%u]: %s\n", i,
			uint128_t_to_l10n_string(
				le128_to_cpu(id_dom->domain_attr[i].max_egrp_dom_cap)));
	}
}

static void stdout_endurance_group_list(struct nvme_id_endurance_group_list *endgrp_list)
{
	int i;
	__u16 num = le16_to_cpu(endgrp_list->num);

	printf("num of endurance group ids: %u\n", num);
	for (i = 0; i < min(num, 2047); i++)
		printf("[%4u]:%#x\n", i, le16_to_cpu(endgrp_list->identifier[i]));
}

static void stdout_id_iocs_iocsc(__u64 iocsc)
{
	__u8 cpncs = NVME_GET(iocsc, IOCS_IOCSC_CPNCS);
	__u8 slmcs = NVME_GET(iocsc, IOCS_IOCSC_SLMCS);
	__u8 znscs = NVME_GET(iocsc, IOCS_IOCSC_ZNSCS);
	__u8 kvcs = NVME_GET(iocsc, IOCS_IOCSC_KVCS);
	__u8 nvmcs = NVME_GET(iocsc, IOCS_IOCSC_NVMCS);

	printf("  [4:4] : %#x\tComputational Programs Namespace Command Set %sSelected\n",
		cpncs, cpncs ? "" : "Not ");
	printf("  [3:3] : %#x\tSubsystem Local Memory Command Set %sSelected\n", slmcs,
		slmcs ? "" : "Not ");
	printf("  [2:2] : %#x\tZoned Namespace Command Set %sSelected\n", znscs,
		znscs ? "" : "Not ");
	printf("  [1:1] : %#x\tKey Value Command Set %sSelected\n", kvcs, kvcs ? "" : "Not ");
	printf("  [0:0] : %#x\tNVM Command Set %sSelected\n", nvmcs, nvmcs ? "" : "Not ");
	printf("\n");
}

static void stdout_id_iocs(struct nvme_id_iocs *iocs)
{
	bool human = stdout_print_ops.flags & VERBOSE;
	__u16 i;

	for (i = 0; i < ARRAY_SIZE(iocs->iocsc); i++) {
		if (iocs->iocsc[i]) {
			printf("I/O Command Set Combination[%u]:%"PRIx64"\n", i,
				(uint64_t)le64_to_cpu(iocs->iocsc[i]));
			if (human)
				stdout_id_iocs_iocsc(le64_to_cpu(iocs->iocsc[i]));
		}
	}
}

static void stdout_error_log(struct nvme_error_log_page *err_log, int entries,
			     const char *devname)
{
	int i;

	printf("Error Log Entries for device:%s entries:%d\n", devname,
								entries);
	printf(".................\n");
	for (i = 0; i < entries; i++) {
		__u16 status = le16_to_cpu(err_log[i].status_field) >> 0x1;

		printf(" Entry[%2d]\n", i);
		printf(".................\n");
		printf("error_count	: %"PRIu64"\n",
			le64_to_cpu(err_log[i].error_count));
		printf("sqid		: %d\n", err_log[i].sqid);
		printf("cmdid		: %#x\n", err_log[i].cmdid);
		printf("status_field	: %#x (%s)\n", status,
			nvme_status_to_string(status, false));
		printf("phase_tag	: %#x\n", le16_to_cpu(err_log[i].status_field) & 0x1);
		printf("parm_err_loc	: %#x\n",
			err_log[i].parm_error_location);
		printf("lba		: %#"PRIx64"\n",
			le64_to_cpu(err_log[i].lba));
		printf("nsid		: %#x\n", err_log[i].nsid);
		printf("vs		: %d\n", err_log[i].vs);
		printf("trtype		: %#x (%s)\n", err_log[i].trtype,
			nvme_trtype_to_string(err_log[i].trtype));
		printf("csi		: %d\n", err_log[i].csi);
		printf("opcode		: %#x\n", err_log[i].opcode);
		printf("cs		: %#"PRIx64"\n",
		       le64_to_cpu(err_log[i].cs));
		printf("trtype_spec_info: %#x\n", err_log[i].trtype_spec_info);
		printf("log_page_version: %d\n", err_log[i].log_page_version);
		printf(".................\n");
	}
}

static void stdout_resv_report(struct nvme_resv_status *status, int bytes,
			       bool eds)
{
	int i, j, regctl, entries;

	regctl = status->regctl[0] | (status->regctl[1] << 8);

	printf("\nNVME Reservation status:\n\n");
	printf("gen       : %u\n", le32_to_cpu(status->gen));
	printf("rtype     : %d\n", status->rtype);
	printf("regctl    : %d\n", regctl);
	printf("ptpls     : %d\n", status->ptpls);

	/* check Extended Data Structure bit */
	if (!eds) {
		/*
		 * if status buffer was too small, don't loop past the end of
		 * the buffer
		 */
		entries = (bytes - 24) / 24;
		if (entries < regctl)
			regctl = entries;

		for (i = 0; i < regctl; i++) {
			printf("regctl[%d] :\n", i);
			printf("  cntlid  : %x\n",
				le16_to_cpu(status->regctl_ds[i].cntlid));
			printf("  rcsts   : %x\n",
				status->regctl_ds[i].rcsts);
			printf("  hostid  : %"PRIx64"\n",
				le64_to_cpu(status->regctl_ds[i].hostid));
			printf("  rkey    : %"PRIx64"\n",
				le64_to_cpu(status->regctl_ds[i].rkey));
		}
	} else {
		/* if status buffer was too small, don't loop past the end of the buffer */
		entries = (bytes - 64) / 64;
		if (entries < regctl)
			regctl = entries;

		for (i = 0; i < regctl; i++) {
			printf("regctlext[%d] :\n", i);
			printf("  cntlid     : %x\n",
				le16_to_cpu(status->regctl_eds[i].cntlid));
			printf("  rcsts      : %x\n",
				status->regctl_eds[i].rcsts);
			printf("  rkey       : %"PRIx64"\n",
				le64_to_cpu(status->regctl_eds[i].rkey));
			printf("  hostid     : ");
			for (j = 0; j < 16; j++)
				printf("%02x",
					status->regctl_eds[i].hostid[j]);
			printf("\n");
		}
	}
	printf("\n");
}

static void stdout_fw_log(struct nvme_firmware_slot *fw_log,
			  const char *devname)
{
	int i;
	__le64 *frs;

	printf("Firmware Log for device:%s\n", devname);
	printf("afi  : %#x\n", fw_log->afi);
	for (i = 0; i < 7; i++) {
		if (fw_log->frs[i][0]) {
			frs = (__le64 *)&fw_log->frs[i];
			printf("frs%d : %#016"PRIx64" (%s)\n", i + 1,
				le64_to_cpu(*frs),
				util_fw_to_string(fw_log->frs[i]));
		}
	}
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

static void stdout_effects_log_human(FILE *stream, __u32 effect)
{
	const char *set = "+";
	const char *clr = "-";

	fprintf(stream, "  CSUPP+");
	fprintf(stream, "  LBCC%s", (effect & NVME_CMD_EFFECTS_LBCC) ? set : clr);
	fprintf(stream, "  NCC%s", (effect & NVME_CMD_EFFECTS_NCC) ? set : clr);
	fprintf(stream, "  NIC%s", (effect & NVME_CMD_EFFECTS_NIC) ? set : clr);
	fprintf(stream, "  CCC%s", (effect & NVME_CMD_EFFECTS_CCC) ? set : clr);
	fprintf(stream, "  USS%s", (effect & NVME_CMD_EFFECTS_UUID_SEL) ? set : clr);

	if ((effect & NVME_CMD_EFFECTS_CSER_MASK) >> 14 == 0)
		fprintf(stream, "  No CSER defined\n");
	else if ((effect & NVME_CMD_EFFECTS_CSER_MASK) >> 14 == 1)
		fprintf(stream, "  No admin command for any namespace\n");
	else
		fprintf(stream, "  Reserved CSER\n");

	if ((effect & NVME_CMD_EFFECTS_CSE_MASK) >> 16 == 0)
		fprintf(stream, "  No command restriction\n");
	else if ((effect & NVME_CMD_EFFECTS_CSE_MASK) >> 16 == 1)
		fprintf(stream, "  No other command for same namespace\n");
	else if ((effect & NVME_CMD_EFFECTS_CSE_MASK) >> 16 == 2)
		fprintf(stream, "  No other command for any namespace\n");
	else
		fprintf(stream, "  Reserved CSE\n");
}

static void stdout_effects_entry(FILE *stream, int admin, int index,
				 __le32 entry, unsigned int human)
{
	__u32 effect;
	char *format_string;

	format_string = admin ? "ACS%-6d[%-32s] %08x" : "IOCS%-5d[%-32s] %08x";

	effect = le32_to_cpu(entry);
	if (effect & NVME_CMD_EFFECTS_CSUPP) {
		fprintf(stream, format_string, index, nvme_cmd_to_string(admin, index),
		       effect);
		if (human)
			stdout_effects_log_human(stream, effect);
		else
			fprintf(stream, "\n");
	}
}

static void stdout_effects_log_segment(int admin, int a, int b,
				       struct nvme_cmd_effects_log *effects,
				       char *header, int human)
{
	FILE *stream;
	char *stream_location;
	size_t stream_size;

	stream = open_memstream(&stream_location, &stream_size);
	if (!stream) {
		perror("Failed to open stream");
		return;
	}

	for (int i = a; i < b; i++) {
		if (admin)
			stdout_effects_entry(stream, admin, i, effects->acs[i], human);
		else
			stdout_effects_entry(stream, admin, i, effects->iocs[i], human);
	}

	fclose(stream);

	if (stream_size && header) {
		printf("%s\n", header);
		fwrite(stream_location, stream_size, 1, stdout);
		printf("\n");
	}

	free(stream_location);
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

static void stdout_support_log_human(__u32 support, __u8 lid)
{
	const char *set = "supported";
	const char *clr = "not supported";
	__u16 lidsp = support >> 16;

	printf("  LSUPP is %s\n", (support & 0x1) ? set : clr);
	printf("  IOS is %s\n", ((support >> 0x1) & 0x1) ? set : clr);

	switch (lid) {
	case NVME_LOG_LID_TELEMETRY_HOST:
		printf("  Maximum Created Data Area is %s\n",
			(lidsp & 0x1) ? set : clr);
		break;
	case NVME_LOG_LID_PERSISTENT_EVENT:
		printf("  Establish Context and Read 512 Bytes of Header is %s\n",
			(lidsp & 0x1) ? set : clr);
		break;
	case NVME_LOG_LID_DISCOVER:
		printf("  Extended Discovery Log Page Entry is %s\n",
			(lidsp & 0x1) ? set : clr);
		printf("  Port Local Entries Only is %s\n",
			(lidsp & 0x2) ? set : clr);
		printf("  All NVM Subsystem Entries is %s\n",
			(lidsp & 0x4) ? set : clr);
		break;
	case NVME_LOG_LID_HOST_DISCOVER:
		printf("  All Host Entries is %s\n",
			(lidsp & 0x1) ? set : clr);
		break;
	default:
		break;
	}
}

static void stdout_supported_log(struct nvme_supported_log_pages *support_log,
				 const char *devname)
{
	int lid, human = stdout_print_ops.flags & VERBOSE;
	__u32 support = 0;

	printf("Support Log Pages Details for %s:\n", devname);
	for (lid = 0; lid < 256; lid++) {
		support = le32_to_cpu(support_log->lid_support[lid]);
		if (support & 0x1) {
			printf("LID %#x - %s\n", lid, nvme_log_to_string(lid));
			if (human)
				stdout_support_log_human(support, lid);
		}
	}
}

static void stdout_endurance_log(struct nvme_endurance_group_log *endurance_log, __u16 group_id,
				 const char *devname)
{
	printf("Endurance Group Log for NVME device:%s Group ID:%x\n", devname, group_id);
	printf("critical_warning	: %u\n", endurance_log->critical_warning);
	printf("endurance_group_features: %u\n", endurance_log->endurance_group_features);
	printf("avl_spare		: %u\n", endurance_log->avl_spare);
	printf("avl_spare_threshold	: %u\n", endurance_log->avl_spare_threshold);
	printf("percent_used		: %u%%\n", endurance_log->percent_used);
	printf("domain_identifier	: %u\n", endurance_log->domain_identifier);
	printf("endurance_estimate	: %s\n",
	       uint128_t_to_l10n_string(le128_to_cpu(endurance_log->endurance_estimate)));
	printf("data_units_read		: %s\n",
	       uint128_t_to_l10n_string(le128_to_cpu(endurance_log->data_units_read)));
	printf("data_units_written	: %s\n",
	       uint128_t_to_l10n_string(le128_to_cpu(endurance_log->data_units_written)));
	printf("media_units_written	: %s\n",
	       uint128_t_to_l10n_string(le128_to_cpu(endurance_log->media_units_written)));
	printf("host_read_cmds		: %s\n",
	       uint128_t_to_l10n_string(le128_to_cpu(endurance_log->host_read_cmds)));
	printf("host_write_cmds		: %s\n",
	       uint128_t_to_l10n_string(le128_to_cpu(endurance_log->host_write_cmds)));
	printf("media_data_integrity_err: %s\n",
	       uint128_t_to_l10n_string(le128_to_cpu(endurance_log->media_data_integrity_err)));
	printf("num_err_info_log_entries: %s\n",
	       uint128_t_to_l10n_string(le128_to_cpu(endurance_log->num_err_info_log_entries)));
	printf("total_end_grp_cap	: %s\n",
	       uint128_t_to_l10n_string(le128_to_cpu(endurance_log->total_end_grp_cap)));
	printf("unalloc_end_grp_cap	: %s\n",
	       uint128_t_to_l10n_string(le128_to_cpu(endurance_log->unalloc_end_grp_cap)));
}

static void stdout_smart_log(struct nvme_smart_log *smart, unsigned int nsid, const char *devname)
{
	__u16 temperature = smart->temperature[1] << 8 | smart->temperature[0];
	int i;
	bool human = stdout_print_ops.flags & VERBOSE;

	printf("Smart Log for NVME device:%s namespace-id:%x\n", devname, nsid);
	printf("critical_warning			: %#x\n", smart->critical_warning);

	if (human) {
		printf("      Available Spare[0]             : %d\n",
		       smart->critical_warning & 0x01);
		printf("      Temp. Threshold[1]             : %d\n",
		       (smart->critical_warning & 0x02) >> 1);
		printf("      NVM subsystem Reliability[2]   : %d\n",
		       (smart->critical_warning & 0x04) >> 2);
		printf("      Read-only[3]                   : %d\n",
		       (smart->critical_warning & 0x08) >> 3);
		printf("      Volatile mem. backup failed[4] : %d\n",
		       (smart->critical_warning & 0x10) >> 4);
		printf("      Persistent Mem. RO[5]          : %d\n",
		       (smart->critical_warning & 0x20) >> 5);
	}

	printf("temperature				: %s (%u K)\n",
	       nvme_degrees_string(temperature), temperature);
	printf("available_spare				: %u%%\n", smart->avail_spare);
	printf("available_spare_threshold		: %u%%\n", smart->spare_thresh);
	printf("percentage_used				: %u%%\n", smart->percent_used);
	printf("endurance group critical warning summary: %#x\n", smart->endu_grp_crit_warn_sumry);
	printf("Data Units Read				: %s (%s)\n",
	       uint128_t_to_l10n_string(le128_to_cpu(smart->data_units_read)),
	       uint128_t_to_si_string(le128_to_cpu(smart->data_units_read), 1000 * 512));
	printf("Data Units Written			: %s (%s)\n",
	       uint128_t_to_l10n_string(le128_to_cpu(smart->data_units_written)),
	       uint128_t_to_si_string(le128_to_cpu(smart->data_units_written), 1000 * 512));
	printf("host_read_commands			: %s\n",
	       uint128_t_to_l10n_string(le128_to_cpu(smart->host_reads)));
	printf("host_write_commands			: %s\n",
	       uint128_t_to_l10n_string(le128_to_cpu(smart->host_writes)));
	printf("controller_busy_time			: %s\n",
	       uint128_t_to_l10n_string(le128_to_cpu(smart->ctrl_busy_time)));
	printf("power_cycles				: %s\n",
	       uint128_t_to_l10n_string(le128_to_cpu(smart->power_cycles)));
	printf("power_on_hours				: %s\n",
	       uint128_t_to_l10n_string(le128_to_cpu(smart->power_on_hours)));
	printf("unsafe_shutdowns			: %s\n",
	       uint128_t_to_l10n_string(le128_to_cpu(smart->unsafe_shutdowns)));
	printf("media_errors				: %s\n",
	       uint128_t_to_l10n_string(le128_to_cpu(smart->media_errors)));
	printf("num_err_log_entries			: %s\n",
	       uint128_t_to_l10n_string(le128_to_cpu(smart->num_err_log_entries)));
	printf("Warning Temperature Time		: %u\n",
	       le32_to_cpu(smart->warning_temp_time));
	printf("Critical Composite Temperature Time	: %u\n",
	       le32_to_cpu(smart->critical_comp_time));

	for (i = 0; i < ARRAY_SIZE(smart->temp_sensor); i++) {
		temperature = le16_to_cpu(smart->temp_sensor[i]);
		if (!temperature)
			continue;
		printf("Temperature Sensor %d			: %s (%u K)\n", i + 1,
		       nvme_degrees_string(temperature), temperature);
	}

	printf("Thermal Management T1 Trans Count	: %u\n",
	       le32_to_cpu(smart->thm_temp1_trans_count));
	printf("Thermal Management T2 Trans Count	: %u\n",
	       le32_to_cpu(smart->thm_temp2_trans_count));
	printf("Thermal Management T1 Total Time	: %u\n",
	       le32_to_cpu(smart->thm_temp1_total_time));
	printf("Thermal Management T2 Total Time	: %u\n",
	       le32_to_cpu(smart->thm_temp2_total_time));
}

static void stdout_ana_log(struct nvme_ana_log *ana_log, const char *devname,
			   size_t len)
{
	int offset = sizeof(struct nvme_ana_log);
	struct nvme_ana_log *hdr = ana_log;
	struct nvme_ana_group_desc *desc;
	size_t nsid_buf_size;
	void *base = ana_log;
	__u32 nr_nsids;
	int i, j;

	printf("Asymmetric Namespace Access Log for NVMe device: %s\n",
			devname);
	printf("ANA LOG HEADER :-\n");
	printf("chgcnt	:	%"PRIu64"\n",
			le64_to_cpu(hdr->chgcnt));
	printf("ngrps	:	%u\n", le16_to_cpu(hdr->ngrps));
	printf("ANA Log Desc :-\n");

	for (i = 0; i < le16_to_cpu(ana_log->ngrps); i++) {
		desc = base + offset;
		nr_nsids = le32_to_cpu(desc->nnsids);
		nsid_buf_size = nr_nsids * sizeof(__le32);

		offset += sizeof(*desc);
		printf("grpid	:	%u\n", le32_to_cpu(desc->grpid));
		printf("nnsids	:	%u\n", le32_to_cpu(desc->nnsids));
		printf("chgcnt	:	%"PRIu64"\n",
		       le64_to_cpu(desc->chgcnt));
		printf("state	:	%s\n",
				nvme_ana_state_to_string(desc->state));
		for (j = 0; j < le32_to_cpu(desc->nnsids); j++)
			printf("	nsid	:	%u\n",
					le32_to_cpu(desc->nsids[j]));
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
	__u8 op, code;

	op = res->dsts & NVME_ST_RESULT_MASK;
	printf("  Operation Result             : %#x", op);
	if (stdout_print_ops.flags & VERBOSE)
		printf(" %s", (op < ARRAY_SIZE(test_res) && test_res[op]) ?
			test_res[op] : test_res[ARRAY_SIZE(test_res) - 1]);
	printf("\n");
	if (op == NVME_ST_RESULT_NOT_USED)
		return;

	code = res->dsts >> NVME_ST_CODE_SHIFT;
	printf("  Self Test Code               : %x", code);

	if (stdout_print_ops.flags & VERBOSE) {
		switch (code) {
		case NVME_ST_CODE_SHORT:
			printf(" Short device self-test operation");
			break;
		case NVME_ST_CODE_EXTENDED:
			printf(" Extended device self-test operation");
			break;
		case NVME_ST_CODE_HOST_INIT:
			printf(" Host-Initiated Refresh operation");
			break;
		case NVME_ST_CODE_VS:
			printf(" Vendor specific");
			break;
		default:
			printf(" Reserved");
			break;
		}
	}
	printf("\n");

	if (op == NVME_ST_RESULT_KNOWN_SEG_FAIL)
		printf("  Segment Number               : %#x\n", res->seg);

	printf("  Valid Diagnostic Information : %#x\n", res->vdi);
	printf("  Power on hours (POH)         : %#"PRIx64"\n",
		(uint64_t)le64_to_cpu(res->poh));

	if (res->vdi & NVME_ST_VALID_DIAG_INFO_NSID)
		printf("  Namespace Identifier         : %#x\n",
			le32_to_cpu(res->nsid));
	if (res->vdi & NVME_ST_VALID_DIAG_INFO_FLBA)
		printf("  Failing LBA                  : %#"PRIx64"\n",
			(uint64_t)le64_to_cpu(res->flba));
	if (res->vdi & NVME_ST_VALID_DIAG_INFO_SCT)
		printf("  Status Code Type             : %#x\n", res->sct);
	if (res->vdi & NVME_ST_VALID_DIAG_INFO_SC) {
		printf("  Status Code                  : %#x", res->sc);
		if (stdout_print_ops.flags & VERBOSE)
			printf(" %s", nvme_status_to_string(
				(res->sct & 7) << 8 | res->sc, false));
		printf("\n");
	}
	printf("  Vendor Specific              : %#x %#x\n",
		res->vs[0], res->vs[1]);
}

static void stdout_self_test_log(struct nvme_self_test_log *self_test,
				 __u8 dst_entries, __u32 size,
				 const char *devname)
{
	int i;
	__u8 num_entries;

	printf("Device Self Test Log for NVME device:%s\n", devname);
	printf("Current operation  : %#x\n", self_test->current_operation);
	printf("Current Completion : %u%%\n", self_test->completion);
	num_entries = min(dst_entries, NVME_LOG_ST_MAX_RESULTS);
	for (i = 0; i < num_entries; i++) {
		printf("Self Test Result[%d]:\n", i);
		stdout_self_test_result(&self_test->result[i]);
	}
}

static void stdout_sanitize_log_sprog(__u32 sprog)
{
	double percent;

	percent = (((double)sprog * 100) / 0x10000);
	printf("\t(%f%%)\n", percent);
}

static void stdout_sanitize_log_sstat(__u16 status)
{
	const char *str = nvme_sstat_status_to_string(status);
	__u16 gde, mvcncld;

	printf("  [2:0] : Sanitize Operation Status  : %#x\t%s\n",
		NVME_GET(status, SANITIZE_SSTAT_STATUS), str);
	printf("  [7:3] : Overwrite Passes Completed : %u\n",
		NVME_GET(status, SANITIZE_SSTAT_COMPLETED_PASSES));

	gde = NVME_GET(status, SANITIZE_SSTAT_GLOBAL_DATA_ERASED);
	if (gde)
		str = "No user data has been written in the NVM subsystem and"\
		       " no PMR has been enabled in the NVM subsystem";
	else
		str = "User data has been written in the NVM subsystem or"\
		       " PMR has been enabled in the NVM subsystem";
	printf("  [8:8] : Global Data Erased         : %#x\t%s\n", gde, str);

	mvcncld = NVME_GET(status, SANITIZE_SSTAT_MVCNCLD);
	printf("  [9:9] : Media Verification Canceled: %#x\t%scanceled\n",
		mvcncld, mvcncld ? "" : "Not ");
	printf("\n");
}

static void stdout_estimate_sanitize_time(const char *text, uint32_t value)
{
	printf("%s:  %u%s\n", text, value,
		value == 0xffffffff ? " (No time period reported)" : "");
}

static void stdout_sanitize_log_ssi(__u8 ssi, __u16 status)
{
	__u8 sans, fails;
	const char *str;

	sans = NVME_GET(ssi, SANITIZE_SSI_SANS);
	str = nvme_ssi_state_to_string(sans);
	printf("  [3:0] : Sanitize State : %#x\t%s\n", sans, str);

	if (status == NVME_SANITIZE_SSTAT_STATUS_COMPLETED_FAILED) {
		fails = NVME_GET(ssi, SANITIZE_SSI_FAILS);
		str = nvme_ssi_state_to_string(fails);
		printf("  [7:4] : Failure State  : %#x\t%s\n", fails, str);
	}
	printf("\n");
}

static void stdout_sanitize_log(struct nvme_sanitize_log_page *sanitize,
				const char *devname)
{
	int human = stdout_print_ops.flags & VERBOSE;
	__u16 status = le16_to_cpu(sanitize->sstat) & NVME_SANITIZE_SSTAT_STATUS_MASK;

	printf("Sanitize Progress                      (SPROG) :  %u",
	       le16_to_cpu(sanitize->sprog));

	if (human && status == NVME_SANITIZE_SSTAT_STATUS_IN_PROGESS)
		stdout_sanitize_log_sprog(le16_to_cpu(sanitize->sprog));
	else
		printf("\n");

	printf("Sanitize Status                        (SSTAT) :  %#x\n",
		le16_to_cpu(sanitize->sstat));
	if (human)
		stdout_sanitize_log_sstat(le16_to_cpu(sanitize->sstat));

	printf("Sanitize Command Dword 10 Information (SCDW10) :  %#x\n",
		le32_to_cpu(sanitize->scdw10));
	stdout_estimate_sanitize_time("Estimated Time For Overwrite                   ",
		le32_to_cpu(sanitize->eto));
	stdout_estimate_sanitize_time("Estimated Time For Block Erase                 ",
		le32_to_cpu(sanitize->etbe));
	stdout_estimate_sanitize_time("Estimated Time For Crypto Erase                ",
		le32_to_cpu(sanitize->etce));
	stdout_estimate_sanitize_time("Estimated Time For Overwrite (No-Deallocate)   ",
		le32_to_cpu(sanitize->etond));
	stdout_estimate_sanitize_time("Estimated Time For Block Erase (No-Deallocate) ",
		le32_to_cpu(sanitize->etbend));
	stdout_estimate_sanitize_time("Estimated Time For Crypto Erase (No-Deallocate)",
		le32_to_cpu(sanitize->etcend));
	stdout_estimate_sanitize_time("Estimated Time For Post-Verification Deallocation",
		le32_to_cpu(sanitize->etpvds));

	printf("Sanitize State Information               (SSI) : %#x\n", sanitize->ssi);
	if (human)
		stdout_sanitize_log_ssi(sanitize->ssi, status);
}

static void stdout_select_result(enum nvme_features_id fid, __u32 result)
{
	if (result & 0x1)
		printf("  Feature is saveable\n");
	if (result & 0x2)
		printf("  Feature is per-namespace\n");
	if (result & 0x4)
		printf("  Feature is changeable\n");
}

static void stdout_lba_range(struct nvme_lba_range_type *lbrt, int nr_ranges)
{
	int i, j;

	for (i = 0; i <= nr_ranges; i++) {
		printf("\ttype       : %#x - %s\n", lbrt->entry[i].type,
			nvme_feature_lba_type_to_string(lbrt->entry[i].type));
		printf("\tattributes : %#x - %s, %s\n", lbrt->entry[i].attributes,
			(lbrt->entry[i].attributes & 0x0001) ?
				"LBA range may be overwritten" :
				"LBA range should not be overwritten",
			((lbrt->entry[i].attributes & 0x0002) >> 1) ?
				"LBA range should be hidden from the OS/EFI/BIOS" :
				"LBA range should be visible from the OS/EFI/BIOS");
		printf("\tslba       : %#"PRIx64"\n", le64_to_cpu(lbrt->entry[i].slba));
		printf("\tnlb        : %#"PRIx64"\n", le64_to_cpu(lbrt->entry[i].nlb));
		printf("\tguid       : ");
		for (j = 0; j < ARRAY_SIZE(lbrt->entry[i].guid); j++)
			printf("%02x", lbrt->entry[i].guid[j]);
		printf("\n");
	}
}

static void stdout_auto_pst(struct nvme_feat_auto_pst *apst)
{
	int i;
	__u64 value;

	printf("\tAuto PST Entries");
	printf("\t.................\n");
	for (i = 0; i < ARRAY_SIZE(apst->apst_entry); i++) {
		value = le64_to_cpu(apst->apst_entry[i]);

		printf("\tEntry[%2d]\n", i);
		printf("\t.................\n");
		printf("\tIdle Time Prior to Transition (ITPT): %u ms\n",
		       (__u32)NVME_GET(value, APST_ENTRY_ITPT));
		printf("\tIdle Transition Power State   (ITPS): %u\n",
		       (__u32)NVME_GET(value, APST_ENTRY_ITPS));
		printf("\t.................\n");
	}
}

static void stdout_timestamp(struct nvme_timestamp *ts)
{
	struct tm *tm;
	char buffer[320];
	time_t timestamp = int48_to_long(ts->timestamp) / 1000;

	tm = localtime(&timestamp);

	printf("\tThe timestamp is : %'"PRIu64" (%s)\n",
		int48_to_long(ts->timestamp),
		strftime(buffer, sizeof(buffer), "%c %Z", tm) ? buffer : "-");
	printf("\t%s\n", (ts->attr & 2) ?
		"The Timestamp field was initialized with a "\
			"Timestamp value using a Set Features command." :
		"The Timestamp field was initialized "\
			"to ‘0’ by a Controller Level Reset.");
	printf("\t%s\n", (ts->attr & 1) ?
		"The controller may have stopped counting during vendor specific "\
			"intervals after the Timestamp value was initialized" :
		"The controller counted time in milliseconds "\
			"continuously since the Timestamp value was initialized.");
}

static void stdout_host_mem_buffer(struct nvme_host_mem_buf_attrs *hmb)
{
	printf("\tHost Memory Descriptor List Entry Count (HMDLEC): %u\n",
		le32_to_cpu(hmb->hmdlec));
	printf("\tHost Memory Descriptor List Address     (HMDLAU): %#x\n",
		le32_to_cpu(hmb->hmdlau));
	printf("\tHost Memory Descriptor List Address     (HMDLAL): %#x\n",
		le32_to_cpu(hmb->hmdlal));
	printf("\tHost Memory Buffer Size                  (HSIZE): %u\n",
		le32_to_cpu(hmb->hsize));
}

static void stdout_directive_show_fields(__u8 dtype, __u8 doper,
					 unsigned int result, unsigned char *buf)
{
	__u8 *field = buf;
	int count, i;

	switch (dtype) {
	case NVME_DIRECTIVE_DTYPE_IDENTIFY:
		switch (doper) {
		case NVME_DIRECTIVE_RECEIVE_IDENTIFY_DOPER_PARAM:
			printf("\tDirective support\n");
			printf("\t\tIdentify Directive       : %s\n",
				(*field & 0x1) ? "supported" : "not supported");
			printf("\t\tStream Directive         : %s\n",
				(*field & 0x2) ? "supported" : "not supported");
			printf("\t\tData Placement Directive : %s\n",
				(*field & 0x4) ? "supported" : "not supported");
			printf("\tDirective enabled\n");
			printf("\t\tIdentify Directive       : %s\n",
				(*(field + 32) & 0x1) ? "enabled" : "disabled");
			printf("\t\tStream Directive         : %s\n",
				(*(field + 32) & 0x2) ? "enabled" : "disabled");
			printf("\t\tData Placement Directive : %s\n",
				(*(field + 32) & 0x4) ? "enabled" : "disabled");
			printf("\tDirective Persistent Across Controller Level Resets\n");
			printf("\t\tIdentify Directive       : %s\n",
				(*(field + 64) & 0x1) ? "enabled" : "disabled");
			printf("\t\tStream Directive         : %s\n",
				(*(field + 64) & 0x2) ? "enabled" : "disabled");
			printf("\t\tData Placement Directive : %s\n",
				(*(field + 64) & 0x4) ? "enabled" : "disabled");
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
			printf("\tMax Streams Limit                          (MSL): %u\n",
				*(__u16 *)field);
			printf("\tNVM Subsystem Streams Available           (NSSA): %u\n",
				*(__u16 *)(field + 2));
			printf("\tNVM Subsystem Streams Open                (NSSO): %u\n",
				*(__u16 *)(field + 4));
			printf("\tNVM Subsystem Stream Capability           (NSSC): %u\n",
				*(__u16 *)(field + 6));
			printf("\tStream Write Size (in unit of LB size)     (SWS): %u\n",
				*(__u32 *)(field + 16));
			printf("\tStream Granularity Size (in unit of SWS)   (SGS): %u\n",
				*(__u16 *)(field + 20));
			printf("\tNamespace Streams Allocated                (NSA): %u\n",
				*(__u16 *)(field + 22));
			printf("\tNamespace Streams Open                     (NSO): %u\n",
				*(__u16 *)(field + 24));
			break;
		case NVME_DIRECTIVE_RECEIVE_STREAMS_DOPER_STATUS:
			count = *(__u16 *)field;
			printf("\tOpen Stream Count  : %u\n", *(__u16 *)field);
			for (i = 0; i < count; i++)
				printf("\tStream Identifier %.6u : %u\n", i + 1,
					*(__u16 *)(field + ((i + 1) * 2)));
			break;
		case NVME_DIRECTIVE_RECEIVE_STREAMS_DOPER_RESOURCE:
			printf("\tNamespace Streams Allocated (NSA): %u\n",
				result & 0xffff);
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

static void stdout_directive_show(__u8 type, __u8 oper, __u16 spec, __u32 nsid, __u32 result,
				  void *buf, __u32 len)
{
	printf("dir-receive: type:%#x operation:%#x spec:%#x nsid:%#x result:%#x\n",
		type, oper, spec, nsid, result);
	if (stdout_print_ops.flags & VERBOSE)
		stdout_directive_show_fields(type, oper, result, buf);
	else if (buf)
		d(buf, len, 16, 1);
}

static void stdout_lba_status_info(__u32 result)
{
	printf("\tLBA Status Information Poll Interval (LSIPI)  : %u\n",
	       NVME_FEAT_LBAS_LSIPI(result));
	printf("\tLBA Status Information Report Interval (LSIRI): %u\n",
	       NVME_FEAT_LBAS_LSIRI(result));
}

void stdout_d(unsigned char *buf, int len, int width, int group)
{
	int i, offset = 0;
	char ascii[32 + 1] = { 0 };

	assert(width < sizeof(ascii));

	printf("     ");

	for (i = 0; i <= 15; i++)
		printf("%3x", i);

	for (i = 0; i < len; i++) {
		if (!(i % width))
			printf("\n%04x:", offset);
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

	if (strlen(ascii)) {
		unsigned int b = width - (i % width);

		printf(" %*s \"%.*s\"", 2 * b + b / group + (b % group ? 1 : 0), "", width, ascii);
	}

	printf("\n");
}

static void stdout_plm_config(struct nvme_plm_config *plmcfg)
{
	printf("\tEnable Event          :%04x\n", le16_to_cpu(plmcfg->ee));
	printf("\tDTWIN Reads Threshold :%"PRIu64"\n", le64_to_cpu(plmcfg->dtwinrt));
	printf("\tDTWIN Writes Threshold:%"PRIu64"\n", le64_to_cpu(plmcfg->dtwinwt));
	printf("\tDTWIN Time Threshold  :%"PRIu64"\n", le64_to_cpu(plmcfg->dtwintt));
}

static void stdout_feat_perfc_std(struct nvme_std_perf_attr *data)
{
	printf("random 4 kib average read latency (R4KARL): %s (0x%02x)\n",
	       nvme_feature_perfc_r4karl_to_string(data->r4karl), data->r4karl);
}

static void stdout_feat_perfc_id_list(struct nvme_perf_attr_id_list *data)
{
	int i;
	int attri_vs;

	printf("attribute type (ATTRTYP): %s (0x%02x)\n",
	       nvme_feature_perfc_attrtyp_to_string(data->attrtyp), data->attrtyp);
	printf("maximum saveable vendor specific performance attributes (MSVSPA): %d\n",
	       data->msvspa);
	printf("unused saveable vendor specific performance attributes (USVSPA): %d\n",
	       data->usvspa);

	printf("performance attribute identifier list\n");
	for (i = 0; i < ARRAY_SIZE(data->id_list); i++) {
		attri_vs = i + NVME_FEAT_PERFC_ATTRI_VS_MIN;
		printf("performance attribute %02xh identifier (PA%02XHI): %s\n", attri_vs,
		       attri_vs, util_uuid_to_string(data->id_list[i].id));
	}
}

static void stdout_feat_perfc_vs(struct nvme_vs_perf_attr *data)
{
	printf("performance attribute identifier (PAID): %s\n", util_uuid_to_string(data->paid));
	printf("attribute length (ATTRL): %u\n", data->attrl);
	printf("vendor specific (VS):\n");
	d((unsigned char *)data->vs, data->attrl, 16, 1);
}

static void stdout_feat_perfc(enum nvme_features_id fid, unsigned int result,
			      struct nvme_perf_characteristics *data)
{
	__u8 attri;
	bool rvspa;

	nvme_feature_decode_perf_characteristics(result, &attri, &rvspa);

	printf("attribute index (ATTRI): %s (0x%02x)\n", nvme_feature_perfc_attri_to_string(attri),
	       attri);

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

	printf("\tNum Metadata Element Descriptors: %d\n", data->ndesc);
	for (i = 0; i < data->ndesc; i++) {
		len = le16_to_cpu(desc->len);
		strncpy(val, (char *)desc->val, min(sizeof(val) - 1, len));

		printf("\tElement[%-3d]:\n", i);
		printf("\t\tType	    : %#02x (%s)\n", desc->type,
		       nvme_host_metadata_type_to_string(fid, desc->type));
		printf("\t\tRevision : %d\n", desc->rev);
		printf("\t\tLength   : %d\n", len);
		printf("\t\tValue    : %s\n", val);

		desc = (struct nvme_metadata_element_desc *)&desc->val[desc->len];
	}
}

static void stdout_feature_show(enum nvme_features_id fid, int sel, unsigned int result)
{
	printf("get-feature:%#0*x (%s), %s value:%#0*x\n", fid ? 4 : 2, fid,
	       nvme_feature_to_string(fid), nvme_select_to_string(sel), result ? 10 : 8, result);
}

static void stdout_feature_show_fields(enum nvme_features_id fid,
				       unsigned int result,
				       unsigned char *buf)
{
	const char *async = "Send async event";
	const char *no_async = "Do not send async event";
	__u8 field;
	uint64_t ull;

	switch (fid) {
	case NVME_FEAT_FID_ARBITRATION:
		printf("\tHigh Priority Weight   (HPW): %u\n", NVME_FEAT_ARB_HPW(result) + 1);
		printf("\tMedium Priority Weight (MPW): %u\n", NVME_FEAT_ARB_MPW(result) + 1);
		printf("\tLow Priority Weight    (LPW): %u\n", NVME_FEAT_ARB_LPW(result) + 1);
		printf("\tArbitration Burst       (AB): ");
		if (NVME_FEAT_ARB_BURST(result) == NVME_FEAT_ARBITRATION_BURST_MASK)
			printf("No limit\n");
		else
			printf("%u\n", 1 << NVME_FEAT_ARB_BURST(result));
		break;
	case NVME_FEAT_FID_POWER_MGMT:
		field = NVME_FEAT_PM_WH(result);
		printf("\tWorkload Hint (WH): %u - %s\n", field,
		       nvme_feature_wl_hints_to_string(field));
		printf("\tPower State   (PS): %u\n", NVME_FEAT_PM_PS(result));
		break;
	case NVME_FEAT_FID_LBA_RANGE:
		field = NVME_FEAT_LBAR_NR(result);
		printf("\tNumber of LBA Ranges (NUM): %u\n", field + 1);
		if (buf)
			stdout_lba_range((struct nvme_lba_range_type *)buf, field);
		break;
	case NVME_FEAT_FID_TEMP_THRESH:
		field = (result & 0x1c00000) >> 22;
		printf("\tTemperature Threshold Hysteresis(TMPTHH): %s (%u K)\n",
		       nvme_degrees_string(field), field);
		field = NVME_FEAT_TT_THSEL(result);
		printf("\tThreshold Type Select         (THSEL): %u - %s\n", field,
		       nvme_feature_temp_type_to_string(field));
		field = NVME_FEAT_TT_TMPSEL(result);
		printf("\tThreshold Temperature Select (TMPSEL): %u - %s\n",
		       field, nvme_feature_temp_sel_to_string(field));
		printf("\tTemperature Threshold         (TMPTH): %s (%u K)\n",
		       nvme_degrees_string(NVME_FEAT_TT_TMPTH(result)), NVME_FEAT_TT_TMPTH(result));
		break;
	case NVME_FEAT_FID_ERR_RECOVERY:
		printf("\tDeallocated or Unwritten Logical Block Error Enable (DULBE): %s\n",
		       NVME_FEAT_ER_DULBE(result) ? "Enabled" : "Disabled");
		printf("\tTime Limited Error Recovery                          (TLER): %u ms\n",
		       NVME_FEAT_ER_TLER(result) * 100);
		break;
	case NVME_FEAT_FID_VOLATILE_WC:
		printf("\tVolatile Write Cache Enable (WCE): %s\n",
		       NVME_FEAT_VWC_WCE(result) ? "Enabled" : "Disabled");
		break;
	case NVME_FEAT_FID_NUM_QUEUES:
		printf("\tNumber of IO Completion Queues Allocated (NCQA): %u\n",
		       NVME_FEAT_NRQS_NCQR(result) + 1);
		printf("\tNumber of IO Submission Queues Allocated (NSQA): %u\n",
		       NVME_FEAT_NRQS_NSQR(result) + 1);
		break;
	case NVME_FEAT_FID_IRQ_COALESCE:
		printf("\tAggregation Time     (TIME): %u usec\n",
		       NVME_FEAT_IRQC_TIME(result) * 100);
		printf("\tAggregation Threshold (THR): %u\n", NVME_FEAT_IRQC_THR(result) + 1);
		break;
	case NVME_FEAT_FID_IRQ_CONFIG:
		printf("\tCoalescing Disable (CD): %s\n",
		       NVME_FEAT_ICFG_CD(result) ? "True" : "False");
		printf("\tInterrupt Vector   (IV): %u\n", NVME_FEAT_ICFG_IV(result));
		break;
	case NVME_FEAT_FID_WRITE_ATOMIC:
		printf("\tDisable Normal (DN): %s\n", NVME_FEAT_WA_DN(result) ? "True" : "False");
		break;
	case NVME_FEAT_FID_ASYNC_EVENT:
		printf("\tDiscovery Log Page Change Notices                         : %s\n",
			NVME_FEAT_AE_DLPCN(result) ? async : no_async);
		printf("\tHost Discovery Log Page Change Notification               : %s\n",
			NVME_FEAT_AE_HDLPCN(result) ? async : no_async);
		printf("\tAVE Discovery Log Page Change Notification                : %s\n",
			NVME_FEAT_AE_ADLPCN(result) ? async : no_async);
		printf("\tPull Model DDC Request Log Page Change Notification       : %s\n",
			NVME_FEAT_AE_PMDRLPCN(result) ? async : no_async);
		printf("\tZone Descriptor Changed Notices                           : %s\n",
			NVME_FEAT_AE_ZDCN(result) ? async : no_async);
		printf("\tAllocated Namespace Attribute Notices                     : %s\n",
			NVME_FEAT_AE_ANSAN(result) ? async : no_async);
		printf("\tReachability Group                                        : %s\n",
			NVME_FEAT_AE_RGRP0(result) ? async : no_async);
		printf("\tReachability Association                                  : %s\n",
			NVME_FEAT_AE_RASSN(result) ? async : no_async);
		printf("\tTemperature Threshold Hysteresis Recovery                 : %s\n",
			NVME_FEAT_AE_TTHRY(result) ? async : no_async);
		printf("\tNormal NVM Subsystem Shutdown                             : %s\n",
			NVME_FEAT_AE_NNSSHDN(result) ? async : no_async);
		printf("\tEndurance Group Event Aggregate Log Change Notices        : %s\n",
		       NVME_FEAT_AE_EGA(result) ? async : no_async);
		printf("\tLBA Status Information Notices                            : %s\n",
		       NVME_FEAT_AE_LBAS(result) ? async : no_async);
		printf("\tPredictable Latency Event Aggregate Log Change Notices    : %s\n",
		       NVME_FEAT_AE_PLA(result) ? async : no_async);
		printf("\tAsymmetric Namespace Access Change Notices                : %s\n",
		       NVME_FEAT_AE_ANA(result) ? async : no_async);
		printf("\tTelemetry Log Notices                                     : %s\n",
		       NVME_FEAT_AE_TELEM(result) ? async : no_async);
		printf("\tFirmware Activation Notices                               : %s\n",
		       NVME_FEAT_AE_FW(result) ? async : no_async);
		printf("\tNamespace Attribute Notices                               : %s\n",
		       NVME_FEAT_AE_NAN(result) ? async : no_async);
		printf("\tSMART / Health Critical Warnings                          : %s\n",
		       NVME_FEAT_AE_SMART(result) ? async : no_async);
		break;
	case NVME_FEAT_FID_AUTO_PST:
		printf("\tAutonomous Power State Transition Enable (APSTE): %s\n",
		       NVME_FEAT_APST_APSTE(result) ? "Enabled" : "Disabled");
		if (buf)
			stdout_auto_pst((struct nvme_feat_auto_pst *)buf);
		break;
	case NVME_FEAT_FID_HOST_MEM_BUF:
		printf("\tEnable Host Memory (EHM): %s\n",
		       NVME_FEAT_HMEM_EHM(result) ? "Enabled" : "Disabled");
		printf("\tHost Memory Non-operational Access Restriction Enable (HMNARE): %s\n",
		       (result & 0x00000004) ? "True" : "False");
		printf("\tHost Memory Non-operational Access Restricted (HMNAR): %s\n",
		       (result & 0x00000008) ? "True" : "False");
		if (buf)
			stdout_host_mem_buffer((struct nvme_host_mem_buf_attrs *)buf);
		break;
	case NVME_FEAT_FID_TIMESTAMP:
		if (buf)
			stdout_timestamp((struct nvme_timestamp *)buf);
		break;
	case NVME_FEAT_FID_KATO:
		printf("\tKeep Alive Timeout (KATO) in milliseconds: %u\n", result);
		break;
	case NVME_FEAT_FID_HCTM:
		printf("\tThermal Management Temperature 1 (TMT1) : %u K (%s)\n",
		       NVME_FEAT_HCTM_TMT1(result),
		       nvme_degrees_string(NVME_FEAT_HCTM_TMT1(result)));
		printf("\tThermal Management Temperature 2 (TMT2) : %u K (%s)\n",
		       NVME_FEAT_HCTM_TMT2(result),
		       nvme_degrees_string(NVME_FEAT_HCTM_TMT2(result)));
		break;
	case NVME_FEAT_FID_NOPSC:
		printf("\tNon-Operational Power State Permissive Mode Enable (NOPPME): %s\n",
		       NVME_FEAT_NOPS_NOPPME(result) ? "True" : "False");
		break;
	case NVME_FEAT_FID_RRL:
		printf("\tRead Recovery Level (RRL): %u\n", NVME_FEAT_RRL_RRL(result));
		break;
	case NVME_FEAT_FID_PLM_CONFIG:
		printf("\tPredictable Latency Window Enabled: %s\n",
		       NVME_FEAT_PLM_PLME(result) ? "True" : "False");
		if (buf)
			stdout_plm_config((struct nvme_plm_config *)buf);
		break;
	case NVME_FEAT_FID_PLM_WINDOW:
		printf("\tWindow Select: %s", nvme_plm_window_to_string(result));
		break;
	case NVME_FEAT_FID_LBA_STS_INTERVAL:
		stdout_lba_status_info(result);
		break;
	case NVME_FEAT_FID_HOST_BEHAVIOR:
		if (buf) {
			struct nvme_feat_host_behavior *host_behavior =
				(struct nvme_feat_host_behavior *)buf;
			printf("\tAdvanced Command Retry Enable (ACRE): %s\n",
			       host_behavior->acre ? "True" : "False");
			printf("\tExtended Telemetry Data Area 4 Supported (ETDAS): %s\n",
			       host_behavior->etdas ? "True" : "False");
			printf("\tLBA Format Extension Enable (LBAFEE): %s\n",
			       host_behavior->lbafee ? "True" : "False");
			printf("\tHost Dispersed Namespace Support (HDISNS) : %s\n",
			       host_behavior->hdisns ? "Enabled" : "Disabled");
			printf("\tCopy Descriptor Format 2h Enabled (CDF2E) : %s\n",
			       host_behavior->cdfe & (1 << 2) ? "True" : "False");
			printf("\tCopy Descriptor Format 3h Enabled (CDF3E) : %s\n",
			       host_behavior->cdfe & (1 << 3) ? "True" : "False");
			printf("\tCopy Descriptor Format 4h Enabled (CDF4E) : %s\n",
			       host_behavior->cdfe & (1 << 4) ? "True" : "False");
		}
		break;
	case NVME_FEAT_FID_SANITIZE:
		printf("\tNo-Deallocate Response Mode (NODRM) : %u\n", NVME_FEAT_SC_NODRM(result));
		break;
	case NVME_FEAT_FID_ENDURANCE_EVT_CFG:
		printf("\tEndurance Group Identifier (ENDGID): %u\n", NVME_FEAT_EG_ENDGID(result));
		printf("\tEndurance Group Critical Warnings  : %u\n", NVME_FEAT_EG_EGCW(result));
		break;
	case NVME_FEAT_FID_IOCS_PROFILE:
		printf("\tI/O Command Set Profile: %s\n", result & 0x1 ? "True" : "False");
		break;
	case NVME_FEAT_FID_SPINUP_CONTROL:
		printf("\tSpinup control feature Enabled: %s\n", (result & 1) ? "True" : "False");
		break;
	case NVME_FEAT_FID_POWER_LOSS_SIGNAL:
		printf("\tPower Loss Signaling Mode (PLSM): %s\n",
		       nvme_pls_mode_to_string(NVME_GET(result, FEAT_PLS_MODE)));
		break;
	case NVME_FEAT_FID_PERF_CHARACTERISTICS:
		stdout_feat_perfc(fid, result, (struct nvme_perf_characteristics *)buf);
		break;
	case NVME_FEAT_FID_ENH_CTRL_METADATA:
	case NVME_FEAT_FID_CTRL_METADATA:
	case NVME_FEAT_FID_NS_METADATA:
		if (buf)
			stdout_host_metadata(fid, (struct nvme_host_metadata *)buf);
		break;
	case NVME_FEAT_FID_SW_PROGRESS:
		printf("\tPre-boot Software Load Count (PBSLC): %u\n", NVME_FEAT_SPM_PBSLC(result));
		break;
	case NVME_FEAT_FID_HOST_ID:
		if (buf) {
			ull =  buf[7]; ull <<= 8; ull |= buf[6]; ull <<= 8; ull |= buf[5]; ull <<= 8;
			ull |= buf[4]; ull <<= 8; ull |= buf[3]; ull <<= 8; ull |= buf[2]; ull <<= 8;
			ull |= buf[1]; ull <<= 8; ull |= buf[0];
			printf("\tHost Identifier (HOSTID):  %" PRIu64 "\n", ull);
		}
		break;
	case NVME_FEAT_FID_RESV_MASK:
		printf("\tMask Reservation Preempted Notification  (RESPRE): %s\n",
		       NVME_FEAT_RM_RESPRE(result) ? "True" : "False");
		printf("\tMask Reservation Released Notification   (RESREL): %s\n",
		       NVME_FEAT_RM_RESREL(result) ? "True" : "False");
		printf("\tMask Registration Preempted Notification (REGPRE): %s\n",
		       NVME_FEAT_RM_REGPRE(result) ? "True" : "False");
		break;
	case NVME_FEAT_FID_RESV_PERSIST:
		printf("\tPersist Through Power Loss (PTPL): %s\n",
		       NVME_FEAT_RP_PTPL(result) ? "True" : "False");
		break;
	case NVME_FEAT_FID_WRITE_PROTECT:
		printf("\tNamespace Write Protect: %s\n", nvme_ns_wp_cfg_to_string(result));
		break;
	case NVME_FEAT_FID_FDP:
		printf("\tFlexible Direct Placement Enable (FDPE)       : %s\n",
		       (result & 0x1) ? "Yes" : "No");
		printf("\tFlexible Direct Placement Configuration Index : %u\n",
		       (result >> 8) & 0xf);
		break;
	case NVME_FEAT_FID_FDP_EVENTS:
		for (unsigned int i = 0; i < result; i++) {
			struct nvme_fdp_supported_event_desc *d;

			d = &((struct nvme_fdp_supported_event_desc *)buf)[i];

			printf("\t%-53s: %sEnabled\n", nvme_fdp_event_to_string(d->evt),
			       d->evta & 0x1 ? "" : "Not ");
		}
		break;
	case NVME_FEAT_FID_BP_WRITE_PROTECT:
		field = NVME_FEAT_BPWPC_BP1WPS(result);
		printf("\tBoot Partition 1 Write Protection State (BP1WPS): %s\n",
			nvme_bpwps_to_string(field));
		field = NVME_FEAT_BPWPC_BP0WPS(result);
		printf("\tBoot Partition 0 Write Protection State (BP0WPS): %s\n",
			nvme_bpwps_to_string(field));
		break;
	default:
		break;
	}
}

static void stdout_lba_status(struct nvme_lba_status *list,
			      unsigned long len)
{
	int idx;

	printf("Number of LBA Status Descriptors(NLSD): %" PRIu32 "\n",
		le32_to_cpu(list->nlsd));
	printf("Completion Condition(CMPC): %u\n", list->cmpc);

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

	for (idx = 0; idx < list->nlsd; idx++) {
		struct nvme_lba_status_desc *e = &list->descs[idx];

		printf("{ DSLBA: %#016"PRIx64", NLB: %#08x, Status: %#02x }\n",
				le64_to_cpu(e->dslba), le32_to_cpu(e->nlb),
				e->status);
	}
}

static void stdout_dev_full_path(nvme_ns_t n, char *path, size_t len)
{
	struct stat st;

	snprintf(path, len, "%s", nvme_ns_get_name(n));
	if (strncmp(path, "/dev/spdk/", 10) == 0 && stat(path, &st) == 0)
		return;

	snprintf(path, len, "/dev/%s", nvme_ns_get_name(n));
	if (stat(path, &st) == 0)
		return;

	/*
	 * We could start trying to search for it but let's make
	 * it simple and just don't show the path at all.
	 */
	snprintf(path, len, "%s", nvme_ns_get_name(n));
}

static void stdout_generic_full_path(nvme_ns_t n, char *path, size_t len)
{
	int head_instance;
	int instance;
	struct stat st;

	/*
	 * There is no block devices for SPDK, point generic path to existing
	 * chardevice.
	 */
	snprintf(path, len, "%s", nvme_ns_get_name(n));
	if (strncmp(path, "/dev/spdk/", 10) == 0 && stat(path, &st) == 0)
		return;

	if (sscanf(nvme_ns_get_name(n), "nvme%dn%d", &instance, &head_instance) != 2)
		return;

	snprintf(path, len, "/dev/ng%dn%d", instance, head_instance);

	if (stat(path, &st) == 0)
		return;

	/*
	 * We could start trying to search for it but let's make
	 * it simple and just don't show the path at all.
	 */
	snprintf(path, len, "ng%dn%d", instance, head_instance);
}

static void stdout_list_item(nvme_ns_t n)
{
	char usage[128] = { 0 }, format[128] = { 0 };
	char devname[128] = { 0 }; char genname[128] = { 0 };

	long long lba = nvme_ns_get_lba_size(n);
	double nsze = nvme_ns_get_lba_count(n) * lba;
	double nuse = nvme_ns_get_lba_util(n) * lba;

	const char *s_suffix = suffix_si_get(&nsze);
	const char *u_suffix = suffix_si_get(&nuse);
	const char *l_suffix = suffix_binary_get(&lba);

	snprintf(usage, sizeof(usage), "%6.2f %2sB / %6.2f %2sB", nuse,
		u_suffix, nsze, s_suffix);
	snprintf(format, sizeof(format), "%3.0f %2sB + %2d B", (double)lba,
		l_suffix, nvme_ns_get_meta_size(n));

	stdout_dev_full_path(n, devname, sizeof(devname));
	stdout_generic_full_path(n, genname, sizeof(genname));

	printf("%-21s %-21s %-20s %-40s %#-10x %-26s %-16s %-8s\n",
		devname, genname, nvme_ns_get_serial(n),
		nvme_ns_get_model(n), nvme_ns_get_nsid(n), usage, format,
		nvme_ns_get_firmware(n));
}

static bool stdout_simple_ns(const char *name, void *arg)
{
	struct nvme_resources *res = arg;
	nvme_ns_t n;

	n = htable_ns_get(&res->ht_n, name);
	stdout_list_item(n);

	return true;
}

static void stdout_simple_list(nvme_root_t r)
{
	struct nvme_resources res;

	nvme_resources_init(r, &res);

	printf("%-21s %-21s %-20s %-40s %-10s %-26s %-16s %-8s\n",
	       "Node", "Generic", "SN", "Model", "Namespace", "Usage", "Format", "FW Rev");
	printf("%-.21s %-.21s %-.20s %-.40s %-.10s %-.26s %-.16s %-.8s\n",
	       dash, dash, dash, dash, dash, dash, dash, dash);
	strset_iterate(&res.namespaces, stdout_simple_ns, &res);

	nvme_resources_free(&res);
}

static void stdout_ns_details(nvme_ns_t n)
{
	char usage[128] = { 0 }, format[128] = { 0 }, usage_binary[128] = { 0 };
	char devname[128] = { 0 }, genname[128] = { 0 };

	long long lba = nvme_ns_get_lba_size(n);
	double nsze = nvme_ns_get_lba_count(n) * lba;
	double nuse = nvme_ns_get_lba_util(n) * lba;
	double nsze_binary = nsze, nuse_binary = nuse;

	const char *s_suffix = suffix_si_get(&nsze);
	const char *u_suffix = suffix_si_get(&nuse);
	const char *l_suffix = suffix_binary_get(&lba);

	const char *s_suffix_binary, *u_suffix_binary;

	sprintf(usage, "%6.2f %1sB / %6.2f %1sB", nuse, u_suffix, nsze, s_suffix);
	sprintf(format, "%3.0f %2sB + %2d B", (double)lba, l_suffix,
		nvme_ns_get_meta_size(n));

	s_suffix_binary = suffix_dbinary_get(&nsze_binary);
	u_suffix_binary = suffix_dbinary_get(&nuse_binary);
	sprintf(usage_binary, "(%7.2f %2sB / %7.2f %2sB)", nuse_binary, u_suffix_binary,
		nsze_binary, s_suffix_binary);

	nvme_dev_full_path(n, devname, sizeof(devname));
	nvme_generic_full_path(n, genname, sizeof(genname));

	printf("%-17s %-17s %#-10x %-21s %-25s %-16s ", devname,
		genname, nvme_ns_get_nsid(n), usage, usage_binary, format);
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
	nvme_subsystem_t s;
	nvme_ctrl_t c;
	bool first;

	strset_init(&ctrls);
	first = true;
	for (s = htable_subsys_getfirst(&res->ht_s, name, &it);
	     s;
	     s = htable_subsys_getnext(&res->ht_s, name, &it)) {
		if (first) {
			printf("%-16s %-96s ", name, nvme_subsystem_get_nqn(s));
			first = false;
		}

		nvme_subsystem_for_each_ctrl(s, c)
			strset_add(&ctrls, nvme_ctrl_get_name(c));
	}

	first = true;
	strset_iterate(&ctrls, stdout_detailed_name, &first);
	strset_clear(&ctrls);
	printf("\n");

	return true;
}

static bool stdout_detailed_ctrl(const char *name, void *arg)
{
	struct nvme_resources *res = arg;
	struct strset namespaces;
	nvme_ctrl_t c;
	nvme_path_t p;
	nvme_ns_t n;
	bool first;

	c = htable_ctrl_get(&res->ht_c, name);
	assert(c);

	printf("%-8s %-6s %-20s %-40s %-8s %-6s %-14s %-6s %-12s ",
	       nvme_ctrl_get_name(c),
	       nvme_ctrl_get_cntlid(c),
	       nvme_ctrl_get_serial(c),
	       nvme_ctrl_get_model(c),
	       nvme_ctrl_get_firmware(c),
	       nvme_ctrl_get_transport(c),
	       nvme_ctrl_get_address(c),
	       nvme_ctrl_get_phy_slot(c),
	       nvme_subsystem_get_name(nvme_ctrl_get_subsystem(c)));

	strset_init(&namespaces);

	nvme_ctrl_for_each_ns(c, n)
		strset_add(&namespaces, nvme_ns_get_name(n));
	nvme_ctrl_for_each_path(c, p) {
		n = nvme_path_get_ns(p);
		if (!n)
			continue;
		strset_add(&namespaces, nvme_ns_get_name(n));
	}

	first = true;
	strset_iterate(&namespaces, stdout_detailed_name, &first);
	strset_clear(&namespaces);

	printf("\n");

	return true;
}

static bool stdout_detailed_ns(const char *name, void *arg)
{
	struct nvme_resources *res = arg;
	struct htable_ns_iter it;
	struct strset ctrls;
	nvme_ctrl_t c;
	nvme_path_t p;
	nvme_ns_t n;
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

		if (nvme_ns_get_ctrl(n)) {
			printf("%s\n", nvme_ctrl_get_name(nvme_ns_get_ctrl(n)));
			return true;
		}

		nvme_namespace_for_each_path(n, p) {
			c = nvme_path_get_ctrl(p);
			strset_add(&ctrls, nvme_ctrl_get_name(c));
		}
	}

	first = true;
	strset_iterate(&ctrls, stdout_detailed_name, &first);
	strset_clear(&ctrls);

	printf("\n");
	return true;
}

static void stdout_detailed_list(nvme_root_t r)
{
	struct nvme_resources res;

	nvme_resources_init(r, &res);

	printf("%-16s %-96s %-.16s\n", "Subsystem", "Subsystem-NQN", "Controllers");
	printf("%-.16s %-.96s %-.16s\n", dash, dash, dash);
	strset_iterate(&res.subsystems, stdout_detailed_subsys, &res);
	printf("\n");

	printf("%-16s %-5s %-20s %-40s %-8s %-6s %-14s %-6s %-12s %-16s\n", "Device",
		"Cntlid", "SN", "MN", "FR", "TxPort", "Address", "Slot", "Subsystem",
		"Namespaces");
	printf("%-.16s %-.6s %-.20s %-.40s %-.8s %-.6s %-.14s %-.6s %-.12s %-.16s\n",
			dash, dash, dash, dash, dash, dash, dash, dash, dash, dash);
	strset_iterate(&res.ctrls, stdout_detailed_ctrl, &res);
	printf("\n");

	printf("%-17s %-17s %-10s %-49s %-16s %-16s\n", "Device", "Generic",
		"NSID", "Usage", "Format", "Controllers");
	printf("%-.17s %-.17s %-.10s %-.49s %-.16s %-.16s\n", dash, dash, dash,
		dash, dash, dash);
	strset_iterate(&res.namespaces, stdout_detailed_ns, &res);

	nvme_resources_free(&res);
}

static void stdout_list_items(nvme_root_t r)
{
	if (stdout_print_ops.flags & VERBOSE)
		stdout_detailed_list(r);
	else
		stdout_simple_list(r);
}

static bool nvme_is_multipath(nvme_subsystem_t s)
{
	nvme_ns_t n;
	nvme_path_t p;

	nvme_subsystem_for_each_ns(s, n)
		nvme_namespace_for_each_path(n, p)
			return true;

	return false;
}

static void stdout_subsystem_topology_multipath(nvme_subsystem_t s,
						     enum nvme_cli_topo_ranking ranking)
{
	nvme_ns_t n;
	nvme_path_t p;
	nvme_ctrl_t c;

	if (ranking == NVME_CLI_TOPO_NAMESPACE) {
		nvme_subsystem_for_each_ns(s, n) {
			if (!nvme_namespace_first_path(n))
				continue;

			printf(" +- ns %d\n", nvme_ns_get_nsid(n));
			printf(" \\\n");

			nvme_namespace_for_each_path(n, p) {
				c = nvme_path_get_ctrl(p);

				printf("  +- %s %s %s %s %s\n",
				       nvme_ctrl_get_name(c),
				       nvme_ctrl_get_transport(c),
				       nvme_ctrl_get_address(c),
				       nvme_ctrl_get_state(c),
				       nvme_path_get_ana_state(p));
			}
		}
	} else {
		/* NVME_CLI_TOPO_CTRL */
		nvme_subsystem_for_each_ctrl(s, c) {
			printf(" +- %s %s %s\n",
			       nvme_ctrl_get_name(c),
			       nvme_ctrl_get_transport(c),
			       nvme_ctrl_get_address(c));
			printf(" \\\n");

			nvme_subsystem_for_each_ns(s, n) {
				nvme_namespace_for_each_path(n, p) {
					if (nvme_path_get_ctrl(p) != c)
						continue;

					printf("  +- ns %d %s %s\n",
					       nvme_ns_get_nsid(n),
					       nvme_ctrl_get_state(c),
					       nvme_path_get_ana_state(p));
				}
			}
		}
	}
}

static void stdout_subsystem_topology(nvme_subsystem_t s,
					   enum nvme_cli_topo_ranking ranking)
{
	nvme_ctrl_t c;
	nvme_ns_t n;

	if (ranking == NVME_CLI_TOPO_NAMESPACE) {
		nvme_subsystem_for_each_ctrl(s, c) {
			nvme_ctrl_for_each_ns(c, n) {
				printf(" +- ns %d\n", nvme_ns_get_nsid(n));
				printf(" \\\n");
				printf("  +- %s %s %s %s\n",
				       nvme_ctrl_get_name(c),
				       nvme_ctrl_get_transport(c),
				       nvme_ctrl_get_address(c),
				       nvme_ctrl_get_state(c));
			}
		}
	} else {
		/* NVME_CLI_TOPO_CTRL */
		nvme_subsystem_for_each_ctrl(s, c) {
			printf(" +- %s %s %s\n",
			       nvme_ctrl_get_name(c),
			       nvme_ctrl_get_transport(c),
			       nvme_ctrl_get_address(c));
			printf(" \\\n");
			nvme_ctrl_for_each_ns(c, n) {
				printf("  +- ns %d %s\n",
				       nvme_ns_get_nsid(n),
				       nvme_ctrl_get_state(c));
			}
		}
	}
}

static void stdout_simple_topology(nvme_root_t r,
				   enum nvme_cli_topo_ranking ranking)
{
	nvme_host_t h;
	nvme_subsystem_t s;
	bool first = true;

	nvme_for_each_host(r, h) {
		nvme_for_each_subsystem(h, s) {
			if (!first)
				printf("\n");
			first = false;

			stdout_subsys_config(s);
			printf("\\\n");

			if (nvme_is_multipath(s))
				stdout_subsystem_topology_multipath(s, ranking);
			else
				stdout_subsystem_topology(s, ranking);
		}
	}
}

static void stdout_topology_namespace(nvme_root_t r)
{
	stdout_simple_topology(r, NVME_CLI_TOPO_NAMESPACE);
}

static void stdout_topology_ctrl(nvme_root_t r)
{
	stdout_simple_topology(r, NVME_CLI_TOPO_CTRL);
}

static void stdout_message(bool error, const char *msg, va_list ap)
{
	vfprintf(error ? stderr : stdout, msg, ap);

	fprintf(error ? stderr : stdout, "\n");
}

static void stdout_perror(const char *msg, va_list ap)
{
	_cleanup_free_ char *error = NULL;

	if (vasprintf(&error, msg, ap) < 0)
		error = alloc_error;

	perror(error);
}

static void stdout_key_value(const char *key, const char *val, va_list ap)
{
	_cleanup_free_ char *value = NULL;

	if (vasprintf(&value, val, ap) < 0)
		value = NULL;

	printf("%s: %s\n", key, value ? value : "Could not allocate string");
}

static void stdout_discovery_log(struct nvmf_discovery_log *log, int numrec)
{
	int i;

	printf("\nDiscovery Log Number of Records %d, Generation counter %"PRIu64"\n",
	       numrec, le64_to_cpu(log->genctr));

	for (i = 0; i < numrec; i++) {
		struct nvmf_disc_log_entry *e = &log->entries[i];

		printf("=====Discovery Log Entry %d======\n", i);
		printf("trtype:  %s\n", nvmf_trtype_str(e->trtype));
		printf("adrfam:  %s\n",
			strlen(e->traddr) ?
			nvmf_adrfam_str(e->adrfam) : "");
		printf("subtype: %s\n", nvmf_subtype_str(e->subtype));
		printf("treq:    %s\n", nvmf_treq_str(e->treq));
		printf("portid:  %d\n", le16_to_cpu(e->portid));
		printf("trsvcid: %s\n", e->trsvcid);
		printf("subnqn:  %s\n", e->subnqn);
		printf("traddr:  %s\n", e->traddr);
		printf("eflags:  %s\n",
		       nvmf_eflags_str(le16_to_cpu(e->eflags)));

		switch (e->trtype) {
		case NVMF_TRTYPE_RDMA:
			printf("rdma_prtype: %s\n",
				nvmf_prtype_str(e->tsas.rdma.prtype));
			printf("rdma_qptype: %s\n",
				nvmf_qptype_str(e->tsas.rdma.qptype));
			printf("rdma_cms:    %s\n",
				nvmf_cms_str(e->tsas.rdma.cms));
			printf("rdma_pkey: %#04x\n",
				le16_to_cpu(e->tsas.rdma.pkey));
			break;
		case NVMF_TRTYPE_TCP:
			printf("sectype: %s\n",
				nvmf_sectype_str(e->tsas.tcp.sectype));
			break;
		}
	}
}

static void stdout_connect_msg(nvme_ctrl_t c)
{
	printf("connecting to device: %s\n", nvme_ctrl_get_name(c));
}

static void stdout_mgmt_addr_list_log(struct nvme_mgmt_addr_list_log *ma_list)
{
	int i;
	bool reserved = true;

	printf("Management Address List:\n");
	for (i = 0; i < ARRAY_SIZE(ma_list->mad); i++) {
		switch (ma_list->mad[i].mat) {
		case 1:
		case 2:
			printf("Descriptor: %d, Type: %d (%s), Address: %s\n", i,
			       ma_list->mad[i].mat,
			       ma_list->mad[i].mat == 1 ? "NVM subsystem management agent" :
			       "fabric interface manager", ma_list->mad[i].madrs);
			reserved = false;
			break;
		case 0xff:
			goto out;
		default:
			break;
		}
	}
out:
	if (reserved)
		printf("All management address descriptors reserved\n");
}

static void stdout_rotational_media_info_log(struct nvme_rotational_media_info_log *info)
{
	printf("endgid: %u\n", le16_to_cpu(info->endgid));
	printf("numa: %u\n", le16_to_cpu(info->numa));
	printf("nrs: %u\n", le16_to_cpu(info->nrs));
	printf("spinc: %u\n", le32_to_cpu(info->spinc));
	printf("fspinc: %u\n", le32_to_cpu(info->fspinc));
	printf("ldc: %u\n", le32_to_cpu(info->ldc));
	printf("fldc: %u\n", le32_to_cpu(info->fldc));
}

static void stdout_dispersed_ns_psub_log(struct nvme_dispersed_ns_participating_nss_log *log)
{
	__u64 numpsub = le64_to_cpu(log->numpsub);
	__u64 i;

	printf("genctr: %"PRIu64"\n", le64_to_cpu(log->genctr));
	printf("numpsub: %"PRIu64"\n", (uint64_t)numpsub);
	for (i = 0; i < numpsub; i++)
		printf("participating_nss %"PRIu64": %-.*s\n", (uint64_t)i, NVME_NQN_LENGTH,
		       &log->participating_nss[i * NVME_NQN_LENGTH]);
}

static void stdout_reachability_groups_log(struct nvme_reachability_groups_log *log, __u64 len)
{
	__u16 i;
	__u32 j;

	print_debug("len: %"PRIu64"\n", (uint64_t)len);
	printf("chngc: %"PRIu64"\n", le64_to_cpu(log->chngc));
	printf("nrgd: %u\n", le16_to_cpu(log->nrgd));

	for (i = 0; i < le16_to_cpu(log->nrgd); i++) {
		printf("rgid: %u\n", le32_to_cpu(log->rgd[i].rgid));
		printf("nnid: %u\n", le32_to_cpu(log->rgd[i].nnid));
		printf("chngc: %"PRIu64"\n", le64_to_cpu(log->rgd[i].chngc));
		for (j = 0; j < le32_to_cpu(log->rgd[i].nnid); j++)
			printf("nsid%u: %u\n", j, le32_to_cpu(log->rgd[i].nsid[j]));
	}
}

static void stdout_reachability_associations_log(struct nvme_reachability_associations_log *log,
						 __u64 len)
{
	__u16 i;
	__u32 j;

	print_debug("len: %"PRIu64"\n", (uint64_t)len);
	printf("chngc: %"PRIu64"\n", le64_to_cpu(log->chngc));
	printf("nrad: %u\n", le16_to_cpu(log->nrad));

	for (i = 0; i < le16_to_cpu(log->nrad); i++) {
		printf("rasid: %u\n", le32_to_cpu(log->rad[i].rasid));
		printf("nrid: %u\n", le32_to_cpu(log->rad[i].nrid));
		printf("chngc: %"PRIu64"\n", le64_to_cpu(log->rad[i].chngc));
		printf("rac: %u\n", log->rad[i].rac);
		for (j = 0; j < le32_to_cpu(log->rad[i].nrid); j++)
			printf("rgid%u: %u\n", j, le32_to_cpu(log->rad[i].rgid[j]));
	}
}

static void stdout_host_discovery_log(struct nvme_host_discover_log *log)
{
	__u32 i;
	__u16 j;
	struct nvme_host_ext_discover_log *hedlpe;
	struct nvmf_ext_attr *exat;
	__u32 thdlpl = le32_to_cpu(log->thdlpl);
	__u32 tel;
	__u16 numexat;
	int n = 0;

	printf("genctr: %"PRIu64"\n", le64_to_cpu(log->genctr));
	printf("numrec: %"PRIu64"\n", le64_to_cpu(log->numrec));
	printf("recfmt: %u\n", le16_to_cpu(log->recfmt));
	printf("hdlpf: %02x\n", log->hdlpf);
	printf("thdlpl: %u\n", thdlpl);

	for (i = sizeof(*log); i < le32_to_cpu(log->thdlpl); i += tel) {
		printf("hedlpe: %d\n", n++);
		hedlpe = (void *)log + i;
		tel = le32_to_cpu(hedlpe->tel);
		numexat = le16_to_cpu(hedlpe->numexat);
		printf("trtype: %s\n", nvmf_trtype_str(hedlpe->trtype));
		printf("adrfam: %s\n",
		       strlen(hedlpe->traddr) ? nvmf_adrfam_str(hedlpe->adrfam) : "");
		printf("eflags: %s\n", nvmf_eflags_str(le16_to_cpu(hedlpe->eflags)));
		printf("hostnqn: %s\n", hedlpe->hostnqn);
		printf("traddr: %s\n", hedlpe->traddr);
		printf("tsas: ");
		switch (hedlpe->trtype) {
		case NVMF_TRTYPE_RDMA:
			printf("prtype: %s, qptype: %s, cms: %s, pkey: 0x%04x\n",
			       nvmf_prtype_str(hedlpe->tsas.rdma.prtype),
			       nvmf_qptype_str(hedlpe->tsas.rdma.qptype),
			       nvmf_cms_str(hedlpe->tsas.rdma.cms),
			       le16_to_cpu(hedlpe->tsas.rdma.pkey));
			break;
		case NVMF_TRTYPE_TCP:
			printf("sectype: %s\n", nvmf_sectype_str(hedlpe->tsas.tcp.sectype));
			break;
		default:
			printf("common:\n");
			d((unsigned char *)hedlpe->tsas.common, sizeof(hedlpe->tsas.common), 16, 1);
			break;
		}
		printf("tel: %u\n", tel);
		printf("numexat: %u\n", numexat);

		exat = hedlpe->exat;
		for (j = 0; j < numexat; j++) {
			printf("exat: %d\n", j);
			printf("exattype: %u\n", le16_to_cpu(exat->exattype));
			printf("exatlen: %u\n", le16_to_cpu(exat->exatlen));
			printf("exatval:\n");
			d((unsigned char *)exat->exatval, le16_to_cpu(exat->exatlen), 16, 1);
			exat = nvmf_exat_ptr_next(exat);
		}
	}
}

static void print_traddr(char *field, __u8 adrfam, __u8 *traddr)
{
	int af = AF_INET;
	socklen_t size = INET_ADDRSTRLEN;
	char dst[INET6_ADDRSTRLEN];

	if (adrfam == NVMF_ADDR_FAMILY_IP6) {
		af = AF_INET6;
		size = INET6_ADDRSTRLEN;
	}

	if (inet_ntop(af, nvmf_adrfam_str(adrfam), dst, size))
		printf("%s: %s\n", field, dst);
}

static void stdout_ave_discovery_log(struct nvme_ave_discover_log *log)
{
	__u32 i;
	__u8 j;
	struct nvme_ave_discover_log_entry *adlpe;
	struct nvme_ave_tr_record *atr;
	__u32 tadlpl = le32_to_cpu(log->tadlpl);
	__u32 tel;
	__u8 numatr;
	int n = 0;

	printf("genctr: %"PRIu64"\n", le64_to_cpu(log->genctr));
	printf("numrec: %"PRIu64"\n", le64_to_cpu(log->numrec));
	printf("recfmt: %u\n", le16_to_cpu(log->recfmt));
	printf("tadlpl: %u\n", tadlpl);

	for (i = sizeof(*log); i < le32_to_cpu(log->tadlpl); i += tel) {
		printf("adlpe: %d\n", n++);
		adlpe = (void *)log + i;
		tel = le32_to_cpu(adlpe->tel);
		numatr = adlpe->numatr;
		printf("tel: %u\n", tel);
		printf("avenqn: %s\n", adlpe->avenqn);
		printf("numatr: %u\n", numatr);

		atr = adlpe->atr;
		for (j = 0; j < numatr; j++) {
			printf("atr: %d\n", j);
			printf("aveadrfam: %s\n", nvmf_adrfam_str(atr->aveadrfam));
			printf("avetrsvcid: %u\n", le16_to_cpu(atr->avetrsvcid));
			print_traddr("avetraddr", atr->aveadrfam, atr->avetraddr);
			atr++;
		}
	}
}

static void stdout_pull_model_ddc_req_log(struct nvme_pull_model_ddc_req_log *log)
{
	__u32 tpdrpl = le32_to_cpu(log->tpdrpl);
	__u32 osp_len = tpdrpl - offsetof(struct nvme_pull_model_ddc_req_log, osp);

	printf("ori: %u\n", log->ori);
	printf("tpdrpl: %u\n", tpdrpl);
	printf("osp:\n");
	d((unsigned char *)log->osp, osp_len, 16, 1);
}

static void stdout_relatives(nvme_root_t r, const char *name)
{
	struct nvme_resources res;
	struct htable_ns_iter it;
	bool block = true;
	bool first = true;
	nvme_ctrl_t c;
	nvme_path_t p;
	nvme_ns_t n;
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

	nvme_resources_init(r, &res);

	if (block) {
		fprintf(stderr, "Namespace %s has parent controller(s):", name);
		for (n = htable_ns_getfirst(&res.ht_n, name, &it); n;
		     n = htable_ns_getnext(&res.ht_n, name, &it)) {
			if (nvme_ns_get_ctrl(n)) {
				fprintf(stderr, "%s", nvme_ctrl_get_name(nvme_ns_get_ctrl(n)));
				break;
			}
			nvme_namespace_for_each_path(n, p) {
				c = nvme_path_get_ctrl(p);
				fprintf(stderr, "%s%s", first ? "" : ", ", nvme_ctrl_get_name(c));
				if (first)
					first = false;
			}
		}
		fprintf(stderr, "\n\n");
	} else {
		c = htable_ctrl_get(&res.ht_c, name);
		if (c) {
			fprintf(stderr, "Controller %s has child namespace(s):", name);
			nvme_ctrl_for_each_ns(c, n) {
				fprintf(stderr, "%s%s", first ? "" : ", ", nvme_ns_get_name(n));
				if (first)
					first = false;
			}
			fprintf(stderr, "\n\n");
		}
	}

	nvme_resources_free(&res);
}

static void stdout_log(const char *devname, struct nvme_get_log_args *args)
{
	struct nvme_aggregate_endurance_group_event *end = args->log;
	struct nvme_supported_cap_config_list_log *cap = args->log;

	switch (args->lid) {
	case NVME_LOG_LID_SUPPORTED_LOG_PAGES:
		break;
	case NVME_LOG_LID_ERROR:
		stdout_error_log((struct nvme_error_log_page *)args->log,
				 args->len / sizeof(struct nvme_error_log_page), devname);
		break;
	case NVME_LOG_LID_SMART:
		stdout_smart_log((struct nvme_smart_log *)args->log, args->nsid, devname);
		break;
	case NVME_LOG_LID_FW_SLOT:
		stdout_fw_log((struct nvme_firmware_slot *)args->log, devname);
		break;
	case NVME_LOG_LID_CHANGED_NS:
		stdout_changed_ns_list_log((struct nvme_ns_list *)args->log, devname, false);
		break;
	case NVME_LOG_LID_CMD_EFFECTS:
		break;
	case NVME_LOG_LID_DEVICE_SELF_TEST:
		stdout_self_test_log((struct nvme_self_test_log *)args->log,
				 args->len / sizeof(struct nvme_self_test_log), 0, devname);
		break;
	case NVME_LOG_LID_TELEMETRY_HOST:
		break;
	case NVME_LOG_LID_TELEMETRY_CTRL:
		break;
	case NVME_LOG_LID_ENDURANCE_GROUP:
		stdout_endurance_log((struct nvme_endurance_group_log *)args->log, args->lsi,
				     devname);
		break;
	case NVME_LOG_LID_PREDICTABLE_LAT_NVMSET:
		stdout_predictable_latency_per_nvmset(
		    (struct nvme_nvmset_predictable_lat_log *)args->log, args->lsi, devname);
		break;
	case NVME_LOG_LID_PREDICTABLE_LAT_AGG:
		stdout_predictable_latency_event_agg_log(
		    (struct nvme_aggregate_predictable_lat_event *)args->log,
		    args->len > sizeof(__u64) ? (args->len - sizeof(__u64)) / sizeof(__le16) : 0,
		    args->len, devname);
		break;
	case NVME_LOG_LID_ANA:
		stdout_ana_log((struct nvme_ana_log *)args->log, devname, args->len);
		break;
	case NVME_LOG_LID_PERSISTENT_EVENT:
		stdout_persistent_event_log((void *)args->log, args->lsp, args->len, devname);
		break;
	case NVME_LOG_LID_LBA_STATUS:
		stdout_lba_status_log((void *)args->log, args->len, devname);
		break;
	case NVME_LOG_LID_ENDURANCE_GRP_EVT:
		stdout_endurance_group_event_agg_log(end, end->num_entries, args->len, devname);
		break;
	case NVME_LOG_LID_MEDIA_UNIT_STATUS:
		stdout_media_unit_stat_log((struct nvme_media_unit_stat_log *)args->log);
		break;
	case NVME_LOG_LID_SUPPORTED_CAP_CONFIG_LIST:
		stdout_supported_cap_config_log(cap);
		break;
	case NVME_LOG_LID_FID_SUPPORTED_EFFECTS:
		break;
	case NVME_LOG_LID_MI_CMD_SUPPORTED_EFFECTS:
		break;
	case NVME_LOG_LID_CMD_AND_FEAT_LOCKDOWN:
		break;
	case NVME_LOG_LID_BOOT_PARTITION:
		break;
	case NVME_LOG_LID_ROTATIONAL_MEDIA_INFO:
		break;
	case NVME_LOG_LID_DISPERSED_NS_PARTICIPATING_NSS:
		break;
	case NVME_LOG_LID_MGMT_ADDR_LIST:
		break;
	case NVME_LOG_LID_PHY_RX_EOM:
		break;
	case NVME_LOG_LID_REACHABILITY_GROUPS:
		break;
	case NVME_LOG_LID_REACHABILITY_ASSOCIATIONS:
		break;
	case NVME_LOG_LID_CHANGED_ALLOC_NS_LIST:
		stdout_changed_ns_list_log((struct nvme_ns_list *)args->log, devname, true);
		break;
	case NVME_LOG_LID_FDP_CONFIGS:
		break;
	case NVME_LOG_LID_FDP_RUH_USAGE:
		break;
	case NVME_LOG_LID_FDP_STATS:
		break;
	case NVME_LOG_LID_FDP_EVENTS:
		break;
	case NVME_LOG_LID_DISCOVER:
		break;
	case NVME_LOG_LID_HOST_DISCOVER:
		break;
	case NVME_LOG_LID_AVE_DISCOVER:
		break;
	case NVME_LOG_LID_PULL_MODEL_DDC_REQ:
		break;
	case NVME_LOG_LID_RESERVATION:
		break;
	case NVME_LOG_LID_SANITIZE:
		break;
	case NVME_LOG_LID_ZNS_CHANGED_ZONES:
		break;
	default:
		break;
	}
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
	.log				= stdout_log,

	/* libnvme tree print functions */
	.list_item			= stdout_list_item,
	.list_items			= stdout_list_items,
	.print_nvme_subsystem_list	= stdout_subsystem_list,
	.topology_ctrl			= stdout_topology_ctrl,
	.topology_namespace		= stdout_topology_namespace,

	/* status and error messages */
	.connect_msg			= stdout_connect_msg,
	.show_message			= stdout_message,
	.show_perror			= stdout_perror,
	.show_status			= stdout_status,
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
