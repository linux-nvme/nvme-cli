// SPDX-License-Identifier: GPL-2.0-or-later
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <sys/stat.h>

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
#include "common.h"

static const uint8_t zero_uuid[16] = { 0 };
static const uint8_t invalid_uuid[16] = {[0 ... 15] = 0xff };
static const char dash[100] = {[0 ... 99] = '-'};

static struct print_ops stdout_print_ops;

struct nvme_bar_cap {
	__u16	mqes;
	__u8	cqr:1;
	__u8	ams:2;
	__u8	rsvd19:5;
	__u8	to;
	__u16	dstrd:4;
	__u16	nssrs:1;
	__u16	css:8;
	__u16	bps:1;
	__u8	cps:2;
	__u8	mpsmin:4;
	__u8	mpsmax:4;
	__u8	pmrs:1;
	__u8	cmbs:1;
	__u8	nsss:1;
	__u8	crwms:1;
	__u8	crims:1;
	__u8	rsvd61:3;
};

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
static void stdout_smart_log(struct nvme_smart_log *smart,
			     unsigned int nsid,
			     const char *devname);

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
	printf("NDWIN Time Minimum High: %"PRIu64" \n",
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
	printf("Predictable Latency Event Aggregate Log for"\
		" device: %s\n", devname);

	printf("Number of Entries Available: %"PRIu64"\n",
		(uint64_t)num_entries);

	num_iter = min(num_entries, log_entries);
	for (int i = 0; i < num_iter; i++) {
		printf("Entry[%d]: %u\n", i + 1,
			le16_to_cpu(pea_log->entries[i]));
	}
}

static void stdout_persistent_event_log_rci(__le32 pel_header_rci)
{
	__u32 rci = le32_to_cpu(pel_header_rci);
	__u32 rsvd19 = (rci & 0xfff80000) >> 19;
	__u8 rce = (rci & 0x40000) >> 18;
	__u8 rcpit = (rci & 0x30000) >> 16;
	__u16 rcpid = rci & 0xffff;

	if(rsvd19)
		printf("  [31:19] : %#x\tReserved\n", rsvd19);
	printf("\tReporting Context Exists (RCE): %s(%u)\n",
		rce ? "true" : "false", rce);
	printf("\tReporting Context Port Identifier Type (RCPIT): %u(%s)\n", rcpit,
		(rcpit == 0x00) ? "Does not already exist" :
		(rcpit == 0x01) ? "NVM subsystem port" :
		(rcpit == 0x02) ? "NVMe-MI port" : "Reserved");
	printf("\tReporting Context Port Identifier (RCPID): %#x\n\n", rcpid);
}

static void stdout_persistent_event_entry_ehai(__u8 ehai)
{
	__u8 rsvd1 = (ehai & 0xfc) >> 2;
	__u8 pit = ehai & 0x03;

	printf("  [7:2] : %#x\tReserved\n", rsvd1);
	printf("\tPort Identifier Type (PIT): %u(%s)\n", pit,
		(pit == 0x00) ? "PIT not reported and PELPID does not apply" :
		(pit == 0x01) ? "NVM subsystem port" :
		(pit == 0x02) ? "NVMe-MI port" :
		"Event not associated with any port and PELPID does not apply");
}

static void stdout_add_bitmap(int i, __u8 seb)
{
	for (int bit = 0; bit < 8; bit++) {
		if (nvme_pel_event_to_string(bit + i * 8)) {
			if (nvme_pel_event_to_string(bit + i * 8))
				if ((seb >> bit) & 0x1)
					printf("	Support %s\n",
					       nvme_pel_event_to_string(bit + i * 8));
		}
	}
}

static void stdout_persistent_event_log(void *pevent_log_info,
					__u8 action, __u32 size,
					const char *devname)
{
	__u32 offset, por_info_len, por_info_list;
	__u64 *fw_rev;
	int fid, cdw11, dword_cnt;
	unsigned char *mem_buf = NULL;
	struct nvme_smart_log *smart_event;
	struct nvme_fw_commit_event *fw_commit_event;
	struct nvme_time_stamp_change_event *ts_change_event;
	struct nvme_power_on_reset_info_list *por_event;
	struct nvme_nss_hw_err_event *nss_hw_err_event;
	struct nvme_change_ns_event	*ns_event;
	struct nvme_format_nvm_start_event *format_start_event;
	struct nvme_format_nvm_compln_event *format_cmpln_event;
	struct nvme_sanitize_start_event *sanitize_start_event;
	struct nvme_sanitize_compln_event *sanitize_cmpln_event;
	struct nvme_set_feature_event *set_feat_event;
	struct nvme_thermal_exc_event *thermal_exc_event;
	struct nvme_persistent_event_log *pevent_log_head;
	struct nvme_persistent_event_entry *pevent_entry_head;

	int human = stdout_print_ops.flags & VERBOSE;

	offset = sizeof(*pevent_log_head);

	printf("Persistent Event Log for device: %s\n", devname);
	printf("Action for Persistent Event Log: %u\n", action);
	if (size >= offset) {
		pevent_log_head = pevent_log_info;
		printf("Log Identifier: %u\n", pevent_log_head->lid);
		printf("Total Number of Events: %u\n",
			le32_to_cpu(pevent_log_head->tnev));
		printf("Total Log Length : %"PRIu64"\n",
			le64_to_cpu(pevent_log_head->tll));
		printf("Log Revision: %u\n", pevent_log_head->rv);
		printf("Log Header Length: %u\n", pevent_log_head->lhl);
		printf("Timestamp: %"PRIu64"\n",
			le64_to_cpu(pevent_log_head->ts));
		printf("Power On Hours (POH): %s",
			uint128_t_to_l10n_string(le128_to_cpu(pevent_log_head->poh)));
		printf("Power Cycle Count: %"PRIu64"\n",
			le64_to_cpu(pevent_log_head->pcc));
		printf("PCI Vendor ID (VID): %u\n",
			le16_to_cpu(pevent_log_head->vid));
		printf("PCI Subsystem Vendor ID (SSVID): %u\n",
			le16_to_cpu(pevent_log_head->ssvid));
		printf("Serial Number (SN): %-.*s\n",
			(int)sizeof(pevent_log_head->sn), pevent_log_head->sn);
		printf("Model Number (MN): %-.*s\n",
			(int)sizeof(pevent_log_head->mn), pevent_log_head->mn);
		printf("NVM Subsystem NVMe Qualified Name (SUBNQN): %-.*s\n",
			(int)sizeof(pevent_log_head->subnqn),
			pevent_log_head->subnqn);
		printf("Generation Number: %u\n",
			le16_to_cpu(pevent_log_head->gen_number));
		printf("Reporting Context Information (RCI): %u\n",
			le32_to_cpu(pevent_log_head->rci));
		if (human)
			stdout_persistent_event_log_rci(pevent_log_head->rci);
		printf("Supported Events Bitmap: \n");
		for (int i = 0; i < 32; i++) {
			if (pevent_log_head->seb[i] == 0)
				continue;
			stdout_add_bitmap(i, pevent_log_head->seb[i]);
		}
	} else {
		printf("No log data can be shown with this log len at least " \
			"512 bytes is required or can be 0 to read the complete "\
			"log page after context established\n");
		return;
	}
	printf("\n");
	printf("\nPersistent Event Entries:\n");
	for (int i = 0; i < le32_to_cpu(pevent_log_head->tnev); i++) {
		if (offset + sizeof(*pevent_entry_head) >= size)
			break;

		pevent_entry_head = pevent_log_info + offset;

		if ((offset + pevent_entry_head->ehl + 3 +
			le16_to_cpu(pevent_entry_head->el)) >= size)
			break;
		printf("Event Number: %u\n", i);
		printf("Event Type: %s\n", nvme_pel_event_to_string(pevent_entry_head->etype));
		printf("Event Type Revision: %u\n", pevent_entry_head->etype_rev);
		printf("Event Header Length: %u\n", pevent_entry_head->ehl);
		printf("Event Header Additional Info: %u\n", pevent_entry_head->ehai);
		if (human)
			stdout_persistent_event_entry_ehai(pevent_entry_head->ehai);
		printf("Controller Identifier: %u\n",
			le16_to_cpu(pevent_entry_head->cntlid));
		printf("Event Timestamp: %"PRIu64"\n",
			le64_to_cpu(pevent_entry_head->ets));
		printf("Port Identifier: %u\n",
			le16_to_cpu(pevent_entry_head->pelpid));
		printf("Vendor Specific Information Length: %u\n",
			le16_to_cpu(pevent_entry_head->vsil));
		printf("Event Length: %u\n", le16_to_cpu(pevent_entry_head->el));

		offset += pevent_entry_head->ehl + 3;

		switch (pevent_entry_head->etype) {
		case NVME_PEL_SMART_HEALTH_EVENT:
			smart_event = pevent_log_info + offset;
			printf("Smart Health Event Entry: \n");
			stdout_smart_log(smart_event, NVME_NSID_ALL, devname);
			break;
		case NVME_PEL_FW_COMMIT_EVENT:
			fw_commit_event = pevent_log_info + offset;
			printf("FW Commit Event Entry: \n");
			printf("Old Firmware Revision: %"PRIu64" (%s)\n",
				le64_to_cpu(fw_commit_event->old_fw_rev),
				util_fw_to_string((char *)&fw_commit_event->old_fw_rev));
			printf("New Firmware Revision: %"PRIu64" (%s)\n",
				le64_to_cpu(fw_commit_event->new_fw_rev),
				util_fw_to_string((char *)&fw_commit_event->new_fw_rev));
			printf("FW Commit Action: %u\n",
				fw_commit_event->fw_commit_action);
			printf("FW Slot: %u\n", fw_commit_event->fw_slot);
			printf("Status Code Type for Firmware Commit Command: %u\n",
				fw_commit_event->sct_fw);
			printf("Status Returned for Firmware Commit Command: %u\n",
				fw_commit_event->sc_fw);
			printf("Vendor Assigned Firmware Commit Result Code: %u\n",
				le16_to_cpu(fw_commit_event->vndr_assign_fw_commit_rc));
			break;
		case NVME_PEL_TIMESTAMP_EVENT:
			ts_change_event = pevent_log_info + offset;
			printf("Time Stamp Change Event Entry: \n");
			printf("Previous Timestamp: %"PRIu64"\n",
				le64_to_cpu(ts_change_event->previous_timestamp));
			printf("Milliseconds Since Reset: %"PRIu64"\n",
				le64_to_cpu(ts_change_event->ml_secs_since_reset));
			break;
		case NVME_PEL_POWER_ON_RESET_EVENT:
			por_info_len = (le16_to_cpu(pevent_entry_head->el) -
				le16_to_cpu(pevent_entry_head->vsil) - sizeof(*fw_rev));

			por_info_list = por_info_len / sizeof(*por_event);

			printf("Power On Reset Event Entry: \n");
			fw_rev = pevent_log_info + offset;
			printf("Firmware Revision: %"PRIu64" (%s)\n", le64_to_cpu(*fw_rev),
				util_fw_to_string((char *)fw_rev));
			printf("Reset Information List: \n");

			for (int i = 0; i < por_info_list; i++) {
				por_event = pevent_log_info + offset +
					sizeof(*fw_rev) + i * sizeof(*por_event);
				printf("Controller ID: %u\n", le16_to_cpu(por_event->cid));
				printf("Firmware Activation: %u\n",
					por_event->fw_act);
				printf("Operation in Progress: %u\n",
					por_event->op_in_prog);
				printf("Controller Power Cycle: %u\n",
					le32_to_cpu(por_event->ctrl_power_cycle));
				printf("Power on milliseconds: %"PRIu64"\n",
					le64_to_cpu(por_event->power_on_ml_seconds));
				printf("Controller Timestamp: %"PRIu64"\n",
					le64_to_cpu(por_event->ctrl_time_stamp));
			}
			break;
		case NVME_PEL_NSS_HW_ERROR_EVENT:
			nss_hw_err_event = pevent_log_info + offset;
			printf("NVM Subsystem Hardware Error Event Code Entry: %u, %s\n",
				le16_to_cpu(nss_hw_err_event->nss_hw_err_event_code),
				nvme_nss_hw_error_to_string(nss_hw_err_event->nss_hw_err_event_code));
			break;
		case NVME_PEL_CHANGE_NS_EVENT:
			ns_event = pevent_log_info + offset;
			printf("Change Namespace Event Entry: \n");
			printf("Namespace Management CDW10: %u\n",
				le32_to_cpu(ns_event->nsmgt_cdw10));
			printf("Namespace Size: %"PRIu64"\n",
				le64_to_cpu(ns_event->nsze));
			printf("Namespace Capacity: %"PRIu64"\n",
				le64_to_cpu(ns_event->nscap));
			printf("Formatted LBA Size: %u\n", ns_event->flbas);
			printf("End-to-end Data Protection Type Settings: %u\n",
				ns_event->dps);
			printf("Namespace Multi-path I/O and Namespace Sharing" \
				" Capabilities: %u\n", ns_event->nmic);
			printf("ANA Group Identifier: %u\n",
				le32_to_cpu(ns_event->ana_grp_id));
			printf("NVM Set Identifier: %u\n", le16_to_cpu(ns_event->nvmset_id));
			printf("Namespace ID: %u\n", le32_to_cpu(ns_event->nsid));
			break;
		case NVME_PEL_FORMAT_START_EVENT:
			format_start_event = pevent_log_info + offset;
			printf("Format NVM Start Event Entry: \n");
			printf("Namespace Identifier: %u\n",
				le32_to_cpu(format_start_event->nsid));
			printf("Format NVM Attributes: %u\n",
				format_start_event->fna);
			printf("Format NVM CDW10: %u\n",
				le32_to_cpu(format_start_event->format_nvm_cdw10));
			break;
		case NVME_PEL_FORMAT_COMPLETION_EVENT:
			format_cmpln_event = pevent_log_info + offset;
			printf("Format NVM Completion Event Entry: \n");
			printf("Namespace Identifier: %u\n",
				le32_to_cpu(format_cmpln_event->nsid));
			printf("Smallest Format Progress Indicator: %u\n",
				format_cmpln_event->smallest_fpi);
			printf("Format NVM Status: %u\n",
				format_cmpln_event->format_nvm_status);
			printf("Completion Information: %u\n",
				le16_to_cpu(format_cmpln_event->compln_info));
			printf("Status Field: %u\n",
				le32_to_cpu(format_cmpln_event->status_field));
			break;
		case NVME_PEL_SANITIZE_START_EVENT:
			sanitize_start_event = pevent_log_info + offset;
			printf("Sanitize Start Event Entry: \n");
			printf("SANICAP: %u\n", sanitize_start_event->sani_cap);
			printf("Sanitize CDW10: %u\n",
				le32_to_cpu(sanitize_start_event->sani_cdw10));
			printf("Sanitize CDW11: %u\n",
				le32_to_cpu(sanitize_start_event->sani_cdw11));
			break;
		case NVME_PEL_SANITIZE_COMPLETION_EVENT:
			sanitize_cmpln_event = pevent_log_info + offset;
			printf("Sanitize Completion Event Entry: \n");
			printf("Sanitize Progress: %u\n",
				le16_to_cpu(sanitize_cmpln_event->sani_prog));
			printf("Sanitize Status: %u\n",
				le16_to_cpu(sanitize_cmpln_event->sani_status));
			printf("Completion Information: %u\n",
				le16_to_cpu(sanitize_cmpln_event->cmpln_info));
			break;
		case NVME_PEL_SET_FEATURE_EVENT:
			set_feat_event = pevent_log_info + offset;
			printf("Set Feature Event Entry: \n");
			dword_cnt =  set_feat_event->layout & 0x03;
			fid = le32_to_cpu(set_feat_event->cdw_mem[0]) & 0x000f;
			cdw11 = le32_to_cpu(set_feat_event->cdw_mem[1]);

			printf("Set Feature ID  :%#02x (%s),  value:%#08x\n", fid,
				nvme_feature_to_string(fid), cdw11);
			if (((set_feat_event->layout & 0xff) >> 2) != 0) {
				mem_buf = (unsigned char *)(set_feat_event + 4 + dword_cnt * 4);
				stdout_feature_show_fields(fid, cdw11, mem_buf);
			}
			break;
		case NVME_PEL_TELEMETRY_CRT:
			d(pevent_log_info + offset, 512, 16, 1);
			break;
		case NVME_PEL_THERMAL_EXCURSION_EVENT:
			thermal_exc_event = pevent_log_info + offset;
			printf("Thermal Excursion Event Entry: \n");
			printf("Over Temperature: %u\n", thermal_exc_event->over_temp);
			printf("Threshold: %u\n", thermal_exc_event->threshold);
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
		struct nvme_aggregate_predictable_lat_event *endurance_log,
		__u64 log_entries, __u32 size, const char *devname)
{
	printf("Endurance Group Event Aggregate Log for"\
		" device: %s\n", devname);

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

	fsp = (fid_support >> NVME_FID_SUPPORTED_EFFECTS_SCOPE_SHIFT) & NVME_FID_SUPPORTED_EFFECTS_SCOPE_MASK;

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
			else
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

	csp = (mi_cmd_support >> NVME_MI_CMD_SUPPORTED_EFFECTS_SCOPE_SHIFT) & NVME_MI_CMD_SUPPORTED_EFFECTS_SCOPE_MASK;

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
			else
				printf("\n");
		}
	}
}

static void stdout_boot_part_log(void *bp_log, const char *devname,
				 __u32 size)
{
	struct nvme_boot_partition *hdr;

	hdr = bp_log;
	printf("Boot Partition Log for device: %s\n", devname);
	printf("Log ID: %u\n", hdr->lid);
	printf("Boot Partition Size: %u KiB\n", le32_to_cpu(hdr->bpinfo) & 0x7fff);
	printf("Active BPID: %u\n", (le32_to_cpu(hdr->bpinfo) >> 31) & 0x1);
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
	__u8 rsvd = (odp >> 2) & 0x3F;
	__u8 edfp = (odp >> 1) & 0x1;
	__u8 pefp = odp & 0x1;

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
	for (i = 0; i < lane->nrows; i++) {
		for (j = 0; j < lane->ncols; j++)
			printf("%c", eye[i * lane->ncols + j]);
		printf("\n");
	}
}

static void stdout_phy_rx_eom_descs(struct nvme_phy_rx_eom_log *log)
{
	void *p = log->descs;
	int i;

	for (i = 0; i < log->nd; i++) {
		struct nvme_eom_lane_desc *desc = p;

		printf("Measurement Status: %s\n",
			desc->mstatus ? "Successful" : "Not Successful");
		printf("Lane: %u\n", desc->lane);
		printf("Eye: %u\n", desc->eye);
		printf("Top: %u\n", le16_to_cpu(desc->top));
		printf("Bottom: %u\n", le16_to_cpu(desc->bottom));
		printf("Left: %u\n", le16_to_cpu(desc->left));
		printf("Right: %u\n", le16_to_cpu(desc->right));
		printf("Number of Rows: %u\n", le16_to_cpu(desc->nrows));
		printf("Number of Columns: %u\n", le16_to_cpu(desc->ncols));
		printf("Eye Data Length: %u\n", le16_to_cpu(desc->edlen));

		if (log->odp & NVME_EOM_PRINTABLE_EYE_PRESENT)
			stdout_eom_printable_eye(desc);

		/* Eye Data field is vendor specific */

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

	if (log->eomip == NVME_PHY_RX_EOM_COMPLETED) {
		stdout_phy_rx_eom_descs(log);
	}
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
	__u8 valid = (fdpa >> 7) & 0x1;
	__u8 rsvd = (fdpa >> 5) & 0x3;
	__u8 fdpvwc = (fdpa >> 4) & 0x1;
	__u8 rgif = fdpa & 0xf;

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

		printf("Reclaim Unit Handle %d Attributes: 0x%"PRIx8" (%s)\n", i, ruhu->ruha,
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
		printf("  Event Type: 0x%"PRIx8" (%s)\n", event->type, nvme_fdp_event_to_string(event->type));
		printf("  Event Timestamp: %"PRIu64" (%s)\n", int48_to_long(event->ts.timestamp),
			strftime(buffer, sizeof(buffer), "%c %Z", tm) ? buffer : "-");

		if (event->flags & NVME_FDP_EVENT_F_PIV)
			printf("  Placement Identifier (PID): 0x%"PRIx16"\n", le16_to_cpu(event->pid));

		if (event->flags & NVME_FDP_EVENT_F_NSIDV)
			printf("  Namespace Identifier (NSID): %"PRIu32"\n", le32_to_cpu(event->nsid));

		if (event->type == NVME_FDP_EVENT_REALLOC) {
			struct nvme_fdp_event_realloc *mr;
			mr = (struct nvme_fdp_event_realloc *)&event->type_specific;

			printf("  Number of LBAs Moved (NLBAM): %"PRIu16"\n", le16_to_cpu(mr->nlbam));

			if (mr->flags & NVME_FDP_EVENT_REALLOC_F_LBAV) {
				printf("  Logical Block Address (LBA): 0x%"PRIx64"\n", le64_to_cpu(mr->lba));
			}
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
		for(j = 0; j < egcn; j++) {
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
			for(k = 0; k < egsets; k++) {
				printf("NVM Set %d Identifier: %u\n", i,
					le16_to_cpu(cap->cap_config_desc[i].egcd[j].nvmsetid[k]));
			}
			chan_desc = (struct nvme_end_grp_chan_desc *) \
					((cap->cap_config_desc[i].egcd[j].nvmsetid[0]) * (sizeof(__u16)*egsets));
			egchans = le16_to_cpu(chan_desc->egchans);
			printf("Number of Channels: %u\n", egchans);
			for(l = 0; l < egchans; l++) {
				printf("Channel Identifier: %u\n",
					le16_to_cpu(chan_desc->chan_config_desc[l].chanid));
				chmus = le16_to_cpu(chan_desc->chan_config_desc[l].chmus);
				printf("Number of Channel Media Units: %u\n", chmus);
				for(m = 0; m < chmus; m++) {
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

static void stdout_subsystem(nvme_root_t r, bool show_ana)
{
	nvme_host_t h;
	bool first = true;

	nvme_for_each_host(r, h) {
		nvme_subsystem_t s;

		nvme_for_each_subsystem(h, s) {
			int len = strlen(nvme_subsystem_get_name(s));

			if (!first)
				printf("\n");
			first = false;

			printf("%s - NQN=%s\n", nvme_subsystem_get_name(s),
			       nvme_subsystem_get_nqn(s));
			printf("%*s   hostnqn=%s\n", len, " ",
			       nvme_host_get_hostnqn(nvme_subsystem_get_host(s)));
			printf("%*s   iopolicy=%s\n", len, " ",
			       nvme_subsystem_get_iopolicy(s));
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
	       cap->ams & 0x02 ? "Supported" : "Not supported");
	printf("\tContiguous Queues Required          (CQR): %s\n", cap->cqr ? "Yes" : "No");
	printf("\tMaximum Queue Entries Supported    (MQES): %u\n\n", cap->mqes + 1);
}

static void stdout_registers_version(__u32 vs)
{
	printf("\tNVMe specification %d.%d\n\n", (vs & 0xffff0000) >> 16,
		(vs & 0x0000ff00) >> 8);
}

static void stdout_registers_cc_ams (__u8 ams)
{
	printf("\tArbitration Mechanism Selected     (AMS): ");
	switch (ams) {
	case 0:
		printf("Round Robin\n");
		break;
	case 1:
		printf("Weighted Round Robin with Urgent Priority Class\n");
		break;
	case 7:
		printf("Vendor Specific\n");
		break;
	default:
		printf("Reserved\n");
		break;
	}
}

static void stdout_registers_cc_shn (__u8 shn)
{
	printf("\tShutdown Notification              (SHN): ");
	switch (shn) {
	case 0:
		printf("No notification; no effect\n");
		break;
	case 1:
		printf("Normal shutdown notification\n");
		break;
	case 2:
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
		1 << ((cc & 0x00f00000) >> NVME_CC_IOCQES_SHIFT));
	printf("\tI/O Submission Queue Entry Size (IOSQES): %u bytes\n",
		1 << ((cc & 0x000f0000) >> NVME_CC_IOSQES_SHIFT));
	stdout_registers_cc_shn((cc & 0x0000c000) >> NVME_CC_SHN_SHIFT);
	stdout_registers_cc_ams((cc & 0x00003800) >> NVME_CC_AMS_SHIFT);
	printf("\tMemory Page Size                   (MPS): %u bytes\n",
		1 << (12 + ((cc & 0x00000780) >> NVME_CC_MPS_SHIFT)));
	printf("\tI/O Command Set Selected           (CSS): %s\n",
		(cc & 0x00000070) == 0x00 ? "NVM Command Set" :
		(cc & 0x00000070) == 0x60 ? "All supported I/O Command Sets" :
		(cc & 0x00000070) == 0x70 ? "Admin Command Set only" : "Reserved");
	printf("\tEnable                              (EN): %s\n\n",
		(cc & 0x00000001) ? "Yes" : "No");
}

static void stdout_registers_csts_shst(__u8 shst)
{
	printf("\tShutdown Status               (SHST): ");
	switch (shst) {
	case 0:
		printf("Normal operation (no shutdown has been requested)\n");
		break;
	case 1:
		printf("Shutdown processing occurring\n");
		break;
	case 2:
		printf("Shutdown processing complete\n");
		break;
	default:
		printf("Reserved\n");
		break;
	}
}

static void stdout_registers_csts(__u32 csts)
{
	printf("\tProcessing Paused               (PP): %s\n",
		(csts & 0x00000020) ? "Yes" : "No");
	printf("\tNVM Subsystem Reset Occurred (NSSRO): %s\n",
		(csts & 0x00000010) ? "Yes" : "No");
	stdout_registers_csts_shst((csts & 0x0000000c) >> 2);
	printf("\tController Fatal Status        (CFS): %s\n",
		(csts & 0x00000002) ? "True" : "False");
	printf("\tReady                          (RDY): %s\n\n",
		(csts & 0x00000001) ? "Yes" : "No");

}

static void stdout_registers_crto(__u32 crto)
{
	printf("\tCRIMT                               : %d secs\n",
		NVME_CRTO_CRIMT(crto)/2 );
	printf("\tCRWMT                               : %d secs\n",
		NVME_CRTO_CRWMT(crto)/2 );
}

static void stdout_registers_aqa(__u32 aqa)
{
	printf("\tAdmin Completion Queue Size (ACQS): %u\n",
		((aqa & 0x0fff0000) >> 16) + 1);
	printf("\tAdmin Submission Queue Size (ASQS): %u\n\n",
		(aqa & 0x00000fff) + 1);

}

static void stdout_registers_cmbloc(__u32 cmbloc, __u32 cmbsz)
{
	static const char *enforced[] = { "Enforced", "Not Enforced" };

	if (cmbsz == 0) {
		printf("\tController Memory Buffer feature is not supported\n\n");
		return;
	}
	printf("\tOffset                                                        (OFST): 0x%x (See cmbsz.szu for granularity)\n",
	       (cmbloc & 0xfffff000) >> 12);

	printf("\tCMB Queue Dword Alignment                                     (CQDA): %d\n",
	       (cmbloc & 0x00000100) >> 8);

	printf("\tCMB Data Metadata Mixed Memory Support                      (CDMMMS): %s\n",
	       enforced[(cmbloc & 0x00000080) >> 7]);

	printf("\tCMB Data Pointer and Command Independent Locations Support (CDPCILS): %s\n",
	       enforced[(cmbloc & 0x00000040) >> 6]);

	printf("\tCMB Data Pointer Mixed Locations Support                    (CDPMLS): %s\n",
	       enforced[(cmbloc & 0x00000020) >> 5]);

	printf("\tCMB Queue Physically Discontiguous Support                   (CQPDS): %s\n",
	       enforced[(cmbloc & 0x00000010) >> 4]);

	printf("\tCMB Queue Mixed Memory Support                               (CQMMS): %s\n",
	       enforced[(cmbloc & 0x00000008) >> 3]);

	printf("\tBase Indicator Register                                        (BIR): 0x%x\n\n",
	       (cmbloc & 0x00000007));
}

static void stdout_registers_cmbsz(__u32 cmbsz)
{
	if (cmbsz == 0) {
		printf("\tController Memory Buffer feature is not supported\n\n");
		return;
	}
	printf("\tSize                      (SZ): %u\n", (cmbsz & 0xfffff000) >> 12);
	printf("\tSize Units               (SZU): %s\n",
	       nvme_register_szu_to_string((cmbsz & 0x00000f00) >> 8));
	printf("\tWrite Data Support       (WDS): Write Data and metadata transfer in Controller Memory Buffer is %s\n",
	       (cmbsz & 0x00000010) ? "Supported" : "Not supported");
	printf("\tRead Data Support        (RDS): Read Data and metadata transfer in Controller Memory Buffer is %s\n",
	       (cmbsz & 0x00000008) ? "Supported" : "Not supported");
	printf("\tPRP SGL List Support   (LISTS): PRP/SG Lists in Controller Memory Buffer is %s\n",
	       (cmbsz & 0x00000004) ? "Supported" : "Not supported");
	printf("\tCompletion Queue Support (CQS): Admin and I/O Completion Queues in Controller Memory Buffer is %s\n",
	       (cmbsz & 0x00000002) ? "Supported" : "Not supported");
	printf("\tSubmission Queue Support (SQS): Admin and I/O Submission Queues in Controller Memory Buffer is %s\n\n",
	       (cmbsz & 0x00000001) ? "Supported" : "Not supported");
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
	printf("\tActive Boot Partition ID      (ABPID): %u\n",
		(bpinfo & 0x80000000) >> 31);
	stdout_registers_bpinfo_brs((bpinfo & 0x03000000) >> 24);
	printf("\tBoot Partition Size            (BPSZ): %u\n",
		bpinfo & 0x00007fff);
}

static void stdout_registers_bprsel(__u32 bprsel)
{
	printf("\tBoot Partition Identifier      (BPID): %u\n",
		(bprsel & 0x80000000) >> 31);
	printf("\tBoot Partition Read Offset    (BPROF): %x\n",
		(bprsel & 0x3ffffc00) >> 10);
	printf("\tBoot Partition Read Size      (BPRSZ): %x\n",
		bprsel & 0x000003ff);
}

static void stdout_registers_bpmbl(uint64_t bpmbl)
{

	printf("\tBoot Partition Memory Buffer Base Address (BMBBA): %"PRIx64"\n",
		bpmbl);
}

static void stdout_registers_cmbmsc(uint64_t cmbmsc)
{
	printf("\tController Base Address         (CBA): %" PRIx64 "\n",
			(cmbmsc & 0xfffffffffffff000) >> 12);
	printf("\tController Memory Space Enable (CMSE): %" PRIx64 "\n",
			(cmbmsc & 0x0000000000000002) >> 1);
	printf("\tCapabilities Registers Enabled  (CRE): CMBLOC and "\
	       "CMBSZ registers are%senabled\n\n",
		(cmbmsc & 0x0000000000000001) ? " " : " NOT ");
}

static void stdout_registers_cmbsts(__u32 cmbsts)
{
	printf("\tController Base Address Invalid (CBAI): %x\n\n",
		(cmbsts & 0x00000001));
}

static void stdout_registers_pmrcap(__u32 pmrcap)
{
	printf("\tController Memory Space Supported                   (CMSS): "\
	       "Referencing PMR with host supplied addresses is %s\n",
	       ((pmrcap & 0x01000000) >> 24) ? "Supported" : "Not Supported");
	printf("\tPersistent Memory Region Timeout                   (PMRTO): %x\n",
		(pmrcap & 0x00ff0000) >> 16);
	printf("\tPersistent Memory Region Write Barrier Mechanisms (PMRWBM): %x\n",
		(pmrcap & 0x00003c00) >> 10);
	printf("\tPersistent Memory Region Time Units                (PMRTU): PMR time unit is %s\n",
		(pmrcap & 0x00000300) >> 8 ? "minutes" : "500 milliseconds");
	printf("\tBase Indicator Register                              (BIR): %x\n",
		(pmrcap & 0x000000e0) >> 5);
	printf("\tWrite Data Support                                   (WDS): Write data to the PMR is %s\n",
		(pmrcap & 0x00000010) ? "supported" : "not supported");
	printf("\tRead Data Support                                    (RDS): Read data from the PMR is %s\n",
		(pmrcap & 0x00000008) ? "supported" : "not supported");
}

static void stdout_registers_pmrctl(__u32 pmrctl)
{
	printf("\tEnable (EN): PMR is %s\n", (pmrctl & 0x00000001) ?
		"READY" : "Disabled");
}

static void stdout_registers_pmrsts(__u32 pmrsts, __u32 pmrctl)
{
	printf("\tController Base Address Invalid (CBAI): %x\n",
		(pmrsts & 0x00001000) >> 12);
	printf("\tHealth Status                   (HSTS): %s\n",
		nvme_register_pmr_hsts_to_string((pmrsts & 0x00000e00) >> 9));
	printf("\tNot Ready                       (NRDY): "\
		"The Persistent Memory Region is %s to process "\
		"PCI Express memory read and write requests\n",
			(pmrsts & 0x00000100) == 0 && (pmrctl & 0x00000001) ?
				"READY" : "Not Ready");
	printf("\tError                            (ERR): %x\n", (pmrsts & 0x000000ff));
}

static void stdout_registers_pmrebs(__u32 pmrebs)
{
	printf("\tPMR Elasticity Buffer Size Base  (PMRWBZ): %x\n", (pmrebs & 0xffffff00) >> 8);
	printf("\tRead Bypass Behavior                     : memory reads not conflicting with memory writes "\
	       "in the PMR Elasticity Buffer %s bypass those memory writes\n",
	       (pmrebs & 0x00000010) ? "SHALL" : "MAY");
	printf("\tPMR Elasticity Buffer Size Units (PMRSZU): %s\n",
		nvme_register_pmr_pmrszu_to_string(pmrebs & 0x0000000f));
}

static void stdout_registers_pmrswtp(__u32 pmrswtp)
{
	printf("\tPMR Sustained Write Throughput       (PMRSWTV): %x\n",
		(pmrswtp & 0xffffff00) >> 8);
	printf("\tPMR Sustained Write Throughput Units (PMRSWTU): %s/second\n",
		nvme_register_pmr_pmrszu_to_string(pmrswtp & 0x0000000f));
}

static void stdout_registers_pmrmscl(uint32_t pmrmscl)
{
	printf("\tController Base Address         (CBA): %#x\n",
		(pmrmscl & 0xfffff000) >> 12);
	printf("\tController Memory Space Enable (CMSE): %#x\n\n",
		(pmrmscl & 0x00000002) >> 1);
}

static void stdout_registers_pmrmscu(uint32_t pmrmscu)
{
	printf("\tController Base Address         (CBA): %#x\n",
		pmrmscu);
}

void stdout_ctrl_registers(void *bar, bool fabrics)
{
	uint64_t cap, asq, acq, bpmbl, cmbmsc;
	uint32_t vs, intms, intmc, cc, csts, nssr, crto, aqa, cmbsz, cmbloc, bpinfo,
		 bprsel, cmbsts, pmrcap, pmrctl, pmrsts, pmrebs, pmrswtp,
		 pmrmscl, pmrmscu;
	int human = stdout_print_ops.flags & VERBOSE;

	cap = mmio_read64(bar + NVME_REG_CAP);
	vs = mmio_read32(bar + NVME_REG_VS);
	intms = mmio_read32(bar + NVME_REG_INTMS);
	intmc = mmio_read32(bar + NVME_REG_INTMC);
	cc = mmio_read32(bar + NVME_REG_CC);
	csts = mmio_read32(bar + NVME_REG_CSTS);
	nssr = mmio_read32(bar + NVME_REG_NSSR);
	crto = mmio_read32(bar + NVME_REG_CRTO);
	aqa = mmio_read32(bar + NVME_REG_AQA);
	asq = mmio_read64(bar + NVME_REG_ASQ);
	acq = mmio_read64(bar + NVME_REG_ACQ);
	cmbloc = mmio_read32(bar + NVME_REG_CMBLOC);
	cmbsz = mmio_read32(bar + NVME_REG_CMBSZ);
	bpinfo = mmio_read32(bar + NVME_REG_BPINFO);
	bprsel = mmio_read32(bar + NVME_REG_BPRSEL);
	bpmbl = mmio_read64(bar + NVME_REG_BPMBL);
	cmbmsc = mmio_read64(bar + NVME_REG_CMBMSC);
	cmbsts = mmio_read32(bar + NVME_REG_CMBSTS);
	pmrcap = mmio_read32(bar + NVME_REG_PMRCAP);
	pmrctl = mmio_read32(bar + NVME_REG_PMRCTL);
	pmrsts = mmio_read32(bar + NVME_REG_PMRSTS);
	pmrebs = mmio_read32(bar + NVME_REG_PMREBS);
	pmrswtp = mmio_read32(bar + NVME_REG_PMRSWTP);
	pmrmscl = mmio_read32(bar + NVME_REG_PMRMSCL);
	pmrmscu = mmio_read32(bar + NVME_REG_PMRMSCU);

	if (human) {
		if (cap != 0xffffffff) {
			printf("cap     : %"PRIx64"\n", cap);
			stdout_registers_cap((struct nvme_bar_cap *)&cap);
		}
		if (vs != 0xffffffff) {
			printf("version : %x\n", vs);
			stdout_registers_version(vs);
		}
		if (cc != 0xffffffff) {
			printf("cc      : %x\n", cc);
			stdout_registers_cc(cc);
		}
		if (csts != 0xffffffff) {
			printf("csts    : %x\n", csts);
			stdout_registers_csts(csts);
		}
		if (nssr != 0xffffffff) {
			printf("nssr    : %x\n", nssr);
			printf("\tNVM Subsystem Reset Control (NSSRC): %u\n\n",
				nssr);
		}
		if (crto != 0xffffffff) {
			printf("crto    : %x\n", crto);
			stdout_registers_crto(crto);
		}
		if (!fabrics) {
			printf("intms   : %x\n", intms);
			printf("\tInterrupt Vector Mask Set (IVMS): %x\n\n",
					intms);

			printf("intmc   : %x\n", intmc);
			printf("\tInterrupt Vector Mask Clear (IVMC): %x\n\n",
					intmc);
			printf("aqa     : %x\n", aqa);
			stdout_registers_aqa(aqa);

			printf("asq     : %"PRIx64"\n", asq);
			printf("\tAdmin Submission Queue Base (ASQB): %"PRIx64"\n\n",
					asq);

			printf("acq     : %"PRIx64"\n", acq);
			printf("\tAdmin Completion Queue Base (ACQB): %"PRIx64"\n\n",
					acq);

			printf("cmbloc  : %x\n", cmbloc);
			stdout_registers_cmbloc(cmbloc, cmbsz);

			printf("cmbsz   : %x\n", cmbsz);
			stdout_registers_cmbsz(cmbsz);

			printf("bpinfo  : %x\n", bpinfo);
			stdout_registers_bpinfo(bpinfo);

			printf("bprsel  : %x\n", bprsel);
			stdout_registers_bprsel(bprsel);

			printf("bpmbl   : %"PRIx64"\n", bpmbl);
			stdout_registers_bpmbl(bpmbl);

			printf("cmbmsc	: %"PRIx64"\n", cmbmsc);
			stdout_registers_cmbmsc(cmbmsc);

			printf("cmbsts	: %x\n", cmbsts);
			stdout_registers_cmbsts(cmbsts);

			printf("pmrcap  : %x\n", pmrcap);
			stdout_registers_pmrcap(pmrcap);

			printf("pmrctl  : %x\n", pmrctl);
			stdout_registers_pmrctl(pmrctl);

			printf("pmrsts  : %x\n", pmrsts);
			stdout_registers_pmrsts(pmrsts, pmrctl);

			printf("pmrebs  : %x\n", pmrebs);
			stdout_registers_pmrebs(pmrebs);

			printf("pmrswtp : %x\n", pmrswtp);
			stdout_registers_pmrswtp(pmrswtp);

			printf("pmrmscl	: %#x\n", pmrmscl);
			stdout_registers_pmrmscl(pmrmscl);

			printf("pmrmscu	: %#x\n", pmrmscu);
			stdout_registers_pmrmscu(pmrmscu);
		}
	} else {
		if (cap != 0xffffffff)
			printf("cap     : %"PRIx64"\n", cap);
		if (vs != 0xffffffff)
			printf("version : %x\n", vs);
		if (cc != 0xffffffff)
			printf("cc      : %x\n", cc);
		if (csts != 0xffffffff)
			printf("csts    : %x\n", csts);
		if (nssr != 0xffffffff)
			printf("nssr    : %x\n", nssr);
		if (crto != 0xffffffff)
			printf("crto    : %x\n", crto);
		if (!fabrics) {
			printf("intms   : %x\n", intms);
			printf("intmc   : %x\n", intmc);
			printf("aqa     : %x\n", aqa);
			printf("asq     : %"PRIx64"\n", asq);
			printf("acq     : %"PRIx64"\n", acq);
			printf("cmbloc  : %x\n", cmbloc);
			printf("cmbsz   : %x\n", cmbsz);
			printf("bpinfo  : %x\n", bpinfo);
			printf("bprsel  : %x\n", bprsel);
			printf("bpmbl   : %"PRIx64"\n", bpmbl);
			printf("cmbmsc	: %"PRIx64"\n", cmbmsc);
			printf("cmbsts	: %x\n", cmbsts);
			printf("pmrcap  : %x\n", pmrcap);
			printf("pmrctl  : %x\n", pmrctl);
			printf("pmrsts  : %x\n", pmrsts);
			printf("pmrebs  : %x\n", pmrebs);
			printf("pmrswtp : %x\n", pmrswtp);
			printf("pmrmscl	: %#x\n", pmrmscl);
			printf("pmrmscu	: %#x\n", pmrmscu);
		}
	}
}

static void stdout_single_property(int offset, uint64_t value64)
{
	int human = stdout_print_ops.flags & VERBOSE;

	uint32_t value32;

	if (!human) {
		if (nvme_is_64bit_reg(offset))
			printf("property: 0x%02x (%s), value: %"PRIx64"\n",
				offset, nvme_register_to_string(offset),
				value64);
		else
			printf("property: 0x%02x (%s), value: %x\n", offset,
				   nvme_register_to_string(offset),
				   (uint32_t) value64);

		return;
	}

	value32 = (uint32_t) value64;

	switch (offset) {
	case NVME_REG_CAP:
		printf("cap : %"PRIx64"\n", value64);
		stdout_registers_cap((struct nvme_bar_cap *)&value64);
		break;
	case NVME_REG_VS:
		printf("version : %x\n", value32);
		stdout_registers_version(value32);
		break;
	case NVME_REG_CC:
		printf("cc : %x\n", value32);
		stdout_registers_cc(value32);
		break;
	case NVME_REG_CSTS:
		printf("csts : %x\n", value32);
		stdout_registers_csts(value32);
		break;
	case NVME_REG_NSSR:
		printf("nssr : %x\n", value32);
		printf("\tNVM Subsystem Reset Control (NSSRC): %u\n\n",
			value32);
		break;
	case NVME_REG_CRTO:
		printf("crto : %x\n", value32);
		stdout_registers_crto(value32);
		break;
	default:
		printf("unknown property: 0x%02x (%s), value: %"PRIx64"\n",
			offset, nvme_register_to_string(offset), value64);
		break;
	}
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

static void stdout_id_ctrl_cmic(__u8 cmic)
{
	__u8 rsvd = (cmic & 0xF0) >> 4;
	__u8 ana = (cmic & 0x8) >> 3;
	__u8 sriov = (cmic & 0x4) >> 2;
	__u8 mctl = (cmic & 0x2) >> 1;
	__u8 mp = cmic & 0x1;

	if (rsvd)
		printf("  [7:4] : %#x\tReserved\n", rsvd);
	printf("  [3:3] : %#x\tANA %ssupported\n", ana, ana ? "" : "not ");
	printf("  [2:2] : %#x\t%s\n", sriov, sriov ? "SR-IOV" : "PCI");
	printf("  [1:1] : %#x\t%s Controller\n",
		mctl, mctl ? "Multi" : "Single");
	printf("  [0:0] : %#x\t%s Port\n", mp, mp ? "Multi" : "Single");
	printf("\n");
}

static void stdout_id_ctrl_oaes(__le32 ctrl_oaes)
{
	__u32 oaes = le32_to_cpu(ctrl_oaes);
	__u32 disc = (oaes >> 31) & 0x1;
	__u32 rsvd0 = (oaes & 0x70000000) >> 28;
	__u32 zicn = (oaes & 0x08000000) >> 27;
	__u32 rsvd1 = (oaes & 0x07FF0000) >> 16;
	__u32 normal_shn = (oaes >> 15) & 0x1;
	__u32 egealpcn = (oaes & 0x4000) >> 14;
	__u32 lbasin = (oaes & 0x2000) >> 13;
	__u32 plealcn = (oaes & 0x1000) >> 12;
	__u32 anacn = (oaes & 0x800) >> 11;
	__u32 rsvd2 = (oaes >> 10) & 0x1;
	__u32 fan = (oaes & 0x200) >> 9;
	__u32 nace = (oaes & 0x100) >> 8;
	__u32 rsvd3 = oaes & 0xFF;

	printf("  [31:31] : %#x\tDiscovery Log Change Notice %sSupported\n",
			disc, disc ? "" : "Not ");
	if (rsvd0)
		printf("  [30:28] : %#x\tReserved\n", rsvd0);
	printf("  [27:27] : %#x\tZone Descriptor Changed Notices %sSupported\n",
			zicn, zicn ? "" : "Not ");
	if (rsvd1)
		printf("  [26:16] : %#x\tReserved\n", rsvd1);
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
	if (rsvd2)
		printf("  [10:10] : %#x\tReserved\n", rsvd2);
	printf("  [9:9] : %#x\tFirmware Activation Notices %sSupported\n",
		fan, fan ? "" : "Not ");
	printf("  [8:8] : %#x\tNamespace Attribute Changed Event %sSupported\n",
		nace, nace ? "" : "Not ");
	if (rsvd3)
		printf("  [7:0] : %#x\tReserved\n", rsvd3);
	printf("\n");
}

static void stdout_id_ctrl_ctratt(__le32 ctrl_ctratt)
{
	__u32 ctratt = le32_to_cpu(ctrl_ctratt);
	__u32 rsvd20 = (ctratt >> 20);
	__u32 fdps = (ctratt >> 19) & 0x1;
	__u32 rsvd16 = (ctratt >> 16) & 0x7;
	__u32 elbas = (ctratt >> 15) & 0x1;
	__u32 delnvmset = (ctratt >> 14) & 0x1;
	__u32 delegrp = (ctratt >> 13) & 0x1;
	__u32 vcap = (ctratt >> 12) & 0x1;
	__u32 fcap = (ctratt >> 11) & 0x1;
	__u32 mds = (ctratt >> 10) & 0x1;
	__u32 hostid128 = (ctratt & NVME_CTRL_CTRATT_128_ID) >> 0;
	__u32 psp = (ctratt & NVME_CTRL_CTRATT_NON_OP_PSP) >> 1;
	__u32 sets = (ctratt & NVME_CTRL_CTRATT_NVM_SETS) >> 2;
	__u32 rrl = (ctratt & NVME_CTRL_CTRATT_READ_RECV_LVLS) >> 3;
	__u32 eg = (ctratt & NVME_CTRL_CTRATT_ENDURANCE_GROUPS) >> 4;
	__u32 iod = (ctratt & NVME_CTRL_CTRATT_PREDICTABLE_LAT) >> 5;
	__u32 tbkas = (ctratt & NVME_CTRL_CTRATT_TBKAS) >> 6;
	__u32 ng = (ctratt & NVME_CTRL_CTRATT_NAMESPACE_GRANULARITY) >> 7;
	__u32 sqa = (ctratt & NVME_CTRL_CTRATT_SQ_ASSOCIATIONS) >> 8;
	__u32 uuidlist = (ctratt & NVME_CTRL_CTRATT_UUID_LIST) >> 9;

	if (rsvd20)
		printf(" [31:20] : %#x\tReserved\n", rsvd20);
	printf("  [19:19] : %#x\tFlexible Data Placement %sSupported\n",
		fdps, fdps ? "" : "Not ");
	if (rsvd16)
		printf("  [18:16] : %#x\tReserved\n", rsvd16);
	printf("  [15:15] : %#x\tExtended LBA Formats %sSupported\n",
		elbas, elbas ? "" : "Not ");
	printf("  [14:14] : %#x\tDelete NVM Set %sSupported\n",
		delnvmset, delnvmset ? "" : "Not ");
	printf("  [13:13] : %#x\tDelete Endurance Group %sSupported\n",
		delegrp, delegrp ? "" : "Not ");
	printf("  [12:12] : %#x\tVariable Capacity Management %sSupported\n",
		vcap, vcap ? "" : "Not ");
	printf("  [11:11] : %#x\tFixed Capacity Management %sSupported\n",
		fcap, fcap ? "" : "Not ");
	printf("  [10:10] : %#x\tMulti Domain Subsystem %sSupported\n",
		mds, mds ? "" : "Not ");
	printf("  [9:9] : %#x\tUUID List %sSupported\n",
		uuidlist, uuidlist ? "" : "Not ");
	printf("  [8:8] : %#x\tSQ Associations %sSupported\n",
		sqa, sqa ? "" : "Not ");
	printf("  [7:7] : %#x\tNamespace Granularity %sSupported\n",
		ng, ng ? "" : "Not ");
	printf("  [6:6] : %#x\tTraffic Based Keep Alive %sSupported\n",
		tbkas, tbkas ? "" : "Not ");
	printf("  [5:5] : %#x\tPredictable Latency Mode %sSupported\n",
		iod, iod ? "" : "Not ");
	printf("  [4:4] : %#x\tEndurance Groups %sSupported\n",
		eg, eg ? "" : "Not ");
	printf("  [3:3] : %#x\tRead Recovery Levels %sSupported\n",
		rrl, rrl ? "" : "Not ");
	printf("  [2:2] : %#x\tNVM Sets %sSupported\n",
		sets, sets ? "" : "Not ");
	printf("  [1:1] : %#x\tNon-Operational Power State Permissive %sSupported\n",
		psp, psp ? "" : "Not ");
	printf("  [0:0] : %#x\t128-bit Host Identifier %sSupported\n",
		hostid128, hostid128 ? "" : "Not ");
	printf("\n");
}

static void stdout_id_ctrl_cntrltype(__u8 cntrltype)
{
	__u8 rsvd = (cntrltype & 0xFC) >> 2;
	__u8 cntrl = cntrltype & 0x3;

	static const char *type[] = {
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
	printf("  [6:0] : %#x\tVPD Write Cycles Remaining \n", vwcr);
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
	__u16 rsvd = (oacs & 0xF800) >> 11;
	__u16 lock = (oacs >> 10) & 0x1;
	__u16 glbas = (oacs & 0x200) >> 9;
	__u16 dbc = (oacs & 0x100) >> 8;
	__u16 vir = (oacs & 0x80) >> 7;
	__u16 nmi = (oacs & 0x40) >> 6;
	__u16 dir = (oacs & 0x20) >> 5;
	__u16 sft = (oacs & 0x10) >> 4;
	__u16 nsm = (oacs & 0x8) >> 3;
	__u16 fwc = (oacs & 0x4) >> 2;
	__u16 fmt = (oacs & 0x2) >> 1;
	__u16 sec = oacs & 0x1;

	if (rsvd)
		printf(" [15:11] : %#x\tReserved\n", rsvd);
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
	printf(" [15:0] : %ld °C (%u K)\tWarning Composite Temperature Threshold (WCTEMP)\n",
	       kelvin_to_celsius(le16_to_cpu(wctemp)), le16_to_cpu(wctemp));
	printf("\n");
}

static void stdout_id_ctrl_cctemp(__le16 cctemp)
{
	printf(" [15:0] : %ld °C (%u K)\tCritical Composite Temperature Threshold (CCTEMP)\n",
	       kelvin_to_celsius(le16_to_cpu(cctemp)), le16_to_cpu(cctemp));
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
	printf(" [15:0] : %ld °C (%u K)\tMinimum Thermal Management Temperature (MNTMT)\n",
	       kelvin_to_celsius(le16_to_cpu(mntmt)), le16_to_cpu(mntmt));
	printf("\n");
}

static void stdout_id_ctrl_mxtmt(__le16 mxtmt)
{
	printf(" [15:0] : %ld °C (%u K)\tMaximum Thermal Management Temperature (MXTMT)\n",
	       kelvin_to_celsius(le16_to_cpu(mxtmt)), le16_to_cpu(mxtmt));
	printf("\n");
}

static void stdout_id_ctrl_sanicap(__le32 ctrl_sanicap)
{
	__u32 sanicap = le32_to_cpu(ctrl_sanicap);
	__u32 rsvd = (sanicap & 0x1FFFFFF8) >> 3;
	__u32 owr = (sanicap & 0x4) >> 2;
	__u32 ber = (sanicap & 0x2) >> 1;
	__u32 cer = sanicap & 0x1;
	__u32 ndi = (sanicap & 0x20000000) >> 29;
	__u32 nodmmas = (sanicap & 0xC0000000) >> 30;

	static const char *modifies_media[] = {
		"Additional media modification after sanitize operation completes successfully is not defined",
		"Media is not additionally modified after sanitize operation completes successfully",
		"Media is additionally modified after sanitize operation completes successfully",
		"Reserved"
	};

	printf("  [31:30] : %#x\t%s\n", nodmmas, modifies_media[nodmmas]);
	printf("  [29:29] : %#x\tNo-Deallocate After Sanitize bit in Sanitize command %sSupported\n",
		ndi, ndi ? "Not " : "");
	if (rsvd)
		printf("  [28:3] : %#x\tReserved\n", rsvd);
	printf("    [2:2] : %#x\tOverwrite Sanitize Operation %sSupported\n",
		owr, owr ? "" : "Not ");
	printf("    [1:1] : %#x\tBlock Erase Sanitize Operation %sSupported\n",
		ber, ber ? "" : "Not ");
	printf("    [0:0] : %#x\tCrypto Erase Sanitize Operation %sSupported\n",
		cer, cer ? "" : "Not ");
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
	__u16 rsvd = (oncs & 0xFE00) >> 9;
	__u16 copy = (oncs & 0x100) >> 8;
	__u16 vrfy = (oncs & 0x80) >> 7;
	__u16 tmst = (oncs & 0x40) >> 6;
	__u16 resv = (oncs & 0x20) >> 5;
	__u16 save = (oncs & 0x10) >> 4;
	__u16 wzro = (oncs & 0x8) >> 3;
	__u16 dsms = (oncs & 0x4) >> 2;
	__u16 wunc = (oncs & 0x2) >> 1;
	__u16 cmp = oncs & 0x1;

	if (rsvd)
		printf(" [15:9] : %#x\tReserved\n", rsvd);
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
	__u8 bcnsid = (fna & 0x8) >> 3;
	__u8 cese = (fna & 0x4) >> 2;
	__u8 cens = (fna & 0x2) >> 1;
	__u8 fmns = fna & 0x1;
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

	static const char *flush_behavior[] = {
		"Support for the NSID field set to FFFFFFFFh is not indicated",
		"Reserved",
		"The Flush command does not support NSID set to FFFFFFFFh",
		"The Flush command supports NSID set to FFFFFFFFh"
	};

	if (rsvd)
		printf("  [7:3] : %#x\tReserved\n", rsvd);
	printf("  [2:1] : %#x\t%s\n", flush, flush_behavior[flush]);
	printf("  [0:0] : %#x\tVolatile Write Cache %sPresent\n",
		vwcp, vwcp ? "" : "Not ");
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
	__u16 rsvd = (ocfs & 0xfffc) >> 2;
	__u8 copy_fmt_1 = (ocfs >> 1) & 0x1;
	__u8 copy_fmt_0 = ocfs & 0x1;
	if (rsvd)
		printf("  [15:2] : %#x\tReserved\n", rsvd);
	printf("  [1:1] : %#x\tController Copy Format 1h %sSupported\n",
		copy_fmt_1, copy_fmt_1 ? "" : "Not ");
	printf("  [0:0] : %#x\tController Copy Format 0h %sSupported\n",
		copy_fmt_0, copy_fmt_0 ? "" : "Not ");
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

static void stdout_id_ns_nsfeat(__u8 nsfeat)
{
	__u8 rsvd = (nsfeat & 0xE0) >> 5;
	__u8 ioopt = (nsfeat & 0x10) >> 4;
	__u8 uidreuse = (nsfeat & 0x8) >> 3;
	__u8 dulbe = (nsfeat & 0x4) >> 2;
	__u8 na = (nsfeat & 0x2) >> 1;
	__u8 thin = nsfeat & 0x1;
	if (rsvd)
		printf("  [7:5] : %#x\tReserved\n", rsvd);
	printf("  [4:4] : %#x\tNPWG, NPWA, NPDG, NPDA, and NOWS are %sSupported\n",
		ioopt, ioopt ? "" : "Not ");
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
	__u8 rsvd = (nmic & 0xFE) >> 1;
	__u8 mp = nmic & 0x1;
	if (rsvd)
		printf("  [7:1] : %#x\tReserved\n", rsvd);
	printf("  [0:0] : %#x\tNamespace Multipath %sCapable\n",
		mp, mp ? "" : "Not ");
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
		printf("nsze    : %#"PRIx64"\n", le64_to_cpu(ns->nsze));
		printf("ncap    : %#"PRIx64"\n", le64_to_cpu(ns->ncap));
		printf("nuse    : %#"PRIx64"\n", le64_to_cpu(ns->nuse));
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
		if (ns->nsfeat & 0x10) {
			printf("npwg    : %u\n", le16_to_cpu(ns->npwg));
			printf("npwa    : %u\n", le16_to_cpu(ns->npwa));
			printf("npdg    : %u\n", le16_to_cpu(ns->npdg));
			printf("npda    : %u\n", le16_to_cpu(ns->npda));
			printf("nows    : %u\n", le16_to_cpu(ns->nows));
		}
		printf("mssrl   : %u\n", le16_to_cpu(ns->mssrl));
		printf("mcl     : %u\n", le32_to_cpu(ns->mcl));
		printf("msrc    : %u\n", ns->msrc);
	}
	printf("nulbaf  : %u\n", ns->nulbaf);
	if (!cap_only) {
		printf("anagrpid: %u\n", le32_to_cpu(ns->anagrpid));
		printf("nsattr	: %u\n", ns->nsattr);
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
	__u8 rsvd1 = (nstat & 0xfe) >> 1;
	__u8 nrdy = nstat & 0x1;
	if (rsvd1)
		printf("  [7:1] : %#x\tReserved\n", rsvd1);
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
}

static void stdout_id_ns_descs(void *data, unsigned int nsid)
{
	int pos, len = 0;
	int i;
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

		switch (cur->nidt) {
		case NVME_NIDT_EUI64:
			memcpy(eui64, data + pos + sizeof(*cur), sizeof(eui64));
			printf("eui64   : ");
			for (i = 0; i < 8; i++)
				printf("%02x", eui64[i]);
			printf("\n");
			len = sizeof(eui64);
			break;
		case NVME_NIDT_NGUID:
			memcpy(nguid, data + pos + sizeof(*cur), sizeof(nguid));
			printf("nguid   : ");
			for (i = 0; i < 16; i++)
				printf("%02x", nguid[i]);
			printf("\n");
			len = sizeof(nguid);
			break;
		case NVME_NIDT_UUID:
			memcpy(uuid, data + pos + sizeof(*cur), 16);
			nvme_uuid_to_string(uuid, uuid_str);
			printf("uuid    : %s\n", uuid_str);
			len = sizeof(uuid);
			break;
		case NVME_NIDT_CSI:
			memcpy(&csi, data + pos + sizeof(*cur), 1);
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
	printf("cntrltype : %d\n", ctrl->cntrltype);
	if (human)
		stdout_id_ctrl_cntrltype(ctrl->cntrltype);
	printf("fguid     : %s\n", util_uuid_to_string(ctrl->fguid));
	printf("crdt1     : %u\n", le16_to_cpu(ctrl->crdt1));
	printf("crdt2     : %u\n", le16_to_cpu(ctrl->crdt2));
	printf("crdt3     : %u\n", le16_to_cpu(ctrl->crdt3));
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
	printf("megcap    : %s\n",
		uint128_t_to_l10n_string(le128_to_cpu(ctrl->megcap)));
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

static void stdout_id_ctrl_nvm(struct nvme_id_ctrl_nvm *ctrl_nvm)
{
	printf("NVMe Identify Controller NVM:\n");
	printf("vsl    : %u\n", ctrl_nvm->vsl);
	printf("wzsl   : %u\n", ctrl_nvm->wzsl);
	printf("wusl   : %u\n", ctrl_nvm->wusl);
	printf("dmrl   : %u\n", ctrl_nvm->dmrl);
	printf("dmrsl  : %u\n", le32_to_cpu(ctrl_nvm->dmrsl));
	printf("dmsl   : %"PRIu64"\n", le64_to_cpu(ctrl_nvm->dmsl));
}

static void stdout_nvm_id_ns_pic(__u8 pic)
{
	__u8 rsvd = (pic & 0xF8) >> 3;
	__u8 stcrs = (pic & 0x3) >> 2;
	__u8 pic_16bpistm = (pic & 0x2) >> 1;
	__u8 pic_16bpists = pic & 0x1;

	if (rsvd)
		printf("  [7:3] : %#x\tReserved\n", rsvd);
	printf("  [2:2] : %#x\tStorage Tag Check Read Support\n", stcrs);
	printf("  [1:1] : %#x\t16b Guard Protection Information Storage Tag Mask\n",
		pic_16bpistm);
	printf("  [0:0] : %#x\t16b Guard Protection Information Storage Tag Support\n",
		pic_16bpists);
	printf("\n");
}

static void stdout_nvm_id_ns(struct nvme_nvm_id_ns *nvm_ns, unsigned int nsid,
			     struct nvme_id_ns *ns, unsigned int lba_index,
			     bool cap_only)
{
	int i, verbose = stdout_print_ops.flags & VERBOSE;
	__u32 elbaf;
	int pif, sts;
	char *in_use = "(in use)";

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

	for (i = 0; i <= ns->nlbaf + ns->nulbaf; i++) {
		elbaf = le32_to_cpu(nvm_ns->elbaf[i]);
		pif = (elbaf >> 7) & 0x3;
		sts = elbaf & 0x7f;
		if (verbose)
			printf("Extended LBA Format %2d : Protection Information Format: "
				"%s(%d) - Storage Tag Size (MSB): %-2d %s\n",
				i, pif == 3 ? "Reserved" :
					pif == 2 ? "64b Guard" :
					pif == 1 ? "32b Guard" : "16b Guard",
					pif, sts, i == (ns->flbas & 0xf) ? in_use : "");
		else
			printf("elbaf %2d : pif:%d sts:%-2d %s\n", i,
				pif, sts, i == (ns->flbas & 0xf) ? in_use : "");
	}
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
		if (ns->mar == 0xffffffff) {
			printf("mar     : No Active Resource Limit\n");
		} else {
			printf("mar     : %u\tActive Resources\n", le32_to_cpu(ns->mar) + 1);
		}
	} else {
		printf("mar     : %#x\n", le32_to_cpu(ns->mar));
	}

	if (human) {
		if (ns->mor == 0xffffffff) {
			printf("mor     : No Open Resource Limit\n");
		} else {
			printf("mor     : %u\tOpen Resources\n", le32_to_cpu(ns->mor) + 1);
		}
	} else {
		printf("mor     : %#x\n", le32_to_cpu(ns->mor));
	}

	stdout_zns_id_ns_recommended_limit(ns->rrl,  human, "rrl ");
	stdout_zns_id_ns_recommended_limit(ns->frl,  human, "frl ");
	stdout_zns_id_ns_recommended_limit(ns->rrl1, human, "rrl1");
	stdout_zns_id_ns_recommended_limit(ns->rrl2, human, "rrl2");
	stdout_zns_id_ns_recommended_limit(ns->rrl3, human, "rrl3");
	stdout_zns_id_ns_recommended_limit(ns->frl,  human, "frl1");
	stdout_zns_id_ns_recommended_limit(ns->frl,  human, "frl2");
	stdout_zns_id_ns_recommended_limit(ns->frl,  human, "frl3");

	printf("numzrwa : %#x\n", le32_to_cpu(ns->numzrwa));
	printf("zrwafg  : %u\n", le16_to_cpu(ns->zrwafg));
	printf("zrwasz  : %u\n", le16_to_cpu(ns->zrwasz));
	if (human) {
		printf("zrwacap : %u\tZone Random Write Area Capability\n", ns->zrwacap);
		stdout_zns_id_ns_zrwacap(ns->zrwacap);
	} else {
		printf("zrwacap : %u\n", ns->zrwacap);
	}

	for (i = 0; i <= id_ns->nlbaf; i++){
		if (human)
			printf("LBA Format Extension %2d : Zone Size: 0x%"PRIx64" LBAs - "
					"Zone Descriptor Extension Size: %-1d bytes%s\n",
				i, le64_to_cpu(ns->lbafe[i].zsze), ns->lbafe[i].zdes << 6,
				i == lbaf ? " (in use)" : "");
		else
			printf("lbafe %2d: zsze:0x%"PRIx64" zdes:%u%s\n", i,
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
	int i;

	for (i = 0; i < 1024; i++) {
		if (ns_list->ns[i])
			printf("[%4u]:%#x\n", i, le32_to_cpu(ns_list->ns[i]));
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
	const char *const recommended_limit[4] = {"","1","2","3"};
	printf("Attrs: Zone Descriptor Extension is %sVaild\n",
		(za & NVME_ZNS_ZA_ZDEV)? "" : "Not ");
	if(za & NVME_ZNS_ZA_RZR) {
		printf("       Reset Zone Recommended with Reset Recommended Limit%s\n",
			recommended_limit[(zai&0xd)>>2]);
	}
	if (za & NVME_ZNS_ZA_FZR) {
		printf("       Finish Zone Recommended with Finish Recommended Limit%s\n",
			recommended_limit[zai&0x3]);
	}
	if (za & NVME_ZNS_ZA_ZFC) {
		printf("       Zone Finished by Controller\n");
	}
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
		if(verbose) {
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
		printf("     SCID      : Secondary Controller Identifier : 0x%.04x\n",
				le16_to_cpu(sc_entry[i].scid));
		printf("     PCID      : Primary Controller Identifier   : 0x%.04x\n",
				le16_to_cpu(sc_entry[i].pcid));
		printf("     SCS       : Secondary Controller State      : 0x%.04x (%s)\n",
				sc_entry[i].scs,
				state_desc[sc_entry[i].scs & 0x1]);
		printf("     VFN       : Virtual Function Number         : 0x%.04x\n",
				le16_to_cpu(sc_entry[i].vfn));
		printf("     NVQ       : Num VQ Flex Resources Assigned  : 0x%.04x\n",
				le16_to_cpu(sc_entry[i].nvq));
		printf("     NVI       : Num VI Flex Resources Assigned  : 0x%.04x\n",
				le16_to_cpu(sc_entry[i].nvi));
	}
}

static void stdout_id_ns_granularity_list(const struct nvme_id_ns_granularity_list *glist)
{
	int i;

	printf("Identify Namespace Granularity List:\n");
	printf("   ATTR        : Namespace Granularity Attributes: 0x%x\n",
		glist->attributes);
	printf("   NUMD        : Number of Descriptors           : %d\n",
		glist->num_descriptors);

	/* Number of Descriptors is a 0's based value */
	for (i = 0; i <= glist->num_descriptors; i++) {
		printf("\n     Entry[%2d] :\n", i);
		printf("................\n");
		printf("     NSG       : Namespace Size Granularity     : 0x%"PRIx64"\n",
			le64_to_cpu(glist->entry[i].nszegran));
		printf("     NCG       : Namespace Capacity Granularity : 0x%"PRIx64"\n",
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
		printf("association  : 0x%x %s\n", identifier_association, association);
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
	for (i = 0; i < min(num, 2047); i++) {
		printf("[%4u]:%#x\n", i, le16_to_cpu(endgrp_list->identifier[i]));
	}
}

static void stdout_id_iocs(struct nvme_id_iocs *iocs)
{
	__u16 i;

	for (i = 0; i < ARRAY_SIZE(iocs->iocsc); i++)
		if (iocs->iocsc[i])
			printf("I/O Command Set Combination[%u]:%"PRIx64"\n", i,
				(uint64_t)le64_to_cpu(iocs->iocsc[i]));
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

		printf(" Entry[%2d]   \n", i);
		printf(".................\n");
		printf("error_count	: %"PRIu64"\n",
			le64_to_cpu(err_log[i].error_count));
		printf("sqid		: %d\n", err_log[i].sqid);
		printf("cmdid		: %#x\n", err_log[i].cmdid);
		printf("status_field	: %#x(%s)\n", status,
			nvme_status_to_string(status, false));
		printf("phase_tag	: %#x\n",
			le16_to_cpu(err_log[i].status_field & 0x1));
		printf("parm_err_loc	: %#x\n",
			err_log[i].parm_error_location);
		printf("lba		: %#"PRIx64"\n",
			le64_to_cpu(err_log[i].lba));
		printf("nsid		: %#x\n", err_log[i].nsid);
		printf("vs		: %d\n", err_log[i].vs);
		printf("trtype		: %s\n",
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

static void stdout_changed_ns_list_log(struct nvme_ns_list *log,
				       const char *devname)
{
	__u32 nsid;
	int i;

	if (log->ns[0] != cpu_to_le32(NVME_NSID_ALL)) {
		for (i = 0; i < NVME_ID_NS_LIST_MAX; i++) {
			nsid = le32_to_cpu(log->ns[i]);
			if (nsid == 0)
				break;

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

	if ((effect & NVME_CMD_EFFECTS_CSE_MASK) >> 16 == 0)
		fprintf(stream, "  No command restriction\n");
	else if ((effect & NVME_CMD_EFFECTS_CSE_MASK) >> 16 == 1)
		fprintf(stream, "  No other command for same namespace\n");
	else if ((effect & NVME_CMD_EFFECTS_CSE_MASK) >> 16 == 2)
		fprintf(stream, "  No other command for any namespace\n");
	else
		fprintf(stream, "  Reserved CSE\n");
}

static void stdout_effects_entry(FILE* stream, int admin, int index,
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
				       char* header, int human)
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
		if (admin) {
			stdout_effects_entry(stream, admin, i, effects->acs[i], human);
		}
		else {
			stdout_effects_entry(stream, admin, i,
						   effects->iocs[i], human);
		}
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
	nvme_effects_log_node_t *node;

	list_for_each(list, node, node) {
		stdout_effects_log_page(node->csi, &node->effects);
	}
}

static void stdout_support_log_human(__u32 support, __u8 lid)
{
	const char *set = "supported";
	const char *clr = "not supported";

	printf("  LSUPP is %s\n", (support & 0x1) ? set : clr);
	printf("  IOS is %s\n", ((support >> 0x1) & 0x1) ? set : clr);
	if (lid == NVME_LOG_LID_PERSISTENT_EVENT) {
		printf("  Establish Context and Read 512 Bytes of Header is %s\n",
			((support >> 0x16) & 0x1) ? set : clr);
	}
}

static void stdout_supported_log(struct nvme_supported_log_pages *support_log,
				 const char *devname)
{
	int lid, human = stdout_print_ops.flags& VERBOSE;
	__u32 support = 0;

	printf("Support Log Pages Details for %s:\n", devname);
	for (lid = 0; lid < 256; lid++) {
		support = le32_to_cpu(support_log->lid_support[lid]);
		if (support & 0x1) {
			printf("LID 0x%x - %s\n", lid, nvme_log_to_string(lid));
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

static void stdout_smart_log(struct nvme_smart_log *smart, unsigned int nsid,
			     const char *devname)
{
	__u16 temperature = smart->temperature[1] << 8 | smart->temperature[0];
	int i;
	bool human = stdout_print_ops.flags & VERBOSE;

	printf("Smart Log for NVME device:%s namespace-id:%x\n", devname, nsid);
	printf("critical_warning			: %#x\n",
		smart->critical_warning);

	if (human) {
		printf("      Available Spare[0]             : %d\n", smart->critical_warning & 0x01);
		printf("      Temp. Threshold[1]             : %d\n", (smart->critical_warning & 0x02) >> 1);
		printf("      NVM subsystem Reliability[2]   : %d\n", (smart->critical_warning & 0x04) >> 2);
		printf("      Read-only[3]                   : %d\n", (smart->critical_warning & 0x08) >> 3);
		printf("      Volatile mem. backup failed[4] : %d\n", (smart->critical_warning & 0x10) >> 4);
		printf("      Persistent Mem. RO[5]          : %d\n", (smart->critical_warning & 0x20) >> 5);
	}

	printf("temperature				: %ld °C (%u K)\n",
		kelvin_to_celsius(temperature), temperature);
	printf("available_spare				: %u%%\n",
		smart->avail_spare);
	printf("available_spare_threshold		: %u%%\n",
		smart->spare_thresh);
	printf("percentage_used				: %u%%\n",
		smart->percent_used);
	printf("endurance group critical warning summary: %#x\n",
		smart->endu_grp_crit_warn_sumry);
	printf("Data Units Read				: %s (%s)\n",
		uint128_t_to_l10n_string(le128_to_cpu(smart->data_units_read)),
		uint128_t_to_si_string(le128_to_cpu(smart->data_units_read),
				       1000 * 512));
	printf("Data Units Written			: %s (%s)\n",
		uint128_t_to_l10n_string(le128_to_cpu(smart->data_units_written)),
		uint128_t_to_si_string(le128_to_cpu(smart->data_units_written),
				       1000 * 512));
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
	for (i = 0; i < 8; i++) {
		__s32 temp = le16_to_cpu(smart->temp_sensor[i]);

		if (temp == 0)
			continue;
		printf("Temperature Sensor %d           : %ld °C (%u K)\n",
		       i + 1, kelvin_to_celsius(temp), temp);
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
	static const char *const test_res[] = {
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

	printf("\t[2:0]\t%s\n", str);
	str = "Number of completed passes if most recent operation was overwrite";
	printf("\t[7:3]\t%s:\t%u\n", str,
		(status >> NVME_SANITIZE_SSTAT_COMPLETED_PASSES_SHIFT) &
			NVME_SANITIZE_SSTAT_COMPLETED_PASSES_MASK);

	printf("\t  [8]\t");
	if (status & NVME_SANITIZE_SSTAT_GLOBAL_DATA_ERASED)
		str = "Global Data Erased set: no NS LB in the NVM subsystem "\
			"has been written to and no PMR in the NVM subsystem "\
			"has been enabled";
	else
		str = "Global Data Erased cleared: a NS LB in the NVM "\
			"subsystem has been written to or a PMR in the NVM "\
			"subsystem has been enabled";
	printf("%s\n", str);
}

static void stdout_estimate_sanitize_time(const char *text, uint32_t value)
{
	printf("%s:  %u%s\n", text, value,
		value == 0xffffffff ? " (No time period reported)" : "");
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
}

static void stdout_select_result(__u32 result)
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

	printf( "\tAuto PST Entries");
	printf("\t.................\n");
	for (i = 0; i < ARRAY_SIZE(apst->apst_entry); i++) {
		value = le64_to_cpu(apst->apst_entry[i]);

		printf("\tEntry[%2d]   \n", i);
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
	printf("\tHost Memory Descriptor List Address     (HMDLAU): 0x%x\n",
		le32_to_cpu(hmb->hmdlau));
	printf("\tHost Memory Descriptor List Address     (HMDLAL): 0x%x\n",
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
			printf("\tDirective support \n");
			printf("\t\tIdentify Directive       : %s\n",
				(*field & 0x1) ? "supported" : "not supported");
			printf("\t\tStream Directive         : %s\n",
				(*field & 0x2) ? "supported" : "not supported");
			printf("\t\tData Placement Directive : %s\n",
				(*field & 0x4) ? "supported" : "not supported");
			printf("\tDirective enabled \n");
			printf("\t\tIdentify Directive       : %s\n",
				(*(field + 32) & 0x1) ? "enabled" : "disabled");
			printf("\t\tStream Directive         : %s\n",
				(*(field + 32) & 0x2) ? "enabled" : "disabled");
			printf("\t\tData Placement Directive : %s\n",
				(*(field + 32) & 0x4) ? "enabled" : "disabled");
			printf("\tDirective Persistent Across Controller Level Resets \n");
			printf("\t\tIdentify Directive       : %s\n",
				(*(field + 32) & 0x1) ? "enabled" : "disabled");
			printf("\t\tStream Directive         : %s\n",
				(*(field + 32) & 0x2) ? "enabled" : "disabled");
			printf("\t\tData Placement Directive : %s\n",
				(*(field + 32) & 0x4) ? "enabled" : "disabled");
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
	printf("\tLBA Status Information Poll Interval (LSIPI)  : %u\n", (result >> 16) & 0xffff);
	printf("\tLBA Status Information Report Interval (LSIRI): %u\n", result & 0xffff);
}

static void stdout_plm_config(struct nvme_plm_config *plmcfg)
{
	printf("\tEnable Event          :%04x\n", le16_to_cpu(plmcfg->ee));
	printf("\tDTWIN Reads Threshold :%"PRIu64"\n", le64_to_cpu(plmcfg->dtwinrt));
	printf("\tDTWIN Writes Threshold:%"PRIu64"\n", le64_to_cpu(plmcfg->dtwinwt));
	printf("\tDTWIN Time Threshold  :%"PRIu64"\n", le64_to_cpu(plmcfg->dtwintt));
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
		printf("\t\tType	    : 0x%02x (%s)\n", desc->type,
		       nvme_host_metadata_type_to_string(fid, desc->type));
		printf("\t\tRevision : %d\n", desc->rev);
		printf("\t\tLength   : %d\n", len);
		printf("\t\tValue    : %s\n", val);

		desc = (struct nvme_metadata_element_desc *)&desc->val[desc->len];
	}
}

static void stdout_feature_show_fields(enum nvme_features_id fid,
				       unsigned int result,
				       unsigned char *buf)
{
	__u8 field;
	uint64_t ull;

	switch (fid) {
	case NVME_FEAT_FID_ARBITRATION:
		printf("\tHigh Priority Weight   (HPW): %u\n", ((result & 0xff000000) >> 24) + 1);
		printf("\tMedium Priority Weight (MPW): %u\n", ((result & 0x00ff0000) >> 16) + 1);
		printf("\tLow Priority Weight    (LPW): %u\n", ((result & 0x0000ff00) >> 8) + 1);
		printf("\tArbitration Burst       (AB): ");
		if ((result & 0x00000007) == 7)
			printf("No limit\n");
		else
			printf("%u\n",  1 << (result & 0x00000007));
		break;
	case NVME_FEAT_FID_POWER_MGMT:
		field = (result & 0x000000E0) >> 5;
		printf("\tWorkload Hint (WH): %u - %s\n", field, nvme_feature_wl_hints_to_string(field));
		printf("\tPower State   (PS): %u\n", result & 0x0000001f);
		break;
	case NVME_FEAT_FID_LBA_RANGE:
		field = result & 0x0000003f;
		printf("\tNumber of LBA Ranges (NUM): %u\n", field + 1);
		if (buf)
			stdout_lba_range((struct nvme_lba_range_type *)buf, field);
		break;
	case NVME_FEAT_FID_TEMP_THRESH:
		field = (result & 0x00300000) >> 20;
		printf("\tThreshold Type Select         (THSEL): %u - %s\n", field,
			nvme_feature_temp_type_to_string(field));
		field = (result & 0x000f0000) >> 16;
		printf("\tThreshold Temperature Select (TMPSEL): %u - %s\n",
		       field, nvme_feature_temp_sel_to_string(field));
		printf("\tTemperature Threshold         (TMPTH): %ld °C (%u K)\n",
		       kelvin_to_celsius(result & 0x0000ffff), result & 0x0000ffff);
		break;
	case NVME_FEAT_FID_ERR_RECOVERY:
		printf("\tDeallocated or Unwritten Logical Block Error Enable (DULBE): %s\n",
			((result & 0x00010000) >> 16) ? "Enabled" : "Disabled");
		printf("\tTime Limited Error Recovery                          (TLER): %u ms\n",
			(result & 0x0000ffff) * 100);
		break;
	case NVME_FEAT_FID_VOLATILE_WC:
		printf("\tVolatile Write Cache Enable (WCE): %s\n", (result & 0x00000001) ? "Enabled" : "Disabled");
		break;
	case NVME_FEAT_FID_NUM_QUEUES:
		printf("\tNumber of IO Completion Queues Allocated (NCQA): %u\n", ((result & 0xffff0000) >> 16) + 1);
		printf("\tNumber of IO Submission Queues Allocated (NSQA): %u\n", (result & 0x0000ffff) + 1);
		break;
	case NVME_FEAT_FID_IRQ_COALESCE:
		printf("\tAggregation Time     (TIME): %u usec\n", ((result & 0x0000ff00) >> 8) * 100);
		printf("\tAggregation Threshold (THR): %u\n", (result & 0x000000ff) + 1);
		break;
	case NVME_FEAT_FID_IRQ_CONFIG:
		printf("\tCoalescing Disable (CD): %s\n", ((result & 0x00010000) >> 16) ? "True" : "False");
		printf("\tInterrupt Vector   (IV): %u\n", result & 0x0000ffff);
		break;
	case NVME_FEAT_FID_WRITE_ATOMIC:
		printf("\tDisable Normal (DN): %s\n", (result & 0x00000001) ? "True" : "False");
		break;
	case NVME_FEAT_FID_ASYNC_EVENT:
		printf("\tDiscovery Log Page Change Notices                         : %s\n",
			((result & 0x80000000) >> 31) ? "Send async event" : "Do not send async event");
		printf("\tEndurance Group Event Aggregate Log Change Notices        : %s\n",
			((result & 0x00004000) >> 14) ? "Send async event" : "Do not send async event");
		printf("\tLBA Status Information Notices                            : %s\n",
			((result & 0x00002000) >> 13) ? "Send async event" : "Do not send async event");
		printf("\tPredictable Latency Event Aggregate Log Change Notices    : %s\n",
			((result & 0x00001000) >> 12) ? "Send async event" : "Do not send async event");
		printf("\tAsymmetric Namespace Access Change Notices                : %s\n",
			((result & 0x00000800) >> 11) ? "Send async event" : "Do not send async event");
		printf("\tTelemetry Log Notices                                     : %s\n",
			((result & 0x00000400) >> 10) ? "Send async event" : "Do not send async event");
		printf("\tFirmware Activation Notices                               : %s\n",
			((result & 0x00000200) >> 9) ? "Send async event" : "Do not send async event");
		printf("\tNamespace Attribute Notices                               : %s\n",
			((result & 0x00000100) >> 8) ? "Send async event" : "Do not send async event");
		printf("\tSMART / Health Critical Warnings                          : %s\n",
			(result & 0x000000ff) ? "Send async event" : "Do not send async event");
		break;
	case NVME_FEAT_FID_AUTO_PST:
		printf("\tAutonomous Power State Transition Enable (APSTE): %s\n",
			(result & 0x00000001) ? "Enabled" : "Disabled");
		if (buf)
			stdout_auto_pst((struct nvme_feat_auto_pst *)buf);
		break;
	case NVME_FEAT_FID_HOST_MEM_BUF:
		printf("\tEnable Host Memory (EHM): %s\n", (result & 0x00000001) ? "Enabled" : "Disabled");
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
		printf("\tThermal Management Temperature 1 (TMT1) : %u K (%ld °C)\n",
		       result >> 16, kelvin_to_celsius(result >> 16));
		printf("\tThermal Management Temperature 2 (TMT2) : %u K (%ld °C)\n",
		       result & 0x0000ffff, kelvin_to_celsius(result & 0x0000ffff));
		break;
	case NVME_FEAT_FID_NOPSC:
		printf("\tNon-Operational Power State Permissive Mode Enable (NOPPME): %s\n",
			(result & 1) ? "True" : "False");
		break;
	case NVME_FEAT_FID_RRL:
		printf("\tRead Recovery Level (RRL): %u\n", result & 0xf);
		break;
	case NVME_FEAT_FID_PLM_CONFIG:
		printf("\tPredictable Latency Window Enabled: %s\n", result & 0x1 ? "True" : "False");
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
		}
		break;
	case NVME_FEAT_FID_SANITIZE:
		printf("\tNo-Deallocate Response Mode (NODRM) : %u\n", result & 0x1);
		break;
	case NVME_FEAT_FID_ENDURANCE_EVT_CFG:
		printf("\tEndurance Group Identifier (ENDGID): %u\n", result & 0xffff);
		printf("\tEndurance Group Critical Warnings  : %u\n", (result >> 16) & 0xff);
		break;
	case NVME_FEAT_FID_IOCS_PROFILE:
		printf("\tI/O Command Set Profile: %s\n", result & 0x1 ? "True" : "False");
		break;
	case NVME_FEAT_FID_SPINUP_CONTROL:
		printf("\tSpinup control feature Enabled: %s\n", (result & 1) ? "True" : "False");
		break;
	case NVME_FEAT_FID_ENH_CTRL_METADATA:
		fallthrough;
	case NVME_FEAT_FID_CTRL_METADATA:
		fallthrough;
	case NVME_FEAT_FID_NS_METADATA:
		if (buf)
			stdout_host_metadata(fid, (struct nvme_host_metadata *)buf);
		break;
	case NVME_FEAT_FID_SW_PROGRESS:
		printf("\tPre-boot Software Load Count (PBSLC): %u\n", result & 0x000000ff);
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
			((result & 0x00000008) >> 3) ? "True" : "False");
		printf("\tMask Reservation Released Notification   (RESREL): %s\n",
			((result & 0x00000004) >> 2) ? "True" : "False");
		printf("\tMask Registration Preempted Notification (REGPRE): %s\n",
			((result & 0x00000002) >> 1) ? "True" : "False");
		break;
	case NVME_FEAT_FID_RESV_PERSIST:
		printf("\tPersist Through Power Loss (PTPL): %s\n", (result & 0x00000001) ? "True" : "False");
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
	case 1:
		printf("\tCompleted due to transferring the amount of data"\
			" specified in the MNDW field\n");
		break;
	case 2:
		printf("\tCompleted due to having performed the action\n"\
			"\tspecified in the Action Type field over the\n"\
			"\tnumber of logical blocks specified in the\n"\
			"\tRange Length field\n");
		break;
	default:
		break;
	}

	for (idx = 0; idx < list->nlsd; idx++) {
		struct nvme_lba_status_desc *e = &list->descs[idx];
		printf("{ DSLBA: 0x%016"PRIu64", NLB: 0x%08x, Status: 0x%02x }\n",
				le64_to_cpu(e->dslba), le32_to_cpu(e->nlb),
				e->status);
	}
}

static void stdout_dev_full_path(nvme_ns_t n, char *path, size_t len)
{
	struct stat st;

	snprintf(path, len, "/dev/%s", nvme_ns_get_name(n));
	if (stat(path, &st) == 0)
		return;

	snprintf(path, len, "/dev/spdk/%s", nvme_ns_get_name(n));
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

	sscanf(nvme_ns_get_name(n), "nvme%dn%d", &instance, &head_instance);
	snprintf(path, len, "/dev/ng%dn%d", instance, head_instance);

	if (stat(path, &st) == 0)
		return;

	snprintf(path, len, "/dev/spdk/ng%dn%d", instance, head_instance);
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
	char usage[128] = { 0 }, format[128] = { 0 };
	char devname[128] = { 0 }, genname[128] = { 0 };

	long long lba = nvme_ns_get_lba_size(n);
	double nsze = nvme_ns_get_lba_count(n) * lba;
	double nuse = nvme_ns_get_lba_util(n) * lba;

	const char *s_suffix = suffix_si_get(&nsze);
	const char *u_suffix = suffix_si_get(&nuse);
	const char *l_suffix = suffix_binary_get(&lba);

	sprintf(usage,"%6.2f %2sB / %6.2f %2sB", nuse, u_suffix, nsze, s_suffix);
	sprintf(format,"%3.0f %2sB + %2d B", (double)lba, l_suffix,
		nvme_ns_get_meta_size(n));

	nvme_dev_full_path(n, devname, sizeof(devname));
	nvme_generic_full_path(n, genname, sizeof(genname));

	printf("%-12s %-12s %#-10x %-26s %-16s ", devname,
		genname, nvme_ns_get_nsid(n), usage, format);
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

	printf("%-8s %-20s %-40s %-8s %-6s %-14s %-6s %-12s ",
	       nvme_ctrl_get_name(c),
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

	printf("%-8s %-20s %-40s %-8s %-6s %-14s %-6s %-12s %-16s\n", "Device",
		"SN", "MN", "FR", "TxPort", "Asdress", "Slot", "Subsystem", "Namespaces");
	printf("%-.8s %-.20s %-.40s %-.8s %-.6s %-.14s %-.6s %-.12s %-.16s\n", dash,
		dash, dash, dash, dash, dash, dash, dash, dash);
	strset_iterate(&res.ctrls, stdout_detailed_ctrl, &res);
	printf("\n");

	printf("%-12s %-12s %-10s %-26s %-16s %-16s\n", "Device", "Generic",
		"NSID", "Usage", "Format", "Controllers");
	printf("%-.12s %-.12s %-.10s %-.26s %-.16s %-.16s\n", dash, dash, dash,
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
			int len = strlen(nvme_subsystem_get_name(s));

			if (!first)
				printf("\n");
			first = false;

			printf("%s - NQN=%s\n", nvme_subsystem_get_name(s),
			       nvme_subsystem_get_nqn(s));
			printf("%*s   hostnqn=%s\n", len, " ",
			       nvme_host_get_hostnqn(nvme_subsystem_get_host(s)));
			printf("%*s   iopolicy=%s\n", len, " ",
			       nvme_subsystem_get_iopolicy(s));
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

	printf("\n");
}

static void stdout_perror(const char *msg)
{
	perror(msg);
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
			printf("rdma_pkey: 0x%04x\n",
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
	printf("device: %s\n", nvme_ctrl_get_name(c));
}

static struct print_ops stdout_print_ops = {
	/* libnvme types.h print functions */
	.ana_log			= stdout_ana_log,
	.boot_part_log			= stdout_boot_part_log,
	.phy_rx_eom_log			= stdout_phy_rx_eom_log,
	.ctrl_list			= stdout_list_ctrl,
	.ctrl_registers			= stdout_ctrl_registers,
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
	.resv_notification_log		= stdout_resv_notif_log,
	.resv_report			= stdout_resv_report,
	.sanitize_log_page		= stdout_sanitize_log,
	.secondary_ctrl_list		= stdout_list_secondary_ctrl,
	.select_result			= stdout_select_result,
	.self_test_log 			= stdout_self_test_log,
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
	.show_feature_fields		= stdout_feature_show_fields,
	.id_ctrl_rpmbs			= stdout_id_ctrl_rpmbs,
	.lba_range			= stdout_lba_range,
	.lba_status_info		= stdout_lba_status_info,

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
};

struct print_ops *nvme_get_stdout_print_ops(enum nvme_print_flags flags)
{
	stdout_print_ops.flags = flags;
	return &stdout_print_ops;
}
