// SPDX-License-Identifier: GPL-2.0-or-later
#include <time.h>

#ifdef CONFIG_FABRICS
#include <arpa/inet.h>
#endif /* CONFIG_FABRICS */

#include <ccan/array_size/array_size.h>
#include <ccan/minmax/minmax.h>
#include <shared/string-util.h>

#include "cleanup.h"
#include "logging.h"
#include "nvme-print.h"
#include "nvme-print-stdout.h"

void stdout_predictable_latency_per_nvmset(
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

void stdout_predictable_latency_event_agg_log(
		struct nvme_aggregate_predictable_lat_event *pea_log,
		__u64 log_entries, __u32 size, const char *devname)
{
	__u64 num_iter;
	__u64 num_entries;
	struct shr_table *t;

	num_entries = le64_to_cpu(pea_log->num_entries);
	printf("Predictable Latency Event Aggregate Log for device: %s\n",
	       devname);

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
				       nvme_pel_event_to_string(bit + i *
				       CHAR_BIT));
		}
	}
}

static void stdout_persistent_event_log_fdp_events(unsigned int cdw11,
						   unsigned int cdw12,
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
			   int verbose)
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
	if (verbose)
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
				 int verbose)
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
	if (verbose)
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
	struct nvme_time_stamp_change_event *ts_change_event =
		pevent_log_info + offset;
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
	__u32 ev_len = le16_to_cpu(pevent_entry_head->el);
	__u32 vlen = le16_to_cpu(pevent_entry_head->vsil);
	struct nvme_power_on_reset_info_list *por_event;
	__u32 por_info_len, por_info_list;

	if (ev_len < vlen + sizeof(*fw_rev))
		return;

	por_info_len = ev_len - vlen - sizeof(*fw_rev);
	por_info_list = por_info_len / sizeof(*por_event);
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
		por_event = pevent_log_info + offset + sizeof(*fw_rev) +
			    i * sizeof(*por_event);

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
	struct nvme_nss_hw_err_event *nss_hw_err_event =
		pevent_log_info + offset;
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
	struct nvme_format_nvm_start_event *format_start_event =
		pevent_log_info + offset;
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
	struct nvme_format_nvm_compln_event *format_cmpln_event =
		pevent_log_info + offset;
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
	struct nvme_sanitize_start_event *sanitize_start_event =
		pevent_log_info + offset;
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

void nvme_show_pel_sanitize_completion_event(void *pevent_log_info,
					     __u32 offset)
{
	struct nvme_sanitize_compln_event *sanitize_cmpln_event =
		pevent_log_info + offset;
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
	struct nvme_set_feature_event *set_feat_event =
		pevent_log_info + offset;
	struct shr_table *t;

	printf("Set Feature Event Entry:\n");
	dword_cnt = NVME_SET_FEAT_EVENT_DW_COUNT(set_feat_event->layout);
	fid = NVME_GET(le32_to_cpu(set_feat_event->cdw_mem[0]),
		       SET_FEATURES_CDW10_FID);
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
	struct nvme_thermal_exc_event *thermal_exc_event =
		pevent_log_info + offset;
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

void stdout_persistent_event_log(void *pevent_log_info, __u8 action, __u32 size,
				 const char *devname)
{
	struct nvme_persistent_event_log *pevent_log_head;
	__u32 offset = sizeof(*pevent_log_head);
	__u16 vsil, el;
	struct nvme_persistent_event_entry *pevent_entry_head;
	int verbose = stdout_print_ops.flags & VERBOSE;
	struct shr_table *t;

	t = stdout_kv_table_create();
	if (!t)
		return;

	stdout_kv_add(t, "Persistent Event Log for device", "%s", devname);
	stdout_kv_add(t, "Action for Persistent Event Log", "%u", action);

	stdout_kv_table_finish(t, "persistent-event-log");

	if (size < offset) {
		printf("No log data can be shown with this log len at least "
		       "512 bytes is required or can be 0 to read the "
		       "complete log page after context established\n");
		return;
	}

	pevent_log_head = pevent_log_info;

	nvme_show_pel_header(pevent_log_head, verbose);

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

		nvme_show_pel_event_header(i, pevent_entry_head, verbose);

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
			if (el >= 512 &&
			    offset + 512 <= size)
				d(pevent_log_info + offset,
				  512, 16, 1);
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

void stdout_endurance_group_event_agg_log(
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

void stdout_lba_status_log(void *lba_status, __u32 size, const char *devname)
{
	struct nvme_lba_status_log *hdr;
	struct nvme_lbas_ns_element *ns_element;
	struct nvme_lba_rd *range_desc;
	size_t offset = sizeof(*hdr);
	__u32 num_lba_desc, num_elements;
	struct shr_table *t;

	if (size < sizeof(*hdr))
		return;

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
		if (offset + sizeof(*ns_element) > size)
			break;
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
			if (num_lba_desc >
			    (size - offset) / sizeof(*range_desc))
				break;
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
			printf("Number of LBA Range Descriptors (NLRD) set to "
			       "%#x for NS element %d\n", num_lba_desc, ele);
		}
	}
}

void stdout_resv_notif_log(struct nvme_resv_notification_log *resv,
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
stdout_fid_support_effects_log_verbose_table(__u32 fid_support)
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

void stdout_fid_support_effects_log(
	struct nvme_fid_supported_effects_log *fid_log, const char *devname)
{
	struct shr_table *t;
	__u32 fid_effect;
	int i, row, verbose = stdout_print_ops.flags & VERBOSE;

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
		if (verbose)
			shr_table_set_row_subtable(t, row,
				stdout_fid_support_effects_log_verbose_table(
					fid_effect));
	}

	stdout_kv_table_finish(t, "fid-support-effects-log");
}

static struct shr_table *
stdout_mi_cmd_support_effects_log_verbose_table(__u32 mi_cmd_support)
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

void stdout_mi_cmd_support_effects_log(
	struct nvme_mi_cmd_supported_effects_log *mi_cmd_log,
	const char *devname)
{
	struct shr_table *t;
	__u32 mi_cmd_effect;
	int i, row, verbose = stdout_print_ops.flags & VERBOSE;

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
		if (verbose)
			shr_table_set_row_subtable(t, row,
				stdout_mi_cmd_support_effects_log_verbose_table(
					mi_cmd_effect));
	}

	stdout_kv_table_finish(t, "mi-cmd-support-effects-log");
}

void stdout_boot_part_log(void *bp_log, const char *devname, __u32 size)
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

void stdout_phy_rx_eom_log(struct nvme_phy_rx_eom_log *log, __u16 controller,
			   size_t len)
{
	int verbose = stdout_print_ops.flags & VERBOSE;
	struct shr_table *t;
	int row;

	if (len < sizeof(*log))
		return;

	printf(
	    "Physical Interface Receiver Eye Opening Measurement Log for controller ID: %u\n",
	    controller);

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
	if (verbose)
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

void stdout_media_unit_stat_log(struct nvme_media_unit_stat_log *mus_log)
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

void stdout_fdp_configs(struct nvme_fdp_config_log *log, size_t len)
{
	unsigned char *p, *end;
	int verbose = stdout_print_ops.flags & VERBOSE;
	uint16_t n;
	struct shr_table *t;
	int row;

	if (len < sizeof(*log))
		return;

	p = (unsigned char *)log->configs;
	end = (unsigned char *)log + len;
	n = le16_to_cpu(log->n) + 1;

	for (int i = 0; i < n; i++) {
		struct nvme_fdp_config_desc *config =
			(struct nvme_fdp_config_desc *)p;
		uint16_t size, nruh, max_nruh;

		if (!shr_buf_has_room(p, end, sizeof(*config)))
			break;

		t = stdout_kv_table_create();
		if (!t)
			return;

		row = stdout_kv_add(t, "FDP Attributes", "%#x", config->fdpa);
		if (verbose)
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
		max_nruh = (size - sizeof(*config)) /
			   sizeof(struct nvme_fdp_ruh_desc);
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

void stdout_fdp_usage(struct nvme_fdp_ruhu_log *log, size_t len)
{
	uint16_t nruh = le16_to_cpu(log->nruh);
	struct shr_table *t;

	t = stdout_kv_table_create();
	if (!t)
		return;

	for (int i = 0; i < nruh; i++) {
		struct nvme_fdp_ruhu_desc *ruhu = &log->ruhus[i];
		const char *ruha_str;
		char name[48];

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

void stdout_fdp_stats(struct nvme_fdp_stats_log *log)
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

void stdout_fdp_events(struct nvme_fdp_events_log *log)
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

			mr = (struct nvme_fdp_event_realloc *)
			     &event->type_specific;

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

void stdout_supported_cap_config_log(
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

void stdout_zns_changed(struct nvme_zns_changed_zone_log *log)
{
	struct shr_table *t;
	uint16_t nrzid;
	int i;

	nrzid = le16_to_cpu(log->nrzid);
	printf("NVMe Changed Zone List:\n");

	if (nrzid == 0xFFFF) {
		printf("Too many zones have changed to fit into the log. Use "
		       "report zones for changes.\n");
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

void stdout_error_log(struct nvme_error_log_page *err_log, int entries,
		      const char *devname, struct nvme_error_log_filter *flt)
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

void stdout_fw_log(struct nvme_firmware_slot *fw_log, const char *devname)
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

void stdout_changed_ns_list_log(struct nvme_ns_list *log, const char *devname,
				bool alloc)
{
	struct shr_table_column columns[] = {
		{ "Index", RIGHT, AUTO_WIDTH },
		{ "NSID",  LEFT,  AUTO_WIDTH },
	};
	struct shr_table *t;
	__u32 nsid;
	int i, row;
	bool changed = false, terminated = false;

	if (log->ns[0] == cpu_to_le32(NVME_NSID_ALL)) {
		printf("more than %d ns changed\n", NVME_ID_NS_LIST_MAX);
		return;
	}

	t = shr_table_init_with_columns(columns, ARRAY_SIZE(columns));
	if (!t)
		return;

	for (i = 0; i < NVME_ID_NS_LIST_MAX; i++) {
		char id[16];

		nsid = le32_to_cpu(log->ns[i]);
		if (nsid == 0) {
			terminated = true;
			break;
		}

		changed = true;
		row = shr_table_get_row_id(t);
		snprintf(id, sizeof(id), "%#x", nsid);
		shr_table_set_value_int(t, 0, row, i, RIGHT);
		shr_table_set_value_str(t, 1, row, id, LEFT);
		shr_table_add_row(t, row);
	}

	if (changed)
		shr_table_print(t);
	shr_table_free(t);

	/*
	 * The terminating 0 can appear at any index, not just index 0, so
	 * this can print after a non-empty list too -- matches old behavior.
	 */
	if (terminated)
		printf("no ns changed\n");
}

static void stdout_effects_entry_decoded(char *buf, size_t len, __u32 effect)
{
	static const char * const cser_desc[] = {
		"No CSER defined",
		"No admin command for any namespace",
	};
	static const char * const cse_desc[] = {
		"No command restriction",
		"No other command for same namespace",
		"No other command for any namespace",
	};
	__u8 cser = NVME_CMD_EFFECTS_CSER(effect);
	__u8 cse = NVME_CMD_EFFECTS_CSE(effect);
	const char *parts[7];
	int n = 0, i;

	if (effect & NVME_CMD_EFFECTS_LBCC)
		parts[n++] = "LBCC";
	if (effect & NVME_CMD_EFFECTS_NCC)
		parts[n++] = "NCC";
	if (effect & NVME_CMD_EFFECTS_NIC)
		parts[n++] = "NIC";
	if (effect & NVME_CMD_EFFECTS_CCC)
		parts[n++] = "CCC";
	if (effect & NVME_CMD_EFFECTS_UUID_SEL)
		parts[n++] = "USS";
	parts[n++] = cser < ARRAY_SIZE(cser_desc) ? cser_desc[cser] :
						     "Reserved CSER";
	parts[n++] = cse < ARRAY_SIZE(cse_desc) ? cse_desc[cse] :
						  "Reserved CSE";

	buf[0] = '\0';
	for (i = 0; i < n; i++) {
		if (i)
			strncat(buf, ", ", len - strlen(buf) - 1);
		strncat(buf, parts[i], len - strlen(buf) - 1);
	}
}

static struct shr_table *stdout_effects_log_segment_build(int admin, int a,
		int b, struct nvme_cmd_effects_log *effects, int verbose)
{
	struct shr_table_column columns_verbose[] = {
		{ "ID",      LEFT, AUTO_WIDTH },
		{ "Command", LEFT, AUTO_WIDTH },
		{ "Effects", LEFT, AUTO_WIDTH },
		{ "Decoded", LEFT, AUTO_WIDTH },
	};
	struct shr_table_column columns[] = {
		{ "ID",      LEFT, AUTO_WIDTH },
		{ "Command", LEFT, AUTO_WIDTH },
		{ "Effects", LEFT, AUTO_WIDTH },
	};
	struct shr_table *t;
	bool has_entries = false;
	int i, row;

	if (verbose)
		t = shr_table_init_with_columns(columns_verbose,
						 ARRAY_SIZE(columns_verbose));
	else
		t = shr_table_init_with_columns(columns, ARRAY_SIZE(columns));
	if (!t)
		return NULL;

	for (i = a; i < b; i++) {
		__le32 entry = admin ? effects->acs[i] : effects->iocs[i];
		__u32 effect = le32_to_cpu(entry);
		char id[16], hex[16];
		int col = 0;

		if (!(effect & NVME_CMD_EFFECTS_CSUPP))
			continue;

		has_entries = true;
		snprintf(id, sizeof(id), "%s%d", admin ? "ACS" : "IOCS", i);
		snprintf(hex, sizeof(hex), "%08x", effect);

		row = shr_table_get_row_id(t);
		shr_table_set_value_str(t, col++, row, id, LEFT);
		shr_table_set_value_str(t, col++, row,
					 nvme_cmd_to_string(admin, i), LEFT);
		shr_table_set_value_str(t, col++, row, hex, LEFT);
		if (verbose) {
			char decoded[128];

			stdout_effects_entry_decoded(decoded,
						      sizeof(decoded), effect);
			shr_table_set_value_str(t, col++, row, decoded, LEFT);
		}
		shr_table_add_row(t, row);
	}

	if (!has_entries) {
		shr_table_free(t);
		return NULL;
	}

	return t;
}

static void stdout_effects_align_tables(struct shr_table **tables, int n,
		int num_columns)
{
	int col, i, width;

	for (col = 0; col < num_columns; col++) {
		width = 0;
		for (i = 0; i < n; i++) {
			int w;

			if (!tables[i])
				continue;
			w = shr_table_get_column_width(tables[i], col);
			if (w > width)
				width = w;
		}
		for (i = 0; i < n; i++) {
			if (tables[i])
				shr_table_set_column_width(tables[i], col,
							    width);
		}
	}
}

void stdout_effects_log_pages(struct list_head *list)
{
	static const char * const headers[4] = {
		"Admin Commands",
		"Vendor Specific Admin Commands",
		"I/O Commands",
		"Vendor Specific I/O Commands",
	};
	nvme_effects_log_node_t *node = NULL;
	int verbose = stdout_print_ops.flags & VERBOSE;
	int num_columns = verbose ? 4 : 3;
	struct shr_table **segs;
	int count = 0, idx, i;

	list_for_each(list, node, node)
		count++;
	if (!count)
		return;

	segs = calloc(count * 4, sizeof(*segs));
	if (!segs)
		return;

	idx = 0;
	list_for_each(list, node, node) {
		segs[idx * 4 + 0] = stdout_effects_log_segment_build(1, 0,
				0xbf, &node->effects, verbose);
		segs[idx * 4 + 1] = stdout_effects_log_segment_build(1, 0xc0,
				0xff, &node->effects, verbose);
		segs[idx * 4 + 2] = stdout_effects_log_segment_build(0, 0,
				0x80, &node->effects, verbose);
		segs[idx * 4 + 3] = stdout_effects_log_segment_build(0, 0x80,
				0x100, &node->effects, verbose);
		idx++;
	}

	stdout_effects_align_tables(segs, count * 4, num_columns);

	idx = 0;
	list_for_each(list, node, node) {
		switch (node->csi) {
		case NVME_CSI_NVM:
			printf("NVM Command Set Log Page\n");
			break;
		case NVME_CSI_KV:
			printf("KV Command Set Log Page\n");
			break;
		case NVME_CSI_ZNS:
			printf("ZNS Command Set Log Page\n");
			break;
		default:
			printf("Unknown Command Set Log Page\n");
			break;
		}
		printf("%-.80s\n", dash);

		for (i = 0; i < 4; i++) {
			struct shr_table *t = segs[idx * 4 + i];

			if (!t)
				continue;
			printf("%s\n", headers[i]);
			shr_table_print(t);
			shr_table_free(t);
			printf("\n");
		}
		idx++;
	}

	free(segs);
}

static struct shr_table *
stdout_support_log_verbose_table(__u32 support, __u8 lid)
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

void stdout_supported_log(struct nvme_supported_log_pages *support_log,
			  const char *devname)
{
	int lid, verbose = stdout_print_ops.flags & VERBOSE;
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
			if (verbose)
				shr_table_set_row_subtable(t, row,
					stdout_support_log_verbose_table(
						support, lid));
		}
	}

	stdout_kv_table_finish(t, "supported-log");
}

void stdout_endurance_log(struct nvme_endurance_group_log *el, __u16 group_id,
			  const char *devname)
{
	struct shr_table *t;

	printf("Endurance Group Log for NVME device:%s Group ID:%x\n", devname,
	       group_id);

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

void stdout_smart_log(struct nvme_smart_log *smart, unsigned int nsid,
		      const char *devname)
{
	__cleanup_free char *ipm_str = NULL;
	__u16 temperature = smart->temperature[1] << 8 | smart->temperature[0];
	__u32 ipm = le32_to_cpu(smart->interval_power_measurement);
	bool verbose = stdout_print_ops.flags & VERBOSE;
	struct shr_table *t;
	char name[32];
	int i, row;

	printf("Smart Log for NVME device:%s namespace-id:%x\n", devname, nsid);

	t = stdout_kv_table_create();
	if (!t)
		return;

	row = stdout_kv_add(t, "critical_warning", "%#x",
			     smart->critical_warning);
	if (verbose)
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
	if (verbose)
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

void stdout_ana_log(struct nvme_ana_log *ana_log, const char *devname,
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
		"Operation was aborted due to a removal of a namespace from "
		"the namespace inventory",
		"Operation was aborted due to the processing of a Format NVM "
		"command",
		"A fatal error or unknown test error occurred while the "
		"controller was executing the device self-test operation and "
		"the operation did not complete",
		"Operation completed with a segment that failed and the "
		"segment that failed is not known",
		"Operation completed with one or more failed segments and the "
		"first segment that failed is indicated in the SegmentNumber "
		"field",
		"Operation was aborted for unknown reason",
		"Operation was aborted due to a sanitize operation",
		"Reserved",
		[NVME_ST_RESULT_NOT_USED] =
			"Entry not used (does not contain a result)",
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

void stdout_self_test_log(struct nvme_self_test_log *self_test,
			  __u8 dst_entries, __u32 size, const char *devname)
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

void stdout_sanitize_log(struct nvme_sanitize_log_page *sanitize,
			 const char *devname)
{
	__cleanup_free char *sprog_val = NULL;
	struct shr_table *t;
	int verbose = stdout_print_ops.flags & VERBOSE;
	__u16 sstat = le16_to_cpu(sanitize->sstat);
	__u16 status = sstat & NVME_SANITIZE_SSTAT_STATUS_MASK;
	double percent;
	int row;

	if (verbose && status == NVME_SANITIZE_SSTAT_STATUS_IN_PROGRESS) {
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
	if (verbose)
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
	if (verbose)
		shr_table_set_row_subtable(t, row,
			stdout_sanitize_log_ssi_table(sanitize->ssi, status));

	stdout_kv_table_finish(t, "sanitize-log");
}

#ifdef CONFIG_FABRICS
void stdout_discovery_log(const struct nvmf_discovery_log *log, int numrec)
{
	int i;

	printf("\nDiscovery Log Number of Records %d, Generation counter %"
	       PRIu64"\n", numrec, le64_to_cpu(log->genctr));

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

void stdout_host_discovery_log(struct nvme_host_discovery_log *log)
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

void stdout_ave_discovery_log(struct nvme_ave_discovery_log *log)
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
#endif /* CONFIG_FABRICS */

void stdout_mgmt_addr_list_log(struct nvme_mgmt_addr_list_log *ma_list)
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

void stdout_rotational_media_info_log(
	struct nvme_rotational_media_info_log *info)
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

void stdout_dispersed_ns_psub_log(
	struct nvme_dispersed_ns_participating_nss_log *log)
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

void stdout_reachability_groups_log(struct nvme_reachability_groups_log *log,
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

void stdout_reachability_associations_log(
	struct nvme_reachability_associations_log *log, __u64 len)
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

void stdout_pull_model_ddc_req_log(struct nvme_pull_model_ddc_req_log *log)
{
	__u32 tpdrpl = le32_to_cpu(log->tpdrpl);
	__u32 osp_len =
		tpdrpl - offsetof(struct nvme_pull_model_ddc_req_log, osp);
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

void stdout_power_meas_log(struct nvme_power_meas_log *log, __u32 size)
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
