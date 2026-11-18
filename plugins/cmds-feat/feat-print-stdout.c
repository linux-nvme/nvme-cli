// SPDX-License-Identifier: GPL-2.0-or-later

#include <inttypes.h>
#include <stdio.h>
#include <string.h>

#include <libnvme.h>

#include <ccan/array_size/array_size.h>
#include <ccan/endian/endian.h>
#include <ccan/minmax/minmax.h>
#include <shared/hex-util.h>
#include <shared/int-util.h>
#include <shared/table-util.h>
#include <shared/uint128-util.h>
#include <shared/uuid-util.h>

#include "feat-print.h"
#include "nvme-print.h"
#include "nvme-print-stdout.h"

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
	int i;

	for (i = 0; i <= nr_ranges; i++) {
		struct nvme_lba_range_type_entry *e = &lbrt->entry[i];
		struct shr_table *t;
		char guid[2 * ARRAY_SIZE(e->guid) + 1];

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

		shr_bin_to_hex(guid, sizeof(guid), e->guid, sizeof(e->guid), 0);
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
	__u16 attrl = le16_to_cpu(data->attrl);
	struct shr_table *t;

	t = stdout_kv_table_create();
	if (!t)
		return;

	stdout_kv_add(t, "performance attribute identifier (PAID)", "%s",
		      shr_uuid_to_string(data->paid));
	stdout_kv_add(t, "attribute length (ATTRL)", "%u", attrl);

	stdout_kv_table_finish(t, "feat-perfc-vs");

	printf("vendor specific (VS):\n");
	d((unsigned char *)data->vs,
	  min_t(size_t, attrl, sizeof(data->vs)), 16, 1);
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
	struct nvme_metadata_element_desc desc;
	const __u8 *val;
	size_t off = 0;
	int i;
	__u16 len;
	struct shr_table *t;

	t = stdout_kv_table_create();
	if (!t)
		return;

	stdout_kv_add(t, "Num Metadata Element Descriptors", "%d", data->ndesc);

	stdout_kv_table_finish(t, "host-metadata");

	for (i = 0; i < data->ndesc; i++) {
		val = nvme_host_metadata_element(data, &off, &desc, &len);
		if (!val)
			break;

		printf("\tElement[%-3d]:\n", i);

		t = stdout_kv_table_create();
		if (!t)
			return;

		shr_table_set_indent(t, 2);
		stdout_kv_add(t, "Type", "%#02x (%s)", desc.type,
			      nvme_host_metadata_type_to_string(fid,
								 desc.type));
		stdout_kv_add(t, "Revision", "%d", desc.rev);
		stdout_kv_add(t, "Length", "%d", le16_to_cpu(desc.len));
		stdout_kv_add(t, "Value", "%.*s", len, (const char *)val);

		stdout_kv_table_finish(t, "host-metadata");
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
	       nvme_feature_to_string(fid), nvme_select_to_string(sel),
	       result ? 10 : 8, result);

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
	__u16 field;

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
		if (NVME_FEAT_ARB_BURST(result) ==
		    NVME_FEAT_ARBITRATION_BURST_MASK)
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
			stdout_lba_range((struct nvme_lba_range_type *)buf,
					 field);
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
			stdout_host_mem_buffer(
				(struct nvme_host_mem_buf_attrs *)buf);
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
			stdout_host_metadata(fid,
					     (struct nvme_host_metadata *)buf);
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

		// NOET is in bits 7:0; bits 31:8 are reserved.
		for (unsigned int i = 0; i < (result & 0xff); i++) {
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
			stdout_rate_limiting_data(
				(struct nvme_rate_limiting_data *)buf);
		break;
	default:
		break;
	}
}

static struct feat_print_ops feat_stdout_print_ops = {
	.select_result			= stdout_select_result,
	.show_feature			= stdout_feature_show,
	.show_feature_fields		= stdout_feature_show_fields,
	.lba_range			= stdout_lba_range,
	.lba_status_info		= stdout_lba_status_info,
};

struct feat_print_ops *feat_get_stdout_print_ops(nvme_print_flags_t flags)
{
	feat_stdout_print_ops.flags = flags;
	return &feat_stdout_print_ops;
}
