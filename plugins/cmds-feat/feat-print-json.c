// SPDX-License-Identifier: GPL-2.0-or-later

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <libnvme.h>

#include <ccan/array_size/array_size.h>
#include <ccan/endian/endian.h>
#include <ccan/minmax/minmax.h>
#include <shared/hex-util.h>
#include <shared/int-util.h>
#include <shared/uint128-util.h>
#include <shared/uuid-util.h>

#include "feat-print.h"
#include "nvme-print.h"
#include "nvme-print-json.h"

#define VAL_LEN 4096

static void json_select_result(enum nvme_features_id fid, __u64 result)
{
	struct json_object *r = json_root();
	char json_str[STR_LEN];
	struct json_object *feature = json_create_array();

	if (result & 0x1)
		array_add_str(feature, "saveable");
	if (result & 0x2)
		array_add_str(feature, "per-namespace");
	if (result & 0x4)
		array_add_str(feature, "changeable");

	sprintf(json_str, "Feature: %#0*x: select", fid ? 4 : 2, fid);
	obj_add_array(r, json_str, feature);
}

static void json_feature_show_fields_arbitration(struct json_object *r,
						 unsigned int result)
{
	char json_str[STR_LEN];

	obj_add_uint(r, "High Priority Weight (HPW)",
		     ((result & 0xff000000) >> 24) + 1);
	obj_add_uint(r, "Medium Priority Weight (MPW)",
		     ((result & 0xff0000) >> 16) + 1);
	obj_add_uint(r, "Low Priority Weight (LPW)",
		     ((result & 0xff00) >> 8) + 1);

	if ((result & 7) == 7)
		sprintf(json_str, "No limit");
	else
		sprintf(json_str, "%u", 1 << (result & 7));

	obj_add_str(r, "Arbitration Burst (AB)", json_str);
}

static void json_feature_show_fields_power_mgmt(struct json_object *r,
						unsigned int result)
{
	__u8 field = (result & 0xe0) >> 5;

	obj_add_uint(r, "Workload Hint (WH)", field);
	obj_add_str(r, "WH description",
		    nvme_feature_wl_hints_to_string(field));
	obj_add_uint(r, "Power State (PS)", result & 0x1f);
	obj_add_uint(r, "Idle I/O Exit Latency Limit (IIELL)",
		     NVME_FEAT_PM_IIELL(result));
}

static void json_lba_range_entry(struct nvme_lba_range_type *lbrt,
				 int nr_ranges, struct json_object *r)
{
	char json_str[STR_LEN];
	struct json_object *lbare;
	int i;
	struct json_object *lbara = json_create_array();

	obj_add_array(r, "LBA Ranges", lbara);

	for (i = 0; i <= nr_ranges; i++) {
		lbare = json_create_object();
		array_add_obj(lbara, lbare);

		obj_add_int(lbare, "LBA range", i);

		obj_add_uint_nx(lbare, "type", lbrt->entry[i].type);

		obj_add_str(lbare, "type description",
			nvme_feature_lba_type_to_string(lbrt->entry[i].type));

		obj_add_uint_nx(lbare, "attributes", lbrt->entry[i].attributes);

		obj_add_str(lbare, "attribute[0]",
			    lbrt->entry[i].attributes & 1 ?
			    "LBA range may be overwritten" :
			    "LBA range should not be overwritten");

		obj_add_str(lbare, "attribute[1]",
			    lbrt->entry[i].attributes & 2 ?
			    "LBA range should be hidden from the OS/EFI/BIOS" :
			    "LBA range should be visible from the OS/EFI/BIOS");

		obj_add_nprix64(lbare, "slba",
				le64_to_cpu(lbrt->entry[i].slba));

		obj_add_nprix64(lbare, "nlb", le64_to_cpu(lbrt->entry[i].nlb));

		shr_bin_to_hex(json_str, sizeof(json_str), lbrt->entry[i].guid,
			       sizeof(lbrt->entry[i].guid), 0);

		obj_add_str(lbare, "guid", json_str);
	}
}

static void json_feature_show_fields_lba_range(struct json_object *r,
					       __u8 field, unsigned char *buf)
{
	obj_add_uint(r, "Number of LBA Ranges (NUM)", field + 1);

	if (buf)
		json_lba_range_entry((struct nvme_lba_range_type *)buf, field,
				     r);
}

static void json_feature_show_fields_temp_thresh(struct json_object *r,
						 unsigned int result)
{
	char json_str[STR_LEN];
	__u8 field;

	field = (result & 0x1c00000) >> 22;
	sprintf(json_str, "%s", nvme_degrees_string(field));
	obj_add_str(r, "Temperature Threshold Hysteresis (TMPTHH)", json_str);

	sprintf(json_str, "%u K", field);
	obj_add_str(r, "TMPTHH kelvin", json_str);

	field = (result & 0x300000) >> 20;
	obj_add_uint(r, "Threshold Type Select (THSEL)", field);
	obj_add_str(r, "THSEL description",
		    nvme_feature_temp_type_to_string(field));

	field = (result & 0xf0000) >> 16;

	obj_add_uint(r, "Threshold Temperature Select (TMPSEL)", field);
	obj_add_str(r, "TMPSEL description",
		    nvme_feature_temp_sel_to_string(field));

	sprintf(json_str, "%s", nvme_degrees_string(result & 0xffff));
	obj_add_str(r, "Temperature Threshold (TMPTH)", json_str);

	sprintf(json_str, "%u K", result & 0xffff);
	obj_add_str(r, "TMPTH kelvin", json_str);
}

static void json_feature_show_fields_err_recovery(struct json_object *r,
						  unsigned int result)
{
	char json_str[STR_LEN];

	obj_add_str(r,
		    "Deallocated or Unwritten Logical Block Error Enable (DULBE)",
		    (result & 0x10000) >> 16 ? "Enabled" : "Disabled");

	sprintf(json_str, "%u ms", (result & 0xffff) * 100);
	obj_add_str(r, "Time Limited Error Recovery (TLER)", json_str);
}

static void json_feature_show_fields_volatile_wc(struct json_object *r,
						 unsigned int result)
{
	obj_add_str(r, "Volatile Write Cache Enable (WCE)",
		    result & 1 ? "Enabled" : "Disabled");
}

static void json_feature_show_fields_num_queues(struct json_object *r,
						unsigned int result)
{
	obj_add_uint(r, "Number of IO Completion Queues Allocated (NCQA)",
		     ((result & 0xffff0000) >> 16) + 1);
	obj_add_uint(r, "Number of IO Submission Queues Allocated (NSQA)",
		     (result & 0xffff) + 1);
}

static void json_feature_show_fields_irq_coalesce(struct json_object *r,
						  unsigned int result)
{
	char json_str[STR_LEN];

	sprintf(json_str, "%u usec", ((result & 0xff00) >> 8) * 100);
	obj_add_str(r, "Aggregation Time (TIME)", json_str);

	obj_add_uint(r, "Aggregation Threshold (THR)", (result & 0xff) + 1);
}

static void json_feature_show_fields_irq_config(struct json_object *r,
						unsigned int result)
{
	obj_add_str(r, "Coalescing Disable (CD)",
		    (result & 0x10000) >> 16 ? "True" : "False");
	obj_add_uint(r, "Interrupt Vector (IV)", result & 0xffff);
}

static void json_feature_show_fields_write_atomic(struct json_object *r,
						  unsigned int result)
{
	obj_add_str(r, "Disable Normal (DN)", result & 1 ? "True" : "False");
}

static void json_feature_show_fields_async_event(struct json_object *r,
						 unsigned int result)
{
	const char *async = "Send async event";
	const char *no_async = "Do not send async event";

	obj_add_str(r, feat_ae_dlpcn,
		    NVME_FEAT_AE_DLPCN(result) ? async : no_async);
	obj_add_str(r, feat_ae_hdlpcn,
		    NVME_FEAT_AE_HDLPCN(result) ? async : no_async);
	obj_add_str(r, feat_ae_adlpcn,
		    NVME_FEAT_AE_ADLPCN(result) ? async : no_async);
	obj_add_str(r, feat_ae_pmdrlpcn,
		    NVME_FEAT_AE_PMDRLPCN(result) ? async : no_async);
	obj_add_str(r, feat_ae_zdcn,
		    NVME_FEAT_AE_ZDCN(result) ? async : no_async);
	obj_add_str(r, feat_ae_tthry,
		    NVME_FEAT_AE_TTHRY(result) ? async : no_async);
	obj_add_str(r, feat_ae_rlccn,
		    NVME_FEAT_AE_RLCCN(result) ? async : no_async);
	obj_add_str(r, feat_ae_lhcn,
		    NVME_FEAT_AE_LHCN(result) ? async : no_async);
	obj_add_str(r, feat_ae_ccrcn,
		    NVME_FEAT_AE_CCRCN(result) ? async : no_async);
	obj_add_str(r, feat_ae_ansan,
		    NVME_FEAT_AE_ANSAN(result) ? async : no_async);
	obj_add_str(r, feat_ae_rgrp0,
		    NVME_FEAT_AE_RGRP0(result) ? async : no_async);
	obj_add_str(r, feat_ae_rassn,
		    NVME_FEAT_AE_RASSN(result) ? async : no_async);
	obj_add_str(r, feat_ae_nnsshdn,
		    NVME_FEAT_AE_NNSSHDN(result) ? async : no_async);
	obj_add_str(r, feat_ae_ega,
		    NVME_FEAT_AE_EGA(result) ? async : no_async);
	obj_add_str(r, feat_ae_lbas,
		    NVME_FEAT_AE_LBAS(result) ? async : no_async);
	obj_add_str(r, feat_ae_pla,
		    NVME_FEAT_AE_PLA(result) ? async : no_async);
	obj_add_str(r, feat_ae_ana,
		    NVME_FEAT_AE_ANA(result) ? async : no_async);
	obj_add_str(r, feat_ae_telem,
		    NVME_FEAT_AE_TELEM(result) ? async : no_async);
	obj_add_str(r, feat_ae_fw, NVME_FEAT_AE_FW(result) ? async : no_async);
	obj_add_str(r, feat_ae_nan,
		    NVME_FEAT_AE_NAN(result) ? async : no_async);
	obj_add_str(r, feat_ae_smart,
		    NVME_FEAT_AE_SMART(result) ? async : no_async);
}

static void json_auto_pst(struct nvme_feat_auto_pst *apst,
			  struct json_object *r)
{
	int i;
	__u64 value;
	char json_str[STR_LEN];
	struct json_object *apsta = json_create_array();
	struct json_object *apste;

	obj_add_array(r, "Auto PST Entries", apsta);

	for (i = 0; i < ARRAY_SIZE(apst->apst_entry); i++) {
		apste = json_create_object();
		array_add_obj(apsta, apste);
		sprintf(json_str, "%2d", i);
		obj_add_str(apste, "entry", json_str);
		value = le64_to_cpu(apst->apst_entry[i]);
		sprintf(json_str, "%u ms",
			(__u32)NVME_GET(value, APST_ENTRY_ITPT));
		obj_add_str(apste, "Idle Time Prior to Transition (ITPT)",
			    json_str);
		obj_add_uint(apste, "Idle Transition Power State (ITPS)",
			     (__u32)NVME_GET(value, APST_ENTRY_ITPS));
	}
}

static void json_feature_show_fields_auto_pst(struct json_object *r,
					      unsigned int result,
					      unsigned char *buf)
{
	obj_add_str(r, "Autonomous Power State Transition Enable (APSTE)",
		    result & 1 ? "Enabled" : "Disabled");

	if (buf)
		json_auto_pst((struct nvme_feat_auto_pst *)buf, r);
}

static void json_host_mem_buffer(struct nvme_host_mem_buf_attrs *hmb,
				 struct json_object *r)
{
	char json_str[STR_LEN];

	obj_add_uint(r, "Host Memory Descriptor List Entry Count (HMDLEC)",
		     le32_to_cpu(hmb->hmdlec));

	sprintf(json_str, "0x%x", le32_to_cpu(hmb->hmdlau));
	obj_add_str(r, "Host Memory Descriptor List Address (HMDLAU)",
		    json_str);

	sprintf(json_str, "0x%x", le32_to_cpu(hmb->hmdlal));
	obj_add_str(r, "Host Memory Descriptor List Address (HMDLAL)",
		    json_str);

	obj_add_uint(r, "Host Memory Buffer Size (HSIZE)",
		     le32_to_cpu(hmb->hsize));
}

static void json_feature_show_fields_host_mem_buf(struct json_object *r,
						  unsigned int result,
						  unsigned char *buf)
{
	obj_add_str(r, "Enable Host Memory (EHM)",
		    result & 1 ? "Enabled" : "Disabled");
	obj_add_str(r,
		    "Host Memory Non-operational Access Restriction Enable (HMNARE)",
		    (result & 0x00000004) ? "True" : "False");
	obj_add_str(r, "Host Memory Non-operational Access Restricted (HMNAR)",
			(result & 0x00000008) ? "True" : "False");

	if (buf)
		json_host_mem_buffer((struct nvme_host_mem_buf_attrs *)buf, r);
}

static void json_feature_show_fields_timestamp(struct json_object *r,
					       unsigned char *buf)
{
	if (buf)
		json_timestamp(r, (struct nvme_timestamp *)buf);
}

static void json_feature_show_fields_kato(struct json_object *r,
					  unsigned int result)
{
	obj_add_uint(r, "Keep Alive Timeout (KATO) in milliseconds", result);
}

static void json_feature_show_fields_hctm(struct json_object *r,
					  unsigned int result)
{
	char json_str[STR_LEN];

	sprintf(json_str, "%u K", result >> 16);
	obj_add_str(r, "Thermal Management Temperature 1 (TMT1)", json_str);

	sprintf(json_str, "%s", nvme_degrees_string(result >> 16));
	obj_add_str(r, "TMT1 celsius", json_str);

	sprintf(json_str, "%u K", result & 0xffff);
	obj_add_str(r, "Thermal Management Temperature 2", json_str);

	sprintf(json_str, "%s", nvme_degrees_string(result & 0xffff));
	obj_add_str(r, "TMT2 celsius", json_str);
}

static void json_feature_show_fields_nopsc(struct json_object *r,
					   unsigned int result)
{
	obj_add_str(r,
		    "Non-Operational Power State Permissive Mode Enable (NOPPME)",
		    result & 1 ? "True" : "False");
}

static void json_feature_show_fields_rrl(struct json_object *r,
					 unsigned int result)
{
	obj_add_uint(r, "Read Recovery Level (RRL)", result & 0xf);
}

static void json_plm_config(struct nvme_plm_config *plmcfg,
			    struct json_object *r)
{
	char json_str[STR_LEN];

	sprintf(json_str, "%04x", le16_to_cpu(plmcfg->ee));
	obj_add_str(r, "Enable Event", json_str);

	obj_add_uint64(r, "DTWIN Reads Threshold",
		       le64_to_cpu(plmcfg->dtwinrt));
	obj_add_uint64(r, "DTWIN Writes Threshold",
		       le64_to_cpu(plmcfg->dtwinwt));
	obj_add_uint64(r, "DTWIN Time Threshold", le64_to_cpu(plmcfg->dtwintt));
}

static void json_feature_show_fields_plm_config(struct json_object *r,
						unsigned int result,
						unsigned char *buf)
{
	obj_add_str(r, "Predictable Latency Window Enabled",
		    result & 1 ? "True" : "False");

	if (buf)
		json_plm_config((struct nvme_plm_config *)buf, r);
}

static void json_feature_show_fields_plm_window(struct json_object *r,
						unsigned int result)
{
	obj_add_str(r, "Window Select", nvme_plm_window_to_string(result));
}

static void json_feature_show_fields_lba_sts_interval(struct json_object *r,
						      unsigned int result)
{
	obj_add_uint(r, "LBA Status Information Poll Interval (LSIPI)",
		     result >> 16);
	obj_add_uint(r, "LBA Status Information Report Interval (LSIRI)",
		     result & 0xffff);
}

static void json_feature_show_fields_host_behavior(struct json_object *r,
						   unsigned char *buf)
{
	if (buf) {
		struct nvme_feat_host_behavior *host =
			(struct nvme_feat_host_behavior *)buf;

		obj_add_str(r, "Host Behavior Support",
			    buf[0] & 0x1 ? "True" : "False");
		obj_add_str(r, "Advanced Command Retry Enable (ACRE)",
			    host->acre ? "True" : "False");
		obj_add_str(r,
			    "Extended Telemetry Data Area 4 Supported (ETDAS)",
			    host->etdas ? "True" : "False");
		obj_add_str(r, "LBA Format Extension Enable (LBAFEE)",
			    host->lbafee ? "True" : "False");
		obj_add_str(r, "Host Dispersed Namespace Support (HDISNS)",
			    host->hdisns ? "Enabled" : "Disabled");
		obj_add_str(r, "Copy Descriptor Format 2h Enable (CDF2E)",
			    host->cdfe & (1 << 2) ? "True" : "False");
		obj_add_str(r, "Copy Descriptor Format 3h Enable (CDF3E)",
			    host->cdfe & (1 << 3) ? "True" : "False");
		obj_add_str(r, "Copy Descriptor Format 4h Enable (CDF4E)",
			    host->cdfe & (1 << 4) ? "True" : "False");
	}
}

static void json_feature_show_fields_sanitize(struct json_object *r,
					      unsigned int result)
{
	obj_add_uint(r, "No-Deallocate Response Mode (NODRM)", result & 1);
}

static void json_feature_show_fields_endurance_evt_cfg(struct json_object *r,
						       unsigned int result)
{
	obj_add_uint(r, "Endurance Group Identifier (ENDGID)", result & 0xffff);
	obj_add_uint(r, "Endurance Group Critical Warnings",
		     result >> 16 & 0xff);
}

static void json_feature_show_fields_iocs_profile(struct json_object *r,
						  unsigned int result)
{
	obj_add_str(r, "I/O Command Set Profile",
		    result & 0x1 ? "True" : "False");
}

static void json_feature_show_fields_spinup_control(struct json_object *r,
						    unsigned int result)
{
	obj_add_str(r, "Spinup control feature Enabled",
		    result & 1 ? "True" : "False");
}

static void json_feature_show_fields_power_loss_signal(struct json_object *r,
						       unsigned int result)
{
	obj_add_str(r, "Power Loss Signaling Mode (PLSM)",
		    nvme_pls_mode_to_string(NVME_GET(result, FEAT_PLS_MODE)));
}

static void json_feat_perfc_std(struct json_object *r,
				struct nvme_std_perf_attr *data)
{
	obj_add_str(r, "random 4 kib average read latency",
		    nvme_feature_perfc_r4karl_to_string(data->r4karl));
	obj_add_uint_02x(r, "R4KARL", data->r4karl);
}

static void json_feat_perfc_id_list(struct json_object *r,
				    struct nvme_perf_attr_id_list *data)
{
	int i;
	int attri_vs;
	char json_str[STR_LEN];
	struct json_object *paida = json_create_array();
	struct json_object *paide;

	obj_add_str(r, "attribute type",
		    nvme_feature_perfc_attrtyp_to_string(data->attrtyp));
	obj_add_uint_02x(r, "ATTRTYP", data->attrtyp);
	obj_add_int(r,
		    "maximum saveable vendor specific performance attributes (MSVSPA)",
		    data->msvspa);
	obj_add_int(r,
		    "unused saveable vendor specific performance attributes (USVSPA)",
		    data->usvspa);

	obj_add_array(r, "performance attribute identifier list", paida);
	for (i = 0; i < ARRAY_SIZE(data->id_list); i++) {
		paide = json_create_object();
		array_add_obj(paida, paide);
		attri_vs = i + NVME_FEAT_PERFC_ATTRI_VS_MIN;
		sprintf(json_str,
			"performance attribute %02xh identifier (PA%02XHI)",
			attri_vs, attri_vs);
		obj_add_str(paide, json_str,
			    shr_uuid_to_string(data->id_list[i].id));
	}
}

static void json_feat_perfc_vs(struct json_object *r,
			       struct nvme_vs_perf_attr *data)
{
	__u16 attrl = le16_to_cpu(data->attrl);

	obj_add_str(r, "performance attribute identifier (PAID)",
		    shr_uuid_to_string(data->paid));
	obj_add_uint(r, "attribute length (ATTRL)", attrl);
	obj_d(r, "vendor specific (VS)", (unsigned char *)data->vs,
	      min_t(size_t, attrl, sizeof(data->vs)), 16, 1);
}

static void json_feat_perfc(struct json_object *r, enum nvme_features_id fid,
			    unsigned int result,
			    struct nvme_perf_characteristics *data)
{
	__u8 attri;
	bool rvspa;

	nvme_feature_decode_perf_characteristics(result, &attri, &rvspa);

	obj_add_str(r, "attribute index",
		    nvme_feature_perfc_attri_to_string(attri));
	obj_add_uint_02x(r, "ATTRI", attri);

	switch (attri) {
	case NVME_FEAT_PERFC_ATTRI_STD:
		json_feat_perfc_std(r, data->std_perf);
		break;
	case NVME_FEAT_PERFC_ATTRI_ID_LIST:
		json_feat_perfc_id_list(r, data->id_list);
		break;
	case NVME_FEAT_PERFC_ATTRI_VS_MIN ... NVME_FEAT_PERFC_ATTRI_VS_MAX:
		json_feat_perfc_vs(r, data->vs_perf);
		break;
	default:
		break;
	}
}

static void json_host_metadata(struct json_object *r, enum nvme_features_id fid,
			       struct nvme_host_metadata *data)
{
	struct nvme_metadata_element_desc desc;
	const __u8 *v;
	size_t off = 0;
	int i;
	char val[VAL_LEN];
	__u16 len;
	char json_str[STR_LEN];
	struct json_object *desca = json_create_array();
	struct json_object *desce;

	obj_add_int(r, "Num Metadata Element Descriptors", data->ndesc);

	obj_add_array(r, "Metadata Element Descriptors", desca);

	for (i = 0; i < data->ndesc; i++) {
		v = nvme_host_metadata_element(data, &off, &desc, &len);
		if (!v)
			break;

		desce = json_create_object();
		array_add_obj(desca, desce);

		obj_add_int(desce, "Element", i);

		snprintf(json_str, sizeof(json_str), "0x%02x", desc.type);
		obj_add_str(desce, "Type", json_str);

		obj_add_str(desce, "Type definition",
			    nvme_host_metadata_type_to_string(fid, desc.type));

		obj_add_int(desce, "Revision", desc.rev);

		obj_add_int(desce, "Length", le16_to_cpu(desc.len));

		snprintf(val, sizeof(val), "%.*s", len, (const char *)v);
		obj_add_str(desce, "Value", val);
	}
}

static void json_feature_show_fields_ns_metadata(struct json_object *r,
						 enum nvme_features_id fid,
						 unsigned char *buf)
{
	if (buf)
		json_host_metadata(r, fid, (struct nvme_host_metadata *)buf);
}

static void json_feature_show_fields_sw_progress(struct json_object *r,
						 unsigned int result)
{
	obj_add_uint(r, "Pre-boot Software Load Count (PBSLC)", result & 0xff);
}

static void json_feature_show_fields_host_id(struct json_object *r,
		unsigned int result, unsigned char *hostid)
{
	bool exhid;

	if (!hostid)
		return;

	nvme_feature_decode_host_id(result, &exhid);

	if (exhid)
		obj_add_str(r, "Host Identifier (HOSTID)",
			    uint128_t_to_l10n_string(le128_to_cpu(hostid)));
	else
		obj_add_uint64(r, "Host Identifier (HOSTID)",
			       le64_to_cpu(*(__le64 *)hostid));
}

static void json_feature_show_fields_resv_nf_mask(struct json_object *r,
						  unsigned int result)
{
	obj_add_str(r, "Mask Reservation Preempted Notification (RESPRE)",
		    (result & 8) >> 3 ? "True" : "False");
	obj_add_str(r, "Mask Reservation Released Notification (RESREL)",
		    (result & 4) >> 2 ? "True" : "False");
	obj_add_str(r, "Mask Registration Preempted Notification (REGPRE)",
		    (result & 2) >> 1 ? "True" : "False");
}

static void json_feature_show_fields_resv_persist(struct json_object *r,
						  unsigned int result)
{
	obj_add_str(r, "Persist Through Power Loss (PTPL)",
		    result & 1 ? "True" : "False");
}

static void json_feature_show_fields_write_protect(struct json_object *r,
						   unsigned int result)
{
	obj_add_str(r, "Namespace Write Protect",
		    nvme_ns_wp_cfg_to_string(result));
}

static void json_feature_show_fields_fdp(struct json_object *r,
					 unsigned int result)
{
	obj_add_str(r, "Flexible Direct Placement Enable (FDPE)",
		    result & 1 ? "Yes" : "No");
	obj_add_uint(r, "Flexible Direct Placement Configuration Index",
		     result >> 8 & 0xf);
}

static void json_feature_show_fields_fdp_events(struct json_object *r,
						unsigned int result,
						unsigned char *buf)
{
	unsigned int i;
	struct nvme_fdp_supported_event_desc *d;
	char json_str[STR_LEN];

	// NOET is in bits 7:0; bits 31:8 are reserved.
	for (i = 0; i < (result & 0xff); i++) {
		d = &((struct nvme_fdp_supported_event_desc *)buf)[i];
		sprintf(json_str, "%s",
			d->evta & 0x1 ? "Enabled" : "Not enabled");
		obj_add_str(r, nvme_fdp_event_to_string(d->evt), json_str);
	}
}

static void json_feature_show_fields_bpwp(struct json_object *r,
					  unsigned int result)
{
	__u8 field;

	field = NVME_FEAT_BPWPC_BP0WPS(result);
	obj_add_str(r, "Boot Partition 0 Write Protection State",
		    nvme_bpwps_to_string(field));
	field = NVME_FEAT_BPWPC_BP1WPS(result);
	obj_add_str(r, "Boot Partition 1 Write Protection State",
		    nvme_bpwps_to_string(field));
}

static char *get_power_and_scale(__u16 power, __u8 scale)
{
	char *str;
	int ret;

	switch (scale) {
	case NVME_PSD_PS_NOT_REPORTED:
		/* Not reported for this power state */
		ret = asprintf(&str, "-");
		break;
	case NVME_PSD_PS_100_MICRO_WATT:
		/* Units of 0.0001W */
		ret = asprintf(&str, "%01u.%04uW", power / 10000,
			       power % 10000);
		break;
	case NVME_PSD_PS_10_MILLI_WATT:
		/* Units of 0.01W */
		ret = asprintf(&str, "%01u.%02uW", power / 100, power % 100);
		break;
	default:
		ret = asprintf(&str, "reserved");
		break;
	}

	if (ret > 0)
		return str;

	return NULL;
}

static void json_feature_show_fields_power_limit(struct json_object *r,
						 unsigned int result)
{
	__u8 field = NVME_FEAT_POWER_LIMIT_PLS(result);

	__cleanup_free char *k =
	    get_power_and_scale(NVME_FEAT_POWER_LIMIT_PLV(result), field);

	obj_add_str(r, "Power Limit Scale (PLS)",
		    nvme_feature_power_limit_scale_to_string(field));
	obj_add_uint(r, "Power Limit Value (PLV)",
		     NVME_FEAT_POWER_LIMIT_PLV(result));
	obj_add_str(r, "Power Limit", k);
}

static void json_feature_show_fields_power_thresh(struct json_object *r,
						  unsigned int result)
{
	__u8 field;
	__u16 ptv;
	__cleanup_free char *k = NULL;

	field = NVME_FEAT_POWER_THRESH_EPT(result);

	obj_add_str(r, "Enable Power Threshold (EPT)",
		    field ? "Enabled" : "Disabled");

	field = NVME_FEAT_POWER_THRESH_PMTS(result);
	obj_add_str(r, "Power Measurement Type Select (PMTS)",
		    nvme_power_measurement_type_to_string(field));

	field = NVME_FEAT_POWER_THRESH_PTS(result);
	obj_add_str(r, "Power Threshold Scale (PTS)",
		    nvme_feature_power_limit_scale_to_string(field));

	ptv = NVME_FEAT_POWER_THRESH_PTV(result);

	obj_add_uint(r, "Power Threshold Value (PTV)", ptv);

	k = get_power_and_scale(ptv, NVME_FEAT_POWER_THRESH_PTS(result));
	obj_add_str(r, "Power Threshold", k);
}

static void json_feature_show_fields_power_meas(struct json_object *r,
						unsigned int result)
{
	__u8 field;
	__u16 smt;

	field = NVME_FEAT_POWER_MEAS_ACT(result);
	obj_add_str(r, "Action (ACT)",
		nvme_power_measurement_action_to_string(field));

	field = NVME_FEAT_POWER_MEAS_PMTS(result);
	obj_add_str(r, "Power Measurement Type Select (PMTS)",
		nvme_power_measurement_type_to_string(field));

	smt = NVME_FEAT_POWER_MEAS_SMT(result);

	obj_add_uint(r, "Stop Measurement Time (SMT)", smt);
}

static void json_feature_show_fields_voltage_threshold(struct json_object *r,
							unsigned int result)
{
	obj_add_uint(r, "Voltage Sensor Select (VSENS)",
		     NVME_FEAT_VOLTAGE_THRESHOLD_VSENS(result));
	obj_add_str(r, "Enable Voltage Threshold (EVT)",
		    result & NVME_FEAT_VOLTAGE_THRESHOLD_EVT ?
		    "Enabled" : "Disabled");
	obj_add_uint(r, "Overvoltage Threshold (OVT)",
		     NVME_FEAT_VOLTAGE_THRESHOLD_OVT(result));
	obj_add_uint(r, "Undervoltage Threshold (UVT)",
		     NVME_FEAT_VOLTAGE_THRESHOLD_UVT(result));
}

static void json_feature_show_fields_voltage_measurement(struct json_object *r,
							  unsigned int result)
{
	obj_add_uint(r, "Action (ACT)",
		     NVME_FEAT_VOLTAGE_MEASUREMENT_ACT(result));
}

static void json_rate_limiting_data(struct json_object *r,
				    struct nvme_rate_limiting_data *rld)
{
	__u16 rlc = le16_to_cpu(rld->rlc);
	__u16 rlm = NVME_RATE_LIMITING_RLC_RLM(rlc);

	obj_add_str(r, "Rate Limiting Enable (RLE)",
		    NVME_RATE_LIMITING_RLC_RLE(rlc) ? "Enabled" : "Disabled");
	obj_add_uint(r, "Rate Limiting Mode (RLM)", rlm);
	obj_add_str(r, "RLM description",
		    rlm == NVME_RATE_LIMITING_MODE_SOFT_LIMIT ? "Soft Limit" :
		    rlm == NVME_RATE_LIMITING_MODE_HARD_LIMIT ?
		    "Hard Limit" : "Reserved");
	obj_add_uint(r, "Bandwidth Scale Factor (BWSF)", rld->bwsf);
	obj_add_uint64(r, "Total Bandwidth Value (TBWV)",
		       le64_to_cpu(rld->tbwv));
	obj_add_uint64(r, "Write Bandwidth Value (WBWV)",
		       le64_to_cpu(rld->wbwv));
	obj_add_uint(r, "Total IOPS (TIOPS)", le32_to_cpu(rld->tiops));
	obj_add_uint(r, "Write IOPS (WIOPS)", le32_to_cpu(rld->wiops));
	obj_add_uint(r, "Read IOPS Ratio (RIOPSR)", rld->riopsr);
	obj_add_uint(r, "Write IOPS Ratio (WIOPSR)", rld->wiopsr);
	obj_add_uint(r, "Read Bandwidth Ratio (RBWR)", rld->rbwr);
	obj_add_uint(r, "Write Bandwidth Ratio (WBWR)", rld->wbwr);
}

static void json_feature_show_fields_rate_limiting(struct json_object *r,
						   unsigned char *buf)
{
	if (buf)
		json_rate_limiting_data(r,
					(struct nvme_rate_limiting_data *)buf);
}

static void json_feature_show(enum nvme_features_id fid, int sel,
			      unsigned int result, void *buf, __u32 data_len)
{
	struct json_object *r;
	char json_str[STR_LEN];

	sprintf(json_str, "feature: %#0*x", fid ? 4 : 2, fid);
	r = obj_create(json_str);

	obj_add_str(r, "name", nvme_feature_to_string(fid));

	sprintf(json_str, "%#0*x", result ? 10 : 8, result);
	obj_add_str(r, nvme_select_to_string(sel), json_str);

	obj_print(r);

	if (NVME_CHECK(sel, GET_FEATURES_SEL, SUPPORTED))
		json_select_result(fid, result);
	else
		json_feature_show_fields(fid, result, buf);
}

void json_feature_show_fields(enum nvme_features_id fid, unsigned int result,
			      unsigned char *buf)
{
	struct json_object *r;
	char json_str[STR_LEN];

	sprintf(json_str, "Feature: %#0*x", fid ? 4 : 2, fid);
	r = obj_create(json_str);

	switch (fid) {
	case NVME_FEAT_FID_ARBITRATION:
		json_feature_show_fields_arbitration(r, result);
		break;
	case NVME_FEAT_FID_POWER_MGMT:
		json_feature_show_fields_power_mgmt(r, result);
		break;
	case NVME_FEAT_FID_LBA_RANGE:
		json_feature_show_fields_lba_range(r, result & 0x3f, buf);
		break;
	case NVME_FEAT_FID_TEMP_THRESH:
		json_feature_show_fields_temp_thresh(r, result);
		break;
	case NVME_FEAT_FID_ERR_RECOVERY:
		json_feature_show_fields_err_recovery(r, result);
		break;
	case NVME_FEAT_FID_VOLATILE_WC:
		json_feature_show_fields_volatile_wc(r, result);
		break;
	case NVME_FEAT_FID_NUM_QUEUES:
		json_feature_show_fields_num_queues(r, result);
		break;
	case NVME_FEAT_FID_IRQ_COALESCE:
		json_feature_show_fields_irq_coalesce(r, result);
		break;
	case NVME_FEAT_FID_IRQ_CONFIG:
		json_feature_show_fields_irq_config(r, result);
		break;
	case NVME_FEAT_FID_WRITE_ATOMIC:
		json_feature_show_fields_write_atomic(r, result);
		break;
	case NVME_FEAT_FID_ASYNC_EVENT:
		json_feature_show_fields_async_event(r, result);
		break;
	case NVME_FEAT_FID_AUTO_PST:
		json_feature_show_fields_auto_pst(r, result, buf);
		break;
	case NVME_FEAT_FID_HOST_MEM_BUF:
		json_feature_show_fields_host_mem_buf(r, result, buf);
		break;
	case NVME_FEAT_FID_TIMESTAMP:
		json_feature_show_fields_timestamp(r, buf);
		break;
	case NVME_FEAT_FID_KATO:
		json_feature_show_fields_kato(r, result);
		break;
	case NVME_FEAT_FID_HCTM:
		json_feature_show_fields_hctm(r, result);
		break;
	case NVME_FEAT_FID_NOPSC:
		json_feature_show_fields_nopsc(r, result);
		break;
	case NVME_FEAT_FID_RRL:
		json_feature_show_fields_rrl(r, result);
		break;
	case NVME_FEAT_FID_PLM_CONFIG:
		json_feature_show_fields_plm_config(r, result, buf);
		break;
	case NVME_FEAT_FID_PLM_WINDOW:
		json_feature_show_fields_plm_window(r, result);
		break;
	case NVME_FEAT_FID_LBA_STS_INTERVAL:
		json_feature_show_fields_lba_sts_interval(r, result);
		break;
	case NVME_FEAT_FID_HOST_BEHAVIOR:
		json_feature_show_fields_host_behavior(r, buf);
		break;
	case NVME_FEAT_FID_SANITIZE:
		json_feature_show_fields_sanitize(r, result);
		break;
	case NVME_FEAT_FID_ENDURANCE_EVT_CFG:
		json_feature_show_fields_endurance_evt_cfg(r, result);
		break;
	case NVME_FEAT_FID_IOCS_PROFILE:
		json_feature_show_fields_iocs_profile(r, result);
		break;
	case NVME_FEAT_FID_SPINUP_CONTROL:
		json_feature_show_fields_spinup_control(r, result);
		break;
	case NVME_FEAT_FID_POWER_LOSS_SIGNAL:
		json_feature_show_fields_power_loss_signal(r, result);
		break;
	case NVME_FEAT_FID_PERF_CHARACTERISTICS:
		json_feat_perfc(r, fid, result,
				(struct nvme_perf_characteristics *)buf);
		break;
	case NVME_FEAT_FID_ENH_CTRL_METADATA:
	case NVME_FEAT_FID_CTRL_METADATA:
	case NVME_FEAT_FID_NS_METADATA:
		json_feature_show_fields_ns_metadata(r, fid, buf);
		break;
	case NVME_FEAT_FID_SW_PROGRESS:
		json_feature_show_fields_sw_progress(r, result);
		break;
	case NVME_FEAT_FID_HOST_ID:
		json_feature_show_fields_host_id(r, result, buf);
		break;
	case NVME_FEAT_FID_RESV_NF_MASK:
		json_feature_show_fields_resv_nf_mask(r, result);
		break;
	case NVME_FEAT_FID_RESV_PERSIST:
		json_feature_show_fields_resv_persist(r, result);
		break;
	case NVME_FEAT_FID_WRITE_PROTECT:
		json_feature_show_fields_write_protect(r, result);
		break;
	case NVME_FEAT_FID_FDP:
		json_feature_show_fields_fdp(r, result);
		break;
	case NVME_FEAT_FID_FDP_EVENTS:
		json_feature_show_fields_fdp_events(r, result, buf);
		break;
	case NVME_FEAT_FID_BP_WRITE_PROTECT:
		json_feature_show_fields_bpwp(r, result);
		break;
	case NVME_FEAT_FID_POWER_LIMIT:
		json_feature_show_fields_power_limit(r, result);
		break;
	case NVME_FEAT_FID_POWER_THRESH:
		json_feature_show_fields_power_thresh(r, result);
		break;
	case NVME_FEAT_FID_POWER_MEASUREMENT:
		json_feature_show_fields_power_meas(r, result);
		break;
	case NVME_FEAT_FID_VOLTAGE_THRESHOLD:
		json_feature_show_fields_voltage_threshold(r, result);
		break;
	case NVME_FEAT_FID_VOLTAGE_MEASUREMENT:
		json_feature_show_fields_voltage_measurement(r, result);
		break;
	case NVME_FEAT_FID_RATE_LIMITING:
		json_feature_show_fields_rate_limiting(r, buf);
		break;
	default:
		break;
	}

	obj_print(r);
}

static void json_lba_range(struct nvme_lba_range_type *lbrt, int nr_ranges)
{
	struct json_object *r = json_root();

	json_lba_range_entry(lbrt, nr_ranges, r);
}

static void json_lba_status_info(__u64 result)
{
	struct json_object *r = json_root();

	obj_add_uint(r, "LBA Status Information Poll Interval (LSIPI)",
		     (result >> 16) & 0xffff);
	obj_add_uint(r, "LBA Status Information Report Interval (LSIRI)",
		     result & 0xffff);
}

static struct feat_print_ops feat_json_print_ops = {
	.select_result			= json_select_result,
	.show_feature			= json_feature_show,
	.show_feature_fields		= json_feature_show_fields,
	.lba_range			= json_lba_range,
	.lba_status_info		= json_lba_status_info,
};

struct feat_print_ops *feat_get_json_print_ops(nvme_print_flags_t flags)
{
	feat_json_print_ops.flags = flags;
	return &feat_json_print_ops;
}
