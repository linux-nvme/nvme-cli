/* SPDX-License-Identifier: GPL-2.0-or-later */
#pragma once

#include <libnvme.h>

#include "nvme-print.h"

/*
 * The host discovery log record at offset @off of a page of @len bytes, or
 * NULL if no whole record starts there. The page ends where its header
 * says or where the buffer ends, whichever comes first. A record must hold
 * at least its fixed part, and its length must not reach past the page.
 * The length of a record need not be a multiple of 4, so a record need not
 * be aligned: copy it before reading it.
 */
static inline void *
nvme_host_discovery_record(struct nvme_host_discovery_log *log, __u64 len,
			   __u64 off)
{
	__u64 thdlpl = le32_to_cpu(log->thdlpl);
	__u64 end = thdlpl < len ? thdlpl : len;
	void *rec;
	__u32 tel;

	if (off > end ||
	    end - off < sizeof(struct nvme_host_ext_discovery_log))
		return NULL;

	rec = (void *)log + off;
	tel = shr_get_unaligned_le32(rec +
		offsetof(struct nvme_host_ext_discovery_log, tel));
	if (tel < sizeof(struct nvme_host_ext_discovery_log) ||
	    tel > end - off)
		return NULL;

	return rec;
}

/*
 * The extended attribute at @p of the host discovery log record @rec of
 * @tel bytes, its header copied to @exat, or NULL if it, with its value,
 * doesn't fit the record.
 */
static inline void *
nvme_host_discovery_exat(void *rec, __u32 tel, void *p,
			 struct nvmf_ext_attr *exat)
{
	void *end = rec + tel;

	if (!shr_buf_has_room(p, end, sizeof(*exat)))
		return NULL;
	memcpy(exat, p, sizeof(*exat));
	if (!shr_buf_has_room(p + sizeof(*exat), end,
			      le16_to_cpu(exat->exatlen)))
		return NULL;

	return p;
}

/* The extended attribute behind the one at @p, as libnvmf_exat_ptr_next() */
static inline void *nvme_host_discovery_exat_next(void *p,
		const struct nvmf_ext_attr *exat)
{
	return p + sizeof(*exat) + ((le16_to_cpu(exat->exatlen) + 3) & ~3);
}

/*
 * The AVE discovery log record at offset @off of a page of @len bytes, or
 * NULL if no whole record starts there, as nvme_host_discovery_record().
 * The length of a record need not be a multiple of 4, so a record need not
 * be aligned: copy it before reading it.
 */
static inline void *
nvme_ave_discovery_record(struct nvme_ave_discovery_log *log, __u64 len,
			  __u64 off)
{
	__u64 tadlpl = le32_to_cpu(log->tadlpl);
	__u64 end = tadlpl < len ? tadlpl : len;
	void *rec;
	__u32 tel;

	if (off > end ||
	    end - off < sizeof(struct nvme_ave_discovery_log_entry))
		return NULL;

	rec = (void *)log + off;
	tel = shr_get_unaligned_le32(rec +
		offsetof(struct nvme_ave_discovery_log_entry, tel));
	if (tel < sizeof(struct nvme_ave_discovery_log_entry) ||
	    tel > end - off)
		return NULL;

	return rec;
}

/*
 * Return: the length of the operating system specific parameters of a pull
 * model DDC request log of @len bytes: what the header says, but no more
 * than the buffer holds.
 */
static inline __u32
nvme_pull_model_ddc_req_osp_len(struct nvme_pull_model_ddc_req_log *log,
				__u64 len)
{
	__u64 tpdrpl = le32_to_cpu(log->tpdrpl);
	__u64 end = tpdrpl < len ? tpdrpl : len;

	if (end <= offsetof(struct nvme_pull_model_ddc_req_log, osp))
		return 0;

	return end - offsetof(struct nvme_pull_model_ddc_req_log, osp);
}

/*
 * Copy the fixed part of the reachability group descriptor at offset @off
 * of a log of @len bytes to @rgd. The descriptors differ in length, so
 * they are only 4 byte aligned. Return: false if the descriptor doesn't
 * fit with its namespace ID list, which nvme_reachability_ids() returns.
 * The next descriptor is at nvme_reachability_group_next().
 */
static inline bool
nvme_reachability_group(struct nvme_reachability_groups_log *log, __u64 len,
			__u64 off, struct nvme_reachability_group_desc *rgd)
{
	if (off > len || len - off < sizeof(*rgd))
		return false;

	memcpy(rgd, (void *)log + off, sizeof(*rgd));
	return le32_to_cpu(rgd->nnid) <=
		(len - off - sizeof(*rgd)) / sizeof(rgd->nsid[0]);
}

static inline __u64
nvme_reachability_group_next(struct nvme_reachability_group_desc *rgd,
			     __u64 off)
{
	return off + sizeof(*rgd) +
		(__u64)le32_to_cpu(rgd->nnid) * sizeof(rgd->nsid[0]);
}

/*
 * The reachability association descriptor at offset @off of a log of @len
 * bytes, as nvme_reachability_group().
 */
static inline bool
nvme_reachability_association(struct nvme_reachability_associations_log *log,
			      __u64 len, __u64 off,
			      struct nvme_reachability_association_desc *rad)
{
	if (off > len || len - off < sizeof(*rad))
		return false;

	memcpy(rad, (void *)log + off, sizeof(*rad));
	return le32_to_cpu(rad->nrid) <=
		(len - off - sizeof(*rad)) / sizeof(rad->rgid[0]);
}

static inline __u64
nvme_reachability_association_next(
		struct nvme_reachability_association_desc *rad, __u64 off)
{
	return off + sizeof(*rad) +
		(__u64)le32_to_cpu(rad->nrid) * sizeof(rad->rgid[0]);
}

/*
 * The IDs which follow the reachability descriptor at offset @off, whose
 * fixed part is @size bytes long. They are 4 byte aligned, as they need.
 */
static inline __le32 *nvme_reachability_ids(void *log, __u64 off, size_t size)
{
	return log + off + size;
}

struct nvme_error_log_filter {
	bool valid;
	__u16 sqid;
	__u16 status;
	__u64 lba;
	__u32 nsid;
	__u8 trtype;
	__u8 csi;
	__u8 opcode;
};

/*
 * Walks the variable-length, device-reported array of EOM descriptors in a
 * phy_rx_eom_log, bounding every step against both dsize and the log
 * buffer actually allocated for it (see shr_buf_has_room()). Shared by the
 * json and stdout backends so the bounds-checking logic exists once.
 */
struct eom_desc_iter {
	unsigned char *p;
	unsigned char *cur;
	unsigned char *end;
	uint32_t dsize;
	uint16_t remaining;
};

static inline void eom_desc_iter_init(struct eom_desc_iter *it,
		struct nvme_phy_rx_eom_log *log, size_t len)
{
	it->p = (unsigned char *)log->descs;
	it->end = (unsigned char *)log + len;
	it->dsize = le32_to_cpu(log->dsize);
	it->remaining = le16_to_cpu(log->nd);
}

/*
 * Copies the fixed part of the next descriptor to @desc: dsize need not
 * keep the descriptors aligned. Returns false once the count is exhausted
 * or a descriptor no longer fits the log buffer -- a corrupt or hostile
 * dsize/nd pair gives no way to locate anything past that point, so the
 * walk stops there rather than guessing.
 */
static inline bool eom_desc_iter_next(struct eom_desc_iter *it,
		struct nvme_eom_lane_desc *desc)
{
	if (!it->remaining)
		return false;

	/*
	 * The full stride, not just the fixed descriptor, must fit: advancing
	 * by dsize below would otherwise form an out-of-bounds pointer.
	 */
	if (it->dsize < sizeof(*desc) ||
	    !shr_buf_has_room(it->p, it->end, it->dsize))
		return false;

	it->remaining--;
	it->cur = it->p;
	memcpy(desc, it->cur, sizeof(*desc));
	it->p += it->dsize;

	return true;
}

/* The eye data of the descriptor eom_desc_iter_next() copied last */
static inline unsigned char *eom_desc_iter_eye(struct eom_desc_iter *it)
{
	return it->cur + sizeof(struct nvme_eom_lane_desc);
}

/*
 * Validates the vendor-specific eye data following the descriptor most
 * recently copied by eom_desc_iter_next() against both dsize and the log
 * buffer. Returns the data and its length via *vsdatalen, or NULL with
 * *vsdatalen == 0 if it doesn't fit.
 */
static inline unsigned char *eom_desc_iter_vsdata(struct eom_desc_iter *it,
		const struct nvme_eom_lane_desc *desc, uint32_t *vsdatalen)
{
	uint16_t nrows = le16_to_cpu(desc->nrows);
	uint16_t ncols = le16_to_cpu(desc->ncols);
	uint32_t edlen = le32_to_cpu(desc->edlen);
	size_t vsdataoffset = (size_t)nrows * ncols + sizeof(*desc);

	if (vsdataoffset > it->dsize || edlen > it->dsize - vsdataoffset ||
	    !shr_buf_has_room(it->cur, it->end, vsdataoffset + edlen)) {
		*vsdatalen = 0;
		return NULL;
	}

	*vsdatalen = edlen;
	return it->cur + vsdataoffset;
}

/*
 * Walks the Media Unit Status Descriptors. A descriptor is CIO + 2 * MUCS
 * bytes long. CIO shall be a multiple of 16, but a device may report
 * another value, so each descriptor is copied before it is read.
 */
struct mus_desc_iter {
	unsigned char *start;
	unsigned char *p;
	unsigned char *end;
	unsigned char *chans;	// Channel Identifiers of the last descriptor
	uint16_t remaining;
	size_t need;		// log length needed if the buffer is short
};

static inline void mus_desc_iter_init(struct mus_desc_iter *it,
		struct nvme_media_unit_stat_log *log, size_t len)
{
	it->start = (unsigned char *)log;
	it->p = (unsigned char *)log->mus_desc;
	it->end = it->start + len;
	it->chans = NULL;
	it->remaining = len < sizeof(*log) ? 0 : le16_to_cpu(log->nmu);
	it->need = 0;
}

static inline bool mus_desc_iter_short(struct mus_desc_iter *it, size_t size)
{
	it->need = it->p - it->start + size;
	it->remaining = 0;

	return false;
}

/*
 * Copies the next descriptor to @desc. Returns false at the end of the
 * list, at the end of the buffer, or at a descriptor whose CIO points
 * into its own header: the next descriptors cannot be located then.
 */
static inline bool mus_desc_iter_next(struct mus_desc_iter *it,
		struct nvme_media_unit_stat_desc *desc)
{
	size_t size;

	if (!it->remaining)
		return false;

	if (!shr_buf_has_room(it->p, it->end, sizeof(*desc)))
		return mus_desc_iter_short(it, sizeof(*desc));

	memcpy(desc, it->p, sizeof(*desc));
	if (desc->cio < sizeof(*desc)) {
		it->remaining = 0;
		return false;
	}

	size = desc->cio + desc->mucs * sizeof(__le16);
	if (!shr_buf_has_room(it->p, it->end, size))
		return mus_desc_iter_short(it, size);

	it->chans = it->p + desc->cio;
	it->p += size;
	it->remaining--;

	return true;
}

/* Channel Identifier @i of the descriptor most recently returned. */
static inline uint16_t mus_desc_iter_chan(const struct mus_desc_iter *it,
		int i)
{
	__le16 id;

	memcpy(&id, it->chans + i * sizeof(id), sizeof(id));

	return le16_to_cpu(id);
}

struct log_print_ops {
	void (*ana_log)(struct nvme_ana_log *ana_log, const char *devname,
			size_t len);
	void (*boot_part_log)(void *bp_log, const char *devname, __u32 size);
	void (*phy_rx_eom_log)(struct nvme_phy_rx_eom_log *log,
			       __u16 controller, size_t len);
	void (*effects_log_list)(struct list_head *list);
	void (*endurance_group_event_agg_log)(
		struct nvme_aggregate_endurance_group_event *endurance_log,
		__u64 log_entries, __u32 size, const char *devname);
	void (*endurance_log)(struct nvme_endurance_group_log *endurance_group,
			      __u16 group_id, const char *devname);
	void (*error_log)(struct nvme_error_log_page *err_log, int entries,
			  const char *devname,
			  struct nvme_error_log_filter *flt);
	void (*fid_supported_effects_log)(
		struct nvme_fid_supported_effects_log *fid_log,
		const char *devname);
	void (*fw_log)(struct nvme_firmware_slot *fw_log, const char *devname);
	void (*lba_status_log)(void *lba_status, __u32 size,
			       const char *devname);
	void (*media_unit_stat_log)(struct nvme_media_unit_stat_log *mus,
				    size_t len);
	void (*mi_cmd_support_effects_log)(
		struct nvme_mi_cmd_supported_effects_log *mi_cmd_log,
		const char *devname);
	void (*ns_list_log)(struct nvme_ns_list *log, const char *devname,
			    bool alloc);
	void (*persistent_event_log)(void *pevent_log_info, __u8 action,
				     __u32 size, const char *devname);
	void (*power_meas_log)(struct nvme_power_meas_log *log, __u32 size);
	void (*predictable_latency_event_agg_log)(
		struct nvme_aggregate_predictable_lat_event *pea_log,
		__u64 log_entries, __u32 size, const char *devname);
	void (*predictable_latency_per_nvmset)(
		struct nvme_nvmset_predictable_lat_log *plpns_log,
		__u16 nvmset_id, const char *devname);
	void (*resv_notification_log)(struct nvme_resv_notification_log *resv,
				      const char *devname);
	void (*sanitize_log_page)(struct nvme_sanitize_log_page *sanitize_log,
				  const char *devname);
	void (*self_test_log)(struct nvme_self_test_log *self_test,
			      __u8 dst_entries, __u32 size,
			      const char *devname);
	void (*smart_log)(struct nvme_smart_log *smart, unsigned int nsid,
			  const char *devname);
	void (*supported_cap_config_list_log)(
		struct nvme_supported_cap_config_list_log *cap_log, size_t len);
	void (*supported_log_pages)(
		struct nvme_supported_log_pages *support_log,
		const char *devname);
	void (*mgmt_addr_list_log)(struct nvme_mgmt_addr_list_log *ma_log);
	void (*rotational_media_info_log)(
		struct nvme_rotational_media_info_log *info);
	void (*dispersed_ns_psub_log)(
		struct nvme_dispersed_ns_participating_nss_log *log, __u64 len);
	void (*reachability_groups_log)(
		struct nvme_reachability_groups_log *log, __u64 len);
	void (*reachability_associations_log)(
		struct nvme_reachability_associations_log *log, __u64 len);
	void (*host_discovery_log)(struct nvme_host_discovery_log *log,
				   __u64 len);
	void (*ave_discovery_log)(struct nvme_ave_discovery_log *log,
				  __u64 len);
	void (*pull_model_ddc_req_log)(struct nvme_pull_model_ddc_req_log *log,
				       __u64 len);
	void (*voltage_meas_log)(struct nvme_voltage_measurement_log *log,
				 __u32 size);
};

struct log_print_ops *log_get_stdout_print_ops(void);
struct log_print_ops *log_get_binary_print_ops(void);

#ifdef CONFIG_JSONC
struct log_print_ops *log_get_json_print_ops(void);
#else
static inline struct log_print_ops *log_get_json_print_ops(void)
{
	return NULL;
}
#endif

void nvme_show_supported_log(struct nvme_supported_log_pages *support,
	const char *devname, nvme_print_flags_t flags);
void nvme_show_error_log(struct nvme_error_log_page *err_log, int entries,
	const char *devname, struct nvme_error_log_filter *flt,
	nvme_print_flags_t flags);
bool nvme_is_error_log_filter(struct nvme_error_log_page *err_log,
			      struct nvme_error_log_filter *flt);
void nvme_show_smart_log(struct nvme_smart_log *smart, unsigned int nsid,
			 const char *devname, nvme_print_flags_t flags);
void nvme_show_ana_log(struct nvme_ana_log *ana_log, const char *devname,
		       size_t len, nvme_print_flags_t flags);
void nvme_show_self_test_log(struct nvme_self_test_log *self_test,
			     __u8 dst_entries, __u32 size, const char *devname,
			     nvme_print_flags_t flags);
void nvme_show_fw_log(struct nvme_firmware_slot *fw_log, const char *devname,
	nvme_print_flags_t flags);
void nvme_print_effects_log_pages(struct list_head *list,
				  nvme_print_flags_t flags);
void nvme_show_changed_ns_list_log(struct nvme_ns_list *log,
				   const char *devname,
				   nvme_print_flags_t flags, bool alloc);
void nvme_show_endurance_log(struct nvme_endurance_group_log *endurance_log,
	__u16 group_id, const char *devname, nvme_print_flags_t flags);
void nvme_show_sanitize_log(struct nvme_sanitize_log_page *sanitize,
	const char *devname, nvme_print_flags_t flags);
void nvme_show_predictable_latency_per_nvmset(
	struct nvme_nvmset_predictable_lat_log *plpns_log,
	__u16 nvmset_id, const char *devname, nvme_print_flags_t flags);
void nvme_show_predictable_latency_event_agg_log(
	struct nvme_aggregate_predictable_lat_event *pea_log,
	__u64 log_entries, __u32 size, const char *devname,
	nvme_print_flags_t flags);
void nvme_show_persistent_event_log(void *pevent_log_info,
	__u8 action, __u32 size, const char *devname,
	nvme_print_flags_t flags);
void nvme_show_endurance_group_event_agg_log(
	struct nvme_aggregate_endurance_group_event *endurance_log,
	__u64 log_entries, __u32 size, const char *devname,
	nvme_print_flags_t flags);
void nvme_show_lba_status_log(void *lba_status, __u32 size,
	const char *devname, nvme_print_flags_t flags);
void nvme_show_resv_notif_log(struct nvme_resv_notification_log *resv,
	const char *devname, nvme_print_flags_t flags);
void nvme_show_boot_part_log(void *bp_log, const char *devname,
	__u32 size, nvme_print_flags_t flags);
void nvme_show_phy_rx_eom_log(struct nvme_phy_rx_eom_log *log,
	__u16 controller, size_t len, nvme_print_flags_t flags);
void nvme_show_fid_support_effects_log(
	struct nvme_fid_supported_effects_log *fid_log, const char *devname,
	nvme_print_flags_t flags);
void nvme_show_mi_cmd_support_effects_log(
	struct nvme_mi_cmd_supported_effects_log *mi_cmd_log,
	const char *devname, nvme_print_flags_t flags);
void nvme_show_media_unit_stat_log(struct nvme_media_unit_stat_log *mus,
	size_t len, nvme_print_flags_t flags);
void nvme_show_supported_cap_config_log(
	struct nvme_supported_cap_config_list_log *caplog, size_t len,
	nvme_print_flags_t flags);
void nvme_show_mgmt_addr_list_log(struct nvme_mgmt_addr_list_log *ma_list,
				  nvme_print_flags_t flags);
void nvme_show_power_meas_log(struct nvme_power_meas_log *log, __u32 size,
			      nvme_print_flags_t flags);
void nvme_show_voltage_meas_log(struct nvme_voltage_measurement_log *log,
				__u32 size, nvme_print_flags_t flags);
void nvme_show_rotational_media_info_log(
	struct nvme_rotational_media_info_log *info, nvme_print_flags_t flags);
void nvme_show_dispersed_ns_psub_log(
	struct nvme_dispersed_ns_participating_nss_log *log, __u64 len,
	nvme_print_flags_t flags);
void nvme_show_reachability_groups_log(struct nvme_reachability_groups_log *log,
				       __u64 len, nvme_print_flags_t flags);
void nvme_show_reachability_associations_log(
	struct nvme_reachability_associations_log *log, __u64 len,
	nvme_print_flags_t flags);
void nvme_show_host_discovery_log(struct nvme_host_discovery_log *log,
				  __u64 len, nvme_print_flags_t flags);
void nvme_show_ave_discovery_log(struct nvme_ave_discovery_log *log,
				 __u64 len, nvme_print_flags_t flags);
void nvme_show_pull_model_ddc_req_log(struct nvme_pull_model_ddc_req_log *log,
				      __u64 len, nvme_print_flags_t flags);

/* Log page decoder for get-log -v, see nvme_show_log() */
bool log_show_log(const char *devname, enum nvme_cmd_get_log_lid lid,
		  __u32 nsid, __u16 lsi, __u8 lsp, void *log, __u32 len,
		  nvme_print_flags_t flags);

const char *nvme_ana_state_to_string(enum nvme_ana_state state);
const char *nvme_log_to_string(__u8 lid);
const char *nvme_nss_hw_error_to_string(__u16 error_code);
const char *nvme_pel_event_to_string(int type);
const char *nvme_resv_notif_to_string(__u8 type);
const char *nvme_sstat_status_to_string(__u16 status);
const char *nvme_trtype_to_string(__u8 trtype);
const char *nvme_ssi_state_to_string(__u8 state);

/* Persistent event log decoders, also used by the ocp and ibm plugins */
const char *nvme_pel_rci_rcpit_to_string(enum nvme_pel_rci_rcpit rcpit);
const char *nvme_pel_ehai_pit_to_string(enum nvme_pel_ehai_pit pit);
void nvme_show_pel_header(struct nvme_persistent_event_log *pevent_log_head,
			  int human);
struct nvme_persistent_event_entry *nvme_pel_event(void *pevent_log_info,
		__u32 size, __u32 offset);
void *nvme_pel_event_data(void *pevent_log_info, __u32 offset, __u32 len,
		__u32 *buf_len);
void nvme_show_pel_event_header(
	int i, struct nvme_persistent_event_entry *pevent_entry_head,
	int human);
void nvme_show_pel_smart_health_event(void *pevent_log_info, __u32 offset,
				      const char *devname);
void nvme_show_pel_fw_commit_event(void *pevent_log_info, __u32 offset);
void nvme_show_pel_timestamp_event(void *pevent_log_info, __u32 offset);
void nvme_show_pel_power_on_reset_event(
	void *pevent_log_info, __u32 offset,
	struct nvme_persistent_event_entry *pevent_entry_head);
void nvme_show_pel_nss_hw_error_event(void *pevent_log_info, __u32 offset);
void nvme_show_pel_change_ns_event(void *pevent_log_info, __u32 offset);
void nvme_show_pel_format_start_event(void *pevent_log_info, __u32 offset);
void nvme_show_pel_format_completion_event(void *pevent_log_info, __u32 offset);
void nvme_show_pel_sanitize_start_event(void *pevent_log_info, __u32 offset);
void nvme_show_pel_sanitize_completion_event(void *pevent_log_info,
					     __u32 offset);
#define NVME_PEL_FEATURE_DATA_SIZE	4096
void *nvme_pel_set_feature_data(void *data, __u32 len);
void nvme_show_pel_set_feature_event(void *data, __u32 len);
void nvme_show_pel_thermal_excursion_event(void *pevent_log_info, __u32 offset);
void nvme_show_pel_vendor_specific_event(void *pevent_log_info, __u32 offset,
					 __u32 event_data_len);
void nvme_json_pevent_log_head(
	struct nvme_persistent_event_log *pevent_log_head,
	struct json_object *r);
void nvme_json_pel_smart_health(void *pevent_log_info, __u32 offset,
				struct json_object *valid_attrs);
void nvme_json_pel_fw_commit(void *pevent_log_info, __u32 offset,
			     struct json_object *valid_attrs);
void nvme_json_pel_timestamp(void *pevent_log_info, __u32 offset,
			     struct json_object *valid_attrs);
void nvme_json_pel_power_on_reset(void *pevent_log_info, __u32 offset,
				  struct json_object *valid_attrs,
				  __le16 vsil, __le16 el,
				  __u32 size);
void nvme_json_pel_nss_hw_error(void *pevent_log_info, __u32 offset,
				struct json_object *valid_attrs);
void nvme_json_pel_change_ns(void *pevent_log_info, __u32 offset,
			     struct json_object *valid_attrs);
void nvme_json_pel_format_start(void *pevent_log_info, __u32 offset,
				struct json_object *valid_attrs);
void nvme_json_pel_format_completion(void *pevent_log_info, __u32 offset,
				     struct json_object *valid_attrs);
void nvme_json_pel_sanitize_start(void *pevent_log_info, __u32 offset,
				  struct json_object *valid_attrs);
void nvme_json_pel_sanitize_completion(void *pevent_log_info, __u32 offset,
				       struct json_object *valid_attrs);
void nvme_json_pel_set_feature(void *data, __u32 len,
			       struct json_object *valid_attrs);
void nvme_json_pel_telemetry_crt(void *pevent_log_info, __u32 offset,
				 struct json_object *valid_attrs,
				 __u32 len, __u32 size);
void nvme_json_pel_thermal_excursion(void *pevent_log_info, __u32 offset,
				     struct json_object *valid_attrs);
void nvme_json_pel_vendor_specific_event(void *pevent_log_info, __u32 offset,
					 __u32 event_data_len,
					 struct json_object *valid_attrs);
