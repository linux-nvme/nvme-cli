#ifndef NVME_PRINT_H
#define NVME_PRINT_H

#include "nvme.h"
#include <inttypes.h>

void d(unsigned char *buf, int len, int width, int group);
void d_raw(unsigned char *buf, unsigned len);
uint64_t int48_to_long(__u8 *data);

void nvme_show_status(__u16 status);
void nvme_show_relatives(const char *name);
const char *nvme_cmd_to_string(int admin, __u8 opcode);
void __nvme_show_id_ctrl(struct nvme_id_ctrl *ctrl, unsigned int mode,
	void (*vendor_show)(__u8 *vs, struct json_object *root));
void nvme_show_id_ctrl(struct nvme_id_ctrl *ctrl, unsigned int mode);
void nvme_show_id_ns(struct nvme_id_ns *ns, unsigned int nsid,
	enum nvme_print_flags flags);
void nvme_show_resv_report(struct nvme_reservation_status *status, int bytes, __u32 cdw11,
	enum nvme_print_flags flags);
void nvme_show_lba_range(struct nvme_lba_range_type *lbrt, int nr_ranges);
void nvme_show_error_log(struct nvme_error_log_page *err_log, int entries,
	const char *devname, enum nvme_print_flags flags);
void nvme_show_smart_log(struct nvme_smart_log *smart, unsigned int nsid,
	const char *devname, enum nvme_print_flags flags);
void nvme_show_ana_log(struct nvme_ana_rsp_hdr *ana_log, const char *devname,
	enum nvme_print_flags flags, size_t len);
void nvme_show_self_test_log(struct nvme_self_test_log *self_test, __u8 dst_entries,
	__u32 size, const char *devname, enum nvme_print_flags flags);
void nvme_show_fw_log(struct nvme_firmware_log_page *fw_log, const char *devname,
	enum nvme_print_flags flags);
void nvme_show_effects_log(struct nvme_effects_log_page *effects, unsigned int flags);
void nvme_show_changed_ns_list_log(struct nvme_changed_ns_list_log *log,
	const char *devname, enum nvme_print_flags flags);
void nvme_show_endurance_log(struct nvme_endurance_group_log *endurance_log,
	__u16 group_id, const char *devname, enum nvme_print_flags flags);
void nvme_show_sanitize_log(struct nvme_sanitize_log_page *sanitize,
	const char *devname, enum nvme_print_flags flags);
void json_predictable_latency_per_nvmset(
	struct nvme_predlat_per_nvmset_log_page *plpns_log,
	__u16 nvmset_id);
void nvme_show_predictable_latency_per_nvmset(
	struct nvme_predlat_per_nvmset_log_page *plpns_log,
	__u16 nvmset_id, const char *devname, enum nvme_print_flags flags);
void json_predictable_latency_event_agg_log(
	struct nvme_event_agg_log_page *pea_log,
	__u64 log_entries);
void nvme_show_predictable_latency_event_agg_log(
	struct nvme_event_agg_log_page *pea_log,
	__u64 log_entries, __u32 size, const char *devname,
	enum nvme_print_flags flags);
void json_persistent_event_log(void *pevent_log_info, __u32 size);
void nvme_show_persistent_event_log(void *pevent_log_info,
	__u8 action, __u32 size, const char *devname,
	enum nvme_print_flags flags);
void json_endurance_group_event_agg_log(
	struct nvme_event_agg_log_page *endurance_log,
	__u64 log_entries);
void nvme_show_endurance_group_event_agg_log(
	struct nvme_event_agg_log_page *endurance_log,
	__u64 log_entries, __u32 size, const char *devname,
	enum nvme_print_flags flags);
void json_lba_status_log(void *lba_status);
void nvme_show_lba_status_log(void *lba_status, __u32 size,
	const char *devname, enum nvme_print_flags flags);
void nvme_show_resv_notif_log(struct nvme_resv_notif_log *resv,
	const char *devname, enum nvme_print_flags flags);
void nvme_show_ctrl_registers(void *bar, bool fabrics, enum nvme_print_flags flags);
void nvme_show_single_property(int offset, uint64_t prop, int human);
void nvme_show_id_ns_descs(void *data, unsigned nsid, enum nvme_print_flags flags);
void nvme_show_lba_status(struct nvme_lba_status *list, unsigned long len,
	enum nvme_print_flags flags);
void nvme_show_list_items(struct nvme_topology *t, enum nvme_print_flags flags);
void nvme_show_subsystem_list(struct nvme_topology *t,
      enum nvme_print_flags flags);
void nvme_show_id_nvmset(struct nvme_id_nvmset *nvmset, unsigned nvmset_id,
	enum nvme_print_flags flags);
void nvme_show_primary_ctrl_caps(const struct nvme_primary_ctrl_caps *caps,
	enum nvme_print_flags flags);
void nvme_show_list_secondary_ctrl(const struct nvme_secondary_controllers_list *sc_list,
	__u32 count, enum nvme_print_flags flags);
void nvme_show_id_ns_granularity_list(const struct nvme_id_ns_granularity_list *glist,
	enum nvme_print_flags flags);
void nvme_show_id_uuid_list(const struct nvme_id_uuid_list *uuid_list,
	enum nvme_print_flags flags);
void nvme_show_id_iocs(struct nvme_id_iocs *iocs);

void nvme_feature_show_fields(enum nvme_feat fid, unsigned int result, unsigned char *buf);
void nvme_directive_show(__u8 type, __u8 oper, __u16 spec, __u32 nsid, __u32 result,
	void *buf, __u32 len, enum nvme_print_flags flags);
void nvme_show_select_result(__u32 result);
void nvme_show_lba_status_info(__u32 result);

void nvme_show_zns_id_ctrl(struct nvme_zns_id_ctrl *ctrl, unsigned int mode);
void nvme_show_id_ctrl_nvm(struct nvme_id_ctrl_nvm *ctrl_nvm,
	enum nvme_print_flags flags);
void nvme_show_zns_id_ns(struct nvme_zns_id_ns *ns,
	struct nvme_id_ns *id_ns, unsigned long flags);
void nvme_show_zns_changed( struct nvme_zns_changed_zone_log *log,
	unsigned long flags);
void nvme_show_zns_report_zones(void *report, __u32 descs,
	__u8 ext_size, __u32 report_size, unsigned long flags);

const char *nvme_status_to_string(__u16 status);
const char *nvme_select_to_string(int sel);
const char *nvme_feature_to_string(enum nvme_feat feature);
const char *nvme_register_to_string(int reg);

#endif
