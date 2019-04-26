#ifndef NVME_PRINT_H
#define NVME_PRINT_H

#include "nvme.h"
#include "json.h"
#include <inttypes.h>

enum {
	TERSE = 0x1u,	// only show a few useful fields
	HUMAN = 0x2u,	// interpret some values for humans
	VS    = 0x4u,	// print vendor specific data area
	RAW   = 0x8u,	// just dump raw bytes
};

void d(unsigned char *buf, int len, int width, int group);
void d_raw(unsigned char *buf, unsigned len);
void show_nvme_status(__u16 status);

uint64_t int48_to_long(__u8 *data);

void __show_nvme_id_ctrl(struct nvme_id_ctrl *ctrl, unsigned int mode, void (*vendor_show)(__u8 *vs, struct json_object *root));
void show_nvme_id_ctrl(struct nvme_id_ctrl *ctrl, unsigned int mode);
void show_nvme_id_ns(struct nvme_id_ns *ns, unsigned int flags);
void show_nvme_resv_report(struct nvme_reservation_status *status, int bytes, __u32 cdw11);
void show_lba_range(struct nvme_lba_range_type *lbrt, int nr_ranges);
void show_error_log(struct nvme_error_log_page *err_log, int entries, const char *devname);
void show_smart_log(struct nvme_smart_log *smart, unsigned int nsid, const char *devname);
void show_ana_log(struct nvme_ana_rsp_hdr *ana_log, const char *devname);
void show_self_test_log(struct nvme_self_test_log *self_test, const char *devname);
void show_fw_log(struct nvme_firmware_log_page *fw_log, const char *devname);
void show_effects_log(struct nvme_effects_log_page *effects, unsigned int flags);
void show_changed_ns_list_log(struct nvme_changed_ns_list_log *log, const char *devname);
void show_endurance_log(struct nvme_endurance_group_log *endurance_group,
			__u16 group_id, const char *devname);
void show_sanitize_log(struct nvme_sanitize_log_page *sanitize, unsigned int mode, const char *devname);
void show_ctrl_registers(void *bar, unsigned int mode, bool fabrics);
void show_single_property(int offset, uint64_t prop, int human);
void show_nvme_id_ns_descs(void *data);
void show_list_items(struct list_item *list_items, unsigned len);
void show_nvme_subsystem_list(struct subsys_list_item *slist, int n);
void show_nvme_id_nvmset(struct nvme_id_nvmset *nvmset);
void show_nvme_list_secondary_ctrl(const struct nvme_secondary_controllers_list *sc_list, __u32 count);

void nvme_feature_show_fields(__u32 fid, unsigned int result, unsigned char *buf);
void nvme_directive_show_fields(__u8 dtype, __u8 doper, unsigned int result, unsigned char *buf);
const char *nvme_status_to_string(__u32 status);
const char *nvme_select_to_string(int sel);
const char *nvme_feature_to_string(int feature);
const char *nvme_register_to_string(int reg);
void nvme_show_select_result(__u32 result);

void json_nvme_id_ctrl(struct nvme_id_ctrl *ctrl, unsigned int mode, void (*vendor_show)(__u8 *vs, struct json_object *root));
void json_nvme_id_ns(struct nvme_id_ns *ns, unsigned int flags);
void json_nvme_resv_report(struct nvme_reservation_status *status, int bytes, __u32 cdw11);
void json_error_log(struct nvme_error_log_page *err_log, int entries, const char *devname);
void json_smart_log(struct nvme_smart_log *smart, unsigned int nsid, const char *devname);
void json_ana_log(struct nvme_ana_rsp_hdr *ana_log, const char *devname);
void json_effects_log(struct nvme_effects_log_page *effects_log, const char *devname);
void json_sanitize_log(struct nvme_sanitize_log_page *sanitize_log, const char *devname);
void json_fw_log(struct nvme_firmware_log_page *fw_log, const char *devname);
void json_changed_ns_list_log(struct nvme_changed_ns_list_log *log, const char *devname);
void json_endurance_log(struct nvme_endurance_group_log *endurance_group,
			__u16 group_id, const char *devname);
void json_print_list_items(struct list_item *items, unsigned amnt);
void json_nvme_id_ns_descs(void *data);
void json_print_nvme_subsystem_list(struct subsys_list_item *slist, int n);
void json_self_test_log(struct nvme_self_test_log *self_test, const char *devname);
void json_nvme_id_nvmset(struct nvme_id_nvmset *nvmset, const char *devname);
void json_ctrl_registers(void *bar);
void json_nvme_list_secondary_ctrl(const struct nvme_secondary_controllers_list *sc_list, __u32 count);

#endif
