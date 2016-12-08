#ifndef NVME_PRINT_H
#define NVME_PRINT_H

#include "nvme.h"
#include <inttypes.h>

enum {
	TERSE = 0x1u,	// only show a few useful fields
	HUMAN = 0x2u,	// interpret some values for humans
	VS    = 0x4u,	// print vendor specific data area
	RAW   = 0x8u,	// just dump raw bytes
};

void d(unsigned char *buf, int len, int width, int group);
void d_raw(unsigned char *buf, unsigned len);

uint64_t int48_to_long(__u8 *data);

void __show_nvme_id_ctrl(struct nvme_id_ctrl *ctrl, unsigned int mode, void (*vendor_show)(__u8 *vs));
void show_nvme_id_ctrl(struct nvme_id_ctrl *ctrl, unsigned int mode);
void show_nvme_id_ns(struct nvme_id_ns *ns, unsigned int flags);
void show_nvme_resv_report(struct nvme_reservation_status *status);
void show_lba_range(struct nvme_lba_range_type *lbrt, int nr_ranges);
void show_error_log(struct nvme_error_log_page *err_log, int entries, const char *devname);
void show_intel_smart_log(struct nvme_additional_smart_log *smart, unsigned int nsid, const char *devname);
void show_smart_log(struct nvme_smart_log *smart, unsigned int nsid, const char *devname);
void show_fw_log(struct nvme_firmware_log_page *fw_log, const char *devname);
void show_ctrl_registers(void *bar, unsigned int mode);

void nvme_feature_show_fields(__u32 fid, unsigned int result, unsigned char *buf);
char *nvme_status_to_string(__u32 status);
char *nvme_select_to_string(int sel);
char *nvme_feature_to_string(int feature);

void json_nvme_id_ctrl(struct nvme_id_ctrl *ctrl, unsigned int mode);
void json_nvme_id_ns(struct nvme_id_ns *ns, unsigned int flags);
void json_nvme_resv_report(struct nvme_reservation_status *status);
void json_error_log(struct nvme_error_log_page *err_log, int entries, const char *devname);
void json_smart_log(struct nvme_smart_log *smart, unsigned int nsid, const char *devname);
void json_add_smart_log(struct nvme_additional_smart_log *smart,
			unsigned int nsid, const char *devname);
void json_fw_log(struct nvme_firmware_log_page *fw_log, const char *devname);
void json_print_list_items(struct list_item *items, unsigned amnt);


#endif
