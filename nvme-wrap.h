// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Definitions for the NVM Express interface: libnvme/libnvme-mi device
 * wrappers.
 */

#ifndef _NVME_WRAP_H
#define _NVME_WRAP_H

#include "nvme.h"

int nvme_cli_identify(struct nvme_dev *dev, struct nvme_identify_args *args);
int nvme_cli_identify_ctrl(struct nvme_dev *dev, struct nvme_id_ctrl *ctrl);
int nvme_cli_identify_ctrl_list(struct nvme_dev *dev, __u16 ctrl_id,
				struct nvme_ctrl_list *list);
int nvme_cli_identify_nsid_ctrl_list(struct nvme_dev *dev, __u32 nsid,
				     __u16 ctrl_id,
				     struct nvme_ctrl_list *list);
int nvme_cli_identify_ns(struct nvme_dev *dev, __u32 nsid,
			 struct nvme_id_ns *ns);
int nvme_cli_identify_ns_descs(struct nvme_dev *dev, __u32 nsid,
			       struct nvme_ns_id_desc *descs);
int nvme_cli_identify_allocated_ns(struct nvme_dev *dev, __u32 nsid,
				   struct nvme_id_ns *ns);
int nvme_cli_identify_active_ns_list(struct nvme_dev *dev, __u32 nsid,
				     struct nvme_ns_list *list);
int nvme_cli_identify_allocated_ns_list(struct nvme_dev *dev, __u32 nsid,
					struct nvme_ns_list *list);
int nvme_cli_identify_primary_ctrl(struct nvme_dev *dev, __u16 cntid,
				   struct nvme_primary_ctrl_cap *cap);
int nvme_cli_identify_secondary_ctrl_list(struct nvme_dev *dev, __u16 cntid,
					  struct nvme_secondary_ctrl_list *sc_list);
int nvme_cli_ns_mgmt_delete(struct nvme_dev *dev, __u32 nsid, __u32 timeout);
int nvme_cli_ns_mgmt_create(struct nvme_dev *dev,
			struct nvme_ns_mgmt_host_sw_specified *data,
			__u32 *nsid, __u32 timeout, __u8 csi);

int nvme_cli_ns_attach(struct nvme_dev *dev, struct nvme_ns_attach_args *args);

int nvme_cli_ns_attach_ctrls(struct nvme_dev *dev, __u32 nsid,
			     struct nvme_ctrl_list *ctrlist);
int nvme_cli_ns_detach_ctrls(struct nvme_dev *dev, __u32 nsid,
			     struct nvme_ctrl_list *ctrlist);

int nvme_cli_format_nvm(struct nvme_dev *dev, struct nvme_format_nvm_args *args);
int nvme_cli_sanitize_nvm(struct nvme_dev *dev,
			  struct nvme_sanitize_nvm_args *args);

int nvme_cli_get_features(struct nvme_dev *dev,
			  struct nvme_get_features_args *args);
int nvme_cli_get_features_arbitration(struct nvme_dev *dev, enum nvme_get_features_sel sel,
				      __u32 *result);
int nvme_cli_get_features_power_mgmt(struct nvme_dev *dev, enum nvme_get_features_sel sel,
				     __u32 *result);
int nvme_cli_set_features(struct nvme_dev *dev, struct nvme_set_features_args *args);
int nvme_cli_set_features_arbitration(struct nvme_dev *dev, __u8 ab, __u8 lpw, __u8 mpw, __u8 hpw,
				      bool  save, __u32 *result);
int nvme_set_features_power_mgmt(int fd, __u8 ps, __u8 wh, bool save, __u32 *result);

int nvme_cli_get_log(struct nvme_dev *dev, struct nvme_get_log_args *args);
int nvme_cli_get_log_page(struct nvme_dev *dev,
                          __u32 xfer_len,
                          struct nvme_get_log_args *args);

int nvme_cli_get_nsid_log(struct nvme_dev *dev, bool rae,
			  enum nvme_cmd_get_log_lid lid,
			  __u32 nsid, __u32 len, void *log);
int nvme_cli_get_log_simple(struct nvme_dev *dev,
			    enum nvme_cmd_get_log_lid lid,
			    __u32 len, void *log);
int nvme_cli_get_log_supported_log_pages(struct nvme_dev *dev, bool rae,
					 struct nvme_supported_log_pages *log);
int nvme_cli_get_log_error(struct nvme_dev *dev, unsigned int nr_entries,
			   bool rae, struct nvme_error_log_page *err_log);
int nvme_cli_get_log_smart(struct nvme_dev *dev, __u32 nsid, bool rae,
			   struct nvme_smart_log *smart_log);
int nvme_cli_get_log_fw_slot(struct nvme_dev *dev, bool rae,
			     struct nvme_firmware_slot *fw_log);
int nvme_cli_get_log_changed_ns_list(struct nvme_dev *dev, bool rae,
				     struct nvme_ns_list *ns_log);
int nvme_cli_get_log_changed_alloc_ns_list(struct nvme_dev *dev, bool rae, __u32 len,
					   struct nvme_ns_list *ns_log);
int nvme_cli_get_log_cmd_effects(struct nvme_dev *dev, enum nvme_csi csi,
				 struct nvme_cmd_effects_log *effects_log);
int nvme_cli_get_log_device_self_test(struct nvme_dev *dev,
				      struct nvme_self_test_log *log);
int nvme_cli_get_log_create_telemetry_host_mcda(struct nvme_dev *dev,
					   enum nvme_telemetry_da mcda,
					   struct nvme_telemetry_log *log);
int nvme_cli_get_log_telemetry_host(struct nvme_dev *dev, __u64 offset,
				    __u32 len, void *log);
int nvme_cli_get_log_telemetry_ctrl(struct nvme_dev *dev, bool rae,
				    __u64 offset, __u32 len, void *log);
int nvme_cli_get_log_endurance_group(struct nvme_dev *dev, __u16 endgid,
				     struct nvme_endurance_group_log *log);
int nvme_cli_get_log_predictable_lat_nvmset(struct nvme_dev *dev,
					    __u16 nvmsetid,
					    struct nvme_nvmset_predictable_lat_log *log);
int nvme_cli_get_log_predictable_lat_event(struct nvme_dev *dev, bool rae,
					   __u32 offset, __u32 len, void *log);
int nvme_cli_get_ana_log_atomic(struct nvme_dev *dev, bool rgo, bool rae,
				unsigned int retries,
				struct nvme_ana_log *log, __u32 *len);
int nvme_cli_get_log_lba_status(struct nvme_dev *dev, bool rae,
				__u64 offset, __u32 len, void *log);
int nvme_cli_get_log_endurance_grp_evt(struct nvme_dev *dev, bool rae,
				       __u32 offset, __u32 len, void *log);
int nvme_cli_get_log_fid_supported_effects(struct nvme_dev *dev, bool rae,
					   struct nvme_fid_supported_effects_log *log);
int nvme_cli_get_log_mi_cmd_supported_effects(struct nvme_dev *dev, bool rae,
					      struct nvme_mi_cmd_supported_effects_log *log);
int nvme_cli_get_log_boot_partition(struct nvme_dev *dev, bool rae, __u8 lsp,
				    __u32 len,
				    struct nvme_boot_partition *part);
int nvme_cli_get_log_phy_rx_eom(struct nvme_dev *dev, __u8 lsp, __u16 controller,
				__u32 len, struct nvme_phy_rx_eom_log *part);
int nvme_cli_get_log_discovery(struct nvme_dev *dev, bool rae,
			       __u32 offset, __u32 len, void *log);
int nvme_cli_get_log_media_unit_stat(struct nvme_dev *dev, __u16 domid,
				     struct nvme_media_unit_stat_log *mus);
int nvme_cli_get_log_support_cap_config_list(struct nvme_dev *dev,
					     __u16 domid,
					     struct nvme_supported_cap_config_list_log *cap);
int nvme_cli_get_log_reservation(struct nvme_dev *dev, bool rae,
				 struct nvme_resv_notification_log *log);
int nvme_cli_get_log_sanitize(struct nvme_dev *dev, bool rae,
			      struct nvme_sanitize_log_page *log);
int nvme_cli_get_log_zns_changed_zones(struct nvme_dev *dev, __u32 nsid,
				       bool rae,
				       struct nvme_zns_changed_zone_log *log);
int nvme_cli_get_log_persistent_event(struct nvme_dev *dev,
				      enum nvme_pevent_log_action action,
				      __u32 size, void *pevent_log);

int nvme_cli_fw_download(struct nvme_dev *dev,
			 struct nvme_fw_download_args *args);

int nvme_cli_fw_commit(struct nvme_dev *dev,
			 struct nvme_fw_commit_args *args);

int nvme_cli_admin_passthru(struct nvme_dev *dev, __u8 opcode, __u8 flags,
			    __u16 rsvd, __u32 nsid, __u32 cdw2, __u32 cdw3,
			    __u32 cdw10, __u32 cdw11, __u32 cdw12, __u32 cdw13,
			    __u32 cdw14, __u32 cdw15, __u32 data_len,
			    void *data, __u32 metadata_len, void *metadata,
			    __u32 timeout_ms, __u32 *result);

int nvme_cli_get_feature_length2(int fid, __u32 cdw11, enum nvme_data_tfr dir,
				__u32 *len);

int nvme_cli_security_send(struct nvme_dev *dev,
			   struct nvme_security_send_args* args);

int nvme_cli_security_receive(struct nvme_dev *dev,
			      struct nvme_security_receive_args* args);

int nvme_cli_get_log_mgmt_addr_list(struct nvme_dev *dev, __u32 len,
				    struct nvme_mgmt_addr_list_log *ma_list);

int nvme_cli_get_log_rotational_media_info(struct nvme_dev *dev, __u16 endgid, __u32 len,
					   struct nvme_rotational_media_info_log *info);

int nvme_cli_get_log_dispersed_ns_participating_nss(struct nvme_dev *dev, __u32 nsid, __u32 len,
	struct nvme_dispersed_ns_participating_nss_log *log);

int nvme_cli_get_log_reachability_groups(struct nvme_dev *dev, bool rgo, bool rae, __u32 len,
					 struct nvme_reachability_groups_log *log);

int nvme_cli_get_log_reachability_associations(struct nvme_dev *dev, bool rgo, bool rae, __u32 len,
					       struct nvme_reachability_associations_log *log);

int nvme_cli_get_log_host_discovery(struct nvme_dev *dev, bool allhoste, bool rae, __u32 len,
				    struct nvme_host_discover_log *log);

int nvme_cli_get_log_ave_discovery(struct nvme_dev *dev, bool rae, __u32 len,
				   struct nvme_ave_discover_log *log);

int nvme_cli_get_log_pull_model_ddc_req(struct nvme_dev *dev, bool rae, __u32 len,
					struct nvme_pull_model_ddc_req_log *log);
#endif /* _NVME_WRAP_H */
