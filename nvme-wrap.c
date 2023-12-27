// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Definitions for the NVM Express interface: libnvme/libnvme-mi device
 * wrappers.
 */

#include <errno.h>

#include <libnvme.h>
#include <libnvme-mi.h>

#include "nvme.h"
#include "nvme-wrap.h"

/*
 * Helper for libnvme functions that pass the fd/ep separately. These just
 * pass the correct handle to the direct/MI function.
 * @op: the name of the libnvme function, without the nvme_/nvme_mi prefix
 * @d: device handle: struct nvme_dev
 */
#define do_admin_op(op, d, ...) ({					\
	int __rc;							\
	if (d->type == NVME_DEV_DIRECT)					\
		__rc = nvme_ ## op(d->direct.fd, __VA_ARGS__);		\
	else if (d->type == NVME_DEV_MI)				\
		__rc = nvme_mi_admin_ ## op (d->mi.ctrl, __VA_ARGS__);	\
	else								\
		__rc = -ENODEV;						\
	__rc; })

/*
 * Helper for libnvme functions use the 'struct _args' pattern. These need
 * the fd and timeout set for the direct interface, and pass the ep as
 * an argument for the MI interface
 * @op: the name of the libnvme function, without the nvme_/nvme_mi prefix
 * @d: device handle: struct nvme_dev
 * @args: op-specific args struct
 */
#define do_admin_args_op(op, d, args) ({				\
	int __rc;							\
	if (d->type == NVME_DEV_DIRECT) {				\
		args->fd = d->direct.fd;				\
		__rc = nvme_ ## op(args);				\
	} else if (d->type == NVME_DEV_MI)				\
		__rc = nvme_mi_admin_ ## op (d->mi.ctrl, args);		\
	else								\
		__rc = -ENODEV;						\
	__rc; })

int nvme_cli_identify(struct nvme_dev *dev, struct nvme_identify_args *args)
{
	return do_admin_args_op(identify, dev, args);
}

int nvme_cli_identify_ctrl(struct nvme_dev *dev, struct nvme_id_ctrl *ctrl)
{
	return do_admin_op(identify_ctrl, dev, ctrl);
}

int nvme_cli_identify_ctrl_list(struct nvme_dev *dev, __u16 ctrl_id,
				struct nvme_ctrl_list *list)
{
	return do_admin_op(identify_ctrl_list, dev, ctrl_id, list);
}

int nvme_cli_identify_nsid_ctrl_list(struct nvme_dev *dev, __u32 nsid,
				     __u16 ctrl_id,
				     struct nvme_ctrl_list *list)
{
	return do_admin_op(identify_nsid_ctrl_list, dev, nsid, ctrl_id, list);
}

int nvme_cli_identify_ns(struct nvme_dev *dev, __u32 nsid,
			 struct nvme_id_ns *ns)
{
	return do_admin_op(identify_ns, dev, nsid, ns);
}

int nvme_cli_identify_ns_descs(struct nvme_dev *dev, __u32 nsid,
			       struct nvme_ns_id_desc *descs)
{
	return do_admin_op(identify_ns_descs, dev, nsid, descs);
}

int nvme_cli_identify_allocated_ns(struct nvme_dev *dev, __u32 nsid,
			 struct nvme_id_ns *ns)
{
	return do_admin_op(identify_allocated_ns, dev, nsid, ns);
}

int nvme_cli_identify_active_ns_list(struct nvme_dev *dev, __u32 nsid,
				     struct nvme_ns_list *list)
{
	return do_admin_op(identify_active_ns_list, dev, nsid, list);
}

int nvme_cli_identify_allocated_ns_list(struct nvme_dev *dev, __u32 nsid,
					struct nvme_ns_list *list)
{
	return do_admin_op(identify_allocated_ns_list, dev, nsid, list);
}

int nvme_cli_identify_primary_ctrl(struct nvme_dev *dev, __u32 nsid,
				   struct nvme_primary_ctrl_cap *cap)
{
	return do_admin_op(identify_primary_ctrl, dev, nsid, cap);
}

int nvme_cli_identify_secondary_ctrl_list(struct nvme_dev *dev,
					  __u16 ctrl_id,
					  struct nvme_secondary_ctrl_list *sc_list)
{
	return do_admin_op(identify_secondary_ctrl_list, dev, ctrl_id,
			   sc_list);
}

int nvme_cli_get_features(struct nvme_dev *dev,
			  struct nvme_get_features_args *args)
{
	return do_admin_args_op(get_features, dev, args);
}

int nvme_cli_ns_mgmt_delete(struct nvme_dev *dev, __u32 nsid)
{
	return do_admin_op(ns_mgmt_delete, dev, nsid);
}

int nvme_cli_ns_attach(struct nvme_dev *dev, struct nvme_ns_attach_args *args)
{
	return do_admin_args_op(ns_attach, dev, args);
}

int nvme_cli_ns_attach_ctrls(struct nvme_dev *dev, __u32 nsid,
			     struct nvme_ctrl_list *ctrlist)
{
	return do_admin_op(ns_attach_ctrls, dev, nsid, ctrlist);
}

int nvme_cli_ns_detach_ctrls(struct nvme_dev *dev, __u32 nsid,
			     struct nvme_ctrl_list *ctrlist)
{
	return do_admin_op(ns_detach_ctrls, dev, nsid, ctrlist);
}

int nvme_cli_format_nvm(struct nvme_dev *dev, struct nvme_format_nvm_args *args)
{
	return do_admin_args_op(format_nvm, dev, args);
}

int nvme_cli_sanitize_nvm(struct nvme_dev *dev, struct nvme_sanitize_nvm_args *args)
{
	return do_admin_args_op(sanitize_nvm, dev, args);
}

int nvme_cli_get_log(struct nvme_dev *dev, struct nvme_get_log_args *args)
{
	return do_admin_args_op(get_log, dev, args);
}

int nvme_cli_get_log_page(struct nvme_dev *dev, __u32 xfer_len,
			  struct nvme_get_log_args *args)
{
	return do_admin_op(get_log_page, dev, xfer_len, args);
}

int nvme_cli_get_nsid_log(struct nvme_dev *dev, bool rae,
			  enum nvme_cmd_get_log_lid lid,
			  __u32 nsid, __u32 len, void *log)
{
	return do_admin_op(get_nsid_log, dev, rae, lid, nsid, len, log);
}

int nvme_cli_get_log_simple(struct nvme_dev *dev,
			    enum nvme_cmd_get_log_lid lid,
			    __u32 len, void *log)
{
	return do_admin_op(get_log_simple, dev, lid, len, log);
}

int nvme_cli_get_log_supported_log_pages(struct nvme_dev *dev, bool rae,
					 struct nvme_supported_log_pages *log)
{
	return do_admin_op(get_log_supported_log_pages, dev, rae, log);
}

int nvme_cli_get_log_error(struct nvme_dev *dev, unsigned int nr_entries,
			   bool rae, struct nvme_error_log_page *err_log)
{
	return do_admin_op(get_log_error, dev, nr_entries, rae, err_log);
}

int nvme_cli_get_log_smart(struct nvme_dev *dev, __u32 nsid, bool rae,
			   struct nvme_smart_log *smart_log)
{
	return do_admin_op(get_log_smart, dev, nsid, rae, smart_log);
}

int nvme_cli_get_log_fw_slot(struct nvme_dev *dev, bool rae,
			     struct nvme_firmware_slot *fw_log)
{
	return do_admin_op(get_log_fw_slot, dev, rae, fw_log);
}

int nvme_cli_get_log_changed_ns_list(struct nvme_dev *dev, bool rae,
				     struct nvme_ns_list *ns_log)
{
	return do_admin_op(get_log_changed_ns_list, dev, rae, ns_log);
}

int nvme_cli_get_log_cmd_effects(struct nvme_dev *dev, enum nvme_csi csi,
				 struct nvme_cmd_effects_log *effects_log)
{
	return do_admin_op(get_log_cmd_effects, dev, csi, effects_log);
}

int nvme_cli_get_log_device_self_test(struct nvme_dev *dev,
				      struct nvme_self_test_log *log)
{
	return do_admin_op(get_log_device_self_test, dev, log);
}

int nvme_cli_get_log_create_telemetry_host(struct nvme_dev *dev,
					   struct nvme_telemetry_log *log)
{
	return do_admin_op(get_log_create_telemetry_host, dev, log);
}

int nvme_cli_get_log_telemetry_host(struct nvme_dev *dev, __u64 offset,
				    __u32 len, void *log)
{
	return do_admin_op(get_log_telemetry_host, dev, offset, len, log);
}

int nvme_cli_get_log_telemetry_ctrl(struct nvme_dev *dev, bool rae,
				    __u64 offset, __u32 len, void *log)
{
	return do_admin_op(get_log_telemetry_ctrl, dev, rae, offset, len, log);
}

int nvme_cli_get_log_endurance_group(struct nvme_dev *dev, __u16 endgid,
				     struct nvme_endurance_group_log *log)
{
	return do_admin_op(get_log_endurance_group, dev, endgid, log);
}

int nvme_cli_get_log_predictable_lat_nvmset(struct nvme_dev *dev,
					    __u16 nvmsetid,
					    struct nvme_nvmset_predictable_lat_log *log)
{
	return do_admin_op(get_log_predictable_lat_nvmset, dev, nvmsetid, log);
}

int nvme_cli_get_log_predictable_lat_event(struct nvme_dev *dev, bool rae,
					   __u32 offset, __u32 len, void *log)
{
	return do_admin_op(get_log_predictable_lat_event, dev, rae, offset,
			   len, log);
}

int nvme_cli_get_log_ana(struct nvme_dev *dev,
			 enum nvme_log_ana_lsp lsp, bool rae,
			 __u64 offset, __u32 len, void *log)
{
	return do_admin_op(get_log_ana, dev, lsp, rae, offset, len, log);
}

int nvme_cli_get_log_ana_groups(struct nvme_dev *dev, bool rae, __u32 len,
				struct nvme_ana_group_desc *log)
{
	return do_admin_op(get_log_ana_groups, dev, rae, len, log);
}

int nvme_cli_get_log_lba_status(struct nvme_dev *dev, bool rae,
				__u64 offset, __u32 len, void *log)
{
	return do_admin_op(get_log_lba_status, dev, rae, offset, len, log);
}

int nvme_cli_get_log_endurance_grp_evt(struct nvme_dev *dev, bool rae,
				       __u32 offset, __u32 len, void *log)
{
	return do_admin_op(get_log_endurance_grp_evt, dev, rae, offset, len,
			   log);
}

int nvme_cli_get_log_fid_supported_effects(struct nvme_dev *dev, bool rae,
					   struct nvme_fid_supported_effects_log *log)
{
	return do_admin_op(get_log_fid_supported_effects, dev, rae, log);
}

int nvme_cli_get_log_mi_cmd_supported_effects(struct nvme_dev *dev, bool rae,
					      struct nvme_mi_cmd_supported_effects_log *log)
{
	return do_admin_op(get_log_mi_cmd_supported_effects, dev, rae, log);
}

int nvme_cli_get_log_boot_partition(struct nvme_dev *dev, bool rae, __u8 lsp,
				    __u32 len,
				    struct nvme_boot_partition *part)
{
	return do_admin_op(get_log_boot_partition, dev, rae, lsp, len, part);
}

int nvme_cli_get_log_phy_rx_eom(struct nvme_dev *dev, __u8 lsp, __u16 controller,
				__u32 len, struct nvme_phy_rx_eom_log *part)
{
	return do_admin_op(get_log_phy_rx_eom, dev, lsp, controller, len, part);
}

int nvme_cli_get_log_discovery(struct nvme_dev *dev, bool rae,
			       __u32 offset, __u32 len, void *log)
{
	return do_admin_op(get_log_discovery, dev, rae, offset, len, log);
}

int nvme_cli_get_log_media_unit_stat(struct nvme_dev *dev, __u16 domid,
				     struct nvme_media_unit_stat_log *mus)
{
	return do_admin_op(get_log_media_unit_stat, dev, domid, mus);
}

int nvme_cli_get_log_support_cap_config_list(struct nvme_dev *dev,
					     __u16 domid,
					     struct nvme_supported_cap_config_list_log *cap)
{
	return do_admin_op(get_log_support_cap_config_list, dev, domid, cap);
}

int nvme_cli_get_log_reservation(struct nvme_dev *dev, bool rae,
				 struct nvme_resv_notification_log *log)
{
	return do_admin_op(get_log_reservation, dev, rae, log);
}

int nvme_cli_get_log_sanitize(struct nvme_dev *dev, bool rae,
			      struct nvme_sanitize_log_page *log)
{
	return do_admin_op(get_log_sanitize, dev, rae, log);
}

int nvme_cli_get_log_zns_changed_zones(struct nvme_dev *dev, __u32 nsid,
				       bool rae,
				       struct nvme_zns_changed_zone_log *log)
{
	return do_admin_op(get_log_zns_changed_zones, dev, nsid, rae, log);
}

int nvme_cli_get_log_persistent_event(struct nvme_dev *dev,
				      enum nvme_pevent_log_action action,
				      __u32 size, void *pevent_log)
{
	return do_admin_op(get_log_persistent_event, dev, action, size,
			   pevent_log);
}

int nvme_cli_fw_download(struct nvme_dev *dev,
			 struct nvme_fw_download_args *args)
{
	return do_admin_args_op(fw_download, dev, args);
}

int nvme_cli_fw_commit(struct nvme_dev *dev,
			 struct nvme_fw_commit_args *args)
{
	return do_admin_args_op(fw_commit, dev, args);
}

int nvme_cli_admin_passthru(struct nvme_dev *dev, __u8 opcode, __u8 flags,
			    __u16 rsvd, __u32 nsid, __u32 cdw2, __u32 cdw3,
			    __u32 cdw10, __u32 cdw11, __u32 cdw12, __u32 cdw13,
			    __u32 cdw14, __u32 cdw15, __u32 data_len,
			    void *data, __u32 metadata_len, void *metadata,
			    __u32 timeout_ms, __u32 *result)
{
	return do_admin_op(admin_passthru, dev, opcode, flags, rsvd, nsid,
			   cdw2, cdw3, cdw10, cdw11, cdw12, cdw13, cdw14, cdw15,
			   data_len, data, metadata_len, metadata, timeout_ms,
			   result);
}

/* The MI & direct interfaces don't have an exactly-matching API for
 * ns_mgmt_create, as we don't support a timeout for MI.
 */
int nvme_cli_ns_mgmt_create(struct nvme_dev *dev,
			struct nvme_ns_mgmt_host_sw_specified *data,
			__u32 *nsid, __u32 timeout, __u8 csi)
{
	if (dev->type == NVME_DEV_DIRECT)
		return nvme_ns_mgmt_create(dev_fd(dev), NULL, nsid, timeout,
							csi, data);
	if (dev->type == NVME_DEV_MI)
		return nvme_mi_admin_ns_mgmt_create(dev->mi.ctrl, NULL,
						    csi, nsid, data);

	return -ENODEV;
}

int nvme_cli_get_feature_length2(int fid, __u32 cdw11, enum nvme_data_tfr dir,
			         __u32 *len)
{
	int err;

	err = nvme_get_feature_length2(fid, cdw11, dir, len);
	if (err != -EEXIST)
		return err;
	return nvme_get_feature_length(fid, cdw11, len);
}

int nvme_cli_security_send(struct nvme_dev *dev,
			   struct nvme_security_send_args* args)
{
	return do_admin_args_op(security_send, dev, args);
}

int nvme_cli_security_receive(struct nvme_dev *dev,
			      struct nvme_security_receive_args* args)
{
	/* Cannot use do_admin_args_op here because the API have different suffix*/
	if (dev->type == NVME_DEV_DIRECT) {
		args->fd = dev->direct.fd;
		args->timeout = NVME_DEFAULT_IOCTL_TIMEOUT;
		return nvme_security_receive(args);
	}

	if (dev->type == NVME_DEV_MI)
		return nvme_mi_admin_security_recv(dev->mi.ctrl, args);

	return -ENODEV;
}

void nvme_cli_set_debug(struct nvme_dev *dev, bool set)
{
	if (dev->type == NVME_DEV_DIRECT)
		nvme_set_debug(set);
}

void nvme_cli_set_latency(struct nvme_dev *dev, bool set)
{
	if (dev->type == NVME_DEV_DIRECT)
		nvme_set_latency(set);
}
