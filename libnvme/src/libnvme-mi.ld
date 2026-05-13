# SPDX-License-Identifier: LGPL-2.1-or-later

LIBNVME_MI_3 {
	global:
		libnvme_mi_admin_xfer;
		libnvme_mi_aem_disable;
		libnvme_mi_aem_enable;
		libnvme_mi_aem_get_enabled;
		libnvme_mi_aem_get_fd;
		libnvme_mi_aem_get_next_event;
		libnvme_mi_aem_process;
		libnvme_mi_close;
		libnvme_mi_control;
		libnvme_mi_ctrl_id;
		libnvme_mi_endpoint_desc;
		libnvme_mi_ep_get_timeout;
		libnvme_mi_ep_set_timeout;
		libnvme_mi_first_endpoint;
		libnvme_mi_init_transport_handle;
		libnvme_mi_mi_config_get;
		libnvme_mi_mi_config_set;
		libnvme_mi_mi_read_mi_data_ctrl;
		libnvme_mi_mi_read_mi_data_ctrl_list;
		libnvme_mi_mi_read_mi_data_port;
		libnvme_mi_mi_read_mi_data_subsys;
		libnvme_mi_mi_subsystem_health_status_poll;
		libnvme_mi_mi_xfer;
		libnvme_mi_next_endpoint;
		libnvme_mi_open_mctp;
		libnvme_mi_scan_ep;
		libnvme_mi_scan_mctp;
		libnvme_mi_set_csi;
		libnvme_mi_status_to_string;
		libnvme_mi_submit_entry;
		libnvme_mi_submit_exit;
	local:
		*;
};
