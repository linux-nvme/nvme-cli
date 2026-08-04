/* struct libnvme_ctrl -- sysfs-backed properties */
%rename(libnvme_ctrl_numa_node_get) libnvme_ctrl_get_numa_node;
%rename(libnvme_ctrl_queue_count_get) libnvme_ctrl_get_queue_count;
%rename(libnvme_ctrl_sqsize_get) libnvme_ctrl_get_sqsize;
%rename(libnvme_ctrl_command_error_count_get) libnvme_ctrl_get_command_error_count;
%rename(libnvme_ctrl_reset_count_get) libnvme_ctrl_get_reset_count;
%rename(libnvme_ctrl_reconnect_count_get) libnvme_ctrl_get_reconnect_count;
%rename(libnvme_ctrl_firmware_get) libnvme_ctrl_get_firmware;
%rename(libnvme_ctrl_firmware_set) libnvme_ctrl_set_firmware;
%rename(libnvme_ctrl_model_get) libnvme_ctrl_get_model;
%rename(libnvme_ctrl_model_set) libnvme_ctrl_set_model;
%rename(libnvme_ctrl_serial_get) libnvme_ctrl_get_serial;
%rename(libnvme_ctrl_serial_set) libnvme_ctrl_set_serial;
%rename(libnvme_ctrl_cntrltype_get) libnvme_ctrl_get_cntrltype;
%rename(libnvme_ctrl_cntrltype_set) libnvme_ctrl_set_cntrltype;
%rename(libnvme_ctrl_cntlid_get) libnvme_ctrl_get_cntlid;
%rename(libnvme_ctrl_cntlid_set) libnvme_ctrl_set_cntlid;
%rename(libnvme_ctrl_dctype_get) libnvme_ctrl_get_dctype;
%rename(libnvme_ctrl_dctype_set) libnvme_ctrl_set_dctype;
%rename(libnvme_ctrl_phy_slot_get) libnvme_ctrl_get_phy_slot;
%rename(libnvme_ctrl_dhchap_host_key_get) libnvme_ctrl_get_dhchap_host_key;
%rename(libnvme_ctrl_dhchap_host_key_set) libnvme_ctrl_set_dhchap_host_key;
%rename(libnvme_ctrl_dhchap_ctrl_key_get) libnvme_ctrl_get_dhchap_ctrl_key;
%rename(libnvme_ctrl_dhchap_ctrl_key_set) libnvme_ctrl_set_dhchap_ctrl_key;
%rename(libnvme_ctrl_keyring_get) libnvme_ctrl_get_keyring;
%rename(libnvme_ctrl_keyring_set) libnvme_ctrl_set_keyring;
%{
	#define libnvme_ctrl_numa_node_get libnvme_ctrl_get_numa_node
	#define libnvme_ctrl_queue_count_get libnvme_ctrl_get_queue_count
	#define libnvme_ctrl_sqsize_get libnvme_ctrl_get_sqsize
	#define libnvme_ctrl_command_error_count_get libnvme_ctrl_get_command_error_count
	#define libnvme_ctrl_reset_count_get libnvme_ctrl_get_reset_count
	#define libnvme_ctrl_reconnect_count_get libnvme_ctrl_get_reconnect_count
	#define libnvme_ctrl_firmware_get libnvme_ctrl_get_firmware
	#define libnvme_ctrl_firmware_set libnvme_ctrl_set_firmware
	#define libnvme_ctrl_model_get libnvme_ctrl_get_model
	#define libnvme_ctrl_model_set libnvme_ctrl_set_model
	#define libnvme_ctrl_serial_get libnvme_ctrl_get_serial
	#define libnvme_ctrl_serial_set libnvme_ctrl_set_serial
	#define libnvme_ctrl_cntrltype_get libnvme_ctrl_get_cntrltype
	#define libnvme_ctrl_cntrltype_set libnvme_ctrl_set_cntrltype
	#define libnvme_ctrl_cntlid_get libnvme_ctrl_get_cntlid
	#define libnvme_ctrl_cntlid_set libnvme_ctrl_set_cntlid
	#define libnvme_ctrl_dctype_get libnvme_ctrl_get_dctype
	#define libnvme_ctrl_dctype_set libnvme_ctrl_set_dctype
	#define libnvme_ctrl_phy_slot_get libnvme_ctrl_get_phy_slot
	#define libnvme_ctrl_dhchap_host_key_get libnvme_ctrl_get_dhchap_host_key
	#define libnvme_ctrl_dhchap_host_key_set libnvme_ctrl_set_dhchap_host_key
	#define libnvme_ctrl_dhchap_ctrl_key_get libnvme_ctrl_get_dhchap_ctrl_key
	#define libnvme_ctrl_dhchap_ctrl_key_set libnvme_ctrl_set_dhchap_ctrl_key
	#define libnvme_ctrl_keyring_get libnvme_ctrl_get_keyring
	#define libnvme_ctrl_keyring_set libnvme_ctrl_set_keyring
%}

%extend struct libnvme_ctrl {
	%immutable numa_node;
	const char * numa_node;
	%immutable queue_count;
	const char * queue_count;
	%immutable sqsize;
	const char * sqsize;
	%immutable command_error_count;
	long command_error_count;
	%immutable reset_count;
	long reset_count;
	%immutable reconnect_count;
	long reconnect_count;
	const char * firmware;
	const char * model;
	const char * serial;
	const char * cntrltype;
	const char * cntlid;
	const char * dctype;
	%immutable phy_slot;
	const char * phy_slot;
	const char * dhchap_host_key;
	const char * dhchap_ctrl_key;
	const char * keyring;
}
