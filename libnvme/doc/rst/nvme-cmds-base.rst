.. _nvme-base-cmds.h:

**nvme-base-cmds.h**


NVMe Base Specification Admin Commands

.. c:function:: void nvme_init_get_log_lpo (struct libnvme_passthru_cmd *cmd, __u64 lpo)

   Initialize passthru command with a Log Page Offset

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command

``__u64 lpo``
  Log Page Offset to set


.. c:function:: void nvme_init_get_log (struct libnvme_passthru_cmd *cmd, __u32 nsid, enum nvme_cmd_get_log_lid lid, enum nvme_csi csi, void *data, __u32 len)

   Initialize passthru command for NVMe Admin Get Log

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``__u32 nsid``
  Namespace identifier, if applicable

``enum nvme_cmd_get_log_lid lid``
  Log Page Identifier, see :c:type:`enum nvme_cmd_get_log_lid <nvme_cmd_get_log_lid>`

``enum nvme_csi csi``
  Command set identifier, see :c:type:`enum nvme_csi <nvme_csi>` for known values

``void *data``
  User space destination address to transfer the data

``__u32 len``
  Length of provided user buffer to hold the log data in bytes


.. c:function:: void nvme_init_get_log_supported_log_pages (struct libnvme_passthru_cmd *cmd, enum nvme_csi csi, struct nvme_supported_log_pages *log)

   Initialize passthru command for Supported Log Pages

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``enum nvme_csi csi``
  Command set identifier, see :c:type:`enum nvme_csi <nvme_csi>` for known values

``struct nvme_supported_log_pages *log``
  Array of LID supported and Effects data structures

**Description**

Initializes the passthru command buffer for the Get Log command with
LID value ``NVME_LOG_LID_SUPPORTED_LOG_PAGES``.


.. c:function:: void nvme_init_get_log_error (struct libnvme_passthru_cmd *cmd, unsigned int nr_entries, struct nvme_error_log_page *err_log)

   Initialize passthru command for Error Information

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``unsigned int nr_entries``
  Number of error log entries allocated

``struct nvme_error_log_page *err_log``
  Array of error logs of size 'entries'

**Description**

Initializes the passthru command buffer for the Get Log command with
LID value ``NVME_LOG_LID_ERROR``.


.. c:function:: void nvme_init_get_log_smart (struct libnvme_passthru_cmd *cmd, __u32 nsid, struct nvme_smart_log *smart_log)

   Initialize passthru command for SMART / Health Information

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``__u32 nsid``
  Optional namespace identifier

``struct nvme_smart_log *smart_log``
  User address to store the smart log

**Description**

Initializes the passthru command buffer for the Get Log command with
LID value ``NVME_LOG_LID_SMART``.


.. c:function:: void nvme_init_get_log_fw_slot (struct libnvme_passthru_cmd *cmd, struct nvme_firmware_slot *fw_log)

   Initialize passthru command for Firmware Slot Information

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``struct nvme_firmware_slot *fw_log``
  User address to store the log page

**Description**

Initializes the passthru command buffer for the Get Log command with
LID value ``NVME_LOG_LID_SMART``.


.. c:function:: void nvme_init_get_log_changed_ns (struct libnvme_passthru_cmd *cmd, struct nvme_ns_list *ns_log)

   Initialize passthru command for Changed Attached Namespace List

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``struct nvme_ns_list *ns_log``
  User address to store the log page

**Description**

Initializes the passthru command buffer for the Get Log command with
LID value ``NVME_LOG_LID_CHANGED_ATTACHED_NS``.


.. c:function:: void nvme_init_get_log_cmd_effects (struct libnvme_passthru_cmd *cmd, enum nvme_csi csi, struct nvme_cmd_effects_log *effects_log)

   Initialize passthru command for Commands Supported and Effects

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``enum nvme_csi csi``
  Command Set Identifier

``struct nvme_cmd_effects_log *effects_log``
  User address to store the effects log

**Description**

Initializes the passthru command buffer for the Get Log command with
LID value ``NVME_LOG_LID_CMD_EFFECTS``.


.. c:function:: void nvme_init_get_log_device_self_test (struct libnvme_passthru_cmd *cmd, struct nvme_self_test_log *log)

   Initialize passthru command for Device Self-test

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``struct nvme_self_test_log *log``
  Userspace address of the log payload

**Description**

Initializes the passthru command buffer for the Get Log command with
LID value ``NVME_LOG_LID_DEVICE_SELF_TEST``.


.. c:function:: void nvme_init_get_log_telemetry_host (struct libnvme_passthru_cmd *cmd, __u64 lpo, void *log, __u32 len)

   Initialize passthru command for Telemetry Host-Initiated

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``__u64 lpo``
  Offset into the telemetry data

``void *log``
  User address for log page data

``__u32 len``
  Length of provided user buffer to hold the log data in bytes

**Description**

Initializes the passthru command buffer for the Get Log command with
LID value ``NVME_LOG_LID_TELEMETRY_HOST``.


.. c:function:: void nvme_init_get_log_create_telemetry_host_mcda (struct libnvme_passthru_cmd *cmd, enum nvme_telemetry_da mcda, struct nvme_telemetry_log *log)

   Initialize passthru command for Create Telemetry Host-Initiated

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``enum nvme_telemetry_da mcda``
  Maximum Created Data Area

``struct nvme_telemetry_log *log``
  Userspace address of the log payload

**Description**

Initializes the passthru command buffer for the Get Log command with
LID value ``NVME_LOG_LID_TELEMETRY_HOST`` and
LSP value ``NVME_LOG_TELEM_HOST_LSP_CREATE``.


.. c:function:: void nvme_init_get_log_create_telemetry_host (struct libnvme_passthru_cmd *cmd, struct nvme_telemetry_log *log)

   Initialize passthru command for Create Telemetry Host-Initiated

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``struct nvme_telemetry_log *log``
  Userspace address of the log payload

**Description**

Initializes the passthru command buffer for the Get Log command with
LID value ``NVME_LOG_LID_TELEMETRY_HOST`` and
LSP value ``NVME_LOG_TELEM_HOST_LSP_CREATE``.


.. c:function:: void nvme_init_get_log_telemetry_ctrl (struct libnvme_passthru_cmd *cmd, __u64 lpo, void *log, __u32 len)

   Initialize passthru command for Telemetry Controller-Initiated

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``__u64 lpo``
  Offset into the telemetry data

``void *log``
  User address for log page data

``__u32 len``
  Length of provided user buffer to hold the log data in bytes

**Description**

Initializes the passthru command buffer for the Get Log command with
LID value ``NVME_LOG_LID_TELEMETRY_CTRL``.


.. c:function:: void nvme_init_get_log_endurance_group (struct libnvme_passthru_cmd *cmd, __u16 endgid, struct nvme_endurance_group_log *log)

   Initialize passthru command for Endurance Group Information

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``__u16 endgid``
  Starting group identifier to return in the list

``struct nvme_endurance_group_log *log``
  User address to store the endurance log

**Description**

Initializes the passthru command buffer for the Get Log command with
LID value ``NVME_LOG_LID_ENDURANCE_GROUP``.


.. c:function:: void nvme_init_get_log_predictable_lat_nvmset (struct libnvme_passthru_cmd *cmd, __u16 nvmsetid, struct nvme_nvmset_predictable_lat_log *log)

   Initialize passthru command for Predictable Latency Per NVM Set

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``__u16 nvmsetid``
  NVM set id

``struct nvme_nvmset_predictable_lat_log *log``
  User address to store the predictable latency log

**Description**

Initializes the passthru command buffer for the Get Log command with
LID value ``NVME_LOG_LID_PREDICTABLE_LAT_NVMSET``.


.. c:function:: void nvme_init_get_log_predictable_lat_event (struct libnvme_passthru_cmd *cmd, __u64 lpo, void *log, __u32 len)

   Initialize passthru command for Predictable Latency Event Aggregate

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``__u64 lpo``
  Offset into the predictable latency event

``void *log``
  User address for log page data

``__u32 len``
  Length of provided user buffer to hold the log data in bytes

**Description**

Initializes the passthru command buffer for the Get Log command with
LID value ``NVME_LOG_LID_PREDICTABLE_LAT_AGG``.


.. c:function:: void nvme_init_get_log_ana (struct libnvme_passthru_cmd *cmd, enum nvme_log_ana_lsp lsp, __u64 lpo, void *log, __u32 len)

   Initialize passthru command for Asymmetric Namespace Access

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``enum nvme_log_ana_lsp lsp``
  Log specific, see :c:type:`enum nvme_get_log_ana_lsp <nvme_get_log_ana_lsp>`

``__u64 lpo``
  Offset to the start of the log page

``void *log``
  User address to store the ana log

``__u32 len``
  The allocated length of the log page

**Description**

Initializes the passthru command buffer for the Get Log command with
LID value ``NVME_LOG_LID_ANA``.


.. c:function:: void nvme_init_get_log_ana_groups (struct libnvme_passthru_cmd *cmd, struct nvme_ana_log *log, __u32 len)

   Initialize passthru command for Asymmetric Namespace Access groups

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``struct nvme_ana_log *log``
  User address to store the ana group log

``__u32 len``
  The allocated length of the log page

**Description**

Initializes the passthru command buffer for the Get Log command with
LID value ``NVME_LOG_LID_ANA`` and LSP value ``NVME_LOG_ANA_LSP_RGO_GROUPS_ONLY``


.. c:function:: void nvme_init_get_log_persistent_event (struct libnvme_passthru_cmd *cmd, enum nvme_pevent_log_action action, void *pevent_log, __u32 len)

   Initialize passthru command for Persistent Event Log

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``enum nvme_pevent_log_action action``
  Action the controller should take during processing this command

``void *pevent_log``
  User address to store the persistent event log

``__u32 len``
  Size of **pevent_log**

**Description**

Initializes the passthru command buffer for the Get Log command with
LID value ``NVME_LOG_PERSISTENT_EVENT``


.. c:function:: void nvme_init_get_log_lba_status (struct libnvme_passthru_cmd *cmd, __u64 lpo, void *log, __u32 len)

   Initialize passthru command for Retrieve LBA Status

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``__u64 lpo``
  Offset to the start of the log page

``void *log``
  User address to store the log page

``__u32 len``
  The allocated length of the log page

**Description**

Initializes the passthru command buffer for the Get Log command with
LID value ``NVME_LOG_LID_LBA_STATUS``


.. c:function:: void nvme_init_get_log_endurance_grp_evt (struct libnvme_passthru_cmd *cmd, __u64 lpo, void *log, __u32 len)

   Initialize passthru command for Endurance Group Event Aggregate

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``__u64 lpo``
  Offset to the start of the log page

``void *log``
  User address to store the log page

``__u32 len``
  The allocated length of the log page

**Description**

Initializes the passthru command buffer for the Get Log command with
LID value ``NVME_LOG_LID_ENDURANCE_GRP_EVT``


.. c:function:: void nvme_init_get_log_media_unit_stat (struct libnvme_passthru_cmd *cmd, __u16 domid, struct nvme_media_unit_stat_log *mus)

   Initialize passthru command for Media Unit Status

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``__u16 domid``
  Domain Identifier selection, if supported

``struct nvme_media_unit_stat_log *mus``
  User address to store the Media Unit statistics log

**Description**

Initializes the passthru command buffer for the Get Log command with
LID value ``NVME_LOG_LID_MEDIA_UNIT_STATUS``


.. c:function:: void nvme_init_get_log_support_cap_config_list (struct libnvme_passthru_cmd *cmd, __u16 domid, struct nvme_supported_cap_config_list_log *cap)

   Initialize passthru command for Supported Capacity Configuration List

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``__u16 domid``
  Domain Identifier selection, if supported

``struct nvme_supported_cap_config_list_log *cap``
  User address to store supported capabilities config list

**Description**

Initializes the passthru command buffer for the Get Log command with
LID value ``NVME_LOG_LID_SUPPORTED_CAP_CONFIG_LIST``


.. c:function:: void nvme_init_get_log_fid_supported_effects (struct libnvme_passthru_cmd *cmd, enum nvme_csi csi, struct nvme_fid_supported_effects_log *log)

   Initialize passthru command for Feature Identifiers Supported and Effects

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``enum nvme_csi csi``
  Command set identifier, see :c:type:`enum nvme_csi <nvme_csi>` for known values

``struct nvme_fid_supported_effects_log *log``
  FID Supported and Effects data structure

**Description**

Initializes the passthru command buffer for the Get Log command with
LID value ``NVME_LOG_LID_FID_SUPPORTED_EFFECTS``


.. c:function:: void nvme_init_get_log_lockdown (struct libnvme_passthru_cmd *cmd, __u8 cnscp, __u16 cntlid, struct nvme_lockdown_log *lockdown_log)

   Initialize passthru command for Command and Feature Lockdown

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``__u8 cnscp``
  Contents and Scope of Command and Feature Identifier
  Lists, see :c:type:`enum nvme_lockdown_log_lsp <nvme_lockdown_log_lsp>`. Set the
  NVME_LOCKDOWN_LOG_LSP_ELPF bit to request the
  Controller-scoped Enhanced log page format instead of
  the original format.

``__u16 cntlid``
  Controller Identifier: scopes the returned log page
  to the specified controller if the ELPF bit is set in
  **cnscp**. Ignored otherwise.

``struct nvme_lockdown_log *lockdown_log``
  Buffer to store the lockdown log

**Description**

Initializes the passthru command buffer for the Get Log command with
LID value ``NVME_LOG_LID_CMD_AND_FEAT_LOCKDOWN``


.. c:function:: void nvme_init_get_log_boot_partition (struct libnvme_passthru_cmd *cmd, __u8 lsp, struct nvme_boot_partition *part, __u32 len)

   Initialize passthru command for Boot Partition

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``__u8 lsp``
  The log specified field of LID

``struct nvme_boot_partition *part``
  User address to store the log page

``__u32 len``
  The allocated size, minimum
  struct nvme_boot_partition

**Description**

Initializes the passthru command buffer for the Get Log command with
LID value ``NVME_LOG_LID_BOOT_PARTITION``


.. c:function:: void nvme_init_get_log_rotational_media_info (struct libnvme_passthru_cmd *cmd, __u16 endgid, struct nvme_rotational_media_info_log *log, __u32 len)

   Initialize passthru command for Rotational Media Information Log

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``__u16 endgid``
  Endurance Group Identifier

``struct nvme_rotational_media_info_log *log``
  User address to store the log page

``__u32 len``
  The allocated length of the log page

**Description**

Initializes the passthru command buffer for the Get Log command with
LID value ``NVME_LOG_LID_ROTATIONAL_MEDIA_INFO``


.. c:function:: void nvme_init_get_log_dispersed_ns_participating_nss (struct libnvme_passthru_cmd *cmd, __u32 nsid, struct nvme_dispersed_ns_participating_nss_log *log, __u32 len)

   Initialize passthru command for Dispersed Namespace Participating NVM Subsystems

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``__u32 nsid``
  Namespace Identifier

``struct nvme_dispersed_ns_participating_nss_log *log``
  User address to store the log page

``__u32 len``
  The allocated length of the log page

**Description**

Initializes the passthru command buffer for the Get Log command with
LID value ``NVME_LOG_LID_DISPERSED_NS_PARTICIPATING_NSS``


.. c:function:: void nvme_init_get_log_mgmt_addr_list (struct libnvme_passthru_cmd *cmd, struct nvme_mgmt_addr_list_log *log, __u32 len)

   Initialize passthru command for Management Address List

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``struct nvme_mgmt_addr_list_log *log``
  User address to store the log page

``__u32 len``
  The allocated length of the log page

**Description**

Initializes the passthru command buffer for the Get Log command with
LID value ``NVME_LOG_LID_MGMT_ADDR_LIST``


.. c:function:: void nvme_init_get_log_power_measurement (struct libnvme_passthru_cmd *cmd, struct nvme_power_meas_log *log, __u32 len)

   Initialize passthru command for Power Measurement

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``struct nvme_power_meas_log *log``
  User address to store the log page

``__u32 len``
  The allocated length of the log page

**Description**

Initializes the passthru command buffer for the Get Log command with
LID value ``NVME_LOG_LID_POWER_MEASUREMENT``


.. c:function:: void nvme_init_get_log_voltage_measurement (struct libnvme_passthru_cmd *cmd, struct nvme_voltage_measurement_log *log, __u32 len)

   Initialize passthru command for Voltage Measurement

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``struct nvme_voltage_measurement_log *log``
  User address to store the log page

``__u32 len``
  The allocated length of the log page

**Description**

Initializes the passthru command buffer for the Get Log command with
LID value ``NVME_LOG_LID_VOLTAGE_MEASUREMENT``


.. c:function:: void nvme_init_get_log_phy_rx_eom (struct libnvme_passthru_cmd *cmd, __u8 lsp, __u16 controller, struct nvme_phy_rx_eom_log *log, __u32 len)

   Initialize passthru command for Physical Interface Receiver Eye Opening Measurement

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``__u8 lsp``
  Log specific, controls action and measurement quality

``__u16 controller``
  Target controller ID

``struct nvme_phy_rx_eom_log *log``
  User address to store the log page

``__u32 len``
  The allocated size, minimum
  struct nvme_phy_rx_eom_log

**Description**

Initializes the passthru command buffer for the Get Log command with
LID value ``NVME_LOG_LID_PHY_RX_EOM``


.. c:function:: void nvme_init_get_log_reachability_groups (struct libnvme_passthru_cmd *cmd, bool rgo, struct nvme_reachability_groups_log *log, __u32 len)

   Initialize passthru command for Retrieve Reachability Groups

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``bool rgo``
  Return groups only

``struct nvme_reachability_groups_log *log``
  User address to store the log page

``__u32 len``
  The allocated length of the log page

**Description**

Initializes the passthru command buffer for the Get Log command with
LID value ``NVME_LOG_LID_REACHABILITY_GROUPS``


.. c:function:: void nvme_init_get_log_reachability_associations (struct libnvme_passthru_cmd *cmd, bool rao, struct nvme_reachability_associations_log *log, __u32 len)

   Initialize passthru command for Reachability Associations Log

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``bool rao``
  Return associations only

``struct nvme_reachability_associations_log *log``
  User address to store the log page

``__u32 len``
  The allocated length of the log page

**Description**

Initializes the passthru command buffer for the Get Log command with
LID value ``NVME_LOG_LID_REACHABILITY_ASSOCIATIONS``


.. c:function:: void nvme_init_get_log_changed_alloc_ns (struct libnvme_passthru_cmd *cmd, struct nvme_ns_list *log, __u32 len)

   Initialize passthru command for Changed Allocated Namespace List

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``struct nvme_ns_list *log``
  User address to store the log page

``__u32 len``
  The allocated length of the log page

**Description**

Initializes the passthru command buffer for the Get Log command with
LID value ``NVME_LOG_LID_CHANGED_ALLOC_NS``


.. c:function:: void nvme_init_get_log_fdp_configurations (struct libnvme_passthru_cmd *cmd, __u16 egid, __u64 lpo, void *log, __u32 len)

   Initialize passthru command for Flexible Data Placement Configurations

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``__u16 egid``
  Endurance group identifier

``__u64 lpo``
  Offset into log page

``void *log``
  Log page data buffer

``__u32 len``
  Length (in bytes) of provided user buffer to hold the log data

**Description**

Initializes the passthru command buffer for the Get Log command with
LID value ``NVME_LOG_LID_FDP_CONFIGS``


.. c:function:: void nvme_init_get_log_reclaim_unit_handle_usage (struct libnvme_passthru_cmd *cmd, __u16 egid, __u64 lpo, void *log, __u32 len)

   Initialize passthru command for Reclaim Unit Handle Usage

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``__u16 egid``
  Endurance group identifier

``__u64 lpo``
  Offset into log page

``void *log``
  Log page data buffer

``__u32 len``
  Length (in bytes) of provided user buffer to hold the log data

**Description**

Initializes the passthru command buffer for the Get Log command with
LID value ``NVME_LOG_LID_RUH_USAGE``


.. c:function:: void nvme_init_get_log_fdp_stats (struct libnvme_passthru_cmd *cmd, __u16 egid, __u64 lpo, void *log, __u32 len)

   Initialize passthru command for Get Flexible Data Placement Statistics

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``__u16 egid``
  Endurance group identifier

``__u64 lpo``
  Offset into log page

``void *log``
  Log page data buffer

``__u32 len``
  Length (in bytes) of provided user buffer to hold the log data

**Description**

Initializes the passthru command buffer for the Get Log command with
LID value ``NVME_LOG_LID_FDP_STATS``


.. c:function:: void nvme_init_get_log_fdp_events (struct libnvme_passthru_cmd *cmd, bool host_events, __u16 egid, __u64 lpo, void *log, __u32 len)

   Initialize passthru command for Flexible Data Placement Events

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``bool host_events``
  Whether to report host or controller events

``__u16 egid``
  Endurance group identifier

``__u64 lpo``
  Offset into log page

``void *log``
  Log page data buffer

``__u32 len``
  Length (in bytes) of provided user buffer to hold
  the log data

**Description**

Initializes the passthru command buffer for the Get Log command with
LID value ``NVME_LOG_LID_FDP_EVENTS``


.. c:function:: void nvme_init_get_log_rate_limiting (struct libnvme_passthru_cmd *cmd, __u64 lpo, void *log, __u32 len)

   Initialize passthru command for Rate Limiting

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``__u64 lpo``
  Offset into log page

``void *log``
  Log page data buffer

``__u32 len``
  Length (in bytes) of provided user buffer to hold the log data

**Description**

Initializes the passthru command buffer for the Get Log command with
LID value ``NVME_LOG_LID_RATE_LIMITING``


.. c:function:: void nvme_init_get_log_host_addressable_ns (struct libnvme_passthru_cmd *cmd, __u64 lpo, void *log, __u32 len)

   Initialize passthru command for Host Addressable Namespaces

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``__u64 lpo``
  Offset into log page

``void *log``
  Log page data buffer

``__u32 len``
  Length (in bytes) of provided user buffer to hold the log data

**Description**

Initializes the passthru command buffer for the Get Log command with
LID value ``NVME_LOG_LID_HOST_ADDRESSABLE_NS``


.. c:function:: void nvme_init_get_log_reservation (struct libnvme_passthru_cmd *cmd, struct nvme_resv_notification_log *log)

   Initialize passthru command for Reservation Notification

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``struct nvme_resv_notification_log *log``
  User address to store the reservation log

**Description**

Initializes the passthru command buffer for the Get Log command with
LID value ``NVME_LOG_LID_RESERVATION``


.. c:function:: void nvme_init_get_log_sanitize (struct libnvme_passthru_cmd *cmd, struct nvme_sanitize_log_page *log)

   Initialize passthru command for Sanitize Status

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``struct nvme_sanitize_log_page *log``
  User address to store the sanitize log

**Description**

Initializes the passthru command buffer for the Get Log command with
LID value ``NVME_LOG_LID_SANITIZE``


.. c:function:: void nvme_init_get_log_mfg_default_config_status (struct libnvme_passthru_cmd *cmd, struct nvme_mfg_default_config_status_log *log)

   Initialize passthru command for Manufacturer Default Configuration Status

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``struct nvme_mfg_default_config_status_log *log``
  User address to store the log

**Description**

Initializes the passthru command buffer for the Get Log command with
LID value ``NVME_LOG_LID_MFG_DEFAULT_CONFIG``


.. c:function:: void nvme_init_get_log_dev_personality (struct libnvme_passthru_cmd *cmd, struct nvme_dev_personalities_log *log, __u32 len)

   Initialize passthru command for Device Personalities

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``struct nvme_dev_personalities_log *log``
  User address to store the log page

``__u32 len``
  The allocated length of the log page

**Description**

Initializes the passthru command buffer for the Get Log command with
LID value ``NVME_LOG_LID_DEV_PERSONALITY``


.. c:function:: void nvme_init_identify (struct libnvme_passthru_cmd *cmd, __u32 nsid, enum nvme_csi csi, enum nvme_identify_cns cns, void *data, __u32 len)

   Initialize passthru command for NVMe Identify

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Command data structure to initialize

``__u32 nsid``
  Namespace identifier

``enum nvme_csi csi``
  Command Set Identifier

``enum nvme_identify_cns cns``
  The Controller or Namespace structure,
  see **enum** nvme_identify_cns

``void *data``
  User space destination address to transfer the data

``__u32 len``
  Length of provided user buffer to hold the data in bytes

**Description**

Prepare the **cmd** data structure for the NVMe Identify command.


.. c:function:: void nvme_init_identify_ns (struct libnvme_passthru_cmd *cmd, __u32 nsid, struct nvme_id_ns *id)

   Initialize passthru command for NVMe Identify Namespace data structure

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Command data structure to initialize

``__u32 nsid``
  Namespace identifier

``struct nvme_id_ns *id``
  User space destination address to transfer the data

**Description**

Initializes the passthru command buffer for the Identify command with
CNS value ``NVME_IDENTIFY_CNS_NS``.


.. c:function:: void nvme_init_identify_ctrl (struct libnvme_passthru_cmd *cmd, struct nvme_id_ctrl *id)

   Initialize passthru command for NVMe Identify Controller data structure

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Command data structure to initialize

``struct nvme_id_ctrl *id``
  User space destination address to transfer the data,

**Description**

Initializes the passthru command buffer for the Identify command with
CNS value ``NVME_IDENTIFY_CNS_CTRL``.


.. c:function:: void nvme_init_identify_active_ns_list (struct libnvme_passthru_cmd *cmd, __u32 nsid, struct nvme_ns_list *list)

   Initialize passthru command for Active Namespaces ID list

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Command data structure to initialize

``__u32 nsid``
  Namespace identifier

``struct nvme_ns_list *list``
  User space destination address to transfer the data

**Description**

Initializes the passthru command buffer for the Identify command with
CNS value ``NVME_IDENTIFY_CNS_NS_ACTIVE_LIST``.


.. c:function:: void nvme_init_identify_ns_descs_list (struct libnvme_passthru_cmd *cmd, __u32 nsid, struct nvme_ns_id_desc *descs)

   Initialize passthru command for Namespace Descriptor list

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Command data structure to initialize

``__u32 nsid``
  The namespace id to retrieve descriptors

``struct nvme_ns_id_desc *descs``
  User space destination address to transfer the data

**Description**

Initializes the passthru command buffer for the Identify command with
CNS value ``NVME_IDENTIFY_CNS_NS_DESC_LIST``.


.. c:function:: void nvme_init_identify_nvmset_list (struct libnvme_passthru_cmd *cmd, __u32 nsid, __u16 nvmsetid, struct nvme_id_nvmset_list *nvmset)

   Initialize passthru command for NVM Set List data structure

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Command data structure to initialize

``__u32 nsid``
  Namespace identifier

``__u16 nvmsetid``
  NVM Set Identifier

``struct nvme_id_nvmset_list *nvmset``
  User space destination address to transfer the data

**Description**

Initializes the passthru command buffer for the Identify command with
CNS value ``NVME_IDENTIFY_CNS_NS_ACTIVE_LIST``.


.. c:function:: void nvme_init_identify_csi_ns (struct libnvme_passthru_cmd *cmd, __u32 nsid, enum nvme_csi csi, __u8 uidx, void *data)

   Initialize passthru command for I/O Command Set specific Identify Namespace data structure

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Command data structure to initialize

``__u32 nsid``
  Namespace identifier

``enum nvme_csi csi``
  Command Set Identifier

``__u8 uidx``
  UUID Index for differentiating vendor specific encoding

``void *data``
  User space destination address to transfer the data

**Description**

Initializes the passthru command buffer for the Identify command with
CNS value ``NVME_IDENTIFY_CNS_CSI_NS``.


.. c:function:: void nvme_init_identify_csi_ctrl (struct libnvme_passthru_cmd *cmd, enum nvme_csi csi, void *data)

   Initialize passthru command for I/O Command Set specific Identify Controller data structure

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Command data structure to initialize

``enum nvme_csi csi``
  Command Set Identifier

``void *data``
  User space destination address to transfer the data

**Description**

Initializes the passthru command buffer for the Identify command with
CNS value ``NVME_IDENTIFY_CNS_CSI_CTRL``.


.. c:function:: void nvme_init_identify_csi_active_ns_list (struct libnvme_passthru_cmd *cmd, __u32 nsid, enum nvme_csi csi, struct nvme_ns_list *ns_list)

   Initialize passthru command for Active namespace ID list

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Command data structure to initialize

``__u32 nsid``
  Return namespaces greater than this identifier

``enum nvme_csi csi``
  Command Set Identifier

``struct nvme_ns_list *ns_list``
  User space destination address to transfer the data

**Description**

Initializes the passthru command buffer for the Identify command with
CNS value ``NVME_IDENTIFY_CNS_CSI_NS_ACTIVE_LIST``.


.. c:function:: void nvme_init_identify_csi_independent_identify_id_ns (struct libnvme_passthru_cmd *cmd, __u32 nsid, struct nvme_id_independent_id_ns *ns)

   Initialize passthru command for I/O Command Set Independent Identify Namespace data structure

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Command data structure to initialize

``__u32 nsid``
  Return namespaces greater than this identifier

``struct nvme_id_independent_id_ns *ns``
  I/O Command Set Independent Identify Namespace data
  structure

**Description**

Initializes the passthru command buffer for the Identify command with
CNS value ``NVME_IDENTIFY_CNS_CSI_INDEPENDENT_ID_NS``.


.. c:function:: void nvme_init_identify_ns_user_data_format (struct libnvme_passthru_cmd *cmd, enum nvme_csi csi, __u16 fidx, __u8 uidx, void *data)

   Initialize passthru command for Identify namespace user data format

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Command data structure to initialize

``enum nvme_csi csi``
  Command Set Identifier

``__u16 fidx``
  Format Index

``__u8 uidx``
  UUID selection, if supported

``void *data``
  User space destination address to transfer the data

**Description**

Initializes the passthru command buffer for the Identify command with
CNS value ``NVME_IDENTIFY_CNS_NS_USER_DATA_FORMAT``.


.. c:function:: void nvme_init_identify_csi_ns_user_data_format (struct libnvme_passthru_cmd *cmd, enum nvme_csi csi, __u16 fidx, __u8 uidx, void *data)

   Initialize passthru command for Identify namespace user data format

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Command data structure to initialize

``enum nvme_csi csi``
  Command Set Identifier

``__u16 fidx``
  Format Index

``__u8 uidx``
  UUID selection, if supported

``void *data``
  User space destination address to transfer the data

**Description**

Initializes the passthru command buffer for the Identify command with
CNS value ``NVME_IDENTIFY_CNS_CSI_NS_USER_DATA_FORMAT``.


.. c:function:: void nvme_init_identify_allocated_ns_list (struct libnvme_passthru_cmd *cmd, __u32 nsid, struct nvme_ns_list *ns_list)

   Initialize passthru command for Allocated namespace ID list

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Command data structure to initialize

``__u32 nsid``
  Return namespaces greater than this identifier

``struct nvme_ns_list *ns_list``
  User space destination address to transfer the data

**Description**

Initializes the passthru command buffer for the Identify command with
CNS value ``NVME_IDENTIFY_CNS_ALLOCATED_NS_LIST``.


.. c:function:: void nvme_init_identify_allocated_ns (struct libnvme_passthru_cmd *cmd, __u32 nsid, struct nvme_id_ns *ns)

   Initialize passthru command for allocated Namespace ID list

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Command data structure to initialize

``__u32 nsid``
  Namespace to identify

``struct nvme_id_ns *ns``
  User space destination address to transfer the data

**Description**

Initializes the passthru command buffer for the Identify command with
CNS value ``NVME_IDENTIFY_CNS_ALLOCATED_NS``.


.. c:function:: void nvme_init_identify_ns_ctrl_list (struct libnvme_passthru_cmd *cmd, __u32 nsid, __u16 cntid, struct nvme_ctrl_list *cntlist)

   Initialize passhtru command for Controller List

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Command data structure to initialize

``__u32 nsid``
  Return controllers that are attached to this nsid

``__u16 cntid``
  Starting CNTLID to return in the list

``struct nvme_ctrl_list *cntlist``
  User space destination address to transfer the data

**Description**

Initializes the passthru command buffer for the Identify command with
CNS value ``NVME_IDENTIFY_CNS_NS_CTRL_LIST``.


.. c:function:: void nvme_init_identify_ctrl_list (struct libnvme_passthru_cmd *cmd, __u16 cntid, struct nvme_ctrl_list *cntlist)

   Initialize passthru command for Controller List of controllers

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Command data structure to initialize

``__u16 cntid``
  Starting CNTLID to return in the list

``struct nvme_ctrl_list *cntlist``
  User space destination address to transfer the data

**Description**

Initializes the passthru command buffer for the Identify command with
CNS value ``NVME_IDENTIFY_CNS_CTRL_LIST``.


.. c:function:: void nvme_init_identify_primary_ctrl_cap (struct libnvme_passthru_cmd *cmd, __u16 cntid, struct nvme_primary_ctrl_cap *cap)

   Initialize passthru command for Primary Controller Capabilities data

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Command data structure to initialize

``__u16 cntid``
  Return controllers starting at this identifier

``struct nvme_primary_ctrl_cap *cap``
  User space destination buffer address to transfer the data

**Description**

Initializes the passthru command buffer for the Identify command with
CNS value ``NVME_IDENTIFY_CNS_PRIMARY_CTRL_CAP``.


.. c:function:: void nvme_init_identify_secondary_ctrl_list (struct libnvme_passthru_cmd *cmd, __u16 cntid, struct nvme_secondary_ctrl_list *sc_list)

   Initialize passhru command for Secondary Controller list

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Command data structure to initialize

``__u16 cntid``
  Return controllers starting at this identifier

``struct nvme_secondary_ctrl_list *sc_list``
  User space destination address to transfer the data

**Description**

Initializes the passthru command buffer for the Identify command with
CNS value ``NVME_IDENTIFY_CNS_SECONDARY_CTRL_LIST``.


.. c:function:: void nvme_init_identify_ns_granularity (struct libnvme_passthru_cmd *cmd, struct nvme_id_ns_granularity_list *gr_list)

   Initialize passthru command for Namespace Granularity list

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Command data structure to initialize

``struct nvme_id_ns_granularity_list *gr_list``
  User space destination address to transfer the data

**Description**

Initializes the passthru command buffer for the Identify command with
CNS value ``NVME_IDENTIFY_CNS_SECONDARY_CTRL_LIST``.


.. c:function:: void nvme_init_identify_uuid_list (struct libnvme_passthru_cmd *cmd, struct nvme_id_uuid_list *uuid_list)

   Initialize passthru command for UUID list

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Command data structure to initialize

``struct nvme_id_uuid_list *uuid_list``
  User space destination address to transfer the data

**Description**

Initializes the passthru command buffer for the Identify command with
CNS value ``NVME_IDENTIFY_CNS_UUID_LIST``.


.. c:function:: void nvme_init_identify_domain_list (struct libnvme_passthru_cmd *cmd, __u16 domid, struct nvme_id_domain_list *list)

   Initialize passthru command for Domain list

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Command data structure to initialize

``__u16 domid``
  Domain ID

``struct nvme_id_domain_list *list``
  User space destination address to transfer data

**Description**

Initializes the passthru command buffer for the Identify command with
CNS value ``NVME_IDENTIFY_CNS_DOMAIN_LIST``.


.. c:function:: void nvme_init_identify_endurance_group_id (struct libnvme_passthru_cmd *cmd, __u16 enggid, struct nvme_id_endurance_group_list *list)

   Initialize passthru command for Endurance group list

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Command data structure to initialize

``__u16 enggid``
  Endurance group identifier

``struct nvme_id_endurance_group_list *list``
  Array of endurance group identifiers


.. c:function:: void nvme_init_identify_csi_allocated_ns_list (struct libnvme_passthru_cmd *cmd, __u32 nsid, enum nvme_csi csi, struct nvme_ns_list *ns_list)

   Initialize passthru command for I/O Command Set specific Allocated Namespace Id list

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Command data structure to initialize

``__u32 nsid``
  Return namespaces greater than this identifier

``enum nvme_csi csi``
  Command Set Identifier

``struct nvme_ns_list *ns_list``
  User space destination address to transfer the data

**Description**

Initializes the passthru command buffer for the Identify command with
CNS value ``NVME_IDENTIFY_CNS_CSI_ALLOCATED_NS_LIST``.


.. c:function:: void nvme_init_identify_csi_id_ns_data_structure (struct libnvme_passthru_cmd *cmd, __u32 nsid, enum nvme_csi csi, void *data)

   Initialize passthru command for I/O Command Set specific Identify Namespace data structure

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Command data structure to initialize

``__u32 nsid``
  Return namespaces greater than this identifier

``enum nvme_csi csi``
  Command Set Identifier

``void *data``
  User space destination address to transfer the data

**Description**

Initializes the passthru command buffer for the Identify command with
CNS value ``NVME_IDENTIFY_CNS_CSI_ID_NS_DATA_STRUCTURE``.


.. c:function:: void nvme_init_identify_command_set_structure (struct libnvme_passthru_cmd *cmd, __u16 cntid, struct nvme_id_iocs *iocs)

   Initialize passthru command for I/O Command Set data structure

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Command data structure to initialize

``__u16 cntid``
  Controller ID

``struct nvme_id_iocs *iocs``
  User space destination address to transfer the data

**Description**

Retrieves list of the controller's supported io command set vectors. See
:c:type:`struct nvme_id_iocs <nvme_id_iocs>`.


.. c:function:: void nvme_init_identify_underlying_ns_list (struct libnvme_passthru_cmd *cmd, __u16 idx, struct nvme_underlying_ns_list *list)

   Initialize passthru command for Get Underlying Namespace List

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Command data structure to initialize

``__u16 idx``
  Index into the list of reportable Underlying Namespaces to
  start reporting from

``struct nvme_underlying_ns_list *list``
  User space destination address to transfer the data

**Description**

Initializes the passthru command buffer for the Identify command with
CNS value ``NVME_IDENTIFY_CNS_UNDERLYING_NS_LIST``.


.. c:function:: void nvme_init_identify_ports_list (struct libnvme_passthru_cmd *cmd, struct nvme_ports_list *list, __u32 len)

   Initialize passthru command for Get Ports List

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Command data structure to initialize

``struct nvme_ports_list *list``
  User space destination address to transfer the data

``__u32 len``
  The allocated length of **list**

**Description**

Initializes the passthru command buffer for the Identify command with
CNS value ``NVME_IDENTIFY_CNS_PORTS_LIST``.


.. c:function:: void nvme_init_identify_iocs_ind_id_alloc_ns (struct libnvme_passthru_cmd *cmd, __u32 nsid, struct nvme_id_independent_id_ns *ns)

   Initialize passthru command for I/O Command Set Independent Identify Namespace data structure for an Allocated Namespace ID

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Command data structure to initialize

``__u32 nsid``
  Allocated namespace identifier

``struct nvme_id_independent_id_ns *ns``
  I/O Command Set Independent Identify Namespace data structure

**Description**

Initializes the passthru command buffer for the Identify command with
CNS value ``NVME_IDENTIFY_CNS_IOCS_IND_ID_ALLOC_NS``.


.. c:function:: void nvme_init_identify_supported_ctrl_state_formats (struct libnvme_passthru_cmd *cmd, struct nvme_supported_ctrl_state_formats *formats)

   Initialize passthru command for Supported Controller State Formats

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Command data structure to initialize

``struct nvme_supported_ctrl_state_formats *formats``
  User space destination address to transfer the data

**Description**

Initializes the passthru command buffer for the Identify command with
CNS value ``NVME_IDENTIFY_CNS_SUPPORTED_CTRL_STATE_FORMATS``.


.. c:function:: void nvme_init_identify_underlying_ctrl_list (struct libnvme_passthru_cmd *cmd, __u16 cntid, struct nvme_ctrl_list *cntlist)

   Initialize passthru command for Get Underlying Controller List

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Command data structure to initialize

``__u16 cntid``
  Starting CNTLID to return in the list

``struct nvme_ctrl_list *cntlist``
  User space destination address to transfer the data

**Description**

Initializes the passthru command buffer for the Identify command with
CNS value ``NVME_IDENTIFY_CNS_UNDERLYING_CTRL_LIST``.


.. c:function:: void nvme_init_identify_exported_nvm_subsys_template_uuid_list (struct libnvme_passthru_cmd *cmd, struct nvme_exported_nvm_subsys_template_uuid_list *list)

   Initialize passthru command for Exported NVM Subsystem Template UUID List

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Command data structure to initialize

``struct nvme_exported_nvm_subsys_template_uuid_list *list``
  User space destination address to transfer the data

**Description**

Initializes the passthru command buffer for the Identify command with
CNS value ``NVME_IDENTIFY_CNS_EXPORTED_NVM_SUBSYS_TEMPLATE_UUID_LIST``.


.. c:function:: void nvme_init_abort (struct libnvme_passthru_cmd *cmd, __u16 sqid, __u16 cid)

   Initialize passthru command for Abort command

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``__u16 sqid``
  Submission Queue Identifier (SQID) of the command to abort

``__u16 cid``
  Command Identifier (CID) of the command to abort

**Description**

Initializes the passthru command buffer for the Abort command.


.. c:function:: void nvme_init_async_event (struct libnvme_passthru_cmd *cmd)

   Initialize passthru command for Asynchronous Event Request command

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

**Description**

Initializes the passthru command buffer for the Asynchronous Event
Request command. All command specific fields are reserved.


.. c:function:: void nvme_init_set_features (struct libnvme_passthru_cmd *cmd, __u8 fid, bool sv)

   Initialize passthru command for Set Features

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``__u8 fid``
  Feature identifier

``bool sv``
  Save value across power states


.. c:function:: void nvme_init_set_features_arbitration (struct libnvme_passthru_cmd *cmd, bool sv, __u8 ab, __u8 lpw, __u8 mpw, __u8 hpw)

   Initialize passthru command for Arbitration Features

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``bool sv``
  Save value across power states

``__u8 ab``
  Arbitration Burst

``__u8 lpw``
  Low Priority Weight

``__u8 mpw``
  Medium Priority Weight

``__u8 hpw``
  High Priority Weight

**Description**

Initializes the passthru command buffer for the Set Features command with
FID value ``NVME_FEAT_FID_ARBRITARTION``


.. c:function:: void nvme_init_set_features_power_mgmt (struct libnvme_passthru_cmd *cmd, bool sv, __u8 ps, __u8 wh)

   Initialize passthru command for Power Management

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``bool sv``
  Save value across power states

``__u8 ps``
  Power State

``__u8 wh``
  Workload Hint

**Description**

Initializes the passthru command buffer for the Set Features command with
FID value ``NVME_FEAT_FID_PWRMGMT_PS``


.. c:function:: void nvme_init_set_features_lba_range (struct libnvme_passthru_cmd *cmd, __u32 nsid, bool sv, __u8 num, struct nvme_lba_range_type *data)

   Initialize passthru command for LBA Range

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``__u32 nsid``
  Namespace ID

``bool sv``
  Save value across power states

``__u8 num``
  Number of ranges in **data**

``struct nvme_lba_range_type *data``
  User address of feature data

**Description**

Initializes the passthru command buffer for the Set Features command with
FID value ``NVME_FEAT_FID_LBA_RANGE``


.. c:function:: void nvme_init_set_features_temp_thresh (struct libnvme_passthru_cmd *cmd, bool sv, __u16 tmpth, __u8 tmpsel, enum nvme_feat_tmpthresh_thsel thsel, __u8 tmpthh)

   Initialize passthru command for Temperature Threshold

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``bool sv``
  Save value across power states

``__u16 tmpth``
  Temperature Threshold

``__u8 tmpsel``
  Threshold Temperature Select

``enum nvme_feat_tmpthresh_thsel thsel``
  Threshold Type Select

``__u8 tmpthh``
  Temperature Threshold Hysteresis

**Description**

Initializes the passthru command buffer for the Set Features command with
FID value ``NVME_FEAT_FID_TEMP_THRESH``


.. c:function:: void nvme_init_set_features_err_recovery (struct libnvme_passthru_cmd *cmd, __u32 nsid, bool sv, __u16 tler, bool dulbe)

   Initialize passthru command for Error Recovery

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``__u32 nsid``
  Namespace ID

``bool sv``
  Save value across power states

``__u16 tler``
  Time-limited error recovery value

``bool dulbe``
  Deallocated or Unwritten Logical Block Error Enable

**Description**

Initializes the passthru command buffer for the Set Features command with
FID value ``NVME_FEAT_FID_ERR_RECOVERY``


.. c:function:: void nvme_init_set_features_volatile_wc (struct libnvme_passthru_cmd *cmd, bool sv, bool wce)

   Initialize passthru command for Volatile Write Cache

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``bool sv``
  Save value across power states

``bool wce``
  Write cache enable

**Description**

Initializes the passthru command buffer for the Set Features command with
FID value ``NVME_FEAT_FID_VOLATILE_WC``


.. c:function:: void nvme_init_set_features_irq_coalesce (struct libnvme_passthru_cmd *cmd, bool sv, __u8 thr, __u8 time)

   Initialize passthru command for IRQ Coalescing

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``bool sv``
  Save value across power states

``__u8 thr``
  Aggregation Threshold

``__u8 time``
  Aggregation Time

**Description**

Initializes the passthru command buffer for the Set Features command with
FID value ``NVME_FEAT_FID_IRQ_COALESCE``


.. c:function:: void nvme_init_set_features_irq_config (struct libnvme_passthru_cmd *cmd, bool sv, __u16 iv, bool cd)

   Initialize passthru command for IRQ Config

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``bool sv``
  Save value across power states

``__u16 iv``
  Interrupt Vector

``bool cd``
  Coalescing Disable

**Description**

Initializes the passthru command buffer for the Set Features command with
FID value ``NVME_FEAT_FID_IRQ_CONFIG``


.. c:function:: void nvme_init_set_features_write_atomic (struct libnvme_passthru_cmd *cmd, bool sv, bool dn)

   Initialize passthru command for Write Atomic

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``bool sv``
  Save value across power states

``bool dn``
  Disable Normal

**Description**

Initializes the passthru command buffer for the Set Features command with
FID value ``NVME_FEAT_FID_WRITE_ATOMIC``


.. c:function:: void nvme_init_set_features_async_event (struct libnvme_passthru_cmd *cmd, bool sv, __u32 events)

   Initialize passthru command for Asynchronous Event Configuration

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``bool sv``
  Save value across power states

``__u32 events``
  Events to enable

**Description**

Initializes the passthru command buffer for the Set Features command with
FID value ``NVME_FEAT_FID_ASYNC_EVENT``


.. c:function:: void nvme_init_set_features_auto_pst (struct libnvme_passthru_cmd *cmd, bool sv, bool apste, struct nvme_feat_auto_pst *apst)

   Initialize passthru command for Autonomous Power State Transition

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``bool sv``
  Save value across power states

``bool apste``
  Autonomous Power State Transition Enable

``struct nvme_feat_auto_pst *apst``
  Autonomous Power State Transition data buffer

**Description**

Initializes the passthru command buffer for the Set Features command with
FID value ``NVME_FEAT_FID_AUTO_PST``


.. c:function:: void nvme_init_set_features_timestamp (struct libnvme_passthru_cmd *cmd, bool sv, __u64 tstmp, struct nvme_timestamp *ts)

   Initialize passthru command for Timestamp

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``bool sv``
  Save value across power states

``__u64 tstmp``
  The current timestamp value to assign to this feature

``struct nvme_timestamp *ts``
  Timestamp data buffer (populated by this function)

**Description**

Initializes the passthru command buffer for the Set Features command with
FID value ``NVME_FEAT_FID_TIMESTAMP``. The caller must provide a valid
buffer via **ts**, which this function will populate.


.. c:function:: void nvme_init_set_features_hctm (struct libnvme_passthru_cmd *cmd, bool sv, __u16 tmt2, __u16 tmt1)

   Initialize passthru command for Host Controlled Thermal Management

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``bool sv``
  Save value across power states

``__u16 tmt2``
  Thermal Management Temperature 2

``__u16 tmt1``
  Thermal Management Temperature 1

**Description**

Initializes the passthru command buffer for the Set Features command with
FID value ``NVME_FEAT_FID_HCTM``


.. c:function:: void nvme_init_set_features_nopsc (struct libnvme_passthru_cmd *cmd, bool sv, bool noppme)

   Initialize passthru command for Non-Operational Power State Config

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``bool sv``
  Save value across power states

``bool noppme``
  Non-Operational Power State Permissive Mode Enable

**Description**

Initializes the passthru command buffer for the Set Features command with
FID value ``NVME_FEAT_FID_NOPSC``


.. c:function:: void nvme_init_set_features_rrl (struct libnvme_passthru_cmd *cmd, bool sv, __u16 nvmsetid, __u8 rrl)

   Initialize passthru command for Read Recovery Level

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``bool sv``
  Save value across power states

``__u16 nvmsetid``
  NVM set id

``__u8 rrl``
  Read recovery level setting

**Description**

Initializes the passthru command buffer for the Set Features command with
FID value ``NVME_FEAT_FID_RRL``


.. c:function:: void nvme_init_set_features_plm_config (struct libnvme_passthru_cmd *cmd, bool sv, __u16 nvmsetid, bool lpe, struct nvme_plm_config *data)

   Initialize passthru command for Predictable Latency Mode Config

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``bool sv``
  Save value across power states

``__u16 nvmsetid``
  NVM Set Identifier

``bool lpe``
  Predictable Latency Enable

``struct nvme_plm_config *data``
  Pointer to structure nvme_plm_config

**Description**

Initializes the passthru command buffer for the Set Features command with
FID value ``NVME_FEAT_FID_PLM_CONFIG``


.. c:function:: void nvme_init_set_features_plm_window (struct libnvme_passthru_cmd *cmd, bool sv, __u16 nvmsetid, enum nvme_feat_plm_window_select wsel)

   Initialize passthru command for Predictable Latency Mode Window

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``bool sv``
  Save value across power states

``__u16 nvmsetid``
  NVM Set Identifier

``enum nvme_feat_plm_window_select wsel``
  Window Select

**Description**

Initializes the passthru command buffer for the Set Features command with
FID value ``NVME_FEAT_FID_PLM_WINDOW``


.. c:function:: void nvme_init_set_features_lba_sts_interval (struct libnvme_passthru_cmd *cmd, bool sv, __u16 lsiri, __u16 lsipi)

   Initialize passthru command for LBA Status Information Interval

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``bool sv``
  Save value across power states

``__u16 lsiri``
  LBA Status Information Report Interval

``__u16 lsipi``
  LBA Status Information Poll Interval

**Description**

Initializes the passthru command buffer for the Set Features command with
FID value ``NVME_FEAT_FID_LBA_STS_INTERVAL``


.. c:function:: void nvme_init_set_features_host_behavior (struct libnvme_passthru_cmd *cmd, bool sv, struct nvme_feat_host_behavior *data)

   Initialize passthru command for Host Behavior

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``bool sv``
  Save value across power states

``struct nvme_feat_host_behavior *data``
  Pointer to structure nvme_feat_host_behavior

**Description**

Initializes the passthru command buffer for the Set Features command with
FID value ``NVME_FEAT_FID_HOST_BEHAVIOR``


.. c:function:: void nvme_init_set_features_sanitize (struct libnvme_passthru_cmd *cmd, bool sv, bool nodrm)

   Initialize passthru command for Sanitize

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``bool sv``
  Save value across power states

``bool nodrm``
  No-Deallocate Response Mode

**Description**

Initializes the passthru command buffer for the Set Features command with
FID value ``NVME_FEAT_FID_SANITIZE``


.. c:function:: void nvme_init_set_features_endurance_evt_cfg (struct libnvme_passthru_cmd *cmd, bool sv, __u16 endgid, __u8 egcw)

   Initialize passthru command for Endurance Group Event Configuration

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``bool sv``
  Save value across power states

``__u16 endgid``
  Endurance Group Identifier

``__u8 egcw``
  Flags to enable warning,
  see :c:type:`enum nvme_eg_critical_warning_flags <nvme_eg_critical_warning_flags>`

**Description**

Initializes the passthru command buffer for the Set Features command with
FID value ``NVME_FEAT_FID_ENDURANCE_EVT_CFG``


.. c:function:: void nvme_init_set_features_sw_progress (struct libnvme_passthru_cmd *cmd, bool sv, __u8 pbslc)

   Initialize passthru command for Software Pogress Marker

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``bool sv``
  Save value across power states

``__u8 pbslc``
  Pre-boot Software Load Count

**Description**

Initializes the passthru command buffer for the Set Features command with
FID value ``NVME_FEAT_FID_SW_PROGRESS``


.. c:function:: void nvme_init_set_features_host_id (struct libnvme_passthru_cmd *cmd, bool sv, bool exhid, __u8 *hostid)

   Initialize passthru command for Host Identifier

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``bool sv``
  Save value across power states

``bool exhid``
  Enable Extended Host Identifier

``__u8 *hostid``
  Host ID buffer to set

**Description**

Initializes the passthru command buffer for the Set Features command with
FID value ``NVME_FEAT_FID_HOST_ID``.


.. c:function:: void nvme_init_set_features_resv_nf_mask (struct libnvme_passthru_cmd *cmd, __u32 nsid, bool sv, __u32 mask)

   Initialize passthru command for Reservation Notification Mask

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``__u32 nsid``
  Namespace ID

``bool sv``
  Save value across power states

``__u32 mask``
  Reservation Notification Mask Field

**Description**

Initializes the passthru command buffer for the Set Features command with
FID value ``NVME_FEAT_FID_RESV_NF_MASK``


.. c:function:: void nvme_init_set_features_resv_persist (struct libnvme_passthru_cmd *cmd, __u32 nsid, bool sv, bool ptpl)

   Initialize passthru command for Reservation Persistence

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``__u32 nsid``
  Namespace ID

``bool sv``
  Save value across power states

``bool ptpl``
  Persist Through Power Loss

**Description**

Initializes the passthru command buffer for the Set Features command with
FID value ``NVME_FEAT_FID_RESV_PERSIST``


.. c:function:: void nvme_init_set_features_write_protect (struct libnvme_passthru_cmd *cmd, __u32 nsid, bool sv, enum nvme_feat_nswpcfg_state wps)

   Initialize passthru command for Write Protect

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``__u32 nsid``
  Namespace ID

``bool sv``
  Save value across power states

``enum nvme_feat_nswpcfg_state wps``
  Write Protection State

**Description**

Initializes the passthru command buffer for the Set Features command with
FID value ``NVME_FEAT_FID_WRITE_PROTECT``


.. c:function:: void nvme_init_set_features_iocs_profile (struct libnvme_passthru_cmd *cmd, bool sv, __u16 iocsci)

   Initialize passthru command for I/O Command Set Profile

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``bool sv``
  Save value across power states

``__u16 iocsci``
  I/O Command Set Combination Index

**Description**

Initializes the passthru command buffer for the Set Features command with
FID value ``NVME_FEAT_FID_IOCS_PROFILE``


.. c:function:: void nvme_init_lm_set_features_ctrl_data_queue (struct libnvme_passthru_cmd *cmd, __u16 cdqid, __u32 hp, __u32 tpt, bool etpt)

   Initialize passthru command for Set Controller Data Queue feature

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``__u16 cdqid``
  Controller Data Queue ID (CDQID)

``__u32 hp``
  Head Pointer (passed in cdw12)

``__u32 tpt``
  Tail Pointer Trigger (passed in cdw13)

``bool etpt``
  Enable Tail Pointer Trigger

**Description**

Initializes the passthru command buffer for the Set Features command with
FID value ``NVME_FEAT_FID_CTRL_DATA_QUEUE``.


.. c:function:: void nvme_init_set_features_rate_limiting (struct libnvme_passthru_cmd *cmd, bool sv, __u8 target, __u16 tid, struct nvme_rate_limiting_data *data)

   Initialize passthru command for Rate Limiting

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``bool sv``
  Save value across power states

``__u8 target``
  Target of the rate limits setting, see
  :c:type:`enum nvme_rate_limiting_target <nvme_rate_limiting_target>`

``__u16 tid``
  Target Identifier for the target specified by **target**

``struct nvme_rate_limiting_data *data``
  User address of the Rate Limiting data buffer, see
  :c:type:`struct nvme_rate_limiting_data <nvme_rate_limiting_data>`

**Description**

Initializes the passthru command buffer for the Set Features command with
FID value ``NVME_FEAT_FID_RATE_LIMITING``


.. c:function:: void nvme_init_set_features_spinup_control (struct libnvme_passthru_cmd *cmd, bool sv, bool sce)

   Initialize passthru command for Spinup Control

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``bool sv``
  Save value across power states

``bool sce``
  Spinup Control Enable (SCE)

**Description**

Initializes the passthru command buffer for the Set Features command with
FID value ``NVME_FEAT_FID_SPINUP_CONTROL``


.. c:function:: void nvme_init_set_features_power_loss_signal (struct libnvme_passthru_cmd *cmd, bool sv, __u8 plsm)

   Initialize passthru command for Power Loss Signaling Config

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``bool sv``
  Save value across power states

``__u8 plsm``
  Power Loss Signaling Mode (PLSM)

**Description**

Initializes the passthru command buffer for the Set Features command with
FID value ``NVME_FEAT_FID_POWER_LOSS_SIGNAL``


.. c:function:: void nvme_init_set_features_perf_characteristics (struct libnvme_passthru_cmd *cmd, bool sv, __u8 attri, bool rvspa, struct nvme_perf_characteristics *data)

   Initialize passthru command for Performance Characteristics

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``bool sv``
  Save value across power states

``__u8 attri``
  Attribute Index (ATTRI)

``bool rvspa``
  Revert Vendor Specific Performance Attribute (RVSPA)

``struct nvme_perf_characteristics *data``
  Pointer to structure nvme_perf_characteristics

**Description**

Initializes the passthru command buffer for the Set Features command with
FID value ``NVME_FEAT_FID_PERF_CHARACTERISTICS``


.. c:function:: void nvme_init_set_features_fdp (struct libnvme_passthru_cmd *cmd, bool sv, __u16 endgid, __u8 fdpcidx, bool fdpe)

   Initialize passthru command for Flexible Data Placement

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``bool sv``
  Save value across power states

``__u16 endgid``
  Endurance Group Identifier (ENDGID)

``__u8 fdpcidx``
  Flexible Data Placement Configuration Index (FDPCIDX)

``bool fdpe``
  Flexible Data Placement Enable (FDPE)

**Description**

Initializes the passthru command buffer for the Set Features command with
FID value ``NVME_FEAT_FID_FDP``


.. c:function:: void nvme_init_set_features_fdp_events (struct libnvme_passthru_cmd *cmd, bool sv, __u16 phndl, bool fdpee, __u8 *event_types, __u8 noet)

   Initialize passthru command for Flexible Data Placement Events

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``bool sv``
  Save value across power states

``__u16 phndl``
  Placement Handle (PHNDL)

``bool fdpee``
  FDP Event Enable (FDPEE)

``__u8 *event_types``
  FDP Event Type List data buffer, see Figure 504 of the Base
  Specification

``__u8 noet``
  Number of FDP Event Types (NOET) contained in **event_types**

**Description**

Initializes the passthru command buffer for the Set Features command with
FID value ``NVME_FEAT_FID_FDP_EVENTS``


.. c:function:: void nvme_init_set_features_ns_admin_label (struct libnvme_passthru_cmd *cmd, __u32 nsid, bool sv, void *label)

   Initialize passthru command for Namespace Admin Label

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``__u32 nsid``
  Namespace Identifier

``bool sv``
  Save value across power states

``void *label``
  256 byte, null-terminated UTF-8 Namespace Admin Label (NSAL)
  data buffer

**Description**

Initializes the passthru command buffer for the Set Features command with
FID value ``NVME_FEAT_FID_NS_ADMIN_LABEL``


.. c:function:: void nvme_init_set_features_personality (struct libnvme_passthru_cmd *cmd, bool sv, __u8 perid, bool chps, bool perfs, __u32 cdw11, void *data, __u32 len)

   Initialize passthru command for Configurable Device Personality

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``bool sv``
  Save value across power states

``__u8 perid``
  Personality Identifier (PERID), see :c:type:`enum nvme_personality_identifier <nvme_personality_identifier>`

``bool chps``
  Change Personality Settings (CHPS)

``bool perfs``
  Personality Freeze State (PERFS)

``__u32 cdw11``
  Personality Identifier specific Command Dword 11 value

``void *data``
  Personality Identifier specific data buffer, or NULL if the
  personality does not use the data buffer

``__u32 len``
  Length of **data**

**Description**

Initializes the passthru command buffer for the Set Features command with
FID value ``NVME_FEAT_FID_CONF_DEV_PERSONALITY``


.. c:function:: void nvme_init_set_features_power_limit (struct libnvme_passthru_cmd *cmd, bool sv, __u8 pls, __u16 plv)

   Initialize passthru command for Power Limit

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``bool sv``
  Save value across power states

``__u8 pls``
  Power Limit Scale (PLS)

``__u16 plv``
  Power Limit Value (PLV)

**Description**

Initializes the passthru command buffer for the Set Features command with
FID value ``NVME_FEAT_FID_POWER_LIMIT``


.. c:function:: void nvme_init_set_features_power_threshold (struct libnvme_passthru_cmd *cmd, bool sv, bool ept, __u8 pmts, __u8 pts, __u16 ptv)

   Initialize passthru command for Power Threshold

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``bool sv``
  Save value across power states

``bool ept``
  Enable Power Threshold (EPT)

``__u8 pmts``
  Power Measurement Type Select (PMTS)

``__u8 pts``
  Power Threshold Scale (PTS)

``__u16 ptv``
  Power Threshold Value (PTV)

**Description**

Initializes the passthru command buffer for the Set Features command with
FID value ``NVME_FEAT_FID_POWER_THRESH``


.. c:function:: void nvme_init_set_features_power_measurement (struct libnvme_passthru_cmd *cmd, bool sv, __u8 act, __u8 pmts, __u16 smt, __u32 actsp)

   Initialize passthru command for Power Measurement

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``bool sv``
  Save value across power states

``__u8 act``
  Action (ACT), see :c:type:`enum nvme_voltage_measurement_act <nvme_voltage_measurement_act>` (the
  Power Measurement and Voltage Measurement Action field
  values are defined identically)

``__u8 pmts``
  Power Measurement Type Select (PMTS), used if **act** requests
  Start Power Measurements

``__u16 smt``
  Stop Measurement Time (SMT), used if **act** requests Start Power
  Measurements

``__u32 actsp``
  Action Specific (ACTSP) Command Dword 12 value

**Description**

Initializes the passthru command buffer for the Set Features command with
FID value ``NVME_FEAT_FID_POWER_MEASUREMENT``


.. c:function:: void nvme_init_set_features_voltage_threshold (struct libnvme_passthru_cmd *cmd, bool sv, __u8 vsens, bool evt, __u16 ovt, __u16 uvt)

   Initialize passthru command for Voltage Threshold

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``bool sv``
  Save value across power states

``__u8 vsens``
  Voltage Sensor Select (VSENS)

``bool evt``
  Enable Voltage Threshold (EVT)

``__u16 ovt``
  Overvoltage Threshold (OVT)

``__u16 uvt``
  Undervoltage Threshold (UVT)

**Description**

Initializes the passthru command buffer for the Set Features command with
FID value ``NVME_FEAT_FID_VOLTAGE_THRESHOLD``


.. c:function:: void nvme_init_set_features_voltage_measurement (struct libnvme_passthru_cmd *cmd, bool sv, __u8 act, struct nvme_voltage_measurement_start_data *data)

   Initialize passthru command for Voltage Measurement

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``bool sv``
  Save value across power states

``__u8 act``
  Action (ACT), see :c:type:`enum nvme_voltage_measurement_act <nvme_voltage_measurement_act>`

``struct nvme_voltage_measurement_start_data *data``
  Start Voltage Measurements data buffer, used if **act** is
  ``NVME_VOLTAGE_MEASUREMENT_ACT_START``, otherwise NULL, see
  :c:type:`struct nvme_voltage_measurement_start_data <nvme_voltage_measurement_start_data>`

**Description**

Initializes the passthru command buffer for the Set Features command with
FID value ``NVME_FEAT_FID_VOLTAGE_MEASUREMENT``


.. c:function:: void nvme_init_set_features_emb_mgmt_ctrl_addr (struct libnvme_passthru_cmd *cmd, bool sv, void *data)

   Initialize passthru command for Embedded Management Controller Address

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``bool sv``
  Save value across power states

``void *data``
  512 byte Embedded Management Controller Address (EMCA) data
  buffer, see :c:type:`struct nvme_mgmt_addr_desc <nvme_mgmt_addr_desc>`

**Description**

Initializes the passthru command buffer for the Set Features command with
FID value ``NVME_FEAT_FID_EMB_MGMT_CTRL_ADDR``


.. c:function:: void nvme_init_set_features_host_mgmt_agent_addr (struct libnvme_passthru_cmd *cmd, bool sv, void *data)

   Initialize passthru command for Host Management Agent Address

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``bool sv``
  Save value across power states

``void *data``
  512 byte Host Management Agent Address (HMAA) data buffer,
  see :c:type:`struct nvme_mgmt_addr_desc <nvme_mgmt_addr_desc>`

**Description**

Initializes the passthru command buffer for the Set Features command with
FID value ``NVME_FEAT_FID_HOST_MGMT_AGENT_ADDR``


.. c:function:: void nvme_init_set_features_enh_ctrl_metadata (struct libnvme_passthru_cmd *cmd, bool sv, __u8 ea, struct nvme_host_metadata *data)

   Initialize passthru command for Enhanced Controller Metadata

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``bool sv``
  Save value across power states

``__u8 ea``
  Element Action (EA), see :c:type:`enum nvme_host_metadata_ea <nvme_host_metadata_ea>`

``struct nvme_host_metadata *data``
  Host Metadata data buffer, see :c:type:`struct nvme_host_metadata <nvme_host_metadata>`

**Description**

Initializes the passthru command buffer for the Set Features command with
FID value ``NVME_FEAT_FID_ENH_CTRL_METADATA``


.. c:function:: void nvme_init_set_features_ctrl_metadata (struct libnvme_passthru_cmd *cmd, bool sv, __u8 ea, struct nvme_host_metadata *data)

   Initialize passthru command for Controller Metadata

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``bool sv``
  Save value across power states

``__u8 ea``
  Element Action (EA), see :c:type:`enum nvme_host_metadata_ea <nvme_host_metadata_ea>`

``struct nvme_host_metadata *data``
  Host Metadata data buffer, see :c:type:`struct nvme_host_metadata <nvme_host_metadata>`

**Description**

Initializes the passthru command buffer for the Set Features command with
FID value ``NVME_FEAT_FID_CTRL_METADATA``


.. c:function:: void nvme_init_set_features_ns_metadata (struct libnvme_passthru_cmd *cmd, bool sv, __u8 ea, struct nvme_host_metadata *data)

   Initialize passthru command for Namespace Metadata

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``bool sv``
  Save value across power states

``__u8 ea``
  Element Action (EA), see :c:type:`enum nvme_host_metadata_ea <nvme_host_metadata_ea>`

``struct nvme_host_metadata *data``
  Host Metadata data buffer, see :c:type:`struct nvme_host_metadata <nvme_host_metadata>`

**Description**

Initializes the passthru command buffer for the Set Features command with
FID value ``NVME_FEAT_FID_NS_METADATA``


.. c:function:: void nvme_init_set_features_bp_write_protect (struct libnvme_passthru_cmd *cmd, bool sv, __u8 bp0wps, __u8 bp1wps)

   Initialize passthru command for Boot Partition Write Protection Config

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``bool sv``
  Save value across power states

``__u8 bp0wps``
  Boot Partition 0 Write Protection State (BP0WPS)

``__u8 bp1wps``
  Boot Partition 1 Write Protection State (BP1WPS)

**Description**

Initializes the passthru command buffer for the Set Features command with
FID value ``NVME_FEAT_FID_BP_WRITE_PROTECT``


.. c:function:: void nvme_init_get_features (struct libnvme_passthru_cmd *cmd, __u8 fid, enum nvme_get_features_sel sel)

   Initialize passthru command for Get Features

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``__u8 fid``
  Feature identifier, see :c:type:`enum nvme_features_id <nvme_features_id>`

``enum nvme_get_features_sel sel``
  Select which type of attribute to return,
  see :c:type:`enum nvme_get_features_sel <nvme_get_features_sel>`


.. c:function:: void nvme_init_get_features_arbitration (struct libnvme_passthru_cmd *cmd, enum nvme_get_features_sel sel)

   Initialize passthru command for Get Features - Arbitration

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``enum nvme_get_features_sel sel``
  Select which type of attribute to return,
  see :c:type:`enum nvme_get_features_sel <nvme_get_features_sel>`

**Description**

Initializes the passthru command buffer for the Get Features command with
FID value ``NVME_FEAT_FID_ARBITRATION``


.. c:function:: void nvme_init_get_features_power_mgmt (struct libnvme_passthru_cmd *cmd, enum nvme_get_features_sel sel)

   Initialize passthru command for Get Features - Power Management

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``enum nvme_get_features_sel sel``
  Select which type of attribute to return,
  see :c:type:`enum nvme_get_features_sel <nvme_get_features_sel>`

**Description**

Initializes the passthru command buffer for the Get Features command with
FID value ``NVME_FEAT_FID_POWER_MGMT``


.. c:function:: void nvme_init_get_features_lba_range (struct libnvme_passthru_cmd *cmd, __u32 nsid, enum nvme_get_features_sel sel, struct nvme_lba_range_type *lrt)

   Initialize passthru command for Get Features - LBA Range

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``__u32 nsid``
  Namespace ID

``enum nvme_get_features_sel sel``
  Select which type of attribute to return,
  see :c:type:`enum nvme_get_features_sel <nvme_get_features_sel>`

``struct nvme_lba_range_type *lrt``
  Buffer to receive LBA Range Type data structure

**Description**

Initializes the passthru command buffer for the Get Features command with
FID value ``NVME_FEAT_FID_LBA_RANGE``


.. c:function:: void nvme_init_get_features_temp_thresh (struct libnvme_passthru_cmd *cmd, enum nvme_get_features_sel sel, __u8 tmpsel, enum nvme_feat_tmpthresh_thsel thsel)

   Initialize passthru command for Get Features - Temperature Threshold

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``enum nvme_get_features_sel sel``
  Select which type of attribute to return,
  see :c:type:`enum nvme_get_features_sel <nvme_get_features_sel>`

``__u8 tmpsel``
  Threshold Temperature Select

``enum nvme_feat_tmpthresh_thsel thsel``
  Threshold Type Select

**Description**

Initializes the passthru command buffer for the Get Features command with
FID value ``NVME_FEAT_FID_TEMP_THRESH``


.. c:function:: void nvme_init_get_features_err_recovery (struct libnvme_passthru_cmd *cmd, __u32 nsid, enum nvme_get_features_sel sel)

   Initialize passthru command for Get Features - Error Recovery

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``__u32 nsid``
  Namespace ID

``enum nvme_get_features_sel sel``
  Select which type of attribute to return,
  see :c:type:`enum nvme_get_features_sel <nvme_get_features_sel>`

**Description**

Initializes the passthru command buffer for the Get Features command with
FID value ``NVME_FEAT_FID_ERR_RECOVERY``


.. c:function:: void nvme_init_get_features_volatile_wc (struct libnvme_passthru_cmd *cmd, enum nvme_get_features_sel sel)

   Initialize passthru command for Get Features - Volatile Write Cache

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``enum nvme_get_features_sel sel``
  Select which type of attribute to return,
  see :c:type:`enum nvme_get_features_sel <nvme_get_features_sel>`

**Description**

Initializes the passthru command buffer for the Get Features command with
FID value ``NVME_FEAT_FID_VOLATILE_WC``


.. c:function:: void nvme_init_get_features_num_queues (struct libnvme_passthru_cmd *cmd, enum nvme_get_features_sel sel)

   Initialize passthru command for Get Features - Number of Queues

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``enum nvme_get_features_sel sel``
  Select which type of attribute to return,
  see :c:type:`enum nvme_get_features_sel <nvme_get_features_sel>`

**Description**

Initializes the passthru command buffer for the Get Features command with
FID value ``NVME_FEAT_FID_NUM_QUEUES``


.. c:function:: void nvme_init_get_features_irq_coalesce (struct libnvme_passthru_cmd *cmd, enum nvme_get_features_sel sel)

   Initialize passthru command for Get Features - IRQ Coalesce

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``enum nvme_get_features_sel sel``
  Select which type of attribute to return,
  see :c:type:`enum nvme_get_features_sel <nvme_get_features_sel>`

**Description**

Initializes the passthru command buffer for the Get Features command with
FID value ``NVME_FEAT_FID_IRQ_COALESCE``


.. c:function:: void nvme_init_get_features_irq_config (struct libnvme_passthru_cmd *cmd, enum nvme_get_features_sel sel, __u16 iv, bool cd)

   Initialize passthru command for Get Features - IRQ Config

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``enum nvme_get_features_sel sel``
  Select which type of attribute to return,
  see :c:type:`enum nvme_get_features_sel <nvme_get_features_sel>`

``__u16 iv``
  Interrupt Vector

``bool cd``
  Coalescing Disable

**Description**

Initializes the passthru command buffer for the Get Features command with
FID value ``NVME_FEAT_FID_IRQ_CONFIG``


.. c:function:: void nvme_init_get_features_write_atomic (struct libnvme_passthru_cmd *cmd, enum nvme_get_features_sel sel)

   Initialize passthru command for Get Features - Write Atomic

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``enum nvme_get_features_sel sel``
  Select which type of attribute to return,
  see :c:type:`enum nvme_get_features_sel <nvme_get_features_sel>`

**Description**

Initializes the passthru command buffer for the Get Features command with
FID value ``NVME_FEAT_FID_WRITE_ATOMIC``


.. c:function:: void nvme_init_get_features_async_event (struct libnvme_passthru_cmd *cmd, enum nvme_get_features_sel sel)

   Initialize passthru command for Get Features - Asynchronous Event Configuration

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``enum nvme_get_features_sel sel``
  Select which type of attribute to return,
  see :c:type:`enum nvme_get_features_sel <nvme_get_features_sel>`

**Description**

Initializes the passthru command buffer for the Get Features command with
FID value ``NVME_FEAT_FID_ASYNC_EVENT``


.. c:function:: void nvme_init_get_features_auto_pst (struct libnvme_passthru_cmd *cmd, enum nvme_get_features_sel sel, struct nvme_feat_auto_pst *apst)

   Initialize passthru command for Get Features - Autonomous Power State Transition

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``enum nvme_get_features_sel sel``
  Select which type of attribute to return,
  see :c:type:`enum nvme_get_features_sel <nvme_get_features_sel>`

``struct nvme_feat_auto_pst *apst``
  Autonomous Power State Transition data buffer

**Description**

Initializes the passthru command buffer for the Get Features command with
FID value ``NVME_FEAT_FID_AUTO_PST``


.. c:function:: void nvme_init_get_features_host_mem_buf (struct libnvme_passthru_cmd *cmd, enum nvme_get_features_sel sel, struct nvme_host_mem_buf_attrs *attrs)

   Initialize passthru command for Get Features - Host Memory Buffer

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``enum nvme_get_features_sel sel``
  Select which type of attribute to return,
  see :c:type:`enum nvme_get_features_sel <nvme_get_features_sel>`

``struct nvme_host_mem_buf_attrs *attrs``
  Buffer for returned Host Memory Buffer Attributes

**Description**

Initializes the passthru command buffer for the Get Features command with
FID value ``NVME_FEAT_FID_HOST_MEM_BUF``


.. c:function:: void nvme_init_get_features_timestamp (struct libnvme_passthru_cmd *cmd, enum nvme_get_features_sel sel, struct nvme_timestamp *ts)

   Initialize passthru command for Get Features - Timestamp

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``enum nvme_get_features_sel sel``
  Select which type of attribute to return,
  see :c:type:`enum nvme_get_features_sel <nvme_get_features_sel>`

``struct nvme_timestamp *ts``
  Current timestamp buffer

**Description**

Initializes the passthru command buffer for the Get Features command with
FID value ``NVME_FEAT_FID_TIMESTAMP``


.. c:function:: void nvme_init_get_features_kato (struct libnvme_passthru_cmd *cmd, enum nvme_get_features_sel sel)

   Initialize passthru command for Get Features - Keep Alive Timeout

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``enum nvme_get_features_sel sel``
  Select which type of attribute to return,
  see :c:type:`enum nvme_get_features_sel <nvme_get_features_sel>`

**Description**

Initializes the passthru command buffer for the Get Features command with
FID value ``NVME_FEAT_FID_KATO``


.. c:function:: void nvme_init_get_features_hctm (struct libnvme_passthru_cmd *cmd, enum nvme_get_features_sel sel)

   Initialize passthru command for Get Features - Host Controlled Thermal Management

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``enum nvme_get_features_sel sel``
  Select which type of attribute to return,
  see :c:type:`enum nvme_get_features_sel <nvme_get_features_sel>`

**Description**

Initializes the passthru command buffer for the Get Features command with
FID value ``NVME_FEAT_FID_HCTM``


.. c:function:: void nvme_init_get_features_nopsc (struct libnvme_passthru_cmd *cmd, enum nvme_get_features_sel sel)

   Initialize passthru command for Get Features - Non-Operational Power State Config

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``enum nvme_get_features_sel sel``
  Select which type of attribute to return,
  see :c:type:`enum nvme_get_features_sel <nvme_get_features_sel>`

**Description**

Initializes the passthru command buffer for the Get Features command with
FID value ``NVME_FEAT_FID_NOPSC``


.. c:function:: void nvme_init_get_features_rrl (struct libnvme_passthru_cmd *cmd, enum nvme_get_features_sel sel)

   Initialize passthru command for Get Features - Read Recovery Level

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``enum nvme_get_features_sel sel``
  Select which type of attribute to return,
  see :c:type:`enum nvme_get_features_sel <nvme_get_features_sel>`

**Description**

Initializes the passthru command buffer for the Get Features command with
FID value ``NVME_FEAT_FID_RRL``


.. c:function:: void nvme_init_get_features_plm_config (struct libnvme_passthru_cmd *cmd, enum nvme_get_features_sel sel, __u16 nvmsetid, struct nvme_plm_config *plmc)

   Initialize passthru command for Get Features - Predictable Latency Mode Config

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``enum nvme_get_features_sel sel``
  Select which type of attribute to return,
  see :c:type:`enum nvme_get_features_sel <nvme_get_features_sel>`

``__u16 nvmsetid``
  NVM set id

``struct nvme_plm_config *plmc``
  Buffer for returned Predictable Latency Mode Config

**Description**

Initializes the passthru command buffer for the Get Features command with
FID value ``NVME_FEAT_FID_PLM_CONFIG``


.. c:function:: void nvme_init_get_features_plm_window (struct libnvme_passthru_cmd *cmd, enum nvme_get_features_sel sel, __u16 nvmsetid)

   Initialize passthru command for Get Features - Predictable Latency Mode Window

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``enum nvme_get_features_sel sel``
  Select which type of attribute to return,
  see :c:type:`enum nvme_get_features_sel <nvme_get_features_sel>`

``__u16 nvmsetid``
  NVM set id

**Description**

Initializes the passthru command buffer for the Get Features command with
FID value ``NVME_FEAT_FID_PLM_WINDOW``


.. c:function:: void nvme_init_get_features_lba_sts_interval (struct libnvme_passthru_cmd *cmd, enum nvme_get_features_sel sel)

   Initialize passthru command for Get Features - LBA Status Information Interval

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``enum nvme_get_features_sel sel``
  Select which type of attribute to return,
  see :c:type:`enum nvme_get_features_sel <nvme_get_features_sel>`

**Description**

Initializes the passthru command buffer for the Get Features command with
FID value ``NVME_FEAT_FID_LBA_STS_INTERVAL``


.. c:function:: void nvme_init_get_features_host_behavior (struct libnvme_passthru_cmd *cmd, enum nvme_get_features_sel sel, struct nvme_feat_host_behavior *fhb)

   Initialize passthru command for Get Features - Host Behavior

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``enum nvme_get_features_sel sel``
  Select which type of attribute to return,
  see :c:type:`enum nvme_get_features_sel <nvme_get_features_sel>`

``struct nvme_feat_host_behavior *fhb``
  Pointer to structure nvme_feat_host_behavior

**Description**

Initializes the passthru command buffer for the Get Features command with
FID value ``NVME_FEAT_FID_HOST_BEHAVIOR``


.. c:function:: void nvme_init_get_features_sanitize (struct libnvme_passthru_cmd *cmd, enum nvme_get_features_sel sel)

   Initialize passthru command for Get Features - Sanitize

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``enum nvme_get_features_sel sel``
  Select which type of attribute to return,
  see :c:type:`enum nvme_get_features_sel <nvme_get_features_sel>`

**Description**

Initializes the passthru command buffer for the Get Features command with
FID value ``NVME_FEAT_FID_SANITIZE``


.. c:function:: void nvme_init_get_features_endurance_event_cfg (struct libnvme_passthru_cmd *cmd, enum nvme_get_features_sel sel, __u16 endgid)

   Initialize passthru command for Get Features - Endurance Group Event Configuration

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``enum nvme_get_features_sel sel``
  Select which type of attribute to return,
  see :c:type:`enum nvme_get_features_sel <nvme_get_features_sel>`

``__u16 endgid``
  Endurance Group Identifier

**Description**

Initializes the passthru command buffer for the Get Features command with
FID value ``NVME_FEAT_FID_ENDURANCE_EVT_CFG``


.. c:function:: void nvme_init_get_features_sw_progress (struct libnvme_passthru_cmd *cmd, enum nvme_get_features_sel sel)

   Initialize passthru command for Get Features - Software Progress

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``enum nvme_get_features_sel sel``
  Select which type of attribute to return,
  see :c:type:`enum nvme_get_features_sel <nvme_get_features_sel>`

**Description**

Initializes the passthru command buffer for the Get Features command with
FID value ``NVME_FEAT_FID_SW_PROGRESS``


.. c:function:: void nvme_init_get_features_host_id (struct libnvme_passthru_cmd *cmd, enum nvme_get_features_sel sel, bool exhid, void *hostid, __u32 len)

   Initialize passthru command for Get Features - Host Identifier

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``enum nvme_get_features_sel sel``
  Select which type of attribute to return,
  see :c:type:`enum nvme_get_features_sel <nvme_get_features_sel>`

``bool exhid``
  Enable Extended Host Identifier

``void *hostid``
  Buffer for returned host ID

``__u32 len``
  Length of **hostid**

**Description**

Initializes the passthru command buffer for the Get Features command with
FID value ``NVME_FEAT_FID_HOST_ID``


.. c:function:: void nvme_init_get_features_resv_nf_mask (struct libnvme_passthru_cmd *cmd, __u32 nsid, enum nvme_get_features_sel sel)

   Initialize passthru command for Get Features - Reservation Notification Mask

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``__u32 nsid``
  Namespace ID

``enum nvme_get_features_sel sel``
  Select which type of attribute to return,
  see :c:type:`enum nvme_get_features_sel <nvme_get_features_sel>`

**Description**

Initializes the passthru command buffer for the Get Features command with
FID value ``NVME_FEAT_FID_RESV_NF_MASK``


.. c:function:: void nvme_init_get_features_resv_persist (struct libnvme_passthru_cmd *cmd, __u32 nsid, enum nvme_get_features_sel sel)

   Initialize passthru command for Get Features - Reservation Persistence

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``__u32 nsid``
  Namespace ID

``enum nvme_get_features_sel sel``
  Select which type of attribute to return,
  see :c:type:`enum nvme_get_features_sel <nvme_get_features_sel>`

**Description**

Initializes the passthru command buffer for the Get Features command with
FID value ``NVME_FEAT_FID_RESV_PERSIST``


.. c:function:: void nvme_init_get_features_write_protect (struct libnvme_passthru_cmd *cmd, __u32 nsid, enum nvme_get_features_sel sel)

   Initialize passthru command for Get Features - Write Protect

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``__u32 nsid``
  Namespace ID

``enum nvme_get_features_sel sel``
  Select which type of attribute to return,
  see :c:type:`enum nvme_get_features_sel <nvme_get_features_sel>`

**Description**

Initializes the passthru command buffer for the Get Features command with
FID value ``NVME_FEAT_FID_WRITE_PROTECT``


.. c:function:: void nvme_init_get_features_iocs_profile (struct libnvme_passthru_cmd *cmd, enum nvme_get_features_sel sel)

   Initialize passthru command for Get Features - I/O Command Set Profile

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``enum nvme_get_features_sel sel``
  Select which type of attribute to return,
  see :c:type:`enum nvme_get_features_sel <nvme_get_features_sel>`

**Description**

Initializes the passthru command buffer for the Get Features command with
FID value ``NVME_FEAT_FID_IOCS_PROFILE``


.. c:function:: void nvme_init_lm_get_features_ctrl_data_queue (struct libnvme_passthru_cmd *cmd, enum nvme_get_features_sel sel, __u16 cdqid, struct nvme_lm_ctrl_data_queue_fid_data *qfd)

   Initialize passthru command for Get Controller Data Queue feature

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``enum nvme_get_features_sel sel``
  Select which type of attribute to return,
  see :c:type:`enum nvme_get_features_sel <nvme_get_features_sel>`

``__u16 cdqid``
  Controller Data Queue ID (CDQID)

``struct nvme_lm_ctrl_data_queue_fid_data *qfd``
  Get Controller Data Queue feature data buffer

**Description**

Initializes the passthru command buffer for the Get Features command with
FID value ``NVME_FEAT_FID_CTRL_DATA_QUEUE``.


.. c:function:: void nvme_init_get_features_rate_limiting (struct libnvme_passthru_cmd *cmd, enum nvme_get_features_sel sel, __u8 target, __u16 tid, struct nvme_rate_limiting_data *data)

   Initialize passthru command for Get Features - Rate Limiting

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``enum nvme_get_features_sel sel``
  Select which type of attribute to return,
  see :c:type:`enum nvme_get_features_sel <nvme_get_features_sel>`

``__u8 target``
  Target of the rate limits setting, see
  :c:type:`enum nvme_rate_limiting_target <nvme_rate_limiting_target>`

``__u16 tid``
  Target Identifier for the target specified by **target**

``struct nvme_rate_limiting_data *data``
  Buffer to receive the Rate Limiting data buffer, see
  :c:type:`struct nvme_rate_limiting_data <nvme_rate_limiting_data>`

**Description**

Initializes the passthru command buffer for the Get Features command with
FID value ``NVME_FEAT_FID_RATE_LIMITING``


.. c:function:: void nvme_init_get_features_spinup_control (struct libnvme_passthru_cmd *cmd, enum nvme_get_features_sel sel)

   Initialize passthru command for Get Features - Spinup Control

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``enum nvme_get_features_sel sel``
  Select which type of attribute to return,
  see :c:type:`enum nvme_get_features_sel <nvme_get_features_sel>`

**Description**

Initializes the passthru command buffer for the Get Features command with
FID value ``NVME_FEAT_FID_SPINUP_CONTROL``


.. c:function:: void nvme_init_get_features_power_loss_signal (struct libnvme_passthru_cmd *cmd, enum nvme_get_features_sel sel)

   Initialize passthru command for Get Features - Power Loss Signaling Config

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``enum nvme_get_features_sel sel``
  Select which type of attribute to return,
  see :c:type:`enum nvme_get_features_sel <nvme_get_features_sel>`

**Description**

Initializes the passthru command buffer for the Get Features command with
FID value ``NVME_FEAT_FID_POWER_LOSS_SIGNAL``


.. c:function:: void nvme_init_get_features_perf_characteristics (struct libnvme_passthru_cmd *cmd, enum nvme_get_features_sel sel, __u8 attri, struct nvme_perf_characteristics *data)

   Initialize passthru command for Get Features - Performance Characteristics

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``enum nvme_get_features_sel sel``
  Select which type of attribute to return,
  see :c:type:`enum nvme_get_features_sel <nvme_get_features_sel>`

``__u8 attri``
  Attribute Index (ATTRI)

``struct nvme_perf_characteristics *data``
  Buffer for returned struct nvme_perf_characteristics

**Description**

Initializes the passthru command buffer for the Get Features command with
FID value ``NVME_FEAT_FID_PERF_CHARACTERISTICS``


.. c:function:: void nvme_init_get_features_fdp (struct libnvme_passthru_cmd *cmd, enum nvme_get_features_sel sel, __u16 endgid)

   Initialize passthru command for Get Features - Flexible Data Placement

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``enum nvme_get_features_sel sel``
  Select which type of attribute to return,
  see :c:type:`enum nvme_get_features_sel <nvme_get_features_sel>`

``__u16 endgid``
  Endurance Group Identifier (ENDGID)

**Description**

Initializes the passthru command buffer for the Get Features command with
FID value ``NVME_FEAT_FID_FDP``


.. c:function:: void nvme_init_get_features_fdp_events (struct libnvme_passthru_cmd *cmd, enum nvme_get_features_sel sel, __u16 phndl, void *data, __u32 len)

   Initialize passthru command for Get Features - Flexible Data Placement Events

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``enum nvme_get_features_sel sel``
  Select which type of attribute to return,
  see :c:type:`enum nvme_get_features_sel <nvme_get_features_sel>`

``__u16 phndl``
  Placement Handle (PHNDL)

``void *data``
  Supported FDP Event Type List data buffer, see :c:type:`struct
  nvme_fdp_supported_event_desc <nvme_fdp_supported_event_desc>`

``__u32 len``
  Length of **data**

**Description**

Initializes the passthru command buffer for the Get Features command with
FID value ``NVME_FEAT_FID_FDP_EVENTS``


.. c:function:: void nvme_init_get_features_ns_admin_label (struct libnvme_passthru_cmd *cmd, enum nvme_get_features_sel sel, void *label)

   Initialize passthru command for Get Features - Namespace Admin Label

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``enum nvme_get_features_sel sel``
  Select which type of attribute to return,
  see :c:type:`enum nvme_get_features_sel <nvme_get_features_sel>`

``void *label``
  256 byte, null-terminated UTF-8 Namespace Admin Label (NSAL)
  data buffer

**Description**

Initializes the passthru command buffer for the Get Features command with
FID value ``NVME_FEAT_FID_NS_ADMIN_LABEL``


.. c:function:: void nvme_init_get_features_personality (struct libnvme_passthru_cmd *cmd, enum nvme_get_features_sel sel, __u8 perid, void *data, __u32 len)

   Initialize passthru command for Get Features - Configurable Device Personality

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``enum nvme_get_features_sel sel``
  Select which type of attribute to return,
  see :c:type:`enum nvme_get_features_sel <nvme_get_features_sel>`

``__u8 perid``
  Personality Identifier (PERID), see :c:type:`enum
  nvme_personality_identifier <nvme_personality_identifier>`

``void *data``
  Personality Identifier specific data buffer, or NULL if the
  personality does not use the data buffer

``__u32 len``
  Length of **data**

**Description**

Initializes the passthru command buffer for the Get Features command with
FID value ``NVME_FEAT_FID_CONF_DEV_PERSONALITY``


.. c:function:: void nvme_init_get_features_power_limit (struct libnvme_passthru_cmd *cmd, enum nvme_get_features_sel sel)

   Initialize passthru command for Get Features - Power Limit

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``enum nvme_get_features_sel sel``
  Select which type of attribute to return,
  see :c:type:`enum nvme_get_features_sel <nvme_get_features_sel>`

**Description**

Initializes the passthru command buffer for the Get Features command with
FID value ``NVME_FEAT_FID_POWER_LIMIT``


.. c:function:: void nvme_init_get_features_power_threshold (struct libnvme_passthru_cmd *cmd, enum nvme_get_features_sel sel)

   Initialize passthru command for Get Features - Power Threshold

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``enum nvme_get_features_sel sel``
  Select which type of attribute to return,
  see :c:type:`enum nvme_get_features_sel <nvme_get_features_sel>`

**Description**

Initializes the passthru command buffer for the Get Features command with
FID value ``NVME_FEAT_FID_POWER_THRESH``


.. c:function:: void nvme_init_get_features_power_measurement (struct libnvme_passthru_cmd *cmd, enum nvme_get_features_sel sel)

   Initialize passthru command for Get Features - Power Measurement

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``enum nvme_get_features_sel sel``
  Select which type of attribute to return,
  see :c:type:`enum nvme_get_features_sel <nvme_get_features_sel>`

**Description**

Initializes the passthru command buffer for the Get Features command with
FID value ``NVME_FEAT_FID_POWER_MEASUREMENT``


.. c:function:: void nvme_init_get_features_voltage_threshold (struct libnvme_passthru_cmd *cmd, enum nvme_get_features_sel sel, __u8 vsens)

   Initialize passthru command for Get Features - Voltage Threshold

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``enum nvme_get_features_sel sel``
  Select which type of attribute to return,
  see :c:type:`enum nvme_get_features_sel <nvme_get_features_sel>`

``__u8 vsens``
  Voltage Sensor Select (VSENS)

**Description**

Initializes the passthru command buffer for the Get Features command with
FID value ``NVME_FEAT_FID_VOLTAGE_THRESHOLD``


.. c:function:: void nvme_init_get_features_voltage_measurement (struct libnvme_passthru_cmd *cmd, enum nvme_get_features_sel sel, void *data, __u32 len)

   Initialize passthru command for Get Features - Voltage Measurement

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``enum nvme_get_features_sel sel``
  Select which type of attribute to return,
  see :c:type:`enum nvme_get_features_sel <nvme_get_features_sel>`

``void *data``
  Start Voltage Measurements data buffer, see :c:type:`struct
  nvme_voltage_measurement_start_data <nvme_voltage_measurement_start_data>`

``__u32 len``
  Length of **data**

**Description**

Initializes the passthru command buffer for the Get Features command with
FID value ``NVME_FEAT_FID_VOLTAGE_MEASUREMENT``


.. c:function:: void nvme_init_get_features_emb_mgmt_ctrl_addr (struct libnvme_passthru_cmd *cmd, enum nvme_get_features_sel sel, void *data)

   Initialize passthru command for Get Features - Embedded Management Controller Address

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``enum nvme_get_features_sel sel``
  Select which type of attribute to return,
  see :c:type:`enum nvme_get_features_sel <nvme_get_features_sel>`

``void *data``
  512 byte Embedded Management Controller Address (EMCA) data
  buffer, see :c:type:`struct nvme_mgmt_addr_desc <nvme_mgmt_addr_desc>`

**Description**

Initializes the passthru command buffer for the Get Features command with
FID value ``NVME_FEAT_FID_EMB_MGMT_CTRL_ADDR``


.. c:function:: void nvme_init_get_features_host_mgmt_agent_addr (struct libnvme_passthru_cmd *cmd, enum nvme_get_features_sel sel, void *data)

   Initialize passthru command for Get Features - Host Management Agent Address

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``enum nvme_get_features_sel sel``
  Select which type of attribute to return,
  see :c:type:`enum nvme_get_features_sel <nvme_get_features_sel>`

``void *data``
  512 byte Host Management Agent Address (HMAA) data buffer,
  see :c:type:`struct nvme_mgmt_addr_desc <nvme_mgmt_addr_desc>`

**Description**

Initializes the passthru command buffer for the Get Features command with
FID value ``NVME_FEAT_FID_HOST_MGMT_AGENT_ADDR``


.. c:function:: void nvme_init_get_features_enh_ctrl_metadata (struct libnvme_passthru_cmd *cmd, enum nvme_get_features_sel sel, struct nvme_host_metadata *data)

   Initialize passthru command for Get Features - Enhanced Controller Metadata

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``enum nvme_get_features_sel sel``
  Select which type of attribute to return,
  see :c:type:`enum nvme_get_features_sel <nvme_get_features_sel>`

``struct nvme_host_metadata *data``
  Host Metadata data buffer, see :c:type:`struct nvme_host_metadata <nvme_host_metadata>`

**Description**

Initializes the passthru command buffer for the Get Features command with
FID value ``NVME_FEAT_FID_ENH_CTRL_METADATA``


.. c:function:: void nvme_init_get_features_ctrl_metadata (struct libnvme_passthru_cmd *cmd, enum nvme_get_features_sel sel, struct nvme_host_metadata *data)

   Initialize passthru command for Get Features - Controller Metadata

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``enum nvme_get_features_sel sel``
  Select which type of attribute to return,
  see :c:type:`enum nvme_get_features_sel <nvme_get_features_sel>`

``struct nvme_host_metadata *data``
  Host Metadata data buffer, see :c:type:`struct nvme_host_metadata <nvme_host_metadata>`

**Description**

Initializes the passthru command buffer for the Get Features command with
FID value ``NVME_FEAT_FID_CTRL_METADATA``


.. c:function:: void nvme_init_get_features_ns_metadata (struct libnvme_passthru_cmd *cmd, enum nvme_get_features_sel sel, struct nvme_host_metadata *data)

   Initialize passthru command for Get Features - Namespace Metadata

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``enum nvme_get_features_sel sel``
  Select which type of attribute to return,
  see :c:type:`enum nvme_get_features_sel <nvme_get_features_sel>`

``struct nvme_host_metadata *data``
  Host Metadata data buffer, see :c:type:`struct nvme_host_metadata <nvme_host_metadata>`

**Description**

Initializes the passthru command buffer for the Get Features command with
FID value ``NVME_FEAT_FID_NS_METADATA``


.. c:function:: void nvme_init_get_features_bp_write_protect (struct libnvme_passthru_cmd *cmd, enum nvme_get_features_sel sel)

   Initialize passthru command for Get Features - Boot Partition Write Protection Config

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``enum nvme_get_features_sel sel``
  Select which type of attribute to return,
  see :c:type:`enum nvme_get_features_sel <nvme_get_features_sel>`

**Description**

Initializes the passthru command buffer for the Get Features command with
FID value ``NVME_FEAT_FID_BP_WRITE_PROTECT``


.. c:function:: void nvme_init_ns_mgmt (struct libnvme_passthru_cmd *cmd, __u32 nsid, enum nvme_ns_mgmt_sel sel, __u8 csi, struct nvme_ns_mgmt_host_sw_specified *data)

   Initialize passthru command for Namespace Management

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``__u32 nsid``
  Namespace identifier

``enum nvme_ns_mgmt_sel sel``
  Type of management operation to perform

``__u8 csi``
  Command Set Identifier

``struct nvme_ns_mgmt_host_sw_specified *data``
  Host Software Specified Fields buffer

**Description**

Initializes the passthru command buffer for the Namespace Management command.


.. c:function:: void nvme_init_ns_mgmt_create (struct libnvme_passthru_cmd *cmd, __u8 csi, struct nvme_ns_mgmt_host_sw_specified *data)

   Initialize passthru command to create a non attached namespace

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``__u8 csi``
  Command Set Identifier

``struct nvme_ns_mgmt_host_sw_specified *data``
  Host Software Specified Fields buffer that defines NS
  creation parameters

**Description**

Initializes the passthru command buffer for the Namespace Management - Create
command. The command uses NVME_NSID_NONE as the target NSID.


.. c:function:: void nvme_init_ns_mgmt_delete (struct libnvme_passthru_cmd *cmd, __u32 nsid)

   Initialize passthru command to delete a non attached namespace

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``__u32 nsid``
  Namespace identifier to delete

**Description**

Initializes the passthru command buffer for the Namespace Management - Delete
command (NVME_NS_MGMT_SEL_DELETE). The command uses the provided **nsid** as
the target NSID.


.. c:function:: void nvme_init_ns_mgmt_restore_default_config (struct libnvme_passthru_cmd *cmd)

   Initialize passthru command to restore the default NVM subsystem namespace configuration

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

**Description**

Initializes the passthru command buffer for the Namespace Management -
Restore Default Namespace Configuration operation
(NVME_NS_MGMT_SEL_RESTORE_DEFAULT_CONFIG). The NSID field is unused for
this operation and is cleared to 0h.


.. c:function:: void nvme_init_fw_commit (struct libnvme_passthru_cmd *cmd, __u8 fs, enum nvme_fw_commit_ca ca, bool bpid)

   Initialize passthru command to commit firmware using the specified action

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``__u8 fs``
  Firmware slot to commit the downloaded image

``enum nvme_fw_commit_ca ca``
  Action to use for the firmware image,
  see :c:type:`enum nvme_fw_commit_ca <nvme_fw_commit_ca>`

``bool bpid``
  Set to true to select the boot partition id

**Description**

Initializes the passthru command buffer for the Firmware Commit command.


.. c:function:: int nvme_init_fw_download (struct libnvme_passthru_cmd *cmd, void *data, __u32 len, __u32 offset)

   Initialize passthru command to download part or all of a firmware image to the controller

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``void *data``
  Userspace address of the firmware data buffer

``__u32 len``
  Length of data in this command in bytes

``__u32 offset``
  Offset in the firmware data

**Description**

Initializes the passthru command buffer for the Firmware Image
Download command.

**Note**

Caller must ensure data_len and offset are DWord-aligned (0x4).

**Return**

0 on success, negative error code otherwise.


.. c:function:: void nvme_init_dev_self_test (struct libnvme_passthru_cmd *cmd, __u32 nsid, enum nvme_dst_stc stc)

   Initialize passthru command to start or abort a self test

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``__u32 nsid``
  Namespace ID to test

``enum nvme_dst_stc stc``
  Self test code, see :c:type:`enum nvme_dst_stc <nvme_dst_stc>`

**Description**

Initializes the passthru command buffer for the Device Self-test command.


.. c:function:: void nvme_init_ns_attach (struct libnvme_passthru_cmd *cmd, __u32 nsid, enum nvme_ns_attach_sel sel, struct nvme_ctrl_list *ctrlist)

   Initialize passthru command for Namespace Attach/Detach

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``__u32 nsid``
  Namespace ID to execute attach selection

``enum nvme_ns_attach_sel sel``
  Attachment selection, see :c:type:`enum nvme_ns_attach_sel <nvme_ns_attach_sel>`

``struct nvme_ctrl_list *ctrlist``
  Controller list buffer to modify attachment state of nsid

**Description**

Initializes the passthru command buffer for the Namespace Attach/Detach
command.


.. c:function:: void nvme_init_ns_attach_ctrls (struct libnvme_passthru_cmd *cmd, __u32 nsid, struct nvme_ctrl_list *ctrlist)

   Initialize passthru command to attach namespace to controllers

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``__u32 nsid``
  Namespace ID to attach

``struct nvme_ctrl_list *ctrlist``
  Controller list buffer to modify attachment state of nsid

**Description**

Initializes the passthru command buffer for the Namespace Attach command
(NVME_NS_ATTACH_SEL_CTRL_ATTACH).


.. c:function:: void nvme_init_ns_detach_ctrls (struct libnvme_passthru_cmd *cmd, __u32 nsid, struct nvme_ctrl_list *ctrlist)

   Initialize passthru command to detach namespace from controllers

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``__u32 nsid``
  Namespace ID to detach

``struct nvme_ctrl_list *ctrlist``
  Controller list buffer to modify attachment state of nsid

**Description**

Initializes the passthru command buffer for the Namespace Detach command
(NVME_NS_ATTACH_SEL_CTRL_DEATTACH).


.. c:function:: void nvme_init_keep_alive (struct libnvme_passthru_cmd *cmd)

   Initialize passthru command for Keep Alive command

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

**Description**

Initializes the passthru command buffer for the Keep Alive command. All
command specific fields are reserved.


.. c:function:: void nvme_init_directive_send (struct libnvme_passthru_cmd *cmd, __u32 nsid, enum nvme_directive_send_doper doper, enum nvme_directive_dtype dtype, __u16 dspec, void *data, __u32 len)

   Initialize passthru command for Directive Send

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``__u32 nsid``
  Namespace ID, if applicable

``enum nvme_directive_send_doper doper``
  Directive send operation, see :c:type:`enum nvme_directive_send_doper <nvme_directive_send_doper>`

``enum nvme_directive_dtype dtype``
  Directive type, see :c:type:`enum nvme_directive_dtype <nvme_directive_dtype>`

``__u16 dspec``
  Directive specific field

``void *data``
  Data payload buffer to be send

``__u32 len``
  Length of data payload in bytes

**Description**

Initializes the passthru command buffer for the Directive Send command.


.. c:function:: void nvme_init_directive_send_id_endir (struct libnvme_passthru_cmd *cmd, __u32 nsid, bool endir, enum nvme_directive_dtype dtype, struct nvme_id_directives *id)

   Initialize passthru command for Directive Send Enable Directive

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``__u32 nsid``
  Namespace Identifier

``bool endir``
  Enable Directive

``enum nvme_directive_dtype dtype``
  Directive Type

``struct nvme_id_directives *id``
  Pointer to structure nvme_id_directives

**Description**

Initializes the passthru command buffer for the Directive Send - Identify
(Enable Directive) command.


.. c:function:: void nvme_init_directive_send_stream_release_identifier (struct libnvme_passthru_cmd *cmd, __u32 nsid, __u16 stream_id)

   Initialize passthru command for Directive Send Stream release identifier

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``__u32 nsid``
  Namespace ID

``__u16 stream_id``
  Stream identifier

**Description**

Initializes the passthru command buffer for the Directive Send - Stream
Release Identifier command.


.. c:function:: void nvme_init_directive_send_stream_release_resource (struct libnvme_passthru_cmd *cmd, __u32 nsid)

   Initialize passthru command for Directive Send Stream release resources

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``__u32 nsid``
  Namespace ID

**Description**

Initializes the passthru command buffer for the Directive Send - Stream
Release Resource command.


.. c:function:: void nvme_init_directive_recv (struct libnvme_passthru_cmd *cmd, __u32 nsid, enum nvme_directive_receive_doper doper, enum nvme_directive_dtype dtype, __u16 dspec, void *data, __u32 len)

   Initialize passthru command for Directive Receive

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``__u32 nsid``
  Namespace ID, if applicable

``enum nvme_directive_receive_doper doper``
  Directive receive operation,
  see :c:type:`enum nvme_directive_receive_doper <nvme_directive_receive_doper>`

``enum nvme_directive_dtype dtype``
  Directive type, see :c:type:`enum nvme_directive_dtype <nvme_directive_dtype>`

``__u16 dspec``
  Directive specific field

``void *data``
  Userspace address of data payload buffer

``__u32 len``
  Length of data payload in bytes

**Description**

Initializes the passthru command buffer for the Directive Receive command.


.. c:function:: void nvme_init_directive_recv_identify_parameters (struct libnvme_passthru_cmd *cmd, __u32 nsid, struct nvme_id_directives *id)

   Initialize passthru command for Directive Receive Identify Parameters

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``__u32 nsid``
  Namespace ID

``struct nvme_id_directives *id``
  Identify parameters buffer

**Description**

Initializes the passthru command buffer for the Directive Receive - Identify
Parameters command.


.. c:function:: void nvme_init_directive_recv_stream_parameters (struct libnvme_passthru_cmd *cmd, __u32 nsid, struct nvme_streams_directive_params *parms)

   Initialize passthru command for Directive Receive Stream Parameters

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``__u32 nsid``
  Namespace ID

``struct nvme_streams_directive_params *parms``
  Streams directive parameters buffer

**Description**

Initializes the passthru command buffer for the Directive Receive - Stream
Parameters command.


.. c:function:: void nvme_init_directive_recv_stream_allocate (struct libnvme_passthru_cmd *cmd, __u32 nsid, __u16 nsr)

   Initialize passthru command for Directive Receive Stream Allocate

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``__u32 nsid``
  Namespace ID

``__u16 nsr``
  Namespace Streams Requested

**Description**

Initializes the passthru command buffer for the Directive Receive - Stream
Allocate command.


.. c:function:: int nvme_init_directive_recv_stream_status (struct libnvme_passthru_cmd *cmd, __u32 nsid, unsigned int nr_entries, struct nvme_streams_directive_status *id)

   Initialize passthru command for Directive Receive Stream Status

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``__u32 nsid``
  Namespace ID

``unsigned int nr_entries``
  Number of streams to receive

``struct nvme_streams_directive_status *id``
  Stream status buffer

**Description**

Initializes the passthru command buffer for the Directive Receive - Stream
Status command.

**Return**

0 on success, negative error code otherwise.


.. c:function:: void nvme_init_virtual_mgmt (struct libnvme_passthru_cmd *cmd, enum nvme_virt_mgmt_act act, enum nvme_virt_mgmt_rt rt, __u16 cntlid, __u16 nr)

   Initialize passthru command for Virtualization Resource Management

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``enum nvme_virt_mgmt_act act``
  Virtual resource action, see :c:type:`enum nvme_virt_mgmt_act <nvme_virt_mgmt_act>`

``enum nvme_virt_mgmt_rt rt``
  Resource type to modify, see :c:type:`enum nvme_virt_mgmt_rt <nvme_virt_mgmt_rt>`

``__u16 cntlid``
  Controller id for which resources are bing modified

``__u16 nr``
  Number of resources being allocated or assigned

**Description**

Initializes the passthru command buffer for the Virtualization
Management command.


.. c:function:: void nvme_init_capacity_mgmt (struct libnvme_passthru_cmd *cmd, __u8 oper, __u16 elid, __u64 cap)

   Initialize passthru command for Capacity Management

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``__u8 oper``
  Operation to be performed by the controller

``__u16 elid``
  Value specific to the value of the Operation field

``__u64 cap``
  Capacity in bytes of the Endurance Group or NVM Set to
  be created

**Description**

Initializes the passthru command buffer for the Capacity Management command.


.. c:function:: void nvme_init_capacity_mgmt_restore_default_config (struct libnvme_passthru_cmd *cmd)

   Initialize passthru command to restore the default Endurance Groups and NVM Sets configuration

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

**Description**

Initializes the passthru command buffer for the Capacity Management -
Restore Default Capacity Management Configuration operation
(NVME_CAPACITY_MGMT_OPER_RESTORE_DEFAULT_CONFIG).


.. c:function:: void nvme_init_dim_send (struct libnvme_passthru_cmd *cmd, __u8 tas, void *data, __u32 len)

   Initialize passthru command for Discovery Information Management (DIM) Send

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``__u8 tas``
  Task field of the Command Dword 10 (cdw10)

``void *data``
  Pointer to the DIM data buffer

``__u32 len``
  Length of **data**

**Description**

Initializes the passthru command buffer for the Discovery Information
Management Send command.


.. c:function:: void nvme_init_clear_export_nvm_res (struct libnvme_passthru_cmd *cmd)

   Initialize passthru command for Clear Exported NVM Resource Configuration

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

**Description**

Initializes the passthru command buffer for the Clear Exported NVM
Resource Configuration command. All command specific fields are
reserved.


.. c:function:: void nvme_init_manage_export_nvms_receive (struct libnvme_passthru_cmd *cmd, __u8 sel, __u8 mos, __u16 mose, __u16 mosi, __u32 ol, __u32 ou, __u32 numdl, void *data, __u32 len)

   Initialize passthru command for Manage Exported NVM Subsystem Receive

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``__u8 sel``
  Select (SEL): management operation to perform, see :c:type:`enum
  nvme_manage_export_nvms_recv_sel <nvme_manage_export_nvms_recv_sel>`

``__u8 mos``
  Management Operation Specific (MOS): specific to **sel**

``__u16 mose``
  Management Operation Specific Extended (MOSE): specific to
  **sel**

``__u16 mosi``
  Management Operation Specific Identifier (MOSI): specific to
  **sel**

``__u32 ol``
  Offset Lower (OL), in dwords: specific to **sel**

``__u32 ou``
  Offset Upper (OU), in dwords: specific to **sel**

``__u32 numdl``
  Number of Dwords (NUMDL) requested, 0's based: specific to
  **sel**

``void *data``
  Pointer to data buffer

``__u32 len``
  Length of **data**

**Description**

Initializes the passthru command buffer for the Manage Exported NVM
Subsystem Receive command.


.. c:function:: void nvme_init_manage_export_nvms_receive_create (struct libnvme_passthru_cmd *cmd, bool tr, __u8 ensti, bool ra, struct nvme_exported_nvm_subsys_create_data *data)

   Initialize passthru command for Manage Exported NVM Subsystem Receive - Create Exported NVM Subsystem

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``bool tr``
  Template Required (TR)

``__u8 ensti``
  Exported NVM Subsystem Template Index (ENSTI), used if **tr** is
  set. Indexes the Exported NVM Subsystem Template UUID List,
  see ``NVME_IDENTIFY_CNS_EXPORTED_NVM_SUBSYS_TEMPLATE_UUID_LIST``.

``bool ra``
  Restricted Access (RA): message-based transports only,
  ignored by memory-based transports

``struct nvme_exported_nvm_subsys_create_data *data``
  Create Exported NVM Subsystem data buffer, see :c:type:`struct
  nvme_exported_nvm_subsys_create_data <nvme_exported_nvm_subsys_create_data>`. The assigned Exported
  NVM Subsystem NQN is returned in this same buffer.

**Description**

Initializes the passthru command buffer for the Manage Exported NVM
Subsystem Receive command with SEL value
``NVME_MANAGE_EXPORT_NVMS_RECV_SEL_CREATE``. The created Exported NVM
Subsystem Identifier is returned in the CQE result, see :c:type:`enum
nvme_export_nvms_create_cqe_dw0 <nvme_export_nvms_create_cqe_dw0>`.


.. c:function:: void nvme_init_manage_export_nvms_receive_list_subsystems (struct libnvme_passthru_cmd *cmd, __u16 esubid, struct nvme_exported_nvm_subsys_list *list, __u32 len)

   Initialize passthru command for Manage Exported NVM Subsystem Receive - List Exported NVM Subsystems

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``__u16 esubid``
  Return Exported NVM Subsystems with an Exported NVM
  Subsystem Identifier greater than or equal to this value

``struct nvme_exported_nvm_subsys_list *list``
  User address to store the Exported NVM Subsystems List data
  structure, see :c:type:`struct nvme_exported_nvm_subsys_list <nvme_exported_nvm_subsys_list>`

``__u32 len``
  The allocated length of **list**

**Description**

Initializes the passthru command buffer for the Manage Exported NVM
Subsystem Receive command with SEL value
``NVME_MANAGE_EXPORT_NVMS_RECV_SEL_LIST_SUBSYSTEMS``.


.. c:function:: void nvme_init_manage_export_nvms_receive_list_namespaces (struct libnvme_passthru_cmd *cmd, __u32 nsid, struct nvme_exported_ns_list *list, __u32 len)

   Initialize passthru command for Manage Exported NVM Subsystem Receive - List Exported Namespaces

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``__u32 nsid``
  Return Exported Namespaces associated with this Exported NVM
  Subsystem, with an Exported Namespace Identifier greater
  than this value

``struct nvme_exported_ns_list *list``
  User address to store the Exported Namespace List data
  structure, see :c:type:`struct nvme_exported_ns_list <nvme_exported_ns_list>`

``__u32 len``
  The allocated length of **list**

**Description**

Initializes the passthru command buffer for the Manage Exported NVM
Subsystem Receive command with SEL value
``NVME_MANAGE_EXPORT_NVMS_RECV_SEL_LIST_NAMESPACES``.


.. c:function:: void nvme_init_manage_export_nvms_receive_list_controllers (struct libnvme_passthru_cmd *cmd, __u16 ecntlid, struct nvme_exported_ctrl_list *list, __u32 len)

   Initialize passthru command for Manage Exported NVM Subsystem Receive - List Exported Controllers (message-based transports only)

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``__u16 ecntlid``
  Return Exported Controllers with an Exported Controller
  Identifier greater than or equal to this value

``struct nvme_exported_ctrl_list *list``
  User address to store the Exported Controller List data
  structure, see :c:type:`struct nvme_exported_ctrl_list <nvme_exported_ctrl_list>`

``__u32 len``
  The allocated length of **list**

**Description**

Initializes the passthru command buffer for the Manage Exported NVM
Subsystem Receive command with SEL value
``NVME_MANAGE_EXPORT_NVMS_RECV_SEL_LIST_CONTROLLERS``.


.. c:function:: void nvme_init_manage_export_nvms_receive_list_ports (struct libnvme_passthru_cmd *cmd, __u16 epid, struct nvme_exported_port_list *list, __u32 len)

   Initialize passthru command for Manage Exported NVM Subsystem Receive - List Exported Ports (memory-based transports only)

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``__u16 epid``
  Return Exported Ports with an Exported Port Identifier
  greater than or equal to this value

``struct nvme_exported_port_list *list``
  User address to store the Exported Ports List data
  structure, see :c:type:`struct nvme_exported_port_list <nvme_exported_port_list>`

``__u32 len``
  The allocated length of **list**

**Description**

Initializes the passthru command buffer for the Manage Exported NVM
Subsystem Receive command with SEL value
``NVME_MANAGE_EXPORT_NVMS_RECV_SEL_LIST_PORTS``.


.. c:function:: void nvme_init_manage_export_ns (struct libnvme_passthru_cmd *cmd, __u8 sel, __u8 mos, bool esubidv, __u16 esubid, void *data, __u32 len)

   Initialize passthru command for Manage Exported Namespace

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``__u8 sel``
  Select (SEL): management operation to perform, see :c:type:`enum
  nvme_manage_export_ns_sel <nvme_manage_export_ns_sel>`

``__u8 mos``
  Management Operation Specific (MOS): specific to **sel**

``bool esubidv``
  Exported NVM Subsystem Identifier Valid (ESUBIDV): if set,
  **esubid** identifies the target Exported NVM Subsystem;
  otherwise the target is identified by the SUBNQN in **data**

``__u16 esubid``
  Exported NVM Subsystem Identifier (ESUBID), used if
  **esubidv** is set

``void *data``
  Pointer to data buffer

``__u32 len``
  Length of **data**

**Description**

Initializes the passthru command buffer for the Manage Exported
Namespace command.


.. c:function:: void nvme_init_manage_export_ns_associate (struct libnvme_passthru_cmd *cmd, __u8 andsf, bool esubidv, __u16 esubid, struct nvme_associate_ns_data *data)

   Initialize passthru command for Manage Exported Namespace - Associate Namespace

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``__u8 andsf``
  Associate Namespace Data Structure Format (ANDSF): the bit
  number in the Exported Namespace Data Structure Formats
  Supported (ENDSFS) field (Identify Controller data structure)
  that defines the format of **data**. Bit 1 selects the format
  defined by :c:type:`struct nvme_associate_ns_data <nvme_associate_ns_data>`.

``bool esubidv``
  Exported NVM Subsystem Identifier Valid (ESUBIDV): if set,
  **esubid** identifies the target Exported NVM Subsystem;
  otherwise the target is identified by the ENSNQN field in
  **data**

``__u16 esubid``
  Exported NVM Subsystem Identifier (ESUBID), used if
  **esubidv** is set

``struct nvme_associate_ns_data *data``
  Associate Namespace data buffer, see :c:type:`struct
  nvme_associate_ns_data <nvme_associate_ns_data>`

**Description**

Initializes the passthru command buffer for the Manage Exported
Namespace command with SEL value ``NVME_MANAGE_EXPORT_NS_SEL_ASSOCIATE``.


.. c:function:: void nvme_init_manage_export_ns_disassociate (struct libnvme_passthru_cmd *cmd, bool esubidv, __u16 esubid, struct nvme_disassociate_ns_data *data)

   Initialize passthru command for Manage Exported Namespace - Disassociate Namespace

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``bool esubidv``
  Exported NVM Subsystem Identifier Valid (ESUBIDV): if set,
  **esubid** identifies the target Exported NVM Subsystem;
  otherwise the target is identified by the ENSNQN field in
  **data**

``__u16 esubid``
  Exported NVM Subsystem Identifier (ESUBID), used if
  **esubidv** is set

``struct nvme_disassociate_ns_data *data``
  Disassociate Namespace data buffer, see :c:type:`struct
  nvme_disassociate_ns_data <nvme_disassociate_ns_data>`

**Description**

Initializes the passthru command buffer for the Manage Exported
Namespace command with SEL value
``NVME_MANAGE_EXPORT_NS_SEL_DISASSOCIATE``.


.. c:function:: void nvme_init_manage_export_nvms_send (struct libnvme_passthru_cmd *cmd, __u8 sel, __u8 mos, __u16 mose, bool esubidv, __u16 esubid, void *data, __u32 len)

   Initialize passthru command for Manage Exported NVM Subsystem Send

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``__u8 sel``
  Select (SEL): management operation to perform, see :c:type:`enum
  nvme_manage_export_nvms_send_sel <nvme_manage_export_nvms_send_sel>`

``__u8 mos``
  Management Operation Specific (MOS): specific to **sel**

``__u16 mose``
  Management Operation Specific Extended (MOSE): specific to
  **sel**

``bool esubidv``
  Exported NVM Subsystem Identifier Valid (ESUBIDV): if set,
  **esubid** identifies the target Exported NVM Subsystem;
  otherwise the target is identified by the SUBNQN in **data**

``__u16 esubid``
  Exported NVM Subsystem Identifier (ESUBID), used if
  **esubidv** is set

``void *data``
  Pointer to data buffer

``__u32 len``
  Length of **data**

**Description**

Initializes the passthru command buffer for the Manage Exported NVM
Subsystem Send command.


.. c:function:: void nvme_init_manage_export_nvms_send_delete (struct libnvme_passthru_cmd *cmd, bool esubidv, __u16 esubid, struct nvme_exported_nvm_subsys_nqn_data *data)

   Initialize passthru command for Manage Exported NVM Subsystem Send - Delete

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``bool esubidv``
  Exported NVM Subsystem Identifier Valid (ESUBIDV): if set,
  **esubid** identifies the Exported NVM Subsystem to delete;
  otherwise it is identified by the SUBNQN in **data**

``__u16 esubid``
  Exported NVM Subsystem Identifier (ESUBID), used if
  **esubidv** is set

``struct nvme_exported_nvm_subsys_nqn_data *data``
  Exported NVM Subsystem NQN data buffer, see :c:type:`struct
  nvme_exported_nvm_subsys_nqn_data <nvme_exported_nvm_subsys_nqn_data>`. Ignored if **esubidv** is set.

**Description**

Initializes the passthru command buffer for the Manage Exported NVM
Subsystem Send command with SEL value
``NVME_MANAGE_EXPORT_NVMS_SEND_SEL_DELETE``.


.. c:function:: void nvme_init_manage_export_nvms_send_change_access_mode (struct libnvme_passthru_cmd *cmd, bool ra, bool esubidv, __u16 esubid, struct nvme_exported_nvm_subsys_nqn_data *data)

   Initialize passthru command for Manage Exported NVM Subsystem Send - Change Access Mode (message-based transports only)

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``bool ra``
  Restricted Access (RA): if set, the Exported NVM Subsystem is
  configured to restrict access to Host NQNs in its Allowed
  Host List; if clear, unrestricted access is allowed

``bool esubidv``
  Exported NVM Subsystem Identifier Valid (ESUBIDV): if set,
  **esubid** identifies the target Exported NVM Subsystem;
  otherwise the target is identified by the SUBNQN in **data**

``__u16 esubid``
  Exported NVM Subsystem Identifier (ESUBID), used if
  **esubidv** is set

``struct nvme_exported_nvm_subsys_nqn_data *data``
  Exported NVM Subsystem NQN data buffer, see :c:type:`struct
  nvme_exported_nvm_subsys_nqn_data <nvme_exported_nvm_subsys_nqn_data>`. Ignored if **esubidv** is set.

**Description**

Initializes the passthru command buffer for the Manage Exported NVM
Subsystem Send command with SEL value
``NVME_MANAGE_EXPORT_NVMS_SEND_SEL_CHANGE_ACCESS_MODE``.


.. c:function:: void nvme_init_manage_export_nvms_send_grant_host_access (struct libnvme_passthru_cmd *cmd, struct nvme_exported_subsys_mgmt_data *data, __u32 len)

   Initialize passthru command for Manage Exported NVM Subsystem Send - Grant Host Access (message-based transports only)

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``struct nvme_exported_subsys_mgmt_data *data``
  Subsystem Management data buffer, see :c:type:`struct
  nvme_exported_subsys_mgmt_data <nvme_exported_subsys_mgmt_data>`

``__u32 len``
  Length of **data**

**Description**

Initializes the passthru command buffer for the Manage Exported NVM
Subsystem Send command with SEL value
``NVME_MANAGE_EXPORT_NVMS_SEND_SEL_GRANT_HOST_ACCESS``. Command Dword 14
(ESUBIDV/ESUBID) is not used by this operation - the target Exported NVM
Subsystem(s) are specified in **data**.


.. c:function:: void nvme_init_manage_export_nvms_send_revoke_host_access (struct libnvme_passthru_cmd *cmd, struct nvme_exported_subsys_mgmt_data *data, __u32 len)

   Initialize passthru command for Manage Exported NVM Subsystem Send - Revoke Host Access (message-based transports only)

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``struct nvme_exported_subsys_mgmt_data *data``
  Subsystem Management data buffer, see :c:type:`struct
  nvme_exported_subsys_mgmt_data <nvme_exported_subsys_mgmt_data>`

``__u32 len``
  Length of **data**

**Description**

Initializes the passthru command buffer for the Manage Exported NVM
Subsystem Send command with SEL value
``NVME_MANAGE_EXPORT_NVMS_SEND_SEL_REVOKE_HOST_ACCESS``. Command Dword 14
(ESUBIDV/ESUBID) is not used by this operation - the target Exported NVM
Subsystem(s) are specified in **data**.


.. c:function:: void nvme_init_manage_export_nvms_send_associate_controllers (struct libnvme_passthru_cmd *cmd, __u16 esubid, struct nvme_exported_ctrl_assoc_data *data, __u32 len)

   Initialize passthru command for Manage Exported NVM Subsystem Send - Associate Controllers (memory-based transports only)

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``__u16 esubid``
  Exported NVM Subsystem Identifier (ESUBID) of the target
  Exported NVM Subsystem

``struct nvme_exported_ctrl_assoc_data *data``
  Associate Controllers data buffer, see :c:type:`struct
  nvme_exported_ctrl_assoc_data <nvme_exported_ctrl_assoc_data>`

``__u32 len``
  Length of **data**

**Description**

Initializes the passthru command buffer for the Manage Exported NVM
Subsystem Send command with SEL value
``NVME_MANAGE_EXPORT_NVMS_SEND_SEL_ASSOCIATE_CONTROLLERS``.


.. c:function:: void nvme_init_manage_export_nvms_send_set_config_state (struct libnvme_passthru_cmd *cmd, bool esubidv, __u16 esubid, void *data, __u32 len)

   Initialize passthru command for Manage Exported NVM Subsystem Send - Set Exported Configuration State

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``bool esubidv``
  Exported NVM Subsystem Identifier Valid (ESUBIDV): if set,
  **esubid** identifies the target Exported NVM Subsystem;
  otherwise the target is identified by the SUBNQN in **data**

``__u16 esubid``
  Exported NVM Subsystem Identifier (ESUBID), used if
  **esubidv** is set

``void *data``
  Exported NVM Subsystem Template specific configuration state
  data buffer

``__u32 len``
  Length of **data**

**Description**

Initializes the passthru command buffer for the Manage Exported NVM
Subsystem Send command with SEL value
``NVME_MANAGE_EXPORT_NVMS_SEND_SEL_SET_CONFIG_STATE``. On failure with
status ``NVME_SC_INVALID_EXPORTED_CONFIG_STATE``, the location of the first
invalid bit is returned in the CQE result, see :c:type:`enum
nvme_export_nvms_set_config_state_cqe_dw0 <nvme_export_nvms_set_config_state_cqe_dw0>`.


.. c:function:: void nvme_init_lockdown (struct libnvme_passthru_cmd *cmd, __u8 scp, __u8 prhbt, __u8 ifc, __u8 ofi, __u8 uidx, __u8 csel, __u16 css)

   Initialize passthru command for Lockdown

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``__u8 scp``
  Scope of the command

``__u8 prhbt``
  Prohibit or allow the command opcode or Set Features command

``__u8 ifc``
  Affected interface

``__u8 ofi``
  Opcode or Feature Identifier

``__u8 uidx``
  UUID Index if controller supports this id selection method

``__u8 csel``
  Controller Select (CSEL): specifies the controller(s)
  affected by this command, see :c:type:`enum nvme_lockdown_csel <nvme_lockdown_csel>`

``__u16 css``
  Controller Select Specific (CSS): meaning is specific to
  **csel** (a Controller Identifier, a Primary Controller
  Identifier, or vendor specific). Ignored if **csel** is
  ``NVME_LOCKDOWN_CSEL_NVM_SUBSYSTEM``.

**Description**

Initializes the passthru command buffer for the Lockdown command.


.. c:function:: void nvme_init_lm_track_send (struct libnvme_passthru_cmd *cmd, __u8 sel, __u16 mos, __u16 cdqid, void *data, __u32 len)

   Initialize passthru command for Track Send command

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``__u8 sel``
  Select (SEL): This field specifies the type of
  management operation to perform

``__u16 mos``
  Management Operation Specific (MOS): This field
  is specific to the SEL type. For the Track Memory Changes
  operation, see :c:type:`enum nvme_lm_tact <nvme_lm_tact>` for the Tracking Action
  (TACT) bit.

``__u16 cdqid``
  Controller Data Queue ID (CDQID) for the Log User Data Changes
  operation, or Controller Identifier (CNTLID) for the Track
  Memory Changes operation

``void *data``
  Track Memory Changes data buffer, see :c:type:`struct
  nvme_lm_track_memory_changes_data <nvme_lm_track_memory_changes_data>`. Only used for the Track
  Memory Changes operation with TACT set to
  ``NVME_LM_TACT_START_TRACKING``, otherwise NULL.

``__u32 len``
  Length of **data**

**Description**

Initializes the passthru command buffer for the Track Send command.


.. c:function:: void nvme_init_lm_track_receive (struct libnvme_passthru_cmd *cmd, __u8 sel, __u16 cntlid, void *data, __u32 len)

   Initialize passthru command for Track Receive command

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``__u8 sel``
  Select (SEL): This field specifies the type of management
  operation to perform.

``__u16 cntlid``
  Controller Identifier (CNTLID): Specifies the identifier of
  the controller for which the tracked memory changes, if any,
  are to be returned. Used by the Tracked Memory Changes
  management operation.

``void *data``
  Pointer to data buffer

``__u32 len``
  Length of **data**

**Description**

Initializes the passthru command buffer for the Track Receive command.


.. c:function:: void nvme_init_lm_migration_send (struct libnvme_passthru_cmd *cmd, __u16 sel, __u16 mos, __u16 cntlid, __u8 stype, bool dudmq, __u8 csvi, __u16 csuuidi, __u64 cso, __u8 uidx, void *data, __u32 len)

   Initialize passthru command for Migration Send command

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``__u16 sel``
  Select (SEL): This field specifies the type of management
  operation to perform.

``__u16 mos``
  Management Operation Specific (MOS): This field is specific
  to the SEL type

``__u16 cntlid``
  Controller ID: This field specifies the identifier of the
  controller to which the operation is performed.

``__u8 stype``
  Suspend Type (STYPE): This field specifies the type of suspend.

``bool dudmq``
  Delete User Data Migration Queue (DUDMQ): If set, the migration
  queue is deleted is deleted as part of the Suspend operation.

``__u8 csvi``
  Controller State Version Index (CSVI)

``__u16 csuuidi``
  Controller State UUID Index (CSUUIDI)

``__u64 cso``
  Offset: This field specifies the offset, in bytes, within
  the data available to be returned and specifies the starting
  point for that data for what is actually returned to the host.

``__u8 uidx``
  UUID Index (UIDX)

``void *data``
  Pointer to data buffer

``__u32 len``
  Length of **data**

**Description**

Initializes the passthru command buffer for the Migration Send command.


.. c:function:: void nvme_init_lm_migration_recv (struct libnvme_passthru_cmd *cmd, __u64 offset, __u16 mos, __u16 cntlid, __u16 csuuidi, __u8 sel, __u8 uidx, __u8 csuidxp, void *data, __u32 len)

   Initialize passthru command for Migration Receive command

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``__u64 offset``
  Offset: This field specifies the offset, in bytes, within
  the data available to be returned and specifies the starting
  point for that data for what is actually returned to the host.

``__u16 mos``
  Management Operation Specific (MOS): This field is specific to
  the SEL type

``__u16 cntlid``
  Controller ID: This field specifies the identifier of the
  controller to which the operation is performed.

``__u16 csuuidi``
  Controller State UUID Index (CSUUIDI)

``__u8 sel``
  Select (SEL): This field specifies the type of management
  operation to perform

``__u8 uidx``
  UUID Index (UIDX)

``__u8 csuidxp``
  Controller State UUID Index Parameter (CSUIDXP)

``void *data``
  Pointer to data buffer

``__u32 len``
  Length of **data**

**Description**

Initializes the passthru command buffer for the Migration Receive command.


.. c:function:: void nvme_init_lm_cdq_create (struct libnvme_passthru_cmd *cmd, __u16 mos, __u16 cntlid, __u32 cdqsize, void *data)

   Initialize passthru command for Controller Data Queue create - Controller Data Queue command

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``__u16 mos``
  Management Operation Specific (MOS): This field is
  specific to the SEL type

``__u16 cntlid``
  Controller ID: For Create CDQ, specifies the target
  migratable controller

``__u32 cdqsize``
  For Create CDQ, specifies the size of CDQ, in dwords - 4 byte

``void *data``
  Pointer to data buffer

**Description**

Initializes the passthru command buffer for the Controller Data Queue
command. Note: The result CDQID is returned in the CQE dword0, which the
submission function must handle.


.. c:function:: void nvme_init_lm_cdq_delete (struct libnvme_passthru_cmd *cmd, __u16 mos, __u16 cdqid)

   Initialize passthru command for Controller Data Queue delete - Controller Data Queue command

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``__u16 mos``
  Management Operation Specific (MOS): This field is
  specific to the SEL type

``__u16 cdqid``
  Controller Data Queue ID (CDQID): For Delete CDQ, this
  field is the CDQID to delete.

**Description**

Initializes the passthru command buffer for the Controller Data Queue delete
command.


.. c:function:: void nvme_init_format_nvm (struct libnvme_passthru_cmd *cmd, __u32 nsid, __u8 lbaf, enum nvme_cmd_format_mset mset, enum nvme_cmd_format_pi pi, enum nvme_cmd_format_pil pil, enum nvme_cmd_format_ses ses)

   Initialize passthru command for Format NVM

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``__u32 nsid``
  Namespace ID to format

``__u8 lbaf``
  Logical block address format

``enum nvme_cmd_format_mset mset``
  Metadata settings (extended or separated)

``enum nvme_cmd_format_pi pi``
  Protection information type

``enum nvme_cmd_format_pil pil``
  Protection information location (beginning or end)

``enum nvme_cmd_format_ses ses``
  Secure erase settings

**Description**

Initializes the passthru command buffer for the Format NVM command.


.. c:function:: void nvme_init_security_send (struct libnvme_passthru_cmd *cmd, __u32 nsid, __u8 nssf, __u16 spsp, __u8 secp, __u32 tl, void *data, __u32 len)

   Initialize passthru command for Security Send

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``__u32 nsid``
  Namespace ID to issue security command on

``__u8 nssf``
  NVMe Security Specific field

``__u16 spsp``
  Security Protocol Specific field

``__u8 secp``
  Security Protocol

``__u32 tl``
  Protocol specific transfer length

``void *data``
  Security data payload buffer to send

``__u32 len``
  Data length of the payload in bytes

**Description**

Initializes the passthru command buffer for the Security Send command.


.. c:function:: void nvme_init_security_receive (struct libnvme_passthru_cmd *cmd, __u32 nsid, __u8 nssf, __u16 spsp, __u8 secp, __u32 al, void *data, __u32 len)

   Initialize passthru command for Security Receive

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``__u32 nsid``
  Namespace ID to issue security command on

``__u8 nssf``
  NVMe Security Specific field

``__u16 spsp``
  Security Protocol Specific field

``__u8 secp``
  Security Protocol

``__u32 al``
  Protocol specific allocation length

``void *data``
  Security data payload buffer to receive data into

``__u32 len``
  Data length of the payload in bytes (must match **al**)

**Description**

Initializes the passthru command buffer for the Security Receive command.


.. c:function:: void nvme_init_sanitize_nvm (struct libnvme_passthru_cmd *cmd, enum nvme_sanitize_sanact sanact, bool ause, __u8 owpass, bool oipbp, bool ndas, bool emvs, bool preq, __u32 ovrpat)

   Initialize passthru command to start a sanitize operation

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``enum nvme_sanitize_sanact sanact``
  Sanitize action, see :c:type:`enum nvme_sanitize_sanact <nvme_sanitize_sanact>`

``bool ause``
  Set to allow unrestricted sanitize exit

``__u8 owpass``
  Overwrite pass count

``bool oipbp``
  Set to overwrite invert pattern between passes

``bool ndas``
  Set to not deallocate blocks after sanitizing

``bool emvs``
  Set to enter media verification state

``bool preq``
  Set to require the sanitize operation to purge user data, as
  defined by IEEE Std 2883, or fail

``__u32 ovrpat``
  Overwrite pattern

**Description**

Initializes the passthru command buffer for the Sanitize NVM command.


.. c:function:: void nvme_init_get_lba_status (struct libnvme_passthru_cmd *cmd, __u32 nsid, __u64 slba, __u32 mndw, enum nvme_lba_status_atype atype, __u16 rl, struct nvme_lba_status *lbas)

   Initialize passthru command to retrieve information on possibly unrecoverable LBAs

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``__u32 nsid``
  Namespace ID to retrieve LBA status

``__u64 slba``
  Starting logical block address to check statuses

``__u32 mndw``
  Maximum number of dwords to return

``enum nvme_lba_status_atype atype``
  Action type mechanism to determine LBA status descriptors to
  return, see :c:type:`enum nvme_lba_status_atype <nvme_lba_status_atype>`

``__u16 rl``
  Range length from slba to perform the action

``struct nvme_lba_status *lbas``
  Data payload buffer to return status descriptors

**Description**

Initializes the passthru command buffer for the Get LBA Status command.


.. c:function:: void nvme_init_sanitize_ns (struct libnvme_passthru_cmd *cmd, enum nvme_sanitize_sanact sanact, bool ause, bool emvs, bool preq)

   Initialize passthru command to start a sanitize namespace operation

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``enum nvme_sanitize_sanact sanact``
  Sanitize action, see :c:type:`enum nvme_sanitize_sanact <nvme_sanitize_sanact>`

``bool ause``
  Set to allow unrestricted sanitize exit

``bool emvs``
  Set to enter media verification state

``bool preq``
  Set to require the sanitize operation to purge user data, as
  defined by IEEE Std 2883, or fail

**Description**

Initializes the passthru command buffer for the Sanitize namespace command.


.. c:function:: void nvme_init_ctrl_list (struct nvme_ctrl_list *cntlist, __u16 num_ctrls, __u16 *ctrlist)

   Initialize an nvme_ctrl_list structure from an array.

**Parameters**

``struct nvme_ctrl_list *cntlist``
  The controller list structure to initialize

``__u16 num_ctrls``
  The number of controllers in the array, :c:type:`ctrlist`.

``__u16 *ctrlist``
  An array of controller identifiers in CPU native endian.

**Description**

This is intended to be used with any command that takes a controller list
argument. See nvme_ns_attach_ctrls() and nvme_ns_detach().


