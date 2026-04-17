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

**Return**

0 on success, the nvme command status if a response was
received (see :c:type:`enum nvme_status_field <nvme_status_field>`) or a negative error otherwise.


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

**Return**

0 on success, the nvme command status if a response was
received (see :c:type:`enum nvme_status_field <nvme_status_field>`) or a negative error otherwise.


.. c:function:: void nvme_init_zns_identify_ns (struct libnvme_passthru_cmd *cmd, __u32 nsid, struct nvme_zns_id_ns *data)

   Initialize passthru command for ZNS identify namespace data

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Command data structure to initialize

``__u32 nsid``
  Namespace to identify

``struct nvme_zns_id_ns *data``
  User space destination address to transfer the data


.. c:function:: void nvme_init_zns_identify_ctrl (struct libnvme_passthru_cmd *cmd, struct nvme_zns_id_ctrl *id)

   Initialize passthru command for ZNS identify controller data

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Command data structure to initialize

``struct nvme_zns_id_ctrl *id``
  User space destination address to transfer the data


.. c:function:: void nvme_init_get_log_lpo (struct libnvme_passthru_cmd *cmd, __u64 lpo)

   Initializes passthru command with a Log Page Offset

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
LID value ``NVME_LOG_LID_CHANGED_NS``.


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


.. c:function:: void nvme_init_get_log_mi_cmd_supported_effects (struct libnvme_passthru_cmd *cmd, struct nvme_mi_cmd_supported_effects_log *log)

   Initialize passthru command for MI Commands Supported by the controller

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``struct nvme_mi_cmd_supported_effects_log *log``
  MI Command Supported and Effects data structure

**Description**

Initializes the passthru command buffer for the Get Log command with
LID value ``NVME_LOG_LID_MI_CMD_SUPPORTED_EFFECTS``


.. c:function:: void nvme_init_get_log_lockdown (struct libnvme_passthru_cmd *cmd, __u8 cnscp, struct nvme_lockdown_log *lockdown_log)

   Initialize passthru command for Command and Feature Lockdown

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``__u8 cnscp``
  Contents and Scope of Command and Feature Identifier
  Lists

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


.. c:function:: void nvme_init_get_log_discovery (struct libnvme_passthru_cmd *cmd, __u64 lpo, void *log, __u32 len)

   Initialize passthru command for Discovery

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``__u64 lpo``
  Offset of this log to retrieve

``void *log``
  User address to store the discovery log

``__u32 len``
  The allocated size for this portion of the log

**Description**

Initializes the passthru command buffer for the Get Log command with
LID value ``NVME_LOG_LID_DISCOVERY``


.. c:function:: void nvme_init_get_log_host_discovery (struct libnvme_passthru_cmd *cmd, bool allhoste, struct nvme_host_discover_log *log, __u32 len)

   Initialize passthru command for Host Discover

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``bool allhoste``
  All host entries

``struct nvme_host_discover_log *log``
  User address to store the log page

``__u32 len``
  The allocated length of the log page

**Description**

Initializes the passthru command buffer for the Get Log command with
LID value ``NVME_LOG_LID_HOST_DISCOVERY``


.. c:function:: void nvme_init_get_log_ave_discovery (struct libnvme_passthru_cmd *cmd, struct nvme_ave_discover_log *log, __u32 len)

   Initialize passthru command for AVE Discovery

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``struct nvme_ave_discover_log *log``
  User address to store the log page

``__u32 len``
  The allocated length of the log page

**Description**

Initializes the passthru command buffer for the Get Log command with
LID value ``NVME_LOG_LID_AVE_DISCOVERY``


.. c:function:: void nvme_init_get_log_pull_model_ddc_req (struct libnvme_passthru_cmd *cmd, struct nvme_pull_model_ddc_req_log *log, __u32 len)

   Initialize passthru command for Pull Model DDC Request

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``struct nvme_pull_model_ddc_req_log *log``
  User address to store the log page

``__u32 len``
  The allocated length of the log page

**Description**

Initializes the passthru command buffer for the Get Log command with
LID value ``NVME_LOG_LID_PULL_MODEL_DDC_REQ``


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


.. c:function:: void nvme_init_get_log_zns_changed_zones (struct libnvme_passthru_cmd *cmd, __u32 nsid, struct nvme_zns_changed_zone_log *log)

   Initialize passthru command for list of zones that have changed

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``__u32 nsid``
  Namespace ID

``struct nvme_zns_changed_zone_log *log``
  User address to store the changed zone log

**Description**

Initializes the passthru command buffer for the Get Log command with
LID value ``NVME_LOG_LID_ZNS_CHANGED_ZONES``


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


.. c:function:: void nvme_init_set_features_resv_mask (struct libnvme_passthru_cmd *cmd, __u32 nsid, bool sv, __u32 mask)

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
FID value ``NVME_FEAT_FID_RESV_MASK``


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


.. c:function:: void nvme_init_get_features_resv_mask (struct libnvme_passthru_cmd *cmd, __u32 nsid, enum nvme_get_features_sel sel)

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
FID value ``NVME_FEAT_FID_RESV_MASK``


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

0 on success, or error code if arguments are invalid.


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

0 on success, or error code if arguments are invalid.


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


.. c:function:: void nvme_init_set_property (struct libnvme_passthru_cmd *cmd, __u32 offset, __u64 value)

   Initialize passthru command to set controller property

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``__u32 offset``
  Property offset from the base to set

``__u64 value``
  The value to set the property

**Description**

Initializes the passthru command buffer for the Fabrics Set Property command.
This is an NVMe-over-Fabrics specific command.


.. c:function:: void nvme_init_get_property (struct libnvme_passthru_cmd *cmd, __u32 offset)

   Initialize passthru command to get a controller property

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``__u32 offset``
  Property offset from the base to retrieve

**Description**

Initializes the passthru command buffer for the Fabrics Get Property command.
This is an NVMe-over-Fabrics specific command.


.. c:function:: void nvme_init_sanitize_nvm (struct libnvme_passthru_cmd *cmd, enum nvme_sanitize_sanact sanact, bool ause, __u8 owpass, bool oipbp, bool ndas, bool emvs, __u32 ovrpat)

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

``__u32 ovrpat``
  Overwrite pattern

**Description**

Initializes the passthru command buffer for the Sanitize NVM command.


.. c:function:: void nvme_init_sanitize_ns (struct libnvme_passthru_cmd *cmd, enum nvme_sanitize_sanact sanact, bool ause, bool emvs)

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

**Description**

Initializes the passthru command buffer for the Sanitize namespace command.


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


.. c:function:: void nvme_init_flush (struct libnvme_passthru_cmd *cmd, __u32 nsid)

   Initialize passthru command for Flush command

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``__u32 nsid``
  Namespace identifier

**Description**

The Flush command requests that the contents of volatile write cache be made
non-volatile.

Initializes the passthru command buffer for the Flush command.


.. c:function:: void nvme_init_dsm (struct libnvme_passthru_cmd *cmd, __u32 nsid, __u16 nr, __u8 idr, __u8 idw, __u8 ad, void *data, __u32 len)

   Initialize passthru command for NVMEe I/O Data Set Management

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``__u32 nsid``
  Namespace identifier

``__u16 nr``
  Number of block ranges in the data set management attributes

``__u8 idr``
  DSM Integral Dataset for Read attribute

``__u8 idw``
  DSM Integral Dataset for Write attribute

``__u8 ad``
  DSM Deallocate attribute

``void *data``
  User space destination address to transfer the data

``__u32 len``
  Length of provided user buffer to hold the log data in bytes


.. c:function:: int nvme_init_var_size_tags (struct libnvme_passthru_cmd *cmd, __u8 pif, __u8 sts, __u64 reftag, __u64 storage_tag)

   Initialize Command Dword fields for Extended LBA based on Variable Sized Tags

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``__u8 pif``
  Protection information format, determines tag placement

``__u8 sts``
  Storage tag size in bits

``__u64 reftag``
  Expected Initial Logical Block Reference Tag (EILBRT)

``__u64 storage_tag``
  Expected Logical Block Storage Tag (ELBST)

**Description**

Initializes the passthru command buffer fields cdw2, cdw3, and cdw14
for commands supporting Extended LBA. This logic is usually called from
the command-specific init function (like nvme_init_zns_append).


.. c:function:: void nvme_init_app_tag (struct libnvme_passthru_cmd *cmd, __u16 lbat, __u16 lbatm)

   Initialize Command Dword fields for Logical Block Application Tag/Mask

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``__u16 lbat``
  Logical block application tag

``__u16 lbatm``
  Logical block application tag mask


.. c:function:: void nvme_init_io (struct libnvme_passthru_cmd *cmd, __u8 opcode, __u32 nsid, __u64 slba, void *data, __u32 data_len, void *metadata, __u32 metadata_len)

   Initialize passthru command for a generic user I/O command

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``__u8 opcode``
  Opcode to execute

``__u32 nsid``
  Namespace ID

``__u64 slba``
  Starting logical block

``void *data``
  Pointer to user address of the data buffer

``__u32 data_len``
  Length of user buffer, **data**, in bytes

``void *metadata``
  Pointer to user address of the metadata buffer

``__u32 metadata_len``
  Length of user buffer, **metadata**, in bytes

**Description**

Initializes the passthru command buffer for a generic NVM I/O command.

**Note**

If **elbas** is true, the caller must ensure the definition/logic for
nvme_init_set_var_size_tags is available and that the return value from
that function is checked for error.


.. c:function:: void nvme_init_read (struct libnvme_passthru_cmd *cmd, __u32 nsid, __u64 slba, __u16 nlb, __u16 control, __u8 dsm, __u16 cev, void *data, __u32 data_len, void *metadata, __u32 metadata_len)

   Initialize passthru command for a user read command

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``__u32 nsid``
  Namespace ID

``__u64 slba``
  Starting logical block

``__u16 nlb``
  Number of logical blocks (0-based)

``__u16 control``
  Upper 16 bits of cdw12

``__u8 dsm``
  Data set management attributes (CETYPE is zero),
  see :c:type:`enum nvme_io_dsm_flags <nvme_io_dsm_flags>`

``__u16 cev``
  Command Extension Value (CETYPE is non-zero)

``void *data``
  Pointer to user address of the data buffer

``__u32 data_len``
  Length of user buffer, **data**, in bytes

``void *metadata``
  Pointer to user address of the metadata buffer

``__u32 metadata_len``
  Length of user buffer, **metadata**, in bytes

**Description**

Initializes the passthru command buffer for the Read command.

**Note**

Assumes a macro or separate function exists to translate the combined
NLB/control/prinfo fields into cdw12/cdw13. This transformation assumes
the parameters are used for a generic nvme_init_io wrapper.


.. c:function:: void nvme_init_write (struct libnvme_passthru_cmd *cmd, __u32 nsid, __u64 slba, __u16 nlb, __u16 control, __u16 dspec, __u8 dsm, __u8 cev, void *data, __u32 data_len, void *metadata, __u32 metadata_len)

   Initialize passthru command for a user write command

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``__u32 nsid``
  Namespace ID

``__u64 slba``
  Starting logical block

``__u16 nlb``
  Number of logical blocks (0-based)

``__u16 control``
  Upper 16 bits of cdw12

``__u16 dspec``
  Directive specific value

``__u8 dsm``
  Data set management attributes (CETYPE is zero),
  see :c:type:`enum nvme_io_dsm_flags <nvme_io_dsm_flags>`

``__u8 cev``
  Command Extension Value (CETYPE is non-zero)

``void *data``
  Pointer to user address of the data buffer

``__u32 data_len``
  Length of user buffer, **data**, in bytes

``void *metadata``
  Pointer to user address of the metadata buffer

``__u32 metadata_len``
  Length of user buffer, **metadata**, in bytes

**Description**

Initializes the passthru command buffer for the Write command.


.. c:function:: void nvme_init_compare (struct libnvme_passthru_cmd *cmd, __u32 nsid, __u64 slba, __u16 nlb, __u16 control, __u8 cev, void *data, __u32 data_len, void *metadata, __u32 metadata_len)

   Initialize passthru command for a user compare command

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``__u32 nsid``
  Namespace ID

``__u64 slba``
  Starting logical block

``__u16 nlb``
  Number of logical blocks (0-based)

``__u16 control``
  Command control flags, see :c:type:`enum nvme_io_control_flags <nvme_io_control_flags>`.

``__u8 cev``
  Command Extension Value (CETYPE is non-zero)

``void *data``
  Pointer to user address of the data buffer

``__u32 data_len``
  Length of user buffer, **data**, in bytes

``void *metadata``
  Pointer to user address of the metadata buffer

``__u32 metadata_len``
  Length of user buffer, **metadata**, in bytes

**Description**

Initializes the passthru command buffer for the Compare command.


.. c:function:: void nvme_init_write_zeros (struct libnvme_passthru_cmd *cmd, __u32 nsid, __u64 slba, __u16 nlb, __u16 control, __u16 dspec, __u8 dsm, __u8 cev)

   Initialize passthru command for a write zeroes command

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``__u32 nsid``
  Namespace ID

``__u64 slba``
  Starting logical block

``__u16 nlb``
  Number of logical blocks (0-based)

``__u16 control``
  Upper 16 bits of cdw12

``__u16 dspec``
  Directive specific value

``__u8 dsm``
  Data set management attributes (CETYPE is zero),
  see :c:type:`enum nvme_io_dsm_flags <nvme_io_dsm_flags>`

``__u8 cev``
  Command Extension Value (CETYPE is non-zero)

**Description**

Initializes the passthru command buffer for the Write Zeroes command.

**Note**

Write Zeroes command does not transfer data or metadata.


.. c:function:: void nvme_init_write_uncorrectable (struct libnvme_passthru_cmd *cmd, __u32 nsid, __u64 slba, __u16 nlb, __u16 control, __u16 dspec)

   Initialize passthru command for a write uncorrectable command

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``__u32 nsid``
  Namespace ID

``__u64 slba``
  Starting logical block

``__u16 nlb``
  Number of logical blocks (0-based)

``__u16 control``
  Upper 16 bits of cdw12

``__u16 dspec``
  Directive specific value

**Description**

Initializes the passthru command buffer for the Write Uncorrectable command.

**Note**

This command transfers no data or metadata.


.. c:function:: void nvme_init_verify (struct libnvme_passthru_cmd *cmd, __u32 nsid, __u64 slba, __u16 nlb, __u16 control, __u8 cev, void *data, __u32 data_len, void *metadata, __u32 metadata_len)

   Initialize passthru command for a verify command

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``__u32 nsid``
  Namespace ID

``__u64 slba``
  Starting logical block

``__u16 nlb``
  Number of logical blocks (0-based)

``__u16 control``
  Upper 16 bits of cdw12

``__u8 cev``
  Command Extension Value (CETYPE is non-zero)

``void *data``
  Pointer to user address of the data buffer

``__u32 data_len``
  Length of user buffer, **data**, in bytes

``void *metadata``
  Pointer to user address of the metadata buffer

``__u32 metadata_len``
  Length of user buffer, **metadata**, in bytes

**Description**

Initializes the passthru command buffer for the Verify command.

**Note**

Verify command transfers data or metadata to the controller to perform
the verification but not back to the host.


.. c:function:: void nvme_init_copy (struct libnvme_passthru_cmd *cmd, __u32 nsid, __u64 sdlba, __u16 nr, __u8 desfmt, __u8 prinfor, __u8 prinfow, __u8 cetype, __u8 dtype, bool stcw, bool stcr, bool fua, bool lr, __u16 cev, __u16 dspec, void *cpydsc)

   Initialize passthru command for Copy command

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``__u32 nsid``
  Namespace identifier

``__u64 sdlba``
  Start destination LBA

``__u16 nr``
  Number of ranges (1-based, 0-based in command)

``__u8 desfmt``
  Descriptor format

``__u8 prinfor``
  Protection information field for read

``__u8 prinfow``
  Protection information field for write

``__u8 cetype``
  Command Extension Type

``__u8 dtype``
  Directive Type

``bool stcw``
  Storage Tag Check Write

``bool stcr``
  Storage Tag Check Read

``bool fua``
  Force unit access

``bool lr``
  Limited retry

``__u16 cev``
  Command Extension Value

``__u16 dspec``
  Directive specific value

``void *cpydsc``
  Range description buffer

**Description**

Initializes the passthru command buffer for the Copy command by calculating
the data length and calling the generic I/O initializer.


.. c:function:: void nvme_init_resv_acquire (struct libnvme_passthru_cmd *cmd, __u32 nsid, enum nvme_resv_racqa racqa, bool iekey, bool disnsrs, enum nvme_resv_rtype rtype, __u64 crkey, __u64 prkey, __le64 *payload)

   Initialize passthru command for Reservation Acquire

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``__u32 nsid``
  Namespace identifier

``enum nvme_resv_racqa racqa``
  The action that is performed by the command,
  see :c:type:`enum nvme_resv_racqa <nvme_resv_racqa>`

``bool iekey``
  Set to ignore the existing key

``bool disnsrs``
  Disperse Namespace Reservation Support

``enum nvme_resv_rtype rtype``
  The type of reservation to be create, see :c:type:`enum nvme_resv_rtype <nvme_resv_rtype>`

``__u64 crkey``
  The current reservation key associated with the host

``__u64 prkey``
  Preempt Reservation Key

``__le64 *payload``
  Data payload buffer to hold crkey and prkey

**Description**

Initializes the passthru command buffer for the Reservation Acquire command.


.. c:function:: void nvme_init_resv_register (struct libnvme_passthru_cmd *cmd, __u32 nsid, enum nvme_resv_rrega rrega, bool iekey, bool disnsrs, enum nvme_resv_cptpl cptpl, __u64 crkey, __u64 nrkey, __le64 *payload)

   Initialize passthru command for Reservation Register

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``__u32 nsid``
  Namespace identifier

``enum nvme_resv_rrega rrega``
  The registration action, see :c:type:`enum nvme_resv_rrega <nvme_resv_rrega>`

``bool iekey``
  Set to ignore the existing key

``bool disnsrs``
  Disperse Namespace Reservation Support

``enum nvme_resv_cptpl cptpl``
  Change persist through power loss, see :c:type:`enum nvme_resv_cptpl <nvme_resv_cptpl>`

``__u64 crkey``
  The current reservation key associated with the host

``__u64 nrkey``
  The new reservation key to be register if action is register or
  replace

``__le64 *payload``
  Data payload buffer to hold crkey and nrkey

**Description**

Initializes the passthru command buffer for the Reservation Register command.


.. c:function:: void nvme_init_resv_release (struct libnvme_passthru_cmd *cmd, __u32 nsid, enum nvme_resv_rrela rrela, bool iekey, bool disnsrs, enum nvme_resv_rtype rtype, __u64 crkey, __le64 *payload)

   Initialize passthru command for Reservation Release

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``__u32 nsid``
  Namespace identifier

``enum nvme_resv_rrela rrela``
  Reservation release action, see :c:type:`enum nvme_resv_rrela <nvme_resv_rrela>`

``bool iekey``
  Set to ignore the existing key

``bool disnsrs``
  Disperse Namespace Reservation Support

``enum nvme_resv_rtype rtype``
  The type of reservation to be create, see :c:type:`enum nvme_resv_rtype <nvme_resv_rtype>`

``__u64 crkey``
  The current reservation key to release

``__le64 *payload``
  Data payload buffer to hold crkey

**Description**

Initializes the passthru command buffer for the Reservation Release command.


.. c:function:: void nvme_init_resv_report (struct libnvme_passthru_cmd *cmd, __u32 nsid, bool eds, bool disnsrs, struct nvme_resv_status *report, __u32 len)

   Initialize passthru command for Reservation Report

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``__u32 nsid``
  Namespace identifier

``bool eds``
  Request extended Data Structure

``bool disnsrs``
  Disperse Namespace Reservation Support

``struct nvme_resv_status *report``
  The user space destination address to store the reservation
  report buffer

``__u32 len``
  Number of bytes to request transferred with this command

**Description**

Initializes the passthru command buffer for the Reservation Report command.


.. c:function:: void nvme_init_io_mgmt_recv (struct libnvme_passthru_cmd *cmd, __u32 nsid, __u8 mo, __u16 mos, void *data, __u32 len)

   Initialize passthru command for I/O Management Receive command

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``__u32 nsid``
  Namespace identifier

``__u8 mo``
  Management Operation

``__u16 mos``
  Management Operation Specific

``void *data``
  Userspace address of the data buffer

``__u32 len``
  Length of **data**

**Description**

Initializes the passthru command buffer for the I/O Management
Receive command.


.. c:function:: void nvme_init_fdp_reclaim_unit_handle_status (struct libnvme_passthru_cmd *cmd, __u32 nsid, void *data, __u32 len)

   Initialize passthru command to get reclaim unit handle status

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``__u32 nsid``
  Namespace identifier

``void *data``
  Response buffer

``__u32 len``
  Length of response buffer

**Description**

Initializes the passthru command buffer for the I/O Management Receive -
Reclaim Unit Handle Status command.


.. c:function:: void nvme_init_io_mgmt_send (struct libnvme_passthru_cmd *cmd, __u32 nsid, __u8 mo, __u16 mos, void *data, __u32 len)

   Initialize passthru command for I/O Management Send command

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``__u32 nsid``
  Namespace identifier

``__u8 mo``
  Management Operation

``__u16 mos``
  Management Operation Specific

``void *data``
  Userspace address of the data buffer

``__u32 len``
  Length of **data**

**Description**

Initializes the passthru command buffer for the I/O Management Send command.


.. c:function:: void nvme_init_fdp_reclaim_unit_handle_update (struct libnvme_passthru_cmd *cmd, __u32 nsid, void *pids, unsigned int npids)

   Initialize passthru command to update a list of reclaim unit handles

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``__u32 nsid``
  Namespace identifier

``void *pids``
  List of placement identifiers buffer

``unsigned int npids``
  Number of placement identifiers

**Description**

Initializes the passthru command buffer for the I/O Management Send -
Reclaim Unit Handle Update command.


.. c:function:: void nvme_init_zns_mgmt_send (struct libnvme_passthru_cmd *cmd, __u32 nsid, __u64 slba, enum nvme_zns_send_action zsa, bool selall, __u8 zsaso, __u8 zm, void *data, __u32 len)

   Initialize passthru command for ZNS management send command

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``__u32 nsid``
  Namespace ID

``__u64 slba``
  Starting logical block address

``enum nvme_zns_send_action zsa``
  Zone send action

``bool selall``
  Select all flag

``__u8 zsaso``
  Zone Send Action Specific Option

``__u8 zm``
  Zone Management

``void *data``
  Userspace address of the data buffer

``__u32 len``
  Length of **data**

**Description**

Initializes the passthru command buffer for the ZNS Management Send command.


.. c:function:: void nvme_init_zns_mgmt_recv (struct libnvme_passthru_cmd *cmd, __u32 nsid, __u64 slba, enum nvme_zns_recv_action zra, __u16 zras, bool zraspf, void *data, __u32 len)

   Initialize passthru command for ZNS management receive command

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``__u32 nsid``
  Namespace ID

``__u64 slba``
  Starting logical block address

``enum nvme_zns_recv_action zra``
  zone receive action

``__u16 zras``
  Zone receive action specific field

``bool zraspf``
  Zone receive action specific features

``void *data``
  Userspace address of the data buffer

``__u32 len``
  Length of **data**

**Description**

Initializes the passthru command buffer for the ZNS Management
Receive command.


.. c:function:: void nvme_init_zns_report_zones (struct libnvme_passthru_cmd *cmd, __u32 nsid, __u64 slba, enum nvme_zns_report_options opts, bool extended, bool partial, void *data, __u32 len)

   Initialize passthru command to return the list of zones

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``__u32 nsid``
  Namespace ID

``__u64 slba``
  Starting LBA

``enum nvme_zns_report_options opts``
  Reporting options

``bool extended``
  Extended report

``bool partial``
  Partial report requested

``void *data``
  Userspace address of the report zones data buffer

``__u32 len``
  Length of the data buffer

**Description**

Initializes the passthru command buffer for the ZNS Management Receive -
Report Zones command.


.. c:function:: void nvme_init_zns_append (struct libnvme_passthru_cmd *cmd, __u32 nsid, __u64 zslba, __u16 nlb, __u16 control, __u16 cev, __u16 dspec, void *data, __u32 data_len, void *metadata, __u32 metadata_len)

   Initialize passthru command to append data to a zone

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``__u32 nsid``
  Namespace ID

``__u64 zslba``
  Zone start logical block address

``__u16 nlb``
  Number of logical blocks

``__u16 control``
  Upper 16 bits of cdw12

``__u16 cev``
  Command Extension Value

``__u16 dspec``
  Directive Specific

``void *data``
  Userspace address of the data buffer

``__u32 data_len``
  Length of **data**

``void *metadata``
  Userspace address of the metadata buffer

``__u32 metadata_len``
  Length of **metadata**

**Description**

Initializes the passthru command buffer for the ZNS Append command.


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


.. c:function:: void nvme_init_lm_track_send (struct libnvme_passthru_cmd *cmd, __u8 sel, __u16 mos, __u16 cdqid)

   Initialize passthru command for Track Send command

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``__u8 sel``
  Select (SEL): This field specifies the type of
  management operation to perform

``__u16 mos``
  Management Operation Specific (MOS): This field
  is specific to the SEL type

``__u16 cdqid``
  Controller Data Queue ID (CDQID)

**Description**

Initializes the passthru command buffer for the Track Send command.


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


.. c:function:: void nvme_init_mi_cmd_flags (struct libnvme_passthru_cmd *cmd, bool ish)

   Initialize command flags for NVMe-MI

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``bool ish``
  Ignore Shutdown (for NVMe-MI command)

**Description**

Initializes the passthru command flags


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


.. c:function:: void nvme_init_dsm_range (struct nvme_dsm_range *dsm, __u32 *ctx_attrs, __u32 *llbas, __u64 *slbas, __u16 nr_ranges)

   Constructs a data set range structure

**Parameters**

``struct nvme_dsm_range *dsm``
  DSM range array

``__u32 *ctx_attrs``
  Array of context attributes

``__u32 *llbas``
  Array of length in logical blocks

``__u64 *slbas``
  Array of starting logical blocks

``__u16 nr_ranges``
  The size of the dsm arrays

**Description**

Each array must be the same size of size 'nr_ranges'. This is intended to be
used with constructing a payload for nvme_dsm().

**Return**

The nvme command status if a response was received or -errno
otherwise.


.. c:function:: void nvme_init_copy_range_f0 (struct nvme_copy_range_f0 *copy, __u16 *nlbs, __u64 *slbas, __u32 *elbts, __u16 *elbatms, __u16 *elbats, __u16 nr)

   Constructs a copy range structure

**Parameters**

``struct nvme_copy_range_f0 *copy``
  Copy range array

``__u16 *nlbs``
  Number of logical blocks

``__u64 *slbas``
  Starting LBA

``__u32 *elbts``
  Expected initial logical block reference tag

``__u16 *elbatms``
  Expected logical block application tag mask

``__u16 *elbats``
  Expected logical block application tag

``__u16 nr``
  Number of descriptors to construct


.. c:function:: void nvme_init_copy_range_f1 (struct nvme_copy_range_f1 *copy, __u16 *nlbs, __u64 *slbas, __u64 *eilbrts, __u16 *elbatms, __u16 *elbats, __u16 nr)

   Constructs a copy range f1 structure

**Parameters**

``struct nvme_copy_range_f1 *copy``
  Copy range array

``__u16 *nlbs``
  Number of logical blocks

``__u64 *slbas``
  Starting LBA

``__u64 *eilbrts``
  Expected initial logical block reference tag

``__u16 *elbatms``
  Expected logical block application tag mask

``__u16 *elbats``
  Expected logical block application tag

``__u16 nr``
  Number of descriptors to construct


.. c:function:: void nvme_init_copy_range_f2 (struct nvme_copy_range_f2 *copy, __u32 *snsids, __u16 *nlbs, __u64 *slbas, __u16 *sopts, __u32 *elbts, __u16 *elbatms, __u16 *elbats, __u16 nr)

   Constructs a copy range f2 structure

**Parameters**

``struct nvme_copy_range_f2 *copy``
  Copy range array

``__u32 *snsids``
  Source namespace identifier

``__u16 *nlbs``
  Number of logical blocks

``__u64 *slbas``
  Starting LBA

``__u16 *sopts``
  Source options

``__u32 *elbts``
  Expected initial logical block reference tag

``__u16 *elbatms``
  Expected logical block application tag mask

``__u16 *elbats``
  Expected logical block application tag

``__u16 nr``
  Number of descriptors to construct


.. c:function:: void nvme_init_copy_range_f3 (struct nvme_copy_range_f3 *copy, __u32 *snsids, __u16 *nlbs, __u64 *slbas, __u16 *sopts, __u64 *eilbrts, __u16 *elbatms, __u16 *elbats, __u16 nr)

   Constructs a copy range f3 structure

**Parameters**

``struct nvme_copy_range_f3 *copy``
  Copy range array

``__u32 *snsids``
  Source namespace identifier

``__u16 *nlbs``
  Number of logical blocks

``__u64 *slbas``
  Starting LBA

``__u16 *sopts``
  Source options

``__u64 *eilbrts``
  Expected initial logical block reference tag

``__u16 *elbatms``
  Expected logical block application tag mask

``__u16 *elbats``
  Expected logical block application tag

``__u16 nr``
  Number of descriptors to construct


.. c:function:: int libnvme_get_log (struct libnvme_transport_handle *hdl, struct libnvme_passthru_cmd *cmd, bool rae, __u32 xfer_len)

   Get log page data

**Parameters**

``struct libnvme_transport_handle *hdl``
  Transport handle

``struct libnvme_passthru_cmd *cmd``
  Passthru command

``bool rae``
  Retain asynchronous events

``__u32 xfer_len``
  Max log transfer size per request to split the total.

**Return**

0 on success, the nvme command status if a response was
received (see :c:type:`enum nvme_status_field <nvme_status_field>`) or a negative error otherwise.


.. c:function:: int libnvme_set_etdas (struct libnvme_transport_handle *hdl, bool *changed)

   Set the Extended Telemetry Data Area 4 Supported bit

**Parameters**

``struct libnvme_transport_handle *hdl``
  Transport handle

``bool *changed``
  boolean to indicate whether or not the host
  behavior support feature had been changed

**Return**

The nvme command status if a response was received (see
:c:type:`enum nvme_status_field <nvme_status_field>`) or -1 with errno set otherwise.


.. c:function:: int libnvme_clear_etdas (struct libnvme_transport_handle *hdl, bool *changed)

   Clear the Extended Telemetry Data Area 4 Supported bit

**Parameters**

``struct libnvme_transport_handle *hdl``
  Transport handle

``bool *changed``
  boolean to indicate whether or not the host
  behavior support feature had been changed

**Return**

The nvme command status if a response was received (see
:c:type:`enum nvme_status_field <nvme_status_field>`) or -1 with errno set otherwise.


.. c:function:: int libnvme_get_uuid_list (struct libnvme_transport_handle *hdl, struct nvme_id_uuid_list *uuid_list)

   Returns the uuid list (if supported)

**Parameters**

``struct libnvme_transport_handle *hdl``
  Transport handle

``struct nvme_id_uuid_list *uuid_list``
  UUID list returned by identify UUID

**Return**

The nvme command status if a response was received (see
:c:type:`enum nvme_status_field <nvme_status_field>`) or -1 with errno set otherwise.


.. c:function:: int libnvme_get_telemetry_max (struct libnvme_transport_handle *hdl, enum nvme_telemetry_da *da, size_t *max_data_tx)

   Get telemetry limits

**Parameters**

``struct libnvme_transport_handle *hdl``
  Transport handle

``enum nvme_telemetry_da *da``
  On success return max supported data area

``size_t *max_data_tx``
  On success set to max transfer chunk supported by
  the controller

**Return**

0 on success, the nvme command status if a response was
received (see :c:type:`enum nvme_status_field <nvme_status_field>`) or a negative error otherwise.


.. c:function:: int libnvme_get_telemetry_log (struct libnvme_transport_handle *hdl, bool create, bool ctrl, bool rae, size_t max_data_tx, enum nvme_telemetry_da da, struct nvme_telemetry_log **log, size_t *size)

   Get specified telemetry log

**Parameters**

``struct libnvme_transport_handle *hdl``
  Transport handle

``bool create``
  Generate new host initated telemetry capture

``bool ctrl``
  Get controller Initiated log

``bool rae``
  Retain asynchronous events

``size_t max_data_tx``
  Set the max data transfer size to be used retrieving telemetry.

``enum nvme_telemetry_da da``
  Log page data area, valid values: :c:type:`enum nvme_telemetry_da <nvme_telemetry_da>`.

``struct nvme_telemetry_log **log``
  On success, set to the value of the allocated and retrieved log.

``size_t *size``
  Ptr to the telemetry log size, so it can be returned

**Description**

The total size allocated can be calculated as:
  (nvme_telemetry_log da size  + 1) * NVME_LOG_TELEM_BLOCK_SIZE.

**Return**

0 on success, the nvme command status if a response was
received (see :c:type:`enum nvme_status_field <nvme_status_field>`) or a negative error otherwise.


.. c:function:: int libnvme_get_ctrl_telemetry (struct libnvme_transport_handle *hdl, bool rae, struct nvme_telemetry_log **log, enum nvme_telemetry_da da, size_t *size)

   Get controller telemetry log

**Parameters**

``struct libnvme_transport_handle *hdl``
  Transport handle

``bool rae``
  Retain asynchronous events

``struct nvme_telemetry_log **log``
  On success, set to the value of the allocated and retrieved log.

``enum nvme_telemetry_da da``
  Log page data area, valid values: :c:type:`enum nvme_telemetry_da <nvme_telemetry_da>`

``size_t *size``
  Ptr to the telemetry log size, so it can be returned

**Description**

The total size allocated can be calculated as:
  (nvme_telemetry_log da size  + 1) * NVME_LOG_TELEM_BLOCK_SIZE.

**Return**

0 on success, the nvme command status if a response was
received (see :c:type:`enum nvme_status_field <nvme_status_field>`) or a negative error otherwise.


.. c:function:: int libnvme_get_host_telemetry (struct libnvme_transport_handle *hdl, struct nvme_telemetry_log **log, enum nvme_telemetry_da da, size_t *size)

   Get host telemetry log

**Parameters**

``struct libnvme_transport_handle *hdl``
  Transport handle

``struct nvme_telemetry_log **log``
  On success, set to the value of the allocated and retrieved log.

``enum nvme_telemetry_da da``
  Log page data area, valid values: :c:type:`enum nvme_telemetry_da <nvme_telemetry_da>`

``size_t *size``
  Ptr to the telemetry log size, so it can be returned

**Description**

The total size allocated can be calculated as:
  (nvme_telemetry_log da size  + 1) * NVME_LOG_TELEM_BLOCK_SIZE.

**Return**

0 on success, the nvme command status if a response was
received (see :c:type:`enum nvme_status_field <nvme_status_field>`) or a negative error otherwise.


.. c:function:: int libnvme_get_new_host_telemetry (struct libnvme_transport_handle *hdl, struct nvme_telemetry_log **log, enum nvme_telemetry_da da, size_t *size)

   Get new host telemetry log

**Parameters**

``struct libnvme_transport_handle *hdl``
  Transport handle

``struct nvme_telemetry_log **log``
  On success, set to the value of the allocated and retrieved log.

``enum nvme_telemetry_da da``
  Log page data area, valid values: :c:type:`enum nvme_telemetry_da <nvme_telemetry_da>`

``size_t *size``
  Ptr to the telemetry log size, so it can be returned

**Description**

The total size allocated can be calculated as:
  (nvme_telemetry_log da size  + 1) * NVME_LOG_TELEM_BLOCK_SIZE.

**Return**

0 on success, the nvme command status if a response was
received (see :c:type:`enum nvme_status_field <nvme_status_field>`) or a negative error otherwise.


.. c:function:: size_t libnvme_get_ana_log_len_from_id_ctrl (const struct nvme_id_ctrl *id_ctrl, bool rgo)

   Retrieve maximum possible ANA log size

**Parameters**

``const struct nvme_id_ctrl *id_ctrl``
  Controller identify data

``bool rgo``
  If true, return maximum log page size without NSIDs

**Return**

A byte limit on the size of the controller's ANA log page


.. c:function:: int libnvme_get_ana_log_atomic (struct libnvme_transport_handle *hdl, bool rae, bool rgo, struct nvme_ana_log *log, __u32 *len, unsigned int retries)

   Retrieve Asymmetric Namespace Access log page atomically

**Parameters**

``struct libnvme_transport_handle *hdl``
  Transport handle

``bool rae``
  Whether to retain asynchronous events

``bool rgo``
  Whether to retrieve ANA groups only (no NSIDs)

``struct nvme_ana_log *log``
  Pointer to a buffer to receive the ANA log page

``__u32 *len``
  Input: the length of the log page buffer.
  Output: the actual length of the ANA log page.

``unsigned int retries``
  The maximum number of times to retry on log page changes

**Description**

See :c:type:`struct nvme_ana_log <nvme_ana_log>` for the definition of the returned structure.

**Return**

If successful, returns 0 and sets *len to the actual log page length.
If unsuccessful, returns the nvme command status if a response was received
(see :c:type:`enum nvme_status_field <nvme_status_field>`) or -1 with errno set otherwise.
Sets errno = EINVAL if retries == 0.
Sets errno = EAGAIN if unable to read the log page atomically
because chgcnt changed during each of the retries attempts.
Sets errno = ENOSPC if the full log page does not fit in the provided buffer.


.. c:function:: int libnvme_get_ana_log_len (struct libnvme_transport_handle *hdl, size_t *analen)

   Retrieve size of the current ANA log

**Parameters**

``struct libnvme_transport_handle *hdl``
  Transport handle

``size_t *analen``
  Pointer to where the length will be set on success

**Return**

0 on success, the nvme command status if a response was
received (see :c:type:`enum nvme_status_field <nvme_status_field>`) or a negative error otherwise.


.. c:function:: int libnvme_get_logical_block_size (struct libnvme_transport_handle *hdl, __u32 nsid, int *blksize)

   Retrieve block size

**Parameters**

``struct libnvme_transport_handle *hdl``
  Transport handle

``__u32 nsid``
  Namespace id

``int *blksize``
  Pointer to where the block size will be set on success

**Return**

0 on success, the nvme command status if a response was
received (see :c:type:`enum nvme_status_field <nvme_status_field>`) or a negative error otherwise.


.. c:function:: int libnvme_get_lba_status_log (struct libnvme_transport_handle *hdl, bool rae, struct nvme_lba_status_log **log)

   Retrieve the LBA Status log page

**Parameters**

``struct libnvme_transport_handle *hdl``
  Transport handle

``bool rae``
  Retain asynchronous events

``struct nvme_lba_status_log **log``
  On success, set to the value of the allocated and retrieved log.

**Return**

0 on success, the nvme command status if a response was
received (see :c:type:`enum nvme_status_field <nvme_status_field>`) or a negative error otherwise.


.. c:function:: int libnvme_get_feature_length (int fid, __u32 cdw11, enum nvme_data_tfr dir, __u32 *len)

   Retrieve the command payload length for a specific feature identifier

**Parameters**

``int fid``
  Feature identifier, see :c:type:`enum nvme_features_id <nvme_features_id>`.

``__u32 cdw11``
  The cdw11 value may affect the transfer (only known fid is
  ``NVME_FEAT_FID_HOST_ID``)

``enum nvme_data_tfr dir``
  Data transfer direction: false - host to controller, true -
  controller to host may affect the transfer (only known fid is
  ``NVME_FEAT_FID_HOST_MEM_BUF``).

``__u32 *len``
  On success, set to this features payload length in bytes.

**Return**

0 on success, -1 with errno set to EINVAL if the function did not
recognize :c:type:`fid`.


.. c:function:: int libnvme_get_directive_receive_length (enum nvme_directive_dtype dtype, enum nvme_directive_receive_doper doper, __u32 *len)

   Get directive receive length

**Parameters**

``enum nvme_directive_dtype dtype``
  Directive type, see :c:type:`enum nvme_directive_dtype <nvme_directive_dtype>`

``enum nvme_directive_receive_doper doper``
  Directive receive operation, see :c:type:`enum nvme_directive_receive_doper <nvme_directive_receive_doper>`

``__u32 *len``
  On success, set to this directives payload length in bytes.

**Return**

0 on success, -1 with errno set to EINVAL if the function did not
recognize :c:type:`dtype` or :c:type:`doper`.


