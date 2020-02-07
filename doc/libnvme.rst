**NVMe Admin command enums**




.. c:type:: enum nvme_admin_opcode

   Known NVMe admin opcodes

**Constants**

``nvme_admin_delete_sq``
  *undescribed*

``nvme_admin_create_sq``
  *undescribed*

``nvme_admin_get_log_page``
  *undescribed*

``nvme_admin_delete_cq``
  *undescribed*

``nvme_admin_create_cq``
  *undescribed*

``nvme_admin_identify``
  *undescribed*

``nvme_admin_abort_cmd``
  *undescribed*

``nvme_admin_set_features``
  *undescribed*

``nvme_admin_get_features``
  *undescribed*

``nvme_admin_async_event``
  *undescribed*

``nvme_admin_ns_mgmt``
  *undescribed*

``nvme_admin_fw_commit``
  *undescribed*

``nvme_admin_fw_download``
  *undescribed*

``nvme_admin_dev_self_test``
  *undescribed*

``nvme_admin_ns_attach``
  *undescribed*

``nvme_admin_keep_alive``
  *undescribed*

``nvme_admin_directive_send``
  *undescribed*

``nvme_admin_directive_recv``
  *undescribed*

``nvme_admin_virtual_mgmt``
  *undescribed*

``nvme_admin_nvme_mi_send``
  *undescribed*

``nvme_admin_nvme_mi_recv``
  *undescribed*

``nvme_admin_dbbuf``
  *undescribed*

``nvme_admin_fabrics``
  *undescribed*

``nvme_admin_format_nvm``
  *undescribed*

``nvme_admin_security_send``
  *undescribed*

``nvme_admin_security_recv``
  *undescribed*

``nvme_admin_sanitize_nvm``
  *undescribed*

``nvme_admin_get_lba_status``
  *undescribed*




.. c:type:: enum nvme_identify_cns


**Constants**

``NVME_IDENTIFY_CNS_NS``
  *undescribed*

``NVME_IDENTIFY_CNS_CTRL``
  *undescribed*

``NVME_IDENTIFY_CNS_NS_ACTIVE_LIST``
  *undescribed*

``NVME_IDENTIFY_CNS_NS_DESC_LIST``
  *undescribed*

``NVME_IDENTIFY_CNS_NVMSET_LIST``
  *undescribed*

``NVME_IDENTIFY_CNS_ALLOCATED_NS_LIST``
  *undescribed*

``NVME_IDENTIFY_CNS_ALLOCATED_NS``
  *undescribed*

``NVME_IDENTIFY_CNS_NS_CTRL_LIST``
  *undescribed*

``NVME_IDENTIFY_CNS_CTRL_LIST``
  *undescribed*

``NVME_IDENTIFY_CNS_PRIMARY_CTRL_CAP``
  *undescribed*

``NVME_IDENTIFY_CNS_SECONDARY_CTRL_LIST``
  *undescribed*

``NVME_IDENTIFY_CNS_NS_GRANULARITY``
  *undescribed*

``NVME_IDENTIFY_CNS_UUID_LIST``
  *undescribed*




.. c:type:: enum nvme_cmd_get_log_lid


**Constants**

``NVME_LOG_LID_ERROR``
  *undescribed*

``NVME_LOG_LID_SMART``
  *undescribed*

``NVME_LOG_LID_FW_SLOT``
  *undescribed*

``NVME_LOG_LID_CHANGED_NS``
  *undescribed*

``NVME_LOG_LID_CMD_EFFECTS``
  *undescribed*

``NVME_LOG_LID_DEVICE_SELF_TEST``
  *undescribed*

``NVME_LOG_LID_TELEMETRY_HOST``
  *undescribed*

``NVME_LOG_LID_TELEMETRY_CTRL``
  *undescribed*

``NVME_LOG_LID_ENDURANCE_GROUP``
  *undescribed*

``NVME_LOG_LID_PREDICTABLE_LAT_NVMSET``
  *undescribed*

``NVME_LOG_LID_PREDICTABLE_LAT_AGG``
  *undescribed*

``NVME_LOG_LID_ANA``
  *undescribed*

``NVME_LOG_LID_PERSISTENT_EVENT``
  *undescribed*

``NVME_LOG_LID_LBA_STATUS``
  *undescribed*

``NVME_LOG_LID_ENDURANCE_GRP_EVT``
  *undescribed*

``NVME_LOG_LID_DISCOVER``
  *undescribed*

``NVME_LOG_LID_RESERVATION``
  *undescribed*

``NVME_LOG_LID_SANITIZE``
  *undescribed*




.. c:type:: enum nvme_features_id


**Constants**

``NVME_FEAT_FID_ARBITRATION``
  *undescribed*

``NVME_FEAT_FID_POWER_MGMT``
  *undescribed*

``NVME_FEAT_FID_LBA_RANGE``
  *undescribed*

``NVME_FEAT_FID_TEMP_THRESH``
  *undescribed*

``NVME_FEAT_FID_ERR_RECOVERY``
  *undescribed*

``NVME_FEAT_FID_VOLATILE_WC``
  *undescribed*

``NVME_FEAT_FID_NUM_QUEUES``
  *undescribed*

``NVME_FEAT_FID_IRQ_COALESCE``
  *undescribed*

``NVME_FEAT_FID_IRQ_CONFIG``
  *undescribed*

``NVME_FEAT_FID_WRITE_ATOMIC``
  *undescribed*

``NVME_FEAT_FID_ASYNC_EVENT``
  *undescribed*

``NVME_FEAT_FID_AUTO_PST``
  *undescribed*

``NVME_FEAT_FID_HOST_MEM_BUF``
  *undescribed*

``NVME_FEAT_FID_TIMESTAMP``
  *undescribed*

``NVME_FEAT_FID_KATO``
  *undescribed*

``NVME_FEAT_FID_HCTM``
  *undescribed*

``NVME_FEAT_FID_NOPSC``
  *undescribed*

``NVME_FEAT_FID_RRL``
  *undescribed*

``NVME_FEAT_FID_PLM_CONFIG``
  *undescribed*

``NVME_FEAT_FID_PLM_WINDOW``
  *undescribed*

``NVME_FEAT_FID_LBA_STS_INTERVAL``
  *undescribed*

``NVME_FEAT_FID_HOST_BEHAVIOR``
  *undescribed*

``NVME_FEAT_FID_SANITIZE``
  *undescribed*

``NVME_FEAT_FID_ENDURANCE_EVT_CFG``
  *undescribed*

``NVME_FEAT_FID_SW_PROGRESS``
  *undescribed*

``NVME_FEAT_FID_HOST_ID``
  *undescribed*

``NVME_FEAT_FID_RESV_MASK``
  *undescribed*

``NVME_FEAT_RESV_PERSIST``
  *undescribed*

``NVME_FEAT_FID_WRITE_PROTECT``
  *undescribed*




.. c:type:: enum nvme_get_features_sel


**Constants**

``NVME_GET_FEATURES_SEL_CURRENT``
  *undescribed*

``NVME_GET_FEATURES_SEL_DEFAULT``
  *undescribed*

``NVME_GET_FEATURES_SEL_SAVED``
  *undescribed*




.. c:type:: enum nvme_cmd_format_mset


**Constants**

``NVME_FORMAT_MSET_SEPARATE``
  *undescribed*

``NVME_FORMAT_MSET_EXTENEDED``
  *undescribed*




.. c:type:: enum nvme_cmd_format_pi


**Constants**

``NVME_FORMAT_PI_DISABLE``
  *undescribed*

``NVME_FORMAT_PI_TYPE1``
  *undescribed*

``NVME_FORMAT_PI_TYPE2``
  *undescribed*

``NVME_FORMAT_PI_TYPE3``
  *undescribed*




.. c:type:: enum nvme_cmd_format_ses


**Constants**

``NVME_FORMAT_SES_NONE``
  *undescribed*

``NVME_FORMAT_SES_USER_DATA_ERASE``
  *undescribed*

``NVME_FORMAT_SES_CRYPTO_ERASE``
  *undescribed*




.. c:type:: enum nvme_ns_mgmt_sel


**Constants**

``NVME_NS_MGMT_SEL_CREATE``
  *undescribed*

``NVME_NS_MGMT_SEL_DELETE``
  *undescribed*




.. c:type:: enum nvme_ns_attach_sel

    NVME_NS_ATTACH_SEL_CTRL_ATTACH: NVME_NP_ATTACH_SEL_CTRL_DEATTACH:

**Constants**

``NVME_NS_ATTACH_SEL_CTRL_ATTACH``
  *undescribed*

``NVME_NS_ATTACH_SEL_CTRL_DEATTACH``
  *undescribed*




.. c:type:: enum nvme_fw_commit_ca


**Constants**

``NVME_FW_COMMIT_CA_REPLACE``
  *undescribed*

``NVME_FW_COMMIT_CA_REPLACE_AND_ACTIVATE``
  *undescribed*

``NVME_FW_COMMIT_CA_SET_ACTIVE``
  *undescribed*

``NVME_FW_COMMIT_CA_REPLACE_AND_ACTIVATE_IMMEDIATE``
  *undescribed*

``NVME_FW_COMMIT_CA_REPLACE_BOOT_PARTITION``
  *undescribed*

``NVME_FW_COMMIT_CA_ACTIVATE_BOOT_PARTITION``
  *undescribed*




.. c:type:: enum nvme_directive_dtype


**Constants**

``NVME_DIRECTIVE_DTYPE_IDENTIFY``
  *undescribed*

``NVME_DIRECTIVE_DTYPE_STREAMS``
  *undescribed*




.. c:type:: enum nvme_cmd_directive_receive_identify_doper


**Constants**

``NVME_DIRECTIVE_RECEIVE_IDENTIFY_DOPER_PARAM``
  *undescribed*




.. c:type:: enum nvme_cmd_directive_receive_streams_doper


**Constants**

``NVME_DIRECTIVE_RECEIVE_STREAMS_DOPER_PARAM``
  *undescribed*

``NVME_DIRECTIVE_RECEIVE_STREAMS_DOPER_STATUS``
  *undescribed*

``NVME_DIRECTIVE_RECEIVE_STREAMS_DOPER_RESOURCE``
  *undescribed*




.. c:type:: enum nvme_cmd_directive_send_identify_doper


**Constants**

``NVME_DIRECTIVE_SEND_IDENTIFY_DOPER_ENDIR``
  *undescribed*




.. c:type:: enum nvme_cmd_directive_send_identify_endir


**Constants**

``NVME_DIRECTIVE_SEND_IDENTIFY_ENDIR_DISABLE``
  *undescribed*

``NVME_DIRECTIVE_SEND_IDENTIFY_ENDIR_ENABLE``
  *undescribed*




.. c:type:: enum nvme_cmd_directive_send_streams_doper


**Constants**

``NVME_DIRECTIVE_SEND_STREAMS_DOPER_RELEASE_IDENTIFIER``
  *undescribed*

``NVME_DIRECTIVE_SEND_STREAMS_DOPER_RELEASE_RESOURCE``
  *undescribed*




.. c:type:: enum nvme_sanitize_sanact


**Constants**

``NVME_SANITIZE_SANACT_EXIT_FAILURE``
  *undescribed*

``NVME_SANITIZE_SANACT_START_BLOCK_ERASE``
  *undescribed*

``NVME_SANITIZE_SANACT_START_OVERWRITE``
  *undescribed*

``NVME_SANITIZE_SANACT_START_CRYPTO_ERASE``
  *undescribed*




.. c:type:: enum nvme_dst_stc


**Constants**

``NVME_DST_STC_SHORT``
  *undescribed*

``NVME_DST_STC_LONG``
  *undescribed*

``NVME_DST_STC_VS``
  *undescribed*

``NVME_DST_STC_ABORT``
  *undescribed*




.. c:type:: enum nvme_virt_mgmt_act


**Constants**

``NVME_VIRT_MGMT_ACT_PRIM_CTRL_FLEX_ALLOC``
  *undescribed*

``NVME_VIRT_MGMT_ACT_OFFLINE_SEC_CTRL``
  *undescribed*

``NVME_VIRT_MGMT_ACT_ASSIGN_SEC_CTRL``
  *undescribed*

``NVME_VIRT_MGMT_ACT_ONLINE_SEC_CTRL``
  *undescribed*




.. c:type:: enum nvme_virt_mgmt_rt


**Constants**

``NVME_VIRT_MGMT_RT_VQ_RESOURCE``
  *undescribed*

``NVME_VIRT_MGMT_RT_VI_RESOURCE``
  *undescribed*


.. c:function:: int nvme_identify (int fd, enum nvme_identify_cns cns, __u32 nsid, __u16 cntid, __u16 nvmsetid, __u8 uuidx, void * data)

   Send the NVMe Identify command

**Parameters**

``int fd``
  File descriptor of nvme device

``enum nvme_identify_cns cns``
  The Controller or Namespace structure, see **enum** nvme_identify_cns

``__u32 nsid``
  Namespace identifier, if applicable

``__u16 cntid``
  The Controller Identifier, if applicable

``__u16 nvmsetid``
  The NVMe Set ID if CNS is 04h

``__u8 uuidx``
  UUID Index if controller supports this id selection method

``void * data``
  User space destination address to transfer the data

**Description**

The Identify command returns a data buffer that describes information about
the NVM subsystem, the controller or the namespace(s).

**Return**

The nvme command status if a response was received or -1 with errno
        set otherwise.


.. c:function:: int nvme_identify_ctrl (int fd, struct nvme_id_ctrl * id)

   Retrieves nvme identify controller

**Parameters**

``int fd``
  File descriptor of nvme device
  id:          User space destination address to transfer the data,

``struct nvme_id_ctrl * id``
  *undescribed*

**Description**

Sends nvme identify with CNS value ``NVME_IDENTIFY_CNS_CTRL``.

See :c:type:`struct nvme_id_ctrl <nvme_id_ctrl>` for details on the data returned.

**Return**

The nvme command status if a response was received or -1 with errno
        set otherwise.


.. c:function:: int nvme_identify_ns (int fd, __u32 nsid, struct nvme_id_ns * ns)

   Retrieves nvme identify namespace

**Parameters**

``int fd``
  File descriptor of nvme device

``__u32 nsid``
  Namespace to identify

``struct nvme_id_ns * ns``
  User space destination address to transfer the data

**Description**

If the Namespace Identifier (NSID) field specifies an active NSID, then the
Identify Namespace data structure is returned to the host for that specified
namespace.

If the controller supports the Namespace Management capability and the NSID
field is set to ``NVME_NSID_ALL``, then the controller returns an Identify Namespace
data structure that specifies capabilities that are common across namespaces
for this controller.

See :c:type:`struct nvme_id_ns <nvme_id_ns>` for details on the structure returned.

**Return**

The nvme command status if a response was received or -1 with errno
        set otherwise.


.. c:function:: int nvme_identify_allocated_ns (int fd, __u32 nsid, struct nvme_id_ns * ns)

   Same as nvme_identify_ns, but only for allocated namespaces

**Parameters**

``int fd``
  File descriptor of nvme device

``__u32 nsid``
  Namespace to identify

``struct nvme_id_ns * ns``
  User space destination address to transfer the data

**Return**

The nvme command status if a response was received or -1 with errno
        set otherwise.


.. c:function:: int nvme_identify_active_ns_list (int fd, __u32 nsid, struct nvme_ns_list * list)

   Retrieves active namespaces id list

**Parameters**

``int fd``
  File descriptor of nvme device

``__u32 nsid``
  Return namespaces greater than this identifer

``struct nvme_ns_list * list``
  *undescribed*

**Description**

A list of 1024 namespace IDs is returned to the host containing NSIDs in
increasing order that are greater than the value specified in the Namespace
Identifier (nsid) field of the command.

See :c:type:`struct nvme_ns_list <nvme_ns_list>` for the definition of the returned structure.

**Return**

The nvme command status if a response was received or -1 with errno
        set otherwise.


.. c:function:: int nvme_identify_allocated_ns_list (int fd, __u32 nsid, struct nvme_ns_list * list)

   Retrieves allocated namespace id list

**Parameters**

``int fd``
  File descriptor of nvme device

``__u32 nsid``
  Return namespaces greater than this identifer

``struct nvme_ns_list * list``
  *undescribed*

**Description**

A list of 1024 namespace IDs is returned to the host containing NSIDs in
increasing order that are greater than the value specified in the Namespace
Identifier (nsid) field of the command.

See :c:type:`struct nvme_ns_list <nvme_ns_list>` for the definition of the returned structure.

**Return**

The nvme command status if a response was received or -1 with errno
        set otherwise.


.. c:function:: int nvme_identify_ctrl_list (int fd, __u16 cntid, struct nvme_ctrl_list * ctrlist)

   Retrieves identify controller list

**Parameters**

``int fd``
  File descriptor of nvme device

``__u16 cntid``
  *undescribed*

``struct nvme_ctrl_list * ctrlist``
  *undescribed*

**Description**

Up to 2047 controller identifiers is returned containing a controller
identifier greater than or equal to the controller identifier  specified in
**cntid**.

See :c:type:`struct nvme_ctrl_list <nvme_ctrl_list>` for a definition of the structure returned.

**Return**

The nvme command status if a response was received or -1 with errno
        set otherwise.


.. c:function:: int nvme_identify_nsid_ctrl_list (int fd, __u32 nsid, __u16 cntid, struct nvme_ctrl_list * ctrlist)


**Parameters**

``int fd``
  File descriptor of nvme device

``__u32 nsid``
  Return controllers that are attached to this nsid

``__u16 cntid``
  *undescribed*

``struct nvme_ctrl_list * ctrlist``
  *undescribed*

**Description**

Up to 2047 controller identifiers is returned containing a controller
identifier greater than or equal to the controller identifier  specified in
**cntid**.

See :c:type:`struct nvme_ctrl_list <nvme_ctrl_list>` for a definition of the structure returned.

**Return**

The nvme command status if a response was received or -1


.. c:function:: int nvme_identify_ns_descs (int fd, __u32 nsid, struct nvme_ns_id_desc * descs)

   Retrieves namespace descriptor list

**Parameters**

``int fd``
  File descriptor of nvme device

``__u32 nsid``
  The namespace id to retrieve destriptors

``struct nvme_ns_id_desc * descs``
  User space destination address to transfer the data

**Description**

A list of Namespace Identification Descriptor structures is returned to the
host for the namespace specified in the Namespace Identifier (NSID) field if
it is an active NSID.

The data returned is in the form of an arrray of 'struct nvme_ns_id_desc'.

See :c:type:`struct nvme_ns_id_desc <nvme_ns_id_desc>` for the definition of the returned structure.

**Return**

The nvme command status if a response was received or -1 with errno
        set otherwise.


.. c:function:: int nvme_identify_nvmset_list (int fd, __u16 nvmsetid, struct nvme_id_nvmset_list * nvmset)

   Retrieves NVM Set List

**Parameters**

``int fd``
  File descriptor of nvme device

``__u16 nvmsetid``
  *undescribed*

``struct nvme_id_nvmset_list * nvmset``
  User space destination address to transfer the data

**Description**

Retrieves an NVM Set List, struct nvme_id_nvmset. The data structure is an
ordered list by NVM Set Identifier, starting with the first NVM Set
Identifier supported by the NVM subsystem that is equal to or greater than
the NVM Set Identifier.

See :c:type:`struct nvme_id_nvmset_list <nvme_id_nvmset_list>` for the defintion of the returned structure.

**Return**

The nvme command status if a response was received or -1 with errno
        set otherwise.


.. c:function:: int nvme_identify_primary_ctrl (int fd, __u16 cntid, struct nvme_primary_ctrl_cap * cap)

   Retrieve NVMe Primary Controller identification :c:type:`fd`:

**Parameters**

``int fd``
  *undescribed*

``__u16 cntid``
  *undescribed*

``struct nvme_primary_ctrl_cap * cap``

**Description**

See :c:type:`struct nvme_primary_ctrl_cap <nvme_primary_ctrl_cap>` for the defintion of the returned structure, **cap**.

**Return**

The nvme command status if a response was received or -1
        with errno set otherwise.


.. c:function:: int nvme_identify_secondary_ctrl_list (int fd, __u16 cntid, struct nvme_secondary_ctrl_list * list)

   Retrieves secondary controller list

**Parameters**

``int fd``
  File descriptor of nvme device

``__u16 cntid``
  Return controllers starting at this identifier

``struct nvme_secondary_ctrl_list * list``
  *undescribed*

**Description**

A Secondary Controller List is returned to the host for up to 127 secondary
controllers associated with the primary controller processing this command.
The list contains entries for controller identifiers greater than or equal
to the value specified in the Controller Identifier (cntid).

See :c:type:`struct nvme_secondary_ctrls_list <nvme_secondary_ctrls_list>` for a defintion of the returned
structure.

**Return**

The nvme command status if a response was received or -1 with errno
        set otherwise.


.. c:function:: int nvme_identify_ns_granularity (int fd, struct nvme_id_ns_granularity_list * list)

   Retrieves namespace granularity identification

**Parameters**

``int fd``
  File descriptor of nvme device

``struct nvme_id_ns_granularity_list * list``
  *undescribed*

**Description**

If the controller supports reporting of Namespace Granularity, then a
Namespace Granularity List is returned to the host for up to sixteen
namespace granularity descriptors

See :c:type:`struct nvme_id_ns_granularity_list <nvme_id_ns_granularity_list>` for the definition of the returned
structure.

**Return**

The nvme command status if a response was received or -1 with errno
        set otherwise.


.. c:function:: int nvme_identify_uuid (int fd, struct nvme_id_uuid_list * list)

   Retrieves device's UUIDs

**Parameters**

``int fd``
  File descriptor of nvme device

``struct nvme_id_uuid_list * list``
  *undescribed*

**Description**

Each UUID List entry is either 0h, the NVMe Invalid UUID, or a valid UUID.
Valid UUIDs are those which are non-zero and are not the NVMe Invalid UUID.

See :c:type:`struct nvme_id_uuid_list <nvme_id_uuid_list>` for the definition of the returned structure.

**Return**

The nvme command status if a response was received or -1 with errno
        set otherwise.


.. c:function:: int nvme_get_log (int fd, enum nvme_cmd_get_log_lid lid, __u32 nsid, __u64 lpo, __u8 lsp, __u16 lsi, bool rae, __u8 uuidx, __u32 len, void * log)

   NVMe Admin Get Log command

**Parameters**

``int fd``
  File descriptor of nvme device

``enum nvme_cmd_get_log_lid lid``
  Log page identifier, see :c:type:`enum nvme_cmd_get_log_lid <nvme_cmd_get_log_lid>` for known values

``__u32 nsid``
  Namespace identifier, if applicable

``__u64 lpo``
  Log page offset for partial log transfers

``__u8 lsp``
  Log specific field

``__u16 lsi``
  Endurance group information

``bool rae``
  Retain asynchronous events

``__u8 uuidx``
  UUID selection, if supported

``__u32 len``
  Length of provided user buffer to hold the log data in bytes

``void * log``
  User space destination address to transfer the data

**Return**

The nvme command status if a response was received or -1 with errno
        set otherwise.


.. c:function:: int nvme_get_log_error (int fd, unsigned nr_entries, bool rae, struct nvme_error_log_page * log)

   Retrieve nvme error log

**Parameters**

``int fd``
  File descriptor of nvme device

``unsigned nr_entries``
  *undescribed*

``bool rae``
  Retain asynchronous events

``struct nvme_error_log_page * log``
  *undescribed*

**Description**

This log page is used to describe extended error information for a command
that completed with error, or may report an error that is not specific to a
particular command.

**Return**

The nvme command status if a response was received or -1 with errno
        set otherwise.


.. c:function:: int nvme_get_log_smart (int fd, __u32 nsid, bool rae, struct nvme_smart_log * log)

   Retrieve nvme smart log

**Parameters**

``int fd``
  File descriptor of nvme device

``__u32 nsid``
  Optional namespace identifier

``bool rae``
  Retain asynchronous events

``struct nvme_smart_log * log``
  *undescribed*

**Description**

This log page is used to provide SMART and general health information. The
information provided is over the life of the controller and is retained
across power cycles. To request the controller log page, the namespace
identifier specified is FFFFFFFFh. The controller may also support
requesting the log page on a per namespace basis, as indicated by bit 0 of
the LPA field in the Identify Controller data structure.

**Return**

The nvme command status if a response was received or -1 with errno
        set otherwise.


.. c:function:: int nvme_get_log_fw_slot (int fd, bool rae, struct nvme_firmware_slot * log)

   Retrieves the controller firmware log

**Parameters**

``int fd``
  File descriptor of nvme device

``bool rae``
  Retain asynchronous events

``struct nvme_firmware_slot * log``
  *undescribed*

**Description**

This log page is used to describe the firmware revision stored in each
firmware slot supported. The firmware revision is indicated as an ASCII
string. The log page also indicates the active slot number.

**Return**

The nvme command status if a response was received or -1 with errno
        set otherwise.


.. c:function:: int nvme_get_log_changed_ns_list (int fd, bool rae, struct nvme_ns_list * log)

   Retrieve namespace changed list

**Parameters**

``int fd``
  File descriptor of nvme device

``bool rae``
  Retain asynchronous events

``struct nvme_ns_list * log``
  *undescribed*

**Description**

This log page is used to describe namespaces attached to this controller
that have changed since the last time the namespace was identified, been
added, or deleted.

**Return**

The nvme command status if a response was received or -1 with errno
        set otherwise.


.. c:function:: int nvme_get_log_cmd_effects (int fd, struct nvme_cmd_effects_log * log)

   Retrieve nvme command effects log

**Parameters**

``int fd``
  File descriptor of nvme device

``struct nvme_cmd_effects_log * log``
  *undescribed*

**Description**

This log page is used to describe the commands that the controller supports
and the effects of those commands on the state of the NVM subsystem.

**Return**

The nvme command status if a response was received or -1 with errno
        set otherwise.


.. c:function:: int nvme_get_log_device_self_test (int fd, struct nvme_self_test_log * log)

   Retrieve the device self test log

**Parameters**

``int fd``
  File descriptor of nvme device

``struct nvme_self_test_log * log``
  Userspace address of the log payload

**Description**

The log page is used to indicate the status of an in progress self test and
the percent complete of that operation, and the results of the previous 20
self-test operations.

**Return**

The nvme command status if a response was received or -1 with errno
        set otherwise.


.. c:function:: int nvme_get_log_create_telemetry_host (int fd, struct nvme_telemetry_log * log)


**Parameters**

``int fd``
  *undescribed*

``struct nvme_telemetry_log * log``
  *undescribed*


.. c:function:: int nvme_get_log_telemetry_host (int fd, __u64 offset, __u32 len, void * log)


**Parameters**

``int fd``
  File descriptor of nvme device

``__u64 offset``
  Offset into the telemetry data

``__u32 len``
  Length of provided user buffer to hold the log data in bytes

``void * log``
  User address for log page data

**Description**

Retreives the Telemetry Host-Initiated log page at the requested offset
using the previously existing capture.

**Return**

The nvme command status if a response was received or -1 with errno
        set otherwise.


.. c:function:: int nvme_get_log_telemetry_ctrl (int fd, bool rae, __u64 offset, __u32 len, void * log)


**Parameters**

``int fd``
  File descriptor of nvme device

``bool rae``
  Retain asynchronous events

``__u64 offset``
  Offset into the telemetry data

``__u32 len``
  Length of provided user buffer to hold the log data in bytes

``void * log``
  User address for log page data


.. c:function:: int nvme_get_log_endurance_group (int fd, __u16 endgid, struct nvme_endurance_group_log * log)


**Parameters**

``int fd``
  File descriptor of nvme device

``__u16 endgid``
  Starting group identifier to return in the list

``struct nvme_endurance_group_log * log``
  User address to store the endurance log

**Description**

This log page indicates if an Endurance Group Event has occurred for a
particular Endurance Group. If an Endurance Group Event has occurred, the
details of the particular event are included in the Endurance Group
Information log page for that Endurance Group. An asynchronous event is
generated when an entry for an Endurance Group is newly added to this log
page.

**Return**

The nvme command status if a response was received or -1 with errno
        set otherwise.


.. c:function:: int nvme_get_log_predictable_lat_nvmset (int fd, __u16 nvmsetid, struct nvme_nvmset_predictable_lat_log * log)


**Parameters**

``int fd``
  *undescribed*

``__u16 nvmsetid``

``struct nvme_nvmset_predictable_lat_log * log``
  *undescribed*

**Return**

The nvme command status if a response was received or -1 with errno
        set otherwise.


.. c:function:: int nvme_get_log_predictable_lat_event (int fd, bool rae, __u32 offset, __u32 len, void * log)


**Parameters**

``int fd``
  File descriptor of nvme device

``bool rae``
  Retain asynchronous events

``__u32 offset``
  *undescribed*

``__u32 len``
  *undescribed*

``void * log``
  *undescribed*


.. c:function:: int nvme_get_log_ana (int fd, enum nvme_log_ana_lsp lsp, bool rae, __u64 offset, __u32 len, void * log)


**Parameters**

``int fd``
  File descriptor of nvme device

``enum nvme_log_ana_lsp lsp``
  Log specific, see :c:type:`enum nvme_get_log_ana_lsp <nvme_get_log_ana_lsp>`

``bool rae``
  Retain asynchronous events

``__u64 offset``
  *undescribed*

``__u32 len``
  The allocated length of the log page

``void * log``
  User address to store the ana log

**Description**

This log consists of a header describing the log and descriptors containing
the asymmetric namespace access information for ANA Groups that contain
namespaces that are attached to the controller processing the command.

See :c:type:`struct nvme_ana_rsp_hdr <nvme_ana_rsp_hdr>` for the defintion of the returned structure.

**Return**

The nvme command status if a response was received or -1 with errno
        set otherwise.


.. c:function:: int nvme_get_log_ana_groups (int fd, bool rae, __u32 len, struct nvme_ana_group_desc * log)


**Parameters**

``int fd``
  File descriptor of nvme device

``bool rae``
  Retain asynchronous events

``__u32 len``
  *undescribed*

``struct nvme_ana_group_desc * log``
  *undescribed*

**Description**

See :c:type:`struct nvme_ana_group_desc <nvme_ana_group_desc>` for the defintion of the returned structure.


.. c:function:: int nvme_get_log_lba_status (int fd, bool rae, __u64 offset, __u32 len, void * log)


**Parameters**

``int fd``
  File descriptor of nvme device

``bool rae``
  Retain asynchronous events

``__u64 offset``
  *undescribed*

``__u32 len``
  *undescribed*

``void * log``
  *undescribed*


.. c:function:: int nvme_get_log_endurance_grp_evt (int fd, bool rae, __u32 offset, __u32 len, void * log)


**Parameters**

``int fd``
  File descriptor of nvme device

``bool rae``
  Retain asynchronous events

``__u32 offset``
  *undescribed*

``__u32 len``
  *undescribed*

``void * log``
  *undescribed*


.. c:function:: int nvme_get_log_discovery (int fd, bool rae, __u32 offset, __u32 len, void * log)


**Parameters**

``int fd``
  File descriptor of nvme device

``bool rae``
  Retain asynchronous events

``__u32 offset``
  Offset of this log to retrieve

``__u32 len``
  The allocated size for this portion of the log

``void * log``
  User address to store the discovery log

**Description**

Supported only by fabrics discovery controllers, returning discovery
records.

**Return**

The nvme command status if a response was received or -1 with errno
        set otherwise.


.. c:function:: int nvme_get_log_reservation (int fd, bool rae, struct nvme_resv_notification_log * log)


**Parameters**

``int fd``
  File descriptor of nvme device

``bool rae``
  Retain asynchronous events

``struct nvme_resv_notification_log * log``
  *undescribed*


.. c:function:: int nvme_get_log_sanitize (int fd, bool rae, struct nvme_sanitize_log_page * log)


**Parameters**

``int fd``
  File descriptor of nvme device

``bool rae``
  Retain asynchronous events

``struct nvme_sanitize_log_page * log``
  User address to store the sanitize log

**Description**

The Sanitize Status log page is used to report sanitize operation time
estimates and information about the most recent sanitize operation.

**Return**

The nvme command status if a response was received or -1 with errno
        set otherwise.


.. c:function:: int nvme_set_features (int fd, __u8 fid, __u32 nsid, __u32 cdw11, __u32 cdw12, bool save, __u8 uuidx, __u32 cdw15, __u32 data_len, void * data, __u32 * result)

   Set a feature attribute

**Parameters**

``int fd``
  File descriptor of nvme device

``__u8 fid``
  Feature identifier

``__u32 nsid``
  Namespace ID, if applicable

``__u32 cdw11``
  Value to set the feature to

``__u32 cdw12``
  Feature specific command dword12 field

``bool save``
  Save value across power states

``__u8 uuidx``
  UUID Index for differentiating vendor specific encoding

``__u32 cdw15``
  *undescribed*

``__u32 data_len``
  Length of feature data, if applicable, in bytes

``void * data``
  User address of feature data, if applicable

``__u32 * result``
  The command completion result from CQE dword0

**Return**

The nvme command status if a response was received or -1 with errno
        set otherwise.


.. c:function:: int nvme_set_features_arbitration (int fd, __u8 ab, __u8 lpw, __u8 mpw, __u8 hpw, bool save, __u32 * result)


**Parameters**

``int fd``
  File descriptor of nvme device

``__u8 ab``
  *undescribed*

``__u8 lpw``
  *undescribed*

``__u8 mpw``
  *undescribed*

``__u8 hpw``
  *undescribed*

``bool save``
  Save value across power states

``__u32 * result``
  The command completion result from CQE dword0

**Return**

The nvme command status if a response was received or -1 with errno
        set otherwise.


.. c:function:: int nvme_set_features_power_mgmt (int fd, __u8 ps, __u8 wh, bool save, __u32 * result)


**Parameters**

``int fd``
  File descriptor of nvme device

``__u8 ps``
  *undescribed*

``__u8 wh``
  *undescribed*

``bool save``
  Save value across power states

``__u32 * result``
  The command completion result from CQE dword0

**Return**

The nvme command status if a response was received or -1 with errno
        set otherwise.


.. c:function:: int nvme_set_features_lba_range (int fd, __u32 nsid, __u32 nr_ranges, bool save, struct nvme_lba_range_type * data, __u32 * result)


**Parameters**

``int fd``
  File descriptor of nvme device

``__u32 nsid``
  *undescribed*

``__u32 nr_ranges``
  *undescribed*

``bool save``
  Save value across power states

``struct nvme_lba_range_type * data``
  *undescribed*

``__u32 * result``
  The command completion result from CQE dword0

**Return**

The nvme command status if a response was received or -1 with errno
        set otherwise.




.. c:type:: enum nvme_feat_tmpthresh_thsel


**Constants**

``NVME_FEATURE_TEMPTHRESH_THSEL_OVER``
  *undescribed*

``NVME_FEATURETEMPTHRESH__THSEL_UNDER``
  *undescribed*


.. c:function:: int nvme_set_features_temp_thresh (int fd, __u16 tmpth, __u8 tmpsel, enum nvme_feat_tmpthresh_thsel thsel, bool save, __u32 * result)


**Parameters**

``int fd``
  File descriptor of nvme device

``__u16 tmpth``
  *undescribed*

``__u8 tmpsel``
  *undescribed*

``enum nvme_feat_tmpthresh_thsel thsel``
  *undescribed*

``bool save``
  Save value across power states

``__u32 * result``
  The command completion result from CQE dword0

**Return**

The nvme command status if a response was received or -1 with errno
        set otherwise.


.. c:function:: int nvme_set_features_err_recovery (int fd, __u32 nsid, __u16 tler, bool dulbe, bool save, __u32 * result)


**Parameters**

``int fd``
  File descriptor of nvme device

``__u32 nsid``
  *undescribed*

``__u16 tler``
  *undescribed*

``bool dulbe``
  *undescribed*

``bool save``
  Save value across power states

``__u32 * result``
  The command completion result from CQE dword0

**Return**

The nvme command status if a response was received or -1 with errno
        set otherwise.


.. c:function:: int nvme_set_features_volatile_wc (int fd, bool wce, bool save, __u32 * result)


**Parameters**

``int fd``
  File descriptor of nvme device

``bool wce``
  *undescribed*

``bool save``
  Save value across power states

``__u32 * result``
  The command completion result from CQE dword0

**Return**

The nvme command status if a response was received or -1 with errno
        set otherwise.


.. c:function:: int nvme_set_features_irq_coalesce (int fd, __u8 thr, __u8 time, bool save, __u32 * result)


**Parameters**

``int fd``
  File descriptor of nvme device

``__u8 thr``
  *undescribed*

``__u8 time``
  *undescribed*

``bool save``
  Save value across power states

``__u32 * result``
  The command completion result from CQE dword0

**Return**

The nvme command status if a response was received or -1 with errno
        set otherwise.


.. c:function:: int nvme_set_features_irq_config (int fd, __u16 iv, bool cd, bool save, __u32 * result)


**Parameters**

``int fd``
  File descriptor of nvme device

``__u16 iv``
  *undescribed*

``bool cd``
  *undescribed*

``bool save``
  Save value across power states

``__u32 * result``
  The command completion result from CQE dword0

**Return**

The nvme command status if a response was received or -1 with errno
        set otherwise.


.. c:function:: int nvme_set_features_write_atomic (int fd, bool dn, bool save, __u32 * result)


**Parameters**

``int fd``
  File descriptor of nvme device

``bool dn``
  *undescribed*

``bool save``
  Save value across power states

``__u32 * result``
  The command completion result from CQE dword0

**Return**

The nvme command status if a response was received or -1 with errno
        set otherwise.




.. c:type:: enum nvme_features_async_event_config_flags


**Constants**

``NVME_FEATURE_AENCFG_SMART_CRIT_SPARE``
  *undescribed*

``NVME_FEATURE_AENCFG_SMART_CRIT_TEMPERATURE``
  *undescribed*

``NVME_FEATURE_AENCFG_SMART_CRIT_DEGRADED``
  *undescribed*

``NVME_FEATURE_AENCFG_SMART_CRIT_READ_ONLY``
  *undescribed*

``NVME_FEATURE_AENCFG_SMART_CRIT_VOLATILE_BACKUP``
  *undescribed*

``NVME_FEATURE_AENCFG_SMART_CRIT_READ_ONLY_PMR``
  *undescribed*

``NVME_FEATURE_AENCFG_NOTICE_NAMESPACE_ATTRIBUTES``
  *undescribed*

``NVME_FEATURE_AENCFG_NOTICE_FIRMWARE_ACTIVATION``
  *undescribed*

``NVME_FEATURE_AENCFG_NOTICE_TELEMETRY_LOG``
  *undescribed*

``NVME_FEATURE_AENCFG_NOTICE_ANA_CHANGE``
  *undescribed*

``NVME_FEATURE_AENCFG_NOTICE_PL_EVENT``
  *undescribed*

``NVME_FEATURE_AENCFG_NOTICE_LBA_STATUS``
  *undescribed*

``NVME_FEATURE_AENCFG_NOTICE_EG_EVENT``
  *undescribed*

``NVME_FEATURE_AENCFG_NOTICE_DISCOVERY_CHANGE``
  *undescribed*


.. c:function:: int nvme_set_features_async_event (int fd, __u32 events, bool save, __u32 * result)


**Parameters**

``int fd``
  File descriptor of nvme device

``__u32 events``
  *undescribed*

``bool save``
  Save value across power states

``__u32 * result``
  The command completion result from CQE dword0

**Return**

The nvme command status if a response was received or -1 with errno
        set otherwise.


.. c:function:: int nvme_set_features_auto_pst (int fd, bool apste, bool save, struct nvme_feat_auto_pst * apst, __u32 * result)


**Parameters**

``int fd``
  File descriptor of nvme device

``bool apste``
  *undescribed*

``bool save``
  Save value across power states

``struct nvme_feat_auto_pst * apst``
  *undescribed*

``__u32 * result``
  The command completion result from CQE dword0

**Return**

The nvme command status if a response was received or -1 with errno
        set otherwise.


.. c:function:: int nvme_set_features_timestamp (int fd, bool save, __u64 timestamp)


**Parameters**

``int fd``
  File descriptor of nvme device

``bool save``
  Save value across power states

``__u64 timestamp``
  The current timestamp value to assign to this this feature

**Return**

The nvme command status if a response was received or -1 with errno
        set otherwise.


.. c:function:: int nvme_set_features_hctm (int fd, __u16 tmt2, __u16 tmt1, bool save, __u32 * result)


**Parameters**

``int fd``
  File descriptor of nvme device

``__u16 tmt2``
  *undescribed*

``__u16 tmt1``
  *undescribed*

``bool save``
  Save value across power states

``__u32 * result``
  The command completion result from CQE dword0

**Return**

The nvme command status if a response was received or -1 with errno
        set otherwise.


.. c:function:: int nvme_set_features_nopsc (int fd, bool noppme, bool save, __u32 * result)


**Parameters**

``int fd``
  *undescribed*

``bool noppme``
  *undescribed*

``bool save``
  *undescribed*

``__u32 * result``
  *undescribed*


.. c:function:: int nvme_set_features_rrl (int fd, __u8 rrl, __u16 nvmsetid, bool save, __u32 * result)


**Parameters**

``int fd``
  File descriptor of nvme device

``__u8 rrl``
  *undescribed*

``__u16 nvmsetid``
  *undescribed*

``bool save``
  Save value across power states

``__u32 * result``
  The command completion result from CQE dword0

**Return**

The nvme command status if a response was received or -1 with errno
        set otherwise.


.. c:function:: int nvme_set_features_plm_config (int fd, bool enable, __u16 nvmsetid, bool save, struct nvme_plm_config * data, __u32 * result)


**Parameters**

``int fd``
  File descriptor of nvme device

``bool enable``
  *undescribed*

``__u16 nvmsetid``
  *undescribed*

``bool save``
  Save value across power states

``struct nvme_plm_config * data``
  *undescribed*

``__u32 * result``
  The command completion result from CQE dword0

**Return**

The nvme command status if a response was received or -1 with errno
        set otherwise.




.. c:type:: enum nvme_feat_plm_window_select


**Constants**

``NVME_FEATURE_PLM_DTWIN``
  *undescribed*

``NVME_FEATURE_PLM_NDWIN``
  *undescribed*


.. c:function:: int nvme_set_features_plm_window (int fd, enum nvme_feat_plm_window_select sel, __u16 nvmsetid, bool save, __u32 * result)


**Parameters**

``int fd``
  File descriptor of nvme device

``enum nvme_feat_plm_window_select sel``
  *undescribed*

``__u16 nvmsetid``
  *undescribed*

``bool save``
  Save value across power states

``__u32 * result``
  The command completion result from CQE dword0

**Return**

The nvme command status if a response was received or -1 with errno
        set otherwise.


.. c:function:: int nvme_set_features_lba_sts_interval (int fd, __u16 lsiri, __u16 lsipi, bool save, __u32 * result)


**Parameters**

``int fd``
  File descriptor of nvme device

``__u16 lsiri``
  *undescribed*

``__u16 lsipi``
  *undescribed*

``bool save``
  Save value across power states

``__u32 * result``
  The command completion result from CQE dword0

**Return**

The nvme command status if a response was received or -1 with errno
        set otherwise.


.. c:function:: int nvme_set_features_host_behavior (int fd, bool save, struct nvme_feat_host_behavior * data)


**Parameters**

``int fd``
  File descriptor of nvme device

``bool save``
  Save value across power states

``struct nvme_feat_host_behavior * data``
  *undescribed*

**Return**

The nvme command status if a response was received or -1 with errno
        set otherwise.


.. c:function:: int nvme_set_features_sanitize (int fd, bool nodrm, bool save, __u32 * result)


**Parameters**

``int fd``
  File descriptor of nvme device

``bool nodrm``
  *undescribed*

``bool save``
  Save value across power states

``__u32 * result``
  The command completion result from CQE dword0

**Return**

The nvme command status if a response was received or -1 with errno
        set otherwise.


.. c:function:: int nvme_set_features_endurance_evt_cfg (int fd, __u16 endgid, __u8 egwarn, bool save, __u32 * result)


**Parameters**

``int fd``
  File descriptor of nvme device

``__u16 endgid``
  *undescribed*

``__u8 egwarn``
  Flags to enable warning, see :c:type:`enum nvme_eg_critical_warning_flags <nvme_eg_critical_warning_flags>`

``bool save``
  Save value across power states

``__u32 * result``
  The command completion result from CQE dword0

**Return**

The nvme command status if a response was received or -1 with errno
        set otherwise.


.. c:function:: int nvme_set_features_sw_progress (int fd, __u8 pbslc, bool save, __u32 * result)


**Parameters**

``int fd``
  File descriptor of nvme device

``__u8 pbslc``
  *undescribed*

``bool save``
  Save value across power states

``__u32 * result``
  The command completion result from CQE dword0

**Return**

The nvme command status if a response was received or -1 with errno
        set otherwise.


.. c:function:: int nvme_set_features_host_id (int fd, bool exhid, bool save, __u8 * hostid)


**Parameters**

``int fd``
  File descriptor of nvme device

``bool exhid``
  *undescribed*

``bool save``
  Save value across power states

``__u8 * hostid``
  *undescribed*

**Return**

The nvme command status if a response was received or -1 with errno
        set otherwise.


.. c:function:: int nvme_set_features_resv_mask (int fd, __u32 mask, bool save, __u32 * result)


**Parameters**

``int fd``
  File descriptor of nvme device

``__u32 mask``
  *undescribed*

``bool save``
  Save value across power states

``__u32 * result``
  The command completion result from CQE dword0

**Return**

The nvme command status if a response was received or -1 with errno
        set otherwise.


.. c:function:: int nvme_set_features_resv_persist (int fd, bool ptpl, bool save, __u32 * result)


**Parameters**

``int fd``
  File descriptor of nvme device

``bool ptpl``
  *undescribed*

``bool save``
  Save value across power states

``__u32 * result``
  The command completion result from CQE dword0

**Return**

The nvme command status if a response was received or -1 with errno
        set otherwise.




.. c:type:: enum nvme_feat_nswpcfg_state


**Constants**

``NVME_FEAT_NS_NO_WRITE_PROTECT``
  *undescribed*

``NVME_FEAT_NS_WRITE_PROTECT``
  *undescribed*

``NVME_FEAT_NS_WRITE_PROTECT_PWR_CYCLE``
  *undescribed*

``NVME_FEAT_NS_WRITE_PROTECT_PERMANENT``
  *undescribed*


.. c:function:: int nvme_set_features_write_protect (int fd, enum nvme_feat_nswpcfg_state state, bool save, __u32 * result)


**Parameters**

``int fd``
  File descriptor of nvme device

``enum nvme_feat_nswpcfg_state state``
  *undescribed*

``bool save``
  Save value across power states

``__u32 * result``
  The command completion result from CQE dword0

**Return**

The nvme command status if a response was received or -1 with errno
        set otherwise.


.. c:function:: int nvme_get_features (int fd, enum nvme_features_id fid, __u32 nsid, enum nvme_get_features_sel sel, __u32 cdw11, __u8 uuidx, __u32 data_len, void * data, __u32 * result)

   Retrieve a feature attribute

**Parameters**

``int fd``
  File descriptor of nvme device

``enum nvme_features_id fid``
  Feature identifier

``__u32 nsid``
  Namespace ID, if applicable

``enum nvme_get_features_sel sel``
  Select which type of attribute to return, see :c:type:`enum nvme_get_features_sel <nvme_get_features_sel>`

``__u32 cdw11``
  Feature specific command dword11 field

``__u8 uuidx``
  UUID Index for differentiating vendor specific encoding

``__u32 data_len``
  Length of feature data, if applicable, in bytes

``void * data``
  User address of feature data, if applicable

``__u32 * result``
  The command completion result from CQE dword0

**Return**

The nvme command status if a response was received or -1 with errno
        set otherwise.


.. c:function:: int nvme_get_features_arbitration (int fd, enum nvme_get_features_sel sel, __u32 * result)


**Parameters**

``int fd``
  File descriptor of nvme device

``enum nvme_get_features_sel sel``
  Select which type of attribute to return, see :c:type:`enum nvme_get_features_sel <nvme_get_features_sel>`

``__u32 * result``
  The command completion result from CQE dword0

**Return**

The nvme command status if a response was received or -1 with errno
        set otherwise.


.. c:function:: int nvme_get_features_power_mgmt (int fd, enum nvme_get_features_sel sel, __u32 * result)


**Parameters**

``int fd``
  File descriptor of nvme device

``enum nvme_get_features_sel sel``
  Select which type of attribute to return, see :c:type:`enum nvme_get_features_sel <nvme_get_features_sel>`

``__u32 * result``
  The command completion result from CQE dword0

**Return**

The nvme command status if a response was received or -1 with errno
        set otherwise.


.. c:function:: int nvme_get_features_lba_range (int fd, enum nvme_get_features_sel sel, struct nvme_lba_range_type * data, __u32 * result)


**Parameters**

``int fd``
  File descriptor of nvme device

``enum nvme_get_features_sel sel``
  Select which type of attribute to return, see :c:type:`enum nvme_get_features_sel <nvme_get_features_sel>`

``struct nvme_lba_range_type * data``
  *undescribed*

``__u32 * result``
  The command completion result from CQE dword0

**Return**

The nvme command status if a response was received or -1 with errno
        set otherwise.


.. c:function:: int nvme_get_features_temp_thresh (int fd, enum nvme_get_features_sel sel, __u32 * result)


**Parameters**

``int fd``
  File descriptor of nvme device

``enum nvme_get_features_sel sel``
  Select which type of attribute to return, see :c:type:`enum nvme_get_features_sel <nvme_get_features_sel>`

``__u32 * result``
  The command completion result from CQE dword0

**Return**

The nvme command status if a response was received or -1 with errno
        set otherwise.


.. c:function:: int nvme_get_features_err_recovery (int fd, enum nvme_get_features_sel sel, __u32 * result)


**Parameters**

``int fd``
  File descriptor of nvme device

``enum nvme_get_features_sel sel``
  Select which type of attribute to return, see :c:type:`enum nvme_get_features_sel <nvme_get_features_sel>`

``__u32 * result``
  The command completion result from CQE dword0

**Return**

The nvme command status if a response was received or -1 with errno
        set otherwise.


.. c:function:: int nvme_get_features_volatile_wc (int fd, enum nvme_get_features_sel sel, __u32 * result)


**Parameters**

``int fd``
  File descriptor of nvme device

``enum nvme_get_features_sel sel``
  Select which type of attribute to return, see :c:type:`enum nvme_get_features_sel <nvme_get_features_sel>`

``__u32 * result``
  The command completion result from CQE dword0

**Return**

The nvme command status if a response was received or -1 with errno
        set otherwise.


.. c:function:: int nvme_get_features_num_queues (int fd, enum nvme_get_features_sel sel, __u32 * result)


**Parameters**

``int fd``
  File descriptor of nvme device

``enum nvme_get_features_sel sel``
  Select which type of attribute to return, see :c:type:`enum nvme_get_features_sel <nvme_get_features_sel>`

``__u32 * result``
  The command completion result from CQE dword0

**Return**

The nvme command status if a response was received or -1 with errno
        set otherwise.


.. c:function:: int nvme_get_features_irq_coalesce (int fd, enum nvme_get_features_sel sel, __u32 * result)


**Parameters**

``int fd``
  File descriptor of nvme device

``enum nvme_get_features_sel sel``
  Select which type of attribute to return, see :c:type:`enum nvme_get_features_sel <nvme_get_features_sel>`

``__u32 * result``
  The command completion result from CQE dword0

**Return**

The nvme command status if a response was received or -1 with errno
        set otherwise.


.. c:function:: int nvme_get_features_irq_config (int fd, enum nvme_get_features_sel sel, __u16 iv, __u32 * result)


**Parameters**

``int fd``
  File descriptor of nvme device

``enum nvme_get_features_sel sel``
  Select which type of attribute to return, see :c:type:`enum nvme_get_features_sel <nvme_get_features_sel>`

``__u16 iv``
  *undescribed*

``__u32 * result``
  The command completion result from CQE dword0

**Return**

The nvme command status if a response was received or -1 with errno
        set otherwise.


.. c:function:: int nvme_get_features_write_atomic (int fd, enum nvme_get_features_sel sel, __u32 * result)


**Parameters**

``int fd``
  File descriptor of nvme device

``enum nvme_get_features_sel sel``
  Select which type of attribute to return, see :c:type:`enum nvme_get_features_sel <nvme_get_features_sel>`

``__u32 * result``
  The command completion result from CQE dword0

**Return**

The nvme command status if a response was received or -1 with errno
        set otherwise.


.. c:function:: int nvme_get_features_async_event (int fd, enum nvme_get_features_sel sel, __u32 * result)


**Parameters**

``int fd``
  File descriptor of nvme device

``enum nvme_get_features_sel sel``
  Select which type of attribute to return, see :c:type:`enum nvme_get_features_sel <nvme_get_features_sel>`

``__u32 * result``
  The command completion result from CQE dword0

**Return**

The nvme command status if a response was received or -1 with errno
        set otherwise.


.. c:function:: int nvme_get_features_auto_pst (int fd, enum nvme_get_features_sel sel, struct nvme_feat_auto_pst * apst, __u32 * result)


**Parameters**

``int fd``
  File descriptor of nvme device

``enum nvme_get_features_sel sel``
  Select which type of attribute to return, see :c:type:`enum nvme_get_features_sel <nvme_get_features_sel>`

``struct nvme_feat_auto_pst * apst``
  *undescribed*

``__u32 * result``
  The command completion result from CQE dword0

**Return**

The nvme command status if a response was received or -1 with errno
        set otherwise.


.. c:function:: int nvme_get_features_host_mem_buf (int fd, enum nvme_get_features_sel sel, __u32 * result)


**Parameters**

``int fd``
  File descriptor of nvme device

``enum nvme_get_features_sel sel``
  Select which type of attribute to return, see :c:type:`enum nvme_get_features_sel <nvme_get_features_sel>`

``__u32 * result``
  The command completion result from CQE dword0

**Return**

The nvme command status if a response was received or -1 with errno
        set otherwise.


.. c:function:: int nvme_get_features_timestamp (int fd, enum nvme_get_features_sel sel, struct nvme_timestamp * ts)


**Parameters**

``int fd``
  File descriptor of nvme device

``enum nvme_get_features_sel sel``
  Select which type of attribute to return, see :c:type:`enum nvme_get_features_sel <nvme_get_features_sel>`

``struct nvme_timestamp * ts``
  *undescribed*

**Return**

The nvme command status if a response was received or -1 with errno
        set otherwise.


.. c:function:: int nvme_get_features_kato (int fd, enum nvme_get_features_sel sel, __u32 * result)


**Parameters**

``int fd``
  File descriptor of nvme device

``enum nvme_get_features_sel sel``
  Select which type of attribute to return, see :c:type:`enum nvme_get_features_sel <nvme_get_features_sel>`

``__u32 * result``
  The command completion result from CQE dword0

**Return**

The nvme command status if a response was received or -1 with errno
        set otherwise.


.. c:function:: int nvme_get_features_hctm (int fd, enum nvme_get_features_sel sel, __u32 * result)


**Parameters**

``int fd``
  File descriptor of nvme device

``enum nvme_get_features_sel sel``
  Select which type of attribute to return, see :c:type:`enum nvme_get_features_sel <nvme_get_features_sel>`

``__u32 * result``
  The command completion result from CQE dword0

**Return**

The nvme command status if a response was received or -1 with errno
        set otherwise.


.. c:function:: int nvme_get_features_nopsc (int fd, enum nvme_get_features_sel sel, __u32 * result)


**Parameters**

``int fd``
  File descriptor of nvme device

``enum nvme_get_features_sel sel``
  Select which type of attribute to return, see :c:type:`enum nvme_get_features_sel <nvme_get_features_sel>`

``__u32 * result``
  The command completion result from CQE dword0

**Return**

The nvme command status if a response was received or -1 with errno
        set otherwise.


.. c:function:: int nvme_get_features_rrl (int fd, enum nvme_get_features_sel sel, __u32 * result)


**Parameters**

``int fd``
  File descriptor of nvme device

``enum nvme_get_features_sel sel``
  Select which type of attribute to return, see :c:type:`enum nvme_get_features_sel <nvme_get_features_sel>`

``__u32 * result``
  The command completion result from CQE dword0

**Return**

The nvme command status if a response was received or -1 with errno
        set otherwise.


.. c:function:: int nvme_get_features_plm_config (int fd, enum nvme_get_features_sel sel, __u16 nvmsetid, struct nvme_plm_config * data, __u32 * result)


**Parameters**

``int fd``
  File descriptor of nvme device

``enum nvme_get_features_sel sel``
  Select which type of attribute to return, see :c:type:`enum nvme_get_features_sel <nvme_get_features_sel>`

``__u16 nvmsetid``
  *undescribed*

``struct nvme_plm_config * data``
  *undescribed*

``__u32 * result``
  The command completion result from CQE dword0

**Return**

The nvme command status if a response was received or -1 with errno
        set otherwise.


.. c:function:: int nvme_get_features_plm_window (int fd, enum nvme_get_features_sel sel, __u16 nvmsetid, __u32 * result)


**Parameters**

``int fd``
  File descriptor of nvme device

``enum nvme_get_features_sel sel``
  Select which type of attribute to return, see :c:type:`enum nvme_get_features_sel <nvme_get_features_sel>`

``__u16 nvmsetid``
  *undescribed*

``__u32 * result``
  The command completion result from CQE dword0

**Return**

The nvme command status if a response was received or -1 with errno
        set otherwise.


.. c:function:: int nvme_get_features_lba_sts_interval (int fd, enum nvme_get_features_sel sel, __u32 * result)


**Parameters**

``int fd``
  File descriptor of nvme device

``enum nvme_get_features_sel sel``
  Select which type of attribute to return, see :c:type:`enum nvme_get_features_sel <nvme_get_features_sel>`

``__u32 * result``
  The command completion result from CQE dword0

**Return**

The nvme command status if a response was received or -1 with errno
        set otherwise.


.. c:function:: int nvme_get_features_host_behavior (int fd, enum nvme_get_features_sel sel, struct nvme_feat_host_behavior * data, __u32 * result)


**Parameters**

``int fd``
  File descriptor of nvme device

``enum nvme_get_features_sel sel``
  Select which type of attribute to return, see :c:type:`enum nvme_get_features_sel <nvme_get_features_sel>`

``struct nvme_feat_host_behavior * data``
  *undescribed*

``__u32 * result``
  The command completion result from CQE dword0

**Return**

The nvme command status if a response was received or -1 with errno
        set otherwise.


.. c:function:: int nvme_get_features_sanitize (int fd, enum nvme_get_features_sel sel, __u32 * result)


**Parameters**

``int fd``
  File descriptor of nvme device

``enum nvme_get_features_sel sel``
  Select which type of attribute to return, see :c:type:`enum nvme_get_features_sel <nvme_get_features_sel>`

``__u32 * result``
  The command completion result from CQE dword0

**Return**

The nvme command status if a response was received or -1 with errno
        set otherwise.


.. c:function:: int nvme_get_features_endurance_event_cfg (int fd, enum nvme_get_features_sel sel, __u16 endgid, __u32 * result)


**Parameters**

``int fd``
  File descriptor of nvme device

``enum nvme_get_features_sel sel``
  Select which type of attribute to return, see :c:type:`enum nvme_get_features_sel <nvme_get_features_sel>`

``__u16 endgid``
  *undescribed*

``__u32 * result``
  The command completion result from CQE dword0

**Return**

The nvme command status if a response was received or -1 with errno
        set otherwise.


.. c:function:: int nvme_get_features_sw_progress (int fd, enum nvme_get_features_sel sel, __u32 * result)


**Parameters**

``int fd``
  File descriptor of nvme device

``enum nvme_get_features_sel sel``
  Select which type of attribute to return, see :c:type:`enum nvme_get_features_sel <nvme_get_features_sel>`

``__u32 * result``
  The command completion result from CQE dword0

**Return**

The nvme command status if a response was received or -1 with errno
        set otherwise.


.. c:function:: int nvme_get_features_host_id (int fd, enum nvme_get_features_sel sel, bool exhid, __u32 len, __u8 * hostid)


**Parameters**

``int fd``
  File descriptor of nvme device

``enum nvme_get_features_sel sel``
  Select which type of attribute to return, see :c:type:`enum nvme_get_features_sel <nvme_get_features_sel>`

``bool exhid``
  *undescribed*

``__u32 len``
  *undescribed*

``__u8 * hostid``
  *undescribed*

**Return**

The nvme command status if a response was received or -1 with errno
        set otherwise.


.. c:function:: int nvme_get_features_resv_mask (int fd, enum nvme_get_features_sel sel, __u32 * result)


**Parameters**

``int fd``
  File descriptor of nvme device

``enum nvme_get_features_sel sel``
  Select which type of attribute to return, see :c:type:`enum nvme_get_features_sel <nvme_get_features_sel>`

``__u32 * result``
  The command completion result from CQE dword0

**Return**

The nvme command status if a response was received or -1 with errno
        set otherwise.


.. c:function:: int nvme_get_features_resv_persist (int fd, enum nvme_get_features_sel sel, __u32 * result)


**Parameters**

``int fd``
  File descriptor of nvme device

``enum nvme_get_features_sel sel``
  Select which type of attribute to return, see :c:type:`enum nvme_get_features_sel <nvme_get_features_sel>`

``__u32 * result``
  The command completion result from CQE dword0

**Return**

The nvme command status if a response was received or -1 with errno
        set otherwise.


.. c:function:: int nvme_get_features_write_protect (int fd, __u32 nsid, enum nvme_get_features_sel sel, __u32 * result)


**Parameters**

``int fd``
  File descriptor of nvme device

``__u32 nsid``
  Namespace ID

``enum nvme_get_features_sel sel``
  Select which type of attribute to return, see :c:type:`enum nvme_get_features_sel <nvme_get_features_sel>`

``__u32 * result``
  The command completion result from CQE dword0

**Return**

The nvme command status if a response was received or -1 with errno
        set otherwise.


.. c:function:: int nvme_format_nvm (int fd, __u32 nsid, __u8 lbaf, enum nvme_cmd_format_mset mset, enum nvme_cmd_format_pi pi, enum nvme_cmd_format_pil pil, enum nvme_cmd_format_ses ses, __u32 timeout)

   Format nvme namespace(s)

**Parameters**

``int fd``
  File descriptor of nvme device

``__u32 nsid``
  Namespace ID to format

``__u8 lbaf``
  Logical block address format

``enum nvme_cmd_format_mset mset``
  Metadata settings (extended or separated), true if extended

``enum nvme_cmd_format_pi pi``
  Protection information type

``enum nvme_cmd_format_pil pil``
  Protection information location (beginning or end), true if end

``enum nvme_cmd_format_ses ses``
  Secure erase settings

``__u32 timeout``
  Set to override default timeout to this value in milliseconds;
  useful for long running formats. 0 will use system default.

**Description**

The Format NVM command is used to low level format the NVM media. This
command is used by the host to change the LBA data size and/or metadata
size. A low level format may destroy all data and metadata associated with
all namespaces or only the specific namespace associated with the command

**Return**

The nvme command status if a response was received or -1 with errno
        set otherwise.


.. c:function:: int nvme_ns_mgmt (int fd, __u32 nsid, enum nvme_ns_mgmt_sel sel, struct nvme_id_ns * ns, __u32 * result, __u32 timeout)


**Parameters**

``int fd``
  File descriptor of nvme device

``__u32 nsid``
  *undescribed*

``enum nvme_ns_mgmt_sel sel``
  *undescribed*

``struct nvme_id_ns * ns``
  *undescribed*

``__u32 * result``
  *undescribed*

``__u32 timeout``
  *undescribed*


.. c:function:: int nvme_ns_mgmt_create (int fd, struct nvme_id_ns * ns, __u32 * nsid, __u32 timeout)


**Parameters**

``int fd``
  File descriptor of nvme device

``struct nvme_id_ns * ns``
  Namespace identifiaction that defines creation parameters

``__u32 * nsid``
  On success, set to the namespace id that was created

``__u32 timeout``
  Overide the default timeout to this value in milliseconds;
  set to 0 to use the system default.

**Description**

On successful creation, the namespace exists in the subsystem, but is not
attached to any controller. Use the nvme_ns_attach_ctrls() to assign the
namespace to one or more controllers.

**Return**

The nvme command status if a response was received or -1 with errno
        set otherwise.


.. c:function:: int nvme_ns_mgmt_delete (int fd, __u32 nsid)


**Parameters**

``int fd``
  File descriptor of nvme device

``__u32 nsid``
  Namespace identifier to delete

**Description**

It is recommended that a namespace being deleted is not attached to any
controller. Use the nvme_ns_detach_ctrls() first if the namespace is still
attached.

**Return**

The nvme command status if a response was received or -1 with errno
        set otherwise.


.. c:function:: int nvme_ns_attach (int fd, __u32 nsid, enum nvme_ns_attach_sel sel, struct nvme_ctrl_list * ctrlist)

   Attach or detach namespace to controller(s)

**Parameters**

``int fd``
  File descriptor of nvme device

``__u32 nsid``
  Namespace ID to execute attach selection

``enum nvme_ns_attach_sel sel``
  Attachment selection, see :c:type:`enum nvme_ns_attach_sel <nvme_ns_attach_sel>`

``struct nvme_ctrl_list * ctrlist``
  Controller list to modify attachment state of nsid


.. c:function:: int nvme_ns_attach_ctrls (int fd, __u32 nsid, struct nvme_ctrl_list * ctrlist)


**Parameters**

``int fd``
  File descriptor of nvme device

``__u32 nsid``
  Namespace ID to attach

``struct nvme_ctrl_list * ctrlist``
  Controller list to modify attachment state of nsid


.. c:function:: int nvme_ns_dettach_ctrls (int fd, __u32 nsid, struct nvme_ctrl_list * ctrlist)


**Parameters**

``int fd``
  File descriptor of nvme device

``__u32 nsid``
  Namespace ID to dettach

``struct nvme_ctrl_list * ctrlist``
  Controller list to modify attachment state of nsid


.. c:function:: int nvme_fw_download (int fd, __u32 offset, __u32 data_len, void * data)

   Download part or all of a firmware image to the controller

**Parameters**

``int fd``
  File descriptor of nvme device

``__u32 offset``
  Offset in the firmware data

``__u32 data_len``
  Length of data in this command in bytes

``void * data``
  Userspace address of the firmware data

**Description**

The Firmware Image Download command is used to download all or a portion of
an image for a future update to the controller. The Firmware Image Download
command downloads a new image (in whole or in part) to the controller.

The image may be constructed of multiple pieces that are individually
downloaded with separate Firmware Image Download commands. Each Firmware
Image Download command includes a Dword Offset and Number of Dwords that
specify a dword range.

The new firmware image is not activated as part of the Firmware Image
Download command. Use the nvme_fw_commit() to activate a newly downloaded
image.

**Return**

The nvme command status if a response was received or -1 with errno
        set otherwise.


.. c:function:: int nvme_fw_commit (int fd, __u8 slot, enum nvme_fw_commit_ca action, bool bpid)

   Commit firmware using the specified action

**Parameters**

``int fd``
  File descriptor of nvme device

``__u8 slot``
  Firmware slot to commit the downloaded image

``enum nvme_fw_commit_ca action``
  Action to use for the firmware image, see :c:type:`enum nvme_fw_commit_ca <nvme_fw_commit_ca>`

``bool bpid``
  Set to true to select the boot partition id

**Description**

The Firmware Commit command is used to modify the firmware image or Boot
Partitions.

**Return**

The nvme command status if a response was received or -1 with errno
        set otherwise. The command status response may specify additional
        reset actions required to complete the commit process.


.. c:function:: int nvme_security_send (int fd, __u32 nsid, __u8 nssf, __u8 spsp0, __u8 spsp1, __u8 secp, __u32 tl, __u32 data_len, void * data, __u32 * result)


**Parameters**

``int fd``
  File descriptor of nvme device

``__u32 nsid``
  Namespace ID to issue security command on

``__u8 nssf``
  NVMe Security Specific field

``__u8 spsp0``
  Security Protocol Specific field

``__u8 spsp1``
  Security Protocol Specific field

``__u8 secp``
  Security Protocol

``__u32 tl``
  Protocol specific transfer length

``__u32 data_len``
  Data length of the payload in bytes

``void * data``
  Security data payload to send

``__u32 * result``
  The command completion result from CQE dword0

**Description**

The Security Send command is used to transfer security protocol data to the
controller. The data structure transferred to the controller as part of this
command contains security protocol specific commands to be performed by the
controller. The data structure transferred may also contain data or
parameters associated with the security protocol commands.

The security data is protocol specific and is not defined by the NVMe
specification.

**Return**

The nvme command status if a response was received or -1 with errno
        set otherwise.


.. c:function:: int nvme_security_receive (int fd, __u32 nsid, __u8 nssf, __u8 spsp0, __u8 spsp1, __u8 secp, __u32 al, __u32 data_len, void * data, __u32 * result)


**Parameters**

``int fd``
  File descriptor of nvme device

``__u32 nsid``
  Namespace ID to issue security command on

``__u8 nssf``
  NVMe Security Specific field

``__u8 spsp0``
  Security Protocol Specific field

``__u8 spsp1``
  Security Protocol Specific field

``__u8 secp``
  Security Protocol

``__u32 al``
  Protocol specific allocation length

``__u32 data_len``
  Data length of the payload in bytes

``void * data``
  Security data payload to send

``__u32 * result``
  The command completion result from CQE dword0

**Return**

The nvme command status if a response was received or -1 with errno
        set otherwise.


.. c:function:: int nvme_get_lba_status (int fd, __u32 nsid, __u64 slba, __u32 mndw, __u16 rl, enum nvme_lba_status_atype atype, struct nvme_lba_status * lbas)

   Retrieve information on possibly unrecoverable LBAs

**Parameters**

``int fd``
  File descriptor of nvme device

``__u32 nsid``
  Namespace ID to retrieve LBA status

``__u64 slba``
  Starting logical block address to check statuses

``__u32 mndw``
  Maximum number of dwords to return

``__u16 rl``
  Range length from slba to perform the action

``enum nvme_lba_status_atype atype``
  Action type mechanism to determine LBA status desctriptors to
  return, see :c:type:`enum nvme_lba_status_atype <nvme_lba_status_atype>`

``struct nvme_lba_status * lbas``
  Data payload to return status descriptors

**Description**

The Get LBA Status command requests information about Potentially
Unrecoverable LBAs. Refer to the specification for action type descriptions.

**Return**

The nvme command status if a response was received or -1 with errno
        set otherwise.


.. c:function:: int nvme_directive_send (int fd, __u32 nsid, __u16 dspec, __u8 doper, enum nvme_directive_dtype dtype, __u32 cdw12, __u32 data_len, void * data, __u32 * result)

   Send directive command

**Parameters**

``int fd``
  File descriptor of nvme device

``__u32 nsid``
  Namespace ID, if applicable

``__u16 dspec``
  Directive specific field

``__u8 doper``
  Directive operation

``enum nvme_directive_dtype dtype``
  Directive type, see :c:type:`enum nvme_directive_dtype <nvme_directive_dtype>`

``__u32 cdw12``
  *undescribed*

``__u32 data_len``
  Length of data payload in bytes

``void * data``
  Usespace address of data payload

``__u32 * result``
  If successful, the CQE dword0 value

**Description**

Directives is a mechanism to enable host and NVM subsystem or controller
information exchange. The Directive Send command is used to transfer data
related to a specific Directive Type from the host to the controller.

See the NVMe specification for more information.

**Return**

The nvme command status if a response was received or -1 with errno
        set otherwise.


.. c:function:: int nvme_directive_send_id_endir (int fd, __u32 nsid, bool endir, enum nvme_directive_dtype dtype, struct nvme_id_directives * id)


**Parameters**

``int fd``
  File descriptor of nvme device

``__u32 nsid``
  Namespace ID

``bool endir``
  *undescribed*

``enum nvme_directive_dtype dtype``
  *undescribed*

``struct nvme_id_directives * id``
  *undescribed*

**Return**

The nvme command status if a response was received or -1 with errno
        set otherwise.


.. c:function:: int nvme_directive_send_stream_release_identifier (int fd, __u32 nsid, __u16 stream_id)


**Parameters**

``int fd``
  File descriptor of nvme device

``__u32 nsid``
  Namespace ID

``__u16 stream_id``
  *undescribed*

**Return**

The nvme command status if a response was received or -1 with errno
        set otherwise.


.. c:function:: int nvme_directive_send_stream_release_resource (int fd, __u32 nsid)


**Parameters**

``int fd``
  File descriptor of nvme device

``__u32 nsid``
  Namespace ID

**Return**

The nvme command status if a response was received or -1 with errno
        set otherwise.


.. c:function:: int nvme_directive_recv (int fd, __u32 nsid, __u16 dspec, __u8 doper, enum nvme_directive_dtype dtype, __u32 cdw12, __u32 data_len, void * data, __u32 * result)

   Receive directive specific data

**Parameters**

``int fd``
  File descriptor of nvme device

``__u32 nsid``
  Namespace ID, if applicable

``__u16 dspec``
  Directive specific field

``__u8 doper``
  Directive operation

``enum nvme_directive_dtype dtype``
  Directive type, see :c:type:`enum nvme_directive_dtype <nvme_directive_dtype>`

``__u32 cdw12``
  *undescribed*

``__u32 data_len``
  Length of data payload

``void * data``
  Usespace address of data payload in bytes

``__u32 * result``
  If successful, the CQE dword0 value

**Return**

The nvme command status if a response was received or -1 with errno
        set otherwise.


.. c:function:: int nvme_directive_recv_identify_parameters (int fd, __u32 nsid, struct nvme_id_directives * id)


**Parameters**

``int fd``
  File descriptor of nvme device

``__u32 nsid``
  Namespace ID

``struct nvme_id_directives * id``
  *undescribed*

**Return**

The nvme command status if a response was received or -1 with errno
        set otherwise.


.. c:function:: int nvme_directive_recv_stream_parameters (int fd, __u32 nsid, struct nvme_streams_directive_params * parms)


**Parameters**

``int fd``
  File descriptor of nvme device

``__u32 nsid``
  Namespace ID

``struct nvme_streams_directive_params * parms``
  *undescribed*

**Return**

The nvme command status if a response was received or -1 with errno
        set otherwise.


.. c:function:: int nvme_directive_recv_stream_status (int fd, __u32 nsid, unsigned nr_entries, struct nvme_streams_directive_status * id)


**Parameters**

``int fd``
  File descriptor of nvme device

``__u32 nsid``
  Namespace ID

``unsigned nr_entries``
  *undescribed*

``struct nvme_streams_directive_status * id``
  *undescribed*

**Return**

The nvme command status if a response was received or -1 with errno
        set otherwise.


.. c:function:: int nvme_directive_recv_stream_allocate (int fd, __u32 nsid, __u16 nsr, __u32 * result)


**Parameters**

``int fd``
  File descriptor of nvme device

``__u32 nsid``
  Namespace ID

``__u16 nsr``
  *undescribed*

``__u32 * result``
  *undescribed*

**Return**

The nvme command status if a response was received or -1 with errno
        set otherwise.




.. c:type:: enum nvme_fctype


**Constants**

``nvme_fabrics_type_property_set``
  *undescribed*

``nvme_fabrics_type_connect``
  *undescribed*

``nvme_fabrics_type_property_get``
  *undescribed*

``nvme_fabrics_type_auth_send``
  *undescribed*

``nvme_fabrics_type_auth_receive``
  *undescribed*

``nvme_fabrics_type_disconnect``
  *undescribed*


.. c:function:: int nvme_set_property (int fd, int offset, __u64 value)

   Set controller property

**Parameters**

``int fd``
  File descriptor of nvme device

``int offset``
  Property offset from the base to set

``__u64 value``
  The value to set the property

**Description**

This is an NVMe-over-Fabrics specific command, not applicable to PCIe. These
properties align to the PCI MMIO controller registers.

**Return**

The nvme command status if a response was received or -1 with errno
        set otherwise.


.. c:function:: int nvme_get_property (int fd, int offset, __u64 * value)

   Get a controller property

**Parameters**

``int fd``
  File descriptor of nvme device

``int offset``
  Property offset from the base to retrieve

``__u64 * value``
  Where the property's value will be stored on success

**Description**

This is an NVMe-over-Fabrics specific command, not applicable to PCIe. These
properties align to the PCI MMIO controller registers.

**Return**

The nvme command status if a response was received or -1 with errno
        set otherwise.


.. c:function:: int nvme_sanitize_nvm (int fd, enum nvme_sanitize_sanact sanact, bool ause, __u8 owpass, bool oipbp, bool nodas, __u32 ovrpat)

   Start a sanitize operation

**Parameters**

``int fd``
  File descriptor of nvme device

``enum nvme_sanitize_sanact sanact``
  Sanitize action, see :c:type:`enum nvme_sanitize_sanact <nvme_sanitize_sanact>`

``bool ause``
  Set to allow unrestriced sanitize exit

``__u8 owpass``
  Overwrite pass count

``bool oipbp``
  Set to overwrite invert pattern between passes

``bool nodas``
  Set to not deallocate blocks after sanitizing

``__u32 ovrpat``
  Overwrite pattern

**Description**

A sanitize operation alters all user data in the NVM subsystem such that
recovery of any previous user data from any cache, the non-volatile media,
or any Controller Memory Buffer is not possible.

The Sanitize command is used to start a sanitize operation or to recover
from a previously failed sanitize operation. The sanitize operation types
that may be supported are Block Erase, Crypto Erase, and Overwrite. All
sanitize operations are processed in the background, i.e., completion of the
sanitize command does not indicate completion of the sanitize operation.

**Return**

The nvme command status if a response was received or -1 with errno
        set otherwise.


.. c:function:: int nvme_dev_self_test (int fd, __u32 nsid, enum nvme_dst_stc stc)

   Start or abort a self test

**Parameters**

``int fd``
  File descriptor of nvme device

``__u32 nsid``
  Namespace ID to test

``enum nvme_dst_stc stc``
  Self test code, see :c:type:`enum nvme_dst_stc <nvme_dst_stc>`

**Description**

The Device Self-test command is used to start a device self-test operation
or abort a device self-test operation. A device self-test operation is a
diagnostic testing sequence that tests the integrity and functionality of
the controller and may include testing of the media associated with
namespaces. The controller may return a response to this command immediately
while running the self-test in the background.

Set the 'nsid' field to 0 to not include namepsaces in the test. Set to
0xffffffff to test all namespaces. All other values tests a specific
namespace, if present.

**Return**

The nvme command status if a response was received or -1 with errno
        set otherwise.


.. c:function:: int nvme_virtual_mgmt (int fd, enum nvme_virt_mgmt_act act, enum nvme_virt_mgmt_rt rt, __u16 cntlid, __u16 nr, __u32 * result)

   Virtualization resource management

**Parameters**

``int fd``
  File descriptor of nvme device

``enum nvme_virt_mgmt_act act``
  Virtual resource action, see :c:type:`enum nvme_virt_mgmt_act <nvme_virt_mgmt_act>`

``enum nvme_virt_mgmt_rt rt``
  Resource type to modify, see :c:type:`enum nvme_virt_mgmt_rt <nvme_virt_mgmt_rt>`

``__u16 cntlid``
  Controller id for which resources are bing modified

``__u16 nr``
  Number of resources being allocated or assigned

``__u32 * result``
  If successful, the CQE dword0

**Description**

The Virtualization Management command is supported by primary controllers
that support the Virtualization Enhancements capability. This command is
used for several functions:

     - Modifying Flexible Resource allocation for the primary controller
     - Assigning Flexible Resources for secondary controllers
     - Setting the Online and Offline state for secondary controllers

**Return**

The nvme command status if a response was received or -1
        with errno set otherwise.


**NVMe IO command**




.. c:type:: enum nvme_io_opcode


**Constants**

``nvme_cmd_flush``
  *undescribed*

``nvme_cmd_write``
  *undescribed*

``nvme_cmd_read``
  *undescribed*

``nvme_cmd_write_uncor``
  *undescribed*

``nvme_cmd_compare``
  *undescribed*

``nvme_cmd_write_zeroes``
  *undescribed*

``nvme_cmd_dsm``
  *undescribed*

``nvme_cmd_verify``
  *undescribed*

``nvme_cmd_resv_register``
  *undescribed*

``nvme_cmd_resv_report``
  *undescribed*

``nvme_cmd_resv_acquire``
  *undescribed*

``nvme_cmd_resv_release``
  *undescribed*


.. c:function:: int nvme_flush (int fd, __u32 nsid)

   Send an nvme flush command

**Parameters**

``int fd``
  File descriptor of nvme device

``__u32 nsid``
  Namespace identifier

**Description**

The Flush command is used to request that the contents of volatile write
cache be made non-volatile.

**Return**

The nvme command status if a response was received or -1 with errno
        set otherwise.




.. c:type:: enum nvme_io_control_flags


**Constants**

``NVME_IO_DTYPE_STREAMS``
  *undescribed*

``NVME_IO_DEAC``
  *undescribed*

``NVME_IO_PRINFO_PRCHK_REF``
  *undescribed*

``NVME_IO_PRINFO_PRCHK_APP``
  *undescribed*

``NVME_IO_PRINFO_PRCHK_GUARD``
  *undescribed*

``NVME_IO_PRINFO_PRACT``
  *undescribed*

``NVME_IO_FUA``
  *undescribed*

``NVME_IO_LR``
  *undescribed*




.. c:type:: enum nvme_io_dsm_flags


**Constants**

``NVME_IO_DSM_FREQ_UNSPEC``
  *undescribed*

``NVME_IO_DSM_FREQ_TYPICAL``
  *undescribed*

``NVME_IO_DSM_FREQ_RARE``
  *undescribed*

``NVME_IO_DSM_FREQ_READS``
  *undescribed*

``NVME_IO_DSM_FREQ_WRITES``
  *undescribed*

``NVME_IO_DSM_FREQ_RW``
  *undescribed*

``NVME_IO_DSM_FREQ_ONCE``
  *undescribed*

``NVME_IO_DSM_FREQ_PREFETCH``
  *undescribed*

``NVME_IO_DSM_FREQ_TEMP``
  *undescribed*

``NVME_IO_DSM_LATENCY_NONE``
  *undescribed*

``NVME_IO_DSM_LATENCY_IDLE``
  *undescribed*

``NVME_IO_DSM_LATENCY_NORM``
  *undescribed*

``NVME_IO_DSM_LATENCY_LOW``
  *undescribed*

``NVME_IO_DSM_SEQ_REQ``
  *undescribed*

``NVME_IO_DSM_COMPRESSED``
  *undescribed*


.. c:function:: int nvme_read (int fd, __u32 nsid, __u64 slba, __u16 nlb, __u16 control, __u8 dsm, __u32 reftag, __u16 apptag, __u16 appmask, __u32 data_len, void * data, __u32 metadata_len, void * metadata)

   Submit an nvme user read command

**Parameters**

``int fd``
  File descriptor of nvme device

``__u32 nsid``
  Namespace ID

``__u64 slba``
  Starting logical block

``__u16 nlb``
  *undescribed*

``__u16 control``
  Command control flags, see :c:type:`enum nvme_io_control_flags <nvme_io_control_flags>`.

``__u8 dsm``
  Data set management attributes, see :c:type:`enum nvme_io_dsm_flags <nvme_io_dsm_flags>`

``__u32 reftag``
  This field specifies the Initial Logical Block Reference Tag
  expected value. Used only if the namespace is formatted to use
  end-to-end protection information.

``__u16 apptag``
  This field specifies the Application Tag Mask expected value.
  Used only if the namespace is formatted to use end-to-end
  protection information.

``__u16 appmask``
  This field specifies the Application Tag expected value. Used
  only if the namespace is formatted to use end-to-end protection
  information.

``__u32 data_len``
  Length of user buffer, **data**, in bytes

``void * data``
  Pointer to user address of the data buffer
  metadata_len:Length of user buffer, **metadata**, in bytes

``__u32 metadata_len``
  *undescribed*

``void * metadata``
  Pointer to user address of the metadata buffer

**Return**

The nvme command status if a response was received or -1 with errno
        set otherwise.


.. c:function:: int nvme_write (int fd, __u32 nsid, __u64 slba, __u16 nlb, __u16 control, __u8 dsm, __u16 dspec, __u32 reftag, __u16 apptag, __u16 appmask, __u32 data_len, void * data, __u32 metadata_len, void * metadata)

   Submit an nvme user write command

**Parameters**

``int fd``
  File descriptor of nvme device

``__u32 nsid``
  Namespace ID

``__u64 slba``
  Starting logical block

``__u16 nlb``
  *undescribed*

``__u16 control``
  Command control flags, see :c:type:`enum nvme_io_control_flags <nvme_io_control_flags>`.

``__u8 dsm``
  Data set management attributes, see :c:type:`enum nvme_io_dsm_flags <nvme_io_dsm_flags>`

``__u16 dspec``
  Directive specific command, eg: stream identifier

``__u32 reftag``
  This field specifies the Initial Logical Block Reference Tag
  expected value. Used only if the namespace is formatted to use
  end-to-end protection information.

``__u16 apptag``
  This field specifies the Application Tag Mask expected value.
  Used only if the namespace is formatted to use end-to-end
  protection information.

``__u16 appmask``
  This field specifies the Application Tag expected value. Used
  only if the namespace is formatted to use end-to-end protection
  information.

``__u32 data_len``
  Length of user buffer, **data**, in bytes

``void * data``
  Pointer to user address of the data buffer
  metadata_len:Length of user buffer, **metadata**, in bytes

``__u32 metadata_len``
  *undescribed*

``void * metadata``
  Pointer to user address of the metadata buffer

**Return**

The nvme command status if a response was received or -1 with errno
        set otherwise.


.. c:function:: int nvme_compare (int fd, __u32 nsid, __u64 slba, __u16 nlb, __u16 control, __u32 reftag, __u16 apptag, __u16 appmask, __u32 data_len, void * data, __u32 metadata_len, void * metadata)

   Submit an nvme user compare command

**Parameters**

``int fd``
  File descriptor of nvme device

``__u32 nsid``
  Namespace ID

``__u64 slba``
  Starting logical block

``__u16 nlb``
  *undescribed*

``__u16 control``
  Command control flags, see :c:type:`enum nvme_io_control_flags <nvme_io_control_flags>`.

``__u32 reftag``
  This field specifies the Initial Logical Block Reference Tag
  expected value. Used only if the namespace is formatted to use
  end-to-end protection information.

``__u16 apptag``
  This field specifies the Application Tag Mask expected value.
  Used only if the namespace is formatted to use end-to-end
  protection information.

``__u16 appmask``
  This field specifies the Application Tag expected value. Used
  only if the namespace is formatted to use end-to-end protection
  information.

``__u32 data_len``
  Length of user buffer, **data**, in bytes

``void * data``
  Pointer to user address of the data buffer
  metadata_len:Length of user buffer, **metadata**, in bytes

``__u32 metadata_len``
  *undescribed*

``void * metadata``
  Pointer to user address of the metadata buffer

**Return**

The nvme command status if a response was received or -1 with errno
        set otherwise.


.. c:function:: int nvme_write_zeros (int fd, __u32 nsid, __u64 slba, __u16 nlb, __u16 control, __u32 reftag, __u16 apptag, __u16 appmask)

   Submit an nvme write zeroes command

**Parameters**

``int fd``
  File descriptor of nvme device

``__u32 nsid``
  Namespace identifier

``__u64 slba``
  Starting logical block

``__u16 nlb``
  Number of logical blocks to clear (0's based value)

``__u16 control``
  Command control flags, see :c:type:`enum nvme_io_control_flags <nvme_io_control_flags>`.

``__u32 reftag``
  This field specifies the Initial Logical Block Reference Tag
  expected value. Used only if the namespace is formatted to use
  end-to-end protection information.

``__u16 apptag``
  This field specifies the Application Tag Mask expected value.
  Used only if the namespace is formatted to use end-to-end
  protection information.

``__u16 appmask``
  This field specifies the Application Tag expected value. Used
  only if the namespace is formatted to use end-to-end protection
  information.

**Description**

The Write Zeroes command is used to set a range of logical blocks to zero.
After successful completion of this command, the value returned by
subsequent reads of logical blocks in this range shall be all bytes cleared
to 0h until a write occurs to this LBA range.

**Return**

The nvme command status if a response was received or -1 with errno
        set otherwise.


.. c:function:: int nvme_write_uncorrectable (int fd, __u32 nsid, __u64 slba, __u16 nlb)

   Submit an nvme write uncorrectable command

**Parameters**

``int fd``
  File descriptor of nvme device

``__u32 nsid``
  Namespace identifier

``__u64 slba``
  Starting logical block

``__u16 nlb``
  Number of logical blocks to invalidate (0's based value)

**Description**

The Write Uncorrectable command is used to mark a range of logical blocks as
invalid. When the specified logical block(s) are read after this operation,
a failure is returned with Unrecovered Read Error status. To clear the
invalid logical block status, a write operation on those logical blocks is
required.

**Return**

The nvme command status if a response was received or -1 with errno
        set otherwise.


.. c:function:: int nvme_verify (int fd, __u32 nsid, __u64 slba, __u16 nlb, __u16 control, __u32 reftag, __u16 apptag, __u16 appmask)

   Send an nvme verify command

**Parameters**

``int fd``
  File descriptor of nvme device

``__u32 nsid``
  Namespace identifier

``__u64 slba``
  Starting logical block

``__u16 nlb``
  Number of logical blocks to verify (0's based value)

``__u16 control``
  Command control flags, see :c:type:`enum nvme_io_control_flags <nvme_io_control_flags>`.

``__u32 reftag``
  This field specifies the Initial Logical Block Reference Tag
  expected value. Used only if the namespace is formatted to use
  end-to-end protection information.

``__u16 apptag``
  This field specifies the Application Tag Mask expected value.
  Used only if the namespace is formatted to use end-to-end
  protection information.

``__u16 appmask``
  This field specifies the Application Tag expected value. Used
  only if the namespace is formatted to use end-to-end protection
  information.

**Description**

The Verify command verifies integrity of stored information by reading data
and metadata, if applicable, for the LBAs indicated without transferring any
data or metadata to the host.

**Return**

The nvme command status if a response was received or -1 with errno
        set otherwise.




.. c:type:: enum nvme_dsm_attributes


**Constants**

``NVME_DSMGMT_IDR``
  *undescribed*

``NVME_DSMGMT_IDW``
  *undescribed*

``NVME_DSMGMT_AD``
  *undescribed*


.. c:function:: int nvme_dsm (int fd, __u32 nsid, __u32 attrs, __u16 nr_ranges, struct nvme_dsm_range * dsm)

   Send an nvme data set management command

**Parameters**

``int fd``
  File descriptor of nvme device

``__u32 nsid``
  Namespace identifier

``__u32 attrs``
  DSM attributes, see :c:type:`enum nvme_dsm_attributes <nvme_dsm_attributes>`
  :c:type:`nr_ranges`:  Number of block ranges in the data set management attributes

``__u16 nr_ranges``
  *undescribed*

``struct nvme_dsm_range * dsm``
  The data set management attributes

**Description**

The Dataset Management command is used by the host to indicate attributes
for ranges of logical blocks. This includes attributes like frequency that
data is read or written, access size, and other information that may be used
to optimize performance and reliability, and may be used to
deallocate/unmap/trim those logical blocks.

**Return**

The nvme command status if a response was received or -1 with errno
        set otherwise.




.. c:type:: enum nvme_reservation_rtype


**Constants**

``NVME_RESERVATION_RTYPE_WE``
  *undescribed*

``NVME_RESERVATION_RTYPE_EA``
  *undescribed*

``NVME_RESERVATION_RTYPE_WERO``
  *undescribed*

``NVME_RESERVATION_RTYPE_EARO``
  *undescribed*

``NVME_RESERVATION_RTYPE_WEAR``
  *undescribed*

``NVME_RESERVATION_RTYPE_EAAR``
  *undescribed*




.. c:type:: enum nvme_reservation_racqa


**Constants**

``NVME_RESERVATION_RACQA_ACQUIRE``
  *undescribed*

``NVME_RESERVATION_RACQA_PREEMPT``
  *undescribed*

``NVME_RESERVATION_RACQA_PREEMPT_AND_ABORT``
  *undescribed*


.. c:function:: int nvme_resv_acquire (int fd, __u32 nsid, enum nvme_reservation_rtype rtype, enum nvme_reservation_racqa racqa, bool iekey, __u64 crkey, __u64 nrkey)

   Send an nvme reservation acquire

**Parameters**

``int fd``
  File descriptor of nvme device

``__u32 nsid``
  Namespace identifier

``enum nvme_reservation_rtype rtype``
  The type of reservation to be create, see :c:type:`enum nvme_reservation_rtype <nvme_reservation_rtype>`

``enum nvme_reservation_racqa racqa``
  The action that is performed by the command, see :c:type:`enum nvme_reservation_racqa <nvme_reservation_racqa>`

``bool iekey``
  Set to ignore the existing key

``__u64 crkey``
  The current reservation key associated with the host

``__u64 nrkey``
  The reservation key to be unregistered from the namespace if
  the action is preempt

**Description**

The Reservation Acquire command is used to acquire a reservation on a
namespace, preempt a reservation held on a namespace, and abort a
reservation held on a namespace.

**Return**

The nvme command status if a response was received or -1 with errno
        set otherwise.




.. c:type:: enum nvme_reservation_rrega


**Constants**

``NVME_RESERVATION_RREGA_REGISTER_KEY``
  *undescribed*

``NVME_RESERVATION_RREGA_UNREGISTER_KEY``
  *undescribed*

``NVME_RESERVATION_RREGA_REPLACE_KEY``
  *undescribed*




.. c:type:: enum nvme_reservation_cptpl


**Constants**

``NVME_RESERVATION_CPTPL_NO_CHANGE``
  *undescribed*

``NVME_RESERVATION_CPTPL_CLEAR``
  *undescribed*

``NVME_RESERVATION_CPTPL_PERSIST``
  *undescribed*


.. c:function:: int nvme_resv_register (int fd, __u32 nsid, enum nvme_reservation_rrega rrega, enum nvme_reservation_cptpl cptpl, bool iekey, __u64 crkey, __u64 nrkey)

   Send an nvme reservation register

**Parameters**

``int fd``
  File descriptor of nvme device

``__u32 nsid``
  Namespace identifier

``enum nvme_reservation_rrega rrega``
  The registration action, see :c:type:`enum nvme_reservation_rrega <nvme_reservation_rrega>`

``enum nvme_reservation_cptpl cptpl``
  Change persist through power loss, see :c:type:`enum nvme_reservation_cptpl <nvme_reservation_cptpl>`

``bool iekey``
  Set to ignore the existing key

``__u64 crkey``
  The current reservation key associated with the host

``__u64 nrkey``
  The new reservation key to be register if action is register or
  replace

**Description**

The Reservation Register command is used to register, unregister, or replace
a reservation key.

**Return**

The nvme command status if a response was received or -1 with errno
        set otherwise.




.. c:type:: enum nvme_reservation_rrela


**Constants**

``NVME_RESERVATION_RRELA_RELEASE``
  *undescribed*

``NVME_RESERVATION_RRELA_CLEAR``
  *undescribed*


.. c:function:: int nvme_resv_release (int fd, __u32 nsid, enum nvme_reservation_rtype rtype, enum nvme_reservation_rrela rrela, bool iekey, __u64 crkey)

   Send an nvme reservation release

**Parameters**

``int fd``
  File descriptor of nvme device

``__u32 nsid``
  Namespace identifier

``enum nvme_reservation_rtype rtype``
  The type of reservation to be create, see :c:type:`enum nvme_reservation_rtype <nvme_reservation_rtype>`

``enum nvme_reservation_rrela rrela``
  Reservation releast action, see :c:type:`enum  nvme_reservation_rrela <nvme_reservation_rrela>`

``bool iekey``
  Set to ignore the existing key

``__u64 crkey``
  The current reservation key to release

**Return**

The nvme command status if a response was received or -1 with errno
        set otherwise.


.. c:function:: int nvme_resv_report (int fd, __u32 nsid, bool eds, __u32 len, struct nvme_reservation_status * report)

   Send an nvme reservation report

**Parameters**

``int fd``
  File descriptor of nvme device

``__u32 nsid``
  Namespace identifier

``bool eds``
  Request extended Data Structure

``__u32 len``
  Number of bytes to request transfered with this command

``struct nvme_reservation_status * report``
  The user space destination address to store the reservation report

**Description**

Returns a Reservation Status data structure to memory that describes the
registration and reservation status of a namespace. See the defintion for
the returned structure, :c:type:`struct nvme_reservation_status <nvme_reservation_status>`, for more details.

**Return**

The nvme command status if a response was received or -1 with errno
        set otherwise.




.. c:type:: struct nvme_fabrics_config


**Definition**

::

  struct nvme_fabrics_config {
    const char *transport;
    const char *traddr;
    const char *trsvcid;
    const char *nqn;
    const char *hostnqn;
    const char *host_traddr;
    const char *hostid;
    int queue_size;
    int nr_io_queues;
    int reconnect_delay;
    int ctrl_loss_tmo;
    int keep_alive_tmo;
    int nr_write_queues;
    int nr_poll_queues;
    int tos;
    bool duplicate_connect;
    bool disable_sqflow;
    bool hdr_digest;
    bool data_digest;
    uint8_t rsvd[0x200];
  };

**Members**



.. c:function:: int nvmf_add_ctrl_opts (struct nvme_fabrics_config * cfg)


**Parameters**

``struct nvme_fabrics_config * cfg``
  *undescribed*


.. c:function:: nvme_ctrl_t nvmf_add_ctrl (struct nvme_fabrics_config * cfg)


**Parameters**

``struct nvme_fabrics_config * cfg``
  *undescribed*


.. c:function:: int nvmf_get_discovery_log (nvme_ctrl_t c, struct nvmf_discovery_log ** logp, int max_retries)


**Parameters**

``nvme_ctrl_t c``
  *undescribed*

``struct nvmf_discovery_log ** logp``
  *undescribed*

``int max_retries``
  *undescribed*


.. c:function:: char * nvmf_hostnqn_generate ()


**Parameters**


.. c:function:: char * nvmf_hostnqn_from_file ()


**Parameters**


.. c:function:: char * nvmf_hostid_from_file ()


**Parameters**


.. c:function:: const char * nvmf_trtype_str (__u8 trtype)


**Parameters**

``__u8 trtype``
  *undescribed*


.. c:function:: const char * nvmf_adrfam_str (__u8 adrfam)


**Parameters**

``__u8 adrfam``
  *undescribed*


.. c:function:: const char * nvmf_subtype_str (__u8 subtype)


**Parameters**

``__u8 subtype``
  *undescribed*


.. c:function:: const char * nvmf_treq_str (__u8 treq)


**Parameters**

``__u8 treq``
  *undescribed*


.. c:function:: const char * nvmf_sectype_str (__u8 sectype)


**Parameters**

``__u8 sectype``
  *undescribed*


.. c:function:: const char * nvmf_prtype_str (__u8 prtype)


**Parameters**

``__u8 prtype``
  *undescribed*


.. c:function:: const char * nvmf_qptype_str (__u8 qptype)


**Parameters**

``__u8 qptype``
  *undescribed*


.. c:function:: const char * nvmf_cms_str (__u8 cm)


**Parameters**

``__u8 cm``
  *undescribed*


.. c:function:: nvme_ctrl_t nvmf_connect_disc_entry (struct nvmf_disc_log_entry * e, const struct nvme_fabrics_config * defcfg, bool * discover)


**Parameters**

``struct nvmf_disc_log_entry * e``
  *undescribed*

``const struct nvme_fabrics_config * defcfg``
  *undescribed*

``bool * discover``
  *undescribed*


.. c:function:: int nvme_namespace_filter (const struct dirent * d)


**Parameters**

``const struct dirent * d``
  *undescribed*


.. c:function:: int nvme_paths_filter (const struct dirent * d)


**Parameters**

``const struct dirent * d``
  *undescribed*


.. c:function:: int nvme_ctrls_filter (const struct dirent * d)


**Parameters**

``const struct dirent * d``
  *undescribed*


.. c:function:: int nvme_subsys_filter (const struct dirent * d)


**Parameters**

``const struct dirent * d``
  *undescribed*


.. c:function:: int nvme_scan_subsystems (struct dirent *** subsys)


**Parameters**

``struct dirent *** subsys``
  *undescribed*


.. c:function:: int nvme_scan_subsystem_ctrls (nvme_subsystem_t s, struct dirent *** ctrls)


**Parameters**

``nvme_subsystem_t s``
  *undescribed*

``struct dirent *** ctrls``
  *undescribed*


.. c:function:: int nvme_scan_subsystem_namespaces (nvme_subsystem_t s, struct dirent *** namespaces)


**Parameters**

``nvme_subsystem_t s``
  *undescribed*

``struct dirent *** namespaces``
  *undescribed*


.. c:function:: int nvme_scan_ctrl_namespace_paths (nvme_ctrl_t c, struct dirent *** namespaces)


**Parameters**

``nvme_ctrl_t c``
  *undescribed*

``struct dirent *** namespaces``
  *undescribed*


.. c:function:: int nvme_scan_ctrl_namespaces (nvme_ctrl_t c, struct dirent *** namespaces)


**Parameters**

``nvme_ctrl_t c``
  *undescribed*

``struct dirent *** namespaces``
  *undescribed*




.. c:type:: struct nvme_passthru_cmd


**Definition**

::

  struct nvme_passthru_cmd {
    __u8 opcode;
    __u8 flags;
    __u16 rsvd1;
    __u32 nsid;
    __u32 cdw2;
    __u32 cdw3;
    __u64 metadata;
    __u64 addr;
    __u32 metadata_len;
    __u32 data_len;
    __u32 cdw10;
    __u32 cdw11;
    __u32 cdw12;
    __u32 cdw13;
    __u32 cdw14;
    __u32 cdw15;
    __u32 timeout_ms;
    __u32 result;
  };

**Members**

``opcode``
  Operation code, see :c:type:`enum nvme_io_opcodes <nvme_io_opcodes>` and :c:type:`enum nvme_admin_opcodes <nvme_admin_opcodes>`

``flags``
  Not supported: intended for command flags (eg: SGL, FUSE)

``rsvd1``
  Reserved for future use

``nsid``
  Namespace Identifier, or Fabrics type

``cdw2``
  Command Dword 2 (no spec defined use)

``cdw3``
  Command Dword 3 (no spec defined use)

``metadata``
  User space address to metadata buffer (NULL if not used)

``addr``
  User space address to data buffer (NULL if not used)

``metadata_len``
  Metadata buffer transfer length

``data_len``
  Data buffer transfer length

``cdw10``
  Command Dword 10 (command specific)

``cdw11``
  Command Dword 11 (command specific)

``cdw12``
  Command Dword 12 (command specific)

``cdw13``
  Command Dword 13 (command specific)

``cdw14``
  Command Dword 14 (command specific)

``cdw15``
  Command Dword 15 (command specific)

``timeout_ms``
  If non-zero, overrides system default timeout in milliseconds

``result``
  Set on completion to the command's CQE DWORD 0 controller response





.. c:type:: struct nvme_passthru_cmd64


**Definition**

::

  struct nvme_passthru_cmd64 {
    __u8 opcode;
    __u8 flags;
    __u16 rsvd1;
    __u32 nsid;
    __u32 cdw2;
    __u32 cdw3;
    __u64 metadata;
    __u64 addr;
    __u32 metadata_len;
    __u32 data_len;
    __u32 cdw10;
    __u32 cdw11;
    __u32 cdw12;
    __u32 cdw13;
    __u32 cdw14;
    __u32 cdw15;
    __u32 timeout_ms;
    __u32 rsvd2;
    __u64 result;
  };

**Members**

``opcode``
  Operation code, see :c:type:`enum nvme_io_opcodes <nvme_io_opcodes>` and :c:type:`enum nvme_admin_opcodes <nvme_admin_opcodes>`

``flags``
  Not supported: intended for command flags (eg: SGL, FUSE)

``rsvd1``
  Reserved for future use

``nsid``
  Namespace Identifier, or Fabrics type

``cdw2``
  Command Dword 2 (no spec defined use)

``cdw3``
  Command Dword 3 (no spec defined use)

``metadata``
  User space address to metadata buffer (NULL if not used)

``addr``
  User space address to data buffer (NULL if not used)

``metadata_len``
  Metadata buffer transfer length

``data_len``
  Data buffer transfer length

``cdw10``
  Command Dword 10 (command specific)

``cdw11``
  Command Dword 11 (command specific)

``cdw12``
  Command Dword 12 (command specific)

``cdw13``
  Command Dword 13 (command specific)

``cdw14``
  Command Dword 14 (command specific)

``cdw15``
  Command Dword 15 (command specific)

``timeout_ms``
  If non-zero, overrides system default timeout in milliseconds

``rsvd2``
  Reserved for future use (and fills an impicit struct pad

``result``
  Set on completion to the command's CQE DWORD 0-1 controller response



.. c:function:: int nvme_submit_admin_passthru64 (int fd, struct nvme_passthru_cmd64 * cmd, __u64 * result)

   Submit a 64-bit nvme passthrough admin command

**Parameters**

``int fd``
  File descriptor of nvme device

``struct nvme_passthru_cmd64 * cmd``
  The nvme admin command to send

``__u64 * result``
  Optional field to return the result from the CQE DW0-1

**Description**

Uses NVME_IOCTL_ADMIN64_CMD for the ioctl request.

**Return**

The nvme command status if a response was received or -1
        with errno set otherwise.


.. c:function:: int nvme_admin_passthru64 (int fd, __u8 opcode, __u8 flags, __u16 rsvd, __u32 nsid, __u32 cdw2, __u32 cdw3, __u32 cdw10, __u32 cdw11, __u32 cdw12, __u32 cdw13, __u32 cdw14, __u32 cdw15, __u32 data_len, void * data, __u32 metadata_len, void * metadata, __u32 timeout_ms, __u64 * result)

   Submit an nvme passthrough command

**Parameters**

``int fd``
  File descriptor of nvme device

``__u8 opcode``
  The nvme io command to send

``__u8 flags``
  NVMe command flags (not used)

``__u16 rsvd``
  Reserevd for future use

``__u32 nsid``
  Namespace identifier

``__u32 cdw2``
  Command dword 2

``__u32 cdw3``
  Command dword 3

``__u32 cdw10``
  Command dword 10

``__u32 cdw11``
  Command dword 11

``__u32 cdw12``
  Command dword 12

``__u32 cdw13``
  Command dword 13

``__u32 cdw14``
  Command dword 14

``__u32 cdw15``
  Command dword 15

``__u32 data_len``
  Length of the data transfered in this command in bytes

``void * data``
  Pointer to user address of the data buffer

``__u32 metadata_len``
  Length of metadata transfered in this command

``void * metadata``
  Pointer to user address of the metadata buffer

``__u32 timeout_ms``
  How long the kernel waits for the command to complete

``__u64 * result``
  Optional field to return the result from the CQE dword 0

**Description**

Parameterized form of nvme_submit_admin_passthru64(). This sets up and
submits a :c:type:`struct nvme_passthru_cmd64 <nvme_passthru_cmd64>`.

Known values for **opcode** are defined in :c:type:`enum nvme_admin_opcode <nvme_admin_opcode>`.

**Return**

The nvme command status if a response was received or -1
        with errno set otherwise.


.. c:function:: int nvme_submit_admin_passthru (int fd, struct nvme_passthru_cmd * cmd, __u32 * result)

   Submit an nvme passthrough admin command

**Parameters**

``int fd``
  File descriptor of nvme device

``struct nvme_passthru_cmd * cmd``
  The nvme admin command to send

``__u32 * result``
  Optional field to return the result from the CQE DW0

**Description**

Uses NVME_IOCTL_ADMIN_CMD for the ioctl request.

**Return**

The nvme command status if a response was received or -1
        with errno set otherwise.


.. c:function:: int nvme_admin_passthru (int fd, __u8 opcode, __u8 flags, __u16 rsvd, __u32 nsid, __u32 cdw2, __u32 cdw3, __u32 cdw10, __u32 cdw11, __u32 cdw12, __u32 cdw13, __u32 cdw14, __u32 cdw15, __u32 data_len, void * data, __u32 metadata_len, void * metadata, __u32 timeout_ms, __u32 * result)

   Submit an nvme passthrough command

**Parameters**

``int fd``
  File descriptor of nvme device

``__u8 opcode``
  The nvme io command to send

``__u8 flags``
  NVMe command flags (not used)

``__u16 rsvd``
  Reserevd for future use

``__u32 nsid``
  Namespace identifier

``__u32 cdw2``
  Command dword 2

``__u32 cdw3``
  Command dword 3

``__u32 cdw10``
  Command dword 10

``__u32 cdw11``
  Command dword 11

``__u32 cdw12``
  Command dword 12

``__u32 cdw13``
  Command dword 13

``__u32 cdw14``
  Command dword 14

``__u32 cdw15``
  Command dword 15

``__u32 data_len``
  Length of the data transfered in this command in bytes

``void * data``
  Pointer to user address of the data buffer

``__u32 metadata_len``
  Length of metadata transfered in this command

``void * metadata``
  Pointer to user address of the metadata buffer

``__u32 timeout_ms``
  How long the kernel waits for the command to complete

``__u32 * result``
  Optional field to return the result from the CQE dword 0

**Description**

Parameterized form of nvme_submit_admin_passthru(). This sets up and
submits a :c:type:`struct nvme_passthru_cmd <nvme_passthru_cmd>`.

Known values for **opcode** are defined in :c:type:`enum nvme_admin_opcode <nvme_admin_opcode>`.

**Return**

The nvme command status if a response was received or -1
        with errno set otherwise.


.. c:function:: int nvme_submit_io_passthru64 (int fd, struct nvme_passthru_cmd64 * cmd, __u64 * result)

   Submit a 64-bit nvme passthrough command

**Parameters**

``int fd``
  File descriptor of nvme device

``struct nvme_passthru_cmd64 * cmd``
  The nvme io command to send

``__u64 * result``
  Optional field to return the result from the CQE DW0-1

**Description**

Uses NVME_IOCTL_IO64_CMD for the ioctl request.

**Return**

The nvme command status if a response was received or -1
        with errno set otherwise.


.. c:function:: int nvme_io_passthru64 (int fd, __u8 opcode, __u8 flags, __u16 rsvd, __u32 nsid, __u32 cdw2, __u32 cdw3, __u32 cdw10, __u32 cdw11, __u32 cdw12, __u32 cdw13, __u32 cdw14, __u32 cdw15, __u32 data_len, void * data, __u32 metadata_len, void * metadata, __u32 timeout_ms, __u64 * result)

   Submit an nvme io passthrough command

**Parameters**

``int fd``
  File descriptor of nvme device

``__u8 opcode``
  The nvme io command to send

``__u8 flags``
  NVMe command flags (not used)

``__u16 rsvd``
  Reserevd for future use

``__u32 nsid``
  Namespace identifier

``__u32 cdw2``
  Command dword 2

``__u32 cdw3``
  Command dword 3

``__u32 cdw10``
  Command dword 10

``__u32 cdw11``
  Command dword 11

``__u32 cdw12``
  Command dword 12

``__u32 cdw13``
  Command dword 13

``__u32 cdw14``
  Command dword 14

``__u32 cdw15``
  Command dword 15

``__u32 data_len``
  Length of the data transfered in this command in bytes

``void * data``
  Pointer to user address of the data buffer

``__u32 metadata_len``
  Length of metadata transfered in this command

``void * metadata``
  Pointer to user address of the metadata buffer

``__u32 timeout_ms``
  How long the kernel waits for the command to complete

``__u64 * result``
  Optional field to return the result from the CQE dword 0

**Description**

Parameterized form of nvme_submit_io_passthru64(). This sets up and submits
a :c:type:`struct nvme_passthru_cmd64 <nvme_passthru_cmd64>`.

Known values for **opcode** are defined in :c:type:`enum nvme_io_opcode <nvme_io_opcode>`.

**Return**

The nvme command status if a response was received or -1 with errno
        set otherwise.


.. c:function:: int nvme_submit_io_passthru (int fd, struct nvme_passthru_cmd * cmd, __u32 * result)

   Submit an nvme passthrough command

**Parameters**

``int fd``
  File descriptor of nvme device

``struct nvme_passthru_cmd * cmd``
  The nvme io command to send

``__u32 * result``
  Optional field to return the result from the CQE DW0

**Description**

Uses NVME_IOCTL_IO_CMD for the ioctl request.

**Return**

The nvme command status if a response was received or -1
        with errno set otherwise.


.. c:function:: int nvme_io_passthru (int fd, __u8 opcode, __u8 flags, __u16 rsvd, __u32 nsid, __u32 cdw2, __u32 cdw3, __u32 cdw10, __u32 cdw11, __u32 cdw12, __u32 cdw13, __u32 cdw14, __u32 cdw15, __u32 data_len, void * data, __u32 metadata_len, void * metadata, __u32 timeout_ms, __u32 * result)

   Submit an nvme io passthrough command

**Parameters**

``int fd``
  File descriptor of nvme device

``__u8 opcode``
  The nvme io command to send

``__u8 flags``
  NVMe command flags (not used)

``__u16 rsvd``
  Reserevd for future use

``__u32 nsid``
  Namespace identifier

``__u32 cdw2``
  Command dword 2

``__u32 cdw3``
  Command dword 3

``__u32 cdw10``
  Command dword 10

``__u32 cdw11``
  Command dword 11

``__u32 cdw12``
  Command dword 12

``__u32 cdw13``
  Command dword 13

``__u32 cdw14``
  Command dword 14

``__u32 cdw15``
  Command dword 15

``__u32 data_len``
  Length of the data transfered in this command in bytes

``void * data``
  Pointer to user address of the data buffer

``__u32 metadata_len``
  Length of metadata transfered in this command

``void * metadata``
  Pointer to user address of the metadata buffer

``__u32 timeout_ms``
  How long the kernel waits for the command to complete

``__u32 * result``
  Optional field to return the result from the CQE dword 0

**Description**

Parameterized form of nvme_submit_io_passthru(). This sets up and submits
a :c:type:`struct nvme_passthru_cmd <nvme_passthru_cmd>`.

Known values for **opcode** are defined in :c:type:`enum nvme_io_opcode <nvme_io_opcode>`.

**Return**

The nvme command status if a response was received or -1
        with errno set otherwise.


.. c:function:: int nvme_subsystem_reset (int fd)

   Initiate a subsystem reset

**Parameters**

``int fd``
  File descriptor of nvme device

**Description**

This should only be sent to controller handles, not to namespaces.

**Return**

Zero if a subsystem reset was initiated or -1 with errno set
        otherwise.


.. c:function:: int nvme_ctrl_reset (int fd)

   Initiate a controller reset

**Parameters**

``int fd``
  File descriptor of nvme device

**Description**

This should only be sent to controller handles, not to namespaces.

**Return**

Zero if a reset was initiated or -1 with errno set otherwise.


.. c:function:: int nvme_ns_rescan (int fd)

   Initiate a controller rescan

**Parameters**

``int fd``
  File descriptor of nvme device

**Description**

This should only be sent to controller handles, not to namespaces.

**Return**

Zero if a rescan was initiated or -1 with errno set otherwise.


.. c:function:: int nvme_get_nsid (int fd)

   Retrieve the NSID from a namespace file descriptor

**Parameters**

``int fd``
  File descriptor of nvme namespace

**Description**

This should only be sent to namespace handles, not to controllers.

**Return**

The namespace identifier if a succecssful or -1 with errno set
        otherwise.


.. c:function:: nvme_subsystem_t nvme_first_subsystem (nvme_root_t r)


**Parameters**

``nvme_root_t r``
  *undescribed*


.. c:function:: nvme_subsystem_t nvme_next_subsystem (nvme_root_t r, nvme_subsystem_t s)


**Parameters**

``nvme_root_t r``
  *undescribed*

``nvme_subsystem_t s``
  *undescribed*


.. c:function:: nvme_ns_t nvme_ctrl_first_ns (nvme_ctrl_t c)


**Parameters**

``nvme_ctrl_t c``
  *undescribed*


.. c:function:: nvme_ns_t nvme_ctrl_next_ns (nvme_ctrl_t c, nvme_ns_t n)


**Parameters**

``nvme_ctrl_t c``
  *undescribed*

``nvme_ns_t n``
  *undescribed*


.. c:function:: nvme_path_t nvme_ctrl_first_path (nvme_ctrl_t c)


**Parameters**

``nvme_ctrl_t c``
  *undescribed*


.. c:function:: nvme_path_t nvme_ctrl_next_path (nvme_ctrl_t c, nvme_path_t p)


**Parameters**

``nvme_ctrl_t c``
  *undescribed*

``nvme_path_t p``
  *undescribed*


.. c:function:: nvme_ctrl_t nvme_subsystem_first_ctrl (nvme_subsystem_t s)


**Parameters**

``nvme_subsystem_t s``
  *undescribed*


.. c:function:: nvme_ctrl_t nvme_subsystem_next_ctrl (nvme_subsystem_t s, nvme_ctrl_t c)


**Parameters**

``nvme_subsystem_t s``
  *undescribed*

``nvme_ctrl_t c``
  *undescribed*


.. c:function:: nvme_ns_t nvme_subsystem_first_ns (nvme_subsystem_t s)


**Parameters**

``nvme_subsystem_t s``
  *undescribed*


.. c:function:: nvme_ns_t nvme_subsystem_next_ns (nvme_subsystem_t s, nvme_ns_t n)


**Parameters**

``nvme_subsystem_t s``
  *undescribed*

``nvme_ns_t n``
  *undescribed*


.. c:function:: nvme_for_each_subsystem_safe ( r,  s,  _s)


**Parameters**

``r``
  *undescribed*

``s``
  *undescribed*

``_s``
  *undescribed*


.. c:function:: nvme_for_each_subsystem ( r,  s)


**Parameters**

``r``
  *undescribed*

``s``
  *undescribed*


.. c:function:: nvme_subsystem_for_each_ctrl_safe ( s,  c,  _c)


**Parameters**

``s``
  *undescribed*

``c``
  *undescribed*

``_c``
  *undescribed*


.. c:function:: nvme_subsystem_for_each_ctrl ( s,  c)


**Parameters**

``s``
  *undescribed*

``c``
  *undescribed*


.. c:function:: nvme_ctrl_for_each_ns_safe ( c,  n,  _n)


**Parameters**

``c``
  *undescribed*

``n``
  *undescribed*

``_n``
  *undescribed*


.. c:function:: nvme_ctrl_for_each_ns ( c,  n)


**Parameters**

``c``
  *undescribed*

``n``
  *undescribed*


.. c:function:: nvme_ctrl_for_each_path_safe ( c,  p,  _p)


**Parameters**

``c``
  *undescribed*

``p``
  *undescribed*

``_p``
  *undescribed*


.. c:function:: nvme_ctrl_for_each_path ( c,  p)


**Parameters**

``c``
  *undescribed*

``p``
  *undescribed*


.. c:function:: nvme_subsystem_for_each_ns_safe ( s,  n,  _n)


**Parameters**

``s``
  *undescribed*

``n``
  *undescribed*

``_n``
  *undescribed*


.. c:function:: nvme_subsystem_for_each_ns ( s,  n)


**Parameters**

``s``
  *undescribed*

``n``
  *undescribed*


.. c:function:: int nvme_ns_get_fd (nvme_ns_t n)


**Parameters**

``nvme_ns_t n``
  *undescribed*


.. c:function:: int nvme_ns_get_nsid (nvme_ns_t n)


**Parameters**

``nvme_ns_t n``
  *undescribed*


.. c:function:: int nvme_ns_get_lba_size (nvme_ns_t n)


**Parameters**

``nvme_ns_t n``
  *undescribed*


.. c:function:: uint64_t nvme_ns_get_lba_count (nvme_ns_t n)


**Parameters**

``nvme_ns_t n``
  *undescribed*


.. c:function:: uint64_t nvme_ns_get_lba_util (nvme_ns_t n)


**Parameters**

``nvme_ns_t n``
  *undescribed*


.. c:function:: const char * nvme_ns_get_sysfs_dir (nvme_ns_t n)


**Parameters**

``nvme_ns_t n``
  *undescribed*


.. c:function:: const char * nvme_ns_get_name (nvme_ns_t n)


**Parameters**

``nvme_ns_t n``
  *undescribed*


.. c:function:: nvme_subsystem_t nvme_ns_get_subsystem (nvme_ns_t n)


**Parameters**

``nvme_ns_t n``
  *undescribed*


.. c:function:: nvme_ctrl_t nvme_ns_get_ctrl (nvme_ns_t n)


**Parameters**

``nvme_ns_t n``
  *undescribed*


.. c:function:: int nvme_ns_read (nvme_ns_t n, void * buf, off_t offset, size_t count)


**Parameters**

``nvme_ns_t n``
  *undescribed*

``void * buf``
  *undescribed*

``off_t offset``
  *undescribed*

``size_t count``
  *undescribed*


.. c:function:: int nvme_ns_write (nvme_ns_t n, void * buf, off_t offset, size_t count)


**Parameters**

``nvme_ns_t n``
  *undescribed*

``void * buf``
  *undescribed*

``off_t offset``
  *undescribed*

``size_t count``
  *undescribed*


.. c:function:: int nvme_ns_verify (nvme_ns_t n, off_t offset, size_t count)


**Parameters**

``nvme_ns_t n``
  *undescribed*

``off_t offset``
  *undescribed*

``size_t count``
  *undescribed*


.. c:function:: int nvme_ns_compare (nvme_ns_t n, void * buf, off_t offset, size_t count)


**Parameters**

``nvme_ns_t n``
  *undescribed*

``void * buf``
  *undescribed*

``off_t offset``
  *undescribed*

``size_t count``
  *undescribed*


.. c:function:: int nvme_ns_write_zeros (nvme_ns_t n, off_t offset, size_t count)


**Parameters**

``nvme_ns_t n``
  *undescribed*

``off_t offset``
  *undescribed*

``size_t count``
  *undescribed*


.. c:function:: int nvme_ns_write_uncorrectable (nvme_ns_t n, off_t offset, size_t count)


**Parameters**

``nvme_ns_t n``
  *undescribed*

``off_t offset``
  *undescribed*

``size_t count``
  *undescribed*


.. c:function:: int nvme_ns_flush (nvme_ns_t n)


**Parameters**

``nvme_ns_t n``
  *undescribed*


.. c:function:: int nvme_ns_identify (nvme_ns_t n, struct nvme_id_ns * ns)


**Parameters**

``nvme_ns_t n``
  *undescribed*

``struct nvme_id_ns * ns``
  *undescribed*


.. c:function:: const char * nvme_path_get_name (nvme_path_t p)


**Parameters**

``nvme_path_t p``
  *undescribed*


.. c:function:: const char * nvme_path_get_sysfs_dir (nvme_path_t p)


**Parameters**

``nvme_path_t p``
  *undescribed*


.. c:function:: const char * nvme_path_get_ana_state (nvme_path_t p)


**Parameters**

``nvme_path_t p``
  *undescribed*


.. c:function:: nvme_ctrl_t nvme_path_get_subsystem (nvme_path_t p)


**Parameters**

``nvme_path_t p``
  *undescribed*


.. c:function:: nvme_ns_t nvme_path_get_ns (nvme_path_t p)


**Parameters**

``nvme_path_t p``
  *undescribed*


.. c:function:: int nvme_ctrl_get_fd (nvme_ctrl_t c)


**Parameters**

``nvme_ctrl_t c``
  *undescribed*


.. c:function:: const char * nvme_ctrl_get_name (nvme_ctrl_t c)


**Parameters**

``nvme_ctrl_t c``
  *undescribed*


.. c:function:: const char * nvme_ctrl_get_sysfs_dir (nvme_ctrl_t c)


**Parameters**

``nvme_ctrl_t c``
  *undescribed*


.. c:function:: const char * nvme_ctrl_get_address (nvme_ctrl_t c)


**Parameters**

``nvme_ctrl_t c``
  *undescribed*


.. c:function:: const char * nvme_ctrl_get_firmware (nvme_ctrl_t c)


**Parameters**

``nvme_ctrl_t c``
  *undescribed*


.. c:function:: const char * nvme_ctrl_get_model (nvme_ctrl_t c)


**Parameters**

``nvme_ctrl_t c``
  *undescribed*


.. c:function:: const char * nvme_ctrl_get_state (nvme_ctrl_t c)


**Parameters**

``nvme_ctrl_t c``
  *undescribed*


.. c:function:: const char * nvme_ctrl_get_numa_node (nvme_ctrl_t c)


**Parameters**

``nvme_ctrl_t c``
  *undescribed*


.. c:function:: const char * nvme_ctrl_get_queue_count (nvme_ctrl_t c)


**Parameters**

``nvme_ctrl_t c``
  *undescribed*


.. c:function:: const char * nvme_ctrl_get_serial (nvme_ctrl_t c)


**Parameters**

``nvme_ctrl_t c``
  *undescribed*


.. c:function:: const char * nvme_ctrl_get_sqsize (nvme_ctrl_t c)


**Parameters**

``nvme_ctrl_t c``
  *undescribed*


.. c:function:: const char * nvme_ctrl_get_transport (nvme_ctrl_t c)


**Parameters**

``nvme_ctrl_t c``
  *undescribed*


.. c:function:: const char * nvme_ctrl_get_nqn (nvme_ctrl_t c)


**Parameters**

``nvme_ctrl_t c``
  *undescribed*


.. c:function:: const char * nvme_ctrl_get_subsysnqn (nvme_ctrl_t c)


**Parameters**

``nvme_ctrl_t c``
  *undescribed*


.. c:function:: nvme_subsystem_t nvme_ctrl_get_subsystem (nvme_ctrl_t c)


**Parameters**

``nvme_ctrl_t c``
  *undescribed*


.. c:function:: int nvme_ctrl_identify (nvme_ctrl_t c, struct nvme_id_ctrl * id)


**Parameters**

``nvme_ctrl_t c``
  *undescribed*

``struct nvme_id_ctrl * id``
  *undescribed*


.. c:function:: int nvme_ctrl_disconnect (nvme_ctrl_t c)


**Parameters**

``nvme_ctrl_t c``
  *undescribed*


.. c:function:: nvme_ctrl_t nvme_scan_ctrl (const char * name)


**Parameters**

``const char * name``
  *undescribed*


.. c:function:: void nvme_free_ctrl (struct nvme_ctrl * c)


**Parameters**

``struct nvme_ctrl * c``
  *undescribed*


.. c:function:: void nvme_unlink_ctrl (struct nvme_ctrl * c)


**Parameters**

``struct nvme_ctrl * c``
  *undescribed*


.. c:function:: const char * nvme_subsystem_get_nqn (nvme_subsystem_t s)


**Parameters**

``nvme_subsystem_t s``
  *undescribed*


.. c:function:: const char * nvme_subsystem_get_sysfs_dir (nvme_subsystem_t s)


**Parameters**

``nvme_subsystem_t s``
  *undescribed*


.. c:function:: const char * nvme_subsystem_get_name (nvme_subsystem_t s)


**Parameters**

``nvme_subsystem_t s``
  *undescribed*


.. c:function:: nvme_root_t nvme_scan_filter (nvme_scan_filter_t f)


**Parameters**

``nvme_scan_filter_t f``
  *undescribed*


.. c:function:: nvme_root_t nvme_scan ()


**Parameters**


.. c:function:: void nvme_refresh_topology (nvme_root_t r)


**Parameters**

``nvme_root_t r``
  *undescribed*


.. c:function:: void nvme_reset_topology (nvme_root_t r)


**Parameters**

``nvme_root_t r``
  *undescribed*


.. c:function:: void nvme_free_tree (nvme_root_t r)


**Parameters**

``nvme_root_t r``
  *undescribed*


.. c:function:: char * nvme_get_subsys_attr (nvme_subsystem_t s, const char * attr)


**Parameters**

``nvme_subsystem_t s``
  *undescribed*

``const char * attr``
  *undescribed*


.. c:function:: char * nvme_get_ctrl_attr (nvme_ctrl_t c, const char * attr)


**Parameters**

``nvme_ctrl_t c``
  *undescribed*

``const char * attr``
  *undescribed*


.. c:function:: char * nvme_get_ns_attr (nvme_ns_t n, const char * attr)


**Parameters**

``nvme_ns_t n``
  *undescribed*

``const char * attr``
  *undescribed*


.. c:function:: char * nvme_get_path_attr (nvme_path_t p, const char * attr)


**Parameters**

``nvme_path_t p``
  *undescribed*

``const char * attr``
  *undescribed*




.. c:type:: enum nvme_constants


**Constants**

``NVME_NSID_ALL``
  *undescribed*

``NVME_NSID_NONE``
  *undescribed*

``NVME_UUID_NONE``
  *undescribed*

``NVME_CNTLID_NONE``
  *undescribed*

``NVME_NVMSETID_NONE``
  *undescribed*

``NVME_LOG_LSP_NONE``
  *undescribed*

``NVME_LOG_LSI_NONE``
  *undescribed*

``NVME_IDENTIFY_DATA_SIZE``
  *undescribed*

``NVME_ID_NVMSET_LIST_MAX``
  *undescribed*

``NVME_ID_UUID_LIST_MAX``
  *undescribed*

``NVME_ID_CTRL_LIST_MAX``
  *undescribed*

``NVME_ID_NS_LIST_MAX``
  *undescribed*

``NVME_ID_SECONDARY_CTRL_MAX``
  *undescribed*

``NVME_FEAT_LBA_RANGE_MAX``
  *undescribed*

``NVME_LOG_ST_MAX_RESULTS``
  *undescribed*

``NVME_DSM_MAX_RANGES``
  *undescribed*


**NVMe controller registers/properties**




.. c:type:: enum nvme_registers


**Constants**

``NVME_REG_CAP``
  Controller Capabilities

``NVME_REG_VS``
  Version

``NVME_REG_INTMS``
  Interrupt Mask Set

``NVME_REG_INTMC``
  Interrupt Mask Clear

``NVME_REG_CC``
  Controller Configuration

``NVME_REG_CSTS``
  Controller Status

``NVME_REG_NSSR``
  NVM Subsystem Reset

``NVME_REG_AQA``
  Admin Queue Attributes

``NVME_REG_ASQ``
  Admin SQ Base Address

``NVME_REG_ACQ``
  Admin CQ Base Address

``NVME_REG_CMBLOC``
  Controller Memory Buffer Location

``NVME_REG_CMBSZ``
  Controller Memory Buffer Size

``NVME_REG_BPINFO``
  Boot Partition Information

``NVME_REG_BPRSEL``
  Boot Partition Read Select

``NVME_REG_BPMBL``
  Boot Partition Memory Buffer Location

``NVME_REG_CMBMSC``
  Controller Memory Buffer Memory Space Control

``NVME_REG_CMBSTS``
  Controller Memory Buffer Status

``NVME_REG_PMRCAP``
  Persistent Memory Capabilities

``NVME_REG_PMRCTL``
  Persistent Memory Region Control

``NVME_REG_PMRSTS``
  Persistent Memory Region Status

``NVME_REG_PMREBS``
  Persistent Memory Region Elasticity Buffer Size

``NVME_REG_PMRSWTP``
  Memory Region Sustained Write Throughput

``NVME_REG_PMRMSC``
  Persistent Memory Region Controller Memory Space Control

``NVME_REG_DBS``
  SQ 0 Tail Doorbell




.. c:type:: enum 


**Constants**

``NVME_CC_ENABLE``
  *undescribed*

``NVME_CC_CSS_NVM``
  *undescribed*

``NVME_CC_EN_SHIFT``
  *undescribed*

``NVME_CC_CSS_SHIFT``
  *undescribed*

``NVME_CC_MPS_SHIFT``
  *undescribed*

``NVME_CC_AMS_SHIFT``
  *undescribed*

``NVME_CC_SHN_SHIFT``
  *undescribed*

``NVME_CC_IOSQES_SHIFT``
  *undescribed*

``NVME_CC_IOCQES_SHIFT``
  *undescribed*

``NVME_CC_AMS_RR``
  *undescribed*

``NVME_CC_AMS_WRRU``
  *undescribed*

``NVME_CC_AMS_VS``
  *undescribed*

``NVME_CC_SHN_NONE``
  *undescribed*

``NVME_CC_SHN_NORMAL``
  *undescribed*

``NVME_CC_SHN_ABRUPT``
  *undescribed*

``NVME_CC_SHN_MASK``
  *undescribed*

``NVME_CSTS_RDY``
  *undescribed*

``NVME_CSTS_CFS``
  *undescribed*

``NVME_CSTS_NSSRO``
  *undescribed*

``NVME_CSTS_PP``
  *undescribed*

``NVME_CSTS_SHST_NORMAL``
  *undescribed*

``NVME_CSTS_SHST_OCCUR``
  *undescribed*

``NVME_CSTS_SHST_CMPLT``
  *undescribed*

``NVME_CSTS_SHST_MASK``
  *undescribed*


**NVMe Identify**




.. c:type:: struct nvme_id_psd


**Definition**

::

  struct nvme_id_psd {
    __le16 mp;
    __u8 rsvd2;
    __u8 flags;
    __le32 enlat;
    __le32 exlat;
    __u8 rrt;
    __u8 rrl;
    __u8 rwt;
    __u8 rwl;
    __le16 idlp;
    __u8 ips;
    __u8 rsvd19;
    __le16 actp;
    __u8 apw;
    __u8 aps;
    __u8 rsvd23[8];
  };

**Members**



.. c:function:: unsigned nvme_psd_power_scale (__u8 ps)

   power scale occupies the upper 3 bits

**Parameters**

``__u8 ps``
  *undescribed*




.. c:type:: enum 


**Constants**

``NVME_PSD_FLAGS_MAX_POWER_SCALE``
  *undescribed*

``NVME_PSD_FLAGS_NON_OP_STATE``
  *undescribed*

``NVME_PSD_RELATIVE_MASK``
  *undescribed*

``NVME_PSD_APW_MASK``
  *undescribed*




.. c:type:: struct nvme_id_ctrl

   Identify Controller data structure

**Definition**

::

  struct nvme_id_ctrl {
    __le16 vid;
    __le16 ssvid;
    char sn[20];
    char mn[40];
    char fr[8];
    __u8 rab;
    __u8 ieee[3];
    __u8 cmic;
    __u8 mdts;
    __le16 cntlid;
    __le32 ver;
    __le32 rtd3r;
    __le32 rtd3e;
    __le32 oaes;
    __le32 ctratt;
    __le16 rrls;
    __u8 rsvd102[9];
    __u8 cntrltype;
    __u8 fguid[16];
    __le16 crdt1;
    __le16 crdt2;
    __le16 crdt3;
    __u8 rsvd134[119];
    __u8 nvmsr;
    __u8 vwci;
    __u8 mec;
    __le16 oacs;
    __u8 acl;
    __u8 aerl;
    __u8 frmw;
    __u8 lpa;
    __u8 elpe;
    __u8 npss;
    __u8 avscc;
    __u8 apsta;
    __le16 wctemp;
    __le16 cctemp;
    __le16 mtfa;
    __le32 hmpre;
    __le32 hmmin;
    __u8 tnvmcap[16];
    __u8 unvmcap[16];
    __le32 rpmbs;
    __le16 edstt;
    __u8 dsto;
    __u8 fwug;
    __le16 kas;
    __le16 hctma;
    __le16 mntmt;
    __le16 mxtmt;
    __le32 sanicap;
    __le32 hmminds;
    __le16 hmmaxd;
    __le16 nsetidmax;
    __le16 endgidmax;
    __u8 anatt;
    __u8 anacap;
    __le32 anagrpmax;
    __le32 nanagrpid;
    __le32 pels;
    __u8 rsvd356[156];
    __u8 sqes;
    __u8 cqes;
    __le16 maxcmd;
    __le32 nn;
    __le16 oncs;
    __le16 fuses;
    __u8 fna;
    __u8 vwc;
    __le16 awun;
    __le16 awupf;
    __u8 nvscc;
    __u8 nwpc;
    __le16 acwu;
    __u8 rsvd534[2];
    __le32 sgls;
    __le32 mnan;
    __u8 rsvd544[224];
    char subnqn[256];
    __u8 rsvd1024[768];
    __le32 ioccsz;
    __le32 iorcsz;
    __le16 icdoff;
    __u8 fcatt;
    __u8 msdbd;
    __le16 ofcs;
    __u8 rsvd1806[242];
    struct nvme_id_psd      psd[32];
    __u8 vs[1024];
  };

**Members**

``vid``
  Vendor ID

``ssvid``
  Subsystem Vendor Id

``sn``
  Serial Number

``mn``
  Model Number

``fr``
  Firmware Revision

``rab``
  Recommended Arbitration Burst

``ieee``
  IEEE

``cmic``
  Controller Mulitpathing Capabilities

``mdts``
  Max Data Transfer Size

``cntlid``
  Controller Identifier

``ver``
  Version

``rtd3r``
  Runtime D3 Resume

``rtd3e``
  Runtime D3 Exit

``oaes``
  Optional Async Events Supported

``ctratt``
  Controller Attributes

``rrls``
  Read Recovery Levels

``cntrltype``
  Controller Type

``fguid``
  FRU GUID

``crdt1``
  Controller Retry Delay 1

``crdt2``
  Controller Retry Delay 2

``crdt3``
  Controller Retry Delay 3

``oacs``
  Optional Admin Commands Supported

``acl``
  Abort Command Limit

``aerl``
  Async Event Request Limit

``lpa``
  Log Page Attributes

``npss``
  Number of Power States Supported





.. c:type:: enum 


**Constants**

``NVME_CTRL_CMIC_MULTI_PORT``
  *undescribed*

``NVME_CTRL_CMIC_MULTI_CTRL``
  *undescribed*

``NVME_CTRL_CMIC_MULTI_SRIOV``
  *undescribed*

``NVME_CTRL_CMIC_MULTI_ANA_REPORTING``
  *undescribed*




.. c:type:: enum 


**Constants**

``NVME_CTRL_OAES_NA``
  *undescribed*

``NVME_CTRL_OAES_FA``
  *undescribed*

``NVME_CTRL_OAES_ANA``
  *undescribed*

``NVME_CTRL_OAES_PLEA``
  *undescribed*

``NVME_CTRL_OAES_LBAS``
  *undescribed*

``NVME_CTRL_OAES_EGE``
  *undescribed*




.. c:type:: enum 


**Constants**

``NVME_CTRL_CTRATT_128_ID``
  *undescribed*

``NVME_CTRL_CTRATT_NON_OP_PSP``
  *undescribed*

``NVME_CTRL_CTRATT_NVM_SETS``
  *undescribed*

``NVME_CTRL_CTRATT_READ_RECV_LVLS``
  *undescribed*

``NVME_CTRL_CTRATT_ENDURANCE_GROUPS``
  *undescribed*

``NVME_CTRL_CTRATT_PREDICTABLE_LAT``
  *undescribed*

``NVME_CTRL_CTRATT_TBKAS``
  *undescribed*

``NVME_CTRL_CTRATT_NAMESPACE_GRANULARITY``
  *undescribed*

``NVME_CTRL_CTRATT_SQ_ASSOCIATIONS``
  *undescribed*

``NVME_CTRL_CTRATT_UUID_LIST``
  *undescribed*




.. c:type:: enum 


**Constants**

``NVME_CTRL_CNTRLTYPE_RESERVED``
  *undescribed*

``NVME_CTRL_CNTRLTYPE_IO``
  *undescribed*

``NVME_CTRL_CNTRLTYPE_DISCOVERY``
  *undescribed*

``NVME_CTRL_CNTRLTYPE_ADMIN``
  *undescribed*




.. c:type:: enum 


**Constants**

``NVME_CTRL_NVMSR_NVMESD``
  *undescribed*

``NVME_CTRL_NVMSR_NVMEE``
  *undescribed*




.. c:type:: enum 


**Constants**

``NVME_CTRL_VWCI_VWCR``
  *undescribed*

``NVME_CTRL_VWCI_VWCRV``
  *undescribed*




.. c:type:: enum 


**Constants**

``NVME_CTRL_MEC_SMBUSME``
  *undescribed*

``NVME_CTRL_MEC_PCIEME``
  *undescribed*




.. c:type:: enum 


**Constants**

``NVME_CTRL_OACS_SECURITY``
  *undescribed*

``NVME_CTRL_OACS_FORMAT``
  *undescribed*

``NVME_CTRL_OACS_FW``
  *undescribed*

``NVME_CTRL_OACS_NS_MGMT``
  *undescribed*

``NVME_CTRL_OACS_SELF_TEST``
  *undescribed*

``NVME_CTRL_OACS_DIRECTIVES``
  *undescribed*

``NVME_CTRL_OACS_NVME_MI``
  *undescribed*

``NVME_CTRL_OACS_VIRT_MGMT``
  *undescribed*

``NVME_CTRL_OACS_DBBUF_CFG``
  *undescribed*

``NVME_CTRL_OACS_LBA_STATUS``
  *undescribed*




.. c:type:: enum 


**Constants**

``NVME_CTRL_FRMW_1ST_RO``
  *undescribed*

``NVME_CTRL_FRMW_NR_SLOTS``
  *undescribed*

``NVME_CTRL_FRMW_FW_ACT_NO_RESET``
  *undescribed*




.. c:type:: enum 


**Constants**

``NVME_CTRL_LPA_SMART_PER_NS``
  *undescribed*

``NVME_CTRL_LPA_CMD_EFFECTS``
  *undescribed*

``NVME_CTRL_LPA_EXTENDED``
  *undescribed*

``NVME_CTRL_LPA_TELEMETRY``
  *undescribed*

``NVME_CTRL_LPA_PERSETENT_EVENT``
  *undescribed*




.. c:type:: enum 


**Constants**

``NVME_CTRL_AVSCC_AVS``
  *undescribed*




.. c:type:: enum 


**Constants**

``NVME_CTRL_APSTA_APST``
  *undescribed*




.. c:type:: enum 


**Constants**

``NVME_CTRL_RPMBS_NR_UNITS``
  *undescribed*

``NVME_CTRL_RPMBS_AUTH_METHOD``
  *undescribed*

``NVME_CTRL_RPMBS_TOTAL_SIZE``
  *undescribed*

``NVME_CTRL_RPMBS_ACCESS_SIZE``
  *undescribed*




.. c:type:: enum 


**Constants**

``NVME_CTRL_DSTO_ONE_DST``
  *undescribed*




.. c:type:: enum 


**Constants**

``NVME_CTRL_HCTMA_HCTM``
  *undescribed*




.. c:type:: enum 


**Constants**

``NVME_CTRL_SANICAP_CES``
  *undescribed*

``NVME_CTRL_SANICAP_BES``
  *undescribed*

``NVME_CTRL_SANICAP_OWS``
  *undescribed*

``NVME_CTRL_SANICAP_NDI``
  *undescribed*

``NVME_CTRL_SANICAP_NODMMAS``
  *undescribed*




.. c:type:: enum 


**Constants**

``NVME_CTRL_ANACAP_OPT``
  *undescribed*

``NVME_CTRL_ANACAP_NON_OPT``
  *undescribed*

``NVME_CTRL_ANACAP_INACCESSIBLE``
  *undescribed*

``NVME_CTRL_ANACAP_PERSISTENT_LOSS``
  *undescribed*

``NVME_CTRL_ANACAP_CHANGE``
  *undescribed*

``NVME_CTRL_ANACAP_GRPID_NO_CHG``
  *undescribed*

``NVME_CTRL_ANACAP_GRPID_MGMT``
  *undescribed*




.. c:type:: enum 


**Constants**

``NVME_CTRL_SQES_MIN``
  *undescribed*

``NVME_CTRL_SQES_MAX``
  *undescribed*




.. c:type:: enum 


**Constants**

``NVME_CTRL_CQES_MIN``
  *undescribed*

``NVME_CTRL_CQES_MAX``
  *undescribed*




.. c:type:: enum 


**Constants**

``NVME_CTRL_ONCS_COMPARE``
  *undescribed*

``NVME_CTRL_ONCS_WRITE_UNCORRECTABLE``
  *undescribed*

``NVME_CTRL_ONCS_DSM``
  *undescribed*

``NVME_CTRL_ONCS_WRITE_ZEROES``
  *undescribed*

``NVME_CTRL_ONCS_SAVE_FEATURES``
  *undescribed*

``NVME_CTRL_ONCS_RESERVATIONS``
  *undescribed*

``NVME_CTRL_ONCS_TIMESTAMP``
  *undescribed*

``NVME_CTRL_ONCS_VERIFY``
  *undescribed*




.. c:type:: enum 


**Constants**

``NVME_CTRL_FUSES_COMPARE_AND_WRITE``
  *undescribed*




.. c:type:: enum 


**Constants**

``NVME_CTRL_FNA_FMT_ALL_NAMESPACES``
  *undescribed*

``NVME_CTRL_FNA_SEC_ALL_NAMESPACES``
  *undescribed*

``NVME_CTRL_FNA_CRYPTO_ERASE``
  *undescribed*




.. c:type:: enum 


**Constants**

``NVME_CTRL_VWC_PRESENT``
  *undescribed*

``NVME_CTRL_VWC_FLUSH``
  *undescribed*




.. c:type:: enum 


**Constants**

``NVME_CTRL_NVSCC_FMT``
  *undescribed*




.. c:type:: enum 


**Constants**

``NVME_CTRL_NWPC_WRITE_PROTECT``
  *undescribed*

``NVME_CTRL_NWPC_WRITE_PROTECT_POWER_CYCLE``
  *undescribed*

``NVME_CTRL_NWPC_WRITE_PROTECT_PERMANENT``
  *undescribed*




.. c:type:: enum 


**Constants**

``NVME_CTRL_SGLS_SUPPORTED``
  *undescribed*

``NVME_CTRL_SGLS_KEYED``
  *undescribed*

``NVME_CTRL_SGLS_BIT_BUCKET``
  *undescribed*

``NVME_CTRL_SGLS_MPTR_BYTE_ALIGNED``
  *undescribed*

``NVME_CTRL_SGLS_OVERSIZE``
  *undescribed*

``NVME_CTRL_SGLS_MPTR_SGL``
  *undescribed*

``NVME_CTRL_SGLS_OFFSET``
  *undescribed*

``NVME_CTRL_SGLS_TPORT``
  *undescribed*




.. c:type:: enum 


**Constants**

``NVME_CTRL_FCATT_DYNAMIC``
  *undescribed*




.. c:type:: enum 


**Constants**

``NVME_CTRL_OFCS_DISCONNECT``
  *undescribed*




.. c:type:: struct nvme_lbaf


**Definition**

::

  struct nvme_lbaf {
    __le16 ms;
    __u8 ds;
    __u8 rp;
  };

**Members**





.. c:type:: enum 


**Constants**

``NVME_LBAF_RP_BEST``
  *undescribed*

``NVME_LBAF_RP_BETTER``
  *undescribed*

``NVME_LBAF_RP_GOOD``
  *undescribed*

``NVME_LBAF_RP_DEGRADED``
  *undescribed*

``NVME_LBAF_RP_MASK``
  *undescribed*




.. c:type:: struct nvme_id_ns


**Definition**

::

  struct nvme_id_ns {
    __le64 nsze;
    __le64 ncap;
    __le64 nuse;
    __u8 nsfeat;
    __u8 nlbaf;
    __u8 flbas;
    __u8 mc;
    __u8 dpc;
    __u8 dps;
    __u8 nmic;
    __u8 rescap;
    __u8 fpi;
    __u8 dlfeat;
    __le16 nawun;
    __le16 nawupf;
    __le16 nacwu;
    __le16 nabsn;
    __le16 nabo;
    __le16 nabspf;
    __le16 noiob;
    __u8 nvmcap[16];
    __le16 npwg;
    __le16 npwa;
    __le16 npdg;
    __le16 npda;
    __le16 nows;
    __u8 rsvd74[18];
    __le32 anagrpid;
    __u8 rsvd96[3];
    __u8 nsattr;
    __le16 nvmsetid;
    __le16 endgid;
    __u8 nguid[16];
    __u8 eui64[8];
    struct nvme_lbaf        lbaf[16];
    __u8 rsvd192[192];
    __u8 vs[3712];
  };

**Members**





.. c:type:: enum 


**Constants**

``NVME_NS_FEAT_THIN``
  *undescribed*

``NVME_NS_FEAT_NATOMIC``
  *undescribed*

``NVME_NS_FEAT_DULBE``
  *undescribed*

``NVME_NS_FEAT_ID_REUSE``
  *undescribed*

``NVME_NS_FEAT_IO_OPT``
  *undescribed*




.. c:type:: enum 


**Constants**

``NVME_NS_FLBAS_LBA_MASK``
  *undescribed*

``NVME_NS_FLBAS_META_EXT``
  *undescribed*




.. c:type:: enum 


**Constants**

``NVME_NS_MC_EXTENDED``
  *undescribed*

``NVME_NS_MC_SEPARATE``
  *undescribed*




.. c:type:: enum 


**Constants**

``NVME_NS_DPC_PI_TYPE1``
  *undescribed*

``NVME_NS_DPC_PI_TYPE2``
  *undescribed*

``NVME_NS_DPC_PI_TYPE3``
  *undescribed*

``NVME_NS_DPC_PI_FIRST``
  *undescribed*

``NVME_NS_DPC_PI_LAST``
  *undescribed*




.. c:type:: enum 


**Constants**

``NVME_NS_DPS_PI_NONE``
  *undescribed*

``NVME_NS_DPS_PI_TYPE1``
  *undescribed*

``NVME_NS_DPS_PI_TYPE2``
  *undescribed*

``NVME_NS_DPS_PI_TYPE3``
  *undescribed*

``NVME_NS_DPS_PI_MASK``
  *undescribed*

``NVME_NS_DPS_PI_FIRST``
  *undescribed*




.. c:type:: enum 


**Constants**

``NVME_NS_NMIC_SHARED``
  *undescribed*




.. c:type:: enum 


**Constants**

``NVME_NS_RESCAP_PTPL``
  *undescribed*

``NVME_NS_RESCAP_WE``
  *undescribed*

``NVME_NS_RESCAP_EA``
  *undescribed*

``NVME_NS_RESCAP_WERO``
  *undescribed*

``NVME_NS_RESCAP_EARO``
  *undescribed*

``NVME_NS_RESCAP_WEAR``
  *undescribed*

``NVME_NS_RESCAP_EAAR``
  *undescribed*

``NVME_NS_RESCAP_IEK_13``
  *undescribed*




.. c:type:: enum 


**Constants**

``NVME_NS_FPI_REMAINING``
  *undescribed*

``NVME_NS_FPI_SUPPORTED``
  *undescribed*




.. c:type:: enum 


**Constants**

``NVME_NS_DLFEAT_RB``
  *undescribed*

``NVME_NS_DLFEAT_RB_NR``
  *undescribed*

``NVME_NS_DLFEAT_RB_ALL_0S``
  *undescribed*

``NVME_NS_DLFEAT_RB_ALL_FS``
  *undescribed*

``NVME_NS_DLFEAT_WRITE_ZEROES``
  *undescribed*

``NVME_NS_DLFEAT_CRC_GUARD``
  *undescribed*




.. c:type:: enum 


**Constants**

``NVME_NS_NSATTR_WRITE_PROTECTED``
  *undescribed*




.. c:type:: struct nvme_ns_id_desc


**Definition**

::

  struct nvme_ns_id_desc {
    __u8 nidt;
    __u8 nidl;
    __le16 reserved;
    __u8 nid[];
  };

**Members**





.. c:type:: enum 


**Constants**

``NVME_NIDT_EUI64``
  *undescribed*

``NVME_NIDT_NGUID``
  *undescribed*

``NVME_NIDT_UUID``
  *undescribed*




.. c:type:: struct nvme_nvmset_attr


**Definition**

::

  struct nvme_nvmset_attr {
    __le16 id;
    __le16 endurance_group_id;
    __u8 rsvd4[4];
    __le32 random_4k_read_typical;
    __le32 opt_write_size;
    __u8 total_nvmset_cap[16];
    __u8 unalloc_nvmset_cap[16];
    __u8 rsvd48[80];
  };

**Members**





.. c:type:: struct nvme_id_nvmset_list


**Definition**

::

  struct nvme_id_nvmset_list {
    __u8 nid;
    __u8 rsvd1[127];
    struct nvme_nvmset_attr ent[NVME_ID_NVMSET_LIST_MAX];
  };

**Members**





.. c:type:: struct nvme_id_ns_granularity_list_entry


**Definition**

::

  struct nvme_id_ns_granularity_list_entry {
    __le64 namespace_size_granularity;
    __le64 namespace_capacity_granularity;
  };

**Members**





.. c:type:: struct nvme_id_ns_granularity_list


**Definition**

::

  struct nvme_id_ns_granularity_list {
    __le32 attributes;
    __u8 num_descriptors;
    __u8 rsvd[27];
    struct nvme_id_ns_granularity_list_entry entry[16];
  };

**Members**





.. c:type:: struct nvme_id_uuid_list_entry


**Definition**

::

  struct nvme_id_uuid_list_entry {
    __u8 header;
    __u8 rsvd1[15];
    __u8 uuid[16];
  };

**Members**





.. c:type:: enum 


**Constants**

``NVME_ID_UUID_HDR_ASSOCIATION_MASK``
  *undescribed*

``NVME_ID_UUID_ASSOCIATION_NONE``
  *undescribed*

``NVME_ID_UUID_ASSOCIATION_VENDOR``
  *undescribed*

``NVME_ID_UUID_ASSOCIATION_SUBSYSTEM_VENDOR``
  *undescribed*




.. c:type:: struct nvme_id_uuid_list


**Definition**

::

  struct nvme_id_uuid_list {
    __u8 rsvd0[32];
    struct nvme_id_uuid_list_entry entry[NVME_ID_UUID_LIST_MAX];
  };

**Members**





.. c:type:: struct nvme_ctrl_list


**Definition**

::

  struct nvme_ctrl_list {
    __le16 num;
    __le16 identifier[NVME_ID_CTRL_LIST_MAX];
  };

**Members**





.. c:type:: struct nvme_ns_list


**Definition**

::

  struct nvme_ns_list {
    __le32 ns[NVME_ID_NS_LIST_MAX];
  };

**Members**





.. c:type:: struct nvme_primary_ctrl_cap


**Definition**

::

  struct nvme_primary_ctrl_cap {
    __le16 cntlid;
    __le16 portid;
    __u8 crt;
    __u8 rsvd5[27];
    __le32 vqfrt;
    __le32 vqrfa;
    __le16 vqrfap;
    __le16 vqprt;
    __le16 vqfrsm;
    __le16 vqgran;
    __u8 rsvd48[16];
    __le32 vifrt;
    __le32 virfa;
    __le16 virfap;
    __le16 viprt;
    __le16 vifrsm;
    __le16 vigran;
    __u8 rsvd80[4016];
  };

**Members**





.. c:type:: struct nvme_secondary_ctrl


**Definition**

::

  struct nvme_secondary_ctrl {
    __le16 scid;
    __le16 pcid;
    __u8 scs;
    __u8 rsvd5[3];
    __le16 vfn;
    __le16 nvq;
    __le16 nvi;
    __u8 rsvd14[18];
  };

**Members**





.. c:type:: struct nvme_secondary_ctrl_list


**Definition**

::

  struct nvme_secondary_ctrl_list {
    __u8 num;
    __u8 rsvd[31];
    struct nvme_secondary_ctrl sc_entry[NVME_ID_SECONDARY_CTRL_MAX];
  };

**Members**



**NVMe Logs**




.. c:type:: struct nvme_error_log_page


**Definition**

::

  struct nvme_error_log_page {
    __le64 error_count;
    __le16 sqid;
    __le16 cmdid;
    __le16 status_field;
    __le16 parm_error_location;
    __le64 lba;
    __le32 nsid;
    __u8 vs;
    __u8 trtype;
    __u8 resv[2];
    __le64 cs;
    __le16 trtype_spec_info;
    __u8 resv2[22];
  };

**Members**





.. c:type:: enum 


**Constants**

``NVME_ERR_PEL_BYTE_MASK``
  *undescribed*

``NVME_ERR_PEL_BIT_MASK``
  *undescribed*




.. c:type:: struct nvme_smart_log


**Definition**

::

  struct nvme_smart_log {
    __u8 critical_warning;
    __u8 temperature[2];
    __u8 avail_spare;
    __u8 spare_thresh;
    __u8 percent_used;
    __u8 endu_grp_crit_warn_sumry;
    __u8 rsvd7[25];
    __u8 data_units_read[16];
    __u8 data_units_written[16];
    __u8 host_reads[16];
    __u8 host_writes[16];
    __u8 ctrl_busy_time[16];
    __u8 power_cycles[16];
    __u8 power_on_hours[16];
    __u8 unsafe_shutdowns[16];
    __u8 media_errors[16];
    __u8 num_err_log_entries[16];
    __le32 warning_temp_time;
    __le32 critical_comp_time;
    __le16 temp_sensor[8];
    __le32 thm_temp1_trans_count;
    __le32 thm_temp2_trans_count;
    __le32 thm_temp1_total_time;
    __le32 thm_temp2_total_time;
    __u8 rsvd232[280];
  };

**Members**





.. c:type:: enum 


**Constants**

``NVME_SMART_CRIT_SPARE``
  *undescribed*

``NVME_SMART_CRIT_TEMPERATURE``
  *undescribed*

``NVME_SMART_CRIT_DEGRADED``
  *undescribed*

``NVME_SMART_CRIT_MEDIA``
  *undescribed*

``NVME_SMART_CRIT_VOLATILE_MEMORY``
  *undescribed*

``NVME_SMART_CRIT_PMR_RO``
  *undescribed*




.. c:type:: enum 


**Constants**

``NVME_SMART_EGCW_SPARE``
  *undescribed*

``NVME_SMART_EGCW_DEGRADED``
  *undescribed*

``NVME_SMART_EGCW_RO``
  *undescribed*




.. c:type:: struct nvme_frs


**Definition**

::

  struct nvme_frs {
    char frs[8];
  };

**Members**





.. c:type:: struct nvme_firmware_slot


**Definition**

::

  struct nvme_firmware_slot {
    __u8 afi;
    __u8 resv[7];
    struct nvme_frs frs[7];
    __u8 resv2[448];
  };

**Members**





.. c:type:: struct nvme_cmd_effects_log


**Definition**

::

  struct nvme_cmd_effects_log {
    __le32 acs[256];
    __le32 iocs[256];
    __u8 resv[2048];
  };

**Members**





.. c:type:: enum 


**Constants**

``NVME_CMD_EFFECTS_CSUPP``
  *undescribed*

``NVME_CMD_EFFECTS_LBCC``
  *undescribed*

``NVME_CMD_EFFECTS_NCC``
  *undescribed*

``NVME_CMD_EFFECTS_NIC``
  *undescribed*

``NVME_CMD_EFFECTS_CCC``
  *undescribed*

``NVME_CMD_EFFECTS_CSE_MASK``
  *undescribed*

``NVME_CMD_EFFECTS_UUID_SEL``
  *undescribed*




.. c:type:: struct nvme_st_result


**Definition**

::

  struct nvme_st_result {
    __u8 dsts;
    __u8 seg;
    __u8 vdi;
    __u8 rsvd;
    __le64 poh;
    __le32 nsid;
    __le64 flba;
    __u8 sct;
    __u8 sc;
    __u8 vs[2];
  };

**Members**





.. c:type:: enum 


**Constants**

``NVME_ST_RESULT_NO_ERR``
  *undescribed*

``NVME_ST_RESULT_ABORTED``
  *undescribed*

``NVME_ST_RESULT_CLR``
  *undescribed*

``NVME_ST_RESULT_NS_REMOVED``
  *undescribed*

``NVME_ST_RESULT_ABORTED_FORMAT``
  *undescribed*

``NVME_ST_RESULT_FATAL_ERR``
  *undescribed*

``NVME_ST_RESULT_UNKNOWN_SEG_FAIL``
  *undescribed*

``NVME_ST_RESULT_KNOWN_SEG_FAIL``
  *undescribed*

``NVME_ST_RESULT_ABORTED_UNKNOWN``
  *undescribed*

``NVME_ST_RESULT_ABORTED_SANITIZE``
  *undescribed*

``NVME_ST_RESULT_NOT_USED``
  *undescribed*




.. c:type:: enum 


**Constants**

``NVME_ST_OPERATION_NONE``
  *undescribed*

``NVME_ST_OPERATION_SHORT``
  *undescribed*

``NVME_ST_OPERATION_EXTENDED``
  *undescribed*

``NVME_ST_OPERATION_VS``
  *undescribed*




.. c:type:: enum 


**Constants**

``NVME_ST_VALID_DIAG_INFO_NSID``
  *undescribed*

``NVME_ST_VALID_DIAG_INFO_FLBA``
  *undescribed*

``NVME_ST_VALID_DIAG_INFO_SCT``
  *undescribed*

``NVME_ST_VALID_DIAG_INFO_SC``
  *undescribed*




.. c:type:: struct nvme_self_test_log


**Definition**

::

  struct nvme_self_test_log {
    __u8 current_operation;
    __u8 completion;
    __u8 rsvd[2];
    struct nvme_st_result   result[NVME_LOG_ST_MAX_RESULTS];
  };

**Members**





.. c:type:: struct nvme_telemetry_log


**Definition**

::

  struct nvme_telemetry_log {
    __u8 lpi;
    __u8 rsvd[4];
    __u8 ieee[3];
    __le16 dalb1;
    __le16 dalb2;
    __le16 dalb3;
    __u8 rsvd1[368];
    __u8 ctrlavail;
    __u8 ctrldgn;
    __u8 rsnident[128];
    __u8 telemetry_dataarea[];
  };

**Members**





.. c:type:: struct nvme_endurance_group_log


**Definition**

::

  struct nvme_endurance_group_log {
    __u8 critical_warning;
    __u8 rsvd1[2];
    __u8 avl_spare;
    __u8 avl_spare_threshold;
    __u8 percent_used;
    __u8 rsvd6[26];
    __u8 endurance_estimate[16];
    __u8 data_units_read[16];
    __u8 data_units_written[16];
    __u8 media_units_written[16];
    __u8 host_read_cmds[16];
    __u8 host_write_cmds[16];
    __u8 media_data_integrity_err[16];
    __u8 num_err_info_log_entries[16];
    __u8 rsvd160[352];
  };

**Members**





.. c:type:: enum nvme_eg_critical_warning_flags


**Constants**

``NVME_EG_CRITICAL_WARNING_SPARE``
  *undescribed*

``NVME_EG_CRITICAL_WARNING_DEGRADED``
  *undescribed*

``NVME_EG_CRITICAL_WARNING_READ_ONLY``
  *undescribed*




.. c:type:: struct nvme_aggregate_endurance_group_event


**Definition**

::

  struct nvme_aggregate_endurance_group_event {
    __le64 num_entries;
    __le16 entries[];
  };

**Members**





.. c:type:: struct nvme_nvmset_predictable_lat_log


**Definition**

::

  struct nvme_nvmset_predictable_lat_log {
    __u8 status;
    __u8 rsvd1;
    __le16 event_type;
    __u8 rsvd4[28];
    __le64 dtwin_rt;
    __le64 dtwin_wt;
    __le64 dtwin_tmax;
    __le64 dtwin_tmin_hi;
    __le64 dtwin_tmin_lo;
    __u8 rsvd72[56];
    __le64 dtwin_re;
    __le64 dtwin_we;
    __le64 dtwin_te;
    __u8 rsvd152[360];
  };

**Members**





.. c:type:: enum 


**Constants**

``NVME_NVMSET_PL_STATUS_DISABLED``
  *undescribed*

``NVME_NVMSET_PL_STATUS_DTWIN``
  *undescribed*

``NVME_NVMSET_PL_STATUS_NDWIN``
  *undescribed*




.. c:type:: enum 


**Constants**

``NVME_NVMSET_PL_EVENT_DTWIN_READ_WARN``
  *undescribed*

``NVME_NVMSET_PL_EVENT_DTWIN_WRITE_WARN``
  *undescribed*

``NVME_NVMSET_PL_EVENT_DTWIN_TIME_WARN``
  *undescribed*

``NVME_NVMSET_PL_EVENT_DTWIN_EXCEEDED``
  *undescribed*

``NVME_NVMSET_PL_EVENT_DTWIN_EXCURSION``
  *undescribed*




.. c:type:: struct nvme_aggregate_predictable_lat_event


**Definition**

::

  struct nvme_aggregate_predictable_lat_event {
    __le64 num_entries;
    __le16 entries[];
  };

**Members**





.. c:type:: struct nvme_ana_group_desc


**Definition**

::

  struct nvme_ana_group_desc {
    __le32 grpid;
    __le32 nnsids;
    __le64 chgcnt;
    __u8 state;
    __u8 rsvd17[15];
    __le32 nsids[];
  };

**Members**





.. c:type:: enum 


**Constants**

``NVME_ANA_STATE_OPTIMIZED``
  *undescribed*

``NVME_ANA_STATE_NONOPTIMIZED``
  *undescribed*

``NVME_ANA_STATE_INACCESSIBLE``
  *undescribed*

``NVME_ANA_STATE_PERSISTENT_LOSS``
  *undescribed*

``NVME_ANA_STATE_CHANGE``
  *undescribed*




.. c:type:: struct nvme_ana_log


**Definition**

::

  struct nvme_ana_log {
    __le64 chgcnt;
    __le16 ngrps;
    __u8 rsvd10[6];
    struct nvme_ana_group_desc descs[];
  };

**Members**





.. c:type:: struct nvme_persistent_event_log


**Definition**

::

  struct nvme_persistent_event_log {
    __u8 lid;
    __u8 rsvd1[3];
    __le32 ttl;
    __u8 rv;
    __u8 rsvd17;
    __le16 lht;
    __le64 ts;
    __u8 poh[16];
    __le64 pcc;
    __le16 vid;
    __le16 ssvid;
    char sn[20];
    char mn[40];
    char subnqn[256];
    __u8 rsvd372;
    __u8 seb[32];
  };

**Members**





.. c:type:: struct nvme_lba_rd


**Definition**

::

  struct nvme_lba_rd {
    __le64 rslba;
    __le32 rnlb;
    __u8 rsvd12[4];
  };

**Members**





.. c:type:: struct nvme_lbas_ns_element


**Definition**

::

  struct nvme_lbas_ns_element {
    __le32 neid;
    __le32 nrld;
    __u8 ratype;
    __u8 rsvd8[7];
    struct nvme_lba_rd lba_rd[];
  };

**Members**





.. c:type:: enum nvme_lba_status_atype


**Constants**

``NVME_LBA_STATUS_ATYPE_SCAN_UNTRACKED``
  *undescribed*

``NVME_LBA_STATUS_ATYPE_SCAN_TRACKED``
  *undescribed*




.. c:type:: struct nvme_lba_status_log


**Definition**

::

  struct nvme_lba_status_log {
    __le32 lslplen;
    __le32 nlslne;
    __le32 estulb;
    __u8 rsvd12[2];
    __le16 lsgc;
    struct nvme_lbas_ns_element elements[];
  };

**Members**





.. c:type:: struct nvme_eg_event_aggregate_log


**Definition**

::

  struct nvme_eg_event_aggregate_log {
    __le64 nr_entries;
    __le16 egids[];
  };

**Members**





.. c:type:: struct nvme_resv_notification_log


**Definition**

::

  struct nvme_resv_notification_log {
    __le64 lpc;
    __u8 rnlpt;
    __u8 nalp;
    __u8 rsvd9[2];
    __le32 nsid;
    __u8 rsvd16[48];
  };

**Members**





.. c:type:: enum 


**Constants**

``NVME_RESV_NOTIFY_RNLPT_EMPTY``
  *undescribed*

``NVME_RESV_NOTIFY_RNLPT_REGISTRATION_PREEMPTED``
  *undescribed*

``NVME_RESV_NOTIFY_RNLPT_RESERVATION_RELEASED``
  *undescribed*

``NVME_RESV_NOTIFY_RNLPT_RESERVATION_PREEMPTED``
  *undescribed*




.. c:type:: struct nvme_sanitize_log_page


**Definition**

::

  struct nvme_sanitize_log_page {
    __le16 sprog;
    __le16 sstat;
    __le32 scdw10;
    __le32 eto;
    __le32 etbe;
    __le32 etce;
    __le32 etond;
    __le32 etbend;
    __le32 etcend;
    __u8 rsvd32[480];
  };

**Members**



**NVMe Directives**




.. c:type:: enum 


**Constants**

``NVME_SANITIZE_SSTAT_NEVER_SANITIZED``
  *undescribed*

``NVME_SANITIZE_SSTAT_COMPLETE_SUCCESS``
  *undescribed*

``NVME_SANITIZE_SSTAT_IN_PROGESS``
  *undescribed*

``NVME_SANITIZE_SSTAT_COMPLETED_FAILED``
  *undescribed*

``NVME_SANITIZE_SSTAT_ND_COMPLETE_SUCCESS``
  *undescribed*




.. c:type:: struct nvme_lba_status_desc


**Definition**

::

  struct nvme_lba_status_desc {
    __le64 dslba;
    __le32 nlb;
    __u8 rsvd12;
    __u8 status;
    __u8 rsvd14[2];
  };

**Members**





.. c:type:: struct nvme_lba_status


**Definition**

::

  struct nvme_lba_status {
    __le32 nlsd;
    __u8 cmpc;
    __u8 rsvd5[3];
    struct nvme_lba_status_desc descs[];
  };

**Members**



**NVMe Management Interface**




.. c:type:: struct nvme_mi_read_nvm_ss_info


**Definition**

::

  struct nvme_mi_read_nvm_ss_info {
    __u8 nump;
    __u8 mjr;
    __u8 mnr;
    __u8 rsvd3[29];
  };

**Members**





.. c:type:: struct nvme_mi_port_pcie


**Definition**

::

  struct nvme_mi_port_pcie {
    __u8 mps;
    __u8 sls;
    __u8 cls;
    __u8 mlw;
    __u8 nlw;
    __u8 pn;
    __u8 rsvd14[18];
  };

**Members**





.. c:type:: struct nvme_mi_port_smb


**Definition**

::

  struct nvme_mi_port_smb {
    __u8 vpd_addr;
    __u8 mvpd_freq;
    __u8 mme_addr;
    __u8 mme_freq;
    __u8 nvmebm;
    __u8 rsvd13[19];
  };

**Members**





.. c:type:: struct nvme_mi_read_port_info


**Definition**

::

  struct nvme_mi_read_port_info {
    __u8 portt;
    __u8 rsvd1;
    __le16 mmctptus;
    __le32 meb;
    union {
      struct nvme_mi_port_pcie pcie;
      struct nvme_mi_port_smb smb;
    };
  };

**Members**

``{unnamed_union}``
  anonymous





.. c:type:: struct nvme_mi_read_ctrl_info


**Definition**

::

  struct nvme_mi_read_ctrl_info {
    __u8 portid;
    __u8 rsvd1[4];
    __u8 prii;
    __le16 pri;
    __le16 vid;
    __le16 did;
    __le16 ssvid;
    __le16 ssid;
    __u8 rsvd16[16];
  };

**Members**





.. c:type:: struct nvme_mi_osc


**Definition**

::

  struct nvme_mi_osc {
    __u8 type;
    __u8 opc;
  };

**Members**





.. c:type:: struct nvme_mi_read_sc_list


**Definition**

::

  struct nvme_mi_read_sc_list {
    __le16 numcmd;
    struct nvme_mi_osc cmds[];
  };

**Members**





.. c:type:: struct nvme_mi_nvm_ss_health_status


**Definition**

::

  struct nvme_mi_nvm_ss_health_status {
    __u8 nss;
    __u8 sw;
    __u8 ctemp;
    __u8 pdlu;
    __le16 ccs;
    __u8 rsvd8[2];
  };

**Members**





.. c:type:: enum 


**Constants**

``NVME_MI_CCS_RDY``
  *undescribed*

``NVME_MI_CSS_CFS``
  *undescribed*

``NVME_MI_CSS_SHST``
  *undescribed*

``NVME_MI_CSS_NSSRO``
  *undescribed*

``NVME_MI_CSS_CECO``
  *undescribed*

``NVME_MI_CSS_NAC``
  *undescribed*

``NVME_MI_CSS_FA``
  *undescribed*

``NVME_MI_CSS_CSTS``
  *undescribed*

``NVME_MI_CSS_CTEMP``
  *undescribed*

``NVME_MI_CSS_PDLU``
  *undescribed*

``NVME_MI_CSS_SPARE``
  *undescribed*

``NVME_MI_CSS_CCWARN``
  *undescribed*




.. c:type:: struct nvme_mi_ctrl_heal_status


**Definition**

::

  struct nvme_mi_ctrl_heal_status {
    __le16 ctlid;
    __le16 csts;
    __le16 ctemp;
    __u8 pdlu;
    __u8 spare;
    __u8 cwarn;
    __u8 rsvd9[7];
  };

**Members**





.. c:type:: enum 


**Constants**

``NVME_MI_CSTS_RDY``
  *undescribed*

``NVME_MI_CSTS_CFS``
  *undescribed*

``NVME_MI_CSTS_SHST``
  *undescribed*

``NVME_MI_CSTS_NSSRO``
  *undescribed*

``NVME_MI_CSTS_CECO``
  *undescribed*

``NVME_MI_CSTS_NAC``
  *undescribed*

``NVME_MI_CSTS_FA``
  *undescribed*

``NVME_MI_CWARN_ST``
  *undescribed*

``NVME_MI_CWARN_TAUT``
  *undescribed*

``NVME_MI_CWARN_RD``
  *undescribed*

``NVME_MI_CWARN_RO``
  *undescribed*

``NVME_MI_CWARN_VMBF``
  *undescribed*




.. c:type:: struct nvme_mi_vpd_mra


**Definition**

::

  struct nvme_mi_vpd_mra {
    __u8 nmravn;
    __u8 ff;
    __u8 rsvd7[6];
    __u8 i18vpwr;
    __u8 m18vpwr;
    __u8 i33vpwr;
    __u8 m33vpwr;
    __u8 rsvd17;
    __u8 m33vapsr;
    __u8 i5vapsr;
    __u8 m5vapsr;
    __u8 i12vapsr;
    __u8 m12vapsr;
    __u8 mtl;
    __u8 tnvmcap[16];
    __u8 rsvd37[27];
  };

**Members**





.. c:type:: struct nvme_mi_vpd_ppmra


**Definition**

::

  struct nvme_mi_vpd_ppmra {
    __u8 nppmravn;
    __u8 pn;
    __u8 ppi;
    __u8 ls;
    __u8 mlw;
    __u8 mctp;
    __u8 refccap;
    __u8 pi;
    __u8 rsvd13[3];
  };

**Members**





.. c:type:: struct nvme_mi_vpd_telem


**Definition**

::

  struct nvme_mi_vpd_telem {
    __u8 type;
    __u8 rev;
    __u8 len;
    __u8 data[0];
  };

**Members**





.. c:type:: enum 


**Constants**

``NVME_MI_ELEM_EED``
  *undescribed*

``NVME_MI_ELEM_USCE``
  *undescribed*

``NVME_MI_ELEM_ECED``
  *undescribed*

``NVME_MI_ELEM_LED``
  *undescribed*

``NVME_MI_ELEM_SMBMED``
  *undescribed*

``NVME_MI_ELEM_PCIESED``
  *undescribed*

``NVME_MI_ELEM_NVMED``
  *undescribed*




.. c:type:: struct nvme_mi_vpd_tra


**Definition**

::

  struct nvme_mi_vpd_tra {
    __u8 vn;
    __u8 rsvd6;
    __u8 ec;
    struct nvme_mi_vpd_telem elems[0];
  };

**Members**





.. c:type:: struct nvme_mi_vpd_mr_common


**Definition**

::

  struct nvme_mi_vpd_mr_common {
    __u8 type;
    __u8 rf;
    __u8 rlen;
    __u8 rchksum;
    __u8 hchksum;
    union {
      struct nvme_mi_vpd_mra nmra;
      struct nvme_mi_vpd_ppmra ppmra;
      struct nvme_mi_vpd_tra tmra;
    };
  };

**Members**

``{unnamed_union}``
  anonymous





.. c:type:: struct nvme_mi_vpd_hdr


**Definition**

::

  struct nvme_mi_vpd_hdr {
    __u8 ipmiver;
    __u8 iuaoff;
    __u8 ciaoff;
    __u8 biaoff;
    __u8 piaoff;
    __u8 mrioff;
    __u8 rsvd6;
    __u8 chchk;
    __u8 vpd[];
  };

**Members**



**NVMe Features**




.. c:type:: struct nvme_feat_auto_pst


**Definition**

::

  struct nvme_feat_auto_pst {
    __le64 apst_entry[32];
  };

**Members**





.. c:type:: struct nvme_timestamp


**Definition**

::

  struct nvme_timestamp {
    __u8 timestamp[6];
    __u8 attr;
    __u8 rsvd;
  };

**Members**





.. c:type:: struct nvme_lba_range_type_entry


**Definition**

::

  struct nvme_lba_range_type_entry {
    __u8 type;
    __u8 attributes;
    __u8 rsvd2[14];
    __u64 slba;
    __u64 nlb;
    __u8 guid[16];
    __u8 rsvd48[16];
  };

**Members**





.. c:type:: enum 


**Constants**

``NVME_LBART_TYPE_GP``
  *undescribed*

``NVME_LBART_TYPE_FS``
  *undescribed*

``NVME_LBART_TYPE_RAID``
  *undescribed*

``NVME_LBART_TYPE_CACHE``
  *undescribed*

``NVME_LBART_TYPE_SWAP``
  *undescribed*

``NVME_LBART_ATTRIB_TEMP``
  *undescribed*

``NVME_LBART_ATTRIB_HIDE``
  *undescribed*




.. c:type:: struct nvme_lba_range_type


**Definition**

::

  struct nvme_lba_range_type {
    struct nvme_lba_range_type_entry entry[NVME_FEAT_LBA_RANGE_MAX];
  };

**Members**





.. c:type:: struct nvme_plm_config


**Definition**

::

  struct nvme_plm_config {
    __le16 ee;
    __u8 rsvd2[30];
    __le64 dtwinrt;
    __le64 dtwinwt;
    __le64 dtwintt;
    __u8 rsvd56[456];
  };

**Members**





.. c:type:: struct nvme_feat_host_behavior


**Definition**

::

  struct nvme_feat_host_behavior {
    __u8 acre;
    __u8 resv1[511];
  };

**Members**





.. c:type:: enum 


**Constants**

``NVME_ENABLE_ACRE``
  *undescribed*




.. c:type:: struct nvme_dsm_range


**Definition**

::

  struct nvme_dsm_range {
    __le32 cattr;
    __le32 nlb;
    __le64 slba;
  };

**Members**





.. c:type:: struct nvme_registered_ctrl


**Definition**

::

  struct nvme_registered_ctrl {
    __le16 cntlid;
    __u8 rcsts;
    __u8 rsvd3[5];
    __le64 hostid;
    __le64 rkey;
  };

**Members**





.. c:type:: struct nvme_registered_ctrl_ext


**Definition**

::

  struct nvme_registered_ctrl_ext {
    __le16 cntlid;
    __u8 rcsts;
    __u8 resv3[5];
    __le64 rkey;
    __u8 hostid[16];
    __u8 resv32[32];
  };

**Members**





.. c:type:: struct nvme_reservation_status


**Definition**

::

  struct nvme_reservation_status {
    __le32 gen;
    __u8 rtype;
    __u8 regctl[2];
    __u8 rsvd7[2];
    __u8 ptpls;
    __u8 rsvd10[14];
    union {
      struct {
        __u8 resv24[40];
        struct nvme_registered_ctrl_ext regctl_eds[0];
      };
      struct nvme_registered_ctrl regctl_ds[0];
    };
  };

**Members**

``{unnamed_union}``
  anonymous

``{unnamed_struct}``
  anonymous





.. c:type:: struct nvme_streams_directive_params


**Definition**

::

  struct nvme_streams_directive_params {
    __le16 msl;
    __le16 nssa;
    __le16 nsso;
    __u8 nssc;
    __u8 rsvd[9];
    __le32 sws;
    __le16 sgs;
    __le16 nsa;
    __le16 nso;
    __u8 rsvd2[6];
  };

**Members**





.. c:type:: struct nvme_streams_directive_status


**Definition**

::

  struct nvme_streams_directive_status {
    __le16 osc;
    __le16 sid[];
  };

**Members**





.. c:type:: struct nvme_id_directives


**Definition**

::

  struct nvme_id_directives {
    __u8 supported[32];
    __u8 enabled[32];
    __u8 rsvd64[4032];
  };

**Members**





.. c:type:: enum 


**Constants**

``NVME_ID_DIR_ID_BIT``
  *undescribed*

``NVME_ID_DIR_SD_BIT``
  *undescribed*




.. c:type:: struct nvme_host_mem_buf_desc


**Definition**

::

  struct nvme_host_mem_buf_desc {
    __le64 addr;
    __le32 size;
    __u32 rsvd;
  };

**Members**





.. c:type:: enum nvme_ae_type


**Constants**

``NVME_AER_ERROR``
  *undescribed*

``NVME_AER_SMART``
  *undescribed*

``NVME_AER_NOTICE``
  *undescribed*

``NVME_AER_CSS``
  *undescribed*

``NVME_AER_VS``
  *undescribed*




.. c:type:: enum nvme_ae_info_error


**Constants**

``NVME_AER_ERROR_INVALID_DB_REG``
  *undescribed*

``NVME_AER_ERROR_INVALID_DB_VAL``
  *undescribed*

``NVME_AER_ERROR_DIAG_FAILURE``
  *undescribed*

``NVME_AER_ERROR_PERSISTENT_INTERNAL_ERROR``
  *undescribed*

``NVME_AER_ERROR_TRANSIENT_INTERNAL_ERROR``
  *undescribed*

``NVME_AER_ERROR_FW_IMAGE_LOAD_ERROR``
  *undescribed*




.. c:type:: enum nvme_ae_info_smart


**Constants**

``NVME_AER_SMART_SUBSYSTEM_RELIABILITY``
  *undescribed*

``NVME_AER_SMART_TEMPERATURE_THRESHOLD``
  *undescribed*

``NVME_AER_SMART_SPARE_THRESHOLD``
  *undescribed*




.. c:type:: enum nvme_ae_info_css_nvm


**Constants**

``NVME_AER_CSS_NVM_RESERVATION``
  *undescribed*

``NVME_AER_CSS_NVM_SANITIZE_COMPLETED``
  *undescribed*

``NVME_AER_CSS_NVM_UNEXPECTED_SANITIZE_DEALLOC``
  *undescribed*




.. c:type:: enum nvme_ae_info_notice


**Constants**

``NVME_AER_NOTICE_NS_CHANGED``
  *undescribed*

``NVME_AER_NOTICE_FW_ACT_STARTING``
  *undescribed*

``NVME_AER_NOTICE_TELEMETRY``
  *undescribed*

``NVME_AER_NOTICE_ANA``
  *undescribed*

``NVME_AER_NOTICE_PL_EVENT``
  *undescribed*

``NVME_AER_NOTICE_LBA_STATUS_ALERT``
  *undescribed*

``NVME_AER_NOTICE_EG_EVENT``
  *undescribed*

``NVME_AER_NOTICE_DISC_CHANGED``
  *undescribed*




.. c:type:: enum nvme_subsys_type


**Constants**

``NVME_NQN_DISC``
  Discovery type target subsystem

``NVME_NQN_NVME``
  NVME type target subsystem




.. c:type:: struct nvmf_disc_log_entry


**Definition**

::

  struct nvmf_disc_log_entry {
    __u8 trtype;
    __u8 adrfam;
    __u8 subtype;
    __u8 treq;
    __le16 portid;
    __le16 cntlid;
    __le16 asqsz;
    __u8 resv10[22];
    char trsvcid[NVMF_TRSVCID_SIZE];
    __u8 resv64[192];
    char subnqn[NVMF_NQN_FIELD_LEN];
    char traddr[NVMF_TRADDR_SIZE];
    union tsas {
      char common[NVMF_TSAS_SIZE];
      struct rdma {
        __u8 qptype;
        __u8 prtype;
        __u8 cms;
        __u8 resv3[5];
        __u16 pkey;
        __u8 resv10[246];
      } rdma;
      struct tcp {
        __u8 sectype;
      } tcp;
    } tsas;
  };

**Members**


**Description**


Discovery log page entry




.. c:type:: enum 


**Constants**

``NVMF_TRTYPE_UNSPECIFIED``
  Not indicated

``NVMF_TRTYPE_RDMA``
  RDMA

``NVMF_TRTYPE_FC``
  Fibre Channel

``NVMF_TRTYPE_TCP``
  TCP

``NVMF_TRTYPE_LOOP``
  Reserved for host usage

``NVMF_TRTYPE_MAX``
  *undescribed*

**Description**

Transport Type codes for Discovery Log Page entry TRTYPE field




.. c:type:: enum 


**Constants**

``NVMF_ADDR_FAMILY_PCI``
  PCIe

``NVMF_ADDR_FAMILY_IP4``
  IPv4

``NVMF_ADDR_FAMILY_IP6``
  IPv6

``NVMF_ADDR_FAMILY_IB``
  InfiniBand

``NVMF_ADDR_FAMILY_FC``
  Fibre Channel

**Description**

Address Family codes for Discovery Log Page entry ADRFAM field




.. c:type:: enum 


**Constants**

``NVMF_TREQ_NOT_SPECIFIED``
  Not specified

``NVMF_TREQ_REQUIRED``
  Required

``NVMF_TREQ_NOT_REQUIRED``
  Not Required

``NVMF_TREQ_DISABLE_SQFLOW``
  SQ flow control disable supported

**Description**

Transport Requirements codes for Discovery Log Page entry TREQ field




.. c:type:: enum 


**Constants**

``NVMF_RDMA_QPTYPE_CONNECTED``
  Reliable Connected

``NVMF_RDMA_QPTYPE_DATAGRAM``
  Reliable Datagram

**Description**

RDMA QP Service Type codes for Discovery Log Page entry TSAS
RDMA_QPTYPE field




.. c:type:: enum 


**Constants**

``NVMF_RDMA_PRTYPE_NOT_SPECIFIED``
  No Provider Specified

``NVMF_RDMA_PRTYPE_IB``
  InfiniBand

``NVMF_RDMA_PRTYPE_ROCE``
  InfiniBand RoCE

``NVMF_RDMA_PRTYPE_ROCEV2``
  InfiniBand RoCEV2

``NVMF_RDMA_PRTYPE_IWARP``
  iWARP

**Description**

RDMA Provider Type codes for Discovery Log Page entry TSAS
RDMA_PRTYPE field




.. c:type:: enum 


**Constants**

``NVMF_RDMA_CMS_RDMA_CM``
  Sockets based endpoint addressing

**Description**

RDMA Connection Management Service Type codes for Discovery Log Page
entry TSAS RDMA_CMS field




.. c:type:: enum 


**Constants**

``NVMF_TCP_SECTYPE_NONE``
  No Security

``NVMF_TCP_SECTYPE_TLS``
  Transport Layer Security




.. c:type:: struct nvmf_discovery_log


**Definition**

::

  struct nvmf_discovery_log {
    __le64 genctr;
    __le64 numrec;
    __le16 recfmt;
    __u8 resv14[1006];
    struct nvmf_disc_log_entry entries[0];
  };

**Members**





.. c:type:: struct nvmf_connect_data


**Definition**

::

  struct nvmf_connect_data {
    __u8 hostid[16];
    __le16 cntlid;
    char resv4[238];
    char subsysnqn[NVMF_NQN_FIELD_LEN];
    char hostnqn[NVMF_NQN_FIELD_LEN];
    char resv5[256];
  };

**Members**





.. c:type:: enum 


**Constants**

``NVME_SCT_GENERIC``
  *undescribed*

``NVME_SCT_CMD_SPECIFIC``
  *undescribed*

``NVME_SCT_MEDIA``
  *undescribed*

``NVME_SCT_PATH``
  *undescribed*

``NVME_SCT_VS``
  *undescribed*

``NVME_SCT_MASK``
  *undescribed*

``NVME_SC_SUCCESS``
  *undescribed*

``NVME_SC_INVALID_OPCODE``
  *undescribed*

``NVME_SC_INVALID_FIELD``
  *undescribed*

``NVME_SC_CMDID_CONFLICT``
  *undescribed*

``NVME_SC_DATA_XFER_ERROR``
  *undescribed*

``NVME_SC_POWER_LOSS``
  *undescribed*

``NVME_SC_INTERNAL``
  *undescribed*

``NVME_SC_ABORT_REQ``
  *undescribed*

``NVME_SC_ABORT_QUEUE``
  *undescribed*

``NVME_SC_FUSED_FAIL``
  *undescribed*

``NVME_SC_FUSED_MISSING``
  *undescribed*

``NVME_SC_INVALID_NS``
  *undescribed*

``NVME_SC_CMD_SEQ_ERROR``
  *undescribed*

``NVME_SC_SGL_INVALID_LAST``
  *undescribed*

``NVME_SC_SGL_INVALID_COUNT``
  *undescribed*

``NVME_SC_SGL_INVALID_DATA``
  *undescribed*

``NVME_SC_SGL_INVALID_METADATA``
  *undescribed*

``NVME_SC_SGL_INVALID_TYPE``
  *undescribed*

``NVME_SC_CMB_INVALID_USE``
  *undescribed*

``NVME_SC_PRP_INVALID_OFFSET``
  *undescribed*

``NVME_SC_AWU_EXCEEDED``
  *undescribed*

``NVME_SC_OP_DENIED``
  *undescribed*

``NVME_SC_SGL_INVALID_OFFSET``
  *undescribed*

``NVME_SC_HOSTID_FORMAT``
  *undescribed*

``NVME_SC_KAT_EXPIRED``
  *undescribed*

``NVME_SC_KAT_INVALID``
  *undescribed*

``NVME_SC_CMD_ABORTED_PREMEPT``
  *undescribed*

``NVME_SC_SANITIZE_FAILED``
  *undescribed*

``NVME_SC_SANITIZE_IN_PROGRESS``
  *undescribed*

``NVME_SC_SGL_INVALID_GRANULARITY``
  *undescribed*

``NVME_SC_CMD_IN_CMBQ_NOT_SUPP``
  *undescribed*

``NVME_SC_NS_WRITE_PROTECTED``
  *undescribed*

``NVME_SC_CMD_INTERRUPTED``
  *undescribed*

``NVME_SC_TRAN_TPORT_ERROR``
  *undescribed*

``NVME_SC_LBA_RANGE``
  *undescribed*

``NVME_SC_CAP_EXCEEDED``
  *undescribed*

``NVME_SC_NS_NOT_READY``
  *undescribed*

``NVME_SC_RESERVATION_CONFLICT``
  *undescribed*

``NVME_SC_FORMAT_IN_PROGRESS``
  *undescribed*

``NVME_SC_CQ_INVALID``
  *undescribed*

``NVME_SC_QID_INVALID``
  *undescribed*

``NVME_SC_QUEUE_SIZE``
  *undescribed*

``NVME_SC_ABORT_LIMIT``
  *undescribed*

``NVME_SC_ABORT_MISSING``
  *undescribed*

``NVME_SC_ASYNC_LIMIT``
  *undescribed*

``NVME_SC_FIRMWARE_SLOT``
  *undescribed*

``NVME_SC_FIRMWARE_IMAGE``
  *undescribed*

``NVME_SC_INVALID_VECTOR``
  *undescribed*

``NVME_SC_INVALID_LOG_PAGE``
  *undescribed*

``NVME_SC_INVALID_FORMAT``
  *undescribed*

``NVME_SC_FW_NEEDS_CONV_RESET``
  *undescribed*

``NVME_SC_INVALID_QUEUE``
  *undescribed*

``NVME_SC_FEATURE_NOT_SAVEABLE``
  *undescribed*

``NVME_SC_FEATURE_NOT_CHANGEABLE``
  *undescribed*

``NVME_SC_FEATURE_NOT_PER_NS``
  *undescribed*

``NVME_SC_FW_NEEDS_SUBSYS_RESET``
  *undescribed*

``NVME_SC_FW_NEEDS_RESET``
  *undescribed*

``NVME_SC_FW_NEEDS_MAX_TIME``
  *undescribed*

``NVME_SC_FW_ACTIVATE_PROHIBITED``
  *undescribed*

``NVME_SC_OVERLAPPING_RANGE``
  *undescribed*

``NVME_SC_NS_INSUFFICIENT_CAP``
  *undescribed*

``NVME_SC_NS_ID_UNAVAILABLE``
  *undescribed*

``NVME_SC_NS_ALREADY_ATTACHED``
  *undescribed*

``NVME_SC_NS_IS_PRIVATE``
  *undescribed*

``NVME_SC_NS_NOT_ATTACHED``
  *undescribed*

``NVME_SC_THIN_PROV_NOT_SUPP``
  *undescribed*

``NVME_SC_CTRL_LIST_INVALID``
  *undescribed*

``NVME_SC_SELF_TEST_IN_PROGRESS``
  *undescribed*

``NVME_SC_BP_WRITE_PROHIBITED``
  *undescribed*

``NVME_SC_INVALID_CTRL_ID``
  *undescribed*

``NVME_SC_INVALID_SEC_CTRL_STATE``
  *undescribed*

``NVME_SC_INVALID_CTRL_RESOURCES``
  *undescribed*

``NVME_SC_INVALID_RESOURCE_ID``
  *undescribed*

``NVME_SC_PMR_SAN_PROHIBITED``
  *undescribed*

``NVME_SC_ANA_GROUP_ID_INVALID``
  *undescribed*

``NVME_SC_ANA_ATTACH_FAILED``
  *undescribed*

``NVME_SC_BAD_ATTRIBUTES``
  *undescribed*

``NVME_SC_INVALID_PI``
  *undescribed*

``NVME_SC_READ_ONLY``
  *undescribed*

``NVME_SC_CONNECT_FORMAT``
  *undescribed*

``NVME_SC_CONNECT_CTRL_BUSY``
  *undescribed*

``NVME_SC_CONNECT_INVALID_PARAM``
  *undescribed*

``NVME_SC_CONNECT_RESTART_DISC``
  *undescribed*

``NVME_SC_CONNECT_INVALID_HOST``
  *undescribed*

``NVME_SC_DISCONNECT_INVALID_QTYPE``
  *undescribed*

``NVME_SC_DISCOVERY_RESTART``
  *undescribed*

``NVME_SC_AUTH_REQUIRED``
  *undescribed*

``NVME_SC_WRITE_FAULT``
  *undescribed*

``NVME_SC_READ_ERROR``
  *undescribed*

``NVME_SC_GUARD_CHECK``
  *undescribed*

``NVME_SC_APPTAG_CHECK``
  *undescribed*

``NVME_SC_REFTAG_CHECK``
  *undescribed*

``NVME_SC_COMPARE_FAILED``
  *undescribed*

``NVME_SC_ACCESS_DENIED``
  *undescribed*

``NVME_SC_UNWRITTEN_BLOCK``
  *undescribed*

``NVME_SC_ANA_INTERNAL_PATH_ERROR``
  *undescribed*

``NVME_SC_ANA_PERSISTENT_LOSS``
  *undescribed*

``NVME_SC_ANA_INACCESSIBLE``
  *undescribed*

``NVME_SC_ANA_TRANSITION``
  *undescribed*

``NVME_SC_CTRL_PATH_ERROR``
  *undescribed*

``NVME_SC_HOST_PATH_ERROR``
  *undescribed*

``NVME_SC_CMD_ABORTED_BY_HOST``
  *undescribed*

``NVME_SC_MASK``
  *undescribed*

``NVME_SC_CRD``
  *undescribed*

``NVME_SC_MORE``
  *undescribed*

``NVME_SC_DNR``
  *undescribed*


.. c:function:: __u8 nvme_status_type (__u16 status)

   Returns SCT(Status Code Type) in status field of the completion queue entry.

**Parameters**

``__u16 status``
  return value from nvme passthrough commands, which is the nvme
  status field, located at DW3 in completion queue entry


.. c:function:: const char * nvme_status_to_string (int status, bool fabrics)


**Parameters**

``int status``
  *undescribed*

``bool fabrics``
  *undescribed*


.. c:function:: int nvme_fw_download_seq (int fd, __u32 size, __u32 xfer, __u32 offset, void * buf)


**Parameters**

``int fd``
  *undescribed*

``__u32 size``
  *undescribed*

``__u32 xfer``
  *undescribed*

``__u32 offset``
  *undescribed*

``void * buf``
  *undescribed*


.. c:function:: int nvme_get_telemetry_log (int fd, bool create, bool ctrl, int data_area, void ** buf, __u32 * log_size)


**Parameters**

``int fd``
  *undescribed*

``bool create``
  *undescribed*

``bool ctrl``
  *undescribed*

``int data_area``
  *undescribed*

``void ** buf``
  *undescribed*

``__u32 * log_size``
  *undescribed*


.. c:function:: void nvme_setup_id_ns (struct nvme_id_ns * ns, __u64 nsze, __u64 ncap, __u8 flbas, __u8 dps, __u8 nmic, __u32 anagrpid, __u16 nvmsetid)


**Parameters**

``struct nvme_id_ns * ns``
  *undescribed*

``__u64 nsze``
  *undescribed*

``__u64 ncap``
  *undescribed*

``__u8 flbas``
  *undescribed*

``__u8 dps``
  *undescribed*

``__u8 nmic``
  *undescribed*

``__u32 anagrpid``
  *undescribed*

``__u16 nvmsetid``
  *undescribed*


.. c:function:: void nvme_setup_ctrl_list (struct nvme_ctrl_list * cntlist, __u16 num_ctrls, __u16 * ctrlist)


**Parameters**

``struct nvme_ctrl_list * cntlist``
  *undescribed*

``__u16 num_ctrls``
  *undescribed*

``__u16 * ctrlist``
  *undescribed*


.. c:function:: void nvme_setup_dsm_range (struct nvme_dsm_range * dsm, __u32 * ctx_attrs, __u32 * llbas, __u64 * slbas, __u16 nr_ranges)

   Constructs a data set range structure

**Parameters**

``struct nvme_dsm_range * dsm``
  DSM range array

``__u32 * ctx_attrs``
  Array of context attributes

``__u32 * llbas``
  Array of length in logical blocks

``__u64 * slbas``
  Array of starting logical blocks

``__u16 nr_ranges``
  The size of the dsm arrays

**Description**

Each array must be the same size of size 'nr_ranges'.

**Return**

The nvme command status if a response was received or -errno
        otherwise.


.. c:function:: int __nvme_get_log_page (int fd, __u32 nsid, __u8 log_id, bool rae, __u32 xfer_len, __u32 data_len, void * data)


**Parameters**

``int fd``
  *undescribed*

``__u32 nsid``
  *undescribed*

``__u8 log_id``
  *undescribed*

``bool rae``
  *undescribed*

``__u32 xfer_len``
  Max partial log transfer size to request while splitting

``__u32 data_len``
  *undescribed*

``void * data``
  *undescribed*


.. c:function:: int nvme_get_log_page (int fd, __u32 nsid, __u8 log_id, bool rae, __u32 data_len, void * data)


**Parameters**

``int fd``
  *undescribed*

``__u32 nsid``
  *undescribed*

``__u8 log_id``
  *undescribed*

``bool rae``
  *undescribed*

``__u32 data_len``
  *undescribed*

``void * data``

**Description**

Calls __nvme_get_log_page() with a default 4k transfer length.


.. c:function:: int nvme_get_ana_log_len (int fd, size_t * analen)


**Parameters**

``int fd``
  *undescribed*

``size_t * analen``
  *undescribed*


.. c:function:: int nvme_namespace_attach_ctrls (int fd, __u32 nsid, __u16 num_ctrls, __u16 * ctrlist)

   Attach namespace to controller(s)

**Parameters**

``int fd``
  File descriptor of nvme device

``__u32 nsid``
  Namespace ID to attach

``__u16 num_ctrls``
  Number of controllers in ctrlist

``__u16 * ctrlist``
  List of controller IDs to perform the attach action

**Return**

The nvme command status if a response was received or -errno
        otherwise.


.. c:function:: int nvme_namespace_detach_ctrls (int fd, __u32 nsid, __u16 num_ctrls, __u16 * ctrlist)

   Detach namespace from controller(s)

**Parameters**

``int fd``
  File descriptor of nvme device

``__u32 nsid``
  Namespace ID to detach

``__u16 num_ctrls``
  Number of controllers in ctrlist

``__u16 * ctrlist``
  List of controller IDs to perform the detach action

**Return**

The nvme command status if a response was received or -errno
        otherwise.


.. c:function:: int nvme_get_feature_length (int fid, __u32 cdw11, __u32 * len)


**Parameters**

``int fid``
  *undescribed*

``__u32 cdw11``
  *undescribed*

``__u32 * len``
  *undescribed*


.. c:function:: int nvme_get_directive_receive_length (__u8 dtype, __u8 doper, __u32 * len)


**Parameters**

``__u8 dtype``
  *undescribed*

``__u8 doper``
  *undescribed*

``__u32 * len``
  *undescribed*


.. c:function:: int nvme_open (const char * name)

   Open an nvme controller or namespace device

**Parameters**

``const char * name``
  The basename of the device to open

**Description**

This will look for the handle in /dev/ and validate the name and filetype
match linux conventions.

**Return**

A file descriptor for the device on a successful open, or -1 with
        errno set otherwise.


