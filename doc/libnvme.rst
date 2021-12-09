.. c:function:: int nvme_namespace_filter (const struct dirent * d)


**Parameters**

``const struct dirent * d``


.. c:function:: int nvme_paths_filter (const struct dirent * d)


**Parameters**

``const struct dirent * d``


.. c:function:: int nvme_ctrls_filter (const struct dirent * d)


**Parameters**

``const struct dirent * d``


.. c:function:: int nvme_subsys_filter (const struct dirent * d)


**Parameters**

``const struct dirent * d``


.. c:function:: int nvme_scan_subsystems (struct dirent *** subsys)


**Parameters**

``struct dirent *** subsys``


.. c:function:: int nvme_scan_subsystem_ctrls (nvme_subsystem_t s, struct dirent *** ctrls)


**Parameters**

``nvme_subsystem_t s``
  *undescribed*

``struct dirent *** ctrls``


.. c:function:: int nvme_scan_subsystem_namespaces (nvme_subsystem_t s, struct dirent *** namespaces)


**Parameters**

``nvme_subsystem_t s``
  *undescribed*

``struct dirent *** namespaces``


.. c:function:: int nvme_scan_ctrl_namespace_paths (nvme_ctrl_t c, struct dirent *** namespaces)


**Parameters**

``nvme_ctrl_t c``
  *undescribed*

``struct dirent *** namespaces``


.. c:function:: int nvme_scan_ctrl_namespaces (nvme_ctrl_t c, struct dirent *** namespaces)


**Parameters**

``nvme_ctrl_t c``
  *undescribed*

``struct dirent *** namespaces``




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

The nvme command status if a response was received (see
:c:type:`enum nvme_status_field <nvme_status_field>`) or -1 with errno set otherwise.


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

The nvme command status if a response was received (see
:c:type:`enum nvme_status_field <nvme_status_field>`) or -1 with errno set otherwise.


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

The nvme command status if a response was received (see
:c:type:`enum nvme_status_field <nvme_status_field>`) or -1 with errno set otherwise.


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

The nvme command status if a response was received (see
:c:type:`enum nvme_status_field <nvme_status_field>`) or -1 with errno set otherwise.


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

The nvme command status if a response was received (see
:c:type:`enum nvme_status_field <nvme_status_field>`) or -1 with errno set otherwise.


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

The nvme command status if a response was received (see
:c:type:`enum nvme_status_field <nvme_status_field>`) or -1 with errno set otherwise.


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

The nvme command status if a response was received (see
:c:type:`enum nvme_status_field <nvme_status_field>`) or -1 with errno set otherwise.


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

The nvme command status if a response was received (see
:c:type:`enum nvme_status_field <nvme_status_field>`) or -1 with errno set otherwise.


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

0 if a reset was initiated or -1 with errno set otherwise.


.. c:function:: int nvme_ns_rescan (int fd)

   Initiate a controller rescan

**Parameters**

``int fd``
  File descriptor of nvme device

**Description**

This should only be sent to controller handles, not to namespaces.

**Return**

0 if a rescan was initiated or -1 with errno set otherwise.


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

``NVME_FEAT_FID_RESV_PERSIST``
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




.. c:type:: enum nvme_directive_receive_doper


**Constants**

``NVME_DIRECTIVE_RECEIVE_IDENTIFY_DOPER_PARAM``
  *undescribed*

``NVME_DIRECTIVE_RECEIVE_STREAMS_DOPER_PARAM``
  *undescribed*

``NVME_DIRECTIVE_RECEIVE_STREAMS_DOPER_STATUS``
  *undescribed*

``NVME_DIRECTIVE_RECEIVE_STREAMS_DOPER_RESOURCE``
  *undescribed*




.. c:type:: enum nvme_directive_send_doper


**Constants**

``NVME_DIRECTIVE_SEND_IDENTIFY_DOPER_ENDIR``
  *undescribed*

``NVME_DIRECTIVE_SEND_STREAMS_DOPER_RELEASE_IDENTIFIER``
  *undescribed*

``NVME_DIRECTIVE_SEND_STREAMS_DOPER_RELEASE_RESOURCE``
  *undescribed*




.. c:type:: enum nvme_directive_send_identify_endir


**Constants**

``NVME_DIRECTIVE_SEND_IDENTIFY_ENDIR_DISABLE``
  *undescribed*

``NVME_DIRECTIVE_SEND_IDENTIFY_ENDIR_ENABLE``
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

The nvme command status if a response was received (see
:c:type:`enum nvme_status_field <nvme_status_field>`) or -1 with errno set otherwise.


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

The nvme command status if a response was received (see
:c:type:`enum nvme_status_field <nvme_status_field>`) or -1 with errno set otherwise.


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

The nvme command status if a response was received (see
:c:type:`enum nvme_status_field <nvme_status_field>`) or -1 with errno set otherwise.


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

The nvme command status if a response was received (see
:c:type:`enum nvme_status_field <nvme_status_field>`) or -1 with errno set otherwise.


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

The nvme command status if a response was received (see
:c:type:`enum nvme_status_field <nvme_status_field>`) or -1 with errno set otherwise.


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

The nvme command status if a response was received (see
:c:type:`enum nvme_status_field <nvme_status_field>`) or -1 with errno set otherwise.


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

The nvme command status if a response was received (see
:c:type:`enum nvme_status_field <nvme_status_field>`) or -1 with errno set otherwise.


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

The nvme command status if a response was received (see
:c:type:`enum nvme_status_field <nvme_status_field>`) or -1


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

The nvme command status if a response was received (see
:c:type:`enum nvme_status_field <nvme_status_field>`) or -1 with errno set otherwise.


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

The nvme command status if a response was received (see
:c:type:`enum nvme_status_field <nvme_status_field>`) or -1 with errno set otherwise.


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

The nvme command status if a response was received (see
:c:type:`enum nvme_status_field <nvme_status_field>`) or -1 with errno set otherwise.


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

The nvme command status if a response was received (see
:c:type:`enum nvme_status_field <nvme_status_field>`) or -1 with errno set otherwise.


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

The nvme command status if a response was received (see
:c:type:`enum nvme_status_field <nvme_status_field>`) or -1 with errno set otherwise.


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

The nvme command status if a response was received (see
:c:type:`enum nvme_status_field <nvme_status_field>`) or -1 with errno set otherwise.


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

The nvme command status if a response was received (see
:c:type:`enum nvme_status_field <nvme_status_field>`) or -1 with errno set otherwise.


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

The nvme command status if a response was received (see
:c:type:`enum nvme_status_field <nvme_status_field>`) or -1 with errno set otherwise.


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

The nvme command status if a response was received (see
:c:type:`enum nvme_status_field <nvme_status_field>`) or -1 with errno set otherwise.


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

The nvme command status if a response was received (see
:c:type:`enum nvme_status_field <nvme_status_field>`) or -1 with errno set otherwise.


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

The nvme command status if a response was received (see
:c:type:`enum nvme_status_field <nvme_status_field>`) or -1 with errno set otherwise.


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

The nvme command status if a response was received (see
:c:type:`enum nvme_status_field <nvme_status_field>`) or -1 with errno set otherwise.


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

The nvme command status if a response was received (see
:c:type:`enum nvme_status_field <nvme_status_field>`) or -1 with errno set otherwise.


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

The nvme command status if a response was received (see
:c:type:`enum nvme_status_field <nvme_status_field>`) or -1 with errno set otherwise.


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

The nvme command status if a response was received (see
:c:type:`enum nvme_status_field <nvme_status_field>`) or -1 with errno set otherwise.


.. c:function:: int nvme_get_log_predictable_lat_nvmset (int fd, __u16 nvmsetid, struct nvme_nvmset_predictable_lat_log * log)


**Parameters**

``int fd``
  *undescribed*

``__u16 nvmsetid``

``struct nvme_nvmset_predictable_lat_log * log``
  *undescribed*

**Return**

The nvme command status if a response was received (see
:c:type:`enum nvme_status_field <nvme_status_field>`) or -1 with errno set otherwise.


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




.. c:type:: enum nvme_log_ana_lsp


**Constants**

``NVME_LOG_ANA_LSP_RGO_NAMESPACES``
  *undescribed*

``NVME_LOG_ANA_LSP_RGO_GROUPS_ONLY``
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

The nvme command status if a response was received (see
:c:type:`enum nvme_status_field <nvme_status_field>`) or -1 with errno set otherwise.


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

The nvme command status if a response was received (see
:c:type:`enum nvme_status_field <nvme_status_field>`) or -1 with errno set otherwise.


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

The nvme command status if a response was received (see
:c:type:`enum nvme_status_field <nvme_status_field>`) or -1 with errno set otherwise.


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

The nvme command status if a response was received (see
:c:type:`enum nvme_status_field <nvme_status_field>`) or -1 with errno set otherwise.


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

The nvme command status if a response was received (see
:c:type:`enum nvme_status_field <nvme_status_field>`) or -1 with errno set otherwise.


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

The nvme command status if a response was received (see
:c:type:`enum nvme_status_field <nvme_status_field>`) or -1 with errno set otherwise.


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

The nvme command status if a response was received (see
:c:type:`enum nvme_status_field <nvme_status_field>`) or -1 with errno set otherwise.




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

The nvme command status if a response was received (see
:c:type:`enum nvme_status_field <nvme_status_field>`) or -1 with errno set otherwise.


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

The nvme command status if a response was received (see
:c:type:`enum nvme_status_field <nvme_status_field>`) or -1 with errno set otherwise.


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

The nvme command status if a response was received (see
:c:type:`enum nvme_status_field <nvme_status_field>`) or -1 with errno set otherwise.


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

The nvme command status if a response was received (see
:c:type:`enum nvme_status_field <nvme_status_field>`) or -1 with errno set otherwise.


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

The nvme command status if a response was received (see
:c:type:`enum nvme_status_field <nvme_status_field>`) or -1 with errno set otherwise.


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

The nvme command status if a response was received (see
:c:type:`enum nvme_status_field <nvme_status_field>`) or -1 with errno set otherwise.




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

The nvme command status if a response was received (see
:c:type:`enum nvme_status_field <nvme_status_field>`) or -1 with errno set otherwise.


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

The nvme command status if a response was received (see
:c:type:`enum nvme_status_field <nvme_status_field>`) or -1 with errno set otherwise.


.. c:function:: int nvme_set_features_timestamp (int fd, bool save, __u64 timestamp)


**Parameters**

``int fd``
  File descriptor of nvme device

``bool save``
  Save value across power states

``__u64 timestamp``
  The current timestamp value to assign to this this feature

**Return**

The nvme command status if a response was received (see
:c:type:`enum nvme_status_field <nvme_status_field>`) or -1 with errno set otherwise.


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

The nvme command status if a response was received (see
:c:type:`enum nvme_status_field <nvme_status_field>`) or -1 with errno set otherwise.


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

The nvme command status if a response was received (see
:c:type:`enum nvme_status_field <nvme_status_field>`) or -1 with errno set otherwise.


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

The nvme command status if a response was received (see
:c:type:`enum nvme_status_field <nvme_status_field>`) or -1 with errno set otherwise.




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

The nvme command status if a response was received (see
:c:type:`enum nvme_status_field <nvme_status_field>`) or -1 with errno set otherwise.


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

The nvme command status if a response was received (see
:c:type:`enum nvme_status_field <nvme_status_field>`) or -1 with errno set otherwise.


.. c:function:: int nvme_set_features_host_behavior (int fd, bool save, struct nvme_feat_host_behavior * data)


**Parameters**

``int fd``
  File descriptor of nvme device

``bool save``
  Save value across power states

``struct nvme_feat_host_behavior * data``
  *undescribed*

**Return**

The nvme command status if a response was received (see
:c:type:`enum nvme_status_field <nvme_status_field>`) or -1 with errno set otherwise.


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

The nvme command status if a response was received (see
:c:type:`enum nvme_status_field <nvme_status_field>`) or -1 with errno set otherwise.


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

The nvme command status if a response was received (see
:c:type:`enum nvme_status_field <nvme_status_field>`) or -1 with errno set otherwise.


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

The nvme command status if a response was received (see
:c:type:`enum nvme_status_field <nvme_status_field>`) or -1 with errno set otherwise.


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

The nvme command status if a response was received (see
:c:type:`enum nvme_status_field <nvme_status_field>`) or -1 with errno set otherwise.


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

The nvme command status if a response was received (see
:c:type:`enum nvme_status_field <nvme_status_field>`) or -1 with errno set otherwise.


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

The nvme command status if a response was received (see
:c:type:`enum nvme_status_field <nvme_status_field>`) or -1 with errno set otherwise.




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

The nvme command status if a response was received (see
:c:type:`enum nvme_status_field <nvme_status_field>`) or -1 with errno set otherwise.


.. c:function:: int nvme_get_features (int fd, enum nvme_features_id fid, __u32 nsid, enum nvme_get_features_sel sel, __u32 cdw11, __u8 uuidx, __u32 data_len, void * data, __u32 * result)

   Retrieve a feature attribute

**Parameters**

``int fd``
  File descriptor of nvme device

``enum nvme_features_id fid``
  Feature identifier, see :c:type:`enum nvme_features_id <nvme_features_id>`

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

The nvme command status if a response was received (see
:c:type:`enum nvme_status_field <nvme_status_field>`) or -1 with errno set otherwise.


.. c:function:: int nvme_get_features_arbitration (int fd, enum nvme_get_features_sel sel, __u32 * result)


**Parameters**

``int fd``
  File descriptor of nvme device

``enum nvme_get_features_sel sel``
  Select which type of attribute to return, see :c:type:`enum nvme_get_features_sel <nvme_get_features_sel>`

``__u32 * result``
  The command completion result from CQE dword0

**Return**

The nvme command status if a response was received (see
:c:type:`enum nvme_status_field <nvme_status_field>`) or -1 with errno set otherwise.


.. c:function:: int nvme_get_features_power_mgmt (int fd, enum nvme_get_features_sel sel, __u32 * result)


**Parameters**

``int fd``
  File descriptor of nvme device

``enum nvme_get_features_sel sel``
  Select which type of attribute to return, see :c:type:`enum nvme_get_features_sel <nvme_get_features_sel>`

``__u32 * result``
  The command completion result from CQE dword0

**Return**

The nvme command status if a response was received (see
:c:type:`enum nvme_status_field <nvme_status_field>`) or -1 with errno set otherwise.


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

The nvme command status if a response was received (see
:c:type:`enum nvme_status_field <nvme_status_field>`) or -1 with errno set otherwise.


.. c:function:: int nvme_get_features_temp_thresh (int fd, enum nvme_get_features_sel sel, __u32 * result)


**Parameters**

``int fd``
  File descriptor of nvme device

``enum nvme_get_features_sel sel``
  Select which type of attribute to return, see :c:type:`enum nvme_get_features_sel <nvme_get_features_sel>`

``__u32 * result``
  The command completion result from CQE dword0

**Return**

The nvme command status if a response was received (see
:c:type:`enum nvme_status_field <nvme_status_field>`) or -1 with errno set otherwise.


.. c:function:: int nvme_get_features_err_recovery (int fd, enum nvme_get_features_sel sel, __u32 * result)


**Parameters**

``int fd``
  File descriptor of nvme device

``enum nvme_get_features_sel sel``
  Select which type of attribute to return, see :c:type:`enum nvme_get_features_sel <nvme_get_features_sel>`

``__u32 * result``
  The command completion result from CQE dword0

**Return**

The nvme command status if a response was received (see
:c:type:`enum nvme_status_field <nvme_status_field>`) or -1 with errno set otherwise.


.. c:function:: int nvme_get_features_volatile_wc (int fd, enum nvme_get_features_sel sel, __u32 * result)


**Parameters**

``int fd``
  File descriptor of nvme device

``enum nvme_get_features_sel sel``
  Select which type of attribute to return, see :c:type:`enum nvme_get_features_sel <nvme_get_features_sel>`

``__u32 * result``
  The command completion result from CQE dword0

**Return**

The nvme command status if a response was received (see
:c:type:`enum nvme_status_field <nvme_status_field>`) or -1 with errno set otherwise.


.. c:function:: int nvme_get_features_num_queues (int fd, enum nvme_get_features_sel sel, __u32 * result)


**Parameters**

``int fd``
  File descriptor of nvme device

``enum nvme_get_features_sel sel``
  Select which type of attribute to return, see :c:type:`enum nvme_get_features_sel <nvme_get_features_sel>`

``__u32 * result``
  The command completion result from CQE dword0

**Return**

The nvme command status if a response was received (see
:c:type:`enum nvme_status_field <nvme_status_field>`) or -1 with errno set otherwise.


.. c:function:: int nvme_get_features_irq_coalesce (int fd, enum nvme_get_features_sel sel, __u32 * result)


**Parameters**

``int fd``
  File descriptor of nvme device

``enum nvme_get_features_sel sel``
  Select which type of attribute to return, see :c:type:`enum nvme_get_features_sel <nvme_get_features_sel>`

``__u32 * result``
  The command completion result from CQE dword0

**Return**

The nvme command status if a response was received (see
:c:type:`enum nvme_status_field <nvme_status_field>`) or -1 with errno set otherwise.


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

The nvme command status if a response was received (see
:c:type:`enum nvme_status_field <nvme_status_field>`) or -1 with errno set otherwise.


.. c:function:: int nvme_get_features_write_atomic (int fd, enum nvme_get_features_sel sel, __u32 * result)


**Parameters**

``int fd``
  File descriptor of nvme device

``enum nvme_get_features_sel sel``
  Select which type of attribute to return, see :c:type:`enum nvme_get_features_sel <nvme_get_features_sel>`

``__u32 * result``
  The command completion result from CQE dword0

**Return**

The nvme command status if a response was received (see
:c:type:`enum nvme_status_field <nvme_status_field>`) or -1 with errno set otherwise.


.. c:function:: int nvme_get_features_async_event (int fd, enum nvme_get_features_sel sel, __u32 * result)


**Parameters**

``int fd``
  File descriptor of nvme device

``enum nvme_get_features_sel sel``
  Select which type of attribute to return, see :c:type:`enum nvme_get_features_sel <nvme_get_features_sel>`

``__u32 * result``
  The command completion result from CQE dword0

**Return**

The nvme command status if a response was received (see
:c:type:`enum nvme_status_field <nvme_status_field>`) or -1 with errno set otherwise.


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

The nvme command status if a response was received (see
:c:type:`enum nvme_status_field <nvme_status_field>`) or -1 with errno set otherwise.


.. c:function:: int nvme_get_features_host_mem_buf (int fd, enum nvme_get_features_sel sel, __u32 * result)


**Parameters**

``int fd``
  File descriptor of nvme device

``enum nvme_get_features_sel sel``
  Select which type of attribute to return, see :c:type:`enum nvme_get_features_sel <nvme_get_features_sel>`

``__u32 * result``
  The command completion result from CQE dword0

**Return**

The nvme command status if a response was received (see
:c:type:`enum nvme_status_field <nvme_status_field>`) or -1 with errno set otherwise.


.. c:function:: int nvme_get_features_timestamp (int fd, enum nvme_get_features_sel sel, struct nvme_timestamp * ts)


**Parameters**

``int fd``
  File descriptor of nvme device

``enum nvme_get_features_sel sel``
  Select which type of attribute to return, see :c:type:`enum nvme_get_features_sel <nvme_get_features_sel>`

``struct nvme_timestamp * ts``
  *undescribed*

**Return**

The nvme command status if a response was received (see
:c:type:`enum nvme_status_field <nvme_status_field>`) or -1 with errno set otherwise.


.. c:function:: int nvme_get_features_kato (int fd, enum nvme_get_features_sel sel, __u32 * result)


**Parameters**

``int fd``
  File descriptor of nvme device

``enum nvme_get_features_sel sel``
  Select which type of attribute to return, see :c:type:`enum nvme_get_features_sel <nvme_get_features_sel>`

``__u32 * result``
  The command completion result from CQE dword0

**Return**

The nvme command status if a response was received (see
:c:type:`enum nvme_status_field <nvme_status_field>`) or -1 with errno set otherwise.


.. c:function:: int nvme_get_features_hctm (int fd, enum nvme_get_features_sel sel, __u32 * result)


**Parameters**

``int fd``
  File descriptor of nvme device

``enum nvme_get_features_sel sel``
  Select which type of attribute to return, see :c:type:`enum nvme_get_features_sel <nvme_get_features_sel>`

``__u32 * result``
  The command completion result from CQE dword0

**Return**

The nvme command status if a response was received (see
:c:type:`enum nvme_status_field <nvme_status_field>`) or -1 with errno set otherwise.


.. c:function:: int nvme_get_features_nopsc (int fd, enum nvme_get_features_sel sel, __u32 * result)


**Parameters**

``int fd``
  File descriptor of nvme device

``enum nvme_get_features_sel sel``
  Select which type of attribute to return, see :c:type:`enum nvme_get_features_sel <nvme_get_features_sel>`

``__u32 * result``
  The command completion result from CQE dword0

**Return**

The nvme command status if a response was received (see
:c:type:`enum nvme_status_field <nvme_status_field>`) or -1 with errno set otherwise.


.. c:function:: int nvme_get_features_rrl (int fd, enum nvme_get_features_sel sel, __u32 * result)


**Parameters**

``int fd``
  File descriptor of nvme device

``enum nvme_get_features_sel sel``
  Select which type of attribute to return, see :c:type:`enum nvme_get_features_sel <nvme_get_features_sel>`

``__u32 * result``
  The command completion result from CQE dword0

**Return**

The nvme command status if a response was received (see
:c:type:`enum nvme_status_field <nvme_status_field>`) or -1 with errno set otherwise.


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

The nvme command status if a response was received (see
:c:type:`enum nvme_status_field <nvme_status_field>`) or -1 with errno set otherwise.


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

The nvme command status if a response was received (see
:c:type:`enum nvme_status_field <nvme_status_field>`) or -1 with errno set otherwise.


.. c:function:: int nvme_get_features_lba_sts_interval (int fd, enum nvme_get_features_sel sel, __u32 * result)


**Parameters**

``int fd``
  File descriptor of nvme device

``enum nvme_get_features_sel sel``
  Select which type of attribute to return, see :c:type:`enum nvme_get_features_sel <nvme_get_features_sel>`

``__u32 * result``
  The command completion result from CQE dword0

**Return**

The nvme command status if a response was received (see
:c:type:`enum nvme_status_field <nvme_status_field>`) or -1 with errno set otherwise.


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

The nvme command status if a response was received (see
:c:type:`enum nvme_status_field <nvme_status_field>`) or -1 with errno set otherwise.


.. c:function:: int nvme_get_features_sanitize (int fd, enum nvme_get_features_sel sel, __u32 * result)


**Parameters**

``int fd``
  File descriptor of nvme device

``enum nvme_get_features_sel sel``
  Select which type of attribute to return, see :c:type:`enum nvme_get_features_sel <nvme_get_features_sel>`

``__u32 * result``
  The command completion result from CQE dword0

**Return**

The nvme command status if a response was received (see
:c:type:`enum nvme_status_field <nvme_status_field>`) or -1 with errno set otherwise.


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

The nvme command status if a response was received (see
:c:type:`enum nvme_status_field <nvme_status_field>`) or -1 with errno set otherwise.


.. c:function:: int nvme_get_features_sw_progress (int fd, enum nvme_get_features_sel sel, __u32 * result)


**Parameters**

``int fd``
  File descriptor of nvme device

``enum nvme_get_features_sel sel``
  Select which type of attribute to return, see :c:type:`enum nvme_get_features_sel <nvme_get_features_sel>`

``__u32 * result``
  The command completion result from CQE dword0

**Return**

The nvme command status if a response was received (see
:c:type:`enum nvme_status_field <nvme_status_field>`) or -1 with errno set otherwise.


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

The nvme command status if a response was received (see
:c:type:`enum nvme_status_field <nvme_status_field>`) or -1 with errno set otherwise.


.. c:function:: int nvme_get_features_resv_mask (int fd, enum nvme_get_features_sel sel, __u32 * result)


**Parameters**

``int fd``
  File descriptor of nvme device

``enum nvme_get_features_sel sel``
  Select which type of attribute to return, see :c:type:`enum nvme_get_features_sel <nvme_get_features_sel>`

``__u32 * result``
  The command completion result from CQE dword0

**Return**

The nvme command status if a response was received (see
:c:type:`enum nvme_status_field <nvme_status_field>`) or -1 with errno set otherwise.


.. c:function:: int nvme_get_features_resv_persist (int fd, enum nvme_get_features_sel sel, __u32 * result)


**Parameters**

``int fd``
  File descriptor of nvme device

``enum nvme_get_features_sel sel``
  Select which type of attribute to return, see :c:type:`enum nvme_get_features_sel <nvme_get_features_sel>`

``__u32 * result``
  The command completion result from CQE dword0

**Return**

The nvme command status if a response was received (see
:c:type:`enum nvme_status_field <nvme_status_field>`) or -1 with errno set otherwise.


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

The nvme command status if a response was received (see
:c:type:`enum nvme_status_field <nvme_status_field>`) or -1 with errno set otherwise.


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

The nvme command status if a response was received (see
:c:type:`enum nvme_status_field <nvme_status_field>`) or -1 with errno set otherwise.


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

The nvme command status if a response was received (see
:c:type:`enum nvme_status_field <nvme_status_field>`) or -1 with errno set otherwise.


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

The nvme command status if a response was received (see
:c:type:`enum nvme_status_field <nvme_status_field>`) or -1 with errno set otherwise.


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


.. c:function:: int nvme_ns_detach_ctrls (int fd, __u32 nsid, struct nvme_ctrl_list * ctrlist)


**Parameters**

``int fd``
  File descriptor of nvme device

``__u32 nsid``
  Namespace ID to detach

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

The nvme command status if a response was received (see
:c:type:`enum nvme_status_field <nvme_status_field>`) or -1 with errno set otherwise.


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

The nvme command status if a response was received (see
:c:type:`enum nvme_status_field <nvme_status_field>`) or -1 with errno set otherwise. The command
        status
        response may specify additional
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

The nvme command status if a response was received (see
:c:type:`enum nvme_status_field <nvme_status_field>`) or -1 with errno set otherwise.


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

The nvme command status if a response was received (see
:c:type:`enum nvme_status_field <nvme_status_field>`) or -1 with errno set otherwise.


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

The nvme command status if a response was received (see
:c:type:`enum nvme_status_field <nvme_status_field>`) or -1 with errno set otherwise.


.. c:function:: int nvme_directive_send (int fd, __u32 nsid, __u16 dspec, enum nvme_directive_send_doper doper, enum nvme_directive_dtype dtype, __u32 cdw12, __u32 data_len, void * data, __u32 * result)

   Send directive command

**Parameters**

``int fd``
  File descriptor of nvme device

``__u32 nsid``
  Namespace ID, if applicable

``__u16 dspec``
  Directive specific field

``enum nvme_directive_send_doper doper``
  Directive send operation, see :c:type:`enum nvme_directive_send_doper <nvme_directive_send_doper>`

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

The nvme command status if a response was received (see
:c:type:`enum nvme_status_field <nvme_status_field>`) or -1 with errno set otherwise.


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

The nvme command status if a response was received (see
:c:type:`enum nvme_status_field <nvme_status_field>`) or -1 with errno set otherwise.


.. c:function:: int nvme_directive_send_stream_release_identifier (int fd, __u32 nsid, __u16 stream_id)


**Parameters**

``int fd``
  File descriptor of nvme device

``__u32 nsid``
  Namespace ID

``__u16 stream_id``
  *undescribed*

**Return**

The nvme command status if a response was received (see
:c:type:`enum nvme_status_field <nvme_status_field>`) or -1 with errno set otherwise.


.. c:function:: int nvme_directive_send_stream_release_resource (int fd, __u32 nsid)


**Parameters**

``int fd``
  File descriptor of nvme device

``__u32 nsid``
  Namespace ID

**Return**

The nvme command status if a response was received (see
:c:type:`enum nvme_status_field <nvme_status_field>`) or -1 with errno set otherwise.


.. c:function:: int nvme_directive_recv (int fd, __u32 nsid, __u16 dspec, enum nvme_directive_receive_doper doper, enum nvme_directive_dtype dtype, __u32 cdw12, __u32 data_len, void * data, __u32 * result)

   Receive directive specific data

**Parameters**

``int fd``
  File descriptor of nvme device

``__u32 nsid``
  Namespace ID, if applicable

``__u16 dspec``
  Directive specific field

``enum nvme_directive_receive_doper doper``
  Directive receive operation, see :c:type:`enum nvme_directive_receive_doper <nvme_directive_receive_doper>`

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

The nvme command status if a response was received (see
:c:type:`enum nvme_status_field <nvme_status_field>`) or -1 with errno set otherwise.


.. c:function:: int nvme_directive_recv_identify_parameters (int fd, __u32 nsid, struct nvme_id_directives * id)


**Parameters**

``int fd``
  File descriptor of nvme device

``__u32 nsid``
  Namespace ID

``struct nvme_id_directives * id``
  *undescribed*

**Return**

The nvme command status if a response was received (see
:c:type:`enum nvme_status_field <nvme_status_field>`) or -1 with errno set otherwise.


.. c:function:: int nvme_directive_recv_stream_parameters (int fd, __u32 nsid, struct nvme_streams_directive_params * parms)


**Parameters**

``int fd``
  File descriptor of nvme device

``__u32 nsid``
  Namespace ID

``struct nvme_streams_directive_params * parms``
  *undescribed*

**Return**

The nvme command status if a response was received (see
:c:type:`enum nvme_status_field <nvme_status_field>`) or -1 with errno set otherwise.


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

The nvme command status if a response was received (see
:c:type:`enum nvme_status_field <nvme_status_field>`) or -1 with errno set otherwise.


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

The nvme command status if a response was received (see
:c:type:`enum nvme_status_field <nvme_status_field>`) or -1 with errno set otherwise.




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

The nvme command status if a response was received (see
:c:type:`enum nvme_status_field <nvme_status_field>`) or -1 with errno set otherwise.


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

The nvme command status if a response was received (see
:c:type:`enum nvme_status_field <nvme_status_field>`) or -1 with errno set otherwise.


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

The nvme command status if a response was received (see
:c:type:`enum nvme_status_field <nvme_status_field>`) or -1 with errno set otherwise.


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

The nvme command status if a response was received (see
:c:type:`enum nvme_status_field <nvme_status_field>`) or -1 with errno set otherwise.


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

The nvme command status if a response was received (see
:c:type:`enum nvme_status_field <nvme_status_field>`) or -1 with errno set otherwise.




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

The nvme command status if a response was received (see
:c:type:`enum nvme_status_field <nvme_status_field>`) or -1 with errno set otherwise.




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

The nvme command status if a response was received (see
:c:type:`enum nvme_status_field <nvme_status_field>`) or -1 with errno set otherwise.


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

The nvme command status if a response was received (see
:c:type:`enum nvme_status_field <nvme_status_field>`) or -1 with errno set otherwise.


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

The nvme command status if a response was received (see
:c:type:`enum nvme_status_field <nvme_status_field>`) or -1 with errno set otherwise.


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

The nvme command status if a response was received (see
:c:type:`enum nvme_status_field <nvme_status_field>`) or -1 with errno set otherwise.


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

The nvme command status if a response was received (see
:c:type:`enum nvme_status_field <nvme_status_field>`) or -1 with errno set otherwise.


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

The nvme command status if a response was received (see
:c:type:`enum nvme_status_field <nvme_status_field>`) or -1 with errno set otherwise.




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

The nvme command status if a response was received (see
:c:type:`enum nvme_status_field <nvme_status_field>`) or -1 with errno set otherwise.




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

The nvme command status if a response was received (see
:c:type:`enum nvme_status_field <nvme_status_field>`) or -1 with errno set otherwise.




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

The nvme command status if a response was received (see
:c:type:`enum nvme_status_field <nvme_status_field>`) or -1 with errno set otherwise.




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

The nvme command status if a response was received (see
:c:type:`enum nvme_status_field <nvme_status_field>`) or -1 with errno set otherwise.


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

The nvme command status if a response was received (see
:c:type:`enum nvme_status_field <nvme_status_field>`) or -1 with errno set otherwise.


.. c:function:: nvme_subsystem_t nvme_first_subsystem (nvme_root_t r)


**Parameters**

``nvme_root_t r``


.. c:function:: nvme_subsystem_t nvme_next_subsystem (nvme_root_t r, nvme_subsystem_t s)


**Parameters**

``nvme_root_t r``
  *undescribed*

``nvme_subsystem_t s``


.. c:function:: nvme_ns_t nvme_ctrl_first_ns (nvme_ctrl_t c)


**Parameters**

``nvme_ctrl_t c``


.. c:function:: nvme_ns_t nvme_ctrl_next_ns (nvme_ctrl_t c, nvme_ns_t n)


**Parameters**

``nvme_ctrl_t c``
  *undescribed*

``nvme_ns_t n``


.. c:function:: nvme_path_t nvme_ctrl_first_path (nvme_ctrl_t c)


**Parameters**

``nvme_ctrl_t c``


.. c:function:: nvme_path_t nvme_ctrl_next_path (nvme_ctrl_t c, nvme_path_t p)


**Parameters**

``nvme_ctrl_t c``
  *undescribed*

``nvme_path_t p``


.. c:function:: nvme_ctrl_t nvme_subsystem_first_ctrl (nvme_subsystem_t s)


**Parameters**

``nvme_subsystem_t s``


.. c:function:: nvme_ctrl_t nvme_subsystem_next_ctrl (nvme_subsystem_t s, nvme_ctrl_t c)


**Parameters**

``nvme_subsystem_t s``
  *undescribed*

``nvme_ctrl_t c``


.. c:function:: nvme_ns_t nvme_subsystem_first_ns (nvme_subsystem_t s)


**Parameters**

``nvme_subsystem_t s``


.. c:function:: nvme_ns_t nvme_subsystem_next_ns (nvme_subsystem_t s, nvme_ns_t n)


**Parameters**

``nvme_subsystem_t s``
  *undescribed*

``nvme_ns_t n``


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


.. c:function:: int nvme_ns_get_nsid (nvme_ns_t n)


**Parameters**

``nvme_ns_t n``


.. c:function:: int nvme_ns_get_lba_size (nvme_ns_t n)


**Parameters**

``nvme_ns_t n``


.. c:function:: uint64_t nvme_ns_get_lba_count (nvme_ns_t n)


**Parameters**

``nvme_ns_t n``


.. c:function:: uint64_t nvme_ns_get_lba_util (nvme_ns_t n)


**Parameters**

``nvme_ns_t n``


.. c:function:: const char * nvme_ns_get_sysfs_dir (nvme_ns_t n)


**Parameters**

``nvme_ns_t n``


.. c:function:: const char * nvme_ns_get_name (nvme_ns_t n)


**Parameters**

``nvme_ns_t n``


.. c:function:: nvme_subsystem_t nvme_ns_get_subsystem (nvme_ns_t n)


**Parameters**

``nvme_ns_t n``


.. c:function:: nvme_ctrl_t nvme_ns_get_ctrl (nvme_ns_t n)


**Parameters**

``nvme_ns_t n``


.. c:function:: int nvme_ns_read (nvme_ns_t n, void * buf, off_t offset, size_t count)


**Parameters**

``nvme_ns_t n``
  *undescribed*

``void * buf``
  *undescribed*

``off_t offset``
  *undescribed*

``size_t count``


.. c:function:: int nvme_ns_write (nvme_ns_t n, void * buf, off_t offset, size_t count)


**Parameters**

``nvme_ns_t n``
  *undescribed*

``void * buf``
  *undescribed*

``off_t offset``
  *undescribed*

``size_t count``


.. c:function:: int nvme_ns_verify (nvme_ns_t n, off_t offset, size_t count)


**Parameters**

``nvme_ns_t n``
  *undescribed*

``off_t offset``
  *undescribed*

``size_t count``


.. c:function:: int nvme_ns_compare (nvme_ns_t n, void * buf, off_t offset, size_t count)


**Parameters**

``nvme_ns_t n``
  *undescribed*

``void * buf``
  *undescribed*

``off_t offset``
  *undescribed*

``size_t count``


.. c:function:: int nvme_ns_write_zeros (nvme_ns_t n, off_t offset, size_t count)


**Parameters**

``nvme_ns_t n``
  *undescribed*

``off_t offset``
  *undescribed*

``size_t count``


.. c:function:: int nvme_ns_write_uncorrectable (nvme_ns_t n, off_t offset, size_t count)


**Parameters**

``nvme_ns_t n``
  *undescribed*

``off_t offset``
  *undescribed*

``size_t count``


.. c:function:: int nvme_ns_flush (nvme_ns_t n)


**Parameters**

``nvme_ns_t n``


.. c:function:: int nvme_ns_identify (nvme_ns_t n, struct nvme_id_ns * ns)


**Parameters**

``nvme_ns_t n``
  *undescribed*

``struct nvme_id_ns * ns``


.. c:function:: const char * nvme_path_get_name (nvme_path_t p)


**Parameters**

``nvme_path_t p``


.. c:function:: const char * nvme_path_get_sysfs_dir (nvme_path_t p)


**Parameters**

``nvme_path_t p``


.. c:function:: const char * nvme_path_get_ana_state (nvme_path_t p)


**Parameters**

``nvme_path_t p``


.. c:function:: nvme_ctrl_t nvme_path_get_subsystem (nvme_path_t p)


**Parameters**

``nvme_path_t p``


.. c:function:: nvme_ns_t nvme_path_get_ns (nvme_path_t p)


**Parameters**

``nvme_path_t p``


.. c:function:: int nvme_ctrl_get_fd (nvme_ctrl_t c)


**Parameters**

``nvme_ctrl_t c``


.. c:function:: const char * nvme_ctrl_get_name (nvme_ctrl_t c)


**Parameters**

``nvme_ctrl_t c``


.. c:function:: const char * nvme_ctrl_get_sysfs_dir (nvme_ctrl_t c)


**Parameters**

``nvme_ctrl_t c``


.. c:function:: const char * nvme_ctrl_get_address (nvme_ctrl_t c)


**Parameters**

``nvme_ctrl_t c``


.. c:function:: const char * nvme_ctrl_get_firmware (nvme_ctrl_t c)


**Parameters**

``nvme_ctrl_t c``


.. c:function:: const char * nvme_ctrl_get_model (nvme_ctrl_t c)


**Parameters**

``nvme_ctrl_t c``


.. c:function:: const char * nvme_ctrl_get_state (nvme_ctrl_t c)


**Parameters**

``nvme_ctrl_t c``


.. c:function:: const char * nvme_ctrl_get_numa_node (nvme_ctrl_t c)


**Parameters**

``nvme_ctrl_t c``


.. c:function:: const char * nvme_ctrl_get_queue_count (nvme_ctrl_t c)


**Parameters**

``nvme_ctrl_t c``


.. c:function:: const char * nvme_ctrl_get_serial (nvme_ctrl_t c)


**Parameters**

``nvme_ctrl_t c``


.. c:function:: const char * nvme_ctrl_get_sqsize (nvme_ctrl_t c)


**Parameters**

``nvme_ctrl_t c``


.. c:function:: const char * nvme_ctrl_get_transport (nvme_ctrl_t c)


**Parameters**

``nvme_ctrl_t c``


.. c:function:: const char * nvme_ctrl_get_subsysnqn (nvme_ctrl_t c)


**Parameters**

``nvme_ctrl_t c``


.. c:function:: nvme_subsystem_t nvme_ctrl_get_subsystem (nvme_ctrl_t c)


**Parameters**

``nvme_ctrl_t c``


.. c:function:: int nvme_ctrl_identify (nvme_ctrl_t c, struct nvme_id_ctrl * id)


**Parameters**

``nvme_ctrl_t c``
  *undescribed*

``struct nvme_id_ctrl * id``


.. c:function:: int nvme_ctrl_disconnect (nvme_ctrl_t c)


**Parameters**

``nvme_ctrl_t c``


.. c:function:: nvme_ctrl_t nvme_scan_ctrl (const char * name)


**Parameters**

``const char * name``


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


.. c:function:: const char * nvme_subsystem_get_sysfs_dir (nvme_subsystem_t s)


**Parameters**

``nvme_subsystem_t s``


.. c:function:: const char * nvme_subsystem_get_name (nvme_subsystem_t s)


**Parameters**

``nvme_subsystem_t s``


.. c:function:: nvme_root_t nvme_scan_filter (nvme_scan_filter_t f)


**Parameters**

``nvme_scan_filter_t f``


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


.. c:function:: char * nvme_get_ctrl_attr (nvme_ctrl_t c, const char * attr)


**Parameters**

``nvme_ctrl_t c``
  *undescribed*

``const char * attr``


.. c:function:: char * nvme_get_ns_attr (nvme_ns_t n, const char * attr)


**Parameters**

``nvme_ns_t n``
  *undescribed*

``const char * attr``


.. c:function:: char * nvme_get_path_attr (nvme_path_t p, const char * attr)


**Parameters**

``nvme_path_t p``
  *undescribed*

``const char * attr``


.. c:function:: __le16 cpu_to_le16 (uint16_t x)


**Parameters**

``uint16_t x``
  16-bit CPU value to turn to little endian.


.. c:function:: __le32 cpu_to_le32 (uint32_t x)


**Parameters**

``uint32_t x``
  32-bit CPU value to turn little endian.


.. c:function:: __le64 cpu_to_le64 (uint64_t x)


**Parameters**

``uint64_t x``
  64-bit CPU value to turn little endian.


.. c:function:: uint16_t le16_to_cpu (__le16 x)


**Parameters**

``__le16 x``
  16-bit little endian value to turn to CPU.


.. c:function:: uint32_t le32_to_cpu (__le32 x)


**Parameters**

``__le32 x``
  32-bit little endian value to turn to CPU.


.. c:function:: uint64_t le64_to_cpu (__le64 x)


**Parameters**

``__le64 x``
  64-bit little endian value to turn to CPU.




.. c:type:: enum nvme_constants

   A place to stash various constant nvme values

**Constants**

``NVME_NSID_ALL``
  A broadcast value that is used to specify all
  namespaces

``NVME_NSID_NONE``
  The invalid namespace id, for when the nsid
  parameter is not used in a command

``NVME_UUID_NONE``
  Use to omit the uuid command parameter

``NVME_CNTLID_NONE``
  Use to omit the cntlid command parameter

``NVME_NVMSETID_NONE``
  Use to omit the nvmsetid command parameter

``NVME_LOG_LSP_NONE``
  Use to omit the log lsp command parameter

``NVME_LOG_LSI_NONE``
  Use to omit the log lsi command parameter

``NVME_IDENTIFY_DATA_SIZE``
  The transfer size for nvme identify commands

``NVME_ID_NVMSET_LIST_MAX``
  The largest possible nvmset index in identify
  nvmeset

``NVME_ID_UUID_LIST_MAX``
  The largest possible uuid index in identify
  uuid list

``NVME_ID_CTRL_LIST_MAX``
  The largest possible controller index in
  identify controller list

``NVME_ID_NS_LIST_MAX``
  The largest possible namespace index in
  identify namespace list

``NVME_ID_SECONDARY_CTRL_MAX``
  The largest possible secondary controller index
  in identify secondary controller

``NVME_ID_ND_DESCRIPTOR_MAX``
  *undescribed*

``NVME_FEAT_LBA_RANGE_MAX``
  The largest possible LBA range index in feature
  lba range type

``NVME_LOG_ST_MAX_RESULTS``
  The largest possible self test result index in the
  device self test log

``NVME_LOG_TELEM_BLOCK_SIZE``
  Specification defined size of Telemetry Data Blocks

``NVME_DSM_MAX_RANGES``
  The largest possible range index in a data-set
  management command

``NVME_NQN_LENGTH``
  Max length for NVMe Qualified Name.

``NVMF_TRADDR_SIZE``
  *undescribed*

``NVMF_TSAS_SIZE``
  *undescribed*

``NVME_NIDT_EUI64_LEN``
  *undescribed*

``NVME_NIDT_NGUID_LEN``
  *undescribed*




.. c:type:: enum nvme_register_offsets

   The nvme controller registers for all transports. This is the layout of BAR0/1 for PCIe, and properties for fabrics.

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


.. c:function:: bool nvme_is_64bit_reg (__u32 offset)

   Checks if offset of the controller register is a know 64bit value.

**Parameters**

``__u32 offset``
  Offset of controller register field in bytes

**Description**

This function does not care about transport so that the offset is not going
to be checked inside of this function for the unsupported fields in a
specific transport. For example, BPMBL(Boot Partition Memory Buffer
Location) register is not supported by fabrics, but it can be chcked here.

Returns true if given offset is 64bit register, otherwise it returns false.




.. c:type:: enum nvme_psd_flags

   Possible flag values in nvme power state descriptor

**Constants**

``NVME_PSD_FLAGS_MXPS``
  Indicates the scale for the Maximum Power
  field. If this bit is cleared, then the scale of the
  Maximum Power field is in 0.01 Watts. If this bit is
  set, then the scale of the Maximum Power field is in
  0.0001 Watts.

``NVME_PSD_FLAGS_NOPS``
  Indicates whether the controller processes I/O
  commands in this power state. If this bit is cleared,
  then the controller processes I/O commands in this
  power state. If this bit is set, then the controller
  does not process I/O commands in this power state.




.. c:type:: enum nvme_psd_ps

   Known values for :c:type:`struct nvme_psd <nvme_psd>` ``ips`` and ``aps``. Use with nvme_psd_power_scale() to extract the power scale field to match this enum. NVME_PSD_IPS_100_MICRO_WATT: 0.0001 watt scale NVME_PSD_IPS_10_MILLI_WATT: 0.01 watt scale

**Constants**

``NVME_PSD_PS_100_MICRO_WATT``
  *undescribed*

``NVME_PSD_PS_10_MILLI_WATT``
  *undescribed*


.. c:function:: unsigned nvme_psd_power_scale (__u8 ps)

   power scale occupies the upper 3 bits

**Parameters**

``__u8 ps``
  *undescribed*




.. c:type:: enum nvme_psd_workload

   Specifies a workload hint in the Power Management Feature (see :c:type:`struct nvme_psd <nvme_psd>`.apw) to inform the NVM subsystem or indicate the conditions for the active power level.

**Constants**

``NVME_PSD_WORKLOAD_1``
  Extended Idle Period with a Burst of Random Write
  consists of five minutes of idle followed by
  thirty-two random write commands of size 1 MiB
  submitted to a single controller while all other
  controllers in the NVM subsystem are idle, and then
  thirty (30) seconds of idle.

``NVME_PSD_WORKLOAD_2``
  Heavy Sequential Writes consists of 80,000
  sequential write commands of size 128 KiB submitted to
  a single controller while all other controllers in the
  NVM subsystem are idle.  The submission queue(s)
  should be sufficiently large allowing the host to
  ensure there are multiple commands pending at all
  times during the workload.




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
    __u8 apws;
    __u8 rsvd23[9];
  };

**Members**

``mp``
  Maximum Power indicates the sustained maximum power consumed by the
  NVM subsystem in this power state. The power in Watts is equal to
  the value in this field multiplied by the scale specified in the Max
  Power Scale bit (see :c:type:`enum nvme_psd_flags <nvme_psd_flags>`). A value of 0 indicates
  Maximum Power is not reported.

``flags``
  Additional decoding flags, see :c:type:`enum nvme_psd_flags <nvme_psd_flags>`.

``enlat``
  Entry Latency indicates the maximum latency in microseconds
  associated with entering this power state. A value of 0 indicates
  Entry Latency is not reported.

``exlat``
  Exit Latency indicates the maximum latency in microseconds
  associated with exiting this power state. A value of 0 indicates
  Exit Latency is not reported.

``rrt``
  Relative Read Throughput indicates the read throughput rank
  associated with this power state relative to others. The value in
  this is less than the number of supported power states.

``rrl``
  Relative Reade Latency indicates the read latency rank associated
  with this power state relative to others. The value in this field is
  less than the number of supported power states.

``rwt``
  Relative Write Throughput indicates write throughput rank associated
  with this power state relative to others. The value in this field is
  less than the number of supported power states

``rwl``
  Relative Write Latency indicates the write latency rank associated
  with this power state relative to others. The value in this field is
  less than the number of supported power states

``idlp``
  Idle Power indicates the typical power consumed by the NVM
  subsystem over 30 seconds in this power state when idle.

``ips``
  Idle Power Scale indicates the scale for :c:type:`struct nvme_id_psd <nvme_id_psd>`.idlp,
  see :c:type:`enum nvme_psd_ps <nvme_psd_ps>` for decoding this field.

``actp``
  Active Power indicates the largest average power consumed by the
  NVM subsystem over a 10 second period in this power state with
  the workload indicated in the Active Power Workload field.

``apws``
  Bits 7-6: Active Power Scale(APS) indicates the scale for the :c:type:`struct
  nvme_id_psd <nvme_id_psd>`.actp, see :c:type:`enum nvme_psd_ps <nvme_psd_ps>` for decoding this value.
  Bits 2-0: Active Power Workload(APW) indicates the workload used to calculate
  maximum power for this power state. See :c:type:`enum nvme_psd_workload <nvme_psd_workload>` for
  decoding this field.





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
    __le16 ocfs;
    __le32 sgls;
    __le32 mnan;
    __u8 rsvd544[224];
    char subnqn[NVME_NQN_LENGTH];
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
  PCI Vendor ID, the company vendor identifier that is assigned by
  the PCI SIG.

``ssvid``
  PCI Subsystem Vendor ID, the company vendor identifier that is
  assigned by the PCI SIG for the subsystem.

``sn``
  Serial Number in ascii

``mn``
  Model Number in ascii

``fr``
  Firmware Revision in ascii, the currently active firmware
  revision for the NVM subsystem

``rab``
  Recommended Arbitration Burst, reported as a power of two

``ieee``
  IEEE assigned Organization Unique Identifier

``cmic``
  Controller Multipath IO and Namespace Sharing  Capabilities of
  the controller and NVM subsystem. See :c:type:`enum nvme_id_ctrl_cmic <nvme_id_ctrl_cmic>`.

``mdts``
  Max Data Transfer Size is the largest data transfer size. The
  host should not submit a command that exceeds this maximum data
  transfer size. The value is in units of the minimum memory page
  size (CAP.MPSMIN) and is reported as a power of two

``cntlid``
  Controller ID, the NVM subsystem unique controller identifier
  associated with the controller.

``ver``
  Version, this field contains the value reported in the Version
  register, or property (see :c:type:`enum nvme_registers <nvme_registers>` ``NVME_REG_VS``).

``rtd3r``
  RTD3 Resume Latency, the expected latency in microseconds to resume
  from Runtime D3

``rtd3e``
  RTD3 Exit Latency, the typical latency in microseconds to enter
  Runtime D3.

``oaes``
  Optional Async Events Supported, see **enum** nvme_id_ctrl_oaes .

``ctratt``
  Controller Attributes, see **enum** nvme_id_ctrl_ctratt

``rrls``
  Read Recovery Levels. If a bit is set, then the corresponding
  Read Recovery Level is supported. If a bit is cleared, then the
  corresponding Read Recovery Level is not supported.

``cntrltype``
  Controller Type, see :c:type:`enum nvme_id_ctrl_cntrltype <nvme_id_ctrl_cntrltype>`

``fguid``
  FRU GUID, a 128-bit value that is globally unique for a given
  Field Replaceable Unit

``crdt1``
  Controller Retry Delay time in 100 millisecod units if CQE CRD
  field is 1

``crdt2``
  Controller Retry Delay time in 100 millisecod units if CQE CRD
  field is 2

``crdt3``
  Controller Retry Delay time in 100 millisecod units if CQE CRD
  field is 3

``nvmsr``
  NVM Subsystem Report, see :c:type:`enum nvme_id_ctrl_nvmsr <nvme_id_ctrl_nvmsr>`

``vwci``
  VPD Write Cycle Information, see :c:type:`enum nvme_id_ctrl_vwci <nvme_id_ctrl_vwci>`

``mec``
  Management Endpoint Capabilities, see :c:type:`enum nvme_id_ctrl_mec <nvme_id_ctrl_mec>`

``oacs``
  Optional Admin Command Support,the optional Admin commands and
  features supported by the controller, see :c:type:`enum nvme_id_ctrl_oacs <nvme_id_ctrl_oacs>`.

``acl``
  Abort Command Limit, the maximum number of concurrently
  executing Abort commands supported by the controller. This is a
  0's based value.

``aerl``
  Async Event Request Limit, the maximum number of concurrently
  outstanding Asynchronous Event Request commands supported by the
  controller This is a 0's based value.

``frmw``
  Firmware Updates indicates capabilities regarding firmware
  updates. See :c:type:`enum nvme_id_ctrl_frmw <nvme_id_ctrl_frmw>`.

``lpa``
  Log Page Attributes, see :c:type:`enum nvme_id_ctrl_lpa <nvme_id_ctrl_lpa>`.

``elpe``
  Error Log Page Entries, the maximum number of Error Information
  log entries that are stored by the controller. This field is a
  0's based value.

``npss``
  Number of Power States Supported, the number of NVM Express
  power states supported by the controller, indicating the number
  of valid entries in :c:type:`struct nvme_id_ctrl <nvme_id_ctrl>`.psd. This is a 0's
  based value.

``avscc``
  Admin Vendor Specific Command Configuration, see
  :c:type:`enum nvme_id_ctrl_avscc <nvme_id_ctrl_avscc>`.

``apsta``
  Autonomous Power State Transition Attributes, see
  :c:type:`enum nvme_id_ctrl_apsta <nvme_id_ctrl_apsta>`.

``wctemp``
  Warning Composite Temperature Threshold indicates
  the minimum Composite Temperature field value (see :c:type:`struct
  nvme_smart_log <nvme_smart_log>`.critical_comp_time) that indicates an overheating
  condition during which controller operation continues.

``cctemp``
  Critical Composite Temperature Threshold, field indicates the
  minimum Composite Temperature field value (see :c:type:`struct
   nvme_smart_log <nvme_smart_log>`.critical_comp_time) that indicates a critical
  overheating condition.

``mtfa``
  Maximum Time for Firmware Activation indicates the maximum time
  the controller temporarily stops processing commands to activate
  the firmware image, specified in 100 millisecond units. This
  field is always valid if the controller supports firmware
  activation without a reset.

``hmpre``
  Host Memory Buffer Preferred Size indicates the preferred size
  that the host is requested to allocate for the Host Memory
  Buffer feature in 4 KiB units.

``hmmin``
  Host Memory Buffer Minimum Size indicates the minimum size that
  the host is requested to allocate for the Host Memory Buffer
  feature in 4 KiB units.

``tnvmcap``
  Total NVM Capacity, the total NVM capacity in the NVM subsystem.
  The value is in bytes.

``unvmcap``
  Unallocated NVM Capacity, the unallocated NVM capacity in the
  NVM subsystem. The value is in bytes.
  **rpmbs**      Replay Protected Memory Block Support, see
  :c:type:`enum nvme_id_ctrl_rpmbs <nvme_id_ctrl_rpmbs>`.
  **edstt**      Extended Device Self-test Time, if Device Self-test command is
  supported (see :c:type:`struct nvme_id_ctrl <nvme_id_ctrl>`.oacs, ``NVME_CTRL_OACS_SELF_TEST``),
  then this field indicates the nominal amount of time in one
  minute units that the controller takes to complete an extended
  device self-test operation when in power state 0.

``dsto``
  Device Self-test Options, see :c:type:`enum nvme_id_ctrl_dsto <nvme_id_ctrl_dsto>`.

``fwug``
  Firmware Update Granularity indicates the granularity and
  alignment requirement of the firmware image being updated by the
  Firmware Image Download command. The value is reported in 4 KiB
  units. A value of 0h indicates no information on granularity is
  provided. A value of FFh indicates no restriction

``kas``
  Keep Alive Support indicates the granularity of the Keep Alive
  Timer in 100 millisecond units.

``hctma``
  Host Controlled Thermal Management Attributes, see :c:type:`enum nvme_id_ctrl_hctm <nvme_id_ctrl_hctm>`.

``mntmt``
  Minimum Thermal Management Temperature indicates the minimum
  temperature, in degrees Kelvin, that the host may request in the
  Thermal Management Temperature 1 field and Thermal Management
  Temperature 2 field of a Set Features command with the Feature
  Identifier field set to ``NVME_FEAT_FID_HCTM``.

``mxtmt``
  Maximum Thermal Management Temperature indicates the maximum
  temperature, in degrees Kelvin, that the host may request in the
  Thermal Management Temperature 1 field and Thermal Management
  Temperature 2 field of the Set Features command with the Feature
  Identifier set to ``NVME_FEAT_FID_HCTM``.

``sanicap``
  Sanitize Capabilities, see :c:type:`enum nvme_id_ctrl_sanicap <nvme_id_ctrl_sanicap>`

``hmminds``
  Host Memory Buffer Minimum Descriptor Entry Size indicates the
  minimum usable size of a Host Memory Buffer Descriptor Entry in
  4 KiB units.

``hmmaxd``
  Host Memory Maximum Descriptors Entries indicates the number of
  usable Host Memory Buffer Descriptor Entries.

``nsetidmax``
  NVM Set Identifier Maximum, defines the maximum value of a valid
  NVM Set Identifier for any controller in the NVM subsystem.

``endgidmax``
  Endurance Group Identifier Maximum, defines the maximum value of
  a valid Endurance Group Identifier for any controller in the NVM
  subsystem.

``anatt``
  ANA Transition Time indicates the maximum amount of time, in
  seconds, for a transition between ANA states or the maximum
  amount of time, in seconds, that the controller reports the ANA
  change state.

``anacap``
  Asymmetric Namespace Access Capabilities, see
  :c:type:`enum nvme_id_ctrl_anacap <nvme_id_ctrl_anacap>`.

``anagrpmax``
  ANA Group Identifier Maximum indicates the maximum value of a
  valid ANA Group Identifier for any controller in the NVM
  subsystem.

``nanagrpid``
  Number of ANA Group Identifiers indicates the number of ANA
  groups supported by this controller.

``pels``
  Persistent Event Log Size indicates the maximum reportable size
  for the Persistent Event Log.

``sqes``
  Submission Queue Entry Size, see :c:type:`enum nvme_id_ctrl_sqes <nvme_id_ctrl_sqes>`.

``cqes``
  Completion Queue Entry Size, see :c:type:`enum nvme_id_ctrl_cqes <nvme_id_ctrl_cqes>`.

``maxcmd``
  Maximum Outstanding Commands indicates the maximum number of
  commands that the controller processes at one time for a
  particular queue.

``nn``
  Number of Namespaces indicates the maximum value of a valid
  nsid for the NVM subsystem. If the MNAN (:c:type:`struct nvme_id_ctrl <nvme_id_ctrl>`.mnan
  field is cleared to 0h, then this field also indicates the
  maximum number of namespaces supported by the NVM.  subsystem.

``oncs``
  Optional NVM Command Support, see :c:type:`enum nvme_id_ctrl_oncs <nvme_id_ctrl_oncs>`.

``fuses``
  Fused Operation Support, see :c:type:`enum nvme_id_ctrl_fuses <nvme_id_ctrl_fuses>`.

``fna``
  Format NVM Attributes, see :c:type:`enum nvme_id_ctrl_fna <nvme_id_ctrl_fna>`.

``vwc``
  Volatile Write Cache, see :c:type:`enum nvme_id_ctrl_vwc <nvme_id_ctrl_vwc>`.

``awun``
  Atomic Write Unit Normal indicates the size of the write
  operation guaranteed to be written atomically to the NVM across
  all namespaces with any supported namespace format during normal
  operation. This field is specified in logical blocks and is a
  0's based value.

``awupf``
  Atomic Write Unit Power Fail indicates the size of the write
  operation guaranteed to be written atomically to the NVM across
  all namespaces with any supported namespace format during a
  power fail or error condition. This field is specified in
  logical blocks and is a 0’s based value.

``nvscc``
  NVM Vendor Specific Command Configuration, see
  :c:type:`enum nvme_id_ctrl_nvscc <nvme_id_ctrl_nvscc>`.

``nwpc``
  Namespace Write Protection Capabilities, see
  :c:type:`enum nvme_id_ctrl_nwpc <nvme_id_ctrl_nwpc>`.

``acwu``
  Atomic Compare & Write Unit indicates the size of the write
  operation guaranteed to be written atomically to the NVM across
  all namespaces with any supported namespace format for a Compare
  and Write fused operation. This field is specified in logical
  blocks and is a 0’s based value.

``ocfs``
  Optional Copy Formats Supported, each bit n means controller supports
  Copy Format n.

``sgls``
  SGL Support, see :c:type:`enum nvme_id_ctrl_sgls <nvme_id_ctrl_sgls>`

``mnan``
  Maximum Number of Allowed Namespaces indicates the maximum
  number of namespaces supported by the NVM subsystem.

``subnqn``
  NVM Subsystem NVMe Qualified Name, UTF-8 null terminated string

``ioccsz``
  I/O Queue Command Capsule Supported Size, defines the maximum
  I/O command capsule size in 16 byte units.

``iorcsz``
  I/O Queue Response Capsule Supported Size, defines the maximum
  I/O response capsule size in 16 byte units.

``icdoff``
  In Capsule Data Offset, defines the offset where data starts
  within a capsule. This value is applicable to I/O Queues only.

``fcatt``
  Fabrics Controller Attributes, see :c:type:`enum nvme_id_ctrl_fcatt <nvme_id_ctrl_fcatt>`.

``msdbd``
  Maximum SGL Data Block Descriptors indicates the maximum
  number of SGL Data Block or Keyed SGL Data Block descriptors
  that a host is allowed to place in a capsule. A value of 0h
  indicates no limit.

``ofcs``
  Optional Fabric Commands Support, see :c:type:`enum nvme_id_ctrl_ofcs <nvme_id_ctrl_ofcs>`.

``psd``
  Power State Descriptors, see :c:type:`struct nvme_id_psd <nvme_id_psd>`.

``vs``
  Vendor Specific





.. c:type:: enum nvme_id_ctrl_cmic


**Constants**

``NVME_CTRL_CMIC_MULTI_PORT``
  *undescribed*

``NVME_CTRL_CMIC_MULTI_CTRL``
  *undescribed*

``NVME_CTRL_CMIC_MULTI_SRIOV``
  *undescribed*

``NVME_CTRL_CMIC_MULTI_ANA_REPORTING``
  *undescribed*




.. c:type:: enum nvme_id_ctrl_oaes

   The typical latency in microseconds to enter Runtime D3

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
  :

``NVME_CTRL_OAES_EGE``
  *undescribed*




.. c:type:: enum nvme_id_ctrl_ctratt


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




.. c:type:: enum nvme_id_ctrl_cntrltype


**Constants**

``NVME_CTRL_CNTRLTYPE_IO``
  *undescribed*

``NVME_CTRL_CNTRLTYPE_DISCOVERY``
  *undescribed*

``NVME_CTRL_CNTRLTYPE_ADMIN``
  *undescribed*




.. c:type:: enum nvme_id_ctrl_nvmsr

   This field reports information associated with the NVM Subsystem, see :c:type:`struct nvme_id_ctrl <nvme_id_ctrl>`.nvmsr.

**Constants**

``NVME_CTRL_NVMSR_NVMESD``
  If set, then the NVM Subsystem is part of an NVMe
  Storage Device; if cleared, then the NVM Subsystem
  is not part of an NVMe Storage Device.

``NVME_CTRL_NVMSR_NVMEE``
  If set’, then the NVM Subsystem is part of an NVMe
  Enclosure; if cleared, then the NVM Subsystem is
  not part of an NVMe Enclosure.




.. c:type:: enum nvme_id_ctrl_vwci

   This field indicates information about remaining number of times that VPD contents are able to be updated using the VPD Write command, see :c:type:`struct nvme_id_ctrl <nvme_id_ctrl>`.vwci.

**Constants**

``NVME_CTRL_VWCI_VWCR``
  Mask to get value of VPD Write Cycles Remaining. If
  the VPD Write Cycle Remaining Valid bit is set, then
  this field contains a value indicating the remaining
  number of times that VPD contents are able to be
  updated using the VPD Write command. If this field is
  set to 7Fh, then the remaining number of times that
  VPD contents are able to be updated using the VPD
  Write command is greater than or equal to 7Fh.

``NVME_CTRL_VWCI_VWCRV``
  VPD Write Cycle Remaining Valid. If this bit is set,
  then the VPD Write Cycle Remaining field is valid. If
  this bit is cleared, then the VPD Write Cycles
  Remaining field is invalid and cleared to 0h.




.. c:type:: enum nvme_id_ctrl_mec

   Flags indicatings the capabilities of the Management Endpoint in the Controller, :c:type:`struct nvme_id_ctrl <nvme_id_ctrl>`.mec.

**Constants**

``NVME_CTRL_MEC_SMBUSME``
  If set, then the NVM Subsystem contains a Management
  Endpoint on an SMBus/I2C port.

``NVME_CTRL_MEC_PCIEME``
  If set, then the NVM Subsystem contains a Management
  Endpoint on a PCIe port.




.. c:type:: enum nvme_id_ctrl_oacs

   Flags indicating the optional Admin commands and features supported by the controller, see :c:type:`struct nvme_id_ctrl <nvme_id_ctrl>`.oacs.

**Constants**

``NVME_CTRL_OACS_SECURITY``
  If set, then the controller supports the
  Security Send and Security Receive commands.

``NVME_CTRL_OACS_FORMAT``
  If set then the controller supports the Format
  NVM command.

``NVME_CTRL_OACS_FW``
  If set, then the controller supports the
  Firmware Commit and Firmware Image Download commands.

``NVME_CTRL_OACS_NS_MGMT``
  If set, then the controller supports the
  Namespace Management capability

``NVME_CTRL_OACS_SELF_TEST``
  If set, then the controller supports the Device
  Self-test command.

``NVME_CTRL_OACS_DIRECTIVES``
  If set, then the controller supports Directives
  and the Directive Send and Directive Receive
  commands.

``NVME_CTRL_OACS_NVME_MI``
  If set, then the controller supports the NVMe-MI
  Send and NVMe-MI Receive commands.

``NVME_CTRL_OACS_VIRT_MGMT``
  If set, then the controller supports the
  Virtualization Management command.

``NVME_CTRL_OACS_DBBUF_CFG``
  If set, then the controller supports the
  Doorbell Buffer Config command.

``NVME_CTRL_OACS_LBA_STATUS``
  If set, then the controller supports the Get LBA
  Status capability.




.. c:type:: enum nvme_id_ctrl_frmw

   Flags and values indicates capabilities regarding firmware updates from :c:type:`struct nvme_id_ctrl <nvme_id_ctrl>`.frmw.

**Constants**

``NVME_CTRL_FRMW_1ST_RO``
  If set, the first firmware slot is readonly

``NVME_CTRL_FRMW_NR_SLOTS``
  Mask to get the value of the number of
  firmware slots that the controller supports.

``NVME_CTRL_FRMW_FW_ACT_NO_RESET``
  If set, the controller supports firmware
  activation without a reset.




.. c:type:: enum nvme_id_ctrl_lpa

   Flags indicating optional attributes for log pages that are accessed via the Get Log Page command.

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




.. c:type:: enum nvme_id_ctrl_avscc

   Flags indicating the configuration settings for Admin Vendor Specific command handling.

**Constants**

``NVME_CTRL_AVSCC_AVS``
  If set, all Admin Vendor Specific Commands use the
  optional vendor specific command format with NDT and
  NDM fields.




.. c:type:: enum nvme_id_ctrl_apsta

   Flags indicating the attributes of the autonomous power state transition feature.

**Constants**

``NVME_CTRL_APSTA_APST``
  If set, then the controller supports autonomous power
  state transitions.




.. c:type:: enum nvme_id_ctrl_rpmbs

   This field indicates if the controller supports one or more Replay Protected Memory Blocks, from :c:type:`struct nvme_id_ctrl <nvme_id_ctrl>`.rpmbs.

**Constants**

``NVME_CTRL_RPMBS_NR_UNITS``
  Mask to get the value of the Number of RPMB Units

``NVME_CTRL_RPMBS_AUTH_METHOD``
  Mask to get the value of the Authentication Method

``NVME_CTRL_RPMBS_TOTAL_SIZE``
  Mask to get the value of Total Size

``NVME_CTRL_RPMBS_ACCESS_SIZE``
  Mask to get the value of Access Size




.. c:type:: enum nvme_id_ctrl_dsto

   Flags indicating the optional Device Self-test command or operation behaviors supported by the controller or NVM subsystem.

**Constants**

``NVME_CTRL_DSTO_ONE_DST``
  If set,  then the NVM subsystem supports only one
  device self-test operation in progress at a time.




.. c:type:: enum nvme_id_ctrl_hctm

   Flags indicate the attributes of the host controlled thermal management feature

**Constants**

``NVME_CTRL_HCTMA_HCTM``
  then the controller supports host controlled thermal
  management, and the Set Features command and Get
  Features command with the Feature Identifier field
  set to ``NVME_FEAT_FID_HCTM``.




.. c:type:: enum nvme_id_ctrl_sanicap

   Indicates attributes for sanitize operations.

**Constants**

``NVME_CTRL_SANICAP_CES``
  Crypto Erase Support. If set, then the
  controller supports the Crypto Erase sanitize operation.

``NVME_CTRL_SANICAP_BES``
  Block Erase Support. If set, then the controller
  supports the Block Erase sanitize operation.

``NVME_CTRL_SANICAP_OWS``
  Overwrite Support. If set, then the controller
  supports the Overwrite sanitize operation.

``NVME_CTRL_SANICAP_NDI``
  No-Deallocate Inhibited. If set and the No-
  Deallocate Response Mode bit is set, then the
  controller deallocates after the sanitize
  operation even if the No-Deallocate After
  Sanitize bit is set in a Sanitize command.

``NVME_CTRL_SANICAP_NODMMAS``
  No-Deallocate Modifies Media After Sanitize,
  mask to extract value.




.. c:type:: enum nvme_id_ctrl_anacap

   This field indicates the capabilities associated with Asymmetric Namespace Access Reporting.

**Constants**

``NVME_CTRL_ANACAP_OPT``
  If set, then the controller is able to
  report ANA Optimized state.

``NVME_CTRL_ANACAP_NON_OPT``
  If set, then the controller is able to
  report ANA Non-Optimized state.

``NVME_CTRL_ANACAP_INACCESSIBLE``
  If set, then the controller is able to
  report ANA Inaccessible state.

``NVME_CTRL_ANACAP_PERSISTENT_LOSS``
  If set, then the controller is able to
  report ANA Persistent Loss state.

``NVME_CTRL_ANACAP_CHANGE``
  If set, then the controller is able to
  report ANA Change state.

``NVME_CTRL_ANACAP_GRPID_NO_CHG``
  If set, then the ANAGRPID field in the
  Identify Namespace data structure
  (:c:type:`struct nvme_id_ns <nvme_id_ns>`.anagrpid), does not
  change while the namespace is attached to
  any controller.

``NVME_CTRL_ANACAP_GRPID_MGMT``
  If set, then the controller supports a
  non-zero value in the ANAGRPID field of
  the Namespace Management command.




.. c:type:: enum nvme_id_ctrl_sqes

   Defines the required and maximum Submission Queue entry size when using the NVM Command Set.

**Constants**

``NVME_CTRL_SQES_MIN``
  Mask to get the value of the required Submission Queue
  Entry size when using the NVM Command Set.

``NVME_CTRL_SQES_MAX``
  Mask to get the value of the maximum Submission Queue
  entry size when using the NVM Command Set.




.. c:type:: enum 

   Defines the required and maximum Completion Queue entry size when using the NVM Command Set.

**Constants**

``NVME_CTRL_CQES_MIN``
  Mask to get the value of the required Completion Queue
  Entry size when using the NVM Command Set.

``NVME_CTRL_CQES_MAX``
  Mask to get the value of the maximum Completion Queue
  entry size when using the NVM Command Set.




.. c:type:: enum nvme_id_ctrl_oncs

   This field indicates the optional NVM commands and features supported by the controller.

**Constants**

``NVME_CTRL_ONCS_COMPARE``
  If set, then the controller supports
  the Compare command.

``NVME_CTRL_ONCS_WRITE_UNCORRECTABLE``
  If set, then the controller supports
  the Write Uncorrectable command.

``NVME_CTRL_ONCS_DSM``
  If set, then the controller supports
  the Dataset Management command.

``NVME_CTRL_ONCS_WRITE_ZEROES``
  If set, then the controller supports
  the Write Zeroes command.

``NVME_CTRL_ONCS_SAVE_FEATURES``
  If set, then the controller supports
  the Save field set to a non-zero value
  in the Set Features command and the
  Select field set to a non-zero value in
  the Get Features command.

``NVME_CTRL_ONCS_RESERVATIONS``
  If set, then the controller supports
  reservations.

``NVME_CTRL_ONCS_TIMESTAMP``
  If set, then the controller supports
  the Timestamp feature.

``NVME_CTRL_ONCS_VERIFY``
  If set, then the controller supports
  the Verify command.




.. c:type:: enum nvme_id_ctrl_fuses

   This field indicates the fused operations that the controller supports.

**Constants**

``NVME_CTRL_FUSES_COMPARE_AND_WRITE``
  If set, then the controller supports the
  Compare and Write fused operation.




.. c:type:: enum nvme_id_ctrl_fna

   This field indicates attributes for the Format NVM command.

**Constants**

``NVME_CTRL_FNA_FMT_ALL_NAMESPACES``
  If set, then all namespaces in an NVM
  subsystem shall be configured with the
  same attributes and a format (excluding
  secure erase) of any namespace results in
  a format of all namespaces in an NVM
  subsystem. If cleared, then the
  controller supports format on a per
  namespace basis.

``NVME_CTRL_FNA_SEC_ALL_NAMESPACES``
  If set, then any secure erase performed
  as part of a format operation results in
  a secure erase of all namespaces in the
  NVM subsystem. If cleared, then any
  secure erase performed as part of a
  format results in a secure erase of the
  particular namespace specified.

``NVME_CTRL_FNA_CRYPTO_ERASE``
  If set, then cryptographic erase is
  supported. If cleared, then cryptographic
  erase is not supported.




.. c:type:: enum nvme_id_ctrl_vwc


**Constants**

``NVME_CTRL_VWC_PRESENT``
  If set, indicates a volatile write cache is present.
  If a volatile write cache is present, then the host
  controls whether the volatile write cache is enabled
  with a Set Features command specifying the value
  ``NVME_FEAT_FID_VOLATILE_WC``.

``NVME_CTRL_VWC_FLUSH``
  Mask to get the value of the flush command behavior.




.. c:type:: enum nvme_id_ctrl_nvscc

   This field indicates the configuration settings for NVM Vendor Specific command handling.

**Constants**

``NVME_CTRL_NVSCC_FMT``
  If set, all NVM Vendor Specific Commands use the
  format format with NDT and NDM fields.




.. c:type:: enum nvme_id_ctrl_nwpc

   This field indicates the optional namespace write protection capabilities supported by the controller.

**Constants**

``NVME_CTRL_NWPC_WRITE_PROTECT``
  If set, then the controller shall
  support the No Write Protect and
  Write Protect namespace write
  protection states and may support
  the Write Protect Until Power
  Cycle state and Permanent Write
  Protect namespace write
  protection states.

``NVME_CTRL_NWPC_WRITE_PROTECT_POWER_CYCLE``
  If set, then the controller
  supports the Write Protect Until
  Power Cycle state.

``NVME_CTRL_NWPC_WRITE_PROTECT_PERMANENT``
  If set, then the controller
  supports the Permanent Write
  Protect state.




.. c:type:: enum nvme_id_ctrl_sgls

   This field indicates if SGLs are supported for the NVM Command Set and the particular SGL types supported.

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




.. c:type:: enum nvme_id_ctrl_fcatt

   This field indicates attributes of the controller that are specific to NVMe over Fabrics.

**Constants**

``NVME_CTRL_FCATT_DYNAMIC``
  If cleared, then the NVM subsystem uses a dynamic
  controller model. If set, then the NVM subsystem
  uses a static controller model.




.. c:type:: enum nvme_id_ctrl_ofcs

   Indicate whether the controller supports optional fabric commands.

**Constants**

``NVME_CTRL_OFCS_DISCONNECT``
  If set, then the controller supports the
  Disconnect command and deletion of individual
  I/O Queues.




.. c:type:: struct nvme_lbaf

   LBA Format Data Structure

**Definition**

::

  struct nvme_lbaf {
    __le16 ms;
    __u8 ds;
    __u8 rp;
  };

**Members**

``ms``
  Metadata Size indicates the number of metadata bytes provided per LBA
  based on the LBA Data Size indicated.

``ds``
  LBA Data Size indicates the LBA data size supported, reported as a
  power of two.

``rp``
  Relative Performance, see :c:type:`enum nvme_lbaf_rp <nvme_lbaf_rp>`.





.. c:type:: enum nvme_lbaf_rp

   This field indicates the relative performance of the LBA format indicated relative to other LBA formats supported by the controller.

**Constants**

``NVME_LBAF_RP_BEST``
  Best performance

``NVME_LBAF_RP_BETTER``
  Better performance

``NVME_LBAF_RP_GOOD``
  Good performance

``NVME_LBAF_RP_DEGRADED``
  Degraded performance

``NVME_LBAF_RP_MASK``
  Mask to get the relative performance value from the
  field




.. c:type:: struct nvme_id_ns

   Identify Namespace data structure

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

``nsze``
  Namespace Size indicates the total size of the namespace in
  logical blocks. The number of logical blocks is based on the
  formatted LBA size.

``ncap``
  Namespace Capacity indicates the maximum number of logical blocks
  that may be allocated in the namespace at any point in time. The
  number of logical blocks is based on the formatted LBA size.

``nuse``
  Namespace Utilization indicates the current number of logical
  blocks allocated in the namespace. This field is smaller than or
  equal to the Namespace Capacity. The number of logical blocks is
  based on the formatted LBA size.

``nsfeat``
  Namespace Features, see :c:type:`enum nvme_id_nsfeat <nvme_id_nsfeat>`.

``nlbaf``
  Number of LBA Formats defines the number of supported LBA data
  size and metadata size combinations supported by the namespace
  and the highest possible index to :c:type:`struct nvme_id_ns <nvme_id_ns>`.labf.

``flbas``
  Formatted LBA Size, see :c:type:`enum nvme_id_ns_flbas <nvme_id_ns_flbas>`.

``mc``
  Metadata Capabilities, see :c:type:`enum nvme_id_ns_mc <nvme_id_ns_mc>`.

``dpc``
  End-to-end Data Protection Capabilities, see
  :c:type:`enum nvme_id_ns_dpc <nvme_id_ns_dpc>`.

``dps``
  End-to-end Data Protection Type Settings, see
  :c:type:`enum nvme_id_ns_dps <nvme_id_ns_dps>`.

``nmic``
  Namespace Multi-path I/O and Namespace Sharing Capabilities, see
  :c:type:`enum nvme_id_ns_nmic <nvme_id_ns_nmic>`.

``rescap``
  Reservation Capabilities, see :c:type:`enum nvme_id_ns_rescap <nvme_id_ns_rescap>`.

``fpi``
  Format Progress Indicator, see :c:type:`enum nvme_nd_ns_fpi <nvme_nd_ns_fpi>`.

``dlfeat``
  Deallocate Logical Block Features, see :c:type:`enum nvme_id_ns_dlfeat <nvme_id_ns_dlfeat>`.

``nawun``
  Namespace Atomic Write Unit Normal indicates the
  namespace specific size of the write operation guaranteed to be
  written atomically to the NVM during normal operation.

``nawupf``
  Namespace Atomic Write Unit Power Fail indicates the
  namespace specific size of the write operation guaranteed to be
  written atomically to the NVM during a power fail or error
  condition.

``nacwu``
  Namespace Atomic Compare & Write Unit indicates the namespace
  specific size of the write operation guaranteed to be written
  atomically to the NVM for a Compare and Write fused command.

``nabsn``
  Namespace Atomic Boundary Size Normal indicates the atomic
  boundary size for this namespace for the NAWUN value. This field
  is specified in logical blocks.

``nabo``
  Namespace Atomic Boundary Offset indicates the LBA on this
  namespace where the first atomic boundary starts.

``nabspf``
  Namespace Atomic Boundary Size Power Fail indicates the atomic
  boundary size for this namespace specific to the Namespace Atomic
  Write Unit Power Fail value. This field is specified in logical
  blocks.

``noiob``
  Namespace Optimal I/O Boundary indicates the optimal I/O boundary
  for this namespace. This field is specified in logical blocks.
  The host should construct Read and Write commands that do not
  cross the I/O boundary to achieve optimal performance.

``nvmcap``
  NVM Capacity indicates the total size of the NVM allocated to
  this namespace. The value is in bytes.

``npwg``
  Namespace Preferred Write Granularity indicates the smallest
  recommended write granularity in logical blocks for this
  namespace. This is a 0's based value.

``npwa``
  Namespace Preferred Write Alignment indicates the recommended
  write alignment in logical blocks for this namespace. This is a
  0's based value.

``npdg``
  Namespace Preferred Deallocate Granularity indicates the
  recommended granularity in logical blocks for the Dataset
  Management command with the Attribute - Deallocate bit.

``npda``
  Namespace Preferred Deallocate Alignment indicates the
  recommended alignment in logical blocks for the Dataset
  Management command with the Attribute - Deallocate bit

``nows``
  Namespace Optimal Write Size indicates the size in logical blocks
  for optimal write performance for this namespace. This is a 0's
  based value.

``anagrpid``
  ANA Group Identifier indicates the ANA Group Identifier of the
  ANA group of which the namespace is a member.

``nsattr``
  Namespace Attributes, see :c:type:`enum nvme_id_ns_attr <nvme_id_ns_attr>`.

``nvmsetid``
  NVM Set Identifier indicates the NVM Set with which this
  namespace is associated.

``endgid``
  Endurance Group Identifier indicates the Endurance Group with
  which this namespace is associated.

``nguid``
  Namespace Globally Unique Identifier contains a 128-bit value
  that is globally unique and assigned to the namespace when the
  namespace is created. This field remains fixed throughout the
  life of the namespace and is preserved across namespace and
  controller operations

``eui64``
  IEEE Extended Unique Identifier contains a 64-bit IEEE Extended
  Unique Identifier (EUI-64) that is globally unique and assigned
  to the namespace when the namespace is created. This field
  remains fixed throughout the life of the namespace and is
  preserved across namespace and controller operations

``lbaf``
  LBA Format, see :c:type:`struct nvme_lbaf <nvme_lbaf>`.

``vs``
  Vendor Specific





.. c:type:: enum nvme_id_nsfeat

   This field defines features of the namespace.

**Constants**

``NVME_NS_FEAT_THIN``
  If set, indicates that the namespace supports thin
  provisioning. Specifically, the Namespace Capacity
  reported may be less than the Namespace Size.

``NVME_NS_FEAT_NATOMIC``
  If set, indicates that the fields NAWUN, NAWUPF, and
  NACWU are defined for this namespace and should be
  used by the host for this namespace instead of the
  AWUN, AWUPF, and ACWU fields in the Identify
  Controller data structure.

``NVME_NS_FEAT_DULBE``
  If set, indicates that the controller supports the
  Deallocated or Unwritten Logical Block error for
  this namespace.  **NVME_NS_FEAT_ID_REUSE**: If set,
  indicates that the value in the NGUID field for this
  namespace, if non- zero, is never reused by the
  controller and that the value in the EUI64 field for
  this namespace, if non-zero, is never reused by the
  controller.

``NVME_NS_FEAT_ID_REUSE``
  *undescribed*

``NVME_NS_FEAT_IO_OPT``
  If set, indicates that the fields NPWG, NPWA, NPDG,
  NPDA, and NOWS are defined for this namespace and
  should be used by the host for I/O optimization




.. c:type:: enum nvme_id_ns_flbas

   This field indicates the LBA data size & metadata size combination that the namespace has been formatted with

**Constants**

``NVME_NS_FLBAS_LBA_MASK``
  Mask to get the index of one of the 16 supported
  LBA Formats indicated in :c:type:`struct nvme_id_ns <nvme_id_ns>`.lbaf.

``NVME_NS_FLBAS_META_EXT``
  Applicable only if format contains metadata. If
  this bit is set, indicates that the metadata is
  transferred at the end of the data LBA, creating an
  extended data LBA. If cleared, indicates that all
  of the metadata for a command is transferred as a
  separate contiguous buffer of data.




.. c:type:: enum nvme_id_ns_mc

   This field indicates the capabilities for metadata.

**Constants**

``NVME_NS_MC_EXTENDED``
  If set, indicates the namespace supports the metadata
  being transferred as part of a separate buffer that is
  specified in the Metadata Pointer.

``NVME_NS_MC_SEPARATE``
  If set, indicates that the namespace supports the
  metadata being transferred as part of an extended data LBA.




.. c:type:: enum nvme_id_ns_dpc

   This field indicates the capabilities for the end-to-end data protection feature.

**Constants**

``NVME_NS_DPC_PI_TYPE1``
  If set, indicates that the namespace supports
  Protection Information Type 1.

``NVME_NS_DPC_PI_TYPE2``
  If set, indicates that the namespace supports
  Protection Information Type 2.

``NVME_NS_DPC_PI_TYPE3``
  If set, indicates that the namespace supports
  Protection Information Type 3.

``NVME_NS_DPC_PI_FIRST``
  If set, indicates that the namespace supports
  protection information transferred as the first eight
  bytes of metadata.

``NVME_NS_DPC_PI_LAST``
  If set, indicates that the namespace supports
  protection information transferred as the last eight
  bytes of metadata.




.. c:type:: enum nvme_id_ns_dps

   This field indicates the Type settings for the end-to-end data protection feature.

**Constants**

``NVME_NS_DPS_PI_NONE``
  Protection information is not enabled

``NVME_NS_DPS_PI_TYPE1``
  Protection information is enabled, Type 1

``NVME_NS_DPS_PI_TYPE2``
  Protection information is enabled, Type 2

``NVME_NS_DPS_PI_TYPE3``
  Protection information is enabled, Type 3

``NVME_NS_DPS_PI_MASK``
  Mask to get the value of the PI type

``NVME_NS_DPS_PI_FIRST``
  If set, indicates that the protection information, if
  enabled, is transferred as the first eight bytes of
  metadata.




.. c:type:: enum nvme_id_ns_nmic

   This field specifies multi-path I/O and namespace sharing capabilities of the namespace.

**Constants**

``NVME_NS_NMIC_SHARED``
  If set, then the namespace may be attached to two or
  more controllers in the NVM subsystem concurrently




.. c:type:: enum nvme_id_ns_rescap

   This field indicates the reservation capabilities of the namespace.

**Constants**

``NVME_NS_RESCAP_PTPL``
  If set, indicates that the namespace supports the
  Persist Through Power Loss capability.

``NVME_NS_RESCAP_WE``
  If set, indicates that the namespace supports the
  Write Exclusive reservation type.

``NVME_NS_RESCAP_EA``
  If set, indicates that the namespace supports the
  Exclusive Access reservation type.

``NVME_NS_RESCAP_WERO``
  If set, indicates that the namespace supports the
  Write Exclusive - Registrants Only reservation type.

``NVME_NS_RESCAP_EARO``
  If set, indicates that the namespace supports the
  Exclusive Access - Registrants Only reservation type.

``NVME_NS_RESCAP_WEAR``
  If set, indicates that the namespace supports the
  Write Exclusive - All Registrants reservation type.

``NVME_NS_RESCAP_EAAR``
  If set, indicates that the namespace supports the
  Exclusive Access - All Registrants reservation type.

``NVME_NS_RESCAP_IEK_13``
  If set, indicates that Ignore Existing Key is used
  as defined in revision 1.3 or later of this specification.




.. c:type:: enum nvme_nd_ns_fpi

   If a format operation is in progress, this field indicates the percentage of the namespace that remains to be formatted.

**Constants**

``NVME_NS_FPI_REMAINING``
  Mask to get the format percent remaining value

``NVME_NS_FPI_SUPPORTED``
  If set, indicates that the namespace supports the
  Format Progress Indicator defined for the field.




.. c:type:: enum nvme_id_ns_dlfeat

   This field indicates information about features that affect deallocating logical blocks for this namespace.

**Constants**

``NVME_NS_DLFEAT_RB``
  Mask to get the value of the read behavior

``NVME_NS_DLFEAT_RB_NR``
  Read behvaior is not reported

``NVME_NS_DLFEAT_RB_ALL_0S``
  A deallocated logical block returns all bytes
  cleared to 0h.

``NVME_NS_DLFEAT_RB_ALL_FS``
  A deallocated logical block returns all bytes
  set to FFh.

``NVME_NS_DLFEAT_WRITE_ZEROES``
  If set, indicates that the controller supports
  the Deallocate bit in the Write Zeroes command
  for this namespace.

``NVME_NS_DLFEAT_CRC_GUARD``
  If set, indicates that the Guard field for
  deallocated logical blocks that contain
  protection information is set to the CRC for
  the value read from the deallocated logical
  block and its metadata




.. c:type:: enum nvme_id_ns_attr

   Specifies attributes of the namespace.

**Constants**

``NVME_NS_NSATTR_WRITE_PROTECTED``
  If set, then the namespace is currently
  write protected and all write access to the
  namespace shall fail.




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

``nidt``
  Namespace Identifier Type, see :c:type:`enum nvme_ns_id_desc_nidt <nvme_ns_id_desc_nidt>`

``nidl``
  Namespace Identifier Length contains the length in bytes of the
  :c:type:`struct nvme_id_ns <nvme_id_ns>`.nid.

``nid``
  Namespace Identifier contains a value that is globally unique and
  assigned to the namespace when the namespace is created. The length
  is defined in :c:type:`struct nvme_id_ns <nvme_id_ns>`.nidl.





.. c:type:: enum nvme_ns_id_desc_nidt

   Known namespace identifier types

**Constants**

``NVME_NIDT_EUI64``
  IEEE Extended Unique Identifier, the NID field contains a
  copy of the EUI64 field in the struct nvme_id_ns.eui64.

``NVME_NIDT_NGUID``
  Namespace Globally Unique Identifier, the NID field
  contains a copy of the NGUID field in struct nvme_id_ns.nguid.

``NVME_NIDT_UUID``
  The NID field contains a 128-bit Universally Unique
  Identifier (UUID) as specified in RFC 4122.




.. c:type:: struct nvme_nvmset_attr

   NVM Set Attributes Entry

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

``id``
  NVM Set Identifier

``endurance_group_id``
  Endurance Group Identifier

``random_4k_read_typical``
  Random 4 KiB Read Typical indicates the typical
  time to complete a 4 KiB random read in 100
  nanosecond units when the NVM Set is in a
  Predictable Latency Mode Deterministic Window and
  there is 1 outstanding command per NVM Set.





.. c:type:: struct nvme_id_nvmset_list

    **nid**;

**Definition**

::

  struct nvme_id_nvmset_list {
    __u8 nid;
    __u8 rsvd1[127];
    struct nvme_nvmset_attr ent[NVME_ID_NVMSET_LIST_MAX];
  };

**Members**

``ent``
  ;





.. c:type:: struct nvme_id_ns_granularity_desc


**Definition**

::

  struct nvme_id_ns_granularity_desc {
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
    struct nvme_id_ns_granularity_desc entry[NVME_ID_ND_DESCRIPTOR_MAX];
    __u8 rsvd288[3808];
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

    **num**;

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

    **num**;

**Definition**

::

  struct nvme_secondary_ctrl_list {
    __u8 num;
    __u8 rsvd[31];
    struct nvme_secondary_ctrl sc_entry[NVME_ID_SECONDARY_CTRL_MAX];
  };

**Members**





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
    __u8 rsvd[2];
    __le64 cs;
    __le16 trtype_spec_info;
    __u8 rsvd2[22];
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




.. c:type:: struct nvme_firmware_slot


**Definition**

::

  struct nvme_firmware_slot {
    __u8 afi;
    __u8 resv[7];
    char frs[7][8];
    __u8 resv2[448];
  };

**Members**





.. c:type:: struct nvme_cmd_effects_log


**Definition**

::

  struct nvme_cmd_effects_log {
    __le32 acs[256];
    __le32 iocs[256];
    __u8 rsvd[2048];
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

``NVME_ST_RESULT_MASK``
  *undescribed*




.. c:type:: enum 


**Constants**

``NVME_ST_CODE_SHIFT``
  *undescribed*

``NVME_ST_CODE_RESRVED``
  *undescribed*

``NVME_ST_CODE_SHORT``
  *undescribed*

``NVME_ST_CODE_EXTENDED``
  *undescribed*

``NVME_ST_CODE_VS``
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

   Retrieve internal data specific to the manufacturer.

**Definition**

::

  struct nvme_telemetry_log {
    __u8 lpi;
    __u8 rsvd1[4];
    __u8 ieee[3];
    __le16 dalb1;
    __le16 dalb2;
    __le16 dalb3;
    __u8 rsvd14[368];
    __u8 ctrlavail;
    __u8 ctrldgn;
    __u8 rsnident[128];
    __u8 data_area[];
  };

**Members**

``lpi``
  Log Identifier, either ``NVME_LOG_LID_TELEMETRY_HOST`` or
  ``NVME_LOG_LID_TELEMETRY_CTRL``

``ieee``
  IEEE OUI Identifier is the Organization Unique Identifier (OUI)
  for the controller vendor that is able to interpret the data.

``dalb1``
  Telemetry Controller-Initiated Data Area 1 Last Block is
  the value of the last block in this area.

``dalb3``
  Telemetry Controller-Initiated Data Area 1 Last Block is
  the value of the last block in this area.

``ctrlavail``
  Telemetry Controller-Initiated Data Available, if cleared,
  then the controller telemetry log does not contain saved
  internal controller state. If this field is set to 1h, the
  controller log contains saved internal controller state. If
  this field is set to 1h, the data will be latched until the
  host releases it by reading the log with RAE cleared.

``ctrldgn``
  Telemetry Controller-Initiated Data Generation Number is
  a value that is incremented each time the controller initiates a
  capture of its internal controller state in the controller .

``rsnident``
  Reason Identifieris a vendor specific identifier that describes
  the operating conditions of the controller at the time of
  capture.

``data_area``
  Telemetry data blocks, vendor specific information data.


**Description**

This log consists of a header describing the log and zero or more Telemetry
Data Blocks. All Telemetry Data Blocks are ``NVME_LOG_TELEM_BLOCK_SIZE``, 512
bytes, in size. This log captures the controller’s internal state.




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





.. c:type:: enum nvme_ana_state


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
    char subnqn[NVME_NQN_LENGTH];
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

``rnlpt``
  See :c:type:`enum nvme_resv_notify_rnlpt <nvme_resv_notify_rnlpt>`.





.. c:type:: enum nvme_resv_notify_rnlpt


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





.. c:type:: enum nvme_sanitize_sstat


**Constants**

``NVME_SANITIZE_SSTAT_STATUS_MASK``
  *undescribed*

``NVME_SANITIZE_SSTAT_STATUS_NEVER_SANITIZED``
  *undescribed*

``NVME_SANITIZE_SSTAT_STATUS_COMPLETE_SUCCESS``
  *undescribed*

``NVME_SANITIZE_SSTAT_STATUS_IN_PROGESS``
  *undescribed*

``NVME_SANITIZE_SSTAT_STATUS_COMPLETED_FAILED``
  *undescribed*

``NVME_SANITIZE_SSTAT_STATUS_ND_COMPLETE_SUCCESS``
  *undescribed*

``NVME_SANITIZE_SSTAT_COMPLETED_PASSES_MASK``
  *undescribed*

``NVME_SANITIZE_SSTAT_COMPLETED_PASSES_SHIFT``
  *undescribed*

``NVME_SANITIZE_SSTAT_GLOBAL_DATA_ERASED``
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





.. c:type:: struct nvme_feat_auto_pst


**Definition**

::

  struct nvme_feat_auto_pst {
    __le64 apst_entry[32];
  };

**Members**

``apst_entry``
  See :c:type:`enum nvme_apst_entry <nvme_apst_entry>`





.. c:type:: enum nvme_apst_entry


**Constants**

``NVME_APST_ENTRY_ITPS_MASK``
  *undescribed*

``NVME_APST_ENTRY_ITPS_SHIFT``
  *undescribed*

``NVME_APST_ENTRY_ITPT_MASK``
  *undescribed*

``NVME_APST_ENTRY_ITPT_SHIFT``
  *undescribed*




.. c:type:: struct nvme_timestamp

    timestamp:

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

    **ee**; **dtwinrt**; **dtwinwt**; **dtwintt**;

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
    __u8 rsvd1[511];
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
    __u8 rsvd3[5];
    __le64 rkey;
    __u8 hostid[16];
    __u8 rsvd32[32];
  };

**Members**





.. c:type:: struct nvme_reservation_status

   {

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
        __u8 rsvd24[40];
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

   Discovery log page entry

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
    __u8 rsvd10[22];
    char trsvcid[NVMF_TRSVCID_SIZE];
    __u8 rsvd64[192];
    char subnqn[NVME_NQN_LENGTH];
    char traddr[NVMF_TRADDR_SIZE];
    union tsas {
      char common[NVMF_TSAS_SIZE];
      struct rdma {
        __u8 qptype;
        __u8 prtype;
        __u8 cms;
        __u8 rsvd3[5];
        __u16 pkey;
        __u8 rsvd10[246];
      } rdma;
      struct tcp {
        __u8 sectype;
      } tcp;
    } tsas;
  };

**Members**





.. c:type:: enum 

   Transport Type codes for Discovery Log Page entry TRTYPE field

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




.. c:type:: enum 

   Address Family codes for Discovery Log Page entry ADRFAM field

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




.. c:type:: enum 

   Transport Requirements codes for Discovery Log Page entry TREQ field

**Constants**

``NVMF_TREQ_NOT_SPECIFIED``
  Not specified

``NVMF_TREQ_REQUIRED``
  Required

``NVMF_TREQ_NOT_REQUIRED``
  Not Required

``NVMF_TREQ_DISABLE_SQFLOW``
  SQ flow control disable supported




.. c:type:: enum 

   RDMA QP Service Type codes for Discovery Log Page entry TSAS RDMA_QPTYPE field

**Constants**

``NVMF_RDMA_QPTYPE_CONNECTED``
  Reliable Connected

``NVMF_RDMA_QPTYPE_DATAGRAM``
  Reliable Datagram




.. c:type:: enum 

   RDMA Provider Type codes for Discovery Log Page entry TSAS RDMA_PRTYPE field

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




.. c:type:: enum 

   RDMA Connection Management Service Type codes for Discovery Log Page entry TSAS RDMA_CMS field

**Constants**

``NVMF_RDMA_CMS_RDMA_CM``
  Sockets based endpoint addressing




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
    __u8 rsvd14[1006];
    struct nvmf_disc_log_entry entries[];
  };

**Members**





.. c:type:: struct nvmf_connect_data


**Definition**

::

  struct nvmf_connect_data {
    __u8 hostid[16];
    __le16 cntlid;
    char rsvd4[238];
    char subsysnqn[NVME_NQN_LENGTH];
    char hostnqn[NVME_NQN_LENGTH];
    char rsvd5[256];
  };

**Members**

``cntlid``
  **subsysnqn**
  **hostnqn**





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

``portt``
  **mmctptus**;

``{unnamed_union}``
  anonymous





.. c:type:: struct nvme_mi_read_ctrl_info

    **portid**; **prii**; **pri**; **vid**; **did**; **ssvid**; **ssid**;

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

    **type**; **opc**;

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

    **nmravn**; **ff**; **i18vpwr**; **m18vpwr**; **i33vpwr**; **m33vpwr**; **m33vapsr**; **i5vapsr**; **m5vapsr**; **i12vapsr**; **m12vapsr**; **mtl**; **tnvmcap**[16];

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





.. c:type:: enum nvme_status_field

   Defines all parts of the nvme status field: status code, status code type, and additional flags.

**Constants**

``NVME_SCT_GENERIC``
  Generic errors applicable to multiple opcodes

``NVME_SCT_CMD_SPECIFIC``
  Errors associated to a specific opcode

``NVME_SCT_MEDIA``
  Errors associated with media and data integrity

``NVME_SCT_PATH``
  Errors associated with the paths connection

``NVME_SCT_VS``
  Vendor specific errors

``NVME_SCT_MASK``
  Mask to get the value of the Status Code Type

``NVME_SC_MASK``
  Mask to get the value of the status code.

``NVME_SC_SUCCESS``
  Successful Completion: The command
  completed without error.

``NVME_SC_INVALID_OPCODE``
  Invalid Command Opcode: A reserved coded
  value or an unsupported value in the
  command opcode field.

``NVME_SC_INVALID_FIELD``
  Invalid Field in Command: A reserved
  coded value or an unsupported value in a
  defined field.

``NVME_SC_CMDID_CONFLICT``
  Command ID Conflict: The command
  identifier is already in use.

``NVME_SC_DATA_XFER_ERROR``
  Data Transfer Error: Transferring the
  data or metadata associated with a
  command experienced an error.

``NVME_SC_POWER_LOSS``
  Commands Aborted due to Power Loss
  Notification: Indicates that the command
  was aborted due to a power loss
  notification.

``NVME_SC_INTERNAL``
  Internal Error: The command was not
  completed successfully due to an internal error.

``NVME_SC_ABORT_REQ``
  Command Abort Requested: The command was
  aborted due to an Abort command being
  received that specified the Submission
  Queue Identifier and Command Identifier
  of this command.

``NVME_SC_ABORT_QUEUE``
  Command Aborted due to SQ Deletion: The
  command was aborted due to a Delete I/O
  Submission Queue request received for the
  Submission Queue to which the command was
  submitted.

``NVME_SC_FUSED_FAIL``
  Command Aborted due to Failed Fused Command:
  The command was aborted due to the other
  command in a fused operation failing.

``NVME_SC_FUSED_MISSING``
  Aborted due to Missing Fused Command: The
  fused command was aborted due to the
  adjacent submission queue entry not
  containing a fused command that is the
  other command.

``NVME_SC_INVALID_NS``
  Invalid Namespace or Format: The
  namespace or the format of that namespace
  is invalid.

``NVME_SC_CMD_SEQ_ERROR``
  Command Sequence Error: The command was
  aborted due to a protocol violation in a
  multi-command sequence.

``NVME_SC_SGL_INVALID_LAST``
  Invalid SGL Segment Descriptor: The
  command includes an invalid SGL Last
  Segment or SGL Segment descriptor.

``NVME_SC_SGL_INVALID_COUNT``
  Invalid Number of SGL Descriptors: There
  is an SGL Last Segment descriptor or an
  SGL Segment descriptor in a location
  other than the last descriptor of a
  segment based on the length indicated.

``NVME_SC_SGL_INVALID_DATA``
  Data SGL Length Invalid: This may occur
  if the length of a Data SGL is too short.
  This may occur if the length of a Data
  SGL is too long and the controller does
  not support SGL transfers longer than the
  amount of data to be transferred as
  indicated in the SGL Support field of the
  Identify Controller data structure.

``NVME_SC_SGL_INVALID_METADATA``
  Metadata SGL Length Invalid: This may
  occur if the length of a Metadata SGL is
  too short. This may occur if the length
  of a Metadata SGL is too long and the
  controller does not support SGL transfers
  longer than the amount of data to be
  transferred as indicated in the SGL
  Support field of the Identify Controller
  data structure.

``NVME_SC_SGL_INVALID_TYPE``
  SGL Descriptor Type Invalid: The type of
  an SGL Descriptor is a type that is not
  supported by the controller.

``NVME_SC_CMB_INVALID_USE``
  Invalid Use of Controller Memory Buffer:
  The attempted use of the Controller
  Memory Buffer is not supported by the
  controller.

``NVME_SC_PRP_INVALID_OFFSET``
  PRP Offset Invalid: The Offset field for
  a PRP entry is invalid.

``NVME_SC_AWU_EXCEEDED``
  Atomic Write Unit Exceeded: The length
  specified exceeds the atomic write unit size.

``NVME_SC_OP_DENIED``
  Operation Denied: The command was denied
  due to lack of access rights. Refer to
  the appropriate security specification.

``NVME_SC_SGL_INVALID_OFFSET``
  SGL Offset Invalid: The offset specified
  in a descriptor is invalid. This may
  occur when using capsules for data
  transfers in NVMe over Fabrics
  implementations and an invalid offset in
  the capsule is specified.

``NVME_SC_HOSTID_FORMAT``
  Host Identifier Inconsistent Format: The
  NVM subsystem detected the simultaneous
  use of 64- bit and 128-bit Host
  Identifier values on different
  controllers.

``NVME_SC_KAT_EXPIRED``
  Keep Alive Timer Expired: The Keep Alive
  Timer expired.

``NVME_SC_KAT_INVALID``
  Keep Alive Timeout Invalid: The Keep
  Alive Timeout value specified is invalid.

``NVME_SC_CMD_ABORTED_PREMEPT``
  Command Aborted due to Preempt and Abort:
  The command was aborted due to a
  Reservation Acquire command.

``NVME_SC_SANITIZE_FAILED``
  Sanitize Failed: The most recent sanitize
  operation failed and no recovery action
  has been successfully completed.

``NVME_SC_SANITIZE_IN_PROGRESS``
  Sanitize In Progress: The requested
  function (e.g., command) is prohibited
  while a sanitize operation is in
  progress.

``NVME_SC_SGL_INVALID_GRANULARITY``
  SGL Data Block Granularity Invalid: The
  Address alignment or Length granularity
  for an SGL Data Block descriptor is
  invalid.

``NVME_SC_CMD_IN_CMBQ_NOT_SUPP``
  Command Not Supported for Queue in CMB:
  The implementation does not support
  submission of the command to a Submission
  Queue in the Controller Memory Buffer or
  command completion to a Completion Queue
  in the Controller Memory Buffer.

``NVME_SC_NS_WRITE_PROTECTED``
  Namespace is Write Protected: The command
  is prohibited while the namespace is
  write protected as a result of a change
  in the namespace write protection state
  as defined by the Namespace Write
  Protection State Machine.

``NVME_SC_CMD_INTERRUPTED``
  Command Interrupted: Command processing
  was interrupted and the controller is
  unable to successfully complete the
  command. The host should retry the
  command.

``NVME_SC_TRAN_TPORT_ERROR``
  Transient Transport Error: A transient
  transport error was detected. If the
  command is retried on the same
  controller, the command is likely to
  succeed. A command that fails with a
  transient transport error four or more
  times should be treated as a persistent
  transport error that is not likely to
  succeed if retried on the same
  controller.

``NVME_SC_LBA_RANGE``
  LBA Out of Range: The command references
  an LBA that exceeds the size of the namespace.

``NVME_SC_CAP_EXCEEDED``
  Capacity Exceeded: Execution of the
  command has caused the capacity of the
  namespace to be exceeded.

``NVME_SC_NS_NOT_READY``
  Namespace Not Ready: The namespace is not
  ready to be accessed as a result of a
  condition other than a condition that is
  reported as an Asymmetric Namespace
  Access condition.

``NVME_SC_RESERVATION_CONFLICT``
  Reservation Conflict: The command was
  aborted due to a conflict with a
  reservation held on the accessed
  namespace.

``NVME_SC_FORMAT_IN_PROGRESS``
  Format In Progress: A Format NVM command
  is in progress on the namespace.

``NVME_SC_CQ_INVALID``
  Completion Queue Invalid: The Completion
  Queue identifier specified in the command
  does not exist.

``NVME_SC_QID_INVALID``
  Invalid Queue Identifier: The creation of
  the I/O Completion Queue failed due to an
  invalid queue identifier specified as
  part of the command. An invalid queue
  identifier is one that is currently in
  use or one that is outside the range
  supported by the controller.

``NVME_SC_QUEUE_SIZE``
  Invalid Queue Size: The host attempted to
  create an I/O Completion Queue with an
  invalid number of entries.

``NVME_SC_ABORT_LIMIT``
  Abort Command Limit Exceeded: The number
  of concurrently outstanding Abort commands has exceeded the limit indicated
                                     in the Identify Controller data
                                     structure.

``NVME_SC_ABORT_MISSING``
  Abort Command is missing: The abort
  command is missing.

``NVME_SC_ASYNC_LIMIT``
  Asynchronous Event Request Limit
  Exceeded: The number of concurrently
  outstanding Asynchronous Event Request
  commands has been exceeded.

``NVME_SC_FIRMWARE_SLOT``
  Invalid Firmware Slot: The firmware slot
  indicated is invalid or read only. This
  error is indicated if the firmware slot
  exceeds the number supported.

``NVME_SC_FIRMWARE_IMAGE``
  Invalid Firmware Image: The firmware
  image specified for activation is invalid
  and not loaded by the controller.

``NVME_SC_INVALID_VECTOR``
  Invalid Interrupt Vector: The creation of
  the I/O Completion Queue failed due to an
  invalid interrupt vector specified as
  part of the command.

``NVME_SC_INVALID_LOG_PAGE``
  Invalid Log Page: The log page indicated
  is invalid. This error condition is also
  returned if a reserved log page is
  requested.

``NVME_SC_INVALID_FORMAT``
  Invalid Format: The LBA Format specified
  is not supported.

``NVME_SC_FW_NEEDS_CONV_RESET``
  Firmware Activation Requires Conventional Reset:
  The firmware commit was successful,
  however, activation of the firmware image
  requires a conventional reset.

``NVME_SC_INVALID_QUEUE``
  Invalid Queue Deletion: Invalid I/O
  Completion Queue specified to delete.

``NVME_SC_FEATURE_NOT_SAVEABLE``
  Feature Identifier Not Saveable: The
  Feature Identifier specified does not
  support a saveable value.

``NVME_SC_FEATURE_NOT_CHANGEABLE``
  Feature Not Changeable: The Feature
  Identifier is not able to be changed.

``NVME_SC_FEATURE_NOT_PER_NS``
  Feature Not Namespace Specific: The
  Feature Identifier specified is not
  namespace specific. The Feature
  Identifier settings apply across all
  namespaces.

``NVME_SC_FW_NEEDS_SUBSYS_RESET``
  Firmware Activation Requires NVM
  Subsystem Reset: The firmware commit was
  successful, however, activation of the
  firmware image requires an NVM Subsystem.

``NVME_SC_FW_NEEDS_RESET``
  Firmware Activation Requires Controller
  Level Reset: The firmware commit was
  successful; however, the image specified
  does not support being activated without
  a reset.

``NVME_SC_FW_NEEDS_MAX_TIME``
  Firmware Activation Requires Maximum Time
  Violation: The image specified if
  activated immediately would exceed the
  Maximum Time for Firmware Activation
  (MTFA) value reported in Identify
  Controller.

``NVME_SC_FW_ACTIVATE_PROHIBITED``
  Firmware Activation Prohibited: The image
  specified is being prohibited from
  activation by the controller for vendor
  specific reasons.

``NVME_SC_OVERLAPPING_RANGE``
  Overlapping Range: The downloaded
  firmware image has overlapping ranges.

``NVME_SC_NS_INSUFFICIENT_CAP``
  Namespace Insufficient Capacity: Creating
  the namespace requires more free space
  than is currently available.

``NVME_SC_NS_ID_UNAVAILABLE``
  Namespace Identifier Unavailable: The
  number of namespaces supported has been
  exceeded.

``NVME_SC_NS_ALREADY_ATTACHED``
  Namespace Already Attached: The
  controller is already attached to the
  namespace specified.

``NVME_SC_NS_IS_PRIVATE``
  Namespace Is Private: The namespace is
  private and is already attached to one
  controller.

``NVME_SC_NS_NOT_ATTACHED``
  Namespace Not Attached: The request to
  detach the controller could not be
  completed because the controller is not
  attached to the namespace.

``NVME_SC_THIN_PROV_NOT_SUPP``
  Thin Provisioning Not Supported: Thin
  provisioning is not supported by the
  controller.

``NVME_SC_CTRL_LIST_INVALID``
  Controller List Invalid: The controller
  list provided contains invalid controller
  ids.

``NVME_SC_SELF_TEST_IN_PROGRESS``
  Device Self-test In Progress:

``NVME_SC_BP_WRITE_PROHIBITED``
  Boot Partition Write Prohibited: The
  command is trying to modify a locked Boot
  Partition.

``NVME_SC_INVALID_CTRL_ID``
  Invalid Controller Identifier:

``NVME_SC_INVALID_SEC_CTRL_STATE``
  Invalid Secondary Controller State

``NVME_SC_INVALID_CTRL_RESOURCES``
  Invalid Number of Controller Resources

``NVME_SC_INVALID_RESOURCE_ID``
  Invalid Resource Identifier

``NVME_SC_PMR_SAN_PROHIBITED``
  Sanitize Prohibited While Persistent
  Memory Region is Enabled

``NVME_SC_ANA_GROUP_ID_INVALID``
  ANA Group Identifier Invalid

``NVME_SC_ANA_ATTACH_FAILED``
  ANA Attach Failed

``NVME_SC_BAD_ATTRIBUTES``
  Conflicting Dataset Management Attributes

``NVME_SC_INVALID_PI``
  Invalid Protection Information

``NVME_SC_READ_ONLY``
  Attempted Write to Read Only Range

``NVME_SC_CONNECT_FORMAT``
  Incompatible Format: The NVM subsystem
  does not support the record format
  specified by the host.

``NVME_SC_CONNECT_CTRL_BUSY``
  Controller Busy: The controller is
  already associated with a host.

``NVME_SC_CONNECT_INVALID_PARAM``
  Connect Invalid Parameters: One or more
  of the command parameters.

``NVME_SC_CONNECT_RESTART_DISC``
  Connect Restart Discovery: The NVM
  subsystem requested is not available.

``NVME_SC_CONNECT_INVALID_HOST``
  Connect Invalid Host: The host is either
  not allowed to establish an association
  to any controller in the NVM subsystem or
  the host is not allowed to establish an
  association to the specified controller

``NVME_SC_DISCONNECT_INVALID_QTYPE``
  Invalid Queue Type: The command was sent
  on the wrong queue type.

``NVME_SC_DISCOVERY_RESTART``
  Discover Restart: The snapshot of the
  records is now invalid or out of date.

``NVME_SC_AUTH_REQUIRED``
  Authentication Required: NVMe in-band
  authentication is required and the queue
  has not yet been authenticated.

``NVME_SC_WRITE_FAULT``
  Write Fault: The write data could not be
  committed to the media.

``NVME_SC_READ_ERROR``
  Unrecovered Read Error: The read data
  could not be recovered from the media.

``NVME_SC_GUARD_CHECK``
  End-to-end Guard Check Error: The command
  was aborted due to an end-to-end guard
  check failure.

``NVME_SC_APPTAG_CHECK``
  End-to-end Application Tag Check Error:
  The command was aborted due to an
  end-to-end application tag check failure.

``NVME_SC_REFTAG_CHECK``
  End-to-end Reference Tag Check Error: The
  command was aborted due to an end-to-end
  reference tag check failure.

``NVME_SC_COMPARE_FAILED``
  Compare Failure: The command failed due
  to a miscompare during a Compare command.

``NVME_SC_ACCESS_DENIED``
  Access Denied: Access to the namespace
  and/or LBA range is denied due to lack of
  access rights.

``NVME_SC_UNWRITTEN_BLOCK``
  Deallocated or Unwritten Logical Block:
  The command failed due to an attempt to
  read from or verify an LBA range
  containing a deallocated or unwritten
  logical block.

``NVME_SC_ANA_INTERNAL_PATH_ERROR``
  Internal Path Error: The command was not
  completed as the result of a controller
  internal error that is specific to the
  controller processing the command.

``NVME_SC_ANA_PERSISTENT_LOSS``
  Asymmetric Access Persistent Loss: The
  requested function (e.g., command) is not
  able to be performed as a result of the
  relationship between the controller and
  the namespace being in the ANA Persistent
  Loss state.

``NVME_SC_ANA_INACCESSIBLE``
  Asymmetric Access Inaccessible: The
  requested function (e.g., command) is not
  able to be performed as a result of the
  relationship between the controller and
  the namespace being in the ANA
  Inaccessible state.

``NVME_SC_ANA_TRANSITION``
  Asymmetric Access Transition: The
  requested function (e.g., command) is not
  able to be performed as a result of the
  relationship between the controller and
  the namespace transitioning between
  Asymmetric Namespace Access states.

``NVME_SC_CTRL_PATH_ERROR``
  Controller Pathing Error: A pathing error
  was detected by the controller.

``NVME_SC_HOST_PATH_ERROR``
  Host Pathing Error: A pathing error was
  detected by the host.

``NVME_SC_CMD_ABORTED_BY_HOST``
  Command Aborted By Host: The command was
  aborted as a result of host action.

``NVME_SC_CRD``
  Mask to get value of Command Retry Delay
  index

``NVME_SC_MORE``
  More bit. If set, more status information
  for this command as part of the Error
  Information log that may be retrieved with
  the Get Log Page command.

``NVME_SC_DNR``
  Do Not Retry bit. If set, if the same
  command is re-submitted to any controller
  in the NVM subsystem, then that
  re-submitted command is expected to fail.


.. c:function:: __u16 nvme_status_code_type (__u16 status_field)

   Returns the NVMe Status Code Type

**Parameters**

``__u16 status_field``
  The NVMe Completion Queue Entry's Status Field

**Description**

See :c:type:`enum nvme_status_field <nvme_status_field>`


.. c:function:: __u16 nvme_status_code (__u16 status_field)

   Returns the NVMe Status Code

**Parameters**

``__u16 status_field``
  The NVMe Completion Queue Entry's Status Field

**Description**

See :c:type:`enum nvme_status_field <nvme_status_field>`


.. c:function:: __u8 nvme_status_to_errno (int status, bool fabrics)

   Converts nvme return status to errno

**Parameters**

``int status``
  Return status from an nvme passthrough commmand

``bool fabrics``
  Set to true if :c:type:`status` is to a fabrics target.

**Return**

An errno representing the nvme status if it is an nvme status field,
or unchanged status is < 0 since errno is already set.


.. c:function:: int nvme_fw_download_seq (int fd, __u32 size, __u32 xfer, __u32 offset, void * buf)


**Parameters**

``int fd``
  File descriptor of nvme device

``__u32 size``
  Total size of the firmware image to transfer

``__u32 xfer``
  Maximum size to send with each partial transfer

``__u32 offset``
  Starting offset to send with this firmware downlaod

``void * buf``
  Address of buffer containing all or part of the firmware image.

**Return**

The nvme command status if a response was received (see
:c:type:`enum nvme_status_field <nvme_status_field>`) or -1 with errno set otherwise.


.. c:function:: int nvme_get_ctrl_telemetry (int fd, bool rae, struct nvme_telemetry_log ** log)


**Parameters**

``int fd``
  File descriptor of nvme device

``bool rae``
  Retain asynchronous events

``struct nvme_telemetry_log ** log``
  On success, set to the value of the allocated and retreived log.

**Description**

The total size allocated can be calculated as:
  (:c:type:`struct nvme_telemetry_log <nvme_telemetry_log>`.dalb3 + 1) * ``NVME_LOG_TELEM_BLOCK_SIZE``.

**Return**

The nvme command status if a response was received (see
:c:type:`enum nvme_status_field <nvme_status_field>`) or -1 with errno set otherwise.


.. c:function:: int nvme_get_host_telemetry (int fd, struct nvme_telemetry_log ** log)


**Parameters**

``int fd``
  File descriptor of nvme device

``struct nvme_telemetry_log ** log``
  On success, set to the value of the allocated and retreived log.

**Description**

The total size allocated can be calculated as:
  (:c:type:`struct nvme_telemetry_log <nvme_telemetry_log>`.dalb3 + 1) * ``NVME_LOG_TELEM_BLOCK_SIZE``.

**Return**

The nvme command status if a response was received (see
:c:type:`enum nvme_status_field <nvme_status_field>`) or -1 with errno set otherwise.


.. c:function:: int nvme_get_new_host_telemetry (int fd, struct nvme_telemetry_log ** log)


**Parameters**

``int fd``
  File descriptor of nvme device

``struct nvme_telemetry_log ** log``
  On success, set to the value of the allocated and retreived log.

**Description**

The total size allocated can be calculated as:
  (:c:type:`struct nvme_telemetry_log <nvme_telemetry_log>`.dalb3 + 1) * ``NVME_LOG_TELEM_BLOCK_SIZE``.

**Return**

The nvme command status if a response was received (see
:c:type:`enum nvme_status_field <nvme_status_field>`) or -1 with errno set otherwise.


.. c:function:: void nvme_init_id_ns (struct nvme_id_ns * ns, __u64 nsze, __u64 ncap, __u8 flbas, __u8 dps, __u8 nmic, __u32 anagrpid, __u16 nvmsetid)

   Initialize an Identify Namepsace structure for creation.

**Parameters**

``struct nvme_id_ns * ns``
  Address of the Identify Namespace structure to initialize

``__u64 nsze``
  Namespace size

``__u64 ncap``
  namespace capacity

``__u8 flbas``
  formatted logical block size settings

``__u8 dps``
  Data protection settings

``__u8 nmic``
  Namespace sharing capabilities

``__u32 anagrpid``
  ANA group identifier

``__u16 nvmsetid``
  NVM Set identifer

**Description**

This is intended to be used with a namespace management "create", see
:c:type:`nvme_ns_mgmt_create`().


.. c:function:: void nvme_init_ctrl_list (struct nvme_ctrl_list * cntlist, __u16 num_ctrls, __u16 * ctrlist)

   Initialize an nvme_ctrl_list structure from an array.

**Parameters**

``struct nvme_ctrl_list * cntlist``
  The controller list structure to initialize

``__u16 num_ctrls``
  The number of controllers in the array, :c:type:`ctrlist`.

``__u16 * ctrlist``
  An array of controller identifiers in CPU native endian.

**Description**

This is intended to be used with any command that takes a controller list
argument. See :c:type:`nvme_ns_attach_ctrls`() and :c:type:`nvme_ns_detach`().


.. c:function:: void nvme_init_dsm_range (struct nvme_dsm_range * dsm, __u32 * ctx_attrs, __u32 * llbas, __u64 * slbas, __u16 nr_ranges)

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

Each array must be the same size of size 'nr_ranges'. This is intended to be
used with constructing a payload for :c:type:`nvme_dsm`().

**Return**

The nvme command status if a response was received or -errno
otherwise.


.. c:function:: int __nvme_get_log_page (int fd, __u32 nsid, __u8 log_id, bool rae, __u32 xfer_len, __u32 data_len, void * data)


**Parameters**

``int fd``
  File descriptor of nvme device

``__u32 nsid``
  Namespace Identifier, if applicable.

``__u8 log_id``
  Log Identifier, see :c:type:`enum nvme_cmd_get_log_lid <nvme_cmd_get_log_lid>`.

``bool rae``
  Retain asynchronous events

``__u32 xfer_len``
  Max log transfer size per request to split the total.

``__u32 data_len``
  Total length of the log to transfer.

``void * data``
  User address of at least :c:type:`data_len` to store the log.

**Return**

The nvme command status if a response was received (see
:c:type:`enum nvme_status_field <nvme_status_field>`) or -1 with errno set otherwise.


.. c:function:: int nvme_get_log_page (int fd, __u32 nsid, __u8 log_id, bool rae, __u32 data_len, void * data)


**Parameters**

``int fd``
  File descriptor of nvme device

``__u32 nsid``
  Namespace Identifier, if applicable.

``__u8 log_id``
  Log Identifier, see :c:type:`enum nvme_cmd_get_log_lid <nvme_cmd_get_log_lid>`.

``bool rae``
  Retain asynchronous events

``__u32 data_len``
  Total length of the log to transfer.

``void * data``
  User address of at least :c:type:`data_len` to store the log.

**Description**

Calls __nvme_get_log_page() with a default 4k transfer length, as that is
guarnateed by the protocol to be a safe transfer size.

**Return**

The nvme command status if a response was received (see
:c:type:`enum nvme_status_field <nvme_status_field>`) or -1 with errno set otherwise.


.. c:function:: int nvme_get_ana_log_len (int fd, size_t * analen)

   Retreive size of the current ANA log

**Parameters**

``int fd``
  File descriptor of nvme device

``size_t * analen``
  Pointer to where the length will be set on success

**Return**

The nvme command status if a response was received (see
:c:type:`enum nvme_status_field <nvme_status_field>`) or -1 with errno set otherwise.


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

The nvme command status if a response was received (see
:c:type:`enum nvme_status_field <nvme_status_field>`) or -1 with errno set otherwise.


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

The nvme command status if a response was received (see
:c:type:`enum nvme_status_field <nvme_status_field>`) or -1 with errno set otherwise.


.. c:function:: int nvme_get_feature_length (int fid, __u32 cdw11, __u32 * len)

   Retreive the command payload length for a specific feature identifier

**Parameters**

``int fid``
  Feature identifier, see :c:type:`enum nvme_features_id <nvme_features_id>`.

``__u32 cdw11``
  The cdw11 value may affect the transfer (only known fid is
  ``NVME_FEAT_FID_HOST_ID``)

``__u32 * len``
  On success, set to this features payload length in bytes.

**Return**

0 on success, -1 with errno set to EINVAL if the function did not
recognize :c:type:`fid`.


.. c:function:: int nvme_get_directive_receive_length (enum nvme_directive_dtype dtype, enum nvme_directive_receive_doper doper, __u32 * len)


**Parameters**

``enum nvme_directive_dtype dtype``
  Directive type, see :c:type:`enum nvme_directive_dtype <nvme_directive_dtype>`

``enum nvme_directive_receive_doper doper``
  Directive receive operation, see :c:type:`enum nvme_directive_receive_doper <nvme_directive_receive_doper>`

``__u32 * len``
  On success, set to this directives payload length in bytes.

**Return**

0 on success, -1 with errno set to EINVAL if the function did not
recognize :c:type:`dtype` or :c:type:`doper`.


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




.. c:type:: struct nvme_fabrics_config

   Defines all linux nvme fabrics initiator options

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
  };

**Members**

``transport``
  The fabric transport to use, either loop, fc, tcp, or rdma

``traddr``
  Transport Address for the target, format specific to transport type

``trsvcid``
  Transport Service Identifier, specific to the transport type

``nqn``
  Target NVMe Qualified Name

``hostnqn``
  Host NVMe Qualified Name

``host_traddr``
  Host Transport Address

``hostid``
  Host Identifier

``queue_size``
  Number of IO queue entries

``nr_io_queues``
  Number of controller IO queues to establish

``reconnect_delay``
  Time between two consecutive reconnect attempts.

``ctrl_loss_tmo``
  Override the default controller reconnect attempt timeout in seconds

``keep_alive_tmo``
  Override the default keep-alive-timeout to this value in seconds

``nr_write_queues``
  Number of queues to use for exclusively for writing

``nr_poll_queues``
  Number of queues to reserve for polling completions

``tos``
  Type of service

``duplicate_connect``
  Allow multiple connections to the same target

``disable_sqflow``
  Disable controller sq flow control

``hdr_digest``
  Generate/verify header digest (TCP)

``data_digest``
  Generate/verify data digest (TCP)



.. c:function:: int nvmf_add_ctrl_opts (struct nvme_fabrics_config * cfg)


**Parameters**

``struct nvme_fabrics_config * cfg``


.. c:function:: nvme_ctrl_t nvmf_add_ctrl (struct nvme_fabrics_config * cfg)


**Parameters**

``struct nvme_fabrics_config * cfg``


.. c:function:: int nvmf_get_discovery_log (nvme_ctrl_t c, struct nvmf_discovery_log ** logp, int max_retries)


**Parameters**

``nvme_ctrl_t c``
  *undescribed*

``struct nvmf_discovery_log ** logp``
  *undescribed*

``int max_retries``


.. c:function:: char * nvmf_hostnqn_generate ()

   Generate a machine specific host nqn

**Parameters**

**Return**

An nvm namespace qualifieid name string based on the machine
identifier, or NULL if not successful.


.. c:function:: char * nvmf_hostnqn_from_file ()

   Reads the host nvm qualified name from the config default location in /etc/nvme/

**Parameters**

**Return**

The host nqn, or NULL if unsuccessful. If found, the caller
is responsible to free the string.


.. c:function:: char * nvmf_hostid_from_file ()

   Reads the host identifier from the config default location in /etc/nvme/.

**Parameters**

**Return**

The host identifier, or NULL if unsuccessful. If found, the caller
        is responsible to free the string.


.. c:function:: nvme_ctrl_t nvmf_connect_disc_entry (struct nvmf_disc_log_entry * e, const struct nvme_fabrics_config * defcfg, bool * discover)


**Parameters**

``struct nvmf_disc_log_entry * e``
  *undescribed*

``const struct nvme_fabrics_config * defcfg``
  *undescribed*

``bool * discover``

**Return**

An 


