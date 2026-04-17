.. c:macro:: NVME_MI_MSGTYPE_NVME

``NVME_MI_MSGTYPE_NVME ()``

   MCTP message type for NVMe-MI messages.

**Parameters**

**Description**


This is defined by MCTP, but is referenced as part of the NVMe-MI message
spec. This is the MCTP NVMe message type (0x4), with the message-integrity
bit (0x80) set.




.. c:enum:: nvme_mi_message_type

   NVMe-MI message type field.

**Constants**

``NVME_MI_MT_CONTROL``
  NVME-MI Control Primitive

``NVME_MI_MT_MI``
  NVMe-MI command

``NVME_MI_MT_ADMIN``
  NVMe Admin command

``NVME_MI_MT_PCIE``
  PCIe command

``NVME_MI_MT_AE``
  Asynchronous Event

**Description**

Used as byte 1 of both request and response messages (NMIMT bits of NMP
byte). Not to be confused with the MCTP message type in byte 0.




.. c:enum:: nvme_mi_ror

   Request or response field.

**Constants**

``NVME_MI_ROR_REQ``
  request message

``NVME_MI_ROR_RSP``
  response message




.. c:enum:: nvme_mi_resp_status

   values for the response status field

**Constants**

``NVME_MI_RESP_SUCCESS``
  success

``NVME_MI_RESP_MPR``
  More Processing Required

``NVME_MI_RESP_INTERNAL_ERR``
  Internal Error

``NVME_MI_RESP_INVALID_OPCODE``
  Invalid command opcode

``NVME_MI_RESP_INVALID_PARAM``
  Invalid command parameter

``NVME_MI_RESP_INVALID_CMD_SIZE``
  Invalid command size

``NVME_MI_RESP_INVALID_INPUT_SIZE``
  Invalid command input data size

``NVME_MI_RESP_ACCESS_DENIED``
  Access Denied

``NVME_MI_RESP_VPD_UPDATES_EXCEEDED``
  More VPD updates than allowed

``NVME_MI_RESP_PCIE_INACCESSIBLE``
  PCIe functionality currently unavailable

``NVME_MI_RESP_MEB_SANITIZED``
  MEB has been cleared due to sanitize

``NVME_MI_RESP_ENC_SERV_FAILURE``
  Enclosure services process failed

``NVME_MI_RESP_ENC_SERV_XFER_FAILURE``
  Transfer with enclosure services failed

``NVME_MI_RESP_ENC_FAILURE``
  Unreoverable enclosure failure

``NVME_MI_RESP_ENC_XFER_REFUSED``
  Enclosure services transfer refused

``NVME_MI_RESP_ENC_FUNC_UNSUP``
  Unsupported enclosure services function

``NVME_MI_RESP_ENC_SERV_UNAVAIL``
  Enclosure services unavailable

``NVME_MI_RESP_ENC_DEGRADED``
  Noncritical failure detected by enc. services

``NVME_MI_RESP_SANITIZE_IN_PROGRESS``
  Command prohibited during sanitize




.. c:struct:: nvme_mi_msg_hdr

   General MI message header.

**Definition**

::

  struct nvme_mi_msg_hdr {
    __u8 type;
    __u8 nmp;
    __u8 meb;
    __u8 rsvd0;
  };

**Members**

``type``
  MCTP message type, will always be NVME_MI_MSGTYPE_NVME

``nmp``
  NVMe-MI message parameters (including MI message type)

``meb``
  Management Endpoint Buffer flag; unused for libnvme-mi implementation

``rsvd0``
  currently reserved


**Description**

Wire format shared by both request and response messages, per NVMe-MI
section 3.1. This is used for all message types, MI and Admin.




.. c:struct:: nvme_mi_msg_resp

   Generic response type.

**Definition**

::

  struct nvme_mi_msg_resp {
    struct nvme_mi_msg_hdr hdr;
    __u8 status;
    __u8 rsvd0[3];
  };

**Members**

``hdr``
  the general request/response message header

``status``
  response status value (see :c:type:`enum nvme_mi_resp_status <nvme_mi_resp_status>`)

``rsvd0``
  reserved data, may be defined by specific response


**Description**

Every response will start with one of these; command-specific responses
will define parts of the reserved data, and may add further fields.




.. c:enum:: nvme_mi_mi_opcode

   Operation code for supported NVMe-MI commands.

**Constants**

``nvme_mi_mi_opcode_mi_data_read``
  Read NVMe-MI Data Structure

``nvme_mi_mi_opcode_subsys_health_status_poll``
  Subsystem Health Status Poll

``nvme_mi_mi_opcode_configuration_set``
  MI Configuration Set

``nvme_mi_mi_opcode_configuration_get``
  MI Configuration Get




.. c:struct:: nvme_mi_mi_req_hdr

   MI request message header.

**Definition**

::

  struct nvme_mi_mi_req_hdr {
    struct nvme_mi_msg_hdr hdr;
    __u8 opcode;
    __u8 rsvd0[3];
    __le32 cdw0, cdw1;
  };

**Members**

``hdr``
  generic MI message header

``opcode``
  opcode (OPC) for the specific MI command

``rsvd0``
  reserved bytes

``cdw0``
  Management Request Doubleword 0 - command specific usage

``cdw1``
  Management Request Doubleword 1 - command specific usage


**Description**

Wire format for MI request message headers, defined in section 5 of NVMe-MI.




.. c:struct:: nvme_mi_mi_resp_hdr

   MI response message header.

**Definition**

::

  struct nvme_mi_mi_resp_hdr {
    struct nvme_mi_msg_hdr hdr;
    __u8 status;
    __u8 nmresp[3];
  };

**Members**

``hdr``
  generic MI message header

``status``
  generic response status from command; non-zero on failure.

``nmresp``
  NVMe Management Response: command-type-specific response data


**Description**

Wire format for MI response message header, defined in section 5 of NVMe-MI.




.. c:enum:: nvme_mi_dtyp

   Data Structure Type field.

**Constants**

``nvme_mi_dtyp_subsys_info``
  NVM Subsystem Information

``nvme_mi_dtyp_port_info``
  Port information

``nvme_mi_dtyp_ctrl_list``
  Controller List

``nvme_mi_dtyp_ctrl_info``
  Controller Information

``nvme_mi_dtyp_opt_cmd_support``
  Optionally Supported Command List

``nvme_mi_dtyp_meb_support``
  Management Endpoint Buffer Command Support List

**Description**

Data Structure Type field for Read NVMe-MI Data Structure command, used to
indicate the particular structure to query from the endpoint.




.. c:enum:: nvme_mi_config_id

   NVMe-MI Configuration identifier.

**Constants**

``NVME_MI_CONFIG_SMBUS_FREQ``
  Current SMBus/I2C frequency

``NVME_MI_CONFIG_HEALTH_STATUS_CHANGE``
  Health Status change - used to clear
  health status bits in CCS bits of
  status poll. Only for Set ops.

``NVME_MI_CONFIG_MCTP_MTU``
  MCTP maximum transmission unit size of port
  specified in dw 0

``NVME_MI_CONFIG_AE``
  Asynchronous Events configuration
  Configuration parameters for the MI Get/Set Configuration commands.

**Description**

See :c:type:`nvme_mi_mi_config_get`() and :c:type:`nvme_mi_config_set`().




.. c:enum:: nvme_mi_config_smbus_freq

   SMBus/I2C frequency values

**Constants**

``NVME_MI_CONFIG_SMBUS_FREQ_100kHz``
  100kHz

``NVME_MI_CONFIG_SMBUS_FREQ_400kHz``
  400kHz

``NVME_MI_CONFIG_SMBUS_FREQ_1MHz``
  1MHz

**Description**

Values used in the SMBus Frequency device configuration. See
:c:type:`nvme_mi_mi_config_get_smbus_freq`() and :c:type:`nvme_mi_mi_config_set_smbus_freq`().




.. c:struct:: nvme_mi_aem_supported_list_header

   Asynchronous Event Supported List Header.

**Definition**

::

  struct nvme_mi_aem_supported_list_header {
    __u8 numaes;
    __u8 aeslver;
    __le16 aest;
    __u8 aeslhl;
  };

**Members**

``numaes``
  Number of AE supported data structures that follow the header

``aeslver``
  AE Supported List Version

``aest``
  AE Supported list length (including this header)

``aeslhl``
  AE Supported list header length


**Description**

This header preceeds a number, (:c:type:`numaes`), of AE supported data structures




.. c:struct:: nvme_mi_aem_supported_item

   AE Supported List Item

**Definition**

::

  struct nvme_mi_aem_supported_item {
    __u8 aesl;
    __le16 aesi;
  };

**Members**

``aesl``
  AE supported list item length

``aesi``
  AE supported info


**Description**

Following this header should be hdr.numaes entries of
nvme_mi_aem_supported_item structures


.. c:function:: bool nvme_mi_aem_aesi_get_aese (__le16 aesi)

   return aese from aesi field

**Parameters**

``__le16 aesi``
  aesi field from **nvme_mi_aem_supported_item**

**Return**

A bool representing the aese value


.. c:function:: __u8 nvme_mi_aem_aesi_get_aesid (__le16 aesi)

   return aesid from aesi field

**Parameters**

``__le16 aesi``
  aesi field from **nvme_mi_aem_supported_item**

**Return**

aesid value


.. c:function:: void nvme_mi_aem_aesi_set_aesid (struct nvme_mi_aem_supported_item *item, __u8 aesid)

   set aesid in the aesi field

**Parameters**

``struct nvme_mi_aem_supported_item *item``
  Pointer to **nvme_mi_aem_supported_item** to update the aesi field

``__u8 aesid``
  aesid value to use


.. c:function:: void nvme_mi_aem_aesi_set_aee (struct nvme_mi_aem_supported_item *item, bool enabled)

   set aee in the aesi field

**Parameters**

``struct nvme_mi_aem_supported_item *item``
  Pointer to **nvme_mi_aem_supported_item** to update the aesi field

``bool enabled``
  aee value to use




.. c:struct:: nvme_mi_aem_supported_list

   AE Supported List received with GET CONFIG Asynchronous Event

**Definition**

::

  struct nvme_mi_aem_supported_list {
    struct nvme_mi_aem_supported_list_header hdr;
  };

**Members**

``hdr``
  AE supported list header


**Description**

Following this header should be hdr.numaes entries of
nvme_mi_aem_supported_item structures




.. c:struct:: nvme_mi_aem_enable_item

   AE Enabled item entry

**Definition**

::

  struct nvme_mi_aem_enable_item {
    __u8 aeel;
    __le16 aeei;
  };

**Members**

``aeel``
  AE Enable Length (length of this structure which is 3)

``aeei``
  AE Enable Info



.. c:function:: bool nvme_mi_aem_aeei_get_aee (__le16 aeei)

   return aee from aeei field

**Parameters**

``__le16 aeei``
  aeei field from **nvme_mi_aem_enable_item**

**Return**

aee value


.. c:function:: __u8 nvme_mi_aem_aeei_get_aeeid (__le16 aeei)

   return aeeid from aeei field

**Parameters**

``__le16 aeei``
  aeei field from **nvme_mi_aem_enable_item**

**Return**

aeeid value


.. c:function:: void nvme_mi_aem_aeei_set_aeeid (struct nvme_mi_aem_enable_item *item, __u8 aeeid)

   set aeeid in the aeei field

**Parameters**

``struct nvme_mi_aem_enable_item *item``
  Pointer to **nvme_mi_aem_enable_item** to update the aeei field

``__u8 aeeid``
  aeeid value to use


.. c:function:: void nvme_mi_aem_aeei_set_aee (struct nvme_mi_aem_enable_item *item, bool enabled)

   set aee in the aeei field

**Parameters**

``struct nvme_mi_aem_enable_item *item``
  Pointer to **nvme_mi_aem_enable_item** to update the aee field

``bool enabled``
  aee value to use




.. c:struct:: nvme_mi_aem_enable_list_header

   AE Enable list header

**Definition**

::

  struct nvme_mi_aem_enable_list_header {
    __u8 numaee;
    __u8 aeelver;
    __le16 aeetl;
    __u8 aeelhl;
  };

**Members**

``numaee``
  Number of AE enable items following the header

``aeelver``
  Version of the AE enable list (zero)

``aeetl``
  Total length of the AE enable list including header and items

``aeelhl``
  Header length of this header (5)





.. c:struct:: nvme_mi_aem_enable_list

   AE enable list sent with SET CONFIG Asyncronous Event

**Definition**

::

  struct nvme_mi_aem_enable_list {
    struct nvme_mi_aem_enable_list_header hdr;
  };

**Members**

``hdr``
  AE enable list header


**Description**

Following this header should be hdr.numaee entries of nvme_mi_aem_enable_item structures




.. c:struct:: nvme_mi_aem_occ_data

   AEM Message definition.

**Definition**

::

  struct nvme_mi_aem_occ_data {
    __u8 aelhlen;
    __u8 aeosil;
    __u8 aeovsil;
    struct {
      __u8 aeoi;
      __le32 aeocidi;
      __u8 aessi;
    } aeoui;
  };

**Members**

``aelhlen``
  AE Occurrence Header Length

``aeosil``
  AE Occurrence Specific Info Length

``aeovsil``
  AE Occurrence Vendor Specific Info Length

``aeoui``
  AE Occurrence Unique ID made up of other subfields


**Description**

A single entry of ae occurrence data that comes with an nvme_aem_msg.
Following this structure is variable length AEOSI (occurrence specific
info) and variable length AEVSI (vendor specific info).  The length of
AEOSI is specified by aeosil and the length of AEVSI is specified by
AEVSI.  Neither field is mandatory and shall be omitted if their length
parameter is set to zero.




.. c:struct:: nvme_mi_aem_occ_list_hdr

   AE occurrence list header

**Definition**

::

  struct nvme_mi_aem_occ_list_hdr {
    __u8 numaeo;
    __u8 aelver;
    __u8 aeolli[3];
    __u8 aeolhl;
    __u8 aemti;
  };

**Members**

``numaeo``
  Number of AE Occurrence Data Structures

``aelver``
  AE Occurrence List Version Number

``aeolli``
  AE Occurrence List Length Info (AEOLLI)

``aeolhl``
  AE Occurrence List Header Length (shall be set to 7)

``aemti``
  AEM Transmission Info


**Description**

The header for the occurrence list.  numaeo defines how many
nvme_mi_aem_occ_data structures (including variable payaloads) are included.
Following this header is each of the numaeo occurrence data structures.


.. c:function:: __u8 nvme_mi_aem_aemti_get_aemgn (__u8 aemti)

   return aemgn from aemti field

**Parameters**

``__u8 aemti``
  aemti field from **nvme_mi_aem_occ_list_hdr**

**Return**

aemgn value


.. c:function:: __u32 nvme_mi_aem_aeolli_get_aeoltl (__u8 *aeolli)

   return aeoltl from aeolli field

**Parameters**

``__u8 *aeolli``
  Pointer to 3 byte aeolli field from **nvme_mi_aem_occ_list_hdr**

**Return**

aeoltl value


.. c:function:: void nvme_mi_aem_aeolli_set_aeoltl (struct nvme_mi_aem_occ_list_hdr *hdr, __u32 aeoltl)

   set aeoltl in the aeolli field

**Parameters**

``struct nvme_mi_aem_occ_list_hdr *hdr``
  Pointer to **nvme_mi_aem_occ_list_hdr** to set the aeolli field

``__u32 aeoltl``
  aeoltl value to use




.. c:struct:: nvme_mi_aem_msg

   AEM Message definition.

**Definition**

::

  struct nvme_mi_aem_msg {
    struct nvme_mi_msg_hdr hdr;
    struct nvme_mi_aem_occ_list_hdr occ_list_hdr;
  };

**Members**

``hdr``
  the general response message header

``occ_list_hdr``
  ae occurrence list header.


**Description**

Every ae message will start with one of these.  The occ_list_hder wil define
information about how many ae occ data entries are included.  Each entry is
defined by the nvme_mi_aem_occ_data structure which will follow the
occ_list_hdr.  Each nvme_mi_aem_occ_data structure has a fixed length header
but a variable length payload ude to occurrence specific and vendor specific
info.  For this reason, do not index the nvme_mi_ae_occ data structures by
array or fixed offset.




.. c:struct:: nvme_mi_admin_req_hdr

   Admin command request header.

**Definition**

::

  struct nvme_mi_admin_req_hdr {
    struct nvme_mi_msg_hdr hdr;
    __u8 opcode;
    __u8 flags;
    __le16 ctrl_id;
    __le32 cdw1, cdw2, cdw3, cdw4, cdw5;
    __le32 doff;
    __le32 dlen;
    __le32 rsvd0, rsvd1;
    __le32 cdw10, cdw11, cdw12, cdw13, cdw14, cdw15;
  };

**Members**

``hdr``
  Generic MI message header

``opcode``
  Admin command opcode (using enum nvme_admin_opcode)

``flags``
  Command Flags, indicating dlen and doff validity; Only defined in
  NVMe-MI version 1.1, no fields defined in 1.2 (where the dlen/doff
  are always considered valid).

``ctrl_id``
  Controller ID target of command

``cdw1``
  Submission Queue Entry doubleword 1

``cdw2``
  Submission Queue Entry doubleword 2

``cdw3``
  Submission Queue Entry doubleword 3

``cdw4``
  Submission Queue Entry doubleword 4

``cdw5``
  Submission Queue Entry doubleword 5

``doff``
  Offset of data to return from command

``dlen``
  Length of sent/returned data

``rsvd0``
  Reserved

``rsvd1``
  Reserved

``cdw10``
  Submission Queue Entry doubleword 10

``cdw11``
  Submission Queue Entry doubleword 11

``cdw12``
  Submission Queue Entry doubleword 12

``cdw13``
  Submission Queue Entry doubleword 13

``cdw14``
  Submission Queue Entry doubleword 14

``cdw15``
  Submission Queue Entry doubleword 15


**Description**

Wire format for Admin command message headers, defined in section 6 of
NVMe-MI.




.. c:struct:: nvme_mi_admin_resp_hdr

   Admin command response header.

**Definition**

::

  struct nvme_mi_admin_resp_hdr {
    struct nvme_mi_msg_hdr hdr;
    __u8 status;
    __u8 rsvd0[3];
    __le32 cdw0, cdw1, cdw3;
  };

**Members**

``hdr``
  Generic MI message header

``status``
  Generic response code, non-zero on failure

``rsvd0``
  Reserved

``cdw0``
  Completion Queue Entry doubleword 0

``cdw1``
  Completion Queue Entry doubleword 1

``cdw3``
  Completion Queue Entry doubleword 3


**Description**

This is the generic response format with the three doublewords of completion
queue data, plus optional response data.




.. c:enum:: nvme_mi_control_opcode

   Operation code for Control Primitives.

**Constants**

``nvme_mi_control_opcode_pause``
  Suspend response transmission/timeout

``nvme_mi_control_opcode_resume``
  Resume from a paused condition

``nvme_mi_control_opcode_abort``
  Re-initialize a Command Slot to the Idle state

``nvme_mi_control_opcode_get_state``
  Get the state of a Command Slot

``nvme_mi_control_opcode_replay``
  Retransmit the Response Message




.. c:struct:: nvme_mi_control_req

   The Control Primitive request.

**Definition**

::

  struct nvme_mi_control_req {
    struct nvme_mi_msg_hdr hdr;
    __u8 opcode;
    __u8 tag;
    __le16 cpsp;
  };

**Members**

``hdr``
  Generic MI message header

``opcode``
  Control Primitive Opcodes (using :c:type:`enum nvme_mi_control_opcode <nvme_mi_control_opcode>`)

``tag``
  flag - Opaque value passed from request to response

``cpsp``
  Control Primitive Specific Parameter



