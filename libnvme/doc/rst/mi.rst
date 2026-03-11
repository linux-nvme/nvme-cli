.. _mi.h - NVMe Management Interface library (libnvme-mi) definitions.:

**mi.h - NVMe Management Interface library (libnvme-mi) definitions.**


These provide an abstraction for the MI messaging between controllers
and a host, typically over an MCTP-over-i2c link to a NVMe device, used
as part of the out-of-band management of a system.

We have a few data structures define here to reflect the topology
of a MI connection with an NVMe subsystem:

 - :c:type:`nvme_mi_ep_t`: an MI endpoint - our mechanism of communication with a
   NVMe subsystem. For MCTP, an endpoint will be the component that
   holds the MCTP address (EID), and receives our request message.

   endpoints are defined in the NVMe-MI spec, and are specific to the MI
   interface.

   Each endpoint will provide access to one or more of:

 - :c:type:`nvme_mi_ctrl_t`: a NVMe controller, as defined by the NVMe base spec.
   The controllers are responsible for processing any NVMe standard
   commands (eg, the Admin command set). An endpoint (:c:type:`nvme_mi_ep_t`)
   may provide access to multiple controllers - so each of the controller-
   type commands will require a :c:type:`nvme_mi_ctrl_t` to be specified, rather than
   an endpoint

A couple of conventions with the libnvme-mi API:

 - All types and functions have the nvme_mi prefix, to distinguish from
   the libnvme core.

 - We currently support either MI commands and Admin commands. The
   former adds a _mi prefix, the latter an _admin prefix. [This does
   result in the MI functions having a double _mi, like
   :c:type:`nvme_mi_mi_subsystem_health_status_poll`, which is apparently amusing
   for our German-speaking readers]

For return values: unless specified in the per-function documentation,
all functions:

 - return 0 on success

 - return -1, with errno set, for errors communicating with the MI device,
   either in request or response data

 - return >1 on MI status errors. This value is the 8-bit MI status
   value, represented by :c:type:`enum nvme_mi_resp_status <nvme_mi_resp_status>`. Note that the
   status values may be vendor-defined above 0xe0.

For the second case, we have a few conventions for errno values:

 - EPROTO: response data violated the MI protocol, and libnvme cannot
   validly interpret the response

 - EIO: Other I/O error communicating with device (eg., valid but
   unexpected response data)

 - EINVAL: invalid input arguments for a command

In line with the core NVMe API, the Admin command functions take an
`_args` structure to provide the command-specific parameters. However,
for the MI interface, the fd and timeout members of these _args structs
are ignored.

References to the specifications here will either to be the NVM Express
Management Interface ("NVMe-MI") or the NVM Express Base specification
("NVMe"). At the time of writing, the versions we're referencing here
are:
 - NVMe-MI 1.2b
 - NVMe 2.0b
with a couple of accommodations for older spec types, particularly NVMe-MI
1.1, where possible.

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



.. c:function:: const char * nvme_mi_status_to_string (int status)

   return a string representation of the MI status.

**Parameters**

``int status``
  MI response status

**Description**

Gives a string description of **status**, as per section 4.1.2 of the NVMe-MI
spec. The status value should be of type NVME_STATUS_MI, and extracted
from the return value using nvme_status_get_value().

Returned string is const, and should not be free()ed.

**Return**

A string representing the status value




.. c:type:: nvme_mi_ep_t

   MI Endpoint object.

**Description**


Represents our communication endpoint on the remote MI-capable device.
To be used for direct MI commands for the endpoint (through the
nvme_mi_mi_* functions(), or to communicate with individual controllers
(see :c:type:`nvme_mi_init_ctrl`).

Endpoints are created through a transport-specific constructor; currently
only MCTP-connected endpoints are supported, through :c:type:`nvme_mi_open_mctp`.
Subsequent operations on the endpoint (and related controllers) are
transport-independent.


.. c:function:: int nvme_mi_set_csi (nvme_mi_ep_t ep, uint8_t csi)

   Assign a CSI to an endpoint.

**Parameters**

``nvme_mi_ep_t ep``
  Endpoint

``uint8_t csi``
  value to use for CSI bit in NMP (0 or 1) for this endpoint

**Return**

0 if successful, -1 otherwise (some endpoints may not support)


.. c:function:: nvme_mi_ep_t nvme_mi_first_endpoint (struct nvme_global_ctx *ctx)

   Start endpoint iterator

**Parameters**

``struct nvme_global_ctx *ctx``
  :c:type:`struct nvme_global_ctx <nvme_global_ctx>` object

**Return**

first MI endpoint object under this root, or NULL if no endpoints
        are present.

**Description**

See: :c:type:`nvme_mi_next_endpoint`, :c:type:`nvme_mi_for_each_endpoint`


.. c:function:: nvme_mi_ep_t nvme_mi_next_endpoint (struct nvme_global_ctx *ctx, nvme_mi_ep_t e)

   Continue endpoint iterator

**Parameters**

``struct nvme_global_ctx *ctx``
  :c:type:`struct nvme_global_ctx <nvme_global_ctx>` object

``nvme_mi_ep_t e``
  :c:type:`nvme_mi_ep_t` current position of iterator

**Return**

next endpoint MI endpoint object after **e** under this root, or NULL
        if no further endpoints are present.

**Description**

See: :c:type:`nvme_mi_first_endpoint`, :c:type:`nvme_mi_for_each_endpoint`


.. c:macro:: nvme_mi_for_each_endpoint

``nvme_mi_for_each_endpoint (c, e)``

   Iterator for NVMe-MI endpoints.

**Parameters**

``c``
  :c:type:`struct nvme_global_ctx <nvme_global_ctx>` object

``e``
  :c:type:`nvme_mi_ep_t` object, set on each iteration


.. c:macro:: nvme_mi_for_each_endpoint_safe

``nvme_mi_for_each_endpoint_safe (c, e, _e)``

   Iterator for NVMe-MI endpoints, allowing deletion during traversal

**Parameters**

``c``
  :c:type:`struct nvme_global_ctx <nvme_global_ctx>` object

``e``
  :c:type:`nvme_mi_ep_t` object, set on each iteration

``_e``
  :c:type:`nvme_mi_ep_t` object used as temporary storage


.. c:function:: int nvme_mi_ep_set_timeout (nvme_mi_ep_t ep, unsigned int timeout_ms)

   set a timeout for NVMe-MI responses

**Parameters**

``nvme_mi_ep_t ep``
  MI endpoint object

``unsigned int timeout_ms``
  Timeout for MI responses, given in milliseconds


.. c:function:: void nvme_mi_ep_set_mprt_max (nvme_mi_ep_t ep, unsigned int mprt_max_ms)

   set the maximum wait time for a More Processing Required response

**Parameters**

``nvme_mi_ep_t ep``
  MI endpoint object

``unsigned int mprt_max_ms``
  Maximum more processing required wait time

**Description**

NVMe-MI endpoints may respond to a request with a "More Processing Required"
response; this also includes a hint on the worst-case processing time for
the eventual response data, with a specification-defined maximum of 65.535
seconds.

This function provides a way to limit the maximum time we're prepared to
wait for the final response. Specify zero in **mprt_max_ms** for no limit.
This should be larger than the command/response timeout set in
:c:type:`nvme_mi_ep_set_timeout`().


.. c:function:: unsigned int nvme_mi_ep_get_timeout (nvme_mi_ep_t ep)

   get the current timeout value for NVMe-MI responses

**Parameters**

``nvme_mi_ep_t ep``
  MI endpoint object

**Description**

Returns the current timeout value, in milliseconds, for this endpoint.


.. c:function:: struct nvme_transport_handle * nvme_mi_first_transport_handle (nvme_mi_ep_t ep)

   Start transport handle iterator

**Parameters**

``nvme_mi_ep_t ep``
  :c:type:`nvme_mi_ep_t` object

**Return**

first transport handle to a MI controller object under this
        root, or NULL if no controllers are present.

**Description**

See: :c:type:`nvme_mi_next_transport_handle`, :c:type:`nvme_mi_for_each_transport_handle`


.. c:function:: struct nvme_transport_handle * nvme_mi_next_transport_handle (nvme_mi_ep_t ep, struct nvme_transport_handle *hdl)

   Continue transport handle iterator

**Parameters**

``nvme_mi_ep_t ep``
  :c:type:`nvme_mi_ep_t` object

``struct nvme_transport_handle *hdl``
  :c:type:`nvme_transport_handle` current position of iterator

**Return**

next transport handle to MI controller object after **c** under
        this endpoint, or NULL if no further controllers are present.

**Description**

See: :c:type:`nvme_mi_first_transport_handle`, :c:type:`nvme_mi_for_each_transport_handle`


.. c:macro:: nvme_mi_for_each_transport_handle

``nvme_mi_for_each_transport_handle (ep, hdl)``

   Iterator for transport handle to NVMe-MI controllers.

**Parameters**

``ep``
  :c:type:`nvme_mi_ep_t` containing endpoints

``hdl``
  :c:type:`nvme_trasnport_handle` object, set on each iteration

**Description**

Allows iteration of the list of controllers behind an endpoint. Unless the
controllers have already been created explicitly, you'll probably want to
call :c:type:`nvme_mi_scan_ep`() to scan for the controllers first.

See: :c:type:`nvme_mi_scan_ep`()


.. c:macro:: nvme_mi_for_each_transport_handle_safe

``nvme_mi_for_each_transport_handle_safe (ep, hdl, _hdl)``

   Iterator for transport handle to NVMe-MI controllers, allowing deletion during traversal

**Parameters**

``ep``
  :c:type:`nvme_mi_ep_t` containing controllers

``hdl``
  :c:type:`nvme_transport_handle` object, set on each iteration

``_hdl``
  :c:type:`nvme_transport_handle` object used as temporary storage

**Description**

Allows iteration of the list of controllers behind an endpoint, safe against
deletion during iteration. Unless the controllers have already been created
explicitly (or you're just iterating to destroy controllers) you'll probably
want to call :c:type:`nvme_mi_scan_ep`() to scan for the controllers first.

See: :c:type:`nvme_mi_scan_ep`()


.. c:function:: nvme_mi_ep_t nvme_mi_open_mctp (struct nvme_global_ctx *ctx, unsigned int netid, uint8_t eid)

   Create an endpoint using a MCTP connection.

**Parameters**

``struct nvme_global_ctx *ctx``
  :c:type:`struct nvme_global_ctx <nvme_global_ctx>` object

``unsigned int netid``
  MCTP network ID on this system

``uint8_t eid``
  MCTP endpoint ID

**Description**

Transport-specific endpoint initialization for MI-connected endpoints. Once
an endpoint is created, the rest of the API is transport-independent.

See :c:type:`nvme_mi_close`

**Return**

New endpoint object for **netid** & **eid**, or NULL on failure.


.. c:function:: int nvme_mi_aem_open (nvme_mi_ep_t ep)

   Prepare an existing endpoint to receive AEMs

**Parameters**

``nvme_mi_ep_t ep``
  Endpoint to configure for AEMs

**Return**

0 if success, -1 otherwise


.. c:function:: void nvme_mi_close (nvme_mi_ep_t ep)

   Close an endpoint connection and release resources, including controller objects.

**Parameters**

``nvme_mi_ep_t ep``
  Endpoint object to close


.. c:function:: struct nvme_global_ctx * nvme_mi_scan_mctp (void)

   look for MCTP-connected NVMe-MI endpoints.

**Parameters**

``void``
  no arguments

**Description**

This function queries the system MCTP daemon ("mctpd") over
D-Bus, to find MCTP endpoints that report support for NVMe-MI over MCTP.

This requires libvnme-mi to be compiled with D-Bus support; if not, this
will return NULL.

**Return**

A **struct** nvme_global_ctx populated with a set of
        MCTP-connected endpoints, or NULL on failure


.. c:function:: int nvme_mi_scan_ep (nvme_mi_ep_t ep, bool force_rescan)

   query an endpoint for its NVMe controllers.

**Parameters**

``nvme_mi_ep_t ep``
  Endpoint to scan

``bool force_rescan``
  close existing controllers and rescan

**Description**

This function queries an MI endpoint for the controllers available, by
performing an MI Read MI Data Structure command (requesting the
controller list). The controllers are stored in the endpoint's internal
list, and can be iterated with nvme_mi_for_each_ctrl.

This will only scan the endpoint once, unless **force_rescan** is set. If
so, all existing controller objects will be freed - the caller must not
hold a reference to those across this call.

See: :c:type:`nvme_mi_for_each_ctrl`

**Return**

The nvme command status if a response was received (see
:c:type:`enum nvme_status_field <nvme_status_field>`) or -1 with errno set otherwise.


.. c:function:: struct nvme_transport_handle * nvme_mi_init_transport_handle (nvme_mi_ep_t ep, __u16 ctrl_id)

   initialise a transport handle to NVMe controller.

**Parameters**

``nvme_mi_ep_t ep``
  Endpoint to create under

``__u16 ctrl_id``
  ID of controller to initialize.

**Description**

Create a connection to a controller behind the endpoint specified in **ep**.
Controller IDs may be queried from the endpoint through
:c:type:`nvme_mi_mi_read_mi_data_ctrl_list`.

See :c:type:`nvme_mi_close_transport_handle`

**Return**

New transport handle object, or NULL on failure.


.. c:function:: __u16 nvme_mi_ctrl_id (struct nvme_transport_handle *hdl)

   get the ID of a controller

**Parameters**

``struct nvme_transport_handle *hdl``
  transport handle to controller to query

**Description**

Retrieve the ID of the controller, as defined by hardware, and available
in the Identify (Controller List) data. This is the value passed to
**nvme_mi_init_transport_handle**, but may have been created internally via
**nvme_mi_scan_ep**.

**Return**

the (locally-stored) ID of this controller.


.. c:function:: char * nvme_mi_endpoint_desc (nvme_mi_ep_t ep)

   Get a string describing a MI endpoint.

**Parameters**

``nvme_mi_ep_t ep``
  endpoint to describe

**Description**

Generates a human-readable string describing the endpoint, with possibly
transport-specific data. The string is allocated during the call, and the
caller is responsible for free()-ing the string.

**Return**

a newly-allocated string containing the endpoint description, or
        NULL on failure.


.. c:function:: int nvme_mi_mi_xfer (nvme_mi_ep_t ep, struct nvme_mi_mi_req_hdr *mi_req, size_t req_data_size, struct nvme_mi_mi_resp_hdr *mi_resp, size_t *resp_data_size)

   Raw mi transfer interface.

**Parameters**

``nvme_mi_ep_t ep``
  endpoint to send the MI command to

``struct nvme_mi_mi_req_hdr *mi_req``
  request data

``size_t req_data_size``
  size of request data payload

``struct nvme_mi_mi_resp_hdr *mi_resp``
  buffer for response data

``size_t *resp_data_size``
  size of response data buffer, updated to received size

**Description**

Performs an arbitrary NVMe MI command, using the provided request data,
in **mi_req**. The size of the request data *payload* is specified in
**req_data_size** - this does not include the standard header length (so a
header-only request would have a size of 0). Note that the Management
Request Doublewords are considered part of the header data.

On success, response data is stored in **mi_resp**, which has an optional
appended payload buffer of **resp_data_size** bytes. The actual payload
size transferred will be stored in **resp_data_size**. This size does not
include the MI response header, so 0 represents no payload.

See: :c:type:`struct nvme_mi_mi_req_hdr <nvme_mi_mi_req_hdr>` and :c:type:`struct nvme_mi_mi_resp_hdr <nvme_mi_mi_resp_hdr>`.

**Return**

The nvme command status if a response was received (see
:c:type:`enum nvme_status_field <nvme_status_field>`) or -1 with errno set otherwise..


.. c:function:: int nvme_mi_mi_read_mi_data_subsys (nvme_mi_ep_t ep, struct nvme_mi_read_nvm_ss_info *s)

   Perform a Read MI Data Structure command, retrieving subsystem data.

**Parameters**

``nvme_mi_ep_t ep``
  endpoint for MI communication

``struct nvme_mi_read_nvm_ss_info *s``
  subsystem information to populate

**Description**

Retrieves the Subsystem information - number of external ports and
NVMe version information. See :c:type:`struct nvme_mi_read_nvm_ss_info <nvme_mi_read_nvm_ss_info>`.

**Return**

The nvme command status if a response was received (see
:c:type:`enum nvme_status_field <nvme_status_field>`) or -1 with errno set otherwise..


.. c:function:: int nvme_mi_mi_read_mi_data_port (nvme_mi_ep_t ep, __u8 portid, struct nvme_mi_read_port_info *p)

   Perform a Read MI Data Structure command, retrieving port data.

**Parameters**

``nvme_mi_ep_t ep``
  endpoint for MI communication

``__u8 portid``
  id of port data to retrieve

``struct nvme_mi_read_port_info *p``
  port information to populate

**Description**

Retrieves the Port information, for the specified port ID. The subsystem
data (from :c:type:`nvme_mi_mi_read_mi_data_subsys`) nmp field contains the allowed
range of port IDs.

See :c:type:`struct nvme_mi_read_port_info <nvme_mi_read_port_info>`.

**Return**

The nvme command status if a response was received (see
:c:type:`enum nvme_status_field <nvme_status_field>`) or -1 with errno set otherwise..


.. c:function:: int nvme_mi_mi_read_mi_data_ctrl_list (nvme_mi_ep_t ep, __u8 start_ctrlid, struct nvme_ctrl_list *list)

   Perform a Read MI Data Structure command, retrieving the list of attached controllers.

**Parameters**

``nvme_mi_ep_t ep``
  endpoint for MI communication

``__u8 start_ctrlid``
  starting controller ID

``struct nvme_ctrl_list *list``
  controller list to populate

**Description**

Retrieves the list of attached controllers, with IDs greater than or
equal to **start_ctrlid**.

See :c:type:`struct nvme_ctrl_list <nvme_ctrl_list>`.

**Return**

The nvme command status if a response was received (see
:c:type:`enum nvme_status_field <nvme_status_field>`) or -1 with errno set otherwise..


.. c:function:: int nvme_mi_mi_read_mi_data_ctrl (nvme_mi_ep_t ep, __u16 ctrl_id, struct nvme_mi_read_ctrl_info *ctrl)

   Perform a Read MI Data Structure command, retrieving controller information

**Parameters**

``nvme_mi_ep_t ep``
  endpoint for MI communication

``__u16 ctrl_id``
  ID of controller to query

``struct nvme_mi_read_ctrl_info *ctrl``
  controller data to populate

**Description**

Retrieves the Controller Information Data Structure for the attached
controller with ID **ctrlid**.

See :c:type:`struct nvme_mi_read_ctrl_info <nvme_mi_read_ctrl_info>`.

**Return**

The nvme command status if a response was received (see
:c:type:`enum nvme_status_field <nvme_status_field>`) or -1 with errno set otherwise..


.. c:function:: int nvme_mi_mi_subsystem_health_status_poll (nvme_mi_ep_t ep, bool clear, struct nvme_mi_nvm_ss_health_status *nshds)

   Read the Subsystem Health Data Structure from the NVM subsystem

**Parameters**

``nvme_mi_ep_t ep``
  endpoint for MI communication

``bool clear``
  flag to clear the Composite Controller Status state

``struct nvme_mi_nvm_ss_health_status *nshds``
  subsystem health status data to populate

**Description**

Retrieves the Subsystem Health Data Structure into **nshds**. If **clear** is
set, requests that the Composite Controller Status bits are cleared after
the read. See NVMe-MI section 5.6 for details on the CCS bits.

See :c:type:`struct nvme_mi_nvm_ss_health_status <nvme_mi_nvm_ss_health_status>`.

**Return**

The nvme command status if a response was received (see
:c:type:`enum nvme_status_field <nvme_status_field>`) or -1 with errno set otherwise..


.. c:function:: int nvme_mi_mi_config_get (nvme_mi_ep_t ep, __u32 dw0, __u32 dw1, __u32 *nmresp)

   query a configuration parameter

**Parameters**

``nvme_mi_ep_t ep``
  endpoint for MI communication

``__u32 dw0``
  management doubleword 0, containing configuration identifier, plus
  config-specific fields

``__u32 dw1``
  management doubleword 0, config-specific.

``__u32 *nmresp``
  set to queried configuration data in NMRESP field of response.

**Description**

Performs a MI Configuration Get command, with the configuration identifier
as the LSB of **dw0**. Other **dw0** and **dw1** data is configuration-identifier
specific.

On a successful Configuration Get, the **nmresp** pointer will be populated with
the bytes from the 3-byte NMRESP field, converted to native endian.

See :c:type:`enum nvme_mi_config_id <nvme_mi_config_id>` for identifiers.

**Return**

The nvme command status if a response was received (see
:c:type:`enum nvme_status_field <nvme_status_field>`) or -1 with errno set otherwise..


.. c:function:: int nvme_mi_mi_config_set (nvme_mi_ep_t ep, __u32 dw0, __u32 dw1)

   set a configuration parameter

**Parameters**

``nvme_mi_ep_t ep``
  endpoint for MI communication

``__u32 dw0``
  management doubleword 0, containing configuration identifier, plus
  config-specific fields

``__u32 dw1``
  management doubleword 0, config-specific.

**Description**

Performs a MI Configuration Set command, with the command as the LSB of
**dw0**. Other **dw0** and **dw1** data is configuration-identifier specific.

See :c:type:`enum nvme_mi_config_id <nvme_mi_config_id>` for identifiers.

**Return**

The nvme command status if a response was received (see
:c:type:`enum nvme_status_field <nvme_status_field>`) or -1 with errno set otherwise..


.. c:function:: int nvme_mi_mi_config_get_smbus_freq (nvme_mi_ep_t ep, __u8 port, enum nvme_mi_config_smbus_freq *freq)

   get configuration: SMBus port frequency

**Parameters**

``nvme_mi_ep_t ep``
  endpoint for MI communication

``__u8 port``
  port ID to query

``enum nvme_mi_config_smbus_freq *freq``
  output value for current frequency configuration

**Description**

Performs a MI Configuration Get, to query the current SMBus frequency of
the port specified in **port**. On success, populates **freq** with the port
frequency

**Return**

The nvme command status if a response was received (see
:c:type:`enum nvme_status_field <nvme_status_field>`) or -1 with errno set otherwise..


.. c:function:: int nvme_mi_mi_config_set_smbus_freq (nvme_mi_ep_t ep, __u8 port, enum nvme_mi_config_smbus_freq freq)

   set configuration: SMBus port frequency

**Parameters**

``nvme_mi_ep_t ep``
  endpoint for MI communication

``__u8 port``
  port ID to set

``enum nvme_mi_config_smbus_freq freq``
  new frequency configuration

**Description**

Performs a MI Configuration Set, to update the current SMBus frequency of
the port specified in **port**.

See :c:type:`struct nvme_mi_read_port_info <nvme_mi_read_port_info>` for the maximum supported SMBus frequency
for the port.

**Return**

The nvme command status if a response was received (see
:c:type:`enum nvme_status_field <nvme_status_field>`) or -1 with errno set otherwise..


.. c:function:: int nvme_mi_mi_config_set_health_status_change (nvme_mi_ep_t ep, __u32 mask)

   clear CCS bits in health status

**Parameters**

``nvme_mi_ep_t ep``
  endpoint for MI communication

``__u32 mask``
  bitmask to clear

**Description**

Performs a MI Configuration Set, to update the current health status poll
values of the Composite Controller Status bits. Bits set in **mask** will
be cleared from future health status poll data, and may be re-triggered by
a future health change event.

See :c:type:`nvme_mi_mi_subsystem_health_status_poll`(), :c:type:`enum nvme_mi_ccs <nvme_mi_ccs>` for
values in **mask**.

**Return**

The nvme command status if a response was received (see
:c:type:`enum nvme_status_field <nvme_status_field>`) or -1 with errno set otherwise..


.. c:function:: int nvme_mi_mi_config_get_mctp_mtu (nvme_mi_ep_t ep, __u8 port, __u16 *mtu)

   get configuration: MCTP MTU

**Parameters**

``nvme_mi_ep_t ep``
  endpoint for MI communication

``__u8 port``
  port ID to query

``__u16 *mtu``
  output value for current MCTP MTU configuration

**Description**

Performs a MI Configuration Get, to query the current MCTP Maximum
Transmission Unit size (MTU) of the port specified in **port**. On success,
populates **mtu** with the MTU.

The default reset value is 64, corresponding to the MCTP baseline MTU.

Some controllers may also use this as the maximum receive unit size, and
may not accept MCTP messages larger than the configured MTU.

**Return**

The nvme command status if a response was received (see
:c:type:`enum nvme_status_field <nvme_status_field>`) or -1 with errno set otherwise..


.. c:function:: int nvme_mi_mi_config_set_mctp_mtu (nvme_mi_ep_t ep, __u8 port, __u16 mtu)

   set configuration: MCTP MTU

**Parameters**

``nvme_mi_ep_t ep``
  endpoint for MI communication

``__u8 port``
  port ID to set

``__u16 mtu``
  new MTU configuration

**Description**

Performs a MI Configuration Set, to update the current MCTP MTU value for
the port specified in **port**.

Some controllers may also use this as the maximum receive unit size, and
may not accept MCTP messages larger than the configured MTU. When setting
this value, you will likely need to change the MTU of the local MCTP
interface(s) to match.

**Return**

The nvme command status if a response was received (see
:c:type:`enum nvme_status_field <nvme_status_field>`) or -1 with errno set otherwise..


.. c:function:: int nvme_mi_mi_config_get_async_event (nvme_mi_ep_t ep, __u8 *aeelver, struct nvme_mi_aem_supported_list *list, size_t *list_num_bytes)

   get configuration: Asynchronous Event

**Parameters**

``nvme_mi_ep_t ep``
  endpoint for MI communication

``__u8 *aeelver``
  Asynchronous Event Enable List Version Number

``struct nvme_mi_aem_supported_list *list``
  AE Supported list header and list contents

``size_t *list_num_bytes``
  number of bytes in the list header and contents buffer.
  This will be populated with returned size of list and contents if successful.

**Description**

Performs a MI Configuration Get, to query the current enable Asynchronous
Events.  On success, populates **aeelver** and the **list** with current info,

**Return**

The nvme command status if a response was received (see
:c:type:`enum nvme_status_field <nvme_status_field>`) or -1 with errno set otherwise..


.. c:function:: int nvme_mi_mi_config_set_async_event (nvme_mi_ep_t ep, bool envfa, bool empfa, bool encfa, __u8 aemd, __u8 aerd, struct nvme_mi_aem_enable_list *enable_list, size_t enable_list_size, struct nvme_mi_aem_occ_list_hdr *occ_list, size_t *occ_list_size)

   set configuration: Asynchronous Event

**Parameters**

``nvme_mi_ep_t ep``
  endpoint for MI communication

``bool envfa``
  Enable SR-IOV Virtual Functions AE

``bool empfa``
  Enable SR-IOV Physical Functions AE

``bool encfa``
  Enable PCI Functions AE.

``__u8 aemd``
  AEM Delay Interval (for Sync only)

``__u8 aerd``
  AEM Retry Delay (for Sync only; time in 100s of ms)

``struct nvme_mi_aem_enable_list *enable_list``
  nvme_mi_aem_enable_listucture containing header and items
  of events to be enabled or disabled.  This is taken as a delta change
  from the current configuration.

``size_t enable_list_size``
  Size of the enable_list including header and data.
  Meant to catch overrun issues.

``struct nvme_mi_aem_occ_list_hdr *occ_list``
  Pointer to populate with the occurrence list (header and data)

``size_t *occ_list_size``
  Total size of provided occ_list buffer.  Will be updated
  with received size if successful

**Description**

Performs a MI Configuration Set, to ACK (sent after an AEM) or Sync (at anytime to enable
or disable Asynchronous Events).

On success, populates **occ_list**.  See TP6035a for details on how occ_list is populated in
ACK versus Sync conditions

**Return**

The nvme command status if a response was received (see
:c:type:`enum nvme_status_field <nvme_status_field>`) or -1 with errno set otherwise..


.. c:function:: int nvme_mi_admin_xfer (struct nvme_transport_handle *hdl, struct nvme_mi_admin_req_hdr *admin_req, size_t req_data_size, struct nvme_mi_admin_resp_hdr *admin_resp, off_t resp_data_offset, size_t *resp_data_size)

   Raw admin transfer interface.

**Parameters**

``struct nvme_transport_handle *hdl``
  transport handle to send the admin command to

``struct nvme_mi_admin_req_hdr *admin_req``
  request data

``size_t req_data_size``
  size of request data payload

``struct nvme_mi_admin_resp_hdr *admin_resp``
  buffer for response data

``off_t resp_data_offset``
  offset into request data to retrieve from controller

``size_t *resp_data_size``
  size of response data buffer, updated to received size

**Description**

Performs an arbitrary NVMe Admin command, using the provided request data,
in **admin_req**. The size of the request data *payload* is specified in
**req_data_size** - this does not include the standard header length (so a
header-only request would have a size of 0).

On success, response data is stored in **admin_resp**, which has an optional
appended payload buffer of **resp_data_size** bytes. The actual payload
transferred will be stored in **resp_data_size**. These sizes do not include
the Admin request header, so 0 represents no payload.

As with all Admin commands, we can request partial data from the Admin
Response payload, offset by **resp_data_offset**.

See: :c:type:`struct nvme_mi_admin_req_hdr <nvme_mi_admin_req_hdr>` and :c:type:`struct nvme_mi_admin_resp_hdr <nvme_mi_admin_resp_hdr>`.

**Return**

The nvme command status if a response was received (see
:c:type:`enum nvme_status_field <nvme_status_field>`) or -1 with errno set otherwise..


.. c:function:: int nvme_mi_control (nvme_mi_ep_t ep, __u8 opcode, __u16 cpsp, __u16 *result_cpsr)

   Perform a Control Primitive command

**Parameters**

``nvme_mi_ep_t ep``
  endpoint for MI communication

``__u8 opcode``
  Control Primitive opcode (using :c:type:`enum nvme_mi_control_opcode <nvme_mi_control_opcode>`)

``__u16 cpsp``
  Control Primitive Specific Parameter

``__u16 *result_cpsr``
  Optional field to return the result from the CPSR field

**Description**

Perform a Control Primitive command, using the opcode specified in **opcode**
Stores the result from the CPSR field in **result_cpsr** if set.

See: :c:type:`enum nvme_mi_control_opcode <nvme_mi_control_opcode>`

**Return**

0 on success, non-zero on failure




.. c:enum:: nvme_mi_aem_handler_next_action

   Next action for the AEM state machine handler

**Constants**

``NVME_MI_AEM_HNA_ACK``
  Send an ack for the AEM

``NVME_MI_AEM_HNA_NONE``
  No further action

**Description**

Used as return value for the AE callback generated when calling nvme_mi_aem_process




.. c:struct:: nvme_mi_event

   AE event information structure

**Definition**

::

  struct nvme_mi_event {
    uint8_t aeoi;
    uint8_t aessi;
    uint32_t aeocidi;
    void *spec_info;
    size_t spec_info_len;
    void *vend_spec_info;
    size_t vend_spec_info_len;
  };

**Members**

``aeoi``
  Event identifier

``aessi``
  Event occurrence scope info

``aeocidi``
  Event occurrence scope ID info

``spec_info``
  Specific info buffer

``spec_info_len``
  Length of specific info buffer

``vend_spec_info``
  Vendor specific info buffer

``vend_spec_info_len``
  Length of vendor specific info buffer


**Description**

Application callbacks for nvme_mi_aem_process will be able to call
nvme_mi_aem_get_next_event which will return a pointer to such an identifier
for the next event the application should parse


.. c:function:: struct nvme_mi_event * nvme_mi_aem_get_next_event (nvme_mi_ep_t ep)

   Get details for the next event to parse

**Parameters**

``nvme_mi_ep_t ep``
  The endpoint with the event

**Description**

When inside a aem_handler, call this and a returned struct pointer
will provide details of event information.  Will return NULL when end of parsing is occurred.
spec_info and vend_spec_info must be copied to persist as they will not be valid
after the handler_next_action has returned.

**Return**

Pointer no next nvme_mi_event or NULL if this is the last one




.. c:struct:: nvme_mi_aem_config

   Provided for nvme_mi_aem_enable

**Definition**

::

  struct nvme_mi_aem_config {
    enum nvme_mi_aem_handler_next_action (*aem_handler)(nvme_mi_ep_t ep,size_t num_events, void *userdata);
    struct nvme_mi_aem_enabled_map enabled_map;
    bool envfa;
    bool empfa;
    bool encfa;
    __u8 aemd;
    __u8 aerd;
  };

**Members**

``aem_handler``
  Callback function for application processing of events

``enabled_map``
  Map indicating which AE should be enabled on the endpoint

``envfa``
  Enable SR-IOV virtual functions AE

``empfa``
  Enable SR-IOV physical functions AE

``encfa``
  Enable PCIe functions AE

``aemd``
  AEM Delay (time in seconds from when event happens to AEM being batched and sent)

``aerd``
  AEM Retry Delay (time in 100s of ms between AEM retries from the endpoint)


**Description**

Application callbacks for nvme_mi_aem_process will be able to call
nvme_mi_aem_get_next_event which will return a pointer to such an identifier
for the next event the application should parse


.. c:function:: int nvme_mi_aem_get_fd (nvme_mi_ep_t ep)

   Returns the pollable fd for AEM data available

**Parameters**

``nvme_mi_ep_t ep``
  The endpoint being monitored for asynchronous data

**Description**

This populated structure can be polled from the application to understand if
a call to nvme_mi_aem_process() is required (when a poll returns > 0).

**Return**

The fd value or -1 if error


.. c:function:: int nvme_mi_aem_enable (nvme_mi_ep_t ep, struct nvme_mi_aem_config *config, void *userdata)

   Enable AE on the provided endpoint

**Parameters**

``nvme_mi_ep_t ep``
  Endpoint to enable AEs

``struct nvme_mi_aem_config *config``
  AE configuraiton including which events are enabled and the callback function

``void *userdata``
  Application provided context pointer for callback function

**Description**

This function is called to enable AE on the endpoint.  Endpoint will provide initial state
(if any) of enabled AEs and application can parse those via the aem_handler fn pointer in
callbacks.  Thes can be obtained in the callback by calling nvme_mi_aem_get_next_event().

Application should poll the fd that can be obtained from nvme_mi_aem_get_fd and then call
nvme_mi_aem_process() when poll() indicates data available.

A call to nvme_mi_aem_process() will grab AEM data and call the aem_handler fn pointer.
At this point the application can call nvme_mi_aem_get_next_event() to get information for
each triggered event.

**Return**

0 is a success, nonzero is an error and errno may be read for further details


.. c:function:: int nvme_mi_aem_get_enabled (nvme_mi_ep_t ep, struct nvme_mi_aem_enabled_map *enabled)

   Return information on which AEs are enabled

**Parameters**

``nvme_mi_ep_t ep``
  Endpoint to check enabled status

``struct nvme_mi_aem_enabled_map *enabled``
  nvme_mi_aem_enabled_map indexed by AE event ID of enabled state

**Return**

0 is a success, nonzero is an error and errno may be read for further details


.. c:function:: int nvme_mi_aem_disable (nvme_mi_ep_t ep)

   Disable AE on the provided endpoint

**Parameters**

``nvme_mi_ep_t ep``
  Endpoint to disable AEs

**Return**

0 is a success, nonzero is an error and errno may be read for further details


.. c:function:: int nvme_mi_aem_process (nvme_mi_ep_t ep, void *userdata)

   Process AEM on the provided endpoint

**Parameters**

``nvme_mi_ep_t ep``
  Endpoint to process

``void *userdata``
  Application provided context pointer for callback function

**Description**

Call this if poll() indicates data is available on the fd provided by nvme_mi_aem_get_fd()

This will call the fn pointer, aem_handler, provided with nvme_mi_aem_config and the
application can call nvme_mi_aem_get_next_event() from within this callback to get
aem event data.  The callback function should return NVME_MI_AEM_HNA_ACK for normal operation.

**Return**

0 is a success, nonzero is an error and errno may be read for further details


