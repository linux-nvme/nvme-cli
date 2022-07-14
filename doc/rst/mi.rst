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

**Description**

Configuration parameters for the MI Get/Set Configuration commands.

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


.. c:function:: nvme_root_t nvme_mi_create_root (FILE *fp, int log_level)

   Create top-level MI (root) handle.

**Parameters**

``FILE *fp``
  File descriptor for logging messages

``int log_level``
  Logging level to use

**Description**

Create the top-level (library) handle for creating subsequent endpoint
objects. Similar to nvme_create_root(), but we provide this to allow linking
without the core libnvme.

See :c:type:`nvme_create_root`.

**Return**

new root object, or NULL on failure.


.. c:function:: void nvme_mi_free_root (nvme_root_t root)

   Free root object.

**Parameters**

``nvme_root_t root``
  root to free




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


.. c:function:: nvme_mi_ep_t nvme_mi_first_endpoint (nvme_root_t m)

   Start endpoint iterator

**Parameters**

``nvme_root_t m``
  :c:type:`nvme_root_t` object

**Return**

first MI endpoint object under this root, or NULL if no endpoints
        are present.

**Description**

See: :c:type:`nvme_mi_next_endpoint`, :c:type:`nvme_mi_for_each_endpoint`


.. c:function:: nvme_mi_ep_t nvme_mi_next_endpoint (nvme_root_t m, nvme_mi_ep_t e)

   Continue endpoint iterator

**Parameters**

``nvme_root_t m``
  :c:type:`nvme_root_t` object

``nvme_mi_ep_t e``
  :c:type:`nvme_mi_ep_t` current position of iterator

**Return**

next endpoint MI endpoint object after **e** under this root, or NULL
        if no further endpoints are present.

**Description**

See: :c:type:`nvme_mi_first_endpoint`, :c:type:`nvme_mi_for_each_endpoint`


.. c:macro:: nvme_mi_for_each_endpoint

``nvme_mi_for_each_endpoint (m, e)``

   Iterator for NVMe-MI endpoints.

**Parameters**

``m``
  :c:type:`nvme_root_t` containing endpoints

``e``
  :c:type:`nvme_mi_ep_t` object, set on each iteration


.. c:macro:: nvme_mi_for_each_endpoint_safe

``nvme_mi_for_each_endpoint_safe (m, e, _e)``

   Iterator for NVMe-MI endpoints, allowing deletion during traversal

**Parameters**

``m``
  :c:type:`nvme_root_t` containing endpoints

``e``
  :c:type:`nvme_mi_ep_t` object, set on each iteration

``_e``
  :c:type:`nvme_mi_ep_t` object used as temporary storage




.. c:type:: nvme_mi_ctrl_t

   NVMe-MI Controller object.

**Description**


Provides NVMe command functionality, through the MI interface.


.. c:function:: nvme_mi_ctrl_t nvme_mi_first_ctrl (nvme_mi_ep_t ep)

   Start controller iterator

**Parameters**

``nvme_mi_ep_t ep``
  :c:type:`nvme_mi_ep_t` object

**Return**

first MI controller object under this root, or NULL if no controllers
        are present.

**Description**

See: :c:type:`nvme_mi_next_ctrl`, :c:type:`nvme_mi_for_each_ctrl`


.. c:function:: nvme_mi_ctrl_t nvme_mi_next_ctrl (nvme_mi_ep_t ep, nvme_mi_ctrl_t c)

   Continue ctrl iterator

**Parameters**

``nvme_mi_ep_t ep``
  :c:type:`nvme_mi_ep_t` object

``nvme_mi_ctrl_t c``
  :c:type:`nvme_mi_ctrl_t` current position of iterator

**Return**

next MI controller object after **c** under this endpoint, or NULL
        if no further controllers are present.

**Description**

See: :c:type:`nvme_mi_first_ctrl`, :c:type:`nvme_mi_for_each_ctrl`


.. c:macro:: nvme_mi_for_each_ctrl

``nvme_mi_for_each_ctrl (ep, c)``

   Iterator for NVMe-MI controllers.

**Parameters**

``ep``
  :c:type:`nvme_mi_ep_t` containing endpoints

``c``
  :c:type:`nvme_mi_ctrl_t` object, set on each iteration

**Description**

Allows iteration of the list of controllers behind an endpoint. Unless the
controllers have already been created explicitly, you'll probably want to
call :c:type:`nvme_mi_scan_ep`() to scan for the controllers first.

See: :c:type:`nvme_mi_scan_ep`()


.. c:macro:: nvme_mi_for_each_ctrl_safe

``nvme_mi_for_each_ctrl_safe (ep, c, _c)``

   Iterator for NVMe-MI controllers, allowing deletion during traversal

**Parameters**

``ep``
  :c:type:`nvme_mi_ep_t` containing controllers

``c``
  :c:type:`nvme_mi_ctrl_t` object, set on each iteration

``_c``
  :c:type:`nvme_mi_ctrl_t` object used as temporary storage

**Description**

Allows iteration of the list of controllers behind an endpoint, safe against
deletion during iteration. Unless the controllers have already been created
explicitly (or you're just iterating to destroy controllers) you'll probably
want to call :c:type:`nvme_mi_scan_ep`() to scan for the controllers first.

See: :c:type:`nvme_mi_scan_ep`()


.. c:function:: nvme_mi_ep_t nvme_mi_open_mctp (nvme_root_t root, unsigned int netid, uint8_t eid)

   Create an endpoint using a MCTP connection.

**Parameters**

``nvme_root_t root``
  root object to create under

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


.. c:function:: void nvme_mi_close (nvme_mi_ep_t ep)

   Close an endpoint connection and release resources, including controller objects.

**Parameters**

``nvme_mi_ep_t ep``
  Endpoint object to close


.. c:function:: nvme_root_t nvme_mi_scan_mctp (void)

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

A **nvme_root_t** populated with a set of MCTP-connected endpoints,
        or NULL on failure


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

0 on success, non-zero on failure


.. c:function:: nvme_mi_ctrl_t nvme_mi_init_ctrl (nvme_mi_ep_t ep, __u16 ctrl_id)

   initialise a NVMe controller.

**Parameters**

``nvme_mi_ep_t ep``
  Endpoint to create under

``__u16 ctrl_id``
  ID of controller to initialize.

**Description**

Create a connection to a controller behind the endpoint specified in **ep**.
Controller IDs may be queried from the endpoint through
:c:type:`nvme_mi_mi_read_mi_data_ctrl_list`.

See :c:type:`nvme_mi_close_ctrl`

**Return**

New controller object, or NULL on failure.


.. c:function:: void nvme_mi_close_ctrl (nvme_mi_ctrl_t ctrl)

   free a controller

**Parameters**

``nvme_mi_ctrl_t ctrl``
  controller to free


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

0 on success, non-zero on failure.


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

0 on success, non-zero on failure.


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

0 on success, non-zero on failure.


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

0 on success, non-zero on failure.


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

0 on success, non-zero on failure.


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

0 on success, non-zero on failure.


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

0 on success, non-zero on failure.


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

0 on success, non-zero on failure.


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

0 on success, non-zero on failure.


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

0 on success, non-zero on failure.


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

0 on success, non-zero on failure.


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

0 on success, non-zero on failure.


.. c:function:: int nvme_mi_admin_xfer (nvme_mi_ctrl_t ctrl, struct nvme_mi_admin_req_hdr *admin_req, size_t req_data_size, struct nvme_mi_admin_resp_hdr *admin_resp, off_t resp_data_offset, size_t *resp_data_size)

   Raw admin transfer interface.

**Parameters**

``nvme_mi_ctrl_t ctrl``
  controller to send the admin command to

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

0 on success, non-zero on failure.


.. c:function:: int nvme_mi_admin_identify_partial (nvme_mi_ctrl_t ctrl, struct nvme_identify_args *args, off_t offset, size_t size)

   Perform an Admin identify command, and retrieve partial response data.

**Parameters**

``nvme_mi_ctrl_t ctrl``
  Controller to process identify command

``struct nvme_identify_args *args``
  Identify command arguments

``off_t offset``
  offset of identify data to retrieve from response

``size_t size``
  size of identify data to return

**Description**

Perform an Identify command, using the Identify command parameters in **args**.
The **offset** and **size** arguments allow the caller to retrieve part of
the identify response. See NVMe-MI section 6.2 for the semantics (and some
handy diagrams) of the offset & size parameters.

Will return an error if the length of the response data (from the controller)
did not match **size**.

Unless you're performing a vendor-unique identify command, You'll probably
want to use one of the identify helpers (nvme_mi_admin_identify,
nvme_mi_admin_identify_cns_nsid, or nvme_mi_admin_identify_<type>) instead
of this. If the type of your identify command is standardized but not
yet supported by libnvme-mi, please contact the maintainers.

See: :c:type:`struct nvme_identify_args <nvme_identify_args>`

**Return**

0 on success, non-zero on failure


.. c:function:: int nvme_mi_admin_identify (nvme_mi_ctrl_t ctrl, struct nvme_identify_args *args)

   Perform an Admin identify command.

**Parameters**

``nvme_mi_ctrl_t ctrl``
  Controller to process identify command

``struct nvme_identify_args *args``
  Identify command arguments

**Description**

Perform an Identify command, using the Identify command parameters in **args**.
Stores the identify data in ->data, and (if set) the result from cdw0
into args->result.

Will return an error if the length of the response data (from the
controller) is not a full :c:type:`NVME_IDENTIFY_DATA_SIZE`.

See: :c:type:`struct nvme_identify_args <nvme_identify_args>`

**Return**

0 on success, non-zero on failure


.. c:function:: int nvme_mi_admin_identify_cns_nsid (nvme_mi_ctrl_t ctrl, enum nvme_identify_cns cns, __u32 nsid, void *data)

   Perform an Admin identify command using specific CNS/NSID parameters.

**Parameters**

``nvme_mi_ctrl_t ctrl``
  Controller to process identify command

``enum nvme_identify_cns cns``
  Controller or Namespace Structure, specifying identified object

``__u32 nsid``
  namespace ID

``void *data``
  buffer for identify data response

**Description**

Perform an Identify command, using the CNS specifier **cns**, and the
namespace ID **nsid** if required by the CNS type.

Stores the identify data in **data**, which is expected to be a buffer of
:c:type:`NVME_IDENTIFY_DATA_SIZE` bytes.

Will return an error if the length of the response data (from the
controller) is not a full :c:type:`NVME_IDENTIFY_DATA_SIZE`.

**Return**

0 on success, non-zero on failure


.. c:function:: int nvme_mi_admin_identify_ctrl (nvme_mi_ctrl_t ctrl, struct nvme_id_ctrl *id)

   Perform an Admin identify for a controller

**Parameters**

``nvme_mi_ctrl_t ctrl``
  Controller to process identify command

``struct nvme_id_ctrl *id``
  Controller identify data to populate

**Description**

Perform an Identify command, for the controller specified by **ctrl**,
writing identify data to **id**.

Will return an error if the length of the response data (from the
controller) is not a full :c:type:`NVME_IDENTIFY_DATA_SIZE`, so **id** will be
fully populated on success.

See: :c:type:`struct nvme_id_ctrl <nvme_id_ctrl>`

**Return**

0 on success, non-zero on failure


.. c:function:: int nvme_mi_admin_identify_ctrl_list (nvme_mi_ctrl_t ctrl, __u16 cntid, struct nvme_ctrl_list *list)

   Perform an Admin identify for a controller list.

**Parameters**

``nvme_mi_ctrl_t ctrl``
  Controller to process identify command

``__u16 cntid``
  Controller ID to specify list start

``struct nvme_ctrl_list *list``
  List data to populate

**Description**

Perform an Identify command, for the controller list starting with
IDs greater than or equal to **cntid**.

Will return an error if the length of the response data (from the
controller) is not a full :c:type:`NVME_IDENTIFY_DATA_SIZE`, so **id** will be
fully populated on success.

See: :c:type:`struct nvme_ctrl_list <nvme_ctrl_list>`

**Return**

0 on success, non-zero on failure


.. c:function:: int nvme_mi_admin_get_log_page (nvme_mi_ctrl_t ctrl, struct nvme_get_log_args *args)

   Retrieve log page data from controller

**Parameters**

``nvme_mi_ctrl_t ctrl``
  Controller to query

``struct nvme_get_log_args *args``
  Get Log Page command arguments

**Description**

Performs a Get Log Page Admin command as specified by **args**. Response data
is stored in **args->data**, which should be a buffer of **args->data_len** bytes.
Resulting data length is stored in **args->data_len** on successful
command completion.

This request may be implemented as multiple log page commands, in order
to fit within MI message-size limits.

See: :c:type:`struct nvme_get_log_args <nvme_get_log_args>`

**Return**

0 on success, non-zero on failure


.. c:function:: int nvme_mi_admin_security_send (nvme_mi_ctrl_t ctrl, struct nvme_security_send_args *args)

   Perform a Security Send command on a controller.

**Parameters**

``nvme_mi_ctrl_t ctrl``
  Controller to send command to

``struct nvme_security_send_args *args``
  Security Send command arguments

**Description**

Performs a Security Send Admin command as specified by **args**. Response data
is stored in **args->data**, which should be a buffer of **args->data_len** bytes.
Resulting data length is stored in **args->data_len** on successful
command completion.

Security Send data length should not be greater than 4096 bytes to
comply with specification limits.

See: :c:type:`struct nvme_get_log_args <nvme_get_log_args>`

**Return**

0 on success, non-zero on failure


.. c:function:: int nvme_mi_admin_security_recv (nvme_mi_ctrl_t ctrl, struct nvme_security_receive_args *args)

   Perform a Security Receive command on a controller.

**Parameters**

``nvme_mi_ctrl_t ctrl``
  Controller to send command to

``struct nvme_security_receive_args *args``
  Security Receive command arguments

**Description**

Performs a Security Receive Admin command as specified by **args**. Response
data is stored in **args->data**, which should be a buffer of **args->data_len**
bytes. Resulting data length is stored in **args->data_len** on successful
command completion.

Security Receive data length should not be greater than 4096 bytes to
comply with specification limits.

See: :c:type:`struct nvme_get_log_args <nvme_get_log_args>`

**Return**

0 on success, non-zero on failure


