.. _nvme-fabrics-cmds.h:

**nvme-fabrics-cmds.h**


NVMe over Fabrics Specific Commands

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


.. c:function:: void nvme_init_get_log_host_discovery (struct libnvme_passthru_cmd *cmd, bool allhoste, struct nvme_host_discovery_log *log, __u32 len)

   Initialize passthru command for Host Discover

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``bool allhoste``
  All host entries

``struct nvme_host_discovery_log *log``
  User address to store the log page

``__u32 len``
  The allocated length of the log page

**Description**

Initializes the passthru command buffer for the Get Log command with
LID value ``NVME_LOG_LID_HOST_DISCOVERY``


.. c:function:: void nvme_init_get_log_ave_discovery (struct libnvme_passthru_cmd *cmd, struct nvme_ave_discovery_log *log, __u32 len)

   Initialize passthru command for AVE Discovery

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``struct nvme_ave_discovery_log *log``
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


.. c:function:: void nvme_init_cross_ctrl_reset (struct libnvme_passthru_cmd *cmd, __u16 icid, __u8 ciu, __u64 cirn)

   Initialize passthru command for Cross-Controller Reset

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``__u16 icid``
  Impacted Controller ID (ICID)

``__u8 ciu``
  Controller Instance Uniquifier (CIU) of the Impacted Controller

``__u64 cirn``
  Controller Instance Random Number (CIRN) of the Impacted
  Controller

**Description**

Initializes the passthru command buffer for the Cross-Controller Reset
command.


.. c:function:: void nvme_init_fabric_zoning_lookup (struct libnvme_passthru_cmd *cmd, void *data, __u32 len)

   Initialize passthru command for Fabric Zoning Lookup

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``void *data``
  Fabric Zoning Lookup data buffer

``__u32 len``
  Length of **data**

**Description**

Initializes the passthru command buffer for the Fabric Zoning Lookup
command. The returned Zoning Data Key is available in the completion
result, see :c:type:`enum nvme_fabric_zoning_recv_cqe_dw0 <nvme_fabric_zoning_recv_cqe_dw0>` for related fields.


.. c:function:: void nvme_init_fabric_zoning_receive (struct libnvme_passthru_cmd *cmd, __u32 zdk, __u32 zdo, bool zdkc, __u32 numd, void *data, __u32 len)

   Initialize passthru command for Fabric Zoning Receive

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``__u32 zdk``
  Zoning Data Key (ZDK), or Transaction ID if **zdkc** is set

``__u32 zdo``
  Zoning Data Offset (ZDO)

``bool zdkc``
  ZDK Context (ZDKC): if set, **zdk** contains a Transaction ID
  instead of a Zoning Data Key

``__u32 numd``
  Number of Dwords (NUMD) to transfer

``void *data``
  Zoning data buffer

``__u32 len``
  Length of **data**

**Description**

Initializes the passthru command buffer for the Fabric Zoning Receive
command.


.. c:function:: void nvme_init_fabric_zoning_send (struct libnvme_passthru_cmd *cmd, __u32 zdk, __u32 zdo, bool lf, bool zdkc, __u32 numd, void *data, __u32 len)

   Initialize passthru command for Fabric Zoning Send

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``__u32 zdk``
  Zoning Data Key (ZDK), or Transaction ID if **zdkc** is set

``__u32 zdo``
  Zoning Data Offset (ZDO)

``bool lf``
  Last Fragment (LF): set if **data** contains the last fragment
  of the Zoning data structure

``bool zdkc``
  ZDK Context (ZDKC): if set, **zdk** contains a Transaction ID
  instead of a Zoning Data Key

``__u32 numd``
  Number of Dwords (NUMD) to transfer

``void *data``
  Zoning data buffer

``__u32 len``
  Length of **data**

**Description**

Initializes the passthru command buffer for the Fabric Zoning Send
command.


.. c:function:: void nvme_init_send_discovery_log_page (struct libnvme_passthru_cmd *cmd, __u8 rlps, __u8 sct, __u8 sc, __u8 tlsp, __u8 tlid, __u32 ndws, __u64 tlpo, void *data, __u32 len)

   Initialize passthru command for Send Discovery Log Page

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``__u8 rlps``
  Requested Log Page Status (RLPS), see :c:type:`enum
  nvme_send_discovery_log_page_rlps <nvme_send_discovery_log_page_rlps>`

``__u8 sct``
  Status Code Type (SCT), used if **rlps** is
  ``NVME_SDLP_RLPS_NOT_SUCCESSFUL``

``__u8 sc``
  Status Code (SC), used if **rlps** is
  ``NVME_SDLP_RLPS_NOT_SUCCESSFUL``

``__u8 tlsp``
  Transferred Log Specific Parameter (TLSP)

``__u8 tlid``
  Transferred Log Page Identifier (TLID)

``__u32 ndws``
  Number of Dwords (NDWS) transferred

``__u64 tlpo``
  Transferred Log Page Offset (TLPO)

``void *data``
  Transferred log page data buffer

``__u32 len``
  Length of **data**

**Description**

Initializes the passthru command buffer for the Send Discovery Log Page
command.


.. c:function:: void nvme_init_manage_export_port (struct libnvme_passthru_cmd *cmd, __u8 sel, __u8 mos, void *data, __u32 len)

   Initialize passthru command for Manage Exported Port

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``__u8 sel``
  Select (SEL): management operation to perform, see :c:type:`enum
  nvme_manage_export_port_sel <nvme_manage_export_port_sel>`

``__u8 mos``
  Management Operation Specific (MOS): specific to **sel**

``void *data``
  Pointer to data buffer

``__u32 len``
  Length of **data**

**Description**

Initializes the passthru command buffer for the Manage Exported Port
command.


.. c:function:: void nvme_init_manage_export_port_create (struct libnvme_passthru_cmd *cmd, bool gepid, struct nvme_exported_port_create_data *data)

   Initialize passthru command for Manage Exported Port - Create

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``bool gepid``
  Generate Exported Port ID (GEPID): if set, the controller
  generates the Exported Port ID (returned in the CQE result,
  see :c:type:`enum nvme_export_port_create_cqe_dw0 <nvme_export_port_create_cqe_dw0>`); if clear, the
  EPID field in **data** specifies it

``struct nvme_exported_port_create_data *data``
  Create data buffer, see :c:type:`struct nvme_exported_port_create_data <nvme_exported_port_create_data>`

**Description**

Initializes the passthru command buffer for the Manage Exported Port
command with SEL value ``NVME_MANAGE_EXPORT_PORT_SEL_CREATE``.


.. c:function:: void nvme_init_manage_export_port_delete (struct libnvme_passthru_cmd *cmd, struct nvme_exported_port_delete_data *data)

   Initialize passthru command for Manage Exported Port - Delete

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``struct nvme_exported_port_delete_data *data``
  Delete data buffer, see :c:type:`struct nvme_exported_port_delete_data <nvme_exported_port_delete_data>`

**Description**

Initializes the passthru command buffer for the Manage Exported Port
command with SEL value ``NVME_MANAGE_EXPORT_PORT_SEL_DELETE``.


.. c:function:: void nvme_init_get_log_cross_ctrl_reset (struct libnvme_passthru_cmd *cmd, bool rmc, struct nvme_cross_ctrl_reset_log *log, __u32 len)

   Initialize passthru command for Cross-Controller Reset

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``bool rmc``
  Remove Completed (RMC), see :c:type:`enum nvme_cross_ctrl_reset_lsp <nvme_cross_ctrl_reset_lsp>`

``struct nvme_cross_ctrl_reset_log *log``
  User address to store the log page

``__u32 len``
  The allocated length of the log page

**Description**

Initializes the passthru command buffer for the Get Log command with
LID value ``NVME_LOG_LID_CROSS_CTRL_RESET``


.. c:function:: void nvme_init_get_log_lost_host_comm (struct libnvme_passthru_cmd *cmd, bool rae, struct nvme_lost_host_comm_log *log, __u32 len)

   Initialize passthru command for Lost Host Communication

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``bool rae``
  Retain Asynchronous Event

``struct nvme_lost_host_comm_log *log``
  User address to store the log page

``__u32 len``
  The allocated length of the log page

**Description**

Initializes the passthru command buffer for the Get Log command with
LID value ``NVME_LOG_LID_LOST_HOST_COMMUNICATION``


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


.. c:function:: void nvme_init_auth_send (struct libnvme_passthru_cmd *cmd, __u16 spsp, __u8 secp, __u32 tl, void *data, __u32 len)

   Initialize passthru command for Authentication Send

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``__u16 spsp``
  Security Protocol Specific field

``__u8 secp``
  Security Protocol

``__u32 tl``
  Protocol specific transfer length

``void *data``
  Authentication message payload buffer to send

``__u32 len``
  Data length of the payload in bytes

**Description**

Initializes the passthru command buffer for the Fabrics Authentication
Send command, used to send a KX-HMAC-CHAP authentication message (e.g.
:c:type:`struct nvmf_auth_kxchap_reply <nvmf_auth_kxchap_reply>`) to a controller. This is an
NVMe-over-Fabrics specific command that reuses the SECP/SPSP0/SPSP1/TL
field encoding of the Security Send command.


.. c:function:: void nvme_init_auth_receive (struct libnvme_passthru_cmd *cmd, __u16 spsp, __u8 secp, __u32 al, void *data, __u32 len)

   Initialize passthru command for Authentication Receive

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``__u16 spsp``
  Security Protocol Specific field

``__u8 secp``
  Security Protocol

``__u32 al``
  Protocol specific allocation length

``void *data``
  Authentication message payload buffer to receive data into

``__u32 len``
  Data length of the payload in bytes (must match **al**)

**Description**

Initializes the passthru command buffer for the Fabrics Authentication
Receive command, used to receive a KX-HMAC-CHAP authentication message
(e.g. :c:type:`struct nvmf_auth_kxchap_challenge <nvmf_auth_kxchap_challenge>`) from a controller. This is an
NVMe-over-Fabrics specific command that reuses the SECP/SPSP0/SPSP1/AL
field encoding of the Security Receive command.


