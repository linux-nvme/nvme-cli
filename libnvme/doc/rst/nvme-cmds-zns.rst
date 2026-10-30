.. _nvme-cmds-zns.h:

**nvme-cmds-zns.h**


Zoned Namespace Command Set Commands

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


