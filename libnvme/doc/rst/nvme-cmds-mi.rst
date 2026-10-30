.. _nvme-cmds-mi.h:

**nvme-cmds-mi.h**


NVMe Management Interface Command Definitions

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


.. c:function:: void nvme_init_mi_cmd_flags (struct libnvme_passthru_cmd *cmd, bool ish)

   Initialize command flags for NVMe-MI

**Parameters**

``struct libnvme_passthru_cmd *cmd``
  Passthru command to use

``bool ish``
  Ignore Shutdown (for NVMe-MI command)

**Description**

Initializes the passthru command flags


