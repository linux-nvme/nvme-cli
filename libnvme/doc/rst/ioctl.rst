.. _ioctl.h:

**ioctl.h**


Linux NVMe ioctl interface functions

.. c:function:: int libnvme_submit_admin_passthru (struct libnvme_transport_handle *hdl, struct libnvme_passthru_cmd *cmd)

   Submit an nvme passthrough admin command

**Parameters**

``struct libnvme_transport_handle *hdl``
  Transport handle

``struct libnvme_passthru_cmd *cmd``
  The nvme admin command to send

**Description**

Uses LIBNVME_IOCTL_ADMIN_CMD for the ioctl request.

**Return**

0 on success, the nvme command status if a response was
received (see :c:type:`enum nvme_status_field <nvme_status_field>`) or a negative error otherwise.


.. c:function:: int libnvme_submit_io_passthru (struct libnvme_transport_handle *hdl, struct libnvme_passthru_cmd *cmd)

   Submit an nvme passthrough command

**Parameters**

``struct libnvme_transport_handle *hdl``
  Transport handle

``struct libnvme_passthru_cmd *cmd``
  The nvme io command to send

**Description**

Uses LIBNVME_IOCTL_IO_CMD for the ioctl request.

**Return**

0 on success, the nvme command status if a response was
received (see :c:type:`enum nvme_status_field <nvme_status_field>`) or a negative error otherwise.


.. c:function:: int libnvme_reset_subsystem (struct libnvme_transport_handle *hdl)

   Initiate a subsystem reset

**Parameters**

``struct libnvme_transport_handle *hdl``
  Transport handle

**Description**

This should only be sent to controller handles, not to namespaces.

**Return**

Zero if a subsystem reset was initiated or -1 with errno set
otherwise.


.. c:function:: int libnvme_reset_ctrl (struct libnvme_transport_handle *hdl)

   Initiate a controller reset

**Parameters**

``struct libnvme_transport_handle *hdl``
  Transport handle

**Description**

This should only be sent to controller handles, not to namespaces.

**Return**

0 if a reset was initiated or -1 with errno set otherwise.


.. c:function:: int libnvme_rescan_ns (struct libnvme_transport_handle *hdl)

   Initiate a controller rescan

**Parameters**

``struct libnvme_transport_handle *hdl``
  Transport handle

**Description**

This should only be sent to controller handles, not to namespaces.

**Return**

0 if a rescan was initiated or -1 with errno set otherwise.


.. c:function:: int libnvme_get_nsid (struct libnvme_transport_handle *hdl, __u32 *nsid)

   Retrieve the NSID from a namespace file descriptor

**Parameters**

``struct libnvme_transport_handle *hdl``
  Transport handle

``__u32 *nsid``
  User pointer to namespace id

**Description**

This should only be sent to namespace handles, not to controllers. The
kernel's interface returns the nsid as the return value. This is unfortunate
for many architectures that are incapable of allowing distinguishing a
namespace id > 0x80000000 from a negative error number.

**Return**

0 if **nsid** was set successfully or -1 with errno set otherwise.


