.. _ioctl.h:

**ioctl.h**


Linux NVMe ioctl interface functions



.. c:struct:: libnvme_passthru_completion

   Async passthru completion record

**Definition**

::

  struct libnvme_passthru_completion {
    struct libnvme_passthru_cmd *cmd;
    void *cookie;
    int status;
  };

**Members**

``cmd``
  Command that completed

``cookie``
  User cookie provided to libnvme_submit_*_passthru()

``status``
  Completion status (NVMe status or negative errno)


**Description**

Used for both admin and IO passthru command completions.


.. c:function:: int libnvme_submit_admin_passthru (struct libnvme_transport_handle *hdl, struct libnvme_passthru_cmd *cmd, void *cookie)

   Queue admin passthru command

**Parameters**

``struct libnvme_transport_handle *hdl``
  Transport handle

``struct libnvme_passthru_cmd *cmd``
  The nvme admin command to send

``void *cookie``
  User-defined opaque value returned at completion

**Description**

Queues **cmd** for asynchronous execution. Completion is reported via
libnvme_reap_passthru().

**Return**

0 on successful queueing, negative error code otherwise.


.. c:function:: int libnvme_exec_admin_passthru (struct libnvme_transport_handle *hdl, struct libnvme_passthru_cmd *cmd)

   Submit an admin passthru command and wait

**Parameters**

``struct libnvme_transport_handle *hdl``
  Transport handle

``struct libnvme_passthru_cmd *cmd``
  The nvme admin command to send

**Description**

Synchronous command execution.

**Return**

The nvme command status if a response was received (see
:c:type:`enum nvme_status_field <nvme_status_field>`), or negative error code otherwise.


.. c:function:: int libnvme_submit_io_passthru (struct libnvme_transport_handle *hdl, struct libnvme_passthru_cmd *cmd, void *cookie)

   Queue IO passthru command

**Parameters**

``struct libnvme_transport_handle *hdl``
  Transport handle

``struct libnvme_passthru_cmd *cmd``
  The nvme IO command to send

``void *cookie``
  User-defined opaque value returned at completion

**Description**

Queues **cmd** for asynchronous execution. Completion is reported via
libnvme_reap_passthru().

**Return**

0 on successful queueing, negative error code otherwise.


.. c:function:: int libnvme_exec_io_passthru (struct libnvme_transport_handle *hdl, struct libnvme_passthru_cmd *cmd)

   Submit an IO passthru command and wait

**Parameters**

``struct libnvme_transport_handle *hdl``
  Transport handle

``struct libnvme_passthru_cmd *cmd``
  The nvme IO command to send

**Description**

Synchronous command execution. Note: when io_uring is enabled, this shares
the async queue. Avoid mixing this with direct async API usage on the same
handle. For batching, use the async API exclusively.

**Return**

The nvme command status if a response was received (see
:c:type:`enum nvme_status_field <nvme_status_field>`), or negative error code otherwise.


.. c:function:: int libnvme_reap_passthru (struct libnvme_transport_handle *hdl, struct libnvme_passthru_completion *completion)

   Reap one async completion

**Parameters**

``struct libnvme_transport_handle *hdl``
  Transport handle

``struct libnvme_passthru_completion *completion``
  Completion output structure

**Description**

Waits for one queued passthru command to complete and stores the
completed command pointer, associated cookie, and completion status in
**completion**.

**Return**

0 on success, negative error code otherwise.


.. c:function:: int libnvme_wait_passthru (struct libnvme_transport_handle *hdl)

   Wait for all pending passthru completions

**Parameters**

``struct libnvme_transport_handle *hdl``
  Transport handle

**Description**

Drains all pending passthru commands from the async queue. Use this
after batching multiple libnvme_submit_admin_passthru() calls when io_uring
is enabled.

**Return**

0 on success, or the first non-zero status encountered.


.. c:function:: int libnvme_reset_subsystem (struct libnvme_transport_handle *hdl)

   Initiate a subsystem reset

**Parameters**

``struct libnvme_transport_handle *hdl``
  Transport handle

**Description**

This should only be sent to controller handles, not to namespaces.

**Return**

Zero if a subsystem reset was initiated or negative error code
otherwise.


.. c:function:: int libnvme_reset_ctrl (struct libnvme_transport_handle *hdl)

   Initiate a controller reset

**Parameters**

``struct libnvme_transport_handle *hdl``
  Transport handle

**Description**

This should only be sent to controller handles, not to namespaces.

**Return**

0 if a reset was initiated or negative error code otherwise.


.. c:function:: int libnvme_rescan_ns (struct libnvme_transport_handle *hdl)

   Initiate a controller rescan

**Parameters**

``struct libnvme_transport_handle *hdl``
  Transport handle

**Description**

This should only be sent to controller handles, not to namespaces.

**Return**

0 if a rescan was initiated or negative error code otherwise.


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

0 if **nsid** was set successfully or negative error code otherwise.


.. c:function:: int libnvme_update_block_size (struct libnvme_transport_handle *hdl, int block_size)

   Update the block size

**Parameters**

``struct libnvme_transport_handle *hdl``
  Transport handle

``int block_size``
  New block size

**Description**

Notify the kernel blkdev to update its block size after a block size change.
This should only be used for namespace handles, not controllers.

**Return**

0 if the block size was updated or a negative error code otherwise.


.. c:function:: int libnvme_reread_partitions (struct libnvme_transport_handle *hdl)

   Reread the partition table

**Parameters**

``struct libnvme_transport_handle *hdl``
  Transport handle

**Description**

Ask the kernel to reread the partition table of a namespace, e.g. after
the namespace has become readable again. This should only be used for
namespace handles, not controllers.

**Return**

0 if the partition table was reread or a negative error code
otherwise.


.. c:function:: int libnvme_read_regs (struct libnvme_transport_handle *hdl, __u32 offset, void *buf, __u32 len)

   Read the controller registers of a PCIe controller

**Parameters**

``struct libnvme_transport_handle *hdl``
  Transport handle

``__u32 offset``
  Offset of the first register in bytes

``void *buf``
  Buffer to store the register values

``__u32 len``
  Number of bytes to read

**Description**

Copies the register range [**offset**, **offset** + **len**) of the controller
into **buf**, using 32-bit MMIO reads. The register values are stored in
little-endian byte order, as they appear in the register map. **offset**
and **len** must be multiples of 4 and the range must be within the first
4 KiB of the register map.

This should only be sent to controller handles, not to namespaces.

**Return**

0 on success or a negative error code otherwise. -ENOTSUP
indicates that the transport has no memory-mapped registers.


.. c:function:: int libnvme_write_reg32 (struct libnvme_transport_handle *hdl, __u32 offset, __u32 value)

   Write a 32-bit controller register of a PCIe controller

**Parameters**

``struct libnvme_transport_handle *hdl``
  Transport handle

``__u32 offset``
  Offset of the register in bytes

``__u32 value``
  Value to write

**Description**

This should only be sent to controller handles, not to namespaces.

**Return**

0 on success or a negative error code otherwise. -ENOTSUP
indicates that the transport has no memory-mapped registers.


.. c:function:: int libnvme_write_reg64 (struct libnvme_transport_handle *hdl, __u32 offset, __u64 value, bool mmio32)

   Write a 64-bit controller register of a PCIe controller

**Parameters**

``struct libnvme_transport_handle *hdl``
  Transport handle

``__u32 offset``
  Offset of the register in bytes

``__u64 value``
  Value to write

``bool mmio32``
  Write the register as two 32-bit values, low half first.
  Some devices do not support 64-bit MMIO.

**Description**

**offset** must be a multiple of 8. This should only be sent to controller
handles, not to namespaces.

**Return**

0 on success or a negative error code otherwise. -ENOTSUP
indicates that the transport has no memory-mapped registers.


