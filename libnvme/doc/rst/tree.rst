.. _tree.h:

**tree.h**


libnvme tree object interface

.. c:function:: void libnvme_skip_namespaces (struct libnvme_global_ctx *ctx)

   Skip namespace scanning

**Parameters**

``struct libnvme_global_ctx *ctx``
  struct libnvme_global_ctx object

**Description**

Sets a flag to skip namespaces during scanning.


.. c:function:: void libnvme_release_fds (struct libnvme_global_ctx *ctx)

   Close all opened file descriptors in the tree

**Parameters**

``struct libnvme_global_ctx *ctx``
  struct libnvme_global_ctx object

**Description**

Controller and Namespace objects cache the file descriptors
of opened nvme devices. This API can be used to close and
clear all cached fds in the tree.


.. c:function:: struct libnvme_host * libnvme_first_host (struct libnvme_global_ctx *ctx)

   Start host iterator

**Parameters**

``struct libnvme_global_ctx *ctx``
  struct libnvme_global_ctx object

**Return**

First :c:type:`struct libnvme_host <libnvme_host>` object in an iterator


.. c:function:: struct libnvme_host * libnvme_next_host (struct libnvme_global_ctx *ctx, struct libnvme_host *h)

   Next host iterator

**Parameters**

``struct libnvme_global_ctx *ctx``
  struct libnvme_global_ctx object

``struct libnvme_host *h``
  Previous :c:type:`struct libnvme_host <libnvme_host>` iterator

**Return**

Next :c:type:`struct libnvme_host <libnvme_host>` object in an iterator


.. c:function:: struct libnvme_global_ctx * libnvme_host_get_global_ctx (struct libnvme_host *h)

   Returns libnvme_global_ctx object

**Parameters**

``struct libnvme_host *h``
  :c:type:`struct libnvme_host <libnvme_host>` object

**Return**

:c:type:`struct libnvme_global_ctx <libnvme_global_ctx>` object from **h**


.. c:function:: int libnvme_get_host (struct libnvme_global_ctx *ctx, const char *hostnqn, const char *hostid, struct libnvme_host **h)

   Returns a host object

**Parameters**

``struct libnvme_global_ctx *ctx``
  struct libnvme_global_ctx object

``const char *hostnqn``
  Host NQN (optional)

``const char *hostid``
  Host ID (optional)

``struct libnvme_host **h``
  :c:type:`struct libnvme_host <libnvme_host>` object to return

**Description**

Returns a host object based on the hostnqn/hostid values or the default if
hostnqn/hostid are NULL.

**Return**

0 on success, negative error code otherwise.


.. c:function:: struct libnvme_subsystem * libnvme_first_subsystem (struct libnvme_host *h)

   Start subsystem iterator

**Parameters**

``struct libnvme_host *h``
  :c:type:`struct libnvme_host <libnvme_host>` object

**Return**

first :c:type:`struct libnvme_subsystem <libnvme_subsystem>` object in an iterator


.. c:function:: struct libnvme_subsystem * libnvme_next_subsystem (struct libnvme_host *h, struct libnvme_subsystem *s)

   Next subsystem iterator

**Parameters**

``struct libnvme_host *h``
  :c:type:`struct libnvme_host <libnvme_host>` object

``struct libnvme_subsystem *s``
  Previous :c:type:`struct libnvme_subsystem <libnvme_subsystem>` iterator

**Return**

next :c:type:`struct libnvme_subsystem <libnvme_subsystem>` object in an iterator


.. c:function:: int libnvme_get_subsystem (struct libnvme_global_ctx *ctx, struct libnvme_host *h, const char *name, const char *subsysnqn, struct libnvme_subsystem **s)

   Returns struct libnvme_subsystem object

**Parameters**

``struct libnvme_global_ctx *ctx``
  struct libnvme_global_ctx object

``struct libnvme_host *h``
  :c:type:`struct libnvme_host <libnvme_host>` object

``const char *name``
  Name of the subsystem (may be NULL)

``const char *subsysnqn``
  Subsystem NQN

``struct libnvme_subsystem **s``
  struct libnvme_subsystem object

**Description**

Returns an :c:type:`struct libnvme_subsystem <libnvme_subsystem>` object in **h** base on **name** (if present)
and **subsysnqn** or create one if not found.


.. c:function:: void libnvme_free_subsystem (struct libnvme_subsystem *s)

   Free a subsystem

**Parameters**

``struct libnvme_subsystem *s``
  subsystem

**Description**

Frees **s** and all related objects.


.. c:function:: struct libnvme_host * libnvme_subsystem_get_host (struct libnvme_subsystem *s)

   Returns struct libnvme_host object

**Parameters**

``struct libnvme_subsystem *s``
  subsystem

**Return**

:c:type:`struct libnvme_host <libnvme_host>` object from **s**


.. c:function:: struct libnvme_ns * libnvme_ctrl_first_ns (struct libnvme_ctrl *c)

   Start namespace iterator

**Parameters**

``struct libnvme_ctrl *c``
  Controller instance

**Return**

First :c:type:`struct libnvme_ns <libnvme_ns>` object of an **c** iterator


.. c:function:: struct libnvme_ns * libnvme_ctrl_next_ns (struct libnvme_ctrl *c, struct libnvme_ns *n)

   Next namespace iterator

**Parameters**

``struct libnvme_ctrl *c``
  Controller instance

``struct libnvme_ns *n``
  Previous struct libnvme_ns iterator

**Return**

Next struct libnvme_ns object of an **c** iterator


.. c:function:: struct libnvme_path * libnvme_ctrl_first_path (struct libnvme_ctrl *c)

   Start path iterator

**Parameters**

``struct libnvme_ctrl *c``
  Controller instance

**Return**

First :c:type:`struct libnvme_path <libnvme_path>` object of an **c** iterator


.. c:function:: struct libnvme_path * libnvme_ctrl_next_path (struct libnvme_ctrl *c, struct libnvme_path *p)

   Next path iterator

**Parameters**

``struct libnvme_ctrl *c``
  Controller instance

``struct libnvme_path *p``
  Previous :c:type:`struct libnvme_path <libnvme_path>` object of an **c** iterator

**Return**

Next :c:type:`struct libnvme_path <libnvme_path>` object of an **c** iterator


.. c:function:: struct libnvme_ctrl * libnvme_subsystem_first_ctrl (struct libnvme_subsystem *s)

   First ctrl iterator

**Parameters**

``struct libnvme_subsystem *s``
  :c:type:`struct libnvme_subsystem <libnvme_subsystem>` object

**Return**

First controller of an **s** iterator


.. c:function:: struct libnvme_ctrl * libnvme_subsystem_next_ctrl (struct libnvme_subsystem *s, struct libnvme_ctrl *c)

   Next ctrl iterator

**Parameters**

``struct libnvme_subsystem *s``
  :c:type:`struct libnvme_subsystem <libnvme_subsystem>` object

``struct libnvme_ctrl *c``
  Previous controller instance of an **s** iterator

**Return**

Next controller of an **s** iterator


.. c:function:: struct libnvme_path * libnvme_namespace_first_path (struct libnvme_ns *ns)

   Start path iterator

**Parameters**

``struct libnvme_ns *ns``
  Namespace instance

**Return**

First :c:type:`struct libnvme_path <libnvme_path>` object of an **ns** iterator


.. c:function:: struct libnvme_path * libnvme_namespace_next_path (struct libnvme_ns *ns, struct libnvme_path *p)

   Next path iterator

**Parameters**

``struct libnvme_ns *ns``
  Namespace instance

``struct libnvme_path *p``
  Previous :c:type:`struct libnvme_path <libnvme_path>` object of an **ns** iterator

**Return**

Next :c:type:`struct libnvme_path <libnvme_path>` object of an **ns** iterator


.. c:function:: struct libnvme_ns * libnvme_subsystem_first_ns (struct libnvme_subsystem *s)

   Start namespace iterator

**Parameters**

``struct libnvme_subsystem *s``
  :c:type:`struct libnvme_subsystem <libnvme_subsystem>` object

**Return**

First :c:type:`struct libnvme_ns <libnvme_ns>` object of an **s** iterator


.. c:function:: struct libnvme_ns * libnvme_subsystem_next_ns (struct libnvme_subsystem *s, struct libnvme_ns *n)

   Next namespace iterator

**Parameters**

``struct libnvme_subsystem *s``
  :c:type:`struct libnvme_subsystem <libnvme_subsystem>` object

``struct libnvme_ns *n``
  Previous :c:type:`struct libnvme_ns <libnvme_ns>` iterator

**Return**

Next :c:type:`struct libnvme_ns <libnvme_ns>` object of an **s** iterator


.. c:macro:: libnvme_for_each_host_safe

``libnvme_for_each_host_safe (r, h, _h)``

   Traverse host list

**Parameters**

``r``
  :c:type:`libnvme_root_t` object

``h``
  :c:type:`struct libnvme_host <libnvme_host>` object

``_h``
  Temporary :c:type:`struct libnvme_host <libnvme_host>` object


.. c:macro:: libnvme_for_each_host

``libnvme_for_each_host (r, h)``

   Traverse host list

**Parameters**

``r``
  :c:type:`libnvme_root_t` object

``h``
  :c:type:`struct libnvme_host <libnvme_host>` object


.. c:macro:: libnvme_for_each_subsystem_safe

``libnvme_for_each_subsystem_safe (h, s, _s)``

   Traverse subsystems

**Parameters**

``h``
  :c:type:`struct libnvme_host <libnvme_host>` object

``s``
  :c:type:`struct libnvme_subsystem <libnvme_subsystem>` object

``_s``
  Temporary :c:type:`struct libnvme_subsystem <libnvme_subsystem>` object


.. c:macro:: libnvme_for_each_subsystem

``libnvme_for_each_subsystem (h, s)``

   Traverse subsystems

**Parameters**

``h``
  :c:type:`struct libnvme_host <libnvme_host>` object

``s``
  :c:type:`struct libnvme_subsystem <libnvme_subsystem>` object


.. c:macro:: libnvme_subsystem_for_each_ctrl_safe

``libnvme_subsystem_for_each_ctrl_safe (s, c, _c)``

   Traverse controllers

**Parameters**

``s``
  :c:type:`struct libnvme_subsystem <libnvme_subsystem>` object

``c``
  Controller instance

``_c``
  A :c:type:`struct libnvme_ctrl <libnvme_ctrl>` node to use as temporary storage


.. c:macro:: libnvme_subsystem_for_each_ctrl

``libnvme_subsystem_for_each_ctrl (s, c)``

   Traverse controllers

**Parameters**

``s``
  :c:type:`struct libnvme_subsystem <libnvme_subsystem>` object

``c``
  Controller instance


.. c:macro:: libnvme_ctrl_for_each_ns_safe

``libnvme_ctrl_for_each_ns_safe (c, n, _n)``

   Traverse namespaces

**Parameters**

``c``
  Controller instance

``n``
  :c:type:`struct libnvme_ns <libnvme_ns>` object

``_n``
  A :c:type:`struct libnvme_ns <libnvme_ns>` node to use as temporary storage


.. c:macro:: libnvme_ctrl_for_each_ns

``libnvme_ctrl_for_each_ns (c, n)``

   Traverse namespaces

**Parameters**

``c``
  Controller instance

``n``
  :c:type:`struct libnvme_ns <libnvme_ns>` object


.. c:macro:: libnvme_ctrl_for_each_path_safe

``libnvme_ctrl_for_each_path_safe (c, p, _p)``

   Traverse paths

**Parameters**

``c``
  Controller instance

``p``
  :c:type:`struct libnvme_path <libnvme_path>` object

``_p``
  A :c:type:`struct libnvme_path <libnvme_path>` node to use as temporary storage


.. c:macro:: libnvme_ctrl_for_each_path

``libnvme_ctrl_for_each_path (c, p)``

   Traverse paths

**Parameters**

``c``
  Controller instance

``p``
  :c:type:`struct libnvme_path <libnvme_path>` object


.. c:macro:: libnvme_subsystem_for_each_ns_safe

``libnvme_subsystem_for_each_ns_safe (s, n, _n)``

   Traverse namespaces

**Parameters**

``s``
  :c:type:`struct libnvme_subsystem <libnvme_subsystem>` object

``n``
  :c:type:`struct libnvme_ns <libnvme_ns>` object

``_n``
  A :c:type:`struct libnvme_ns <libnvme_ns>` node to use as temporary storage


.. c:macro:: libnvme_subsystem_for_each_ns

``libnvme_subsystem_for_each_ns (s, n)``

   Traverse namespaces

**Parameters**

``s``
  :c:type:`struct libnvme_subsystem <libnvme_subsystem>` object

``n``
  :c:type:`struct libnvme_ns <libnvme_ns>` object


.. c:macro:: libnvme_namespace_for_each_path_safe

``libnvme_namespace_for_each_path_safe (n, p, _p)``

   Traverse paths

**Parameters**

``n``
  Namespace instance

``p``
  :c:type:`struct libnvme_path <libnvme_path>` object

``_p``
  A :c:type:`struct libnvme_path <libnvme_path>` node to use as temporary storage


.. c:macro:: libnvme_namespace_for_each_path

``libnvme_namespace_for_each_path (n, p)``

   Traverse paths

**Parameters**

``n``
  Namespace instance

``p``
  :c:type:`struct libnvme_path <libnvme_path>` object


.. c:function:: const char * libnvme_ns_get_firmware (struct libnvme_ns *n)

   Firmware string of a namespace

**Parameters**

``struct libnvme_ns *n``
  Namespace instance

**Return**

Firmware string of **n**


.. c:function:: const char * libnvme_ns_get_serial (struct libnvme_ns *n)

   Serial number of a namespace

**Parameters**

``struct libnvme_ns *n``
  Namespace instance

**Return**

Serial number string of **n**


.. c:function:: const char * libnvme_ns_get_model (struct libnvme_ns *n)

   Model of a namespace

**Parameters**

``struct libnvme_ns *n``
  Namespace instance

**Return**

Model string of **n**


.. c:function:: struct libnvme_subsystem * libnvme_ns_get_subsystem (struct libnvme_ns *n)

   :c:type:`struct libnvme_subsystem <libnvme_subsystem>` of a namespace

**Parameters**

``struct libnvme_ns *n``
  Namespace instance

**Return**

struct libnvme_subsystem object of **n**


.. c:function:: struct libnvme_ctrl * libnvme_ns_get_ctrl (struct libnvme_ns *n)

   :c:type:`struct libnvme_ctrl <libnvme_ctrl>` of a namespace

**Parameters**

``struct libnvme_ns *n``
  Namespace instance

**Description**

struct libnvme_ctrl object may be NULL for a multipathed namespace

**Return**

struct libnvme_ctrl object of **n** if present


.. c:function:: void libnvme_free_ns (struct libnvme_ns *n)

   Free a namespace object

**Parameters**

``struct libnvme_ns *n``
  Namespace instance


.. c:function:: int libnvme_ns_read (struct libnvme_ns *n, void *buf, off_t offset, size_t count)

   Read from a namespace

**Parameters**

``struct libnvme_ns *n``
  Namespace instance

``void *buf``
  Buffer into which the data will be transferred

``off_t offset``
  LBA offset of **n**

``size_t count``
  Number of sectors in **buf**

**Return**

Number of sectors read or -1 on error.


.. c:function:: int libnvme_ns_write (struct libnvme_ns *n, void *buf, off_t offset, size_t count)

   Write to a namespace

**Parameters**

``struct libnvme_ns *n``
  Namespace instance

``void *buf``
  Buffer with data to be written

``off_t offset``
  LBA offset of **n**

``size_t count``
  Number of sectors in **buf**

**Return**

Number of sectors written or -1 on error


.. c:function:: int libnvme_ns_verify (struct libnvme_ns *n, off_t offset, size_t count)

   Verify data on a namespace

**Parameters**

``struct libnvme_ns *n``
  Namespace instance

``off_t offset``
  LBA offset of **n**

``size_t count``
  Number of sectors to be verified

**Return**

Number of sectors verified


.. c:function:: int libnvme_ns_compare (struct libnvme_ns *n, void *buf, off_t offset, size_t count)

   Compare data on a namespace

**Parameters**

``struct libnvme_ns *n``
  Namespace instance

``void *buf``
  Buffer with data to be compared

``off_t offset``
  LBA offset of **n**

``size_t count``
  Number of sectors in **buf**

**Return**

Number of sectors compared


.. c:function:: int libnvme_ns_write_zeros (struct libnvme_ns *n, off_t offset, size_t count)

   Write zeros to a namespace

**Parameters**

``struct libnvme_ns *n``
  Namespace instance

``off_t offset``
  LBA offset in **n**

``size_t count``
  Number of sectors to be written

**Return**

Number of sectors written


.. c:function:: int libnvme_ns_write_uncorrectable (struct libnvme_ns *n, off_t offset, size_t count)

   Issus a 'write uncorrectable' command

**Parameters**

``struct libnvme_ns *n``
  Namespace instance

``off_t offset``
  LBA offset in **n**

``size_t count``
  Number of sectors to be written

**Return**

Number of sectors written


.. c:function:: int libnvme_ns_flush (struct libnvme_ns *n)

   Flush data to a namespace

**Parameters**

``struct libnvme_ns *n``
  Namespace instance

**Return**

0 on success, negative error code otherwise.


.. c:function:: int libnvme_ns_identify (struct libnvme_ns *n, struct nvme_id_ns *ns)

   Issue an 'identify namespace' command

**Parameters**

``struct libnvme_ns *n``
  Namespace instance

``struct nvme_id_ns *ns``
  :c:type:`nvme_id_ns` buffer

**Description**

Writes the data returned by the 'identify namespace' command
into **ns**.

**Return**

0 on success, negative error code otherwise.


.. c:function:: int libnvme_ns_identify_descs (struct libnvme_ns *n, struct nvme_ns_id_desc *descs)

   Issue an 'identify descriptors' command

**Parameters**

``struct libnvme_ns *n``
  Namespace instance

``struct nvme_ns_id_desc *descs``
  List of identify descriptors

**Description**

Writes the data returned by the 'identify descriptors' command
into **descs**.

**Return**

0 on success, negative error code otherwise.


.. c:function:: struct libnvme_ctrl * libnvme_path_get_ctrl (struct libnvme_path *p)

   Parent controller of an struct libnvme_path object

**Parameters**

``struct libnvme_path *p``
  :c:type:`struct libnvme_path <libnvme_path>` object

**Return**

Parent controller if present


.. c:function:: struct libnvme_ns * libnvme_path_get_ns (struct libnvme_path *p)

   Parent namespace of an struct libnvme_path object

**Parameters**

``struct libnvme_path *p``
  :c:type:`struct libnvme_path <libnvme_path>` object

**Return**

Parent namespace if present


.. c:function:: void libnvme_path_reset_stat (struct libnvme_path *p)

   Resets namespace path nvme stat

**Parameters**

``struct libnvme_path *p``
  :c:type:`struct libnvme_path <libnvme_path>` object


.. c:function:: int libnvme_path_update_stat (struct libnvme_path *p, bool diffstat)

   Update stat of an nvme_path_t object

**Parameters**

``struct libnvme_path *p``
  :c:type:`struct libnvme_path <libnvme_path>` object

``bool diffstat``
  If set to true then getters return the diff stat otherwise
  return the current absolute stat

**Return**

0 on success, negative error code otherwise.


.. c:function:: unsigned long libnvme_path_get_read_ios (struct libnvme_path *p)

   Calculate and return read IOs

**Parameters**

``struct libnvme_path *p``
  :c:type:`struct libnvme_path <libnvme_path>` object

**Return**

Num of read IOs processed between two stat samples


.. c:function:: unsigned long libnvme_path_get_write_ios (struct libnvme_path *p)

   Get write I/Os

**Parameters**

``struct libnvme_path *p``
  :c:type:`struct libnvme_path <libnvme_path>` object

**Return**

Num of write I/Os processed between two stat samples


.. c:function:: unsigned int libnvme_path_get_read_ticks (struct libnvme_path *p)

   Get read I/O ticks

**Parameters**

``struct libnvme_path *p``
  :c:type:`struct libnvme_path <libnvme_path>` object

**Return**

Time, in milliseconds, sepnt processing read I/O requests
             between two stat samples


.. c:function:: unsigned long long libnvme_path_get_read_sectors (struct libnvme_path *p)

   Get read I/O sectors

**Parameters**

``struct libnvme_path *p``
  :c:type:`struct libnvme_path <libnvme_path>` object

**Return**

Number of sectors read from the device between two stat samples


.. c:function:: unsigned long long libnvme_path_get_write_sectors (struct libnvme_path *p)

   Get write I/O sectors

**Parameters**

``struct libnvme_path *p``
  :c:type:`struct libnvme_path <libnvme_path>` object

**Return**

Num of sectors written to the device between two stat samples


.. c:function:: unsigned int libnvme_path_get_write_ticks (struct libnvme_path *p)

   Get write I/O ticks

**Parameters**

``struct libnvme_path *p``
  :c:type:`struct libnvme_path <libnvme_path>` object

**Return**

Time, in milliseconds, sepnt processing write I/O requests
             between two stat samples


.. c:function:: double libnvme_path_get_stat_interval (struct libnvme_path *p)

   Get interval between two stat samples

**Parameters**

``struct libnvme_path *p``
  :c:type:`struct libnvme_path <libnvme_path>` object

**Return**

Interval, in milliseconds between collection of two consecutive
             stat samples


.. c:function:: unsigned int libnvme_path_get_io_ticks (struct libnvme_path *p)

   Get I/O ticks

**Parameters**

``struct libnvme_path *p``
  :c:type:`struct libnvme_path <libnvme_path>` object

**Return**

Time consumed, in milliseconds, processing I/O requests between
             two stat samples


.. c:function:: unsigned int libnvme_path_get_inflights (struct libnvme_path *p)

   Inflight IOs for nvme_path_t object

**Parameters**

``struct libnvme_path *p``
  :c:type:`struct libnvme_path <libnvme_path>` object

**Return**

Inflight number of IOs


.. c:function:: struct libnvme_transport_handle * libnvme_ctrl_get_transport_handle (struct libnvme_ctrl *c)

   Get associated transport handle

**Parameters**

``struct libnvme_ctrl *c``
  Controller instance

**Description**

libnvme will open() the device (if not already opened) and keep an
internal copy of the link handle. Following calls to this API retrieve
the internal cached copy of the link handle. The file will remain
opened and the handle will remain cached until the controller object
is deleted or libnvme_ctrl_release_transport_handle() is called.

**Return**

Link handle associated with **c** or NULL


.. c:function:: void libnvme_ctrl_release_transport_handle (struct libnvme_ctrl *c)

   Free transport handle from controller object

**Parameters**

``struct libnvme_ctrl *c``
  Controller instance


.. c:function:: char * libnvme_ctrl_get_src_addr (struct libnvme_ctrl *c, char *src_addr, size_t src_addr_len)

   Extract src_addr from the c->address string

**Parameters**

``struct libnvme_ctrl *c``
  Controller instance

``char *src_addr``
  Where to copy the src_addr. Size must be at least
  INET6_ADDRSTRLEN.

``size_t src_addr_len``
  Length of the buffer **src_addr**.

**Return**

Pointer to **src_addr** on success. NULL on failure to extract the
src_addr.


.. c:function:: const char * libnvme_ctrl_get_state (struct libnvme_ctrl *c)

   Running state of a controller

**Parameters**

``struct libnvme_ctrl *c``
  Controller instance

**Return**

String indicating the running state of **c**


.. c:function:: bool libnvme_transport_is_fabric (const char *transport)

   True for a fabrics transport string

**Parameters**

``const char *transport``
  Transport name, e.g. "tcp", "pcie"

**Description**

A transport is either local (pcie, apple-nvme) or NVMe-over-Fabrics
(tcp, rdma, fc, loop). Use this when only the transport string is
available, e.g. before a controller exists to ask
libnvme_ctrl_is_transport_fabric() instead.

**Return**

true if **transport** is a fabrics transport, false if local.


.. c:function:: bool libnvme_ctrl_is_transport_fabric (struct libnvme_ctrl *c)

   True for a fabrics transport

**Parameters**

``struct libnvme_ctrl *c``
  Controller instance

**Description**

A controller is reachable either over a local transport (pcie,
apple-nvme) or over NVMe-over-Fabrics (tcp, rdma, fc, loop).

**Return**

true if **c** uses a fabrics transport, false if local.


.. c:function:: char * libnvme_ctrl_owner (struct libnvme_ctrl *c)

   Registered orchestrator owner of a controller

**Parameters**

``struct libnvme_ctrl *c``
  Controller instance

**Description**

Looks up the controller's "owner" entry in the ownership registry.  In a
build without fabrics support this always returns NULL.

**Return**

a newly allocated owner string (the caller frees), or NULL if the
controller is unowned, local (non-fabrics), or the registry is unreadable.


.. c:function:: struct libnvme_subsystem * libnvme_ctrl_get_subsystem (struct libnvme_ctrl *c)

   Parent subsystem of a controller

**Parameters**

``struct libnvme_ctrl *c``
  Controller instance

**Return**

Parent struct libnvme_subsystem object


.. c:function:: const char * libnvme_ns_head_get_sysfs_dir (struct libnvme_ns_head *head)

   sysfs dir of namespave head

**Parameters**

``struct libnvme_ns_head *head``
  namespace head instance

**Return**

sysfs directory name of **head**


.. c:function:: int libnvme_ns_update_stat (struct libnvme_ns *n, bool diffstat)

   update the nvme namespace stat

**Parameters**

``struct libnvme_ns *n``
  :c:type:`struct libnvme_ns <libnvme_ns>` object

``bool diffstat``
  If set to true then getters return the diff stat otherwise
  return the current absolute stat

**Return**

0 on success, negative error code otherwise.


.. c:function:: void libnvme_ns_reset_stat (struct libnvme_ns *n)

   Resets nvme namespace stat

**Parameters**

``struct libnvme_ns *n``
  :c:type:`struct libnvme_ns <libnvme_ns>` object


.. c:function:: unsigned int libnvme_ns_get_inflights (struct libnvme_ns *n)

   Inflight IOs for nvme_ns_t object

**Parameters**

``struct libnvme_ns *n``
  :c:type:`struct libnvme_ns <libnvme_ns>` object

**Return**

Inflight number of IOs


.. c:function:: unsigned int libnvme_ns_get_io_ticks (struct libnvme_ns *n)

   Get IO ticks

**Parameters**

``struct libnvme_ns *n``
  :c:type:`struct libnvme_ns <libnvme_ns>` object

**Return**

Time consumed, in milliseconds, processing I/O requests between
             two stat samples


.. c:function:: unsigned int libnvme_ns_get_read_ticks (struct libnvme_ns *n)

   Get read I/O ticks

**Parameters**

``struct libnvme_ns *n``
  :c:type:`struct libnvme_ns <libnvme_ns>` object

**Return**

Time, in milliseconds, sepnt processing read I/O requests
             between two stat samples


.. c:function:: unsigned int libnvme_ns_get_write_ticks (struct libnvme_ns *n)

   Get write I/O ticks

**Parameters**

``struct libnvme_ns *n``
  :c:type:`struct libnvme_ns <libnvme_ns>` object

**Return**

Time, in milliseconds, sepnt processing write I/O requests
             between two stat samples


.. c:function:: double libnvme_ns_get_stat_interval (struct libnvme_ns *n)

   Get interval between two stat samples

**Parameters**

``struct libnvme_ns *n``
  :c:type:`struct libnvme_ns <libnvme_ns>` object

**Return**

Interval, in milliseconds, between collection of two consecutive
             stat samples


.. c:function:: unsigned long libnvme_ns_get_read_ios (struct libnvme_ns *n)

   Get num of read I/Os

**Parameters**

``struct libnvme_ns *n``
  :c:type:`struct libnvme_ns <libnvme_ns>` object

**Return**

Num of read IOs processed between two stat samples


.. c:function:: unsigned long libnvme_ns_get_write_ios (struct libnvme_ns *n)

   Get num of write I/Os

**Parameters**

``struct libnvme_ns *n``
  :c:type:`struct libnvme_ns <libnvme_ns>` object

**Return**

Num of write IOs processed between two consecutive stat samples


.. c:function:: unsigned long long libnvme_ns_get_read_sectors (struct libnvme_ns *n)

   Get num of read sectors

**Parameters**

``struct libnvme_ns *n``
  :c:type:`struct libnvme_ns <libnvme_ns>` object

**Return**

Num of sectors read from the device between two stat samples


.. c:function:: unsigned long long libnvme_ns_get_write_sectors (struct libnvme_ns *n)

   Get num of write sectors

**Parameters**

``struct libnvme_ns *n``
  :c:type:`struct libnvme_ns <libnvme_ns>` object

**Return**

Num of sectors written to the device between two stat samples


.. c:function:: int libnvme_ctrl_identify (struct libnvme_ctrl *c, struct nvme_id_ctrl *id)

   Issues an 'identify controller' command

**Parameters**

``struct libnvme_ctrl *c``
  Controller instance

``struct nvme_id_ctrl *id``
  Identify controller data structure

**Description**

Issues an 'identify controller' command to **c** and copies the
data into **id**.

**Return**

0 on success, negative error code otherwise.


.. c:function:: int libnvme_scan_ctrl (struct libnvme_global_ctx *ctx, const char *name, struct libnvme_ctrl **c)

   Scan on a controller

**Parameters**

``struct libnvme_global_ctx *ctx``
  struct libnvme_global_ctx object

``const char *name``
  Name of the controller

``struct libnvme_ctrl **c``
  **struct** libnvme_ctrl object to return

**Description**

Scans a controller with sysfs name **name** and add it to **r**.

**Return**

0 on success, negative error code otherwise.


.. c:function:: void libnvme_rescan_ctrl (struct libnvme_ctrl *c)

   Rescan an existing controller

**Parameters**

``struct libnvme_ctrl *c``
  Controller instance


.. c:function:: int libnvme_init_ctrl (struct libnvme_host *h, struct libnvme_ctrl *c, int instance)

   Initialize struct libnvme_ctrl object for an existing controller.

**Parameters**

``struct libnvme_host *h``
  struct libnvme_host object

``struct libnvme_ctrl *c``
  struct libnvme_ctrl object

``int instance``
  Instance number (e.g. 1 for nvme1)

**Return**

0 on success, negative error code otherwise.


.. c:function:: void libnvme_free_ctrl (struct libnvme_ctrl *c)

   Free controller

**Parameters**

``struct libnvme_ctrl *c``
  Controller instance


.. c:function:: void libnvme_unlink_ctrl (struct libnvme_ctrl *c)

   Unlink controller

**Parameters**

``struct libnvme_ctrl *c``
  Controller instance


.. c:function:: int libnvme_scan_topology (struct libnvme_global_ctx *ctx, libnvme_scan_filter_t f, void *f_args)

   Scan NVMe topology and apply filter

**Parameters**

``struct libnvme_global_ctx *ctx``
  struct libnvme_global_ctx object

``libnvme_scan_filter_t f``
  filter to apply

``void *f_args``
  user-specified argument to **f**

**Description**

Scans the NVMe topology and filters out the resulting elements
by applying **f**.

**Return**

0 on success, negative error code otherwise.


.. c:function:: void libnvme_host_release_fds (struct libnvme_host *h)

   Close all opened file descriptors under host

**Parameters**

``struct libnvme_host *h``
  struct libnvme_host object

**Description**

Controller and Namespace objects cache the file descriptors
of opened nvme devices. This API can be used to close and
clear all cached fds under this host.


.. c:function:: void libnvme_free_host (struct libnvme_host *h)

   Free struct libnvme_host object

**Parameters**

``struct libnvme_host *h``
  struct libnvme_host object


.. c:function:: int libnvme_refresh_topology (struct libnvme_global_ctx *ctx)

   Refresh libnvme_root_t object contents

**Parameters**

``struct libnvme_global_ctx *ctx``
  :c:type:`struct libnvme_global_ctx <libnvme_global_ctx>` object

**Description**

Removes all elements in **r** and rescans the existing topology.

**Return**

0 on success, negative error code otherwise.


.. c:function:: char * libnvme_get_attr (const char *d, const char *attr)

   Read sysfs attribute

**Parameters**

``const char *d``
  sysfs directory

``const char *attr``
  sysfs attribute name

**Return**

A newly allocated string with the contents of **attr** (the caller
        frees), or ``NULL`` in case of an empty value or error.


.. c:function:: char * libnvme_get_subsys_attr (struct libnvme_subsystem *s, const char *attr)

   Read subsystem sysfs attribute

**Parameters**

``struct libnvme_subsystem *s``
  struct libnvme_subsystem object

``const char *attr``
  sysfs attribute name

**Return**

A newly allocated string with the contents of **attr** (the caller
        frees), or ``NULL`` in case of an empty value or error.


.. c:function:: char * libnvme_get_ctrl_attr (struct libnvme_ctrl *c, const char *attr)

   Read controller sysfs attribute

**Parameters**

``struct libnvme_ctrl *c``
  Controller instance

``const char *attr``
  sysfs attribute name

**Return**

A newly allocated string with the contents of **attr** (the caller
        frees), or ``NULL`` in case of an empty value or error.


.. c:function:: char * libnvme_get_ns_attr (struct libnvme_ns *n, const char *attr)

   Read namespace sysfs attribute

**Parameters**

``struct libnvme_ns *n``
  struct libnvme_ns object

``const char *attr``
  sysfs attribute name

**Return**

A newly allocated string with the contents of **attr** (the caller
        frees), or ``NULL`` in case of an empty value or error.


.. c:function:: struct libnvme_ns * libnvme_subsystem_lookup_namespace (struct libnvme_subsystem *s, __u32 nsid)

   lookup namespace by NSID

**Parameters**

``struct libnvme_subsystem *s``
  struct libnvme_subsystem object

``__u32 nsid``
  Namespace id

**Return**

struct libnvme_ns of the namespace with id **nsid** in subsystem **s**


.. c:function:: void libnvme_subsystem_release_fds (struct libnvme_subsystem *s)

   Close all opened fds under subsystem

**Parameters**

``struct libnvme_subsystem *s``
  struct libnvme_subsystem object

**Description**

Controller and Namespace objects cache the file descriptors
of opened nvme devices. This API can be used to close and
clear all cached fds under this subsystem.


.. c:function:: char * libnvme_get_path_attr (struct libnvme_path *p, const char *attr)

   Read path sysfs attribute

**Parameters**

``struct libnvme_path *p``
  struct libnvme_path object

``const char *attr``
  sysfs attribute name

**Return**

A newly allocated string with the contents of **attr** (the caller
        frees), or ``NULL`` in case of an empty value or error.


.. c:function:: int libnvme_scan_namespace (struct libnvme_global_ctx *ctx, const char *name, struct libnvme_ns **ns)

   scan namespace based on sysfs name

**Parameters**

``struct libnvme_global_ctx *ctx``
  :c:type:`struct libnvme_global_ctx <libnvme_global_ctx>` object

``const char *name``
  sysfs name of the namespace to scan

``struct libnvme_ns **ns``
  :c:type:`struct libnvme_ns <libnvme_ns>` object to return

**Return**

0 on success, negative error code otherwise.


