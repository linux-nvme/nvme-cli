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


.. c:function:: libnvme_host_t libnvme_first_host (struct libnvme_global_ctx *ctx)

   Start host iterator

**Parameters**

``struct libnvme_global_ctx *ctx``
  struct libnvme_global_ctx object

**Return**

First :c:type:`libnvme_host_t` object in an iterator


.. c:function:: libnvme_host_t libnvme_next_host (struct libnvme_global_ctx *ctx, libnvme_host_t h)

   Next host iterator

**Parameters**

``struct libnvme_global_ctx *ctx``
  struct libnvme_global_ctx object

``libnvme_host_t h``
  Previous :c:type:`libnvme_host_t` iterator

**Return**

Next :c:type:`libnvme_host_t` object in an iterator


.. c:function:: struct libnvme_global_ctx * libnvme_host_get_global_ctx (libnvme_host_t h)

   Returns libnvme_global_ctx object

**Parameters**

``libnvme_host_t h``
  :c:type:`libnvme_host_t` object

**Return**

:c:type:`struct libnvme_global_ctx <libnvme_global_ctx>` object from **h**


.. c:function:: void libnvme_host_set_pdc_enabled (libnvme_host_t h, bool enabled)

   Set Persistent Discovery Controller flag

**Parameters**

``libnvme_host_t h``
  Host for which the falg should be set

``bool enabled``
  The bool to set the enabled flag

**Description**

When libnvme_host_set_pdc_enabled() is not used to set the PDC flag,
libnvme_host_is_pdc_enabled() will return the default value which was
passed into the function and not the undefined flag value.


.. c:function:: bool libnvme_host_is_pdc_enabled (libnvme_host_t h, bool fallback)

   Is Persistenct Discovery Controller enabled

**Parameters**

``libnvme_host_t h``
  Host which to check if PDC is enabled

``bool fallback``
  The fallback default value of the flag when
  **libnvme_host_set_pdc_enabled** has not be used
  to set the flag.

**Return**

true if PDC is enabled for **h**, else false


.. c:function:: int libnvme_get_host (struct libnvme_global_ctx *ctx, const char *hostnqn, const char *hostid, libnvme_host_t *h)

   Returns a host object

**Parameters**

``struct libnvme_global_ctx *ctx``
  struct libnvme_global_ctx object

``const char *hostnqn``
  Host NQN (optional)

``const char *hostid``
  Host ID (optional)

``libnvme_host_t *h``
  :c:type:`libnvme_host_t` object to return

**Description**

Returns a host object based on the hostnqn/hostid values or the default if
hostnqn/hostid are NULL.

**Return**

0 on success, negative error code otherwise.


.. c:function:: libnvme_subsystem_t libnvme_first_subsystem (libnvme_host_t h)

   Start subsystem iterator

**Parameters**

``libnvme_host_t h``
  :c:type:`libnvme_host_t` object

**Return**

first :c:type:`libnvme_subsystem_t` object in an iterator


.. c:function:: libnvme_subsystem_t libnvme_next_subsystem (libnvme_host_t h, libnvme_subsystem_t s)

   Next subsystem iterator

**Parameters**

``libnvme_host_t h``
  :c:type:`libnvme_host_t` object

``libnvme_subsystem_t s``
  Previous :c:type:`libnvme_subsystem_t` iterator

**Return**

next :c:type:`libnvme_subsystem_t` object in an iterator


.. c:function:: int libnvme_get_subsystem (struct libnvme_global_ctx *ctx, struct libnvme_host *h, const char *name, const char *subsysnqn, struct libnvme_subsystem **s)

   Returns libnvme_subsystem_t object

**Parameters**

``struct libnvme_global_ctx *ctx``
  struct libnvme_global_ctx object

``struct libnvme_host *h``
  :c:type:`libnvme_host_t` object

``const char *name``
  Name of the subsystem (may be NULL)

``const char *subsysnqn``
  Subsystem NQN

``struct libnvme_subsystem **s``
  libnvme_subsystem_t object

**Description**

Returns an :c:type:`libnvme_subsystem_t` object in **h** base on **name** (if present)
and **subsysnqn** or create one if not found.


.. c:function:: void libnvme_free_subsystem (struct libnvme_subsystem *s)

   Free a subsystem

**Parameters**

``struct libnvme_subsystem *s``
  subsystem

**Description**

Frees **s** and all related objects.


.. c:function:: libnvme_host_t libnvme_subsystem_get_host (libnvme_subsystem_t s)

   Returns libnvme_host_t object

**Parameters**

``libnvme_subsystem_t s``
  subsystem

**Return**

:c:type:`libnvme_host_t` object from **s**


.. c:function:: char * libnvme_subsystem_get_iopolicy (libnvme_subsystem_t s)

   Get subsystem iopolicy name

**Parameters**

``libnvme_subsystem_t s``
  subsystem

**Return**

The iopolicy configured in subsystem **s**


.. c:function:: libnvme_ns_t libnvme_ctrl_first_ns (libnvme_ctrl_t c)

   Start namespace iterator

**Parameters**

``libnvme_ctrl_t c``
  Controller instance

**Return**

First :c:type:`libnvme_ns_t` object of an **c** iterator


.. c:function:: libnvme_ns_t libnvme_ctrl_next_ns (libnvme_ctrl_t c, libnvme_ns_t n)

   Next namespace iterator

**Parameters**

``libnvme_ctrl_t c``
  Controller instance

``libnvme_ns_t n``
  Previous libnvme_ns_t iterator

**Return**

Next libnvme_ns_t object of an **c** iterator


.. c:function:: libnvme_path_t libnvme_ctrl_first_path (libnvme_ctrl_t c)

   Start path iterator

**Parameters**

``libnvme_ctrl_t c``
  Controller instance

**Return**

First :c:type:`libnvme_path_t` object of an **c** iterator


.. c:function:: libnvme_path_t libnvme_ctrl_next_path (libnvme_ctrl_t c, libnvme_path_t p)

   Next path iterator

**Parameters**

``libnvme_ctrl_t c``
  Controller instance

``libnvme_path_t p``
  Previous :c:type:`libnvme_path_t` object of an **c** iterator

**Return**

Next :c:type:`libnvme_path_t` object of an **c** iterator


.. c:function:: libnvme_ctrl_t libnvme_subsystem_first_ctrl (libnvme_subsystem_t s)

   First ctrl iterator

**Parameters**

``libnvme_subsystem_t s``
  :c:type:`libnvme_subsystem_t` object

**Return**

First controller of an **s** iterator


.. c:function:: libnvme_ctrl_t libnvme_subsystem_next_ctrl (libnvme_subsystem_t s, libnvme_ctrl_t c)

   Next ctrl iterator

**Parameters**

``libnvme_subsystem_t s``
  :c:type:`libnvme_subsystem_t` object

``libnvme_ctrl_t c``
  Previous controller instance of an **s** iterator

**Return**

Next controller of an **s** iterator


.. c:function:: libnvme_path_t libnvme_namespace_first_path (libnvme_ns_t ns)

   Start path iterator

**Parameters**

``libnvme_ns_t ns``
  Namespace instance

**Return**

First :c:type:`libnvme_path_t` object of an **ns** iterator


.. c:function:: libnvme_path_t libnvme_namespace_next_path (libnvme_ns_t ns, libnvme_path_t p)

   Next path iterator

**Parameters**

``libnvme_ns_t ns``
  Namespace instance

``libnvme_path_t p``
  Previous :c:type:`libnvme_path_t` object of an **ns** iterator

**Return**

Next :c:type:`libnvme_path_t` object of an **ns** iterator


.. c:function:: libnvme_ns_t libnvme_subsystem_first_ns (libnvme_subsystem_t s)

   Start namespace iterator

**Parameters**

``libnvme_subsystem_t s``
  :c:type:`libnvme_subsystem_t` object

**Return**

First :c:type:`libnvme_ns_t` object of an **s** iterator


.. c:function:: libnvme_ns_t libnvme_subsystem_next_ns (libnvme_subsystem_t s, libnvme_ns_t n)

   Next namespace iterator

**Parameters**

``libnvme_subsystem_t s``
  :c:type:`libnvme_subsystem_t` object

``libnvme_ns_t n``
  Previous :c:type:`libnvme_ns_t` iterator

**Return**

Next :c:type:`libnvme_ns_t` object of an **s** iterator


.. c:macro:: libnvme_for_each_host_safe

``libnvme_for_each_host_safe (r, h, _h)``

   Traverse host list

**Parameters**

``r``
  :c:type:`libnvme_root_t` object

``h``
  :c:type:`libnvme_host_t` object

``_h``
  Temporary :c:type:`libnvme_host_t` object


.. c:macro:: libnvme_for_each_host

``libnvme_for_each_host (r, h)``

   Traverse host list

**Parameters**

``r``
  :c:type:`libnvme_root_t` object

``h``
  :c:type:`libnvme_host_t` object


.. c:macro:: libnvme_for_each_subsystem_safe

``libnvme_for_each_subsystem_safe (h, s, _s)``

   Traverse subsystems

**Parameters**

``h``
  :c:type:`libnvme_host_t` object

``s``
  :c:type:`libnvme_subsystem_t` object

``_s``
  Temporary :c:type:`libnvme_subsystem_t` object


.. c:macro:: libnvme_for_each_subsystem

``libnvme_for_each_subsystem (h, s)``

   Traverse subsystems

**Parameters**

``h``
  :c:type:`libnvme_host_t` object

``s``
  :c:type:`libnvme_subsystem_t` object


.. c:macro:: libnvme_subsystem_for_each_ctrl_safe

``libnvme_subsystem_for_each_ctrl_safe (s, c, _c)``

   Traverse controllers

**Parameters**

``s``
  :c:type:`libnvme_subsystem_t` object

``c``
  Controller instance

``_c``
  A :c:type:`libnvme_ctrl_t_node` to use as temporary storage


.. c:macro:: libnvme_subsystem_for_each_ctrl

``libnvme_subsystem_for_each_ctrl (s, c)``

   Traverse controllers

**Parameters**

``s``
  :c:type:`libnvme_subsystem_t` object

``c``
  Controller instance


.. c:macro:: libnvme_ctrl_for_each_ns_safe

``libnvme_ctrl_for_each_ns_safe (c, n, _n)``

   Traverse namespaces

**Parameters**

``c``
  Controller instance

``n``
  :c:type:`libnvme_ns_t` object

``_n``
  A :c:type:`libnvme_ns_t_node` to use as temporary storage


.. c:macro:: libnvme_ctrl_for_each_ns

``libnvme_ctrl_for_each_ns (c, n)``

   Traverse namespaces

**Parameters**

``c``
  Controller instance

``n``
  :c:type:`libnvme_ns_t` object


.. c:macro:: libnvme_ctrl_for_each_path_safe

``libnvme_ctrl_for_each_path_safe (c, p, _p)``

   Traverse paths

**Parameters**

``c``
  Controller instance

``p``
  :c:type:`libnvme_path_t` object

``_p``
  A :c:type:`libnvme_path_t_node` to use as temporary storage


.. c:macro:: libnvme_ctrl_for_each_path

``libnvme_ctrl_for_each_path (c, p)``

   Traverse paths

**Parameters**

``c``
  Controller instance

``p``
  :c:type:`libnvme_path_t` object


.. c:macro:: libnvme_subsystem_for_each_ns_safe

``libnvme_subsystem_for_each_ns_safe (s, n, _n)``

   Traverse namespaces

**Parameters**

``s``
  :c:type:`libnvme_subsystem_t` object

``n``
  :c:type:`libnvme_ns_t` object

``_n``
  A :c:type:`libnvme_ns_t_node` to use as temporary storage


.. c:macro:: libnvme_subsystem_for_each_ns

``libnvme_subsystem_for_each_ns (s, n)``

   Traverse namespaces

**Parameters**

``s``
  :c:type:`libnvme_subsystem_t` object

``n``
  :c:type:`libnvme_ns_t` object


.. c:macro:: libnvme_namespace_for_each_path_safe

``libnvme_namespace_for_each_path_safe (n, p, _p)``

   Traverse paths

**Parameters**

``n``
  Namespace instance

``p``
  :c:type:`libnvme_path_t` object

``_p``
  A :c:type:`libnvme_path_t_node` to use as temporary storage


.. c:macro:: libnvme_namespace_for_each_path

``libnvme_namespace_for_each_path (n, p)``

   Traverse paths

**Parameters**

``n``
  Namespace instance

``p``
  :c:type:`libnvme_path_t` object


.. c:function:: void libnvme_ns_copy_uuid (libnvme_ns_t n, unsigned char out[NVME_UUID_LEN])

   Copy UUID of a namespace into a caller buffer

**Parameters**

``libnvme_ns_t n``
  Namespace instance

``unsigned char out[NVME_UUID_LEN]``
  buffer for the UUID

**Description**

Copies the namespace's uuid into **out**


.. c:function:: long libnvme_ns_get_command_retry_count (libnvme_ns_t n)

   Get command retry count

**Parameters**

``libnvme_ns_t n``
  :c:type:`libnvme_ns_t` object

**Return**

Number of times any command issued to namespace **n** has to be retried


.. c:function:: long libnvme_ns_get_command_error_count (libnvme_ns_t n)

   Get command error count

**Parameters**

``libnvme_ns_t n``
  :c:type:`libnvme_ns_t` object

**Return**

Number of times command issued to namespace **n** returns non-zero
status or error


.. c:function:: long libnvme_ns_get_io_requeue_no_usable_path_count (libnvme_ns_t n)

   Get I/Os requeue count

**Parameters**

``libnvme_ns_t n``
  :c:type:`libnvme_ns_t` object

**Return**

Number of I/Os which are re-queued due to the unavalibility of
any usable path (maybe path is currently experiencing transinet link failure)


.. c:function:: long libnvme_ns_get_io_fail_no_available_path_count (libnvme_ns_t n)

   Get I/Os failed count

**Parameters**

``libnvme_ns_t n``
  :c:type:`libnvme_ns_t` object

**Return**

Number of I/Os which are forced to fail due to no path available


.. c:function:: const char * libnvme_ns_get_firmware (libnvme_ns_t n)

   Firmware string of a namespace

**Parameters**

``libnvme_ns_t n``
  Namespace instance

**Return**

Firmware string of **n**


.. c:function:: const char * libnvme_ns_get_serial (libnvme_ns_t n)

   Serial number of a namespace

**Parameters**

``libnvme_ns_t n``
  Namespace instance

**Return**

Serial number string of **n**


.. c:function:: const char * libnvme_ns_get_model (libnvme_ns_t n)

   Model of a namespace

**Parameters**

``libnvme_ns_t n``
  Namespace instance

**Return**

Model string of **n**


.. c:function:: libnvme_subsystem_t libnvme_ns_get_subsystem (libnvme_ns_t n)

   :c:type:`libnvme_subsystem_t` of a namespace

**Parameters**

``libnvme_ns_t n``
  Namespace instance

**Return**

libnvme_subsystem_t object of **n**


.. c:function:: libnvme_ctrl_t libnvme_ns_get_ctrl (libnvme_ns_t n)

   :c:type:`libnvme_ctrl_t` of a namespace

**Parameters**

``libnvme_ns_t n``
  Namespace instance

**Description**

libnvme_ctrl_t object may be NULL for a multipathed namespace

**Return**

libnvme_ctrl_t object of **n** if present


.. c:function:: void libnvme_free_ns (struct libnvme_ns *n)

   Free a namespace object

**Parameters**

``struct libnvme_ns *n``
  Namespace instance


.. c:function:: int libnvme_ns_read (libnvme_ns_t n, void *buf, off_t offset, size_t count)

   Read from a namespace

**Parameters**

``libnvme_ns_t n``
  Namespace instance

``void *buf``
  Buffer into which the data will be transferred

``off_t offset``
  LBA offset of **n**

``size_t count``
  Number of sectors in **buf**

**Return**

Number of sectors read or -1 on error.


.. c:function:: int libnvme_ns_write (libnvme_ns_t n, void *buf, off_t offset, size_t count)

   Write to a namespace

**Parameters**

``libnvme_ns_t n``
  Namespace instance

``void *buf``
  Buffer with data to be written

``off_t offset``
  LBA offset of **n**

``size_t count``
  Number of sectors in **buf**

**Return**

Number of sectors written or -1 on error


.. c:function:: int libnvme_ns_verify (libnvme_ns_t n, off_t offset, size_t count)

   Verify data on a namespace

**Parameters**

``libnvme_ns_t n``
  Namespace instance

``off_t offset``
  LBA offset of **n**

``size_t count``
  Number of sectors to be verified

**Return**

Number of sectors verified


.. c:function:: int libnvme_ns_compare (libnvme_ns_t n, void *buf, off_t offset, size_t count)

   Compare data on a namespace

**Parameters**

``libnvme_ns_t n``
  Namespace instance

``void *buf``
  Buffer with data to be compared

``off_t offset``
  LBA offset of **n**

``size_t count``
  Number of sectors in **buf**

**Return**

Number of sectors compared


.. c:function:: int libnvme_ns_write_zeros (libnvme_ns_t n, off_t offset, size_t count)

   Write zeros to a namespace

**Parameters**

``libnvme_ns_t n``
  Namespace instance

``off_t offset``
  LBA offset in **n**

``size_t count``
  Number of sectors to be written

**Return**

Number of sectors written


.. c:function:: int libnvme_ns_write_uncorrectable (libnvme_ns_t n, off_t offset, size_t count)

   Issus a 'write uncorrectable' command

**Parameters**

``libnvme_ns_t n``
  Namespace instance

``off_t offset``
  LBA offset in **n**

``size_t count``
  Number of sectors to be written

**Return**

Number of sectors written


.. c:function:: int libnvme_ns_flush (libnvme_ns_t n)

   Flush data to a namespace

**Parameters**

``libnvme_ns_t n``
  Namespace instance

**Return**

0 on success, negative error code otherwise.


.. c:function:: int libnvme_ns_identify (libnvme_ns_t n, struct nvme_id_ns *ns)

   Issue an 'identify namespace' command

**Parameters**

``libnvme_ns_t n``
  Namespace instance

``struct nvme_id_ns *ns``
  :c:type:`nvme_id_ns` buffer

**Description**

Writes the data returned by the 'identify namespace' command
into **ns**.

**Return**

0 on success, negative error code otherwise.


.. c:function:: int libnvme_ns_identify_descs (libnvme_ns_t n, struct nvme_ns_id_desc *descs)

   Issue an 'identify descriptors' command

**Parameters**

``libnvme_ns_t n``
  Namespace instance

``struct nvme_ns_id_desc *descs``
  List of identify descriptors

**Description**

Writes the data returned by the 'identify descriptors' command
into **descs**.

**Return**

0 on success, negative error code otherwise.


.. c:function:: int libnvme_path_get_queue_depth (libnvme_path_t p)

   Queue depth of an libnvme_path_t object

**Parameters**

``libnvme_path_t p``
  :c:type:`libnvme_path_t` object

**Return**

Queue depth of **p**


.. c:function:: char * libnvme_path_get_ana_state (libnvme_path_t p)

   ANA state of an nvme_path_t object

**Parameters**

``libnvme_path_t p``
  :c:type:`libnvme_path_t` object

**Return**

ANA state of **p**


.. c:function:: char * libnvme_path_get_numa_nodes (libnvme_path_t p)

   Numa nodes of an nvme_path_t object

**Parameters**

``libnvme_path_t p``
  :c:type:`libnvme_path_t` object

**Return**

Numa nodes of **p**


.. c:function:: long libnvme_path_get_multipath_failover_count (libnvme_path_t p)

   Get multipath failover count

**Parameters**

``libnvme_path_t p``
  :c:type:`libnvme_path_t` object

**Return**

Number of times I/Os have to be failed over to another active path
from path **p** maybe due to any transient error observed on path **p**


.. c:function:: long libnvme_path_get_command_retry_count (libnvme_path_t p)

   Get command retry count

**Parameters**

``libnvme_path_t p``
  :c:type:`libnvme_path_t` object

**Return**

Number of times any command issued to the namespace represented by
path **p** has to be retried


.. c:function:: long libnvme_path_get_command_error_count (libnvme_path_t p)

   Get command error count

**Parameters**

``libnvme_path_t p``
  :c:type:`libnvme_path_t` object

**Return**

Number of times command issued to the namespace represented by path
**p** returns non-zero status or error


.. c:function:: libnvme_ctrl_t libnvme_path_get_ctrl (libnvme_path_t p)

   Parent controller of an libnvme_path_t object

**Parameters**

``libnvme_path_t p``
  :c:type:`libnvme_path_t` object

**Return**

Parent controller if present


.. c:function:: libnvme_ns_t libnvme_path_get_ns (libnvme_path_t p)

   Parent namespace of an libnvme_path_t object

**Parameters**

``libnvme_path_t p``
  :c:type:`libnvme_path_t` object

**Return**

Parent namespace if present


.. c:function:: void libnvme_path_reset_stat (libnvme_path_t p)

   Resets namespace path nvme stat

**Parameters**

``libnvme_path_t p``
  :c:type:`libnvme_path_t` object


.. c:function:: int libnvme_path_update_stat (libnvme_path_t p, bool diffstat)

   Update stat of an nvme_path_t object

**Parameters**

``libnvme_path_t p``
  :c:type:`libnvme_path_t` object

``bool diffstat``
  If set to true then getters return the diff stat otherwise
  return the current absolute stat

**Return**

0 on success, negative error code otherwise.


.. c:function:: unsigned long libnvme_path_get_read_ios (libnvme_path_t p)

   Calculate and return read IOs

**Parameters**

``libnvme_path_t p``
  :c:type:`libnvme_path_t` object

**Return**

Num of read IOs processed between two stat samples


.. c:function:: unsigned long libnvme_path_get_write_ios (libnvme_path_t p)

   Get write I/Os

**Parameters**

``libnvme_path_t p``
  :c:type:`libnvme_path_t` object

**Return**

Num of write I/Os processed between two stat samples


.. c:function:: unsigned int libnvme_path_get_read_ticks (libnvme_path_t p)

   Get read I/O ticks

**Parameters**

``libnvme_path_t p``
  :c:type:`libnvme_path_t` object

**Return**

Time, in milliseconds, sepnt processing read I/O requests
             between two stat samples


.. c:function:: unsigned long long libnvme_path_get_read_sectors (libnvme_path_t p)

   Get read I/O sectors

**Parameters**

``libnvme_path_t p``
  :c:type:`libnvme_path_t` object

**Return**

Number of sectors read from the device between two stat samples


.. c:function:: unsigned long long libnvme_path_get_write_sectors (libnvme_path_t p)

   Get write I/O sectors

**Parameters**

``libnvme_path_t p``
  :c:type:`libnvme_path_t` object

**Return**

Num of sectors written to the device between two stat samples


.. c:function:: unsigned int libnvme_path_get_write_ticks (libnvme_path_t p)

   Get write I/O ticks

**Parameters**

``libnvme_path_t p``
  :c:type:`libnvme_path_t` object

**Return**

Time, in milliseconds, sepnt processing write I/O requests
             between two stat samples


.. c:function:: double libnvme_path_get_stat_interval (libnvme_path_t p)

   Get interval between two stat samples

**Parameters**

``libnvme_path_t p``
  :c:type:`libnvme_path_t` object

**Return**

Interval, in milliseconds between collection of two consecutive
             stat samples


.. c:function:: unsigned int libnvme_path_get_io_ticks (libnvme_path_t p)

   Get I/O ticks

**Parameters**

``libnvme_path_t p``
  :c:type:`libnvme_path_t` object

**Return**

Time consumed, in milliseconds, processing I/O requests between
             two stat samples


.. c:function:: unsigned int libnvme_path_get_inflights (libnvme_path_t p)

   Inflight IOs for nvme_path_t object

**Parameters**

``libnvme_path_t p``
  :c:type:`libnvme_path_t` object

**Return**

Inflight number of IOs


.. c:function:: struct libnvme_transport_handle * libnvme_ctrl_get_transport_handle (libnvme_ctrl_t c)

   Get associated transport handle

**Parameters**

``libnvme_ctrl_t c``
  Controller instance

**Description**

libnvme will open() the device (if not already opened) and keep an
internal copy of the link handle. Following calls to this API retrieve
the internal cached copy of the link handle. The file will remain
opened and the handle will remain cached until the controller object
is deleted or libnvme_ctrl_release_transport_handle() is called.

**Return**

Link handle associated with **c** or NULL


.. c:function:: void libnvme_ctrl_release_transport_handle (libnvme_ctrl_t c)

   Free transport handle from controller object

**Parameters**

``libnvme_ctrl_t c``
  Controller instance


.. c:function:: char * libnvme_ctrl_get_src_addr (libnvme_ctrl_t c, char *src_addr, size_t src_addr_len)

   Extract src_addr from the c->address string

**Parameters**

``libnvme_ctrl_t c``
  Controller instance

``char *src_addr``
  Where to copy the src_addr. Size must be at least
  INET6_ADDRSTRLEN.

``size_t src_addr_len``
  Length of the buffer **src_addr**.

**Return**

Pointer to **src_addr** on success. NULL on failure to extract the
src_addr.


.. c:function:: const char * libnvme_ctrl_get_state (libnvme_ctrl_t c)

   Running state of a controller

**Parameters**

``libnvme_ctrl_t c``
  Controller instance

**Return**

String indicating the running state of **c**


.. c:function:: bool libnvme_ctrl_is_transport_fabric (libnvme_ctrl_t c)

   True for a fabrics transport

**Parameters**

``libnvme_ctrl_t c``
  Controller instance

**Description**

A controller is reachable either over a local transport (pcie,
apple-nvme) or over NVMe-over-Fabrics (tcp, rdma, fc, loop).

**Return**

true if **c** uses a fabrics transport, false if local.


.. c:function:: char * libnvme_ctrl_owner (libnvme_ctrl_t c)

   Registered orchestrator owner of a controller

**Parameters**

``libnvme_ctrl_t c``
  Controller instance

**Description**

Looks up the controller's "owner" entry in the ownership registry.  In a
build without fabrics support this always returns NULL.

**Return**

a newly allocated owner string (the caller frees), or NULL if the
controller is unowned, local (non-fabrics), or the registry is unreadable.


.. c:function:: libnvme_subsystem_t libnvme_ctrl_get_subsystem (libnvme_ctrl_t c)

   Parent subsystem of a controller

**Parameters**

``libnvme_ctrl_t c``
  Controller instance

**Return**

Parent libnvme_subsystem_t object


.. c:function:: const char * libnvme_ns_head_get_sysfs_dir (libnvme_ns_head_t head)

   sysfs dir of namespave head

**Parameters**

``libnvme_ns_head_t head``
  namespace head instance

**Return**

sysfs directory name of **head**


.. c:function:: int libnvme_ns_update_stat (libnvme_ns_t n, bool diffstat)

   update the nvme namespace stat

**Parameters**

``libnvme_ns_t n``
  :c:type:`libnvme_ns_t` object

``bool diffstat``
  If set to true then getters return the diff stat otherwise
  return the current absolute stat

**Return**

0 on success, negative error code otherwise.


.. c:function:: void libnvme_ns_reset_stat (libnvme_ns_t n)

   Resets nvme namespace stat

**Parameters**

``libnvme_ns_t n``
  :c:type:`libnvme_ns_t` object


.. c:function:: unsigned int libnvme_ns_get_inflights (libnvme_ns_t n)

   Inflight IOs for nvme_ns_t object

**Parameters**

``libnvme_ns_t n``
  :c:type:`libnvme_ns_t` object

**Return**

Inflight number of IOs


.. c:function:: unsigned int libnvme_ns_get_io_ticks (libnvme_ns_t n)

   Get IO ticks

**Parameters**

``libnvme_ns_t n``
  :c:type:`libnvme_ns_t` object

**Return**

Time consumed, in milliseconds, processing I/O requests between
             two stat samples


.. c:function:: unsigned int libnvme_ns_get_read_ticks (libnvme_ns_t n)

   Get read I/O ticks

**Parameters**

``libnvme_ns_t n``
  :c:type:`libnvme_ns_t` object

**Return**

Time, in milliseconds, sepnt processing read I/O requests
             between two stat samples


.. c:function:: unsigned int libnvme_ns_get_write_ticks (libnvme_ns_t n)

   Get write I/O ticks

**Parameters**

``libnvme_ns_t n``
  :c:type:`libnvme_ns_t` object

**Return**

Time, in milliseconds, sepnt processing write I/O requests
             between two stat samples


.. c:function:: double libnvme_ns_get_stat_interval (libnvme_ns_t n)

   Get interval between two stat samples

**Parameters**

``libnvme_ns_t n``
  :c:type:`libnvme_ns_t` object

**Return**

Interval, in milliseconds, between collection of two consecutive
             stat samples


.. c:function:: unsigned long libnvme_ns_get_read_ios (libnvme_ns_t n)

   Get num of read I/Os

**Parameters**

``libnvme_ns_t n``
  :c:type:`libnvme_ns_t` object

**Return**

Num of read IOs processed between two stat samples


.. c:function:: unsigned long libnvme_ns_get_write_ios (libnvme_ns_t n)

   Get num of write I/Os

**Parameters**

``libnvme_ns_t n``
  :c:type:`libnvme_ns_t` object

**Return**

Num of write IOs processed between two consecutive stat samples


.. c:function:: unsigned long long libnvme_ns_get_read_sectors (libnvme_ns_t n)

   Get num of read sectors

**Parameters**

``libnvme_ns_t n``
  :c:type:`libnvme_ns_t` object

**Return**

Num of sectors read from the device between two stat samples


.. c:function:: unsigned long long libnvme_ns_get_write_sectors (libnvme_ns_t n)

   Get num of write sectors

**Parameters**

``libnvme_ns_t n``
  :c:type:`libnvme_ns_t` object

**Return**

Num of sectors written to the device between two stat samples


.. c:function:: long libnvme_ctrl_get_command_error_count (libnvme_ctrl_t c)

   Get admin command error count

**Parameters**

``libnvme_ctrl_t c``
  Controller instance

**Return**

Number of times admin command issued to controller **c** failed or
returned error status


.. c:function:: long libnvme_ctrl_get_reset_count (libnvme_ctrl_t c)

   Get controller reset count

**Parameters**

``libnvme_ctrl_t c``
  Controller instance

**Return**

Number of timer controller **c** is reset


.. c:function:: long libnvme_ctrl_get_reconnect_count (libnvme_ctrl_t c)

   Get controller reconnect count

**Parameters**

``libnvme_ctrl_t c``
  Controller instance

**Return**

Number of times controller has to reconnect to the target


.. c:function:: int libnvme_ctrl_identify (libnvme_ctrl_t c, struct nvme_id_ctrl *id)

   Issues an 'identify controller' command

**Parameters**

``libnvme_ctrl_t c``
  Controller instance

``struct nvme_id_ctrl *id``
  Identify controller data structure

**Description**

Issues an 'identify controller' command to **c** and copies the
data into **id**.

**Return**

0 on success, negative error code otherwise.


.. c:function:: int libnvme_scan_ctrl (struct libnvme_global_ctx *ctx, const char *name, libnvme_ctrl_t *c)

   Scan on a controller

**Parameters**

``struct libnvme_global_ctx *ctx``
  struct libnvme_global_ctx object

``const char *name``
  Name of the controller

``libnvme_ctrl_t *c``
  **libnvme_ctrl_t** object to return

**Description**

Scans a controller with sysfs name **name** and add it to **r**.

**Return**

0 on success, negative error code otherwise.


.. c:function:: void libnvme_rescan_ctrl (libnvme_ctrl_t c)

   Rescan an existing controller

**Parameters**

``libnvme_ctrl_t c``
  Controller instance


.. c:function:: int libnvme_init_ctrl (libnvme_host_t h, libnvme_ctrl_t c, int instance)

   Initialize libnvme_ctrl_t object for an existing controller.

**Parameters**

``libnvme_host_t h``
  libnvme_host_t object

``libnvme_ctrl_t c``
  libnvme_ctrl_t object

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
  libnvme_host_t object

**Description**

Controller and Namespace objects cache the file descriptors
of opened nvme devices. This API can be used to close and
clear all cached fds under this host.


.. c:function:: void libnvme_free_host (libnvme_host_t h)

   Free libnvme_host_t object

**Parameters**

``libnvme_host_t h``
  libnvme_host_t object


.. c:function:: int libnvme_read_config (struct libnvme_global_ctx *ctx, const char *config_file)

   Read NVMe JSON configuration file

**Parameters**

``struct libnvme_global_ctx *ctx``
  :c:type:`struct libnvme_global_ctx <libnvme_global_ctx>` object

``const char *config_file``
  JSON configuration file

**Description**

Read in the contents of **config_file** and merge them with
the elements in **r**.

**Return**

0 on success, negative error code otherwise.


.. c:function:: void libnvme_refresh_topology (struct libnvme_global_ctx *ctx)

   Refresh libnvme_root_t object contents

**Parameters**

``struct libnvme_global_ctx *ctx``
  :c:type:`struct libnvme_global_ctx <libnvme_global_ctx>` object

**Description**

Removes all elements in **r** and rescans the existing topology.


.. c:function:: int libnvme_dump_config (struct libnvme_global_ctx *ctx, int fd)

   Print the JSON configuration

**Parameters**

``struct libnvme_global_ctx *ctx``
  :c:type:`struct libnvme_global_ctx <libnvme_global_ctx>` object

``int fd``
  File descriptor to write the JSON configuration.

**Description**

Writes the current contents of the JSON configuration
to the file descriptor fd.

**Return**

0 on success, negative error code otherwise.


.. c:function:: int libnvme_dump_tree (struct libnvme_global_ctx *ctx)

   Dump internal object tree

**Parameters**

``struct libnvme_global_ctx *ctx``
  :c:type:`struct libnvme_global_ctx <libnvme_global_ctx>` object

**Description**

Prints the internal object tree in JSON format
to stdout.

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

String with the contents of **attr** or ``NULL`` in case of an empty
        value or error.


.. c:function:: char * libnvme_get_subsys_attr (libnvme_subsystem_t s, const char *attr)

   Read subsystem sysfs attribute

**Parameters**

``libnvme_subsystem_t s``
  libnvme_subsystem_t object

``const char *attr``
  sysfs attribute name

**Return**

String with the contents of **attr** or ``NULL`` in case of an empty
        value or error.


.. c:function:: char * libnvme_get_ctrl_attr (libnvme_ctrl_t c, const char *attr)

   Read controller sysfs attribute

**Parameters**

``libnvme_ctrl_t c``
  Controller instance

``const char *attr``
  sysfs attribute name

**Return**

String with the contents of **attr** or ``NULL`` in case of an empty value
        or in case of an error.


.. c:function:: char * libnvme_get_ns_attr (libnvme_ns_t n, const char *attr)

   Read namespace sysfs attribute

**Parameters**

``libnvme_ns_t n``
  libnvme_ns_t object

``const char *attr``
  sysfs attribute name

**Return**

String with the contents of **attr** or ``NULL`` in case of an empty value
        or in case of an error.


.. c:function:: libnvme_ns_t libnvme_subsystem_lookup_namespace (struct libnvme_subsystem *s, __u32 nsid)

   lookup namespace by NSID

**Parameters**

``struct libnvme_subsystem *s``
  libnvme_subsystem_t object

``__u32 nsid``
  Namespace id

**Return**

libnvme_ns_t of the namespace with id **nsid** in subsystem **s**


.. c:function:: void libnvme_subsystem_release_fds (struct libnvme_subsystem *s)

   Close all opened fds under subsystem

**Parameters**

``struct libnvme_subsystem *s``
  libnvme_subsystem_t object

**Description**

Controller and Namespace objects cache the file descriptors
of opened nvme devices. This API can be used to close and
clear all cached fds under this subsystem.


.. c:function:: char * libnvme_get_path_attr (libnvme_path_t p, const char *attr)

   Read path sysfs attribute

**Parameters**

``libnvme_path_t p``
  libnvme_path_t object

``const char *attr``
  sysfs attribute name

**Return**

String with the contents of **attr** or ``NULL`` in case of an empty value
        or in case of an error.


.. c:function:: int libnvme_scan_namespace (struct libnvme_global_ctx *ctx, const char *name, libnvme_ns_t *ns)

   scan namespace based on sysfs name

**Parameters**

``struct libnvme_global_ctx *ctx``
  :c:type:`struct libnvme_global_ctx <libnvme_global_ctx>` object

``const char *name``
  sysfs name of the namespace to scan

``libnvme_ns_t *ns``
  :c:type:`libnvme_ns_t` object to return

**Return**

0 on success, negative error code otherwise.


