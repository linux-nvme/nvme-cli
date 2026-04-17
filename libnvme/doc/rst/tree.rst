.. _tree.h:

**tree.h**


libnvme tree object interface

.. c:function:: void libnvme_set_application (struct libnvme_global_ctx *ctx, const char *a)

   Specify managing application

**Parameters**

``struct libnvme_global_ctx *ctx``
  struct libnvme_global_ctx object

``const char *a``
  Application string

**Description**

Sets the managing application string for **r**.


.. c:function:: const char * libnvme_get_application (struct libnvme_global_ctx *ctx)

   Get managing application

**Parameters**

``struct libnvme_global_ctx *ctx``
  struct libnvme_global_ctx object

**Description**

Returns the managing application string for **r** or NULL if not set.


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

0 on success or negative error code otherwise


.. c:function:: int libnvme_host_get_ids (struct libnvme_global_ctx *ctx, const char *hostnqn_arg, const char *hostid_arg, char **hostnqn, char **hostid)

   Retrieve host ids from various sources

**Parameters**

``struct libnvme_global_ctx *ctx``
  struct libnvme_global_ctx object

``const char *hostnqn_arg``
  Input hostnqn (command line) argument

``const char *hostid_arg``
  Input hostid (command line) argument

``char **hostnqn``
  Output hostnqn

``char **hostid``
  Output hostid

**Description**

libnvme_host_get_ids figures out which hostnqn/hostid is to be used.
There are several sources where this information can be retrieved.

The order is:

 - Start with informartion from DMI or device-tree
 - Override hostnqn and hostid from /etc/nvme files
 - Override hostnqn or hostid with values from JSON
   configuration file. The first host entry in the file is
   considered the default host.
 - Override hostnqn or hostid with values from the command line
   (**hostnqn_arg**, **hostid_arg**).

 If the IDs are still NULL after the lookup algorithm, the function
 will generate random IDs.

 The function also verifies that hostnqn and hostid matches. The Linux
 NVMe implementation expects a 1:1 matching between the IDs.

**Return**

0 on success (**hostnqn** and **hostid** contain valid strings
 which the caller needs to free), or negative error code otherwise.


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


.. c:function:: bool libnvme_ctrl_match_config (struct libnvme_ctrl *c, const char *transport, const char *traddr, const char *trsvcid, const char *subsysnqn, const char *host_traddr, const char *host_iface)

   Check if ctrl **c** matches config params

**Parameters**

``struct libnvme_ctrl *c``
  An existing controller instance

``const char *transport``
  Transport name

``const char *traddr``
  Transport address

``const char *trsvcid``
  Transport service identifier

``const char *subsysnqn``
  Subsystem NQN

``const char *host_traddr``
  Host transport address

``const char *host_iface``
  Host interface name

**Description**

Check that controller **c** matches parameters: **transport**, **traddr**,
**trsvcid**, **subsysnqn**, **host_traddr**, and **host_iface**. Parameters set
to NULL will be ignored.

**Return**

true if there's a match, false otherwise.


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


.. c:function:: enum nvme_csi libnvme_ns_get_csi (libnvme_ns_t n)

   Command set identifier of a namespace

**Parameters**

``libnvme_ns_t n``
  Namespace instance

**Return**

The namespace's command set identifier in use


.. c:function:: const uint8_t * libnvme_ns_get_eui64 (libnvme_ns_t n)

   64-bit eui of a namespace

**Parameters**

``libnvme_ns_t n``
  Namespace instance

**Return**

A pointer to the 64-bit eui


.. c:function:: const uint8_t * libnvme_ns_get_nguid (libnvme_ns_t n)

   128-bit nguid of a namespace

**Parameters**

``libnvme_ns_t n``
  Namespace instance

**Return**

A pointer to the 128-bit nguid


.. c:function:: void libnvme_ns_get_uuid (libnvme_ns_t n, unsigned char out[NVME_UUID_LEN])

   UUID of a namespace

**Parameters**

``libnvme_ns_t n``
  Namespace instance

``unsigned char out[NVME_UUID_LEN]``
  buffer for the UUID

**Description**

Copies the namespace's uuid into **out**


.. c:function:: const char * libnvme_ns_get_generic_name (libnvme_ns_t n)

   Returns name of generic namespace chardev.

**Parameters**

``libnvme_ns_t n``
  Namespace instance

**Return**

Name of generic namespace chardev


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

0 on success, -1 on error.


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

0 on success, -1 on error.


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

0 on success, -1 on error.


.. c:function:: int libnvme_path_get_queue_depth (libnvme_path_t p)

   Queue depth of an libnvme_path_t object

**Parameters**

``libnvme_path_t p``
  :c:type:`libnvme_path_t` object

**Return**

Queue depth of **p**


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

0 on success or -1 on failure.


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

0 on success or negative error code otherwise


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

0 on success or negative error code otherwise


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

0 on success, or negative error code otherwise.


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

0 on success or negative error code otherwise


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

0 on success, or negative error code otherwise.


.. c:function:: int libnvme_dump_tree (struct libnvme_global_ctx *ctx)

   Dump internal object tree

**Parameters**

``struct libnvme_global_ctx *ctx``
  :c:type:`struct libnvme_global_ctx <libnvme_global_ctx>` object

**Description**

Prints the internal object tree in JSON format
to stdout.

**Return**

0 on success or negative error code otherwise


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

0 on success or negative error code otherwise


