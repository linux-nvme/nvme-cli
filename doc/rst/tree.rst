.. _tree.h:

**tree.h**


libnvme tree object interface

.. c:function:: nvme_root_t nvme_create_root (FILE *fp, int log_level)

   Initialize root object

**Parameters**

``FILE *fp``
  File descriptor for logging messages

``int log_level``
  Logging level to use

**Return**

Initialized :c:type:`nvme_root_t` object


.. c:function:: void nvme_free_tree (nvme_root_t r)

   Free root object

**Parameters**

``nvme_root_t r``
  :c:type:`nvme_root_t` object

**Description**

Free an :c:type:`nvme_root_t` object and all attached objects


.. c:function:: nvme_host_t nvme_first_host (nvme_root_t r)

   Start host iterator

**Parameters**

``nvme_root_t r``
  :c:type:`nvme_root_t` object

**Return**

First :c:type:`nvme_host_t` object in an iterator


.. c:function:: nvme_host_t nvme_next_host (nvme_root_t r, nvme_host_t h)

   Next host iterator

**Parameters**

``nvme_root_t r``
  :c:type:`nvme_root_t` object

``nvme_host_t h``
  Previous :c:type:`nvme_host_t` iterator

**Return**

Next :c:type:`nvme_host_t` object in an iterator


.. c:function:: nvme_root_t nvme_host_get_root (nvme_host_t h)

   Returns nvme_root_t object

**Parameters**

``nvme_host_t h``
  :c:type:`nvme_host_t` object

**Return**

:c:type:`nvme_root_t` object from **h**


.. c:function:: nvme_host_t nvme_lookup_host (nvme_root_t r, const char *hostnqn, const char *hostid)

   Lookup nvme_host_t object

**Parameters**

``nvme_root_t r``
  :c:type:`nvme_root_t` object

``const char *hostnqn``
  Host NQN

``const char *hostid``
  Host ID

**Description**

Lookup a nvme_host_t object based on **hostnqn** and **hostid**
or create one if not found.

**Return**

:c:type:`nvme_host_t` object


.. c:function:: const char * nvme_host_get_dhchap_key (nvme_host_t h)

   Return host key

**Parameters**

``nvme_host_t h``
  Host for which the key should be returned

**Return**

DH-HMAC-CHAP host key or NULL if not set


.. c:function:: void nvme_host_set_dhchap_key (nvme_host_t h, const char *key)

   set host key

**Parameters**

``nvme_host_t h``
  Host for which the key should be set

``const char *key``
  DH-HMAC-CHAP Key to set or NULL to clear existing key


.. c:function:: void nvme_host_set_pdc_enabled (nvme_host_t h, bool enabled)

   Set Persistent Discovery Controller flag

**Parameters**

``nvme_host_t h``
  Host for which the falg should be set

``bool enabled``
  The bool to set the enabled flag

**Description**

When nvme_host_set_pdc_enabled() is not used to set the PDC flag,
nvme_host_is_pdc_enabled() will return the default value which was
passed into the function and not the undefined flag value.


.. c:function:: bool nvme_host_is_pdc_enabled (nvme_host_t h, bool fallback)

   Is Persistenct Discovery Controller enabled

**Parameters**

``nvme_host_t h``
  Host which to check if PDC is enabled

``bool fallback``
  The fallback default value of the flag when
  **nvme_host_set_pdc_enabled** has not be used
  to set the flag.

**Return**

true if PDC is enabled for **h**, else false


.. c:function:: nvme_host_t nvme_default_host (nvme_root_t r)

   Initializes the default host

**Parameters**

``nvme_root_t r``
  :c:type:`nvme_root_t` object

**Description**

Initializes the default host object based on the values in
/etc/nvme/hostnqn and /etc/nvme/hostid and attaches it to **r**.

**Return**

:c:type:`nvme_host_t` object


.. c:function:: nvme_subsystem_t nvme_first_subsystem (nvme_host_t h)

   Start subsystem iterator

**Parameters**

``nvme_host_t h``
  :c:type:`nvme_host_t` object

**Return**

first :c:type:`nvme_subsystem_t` object in an iterator


.. c:function:: nvme_subsystem_t nvme_next_subsystem (nvme_host_t h, nvme_subsystem_t s)

   Next subsystem iterator

**Parameters**

``nvme_host_t h``
  :c:type:`nvme_host_t` object

``nvme_subsystem_t s``
  Previous :c:type:`nvme_subsystem_t` iterator

**Return**

next :c:type:`nvme_subsystem_t` object in an iterator


.. c:function:: nvme_subsystem_t nvme_lookup_subsystem (struct nvme_host *h, const char *name, const char *subsysnqn)

   Lookup nvme_subsystem_t object

**Parameters**

``struct nvme_host *h``
  :c:type:`nvme_host_t` object

``const char *name``
  Name of the subsystem (may be NULL)

``const char *subsysnqn``
  Subsystem NQN

**Description**

Lookup a :c:type:`nvme_subsystem_t` object in **h** base on **name** (if present)
and **subsysnqn** or create one if not found.

**Return**

nvme_subsystem_t object


.. c:function:: void nvme_free_subsystem (struct nvme_subsystem *s)

   Free a subsystem

**Parameters**

``struct nvme_subsystem *s``
  subsystem

**Description**

Frees **s** and all related objects.


.. c:function:: nvme_host_t nvme_subsystem_get_host (nvme_subsystem_t s)

   Returns nvme_host_t object

**Parameters**

``nvme_subsystem_t s``
  subsystem

**Return**

:c:type:`nvme_host_t` object from **s**


.. c:function:: nvme_ns_t nvme_ctrl_first_ns (nvme_ctrl_t c)

   Start namespace iterator

**Parameters**

``nvme_ctrl_t c``
  Controller instance

**Return**

First :c:type:`nvme_ns_t` object of an **c** iterator


.. c:function:: nvme_ns_t nvme_ctrl_next_ns (nvme_ctrl_t c, nvme_ns_t n)

   Next namespace iterator

**Parameters**

``nvme_ctrl_t c``
  Controller instance

``nvme_ns_t n``
  Previous nvme_ns_t iterator

**Return**

Next nvme_ns_t object of an **c** iterator


.. c:function:: nvme_path_t nvme_ctrl_first_path (nvme_ctrl_t c)

   Start path iterator

**Parameters**

``nvme_ctrl_t c``
  Controller instance

**Return**

First :c:type:`nvme_path_t` object of an **c** iterator


.. c:function:: nvme_path_t nvme_ctrl_next_path (nvme_ctrl_t c, nvme_path_t p)

   Next path iterator

**Parameters**

``nvme_ctrl_t c``
  Controller instance

``nvme_path_t p``
  Previous :c:type:`nvme_path_t` object of an **c** iterator

**Return**

Next :c:type:`nvme_path_t` object of an **c** iterator


.. c:function:: nvme_ctrl_t nvme_subsystem_first_ctrl (nvme_subsystem_t s)

   First ctrl iterator

**Parameters**

``nvme_subsystem_t s``
  :c:type:`nvme_subsystem_t` object

**Return**

First controller of an **s** iterator


.. c:function:: nvme_ctrl_t nvme_subsystem_next_ctrl (nvme_subsystem_t s, nvme_ctrl_t c)

   Next ctrl iterator

**Parameters**

``nvme_subsystem_t s``
  :c:type:`nvme_subsystem_t` object

``nvme_ctrl_t c``
  Previous controller instance of an **s** iterator

**Return**

Next controller of an **s** iterator


.. c:function:: nvme_path_t nvme_namespace_first_path (nvme_ns_t ns)

   Start path iterator

**Parameters**

``nvme_ns_t ns``
  Namespace instance

**Return**

First :c:type:`nvme_path_t` object of an **ns** iterator


.. c:function:: nvme_path_t nvme_namespace_next_path (nvme_ns_t ns, nvme_path_t p)

   Next path iterator

**Parameters**

``nvme_ns_t ns``
  Namespace instance

``nvme_path_t p``
  Previous :c:type:`nvme_path_t` object of an **ns** iterator

**Return**

Next :c:type:`nvme_path_t` object of an **ns** iterator


.. c:function:: nvme_ctrl_t nvme_lookup_ctrl (nvme_subsystem_t s, const char *transport, const char *traddr, const char *host_traddr, const char *host_iface, const char *trsvcid, nvme_ctrl_t p)

   Lookup nvme_ctrl_t object

**Parameters**

``nvme_subsystem_t s``
  :c:type:`nvme_subsystem_t` object

``const char *transport``
  Transport name

``const char *traddr``
  Transport address

``const char *host_traddr``
  Host transport address

``const char *host_iface``
  Host interface name

``const char *trsvcid``
  Transport service identifier

``nvme_ctrl_t p``
  Previous controller instance

**Description**

Lookup a controller in **s** based on **transport**, **traddr**,
**host_traddr**, **host_iface**, and **trsvcid**. **transport** must be specified,
other fields may be required depending on the transport. A new
object is created if none is found. If **p** is specified the lookup
will start at **p** instead of the first controller.

**Return**

Controller instance


.. c:function:: nvme_ctrl_t nvme_create_ctrl (nvme_root_t r, const char *subsysnqn, const char *transport, const char *traddr, const char *host_traddr, const char *host_iface, const char *trsvcid)

   Allocate an unconnected NVMe controller

**Parameters**

``nvme_root_t r``
  NVMe root element

``const char *subsysnqn``
  Subsystem NQN

``const char *transport``
  Transport type

``const char *traddr``
  Transport address

``const char *host_traddr``
  Host transport address

``const char *host_iface``
  Host interface name

``const char *trsvcid``
  Transport service ID

**Description**

Creates an unconnected controller to be used for nvme_add_ctrl().

**Return**

Controller instance


.. c:function:: nvme_ns_t nvme_subsystem_first_ns (nvme_subsystem_t s)

   Start namespace iterator

**Parameters**

``nvme_subsystem_t s``
  :c:type:`nvme_subsystem_t` object

**Return**

First :c:type:`nvme_ns_t` object of an **s** iterator


.. c:function:: nvme_ns_t nvme_subsystem_next_ns (nvme_subsystem_t s, nvme_ns_t n)

   Next namespace iterator

**Parameters**

``nvme_subsystem_t s``
  :c:type:`nvme_subsystem_t` object

``nvme_ns_t n``
  Previous :c:type:`nvme_ns_t` iterator

**Return**

Next :c:type:`nvme_ns_t` object of an **s** iterator


.. c:macro:: nvme_for_each_host_safe

``nvme_for_each_host_safe (r, h, _h)``

   Traverse host list

**Parameters**

``r``
  :c:type:`nvme_root_t` object

``h``
  :c:type:`nvme_host_t` object

``_h``
  Temporary :c:type:`nvme_host_t` object


.. c:macro:: nvme_for_each_host

``nvme_for_each_host (r, h)``

   Traverse host list

**Parameters**

``r``
  :c:type:`nvme_root_t` object

``h``
  :c:type:`nvme_host_t` object


.. c:macro:: nvme_for_each_subsystem_safe

``nvme_for_each_subsystem_safe (h, s, _s)``

   Traverse subsystems

**Parameters**

``h``
  :c:type:`nvme_host_t` object

``s``
  :c:type:`nvme_subsystem_t` object

``_s``
  Temporary :c:type:`nvme_subsystem_t` object


.. c:macro:: nvme_for_each_subsystem

``nvme_for_each_subsystem (h, s)``

   Traverse subsystems

**Parameters**

``h``
  :c:type:`nvme_host_t` object

``s``
  :c:type:`nvme_subsystem_t` object


.. c:macro:: nvme_subsystem_for_each_ctrl_safe

``nvme_subsystem_for_each_ctrl_safe (s, c, _c)``

   Traverse controllers

**Parameters**

``s``
  :c:type:`nvme_subsystem_t` object

``c``
  Controller instance

``_c``
  A :c:type:`nvme_ctrl_t_node` to use as temporary storage


.. c:macro:: nvme_subsystem_for_each_ctrl

``nvme_subsystem_for_each_ctrl (s, c)``

   Traverse controllers

**Parameters**

``s``
  :c:type:`nvme_subsystem_t` object

``c``
  Controller instance


.. c:macro:: nvme_ctrl_for_each_ns_safe

``nvme_ctrl_for_each_ns_safe (c, n, _n)``

   Traverse namespaces

**Parameters**

``c``
  Controller instance

``n``
  :c:type:`nvme_ns_t` object

``_n``
  A :c:type:`nvme_ns_t_node` to use as temporary storage


.. c:macro:: nvme_ctrl_for_each_ns

``nvme_ctrl_for_each_ns (c, n)``

   Traverse namespaces

**Parameters**

``c``
  Controller instance

``n``
  :c:type:`nvme_ns_t` object


.. c:macro:: nvme_ctrl_for_each_path_safe

``nvme_ctrl_for_each_path_safe (c, p, _p)``

   Traverse paths

**Parameters**

``c``
  Controller instance

``p``
  :c:type:`nvme_path_t` object

``_p``
  A :c:type:`nvme_path_t_node` to use as temporary storage


.. c:macro:: nvme_ctrl_for_each_path

``nvme_ctrl_for_each_path (c, p)``

   Traverse paths

**Parameters**

``c``
  Controller instance

``p``
  :c:type:`nvme_path_t` object


.. c:macro:: nvme_subsystem_for_each_ns_safe

``nvme_subsystem_for_each_ns_safe (s, n, _n)``

   Traverse namespaces

**Parameters**

``s``
  :c:type:`nvme_subsystem_t` object

``n``
  :c:type:`nvme_ns_t` object

``_n``
  A :c:type:`nvme_ns_t_node` to use as temporary storage


.. c:macro:: nvme_subsystem_for_each_ns

``nvme_subsystem_for_each_ns (s, n)``

   Traverse namespaces

**Parameters**

``s``
  :c:type:`nvme_subsystem_t` object

``n``
  :c:type:`nvme_ns_t` object


.. c:macro:: nvme_namespace_for_each_path_safe

``nvme_namespace_for_each_path_safe (n, p, _p)``

   Traverse paths

**Parameters**

``n``
  Namespace instance

``p``
  :c:type:`nvme_path_t` object

``_p``
  A :c:type:`nvme_path_t_node` to use as temporary storage


.. c:macro:: nvme_namespace_for_each_path

``nvme_namespace_for_each_path (n, p)``

   Traverse paths

**Parameters**

``n``
  Namespace instance

``p``
  :c:type:`nvme_path_t` object


.. c:function:: int nvme_ns_get_fd (nvme_ns_t n)

   Get associated file descriptor

**Parameters**

``nvme_ns_t n``
  Namespace instance

**Return**

File descriptor associated with **n** or -1


.. c:function:: int nvme_ns_get_nsid (nvme_ns_t n)

   NSID of a namespace

**Parameters**

``nvme_ns_t n``
  Namespace instance

**Return**

NSID of **n**


.. c:function:: int nvme_ns_get_lba_size (nvme_ns_t n)

   LBA size of a namespace

**Parameters**

``nvme_ns_t n``
  Namespace instance

**Return**

LBA size of **n**


.. c:function:: int nvme_ns_get_meta_size (nvme_ns_t n)

   Metadata size of a namespace

**Parameters**

``nvme_ns_t n``
  Namespace instance

**Return**

Metadata size of **n**


.. c:function:: uint64_t nvme_ns_get_lba_count (nvme_ns_t n)

   LBA count of a namespace

**Parameters**

``nvme_ns_t n``
  Namespace instance

**Return**

LBA count of **n**


.. c:function:: uint64_t nvme_ns_get_lba_util (nvme_ns_t n)

   LBA utilization of a namespace

**Parameters**

``nvme_ns_t n``
  Namespace instance

**Return**

LBA utilization of **n**


.. c:function:: enum nvme_csi nvme_ns_get_csi (nvme_ns_t n)

   Command set identifier of a namespace

**Parameters**

``nvme_ns_t n``
  Namespace instance

**Return**

The namespace's command set identifier in use


.. c:function:: const uint8_t * nvme_ns_get_eui64 (nvme_ns_t n)

   64-bit eui of a namespace

**Parameters**

``nvme_ns_t n``
  Namespace instance

**Return**

A pointer to the 64-bit eui


.. c:function:: const uint8_t * nvme_ns_get_nguid (nvme_ns_t n)

   128-bit nguid of a namespace

**Parameters**

``nvme_ns_t n``
  Namespace instance

**Return**

A pointer to the 128-bit nguid


.. c:function:: void nvme_ns_get_uuid (nvme_ns_t n, unsigned char out[NVME_UUID_LEN])

   UUID of a namespace

**Parameters**

``nvme_ns_t n``
  Namespace instance

``unsigned char out[NVME_UUID_LEN]``
  buffer for the UUID

**Description**

Copies the namespace's uuid into **out**


.. c:function:: const char * nvme_ns_get_sysfs_dir (nvme_ns_t n)

   sysfs directory of a namespace

**Parameters**

``nvme_ns_t n``
  Namespace instance

**Return**

sysfs directory name of **n**


.. c:function:: const char * nvme_ns_get_name (nvme_ns_t n)

   sysfs name of a namespace

**Parameters**

``nvme_ns_t n``
  Namespace instance

**Return**

sysfs name of **n**


.. c:function:: const char * nvme_ns_get_generic_name (nvme_ns_t n)

   Returns name of generic namespace chardev.

**Parameters**

``nvme_ns_t n``
  Namespace instance

**Return**

Name of generic namespace chardev


.. c:function:: const char * nvme_ns_get_firmware (nvme_ns_t n)

   Firmware string of a namespace

**Parameters**

``nvme_ns_t n``
  Namespace instance

**Return**

Firmware string of **n**


.. c:function:: const char * nvme_ns_get_serial (nvme_ns_t n)

   Serial number of a namespace

**Parameters**

``nvme_ns_t n``
  Namespace instance

**Return**

Serial number string of **n**


.. c:function:: const char * nvme_ns_get_model (nvme_ns_t n)

   Model of a namespace

**Parameters**

``nvme_ns_t n``
  Namespace instance

**Return**

Model string of **n**


.. c:function:: nvme_subsystem_t nvme_ns_get_subsystem (nvme_ns_t n)

   :c:type:`nvme_subsystem_t` of a namespace

**Parameters**

``nvme_ns_t n``
  Namespace instance

**Return**

nvme_subsystem_t object of **n**


.. c:function:: nvme_ctrl_t nvme_ns_get_ctrl (nvme_ns_t n)

   :c:type:`nvme_ctrl_t` of a namespace

**Parameters**

``nvme_ns_t n``
  Namespace instance

**Description**

nvme_ctrl_t object may be NULL for a multipathed namespace

**Return**

nvme_ctrl_t object of **n** if present


.. c:function:: void nvme_free_ns (struct nvme_ns *n)

   Free a namespace object

**Parameters**

``struct nvme_ns *n``
  Namespace instance


.. c:function:: int nvme_ns_read (nvme_ns_t n, void *buf, off_t offset, size_t count)

   Read from a namespace

**Parameters**

``nvme_ns_t n``
  Namespace instance

``void *buf``
  Buffer into which the data will be transferred

``off_t offset``
  LBA offset of **n**

``size_t count``
  Number of sectors in **buf**

**Return**

Number of sectors read or -1 on error.


.. c:function:: int nvme_ns_write (nvme_ns_t n, void *buf, off_t offset, size_t count)

   Write to a namespace

**Parameters**

``nvme_ns_t n``
  Namespace instance

``void *buf``
  Buffer with data to be written

``off_t offset``
  LBA offset of **n**

``size_t count``
  Number of sectors in **buf**

**Return**

Number of sectors written or -1 on error


.. c:function:: int nvme_ns_verify (nvme_ns_t n, off_t offset, size_t count)

   Verify data on a namespace

**Parameters**

``nvme_ns_t n``
  Namespace instance

``off_t offset``
  LBA offset of **n**

``size_t count``
  Number of sectors to be verified

**Return**

Number of sectors verified


.. c:function:: int nvme_ns_compare (nvme_ns_t n, void *buf, off_t offset, size_t count)

   Compare data on a namespace

**Parameters**

``nvme_ns_t n``
  Namespace instance

``void *buf``
  Buffer with data to be compared

``off_t offset``
  LBA offset of **n**

``size_t count``
  Number of sectors in **buf**

**Return**

Number of sectors compared


.. c:function:: int nvme_ns_write_zeros (nvme_ns_t n, off_t offset, size_t count)

   Write zeros to a namespace

**Parameters**

``nvme_ns_t n``
  Namespace instance

``off_t offset``
  LBA offset in **n**

``size_t count``
  Number of sectors to be written

**Return**

Number of sectors written


.. c:function:: int nvme_ns_write_uncorrectable (nvme_ns_t n, off_t offset, size_t count)

   Issus a 'write uncorrectable' command

**Parameters**

``nvme_ns_t n``
  Namespace instance

``off_t offset``
  LBA offset in **n**

``size_t count``
  Number of sectors to be written

**Return**

Number of sectors written


.. c:function:: int nvme_ns_flush (nvme_ns_t n)

   Flush data to a namespace

**Parameters**

``nvme_ns_t n``
  Namespace instance

**Return**

0 on success, -1 on error.


.. c:function:: int nvme_ns_identify (nvme_ns_t n, struct nvme_id_ns *ns)

   Issue an 'identify namespace' command

**Parameters**

``nvme_ns_t n``
  Namespace instance

``struct nvme_id_ns *ns``
  :c:type:`nvme_id_ns` buffer

**Description**

Writes the data returned by the 'identify namespace' command
into **ns**.

**Return**

0 on success, -1 on error.


.. c:function:: int nvme_ns_identify_descs (nvme_ns_t n, struct nvme_ns_id_desc *descs)

   Issue an 'identify descriptors' command

**Parameters**

``nvme_ns_t n``
  Namespace instance

``struct nvme_ns_id_desc *descs``
  List of identify descriptors

**Description**

Writes the data returned by the 'identify descriptors' command
into **descs**.

**Return**

0 on success, -1 on error.


.. c:function:: const char * nvme_path_get_name (nvme_path_t p)

   sysfs name of an :c:type:`nvme_path_t` object

**Parameters**

``nvme_path_t p``
  :c:type:`nvme_path_t` object

**Return**

sysfs name of **p**


.. c:function:: const char * nvme_path_get_sysfs_dir (nvme_path_t p)

   sysfs directory of an nvme_path_t object

**Parameters**

``nvme_path_t p``
  :c:type:`nvme_path_t` object

**Return**

sysfs directory of **p**


.. c:function:: const char * nvme_path_get_ana_state (nvme_path_t p)

   ANA state of an nvme_path_t object

**Parameters**

``nvme_path_t p``
  :c:type:`nvme_path_t` object

**Return**

ANA (Asynchronous Namespace Access) state of **p**


.. c:function:: nvme_ctrl_t nvme_path_get_ctrl (nvme_path_t p)

   Parent controller of an nvme_path_t object

**Parameters**

``nvme_path_t p``
  :c:type:`nvme_path_t` object

**Return**

Parent controller if present


.. c:function:: nvme_ns_t nvme_path_get_ns (nvme_path_t p)

   Parent namespace of an nvme_path_t object

**Parameters**

``nvme_path_t p``
  :c:type:`nvme_path_t` object

**Return**

Parent namespace if present


.. c:function:: int nvme_ctrl_get_fd (nvme_ctrl_t c)

   Get associated file descriptor

**Parameters**

``nvme_ctrl_t c``
  Controller instance

**Return**

File descriptor associated with **c** or -1


.. c:function:: const char * nvme_ctrl_get_name (nvme_ctrl_t c)

   sysfs name of a controller

**Parameters**

``nvme_ctrl_t c``
  Controller instance

**Return**

sysfs name of **c**


.. c:function:: const char * nvme_ctrl_get_sysfs_dir (nvme_ctrl_t c)

   sysfs directory of a controller

**Parameters**

``nvme_ctrl_t c``
  Controller instance

**Return**

sysfs directory name of **c**


.. c:function:: const char * nvme_ctrl_get_address (nvme_ctrl_t c)

   Address string of a controller

**Parameters**

``nvme_ctrl_t c``
  Controller instance

**Return**

NVMe-over-Fabrics address string of **c** or empty string
of no address is present.


.. c:function:: const char * nvme_ctrl_get_firmware (nvme_ctrl_t c)

   Firmware string of a controller

**Parameters**

``nvme_ctrl_t c``
  Controller instance

**Return**

Firmware string of **c**


.. c:function:: const char * nvme_ctrl_get_model (nvme_ctrl_t c)

   Model of a controller

**Parameters**

``nvme_ctrl_t c``
  Controller instance

**Return**

Model string of **c**


.. c:function:: const char * nvme_ctrl_get_state (nvme_ctrl_t c)

   Running state of an controller

**Parameters**

``nvme_ctrl_t c``
  Controller instance

**Return**

String indicating the running state of **c**


.. c:function:: const char * nvme_ctrl_get_numa_node (nvme_ctrl_t c)

   NUMA node of a controller

**Parameters**

``nvme_ctrl_t c``
  Controller instance

**Return**

String indicating the NUMA node


.. c:function:: const char * nvme_ctrl_get_queue_count (nvme_ctrl_t c)

   Queue count of a controller

**Parameters**

``nvme_ctrl_t c``
  Controller instance

**Return**

Queue count of **c**


.. c:function:: const char * nvme_ctrl_get_serial (nvme_ctrl_t c)

   Serial number of a controller

**Parameters**

``nvme_ctrl_t c``
  Controller instance

**Return**

Serial number string of **c**


.. c:function:: const char * nvme_ctrl_get_sqsize (nvme_ctrl_t c)

   SQ size of a controller

**Parameters**

``nvme_ctrl_t c``
  Controller instance

**Return**

SQ size (as string) of **c**


.. c:function:: const char * nvme_ctrl_get_transport (nvme_ctrl_t c)

   Transport type of a controller

**Parameters**

``nvme_ctrl_t c``
  Controller instance

**Return**

Transport type of **c**


.. c:function:: const char * nvme_ctrl_get_subsysnqn (nvme_ctrl_t c)

   Subsystem NQN of a controller

**Parameters**

``nvme_ctrl_t c``
  Controller instance

**Return**

Subsystem NQN of **c**


.. c:function:: nvme_subsystem_t nvme_ctrl_get_subsystem (nvme_ctrl_t c)

   Parent subsystem of a controller

**Parameters**

``nvme_ctrl_t c``
  Controller instance

**Return**

Parent nvme_subsystem_t object


.. c:function:: const char * nvme_ctrl_get_traddr (nvme_ctrl_t c)

   Transport address of a controller

**Parameters**

``nvme_ctrl_t c``
  Controller instance

**Return**

Transport address of **c**


.. c:function:: const char * nvme_ctrl_get_trsvcid (nvme_ctrl_t c)

   Transport service identifier of a controller

**Parameters**

``nvme_ctrl_t c``
  Controller instance

**Return**

Transport service identifier of **c** (if present)


.. c:function:: const char * nvme_ctrl_get_host_traddr (nvme_ctrl_t c)

   Host transport address of a controller

**Parameters**

``nvme_ctrl_t c``
  Controller instance

**Return**

Host transport address of **c** (if present)


.. c:function:: const char * nvme_ctrl_get_host_iface (nvme_ctrl_t c)

   Host interface name of a controller

**Parameters**

``nvme_ctrl_t c``
  Controller instance

**Return**

Host interface name of **c** (if present)


.. c:function:: const char * nvme_ctrl_get_dhchap_host_key (nvme_ctrl_t c)

   Return host key

**Parameters**

``nvme_ctrl_t c``
  Controller to be checked

**Return**

DH-HMAC-CHAP host key or NULL if not set


.. c:function:: void nvme_ctrl_set_dhchap_host_key (nvme_ctrl_t c, const char *key)

   Set host key

**Parameters**

``nvme_ctrl_t c``
  Host for which the key should be set

``const char *key``
  DH-HMAC-CHAP Key to set or NULL to clear existing key


.. c:function:: const char * nvme_ctrl_get_dhchap_key (nvme_ctrl_t c)

   Return controller key

**Parameters**

``nvme_ctrl_t c``
  Controller for which the key should be set

**Return**

DH-HMAC-CHAP controller key or NULL if not set


.. c:function:: void nvme_ctrl_set_dhchap_key (nvme_ctrl_t c, const char *key)

   Set controller key

**Parameters**

``nvme_ctrl_t c``
  Controller for which the key should be set

``const char *key``
  DH-HMAC-CHAP Key to set or NULL to clear existing key


.. c:function:: struct nvme_fabrics_config * nvme_ctrl_get_config (nvme_ctrl_t c)

   Fabrics configuration of a controller

**Parameters**

``nvme_ctrl_t c``
  Controller instance

**Return**

Fabrics configuration of **c**


.. c:function:: void nvme_ctrl_set_discovered (nvme_ctrl_t c, bool discovered)

   Set the 'discovered' flag

**Parameters**

``nvme_ctrl_t c``
  nvme_ctrl_t object

``bool discovered``
  Value of the 'discovered' flag

**Description**

Set the 'discovered' flag of **c** to **discovered**


.. c:function:: bool nvme_ctrl_is_discovered (nvme_ctrl_t c)

   Returns the value of the 'discovered' flag

**Parameters**

``nvme_ctrl_t c``
  Controller instance

**Return**

Value of the 'discovered' flag of **c**


.. c:function:: void nvme_ctrl_set_persistent (nvme_ctrl_t c, bool persistent)

   Set the 'persistent' flag

**Parameters**

``nvme_ctrl_t c``
  Controller instance

``bool persistent``
  value of the 'persistent' flag

**Description**

Set the 'persistent' flag of **c** to **persistent**


.. c:function:: bool nvme_ctrl_is_persistent (nvme_ctrl_t c)

   Returns the value of the 'persistent' flag

**Parameters**

``nvme_ctrl_t c``
  Controller instance

**Return**

Value of the 'persistent' flag of **c**


.. c:function:: void nvme_ctrl_set_discovery_ctrl (nvme_ctrl_t c, bool discovery)

   Set the 'discovery_ctrl' flag

**Parameters**

``nvme_ctrl_t c``
  Controller to be modified

``bool discovery``
  value of the discovery_ctrl flag

**Description**

Sets the 'discovery_ctrl' flag in **c** to specify whether
**c** connects to a discovery subsystem.


.. c:function:: bool nvme_ctrl_is_discovery_ctrl (nvme_ctrl_t c)

   Check the 'discovery_ctrl' flag

**Parameters**

``nvme_ctrl_t c``
  Controller to be checked

**Description**

Returns the value of the 'discovery_ctrl' flag which specifies whether
**c** connects to a discovery subsystem.

**Return**

Value of the 'discover_ctrl' flag


.. c:function:: void nvme_ctrl_set_unique_discovery_ctrl (nvme_ctrl_t c, bool unique)

   Set the 'unique_discovery_ctrl' flag

**Parameters**

``nvme_ctrl_t c``
  Controller to be modified

``bool unique``
  value of the unique_disc_ctrl flag

**Description**

Sets the 'unique_discovery_ctrl' flag in **c** to specify wheter
**c** is a unique discovery controller


.. c:function:: bool nvme_ctrl_is_unique_discovery_ctrl (nvme_ctrl_t c)

   Check the 'unique_discovery_ctrl' flag

**Parameters**

``nvme_ctrl_t c``
  Controller to be checked

**Return**

Value of the 'unique_discovery_ctrl' flag


.. c:function:: int nvme_ctrl_identify (nvme_ctrl_t c, struct nvme_id_ctrl *id)

   Issues an 'identify controller' command

**Parameters**

``nvme_ctrl_t c``
  Controller instance

``struct nvme_id_ctrl *id``
  Identify controller data structure

**Description**

Issues an 'identify controller' command to **c** and copies the
data into **id**.

**Return**

0 on success or -1 on failure.


.. c:function:: int nvme_disconnect_ctrl (nvme_ctrl_t c)

   Disconnect a controller

**Parameters**

``nvme_ctrl_t c``
  Controller instance

**Description**

Issues a 'disconnect' fabrics command to **c**

**Return**

0 on success, -1 on failure.


.. c:function:: nvme_ctrl_t nvme_scan_ctrl (nvme_root_t r, const char *name)

   Scan on a controller

**Parameters**

``nvme_root_t r``
  nvme_root_t object

``const char *name``
  Name of the controller

**Description**

Scans a controller with sysfs name **name** and add it to **r**.

**Return**

nvme_ctrl_t object


.. c:function:: void nvme_rescan_ctrl (nvme_ctrl_t c)

   Rescan an existing controller

**Parameters**

``nvme_ctrl_t c``
  Controller instance


.. c:function:: int nvme_init_ctrl (nvme_host_t h, nvme_ctrl_t c, int instance)

   Initialize nvme_ctrl_t object for an existing controller.

**Parameters**

``nvme_host_t h``
  nvme_host_t object

``nvme_ctrl_t c``
  nvme_ctrl_t object

``int instance``
  Instance number (e.g. 1 for nvme1)

**Return**

The ioctl() return code. Typically 0 on success.


.. c:function:: void nvme_free_ctrl (struct nvme_ctrl *c)

   Free controller

**Parameters**

``struct nvme_ctrl *c``
  Controller instance


.. c:function:: void nvme_unlink_ctrl (struct nvme_ctrl *c)

   Unlink controller

**Parameters**

``struct nvme_ctrl *c``
  Controller instance


.. c:function:: const char * nvme_subsystem_get_nqn (nvme_subsystem_t s)

   Retrieve NQN from subsystem

**Parameters**

``nvme_subsystem_t s``
  nvme_subsystem_t object

**Return**

NQN of subsystem


.. c:function:: const char * nvme_subsystem_get_sysfs_dir (nvme_subsystem_t s)

   sysfs directory of an nvme_subsystem_t object

**Parameters**

``nvme_subsystem_t s``
  nvme_subsystem_t object

**Return**

sysfs directory name of **s**


.. c:function:: const char * nvme_subsystem_get_name (nvme_subsystem_t s)

   sysfs name of an nvme_subsystem_t object

**Parameters**

``nvme_subsystem_t s``
  nvme_subsystem_t object

**Return**

sysfs name of **s**


.. c:function:: const char * nvme_subsystem_get_type (nvme_subsystem_t s)

   Returns the type of a subsystem

**Parameters**

``nvme_subsystem_t s``
  nvme_subsystem_t object

**Description**

Returns the subsystem type of **s**.

**Return**

'nvm' or 'discovery'


.. c:function:: int nvme_scan_topology (nvme_root_t r, nvme_scan_filter_t f, void *f_args)

   Scan NVMe topology and apply filter

**Parameters**

``nvme_root_t r``
  nvme_root_t object

``nvme_scan_filter_t f``
  filter to apply

``void *f_args``
  user-specified argument to **f**

**Description**

Scans the NVMe topology and filters out the resulting elements
by applying **f**.

**Return**

Number of elements scanned


.. c:function:: const char * nvme_host_get_hostnqn (nvme_host_t h)

   Host NQN of an nvme_host_t object

**Parameters**

``nvme_host_t h``
  nvme_host_t object

**Return**

Host NQN of **h**


.. c:function:: const char * nvme_host_get_hostid (nvme_host_t h)

   Host ID of an nvme_host_t object

**Parameters**

``nvme_host_t h``
  nvme_host_t object

**Return**

Host ID of **h**


.. c:function:: void nvme_free_host (nvme_host_t h)

   Free nvme_host_t object

**Parameters**

``nvme_host_t h``
  nvme_host_t object


.. c:function:: nvme_root_t nvme_scan (const char *config_file)

   Scan NVMe topology

**Parameters**

``const char *config_file``
  Configuration file

**Return**

nvme_root_t object of found elements


.. c:function:: int nvme_read_config (nvme_root_t r, const char *config_file)

   Read NVMe JSON configuration file

**Parameters**

``nvme_root_t r``
  nvme_root_t object

``const char *config_file``
  JSON configuration file

**Description**

Read in the contents of **config_file** and merge them with
the elements in **r**.

**Return**

0 on success, -1 on failure with errno set.


.. c:function:: void nvme_refresh_topology (nvme_root_t r)

   Refresh nvme_root_t object contents

**Parameters**

``nvme_root_t r``
  nvme_root_t object

**Description**

Removes all elements in **r** and rescans the existing topology.


.. c:function:: int nvme_update_config (nvme_root_t r)

   Update JSON configuration

**Parameters**

``nvme_root_t r``
  nvme_root_t object

**Description**

Updates the JSON configuration file with the contents of **r**.

**Return**

0 on success, -1 on failure.


.. c:function:: int nvme_dump_config (nvme_root_t r)

   Print the JSON configuration

**Parameters**

``nvme_root_t r``
  nvme_root_t object

**Description**

Prints the current contents of the JSON configuration
file to stdout.

**Return**

0 on success, -1 on failure.


.. c:function:: int nvme_dump_tree (nvme_root_t r)

   Dump internal object tree

**Parameters**

``nvme_root_t r``
  nvme_root_t object

**Description**

Prints the internal object tree in JSON format
to stdout.

**Return**

0 on success, -1 on failure.


.. c:function:: char * nvme_get_attr (const char *d, const char *attr)

   Read sysfs attribute

**Parameters**

``const char *d``
  sysfs directory

``const char *attr``
  sysfs attribute name

**Return**

String with the contents of **attr** or ``NULL`` in case of an empty value
        or in case of an error (indicated by non-zero errno code).


.. c:function:: char * nvme_get_subsys_attr (nvme_subsystem_t s, const char *attr)

   Read subsystem sysfs attribute

**Parameters**

``nvme_subsystem_t s``
  nvme_subsystem_t object

``const char *attr``
  sysfs attribute name

**Return**

String with the contents of **attr** or ``NULL`` in case of an empty value
        or in case of an error (indicated by non-zero errno code).


.. c:function:: char * nvme_get_ctrl_attr (nvme_ctrl_t c, const char *attr)

   Read controller sysfs attribute

**Parameters**

``nvme_ctrl_t c``
  Controller instance

``const char *attr``
  sysfs attribute name

**Return**

String with the contents of **attr** or ``NULL`` in case of an empty value
        or in case of an error (indicated by non-zero errno code).


.. c:function:: char * nvme_get_ns_attr (nvme_ns_t n, const char *attr)

   Read namespace sysfs attribute

**Parameters**

``nvme_ns_t n``
  nvme_ns_t object

``const char *attr``
  sysfs attribute name

**Return**

String with the contents of **attr** or ``NULL`` in case of an empty value
        or in case of an error (indicated by non-zero errno code).


.. c:function:: nvme_ns_t nvme_subsystem_lookup_namespace (struct nvme_subsystem *s, __u32 nsid)

   lookup namespace by NSID

**Parameters**

``struct nvme_subsystem *s``
  nvme_subsystem_t object

``__u32 nsid``
  Namespace id

**Return**

nvme_ns_t of the namespace with id **nsid** in subsystem **s**


.. c:function:: char * nvme_get_path_attr (nvme_path_t p, const char *attr)

   Read path sysfs attribute

**Parameters**

``nvme_path_t p``
  nvme_path_t object

``const char *attr``
  sysfs attribute name

**Return**

String with the contents of **attr** or ``NULL`` in case of an empty value
        or in case of an error (indicated by non-zero errno code).


.. c:function:: nvme_ns_t nvme_scan_namespace (const char *name)

   scan namespace based on sysfs name

**Parameters**

``const char *name``
  sysfs name of the namespace to scan

**Return**

nvme_ns_t object or NULL if not found.


.. c:function:: const char * nvme_host_get_hostsymname (nvme_host_t h)

   Get the host's symbolic name

**Parameters**

``nvme_host_t h``
  Host for which the symbolic name should be returned.

**Return**

The symbolic name or NULL if a symbolic name hasn't been
configure.


.. c:function:: void nvme_host_set_hostsymname (nvme_host_t h, const char *hostsymname)

   Set the host's symbolic name

**Parameters**

``nvme_host_t h``
  Host for which the symbolic name should be set.

``const char *hostsymname``
  Symbolic name


