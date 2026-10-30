.. _registry.h:

**registry.h**


NVMe controller ownership registry.

The registry records which orchestrator owns each connected NVMe-oF
controller.  It is stored under /run/nvme/registry/ as one directory per
live controller (e.g. nvme3/), containing one plain text file per attribute
(e.g. nvme3/owner).  Registry support is only available when fabrics support
is enabled (-Dfabrics=enabled).

The registry is a cooperative coordination mechanism.  All participants are
assumed to be cooperative; there is no OS-level enforcement.  Its primary
purpose is to prevent accidental disconnection of controllers managed by one
orchestrator by another.

.. c:function:: int libnvmf_registry_retrieve (struct libnvme_global_ctx *ctx, const char *device, const char *attr, char **value)

   Read an attribute from a controller's registry entry

**Parameters**

``struct libnvme_global_ctx *ctx``
  libnvme global context; must not be NULL

``const char *device``
  Kernel device name (e.g. "nvme3")

``const char *attr``
  Attribute name to retrieve (e.g. "owner")

``char **value``
  On success, set to a newly allocated string with the attribute
  value.  The caller must free this string.

**Return**

0 on success, -ENOENT if the controller is not registered or the
attribute is not present, -ENOMEM on allocation failure, negative errno
from underlying system calls otherwise.


.. c:function:: int libnvmf_registry_attr_equal (struct libnvme_global_ctx *ctx, const char *device, const char *attr, const char *value)

   Compare a registry attribute to a value

**Parameters**

``struct libnvme_global_ctx *ctx``
  libnvme global context; must not be NULL

``const char *device``
  Kernel device name (e.g. "nvme3")

``const char *attr``
  Attribute name to compare (e.g. "owner")

``const char *value``
  Value to compare against; NULL means "attribute absent"

**Return**

0 if **attr** equals **value** (a missing attribute equals a NULL
**value**), >0 if it differs, negative errno on a read error.


.. c:function:: int libnvmf_registry_update (struct libnvme_global_ctx *ctx, const char *device, const char *attr, const char *value)

   Update an attribute in a controller's registry entry

**Parameters**

``struct libnvme_global_ctx *ctx``
  libnvme global context; must not be NULL

``const char *device``
  Kernel device name (e.g. "nvme3")

``const char *attr``
  Attribute name to update (e.g. "owner")

``const char *value``
  New attribute value, or NULL to remove the attribute file

**Description**

Writes the attribute value to the controller's registry entry using an
atomic tmp-file rename.  If the entry does not exist, it is created
atomically the same way as on connect, including the best-effort seqnum
stamp for the udev cleanup rule.  If **value** is NULL, the attribute file is
removed instead; a missing entry is left alone in this case.

**Return**

0 on success, negative errno from underlying system calls otherwise.


.. c:function:: int libnvmf_registry_delete (struct libnvme_global_ctx *ctx, const char *device)

   Remove a controller's registry entry

**Parameters**

``struct libnvme_global_ctx *ctx``
  libnvme global context; must not be NULL

``const char *device``
  Kernel device name (e.g. "nvme3")

**Description**

Removes the registry directory and all attribute files for **device**.  Called
by the owning orchestrator on intentional disconnect.  The udev REMOVE rule
handles the common case of kernel-driven removal directly via rm -rf and
does not call this function.

**Return**

0 on success, -ENOENT if no entry exists, negative errno from
underlying system calls otherwise.


.. c:function:: int libnvmf_registry_device_for_each (struct libnvme_global_ctx *ctx, int (*callback)(const char *device, void *user_data), void *user_data)

   Iterate over live controller registry entries

**Parameters**

``struct libnvme_global_ctx *ctx``
  libnvme global context; must not be NULL

``int (*callback)(const char *device, void *user_data)``
  Callback invoked for each live entry

``void *user_data``
  User data passed to **callback**

**Description**

Scans the registry directory and invokes **callback** for each entry whose
corresponding /dev/nvmeN device node exists.  Stale entries left behind
after a controller is removed are silently skipped.  The existence check is
advisory: a device may be removed between the check and callback invocation;
callers should handle ENOENT gracefully.

**Return**

0 on success, negative errno if the registry directory cannot be
opened.  Returns 0 when the directory does not exist (nothing registered).


.. c:function:: int libnvmf_registry_attr_for_each (struct libnvme_global_ctx *ctx, const char *device, void (*callback)(const char *attr, const char *value, void *user_data), void *user_data)

   Iterate over attributes in a controller's registry entry

**Parameters**

``struct libnvme_global_ctx *ctx``
  libnvme global context; must not be NULL

``const char *device``
  Kernel device name (e.g. "nvme3")

``void (*callback)(const char *attr, const char *value, void *user_data)``
  Callback invoked for each attribute

``void *user_data``
  User data passed to **callback**

**Description**

Opens the registry directory for **device** and invokes **callback** for each
attribute file found.  Attribute files that disappear during iteration
(e.g. because the device is removed concurrently) are silently skipped.

**Return**

0 on success, -ENOENT if the device directory does not exist at the
time of the initial open, negative errno otherwise.


