.. _scan.h:

**scan.h**


.. c:function:: int libnvme_scan_subsystems (struct libnvme_global_ctx *ctx, struct dirent ***subsys)

   Scan for subsystems

**Parameters**

``struct libnvme_global_ctx *ctx``
  :c:type:`struct libnvme_global_ctx <libnvme_global_ctx>` object

``struct dirent ***subsys``
  Pointer to array of dirents

**Return**

number of entries in **subsys** or a negative error code


.. c:function:: int libnvme_scan_subsystem_namespaces (struct libnvme_subsystem *s, struct dirent ***ns)

   Scan for namespaces in a subsystem

**Parameters**

``struct libnvme_subsystem *s``
  Subsystem to scan

``struct dirent ***ns``
  Pointer to array of dirents

**Return**

number of entries in **ns** or a negative error code


.. c:function:: int libnvme_scan_ctrls (struct libnvme_global_ctx *ctx, struct dirent ***ctrls)

   Scan for controllers

**Parameters**

``struct libnvme_global_ctx *ctx``
  :c:type:`struct libnvme_global_ctx <libnvme_global_ctx>` object

``struct dirent ***ctrls``
  Pointer to array of dirents

**Return**

number of entries in **ctrls** or a negative error code


.. c:function:: int libnvme_scan_ctrl_namespace_paths (struct libnvme_ctrl *c, struct dirent ***paths)

   Scan for namespace paths in a controller

**Parameters**

``struct libnvme_ctrl *c``
  Controller to scan

``struct dirent ***paths``
  Pointer to array of dirents

**Return**

number of entries in **paths** or a negative error code


.. c:function:: int libnvme_scan_ctrl_namespaces (struct libnvme_ctrl *c, struct dirent ***ns)

   Scan for namespaces in a controller

**Parameters**

``struct libnvme_ctrl *c``
  Controller to scan

``struct dirent ***ns``
  Pointer to array of dirents

**Return**

number of entries in **ns** or a negative error code


.. c:function:: int libnvme_scan_ns_head_paths (struct libnvme_ns_head *head, struct dirent ***paths)

   Scan for namespace paths

**Parameters**

``struct libnvme_ns_head *head``
  Namespace head node to scan

``struct dirent ***paths``
  Pointer to array of dirents

**Return**

number of entries in **ents** or a negative error code


