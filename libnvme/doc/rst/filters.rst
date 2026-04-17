.. _filters.h:

**filters.h**


libnvme directory filter

.. c:function:: int libnvme_filter_namespace (const struct dirent *d)

   Filter for namespaces

**Parameters**

``const struct dirent *d``
  dirent to check

**Return**

1 if **d** matches, 0 otherwise


.. c:function:: int libnvme_filter_paths (const struct dirent *d)

   Filter for paths

**Parameters**

``const struct dirent *d``
  dirent to check

**Return**

1 if **d** matches, 0 otherwise


.. c:function:: int libnvme_filter_ctrls (const struct dirent *d)

   Filter for controllers

**Parameters**

``const struct dirent *d``
  dirent to check

**Return**

1 if **d** matches, 0 otherwise


.. c:function:: int libnvme_filter_subsys (const struct dirent *d)

   Filter for subsystems

**Parameters**

``const struct dirent *d``
  dirent to check

**Return**

1 if **d** matches, 0 otherwise


.. c:function:: int libnvme_scan_subsystems (struct dirent ***subsys)

   Scan for subsystems

**Parameters**

``struct dirent ***subsys``
  Pointer to array of dirents

**Return**

number of entries in **subsys** or a negative error code


.. c:function:: int libnvme_scan_subsystem_namespaces (libnvme_subsystem_t s, struct dirent ***ns)

   Scan for namespaces in a subsystem

**Parameters**

``libnvme_subsystem_t s``
  Subsystem to scan

``struct dirent ***ns``
  Pointer to array of dirents

**Return**

number of entries in **ns** or a negative error code


.. c:function:: int libnvme_scan_ctrls (struct dirent ***ctrls)

   Scan for controllers

**Parameters**

``struct dirent ***ctrls``
  Pointer to array of dirents

**Return**

number of entries in **ctrls** or a negative error code


.. c:function:: int libnvme_scan_ctrl_namespace_paths (libnvme_ctrl_t c, struct dirent ***paths)

   Scan for namespace paths in a controller

**Parameters**

``libnvme_ctrl_t c``
  Controller to scan

``struct dirent ***paths``
  Pointer to array of dirents

**Return**

number of entries in **paths** or a negative error code


.. c:function:: int libnvme_scan_ctrl_namespaces (libnvme_ctrl_t c, struct dirent ***ns)

   Scan for namespaces in a controller

**Parameters**

``libnvme_ctrl_t c``
  Controller to scan

``struct dirent ***ns``
  Pointer to array of dirents

**Return**

number of entries in **ns** or a negative error code


.. c:function:: int libnvme_scan_ns_head_paths (libnvme_ns_head_t head, struct dirent ***paths)

   Scan for namespace paths

**Parameters**

``libnvme_ns_head_t head``
  Namespace head node to scan

``struct dirent ***paths``
  Pointer to array of dirents

**Return**

number of entries in **ents** or a negative error code


