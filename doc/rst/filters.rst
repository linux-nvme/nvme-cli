.. _filters.h:

**filters.h**


libnvme directory filter

.. c:function:: int nvme_namespace_filter (const struct dirent *d)

   Filter for namespaces

**Parameters**

``const struct dirent *d``
  dirent to check

**Return**

1 if **d** matches, 0 otherwise


.. c:function:: int nvme_paths_filter (const struct dirent *d)

   Filter for paths

**Parameters**

``const struct dirent *d``
  dirent to check

**Return**

1 if **d** matches, 0 otherwise


.. c:function:: int nvme_ctrls_filter (const struct dirent *d)

   Filter for controllers

**Parameters**

``const struct dirent *d``
  dirent to check

**Return**

1 if **d** matches, 0 otherwise


.. c:function:: int nvme_subsys_filter (const struct dirent *d)

   Filter for subsystems

**Parameters**

``const struct dirent *d``
  dirent to check

**Return**

1 if **d** matches, 0 otherwise


.. c:function:: int nvme_scan_subsystems (struct dirent ***subsys)

   Scan for subsystems

**Parameters**

``struct dirent ***subsys``
  Pointer to array of dirents

**Return**

number of entries in **subsys**


.. c:function:: int nvme_scan_subsystem_namespaces (nvme_subsystem_t s, struct dirent ***ns)

   Scan for namespaces in a subsystem

**Parameters**

``nvme_subsystem_t s``
  Subsystem to scan

``struct dirent ***ns``
  Pointer to array of dirents

**Return**

number of entries in **ns**


.. c:function:: int nvme_scan_ctrls (struct dirent ***ctrls)

   Scan for controllers

**Parameters**

``struct dirent ***ctrls``
  Pointer to array of dirents

**Return**

number of entries in **ctrls**


.. c:function:: int nvme_scan_ctrl_namespace_paths (nvme_ctrl_t c, struct dirent ***paths)

   Scan for namespace paths in a controller

**Parameters**

``nvme_ctrl_t c``
  Controller to scan

``struct dirent ***paths``
  Pointer to array of dirents

**Return**

number of entries in **paths**


.. c:function:: int nvme_scan_ctrl_namespaces (nvme_ctrl_t c, struct dirent ***ns)

   Scan for namespaces in a controller

**Parameters**

``nvme_ctrl_t c``
  Controller to scan

``struct dirent ***ns``
  Pointer to array of dirents

**Return**

number of entries in **ns**


