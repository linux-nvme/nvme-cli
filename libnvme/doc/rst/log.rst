.. _log.h:

**log.h**


logging functions

.. c:function:: void nvme_init_logging (nvme_root_t r, int lvl, bool log_pid, bool log_tstamp)

   Initialize logging

**Parameters**

``nvme_root_t r``
  nvme_root_t context

``int lvl``
  Logging level to set

``bool log_pid``
  Boolean to enable logging of the PID

``bool log_tstamp``
  Boolean to enable logging of the timestamp

**Description**

Sets the default logging variables for the library.


.. c:function:: void nvme_init_default_logging (FILE *fp, int lvl, bool log_pid, bool log_tstamp)

   Initialize default (fallback) logging

**Parameters**

``FILE *fp``
  File descriptor for logging messages

``int lvl``
  Logging level to set

``bool log_pid``
  Boolean to enable logging of the PID

``bool log_tstamp``
  Boolean to enable logging of the timestamp

**Description**

Sets the default logging settings for the library in case the root object
is absent.


.. c:function:: int nvme_get_logging_level (nvme_root_t r, bool *log_pid, bool *log_tstamp)

   Get current logging level

**Parameters**

``nvme_root_t r``
  nvme_root_t context

``bool *log_pid``
  Pointer to store a current value of logging of
  the PID flag at (optional).

``bool *log_tstamp``
  Pointer to store a current value of logging of
  the timestamp flag at (optional).

**Description**

Retrieves current values of logging variables.

**Return**

current log level value or DEFAULT_LOGLEVEL if not initialized.


.. c:function:: void nvme_set_root (nvme_root_t r)

   Set nvme_root_t context

**Parameters**

``nvme_root_t r``
  nvme_root_t context

**Description**

In order to be able to log from code paths where no root object is passed in
via the arguments use the the default one which can be set via this call.
When creating a new root object with **nvme_create_root** the global root object
will be set as well. This means the global root object is always pointing to
the latest created root object. Note the first **nvme_free_tree** call will reset
the global root object.

This function is deprecated. Use nvme_init_default_logging or/and
nvme_init_logging instead.


.. c:function:: void nvme_set_debug (bool debug)

   Set NVMe command debugging output

**Parameters**

``bool debug``
  true to enable or false to disable

**Description**

This function is deprecated. Use nvme_init_default_logging instead.


.. c:function:: bool nvme_get_debug (void)

   Get NVMe command debugging output

**Parameters**

``void``
  no arguments

**Description**


This function is deprecated. Use nvme_get_logging_level instead.

**Return**

false if disabled or true if enabled.


