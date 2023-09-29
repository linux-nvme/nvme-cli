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


