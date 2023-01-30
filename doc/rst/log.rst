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


