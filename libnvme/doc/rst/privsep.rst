.. _privsep.h:

**privsep.h**


Privilege separation

A privileged process starts the helper with libnvme_privsep_spawn() and
then drops its privileges. A global context with an attached helper
opens devices through the helper. The helper issues the ioctls and
returns the raw results.

.. c:function:: int libnvme_privsep_spawn (const char *helper, struct libnvme_privsep **psp)

   Start the privilege separation helper

**Parameters**

``const char *helper``
  Path of the helper binary or NULL for the installed helper

``struct libnvme_privsep **psp``
  On success, the helper channel

**Description**

Starts the helper as a child process and checks that it speaks the same
protocol version. The helper inherits the credentials of the caller, so
call this function before dropping privileges.

**Return**

0 on success or a negative error code otherwise.


.. c:function:: void libnvme_privsep_free (struct libnvme_privsep *ps)

   Stop the privilege separation helper

**Parameters**

``struct libnvme_privsep *ps``
  Helper channel

**Description**

Closes the channel and waits for the helper to exit. All transport
handles opened through the helper must be closed before.


.. c:function:: void libnvme_set_privsep (struct libnvme_global_ctx *ctx, struct libnvme_privsep *ps)

   Open devices through the helper

**Parameters**

``struct libnvme_global_ctx *ctx``
  :c:type:`struct libnvme_global_ctx <libnvme_global_ctx>` object

``struct libnvme_privsep *ps``
  Helper channel or NULL to open devices directly

**Description**

libnvme_open() on **ctx** returns transport handles which forward the
commands to the helper. MI endpoints are not affected. Several contexts
can share one helper channel. The channel must outlive the contexts and
their transport handles. Commands on one channel must not be issued
concurrently.


