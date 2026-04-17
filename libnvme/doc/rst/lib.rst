.. c:function:: struct libnvme_global_ctx * libnvme_create_global_ctx (FILE *fp, int log_level)

   Initialize global context object

**Parameters**

``FILE *fp``
  File descriptor for logging messages

``int log_level``
  Logging level to use

**Return**

Initialized :c:type:`struct libnvme_global_ctx <libnvme_global_ctx>` object


.. c:function:: void libnvme_free_global_ctx (struct libnvme_global_ctx *ctx)

   Free global context object

**Parameters**

``struct libnvme_global_ctx *ctx``
  :c:type:`struct libnvme_global_ctx <libnvme_global_ctx>` object

**Description**

Free an :c:type:`struct libnvme_global_ctx <libnvme_global_ctx>` object and all attached objects


.. c:function:: void libnvme_set_logging_level (struct libnvme_global_ctx *ctx, int log_level, bool log_pid, bool log_tstamp)

   Set current logging level

**Parameters**

``struct libnvme_global_ctx *ctx``
  struct libnvme_global_ctx object

``int log_level``
  Logging level to set

``bool log_pid``
  Boolean to enable logging of the PID

``bool log_tstamp``
  Boolean to enable logging of the timestamp

**Description**

Sets the current logging level for the global context.


.. c:function:: int libnvme_get_logging_level (struct libnvme_global_ctx *ctx, bool *log_pid, bool *log_tstamp)

   Get current logging level

**Parameters**

``struct libnvme_global_ctx *ctx``
  struct libnvme_global_ctx object

``bool *log_pid``
  Pointer to store a current value of logging of
  the PID flag at (optional).

``bool *log_tstamp``
  Pointer to store a current value of logging of
  the timestamp flag at (optional).

**Description**

Retrieves current values of logging variables.

**Return**

current log level value or LIBNVME_DEFAULT_LOGLEVEL if not initialized.


.. c:function:: int libnvme_open (struct libnvme_global_ctx *ctx, const char *name, struct libnvme_transport_handle **hdl)

   Open an nvme controller or namespace device

**Parameters**

``struct libnvme_global_ctx *ctx``
  struct libnvme_global_ctx object

``const char *name``
  The basename of the device to open

``struct libnvme_transport_handle **hdl``
  Transport handle to return

**Description**

This will look for the handle in /dev/ and validate the name and filetype
match linux conventions.

**Return**

0 on success or negative error code otherwise


.. c:function:: void libnvme_close (struct libnvme_transport_handle *hdl)

   Close transport handle

**Parameters**

``struct libnvme_transport_handle *hdl``
  Transport handle


.. c:function:: int libnvme_transport_handle_get_fd (struct libnvme_transport_handle *hdl)

   Return file descriptor from the transport handle

**Parameters**

``struct libnvme_transport_handle *hdl``
  Transport handle

**Description**

If the device handle is for a ioctl based device,
libnvme_transport_handle_get_fd will return a valid file descriptor.

**Return**

File descriptor for an IOCTL based transport handle, otherwise -1.


.. c:function:: const char * libnvme_transport_handle_get_name (struct libnvme_transport_handle *hdl)

   Return name of the device transport handle

**Parameters**

``struct libnvme_transport_handle *hdl``
  Transport handle

**Return**

Device file name, otherwise -1.


.. c:function:: bool libnvme_transport_handle_is_ctrl (struct libnvme_transport_handle *hdl)

   Check if transport handle is a controller device

**Parameters**

``struct libnvme_transport_handle *hdl``
  Transport handle

**Return**

Return true if transport handle is a controller device,
otherwise false.


.. c:function:: bool libnvme_transport_handle_is_direct (struct libnvme_transport_handle *hdl)

   Check if transport handle is using IOCTL interface

**Parameters**

``struct libnvme_transport_handle *hdl``
  Transport handle

**Return**

Return true if transport handle is using IOCTL interface,
otherwise false.


.. c:function:: bool libnvme_transport_handle_is_mi (struct libnvme_transport_handle *hdl)

   Check if transport handle is a using MI interface

**Parameters**

``struct libnvme_transport_handle *hdl``
  Transport handle

**Return**

Return true if transport handle is using MI interface,
otherwise false.


.. c:function:: bool libnvme_transport_handle_is_ns (struct libnvme_transport_handle *hdl)

   Check if transport handle is a namespace device

**Parameters**

``struct libnvme_transport_handle *hdl``
  Transport handle

**Return**

Return true if transport handle is a namespace device,
otherwise false.


.. c:function:: void libnvme_transport_handle_set_submit_entry (struct libnvme_transport_handle *hdl, void *(*submit_entry)(struct libnvme_transport_handle *hdl, struct libnvme_passthru_cmd *cmd))

   Install a submit-entry callback

**Parameters**

``struct libnvme_transport_handle *hdl``
  Transport handle to configure

``void *(*submit_entry)(struct libnvme_transport_handle *hdl, struct libnvme_passthru_cmd *cmd)``
  Callback invoked immediately before a passthrough command is
  submitted. The function receives the command about to be issued
  and may return an opaque pointer representing per-command
  context. This pointer is later passed unmodified to the
  submit-exit callback. Implementations typically use this hook
  for logging, tracing, or allocating per-command state.

**Description**

Installs a user-defined callback that is invoked at the moment a passthrough
command enters the NVMe submission path. Passing NULL removes any previously
installed callback.

**Return**

None.


.. c:function:: void libnvme_transport_handle_set_submit_exit (struct libnvme_transport_handle *hdl, void (*submit_exit)(struct libnvme_transport_handle *hdl, struct libnvme_passthru_cmd *cmd, int err, void *user_data))

   Install a submit-exit callback

**Parameters**

``struct libnvme_transport_handle *hdl``
  Transport handle to configure

``void (*submit_exit)(struct libnvme_transport_handle *hdl, struct libnvme_passthru_cmd *cmd, int err, void *user_data)``
  Callback invoked after a passthrough command completes. The
  function receives the command, the completion status **err**
  (0 for success, a negative errno, or an NVMe status value), and
  the **user_data** pointer returned earlier by the submit-entry
  callback. Implementations typically use this hook for logging,
  tracing, or freeing per-command state.

**Description**

Installs a callback that is invoked when a passthrough command leaves the
NVMe submission path. Passing NULL removes any previously installed callback.

**Return**

None.


.. c:function:: void libnvme_transport_handle_set_decide_retry (struct libnvme_transport_handle *hdl, bool (*decide_retry)(struct libnvme_transport_handle *hdl, struct libnvme_passthru_cmd *cmd, int err))

   Install a retry-decision callback

**Parameters**

``struct libnvme_transport_handle *hdl``
  Transport handle to configure

``bool (*decide_retry)(struct libnvme_transport_handle *hdl, struct libnvme_passthru_cmd *cmd, int err)``
  Callback used to determine whether a passthrough command
  should be retried after an error. The function is called with
  the command that failed and the error code returned by the
  kernel or device. The callback should return true if the
  submission path should retry the command, or false if the
  error is final.

**Description**

Installs a user-provided callback to control retry behavior for
passthrough commands issued through **hdl**. This allows transports or
higher-level logic to implement custom retry policies, such as retrying on
transient conditions like -EAGAIN or device-specific status codes.

Passing NULL clears any previously installed callback and reverts to the
default behavior (no retries).

**Return**

None.


.. c:function:: void libnvme_set_probe_enabled (struct libnvme_global_ctx *ctx, bool enabled)

   enable/disable the probe for new MI endpoints

**Parameters**

``struct libnvme_global_ctx *ctx``
  :c:type:`struct libnvme_global_ctx <libnvme_global_ctx>` object

``bool enabled``
  whether to probe new endpoints

**Description**

Controls whether newly-created endpoints are probed for quirks on creation.
Defaults to enabled, which results in some initial messaging with the
endpoint to determine model-specific details.


.. c:function:: void libnvme_set_dry_run (struct libnvme_global_ctx *ctx, bool enable)

   Set global dry run state

**Parameters**

``struct libnvme_global_ctx *ctx``
  struct libnvme_global_ctx object

``bool enable``
  Enable/disable dry run state

**Description**

When dry_run is enabled, any IOCTL commands send via the passthru
interface won't be executed.


.. c:function:: void libnvme_set_ioctl_probing (struct libnvme_global_ctx *ctx, bool enable)

   Enable/disable 64-bit IOCTL probing

**Parameters**

``struct libnvme_global_ctx *ctx``
  struct libnvme_global_ctx object

``bool enable``
  Enable/disable 64-bit IOCTL probing

**Description**

When IOCTL probing is enabled, a 64-bit IOCTL command is issued to
figure out if the passthru interface supports it.

IOCTL probing is enabled per default.


