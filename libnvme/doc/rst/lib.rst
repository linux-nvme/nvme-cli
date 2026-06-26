.. c:function:: struct libnvme_global_ctx * libnvme_create_global_ctx (void)

   Initialize global context object

**Parameters**

``void``
  no arguments

**Description**


Creates a global context with default settings: logging to stderr at
LIBNVME_DEFAULT_LOGLEVEL.  Use libnvme_set_logging_file() and
libnvme_set_logging_level() to adjust these after creation.

**Return**

Initialized :c:type:`struct libnvme_global_ctx <libnvme_global_ctx>` object


.. c:function:: void libnvme_free_global_ctx (struct libnvme_global_ctx *ctx)

   Free global context object

**Parameters**

``struct libnvme_global_ctx *ctx``
  :c:type:`struct libnvme_global_ctx <libnvme_global_ctx>` object

**Description**

Free an :c:type:`struct libnvme_global_ctx <libnvme_global_ctx>` object and all attached objects


.. c:function:: int libnvme_set_owner (struct libnvme_global_ctx *ctx, const char *owner)

   Set the orchestrator identity for the registry

**Parameters**

``struct libnvme_global_ctx *ctx``
  :c:type:`struct libnvme_global_ctx <libnvme_global_ctx>` object

``const char *owner``
  Orchestrator identity string (e.g. "stas", "nbft").

**Description**

Records the orchestrator identity used when claiming registry ownership of
connections made through **ctx**.  A later call overwrites the previous value;
treating the identity as immutable is a policy decision left to the caller.
A process that does not participate in the registry simply never calls this.

This is the supported way to record the registry owner;
libnvme_create_global_ctx() deliberately takes no owner parameter.

**Return**

0 on success, -EINVAL or -ENOMEM on error.


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


.. c:function:: void libnvme_set_logging_file (struct libnvme_global_ctx *ctx, FILE *fp)

   Set the log output file for the global context

**Parameters**

``struct libnvme_global_ctx *ctx``
  struct libnvme_global_ctx object

``FILE *fp``
  File stream to write log messages to, or NULL to use stderr

**Description**

Sets the file descriptor used for log output.  Passing NULL reverts to the
default (stderr).


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

0 on success, negative error code otherwise.


.. c:function:: void libnvme_close (struct libnvme_transport_handle *hdl)

   Close transport handle

**Parameters**

``struct libnvme_transport_handle *hdl``
  Transport handle


.. c:function:: libnvme_fd_t libnvme_transport_handle_get_fd (struct libnvme_transport_handle *hdl)

   Return file descriptor from the transport handle

**Parameters**

``struct libnvme_transport_handle *hdl``
  Transport handle

**Description**

If the device handle is for a ioctl based device,
libnvme_transport_handle_get_fd will return a valid file descriptor.

**Return**

File descriptor for an IOCTL based transport handle,
otherwise LIBNVME_INVALID_FD.


.. c:function:: struct libnvme_mi_ep * libnvme_transport_handle_get_mi_ep (struct libnvme_transport_handle *hdl)

   get the MI endpoint from a transport handle

**Parameters**

``struct libnvme_transport_handle *hdl``
  transport handle

**Description**

Retrieve the MI endpoint associated with this transport handle. Only valid
for MI-type transport handles (check with libnvme_transport_handle_is_mi
first).

**Return**

the MI endpoint, or NULL if the handle is not an MI handle.


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


.. c:function:: void libnvme_transport_handle_set_timeout (struct libnvme_transport_handle *hdl, __u32 timeout_ms)

   Set the default command timeout

**Parameters**

``struct libnvme_transport_handle *hdl``
  Transport handle to configure

``__u32 timeout_ms``
  Timeout in milliseconds. A value of 0 means use the kernel
  default (NVME_DEFAULT_IOCTL_TIMEOUT).

**Description**

Sets a default timeout that is applied to every passthrough command
submitted through **hdl** when the command's own timeout_ms field is 0.
Commands that set a non-zero timeout_ms override this default.


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


