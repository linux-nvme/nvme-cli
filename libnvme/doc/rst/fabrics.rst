.. _fabrics.h:

**fabrics.h**


Fabrics-specific definitions.

.. c:function:: char * libnvmf_generate_hostnqn (void)

   Generate a machine specific host nqn

**Parameters**

``void``
  no arguments

**Return**

An nvm namespace qualified name string based on the machine
identifier, or NULL if not successful.


.. c:function:: char * libnvmf_generate_hostnqn_from_hostid (char *hostid)

   Generate a host nqn from host identifier

**Parameters**

``char *hostid``
  Host identifier

**Description**

If **hostid** is NULL, the function generates it based on the machine
identifier.

**Return**

On success, an NVMe Qualified Name for host identification. This
name is based on the given host identifier. On failure, NULL.


.. c:function:: char * libnvmf_generate_hostid (void)

   Generate a machine specific host identifier

**Parameters**

``void``
  no arguments

**Return**

On success, an identifier string based on the machine identifier to
be used as NVMe Host Identifier, or NULL on failure.


.. c:function:: char * libnvmf_read_hostnqn (struct libnvme_global_ctx *ctx)

   Reads the host nvm qualified name from the config default location

**Parameters**

``struct libnvme_global_ctx *ctx``
  struct libnvme_global_ctx object

**Description**

Retrieve the qualified name from the config file located in $SYSCONFDIR/nvme.
$SYSCONFDIR is usually /etc.

**Return**

The host nqn, or NULL if unsuccessful. If found, the caller
is responsible to free the string.


.. c:function:: char * libnvmf_read_hostid (struct libnvme_global_ctx *ctx)

   Reads the host identifier from the config default location

**Parameters**

``struct libnvme_global_ctx *ctx``
  struct libnvme_global_ctx object

**Description**

Retrieve the host idenditifer from the config file located in
$SYSCONFDIR/nvme/. $SYSCONFDIR is usually /etc.

**Return**

The host identifier, or NULL if unsuccessful. If found, the caller
        is responsible to free the string.


.. c:function:: int libnvmf_host_get_ids (struct libnvme_global_ctx *ctx, const char *hostnqn_arg, const char *hostid_arg, char **hostnqn, char **hostid)

   Retrieve host ids from various sources

**Parameters**

``struct libnvme_global_ctx *ctx``
  struct libnvme_global_ctx object

``const char *hostnqn_arg``
  Input hostnqn (command line) argument

``const char *hostid_arg``
  Input hostid (command line) argument

``char **hostnqn``
  Output hostnqn; may be NULL if the caller does not need it

``char **hostid``
  Output hostid; may be NULL if the caller does not need it

**Description**

libnvmf_host_get_ids figures out which hostnqn/hostid is to be used.
There are several sources where this information can be retrieved.

The order is:

 - Start with hostnqn/hostid given on the command line
   (**hostnqn_arg**, **hostid_arg**), if any
 - Otherwise, use the first host already resolved in **ctx**'s host
   list, if any
 - Otherwise, use **ctx**'s own hostnqn/hostid default, or
   /etc/nvme/hostnqn and /etc/nvme/hostid if **ctx** has none
 - Otherwise, if hostnqn is known but hostid is not, and hostnqn
   has a "uuid:" component, derive hostid from it
 - As a last resort, derive a still-missing hostid from DMI or
   device-tree information (or generate a random one), then build
   a hostnqn from that hostid if one is still missing

 The function also checks that hostnqn and hostid match, logging a
 debug warning if not. The Linux NVMe implementation expects a 1:1
 matching between the IDs.

**Return**

0 on success (**hostnqn** and **hostid** contain valid strings
 which the caller needs to free), or negative error code otherwise.


.. c:function:: const char * libnvmf_trtype_str (__u8 trtype)

   Decode TRTYPE field

**Parameters**

``__u8 trtype``
  value to be decoded

**Description**

Decode the transport type field in the discovery
log page entry.

**Return**

decoded string


.. c:function:: const char * libnvmf_adrfam_str (__u8 adrfam)

   Decode ADRFAM field

**Parameters**

``__u8 adrfam``
  value to be decoded

**Description**

Decode the address family field in the discovery
log page entry.

**Return**

decoded string


.. c:function:: const char * libnvmf_subtype_str (__u8 subtype)

   Decode SUBTYPE field

**Parameters**

``__u8 subtype``
  value to be decoded

**Description**

Decode the subsystem type field in the discovery
log page entry.

**Return**

decoded string


.. c:function:: const char * libnvmf_treq_str (__u8 treq)

   Decode TREQ field

**Parameters**

``__u8 treq``
  value to be decoded

**Description**

Decode the transport requirements field in the
discovery log page entry.

**Return**

decoded string


.. c:function:: const char * libnvmf_eflags_str (__u16 eflags)

   Decode EFLAGS field

**Parameters**

``__u16 eflags``
  value to be decoded

**Description**

Decode the EFLAGS field in the discovery log page
entry.

**Return**

decoded string


.. c:function:: const char * libnvmf_sectype_str (__u8 sectype)

   Decode SECTYPE field

**Parameters**

``__u8 sectype``
  value to be decoded

**Description**

Decode the SECTYPE field in the discovery log page
entry.

**Return**

decoded string


.. c:function:: const char * libnvmf_prtype_str (__u8 prtype)

   Decode RDMA Provider type field

**Parameters**

``__u8 prtype``
  value to be decoded

**Description**

Decode the RDMA Provider type field in the discovery
log page entry.

**Return**

decoded string


.. c:function:: const char * libnvmf_qptype_str (__u8 qptype)

   Decode RDMA QP Service type field

**Parameters**

``__u8 qptype``
  value to be decoded

**Description**

Decode the RDMA QP Service type field in the discovery log page
entry.

**Return**

decoded string


.. c:function:: const char * libnvmf_cms_str (__u8 cms)

   Decode RDMA connection management service field

**Parameters**

``__u8 cms``
  value to be decoded

**Description**

Decode the RDMA connection management service field in the discovery
log page entry.

**Return**

decoded string


.. c:function:: int libnvmf_add_ctrl (libnvme_host_t h, libnvme_ctrl_t c)

   Connect a controller and update topology

**Parameters**

``libnvme_host_t h``
  Host to which the controller should be attached

``libnvme_ctrl_t c``
  Controller to be connected

**Description**

Issues a 'connect' command to the NVMe-oF controller and inserts **c**
into the topology using **h** as parent.
**c** must be initialized and not connected to the topology.

**Return**

0 on success, negative error code otherwise.


.. c:function:: int libnvmf_connect_ctrl (libnvme_ctrl_t c)

   Connect a controller

**Parameters**

``libnvme_ctrl_t c``
  Controller to be connected

**Description**

Issues a 'connect' command to the NVMe-oF controller.
**c** must be initialized and not connected to the topology.

**Return**

0 on success, negative error code otherwise.


.. c:function:: int libnvmf_get_discovery_log (libnvme_ctrl_t ctrl, const struct libnvmf_discovery_args *args, struct nvmf_discovery_log **logp)

   Fetch the NVMe-oF discovery log page

**Parameters**

``libnvme_ctrl_t ctrl``
  Discovery controller

``const struct libnvmf_discovery_args *args``
  Optional arguments (pass NULL for defaults)

``struct nvmf_discovery_log **logp``
  On success, set to the allocated log page (caller must free())

**Description**

Issues the three-phase Get Log Page protocol against **ctrl**, validates
generation-counter atomicity, and normalises each log entry.

**Return**

0 on success, negative error code otherwise.


.. c:function:: bool libnvmf_is_registration_supported (libnvme_ctrl_t c)

   check whether registration can be performed.

**Parameters**

``libnvme_ctrl_t c``
  Controller instance

**Description**

Only discovery controllers (DC) that comply with TP8010 support
explicit registration with the DIM PDU. These can be identified by
looking at the value of a dctype in the Identify command
response. A value of 1 (DDC) or 2 (CDC) indicates that the DC
supports explicit registration.

**Return**

true if controller supports explicit registration. false
otherwise.


.. c:function:: int libnvmf_register_ctrl (libnvme_ctrl_t c, enum nvmf_dim_tas tas, __u32 *result)

   Perform registration task with a DC

**Parameters**

``libnvme_ctrl_t c``
  Controller instance

``enum nvmf_dim_tas tas``
  Task field of the Command Dword 10 (cdw10). Indicates whether to
  perform a Registration, Deregistration, or Registration-update.

``__u32 *result``
  The command-specific result returned by the DC upon command
  completion.

**Description**

Perform registration task with a Discovery Controller (DC). Three
tasks are supported: register, deregister, and registration update.

**Return**

0 on success, negative error code otherwise.


.. c:function:: int libnvmf_uri_parse (const char *str, struct libnvmf_uri **uri)

   Parse the URI string

**Parameters**

``const char *str``
  URI string

``struct libnvmf_uri **uri``
  URI object to return

**Description**

Parse the URI string as defined in the NVM Express Boot Specification.
Supported URI elements looks as follows:

  nvme+tcp://user**host**:port/subsys_nqn/nid?query=val#fragment

**Return**

0 on success, negative error code otherwise.


.. c:function:: void libnvmf_uri_free (struct libnvmf_uri *uri)

   Free the URI structure

**Parameters**

``struct libnvmf_uri *uri``
  :c:type:`libnvme_fabrics_uri` structure

**Description**

Free an :c:type:`libnvmf_uri` structure.


.. c:function:: const char * libnvmf_get_default_trsvcid (const char *transport, bool discovery_ctrl)

   Get default transport service ID

**Parameters**

``const char *transport``
  Transport type string (e.g., "tcp", "rdma")

``bool discovery_ctrl``
  True if for discovery controller, false otherwise

**Description**

Returns the default trsvcid (port) for the given transport and controller
type.

**Return**

Allocated string with default trsvcid, or NULL on failure.


.. c:function:: int libnvmf_context_create (struct libnvme_global_ctx *ctx, bool (*decide_retry)(struct libnvmf_context *fctx, int err, void *user_data), void (*connected)(struct libnvmf_context *fctx, struct libnvme_ctrl *c, void *user_data), void (*already_connected)(struct libnvmf_context *fctx, struct libnvme_host *host, const char *subsysnqn, const char *transport, const char *traddr, const char *trsvcid, void *user_data), void *user_data, struct libnvmf_context **fctxp)

   Create a new fabrics context for discovery/connect

**Parameters**

``struct libnvme_global_ctx *ctx``
  Global context

``bool (*decide_retry)(struct libnvmf_context *fctx, int err, void *user_data)``
  Hook to decide if a retry should be attempted

``void (*connected)(struct libnvmf_context *fctx, struct libnvme_ctrl *c, void *user_data)``
  Hook invoked when a connection is established

``void (*already_connected)(struct libnvmf_context *fctx, struct libnvme_host *host, const char *subsysnqn, const char *transport, const char *traddr, const char *trsvcid, void *user_data)``
  Hook invoked if already connected

``void *user_data``
  User data passed to hooks

``struct libnvmf_context **fctxp``
  Pointer to store the created context

**Description**

Allocates and initializes a new fabrics context for discovery/connect
operations.

**Return**

0 on success, negative error code otherwise.


.. c:function:: void libnvmf_context_free (struct libnvmf_context *fctx)

   Free a fabrics context

**Parameters**

``struct libnvmf_context *fctx``
  Fabrics context to free

**Description**

Releases all resources associated with **fctx**. The context must have
been previously created with libnvmf_context_create().

After this call, **fctx** must not be used.


.. c:function:: int libnvmf_context_set_discovery_hooks (struct libnvmf_context *fctx, void (*discovery_log)(struct libnvmf_context *fctx, struct nvmf_discovery_log *log, uint64_t numrec, void *user_data))

   Set discovery hooks for context

**Parameters**

``struct libnvmf_context *fctx``
  Fabrics context

``void (*discovery_log)(struct libnvmf_context *fctx, struct nvmf_discovery_log *log, uint64_t numrec, void *user_data)``
  Hook for discovery log events

**Description**

Sets the hooks used during discovery operations for the given context.

**Return**

0 on success, negative error code otherwise.


.. c:function:: int libnvmf_context_set_connection (struct libnvmf_context *fctx, const char *subsysnqn, const char *transport, const char *traddr, const char *trsvcid, const char *host_traddr, const char *host_iface)

   Set connection parameters for context

**Parameters**

``struct libnvmf_context *fctx``
  Fabrics context

``const char *subsysnqn``
  Subsystem NQN

``const char *transport``
  Transport type

``const char *traddr``
  Transport address

``const char *trsvcid``
  Transport service ID

``const char *host_traddr``
  Host transport address

``const char *host_iface``
  Host interface

**Description**

Sets the connection parameters for the context.

**Return**

0 on success, negative error code otherwise.


.. c:function:: int libnvmf_context_set_hostnqn (struct libnvmf_context *fctx, const char *hostnqn, const char *hostid)

   Set host NQN and host ID for context

**Parameters**

``struct libnvmf_context *fctx``
  Fabrics context

``const char *hostnqn``
  Host NQN

``const char *hostid``
  Host identifier

**Description**

Sets the host NQN and host ID for the context.

**Return**

0 on success, negative error code otherwise.


.. c:function:: int libnvmf_context_set_connection_from_tid (struct libnvmf_context *fctx, const struct libnvmf_tid *tid)

   Set connection and identity from a TID

**Parameters**

``struct libnvmf_context *fctx``
  Fabrics context

``const struct libnvmf_tid *tid``
  Transport ID to copy from

**Description**

Equivalent to libnvmf_context_set_connection() followed by
libnvmf_context_set_hostnqn(), reading every field from **tid**.

**Return**

0 on success, -EINVAL if **fctx** or **tid** is NULL.


.. c:function:: int libnvmf_context_set_crypto (struct libnvmf_context *fctx, const char *hostkey, const char *ctrlkey, const char *keyring, const char *tls_key, const char *tls_key_identity)

   Set cryptographic parameters for context

**Parameters**

``struct libnvmf_context *fctx``
  Fabrics context

``const char *hostkey``
  Host key

``const char *ctrlkey``
  Controller key

``const char *keyring``
  Keyring identifier

``const char *tls_key``
  TLS key

``const char *tls_key_identity``
  TLS key identity

**Description**

Sets cryptographic and TLS parameters for the context.

**Return**

0 on success, negative error code otherwise.


.. c:function:: int libnvmf_context_set_device (struct libnvmf_context *fctx, const char *device)

   Set device for context

**Parameters**

``struct libnvmf_context *fctx``
  Fabrics context

``const char *device``
  Device path or identifier

**Description**

Sets the device to be used by the context.

**Return**

0 on success, negative error code otherwise.


.. c:function:: int libnvmf_context_set_devid_file (struct libnvmf_context *fctx, const char *devid_file)

   Set devid file for context

**Parameters**

``struct libnvmf_context *fctx``
  Fabrics context

``const char *devid_file``
  Path to the output file

**Description**

Configure a file that libnvmf_connect() uses to record the
kernel-assigned device name (for example, "nvme0").

If the controller is already connected, the existing device name is
written. Otherwise, the device name is written after the controller is
connected.

The output file is created before attempting the connection. If the
file cannot be created, for example because the parent directory does
not exist, libnvmf_connect() fails without attempting the connection.

This is intended for applications that need to identify the device
associated with a connection, for example to disconnect it later.

**Return**

0 on success, negative error code otherwise.


.. c:function:: int libnvmf_context_set_io_queues (struct libnvmf_context *fctx, int nr_io_queues, int nr_write_queues, int nr_poll_queues, int queue_size, bool disable_sqflow)

   Set I/O queue topology for context

**Parameters**

``struct libnvmf_context *fctx``
  Fabrics context

``int nr_io_queues``
  Number of I/O queues

``int nr_write_queues``
  Number of write-only queues

``int nr_poll_queues``
  Number of polling queues

``int queue_size``
  Number of entries per I/O queue (SQSIZE in Connect command)

``bool disable_sqflow``
  Disable SQ flow control negotiation

**Description**

Convenience setter for the five parameters that together define the I/O
queue structure used when establishing a controller connection. All five
feed directly into the Connect command at queue creation time.
**nr_write_queues** and **nr_poll_queues** are additive: total I/O queues is
**nr_io_queues** + **nr_write_queues** + **nr_poll_queues**.

Individual libnvmf_context_set_nr_io_queues(), _set_nr_write_queues(),
_set_nr_poll_queues(), _set_queue_size(), and _set_disable_sqflow()
accessors are also available when only a subset needs to change.

**Return**

0 on success, negative error code otherwise.


.. c:function:: int libnvmf_context_set_reconnect_policy (struct libnvmf_context *fctx, int ctrl_loss_tmo, int reconnect_delay, int fast_io_fail_tmo)

   Set reconnect policy for context

**Parameters**

``struct libnvmf_context *fctx``
  Fabrics context

``int ctrl_loss_tmo``
  Controller loss timeout in seconds; negative means retry
  indefinitely

``int reconnect_delay``
  Delay between reconnect attempts in seconds

``int fast_io_fail_tmo``
  Fast I/O fail timeout in seconds; negative disables it;
  must not exceed **ctrl_loss_tmo**

**Description**

Convenience setter for the three coupled reconnect policy parameters.
**ctrl_loss_tmo** and **reconnect_delay** are coupled: the kernel derives the
maximum reconnect attempt count from their ratio. **fast_io_fail_tmo**
controls how quickly outstanding I/O is failed while reconnection is in
progress.

Individual libnvmf_context_set_ctrl_loss_tmo(), _set_reconnect_delay(),
and _set_fast_io_fail_tmo() accessors are also available when only a
subset needs to change.

**Return**

0 on success, negative error code otherwise.


.. c:function:: int libnvmf_get_owner_from_tid (struct libnvme_global_ctx *ctx, const struct libnvmf_tid *tid, char **owner)

   Get the registry owner of a transport ID

**Parameters**

``struct libnvme_global_ctx *ctx``
  Global context

``const struct libnvmf_tid *tid``
  Transport ID identifying the connection to check

``char **owner``
  Returned owner, NULL if no matching controller exists or it is
  unowned

**Description**

Resolves the controller, if any, matching **tid** and reports its registry
owner. Does not connect, disconnect, or otherwise modify controller
state.

When a matching owned controller exists, **owner** is set to a newly
allocated string that the caller must free(). Otherwise, **owner** is set
to NULL. A negative errno return indicates the lookup failed; it is
never used to report that no owner exists.

**Return**

0 on success (check **owner**), negative errno on failure.


.. c:function:: int libnvmf_get_owner_from_fctx (struct libnvme_global_ctx *ctx, struct libnvmf_context *fctx, char **owner)

   Get the registry owner of a fabrics context

**Parameters**

``struct libnvme_global_ctx *ctx``
  Global context

``struct libnvmf_context *fctx``
  Fabrics context describing the connection to check

``char **owner``
  Returned owner, NULL if no matching controller exists or it is
  unowned

**Description**

Convenience wrapper around libnvmf_get_owner_from_tid() for callers that
already have a libnvmf_context rather than a bare TID. If **fctx** names an
explicit device, its registry entry is checked directly. Otherwise, a
controller is resolved from **fctx**'s connection parameters. The **owner**
contract is identical to libnvmf_get_owner_from_tid().

**Return**

0 on success (check **owner**), negative errno on failure.


.. c:function:: int libnvmf_discover (struct libnvme_global_ctx *ctx, struct libnvmf_context *fctx)

   Discover fabrics subsystems

**Parameters**

``struct libnvme_global_ctx *ctx``
  Global context

``struct libnvmf_context *fctx``
  Fabrics context

**Description**

Performs discovery for fabrics subsystems and optionally connects.

**Return**

0 on success, negative error code otherwise.


.. c:function:: int libnvmf_discover_nbft (struct libnvme_global_ctx *ctx, struct libnvmf_context *fctx)

   Discover fabrics subsystems using NBFT

**Parameters**

``struct libnvme_global_ctx *ctx``
  Global context

``struct libnvmf_context *fctx``
  Fabrics context

**Description**

Performs discovery using the NBFT tables found at **fctx**'s nbft_path.

**Return**

0 on success, negative error code otherwise.


.. c:function:: int libnvmf_create_ctrl (struct libnvme_global_ctx *ctx, struct libnvmf_context *fctx, libnvme_ctrl_t *c)

   Allocate an unconnected NVMe controller

**Parameters**

``struct libnvme_global_ctx *ctx``
  struct libnvme_global_ctx object

``struct libnvmf_context *fctx``
  Fabrics context

``libnvme_ctrl_t *c``
  **libnvme_ctrl_t** object to return

**Description**

Creates an unconnected controller to be used for libnvme_add_ctrl().

**Return**

0 on success, negative error code otherwise.


.. c:function:: int libnvmf_connect (struct libnvme_global_ctx *ctx, struct libnvmf_context *fctx)

   Connect to fabrics subsystem

**Parameters**

``struct libnvme_global_ctx *ctx``
  Global context

``struct libnvmf_context *fctx``
  Fabrics context

**Description**

Connects to the fabrics subsystem using the provided context.

**Return**

0 on success, negative error code otherwise.


.. c:function:: int libnvmf_disconnect_ctrl (libnvme_ctrl_t c)

   Disconnect a controller

**Parameters**

``libnvme_ctrl_t c``
  Controller instance

**Description**

Issues a 'disconnect' fabrics command to **c**

**Return**

0 on success, -1 on failure.


.. c:function:: int libnvmf_nbft_read_files (struct libnvme_global_ctx *ctx, char *path, struct nbft_file_entry **head)

   Read NBFT files from path

**Parameters**

``struct libnvme_global_ctx *ctx``
  struct libnvme_global_ctx object

``char *path``
  Path to NBFT files

``struct nbft_file_entry **head``
  Pointer to store linked list of NBFT file entries

**Description**

Reads NBFT files from the specified path and populates a linked list.

**Return**

0 on success, negative error code otherwise.


.. c:function:: void libnvmf_nbft_free (struct libnvme_global_ctx *ctx, struct nbft_file_entry *head)

   Free NBFT file entry list

**Parameters**

``struct libnvme_global_ctx *ctx``
  struct libnvme_global_ctx object

``struct nbft_file_entry *head``
  Head of the NBFT file entry list

**Description**

Frees all memory associated with the NBFT file entry list.


