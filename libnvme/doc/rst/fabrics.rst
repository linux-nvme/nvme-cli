.. _fabrics.h:

**fabrics.h**


Fabrics-specific definitions.

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

0 on success, or an error code on failure.


.. c:function:: int libnvmf_connect_ctrl (libnvme_ctrl_t c)

   Connect a controller

**Parameters**

``libnvme_ctrl_t c``
  Controller to be connected

**Description**

Issues a 'connect' command to the NVMe-oF controller.
**c** must be initialized and not connected to the topology.

**Return**

0 on success, or an error code on failure.


.. c:function:: int libnvmf_discovery_args_create (struct libnvmf_discovery_args **argsp)

   Allocate a discovery args object

**Parameters**

``struct libnvmf_discovery_args **argsp``
  On success, set to the newly allocated object

**Description**

Allocates and initialises a :c:type:`struct libnvmf_discovery_args <libnvmf_discovery_args>` with sensible
defaults. The caller must release it with libnvmf_discovery_args_free().

**Return**

0 on success, or a negative error code on failure.


.. c:function:: void libnvmf_discovery_args_free (struct libnvmf_discovery_args *args)

   Release a discovery args object

**Parameters**

``struct libnvmf_discovery_args *args``
  Object previously returned by libnvmf_discovery_args_create()


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

0 on success, or a negative error code on failure.


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

0 on success, or an error code on failure.


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

0 on success, or a negative error code on failure.


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
  Callback to decide if a retry should be attempted

``void (*connected)(struct libnvmf_context *fctx, struct libnvme_ctrl *c, void *user_data)``
  Callback invoked when a connection is established

``void (*already_connected)(struct libnvmf_context *fctx, struct libnvme_host *host, const char *subsysnqn, const char *transport, const char *traddr, const char *trsvcid, void *user_data)``
  Callback invoked if already connected

``void *user_data``
  User data passed to callbacks

``struct libnvmf_context **fctxp``
  Pointer to store the created context

**Description**

Allocates and initializes a new fabrics context for discovery/connect
operations.

**Return**

0 on success, or a negative error code on failure.


.. c:function:: void libnvmf_context_free (struct libnvmf_context *fctx)

   Free a fabrics context

**Parameters**

``struct libnvmf_context *fctx``
  Fabrics context to free

**Description**

Releases all resources associated with **fctx**. The context must have
been previously created with libnvmf_context_create().

After this call, **fctx** must not be used.


.. c:function:: int libnvmf_context_set_discovery_cbs (struct libnvmf_context *fctx, void (*discovery_log)(struct libnvmf_context *fctx, bool connect, struct nvmf_discovery_log *log, uint64_t numrec, void *user_data), int (*parser_init)(struct libnvmf_context *fctx, void *user_data), void (*parser_cleanup)(struct libnvmf_context *fctx, void *user_data), int (*parser_next_line)(struct libnvmf_context *fctx, void *user_data))

   Set discovery callbacks for context

**Parameters**

``struct libnvmf_context *fctx``
  Fabrics context

``void (*discovery_log)(struct libnvmf_context *fctx, bool connect, struct nvmf_discovery_log *log, uint64_t numrec, void *user_data)``
  Callback for discovery log events

``int (*parser_init)(struct libnvmf_context *fctx, void *user_data)``
  Callback to initialize parser

``void (*parser_cleanup)(struct libnvmf_context *fctx, void *user_data)``
  Callback to cleanup parser

``int (*parser_next_line)(struct libnvmf_context *fctx, void *user_data)``
  Callback to parse next line

**Description**

Sets the callbacks used during discovery operations for the given context.

**Return**

0 on success, or a negative error code on failure.


.. c:function:: int libnvmf_context_set_discovery_defaults (struct libnvmf_context *fctx, int max_discovery_retries, int keep_alive_timeout)

   Set default discovery parameters

**Parameters**

``struct libnvmf_context *fctx``
  Fabrics context

``int max_discovery_retries``
  Maximum number of discovery retries

``int keep_alive_timeout``
  Keep-alive timeout in seconds

**Description**

Sets default values for discovery retries and keep-alive timeout.

**Return**

0 on success, or a negative error code on failure.


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

0 on success, or a negative error code on failure.


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

0 on success, or a negative error code on failure.


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

0 on success, or a negative error code on failure.


.. c:function:: int libnvmf_context_set_persistent (struct libnvmf_context *fctx, bool persistent)

   Set persistence for context

**Parameters**

``struct libnvmf_context *fctx``
  Fabrics context

``bool persistent``
  Whether to enable persistent connections

**Description**

Sets whether the context should use persistent connections.

**Return**

0 on success, or a negative error code on failure.


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

0 on success, or a negative error code on failure.


.. c:function:: struct libnvme_fabrics_config * libnvmf_context_get_fabrics_config (struct libnvmf_context *fctx)

   Fabrics configuration of a fabrics context

**Parameters**

``struct libnvmf_context *fctx``
  Fabrics context

**Return**

Fabrics configuration of **fctx**


.. c:function:: struct libnvme_fabrics_config * libnvmf_ctrl_get_fabrics_config (libnvme_ctrl_t c)

   Fabrics configuration of a controller

**Parameters**

``libnvme_ctrl_t c``
  Controller instance

**Return**

Fabrics configuration of **c**


.. c:function:: int libnvmf_discovery (struct libnvme_global_ctx *ctx, struct libnvmf_context *fctx, bool connect, bool force)

   Perform fabrics discovery

**Parameters**

``struct libnvme_global_ctx *ctx``
  Global context

``struct libnvmf_context *fctx``
  Fabrics context

``bool connect``
  Whether to connect discovered subsystems

``bool force``
  Force discovery even if already connected

**Description**

Performs discovery for fabrics subsystems and optionally connects.

**Return**

0 on success, or a negative error code on failure.


.. c:function:: int libnvmf_discovery_config_json (struct libnvme_global_ctx *ctx, struct libnvmf_context *fctx, bool connect, bool force)

   Perform discovery using JSON config

**Parameters**

``struct libnvme_global_ctx *ctx``
  Global context

``struct libnvmf_context *fctx``
  Fabrics context

``bool connect``
  Whether to connect discovered subsystems

``bool force``
  Force discovery even if already connected

**Description**

Performs discovery using a JSON configuration.

**Return**

0 on success, or a negative error code on failure.


.. c:function:: int libnvmf_discovery_config_file (struct libnvme_global_ctx *ctx, struct libnvmf_context *fctx, bool connect, bool force)

   Perform discovery using config file

**Parameters**

``struct libnvme_global_ctx *ctx``
  Global context

``struct libnvmf_context *fctx``
  Fabrics context

``bool connect``
  Whether to connect discovered subsystems

``bool force``
  Force discovery even if already connected

**Description**

Performs discovery using a configuration file.

**Return**

0 on success, or a negative error code on failure.


.. c:function:: int libnvmf_discovery_nbft (struct libnvme_global_ctx *ctx, struct libnvmf_context *fctx, bool connect, char *nbft_path)

   Perform discovery using NBFT

**Parameters**

``struct libnvme_global_ctx *ctx``
  Global context

``struct libnvmf_context *fctx``
  Fabrics context

``bool connect``
  Whether to connect discovered subsystems

``char *nbft_path``
  Path to NBFT file

**Description**

Performs discovery using the specified NBFT file.

**Return**

0 on success, or a negative error code on failure.


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

0 on success or negative error code otherwise


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

0 on success, or a negative error code on failure.


.. c:function:: int libnvmf_disconnect_ctrl (libnvme_ctrl_t c)

   Disconnect a controller

**Parameters**

``libnvme_ctrl_t c``
  Controller instance

**Description**

Issues a 'disconnect' fabrics command to **c**

**Return**

0 on success, -1 on failure.


.. c:function:: int libnvmf_connect_config_json (struct libnvme_global_ctx *ctx, struct libnvmf_context *fctx)

   Connect using JSON config

**Parameters**

``struct libnvme_global_ctx *ctx``
  Global context

``struct libnvmf_context *fctx``
  Fabrics context

**Description**

Connects to the fabrics subsystem using a JSON configuration.

**Return**

0 on success, or a negative error code on failure.


.. c:function:: int libnvmf_config_modify (struct libnvme_global_ctx *ctx, struct libnvmf_context *fctx)

   Modify and update the configurtion

**Parameters**

``struct libnvme_global_ctx *ctx``
  Global context

``struct libnvmf_context *fctx``
  Fabrics context

**Description**

Update the current configuration by adding the crypto
information.

**Return**

0 on success, or a negative error code on failure.


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

0 on success, or a negative error code on failure.


.. c:function:: void libnvmf_nbft_free (struct libnvme_global_ctx *ctx, struct nbft_file_entry *head)

   Free NBFT file entry list

**Parameters**

``struct libnvme_global_ctx *ctx``
  struct libnvme_global_ctx object

``struct nbft_file_entry *head``
  Head of the NBFT file entry list

**Description**

Frees all memory associated with the NBFT file entry list.


