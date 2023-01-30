.. _fabrics.h:

**fabrics.h**


Fabrics-specific definitions.



.. c:struct:: nvme_fabrics_config

   Defines all linux nvme fabrics initiator options

**Definition**

::

  struct nvme_fabrics_config {
    char *host_traddr;
    char *host_iface;
    int queue_size;
    int nr_io_queues;
    int reconnect_delay;
    int ctrl_loss_tmo;
    int fast_io_fail_tmo;
    int keep_alive_tmo;
    int nr_write_queues;
    int nr_poll_queues;
    int tos;
    bool duplicate_connect;
    bool disable_sqflow;
    bool hdr_digest;
    bool data_digest;
    bool tls;
  };

**Members**

``host_traddr``
  Host transport address

``host_iface``
  Host interface name

``queue_size``
  Number of IO queue entries

``nr_io_queues``
  Number of controller IO queues to establish

``reconnect_delay``
  Time between two consecutive reconnect attempts.

``ctrl_loss_tmo``
  Override the default controller reconnect attempt timeout in seconds

``fast_io_fail_tmo``
  Set the fast I/O fail timeout in seconds.

``keep_alive_tmo``
  Override the default keep-alive-timeout to this value in seconds

``nr_write_queues``
  Number of queues to use for exclusively for writing

``nr_poll_queues``
  Number of queues to reserve for polling completions

``tos``
  Type of service

``duplicate_connect``
  Allow multiple connections to the same target

``disable_sqflow``
  Disable controller sq flow control

``hdr_digest``
  Generate/verify header digest (TCP)

``data_digest``
  Generate/verify data digest (TCP)

``tls``
  Start TLS on the connection (TCP)



.. c:function:: const char * nvmf_trtype_str (__u8 trtype)

   Decode TRTYPE field

**Parameters**

``__u8 trtype``
  value to be decoded

**Description**

Decode the transport type field in the discovery
log page entry.

**Return**

decoded string


.. c:function:: const char * nvmf_adrfam_str (__u8 adrfam)

   Decode ADRFAM field

**Parameters**

``__u8 adrfam``
  value to be decoded

**Description**

Decode the address family field in the discovery
log page entry.

**Return**

decoded string


.. c:function:: const char * nvmf_subtype_str (__u8 subtype)

   Decode SUBTYPE field

**Parameters**

``__u8 subtype``
  value to be decoded

**Description**

Decode the subsystem type field in the discovery
log page entry.

**Return**

decoded string


.. c:function:: const char * nvmf_treq_str (__u8 treq)

   Decode TREQ field

**Parameters**

``__u8 treq``
  value to be decoded

**Description**

Decode the transport requirements field in the
discovery log page entry.

**Return**

decoded string


.. c:function:: const char * nvmf_eflags_str (__u16 eflags)

   Decode EFLAGS field

**Parameters**

``__u16 eflags``
  value to be decoded

**Description**

Decode the EFLAGS field in the discovery log page
entry.

**Return**

decoded string


.. c:function:: const char * nvmf_sectype_str (__u8 sectype)

   Decode SECTYPE field

**Parameters**

``__u8 sectype``
  value to be decoded

**Description**

Decode the SECTYPE field in the discovery log page
entry.

**Return**

decoded string


.. c:function:: const char * nvmf_prtype_str (__u8 prtype)

   Decode RDMA Provider type field

**Parameters**

``__u8 prtype``
  value to be decoded

**Description**

Decode the RDMA Provider type field in the discovery
log page entry.

**Return**

decoded string


.. c:function:: const char * nvmf_qptype_str (__u8 qptype)

   Decode RDMA QP Service type field

**Parameters**

``__u8 qptype``
  value to be decoded

**Description**

Decode the RDMA QP Service type field in the discovery log page
entry.

**Return**

decoded string


.. c:function:: const char * nvmf_cms_str (__u8 cms)

   Decode RDMA connection management service field

**Parameters**

``__u8 cms``
  value to be decoded

**Description**

Decode the RDMA connection management service field in the discovery
log page entry.

**Return**

decoded string


.. c:function:: void nvmf_default_config (struct nvme_fabrics_config *cfg)

   Default values for fabrics configuration

**Parameters**

``struct nvme_fabrics_config *cfg``
  config values to set

**Description**

Initializes **cfg** with default values.


.. c:function:: void nvmf_update_config (nvme_ctrl_t c, const struct nvme_fabrics_config *cfg)

   Update fabrics configuration values

**Parameters**

``nvme_ctrl_t c``
  Controller to be modified

``const struct nvme_fabrics_config *cfg``
  Updated configuration values

**Description**

Updates the values from **c** with the configuration values from **cfg**;
all non-default values from **cfg** will overwrite the values in **c**.


.. c:function:: int nvmf_add_ctrl (nvme_host_t h, nvme_ctrl_t c, const struct nvme_fabrics_config *cfg)

   Connect a controller and update topology

**Parameters**

``nvme_host_t h``
  Host to which the controller should be attached

``nvme_ctrl_t c``
  Controller to be connected

``const struct nvme_fabrics_config *cfg``
  Default configuration for the controller

**Description**

Issues a 'connect' command to the NVMe-oF controller and inserts **c**
into the topology using **h** as parent.
**c** must be initialized and not connected to the topology.

**Return**

0 on success; on failure errno is set and -1 is returned.


.. c:function:: int nvmf_get_discovery_log (nvme_ctrl_t c, struct nvmf_discovery_log **logp, int max_retries)

   Return the discovery log page

**Parameters**

``nvme_ctrl_t c``
  Discovery controller to use

``struct nvmf_discovery_log **logp``
  Pointer to the log page to be returned

``int max_retries``
  Number of retries in case of failure

**Description**

The memory allocated for the log page and returned in **logp**
must be freed by the caller using free().

**Note**

Consider using nvmf_get_discovery_wargs() instead.

**Return**

0 on success; on failure -1 is returned and errno is set




.. c:struct:: nvme_get_discovery_args

   Arguments for nvmf_get_discovery_wargs()

**Definition**

::

  struct nvme_get_discovery_args {
    nvme_ctrl_t c;
    int args_size;
    int max_retries;
    __u32 *result;
    __u32 timeout;
    __u8 lsp;
  };

**Members**

``c``
  Discovery controller

``args_size``
  Length of the structure

``max_retries``
  Number of retries in case of failure

``result``
  The command completion result from CQE dword0

``timeout``
  Timeout in ms (default: NVME_DEFAULT_IOCTL_TIMEOUT)

``lsp``
  Log specific field (See enum nvmf_log_discovery_lsp)



.. c:function:: struct nvmf_discovery_log * nvmf_get_discovery_wargs (struct nvme_get_discovery_args *args)

   Get the discovery log page with args

**Parameters**

``struct nvme_get_discovery_args *args``
  Argument structure

**Description**

This function is similar to nvmf_get_discovery_log(), but
takes an extensible **args** parameter. **args** provides more
options than nvmf_get_discovery_log().

This function performs a get discovery log page (DLP) command
and returns the DLP. The memory allocated for the returned
DLP must be freed by the caller using free().

**Return**

Pointer to the discovery log page (to be freed). NULL
on failure and errno is set.


.. c:function:: char * nvmf_hostnqn_generate ()

   Generate a machine specific host nqn

**Parameters**

**Return**

An nvm namespace qualified name string based on the machine
identifier, or NULL if not successful.


.. c:function:: char * nvmf_hostnqn_from_file ()

   Reads the host nvm qualified name from the config default location in /usr/local/etc/nvme/

**Parameters**

**Return**

The host nqn, or NULL if unsuccessful. If found, the caller
is responsible to free the string.


.. c:function:: char * nvmf_hostid_from_file ()

   Reads the host identifier from the config default location in /usr/local/etc/nvme/.

**Parameters**

**Return**

The host identifier, or NULL if unsuccessful. If found, the caller
        is responsible to free the string.


.. c:function:: nvme_ctrl_t nvmf_connect_disc_entry (nvme_host_t h, struct nvmf_disc_log_entry *e, const struct nvme_fabrics_config *defcfg, bool *discover)

   Connect controller based on the discovery log page entry

**Parameters**

``nvme_host_t h``
  Host to which the controller should be connected

``struct nvmf_disc_log_entry *e``
  Discovery log page entry

``const struct nvme_fabrics_config *defcfg``
  Default configuration to be used for the new controller

``bool *discover``
  Set to 'true' if the new controller is a discovery controller

**Return**

Pointer to the new controller


.. c:function:: bool nvmf_is_registration_supported (nvme_ctrl_t c)

   check whether registration can be performed.

**Parameters**

``nvme_ctrl_t c``
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


.. c:function:: int nvmf_register_ctrl (nvme_ctrl_t c, enum nvmf_dim_tas tas, __u32 *result)

   Perform registration task with a DC

**Parameters**

``nvme_ctrl_t c``
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

0 on success; on failure -1 is returned and errno is set


