.. c:function:: const char * libnvmf_context_get_transport (const struct libnvmf_context *p)

   Get transport.

**Parameters**

``const struct libnvmf_context *p``
  The :c:type:`struct libnvmf_context <libnvmf_context>` instance to query.

**Return**

The value of the transport field, or NULL if not set.


.. c:function:: const char * libnvmf_context_get_traddr (const struct libnvmf_context *p)

   Get traddr.

**Parameters**

``const struct libnvmf_context *p``
  The :c:type:`struct libnvmf_context <libnvmf_context>` instance to query.

**Return**

The value of the traddr field, or NULL if not set.


.. c:function:: const char * libnvmf_context_get_host_traddr (const struct libnvmf_context *p)

   Get host_traddr.

**Parameters**

``const struct libnvmf_context *p``
  The :c:type:`struct libnvmf_context <libnvmf_context>` instance to query.

**Return**

The value of the host_traddr field, or NULL if not set.


.. c:function:: const char * libnvmf_context_get_host_iface (const struct libnvmf_context *p)

   Get host_iface.

**Parameters**

``const struct libnvmf_context *p``
  The :c:type:`struct libnvmf_context <libnvmf_context>` instance to query.

**Return**

The value of the host_iface field, or NULL if not set.


.. c:function:: const char * libnvmf_context_get_trsvcid (const struct libnvmf_context *p)

   Get trsvcid.

**Parameters**

``const struct libnvmf_context *p``
  The :c:type:`struct libnvmf_context <libnvmf_context>` instance to query.

**Return**

The value of the trsvcid field, or NULL if not set.


.. c:function:: const char * libnvmf_context_get_subsysnqn (const struct libnvmf_context *p)

   Get subsysnqn.

**Parameters**

``const struct libnvmf_context *p``
  The :c:type:`struct libnvmf_context <libnvmf_context>` instance to query.

**Return**

The value of the subsysnqn field, or NULL if not set.


.. c:function:: void libnvmf_context_set_queue_size (struct libnvmf_context *p, int queue_size)

   Set queue_size.

**Parameters**

``struct libnvmf_context *p``
  The :c:type:`struct libnvmf_context <libnvmf_context>` instance to update.

``int queue_size``
  Value to assign to the queue_size field.


.. c:function:: int libnvmf_context_get_queue_size (const struct libnvmf_context *p)

   Get queue_size.

**Parameters**

``const struct libnvmf_context *p``
  The :c:type:`struct libnvmf_context <libnvmf_context>` instance to query.

**Return**

The value of the queue_size field.


.. c:function:: void libnvmf_context_set_nr_io_queues (struct libnvmf_context *p, int nr_io_queues)

   Set nr_io_queues.

**Parameters**

``struct libnvmf_context *p``
  The :c:type:`struct libnvmf_context <libnvmf_context>` instance to update.

``int nr_io_queues``
  Value to assign to the nr_io_queues field.


.. c:function:: int libnvmf_context_get_nr_io_queues (const struct libnvmf_context *p)

   Get nr_io_queues.

**Parameters**

``const struct libnvmf_context *p``
  The :c:type:`struct libnvmf_context <libnvmf_context>` instance to query.

**Return**

The value of the nr_io_queues field.


.. c:function:: void libnvmf_context_set_reconnect_delay (struct libnvmf_context *p, int reconnect_delay)

   Set reconnect_delay.

**Parameters**

``struct libnvmf_context *p``
  The :c:type:`struct libnvmf_context <libnvmf_context>` instance to update.

``int reconnect_delay``
  Value to assign to the reconnect_delay field.


.. c:function:: int libnvmf_context_get_reconnect_delay (const struct libnvmf_context *p)

   Get reconnect_delay.

**Parameters**

``const struct libnvmf_context *p``
  The :c:type:`struct libnvmf_context <libnvmf_context>` instance to query.

**Return**

The value of the reconnect_delay field.


.. c:function:: void libnvmf_context_set_ctrl_loss_tmo (struct libnvmf_context *p, int ctrl_loss_tmo)

   Set ctrl_loss_tmo.

**Parameters**

``struct libnvmf_context *p``
  The :c:type:`struct libnvmf_context <libnvmf_context>` instance to update.

``int ctrl_loss_tmo``
  Value to assign to the ctrl_loss_tmo field.


.. c:function:: int libnvmf_context_get_ctrl_loss_tmo (const struct libnvmf_context *p)

   Get ctrl_loss_tmo.

**Parameters**

``const struct libnvmf_context *p``
  The :c:type:`struct libnvmf_context <libnvmf_context>` instance to query.

**Return**

The value of the ctrl_loss_tmo field.


.. c:function:: void libnvmf_context_set_fast_io_fail_tmo (struct libnvmf_context *p, int fast_io_fail_tmo)

   Set fast_io_fail_tmo.

**Parameters**

``struct libnvmf_context *p``
  The :c:type:`struct libnvmf_context <libnvmf_context>` instance to update.

``int fast_io_fail_tmo``
  Value to assign to the fast_io_fail_tmo field.


.. c:function:: int libnvmf_context_get_fast_io_fail_tmo (const struct libnvmf_context *p)

   Get fast_io_fail_tmo.

**Parameters**

``const struct libnvmf_context *p``
  The :c:type:`struct libnvmf_context <libnvmf_context>` instance to query.

**Return**

The value of the fast_io_fail_tmo field.


.. c:function:: void libnvmf_context_set_keep_alive_tmo (struct libnvmf_context *p, int keep_alive_tmo)

   Set keep_alive_tmo.

**Parameters**

``struct libnvmf_context *p``
  The :c:type:`struct libnvmf_context <libnvmf_context>` instance to update.

``int keep_alive_tmo``
  Value to assign to the keep_alive_tmo field.


.. c:function:: int libnvmf_context_get_keep_alive_tmo (const struct libnvmf_context *p)

   Get keep_alive_tmo.

**Parameters**

``const struct libnvmf_context *p``
  The :c:type:`struct libnvmf_context <libnvmf_context>` instance to query.

**Return**

The value of the keep_alive_tmo field.


.. c:function:: void libnvmf_context_set_nr_write_queues (struct libnvmf_context *p, int nr_write_queues)

   Set nr_write_queues.

**Parameters**

``struct libnvmf_context *p``
  The :c:type:`struct libnvmf_context <libnvmf_context>` instance to update.

``int nr_write_queues``
  Value to assign to the nr_write_queues field.


.. c:function:: int libnvmf_context_get_nr_write_queues (const struct libnvmf_context *p)

   Get nr_write_queues.

**Parameters**

``const struct libnvmf_context *p``
  The :c:type:`struct libnvmf_context <libnvmf_context>` instance to query.

**Return**

The value of the nr_write_queues field.


.. c:function:: void libnvmf_context_set_nr_poll_queues (struct libnvmf_context *p, int nr_poll_queues)

   Set nr_poll_queues.

**Parameters**

``struct libnvmf_context *p``
  The :c:type:`struct libnvmf_context <libnvmf_context>` instance to update.

``int nr_poll_queues``
  Value to assign to the nr_poll_queues field.


.. c:function:: int libnvmf_context_get_nr_poll_queues (const struct libnvmf_context *p)

   Get nr_poll_queues.

**Parameters**

``const struct libnvmf_context *p``
  The :c:type:`struct libnvmf_context <libnvmf_context>` instance to query.

**Return**

The value of the nr_poll_queues field.


.. c:function:: void libnvmf_context_set_tos (struct libnvmf_context *p, int tos)

   Set tos.

**Parameters**

``struct libnvmf_context *p``
  The :c:type:`struct libnvmf_context <libnvmf_context>` instance to update.

``int tos``
  Value to assign to the tos field.


.. c:function:: int libnvmf_context_get_tos (const struct libnvmf_context *p)

   Get tos.

**Parameters**

``const struct libnvmf_context *p``
  The :c:type:`struct libnvmf_context <libnvmf_context>` instance to query.

**Return**

The value of the tos field.


.. c:function:: void libnvmf_context_set_keyring_id (struct libnvmf_context *p, long keyring_id)

   Set keyring_id.

**Parameters**

``struct libnvmf_context *p``
  The :c:type:`struct libnvmf_context <libnvmf_context>` instance to update.

``long keyring_id``
  Value to assign to the keyring_id field.


.. c:function:: long libnvmf_context_get_keyring_id (const struct libnvmf_context *p)

   Get keyring_id.

**Parameters**

``const struct libnvmf_context *p``
  The :c:type:`struct libnvmf_context <libnvmf_context>` instance to query.

**Return**

The value of the keyring_id field.


.. c:function:: void libnvmf_context_set_tls_key_id (struct libnvmf_context *p, long tls_key_id)

   Set tls_key_id.

**Parameters**

``struct libnvmf_context *p``
  The :c:type:`struct libnvmf_context <libnvmf_context>` instance to update.

``long tls_key_id``
  Value to assign to the tls_key_id field.


.. c:function:: long libnvmf_context_get_tls_key_id (const struct libnvmf_context *p)

   Get tls_key_id.

**Parameters**

``const struct libnvmf_context *p``
  The :c:type:`struct libnvmf_context <libnvmf_context>` instance to query.

**Return**

The value of the tls_key_id field.


.. c:function:: void libnvmf_context_set_tls_configured_key_id (struct libnvmf_context *p, long tls_configured_key_id)

   Set tls_configured_key_id.

**Parameters**

``struct libnvmf_context *p``
  The :c:type:`struct libnvmf_context <libnvmf_context>` instance to update.

``long tls_configured_key_id``
  Value to assign to the tls_configured_key_id field.


.. c:function:: long libnvmf_context_get_tls_configured_key_id (const struct libnvmf_context *p)

   Get tls_configured_key_id.

**Parameters**

``const struct libnvmf_context *p``
  The :c:type:`struct libnvmf_context <libnvmf_context>` instance to query.

**Return**

The value of the tls_configured_key_id field.


.. c:function:: void libnvmf_context_set_duplicate_connect (struct libnvmf_context *p, bool duplicate_connect)

   Set duplicate_connect.

**Parameters**

``struct libnvmf_context *p``
  The :c:type:`struct libnvmf_context <libnvmf_context>` instance to update.

``bool duplicate_connect``
  Value to assign to the duplicate_connect field.


.. c:function:: bool libnvmf_context_get_duplicate_connect (const struct libnvmf_context *p)

   Get duplicate_connect.

**Parameters**

``const struct libnvmf_context *p``
  The :c:type:`struct libnvmf_context <libnvmf_context>` instance to query.

**Return**

The value of the duplicate_connect field.


.. c:function:: void libnvmf_context_set_disable_sqflow (struct libnvmf_context *p, bool disable_sqflow)

   Set disable_sqflow.

**Parameters**

``struct libnvmf_context *p``
  The :c:type:`struct libnvmf_context <libnvmf_context>` instance to update.

``bool disable_sqflow``
  Value to assign to the disable_sqflow field.


.. c:function:: bool libnvmf_context_get_disable_sqflow (const struct libnvmf_context *p)

   Get disable_sqflow.

**Parameters**

``const struct libnvmf_context *p``
  The :c:type:`struct libnvmf_context <libnvmf_context>` instance to query.

**Return**

The value of the disable_sqflow field.


.. c:function:: void libnvmf_context_set_hdr_digest (struct libnvmf_context *p, bool hdr_digest)

   Set hdr_digest.

**Parameters**

``struct libnvmf_context *p``
  The :c:type:`struct libnvmf_context <libnvmf_context>` instance to update.

``bool hdr_digest``
  Value to assign to the hdr_digest field.


.. c:function:: bool libnvmf_context_get_hdr_digest (const struct libnvmf_context *p)

   Get hdr_digest.

**Parameters**

``const struct libnvmf_context *p``
  The :c:type:`struct libnvmf_context <libnvmf_context>` instance to query.

**Return**

The value of the hdr_digest field.


.. c:function:: void libnvmf_context_set_data_digest (struct libnvmf_context *p, bool data_digest)

   Set data_digest.

**Parameters**

``struct libnvmf_context *p``
  The :c:type:`struct libnvmf_context <libnvmf_context>` instance to update.

``bool data_digest``
  Value to assign to the data_digest field.


.. c:function:: bool libnvmf_context_get_data_digest (const struct libnvmf_context *p)

   Get data_digest.

**Parameters**

``const struct libnvmf_context *p``
  The :c:type:`struct libnvmf_context <libnvmf_context>` instance to query.

**Return**

The value of the data_digest field.


.. c:function:: void libnvmf_context_set_tls (struct libnvmf_context *p, bool tls)

   Set tls.

**Parameters**

``struct libnvmf_context *p``
  The :c:type:`struct libnvmf_context <libnvmf_context>` instance to update.

``bool tls``
  Value to assign to the tls field.


.. c:function:: bool libnvmf_context_get_tls (const struct libnvmf_context *p)

   Get tls.

**Parameters**

``const struct libnvmf_context *p``
  The :c:type:`struct libnvmf_context <libnvmf_context>` instance to query.

**Return**

The value of the tls field.


.. c:function:: void libnvmf_context_set_concat (struct libnvmf_context *p, bool concat)

   Set concat.

**Parameters**

``struct libnvmf_context *p``
  The :c:type:`struct libnvmf_context <libnvmf_context>` instance to update.

``bool concat``
  Value to assign to the concat field.


.. c:function:: bool libnvmf_context_get_concat (const struct libnvmf_context *p)

   Get concat.

**Parameters**

``const struct libnvmf_context *p``
  The :c:type:`struct libnvmf_context <libnvmf_context>` instance to query.

**Return**

The value of the concat field.


.. c:function:: void libnvmf_context_set_default_max_discovery_retries (struct libnvmf_context *p, int default_max_discovery_retries)

   Setter.

**Parameters**

``struct libnvmf_context *p``
  The :c:type:`struct libnvmf_context <libnvmf_context>` instance to update.

``int default_max_discovery_retries``
  New value.


.. c:function:: int libnvmf_context_get_default_max_discovery_retries (const struct libnvmf_context *p)

   Getter.

**Parameters**

``const struct libnvmf_context *p``
  The :c:type:`struct libnvmf_context <libnvmf_context>` instance to query.

**Return**

The value of the default_max_discovery_retries field.


.. c:function:: void libnvmf_context_set_default_keep_alive_timeout (struct libnvmf_context *p, int default_keep_alive_timeout)

   Setter.

**Parameters**

``struct libnvmf_context *p``
  The :c:type:`struct libnvmf_context <libnvmf_context>` instance to update.

``int default_keep_alive_timeout``
  New value.


.. c:function:: int libnvmf_context_get_default_keep_alive_timeout (const struct libnvmf_context *p)

   Getter.

**Parameters**

``const struct libnvmf_context *p``
  The :c:type:`struct libnvmf_context <libnvmf_context>` instance to query.

**Return**

The value of the default_keep_alive_timeout field.


.. c:function:: const char * libnvmf_context_get_device (const struct libnvmf_context *p)

   Get device.

**Parameters**

``const struct libnvmf_context *p``
  The :c:type:`struct libnvmf_context <libnvmf_context>` instance to query.

**Return**

The value of the device field, or NULL if not set.


.. c:function:: void libnvmf_context_set_persistent (struct libnvmf_context *p, bool persistent)

   Set persistent.

**Parameters**

``struct libnvmf_context *p``
  The :c:type:`struct libnvmf_context <libnvmf_context>` instance to update.

``bool persistent``
  Value to assign to the persistent field.


.. c:function:: bool libnvmf_context_get_persistent (const struct libnvmf_context *p)

   Get persistent.

**Parameters**

``const struct libnvmf_context *p``
  The :c:type:`struct libnvmf_context <libnvmf_context>` instance to query.

**Return**

The value of the persistent field.


.. c:function:: const char * libnvmf_context_get_hostnqn (const struct libnvmf_context *p)

   Get hostnqn.

**Parameters**

``const struct libnvmf_context *p``
  The :c:type:`struct libnvmf_context <libnvmf_context>` instance to query.

**Return**

The value of the hostnqn field, or NULL if not set.


.. c:function:: const char * libnvmf_context_get_hostid (const struct libnvmf_context *p)

   Get hostid.

**Parameters**

``const struct libnvmf_context *p``
  The :c:type:`struct libnvmf_context <libnvmf_context>` instance to query.

**Return**

The value of the hostid field, or NULL if not set.


.. c:function:: const char * libnvmf_context_get_hostkey (const struct libnvmf_context *p)

   Get hostkey.

**Parameters**

``const struct libnvmf_context *p``
  The :c:type:`struct libnvmf_context <libnvmf_context>` instance to query.

**Return**

The value of the hostkey field, or NULL if not set.


.. c:function:: const char * libnvmf_context_get_ctrlkey (const struct libnvmf_context *p)

   Get ctrlkey.

**Parameters**

``const struct libnvmf_context *p``
  The :c:type:`struct libnvmf_context <libnvmf_context>` instance to query.

**Return**

The value of the ctrlkey field, or NULL if not set.


.. c:function:: const char * libnvmf_context_get_keyring (const struct libnvmf_context *p)

   Get keyring.

**Parameters**

``const struct libnvmf_context *p``
  The :c:type:`struct libnvmf_context <libnvmf_context>` instance to query.

**Return**

The value of the keyring field, or NULL if not set.


.. c:function:: const char * libnvmf_context_get_tls_key (const struct libnvmf_context *p)

   Get tls_key.

**Parameters**

``const struct libnvmf_context *p``
  The :c:type:`struct libnvmf_context <libnvmf_context>` instance to query.

**Return**

The value of the tls_key field, or NULL if not set.


.. c:function:: const char * libnvmf_context_get_tls_key_identity (const struct libnvmf_context *p)

   Get tls_key_identity.

**Parameters**

``const struct libnvmf_context *p``
  The :c:type:`struct libnvmf_context <libnvmf_context>` instance to query.

**Return**

The value of the tls_key_identity field, or NULL if not set.


.. c:function:: int libnvmf_discovery_args_new (struct libnvmf_discovery_args **pp)

   Allocate and initialise a new instance.

**Parameters**

``struct libnvmf_discovery_args **pp``
  On success, *pp is set to the newly allocated object.

**Description**

Allocates a zeroed :c:type:`struct libnvmf_discovery_args <libnvmf_discovery_args>` on the heap.
The caller must release it with libnvmf_discovery_args_free().

**Return**

0 on success, -EINVAL if **pp** is NULL,
        -ENOMEM if allocation fails.


.. c:function:: void libnvmf_discovery_args_free (struct libnvmf_discovery_args *p)

   Release a libnvmf_discovery_args object.

**Parameters**

``struct libnvmf_discovery_args *p``
  Object previously returned by libnvmf_discovery_args_new().
  A NULL pointer is silently ignored.


.. c:function:: void libnvmf_discovery_args_init_defaults (struct libnvmf_discovery_args *p)

   Set fields to their defaults.

**Parameters**

``struct libnvmf_discovery_args *p``
  The :c:type:`struct libnvmf_discovery_args <libnvmf_discovery_args>` instance to initialise.

**Description**

Sets each field that carries a default annotation to its
compile-time default value.  Called automatically by
libnvmf_discovery_args_new() but may also be called directly to reset an
instance to its defaults without reallocating it.


.. c:function:: void libnvmf_discovery_args_set_max_retries (struct libnvmf_discovery_args *p, int max_retries)

   Set max_retries.

**Parameters**

``struct libnvmf_discovery_args *p``
  The :c:type:`struct libnvmf_discovery_args <libnvmf_discovery_args>` instance to update.

``int max_retries``
  Value to assign to the max_retries field.


.. c:function:: int libnvmf_discovery_args_get_max_retries (const struct libnvmf_discovery_args *p)

   Get max_retries.

**Parameters**

``const struct libnvmf_discovery_args *p``
  The :c:type:`struct libnvmf_discovery_args <libnvmf_discovery_args>` instance to query.

**Return**

The value of the max_retries field.


.. c:function:: void libnvmf_discovery_args_set_lsp (struct libnvmf_discovery_args *p, __u8 lsp)

   Set lsp.

**Parameters**

``struct libnvmf_discovery_args *p``
  The :c:type:`struct libnvmf_discovery_args <libnvmf_discovery_args>` instance to update.

``__u8 lsp``
  Value to assign to the lsp field.


.. c:function:: __u8 libnvmf_discovery_args_get_lsp (const struct libnvmf_discovery_args *p)

   Get lsp.

**Parameters**

``const struct libnvmf_discovery_args *p``
  The :c:type:`struct libnvmf_discovery_args <libnvmf_discovery_args>` instance to query.

**Return**

The value of the lsp field.


.. c:function:: void libnvmf_uri_set_scheme (struct libnvmf_uri *p, const char *scheme)

   Set scheme.

**Parameters**

``struct libnvmf_uri *p``
  The :c:type:`struct libnvmf_uri <libnvmf_uri>` instance to update.

``const char *scheme``
  New string; a copy is stored. Pass NULL to clear.


.. c:function:: const char * libnvmf_uri_get_scheme (const struct libnvmf_uri *p)

   Get scheme.

**Parameters**

``const struct libnvmf_uri *p``
  The :c:type:`struct libnvmf_uri <libnvmf_uri>` instance to query.

**Return**

The value of the scheme field, or NULL if not set.


.. c:function:: void libnvmf_uri_set_protocol (struct libnvmf_uri *p, const char *protocol)

   Set protocol.

**Parameters**

``struct libnvmf_uri *p``
  The :c:type:`struct libnvmf_uri <libnvmf_uri>` instance to update.

``const char *protocol``
  New string; a copy is stored. Pass NULL to clear.


.. c:function:: const char * libnvmf_uri_get_protocol (const struct libnvmf_uri *p)

   Get protocol.

**Parameters**

``const struct libnvmf_uri *p``
  The :c:type:`struct libnvmf_uri <libnvmf_uri>` instance to query.

**Return**

The value of the protocol field, or NULL if not set.


.. c:function:: void libnvmf_uri_set_userinfo (struct libnvmf_uri *p, const char *userinfo)

   Set userinfo.

**Parameters**

``struct libnvmf_uri *p``
  The :c:type:`struct libnvmf_uri <libnvmf_uri>` instance to update.

``const char *userinfo``
  New string; a copy is stored. Pass NULL to clear.


.. c:function:: const char * libnvmf_uri_get_userinfo (const struct libnvmf_uri *p)

   Get userinfo.

**Parameters**

``const struct libnvmf_uri *p``
  The :c:type:`struct libnvmf_uri <libnvmf_uri>` instance to query.

**Return**

The value of the userinfo field, or NULL if not set.


.. c:function:: void libnvmf_uri_set_host (struct libnvmf_uri *p, const char *host)

   Set host.

**Parameters**

``struct libnvmf_uri *p``
  The :c:type:`struct libnvmf_uri <libnvmf_uri>` instance to update.

``const char *host``
  New string; a copy is stored. Pass NULL to clear.


.. c:function:: const char * libnvmf_uri_get_host (const struct libnvmf_uri *p)

   Get host.

**Parameters**

``const struct libnvmf_uri *p``
  The :c:type:`struct libnvmf_uri <libnvmf_uri>` instance to query.

**Return**

The value of the host field, or NULL if not set.


.. c:function:: void libnvmf_uri_set_port (struct libnvmf_uri *p, int port)

   Set port.

**Parameters**

``struct libnvmf_uri *p``
  The :c:type:`struct libnvmf_uri <libnvmf_uri>` instance to update.

``int port``
  Value to assign to the port field.


.. c:function:: int libnvmf_uri_get_port (const struct libnvmf_uri *p)

   Get port.

**Parameters**

``const struct libnvmf_uri *p``
  The :c:type:`struct libnvmf_uri <libnvmf_uri>` instance to query.

**Return**

The value of the port field.


.. c:function:: void libnvmf_uri_set_path_segments (struct libnvmf_uri *p, const char *const *path_segments)

   Set path_segments.

**Parameters**

``struct libnvmf_uri *p``
  The :c:type:`struct libnvmf_uri <libnvmf_uri>` instance to update.

``const char *const *path_segments``
  New NULL-terminated string array; deep-copied.


.. c:function:: const char *const * libnvmf_uri_get_path_segments (const struct libnvmf_uri *p)

   Get path_segments.

**Parameters**

``const struct libnvmf_uri *p``
  The :c:type:`struct libnvmf_uri <libnvmf_uri>` instance to query.

**Return**

The value of the path_segments field.


.. c:function:: void libnvmf_uri_set_query (struct libnvmf_uri *p, const char *query)

   Set query.

**Parameters**

``struct libnvmf_uri *p``
  The :c:type:`struct libnvmf_uri <libnvmf_uri>` instance to update.

``const char *query``
  New string; a copy is stored. Pass NULL to clear.


.. c:function:: const char * libnvmf_uri_get_query (const struct libnvmf_uri *p)

   Get query.

**Parameters**

``const struct libnvmf_uri *p``
  The :c:type:`struct libnvmf_uri <libnvmf_uri>` instance to query.

**Return**

The value of the query field, or NULL if not set.


.. c:function:: void libnvmf_uri_set_fragment (struct libnvmf_uri *p, const char *fragment)

   Set fragment.

**Parameters**

``struct libnvmf_uri *p``
  The :c:type:`struct libnvmf_uri <libnvmf_uri>` instance to update.

``const char *fragment``
  New string; a copy is stored. Pass NULL to clear.


.. c:function:: const char * libnvmf_uri_get_fragment (const struct libnvmf_uri *p)

   Get fragment.

**Parameters**

``const struct libnvmf_uri *p``
  The :c:type:`struct libnvmf_uri <libnvmf_uri>` instance to query.

**Return**

The value of the fragment field, or NULL if not set.


