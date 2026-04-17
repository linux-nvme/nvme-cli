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


