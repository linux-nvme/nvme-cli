.. _config.h:

**config.h**


NVMe-oF connection configuration.

The configuration consists of a main INI file and optional .conf drop-ins
under <file>.d/. At load time, these inputs are resolved into a flat list
of connections. Each connection contains the complete role, addressing,
identity, and parameter set after all defaults and overrides have been
applied.

Files, sections, and drop-ins are internal representation details and are
not exposed through this API.

The configuration API is read-only. It provides access to resolved
connection data but does not provide setters.

Connection configuration support is available only when NVMe-oF fabrics
support is enabled.

.. c:function:: int libnvmf_config_read (struct libnvme_global_ctx *ctx, const char *file, struct libnvmf_config **out)

   read and resolve a connection configuration.

**Parameters**

``struct libnvme_global_ctx *ctx``
  libnvme global context

``const char *file``
  main configuration file, or NULL for the default
  (/etc/nvme/nvme-fabrics.conf).  The drop-in directory is always
  derived from the file name: the .conf files under <file>.d/.

``struct libnvmf_config **out``
  the resolved configuration on success; NULL on error

**Description**

Reads the main file (if it exists) and the drop-ins (if the directory
exists) and resolves them into the flat connection list.  An absent
configuration is valid and yields an empty list.  Any validation error
in any file fails the read as a unit; diagnostics carry file:line and
are reported through **ctx**.

**Return**

0 on success (***out** is the resolved configuration), negative
errno otherwise (***out** is NULL).


.. c:function:: void libnvmf_config_free (struct libnvmf_config *config)

   release a resolved configuration.

**Parameters**

``struct libnvmf_config *config``
  configuration to free; NULL is a no-op.

**Description**

Invalidates every connection and parameter set obtained from **config**.


.. c:function:: int libnvmf_config_validate (struct libnvme_global_ctx *ctx, const char *file)

   dry-run a connection configuration.

**Parameters**

``struct libnvme_global_ctx *ctx``
  libnvme global context

``const char *file``
  main configuration file, or NULL for the default.

**Description**

Reads and resolves like libnvmf_config_read(), reporting every
diagnostic through **ctx**, without handing back a configuration.

**Return**

0 when the configuration is valid (including absent),
negative errno otherwise.


.. c:function:: void libnvmf_config_conn_for_each (const struct libnvmf_config *config, void (*callback)(const struct libnvmf_config_conn *conn, void *user_data), void *user_data)

   iterate over the resolved connections.

**Parameters**

``const struct libnvmf_config *config``
  the resolved configuration

``void (*callback)(const struct libnvmf_config_conn *conn, void *user_data)``
  called once per connection, in file order (main file first,
  then the drop-ins in sorted order)

``void *user_data``
  caller context passed to **callback**


.. c:function:: bool libnvmf_config_conn_is_dc (const struct libnvmf_config_conn *conn)

   is this connection a discovery controller?

**Parameters**

``const struct libnvmf_config_conn *conn``
  the resolved connection

**Return**

true for a discovery controller, false for an I/O controller.


.. c:function:: const char * libnvmf_config_conn_get_transport (const struct libnvmf_config_conn *conn)

   a connection's transport.

**Parameters**

``const struct libnvmf_config_conn *conn``
  the resolved connection

**Description**

Addressing is exposed as raw strings, not a TID: the configuration is a
human interface and traddr/host-traddr may legitimately name a host,
while TID construction rejects one.  Resolve first, then build a TID
with libnvmf_tid_from_fields() + libnvmf_tid_set_identity().

**Return**

borrowed string, valid while the owning configuration is alive.


.. c:function:: const char * libnvmf_config_conn_get_traddr (const struct libnvmf_config_conn *conn)

   a connection's transport address.

**Parameters**

``const struct libnvmf_config_conn *conn``
  the resolved connection

**Description**

May be a hostname; see libnvmf_config_conn_get_transport().

**Return**

borrowed string, valid while the owning configuration is alive.


.. c:function:: const char * libnvmf_config_conn_get_trsvcid (const struct libnvmf_config_conn *conn)

   a connection's transport service ID.

**Parameters**

``const struct libnvmf_config_conn *conn``
  the resolved connection

**Return**

borrowed string, or NULL when unset (the transport default
applies).


.. c:function:: const char * libnvmf_config_conn_get_subsysnqn (const struct libnvmf_config_conn *conn)

   a connection's subsystem NQN.

**Parameters**

``const struct libnvmf_config_conn *conn``
  the resolved connection

**Return**

borrowed string; the well-known discovery NQN for a discovery
controller with no explicit nqn.


.. c:function:: const char * libnvmf_config_conn_get_host_traddr (const struct libnvmf_config_conn *conn)

   a connection's host transport address.

**Parameters**

``const struct libnvmf_config_conn *conn``
  the resolved connection

**Description**

Never a hostname -- always one of the host's own local addresses.

**Return**

borrowed string, or NULL when the path left it unset.


.. c:function:: const char * libnvmf_config_conn_get_host_iface (const struct libnvmf_config_conn *conn)

   a connection's host interface binding.

**Parameters**

``const struct libnvmf_config_conn *conn``
  the resolved connection

**Return**

borrowed string, or NULL when the path left it unset.


.. c:function:: const char * libnvmf_config_conn_get_hostnqn (const struct libnvmf_config_conn *conn)

   a connection's host NQN.

**Parameters**

``const struct libnvmf_config_conn *conn``
  the resolved connection

**Return**

borrowed string, or NULL when the configuration leaves the host
identity to the system default (the connect path applies its usual
/etc/nvme/hostnqn fallback).


.. c:function:: const char * libnvmf_config_conn_get_hostid (const struct libnvmf_config_conn *conn)

   a connection's host identifier.

**Parameters**

``const struct libnvmf_config_conn *conn``
  the resolved connection

**Return**

borrowed string, or NULL when the configuration leaves the host
identity to the system default (the connect path applies its usual
hostid fallback).


.. c:function:: const struct libnvmf_params * libnvmf_config_conn_get_params (const struct libnvmf_config_conn *conn)

   a connection's resolved parameters.

**Parameters**

``const struct libnvmf_config_conn *conn``
  the resolved connection

**Description**

Every cascade level is already merged; what remains unset is a "use the
kernel default".

**Return**

borrowed pointer, valid while the owning configuration is alive.


.. c:function:: const char * libnvmf_config_conn_get_hostsymname (const struct libnvmf_config_conn *conn)

   the persona's symbolic name.

**Parameters**

``const struct libnvmf_config_conn *conn``
  the resolved connection

**Return**

borrowed string, or NULL when the persona has none.


.. c:function:: const char * libnvmf_config_conn_get_source (const struct libnvmf_config_conn *conn)

   the file a connection came from.

**Parameters**

``const struct libnvmf_config_conn *conn``
  the resolved connection

**Description**

Provenance for diagnostics and "config show" style output.

**Return**

borrowed string; the originating file's path.


.. c:function:: const struct libnvmf_params * libnvmf_config_resolve_discovered (const struct libnvmf_config *config, const struct libnvmf_config_conn *via_dc, bool is_dc)

   parameters for a controller that is not in the configuration.

**Parameters**

``const struct libnvmf_config *config``
  the resolved configuration

``const struct libnvmf_config_conn *via_dc``
  the DC connection the controller was discovered through, or NULL
  for a controller with no configured origin (e.g. an
  mDNS-discovered DC)

``bool is_dc``
  true for a discovered discovery controller (a referral), false
  for a discovered I/O controller

**Description**

A controller learned at runtime -- from a discovery log page, an AEN, or
mDNS -- has no section in the configuration, but still draws parameters
from it: the defaults of the file scope it was discovered through, or the
top-level scope when it has no configured origin.  The four combinations:

  (via_dc = DC,   is_dc = true)   a referral: a DC discovered via a DC;
                                  draws that DC's DC-defaults scope
  (via_dc = DC,   is_dc = false)  a DLP-discovered IOC; draws that DC's
                                  IOC-defaults scope
  (via_dc = NULL, is_dc = true)   a DC with no configured origin (e.g.
                                  mDNS); draws the top-level DC scope
  (via_dc = NULL, is_dc = false)  an IOC with no configured origin;
                                  draws the top-level IOC scope

**Return**

borrowed parameter set, valid while **config** is alive.  **via_dc** must
be a connection of **config**; an I/O-controller **via_dc** yields NULL.  Passing
a connection that does not belong to **config** is undefined.


.. c:function:: int libnvmf_config_get_discovered_params (const struct libnvmf_config *config, const char *hostnqn, bool is_dc, const char *nqn, const struct libnvmf_params **params)

   discovered controller parameters.

**Parameters**

``const struct libnvmf_config *config``
  the resolved configuration

``const char *hostnqn``
  the host NQN that selects the file, or NULL for the top-level
  file

``bool is_dc``
  true for a discovery controller, false for an I/O controller

``const char *nqn``
  the NQN of the discovered controller, or NULL

``const struct libnvmf_params **params``
  set to the parameters, valid while **config** is alive

**Description**

A controller found through discovery has no section in the
configuration. Its parameters come from one file: the file whose [Host]
section has **hostnqn**. For a controller found through a discovery
controller of **config**, use libnvmf_config_conn_get_hostnqn() of that
discovery controller's connection.

The parameters are the defaults of that file for a discovery controller
or an I/O controller. If the file also has a section with nqn = **nqn**,
its kxchap-secret and kxchap-ctrl-secret replace the defaults. That
section is a [Discovery Controller] section if **is_dc** is true, a
[Subsystem] section otherwise. Its controller= lines do not matter. A
section with the well-known discovery NQN never matches.

**Return**

0 on success, -EINVAL if **config** or **params** is NULL, or -ENOENT
if no file of **config** has **hostnqn**.


.. c:function:: const char * libnvmf_config_get_hostnqn (const struct libnvmf_config *config)

   the top-level [Host] host NQN.

**Parameters**

``const struct libnvmf_config *config``
  the resolved configuration

**Description**

The identity of the configuration's default persona, as written in the
top-level file's [Host] section.  A drop-in's persona is deliberately not
reachable here: it belongs to that drop-in's own connections.

Each connection already carries the identity it is made under, but a
configuration may name a persona and configure no connections at all -- a
host that only connects what it discovers.  This is how that identity is
read.

**Return**

borrowed string, valid while **config** is alive, or NULL when the
top-level file names no host NQN (the caller falls back to the system
identity in /etc/nvme/hostnqn).


.. c:function:: const char * libnvmf_config_get_hostid (const struct libnvmf_config *config)

   the top-level [Host] host ID.

**Parameters**

``const struct libnvmf_config *config``
  the resolved configuration

**Description**

See libnvmf_config_get_hostnqn().

**Return**

borrowed string, valid while **config** is alive, or NULL when the
top-level file names no host ID (the caller falls back to the system
identity in /etc/nvme/hostid).


.. c:function:: const char * libnvmf_config_get_hostsymname (const struct libnvmf_config *config)

   the top-level [Host] symbolic name.

**Parameters**

``const struct libnvmf_config *config``
  the resolved configuration

**Description**

The symbolic name a Discovery Information Management (DIM) command reports
to a Centralized Discovery Controller (TP8010).  Unlike the host NQN and
host ID it has no system-wide file to fall back on, so this is the only
place it can be configured for a host that connects only what it discovers.

**Return**

borrowed string, valid while **config** is alive, or NULL when the
top-level file names no symbolic name.


.. c:function:: int libnvmf_connect_args_emit (const struct libnvmf_tid *tid, const struct libnvmf_params *params, void (*callback)(const char *arg, void *user_data), void *user_data)

   render a connection as "nvme connect" options.

**Parameters**

``const struct libnvmf_tid *tid``
  addressing + identity, or NULL to emit the parameters only

``const struct libnvmf_params *params``
  connection parameters, or NULL to emit the TID only

``void (*callback)(const char *arg, void *user_data)``
  called once per formatted option, e.g. "--transport=tcp";
  the string is only valid for the duration of the call

``void *user_data``
  caller context passed to **callback**

**Description**

Emits the TID's set fields first, in fixed order (--transport, --traddr,
--trsvcid, --nqn, --host-traddr, --host-iface, --hostnqn, --hostid),
then the parameters in their iteration order.  Unset and reset
parameters are skipped so the kernel default applies; a boolean
parameter is emitted as a bare "--flag" when true and skipped when
false.  Consumer-private options are the caller's to append.

This is the consumption path for the resolved configuration: each
connection becomes the option list of one "nvme connect" invocation.
It also renders a connection as a human-readable, copy-pasteable
command line for "config show" style output.

**Return**

0 on success, -EINVAL when **callback** is NULL, -ENOMEM when
formatting an option fails (the emission stops there).


.. c:function:: void libnvmf_context_set_config (struct libnvmf_context *fctx, const struct libnvmf_config *config, const struct libnvmf_config_conn *conn)

   Set the configuration for discovery

**Parameters**

``struct libnvmf_context *fctx``
  Fabrics context of a discovery controller

``const struct libnvmf_config *config``
  Resolved configuration, or NULL

``const struct libnvmf_config_conn *conn``
  Connection of the discovery controller in **config**

**Description**

libnvmf_discover() connects to the controllers in the discovery log
page. With a configuration, a controller gets the KX-HMAC-CHAP secrets
of the [Subsystem] or [Discovery Controller] section with its NQN. The
section must be in the same file as **conn**.

If no section sets the host secret, the controller uses the host secret
of the discovery controller. This is also what happens without a
configuration. The controller secret comes only from a section.

The caller keeps ownership of **config** and **conn**. They must stay valid
until libnvmf_discover() returns.


.. c:function:: int libnvmf_context_apply_params (struct libnvmf_context *fctx, const struct libnvmf_params *params)

   apply a parameter set to a connect context.

**Parameters**

``struct libnvmf_context *fctx``
  fabrics context to update

``const struct libnvmf_params *params``
  a resolved parameter set

**Description**

Applies every set key via its typed setter. An unset key is left
untouched, and an explicit reset (empty string) is skipped, since
**fctx** already carries the kernel default either way.

**Return**

0 on success, -EINVAL if **fctx** or **params** is NULL.


.. c:function:: struct libnvmf_config_emitter * libnvmf_config_emit_new (struct libnvme_global_ctx *ctx)

   Create a configuration emitter.

**Parameters**

``struct libnvme_global_ctx *ctx``
  libnvme global context. Must not be NULL.

**Return**

A new emitter on success, or NULL on failure.
Free the emitter with libnvmf_config_emit_free().


.. c:function:: void libnvmf_config_emit_free (struct libnvmf_config_emitter *emitter)

   Free a configuration emitter.

**Parameters**

``struct libnvmf_config_emitter *emitter``
  Emitter to free. NULL is ignored.


.. c:function:: int libnvmf_config_emit_add (struct libnvmf_config_emitter *emitter, bool is_dc, const char *transport, const char *traddr, const char *trsvcid, const char *subsysnqn, const char *host_traddr, const char *host_iface, const char *hostnqn, const char *hostid, const struct libnvmf_params *params, const char *hostsymname)

   Add a connection to a configuration emitter.

**Parameters**

``struct libnvmf_config_emitter *emitter``
  Configuration emitter.

``bool is_dc``
  Discovery controller if true, I/O controller if false.

``const char *transport``
  Transport type. Required.

``const char *traddr``
  Transport address. Required. Written verbatim, even if a
  hostname; resolution happens at connect time, not here.

``const char *trsvcid``
  Transport service ID, or NULL.

``const char *subsysnqn``
  Subsystem NQN. Required unless **is_dc** is true.

``const char *host_traddr``
  Host transport address, or NULL.

``const char *host_iface``
  Host interface, or NULL.

``const char *hostnqn``
  Host NQN, or NULL.

``const char *hostid``
  Host identifier, or NULL.

``const struct libnvmf_params *params``
  Connection parameters, or NULL.

``const char *hostsymname``
  Host symbolic name, or NULL.

**Description**

The parameter set is copied by the emitter.

**Return**



* 0 on success.
* -EINVAL if a required parameter is missing or if **hostsymname**
  conflicts with an existing persona.
* -ENOMEM if memory allocation fails.


.. c:function:: int libnvmf_config_emit_install (struct libnvmf_config_emitter *emitter, const char *file, bool force)

   Write a configuration to disk.

**Parameters**

``struct libnvmf_config_emitter *emitter``
  Configuration emitter.

``const char *file``
  Destination configuration file, or NULL to use the default
  configuration file.

``bool force``
  Overwrite an existing configuration if true.

**Description**

The default persona is written to the main configuration file. Each
named persona is written to a separate drop-in file.

The generated configuration is validated by reading it back through the
standard parser before it is installed. Files are written atomically
(temporary file followed by rename). If any step fails, no configuration
is installed.

**Return**



* 0 on success.
* -EEXIST if a configuration already exists and **force** is false.
* -EINVAL if **emitter** is NULL.
* A negative errno value on other failures.


.. c:function:: struct libnvmf_params * libnvmf_params_new (void)

   Create a connection parameter set.

**Parameters**

``void``
  no arguments

**Return**

A new parameter set on success, or NULL on failure.
Free the parameter set with libnvmf_params_free().


.. c:function:: void libnvmf_params_free (struct libnvmf_params *params)

   Free a connection parameter set.

**Parameters**

``struct libnvmf_params *params``
  Parameter set to free. NULL is ignored.

**Description**

Only free a set obtained from libnvmf_params_new(); never call this on
a set borrowed from a configuration.


.. c:function:: int libnvmf_params_set (struct libnvmf_params *params, const char *key, const char *value)

   Set a connection parameter.

**Parameters**

``struct libnvmf_params *params``
  Caller-owned parameter set.

``const char *key``
  Parameter name.

``const char *value``
  Parameter value as a string. An empty string restores the
  kernel default for the parameter.

**Description**

If the parameter already exists, its value is replaced.

**Return**



* 0 on success.
* -EINVAL if **key** is unknown, is not a connection parameter,
  or if **value** is invalid for the parameter type.
* -ENOMEM if memory allocation fails.


.. c:function:: const char * libnvmf_params_get (const struct libnvmf_params *params, const char *key)

   look up one connection parameter.

**Parameters**

``const struct libnvmf_params *params``
  a resolved parameter set

``const char *key``
  the configuration key name (the "nvme connect" long-option name,
  e.g. "ctrl-loss-tmo")

**Return**

NULL when **key** is unset (the kernel default applies), the empty
string for an explicit reset to the kernel default, the value string
otherwise.  Borrowed; valid while the owning configuration is alive.


.. c:function:: void libnvmf_params_for_each (const struct libnvmf_params *params, void (*callback)(const char *key, const char *value, void *user_data), void *user_data)

   iterate over set connection parameters.

**Parameters**

``const struct libnvmf_params *params``
  a resolved parameter set

``void (*callback)(const char *key, const char *value, void *user_data)``
  called once per key in first-insertion order; **value** is the
  empty string for an explicit reset, never NULL

``void *user_data``
  caller context passed to **callback**


