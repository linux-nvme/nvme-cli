.. c:function:: int libnvmf_tid_from_fields (const char *transport, const char *traddr, const char *trsvcid, const char *subsysnqn, const char *host_traddr, const char *host_iface, const char *hostnqn, const char *hostid, struct libnvmf_tid **out)

   Allocate a TID from individual field strings.

**Parameters**

``const char *transport``
  Transport type (e.g. "tcp", "rdma", "fc").

``const char *traddr``
  Transport address.

``const char *trsvcid``
  Transport service ID (e.g. "8009").

``const char *subsysnqn``
  Subsystem NQN.

``const char *host_traddr``
  Host transport address, or NULL.

``const char *host_iface``
  Host interface name, or NULL.

``const char *hostnqn``
  Host NQN, or NULL.

``const char *hostid``
  Host Identifier, or NULL.

``struct libnvmf_tid **out``
  The allocated TID on success; NULL on error.

**Description**

Convenience constructor.  NULL fields are stored as NULL.  For an IP
transport (tcp, rdma) a numeric traddr/host_traddr is canonicalized; a
hostname is rejected -- resolving it is the caller's job, not libnvme's.

**Return**

0 on success (***out** is the allocated TID); -EINVAL if **out** is
NULL or traddr/host_traddr is not numeric on an IP transport; -ENOMEM on
allocation failure.


.. c:function:: int libnvmf_tid_set_identity (struct libnvmf_tid *tid, const char *subsysnqn, const char *hostnqn, const char *hostid)

   Set the subsystem and host identity together.

**Parameters**

``struct libnvmf_tid *tid``
  The transport ID.

``const char *subsysnqn``
  Subsystem NQN, or NULL to leave it unchanged.

``const char *hostnqn``
  Host NQN, or NULL to leave it unchanged.

``const char *hostid``
  Host Identifier, or NULL to leave it unchanged (or derive it).

**Description**

Identity is applied after addressing -- which subsystem, and which host
persona, are decided by context.  A NULL argument leaves that field as-is,
which is why the three are set through one call rather than per-field
setters (addressing has none: it is construction-only).

hostid is never left to chance: when no hostid is set but the resulting
hostnqn carries a UUID (nqn.2014-08.org.nvmexpress:uuid:<X>), the hostid is
derived from it -- the deterministic, per-host value (TP4126), never a
random one.  A hostid without a hostnqn is rejected: one host is one
(hostnqn, hostid) pair.

**Return**

0 on success; -EINVAL for a NULL **tid** or a hostid without a hostnqn;
-ENOMEM on allocation failure.


.. c:function:: struct libnvmf_tid * libnvmf_tid_dup (const struct libnvmf_tid *tid)

   Allocate a copy of an existing TID.

**Parameters**

``const struct libnvmf_tid *tid``
  Source TID, or NULL.

**Return**

Allocated copy, or NULL if **tid** is NULL or on allocation failure.


.. c:function:: int libnvmf_tid_parse (struct libnvme_global_ctx *ctx, const char *str, struct libnvmf_tid **out)

   Allocate a TID from a semicolon-separated key=value string.

**Parameters**

``struct libnvme_global_ctx *ctx``
  Global context used only for logging the diagnostics below.

``const char *str``
  Input string, e.g. "transport=tcp;traddr=1.2.3.4;trsvcid=8009".

``struct libnvmf_tid **out``
  The allocated TID on success; NULL on error.

**Description**

Recognized keys are the "nvme connect" option names: transport, traddr,
trsvcid, nqn, host-traddr, host-iface, hostnqn, hostid.  (The "nqn",
"host-traddr", and "host-iface" string keys map onto the struct's
subsysnqn, host_traddr, and host_iface fields, whose names follow the
C-identifier convention.)  Unknown keys, bare keys (no '='), and empty
values are logged at WARN level and skipped.
Whitespace around keys and values is trimmed.
Like libnvmf_tid_from_fields(), a traddr/host-traddr that is not numeric on
an IP transport fails the whole parse.

**Return**

0 on success (***out** is the allocated TID); -EINVAL if **ctx**, **out** or
**str** is NULL, or a traddr/host-traddr is not numeric on an IP transport;
-ENOMEM on allocation failure.


.. c:function:: int libnvmf_tid_parse_strict (struct libnvme_global_ctx *ctx, const char *str, struct libnvmf_tid **out)

   Like libnvmf_tid_parse(), but reject malformed input.

**Parameters**

``struct libnvme_global_ctx *ctx``
  Global context for logging.

``const char *str``
  Input string.

``struct libnvmf_tid **out``
  The allocated TID on success; NULL on error.

**Description**

Same as libnvmf_tid_parse() except that a malformed token -- a non-empty bare
token (no '='), an empty value, or an unrecognized key -- fails the whole
parse instead of being skipped.  Empty tokens (from ";;" or a trailing ';')
are still benign.  Useful when an unrecognized key should be treated as an
error (e.g. a typo in a hand-edited config) rather than silently ignored.

**Return**

0 on success (***out** is the allocated TID); -EINVAL if **ctx**, **out** or
**str** is NULL, or on a malformed token; -ENOMEM on allocation failure.


.. c:function:: bool libnvmf_traddr_is_numeric (const char *traddr)

   Would this address survive TID construction?

**Parameters**

``const char *traddr``
  A candidate traddr/host_traddr, or NULL.

**Description**

The TID constructors accept a numeric IP only and reject a hostname; this
lets a caller check a candidate address -- and decide whether it must
resolve it first -- before building the TID, using the same definition of
"numeric" the constructors use internally (including an IPv6 scope
suffix, which is numeric).

**Return**

true if **traddr** is a numeric address, false otherwise (including a
NULL **traddr** or an allocation failure while checking).


.. c:function:: bool libnvmf_tid_is_empty (const struct libnvmf_tid *tid)

   Test whether a TID sets no fields.

**Parameters**

``const struct libnvmf_tid *tid``
  The transport ID, or NULL.

**Return**

true if **tid** is NULL or every field is unset, false otherwise.


.. c:function:: const char * libnvmf_tid_get_canonical (const struct libnvmf_tid *tid)

   Return the canonical string form of a TID.

**Parameters**

``const struct libnvmf_tid *tid``
  The transport ID.

**Description**

Returns a deterministic, fixed-field-order semicolon-separated key=value
string (e.g. "transport=tcp;traddr=1.2.3.4;trsvcid=8009").  Only non-NULL
fields are included.  The string is lazily computed and cached; it is
invalidated by any identity change.

The fixed field order makes the output independent of the order fields
were set, so the same logical TID always yields the same canonical string.
This is the stable primitive libnvme provides for naming a connection; a
caller that wants a compact hash (e.g. for a systemd unit name) derives it
from this string itself -- libnvme does not hash it.

The constructors store numeric addresses in one form: IPv6 is compressed,
and an IPv4-mapped IPv6 address ("::ffff:1.2.3.4") becomes the IPv4
address ("1.2.3.4").  So two spellings of one numeric address yield the
same canonical string.

**Return**

Cached canonical string, or NULL on allocation failure.


.. c:function:: const char * libnvmf_tid_str (const struct libnvmf_tid *tid)

   Human-readable string form of a TID, for logging.

**Parameters**

``const struct libnvmf_tid *tid``
  The transport ID.

**Description**

Returns "(transport, traddr, trsvcid[, subsysnqn][, host_iface][, host_traddr])"
— the same rendering nvme-stas uses, so logs from both tools line up.
hostnqn and hostid are omitted.  Lazily computed and cached; invalidated by
any setter.

**Return**

Cached string, or NULL if **tid** is NULL or on allocation failure.


