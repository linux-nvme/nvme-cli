.. _exclusion.h:

**exclusion.h**


System-wide NVMe-oF exclusion list.

The exclusion list prevents orchestrators from auto-connecting to
controllers that a local administrator has explicitly excluded.  Each list
file holds an "[exclusions]" INI section with any number of
"exclusion = key=val;key=val" entries.

Matching is minimal: only fields present in the exclusion entry are
checked.  A NULL caller parameter for a field that IS present in an entry
causes that entry not to match — NULL means "this connection has no value
for this field", not "match any value".

Lists live in /etc/nvme/exclusions.conf (the default list) and
/etc/nvme/exclusions.conf.d/<name>.conf (named drop-ins).

Exclusion support is only available when fabrics support is enabled.

.. c:function:: bool libnvmf_exclusion_match (struct libnvme_global_ctx *ctx, const struct libnvmf_tid *tid)

   check whether a controller matches any exclusion entry.

**Parameters**

``struct libnvme_global_ctx *ctx``
  libnvme global context; must not be NULL

``const struct libnvmf_tid *tid``
  Transport ID identifying the controller.  All fields are optional;
  NULL means "this connection has no value for this field".

**Description**

Re-reads the exclusion directory on every call (no caching).
Entries with unknown keys never match (fail-safe).

**Return**

true if any exclusion entry matches, false otherwise.
Returns false (not excluded / fail-open) if the directory cannot be read.


.. c:function:: bool libnvmf_exclusion_entry_valid (struct libnvme_global_ctx *ctx, const char *entry)

   validate an entry string.

**Parameters**

``struct libnvme_global_ctx *ctx``
  libnvme global context; must not be NULL

``const char *entry``
  Exclusion entry, e.g. "transport=tcp;traddr=1.2.3.4".

**Description**

Returns true when every key is known and the entry has at least one
recognized field; false for unknown/bare keys or an empty/field-less entry.
Use this to pre-validate a hand-edited entry before writing it.

**Return**

true if the entry is valid, false otherwise.


.. c:function:: int libnvmf_exclusion_list_for_each (struct libnvme_global_ctx *ctx, void (*callback)(const char *name, void *user_data), void *user_data)

   iterate over exclusion list names.

**Parameters**

``struct libnvme_global_ctx *ctx``
  libnvme global context; must not be NULL

``void (*callback)(const char *name, void *user_data)``
  called for each .conf file; name is basename without .conf suffix

``void *user_data``
  caller context passed to **callback**

**Return**

0 on success, negative errno on error.
Returns 0 when the directory does not exist (nothing excluded).


.. c:function:: int libnvmf_exclusion_entry_for_each (struct libnvme_global_ctx *ctx, const char *name, void (*callback)(const char *entry, void *user_data), void *user_data)

   iterate over entries in a named list.

**Parameters**

``struct libnvme_global_ctx *ctx``
  libnvme global context; must not be NULL

``const char *name``
  list name (basename without .conf suffix)

``void (*callback)(const char *entry, void *user_data)``
  called with the raw entry string (e.g. "transport=tcp;traddr=...")

``void *user_data``
  caller context passed to **callback**

**Return**

0 on success, -ENOENT if the list does not exist, negative errno otherwise.


.. c:function:: int libnvmf_exclusion_create (struct libnvme_global_ctx *ctx, const char *name)

   create a new exclusion list.

**Parameters**

``struct libnvme_global_ctx *ctx``
  libnvme global context; must not be NULL

``const char *name``
  list name (used as filename: <dir>/<name>.conf)

**Return**

0 on success, -EEXIST if the list already exists, negative errno otherwise.


.. c:function:: int libnvmf_exclusion_delete (struct libnvme_global_ctx *ctx, const char *name)

   delete an exclusion list.

**Parameters**

``struct libnvme_global_ctx *ctx``
  libnvme global context; must not be NULL

``const char *name``
  list name

**Return**

0 on success, -ENOENT if the list does not exist, negative errno otherwise.


.. c:function:: int libnvmf_exclusion_add (struct libnvme_global_ctx *ctx, const char *name, const char *entry)

   append an entry to a named list (atomic write).

**Parameters**

``struct libnvme_global_ctx *ctx``
  libnvme global context; must not be NULL

``const char *name``
  list name

``const char *entry``
  semicolon-separated key=value string (e.g. "transport=tcp;traddr=192.168.1.1")

**Description**

Creates the list if it does not exist.  Validates the entry for unknown keys
before writing; returns -EINVAL if the entry is invalid.

**Return**

0 on success, negative errno otherwise.


.. c:function:: int libnvmf_exclusion_add_ctrl (struct libnvme_global_ctx *ctx, const char *name, struct libnvme_ctrl *c)

   append an entry built from a controller.

**Parameters**

``struct libnvme_global_ctx *ctx``
  libnvme global context; must not be NULL

``const char *name``
  list name

``struct libnvme_ctrl *c``
  connected controller; the entry's transport, traddr, trsvcid,
  subsysnqn and (when set) host-iface are taken from it

**Description**

Builds the exclusion entry from the controller's transport parameters inside
libnvme -- the caller needs no knowledge of the on-disk entry format -- then
appends it via libnvmf_exclusion_add().  Creates the list if it does not
exist.

**Return**

0 on success, -EINVAL if **ctx** or **c** is NULL or the controller lacks
        a transport/traddr/subsysnqn, negative errno otherwise.


.. c:function:: int libnvmf_exclusion_add_subsysnqn (struct libnvme_global_ctx *ctx, const char *name, const char *subsysnqn)

   append a subsystem-NQN-only entry.

**Parameters**

``struct libnvme_global_ctx *ctx``
  libnvme global context; must not be NULL

``const char *name``
  list name

``const char *subsysnqn``
  subsystem NQN to exclude; must not be NULL or empty

**Description**

Builds an exclusion entry matching every controller of a subsystem (the
entry constrains only the NQN) inside libnvme -- the caller needs no
knowledge of the on-disk entry format -- then appends it via
libnvmf_exclusion_add().  Creates the list if it does not exist.

**Return**

0 on success, -EINVAL if **ctx** or **subsysnqn** is NULL/empty,
        negative errno otherwise.


.. c:function:: int libnvmf_exclusion_remove (struct libnvme_global_ctx *ctx, const char *name, const char *entry)

   remove an entry by exact content match (atomic write).

**Parameters**

``struct libnvme_global_ctx *ctx``
  libnvme global context; must not be NULL

``const char *name``
  list name

``const char *entry``
  entry string to remove, exactly as returned by
  libnvmf_exclusion_entry_for_each() (e.g. "transport=tcp;traddr=192.168.1.1")

**Return**

0 on success, -ENOENT if the entry or list does not exist, negative errno otherwise.


.. c:function:: int libnvmf_exclusion_read (struct libnvme_global_ctx *ctx, const char *name, char **text, uint64_t *version)

   read a list's raw text and a concurrency token.

**Parameters**

``struct libnvme_global_ctx *ctx``
  libnvme global context; must not be NULL

``const char *name``
  list name

``char **text``
  on success, set to the file's full contents as a newly allocated,
  NUL-terminated string (caller frees).  A missing list reads as an
  empty string so an editor can create it.

``uint64_t *version``
  on success, set to an opaque token identifying the contents read.
  0 means the list did not exist.  Pass it back to
  libnvmf_exclusion_write() to detect concurrent modification.

**Description**

Intended for read-modify-write editors: read the raw text, let a human edit
it, then write it back.  The directory location is entirely libnvme's
concern -- the caller works only in terms of list names.

**Return**

0 on success, -EINVAL for a bad name or NULL out-param, negative
        errno otherwise.


.. c:function:: int libnvmf_exclusion_write (struct libnvme_global_ctx *ctx, const char *name, const char *text, uint64_t version)

   atomically replace a list's contents.

**Parameters**

``struct libnvme_global_ctx *ctx``
  libnvme global context; must not be NULL

``const char *name``
  list name

``const char *text``
  full replacement contents (every "exclusion = ..." line is
  validated and must sit inside the [exclusions] section;
  invalid entries cause -EINVAL and no write)

``uint64_t version``
  token from a prior libnvmf_exclusion_read().  The write proceeds
  only if the on-disk list still matches **version**; otherwise it
  returns -ESTALE and leaves the file untouched, so a concurrent
  editor's changes are never silently overwritten.

**Description**

The replacement is installed atomically (temp file + rename) with mode 0644.

**Return**

0 on success, -ESTALE if the list changed since **version** was read,
        -EINVAL for an invalid entry or name, negative errno otherwise.


