.. _sed.h - TCG Storage (Self-Encrypting Drive) support:

**sed.h - TCG Storage (Self-Encrypting Drive) support**


.. c:macro:: LIBNVME_SED_KEY_MAX

``LIBNVME_SED_KEY_MAX ()``

   Maximum size of a SED key

**Parameters**




.. c:enum:: libnvme_sed_key_type

   Source of a SED key

**Constants**

``LIBNVME_SED_KEY_INCLUDED``
  The key is stored in :c:type:`struct libnvme_sed_key <libnvme_sed_key>`

``LIBNVME_SED_KEY_KEYRING``
  The kernel looks up the key in its keyring




.. c:struct:: libnvme_sed_key

   SED key (password or PSID)

**Definition**

::

  struct libnvme_sed_key {
    __u8 type;
    __u8 len;
    __u8 key[LIBNVME_SED_KEY_MAX];
  };

**Members**

``type``
  Key source, see :c:type:`enum libnvme_sed_key_type <libnvme_sed_key_type>`

``len``
  Length of **key** in bytes, ignored for
  ``LIBNVME_SED_KEY_KEYRING``

``key``
  Key data





.. c:enum:: libnvme_sed_lock_state

   Locking range lock state

**Constants**

``LIBNVME_SED_LOCK_RO``
  Read-only, writes are locked

``LIBNVME_SED_LOCK_RW``
  Read-write, the range is unlocked

``LIBNVME_SED_LOCK_LK``
  Reads and writes are locked


.. c:function:: int libnvme_sed_discover (struct libnvme_transport_handle *hdl, void *buf, __u32 len)

   Retrieve the TCG Level 0 Discovery data

**Parameters**

``struct libnvme_transport_handle *hdl``
  Transport handle

``void *buf``
  Buffer for the Level 0 Discovery data

``__u32 len``
  Size of **buf** in bytes

**Description**

Issues a Security Receive for the Level 0 Discovery ComID. The data
is returned unparsed; use libnvme_sed_l0_for_each() or
libnvme_sed_l0_find() to walk the feature descriptors.

**Return**

0 on success, the NVMe command status if a response was
received (see :c:type:`enum nvme_status_field <nvme_status_field>`) or a negative error code
otherwise.


.. c:function:: struct tcg_l0_desc * libnvme_sed_l0_next (void *buf, size_t len, struct tcg_l0_desc *desc)

   Return the next Level 0 Discovery descriptor

**Parameters**

``void *buf``
  Level 0 Discovery data

``size_t len``
  Size of **buf** in bytes

``struct tcg_l0_desc *desc``
  Current descriptor, or NULL to get the first descriptor

**Description**

The walk ends at the length reported in the header or at the end of
**buf**, whichever comes first. A descriptor which does not fit
completely ends the walk.

**Return**

Pointer to the next descriptor, or NULL if there is none.


.. c:function:: struct tcg_l0_desc * libnvme_sed_l0_find (void *buf, size_t len, __u16 code)

   Find a Level 0 Discovery descriptor

**Parameters**

``void *buf``
  Level 0 Discovery data

``size_t len``
  Size of **buf** in bytes

``__u16 code``
  Feature code, see :c:type:`enum tcg_l0_code <tcg_l0_code>`

**Return**

Pointer to the first descriptor with feature code **code**, or
NULL if there is none.


.. c:macro:: libnvme_sed_l0_for_each

``libnvme_sed_l0_for_each (desc, buf, len)``

   Iterate over Level 0 Discovery descriptors

**Parameters**

``desc``
  :c:type:`struct tcg_l0_desc <tcg_l0_desc>` pointer used as the loop cursor

``buf``
  Level 0 Discovery data

``len``
  Size of **buf** in bytes


.. c:function:: void * libnvme_sed_l0_data (struct tcg_l0_desc *desc)

   Return the feature data of a descriptor

**Parameters**

``struct tcg_l0_desc *desc``
  Level 0 Discovery feature descriptor

**Return**

Pointer to the feature data following the descriptor header.


.. c:function:: int libnvme_sed_take_ownership (struct libnvme_transport_handle *hdl, const struct libnvme_sed_key *key)

   Take ownership of the TPer

**Parameters**

``struct libnvme_transport_handle *hdl``
  Transport handle

``const struct libnvme_sed_key *key``
  New SID password

**Return**

See the return value convention above.


.. c:function:: int libnvme_sed_activate_lsp (struct libnvme_transport_handle *hdl, const struct libnvme_sed_key *key)

   Activate the Locking SP

**Parameters**

``struct libnvme_transport_handle *hdl``
  Transport handle

``const struct libnvme_sed_key *key``
  SID password

**Return**

See the return value convention above.


.. c:function:: int libnvme_sed_setup_range (struct libnvme_transport_handle *hdl, const struct libnvme_sed_key *key, bool read_lock, bool write_lock)

   Configure the global locking range

**Parameters**

``struct libnvme_transport_handle *hdl``
  Transport handle

``const struct libnvme_sed_key *key``
  Admin1 password

``bool read_lock``
  Enable read locking

``bool write_lock``
  Enable write locking

**Return**

See the return value convention above.


.. c:function:: int libnvme_sed_lock_unlock (struct libnvme_transport_handle *hdl, const struct libnvme_sed_key *key, enum libnvme_sed_lock_state state)

   Change the lock state of the global range

**Parameters**

``struct libnvme_transport_handle *hdl``
  Transport handle

``const struct libnvme_sed_key *key``
  Admin1 password

``enum libnvme_sed_lock_state state``
  New lock state, see :c:type:`enum libnvme_sed_lock_state <libnvme_sed_lock_state>`

**Return**

See the return value convention above.


.. c:function:: int libnvme_sed_set_password (struct libnvme_transport_handle *hdl, const struct libnvme_sed_key *key, const struct libnvme_sed_key *new_key)

   Change the Admin1 password

**Parameters**

``struct libnvme_transport_handle *hdl``
  Transport handle

``const struct libnvme_sed_key *key``
  Current Admin1 password

``const struct libnvme_sed_key *new_key``
  New Admin1 password

**Return**

See the return value convention above.


.. c:function:: int libnvme_sed_set_sid_password (struct libnvme_transport_handle *hdl, const struct libnvme_sed_key *key, const struct libnvme_sed_key *new_key)

   Change the SID password

**Parameters**

``struct libnvme_transport_handle *hdl``
  Transport handle

``const struct libnvme_sed_key *key``
  Current SID password

``const struct libnvme_sed_key *new_key``
  New SID password

**Return**

See the return value convention above.


.. c:function:: int libnvme_sed_revert_tper (struct libnvme_transport_handle *hdl, const struct libnvme_sed_key *key)

   Revert the TPer to its factory state

**Parameters**

``struct libnvme_transport_handle *hdl``
  Transport handle

``const struct libnvme_sed_key *key``
  SID password

**Description**

This erases all user data.

**Return**

See the return value convention above.


.. c:function:: int libnvme_sed_revert_psid (struct libnvme_transport_handle *hdl, const struct libnvme_sed_key *psid)

   Revert the TPer using the PSID

**Parameters**

``struct libnvme_transport_handle *hdl``
  Transport handle

``const struct libnvme_sed_key *psid``
  Physical Security ID printed on the drive label

**Description**

This erases all user data.

**Return**

See the return value convention above.


.. c:function:: int libnvme_sed_revert_lsp (struct libnvme_transport_handle *hdl, const struct libnvme_sed_key *key, bool keep_data)

   Revert the Locking SP

**Parameters**

``struct libnvme_transport_handle *hdl``
  Transport handle

``const struct libnvme_sed_key *key``
  Admin1 password

``bool keep_data``
  Preserve the user data

**Return**

See the return value convention above.


