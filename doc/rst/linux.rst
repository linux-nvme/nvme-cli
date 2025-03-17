.. _linux.h:

**linux.h**


linux-specific utility functions

.. c:function:: int nvme_fw_download_seq (int fd, __u32 size, __u32 xfer, __u32 offset, void *buf)

   Firmware download sequence

**Parameters**

``int fd``
  File descriptor of nvme device

``__u32 size``
  Total size of the firmware image to transfer

``__u32 xfer``
  Maximum size to send with each partial transfer

``__u32 offset``
  Starting offset to send with this firmware download

``void *buf``
  Address of buffer containing all or part of the firmware image.

**Return**

The nvme command status if a response was received (see
:c:type:`enum nvme_status_field <nvme_status_field>`) or -1 with errno set otherwise.


.. c:function:: int nvme_get_telemetry_max (int fd, enum nvme_telemetry_da *da, size_t *max_data_tx)

   Get telemetry limits

**Parameters**

``int fd``
  File descriptor of nvme device

``enum nvme_telemetry_da *da``
  On success return max supported data area

``size_t *max_data_tx``
  On success set to max transfer chunk supported by the controller

**Return**

The nvme command status if a response was received (see
:c:type:`enum nvme_status_field <nvme_status_field>`) or -1 with errno set otherwise.


.. c:function:: int nvme_get_telemetry_log (int fd, bool create, bool ctrl, bool rae, size_t max_data_tx, enum nvme_telemetry_da da, struct nvme_telemetry_log **log, size_t *size)

   Get specified telemetry log

**Parameters**

``int fd``
  File descriptor of nvme device

``bool create``
  Generate new host initated telemetry capture

``bool ctrl``
  Get controller Initiated log

``bool rae``
  Retain asynchronous events

``size_t max_data_tx``
  Set the max data transfer size to be used retrieving telemetry.

``enum nvme_telemetry_da da``
  Log page data area, valid values: :c:type:`enum nvme_telemetry_da <nvme_telemetry_da>`.

``struct nvme_telemetry_log **log``
  On success, set to the value of the allocated and retrieved log.

``size_t *size``
  Ptr to the telemetry log size, so it can be returned

**Description**

The total size allocated can be calculated as:
  (nvme_telemetry_log da size  + 1) * NVME_LOG_TELEM_BLOCK_SIZE.

**Return**

The nvme command status if a response was received (see
:c:type:`enum nvme_status_field <nvme_status_field>`) or -1 with errno set otherwise.


.. c:function:: int nvme_get_ctrl_telemetry (int fd, bool rae, struct nvme_telemetry_log **log, enum nvme_telemetry_da da, size_t *size)

   Get controller telemetry log

**Parameters**

``int fd``
  File descriptor of nvme device

``bool rae``
  Retain asynchronous events

``struct nvme_telemetry_log **log``
  On success, set to the value of the allocated and retrieved log.

``enum nvme_telemetry_da da``
  Log page data area, valid values: :c:type:`enum nvme_telemetry_da <nvme_telemetry_da>`

``size_t *size``
  Ptr to the telemetry log size, so it can be returned

**Description**

The total size allocated can be calculated as:
  (nvme_telemetry_log da size  + 1) * NVME_LOG_TELEM_BLOCK_SIZE.

**Return**

The nvme command status if a response was received (see
:c:type:`enum nvme_status_field <nvme_status_field>`) or -1 with errno set otherwise.


.. c:function:: int nvme_get_host_telemetry (int fd, struct nvme_telemetry_log **log, enum nvme_telemetry_da da, size_t *size)

   Get host telemetry log

**Parameters**

``int fd``
  File descriptor of nvme device

``struct nvme_telemetry_log **log``
  On success, set to the value of the allocated and retrieved log.

``enum nvme_telemetry_da da``
  Log page data area, valid values: :c:type:`enum nvme_telemetry_da <nvme_telemetry_da>`

``size_t *size``
  Ptr to the telemetry log size, so it can be returned

**Description**

The total size allocated can be calculated as:
  (nvme_telemetry_log da size  + 1) * NVME_LOG_TELEM_BLOCK_SIZE.

**Return**

The nvme command status if a response was received (see
:c:type:`enum nvme_status_field <nvme_status_field>`) or -1 with errno set otherwise.


.. c:function:: int nvme_get_new_host_telemetry (int fd, struct nvme_telemetry_log **log, enum nvme_telemetry_da da, size_t *size)

   Get new host telemetry log

**Parameters**

``int fd``
  File descriptor of nvme device

``struct nvme_telemetry_log **log``
  On success, set to the value of the allocated and retrieved log.

``enum nvme_telemetry_da da``
  Log page data area, valid values: :c:type:`enum nvme_telemetry_da <nvme_telemetry_da>`

``size_t *size``
  Ptr to the telemetry log size, so it can be returned

**Description**

The total size allocated can be calculated as:
  (nvme_telemetry_log da size  + 1) * NVME_LOG_TELEM_BLOCK_SIZE.

**Return**

The nvme command status if a response was received (see
:c:type:`enum nvme_status_field <nvme_status_field>`) or -1 with errno set otherwise.


.. c:function:: size_t nvme_get_ana_log_len_from_id_ctrl (const struct nvme_id_ctrl *id_ctrl, bool rgo)

   Retrieve maximum possible ANA log size

**Parameters**

``const struct nvme_id_ctrl *id_ctrl``
  Controller identify data

``bool rgo``
  If true, return maximum log page size without NSIDs

**Return**

A byte limit on the size of the controller's ANA log page


.. c:function:: int nvme_get_ana_log_len (int fd, size_t *analen)

   Retrieve size of the current ANA log

**Parameters**

``int fd``
  File descriptor of nvme device

``size_t *analen``
  Pointer to where the length will be set on success

**Return**

The nvme command status if a response was received (see
:c:type:`enum nvme_status_field <nvme_status_field>`) or -1 with errno set otherwise.


.. c:function:: int nvme_get_logical_block_size (int fd, __u32 nsid, int *blksize)

   Retrieve block size

**Parameters**

``int fd``
  File descriptor of nvme device

``__u32 nsid``
  Namespace id

``int *blksize``
  Pointer to where the block size will be set on success

**Return**

The nvme command status if a response was received (see
:c:type:`enum nvme_status_field <nvme_status_field>`) or -1 with errno set otherwise.


.. c:function:: int nvme_get_lba_status_log (int fd, bool rae, struct nvme_lba_status_log **log)

   Retrieve the LBA Status log page

**Parameters**

``int fd``
  File descriptor of the nvme device

``bool rae``
  Retain asynchronous events

``struct nvme_lba_status_log **log``
  On success, set to the value of the allocated and retrieved log.

**Return**

The nvme command status if a response was received (see
:c:type:`enum nvme_status_field <nvme_status_field>`) or -1 with errno set otherwise.


.. c:function:: int nvme_namespace_attach_ctrls (int fd, __u32 nsid, __u16 num_ctrls, __u16 *ctrlist)

   Attach namespace to controller(s)

**Parameters**

``int fd``
  File descriptor of nvme device

``__u32 nsid``
  Namespace ID to attach

``__u16 num_ctrls``
  Number of controllers in ctrlist

``__u16 *ctrlist``
  List of controller IDs to perform the attach action

**Return**

The nvme command status if a response was received (see
:c:type:`enum nvme_status_field <nvme_status_field>`) or -1 with errno set otherwise.


.. c:function:: int nvme_namespace_detach_ctrls (int fd, __u32 nsid, __u16 num_ctrls, __u16 *ctrlist)

   Detach namespace from controller(s)

**Parameters**

``int fd``
  File descriptor of nvme device

``__u32 nsid``
  Namespace ID to detach

``__u16 num_ctrls``
  Number of controllers in ctrlist

``__u16 *ctrlist``
  List of controller IDs to perform the detach action

**Return**

The nvme command status if a response was received (see
:c:type:`enum nvme_status_field <nvme_status_field>`) or -1 with errno set otherwise.


.. c:function:: int nvme_open (const char *name)

   Open an nvme controller or namespace device

**Parameters**

``const char *name``
  The basename of the device to open

**Description**

This will look for the handle in /dev/ and validate the name and filetype
match linux conventions.

**Return**

A file descriptor for the device on a successful open, or -1 with
errno set otherwise.




.. c:enum:: nvme_hmac_alg

   HMAC algorithm

**Constants**

``NVME_HMAC_ALG_NONE``
  No HMAC algorithm

``NVME_HMAC_ALG_SHA2_256``
  SHA2-256

``NVME_HMAC_ALG_SHA2_384``
  SHA2-384

``NVME_HMAC_ALG_SHA2_512``
  SHA2-512


.. c:function:: int nvme_gen_dhchap_key (char *hostnqn, enum nvme_hmac_alg hmac, unsigned int key_len, unsigned char *secret, unsigned char *key)

   DH-HMAC-CHAP key generation

**Parameters**

``char *hostnqn``
  Host NVMe Qualified Name

``enum nvme_hmac_alg hmac``
  HMAC algorithm

``unsigned int key_len``
  Output key length

``unsigned char *secret``
  Secret to used for digest

``unsigned char *key``
  Generated DH-HMAC-CHAP key

**Return**

If key generation was successful the function returns 0 or
-1 with errno set otherwise.


.. c:function:: long nvme_lookup_keyring (const char *keyring)

   Lookup keyring serial number

**Parameters**

``const char *keyring``
  Keyring name

**Description**

Looks up the serial number of the keyring **keyring**.

**Return**

The key serial number of the keyring
or 0 with errno set otherwise.


.. c:function:: char * nvme_describe_key_serial (long key_id)

   Return key description

**Parameters**

``long key_id``
  Key serial number

**Description**

Fetches the description of the key or keyring identified
by the serial number **key_id**.

**Return**

The description of **key_id** or NULL on failure.
The returned string needs to be freed by the caller.


.. c:function:: long nvme_lookup_key (const char *type, const char *identity)

   Lookup key serial number

**Parameters**

``const char *type``
  Key type

``const char *identity``
  Key description

**Description**

Looks up the serial number of the key **identity**
with type ``type`` in the current session keyring.

**Return**

The key serial number of the key
or 0 with errno set otherwise.


.. c:function:: int nvme_set_keyring (long keyring_id)

   Link keyring for lookup

**Parameters**

``long keyring_id``
  Keyring id

**Description**

Links **keyring_id** into the session keyring such that
its keys are available for further key lookups.

**Return**

0 on success, a negative number on error
with errno set.


.. c:function:: unsigned char * nvme_read_key (long keyring_id, long key_id, int *len)

   Read key raw data

**Parameters**

``long keyring_id``
  Id of the keyring holding ``key_id``

``long key_id``
  Key id

``int *len``
  Length of the returned data

**Description**

Links the keyring specified by **keyring_id** into the session
keyring and reads the payload of the key specified by **key_id**.
**len** holds the size of the returned buffer.
If **keyring** is 0 the default keyring '.nvme' is used.

**Return**

Pointer to the payload on success,
or NULL with errno set otherwise.


.. c:function:: long nvme_update_key (long keyring_id, const char *key_type, const char *identity, unsigned char *key_data, int key_len)

   Update key raw data

**Parameters**

``long keyring_id``
  Id of the keyring holding ``key_id``

``const char *key_type``
  Type of the key to insert

``const char *identity``
  Key identity string

``unsigned char *key_data``
  Raw data of the key

``int key_len``
  Length of **key_data**

**Description**

Links the keyring specified by **keyring_id** into the session
keyring and updates the key reference by **identity** with **key_data**.
The old key with identity **identity** will be revoked to make it
inaccessible.

**Return**

Key id of the new key or 0 with errno set otherwise.


.. c:macro:: nvme_scan_tls_keys_cb_t

   **Typedef**: Callback for iterating TLS keys


**Syntax**

  ``void nvme_scan_tls_keys_cb_t (long keyring, long key, char *desc, int desc_len, void *data)``

**Parameters**

``long keyring``
  Keyring which has been iterated

``long key``
  Key for which the callback has been invoked

``char *desc``
  Description of the key

``int desc_len``
  Length of **desc**

``void *data``
  Pointer for caller data

**Description**

Called for each TLS PSK in the keyring.


.. c:function:: int nvme_scan_tls_keys (const char *keyring, nvme_scan_tls_keys_cb_t cb, void *data)

   Iterate over TLS keys in a keyring

**Parameters**

``const char *keyring``
  Keyring holding TLS keys

``nvme_scan_tls_keys_cb_t cb``
  Callback function

``void *data``
  Pointer for data to be passed to **cb**

**Description**

Iterates **keyring** and call **cb** for each TLS key. When **keyring** is NULL
the default '.nvme' keyring is used.
A TLS key must be of type 'psk' and the description must be of the
form 'NVMe<0|1><R|G>0<1|2> <identity>', otherwise it will be skipped
during iteration.

**Return**

Number of keys for which **cb** was called, or -1 with errno set
on error.


.. c:function:: long nvme_insert_tls_key (const char *keyring, const char *key_type, const char *hostnqn, const char *subsysnqn, int hmac, unsigned char *configured_key, int key_len)

   Derive and insert TLS key

**Parameters**

``const char *keyring``
  Keyring to use

``const char *key_type``
  Type of the resulting key

``const char *hostnqn``
  Host NVMe Qualified Name

``const char *subsysnqn``
  Subsystem NVMe Qualified Name

``int hmac``
  HMAC algorithm

``unsigned char *configured_key``
  Configured key data to derive the key from

``int key_len``
  Length of **configured_key**

**Description**

Derives a 'retained' TLS key as specified in NVMe TCP 1.0a and
stores it as type **key_type** in the keyring specified by **keyring**.

**Return**

The key serial number if the key could be inserted into
the keyring or 0 with errno otherwise.


.. c:function:: long nvme_insert_tls_key_versioned (const char *keyring, const char *key_type, const char *hostnqn, const char *subsysnqn, int version, int hmac, unsigned char *configured_key, int key_len)

   Derive and insert TLS key

**Parameters**

``const char *keyring``
  Keyring to use

``const char *key_type``
  Type of the resulting key

``const char *hostnqn``
  Host NVMe Qualified Name

``const char *subsysnqn``
  Subsystem NVMe Qualified Name

``int version``
  Key version to use

``int hmac``
  HMAC algorithm

``unsigned char *configured_key``
  Configured key data to derive the key from

``int key_len``
  Length of **configured_key**

**Description**

Derives a 'retained' TLS key as specified in NVMe TCP 1.0a (if
**version** s set to '0') or NVMe TP8028 (if **version** is set to '1) and
stores it as type **key_type** in the keyring specified by **keyring**.

**Return**

The key serial number if the key could be inserted into
the keyring or 0 with errno otherwise.


.. c:function:: char * nvme_generate_tls_key_identity (const char *hostnqn, const char *subsysnqn, int version, int hmac, unsigned char *configured_key, int key_len)

   Generate the TLS key identity

**Parameters**

``const char *hostnqn``
  Host NVMe Qualified Name

``const char *subsysnqn``
  Subsystem NVMe Qualified Name

``int version``
  Key version to use

``int hmac``
  HMAC algorithm

``unsigned char *configured_key``
  Configured key data to derive the key from

``int key_len``
  Length of **configured_key**

**Description**

Derives a 'retained' TLS key as specified in NVMe TCP and
generate the corresponding TLs identity.

**Return**

The string containing the TLS identity. It is the responsibility
of the caller to free the returned string.


.. c:function:: long nvme_revoke_tls_key (const char *keyring, const char *key_type, const char *identity)

   Revoke TLS key from keyring

**Parameters**

``const char *keyring``
  Keyring to use

``const char *key_type``
  Type of the key to revoke

``const char *identity``
  Key identity string

**Return**

0 on success or on failure -1 with errno set.


.. c:function:: char * nvme_export_tls_key (const unsigned char *key_data, int key_len)

   Export a TLS key

**Parameters**

``const unsigned char *key_data``
  Raw data of the key

``int key_len``
  Length of **key_data**

**Description**

Returns **key_data** in the PSK Interchange format as defined in section
3.6.1.5 of the NVMe TCP Transport specification.

**Return**

The string containing the TLS identity or NULL with errno set
on error. It is the responsibility of the caller to free the returned
string.


.. c:function:: char * nvme_export_tls_key_versioned (unsigned char version, unsigned char hmac, const unsigned char *key_data, size_t key_len)

   Export a TLS pre-shared key

**Parameters**

``unsigned char version``
  Indicated the representation of the TLS PSK

``unsigned char hmac``
  HMAC algorithm used to transfor the configured PSK
  in a retained PSK

``const unsigned char *key_data``
  Raw data of the key

``size_t key_len``
  Length of **key_data**

**Description**

Returns **key_data** in the PSK Interchange format as defined in section
3.6.1.5 of the NVMe TCP Transport specification.

**Return**

The string containing the TLS identity or NULL with errno set
on error. It is the responsibility of the caller to free the returned
string.


.. c:function:: unsigned char * nvme_import_tls_key (const char *encoded_key, int *key_len, unsigned int *hmac)

   Import a TLS key

**Parameters**

``const char *encoded_key``
  TLS key in PSK interchange format

``int *key_len``
  Length of the resulting key data

``unsigned int *hmac``
  HMAC algorithm

**Description**

Imports **key_data** in the PSK Interchange format as defined in section
3.6.1.5 of the NVMe TCP Transport specification.

**Return**

The raw data of the PSK or NULL with errno set on error. It is
the responsibility of the caller to free the returned string.


.. c:function:: unsigned char * nvme_import_tls_key_versioned (const char *encoded_key, unsigned char *version, unsigned char *hmac, size_t *key_len)

   Import a TLS key

**Parameters**

``const char *encoded_key``
  TLS key in PSK interchange format

``unsigned char *version``
  Indicated the representation of the TLS PSK

``unsigned char *hmac``
  HMAC algorithm used to transfor the configured
  PSK in a retained PSK

``size_t *key_len``
  Length of the resulting key data

**Description**

Imports **key_data** in the PSK Interchange format as defined in section
3.6.1.5 of the NVMe TCP Transport specification.

**Return**

The raw data of the PSK or NULL with errno set on error. It is
the responsibility of the caller to free the returned string.


.. c:function:: int nvme_submit_passthru (int fd, unsigned long ioctl_cmd, struct nvme_passthru_cmd *cmd, __u32 *result)

   Low level ioctl wrapper for passthru commands

**Parameters**

``int fd``
  File descriptor of the nvme device

``unsigned long ioctl_cmd``
  IOCTL command id

``struct nvme_passthru_cmd *cmd``
  Passhtru command

``__u32 *result``
  Optional field to return the result

**Description**

This is a low level library function which should not be used directly. It is
exposed as weak symbol so that the user application is able to provide their own
implementation of this function with additional debugging or logging code.

**Return**

The value from the ioctl system call (see ioctl documentation)


.. c:function:: int nvme_submit_passthru64 (int fd, unsigned long ioctl_cmd, struct nvme_passthru_cmd64 *cmd, __u64 *result)

   Low level ioctl wrapper for passthru commands

**Parameters**

``int fd``
  File descriptor of the nvme device

``unsigned long ioctl_cmd``
  IOCTL command id

``struct nvme_passthru_cmd64 *cmd``
  Passhtru command

``__u64 *result``
  Optional field to return the result

**Description**

This is a low level library function which should not be used directly. It is
exposed as weak symbol so that the user application is able to provide their own
implementation of this function with additional debugging or logging code.

**Return**

The value from the ioctl system call (see ioctl documentation)


