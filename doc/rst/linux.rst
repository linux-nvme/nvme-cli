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




.. c:enum:: nvme_telemetry_da

   Telemetry Log Data Area

**Constants**

``NVME_TELEMETRY_DA_1``
  Data Area 1

``NVME_TELEMETRY_DA_2``
  Data Area 2

``NVME_TELEMETRY_DA_3``
  Data Area 3

``NVME_TELEMETRY_DA_4``
  Data Area 4


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


