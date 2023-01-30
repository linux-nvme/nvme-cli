.. _util.h:

**util.h**


libnvme utility functions



.. c:enum:: nvme_connect_err

   nvme connect error codes

**Constants**

``ENVME_CONNECT_RESOLVE``
  failed to resolve host

``ENVME_CONNECT_ADDRFAM``
  unrecognized address family

``ENVME_CONNECT_TRADDR``
  failed to get traddr

``ENVME_CONNECT_TARG``
  need a transport (-t) argument

``ENVME_CONNECT_AARG``
  need a address (-a) argument

``ENVME_CONNECT_OPEN``
  failed to open nvme-fabrics device

``ENVME_CONNECT_WRITE``
  failed to write to nvme-fabrics device

``ENVME_CONNECT_READ``
  failed to read from nvme-fabrics device

``ENVME_CONNECT_PARSE``
  failed to parse ctrl info

``ENVME_CONNECT_INVAL_TR``
  invalid transport type

``ENVME_CONNECT_LOOKUP_SUBSYS_NAME``
  failed to lookup subsystem name

``ENVME_CONNECT_LOOKUP_SUBSYS``
  failed to lookup subsystem

``ENVME_CONNECT_ALREADY``
  the connect attempt failed, already connected

``ENVME_CONNECT_INVAL``
  invalid arguments/configuration

``ENVME_CONNECT_ADDRINUSE``
  hostnqn already in use

``ENVME_CONNECT_NODEV``
  invalid interface

``ENVME_CONNECT_OPNOTSUPP``
  not supported

``ENVME_CONNECT_CONNREFUSED``
  connection refused


.. c:function:: __u8 nvme_status_to_errno (int status, bool fabrics)

   Converts nvme return status to errno

**Parameters**

``int status``
  Return status from an nvme passthrough command

``bool fabrics``
  Set to true if :c:type:`status` is to a fabrics target.

**Return**

An errno representing the nvme status if it is an nvme status field,
or unchanged status is < 0 since errno is already set.


.. c:function:: const char * nvme_status_to_string (int status, bool fabrics)

   Returns string describing nvme return status.

**Parameters**

``int status``
  Return status from an nvme passthrough command

``bool fabrics``
  Set to true if :c:type:`status` is to a fabrics target.

**Return**

String representation of the nvme status if it is an nvme status field,
or a standard errno string if status is < 0.


.. c:function:: const char * nvme_errno_to_string (int err)

   Returns string describing nvme connect failures

**Parameters**

``int err``
  Returned error code from nvme_add_ctrl()

**Return**

String representation of the nvme connect error codes


.. c:function:: void nvme_init_ctrl_list (struct nvme_ctrl_list *cntlist, __u16 num_ctrls, __u16 *ctrlist)

   Initialize an nvme_ctrl_list structure from an array.

**Parameters**

``struct nvme_ctrl_list *cntlist``
  The controller list structure to initialize

``__u16 num_ctrls``
  The number of controllers in the array, :c:type:`ctrlist`.

``__u16 *ctrlist``
  An array of controller identifiers in CPU native endian.

**Description**

This is intended to be used with any command that takes a controller list
argument. See nvme_ns_attach_ctrls() and nvme_ns_detach().


.. c:function:: void nvme_init_dsm_range (struct nvme_dsm_range *dsm, __u32 *ctx_attrs, __u32 *llbas, __u64 *slbas, __u16 nr_ranges)

   Constructs a data set range structure

**Parameters**

``struct nvme_dsm_range *dsm``
  DSM range array

``__u32 *ctx_attrs``
  Array of context attributes

``__u32 *llbas``
  Array of length in logical blocks

``__u64 *slbas``
  Array of starting logical blocks

``__u16 nr_ranges``
  The size of the dsm arrays

**Description**

Each array must be the same size of size 'nr_ranges'. This is intended to be
used with constructing a payload for nvme_dsm().

**Return**

The nvme command status if a response was received or -errno
otherwise.


.. c:function:: void nvme_init_copy_range (struct nvme_copy_range *copy, __u16 *nlbs, __u64 *slbas, __u32 *eilbrts, __u32 *elbatms, __u32 *elbats, __u16 nr)

   Constructs a copy range structure

**Parameters**

``struct nvme_copy_range *copy``
  Copy range array

``__u16 *nlbs``
  Number of logical blocks

``__u64 *slbas``
  Starting LBA

``__u32 *eilbrts``
  Expected initial logical block reference tag

``__u32 *elbatms``
  Expected logical block application tag mask

``__u32 *elbats``
  Expected logical block application tag

``__u16 nr``
  Number of descriptors to construct


.. c:function:: void nvme_init_copy_range_f1 (struct nvme_copy_range_f1 *copy, __u16 *nlbs, __u64 *slbas, __u64 *eilbrts, __u32 *elbatms, __u32 *elbats, __u16 nr)

   Constructs a copy range f1 structure

**Parameters**

``struct nvme_copy_range_f1 *copy``
  Copy range array

``__u16 *nlbs``
  Number of logical blocks

``__u64 *slbas``
  Starting LBA

``__u64 *eilbrts``
  Expected initial logical block reference tag

``__u32 *elbatms``
  Expected logical block application tag mask

``__u32 *elbats``
  Expected logical block application tag

``__u16 nr``
  Number of descriptors to construct


.. c:function:: int nvme_get_feature_length (int fid, __u32 cdw11, __u32 *len)

   Retreive the command payload length for a specific feature identifier

**Parameters**

``int fid``
  Feature identifier, see :c:type:`enum nvme_features_id <nvme_features_id>`.

``__u32 cdw11``
  The cdw11 value may affect the transfer (only known fid is
  ``NVME_FEAT_FID_HOST_ID``)

``__u32 *len``
  On success, set to this features payload length in bytes.

**Return**

0 on success, -1 with errno set to EINVAL if the function did not
recognize :c:type:`fid`.


.. c:function:: int nvme_get_feature_length2 (int fid, __u32 cdw11, enum nvme_data_tfr dir, __u32 *len)

   Retreive the command payload length for a specific feature identifier

**Parameters**

``int fid``
  Feature identifier, see :c:type:`enum nvme_features_id <nvme_features_id>`.

``__u32 cdw11``
  The cdw11 value may affect the transfer (only known fid is
  ``NVME_FEAT_FID_HOST_ID``)

``enum nvme_data_tfr dir``
  Data transfer direction: false - host to controller, true -
  controller to host may affect the transfer (only known fid is
  ``NVME_FEAT_FID_HOST_MEM_BUF``).

``__u32 *len``
  On success, set to this features payload length in bytes.

**Return**

0 on success, -1 with errno set to EINVAL if the function did not
recognize :c:type:`fid`.


.. c:function:: int nvme_get_directive_receive_length (enum nvme_directive_dtype dtype, enum nvme_directive_receive_doper doper, __u32 *len)

   Get directive receive length

**Parameters**

``enum nvme_directive_dtype dtype``
  Directive type, see :c:type:`enum nvme_directive_dtype <nvme_directive_dtype>`

``enum nvme_directive_receive_doper doper``
  Directive receive operation, see :c:type:`enum nvme_directive_receive_doper <nvme_directive_receive_doper>`

``__u32 *len``
  On success, set to this directives payload length in bytes.

**Return**

0 on success, -1 with errno set to EINVAL if the function did not
recognize :c:type:`dtype` or :c:type:`doper`.


.. c:function:: size_t get_entity_name (char *buffer, size_t bufsz)

   Get Entity Name (ENAME).

**Parameters**

``char *buffer``
  The buffer where the ENAME will be saved as an ASCII string.

``size_t bufsz``
  The size of **buffer**.

**Description**

Per TP8010, ENAME is defined as the name associated with the host (i.e.
hostname).

**Return**

Number of characters copied to **buffer**.


.. c:function:: size_t get_entity_version (char *buffer, size_t bufsz)

   Get Entity Version (EVER).

**Parameters**

``char *buffer``
  The buffer where the EVER will be saved as an ASCII string.

``size_t bufsz``
  The size of **buffer**.

**Description**

EVER is defined as the operating system name and version as an ASCII
string. This function reads different files from the file system and
builds a string as follows: [os type] [os release] [distro release]

    E.g. "Linux 5.17.0-rc1 SLES 15.4"

**Return**

Number of characters copied to **buffer**.


.. c:function:: char * kv_strip (char *kv)

   Strip blanks from key value string

**Parameters**

``char *kv``
  The key-value string to strip

**Description**

Strip leading/trailing blanks as well as trailing comments from the
Key=Value string pointed to by **kv**.

**Return**

A pointer to the stripped string. Note that the original string,
**kv**, gets modified.


.. c:function:: char * kv_keymatch (const char *kv, const char *key)

   Look for key in key value string

**Parameters**

``const char *kv``
  The key=value string to search for the presence of **key**

``const char *key``
  The key to look for

**Description**

Look for **key** in the Key=Value pair pointed to by **k** and return a
pointer to the Value if **key** is found.

Check if **kv** starts with **key**. If it does then make sure that we
have a whole-word match on the **key**, and if we do, return a pointer
to the first character of value (i.e. skip leading spaces, tabs,
and equal sign)

**Return**

A pointer to the first character of "value" if a match is found.
NULL otherwise.


.. c:function:: char * startswith (const char *s, const char *prefix)

   Checks that a string starts with a given prefix.

**Parameters**

``const char *s``
  The string to check

``const char *prefix``
  A string that **s** could be starting with

**Return**

If **s** starts with **prefix**, then return a pointer within **s** at
the first character after the matched **prefix**. NULL otherwise.


.. c:macro:: round_up

``round_up (val, mult)``

   Round a value **val** to the next multiple specified by **mult**.

**Parameters**

``val``
  Value to round

``mult``
  Multiple to round to.

**Description**

usage: int x = round_up(13, sizeof(__u32)); // 13 -> 16


.. c:function:: __u16 nvmf_exat_len (size_t val_len)

   Return length rounded up by 4

**Parameters**

``size_t val_len``
  Value length

**Description**

Return the size in bytes, rounded to a multiple of 4 (e.g., size of
__u32), of the buffer needed to hold the exat value of size
**val_len**.

**Return**

Length rounded up by 4


.. c:function:: __u16 nvmf_exat_size (size_t val_len)

   Return min aligned size to hold value

**Parameters**

``size_t val_len``
  This is the length of the data to be copied to the "exatval"
  field of a "struct nvmf_ext_attr".

**Description**

Return the size of the "struct nvmf_ext_attr" needed to hold
a value of size **val_len**.

**Return**

The size in bytes, rounded to a multiple of 4 (i.e. size of
__u32), of the "struct nvmf_ext_attr" required to hold a string of
length **val_len**.


.. c:function:: struct nvmf_ext_attr * nvmf_exat_ptr_next (struct nvmf_ext_attr *p)

   Increment **p** to the next element in the array.

**Parameters**

``struct nvmf_ext_attr *p``
  Pointer to an element of an array of "struct nvmf_ext_attr".

**Description**

Extended attributes are saved to an array of "struct nvmf_ext_attr"
where each element of the array is of variable size. In order to
move to the next element in the array one must increment the
pointer to the current element (**p**) by the size of the current
element.

**Return**

Pointer to the next element in the array.




.. c:enum:: nvme_version

   Selector for version to be returned by **nvme_get_version**

**Constants**

``NVME_VERSION_PROJECT``
  Project release version

``NVME_VERSION_GIT``
  Git reference


.. c:function:: const char * nvme_get_version (enum nvme_version type)

   Return version libnvme string

**Parameters**

``enum nvme_version type``
  Selects which version type (see **struct** nvme_version)

**Return**

Returns version string for known types or else "n/a"


.. c:function:: int nvme_uuid_to_string (unsigned char uuid[NVME_UUID_LEN], char *str)

   Return string represenation of encoded UUID

**Parameters**

``unsigned char uuid[NVME_UUID_LEN]``
  Binary encoded input UUID

``char *str``
  Output string represenation of UUID

**Return**

Returns error code if type conversion fails.


.. c:function:: int nvme_uuid_from_string (const char *str, unsigned char uuid[NVME_UUID_LEN])

   Return encoded UUID represenation of string UUID

**Parameters**

``const char *str``
  Output string represenation of UUID

``unsigned char uuid[NVME_UUID_LEN]``
  Binary encoded input UUID

**Return**

Returns error code if type conversion fails.


.. c:function:: int nvme_uuid_random (unsigned char uuid[NVME_UUID_LEN])

   Generate random UUID

**Parameters**

``unsigned char uuid[NVME_UUID_LEN]``
  Generated random UUID

**Description**

Generate random number according
https://www.rfc-editor.org/rfc/rfc4122#section-4.4

**Return**

Returns error code if generating of random number fails.


