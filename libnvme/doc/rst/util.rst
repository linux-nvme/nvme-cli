.. _util.h:

**util.h**


libnvme utility functions



.. c:enum:: libnvme_connect_err

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

``ENVME_CONNECT_ADDRNOTAVAIL``
  cannot assign requested address

``ENVME_CONNECT_IGNORED``
  connect attempt is ignored due to configuration

``ENVME_CONNECT_NOKEY``
  the TLS key is missing


.. c:function:: __u8 libnvme_status_to_errno (int status, bool fabrics)

   Converts nvme return status to errno

**Parameters**

``int status``
  Return status from an nvme passthrough command

``bool fabrics``
  Set to true if :c:type:`status` is to a fabrics target.

**Return**

An errno representing the nvme status if it is an nvme status field,
or unchanged status is < 0 since errno is already set.


.. c:function:: const char * libnvme_status_to_string (int status, bool fabrics)

   Returns string describing nvme return status.

**Parameters**

``int status``
  Return status from an nvme passthrough command

``bool fabrics``
  Set to true if :c:type:`status` is to a fabrics target.

**Return**

String representation of the nvme status if it is an nvme status field,
or a standard errno string if status is < 0.


.. c:function:: const char * libnvme_sanitize_ns_status_to_string (__u16 sc)

   Returns sanitize ns status string.

**Parameters**

``__u16 sc``
  Return status code from an sanitize ns command

**Return**

The sanitize ns status string if it is a specific status code.


.. c:function:: const char * libnvme_set_features_status_to_string (__u16 sc)

   Returns set features status string.

**Parameters**

``__u16 sc``
  Return status code from an set features command

**Return**

The set features status string if it is a specific status code.


.. c:function:: const char * libnvme_opcode_status_to_string (int status, bool admin, __u8 opcode)

   Returns nvme opcode status string.

**Parameters**

``int status``
  Return status from an nvme passthrough command

``bool admin``
  Set to true if an admin command

``__u8 opcode``
  Opcode from an nvme passthrough command

**Return**

The nvme opcode status string if it is an nvme status field,
or a standard errno string if status is < 0.


.. c:function:: const char * libnvme_errno_to_string (int err)

   Returns string describing nvme connect failures

**Parameters**

``int err``
  Returned error code from libnvme_add_ctrl()

**Return**

String representation of the nvme connect error codes


.. c:function:: const char * libnvme_strerror (int err)

   Returns string describing nvme errors and errno

**Parameters**

``int err``
  Returned error codes from all libnvme functions

**Return**

String representation of either the nvme connect error codes
(positive values) or errno string (negative values)


.. c:function:: struct nvmf_ext_attr * libnvmf_exat_ptr_next (struct nvmf_ext_attr *p)

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




.. c:enum:: libnvme_version

   Selector for version to be returned by **libnvme_get_version**

**Constants**

``LIBNVME_VERSION_PROJECT``
  Project release version

``LIBNVME_VERSION_GIT``
  Git reference


.. c:function:: const char * libnvme_get_version (enum libnvme_version type)

   Return version libnvme string

**Parameters**

``enum libnvme_version type``
  Selects which version type (see **struct** libnvme_version)

**Return**

Returns version string for known types or else "n/a"


.. c:function:: int libnvme_uuid_to_string (unsigned char uuid[NVME_UUID_LEN], char *str)

   Return string represenation of encoded UUID

**Parameters**

``unsigned char uuid[NVME_UUID_LEN]``
  Binary encoded input UUID

``char *str``
  Output string represenation of UUID

**Return**

Returns error code if type conversion fails.


.. c:function:: int libnvme_uuid_from_string (const char *str, unsigned char uuid[NVME_UUID_LEN])

   Return encoded UUID represenation of string UUID

**Parameters**

``const char *str``
  Output string represenation of UUID

``unsigned char uuid[NVME_UUID_LEN]``
  Binary encoded input UUID

**Return**

Returns error code if type conversion fails.


.. c:function:: int libnvme_random_uuid (unsigned char uuid[NVME_UUID_LEN])

   Generate random UUID

**Parameters**

``unsigned char uuid[NVME_UUID_LEN]``
  Generated random UUID

**Description**

Generate random number according
https://www.rfc-editor.org/rfc/rfc4122#section-4.4

**Return**

Returns error code if generating of random number fails.


.. c:function:: int libnvme_find_uuid (struct nvme_id_uuid_list *uuid_list, const unsigned char uuid[NVME_UUID_LEN])

   Find UUID position on UUID list

**Parameters**

``struct nvme_id_uuid_list *uuid_list``
  UUID list returned by identify UUID

``const unsigned char uuid[NVME_UUID_LEN]``
  Binary encoded input UUID

**Return**

The array position where given UUID is present, or -1 on failure
 with errno set.


.. c:function:: char * libnvme_basename (const char *path)

   Return the final path component (the one after the last '/')

**Parameters**

``const char *path``
  A string containing a filesystem path

**Return**

A pointer into the original null-terminated path string.


