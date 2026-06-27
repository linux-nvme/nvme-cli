.. _nvme-cmds.h:

**nvme-cmds.h**


NVMe command initialization functions. This header includes all
specification-aligned command headers for backward compatibility.

.. c:function:: int libnvme_get_log (struct libnvme_transport_handle *hdl, struct libnvme_passthru_cmd *cmd, bool rae, __u32 xfer_len)

   Get log page data

**Parameters**

``struct libnvme_transport_handle *hdl``
  Transport handle

``struct libnvme_passthru_cmd *cmd``
  Passthru command

``bool rae``
  Retain asynchronous events

``__u32 xfer_len``
  Max log transfer size per request to split the total.

**Return**

0 on success, the nvme command status if a response was
received (see :c:type:`enum nvme_status_field <nvme_status_field>`) or a negative error otherwise.


.. c:function:: int libnvme_get_log_dynamic_chunk (struct libnvme_transport_handle *hdl, struct libnvme_passthru_cmd *cmd, bool rae, __u32 xfer_len)

   Get log page data with dynamic chunk size

**Parameters**

``struct libnvme_transport_handle *hdl``
  Transport handle

``struct libnvme_passthru_cmd *cmd``
  Passthru command

``bool rae``
  Retain asynchronous events

``__u32 xfer_len``
  Initial max log transfer size per request to split the total.
  Dynamically divide chunk size by 2 when any error is encountered,
  and retry until the chunk size is down to 4k or the command
  succeeds. This allows for successful retrieval of log pages that
  may have a smaller maximum transfer size than the controller's
  MDTS value, without requiring the caller to know the optimal
  chunk size in advance.

**Return**

0 on success, the nvme command status if a response was
received (see :c:type:`enum nvme_status_field <nvme_status_field>`) or a negative error otherwise.


.. c:function:: int libnvme_set_etdas (struct libnvme_transport_handle *hdl, bool *changed)

   Set the Extended Telemetry Data Area 4 Supported bit

**Parameters**

``struct libnvme_transport_handle *hdl``
  Transport handle

``bool *changed``
  boolean to indicate whether or not the host
  behavior support feature had been changed

**Return**

The nvme command status if a response was received (see
:c:type:`enum nvme_status_field <nvme_status_field>`) or negative error code otherwise.


.. c:function:: int libnvme_clear_etdas (struct libnvme_transport_handle *hdl, bool *changed)

   Clear the Extended Telemetry Data Area 4 Supported bit

**Parameters**

``struct libnvme_transport_handle *hdl``
  Transport handle

``bool *changed``
  boolean to indicate whether or not the host
  behavior support feature had been changed

**Return**

The nvme command status if a response was received (see
:c:type:`enum nvme_status_field <nvme_status_field>`) or negative error code otherwise.


.. c:function:: int libnvme_get_uuid_list (struct libnvme_transport_handle *hdl, struct nvme_id_uuid_list *uuid_list)

   Returns the uuid list (if supported)

**Parameters**

``struct libnvme_transport_handle *hdl``
  Transport handle

``struct nvme_id_uuid_list *uuid_list``
  UUID list returned by identify UUID

**Return**

The nvme command status if a response was received (see
:c:type:`enum nvme_status_field <nvme_status_field>`) or negative error code otherwise.


.. c:function:: int libnvme_get_telemetry_max (struct libnvme_transport_handle *hdl, enum nvme_telemetry_da *da, size_t *max_data_tx)

   Get telemetry limits

**Parameters**

``struct libnvme_transport_handle *hdl``
  Transport handle

``enum nvme_telemetry_da *da``
  On success return max supported data area

``size_t *max_data_tx``
  On success set to max transfer chunk supported by
  the controller

**Return**

0 on success, the nvme command status if a response was
received (see :c:type:`enum nvme_status_field <nvme_status_field>`) or a negative error otherwise.


.. c:function:: int libnvme_get_telemetry_log (struct libnvme_transport_handle *hdl, bool create, bool ctrl, bool rae, size_t max_data_tx, enum nvme_telemetry_da da, struct nvme_telemetry_log **log, size_t *size)

   Get specified telemetry log

**Parameters**

``struct libnvme_transport_handle *hdl``
  Transport handle

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

0 on success, the nvme command status if a response was
received (see :c:type:`enum nvme_status_field <nvme_status_field>`) or a negative error otherwise.


.. c:function:: int libnvme_get_ctrl_telemetry (struct libnvme_transport_handle *hdl, bool rae, struct nvme_telemetry_log **log, enum nvme_telemetry_da da, size_t *size)

   Get controller telemetry log

**Parameters**

``struct libnvme_transport_handle *hdl``
  Transport handle

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

0 on success, the nvme command status if a response was
received (see :c:type:`enum nvme_status_field <nvme_status_field>`) or a negative error otherwise.


.. c:function:: int libnvme_get_host_telemetry (struct libnvme_transport_handle *hdl, struct nvme_telemetry_log **log, enum nvme_telemetry_da da, size_t *size)

   Get host telemetry log

**Parameters**

``struct libnvme_transport_handle *hdl``
  Transport handle

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

0 on success, the nvme command status if a response was
received (see :c:type:`enum nvme_status_field <nvme_status_field>`) or a negative error otherwise.


.. c:function:: int libnvme_get_new_host_telemetry (struct libnvme_transport_handle *hdl, struct nvme_telemetry_log **log, enum nvme_telemetry_da da, size_t *size)

   Get new host telemetry log

**Parameters**

``struct libnvme_transport_handle *hdl``
  Transport handle

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

0 on success, the nvme command status if a response was
received (see :c:type:`enum nvme_status_field <nvme_status_field>`) or a negative error otherwise.


.. c:function:: size_t libnvme_get_ana_log_len_from_id_ctrl (const struct nvme_id_ctrl *id_ctrl, bool rgo)

   Retrieve maximum possible ANA log size

**Parameters**

``const struct nvme_id_ctrl *id_ctrl``
  Controller identify data

``bool rgo``
  If true, return maximum log page size without NSIDs

**Return**

A byte limit on the size of the controller's ANA log page


.. c:function:: int libnvme_get_ana_log_atomic (struct libnvme_transport_handle *hdl, bool rae, bool rgo, struct nvme_ana_log *log, __u32 *len, unsigned int retries)

   Retrieve Asymmetric Namespace Access log page atomically

**Parameters**

``struct libnvme_transport_handle *hdl``
  Transport handle

``bool rae``
  Whether to retain asynchronous events

``bool rgo``
  Whether to retrieve ANA groups only (no NSIDs)

``struct nvme_ana_log *log``
  Pointer to a buffer to receive the ANA log page

``__u32 *len``
  Input: the length of the log page buffer.
  Output: the actual length of the ANA log page.

``unsigned int retries``
  The maximum number of times to retry on log page changes

**Description**

See :c:type:`struct nvme_ana_log <nvme_ana_log>` for the definition of the returned structure.

**Return**

If successful, returns 0 and sets *len to the actual log page length.
If unsuccessful, returns the nvme command status if a response was received
(see :c:type:`enum nvme_status_field <nvme_status_field>`) or negative error code otherwise.
Sets errno = EINVAL if retries == 0.
Sets errno = EAGAIN if unable to read the log page atomically
because chgcnt changed during each of the retries attempts.
Sets errno = ENOSPC if the full log page does not fit in the provided buffer.


.. c:function:: int libnvme_get_ana_log_len (struct libnvme_transport_handle *hdl, size_t *analen)

   Retrieve size of the current ANA log

**Parameters**

``struct libnvme_transport_handle *hdl``
  Transport handle

``size_t *analen``
  Pointer to where the length will be set on success

**Return**

0 on success, the nvme command status if a response was
received (see :c:type:`enum nvme_status_field <nvme_status_field>`) or a negative error otherwise.


.. c:function:: int libnvme_get_logical_block_size (struct libnvme_transport_handle *hdl, __u32 nsid, int *blksize)

   Retrieve block size

**Parameters**

``struct libnvme_transport_handle *hdl``
  Transport handle

``__u32 nsid``
  Namespace id

``int *blksize``
  Pointer to where the block size will be set on success

**Return**

0 on success, the nvme command status if a response was
received (see :c:type:`enum nvme_status_field <nvme_status_field>`) or a negative error otherwise.


.. c:function:: int libnvme_get_lba_status_log (struct libnvme_transport_handle *hdl, bool rae, struct nvme_lba_status_log **log)

   Retrieve the LBA Status log page

**Parameters**

``struct libnvme_transport_handle *hdl``
  Transport handle

``bool rae``
  Retain asynchronous events

``struct nvme_lba_status_log **log``
  On success, set to the value of the allocated and retrieved log.

**Return**

0 on success, the nvme command status if a response was
received (see :c:type:`enum nvme_status_field <nvme_status_field>`) or a negative error otherwise.


.. c:function:: int libnvme_get_feature_length (int fid, __u32 cdw11, enum nvme_data_tfr dir, __u32 *len)

   Retrieve the command payload length for a specific feature identifier

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


.. c:function:: int libnvme_get_directive_receive_length (enum nvme_directive_dtype dtype, enum nvme_directive_receive_doper doper, __u32 *len)

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


