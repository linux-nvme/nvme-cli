/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * This file is part of libnvme.
 * Copyright (c) 2020 Western Digital Corporation or its affiliates.
 *
 * Authors: Keith Busch <keith.busch@wdc.com>
 *	    Chaitanya Kulkarni <chaitanya.kulkarni@wdc.com>
 *	    Daniel Wagner <dwagner@suse.de>
 */

#pragma once

/**
 * DOC: nvme-cmds.h
 *
 * NVMe command initialization functions. This header includes all
 * specification-aligned command headers for backward compatibility.
 */

#include <nvme/ioctl.h>
#include <nvme/nvme-types.h>
#include <nvme/nvme-cmds-base.h>
#include <nvme/nvme-cmds-fabrics.h>
#include <nvme/nvme-cmds-mi.h>
#include <nvme/nvme-cmds-nvm.h>
#include <nvme/nvme-cmds-zns.h>

#define NVME_FIELD_ENCODE(value, shift, mask) \
	(((__u32)(value) & (mask)) << (shift))

#define NVME_FIELD_DECODE(value, shift, mask) \
	(((value) >> (shift)) & (mask))


/**
 * libnvme_get_log() - Get log page data
 * @hdl:	Transport handle
 * @cmd:	Passthru command
 * @rae:	Retain asynchronous events
 * @xfer_len:	Max log transfer size per request to split the total.
 *
 * Return: 0 on success, the nvme command status if a response was
 * received (see &enum nvme_status_field) or a negative error otherwise.
 */
int libnvme_get_log(struct libnvme_transport_handle *hdl,
		struct libnvme_passthru_cmd *cmd, bool rae,
		 __u32 xfer_len);

/**
 * libnvme_get_log_dynamic_chunk() - Get log page data with dynamic chunk size
 * @hdl:	Transport handle
 * @cmd:	Passthru command
 * @rae:	Retain asynchronous events
 * @xfer_len:	Initial max log transfer size per request to split the total.
 *	 Dynamically divide chunk size by 2 when any error is encountered,
 *	 and retry until the chunk size is down to 4k or the command
 *	 succeeds. This allows for successful retrieval of log pages that
 *	 may have a smaller maximum transfer size than the controller's
 *	 MDTS value, without requiring the caller to know the optimal
 *	 chunk size in advance.
 *
 * Return: 0 on success, the nvme command status if a response was
 * received (see &enum nvme_status_field) or a negative error otherwise.
 */
int libnvme_get_log_dynamic_chunk(struct libnvme_transport_handle *hdl,
		struct libnvme_passthru_cmd *cmd, bool rae,
		__u32 xfer_len);

/**
 * libnvme_set_etdas() - Set the Extended Telemetry Data Area 4 Supported bit
 * @hdl:	Transport handle
 * @changed:	boolean to indicate whether or not the host
 *		behavior support feature had been changed
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or negative error code otherwise.
 */
int libnvme_set_etdas(struct libnvme_transport_handle *hdl, bool *changed);

/**
 * libnvme_clear_etdas() - Clear the Extended Telemetry Data Area 4
 * Supported bit
 * @hdl:	Transport handle
 * @changed:	boolean to indicate whether or not the host
 *		behavior support feature had been changed
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or negative error code otherwise.
 */
int libnvme_clear_etdas(struct libnvme_transport_handle *hdl, bool *changed);

/**
 * libnvme_get_uuid_list - Returns the uuid list (if supported)
 * @hdl:	Transport handle
 * @uuid_list:	UUID list returned by identify UUID
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or negative error code otherwise.
 */
int libnvme_get_uuid_list(struct libnvme_transport_handle *hdl,
		struct nvme_id_uuid_list *uuid_list);

/**
 * libnvme_get_telemetry_max() - Get telemetry limits
 * @hdl:	Transport handle
 * @da:		On success return max supported data area
 * @max_data_tx: On success set to max transfer chunk supported by
 *		the controller
 *
 * Return: 0 on success, the nvme command status if a response was
 * received (see &enum nvme_status_field) or a negative error otherwise.
 */
int libnvme_get_telemetry_max(struct libnvme_transport_handle *hdl,
		enum nvme_telemetry_da *da, size_t *max_data_tx);

/**
 * libnvme_get_telemetry_log() - Get specified telemetry log
 * @hdl:	Transport handle
 * @create:	Generate new host initated telemetry capture
 * @ctrl:	Get controller Initiated log
 * @rae:	Retain asynchronous events
 * @max_data_tx: Set the max data transfer size to be used retrieving telemetry.
 * @da:		Log page data area, valid values: &enum nvme_telemetry_da.
 * @log:	On success, set to the value of the allocated and retrieved log.
 * @size:	Ptr to the telemetry log size, so it can be returned
 *
 * The total size allocated can be calculated as:
 *   (nvme_telemetry_log da size  + 1) * NVME_LOG_TELEM_BLOCK_SIZE.
 *
 * Return: 0 on success, the nvme command status if a response was
 * received (see &enum nvme_status_field) or a negative error otherwise.
 */
int libnvme_get_telemetry_log(struct libnvme_transport_handle *hdl, bool create,
		bool ctrl, bool rae, size_t max_data_tx,
		enum nvme_telemetry_da da, struct nvme_telemetry_log **log,
		size_t *size);

/**
 * libnvme_get_ctrl_telemetry() - Get controller telemetry log
 * @hdl:	Transport handle
 * @rae:	Retain asynchronous events
 * @log:	On success, set to the value of the allocated and retrieved log.
 * @da:		Log page data area, valid values: &enum nvme_telemetry_da
 * @size:	Ptr to the telemetry log size, so it can be returned
 *
 * The total size allocated can be calculated as:
 *   (nvme_telemetry_log da size  + 1) * NVME_LOG_TELEM_BLOCK_SIZE.
 *
 * Return: 0 on success, the nvme command status if a response was
 * received (see &enum nvme_status_field) or a negative error otherwise.
 */
int libnvme_get_ctrl_telemetry(struct libnvme_transport_handle *hdl, bool rae,
		struct nvme_telemetry_log **log,
		enum nvme_telemetry_da da, size_t *size);

/**
 * libnvme_get_host_telemetry() - Get host telemetry log
 * @hdl:	Transport handle
 * @log:	On success, set to the value of the allocated and retrieved log.
 * @da:		Log page data area, valid values: &enum nvme_telemetry_da
 * @size:	Ptr to the telemetry log size, so it can be returned
 *
 * The total size allocated can be calculated as:
 *   (nvme_telemetry_log da size  + 1) * NVME_LOG_TELEM_BLOCK_SIZE.
 *
 * Return: 0 on success, the nvme command status if a response was
 * received (see &enum nvme_status_field) or a negative error otherwise.
 */
int libnvme_get_host_telemetry(struct libnvme_transport_handle *hdl,
		struct nvme_telemetry_log **log,
		enum nvme_telemetry_da da, size_t *size);

/**
 * libnvme_get_new_host_telemetry() - Get new host telemetry log
 * @hdl:	Transport handle
 * @log:	On success, set to the value of the allocated and retrieved log.
 * @da:		Log page data area, valid values: &enum nvme_telemetry_da
 * @size:	Ptr to the telemetry log size, so it can be returned
 *
 * The total size allocated can be calculated as:
 *   (nvme_telemetry_log da size  + 1) * NVME_LOG_TELEM_BLOCK_SIZE.
 *
 * Return: 0 on success, the nvme command status if a response was
 * received (see &enum nvme_status_field) or a negative error otherwise.
 */
int libnvme_get_new_host_telemetry(struct libnvme_transport_handle *hdl,
		struct nvme_telemetry_log **log,
		enum nvme_telemetry_da da, size_t *size);

/**
 * libnvme_get_ana_log_len_from_id_ctrl() - Retrieve maximum possible
 * ANA log size
 * @id_ctrl:	Controller identify data
 * @rgo:	If true, return maximum log page size without NSIDs
 *
 * Return: A byte limit on the size of the controller's ANA log page
 */
size_t libnvme_get_ana_log_len_from_id_ctrl(const struct nvme_id_ctrl *id_ctrl,
		bool rgo);

/**
 * libnvme_get_ana_log_atomic() - Retrieve Asymmetric Namespace Access
 * log page atomically
 * @hdl:	Transport handle
 * @rae:	Whether to retain asynchronous events
 * @rgo:	Whether to retrieve ANA groups only (no NSIDs)
 * @log:	Pointer to a buffer to receive the ANA log page
 * @len:	Input: the length of the log page buffer.
 *		Output: the actual length of the ANA log page.
 * @retries:	The maximum number of times to retry on log page changes
 *
 * See &struct nvme_ana_log for the definition of the returned structure.
 *
 * Return: If successful, returns 0 and sets *len to the actual log page length.
 * If unsuccessful, returns the nvme command status if a response was received
 * (see &enum nvme_status_field) or negative error code otherwise.
 * Sets errno = EINVAL if retries == 0.
 * Sets errno = EAGAIN if unable to read the log page atomically
 * because chgcnt changed during each of the retries attempts.
 * Sets errno = ENOSPC if the full log page does not fit in the provided buffer.
 */
int
libnvme_get_ana_log_atomic(struct libnvme_transport_handle *hdl, bool rae,
		bool rgo, struct nvme_ana_log *log, __u32 *len,
		unsigned int retries);

/**
 * libnvme_get_ana_log_len() - Retrieve size of the current ANA log
 * @hdl:	Transport handle
 * @analen:	Pointer to where the length will be set on success
 *
 * Return: 0 on success, the nvme command status if a response was
 * received (see &enum nvme_status_field) or a negative error otherwise.
 */
int libnvme_get_ana_log_len(struct libnvme_transport_handle *hdl,
		size_t *analen);

/**
 * libnvme_get_logical_block_size() - Retrieve block size
 * @hdl:	Transport handle
 * @nsid:	Namespace id
 * @blksize:	Pointer to where the block size will be set on success
 *
 * Return: 0 on success, the nvme command status if a response was
 * received (see &enum nvme_status_field) or a negative error otherwise.
 */
int libnvme_get_logical_block_size(struct libnvme_transport_handle *hdl,
		__u32 nsid, int *blksize);

/**
 * libnvme_get_lba_status_log() - Retrieve the LBA Status log page
 * @hdl:	Transport handle
 * @rae:	Retain asynchronous events
 * @log:	On success, set to the value of the allocated and retrieved log.
 *
 * Return: 0 on success, the nvme command status if a response was
 * received (see &enum nvme_status_field) or a negative error otherwise.
 */
int libnvme_get_lba_status_log(struct libnvme_transport_handle *hdl, bool rae,
		struct nvme_lba_status_log **log);

/**
 * libnvme_get_feature_length() - Retrieve the command payload length for a
 *			       specific feature identifier
 * @fid:   Feature identifier, see &enum nvme_features_id.
 * @cdw11: The cdw11 value may affect the transfer (only known fid is
 *	   %NVME_FEAT_FID_HOST_ID)
 * @dir:   Data transfer direction: false - host to controller, true -
 *	   controller to host may affect the transfer (only known fid is
 *	   %NVME_FEAT_FID_HOST_MEM_BUF).
 * @len:   On success, set to this features payload length in bytes.
 *
 * Return: 0 on success, -1 with errno set to EINVAL if the function did not
 * recognize &fid.
 */
int libnvme_get_feature_length(int fid, __u32 cdw11, enum nvme_data_tfr dir,
			    __u32 *len);

/**
 * libnvme_get_directive_receive_length() - Get directive receive length
 * @dtype: Directive type, see &enum nvme_directive_dtype
 * @doper: Directive receive operation, see &enum nvme_directive_receive_doper
 * @len:   On success, set to this directives payload length in bytes.
 *
 * Return: 0 on success, -1 with errno set to EINVAL if the function did not
 * recognize &dtype or &doper.
 */
int libnvme_get_directive_receive_length(enum nvme_directive_dtype dtype,
		enum nvme_directive_receive_doper doper, __u32 *len);
