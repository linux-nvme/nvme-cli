// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libnvme.
 * Copyright (c) 2020 Western Digital Corporation or its affiliates.
 *
 * Authors: Keith Busch <keith.busch@wdc.com>
 * 	    Chaitanya Kulkarni <chaitanya.kulkarni@wdc.com>
 */
#ifndef _LIBNVME_UTIL_H
#define _LIBNVME_UTIL_H

#include "ioctl.h"

/**
 * nvme_status_to_errno() - Converts nvme return status to errno
 * @status:  Return status from an nvme passthrough commmand
 * @fabrics: Set to true if &status is to a fabrics target.
 *
 * Return: An errno representing the nvme status if it is an nvme status field,
 *	   or unchanged status is < 0 since errno is already set.
 */
__u8 nvme_status_to_errno(int status, bool fabrics);

/**
 * nvme_fw_download_seq() -
 * @fd:     File descriptor of nvme device
 * @size:   Total size of the firmware image to transfer
 * @xfer:   Maximum size to send with each partial transfer
 * @offset: Starting offset to send with this firmware downlaod
 * @buf:    Address of buffer containing all or part of the firmware image.
 *
 * Return: The nvme command status if a response was received (see
 * 	   &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_fw_download_seq(int fd, __u32 size, __u32 xfer, __u32 offset,
			 void *buf);

/**
 * nvme_get_ctrl_telemetry() -
 * @fd:	   File descriptor of nvme device
 * @rae:   Retain asynchronous events
 * @log:   On success, set to the value of the allocated and retreived log.
 *
 * The total size allocated can be calculated as:
 *   (&struct nvme_telemetry_log.dalb3 + 1) * %NVME_LOG_TELEM_BLOCK_SIZE.
 *
 * Return: The nvme command status if a response was received (see
 * 	   &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_get_ctrl_telemetry(int fd, bool rae, struct nvme_telemetry_log **log);

/**
 * nvme_get_host_telemetry() -
 * @fd:	 File descriptor of nvme device
 * @log: On success, set to the value of the allocated and retreived log.
 *
 * The total size allocated can be calculated as:
 *   (&struct nvme_telemetry_log.dalb3 + 1) * %NVME_LOG_TELEM_BLOCK_SIZE.
 *
 * Return: The nvme command status if a response was received (see
 * 	   &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_get_host_telemetry(int fd,  struct nvme_telemetry_log **log);

/**
 * nvme_get_new_host_telemetry() -
 * @fd:  File descriptor of nvme device
 * @log: On success, set to the value of the allocated and retreived log.
 *
 * The total size allocated can be calculated as:
 *   (&struct nvme_telemetry_log.dalb3 + 1) * %NVME_LOG_TELEM_BLOCK_SIZE.
 *
 * Return: The nvme command status if a response was received (see
 * 	   &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_get_new_host_telemetry(int fd,  struct nvme_telemetry_log **log);

/**
 * nvme_init_id_ns() - Initialize an Identify Namepsace structure for creation.
 * @ns:	      Address of the Identify Namespace structure to initialize
 * @nsze:     Namespace size
 * @ncap:     namespace capacity
 * @flbas:    formatted logical block size settings
 * @dps:      Data protection settings
 * @nmic:     Namespace sharing capabilities
 * @anagrpid: ANA group identifier
 * @nvmsetid: NVM Set identifer
 *
 * This is intended to be used with a namespace management "create", see
 * &nvme_ns_mgmt_create().
 */
void nvme_init_id_ns(struct nvme_id_ns *ns, __u64 nsze, __u64 ncap, __u8 flbas,
		     __u8 dps, __u8 nmic, __u32 anagrpid, __u16 nvmsetid);

/**
 * nvme_init_ctrl_list() - Initialize an nvme_ctrl_list structure from an array.
 * @cntlist:   The controller list structure to initialize
 * @num_ctrls: The number of controllers in the array, &ctrlist.
 * @ctrlist:   An array of controller identifiers in CPU native endian.
 *
 * This is intended to be used with any command that takes a controller list
 * argument. See &nvme_ns_attach_ctrls() and &nvme_ns_detach().
 */
void nvme_init_ctrl_list(struct nvme_ctrl_list *cntlist, __u16 num_ctrls,
			 __u16 *ctrlist);

/**
 * nvme_init_dsm_range() - Constructs a data set range structure
 * @dsm:	DSM range array
 * @ctx_attrs:	Array of context attributes
 * @llbas:	Array of length in logical blocks
 * @slbas:	Array of starting logical blocks
 * @nr_ranges:	The size of the dsm arrays
 *
 * Each array must be the same size of size 'nr_ranges'. This is intended to be
 * used with constructing a payload for &nvme_dsm().
 *
 * Return: The nvme command status if a response was received or -errno
 * 	   otherwise.
 */
void nvme_init_dsm_range(struct nvme_dsm_range *dsm, __u32 *ctx_attrs,
			  __u32 *llbas, __u64 *slbas, __u16 nr_ranges);

/**
 * __nvme_get_log_page() -
 * @fd:	      File descriptor of nvme device
 * @nsid:     Namespace Identifier, if applicable.
 * @log_id:   Log Identifier, see &enum nvme_cmd_get_log_lid.
 * @rae:      Retain asynchronous events
 * @xfer_len: Max log transfer size per request to split the total.
 * @data_len: Total length of the log to transfer.
 * @data:     User address of at least &data_len to store the log.
 *
 * Return: The nvme command status if a response was received (see
 * 	   &enum nvme_status_field) or -1 with errno set otherwise.
 */
int __nvme_get_log_page(int fd, __u32 nsid, __u8 log_id, bool rae,
			__u32 xfer_len, __u32 data_len, void *data);

/**
 * nvme_get_log_page() -
 * @fd:	      File descriptor of nvme device
 * @nsid:     Namespace Identifier, if applicable.
 * @log_id:   Log Identifier, see &enum nvme_cmd_get_log_lid.
 * @rae:      Retain asynchronous events
 * @data_len: Total length of the log to transfer.
 * @data:     User address of at least &data_len to store the log.
 *
 * Calls __nvme_get_log_page() with a default 4k transfer length, as that is
 * guarnateed by the protocol to be a safe transfer size.
 *
 * Return: The nvme command status if a response was received (see
 * 	   &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_get_log_page(int fd, __u32 nsid, __u8 log_id, bool rae,
		      __u32 data_len, void *data);

/**
 * nvme_get_ana_log_len() - Retreive size of the current ANA log
 * @fd:		File descriptor of nvme device
 * @analen:	Pointer to where the length will be set on success
 *
 * Return: The nvme command status if a response was received (see
 * 	   &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_get_ana_log_len(int fd, size_t *analen);

/**
 * nvme_namespace_attach_ctrls() - Attach namespace to controller(s)
 * @fd:		File descriptor of nvme device
 * @nsid:	Namespace ID to attach
 * @num_ctrls:	Number of controllers in ctrlist
 * @ctrlist:	List of controller IDs to perform the attach action
 *
 * Return: The nvme command status if a response was received (see
 * 	   &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_namespace_attach_ctrls(int fd, __u32 nsid, __u16 num_ctrls, __u16 *ctrlist);

/**
 * nvme_namespace_detach_ctrls() - Detach namespace from controller(s)
 * @fd:		File descriptor of nvme device
 * @nsid:	Namespace ID to detach
 * @num_ctrls:	Number of controllers in ctrlist
 * @ctrlist:	List of controller IDs to perform the detach action
 *
 * Return: The nvme command status if a response was received (see
 * 	   &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_namespace_detach_ctrls(int fd, __u32 nsid, __u16 num_ctrls, __u16 *ctrlist);

/**
 * nvme_get_feature_length() - Retreive the command payload length for a
 * 			       specific feature identifier
 * @fid:   Feature identifier, see &enum nvme_features_id.
 * @cdw11: The cdw11 value may affect the transfer (only known fid is
 * 	   %NVME_FEAT_FID_HOST_ID)
 * @len:   On success, set to this features payload length in bytes.
 *
 * Return: 0 on success, -1 with errno set to EINVAL if the function did not
 * 	   recognize &fid.
 */
int nvme_get_feature_length(int fid, __u32 cdw11, __u32 *len);

/**
 * nvme_get_directive_receive_length() -
 * @dtype: Directive type, see &enum nvme_directive_dtype
 * @doper: Directive receive operation, see &enum nvme_directive_receive_doper
 * @len:   On success, set to this directives payload length in bytes.
 *
 * Return: 0 on success, -1 with errno set to EINVAL if the function did not
 * 	   recognize &dtype or &doper.
 */
int nvme_get_directive_receive_length(enum nvme_directive_dtype dtype,
		enum nvme_directive_receive_doper doper, __u32 *len);

/**
 * nvme_open() - Open an nvme controller or namespace device
 * @name: The basename of the device to open
 *
 * This will look for the handle in /dev/ and validate the name and filetype
 * match linux conventions.
 *
 * Return: A file descriptor for the device on a successful open, or -1 with
 * 	   errno set otherwise.
 */
int nvme_open(const char *name);

#endif /* _LIBNVME_UTIL_H */
