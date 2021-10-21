// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libnvme.
 * Copyright (c) 2020 Western Digital Corporation or its affiliates.
 *
 * Authors: Keith Busch <keith.busch@wdc.com>
 * 	    Chaitanya Kulkarni <chaitanya.kulkarni@wdc.com>
 */
#ifndef _LIBNVME_LINUX_H
#define _LIBNVME_LINUX_H

#include "types.h"

/**
 * nvme_fw_download_seq() -
 * @fd:     File descriptor of nvme device
 * @size:   Total size of the firmware image to transfer
 * @xfer:   Maximum size to send with each partial transfer
 * @offset: Starting offset to send with this firmware downlaod
 * @buf:    Address of buffer containing all or part of the firmware image.
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
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
 * &enum nvme_status_field) or -1 with errno set otherwise.
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
 * &enum nvme_status_field) or -1 with errno set otherwise.
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
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_get_new_host_telemetry(int fd,  struct nvme_telemetry_log **log);

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
 * &enum nvme_status_field) or -1 with errno set otherwise.
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
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_get_log_page(int fd, __u32 nsid, __u8 log_id, bool rae,
		      __u32 data_len, void *data);

/**
 * nvme_get_ana_log_len() - Retreive size of the current ANA log
 * @fd:		File descriptor of nvme device
 * @analen:	Pointer to where the length will be set on success
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_get_ana_log_len(int fd, size_t *analen);

/**
 * nvme_get_lba_status_log() - Retreive the LBA Status log page
 * @fd:	   File descriptor of the nvme device
 * @rae:   Retain asynchronous events
 * @log:   On success, set to the value of the allocated and retreived log.
 */
int nvme_get_lba_status_log(int fd, bool rae, struct nvme_lba_status_log **log);

/**
 * nvme_namespace_attach_ctrls() - Attach namespace to controller(s)
 * @fd:		File descriptor of nvme device
 * @nsid:	Namespace ID to attach
 * @num_ctrls:	Number of controllers in ctrlist
 * @ctrlist:	List of controller IDs to perform the attach action
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
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
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_namespace_detach_ctrls(int fd, __u32 nsid, __u16 num_ctrls, __u16 *ctrlist);

/**
 * nvme_open() - Open an nvme controller or namespace device
 * @name: The basename of the device to open
 *
 * This will look for the handle in /dev/ and validate the name and filetype
 * match linux conventions.
 *
 * Return: A file descriptor for the device on a successful open, or -1 with
 * errno set otherwise.
 */
int nvme_open(const char *name);

#endif /* _LIBNVME_LINUX_H */
