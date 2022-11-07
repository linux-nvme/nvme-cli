// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libnvme.
 * Copyright (c) 2020 Western Digital Corporation or its affiliates.
 *
 * Authors: Keith Busch <keith.busch@wdc.com>
 *	    Chaitanya Kulkarni <chaitanya.kulkarni@wdc.com>
 */
#ifndef _LIBNVME_LINUX_H
#define _LIBNVME_LINUX_H

#include <stddef.h>

#include "ioctl.h"
#include "types.h"

/**
 * DOC: linux.h
 *
 * linux-specific utility functions
 */

/**
 * nvme_fw_download_seq() - Firmware download sequence
 * @fd:		File descriptor of nvme device
 * @size:	Total size of the firmware image to transfer
 * @xfer:	Maximum size to send with each partial transfer
 * @offset:	Starting offset to send with this firmware download
 * @buf:	Address of buffer containing all or part of the firmware image.
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_fw_download_seq(int fd, __u32 size, __u32 xfer, __u32 offset,
			 void *buf);

/**
 * enum nvme_telemetry_da - Telemetry Log Data Area
 * @NVME_TELEMETRY_DA_1:	Data Area 1
 * @NVME_TELEMETRY_DA_2:	Data Area 2
 * @NVME_TELEMETRY_DA_3:	Data Area 3
 * @NVME_TELEMETRY_DA_4:	Data Area 4
 */
enum nvme_telemetry_da {
	NVME_TELEMETRY_DA_1	= 1,
	NVME_TELEMETRY_DA_2	= 2,
	NVME_TELEMETRY_DA_3	= 3,
	NVME_TELEMETRY_DA_4	= 4,
};

/**
 * nvme_get_ctrl_telemetry() - Get controller telemetry log
 * @fd:		File descriptor of nvme device
 * @rae:	Retain asynchronous events
 * @log:	On success, set to the value of the allocated and retrieved log.
 * @da:		Log page data area, valid values: &enum nvme_telemetry_da
 * @size:	Ptr to the telemetry log size, so it can be returned
 *
 * The total size allocated can be calculated as:
 *   (nvme_telemetry_log da size  + 1) * NVME_LOG_TELEM_BLOCK_SIZE.
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_get_ctrl_telemetry(int fd, bool rae, struct nvme_telemetry_log **log,
		enum nvme_telemetry_da da, size_t *size);

/**
 * nvme_get_host_telemetry() - Get host telemetry log
 * @fd:		File descriptor of nvme device
 * @log:	On success, set to the value of the allocated and retrieved log.
 * @da:		Log page data area, valid values: &enum nvme_telemetry_da
 * @size:	Ptr to the telemetry log size, so it can be returned
 *
 * The total size allocated can be calculated as:
 *   (nvme_telemetry_log da size  + 1) * NVME_LOG_TELEM_BLOCK_SIZE.
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_get_host_telemetry(int fd,  struct nvme_telemetry_log **log,
		enum nvme_telemetry_da da, size_t *size);

/**
 * nvme_get_new_host_telemetry() - Get new host telemetry log
 * @fd:		File descriptor of nvme device
 * @log:	On success, set to the value of the allocated and retrieved log.
 * @da:		Log page data area, valid values: &enum nvme_telemetry_da
 * @size:	Ptr to the telemetry log size, so it can be returned
 *
 * The total size allocated can be calculated as:
 *   (nvme_telemetry_log da size  + 1) * NVME_LOG_TELEM_BLOCK_SIZE.
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_get_new_host_telemetry(int fd,  struct nvme_telemetry_log **log,
		enum nvme_telemetry_da da, size_t *size);

/**
 * nvme_get_ana_log_len() - Retrieve size of the current ANA log
 * @fd:		File descriptor of nvme device
 * @analen:	Pointer to where the length will be set on success
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_get_ana_log_len(int fd, size_t *analen);

/**
 * nvme_get_logical_block_size() - Retrieve block size
 * @fd:		File descriptor of nvme device
 * @nsid:	Namespace id
 * @blksize:	Pointer to where the block size will be set on success
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_get_logical_block_size(int fd, __u32 nsid, int *blksize);

/**
 * nvme_get_lba_status_log() - Retrieve the LBA Status log page
 * @fd:		File descriptor of the nvme device
 * @rae:	Retain asynchronous events
 * @log:	On success, set to the value of the allocated and retrieved log.
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
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
 * @name:	The basename of the device to open
 *
 * This will look for the handle in /dev/ and validate the name and filetype
 * match linux conventions.
 *
 * Return: A file descriptor for the device on a successful open, or -1 with
 * errno set otherwise.
 */
int nvme_open(const char *name);

/**
 * enum nvme_hmac_alg - HMAC algorithm
 * @NVME_HMAC_ALG_NONE:		No HMAC algorithm
 * @NVME_HMAC_ALG_SHA2_256:	SHA2-256
 * @NVME_HMAC_ALG_SHA2_384:	SHA2-384
 * @NVME_HMAC_ALG_SHA2_512:	SHA2-512
 */
enum nvme_hmac_alg {
	NVME_HMAC_ALG_NONE	= 0,
	NVME_HMAC_ALG_SHA2_256	= 1,
	NVME_HMAC_ALG_SHA2_384	= 2,
	NVME_HMAC_ALG_SHA2_512	= 3,
};

/**
 * nvme_gen_dhchap_key() - DH-HMAC-CHAP key generation
 * @hostnqn:	Host NVMe Qualified Name
 * @hmac:	HMAC algorithm
 * @key_len:	Output key length
 * @secret:	Secret to used for digest
 * @key:	Generated DH-HMAC-CHAP key
 *
 * Return: If key generation was successful the function returns 0 or
 * -1 with errno set otherwise.
 */
int nvme_gen_dhchap_key(char *hostnqn, enum nvme_hmac_alg hmac,
			unsigned int key_len, unsigned char *secret,
			unsigned char *key);

#endif /* _LIBNVME_LINUX_H */
