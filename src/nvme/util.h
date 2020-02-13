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

#include <stdbool.h>
#include <linux/types.h>

#include "ioctl.h"

/**
 * nvme_status_to_errno() - Converts nvme return status to errno
 * @status: Return status from an nvme passthrough commmand
 * @fabrics: true if given status is for fabrics
 *
 * If status < 0, errno is already set.
 *
 * Return: Appropriate errno for the given nvme status
 */
__u8 nvme_status_to_errno(int status, bool fabrics);

/**
 * nvme_fw_download_seq() -
 * @fd:
 * @size:
 * @xfer:
 * @offset:
 * @buf:
 *
 * Return: 
 */
int nvme_fw_download_seq(int fd, __u32 size, __u32 xfer, __u32 offset,
			 void *buf);

/**
 * nvme_get_ctrl_telemetry() -
 * @fd:
 * @rae:
 * @buf:
 * @log_size:
 *
 * Returns:
 */
int nvme_get_ctrl_telemetry(int fd, bool rae, void **buf, __u32 *log_size);

/**
 * nvme_get_host_telemetry() -
 * @fd:
 * @buf:
 * @log_size:
 *
 * Returns:
 */
int nvme_get_host_telemetry(int fd, void **buf, __u32 *log_size);

/**
 * nvme_get_new_host_telemetry() -
 * @fd:
 * @buf:
 * @log_size:
 *
 * Returns:
 */
int nvme_get_new_host_telemetry(int fd, void **buf, __u32 *log_size);

/**
 * nvme_setup_id_ns() -
 * @ns:
 * @nsze:
 * @ncap:
 * @flbas:
 * @dps:
 * @nmic:
 * @anagrpid:
 * @nvmsetid:
 */
void nvme_setup_id_ns(struct nvme_id_ns *ns, __u64 nsze, __u64 ncap, __u8 flbas,
		__u8 dps, __u8 nmic, __u32 anagrpid, __u16 nvmsetid);

/**
 * nvme_setup_ctrl_list() -
 * @cntlist:
 * @num_ctrls:
 * @ctrlist:
 */
void nvme_setup_ctrl_list(struct nvme_ctrl_list *cntlist, __u16 num_ctrls,
			  __u16 *ctrlist);

/**
 * nvme_dsm_range() - Constructs a data set range structure
 * @dsm:	DSM range array
 * @ctx_attrs:	Array of context attributes
 * @llbas:	Array of length in logical blocks
 * @slbas:	Array of starting logical blocks
 * @nr_ranges:	The size of the dsm arrays
 *
 * Each array must be the same size of size 'nr_ranges'.
 *
 * Return: The nvme command status if a response was received or -errno
 * 	   otherwise.
 */
void nvme_setup_dsm_range(struct nvme_dsm_range *dsm, __u32 *ctx_attrs,
			  __u32 *llbas, __u64 *slbas, __u16 nr_ranges);

/**
 * __nvme_get_log_page() -
 * @fd:
 * @nsid:
 * @log_id:
 * @rae:
 * @xfer_len:	Max partial log transfer size to request while splitting
 * @data_len:
 * @data:
 */
int __nvme_get_log_page(int fd, __u32 nsid, __u8 log_id, bool rae,
		__u32 xfer_len, __u32 data_len, void *data);

/**
 * nvme_get_log_page() -
 * @fd:
 * @nsid:
 * @log_id:
 * @rae:
 * @data_len:
 * @data:
 *
 * Calls __nvme_get_log_page() with a default 4k transfer length.
 */
int nvme_get_log_page(int fd, __u32 nsid, __u8 log_id, bool rae,
		__u32 data_len, void *data);

/**
 * nvme_get_ana_log_len() - Retreive size of the current ANA log
 * @fd:		File descriptor of nvme device
 * @analen:	Pointer to where the length will be set on success
 *
 * Return: 0 on success, -1 otherwise with errno set
 */
int nvme_get_ana_log_len(int fd, size_t *analen);

/**
 * nvme_namespace_attach_ctrls() - Attach namespace to controller(s)
 * @fd:		File descriptor of nvme device
 * @nsid:	Namespace ID to attach
 * @num_ctrls:	Number of controllers in ctrlist
 * @ctrlist:	List of controller IDs to perform the attach action
 *
 * Return: The nvme command status if a response was received or -1
 * 	   with errno set otherwise.
 */
int nvme_namespace_attach_ctrls(int fd, __u32 nsid, __u16 num_ctrls, __u16 *ctrlist);

/**
 * nvme_namespace_detach_ctrls() - Detach namespace from controller(s)
 * @fd:		File descriptor of nvme device
 * @nsid:	Namespace ID to detach
 * @num_ctrls:	Number of controllers in ctrlist
 * @ctrlist:	List of controller IDs to perform the detach action
 *
 * Return: The nvme command status if a response was received or -1
 * 	   with errno set otherwise.
 */
int nvme_namespace_detach_ctrls(int fd, __u32 nsid, __u16 num_ctrls, __u16 *ctrlist);

/**
 * nvme_get_feature_length() - Retreive the command payload length for a
 * 			       specific feature identifier
 * @fid:
 * @cdw11:
 * @len:
 *
 * Return: 0 on success, -1 with errno set otherwise
 */
int nvme_get_feature_length(int fid, __u32 cdw11, __u32 *len);

/**
 * nvme_get_directive_receive_length() -
 * @dtype:	Directive type, see &enum nvme_directive_dtype
 * @doper:	Directive receive operation, see &enum nvme_directive_receive_doper
 * @len:	Address to save the payload length of the directive in bytes on
 * 		a successful decode
 *
 * Return: 0 on success, -1 with errno set to EINVAL.
 */
int nvme_get_directive_receive_length(enum nvme_directive_dtype dtype,
		enum nvme_directive_receive_doper doper, __u32 *len);

/**
 * nvme_open() - Open an nvme controller or namespace device
 * @name:	The basename of the device to open
 *
 * This will look for the handle in /dev/ and validate the name and filetype
 * match linux conventions.
 *
 * Return: A file descriptor for the device on a successful open, or -1 with
 * 	   errno set otherwise.
 */
int nvme_open(const char *name);

/**
 * nvme_set_attr() -
 * @dir:
 * @attr:
 * @value:
 *
 * Return 
 */
int nvme_set_attr(const char *dir, const char *attr, const char *value);

#endif /* _LIBNVME_UTIL_H */
