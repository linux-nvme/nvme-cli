// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libnvme.
 * Copyright (c) 2020 Western Digital Corporation or its affiliates.
 *
 * Authors: Keith Busch <keith.busch@wdc.com>
 *	    Chaitanya Kulkarni <chaitanya.kulkarni@wdc.com>
 */

#pragma once

#include <nvme/lib-types.h>

/**
 * DOC: ioctl.h
 *
 * Linux NVMe ioctl interface functions
 */

/* '0' is interpreted by the kernel to mean 'apply the default timeout' */
#define NVME_DEFAULT_IOCTL_TIMEOUT 0

/*
 * 4k is the smallest possible transfer unit, so restricting to 4k
 * avoids having to check the MDTS value of the controller.
 */
#define NVME_LOG_PAGE_PDU_SIZE 4096

/**
 * libnvme_submit_admin_passthru() - Submit an nvme passthrough admin command
 * @hdl:	Transport handle
 * @cmd:	The nvme admin command to send
 *
 * Uses LIBNVME_IOCTL_ADMIN_CMD for the ioctl request.
 *
 * Return: 0 on success, the nvme command status if a response was
 * received (see &enum nvme_status_field) or a negative error otherwise.
 */
int libnvme_submit_admin_passthru(struct libnvme_transport_handle *hdl,
		struct libnvme_passthru_cmd *cmd);

/**
 * libnvme_submit_io_passthru() - Submit an nvme passthrough command
 * @hdl:	Transport handle
 * @cmd:	The nvme io command to send
 *
 * Uses LIBNVME_IOCTL_IO_CMD for the ioctl request.
 *
 * Return: 0 on success, the nvme command status if a response was
 * received (see &enum nvme_status_field) or a negative error otherwise.
 */
int libnvme_submit_io_passthru(struct libnvme_transport_handle *hdl,
		struct libnvme_passthru_cmd *cmd);

/**
 * libnvme_reset_subsystem() - Initiate a subsystem reset
 * @hdl:	Transport handle
 *
 * This should only be sent to controller handles, not to namespaces.
 *
 * Return: Zero if a subsystem reset was initiated or -1 with errno set
 * otherwise.
 */
int libnvme_reset_subsystem(struct libnvme_transport_handle *hdl);

/**
 * libnvme_reset_ctrl() - Initiate a controller reset
 * @hdl:	Transport handle
 *
 * This should only be sent to controller handles, not to namespaces.
 *
 * Return: 0 if a reset was initiated or -1 with errno set otherwise.
 */
int libnvme_reset_ctrl(struct libnvme_transport_handle *hdl);

/**
 * libnvme_rescan_ns() - Initiate a controller rescan
 * @hdl:	Transport handle
 *
 * This should only be sent to controller handles, not to namespaces.
 *
 * Return: 0 if a rescan was initiated or -1 with errno set otherwise.
 */
int libnvme_rescan_ns(struct libnvme_transport_handle *hdl);

/**
 * libnvme_get_nsid() - Retrieve the NSID from a namespace file descriptor
 * @hdl:	Transport handle
 * @nsid:	User pointer to namespace id
 *
 * This should only be sent to namespace handles, not to controllers. The
 * kernel's interface returns the nsid as the return value. This is unfortunate
 * for many architectures that are incapable of allowing distinguishing a
 * namespace id > 0x80000000 from a negative error number.
 *
 * Return: 0 if @nsid was set successfully or -1 with errno set otherwise.
 */
int libnvme_get_nsid(struct libnvme_transport_handle *hdl, __u32 *nsid);

/**
 * libnvme_update_block_size() - Update the block size
 * @hdl:	Transport handle
 * @block_size:	New block size
 *
 * Notify the kernel blkdev to update its block size after a block size change.
 * This should only be used for namespace handles, not controllers.
 *
 * Return: 0 if the block size was updated or a negative error code otherwise.
 */
int libnvme_update_block_size(struct libnvme_transport_handle *hdl, int block_size);
