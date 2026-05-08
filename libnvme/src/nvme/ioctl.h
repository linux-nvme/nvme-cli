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
 * libnvme_wait_admin_passthru() - Wait for pending admin passthru completions
 * @hdl:	Transport handle
 *
 * When io_uring is enabled, libnvme_submit_admin_passthru() queues commands
 * asynchronously. Call this function after one or more submits to drain all
 * pending completions before inspecting response data.
 *
 * This is a no-op when io_uring is not available.
 *
 * Return: 0 on success or a negative error code otherwise.
 */
int libnvme_wait_admin_passthru(struct libnvme_transport_handle *hdl);

/**
 * libnvme_exec_admin_passthru() - Submit an admin passthru command and wait
 * @hdl:	Transport handle
 * @cmd:	The nvme admin command to send
 *
 * Convenience wrapper that combines libnvme_submit_admin_passthru() and
 * libnvme_wait_admin_passthru() into a single synchronous call. Use this
 * for the common case where commands are sent one at a time. Use the
 * split-phase API directly when batching multiple commands with io_uring.
 *
 * Return: 0 on success, the nvme command status if a response was
 * received (see &enum nvme_status_field) or a negative error otherwise.
 */
static inline int libnvme_exec_admin_passthru(
		struct libnvme_transport_handle *hdl,
		struct libnvme_passthru_cmd *cmd)
{
	int err = libnvme_submit_admin_passthru(hdl, cmd);
	return err ? err : libnvme_wait_admin_passthru(hdl);
}

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
 * libnvme_wait_io_passthru() - Wait for pending IO passthru completions
 * @hdl:	Transport handle
 *
 * Counterpart to libnvme_submit_io_passthru() for the split-phase API.
 * Currently a no-op as the IO passthru path does not yet use io_uring.
 *
 * Return: 0 on success or a negative error code otherwise.
 */
int libnvme_wait_io_passthru(struct libnvme_transport_handle *hdl);

/**
 * libnvme_exec_io_passthru() - Submit an IO passthru command and wait
 * @hdl:	Transport handle
 * @cmd:	The nvme IO command to send
 *
 * Convenience wrapper combining libnvme_submit_io_passthru() and
 * libnvme_wait_io_passthru() into a single synchronous call.
 *
 * Return: 0 on success, the nvme command status if a response was
 * received (see &enum nvme_status_field) or a negative error otherwise.
 */
static inline int libnvme_exec_io_passthru(
		struct libnvme_transport_handle *hdl,
		struct libnvme_passthru_cmd *cmd)
{
	int err = libnvme_submit_io_passthru(hdl, cmd);
	return err ? err : libnvme_wait_io_passthru(hdl);
}

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
int libnvme_update_block_size(struct libnvme_transport_handle *hdl,
		int block_size);
