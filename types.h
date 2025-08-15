/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef TYPES_H
#define TYPES_H

#include "nvme/types.h"

/**
 * struct nvme_get_log_args - Arguments for the NVMe Admin Get Log command
 * @nsid:	Namespace identifier, if applicable
 * @rae:	Retain asynchronous events
 * @lsp:	Log specific field
 * @lid:	Log page identifier, see &enum nvme_cmd_get_log_lid for known
 *			values
 * @lsi:	Log Specific Identifier
 * @csi:	Command set identifier, see &enum nvme_csi for known values
 * @ot:		Offset Type; if set @lpo specifies the index into the list
 *			of data structures, otherwise @lpo specifies the byte offset
 *			into the log page.
 * @uidx:	UUID selection, if supported
 * @lpo:	Log page offset for partial log transfers
 * @log:	User space destination address to transfer the data
 * @len:	Length of provided user buffer to hold the log data in bytes
 * @result:	The command completion result from CQE dword0
 */
struct nvme_get_log_args {
	__u32 nsid;
	bool rae;
	__u8 lsp;
	enum nvme_cmd_get_log_lid lid;
	__u16 lsi;
	enum nvme_csi csi;
	bool ot;
	__u8 uidx;
	__u64 lpo;
	void *log;
	__u32 len;
	__u32 *result;
};

#endif
