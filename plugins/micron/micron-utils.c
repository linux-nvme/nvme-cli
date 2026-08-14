// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * Copyright (c) 2025 Micron Technology, Inc.
 *
 * Authors: Broc Going <bgoing@micron.com>
 */

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

#include <libnvme.h>

#include <shared/fs-util.h>
#include <shared/proc-util.h>

#include "micron-utils.h"

char *micron_get_ctrl_name(struct libnvme_transport_handle *hdl)
{
	const char *name = libnvme_transport_handle_get_name(hdl);
	char *ctrl_name = NULL;

	if (libnvme_transport_handle_is_ctrl(hdl)) {
		ctrl_name = strdup(name);
	} else {
		const char *p = strlen(name) > 4 ? strchr(name + 4, 'n') : NULL;

		ctrl_name = p ? strndup(name, p - name) : strdup(name);
	}

	return ctrl_name;
}

char *micron_get_ns_name(struct libnvme_transport_handle *hdl)
{
	const char *name = libnvme_transport_handle_get_name(hdl);
	char *ns_name = NULL;

	if (libnvme_transport_handle_is_ns(hdl)) {
		ns_name = strdup(name);
	} else {
		if (asprintf(&ns_name, "%sn1", name) < 0)
			return NULL;
	}

	return ns_name;
}

int micron_run_spawn(char *const argv[], const char *outfile, bool append)
{
	int fd = -1;
	shr_proc_t proc;
	bool exited;
	int code;
	int ret;

	if (outfile) {
		int oflags = O_WRONLY | O_CREAT | (append ? O_APPEND : O_TRUNC);

		fd = shr_open_rawdata(outfile, oflags, 0644);
		if (fd < 0)
			return -errno;

		/*
		 * The child inherits this fd and writes through it directly.
		 * On Windows O_APPEND is a per-write lseek done by the parent's
		 * CRT, not a kernel append flag, so the inherited handle starts
		 * at offset 0 and would overwrite existing content. Position it
		 * at EOF once before the spawn. On Linux, O_APPEND already
		 * forces writes to EOF, so this seek is a no-op.
		 */
		if (append)
			lseek(fd, 0, SEEK_END);
	}

	/* Redirect both stdout and stderr to the file, matching prior behavior. */
	ret = shr_spawnp((const char *const *)argv, fd, fd, &proc);
	if (fd >= 0)
		close(fd);
	if (ret)
		return ret;

	ret = shr_wait_proc(proc, &exited, &code);
	if (ret)
		return ret;

	return (exited && code == 0) ? 0 : -EIO;
}
