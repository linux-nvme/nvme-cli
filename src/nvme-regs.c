// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * This file is part of nvme-cli.
 *
 * Copyright (c) 2014-2015, Intel Corporation.
 * Copyright (c) 2026 SUSE Software Solutions
 *
 * Authors: Keith Busch <kbusch@kernel.org>
 *          Daniel Wagner <dwagner@suse.com>
 */
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

#ifdef NVME_HAVE_MMAP
#include <sys/mman.h>
#endif

#include <libnvme.h>
#include <libnvme-mi.h>

#include <shared/fs-util.h>
#include <cleanup.h>

#include "logging.h"
#include "nvme-print.h"
#include "nvme-regs.h"

void *mmap_registers(struct libnvme_transport_handle *hdl, bool writable)
{
	void *membase = NULL;
#ifdef NVME_HAVE_MMAP
	__cleanup_free char *path = NULL;
	int fd;
	int prot = PROT_READ;
	int err;

	if (writable)
		prot |= PROT_WRITE;

	err = asprintf(&path, "/sys/class/nvme/%s/device/resource0",
		libnvme_transport_handle_get_name(hdl));
	if (err < 0)
		return NULL;

	fd = open(path, writable ? O_RDWR : O_RDONLY);
	if (fd < 0) {
		if (log_level >= LIBNVME_LOG_INFO) {
			nvme_show_error("%s did not find a pci resource, open failed %s",
				libnvme_transport_handle_get_name(hdl),
				libnvme_strerror(errno));
		}
		return NULL;
	}

	membase = mmap(NULL, shr_getpagesize(), prot, MAP_SHARED, fd, 0);
	if (membase == MAP_FAILED) {
		if (log_level >= LIBNVME_LOG_INFO) {
			nvme_show_error("Failed to map registers to userspace.\n\n"
				"Did your kernel enable CONFIG_IO_STRICT_DEVMEM?\n"
				"You can disable this feature with command line argument\n\n"
				"\tio_memory=relaxed\n\n"
				"Also ensure secure boot is disabled.");
		}
		membase = NULL;
	}

	close(fd);
#endif
	return membase;
}

int munmap_registers(void *addr)
{
#ifdef NVME_HAVE_MMAP
	return munmap(addr, shr_getpagesize());
#else
	return 0;
#endif
}
