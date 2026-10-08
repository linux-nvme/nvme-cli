// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2026 SUSE LLC
 *
 * Authors: Daniel Wagner <dwagner@suse.de>
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sysctl.h>
#include <sys/types.h>
#include <sys/utsname.h>

#include <libnvme.h>

#include "micron-utils.h"
#include "nvme-print.h"
#include "src/cleanup.h"

/*
 * FreeBSD has no sysfs, so there is no "/sys/class/nvme/<ctrl>/device"
 * symlink for shr_pci_open_class_config() to resolve a device's PCI config
 * space from. Unlike nvme-pci-ids-freebsd.c's sysctl-based PCI-ID lookup,
 * reading/writing arbitrary config-space registers (the AER status/mask
 * registers) has no sysctl equivalent, so this isn't implemented here.
 */
int micron_get_pcie_aer_errors(struct libnvme_transport_handle *hdl,
	__u32 *correctable_errors, __u32 *uncorrectable_errors)
{
	*correctable_errors = 0;
	*uncorrectable_errors = 0;
	nvme_show_error("register reads not supported on the current platform");
	return -ENOTSUP;
}

int micron_clear_pcie_aer_correctable_errors(
	struct libnvme_transport_handle *hdl)
{
	nvme_show_error("register writes not supported on the current platform");
	return -ENOTSUP;
}

#define OS_CONFIG_CAPTURE_MAX (1 << 20)

static void write_section_header(FILE *fp, const char *header)
{
	fprintf(fp, "\n\n\n\n%s\n-----------------------------------------------\n",
		header);
}

/* Appends a string-valued sysctl (e.g. "kern.version", "kern.msgbuf"). */
static void write_sysctl_string(FILE *fp, const char *name)
{
	__cleanup_free char *buf = NULL;
	size_t len = 0;

	if (sysctlbyname(name, NULL, &len, NULL, 0) < 0 || !len)
		return;

	buf = malloc(len + 1);
	if (!buf)
		return;

	if (sysctlbyname(name, buf, &len, NULL, 0) < 0)
		return;
	buf[len] = '\0';

	fprintf(fp, "%s\n", buf);
}

static void write_sysctl_ulong(FILE *fp, const char *label, const char *name)
{
	unsigned long val;
	size_t len = sizeof(val);

	if (sysctlbyname(name, &val, &len, NULL, 0) < 0)
		return;

	fprintf(fp, "%-18s: %lu\n", label, val);
}

static void write_sysctl_int(FILE *fp, const char *label, const char *name)
{
	int val;
	size_t len = sizeof(val);

	if (sysctlbyname(name, &val, &len, NULL, 0) < 0)
		return;

	fprintf(fp, "%-18s: %d\n", label, val);
}

static void write_file_contents(FILE *fp, const char *path)
{
	__cleanup_file FILE *in = fopen(path, "r");
	char buf[4096];
	size_t total = 0, n;

	if (!in)
		return;

	while (total < OS_CONFIG_CAPTURE_MAX &&
	       (n = fread(buf, 1, sizeof(buf), in)) > 0) {
		fwrite(buf, 1, n, fp);
		total += n;
	}
}

void micron_write_os_config_to_file(const char *file_name)
{
	__cleanup_file FILE *fp = fopen(file_name, "w+");
	struct utsname uts;

	if (!fp) {
		nvme_show_error("Failed to create %s", file_name);
		return;
	}

	write_section_header(fp, "SYSTEM INFORMATION");
	if (!uname(&uts))
		fprintf(fp, "%s %s %s %s %s\n", uts.sysname, uts.nodename,
			uts.release, uts.version, uts.machine);
	write_sysctl_string(fp, "kern.version");

	write_section_header(fp, "SYSTEM MEMORY INFORMATION");
	write_sysctl_ulong(fp, "Physical Memory", "hw.physmem");
	write_sysctl_ulong(fp, "Real Memory", "hw.realmem");
	write_sysctl_ulong(fp, "User Memory", "hw.usermem");

	write_section_header(fp, "CPU INFORMATION");
	write_sysctl_string(fp, "hw.model");
	write_sysctl_string(fp, "hw.machine");
	write_sysctl_int(fp, "Logical CPUs", "hw.ncpu");
	write_sysctl_int(fp, "Clock Rate (MHz)", "hw.clockrate");

	write_section_header(fp, "KERNEL DMESG");
	write_sysctl_string(fp, "kern.msgbuf");

	write_section_header(fp, "/VAR/LOG/MESSAGES");
	write_file_contents(fp, "/var/log/messages");
}

void micron_get_os_string(char *buf, size_t len)
{
	struct utsname un;

	if (!buf || !len)
		return;
	buf[0] = '\0';

	if (uname(&un))
		return;

	snprintf(buf, len, "%s %s %s", un.sysname, un.release, un.machine);
}
