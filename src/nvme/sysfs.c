// SPDX-License-Identifier: LGPL-2.1-or-later
#include <stdio.h>
#include <stdlib.h>

#include "private.h"

#define PATH_UUID_IBM			"/proc/device-tree/ibm,partition-uuid"
#define PATH_SYSFS_BLOCK		"/sys/block"
#define PATH_SYSFS_SLOTS		"/sys/bus/pci/slots"
#define PATH_SYSFS_NVME_SUBSYSTEM	"/sys/class/nvme-subsystem"
#define PATH_SYSFS_NVME			"/sys/class/nvme"
#define PATH_DMI_ENTRIES		"/sys/firmware/dmi/entries"

static const char *make_sysfs_dir(const char *path)
{
	char *basepath = getenv("LIBNVME_SYSFS_PATH");
	char *str;

	if (!basepath)
		return path;

	if (asprintf(&str, "%s%s", basepath, path) < 0)
		return NULL;

	return str;
}

const char *nvme_subsys_sysfs_dir(void)
{
	static const char *str;

	if (str)
		return str;

	return str = make_sysfs_dir(PATH_SYSFS_NVME_SUBSYSTEM);
}

const char *nvme_ctrl_sysfs_dir(void)
{
	static const char *str;

	if (str)
		return str;

	return str = make_sysfs_dir(PATH_SYSFS_NVME);
}

const char *nvme_ns_sysfs_dir(void)
{
	static const char *str;

	if (str)
		return str;

	return str = make_sysfs_dir(PATH_SYSFS_BLOCK);
}

const char *nvme_slots_sysfs_dir(void)
{
	static const char *str;

	if (str)
		return str;

	return str = make_sysfs_dir(PATH_SYSFS_SLOTS);
}

const char *nvme_uuid_ibm_filename(void)
{
	static const char *str;

	if (str)
		return str;

	return str = make_sysfs_dir(PATH_UUID_IBM);
}

const char *nvme_dmi_entries_dir(void)
{
	static const char *str;

	if (str)
		return str;

	return str = make_sysfs_dir(PATH_DMI_ENTRIES);
}
