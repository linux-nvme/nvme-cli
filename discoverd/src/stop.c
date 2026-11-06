// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 Dell Technologies Inc. or its subsidiaries.
 *
 * Authors: Martin Belanger <martin.belanger@dell.com>
 */

#include <dirent.h>
#include <errno.h>
#include <fnmatch.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>

#include <systemd/sd-bus.h>

#include <ccan/list/list.h>
#include <ccan/str/str.h>

#include <daemon-util/log.h>
#include <shared/cleanup-util.h>
#include <shared/string-util.h>

#include "state.h"
#include "stop.h"
#include "units.h"

/*
 * The ExecStop= of the connection units (nvme-discoverd --stop-unit).
 *
 * At shutdown, the controller is not disconnected while a namespace of
 * its subsystem, or a device on top of it, is mounted or used as swap.
 * A disconnect would remove the device under a mounted file system. The
 * _netdev mounts are unmounted before the unit stops, but systemd never
 * unmounts the root file system or /usr, and nothing orders a mount
 * without _netdev against the unit.
 *
 * The in-use check reads sysfs and /proc directly instead of scanning
 * the libnvme tree. It runs at shutdown, and a full scan builds the whole
 * tree to answer a question about one subsystem. Plain file reads also
 * let the unit test use a fake sysfs and /proc under a root directory.
 *
 * Block devices are matched by device number (major:minor), not by name.
 * A mount source can be /dev/mapper/vg-lv, /dev/dm-0 or /dev/root, and
 * all of these have the same device number.
 */

#define SYSFS_BLOCK_DIR		"/sys/class/block"
#define SYSTEMD_PRIVATE_BUS	"unix:path=/run/systemd/private"

/* Bound for a loop in a corrupt sysfs. */
#define MAX_DEPTH		8

/*
 * A set of block device numbers (major:minor), without duplicates.
 * @failed is set if a device could not be added (out of memory).
 */
struct dev_set {
	struct list_head devs;
	bool failed;
};

struct dev_entry {
	struct list_node entry;
	dev_t dev;
};

static void dev_set_init(struct dev_set *s)
{
	list_head_init(&s->devs);
	s->failed = false;
}

static void dev_set_free(struct dev_set *s)
{
	struct dev_entry *e, *next;

	list_for_each_safe(&s->devs, e, next, entry)
		free(e);
}

/* Is @dev in set @s? */
static bool dev_set_has(const struct dev_set *s, dev_t dev)
{
	struct dev_entry *e;

	list_for_each(&s->devs, e, entry)
		if (e->dev == dev)
			return true;

	return false;
}

/* Add @dev to set @s. Sets @s->failed if out of memory. */
static void dev_set_add(struct dev_set *s, dev_t dev)
{
	struct dev_entry *e;

	if (dev_set_has(s, dev))
		return;

	e = malloc(sizeof(*e));
	if (!e) {
		s->failed = true;
		return;
	}
	e->dev = dev;
	list_add_tail(&s->devs, &e->entry);
}

/*
 * snprintf() into a path buffer. Returns false if the path does not fit
 * in @len bytes.
 */
static __attribute__((format(printf, 3, 4)))
bool fmt_path(char *buf, size_t len, const char *fmt, ...)
{
	va_list ap;
	int n;

	va_start(ap, fmt);
	n = vsnprintf(buf, len, fmt, ap);
	va_end(ap);

	return n >= 0 && (size_t)n < len;
}

/*
 * Read a sysfs "dev" file ("major:minor") into @dev.
 * Returns 0 or a negative errno.
 */
static int read_dev(const char *path, dev_t *dev)
{
	__cleanup_file FILE *f = fopen(path, "r");
	unsigned int maj, min;

	if (!f)
		return -errno;
	if (fscanf(f, "%u:%u", &maj, &min) != 2)
		return -EINVAL;
	*dev = makedev(maj, min);

	return 0;
}

/*
 * Add block device @name to set @s, then its partitions and the devices
 * that use it (its "holders", e.g. LVM or dm-crypt), recursively.
 * @depth limits the recursion.
 */
static void add_blockdev(struct dev_set *s, const char *root,
			 const char *name, int depth)
{
	char dir[PATH_MAX], path[PATH_MAX];
	struct dirent *de;
	dev_t dev = 0;
	DIR *d;

	if (depth > MAX_DEPTH)
		return;

	if (!fmt_path(dir, sizeof(dir), "%s" SYSFS_BLOCK_DIR "/%s",
		      root, name) ||
	    !fmt_path(path, sizeof(path), "%s/dev", dir) ||
	    read_dev(path, &dev))
		return;
	dev_set_add(s, dev);

	d = NULL;
	if (fmt_path(path, sizeof(path), "%s/holders", dir))
		d = opendir(path);
	if (d) {
		while ((de = readdir(d))) {
			if (de->d_name[0] == '.')
				continue;
			add_blockdev(s, root, de->d_name, depth + 1);
		}
		closedir(d);
	}

	d = opendir(dir);
	if (!d)
		return;
	while ((de = readdir(d))) {
		if (!shr_startswith(de->d_name, name) ||
		    streq(de->d_name, name))
			continue;
		if (!fmt_path(path, sizeof(path), "%s/%s/partition",
			      dir, de->d_name) ||
		    access(path, F_OK))
			continue;
		add_blockdev(s, root, de->d_name, depth + 1);
	}
	closedir(d);
}

/*
 * Add every namespace block device listed in sysfs directory @dir
 * (entries named nvme*n*) to set @s, with the devices on top of them.
 */
static void add_namespaces(struct dev_set *s, const char *root,
			   const char *dir)
{
	struct dirent *de;
	DIR *d;

	d = opendir(dir);
	if (!d)
		return;
	while ((de = readdir(d))) {
		if (fnmatch("nvme*n*", de->d_name, 0))
			continue;
		add_blockdev(s, root, de->d_name, 0);
	}
	closedir(d);
}

/*
 * Add the namespace block devices of controller @devid to set @s, with
 * the devices on top of them. With native multipath, the namespaces are
 * in the subsystem directory. Without it, they are in the controller
 * directory. Both are checked.
 */
static void add_ctrl_namespaces(struct dev_set *s, const char *root,
				const char *devid)
{
	char dir[PATH_MAX], path[PATH_MAX];
	struct dirent *de;
	DIR *d;

	if (fmt_path(dir, sizeof(dir), "%s" SYSFS_NVME_DIR "/%s", root, devid))
		add_namespaces(s, root, dir);

	if (!fmt_path(dir, sizeof(dir), "%s" SYSFS_NVME_SUBSYS_DIR, root))
		return;
	d = opendir(dir);
	if (!d)
		return;
	while ((de = readdir(d))) {
		if (de->d_name[0] == '.')
			continue;
		if (!fmt_path(path, sizeof(path), "%s/%s/%s",
			      dir, de->d_name, devid) ||
		    access(path, F_OK))
			continue;
		if (fmt_path(path, sizeof(path), "%s/%s", dir, de->d_name))
			add_namespaces(s, root, path);
		break;
	}
	closedir(d);
}

/* Is @path a block device whose device number is in set @s? */
static bool is_blockdev_in(const struct dev_set *s, const char *path)
{
	struct stat st;

	if (path[0] != '/' || stat(path, &st) || !S_ISBLK(st.st_mode))
		return false;

	return dev_set_has(s, st.st_rdev);
}

/*
 * Is a device of set @s mounted? Checks the device number of each mount,
 * and also its source: the device number of a btrfs mount is not the one
 * of its block device.
 */
static bool is_mounted(const struct dev_set *s, const char *root)
{
	__cleanup_free char *line = NULL;
	__cleanup_file FILE *f = NULL;
	char path[PATH_MAX], src[PATH_MAX];
	unsigned int maj, min;
	size_t len = 0;
	char *sep;

	if (!fmt_path(path, sizeof(path), "%s/proc/self/mountinfo", root))
		return false;
	f = fopen(path, "r");
	if (!f)
		return false;

	while (getline(&line, &len, f) > 0) {
		if (sscanf(line, "%*s %*s %u:%u", &maj, &min) == 2 &&
		    dev_set_has(s, makedev(maj, min)))
			return true;
		sep = strstr(line, " - ");
		if (sep && sscanf(sep, " - %*s %4095s", src) == 1 &&
		    is_blockdev_in(s, src))
			return true;
	}

	return false;
}

/* Is a device of set @s used as swap? */
static bool is_swap(const struct dev_set *s, const char *root)
{
	__cleanup_free char *line = NULL;
	__cleanup_file FILE *f = NULL;
	char path[PATH_MAX], src[PATH_MAX];
	size_t len = 0;

	if (!fmt_path(path, sizeof(path), "%s/proc/swaps", root))
		return false;
	f = fopen(path, "r");
	if (!f)
		return false;

	while (getline(&line, &len, f) > 0) {
		if (sscanf(line, "%4095s", src) == 1 && is_blockdev_in(s, src))
			return true;
	}

	return false;
}

bool stop_ctrl_in_use(const char *root, const char *devid)
{
	struct dev_set s;
	bool in_use;

	dev_set_init(&s);
	add_ctrl_namespaces(&s, root, devid);

	/* A device that is missing from the set could be mounted. */
	in_use = s.failed || is_mounted(&s, root) || is_swap(&s, root);
	dev_set_free(&s);

	return in_use;
}

/*
 * Is the system shutting down (systemd's SystemState is "stopping")?
 * Returns false if systemd cannot be asked. At shutdown, the D-Bus
 * broker can be stopped already, so ask systemd over its private socket
 * first, as systemctl does.
 */
static bool system_stopping(void)
{
	__cleanup_free char *state = NULL;
	sd_bus *bus = NULL;
	int r;

	r = sd_bus_new(&bus);
	if (r >= 0) {
		r = sd_bus_set_address(bus, SYSTEMD_PRIVATE_BUS);
		if (r >= 0)
			r = sd_bus_start(bus);
		if (r < 0)
			bus = sd_bus_unref(bus);
	}
	if (r < 0 && sd_bus_open_system(&bus) < 0)
		return false;

	r = sd_bus_get_property_string(bus, SYSTEMD_BUS_NAME,
				       SYSTEMD_OBJ_PATH, SYSTEMD_MGR_IFACE,
				       "SystemState", NULL, &state);
	sd_bus_flush_close_unref(bus);
	if (r < 0)
		return false;

	return streq(state, "stopping");
}

int stop_unit(const char *unit_name, const char *nvme_path)
{
	__cleanup_free char *devid = NULL;
	__cleanup_free char *owner = NULL;

	devid = unit_read_devid(unit_name);
	if (!devid)
		return 0;

	/* The kernel reuses device names. */
	owner = state_read_unit(devid);
	if (!owner || !streq(owner, unit_name) || !state_ctrl_present(devid))
		return 0;

	if (system_stopping() && stop_ctrl_in_use("", devid)) {
		log_info("%s: in use, not disconnected at shutdown", devid);
		return 0;
	}

	execl(nvme_path, nvme_path, "disconnect", "-d", devid, (char *)NULL);
	log_err("%s: %s", nvme_path, strerror(errno));

	return 1;
}
