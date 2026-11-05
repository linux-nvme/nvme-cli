// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 Dell Technologies Inc. or its subsidiaries.
 *
 * Authors: Martin Belanger <martin.belanger@dell.com>
 */

#include <dirent.h>
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <daemon-util/log.h>
#include <shared/cleanup-util.h>
#include <shared/fs-util.h>

#include "state.h"
#include "sysfs.h"

/*
 * Manages discoverd's runtime state files under RUNDIR/nvme/discoverd/ (see
 * the layout comment in state.h) - the on-disk link between a kernel device
 * name (nvmeX), the systemd transient unit that owns it, and the .devid
 * file nvme connect writes back so ExecStop= can find the device to
 * disconnect. No TID/transport data is stored here; that is read from
 * sysfs or re-derived from the unit itself.
 */

static char units_dir[PATH_MAX] = STATE_RUN_DIR "/units";
static char ctrls_dir[PATH_MAX] = STATE_RUN_DIR "/controllers";
static char desired_path[PATH_MAX] = STATE_RUN_DIR "/desired";

int state_set_dir(const char *dir)
{
	int n1, n2, n3;

	if (!dir)
		dir = STATE_RUN_DIR;

	n1 = snprintf(units_dir, sizeof(units_dir), "%s/units", dir);
	n2 = snprintf(ctrls_dir, sizeof(ctrls_dir), "%s/controllers", dir);
	n3 = snprintf(desired_path, sizeof(desired_path), "%s/desired", dir);
	if (n1 < 0 || n1 >= (int)sizeof(units_dir) ||
	    n2 < 0 || n2 >= (int)sizeof(ctrls_dir) ||
	    n3 < 0 || n3 >= (int)sizeof(desired_path)) {
		state_set_dir(NULL);
		return -ENAMETOOLONG;
	}

	return 0;
}

const char *state_units_dir(void)
{
	return units_dir;
}

const char *state_ctrls_dir(void)
{
	return ctrls_dir;
}

const char *state_desired_path(void)
{
	return desired_path;
}

/* The path of file @name of @devid's state, or of the directory if NULL. */
static int ctrl_path(char *buf, size_t len, const char *devid,
		     const char *name)
{
	int n;

	if (name)
		n = snprintf(buf, len, "%s/%s/%s", ctrls_dir, devid, name);
	else
		n = snprintf(buf, len, "%s/%s", ctrls_dir, devid);

	return n < 0 || (size_t)n >= len ? -ENAMETOOLONG : 0;
}

int state_init(void)
{
	int ret;

	ret = shr_mkdir_p(units_dir, 0755);
	if (ret)
		return ret;

	return shr_mkdir_p(ctrls_dir, 0755);
}

/* Read the inode recorded for @devid. Returns false if there is none. */
static bool state_read_ino(const char *devid, uint64_t *ino)
{
	char path[PATH_MAX];
	FILE *f;
	bool ok;

	if (ctrl_path(path, sizeof(path), devid, "ino"))
		return false;
	f = fopen(path, "r");
	if (!f)
		return false;

	ok = fscanf(f, "%" SCNu64, ino) == 1;
	fclose(f);

	return ok;
}

bool state_ctrl_present(const char *devid)
{
	__cleanup_free char *syspath = sysfs_nvme_path(devid);
	struct stat st;
	uint64_t ino;

	if (!syspath || stat(syspath, &st))
		return false;

	return state_read_ino(devid, &ino) && ino == (uint64_t)st.st_ino;
}

void state_gc(void)
{
	struct dirent *de;
	DIR *d;

	d = opendir(ctrls_dir);
	if (!d)
		return;

	while ((de = readdir(d))) {
		__cleanup_free char *syspath = NULL;
		struct stat st;
		uint64_t ino;

		if (de->d_name[0] == '.')
			continue;

		syspath = sysfs_nvme_path(de->d_name);
		if (!syspath)
			continue;
		if (!stat(syspath, &st)) {
			if (!state_read_ino(de->d_name, &ino) ||
			    ino == (uint64_t)st.st_ino)
				continue;
			log_info("%s: device name reused, removing stale state",
				 de->d_name);
		} else {
			log_info("%s: device gone, removing stale state",
				 de->d_name);
		}

		state_remove_ctrl(de->d_name);
	}

	closedir(d);
}

int state_write_desired(const char *content)
{
	char tmp[PATH_MAX + 8];
	size_t len = strlen(content);
	ssize_t n;
	int fd;

	snprintf(tmp, sizeof(tmp), "%s.XXXXXX", desired_path);
	fd = shr_mkstemp(tmp);
	if (fd < 0)
		return -errno;

	n = write(fd, content, len);
	close(fd);
	if (n < 0 || (size_t)n != len || rename(tmp, desired_path) < 0) {
		int r = n < 0 ? -errno : -EIO;

		unlink(tmp);
		return r;
	}

	return 0;
}

char *state_read_desired(void)
{
	char *content = NULL;
	size_t size = 0;
	FILE *f;

	f = fopen(desired_path, "r");
	if (!f)
		return NULL;

	if (getdelim(&content, &size, '\0', f) < 0) {
		free(content);
		content = NULL;
	}
	fclose(f);

	return content;
}

char *state_read_unit(const char *devid)
{
	char path[PATH_MAX];
	char buf[256];
	FILE *f;
	char *ret;

	if (ctrl_path(path, sizeof(path), devid, "unit"))
		return NULL;
	f = fopen(path, "r");
	if (!f)
		return NULL;

	if (!fgets(buf, sizeof(buf), f)) {
		fclose(f);
		return NULL;
	}
	fclose(f);

	ret = strdup(buf);
	if (ret) {
		char *nl = strchr(ret, '\n');

		if (nl)
			*nl = '\0';
	}
	return ret;
}

void state_remove_ctrl(const char *devid)
{
	char path[PATH_MAX];

	if (!ctrl_path(path, sizeof(path), devid, "unit"))
		unlink(path);
	if (!ctrl_path(path, sizeof(path), devid, "ino"))
		unlink(path);
	if (!ctrl_path(path, sizeof(path), devid, NULL))
		rmdir(path);
}

void state_remove_devid(const char *unit_name)
{
	char base[256];
	char path[PATH_MAX];
	char *dot;
	int n;

	/* The .devid file is named after %N (unit name without .service). */
	snprintf(base, sizeof(base), "%s", unit_name);
	dot = strrchr(base, '.');
	if (dot && !strcmp(dot, ".service"))
		*dot = '\0';

	n = snprintf(path, sizeof(path), "%s/%s.devid", units_dir, base);
	if (n >= 0 && (size_t)n < sizeof(path))
		unlink(path);
}
