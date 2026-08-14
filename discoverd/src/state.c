// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 Dell Technologies Inc. or its subsidiaries.
 *
 * Authors: Martin Belanger <martin.belanger@dell.com>
 */

#include <dirent.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <shared/array-util.h>
#include <shared/fs-util.h>

#include "state.h"

/*
 * Manages discoverd's runtime state files under RUNDIR/nvme/discoverd/ (see
 * the layout comment in state.h) - the on-disk link between a kernel device
 * name (nvmeX), the systemd transient unit that owns it, and the .devid
 * file nvme connect writes back so ExecStop= can find the device to
 * disconnect. No TID/transport data is stored here; that is read from
 * sysfs or re-derived from the unit itself.
 */

int state_init(void)
{
	int ret;

	ret = shr_mkdir_p(STATE_UNITS_DIR, 0755);
	if (ret)
		return ret;

	return shr_mkdir_p(STATE_CTRLS_DIR, 0755);
}

char *state_read_unit(const char *devid)
{
	char path[512];
	char buf[256];
	FILE *f;
	char *ret;

	snprintf(path, sizeof(path), STATE_CTRLS_DIR "/%s/unit", devid);
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
	char path[512];

	snprintf(path, sizeof(path), STATE_CTRLS_DIR "/%s/unit", devid);
	unlink(path);
	snprintf(path, sizeof(path), STATE_CTRLS_DIR "/%s", devid);
	rmdir(path);
}

void state_remove_devid(const char *unit_name)
{
	char base[256];
	char path[512];
	char *dot;

	/* The .devid file is named after %N (unit name without .service). */
	snprintf(base, sizeof(base), "%s", unit_name);
	dot = strrchr(base, '.');
	if (dot && !strcmp(dot, ".service"))
		*dot = '\0';

	snprintf(path, sizeof(path), STATE_UNITS_DIR "/%s.devid", base);
	unlink(path);
}

/*
 * List every devid (e.g. "nvme3") that currently has a state directory
 * under STATE_CTRLS_DIR - i.e. every controller discoverd believes it
 * owns a transient unit for, regardless of whether the kernel device
 * still exists right now. Used by the startup audit to reconcile that
 * belief against what is actually present in sysfs: a devid that no
 * longer exists means the device dropped while discoverd was down and
 * needs reconnecting; a devid that does exist is simply adopted.
 *
 * Returns a NULL-terminated array of strdup'd devid strings (caller
 * frees each entry and the array itself), an empty (non-NULL,
 * single NULL-terminator) array if the directory exists but is empty,
 * or NULL if STATE_CTRLS_DIR itself could not be opened or on
 * allocation failure.
 */
SHR_PTRARRAY_DEFINE(str_list, char);

char **state_list_ctrls(void)
{
	DIR *d;
	struct dirent *ent;
	struct str_list a = { 0 };
	bool ok = true;
	size_t i;

	d = opendir(STATE_CTRLS_DIR);
	if (!d)
		return NULL;

	while ((ent = readdir(d))) {
		char *name;

		if (ent->d_name[0] == '.')
			continue;
		name = strdup(ent->d_name);
		if (!name || str_list_append(&a, name) < 0) {
			free(name);
			ok = false;
			break;
		}
	}
	closedir(d);

	if (ok && str_list_append(&a, NULL) < 0)
		ok = false;

	if (ok)
		return a.items;

	for (i = 0; i < a.len; i++)
		free(a.items[i]);
	str_list_free(&a);
	return NULL;
}
