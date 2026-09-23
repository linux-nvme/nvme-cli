// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 Dell Technologies Inc. or its subsidiaries.
 *
 * Authors: Martin Belanger <martin.belanger@dell.com>
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

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
