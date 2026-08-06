// SPDX-License-Identifier: LGPL-2.1-or-later

/*
 * This file is part of libnvme.
 *
 * Copyright (c) 2025, Dell Technologies Inc. or its subsidiaries.
 * Authors: Martin Belanger <Martin.Belanger@dell.com>
 *
 *   ____                           _           _    ____          _
 *  / ___| ___ _ __   ___ _ __ __ _| |_ ___  __| |  / ___|___   __| | ___
 * | |  _ / _ \ '_ \ / _ \ '__/ _` | __/ _ \/ _` | | |   / _ \ / _` |/ _ \
 * | |_| |  __/ | | |  __/ | | (_| | ||  __/ (_| | | |__| (_) | (_| |  __/
 *  \____|\___|_| |_|\___|_|  \__,_|\__\___|\__,_|  \____\___/ \__,_|\___|
 *
 * Auto-generated struct member accessors (setter/getter)
 *
 * To update run: meson compile -C [BUILD-DIR] update-accessors
 * Or:            make update-accessors
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <compiler-attributes.h>

#include "private.h"
#include "private-tree.h"
#include "subsys-sysfs.h"

struct libnvme_subsystem_sysfs {
	char *model;
	char *serial;
	char *firmware;
	char *iopolicy;
};

struct libnvme_subsystem_sysfs *libnvme_subsystem_sysfs_alloc(void)
{
	return calloc(1, sizeof(struct libnvme_subsystem_sysfs));
}

void libnvme_subsystem_sysfs_reset(
		struct libnvme_subsystem_sysfs *sysfs)
{
	if (!sysfs)
		return;

}

void libnvme_subsystem_sysfs_free(
		struct libnvme_subsystem_sysfs *sysfs)
{
	if (!sysfs)
		return;

	SYSFS_FREE(sysfs->model);
	SYSFS_FREE(sysfs->serial);
	SYSFS_FREE(sysfs->firmware);
	SYSFS_FREE(sysfs->iopolicy);
	free(sysfs);
}

__shr_public void libnvme_subsystem_set_model(
		struct libnvme_subsystem *p,
		const char *model)
{
	SYSFS_FREE(p->sysfs->model);
	p->sysfs->model = model ? strdup(model) : NO_SYSFS_ATTR;
}

__shr_public int libnvme_subsystem_get_model(
		const struct libnvme_subsystem *p,
		const char **val,
		const char *dflt)
{
	struct libnvme_subsystem *c = (struct libnvme_subsystem *)p;

	*val = dflt;

	if (__shr_unlikely(!SYSFS_IS_LOADED(c->sysfs->model))) {
		c->sysfs->model = libnvme_get_subsys_attr(c, "model");
		if (!c->sysfs->model)
			c->sysfs->model = NO_SYSFS_ATTR;
	}

	if (SYSFS_IS_ABSENT(c->sysfs->model))
		return -ENOENT;

	*val = c->sysfs->model;
	return 0;
}

__shr_public void libnvme_subsystem_set_serial(
		struct libnvme_subsystem *p,
		const char *serial)
{
	SYSFS_FREE(p->sysfs->serial);
	p->sysfs->serial = serial ? strdup(serial) : NO_SYSFS_ATTR;
}

__shr_public int libnvme_subsystem_get_serial(
		const struct libnvme_subsystem *p,
		const char **val,
		const char *dflt)
{
	struct libnvme_subsystem *c = (struct libnvme_subsystem *)p;

	*val = dflt;

	if (__shr_unlikely(!SYSFS_IS_LOADED(c->sysfs->serial))) {
		c->sysfs->serial = libnvme_get_subsys_attr(c, "serial");
		if (!c->sysfs->serial)
			c->sysfs->serial = NO_SYSFS_ATTR;
	}

	if (SYSFS_IS_ABSENT(c->sysfs->serial))
		return -ENOENT;

	*val = c->sysfs->serial;
	return 0;
}

__shr_public void libnvme_subsystem_set_firmware(
		struct libnvme_subsystem *p,
		const char *firmware)
{
	SYSFS_FREE(p->sysfs->firmware);
	p->sysfs->firmware = firmware ? strdup(firmware) : NO_SYSFS_ATTR;
}

__shr_public int libnvme_subsystem_get_firmware(
		const struct libnvme_subsystem *p,
		const char **val,
		const char *dflt)
{
	struct libnvme_subsystem *c = (struct libnvme_subsystem *)p;

	*val = dflt;

	if (__shr_unlikely(!SYSFS_IS_LOADED(c->sysfs->firmware))) {
		c->sysfs->firmware = libnvme_get_subsys_attr(c, "firmware_rev");
		if (!c->sysfs->firmware)
			c->sysfs->firmware = NO_SYSFS_ATTR;
	}

	if (SYSFS_IS_ABSENT(c->sysfs->firmware))
		return -ENOENT;

	*val = c->sysfs->firmware;
	return 0;
}

__shr_public int libnvme_subsystem_get_iopolicy(
		const struct libnvme_subsystem *p,
		const char **val,
		const char *dflt)
{
	struct libnvme_subsystem *c = (struct libnvme_subsystem *)p;
	__cleanup_free char *str = NULL;

	*val = dflt;

	str = libnvme_get_subsys_attr(c, "iopolicy");
	if (!str)
		return -ENOENT;

	if (!c->sysfs->iopolicy || strcmp(str, c->sysfs->iopolicy)) {
		free(c->sysfs->iopolicy);
		c->sysfs->iopolicy = strdup(str);
		if (!c->sysfs->iopolicy)
			return -ENOMEM;
	}

	*val = c->sysfs->iopolicy;
	return 0;
}

