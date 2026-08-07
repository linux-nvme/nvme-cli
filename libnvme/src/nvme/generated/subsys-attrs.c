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

#include "../private.h"
#include "../private-tree.h"
#include "subsys-attrs.h"

struct libnvme_subsystem_attrs {
	char *model;
	char *serial;
	char *firmware;
	char *iopolicy;
};

struct libnvme_subsystem_attrs *libnvme_subsystem_attrs_alloc(void)
{
	return calloc(1, sizeof(struct libnvme_subsystem_attrs));
}

void libnvme_subsystem_attrs_reset(
		struct libnvme_subsystem_attrs *attrs)
{
	if (!attrs)
		return;

}

void libnvme_subsystem_attrs_free(
		struct libnvme_subsystem_attrs *attrs)
{
	if (!attrs)
		return;

	ATTR_FREE(attrs->model);
	ATTR_FREE(attrs->serial);
	ATTR_FREE(attrs->firmware);
	ATTR_FREE(attrs->iopolicy);
	free(attrs);
}

__shr_public void libnvme_subsystem_set_model(
		struct libnvme_subsystem *p,
		const char *model)
{
	ATTR_FREE(p->attrs->model);
	p->attrs->model = model ? strdup(model) : NO_ATTR;
}

__shr_public int libnvme_subsystem_get_model(
		const struct libnvme_subsystem *p,
		const char **val,
		const char *dflt)
{
	struct libnvme_subsystem *c = (struct libnvme_subsystem *)p;

	*val = dflt;

	if (__shr_unlikely(!ATTR_IS_LOADED(c->attrs->model))) {
		c->attrs->model = libnvme_get_subsys_attr(c, "model");
		if (!c->attrs->model)
			c->attrs->model = NO_ATTR;
	}

	if (ATTR_IS_ABSENT(c->attrs->model))
		return -ENOENT;

	*val = c->attrs->model;
	return 0;
}

__shr_public void libnvme_subsystem_set_serial(
		struct libnvme_subsystem *p,
		const char *serial)
{
	ATTR_FREE(p->attrs->serial);
	p->attrs->serial = serial ? strdup(serial) : NO_ATTR;
}

__shr_public int libnvme_subsystem_get_serial(
		const struct libnvme_subsystem *p,
		const char **val,
		const char *dflt)
{
	struct libnvme_subsystem *c = (struct libnvme_subsystem *)p;

	*val = dflt;

	if (__shr_unlikely(!ATTR_IS_LOADED(c->attrs->serial))) {
		c->attrs->serial = libnvme_get_subsys_attr(c, "serial");
		if (!c->attrs->serial)
			c->attrs->serial = NO_ATTR;
	}

	if (ATTR_IS_ABSENT(c->attrs->serial))
		return -ENOENT;

	*val = c->attrs->serial;
	return 0;
}

__shr_public void libnvme_subsystem_set_firmware(
		struct libnvme_subsystem *p,
		const char *firmware)
{
	ATTR_FREE(p->attrs->firmware);
	p->attrs->firmware = firmware ? strdup(firmware) : NO_ATTR;
}

__shr_public int libnvme_subsystem_get_firmware(
		const struct libnvme_subsystem *p,
		const char **val,
		const char *dflt)
{
	struct libnvme_subsystem *c = (struct libnvme_subsystem *)p;

	*val = dflt;

	if (__shr_unlikely(!ATTR_IS_LOADED(c->attrs->firmware))) {
		c->attrs->firmware = libnvme_get_subsys_attr(c, "firmware_rev");
		if (!c->attrs->firmware)
			c->attrs->firmware = NO_ATTR;
	}

	if (ATTR_IS_ABSENT(c->attrs->firmware))
		return -ENOENT;

	*val = c->attrs->firmware;
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

	if (!c->attrs->iopolicy || strcmp(str, c->attrs->iopolicy)) {
		free(c->attrs->iopolicy);
		c->attrs->iopolicy = strdup(str);
		if (!c->attrs->iopolicy)
			return -ENOMEM;
	}

	*val = c->attrs->iopolicy;
	return 0;
}

