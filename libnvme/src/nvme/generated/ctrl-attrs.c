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
#include "ctrl-attrs.h"

struct libnvme_ctrl_attrs {
	char *numa_node;
	char *queue_count;
	char *sqsize;
	long command_error_count;
	long reset_count;
	long reconnect_count;
	char *firmware;
	char *model;
	char *serial;
	char *cntrltype;
	char *cntlid;
	char *dctype;
	char *phy_slot;
	char *dhchap_host_key;
	char *dhchap_ctrl_key;
	char *keyring;
};

struct libnvme_ctrl_attrs *libnvme_ctrl_attrs_alloc(void)
{
	return calloc(1, sizeof(struct libnvme_ctrl_attrs));
}

void libnvme_ctrl_attrs_reset(
		struct libnvme_ctrl_attrs *attrs)
{
	if (!attrs)
		return;

	ATTR_FREE(attrs->numa_node);
	ATTR_FREE(attrs->queue_count);
	ATTR_FREE(attrs->sqsize);
	ATTR_FREE(attrs->firmware);
	ATTR_FREE(attrs->model);
	ATTR_FREE(attrs->serial);
	ATTR_FREE(attrs->cntrltype);
	ATTR_FREE(attrs->cntlid);
	ATTR_FREE(attrs->dctype);
	ATTR_FREE(attrs->phy_slot);
	ATTR_FREE(attrs->dhchap_host_key);
	ATTR_FREE(attrs->dhchap_ctrl_key);
	ATTR_FREE(attrs->keyring);
}

void libnvme_ctrl_attrs_free(
		struct libnvme_ctrl_attrs *attrs)
{
	if (!attrs)
		return;

	free(attrs);
}

__shr_public int libnvme_ctrl_get_numa_node(
		const struct libnvme_ctrl *p,
		const char **val,
		const char *dflt)
{
	struct libnvme_ctrl *c = (struct libnvme_ctrl *)p;

	*val = dflt;

	if (__shr_unlikely(!ATTR_IS_LOADED(c->attrs->numa_node))) {
		c->attrs->numa_node = libnvme_get_ctrl_attr(c, "numa_node");
		if (!c->attrs->numa_node)
			c->attrs->numa_node = NO_ATTR;
	}

	if (ATTR_IS_ABSENT(c->attrs->numa_node))
		return -ENOENT;

	*val = c->attrs->numa_node;
	return 0;
}

__shr_public int libnvme_ctrl_get_queue_count(
		const struct libnvme_ctrl *p,
		const char **val,
		const char *dflt)
{
	struct libnvme_ctrl *c = (struct libnvme_ctrl *)p;

	*val = dflt;

	if (__shr_unlikely(!ATTR_IS_LOADED(c->attrs->queue_count))) {
		c->attrs->queue_count = libnvme_get_ctrl_attr(c, "queue_count");
		if (!c->attrs->queue_count)
			c->attrs->queue_count = NO_ATTR;
	}

	if (ATTR_IS_ABSENT(c->attrs->queue_count))
		return -ENOENT;

	*val = c->attrs->queue_count;
	return 0;
}

__shr_public int libnvme_ctrl_get_sqsize(
		const struct libnvme_ctrl *p,
		const char **val,
		const char *dflt)
{
	struct libnvme_ctrl *c = (struct libnvme_ctrl *)p;

	*val = dflt;

	if (__shr_unlikely(!ATTR_IS_LOADED(c->attrs->sqsize))) {
		c->attrs->sqsize = libnvme_get_ctrl_attr(c, "sqsize");
		if (!c->attrs->sqsize)
			c->attrs->sqsize = NO_ATTR;
	}

	if (ATTR_IS_ABSENT(c->attrs->sqsize))
		return -ENOENT;

	*val = c->attrs->sqsize;
	return 0;
}

__shr_public int libnvme_ctrl_get_command_error_count(
		const struct libnvme_ctrl *p,
		long *val,
		long dflt)
{
	struct libnvme_ctrl *c = (struct libnvme_ctrl *)p;
	__cleanup_free char *str = NULL;

	*val = dflt;

	str = libnvme_get_ctrl_attr(c, "diag/command_error_count");
	if (!str)
		return -ENOENT;

	if (sscanf(str, "%ld", &c->attrs->command_error_count) != 1)
		return -EINVAL;

	*val = c->attrs->command_error_count;
	return 0;
}

__shr_public int libnvme_ctrl_get_reset_count(
		const struct libnvme_ctrl *p,
		long *val,
		long dflt)
{
	struct libnvme_ctrl *c = (struct libnvme_ctrl *)p;
	__cleanup_free char *str = NULL;

	*val = dflt;

	str = libnvme_get_ctrl_attr(c, "diag/reset_count");
	if (!str)
		return -ENOENT;

	if (sscanf(str, "%ld", &c->attrs->reset_count) != 1)
		return -EINVAL;

	*val = c->attrs->reset_count;
	return 0;
}

__shr_public int libnvme_ctrl_get_reconnect_count(
		const struct libnvme_ctrl *p,
		long *val,
		long dflt)
{
	struct libnvme_ctrl *c = (struct libnvme_ctrl *)p;
	__cleanup_free char *str = NULL;

	*val = dflt;

	str = libnvme_get_ctrl_attr(c, "diag/reconnect_count");
	if (!str)
		return -ENOENT;

	if (sscanf(str, "%ld", &c->attrs->reconnect_count) != 1)
		return -EINVAL;

	*val = c->attrs->reconnect_count;
	return 0;
}

__shr_public void libnvme_ctrl_set_firmware(
		struct libnvme_ctrl *p,
		const char *firmware)
{
	ATTR_FREE(p->attrs->firmware);
	p->attrs->firmware = firmware ? strdup(firmware) : NO_ATTR;
}

__shr_public int libnvme_ctrl_get_firmware(
		const struct libnvme_ctrl *p,
		const char **val,
		const char *dflt)
{
	struct libnvme_ctrl *c = (struct libnvme_ctrl *)p;
	int ret;

	*val = dflt;

	if (__shr_unlikely(!ATTR_IS_LOADED(c->attrs->firmware))) {
		ret = libnvme_ctrl_load_identity(c);
		if (ret)
			return ret;
		if (!c->attrs->firmware)
			c->attrs->firmware = NO_ATTR;
	}

	if (ATTR_IS_ABSENT(c->attrs->firmware))
		return -ENOENT;

	*val = c->attrs->firmware;
	return 0;
}

__shr_public void libnvme_ctrl_set_model(
		struct libnvme_ctrl *p,
		const char *model)
{
	ATTR_FREE(p->attrs->model);
	p->attrs->model = model ? strdup(model) : NO_ATTR;
}

__shr_public int libnvme_ctrl_get_model(
		const struct libnvme_ctrl *p,
		const char **val,
		const char *dflt)
{
	struct libnvme_ctrl *c = (struct libnvme_ctrl *)p;
	int ret;

	*val = dflt;

	if (__shr_unlikely(!ATTR_IS_LOADED(c->attrs->model))) {
		ret = libnvme_ctrl_load_identity(c);
		if (ret)
			return ret;
		if (!c->attrs->model)
			c->attrs->model = NO_ATTR;
	}

	if (ATTR_IS_ABSENT(c->attrs->model))
		return -ENOENT;

	*val = c->attrs->model;
	return 0;
}

__shr_public void libnvme_ctrl_set_serial(
		struct libnvme_ctrl *p,
		const char *serial)
{
	ATTR_FREE(p->attrs->serial);
	p->attrs->serial = serial ? strdup(serial) : NO_ATTR;
}

__shr_public int libnvme_ctrl_get_serial(
		const struct libnvme_ctrl *p,
		const char **val,
		const char *dflt)
{
	struct libnvme_ctrl *c = (struct libnvme_ctrl *)p;
	int ret;

	*val = dflt;

	if (__shr_unlikely(!ATTR_IS_LOADED(c->attrs->serial))) {
		ret = libnvme_ctrl_load_identity(c);
		if (ret)
			return ret;
		if (!c->attrs->serial)
			c->attrs->serial = NO_ATTR;
	}

	if (ATTR_IS_ABSENT(c->attrs->serial))
		return -ENOENT;

	*val = c->attrs->serial;
	return 0;
}

__shr_public void libnvme_ctrl_set_cntrltype(
		struct libnvme_ctrl *p,
		const char *cntrltype)
{
	ATTR_FREE(p->attrs->cntrltype);
	p->attrs->cntrltype = cntrltype ? strdup(cntrltype) : NO_ATTR;
}

__shr_public int libnvme_ctrl_get_cntrltype(
		const struct libnvme_ctrl *p,
		const char **val,
		const char *dflt)
{
	struct libnvme_ctrl *c = (struct libnvme_ctrl *)p;
	int ret;

	*val = dflt;

	if (__shr_unlikely(!ATTR_IS_LOADED(c->attrs->cntrltype))) {
		ret = libnvme_ctrl_load_identity(c);
		if (ret)
			return ret;
		if (!c->attrs->cntrltype)
			c->attrs->cntrltype = NO_ATTR;
	}

	if (ATTR_IS_ABSENT(c->attrs->cntrltype))
		return -ENOENT;

	*val = c->attrs->cntrltype;
	return 0;
}

__shr_public void libnvme_ctrl_set_cntlid(
		struct libnvme_ctrl *p,
		const char *cntlid)
{
	ATTR_FREE(p->attrs->cntlid);
	p->attrs->cntlid = cntlid ? strdup(cntlid) : NO_ATTR;
}

__shr_public int libnvme_ctrl_get_cntlid(
		const struct libnvme_ctrl *p,
		const char **val,
		const char *dflt)
{
	struct libnvme_ctrl *c = (struct libnvme_ctrl *)p;
	int ret;

	*val = dflt;

	if (__shr_unlikely(!ATTR_IS_LOADED(c->attrs->cntlid))) {
		ret = libnvme_ctrl_load_identity(c);
		if (ret)
			return ret;
		if (!c->attrs->cntlid)
			c->attrs->cntlid = NO_ATTR;
	}

	if (ATTR_IS_ABSENT(c->attrs->cntlid))
		return -ENOENT;

	*val = c->attrs->cntlid;
	return 0;
}

__shr_public void libnvme_ctrl_set_dctype(
		struct libnvme_ctrl *p,
		const char *dctype)
{
	ATTR_FREE(p->attrs->dctype);
	p->attrs->dctype = dctype ? strdup(dctype) : NO_ATTR;
}

__shr_public int libnvme_ctrl_get_dctype(
		const struct libnvme_ctrl *p,
		const char **val,
		const char *dflt)
{
	struct libnvme_ctrl *c = (struct libnvme_ctrl *)p;
	int ret;

	*val = dflt;

	if (__shr_unlikely(!ATTR_IS_LOADED(c->attrs->dctype))) {
		ret = libnvme_ctrl_load_identity(c);
		if (ret)
			return ret;
		if (!c->attrs->dctype)
			c->attrs->dctype = NO_ATTR;
	}

	if (ATTR_IS_ABSENT(c->attrs->dctype))
		return -ENOENT;

	*val = c->attrs->dctype;
	return 0;
}

__shr_public int libnvme_ctrl_get_phy_slot(
		const struct libnvme_ctrl *p,
		const char **val,
		const char *dflt)
{
	struct libnvme_ctrl *c = (struct libnvme_ctrl *)p;
	int ret;

	*val = dflt;

	if (__shr_unlikely(!ATTR_IS_LOADED(c->attrs->phy_slot))) {
		ret = libnvme_ctrl_load_phy_slot(c);
		if (ret)
			return ret;
		if (!c->attrs->phy_slot)
			c->attrs->phy_slot = NO_ATTR;
	}

	if (ATTR_IS_ABSENT(c->attrs->phy_slot))
		return -ENOENT;

	*val = c->attrs->phy_slot;
	return 0;
}

__shr_public void libnvme_ctrl_set_dhchap_host_key(
		struct libnvme_ctrl *p,
		const char *dhchap_host_key)
{
	ATTR_FREE(p->attrs->dhchap_host_key);
	p->attrs->dhchap_host_key =
		dhchap_host_key ? strdup(dhchap_host_key) : NO_ATTR;
}

__shr_public int libnvme_ctrl_get_dhchap_host_key(
		const struct libnvme_ctrl *p,
		const char **val,
		const char *dflt)
{
	struct libnvme_ctrl *c = (struct libnvme_ctrl *)p;
	int ret;

	*val = dflt;

	if (__shr_unlikely(!ATTR_IS_LOADED(c->attrs->dhchap_host_key))) {
		ret = libnvmf_ctrl_load_fabrics_attrs(c);
		if (ret)
			return ret;
		if (!c->attrs->dhchap_host_key)
			c->attrs->dhchap_host_key = NO_ATTR;
	}

	if (ATTR_IS_ABSENT(c->attrs->dhchap_host_key))
		return -ENOENT;

	*val = c->attrs->dhchap_host_key;
	return 0;
}

__shr_public void libnvme_ctrl_set_dhchap_ctrl_key(
		struct libnvme_ctrl *p,
		const char *dhchap_ctrl_key)
{
	ATTR_FREE(p->attrs->dhchap_ctrl_key);
	p->attrs->dhchap_ctrl_key =
		dhchap_ctrl_key ? strdup(dhchap_ctrl_key) : NO_ATTR;
}

__shr_public int libnvme_ctrl_get_dhchap_ctrl_key(
		const struct libnvme_ctrl *p,
		const char **val,
		const char *dflt)
{
	struct libnvme_ctrl *c = (struct libnvme_ctrl *)p;
	int ret;

	*val = dflt;

	if (__shr_unlikely(!ATTR_IS_LOADED(c->attrs->dhchap_ctrl_key))) {
		ret = libnvmf_ctrl_load_fabrics_attrs(c);
		if (ret)
			return ret;
		if (!c->attrs->dhchap_ctrl_key)
			c->attrs->dhchap_ctrl_key = NO_ATTR;
	}

	if (ATTR_IS_ABSENT(c->attrs->dhchap_ctrl_key))
		return -ENOENT;

	*val = c->attrs->dhchap_ctrl_key;
	return 0;
}

__shr_public void libnvme_ctrl_set_keyring(
		struct libnvme_ctrl *p,
		const char *keyring)
{
	ATTR_FREE(p->attrs->keyring);
	p->attrs->keyring = keyring ? strdup(keyring) : NO_ATTR;
}

__shr_public int libnvme_ctrl_get_keyring(
		const struct libnvme_ctrl *p,
		const char **val,
		const char *dflt)
{
	struct libnvme_ctrl *c = (struct libnvme_ctrl *)p;
	int ret;

	*val = dflt;

	if (__shr_unlikely(!ATTR_IS_LOADED(c->attrs->keyring))) {
		ret = libnvmf_ctrl_load_fabrics_attrs(c);
		if (ret)
			return ret;
		if (!c->attrs->keyring)
			c->attrs->keyring = NO_ATTR;
	}

	if (ATTR_IS_ABSENT(c->attrs->keyring))
		return -ENOENT;

	*val = c->attrs->keyring;
	return 0;
}

