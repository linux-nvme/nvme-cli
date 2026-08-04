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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <compiler-attributes.h>

#include "private.h"
#include "private-tree.h"
#include "ctrl-sysfs.h"

struct libnvme_ctrl_sysfs {
	char *numa_node;
	char *queue_count;
	char *sqsize;
	volatile long command_error_count;
	volatile long reset_count;
	volatile long reconnect_count;
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

struct libnvme_ctrl_sysfs *libnvme_ctrl_sysfs_alloc(void)
{
	return calloc(1, sizeof(struct libnvme_ctrl_sysfs));
}

void libnvme_ctrl_sysfs_reset(
		struct libnvme_ctrl_sysfs *sysfs)
{
	if (!sysfs)
		return;

	SYSFS_FREE(sysfs->numa_node);
	SYSFS_FREE(sysfs->queue_count);
	SYSFS_FREE(sysfs->sqsize);
	SYSFS_FREE(sysfs->firmware);
	SYSFS_FREE(sysfs->model);
	SYSFS_FREE(sysfs->serial);
	SYSFS_FREE(sysfs->cntrltype);
	SYSFS_FREE(sysfs->cntlid);
	SYSFS_FREE(sysfs->dctype);
	SYSFS_FREE(sysfs->phy_slot);
	SYSFS_FREE(sysfs->dhchap_host_key);
	SYSFS_FREE(sysfs->dhchap_ctrl_key);
	SYSFS_FREE(sysfs->keyring);
}

void libnvme_ctrl_sysfs_free(
		struct libnvme_ctrl_sysfs *sysfs)
{
	if (!sysfs)
		return;

	free(sysfs);
}

__shr_public const char *libnvme_ctrl_get_numa_node(
		const struct libnvme_ctrl *p)
{
	struct libnvme_ctrl *c = (struct libnvme_ctrl *)p;

	if (__shr_unlikely(!SYSFS_IS_LOADED(c->sysfs->numa_node))) {
		c->sysfs->numa_node = libnvme_get_ctrl_attr(c, "numa_node");
		if (!c->sysfs->numa_node)
			c->sysfs->numa_node = NO_SYSFS_ATTR;
	}

	return SYSFS_GET(c->sysfs->numa_node);
}

__shr_public const char *libnvme_ctrl_get_queue_count(
		const struct libnvme_ctrl *p)
{
	struct libnvme_ctrl *c = (struct libnvme_ctrl *)p;

	if (__shr_unlikely(!SYSFS_IS_LOADED(c->sysfs->queue_count))) {
		c->sysfs->queue_count = libnvme_get_ctrl_attr(c, "queue_count");
		if (!c->sysfs->queue_count)
			c->sysfs->queue_count = NO_SYSFS_ATTR;
	}

	return SYSFS_GET(c->sysfs->queue_count);
}

__shr_public const char *libnvme_ctrl_get_sqsize(const struct libnvme_ctrl *p)
{
	struct libnvme_ctrl *c = (struct libnvme_ctrl *)p;

	if (__shr_unlikely(!SYSFS_IS_LOADED(c->sysfs->sqsize))) {
		c->sysfs->sqsize = libnvme_get_ctrl_attr(c, "sqsize");
		if (!c->sysfs->sqsize)
			c->sysfs->sqsize = NO_SYSFS_ATTR;
	}

	return SYSFS_GET(c->sysfs->sqsize);
}

__shr_public long libnvme_ctrl_get_command_error_count(
		const struct libnvme_ctrl *p)
{
	struct libnvme_ctrl *c = (struct libnvme_ctrl *)p;
	char *val;

	val = libnvme_get_ctrl_attr(c, "diag/command_error_count");
	if (val)
		sscanf(val, "%ld", &c->sysfs->command_error_count);
	free(val);

	return c->sysfs->command_error_count;
}

__shr_public long libnvme_ctrl_get_reset_count(const struct libnvme_ctrl *p)
{
	struct libnvme_ctrl *c = (struct libnvme_ctrl *)p;
	char *val;

	val = libnvme_get_ctrl_attr(c, "diag/reset_count");
	if (val)
		sscanf(val, "%ld", &c->sysfs->reset_count);
	free(val);

	return c->sysfs->reset_count;
}

__shr_public long libnvme_ctrl_get_reconnect_count(const struct libnvme_ctrl *p)
{
	struct libnvme_ctrl *c = (struct libnvme_ctrl *)p;
	char *val;

	val = libnvme_get_ctrl_attr(c, "diag/reconnect_count");
	if (val)
		sscanf(val, "%ld", &c->sysfs->reconnect_count);
	free(val);

	return c->sysfs->reconnect_count;
}

__shr_public void libnvme_ctrl_set_firmware(
		struct libnvme_ctrl *p,
		const char *firmware)
{
	SYSFS_FREE(p->sysfs->firmware);
	p->sysfs->firmware = firmware ? strdup(firmware) : NO_SYSFS_ATTR;
}

__shr_public const char *libnvme_ctrl_get_firmware(const struct libnvme_ctrl *p)
{
	struct libnvme_ctrl *c = (struct libnvme_ctrl *)p;

	if (__shr_unlikely(!SYSFS_IS_LOADED(c->sysfs->firmware))) {
		libnvme_ctrl_load_identity(c);
		if (!c->sysfs->firmware)
			c->sysfs->firmware = NO_SYSFS_ATTR;
	}

	return SYSFS_GET(c->sysfs->firmware);
}

__shr_public void libnvme_ctrl_set_model(
		struct libnvme_ctrl *p,
		const char *model)
{
	SYSFS_FREE(p->sysfs->model);
	p->sysfs->model = model ? strdup(model) : NO_SYSFS_ATTR;
}

__shr_public const char *libnvme_ctrl_get_model(const struct libnvme_ctrl *p)
{
	struct libnvme_ctrl *c = (struct libnvme_ctrl *)p;

	if (__shr_unlikely(!SYSFS_IS_LOADED(c->sysfs->model))) {
		libnvme_ctrl_load_identity(c);
		if (!c->sysfs->model)
			c->sysfs->model = NO_SYSFS_ATTR;
	}

	return SYSFS_GET(c->sysfs->model);
}

__shr_public void libnvme_ctrl_set_serial(
		struct libnvme_ctrl *p,
		const char *serial)
{
	SYSFS_FREE(p->sysfs->serial);
	p->sysfs->serial = serial ? strdup(serial) : NO_SYSFS_ATTR;
}

__shr_public const char *libnvme_ctrl_get_serial(const struct libnvme_ctrl *p)
{
	struct libnvme_ctrl *c = (struct libnvme_ctrl *)p;

	if (__shr_unlikely(!SYSFS_IS_LOADED(c->sysfs->serial))) {
		libnvme_ctrl_load_identity(c);
		if (!c->sysfs->serial)
			c->sysfs->serial = NO_SYSFS_ATTR;
	}

	return SYSFS_GET(c->sysfs->serial);
}

__shr_public void libnvme_ctrl_set_cntrltype(
		struct libnvme_ctrl *p,
		const char *cntrltype)
{
	SYSFS_FREE(p->sysfs->cntrltype);
	p->sysfs->cntrltype = cntrltype ? strdup(cntrltype) : NO_SYSFS_ATTR;
}

__shr_public const char *libnvme_ctrl_get_cntrltype(
		const struct libnvme_ctrl *p)
{
	struct libnvme_ctrl *c = (struct libnvme_ctrl *)p;

	if (__shr_unlikely(!SYSFS_IS_LOADED(c->sysfs->cntrltype))) {
		libnvme_ctrl_load_identity(c);
		if (!c->sysfs->cntrltype)
			c->sysfs->cntrltype = NO_SYSFS_ATTR;
	}

	return SYSFS_GET(c->sysfs->cntrltype);
}

__shr_public void libnvme_ctrl_set_cntlid(
		struct libnvme_ctrl *p,
		const char *cntlid)
{
	SYSFS_FREE(p->sysfs->cntlid);
	p->sysfs->cntlid = cntlid ? strdup(cntlid) : NO_SYSFS_ATTR;
}

__shr_public const char *libnvme_ctrl_get_cntlid(const struct libnvme_ctrl *p)
{
	struct libnvme_ctrl *c = (struct libnvme_ctrl *)p;

	if (__shr_unlikely(!SYSFS_IS_LOADED(c->sysfs->cntlid))) {
		libnvme_ctrl_load_identity(c);
		if (!c->sysfs->cntlid)
			c->sysfs->cntlid = NO_SYSFS_ATTR;
	}

	return SYSFS_GET(c->sysfs->cntlid);
}

__shr_public void libnvme_ctrl_set_dctype(
		struct libnvme_ctrl *p,
		const char *dctype)
{
	SYSFS_FREE(p->sysfs->dctype);
	p->sysfs->dctype = dctype ? strdup(dctype) : NO_SYSFS_ATTR;
}

__shr_public const char *libnvme_ctrl_get_dctype(const struct libnvme_ctrl *p)
{
	struct libnvme_ctrl *c = (struct libnvme_ctrl *)p;

	if (__shr_unlikely(!SYSFS_IS_LOADED(c->sysfs->dctype))) {
		libnvme_ctrl_load_identity(c);
		if (!c->sysfs->dctype)
			c->sysfs->dctype = NO_SYSFS_ATTR;
	}

	return SYSFS_GET(c->sysfs->dctype);
}

__shr_public const char *libnvme_ctrl_get_phy_slot(const struct libnvme_ctrl *p)
{
	struct libnvme_ctrl *c = (struct libnvme_ctrl *)p;

	if (__shr_unlikely(!SYSFS_IS_LOADED(c->sysfs->phy_slot))) {
		libnvme_ctrl_load_phy_slot(c);
		if (!c->sysfs->phy_slot)
			c->sysfs->phy_slot = NO_SYSFS_ATTR;
	}

	return SYSFS_GET(c->sysfs->phy_slot);
}

__shr_public void libnvme_ctrl_set_dhchap_host_key(
		struct libnvme_ctrl *p,
		const char *dhchap_host_key)
{
	SYSFS_FREE(p->sysfs->dhchap_host_key);
	p->sysfs->dhchap_host_key =
		dhchap_host_key ? strdup(dhchap_host_key) : NO_SYSFS_ATTR;
}

__shr_public const char *libnvme_ctrl_get_dhchap_host_key(
		const struct libnvme_ctrl *p)
{
	struct libnvme_ctrl *c = (struct libnvme_ctrl *)p;

	if (__shr_unlikely(!SYSFS_IS_LOADED(c->sysfs->dhchap_host_key))) {
		libnvmf_ctrl_load_fabrics_attrs(c);
		if (!c->sysfs->dhchap_host_key)
			c->sysfs->dhchap_host_key = NO_SYSFS_ATTR;
	}

	return SYSFS_GET(c->sysfs->dhchap_host_key);
}

__shr_public void libnvme_ctrl_set_dhchap_ctrl_key(
		struct libnvme_ctrl *p,
		const char *dhchap_ctrl_key)
{
	SYSFS_FREE(p->sysfs->dhchap_ctrl_key);
	p->sysfs->dhchap_ctrl_key =
		dhchap_ctrl_key ? strdup(dhchap_ctrl_key) : NO_SYSFS_ATTR;
}

__shr_public const char *libnvme_ctrl_get_dhchap_ctrl_key(
		const struct libnvme_ctrl *p)
{
	struct libnvme_ctrl *c = (struct libnvme_ctrl *)p;

	if (__shr_unlikely(!SYSFS_IS_LOADED(c->sysfs->dhchap_ctrl_key))) {
		libnvmf_ctrl_load_fabrics_attrs(c);
		if (!c->sysfs->dhchap_ctrl_key)
			c->sysfs->dhchap_ctrl_key = NO_SYSFS_ATTR;
	}

	return SYSFS_GET(c->sysfs->dhchap_ctrl_key);
}

__shr_public void libnvme_ctrl_set_keyring(
		struct libnvme_ctrl *p,
		const char *keyring)
{
	SYSFS_FREE(p->sysfs->keyring);
	p->sysfs->keyring = keyring ? strdup(keyring) : NO_SYSFS_ATTR;
}

__shr_public const char *libnvme_ctrl_get_keyring(const struct libnvme_ctrl *p)
{
	struct libnvme_ctrl *c = (struct libnvme_ctrl *)p;

	if (__shr_unlikely(!SYSFS_IS_LOADED(c->sysfs->keyring))) {
		libnvmf_ctrl_load_fabrics_attrs(c);
		if (!c->sysfs->keyring)
			c->sysfs->keyring = NO_SYSFS_ATTR;
	}

	return SYSFS_GET(c->sysfs->keyring);
}

