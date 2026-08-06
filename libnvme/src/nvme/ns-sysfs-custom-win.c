// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libnvme.
 * Copyright (c) 2026, Dell Technologies Inc. or its subsidiaries.
 *
 * Authors: Martin Belanger <Martin.Belanger@dell.com>
 */

#include <ccan/endian/endian.h>
#include <ccan/ilog/ilog.h>

#include "mem.h"

#include "ns-sysfs.c"

/*
 * Windows has no sysfs: lba_size/lba_count/lba_util/meta_size all come
 * from one Identify Namespace command, matching what libnvme_ns_init()
 * used to do eagerly before this conversion. Each field's own
 * SYSFS_IS_LOADED() check keeps a caller that only reads one of these
 * four from paying for more than one Identify command in the common
 * case, but a prior call can leave some fields loaded and others not
 * (e.g. -ENOMEM after lba_count's malloc but before lba_util's) --
 * guard each field here too, so a retry never re-mallocs an
 * already-loaded field and leaks the old allocation.
 */
static int ns_win_load_geometry(struct libnvme_ns *n)
{
	__cleanup_libnvme_free struct nvme_id_ns *id = NULL;
	uint8_t flbas;
	int ret;

	id = libnvme_alloc(sizeof(*id));
	if (!id)
		return -ENOMEM;

	ret = libnvme_ns_identify(n, id);
	if (ret)
		return ret;

	nvme_id_ns_flbas_to_lbaf_inuse(id->flbas, &flbas);

	if (!SYSFS_IS_LOADED(n->sysfs->lba_size)) {
		n->sysfs->lba_size = malloc(sizeof(int));
		if (!n->sysfs->lba_size)
			return -ENOMEM;
		*n->sysfs->lba_size = 1 << id->lbaf[flbas].ds;
	}

	if (!SYSFS_IS_LOADED(n->sysfs->lba_count)) {
		n->sysfs->lba_count = malloc(sizeof(uint64_t));
		if (!n->sysfs->lba_count)
			return -ENOMEM;
		*n->sysfs->lba_count = le64_to_cpu(id->nsze);
	}

	if (!SYSFS_IS_LOADED(n->sysfs->lba_util)) {
		n->sysfs->lba_util = malloc(sizeof(uint64_t));
		if (!n->sysfs->lba_util)
			return -ENOMEM;
		*n->sysfs->lba_util = le64_to_cpu(id->nuse);
	}

	if (!SYSFS_IS_LOADED(n->sysfs->meta_size)) {
		n->sysfs->meta_size = malloc(sizeof(int));
		if (!n->sysfs->meta_size)
			return -ENOMEM;
		*n->sysfs->meta_size = le16_to_cpu(id->lbaf[flbas].ms);
	}

	return 0;
}

__shr_public int libnvme_ns_get_lba_size(
		const struct libnvme_ns *p,
		int *val,
		int dflt)
{
	struct libnvme_ns *n = (struct libnvme_ns *)p;
	int ret;

	*val = dflt;

	if (__shr_unlikely(!SYSFS_IS_LOADED(n->sysfs->lba_size))) {
		ret = ns_win_load_geometry(n);
		if (ret)
			return ret;
		if (!n->sysfs->lba_size)
			n->sysfs->lba_size = (int *)NO_SYSFS_ATTR;
	}

	if (SYSFS_IS_ABSENT(n->sysfs->lba_size))
		return -ENOENT;

	*val = *n->sysfs->lba_size;
	return 0;
}

/* Pure derivation, no field of its own -- identical to the Linux body,
 * since it only depends on lba_size's own (already per-OS-resolved)
 * getter, never on sysfs directly.
 */
__shr_public int libnvme_ns_get_lba_shift(
		const struct libnvme_ns *p,
		int *val,
		int dflt)
{
	int lba_size;
	int ret;

	*val = dflt;

	ret = libnvme_ns_get_lba_size(p, &lba_size, 0);
	if (ret)
		return ret;

	/* lba_size is a power of two (NVMe LBADS is defined as an
	 * exponent, 2^n), so it has exactly one bit set -- ilog32()
	 * reports the position of that bit, i.e. the shift.
	 */
	*val = ilog32(lba_size) - 1;
	return 0;
}

__shr_public int libnvme_ns_get_lba_count(
		const struct libnvme_ns *p,
		uint64_t *val,
		uint64_t dflt)
{
	struct libnvme_ns *n = (struct libnvme_ns *)p;
	int ret;

	*val = dflt;

	if (__shr_unlikely(!SYSFS_IS_LOADED(n->sysfs->lba_count))) {
		ret = ns_win_load_geometry(n);
		if (ret)
			return ret;
		if (!n->sysfs->lba_count)
			n->sysfs->lba_count = (uint64_t *)NO_SYSFS_ATTR;
	}

	if (SYSFS_IS_ABSENT(n->sysfs->lba_count))
		return -ENOENT;

	*val = *n->sysfs->lba_count;
	return 0;
}

__shr_public int libnvme_ns_get_lba_util(
		const struct libnvme_ns *p,
		uint64_t *val,
		uint64_t dflt)
{
	struct libnvme_ns *n = (struct libnvme_ns *)p;
	int ret;

	*val = dflt;

	if (__shr_unlikely(!SYSFS_IS_LOADED(n->sysfs->lba_util))) {
		ret = ns_win_load_geometry(n);
		if (ret)
			return ret;
		if (!n->sysfs->lba_util)
			n->sysfs->lba_util = (uint64_t *)NO_SYSFS_ATTR;
	}

	if (SYSFS_IS_ABSENT(n->sysfs->lba_util))
		return -ENOENT;

	*val = *n->sysfs->lba_util;
	return 0;
}

__shr_public int libnvme_ns_get_meta_size(
		const struct libnvme_ns *p,
		int *val,
		int dflt)
{
	struct libnvme_ns *n = (struct libnvme_ns *)p;
	int ret;

	*val = dflt;

	if (__shr_unlikely(!SYSFS_IS_LOADED(n->sysfs->meta_size))) {
		ret = ns_win_load_geometry(n);
		if (ret)
			return ret;
		if (!n->sysfs->meta_size)
			n->sysfs->meta_size = (int *)NO_SYSFS_ATTR;
	}

	if (SYSFS_IS_ABSENT(n->sysfs->meta_size))
		return -ENOENT;

	*val = *n->sysfs->meta_size;
	return 0;
}

/*
 * Windows never had a source for csi -- the old eager code left it at
 * its zero-initialized default (NVME_CSI_NVM) always, never really
 * populating it. Report -ENOENT: honest absence beats a fabricated
 * value.
 */
__shr_public int libnvme_ns_get_csi(
		__shr_unused const struct libnvme_ns *p,
		enum nvme_csi *val,
		enum nvme_csi dflt)
{
	*val = dflt;

	return -ENOENT;
}
