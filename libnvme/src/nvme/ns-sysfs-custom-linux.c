// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libnvme.
 * Copyright (c) 2026, Dell Technologies Inc. or its subsidiaries.
 *
 * Authors: Martin Belanger <Martin.Belanger@dell.com>
 */

#include <ccan/endian/endian.h>

#include "mem.h"

#include "ns-sysfs.c"

#define GETSHIFT(x) (__builtin_ffsll(x) - 1)

/*
 * No "csi" attribute: lba_count/lba_util/meta_size come from one
 * Identify Namespace command instead. Each field's own
 * SYSFS_IS_LOADED() check keeps a caller that only reads one of these
 * three from paying for more than one Identify command in the common
 * case, but a prior call can leave some fields loaded and others not
 * (e.g. -ENOMEM after lba_count's malloc but before lba_util's) --
 * guard each field here too, so a retry never re-mallocs an
 * already-loaded field and leaks the old allocation.
 */
static int ns_identify_geometry(struct libnvme_ns *n)
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

/*
 * "size" is in 512-byte units and lba_count is in lba_size units, which
 * are not necessarily the same -- matches the shift math libnvme_ns_init()
 * used to do unconditionally before this conversion.
 */
static int ns_load_lba_count_from_size_attr(struct libnvme_ns *n)
{
	__cleanup_free char *str = NULL;
	char *endptr;
	int lba_shift;
	uint64_t size;
	int ret;

	str = libnvme_get_ns_attr(n, "size");
	if (!str)
		return -ENOENT;

	errno = 0;
	size = strtoull(str, &endptr, 0);
	if (errno != 0)
		return -errno;
	if (endptr == str)
		return -EINVAL;

	ret = libnvme_ns_get_lba_shift(n, &lba_shift, 0);
	if (ret)
		return ret;

	n->sysfs->lba_count = malloc(sizeof(uint64_t));
	if (!n->sysfs->lba_count)
		return -ENOMEM;

	*n->sysfs->lba_count = size >> (lba_shift - SECTOR_SHIFT);
	return 0;
}

static int ns_load_lba_util_attr(struct libnvme_ns *n)
{
	__cleanup_free char *str = NULL;
	char *endptr;
	uint64_t val;

	str = libnvme_get_ns_attr(n, "nuse");
	if (!str)
		return -ENOENT;

	errno = 0;
	val = strtoull(str, &endptr, 0);
	if (errno != 0)
		return -errno;
	if (endptr == str)
		return -EINVAL;

	n->sysfs->lba_util = malloc(sizeof(uint64_t));
	if (!n->sysfs->lba_util)
		return -ENOMEM;

	*n->sysfs->lba_util = val;
	return 0;
}

static int ns_load_meta_size_attr(struct libnvme_ns *n)
{
	__cleanup_free char *str = NULL;
	char *endptr;
	long val;

	str = libnvme_get_ns_attr(n, "metadata_bytes");
	if (!str)
		return -ENOENT;

	errno = 0;
	val = strtol(str, &endptr, 0);
	if (errno != 0)
		return -errno;
	if (endptr == str)
		return -EINVAL;

	n->sysfs->meta_size = malloc(sizeof(int));
	if (!n->sysfs->meta_size)
		return -ENOMEM;

	*n->sysfs->meta_size = (int)val;
	return 0;
}

/*
 * The "csi" sysfs attribute exists on newer kernels only; its
 * presence decides how the lba/metadata attributes are read.
 *
 * Return: 1 if present, 0 if absent, or a negative errno on a real
 * failure reading it (not just absence).
 */
static int ns_csi_attr_exists(struct libnvme_ns *n)
{
	enum nvme_csi csi;
	int ret;

	ret = libnvme_ns_get_csi(n, &csi, NVME_CSI_NVM);
	if (ret == -ENOENT)
		return 0;
	if (ret)
		return ret;

	return 1;
}

/*
 * Read unconditionally, regardless of whether "csi" exists -- unlike
 * lba_count/lba_util/meta_size/csi, this attribute isn't gated by it.
 */
__shr_public int libnvme_ns_get_lba_size(
		const struct libnvme_ns *p,
		int *val,
		int dflt)
{
	struct libnvme_ns *n = (struct libnvme_ns *)p;
	__cleanup_free char *str = NULL;

	*val = dflt;

	if (__shr_unlikely(!SYSFS_IS_LOADED(n->sysfs->lba_size))) {
		str = libnvme_get_ns_attr(n, "queue/logical_block_size");
		if (!str)
			n->sysfs->lba_size = (int *)NO_SYSFS_ATTR;
		else {
			n->sysfs->lba_size = malloc(sizeof(int));
			if (!n->sysfs->lba_size)
				return -ENOMEM;
			if (sscanf(str, "%d", n->sysfs->lba_size) != 1) {
				free(n->sysfs->lba_size);
				n->sysfs->lba_size = NULL;
				return -EINVAL;
			}
		}
	}

	if (SYSFS_IS_ABSENT(n->sysfs->lba_size))
		return -ENOENT;

	*val = *n->sysfs->lba_size;
	return 0;
}

/* Pure derivation, no field of its own -- recomputed every call from
 * lba_size's own (already cached) getter.
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

	*val = GETSHIFT(lba_size);
	return 0;
}

__shr_public int libnvme_ns_get_lba_count(
		const struct libnvme_ns *p,
		uint64_t *val,
		uint64_t dflt)
{
	struct libnvme_ns *n = (struct libnvme_ns *)p;
	int has_csi, ret;

	*val = dflt;

	if (__shr_unlikely(!SYSFS_IS_LOADED(n->sysfs->lba_count))) {
		has_csi = ns_csi_attr_exists(n);
		if (has_csi < 0)
			return has_csi;

		if (has_csi)
			ret = ns_load_lba_count_from_size_attr(n);
		else
			ret = ns_identify_geometry(n);
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
	int has_csi, ret;

	*val = dflt;

	if (__shr_unlikely(!SYSFS_IS_LOADED(n->sysfs->lba_util))) {
		has_csi = ns_csi_attr_exists(n);
		if (has_csi < 0)
			return has_csi;

		if (has_csi)
			ret = ns_load_lba_util_attr(n);
		else
			ret = ns_identify_geometry(n);
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
	int has_csi, ret;

	*val = dflt;

	if (__shr_unlikely(!SYSFS_IS_LOADED(n->sysfs->meta_size))) {
		has_csi = ns_csi_attr_exists(n);
		if (has_csi < 0)
			return has_csi;

		if (has_csi)
			ret = ns_load_meta_size_attr(n);
		else
			ret = ns_identify_geometry(n);
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

__shr_public int libnvme_ns_get_csi(
		const struct libnvme_ns *p,
		enum nvme_csi *val,
		enum nvme_csi dflt)
{
	struct libnvme_ns *n = (struct libnvme_ns *)p;
	__cleanup_free char *str = NULL;

	*val = dflt;

	if (__shr_unlikely(!SYSFS_IS_LOADED(n->sysfs->csi))) {
		str = libnvme_get_ns_attr(n, "csi");
		if (!str) {
			n->sysfs->csi = (enum nvme_csi *)NO_SYSFS_ATTR;
		} else {
			n->sysfs->csi = malloc(sizeof(enum nvme_csi));
			if (!n->sysfs->csi)
				return -ENOMEM;

			if (sscanf(str, "%d", (int *)n->sysfs->csi) != 1) {
				free(n->sysfs->csi);
				n->sysfs->csi = NULL;
				return -EINVAL;
			}
		}
	}

	if (SYSFS_IS_ABSENT(n->sysfs->csi))
		return -ENOENT;

	*val = *n->sysfs->csi;
	return 0;
}
