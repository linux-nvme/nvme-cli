// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libnvme.
 * Copyright (c) 2026, Dell Technologies Inc. or its subsidiaries.
 *
 * Authors: Martin Belanger <Martin.Belanger@dell.com>
 */

#include <ccan/endian/endian.h>
#include <ccan/ilog/ilog.h>
#include <dirent.h>
#include <errno.h>

#include "cleanup-linux.h"
#include "lib.h"
#include "mem.h"
#include "util.h"

#include "generated/attr-accessors.c"
#include "generated/attr-accessors-linux.c"

#ifdef CONFIG_FABRICS
int libnvmf_ctrl_load_fabrics_attrs(struct libnvme_ctrl *c)
{
	__cleanup_free char *tls_key = NULL;
	char *host_key, *ctrl_key;

	host_key = libnvme_get_ctrl_attr(c, "dhchap_secret");
	if (host_key && !strcmp(host_key, "none")) {
		free(host_key);
		host_key = NULL;
	}
	if (host_key) {
		ATTR_FREE(c->attrs->dhchap_host_key);
		c->attrs->dhchap_host_key = host_key;
	}

	ctrl_key = libnvme_get_ctrl_attr(c, "dhchap_ctrl_secret");
	if (ctrl_key && !strcmp(ctrl_key, "none")) {
		free(ctrl_key);
		ctrl_key = NULL;
	}
	if (ctrl_key) {
		ATTR_FREE(c->attrs->dhchap_ctrl_key);
		c->attrs->dhchap_ctrl_key = ctrl_key;
	}

	/*
	 * tls_key's presence gates keyring the same way it gates cfg's
	 * tls_key_id in tree-fabrics.c's libnvmf_read_sysfs_tls() -- read
	 * again here rather than threading state between the two, since
	 * cfg stays eager while this group is lazy.
	 */
	tls_key = libnvme_get_ctrl_attr(c, "tls_key");
	if (tls_key)
		c->attrs->keyring = libnvme_get_ctrl_attr(c, "tls_keyring");

	return 0;
}
#else
int libnvmf_ctrl_load_fabrics_attrs(__shr_unused struct libnvme_ctrl *c)
{
	return 0;
}
#endif

int libnvme_ctrl_load_identity(struct libnvme_ctrl *c)
{
	c->attrs->firmware = libnvme_get_ctrl_attr(c, "firmware_rev");
	c->attrs->model = libnvme_get_ctrl_attr(c, "model");
	c->attrs->serial = libnvme_get_ctrl_attr(c, "serial");
	c->attrs->cntrltype = libnvme_get_ctrl_attr(c, "cntrltype");
	c->attrs->cntlid = libnvme_get_ctrl_attr(c, "cntlid");
	c->attrs->dctype = libnvme_get_ctrl_attr(c, "dctype");

	return 0;
}

int libnvme_ctrl_load_phy_slot(struct libnvme_ctrl *c)
{
	const char *slots_sysfs_dir = libnvme_slots_sysfs_dir(c->ctx);
	__cleanup_free char *target_addr = NULL;
	__cleanup_dir DIR *slots_dir = NULL;
	struct dirent *entry;
	int ret;

	if (!c->address)
		return 0;

	slots_dir = opendir(slots_sysfs_dir);
	if (!slots_dir) {
		ret = -errno;
		libnvme_msg(c->ctx, LIBNVME_LOG_WARN,
			"failed to open slots dir %s\n", slots_sysfs_dir);
		return ret;
	}

	target_addr = strndup(c->address, 10);
	while ((entry = readdir(slots_dir))) {
		__cleanup_free char *path = NULL;
		__cleanup_free char *addr = NULL;

		if (entry->d_type != DT_DIR ||
		    !strncmp(entry->d_name, ".", 1) ||
		    !strncmp(entry->d_name, "..", 2))
			continue;

		ret = asprintf(&path, "%s/%s", slots_sysfs_dir, entry->d_name);
		if (ret < 0)
			return -ENOMEM;

		/* some directories don't have an address entry */
		addr = libnvme_get_attr(path, "address");
		if (!addr)
			continue;
		if (strcmp(addr, target_addr))
			continue;

		c->attrs->phy_slot = strdup(entry->d_name);
		return 0;
	}

	return 0;
}

/*
 * No "csi" attribute: lba_count/lba_util/meta_size come from one
 * Identify Namespace command instead. Each field's own
 * ATTR_IS_LOADED() check keeps a caller that only reads one of these
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

	if (!ATTR_IS_LOADED(n->attrs->lba_count)) {
		n->attrs->lba_count = malloc(sizeof(uint64_t));
		if (!n->attrs->lba_count)
			return -ENOMEM;
		*n->attrs->lba_count = le64_to_cpu(id->nsze);
	}

	if (!ATTR_IS_LOADED(n->attrs->lba_util)) {
		n->attrs->lba_util = malloc(sizeof(uint64_t));
		if (!n->attrs->lba_util)
			return -ENOMEM;
		*n->attrs->lba_util = le64_to_cpu(id->nuse);
	}

	if (!ATTR_IS_LOADED(n->attrs->meta_size)) {
		n->attrs->meta_size = malloc(sizeof(int));
		if (!n->attrs->meta_size)
			return -ENOMEM;
		*n->attrs->meta_size = le16_to_cpu(id->lbaf[flbas].ms);
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

	n->attrs->lba_count = malloc(sizeof(uint64_t));
	if (!n->attrs->lba_count)
		return -ENOMEM;

	*n->attrs->lba_count = size >> (lba_shift - SECTOR_SHIFT);
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

	n->attrs->lba_util = malloc(sizeof(uint64_t));
	if (!n->attrs->lba_util)
		return -ENOMEM;

	*n->attrs->lba_util = val;
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

	n->attrs->meta_size = malloc(sizeof(int));
	if (!n->attrs->meta_size)
		return -ENOMEM;

	*n->attrs->meta_size = (int)val;
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

	if (__shr_unlikely(!ATTR_IS_LOADED(n->attrs->lba_size))) {
		str = libnvme_get_ns_attr(n, "queue/logical_block_size");
		if (!str)
			n->attrs->lba_size = (int *)NO_ATTR;
		else {
			n->attrs->lba_size = malloc(sizeof(int));
			if (!n->attrs->lba_size)
				return -ENOMEM;
			if (sscanf(str, "%d", n->attrs->lba_size) != 1) {
				free(n->attrs->lba_size);
				n->attrs->lba_size = NULL;
				return -EINVAL;
			}
		}
	}

	if (ATTR_IS_ABSENT(n->attrs->lba_size))
		return -ENOENT;

	*val = *n->attrs->lba_size;
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
	int has_csi, ret;

	*val = dflt;

	if (__shr_unlikely(!ATTR_IS_LOADED(n->attrs->lba_count))) {
		has_csi = ns_csi_attr_exists(n);
		if (has_csi < 0)
			return has_csi;

		if (has_csi)
			ret = ns_load_lba_count_from_size_attr(n);
		else
			ret = ns_identify_geometry(n);
		if (ret)
			return ret;
		if (!n->attrs->lba_count)
			n->attrs->lba_count = (uint64_t *)NO_ATTR;
	}

	if (ATTR_IS_ABSENT(n->attrs->lba_count))
		return -ENOENT;

	*val = *n->attrs->lba_count;
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

	if (__shr_unlikely(!ATTR_IS_LOADED(n->attrs->lba_util))) {
		has_csi = ns_csi_attr_exists(n);
		if (has_csi < 0)
			return has_csi;

		if (has_csi)
			ret = ns_load_lba_util_attr(n);
		else
			ret = ns_identify_geometry(n);
		if (ret)
			return ret;
		if (!n->attrs->lba_util)
			n->attrs->lba_util = (uint64_t *)NO_ATTR;
	}

	if (ATTR_IS_ABSENT(n->attrs->lba_util))
		return -ENOENT;

	*val = *n->attrs->lba_util;
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

	if (__shr_unlikely(!ATTR_IS_LOADED(n->attrs->meta_size))) {
		has_csi = ns_csi_attr_exists(n);
		if (has_csi < 0)
			return has_csi;

		if (has_csi)
			ret = ns_load_meta_size_attr(n);
		else
			ret = ns_identify_geometry(n);
		if (ret)
			return ret;
		if (!n->attrs->meta_size)
			n->attrs->meta_size = (int *)NO_ATTR;
	}

	if (ATTR_IS_ABSENT(n->attrs->meta_size))
		return -ENOENT;

	*val = *n->attrs->meta_size;
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

	if (__shr_unlikely(!ATTR_IS_LOADED(n->attrs->csi))) {
		str = libnvme_get_ns_attr(n, "csi");
		if (!str) {
			n->attrs->csi = (enum nvme_csi *)NO_ATTR;
		} else {
			n->attrs->csi = malloc(sizeof(enum nvme_csi));
			if (!n->attrs->csi)
				return -ENOMEM;

			if (sscanf(str, "%d", (int *)n->attrs->csi) != 1) {
				free(n->attrs->csi);
				n->attrs->csi = NULL;
				return -EINVAL;
			}
		}
	}

	if (ATTR_IS_ABSENT(n->attrs->csi))
		return -ENOENT;

	*val = *n->attrs->csi;
	return 0;
}

/*
 * eui64/nguid/uuid each live in their own optional sysfs attribute,
 * read lazily and independently on first use, and cached for the
 * lifetime of the namespace object -- the returned pointer stays valid
 * until the namespace is freed, same lifetime guarantee every other
 * pointer-returning lazy getter (e.g. libnvme_ctrl_get_model()) already
 * gives its caller. "eui" is raw text copied byte-for-byte;
 * "nguid"/"uuid" are hyphenated hex strings decoded with
 * libnvme_uuid_from_string(), the same helper used everywhere else a
 * UUID-shaped attribute is parsed.
 */
__shr_public int libnvme_ns_get_eui64(
		const struct libnvme_ns *p,
		const uint8_t **val,
		const uint8_t *dflt)
{
	struct libnvme_ns *n = (struct libnvme_ns *)p;
	__cleanup_free char *str = NULL;

	*val = dflt;

	if (__shr_unlikely(!ATTR_IS_LOADED(n->attrs->eui64))) {
		str = libnvme_get_ns_attr(n, "eui");
		if (!str) {
			n->attrs->eui64 = (uint8_t *)NO_ATTR;
		} else {
			n->attrs->eui64 = malloc(8);
			if (!n->attrs->eui64)
				return -ENOMEM;
			memcpy(n->attrs->eui64, str, 8);
		}
	}

	if (ATTR_IS_ABSENT(n->attrs->eui64))
		return -ENOENT;

	*val = n->attrs->eui64;
	return 0;
}

__shr_public int libnvme_ns_get_nguid(
		const struct libnvme_ns *p,
		const uint8_t **val,
		const uint8_t *dflt)
{
	struct libnvme_ns *n = (struct libnvme_ns *)p;
	__cleanup_free char *str = NULL;

	*val = dflt;

	if (__shr_unlikely(!ATTR_IS_LOADED(n->attrs->nguid))) {
		str = libnvme_get_ns_attr(n, "nguid");
		if (!str) {
			n->attrs->nguid = (uint8_t *)NO_ATTR;
		} else {
			n->attrs->nguid = malloc(16);
			if (!n->attrs->nguid)
				return -ENOMEM;
			if (libnvme_uuid_from_string(str, n->attrs->nguid)) {
				free(n->attrs->nguid);
				n->attrs->nguid = NULL;
				return -EINVAL;
			}
		}
	}

	if (ATTR_IS_ABSENT(n->attrs->nguid))
		return -ENOENT;

	*val = n->attrs->nguid;
	return 0;
}

__shr_public int libnvme_ns_get_uuid(
		const struct libnvme_ns *p,
		const unsigned char **val,
		const unsigned char *dflt)
{
	struct libnvme_ns *n = (struct libnvme_ns *)p;
	__cleanup_free char *str = NULL;

	*val = dflt;

	if (__shr_unlikely(!ATTR_IS_LOADED(n->attrs->uuid))) {
		str = libnvme_get_ns_attr(n, "uuid");
		if (!str) {
			n->attrs->uuid = (unsigned char *)NO_ATTR;
		} else {
			n->attrs->uuid = malloc(NVME_UUID_LEN);
			if (!n->attrs->uuid)
				return -ENOMEM;
			if (libnvme_uuid_from_string(str, n->attrs->uuid)) {
				free(n->attrs->uuid);
				n->attrs->uuid = NULL;
				return -EINVAL;
			}
		}
	}

	if (ATTR_IS_ABSENT(n->attrs->uuid))
		return -ENOENT;

	*val = n->attrs->uuid;
	return 0;
}
