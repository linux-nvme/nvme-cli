// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libnvme.
 * Copyright (c) 2026 SUSE Software Solutions
 *
 * Authors: Daniel Wagner <dwagner@suse.de>
 */

#include <stddef.h>

#include <ccan/minmax/minmax.h>

#include <shared/compiler-attributes-util.h>

#include <libnvme.h>
#include <libnvme-sed.h>
#include <nvme/endian.h>

_Static_assert(sizeof(struct tcg_l0_header) == 48, "tcg_l0_header size");
_Static_assert(sizeof(struct tcg_l0_desc) == 4, "tcg_l0_desc size");
_Static_assert(sizeof(struct tcg_l0_geometry) == 28, "tcg_l0_geometry size");
_Static_assert(sizeof(struct tcg_l0_opal_v2) == 16, "tcg_l0_opal_v2 size");
_Static_assert(offsetof(struct tcg_l0_opal_v2, num_locking_sp_admin_auth) == 5,
	       "tcg_l0_opal_v2 num_locking_sp_admin_auth offset");
_Static_assert(offsetof(struct tcg_l0_opal_v2, initial_cpin_sid_ind) == 9,
	       "tcg_l0_opal_v2 initial_cpin_sid_ind offset");
_Static_assert(sizeof(struct tcg_l0_opalite) == 16, "tcg_l0_opalite size");
_Static_assert(sizeof(struct tcg_l0_pyrite_v2) == 16, "tcg_l0_pyrite_v2 size");
_Static_assert(sizeof(struct tcg_l0_ruby) == 16, "tcg_l0_ruby size");
_Static_assert(sizeof(struct tcg_l0_cnl) == 16, "tcg_l0_cnl size");
_Static_assert(sizeof(struct tcg_l0_data_removal) == 32,
	       "tcg_l0_data_removal size");
_Static_assert(offsetof(struct tcg_l0_data_removal, time_mechanism_bit5) == 14,
	       "tcg_l0_data_removal time_mechanism_bit5 offset");

__shr_public int libnvme_sed_discover(struct libnvme_transport_handle *hdl,
		void *buf, __u32 len)
{
	struct libnvme_passthru_cmd cmd;

	nvme_init_security_receive(&cmd, 0, 0, TCG_L0_DISCOVERY_COMID,
			TCG_L0_DISCOVERY_SECP, len, buf, len);

	return libnvme_exec_admin_passthru(hdl, &cmd);
}

__shr_public struct tcg_l0_desc *libnvme_sed_l0_next(void *buf, size_t len,
		struct tcg_l0_desc *desc)
{
	struct tcg_l0_header *hdr = buf;
	__u8 *end, *pos;

	if (len < sizeof(*hdr))
		return NULL;

	/* the length excludes the length field itself */
	end = (__u8 *)buf + min_t(__u64,
		(__u64)be32toh(hdr->length) + sizeof(hdr->length), len);

	if (desc)
		pos = (__u8 *)libnvme_sed_l0_data(desc) + desc->length;
	else
		pos = (__u8 *)(hdr + 1);

	if (pos + sizeof(*desc) > end)
		return NULL;

	desc = (struct tcg_l0_desc *)pos;
	if ((__u8 *)libnvme_sed_l0_data(desc) + desc->length > end)
		return NULL;

	return desc;
}

__shr_public struct tcg_l0_desc *libnvme_sed_l0_find(void *buf, size_t len,
		__u16 code)
{
	struct tcg_l0_desc *desc;

	libnvme_sed_l0_for_each(desc, buf, len) {
		if (be16toh(desc->code) == code)
			return desc;
	}

	return NULL;
}
