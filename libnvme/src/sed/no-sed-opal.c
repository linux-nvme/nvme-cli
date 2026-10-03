// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libnvme.
 * Copyright (c) 2026 SUSE Software Solutions
 *
 * Authors: Daniel Wagner <dwagner@suse.de>
 */

#include <errno.h>

#include <shared/compiler-attributes-util.h>

#include <libnvme.h>
#include <libnvme-sed.h>

__shr_public int libnvme_sed_take_ownership(
		struct libnvme_transport_handle *hdl,
		const struct libnvme_sed_key *key)
{
	return -ENOTSUP;
}

__shr_public int libnvme_sed_activate_lsp(struct libnvme_transport_handle *hdl,
		const struct libnvme_sed_key *key)
{
	return -ENOTSUP;
}

__shr_public int libnvme_sed_setup_range(struct libnvme_transport_handle *hdl,
		const struct libnvme_sed_key *key, bool read_lock,
		bool write_lock)
{
	return -ENOTSUP;
}

__shr_public int libnvme_sed_lock_unlock(struct libnvme_transport_handle *hdl,
		const struct libnvme_sed_key *key,
		enum libnvme_sed_lock_state state)
{
	return -ENOTSUP;
}

__shr_public int libnvme_sed_set_password(struct libnvme_transport_handle *hdl,
		const struct libnvme_sed_key *key,
		const struct libnvme_sed_key *new_key)
{
	return -ENOTSUP;
}

__shr_public int libnvme_sed_set_sid_password(
		struct libnvme_transport_handle *hdl,
		const struct libnvme_sed_key *key,
		const struct libnvme_sed_key *new_key)
{
	return -ENOTSUP;
}

__shr_public int libnvme_sed_revert_tper(struct libnvme_transport_handle *hdl,
		const struct libnvme_sed_key *key)
{
	return -ENOTSUP;
}

__shr_public int libnvme_sed_revert_psid(struct libnvme_transport_handle *hdl,
		const struct libnvme_sed_key *psid)
{
	return -ENOTSUP;
}

__shr_public int libnvme_sed_revert_lsp(struct libnvme_transport_handle *hdl,
		const struct libnvme_sed_key *key, bool keep_data)
{
	return -ENOTSUP;
}
