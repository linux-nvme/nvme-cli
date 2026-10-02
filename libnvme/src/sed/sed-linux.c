// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libnvme.
 * Copyright (c) 2026 SUSE Software Solutions
 *
 * Authors: Daniel Wagner <dwagner@suse.de>
 */

#include <errno.h>
#include <string.h>

#include <sys/ioctl.h>

#include <linux/sed-opal.h>

#include <shared/compiler-attributes-util.h>

#include <libnvme.h>
#include <libnvme-sed.h>

_Static_assert(sizeof(((struct opal_key *)0)->key) >= LIBNVME_SED_KEY_MAX,
	"opal_key too small for libnvme_sed_key");

static int sed_opal_key(struct opal_key *okey,
		const struct libnvme_sed_key *key)
{
	memset(okey, 0, sizeof(*okey));

	switch (key->type) {
	case LIBNVME_SED_KEY_INCLUDED:
		okey->key_len = key->len;
		memcpy(okey->key, key->key, key->len);
		break;
#if NVME_HAVE_KEY_TYPE
	case LIBNVME_SED_KEY_KEYRING:
		okey->key_type = OPAL_KEYRING;
		break;
#endif
	default:
		return -ENOTSUP;
	}

	return 0;
}

static int sed_opal_session(struct opal_session_info *session,
		const struct libnvme_sed_key *key)
{
	session->sum = 0;
	session->who = OPAL_ADMIN1;

	return sed_opal_key(&session->opal_key, key);
}

/*
 * The kernel returns a negative errno for its own failures and a
 * positive TCG method status if the TPer rejected the method.
 */
static int sed_opal_ioctl(struct libnvme_transport_handle *hdl,
		unsigned long req, void *arg)
{
	int ret;

	if (!libnvme_transport_handle_is_ns(hdl))
		return -EINVAL;

	ret = ioctl(libnvme_transport_handle_get_fd(hdl), req, arg);
	if (ret < 0)
		return -errno;

	return ret;
}

__shr_public int libnvme_sed_take_ownership(
		struct libnvme_transport_handle *hdl,
		const struct libnvme_sed_key *key)
{
	struct opal_key okey;
	int ret;

	ret = sed_opal_key(&okey, key);
	if (ret)
		return ret;

	return sed_opal_ioctl(hdl, IOC_OPAL_TAKE_OWNERSHIP, &okey);
}

__shr_public int libnvme_sed_activate_lsp(struct libnvme_transport_handle *hdl,
		const struct libnvme_sed_key *key)
{
	struct opal_lr_act act = {};
	int ret;

	ret = sed_opal_key(&act.key, key);
	if (ret)
		return ret;

	/* lr[0] is zero, which selects the global locking range */
	act.num_lrs = 1;

	return sed_opal_ioctl(hdl, IOC_OPAL_ACTIVATE_LSP, &act);
}

__shr_public int libnvme_sed_setup_range(struct libnvme_transport_handle *hdl,
		const struct libnvme_sed_key *key, bool read_lock,
		bool write_lock)
{
	struct opal_user_lr_setup setup = {};
	int ret;

	ret = sed_opal_session(&setup.session, key);
	if (ret)
		return ret;

	setup.RLE = read_lock;
	setup.WLE = write_lock;

	return sed_opal_ioctl(hdl, IOC_OPAL_LR_SETUP, &setup);
}

__shr_public int libnvme_sed_lock_unlock(struct libnvme_transport_handle *hdl,
		const struct libnvme_sed_key *key,
		enum libnvme_sed_lock_state state)
{
	struct opal_lock_unlock lu = {};
	int ret;

	switch (state) {
	case LIBNVME_SED_LOCK_RO:
		lu.l_state = OPAL_RO;
		break;
	case LIBNVME_SED_LOCK_RW:
		lu.l_state = OPAL_RW;
		break;
	case LIBNVME_SED_LOCK_LK:
		lu.l_state = OPAL_LK;
		break;
	default:
		return -EINVAL;
	}

	ret = sed_opal_session(&lu.session, key);
	if (ret)
		return ret;

	return sed_opal_ioctl(hdl, IOC_OPAL_LOCK_UNLOCK, &lu);
}

static int sed_opal_new_pw(struct opal_new_pw *pw,
		const struct libnvme_sed_key *key,
		const struct libnvme_sed_key *new_key)
{
	int ret;

	memset(pw, 0, sizeof(*pw));

	ret = sed_opal_session(&pw->session, key);
	if (ret)
		return ret;

	return sed_opal_session(&pw->new_user_pw, new_key);
}

__shr_public int libnvme_sed_set_password(struct libnvme_transport_handle *hdl,
		const struct libnvme_sed_key *key,
		const struct libnvme_sed_key *new_key)
{
	struct opal_new_pw pw;
	int ret;

	ret = sed_opal_new_pw(&pw, key, new_key);
	if (ret)
		return ret;

	return sed_opal_ioctl(hdl, IOC_OPAL_SET_PW, &pw);
}

__shr_public int libnvme_sed_set_sid_password(
		struct libnvme_transport_handle *hdl,
		const struct libnvme_sed_key *key,
		const struct libnvme_sed_key *new_key)
{
#ifdef IOC_OPAL_SET_SID_PW
	struct opal_new_pw pw;
	int ret;

	ret = sed_opal_new_pw(&pw, key, new_key);
	if (ret)
		return ret;

	return sed_opal_ioctl(hdl, IOC_OPAL_SET_SID_PW, &pw);
#else
	return -ENOTSUP;
#endif
}

__shr_public int libnvme_sed_revert_tper(struct libnvme_transport_handle *hdl,
		const struct libnvme_sed_key *key)
{
	struct opal_key okey;
	int ret;

	ret = sed_opal_key(&okey, key);
	if (ret)
		return ret;

	return sed_opal_ioctl(hdl, IOC_OPAL_REVERT_TPR, &okey);
}

__shr_public int libnvme_sed_revert_psid(struct libnvme_transport_handle *hdl,
		const struct libnvme_sed_key *psid)
{
#ifdef IOC_OPAL_PSID_REVERT_TPR
	struct opal_key okey;
	int ret;

	ret = sed_opal_key(&okey, psid);
	if (ret)
		return ret;

	return sed_opal_ioctl(hdl, IOC_OPAL_PSID_REVERT_TPR, &okey);
#else
	return -ENOTSUP;
#endif
}

__shr_public int libnvme_sed_revert_lsp(struct libnvme_transport_handle *hdl,
		const struct libnvme_sed_key *key, bool keep_data)
{
#ifdef IOC_OPAL_REVERT_LSP
	struct opal_revert_lsp revert = {};
	int ret;

	ret = sed_opal_key(&revert.key, key);
	if (ret)
		return ret;

	if (keep_data)
		revert.options = OPAL_PRESERVE;

	return sed_opal_ioctl(hdl, IOC_OPAL_REVERT_LSP, &revert);
#else
	return -ENOTSUP;
#endif
}
