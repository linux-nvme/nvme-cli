# SPDX-License-Identifier: LGPL-2.1-or-later

LIBNVME_SED_3 {
	global:
		libnvme_sed_activate_lsp;
		libnvme_sed_discover;
		libnvme_sed_l0_find;
		libnvme_sed_l0_next;
		libnvme_sed_lock_unlock;
		libnvme_sed_revert_lsp;
		libnvme_sed_revert_psid;
		libnvme_sed_revert_tper;
		libnvme_sed_set_password;
		libnvme_sed_set_sid_password;
		libnvme_sed_setup_range;
		libnvme_sed_take_ownership;
	local:
		*;
};
