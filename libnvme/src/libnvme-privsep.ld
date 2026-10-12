# SPDX-License-Identifier: LGPL-2.1-or-later

LIBNVME_PRIVSEP_3 {
	global:
		libnvme_privsep_free;
		libnvme_privsep_spawn;
		libnvme_set_privsep;
	local:
		*;
};
