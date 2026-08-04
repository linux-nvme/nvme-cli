// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libnvme.
 * Copyright (c) 2026, Dell Technologies Inc. or its subsidiaries.
 *
 * Authors: Martin Belanger <Martin.Belanger@dell.com>
 */

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
		SYSFS_FREE(c->sysfs->dhchap_host_key);
		c->sysfs->dhchap_host_key = host_key;
	}

	ctrl_key = libnvme_get_ctrl_attr(c, "dhchap_ctrl_secret");
	if (ctrl_key && !strcmp(ctrl_key, "none")) {
		free(ctrl_key);
		ctrl_key = NULL;
	}
	if (ctrl_key) {
		SYSFS_FREE(c->sysfs->dhchap_ctrl_key);
		c->sysfs->dhchap_ctrl_key = ctrl_key;
	}

	/*
	 * tls_key's presence gates keyring the same way it gates cfg's
	 * tls_key_id in tree-fabrics.c's libnvmf_read_sysfs_tls() -- read
	 * again here rather than threading state between the two, since
	 * cfg stays eager while this group is lazy.
	 */
	tls_key = libnvme_get_ctrl_attr(c, "tls_key");
	if (tls_key)
		c->sysfs->keyring = libnvme_get_ctrl_attr(c, "tls_keyring");

	return 0;
}
