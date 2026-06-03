// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libnvme.
 * Copyright (c) 2026 SUSE Software Solutions
 *
 * Authors: Daniel Wagner <dwagner@suse.de>
 */

#include "private.h"
#include "compiler-attributes.h"

bool traddr_is_hostname(struct libnvme_global_ctx *ctx,
		const char *transport, const char *traddr)
{
	return false;
}

void libnvmf_default_config(struct libnvme_fabrics_config *cfg)
{
}

void libnvmf_read_sysfs_fabrics_attrs(struct libnvme_global_ctx *ctx,
		libnvme_ctrl_t c)
{
}

libnvme_ctrl_t libnvme_ctrl_find(libnvme_subsystem_t s,
		const struct libnvme_ctrl_params *params, libnvme_ctrl_t p)
{
#ifndef _WIN32
	struct libnvme_ctrl *c;

	c = p ? libnvme_subsystem_next_ctrl(s, p) :
		libnvme_subsystem_first_ctrl(s);
	for (; c; c = libnvme_subsystem_next_ctrl(s, c)) {
		if (!streq0(c->transport, params->transport))
			continue;
		if (params->traddr && c->traddr &&
		    !streqcase0(c->traddr, params->traddr))
			continue;
		return c;
	}
#endif
	return NULL;
}

__libnvme_public char *libnvme_ctrl_owner(libnvme_ctrl_t c)
{
	return NULL;
}
