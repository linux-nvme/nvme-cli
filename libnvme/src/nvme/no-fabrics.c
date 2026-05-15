// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libnvme.
 * Copyright (c) 2026 SUSE Software Solutions
 *
 * Authors: Daniel Wagner <dwagner@suse.de>
 */

#include "private-fabrics.h"

bool traddr_is_hostname(struct libnvme_global_ctx *ctx,
		const char *transport, const char *traddr)
{
	return false;
}

void libnvmf_default_config(struct libnvme_fabrics_config *cfg)
{
}

ctrl_match_t _candidate_init_fabrics(struct libnvme_global_ctx *ctx,
		struct candidate_args *candidate,
		const struct libnvmf_context *fctx)
{
	return NULL;
}

void libnvmf_read_sysfs_fabrics_attrs(struct libnvme_global_ctx *ctx,
		libnvme_ctrl_t c)
{
}
