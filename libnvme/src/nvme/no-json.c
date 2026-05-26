// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libnvme.
 * Copyright (c) 2023 SUSE Software Solutions
 *
 * Authors: Daniel Wagner <dwagner@suse.de>
 */

#include <errno.h>

#include <libnvme.h>
#include "compiler-attributes.h"

int json_read_config(struct libnvme_global_ctx *ctx, const char *config_file)
{
	return -ENOTSUP;
}

int json_update_config(struct libnvme_global_ctx *ctx, int fd)
{
	return -ENOTSUP;
}

int json_dump_tree(struct libnvme_global_ctx *ctx)
{
	return -ENOTSUP;
}

#ifdef CONFIG_FABRICS
int libnvmf_registry_create(int instance, const char *owner)
{
	return 0;
}

__libnvme_public int libnvmf_registry_retrieve(const char *device,
					       const char *key, char **value)
{
	return -ENOTSUP;
}

__libnvme_public int libnvmf_registry_update(const char *device,
					     const char *key, const char *value)
{
	return -ENOTSUP;
}

__libnvme_public int libnvmf_registry_delete(const char *device)
{
	return -ENOTSUP;
}

__libnvme_public int libnvmf_registry_for_each(
		void (*cback)(const char *device, const char *owner,
			      void *user_data),
		void *user_data)
{
	return 0;
}
#endif
