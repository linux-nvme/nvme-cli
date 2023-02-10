// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libnvme.
 * Copyright (c) 2023 SUSE Software Solutions
 *
 * Authors: Daniel Wagner <dwagner@suse.de>
 */

#include "tree.h"

#include <errno.h>

int json_read_config(nvme_root_t r, const char *config_file)
{
	return -ENOTSUP;
}

int json_update_config(nvme_root_t r, const char *config_file)
{
	return -ENOTSUP;
}

int json_dump_tree(nvme_root_t r)
{
	return -ENOTSUP;
}
