// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libnvme.
 * Copyright (c) 2021 SUSE Software Solutions
 *
 * Authors: Hannes Reinecke <hare@suse.de>
 */

#ifndef _LIBNVME_PRIVATE_H
#define _LIBNVME_PRIVATE_H

int nvme_set_attr(const char *dir, const char *attr, const char *value);

void json_read_config(nvme_root_t r, const char *config_file);

void json_update_config(nvme_root_t r, const char *config_file);

#endif /* _LIBNVME_PRIVATE_H */
