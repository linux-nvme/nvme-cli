/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 Dell Technologies Inc. or its subsidiaries.
 *
 * Authors: Martin Belanger <martin.belanger@dell.com>
 */
#pragma once

#include <stdbool.h>

/*
 * Is a namespace of the subsystem of controller @devid, or a block device
 * on top of it (partition, LVM, dm-crypt), mounted or used as swap?
 * @root is prepended to the /sys and /proc paths: "" for the running
 * system.
 */
bool stop_ctrl_in_use(const char *root, const char *devid);

/*
 * The ExecStop= of a connection unit: disconnect the controller that
 * @unit_name connected, with "@nvme_path disconnect". Does nothing if the
 * device name now belongs to another controller. At shutdown, does
 * nothing while the controller is in use (see stop_ctrl_in_use()).
 * Does not return if it runs nvme. Returns the exit status otherwise.
 */
int stop_unit(const char *unit_name, const char *nvme_path);
