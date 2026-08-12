/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * This file is part of nvme-cli.
 *
 * Copyright (c) 2014-2015, Intel Corporation.
 * Copyright (c) 2026 SUSE Software Solutions
 *
 * Authors: Keith Busch <kbusch@kernel.org>
 *          Daniel Wagner <dwagner@suse.com>
 */

#undef CMD_INC_FILE
#define CMD_INC_FILE plugins/ns/ns-plugin

#if !defined(NS_PLUGIN) || defined(CMD_HEADER_MULTI_READ)
#define NS_PLUGIN

#include "cmd.h"

PLUGIN(NAME_CORE("ns", "Manage NVMe namespaces", NVME_VERSION),
	COMMAND_LIST(
		ENTRY("create", "Creates a namespace with the provided parameters", create_ns)
		ENTRY("delete", "Deletes a namespace from the controller", delete_ns)
		ENTRY("attach", "Attaches a namespace to requested controller(s)", attach_ns)
		ENTRY("detach", "Detaches a namespace from requested controller(s)", detach_ns)
		ENTRY("get-id", "Retrieve the namespace ID of opened block device", get_ns_id)
	)
);

#endif

#include "define_cmd.h"
