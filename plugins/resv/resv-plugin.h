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
#define CMD_INC_FILE plugins/resv/resv-plugin

#if !defined(RESV_PLUGIN) || defined(CMD_HEADER_MULTI_READ)
#define RESV_PLUGIN

#include "cmd.h"

PLUGIN(NAME_CORE("resv", "Submit NVMe Reservation commands", NVME_VERSION),
	COMMAND_LIST(
		ENTRY("acquire", "Submit a Reservation Acquire, return results", resv_acquire)
		ENTRY("register", "Submit a Reservation Register, return results", resv_register)
		ENTRY("release", "Submit a Reservation Release, return results", resv_release)
		ENTRY("report", "Submit a Reservation Report, return results", resv_report)
	)
);

#endif

#include "define_cmd.h"
