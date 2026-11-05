/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 SUSE LLC
 *
 * Authors: Daniel Wagner <dwagner@suse.de>
 */
#pragma once

#include <stdbool.h>

/*
 * What a transient unit runs, independent of how it is started. units.c
 * turns it into a StartTransientUnit call, or hands it to the local runner
 * (units-local.h).
 */
struct unit_spec {
	const char *name;
	const char *description;
	/*
	 * A connection unit stays active after the connect (RemainAfterExit=),
	 * is ordered before the remote file systems, and disconnects on stop.
	 * A connect-all unit is none of this.
	 */
	bool connection;
	bool is_fc;                    // no After=network.target
	const char *const *exec_start; // argv, argv[0] is the binary
	char *exec_start_post;         // shell commands, NULL for none
	char *exec_stop;
	char *exec_stop_post;
};
