// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 SUSE Software Solutions
 *
 * Authors: Daniel Wagner <dwagner@suse.de>
 */

/*
 * Only main() lives here, so the fuzz tests can link everything else of
 * the program and run it with their own main().
 */
#include "plugin.h"

int main(int argc, char **argv)
{
	return nvme_main(argc, argv);
}
