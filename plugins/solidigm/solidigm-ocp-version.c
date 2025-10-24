// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2023 Solidigm.
 *
 * Author: leonardo.da.cunha@solidigm.com
 */

#include <stdio.h>
#include "nvme.h"

int sldgm_ocp_version(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc = "Prints OCP extensions version of Solidigm plugin";

	OPT_ARGS(opts) = {
		OPT_END()
	};

	int err = argconfig_parse(argc, argv, desc, opts);

	if (!err)
		printf("1.0\n");

	return err;
}
