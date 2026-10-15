/* SPDX-License-Identifier: GPL-2.0-or-later */
#pragma once

#include "../../../src/argconfig.h"

int ref_argconfig_parse(int argc, char *argv[],
			struct argconfig_commandline_options *options,
			char ***operands, int *nr_operands);
int ref_argconfig_parse_global(int argc, char *argv[],
			       struct argconfig_commandline_options *options,
			       int *argind);
