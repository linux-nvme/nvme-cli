// SPDX-License-Identifier: GPL-2.0-or-later

#include "logging.h"

int log_level;

int map_log_level(int verbose, bool quiet)
{
	int log_level;

	/*
	 * LOG_NOTICE is unused thus the user has to provide two 'v' for getting
	 * any feedback at all. Thus skip this level
	 */
	verbose++;

	switch (verbose) {
	case 0:
		log_level = LOG_WARNING;
		break;
	case 1:
		log_level = LOG_NOTICE;
		break;
	case 2:
		log_level = LOG_INFO;
		break;
	default:
		log_level = LOG_DEBUG;
		break;
	}
	if (quiet)
		log_level = LOG_ERR;

	return log_level;
}
