/* SPDX-License-Identifier: GPL-2.0-or-later */

#ifndef DEBUG_H_
#define DEBUG_H_

#include <stdbool.h>

#define print_info(...)				\
	do {					\
		if (log_level >= LOG_INFO)	\
			printf(__VA_ARGS__);	\
	} while (false)

#define print_debug(...)			\
	do {					\
		if (log_level >= LOG_DEBUG)	\
			printf(__VA_ARGS__);	\
	} while (false)

extern int log_level;

int map_log_level(int verbose, bool quiet);

#endif // DEBUG_H_
