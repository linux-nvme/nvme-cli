/* SPDX-License-Identifier: GPL-2.0-or-later */

#ifndef DEBUG_H_
#define DEBUG_H_

#include <stdbool.h>

#include <nvme/lib.h>

#define print_info(...)					\
	do {						\
		if (is_printable_at_level(LIBNVME_LOG_INFO))	\
			printf(__VA_ARGS__);		\
	} while (false)

#define print_debug(...)				\
	do {						\
		if (is_printable_at_level(LIBNVME_LOG_DEBUG))	\
			printf(__VA_ARGS__);		\
	} while (false)

extern int log_level;

struct libnvme_transport_handle;
struct libnvme_passthru_cmd;

void *nvme_submit_entry(struct libnvme_transport_handle *hdl,
		struct libnvme_passthru_cmd *cmd);
void nvme_submit_exit(struct libnvme_transport_handle *hdl,
		struct libnvme_passthru_cmd *cmd, int err, void *user_data);
bool nvme_decide_retry(struct libnvme_transport_handle *hdl,
		struct libnvme_passthru_cmd *cmd, int err);

bool is_printable_at_level(int level);
int map_log_level(int verbose, bool quiet);

#endif // DEBUG_H_
