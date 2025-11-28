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

struct nvme_transport_handle;
struct nvme_passthru_cmd;

void *nvme_submit_entry(struct nvme_transport_handle *hdl,
		struct nvme_passthru_cmd *cmd);
void nvme_submit_exit(struct nvme_transport_handle *hdl,
		struct nvme_passthru_cmd *cmd, int err, void *user_data);
bool nvme_decide_retry(struct nvme_transport_handle *hdl,
		struct nvme_passthru_cmd *cmd, int err);

int map_log_level(int verbose, bool quiet);

#endif // DEBUG_H_
