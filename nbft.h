/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <libnvme.h>
#include "nvme.h"

#include <ccan/list/list.h>

#define NBFT_SYSFS_PATH		"/sys/firmware/acpi/tables"

struct nbft_file_entry {
	struct list_node node;
	struct nbft_info *nbft;
};

int read_nbft_files(struct list_head *nbft_list, const char *path);
void free_nbfts(struct list_head *nbft_list);

extern int discover_from_nbft(nvme_root_t r, const char *hostnqn_arg, const char *hostid_arg,
			      const char *hostnqn_sys, const char *hostid_sys,
			      const char *desc, bool connect,
			      const struct nvme_fabrics_config *cfg, const char *nbft_path,
			      enum nvme_print_flags flags, bool verbose);
