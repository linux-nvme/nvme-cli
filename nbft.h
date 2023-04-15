/* SPDX-License-Identifier: GPL-2.0-or-later */

#include <ccan/list/list.h>

#define NBFT_SYSFS_PATH		"/sys/firmware/acpi/tables"

struct nbft_file_entry {
	struct list_node node;
	struct nbft_info *nbft;
};

int read_nbft_files(struct list_head *nbft_list, char *path);
void free_nbfts(struct list_head *nbft_list);

extern int discover_from_nbft(nvme_root_t r, char *hostnqn_arg, char *hostid_arg,
			      char *hostnqn_sys, char *hostid_sys,
			      const char *desc, bool connect,
			      const struct nvme_fabrics_config *cfg, char *nbft_path,
			      enum nvme_print_flags flags, bool verbose);
