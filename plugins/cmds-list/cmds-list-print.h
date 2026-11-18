/* SPDX-License-Identifier: GPL-2.0-or-later */
#pragma once

#include <libnvme.h>

#include <ccan/str/str.h>
#include <shared/table-util.h>

#include "args.h"

enum nvme_cli_topo_ranking {
	NVME_CLI_TOPO_NAMESPACE,
	NVME_CLI_TOPO_CTRL,
	NVME_CLI_TOPO_MULTIPATH,
};

static inline bool nvme_is_multipath(struct libnvme_subsystem *s)
{
	struct libnvme_ns *n;
	struct libnvme_path *p;

	libnvme_subsystem_for_each_ns(s, n)
		libnvme_namespace_for_each_path(n, p)
			return true;

	return false;
}

static inline bool subsystem_iopolicy_filter(const char *name, void *arg)
{
	struct libnvme_subsystem *s = arg;
	const char *iopolicy;

	libnvme_subsystem_get_iopolicy(s, &iopolicy, "");

	if (streq(iopolicy, "queue-depth")) {
		/* exclude "Nodes" for iopolicy queue-depth */
		if (streq(name, "Nodes"))
			return false;
	} else if (streq(iopolicy, "numa")) {
		/* exclude "Qdepth" for iopolicy numa */
		if (streq(name, "Qdepth"))
			return false;
	} else { /* round-robin */
		/* exclude "Nodes" and "Qdepth" for iopolicy round-robin */
		if (streq(name, "Nodes") || streq(name, "Qdepth"))
			return false;
	}

	return true;
}

/*
 * The printers of the libnvme tree and of nvme top. They run in process:
 * they read sysfs while printing.
 */
struct cmds_list_print_ops {
	void (*list_item)(struct libnvme_ns *n, struct shr_table *t);
	void (*list_items)(struct libnvme_global_ctx *ctx);
	void (*print_nvme_subsystem_list)(struct libnvme_global_ctx *ctx,
					  bool show_ana);
	void (*topology_ctrl)(struct libnvme_global_ctx *ctx);
	void (*topology_namespace)(struct libnvme_global_ctx *ctx);
	void (*topology_multipath)(struct libnvme_global_ctx *ctx);
	void (*topology_tabular)(struct libnvme_global_ctx *ctx);
	void (*top)(int refresh_interval);
	nvme_print_flags_t flags;
};

struct cmds_list_print_ops *
cmds_list_get_stdout_print_ops(nvme_print_flags_t flags);

#ifdef CONFIG_JSONC
struct cmds_list_print_ops *
cmds_list_get_json_print_ops(nvme_print_flags_t flags);
#else
static inline struct cmds_list_print_ops *
cmds_list_get_json_print_ops(nvme_print_flags_t flags)
{
	return NULL;
}
#endif

#ifdef CONFIG_TOP
void stdout_top(int refresh_interval);
#endif

void nvme_dev_full_path(struct libnvme_ns *n, char *path, size_t len);
void nvme_generic_full_path(struct libnvme_ns *n, char *path, size_t len);

void nvme_show_list_items(struct libnvme_global_ctx *ctx,
			  nvme_print_flags_t flags);
void nvme_show_subsystem_list(struct libnvme_global_ctx *ctx, bool show_ana,
			      nvme_print_flags_t flags);
void nvme_show_topology(struct libnvme_global_ctx *ctx,
			enum nvme_cli_topo_ranking ranking,
			nvme_print_flags_t flags);
void nvme_show_topology_tabular(struct libnvme_global_ctx *ctx,
				nvme_print_flags_t flags);
void nvme_show_top(nvme_print_flags_t flags, int refresh_interval);

/* A row of the table of nvme list, used by "nvme zns list" as well */
void nvme_show_list_item(struct libnvme_ns *n, struct shr_table *t);
