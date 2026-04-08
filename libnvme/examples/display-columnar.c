// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libnvme.
 * Copyright (c) 2020 Western Digital Corporation or its affiliates.
 *
 * Authors: Keith Busch <keith.busch@wdc.com>
 */

/*
 * display-columnar: Scans the nvme topology, prints each record type in a
 * column format for easy visual scanning.
 */
#include <stdio.h>
#include <inttypes.h>
#include <libnvme.h>

static const char dash[101] = {[0 ... 99] = '-'};
int main()
{
	struct libnvme_global_ctx *ctx;
	libnvme_host_t h;
	libnvme_subsystem_t s;
	libnvme_ctrl_t c;
	libnvme_path_t p;
	libnvme_ns_t n;
	int err;

	ctx = libnvme_create_global_ctx(stdout, DEFAULT_LOGLEVEL);
	if (!ctx)
		return 1;

	err = libnvme_scan_topology(ctx, NULL, NULL);
	if (err) {
		libnvme_free_global_ctx(ctx);
		return 1;
	}

	printf("%-16s %-96s %-.16s\n", "Subsystem", "Subsystem-NQN", "Controllers");
	printf("%-.16s %-.96s %-.16s\n", dash, dash, dash);

	libnvme_for_each_host(ctx, h) {
		libnvme_for_each_subsystem(h, s) {
			bool first = true;
			printf("%-16s %-96s ", libnvme_subsystem_get_name(s),
			       libnvme_subsystem_get_subsysnqn(s));

			libnvme_subsystem_for_each_ctrl(s, c) {
				printf("%s%s", first ? "": ", ",
				       libnvme_ctrl_get_name(c));
				first = false;
			}
			printf("\n");
		}
	}
	printf("\n");

	printf("%-8s %-20s %-40s %-8s %-6s %-14s %-12s %-16s\n", "Device",
		"SN", "MN", "FR", "TxPort", "Address", "Subsystem", "Namespaces");
	printf("%-.8s %-.20s %-.40s %-.8s %-.6s %-.14s %-.12s %-.16s\n", dash, dash,
		dash, dash, dash, dash, dash, dash);

	libnvme_for_each_host(ctx, h) {
		libnvme_for_each_subsystem(h, s) {
			libnvme_subsystem_for_each_ctrl(s, c) {
				bool first = true;

				printf("%-8s %-20s %-40s %-8s %-6s %-14s %-12s ",
				       libnvme_ctrl_get_name(c),
				       libnvme_ctrl_get_serial(c),
				       libnvme_ctrl_get_model(c),
				       libnvme_ctrl_get_firmware(c),
				       libnvme_ctrl_get_transport(c),
				       libnvme_ctrl_get_traddr(c),
				       libnvme_subsystem_get_name(s));

				libnvme_ctrl_for_each_ns(c, n) {
					printf("%s%s", first ? "": ", ",
					       libnvme_ns_get_name(n));
					first = false;
				}

				libnvme_ctrl_for_each_path(c, p) {
					printf("%s%s", first ? "": ", ",
					       libnvme_ns_get_name(libnvme_path_get_ns(p)));
					first = false;
				}
				printf("\n");
			}
		}
	}
	printf("\n");

 	printf("%-12s %-8s %-16s %-8s %-16s\n", "Device", "NSID", "Sectors", "Format", "Controllers");
	printf("%-.12s %-.8s %-.16s %-.8s %-.16s\n", dash, dash, dash, dash, dash);

	libnvme_for_each_host(ctx, h) {
		libnvme_for_each_subsystem(h, s) {
			libnvme_subsystem_for_each_ctrl(s, c) {
				libnvme_ctrl_for_each_ns(c, n)
					printf("%-12s %-8d %-16" PRIu64 " %-8d %s\n",
					       libnvme_ns_get_name(n),
					       libnvme_ns_get_nsid(n),
					       libnvme_ns_get_lba_count(n),
					       libnvme_ns_get_lba_size(n),
					       libnvme_ctrl_get_name(c));
			}

			libnvme_subsystem_for_each_ns(s, n) {
				bool first = true;

				printf("%-12s %-8d %-16" PRIu64 " %-8d ",
				       libnvme_ns_get_name(n),
				       libnvme_ns_get_nsid(n),
				       libnvme_ns_get_lba_count(n),
				       libnvme_ns_get_lba_size(n));
				libnvme_subsystem_for_each_ctrl(s, c) {
					printf("%s%s", first ? "" : ", ",
					       libnvme_ctrl_get_name(c));
					first = false;
				}
				printf("\n");
			}
		}
	}
	return 0;
}

