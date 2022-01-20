// SPDX-License-Identifier: LGPL-2.1-or-later
/**
 * This file is part of libnvme.
 * Copyright (c) 2020 Western Digital Corporation or its affiliates.
 *
 * Authors: Keith Busch <keith.busch@wdc.com>
 */

/**
 * display-columnar: Scans the nvme topology, prints each record type in a
 * column format for easy visual scanning.
 */
#include <stdio.h>
#include <inttypes.h>
#include <libnvme.h>

static const char dash[101] = {[0 ... 99] = '-'};
int main()
{
	nvme_root_t r;
	nvme_host_t h;
	nvme_subsystem_t s;
	nvme_ctrl_t c;
	nvme_path_t p;
	nvme_ns_t n;

	r = nvme_scan(NULL);
	if (!r)
		return -1;


	printf("%-16s %-96s %-.16s\n", "Subsystem", "Subsystem-NQN", "Controllers");
	printf("%-.16s %-.96s %-.16s\n", dash, dash, dash);

	nvme_for_each_host(r, h) {
		nvme_for_each_subsystem(h, s) {
			bool first = true;
			printf("%-16s %-96s ", nvme_subsystem_get_name(s),
			       nvme_subsystem_get_nqn(s));

			nvme_subsystem_for_each_ctrl(s, c) {
				printf("%s%s", first ? "": ", ",
				       nvme_ctrl_get_name(c));
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

	nvme_for_each_host(r, h) {
		nvme_for_each_subsystem(h, s) {
			nvme_subsystem_for_each_ctrl(s, c) {
				bool first = true;

				printf("%-8s %-20s %-40s %-8s %-6s %-14s %-12s ",
				       nvme_ctrl_get_name(c),
				       nvme_ctrl_get_serial(c),
				       nvme_ctrl_get_model(c),
				       nvme_ctrl_get_firmware(c),
				       nvme_ctrl_get_transport(c),
				       nvme_ctrl_get_address(c),
				       nvme_subsystem_get_name(s));

				nvme_ctrl_for_each_ns(c, n) {
					printf("%s%s", first ? "": ", ",
					       nvme_ns_get_name(n));
					first = false;
				}

				nvme_ctrl_for_each_path(c, p) {
					printf("%s%s", first ? "": ", ",
					       nvme_ns_get_name(nvme_path_get_ns(p)));
					first = false;
				}
				printf("\n");
			}
		}
	}
	printf("\n");

 	printf("%-12s %-8s %-16s %-8s %-16s\n", "Device", "NSID", "Sectors", "Format", "Controllers");
	printf("%-.12s %-.8s %-.16s %-.8s %-.16s\n", dash, dash, dash, dash, dash);

	nvme_for_each_host(r, h) {
		nvme_for_each_subsystem(h, s) {
			nvme_subsystem_for_each_ctrl(s, c) {
				nvme_ctrl_for_each_ns(c, n)
					printf("%-12s %-8d %-16" PRIu64 " %-8d %s\n",
					       nvme_ns_get_name(n),
					       nvme_ns_get_nsid(n),
					       nvme_ns_get_lba_count(n),
					       nvme_ns_get_lba_size(n),
					       nvme_ctrl_get_name(c));
			}

			nvme_subsystem_for_each_ns(s, n) {
				bool first = true;

				printf("%-12s %-8d %-16" PRIu64 " %-8d ",
				       nvme_ns_get_name(n),
				       nvme_ns_get_nsid(n),
				       nvme_ns_get_lba_count(n),
				       nvme_ns_get_lba_size(n));
				nvme_subsystem_for_each_ctrl(s, c) {
					printf("%s%s", first ? "" : ", ",
					       nvme_ctrl_get_name(c));
					first = false;
				}
				printf("\n");
			}
		}
	}
	return 0;
}

