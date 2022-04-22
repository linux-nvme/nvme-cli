// SPDX-License-Identifier: LGPL-2.1-or-later
/**
 * This file is part of libnvme.
 * Copyright (c) 2020 Western Digital Corporation or its affiliates.
 *
 * Authors: Keith Busch <keith.busch@wdc.com>
 */

/**
 * Search out for ZNS type namespaces, and if found, report their properties.
 */
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <stdlib.h>
#include <libnvme.h>
#include <inttypes.h>

#include <ccan/endian/endian.h>

static void show_zns_properties(nvme_ns_t n)
{
	struct nvme_zns_id_ns zns_ns;
	struct nvme_zns_id_ctrl zns_ctrl;
	struct nvme_zone_report *zr;
	__u32 result;

	zr = calloc(1, 0x1000);
	if (!zr)
		return;

	if (nvme_zns_identify_ns(nvme_ns_get_fd(n), nvme_ns_get_nsid(n),
				 &zns_ns)) {
		fprintf(stderr, "failed to identify zns ns\n");;
	}

	printf("zoc:%x ozcs:%x mar:%x mor:%x\n", le16_to_cpu(zns_ns.zoc),
		le16_to_cpu(zns_ns.ozcs), le32_to_cpu(zns_ns.mar),
		le32_to_cpu(zns_ns.mor));

	if (nvme_zns_identify_ctrl(nvme_ns_get_fd(n), &zns_ctrl)) {
		fprintf(stderr, "failed to identify zns ctrl\n");;
		free(zr);
		return;
	}

	printf("zasl:%u\n", zns_ctrl.zasl);

	if (nvme_zns_report_zones(nvme_ns_get_fd(n), nvme_ns_get_nsid(n), 0,
				  NVME_ZNS_ZRAS_REPORT_ALL, false,
				  true, 0x1000, (void *)zr,
				  NVME_DEFAULT_IOCTL_TIMEOUT, &result)) {
		fprintf(stderr, "failed to report zones, result %x\n",
			le32_to_cpu(result));
		free(zr);
		return;
	}

	printf("nr_zones:%"PRIu64"\n", le64_to_cpu(zr->nr_zones));
	free(zr);
}

int main()
{
	nvme_subsystem_t s;
	nvme_root_t r;
	nvme_host_t h;
	nvme_ctrl_t c;
	nvme_ns_t n;

	r = nvme_scan(NULL);
	if (!r)
		return -1;

	nvme_for_each_host(r, h) {
		nvme_for_each_subsystem(h, s) {
			nvme_subsystem_for_each_ctrl(s, c) {
				nvme_ctrl_for_each_ns(c, n) {
					if (nvme_ns_get_csi(n) == NVME_CSI_ZNS)
						show_zns_properties(n);
				}
			}
			nvme_subsystem_for_each_ns(s, n) {
				if (nvme_ns_get_csi(n) == NVME_CSI_ZNS)
					show_zns_properties(n);
			}
		}
	}
	nvme_free_tree(r);
}
