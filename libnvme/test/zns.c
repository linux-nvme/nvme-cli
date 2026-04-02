// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libnvme.
 * Copyright (c) 2020 Western Digital Corporation or its affiliates.
 *
 * Authors: Keith Busch <keith.busch@wdc.com>
 */

/*
 * Search out for ZNS type namespaces, and if found, report their properties.
 */
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <ccan/endian/endian.h>

#include <libnvme.h>

#include "nvme/private.h"

static void show_zns_properties(libnvme_ns_t n)
{
	struct libnvme_transport_handle *hdl;
	struct libnvme_passthru_cmd cmd;
	struct nvme_zns_id_ns zns_ns;
	struct nvme_zns_id_ctrl zns_ctrl;
	struct nvme_zone_report *zr;
	int err;

	err = libnvme_ns_get_transport_handle(n, &hdl);
	if (err)
		return;

	zr = calloc(1, 0x1000);
	if (!zr)
		return;

	nvme_init_zns_identify_ns(&cmd, libnvme_ns_get_nsid(n), &zns_ns);
	if (libnvme_submit_admin_passthru(hdl, &cmd)) {
		fprintf(stderr, "failed to identify zns ns, result %" PRIx64 "\n",
			(uint64_t)cmd.result);
		free(zr);
		return;
	}

	printf("zoc:%x ozcs:%x mar:%x mor:%x\n", le16_to_cpu(zns_ns.zoc),
		le16_to_cpu(zns_ns.ozcs), le32_to_cpu(zns_ns.mar),
		le32_to_cpu(zns_ns.mor));

	nvme_init_zns_identify_ctrl(&cmd, &zns_ctrl);
	if (libnvme_submit_admin_passthru(hdl, &cmd)) {
		fprintf(stderr, "failed to identify zns ctrl\n");;
		free(zr);
		return;
	}

	printf("zasl:%u\n", zns_ctrl.zasl);
	nvme_init_zns_report_zones(&cmd, libnvme_ns_get_nsid(n), 0,
				  NVME_ZNS_ZRAS_REPORT_ALL, false,
				  true, (void *)zr, 0x1000);
	if (libnvme_submit_io_passthru(hdl, &cmd)) {
		fprintf(stderr, "failed to report zones, result %" PRIx64"\n",
			(uint64_t)cmd.result);
		free(zr);
		return;
	}

	printf("nr_zones:%"PRIu64"\n", le64_to_cpu(zr->nr_zones));
	free(zr);
}

int main()
{
	struct libnvme_global_ctx *ctx;
	libnvme_subsystem_t s;
	libnvme_host_t h;
	libnvme_ctrl_t c;
	libnvme_ns_t n;
	int err;

	ctx = libnvme_create_global_ctx(stdout, DEFAULT_LOGLEVEL);
	if (!ctx)
		return 1;

	err = libnvme_scan_topology(ctx, NULL, NULL);
	if (err && !(err == -ENOENT || err == -EACCES)) {
		libnvme_free_global_ctx(ctx);
		return 1;
	}

	libnvme_for_each_host(ctx, h) {
		libnvme_for_each_subsystem(h, s) {
			libnvme_subsystem_for_each_ctrl(s, c) {
				libnvme_ctrl_for_each_ns(c, n) {
					if (libnvme_ns_get_csi(n) == NVME_CSI_ZNS)
						show_zns_properties(n);
				}
			}
			libnvme_subsystem_for_each_ns(s, n) {
				if (libnvme_ns_get_csi(n) == NVME_CSI_ZNS)
					show_zns_properties(n);
			}
		}
	}

	libnvme_free_global_ctx(ctx);
	return 0;
}
