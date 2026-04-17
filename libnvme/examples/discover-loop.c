// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libnvme.
 * Copyright (c) 2020 Western Digital Corporation or its affiliates.
 *
 * Authors: Keith Busch <keith.busch@wdc.com>
 */

/*
 * discover-loop: Use fabrics commands to discover any loop targets and print
 * those records. You must have at least one configured nvme loop target on the
 * system (no existing connection required). The output will look more
 * interesting with more targets.
 */
#define __SANE_USERSPACE_TYPES__

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <ccan/endian/endian.h>

#include <libnvme.h>

static void print_discover_log(struct nvmf_discovery_log *log)
{
	int i, numrec = le64_to_cpu(log->numrec);

	printf(".\n");
	printf("|-- genctr:%llx\n", log->genctr);
	printf("|-- numrec:%x\n", numrec);
	printf("`-- recfmt:%x\n", log->recfmt);

	for (i = 0; i < numrec; i++) {
		struct nvmf_disc_log_entry *e = &log->entries[i];

		printf("  %c-- Entry:%d\n", (i < numrec - 1) ? '|' : '`', i);
		printf("  %c   |-- trtype:%x\n", (i < numrec - 1) ? '|' : ' ', e->trtype);
		printf("  %c   |-- adrfam:%x\n", (i < numrec - 1) ? '|' : ' ', e->adrfam);
		printf("  %c   |-- subtype:%x\n", (i < numrec - 1) ? '|' : ' ', e->subtype);
		printf("  %c   |-- treq:%x\n", (i < numrec - 1) ? '|' : ' ', e->treq);
		printf("  %c   |-- portid:%x\n", (i < numrec - 1) ? '|' : ' ', e->portid);
		printf("  %c   |-- cntlid:%x\n", (i < numrec - 1) ? '|' : ' ', e->cntlid);
		printf("  %c   |-- asqsz:%x\n", (i < numrec - 1) ? '|' : ' ', e->asqsz);
		printf("  %c   |-- trsvcid:%s\n", (i < numrec - 1) ? '|' : ' ', e->trsvcid);
		printf("  %c   |-- subnqn:%s\n", (i < numrec - 1) ? '|' : ' ', e->subnqn);
		printf("  %c   `-- traddr:%s\n", (i < numrec - 1) ? '|' : ' ', e->traddr);
	}
}

int main()
{
	struct nvmf_discovery_log *log = NULL;
	struct libnvme_global_ctx *ctx;
	struct libnvmf_context *fctx;
	libnvme_host_t h;
	libnvme_ctrl_t c;
	int ret;
	struct libnvmf_discovery_args *args;

	ctx = libnvme_create_global_ctx(stdout, LIBNVME_DEFAULT_LOGLEVEL);
	if (!ctx)
		return 1;

	ret = libnvmf_context_create(ctx, NULL, NULL, NULL, NULL, &fctx);
	if (ret)
		goto free_ctx;

	ret = libnvmf_context_set_connection(fctx, NVME_DISC_SUBSYS_NAME,
		"loop", NULL, NULL, NULL, NULL);
	if (ret)
		goto free_ctx;

	ret = libnvme_scan_topology(ctx, NULL, NULL);
	if (ret)
		goto free_fctx;

	ret = libnvme_get_host(ctx, NULL, NULL, &h);
	if (ret) {
		fprintf(stderr, "Failed to allocated memory\n");
		goto free_fctx;
	}

	ret = libnvmf_create_ctrl(ctx, fctx, &c);
	if (ret) {
		fprintf(stderr, "Failed to allocate memory\n");
		goto free_fctx;
	}

	ret = libnvmf_add_ctrl(h, c);
	if (ret) {
		fprintf(stderr, "no controller found\n");
		goto free_fctx;
	}

	ret = libnvmf_discovery_args_create(&args);
	if (!ret) {
		libnvmf_discovery_args_set_max_retries(args, 4);
		ret = libnvmf_get_discovery_log(c, args, &log);
		libnvmf_discovery_args_free(args);
	}

	libnvmf_disconnect_ctrl(c);
	libnvme_free_ctrl(c);

	if (ret)
		fprintf(stderr, "nvmf-discover-log:%x\n", ret);
	else
		print_discover_log(log);

free_fctx:
	libnvmf_context_free(fctx);
free_ctx:
	libnvme_free_global_ctx(ctx);
	free(log);

	return ret ? 1 : 0;
}
