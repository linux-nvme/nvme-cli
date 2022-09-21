// SPDX-License-Identifier: LGPL-2.1-or-later
/**
 * This file is part of libnvme.
 * Copyright (c) 2020 Western Digital Corporation or its affiliates.
 *
 * Authors: Keith Busch <keith.busch@wdc.com>
 */

/**
 * discover-loop: Use fabrics commands to discover any loop targets and print
 * those records. You must have at least one configured nvme loop target on the
 * system (no existing connection required). The output will look more
 * interesting with more targets.
 */
#define __SANE_USERSPACE_TYPES__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <libnvme.h>

#include <ccan/endian/endian.h>

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
	nvme_root_t r;
	nvme_host_t h;
	nvme_ctrl_t c;
	int ret;
	struct nvme_fabrics_config cfg;

	nvmf_default_config(&cfg);

	r = nvme_scan(NULL);
	h = nvme_default_host(r);
	if (!h) {
		fprintf(stderr, "Failed to allocated memory\n");
		return ENOMEM;
	}
	c = nvme_create_ctrl(r, NVME_DISC_SUBSYS_NAME, "loop",
			     NULL, NULL, NULL, NULL);
	if (!c) {
		fprintf(stderr, "Failed to allocate memory\n");
		return ENOMEM;
	}
	ret = nvmf_add_ctrl(h, c, &cfg);
	if (ret < 0) {
		fprintf(stderr, "no controller found\n");
		return errno;
	}

	ret = nvmf_get_discovery_log(c, &log, 4);
	nvme_disconnect_ctrl(c);
	nvme_free_ctrl(c);

	if (ret)
		fprintf(stderr, "nvmf-discover-log:%x\n", ret);
	else
		print_discover_log(log);

	nvme_free_tree(r);
	free(log);
	return 0;
}
