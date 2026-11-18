// SPDX-License-Identifier: GPL-2.0-or-later
#include <time.h>

#ifdef CONFIG_FABRICS
#include <arpa/inet.h>
#endif /* CONFIG_FABRICS */

#include <ccan/array_size/array_size.h>
#include <ccan/minmax/minmax.h>
#include <shared/string-util.h>
#include <shared/unaligned-util.h>

#include "cleanup.h"
#include "logging.h"
#include "nvme-print.h"
#include "nvme-print-stdout.h"

#ifdef CONFIG_FABRICS
void stdout_discovery_log(const struct nvmf_discovery_log *log, int numrec)
{
	int i;

	printf("\nDiscovery Log Number of Records %d, Generation counter %"
	       PRIu64"\n", numrec, le64_to_cpu(log->genctr));

	for (i = 0; i < numrec; i++) {
		const struct nvmf_disc_log_entry *e = &log->entries[i];

		/*
		 * e->trsvcid/subnqn/traddr are fixed-width fields off the
		 * wire, space-padded per the spec, and not guaranteed
		 * NUL-terminated by a non-compliant DC. shr_buf2str() bounds
		 * the read to the field's own size and strips the padding.
		 */
		__cleanup_free char *trsvcid = NULL;
		__cleanup_free char *subnqn = NULL;
		__cleanup_free char *traddr = NULL;
		struct shr_table *t;

		trsvcid = shr_buf2str(e->trsvcid, sizeof(e->trsvcid));
		subnqn = shr_buf2str(e->subnqn, sizeof(e->subnqn));
		traddr = shr_buf2str(e->traddr, sizeof(e->traddr));

		printf("=====Discovery Log Entry %d======\n", i);

		t = stdout_kv_table_create();
		if (!t)
			return;

		stdout_kv_add(t, "trtype", "%s", libnvmf_trtype_str(e->trtype));
		stdout_kv_add(t, "adrfam", "%s",
			      e->traddr[0] ?
			      libnvmf_adrfam_str(e->adrfam) : "");
		stdout_kv_add(t, "subtype", "%s",
			      libnvmf_subtype_str(e->subtype));
		stdout_kv_add(t, "treq", "%s", libnvmf_treq_str(e->treq));
		stdout_kv_add(t, "portid", "%d", le16_to_cpu(e->portid));
		stdout_kv_add(t, "trsvcid", "%s", trsvcid);
		stdout_kv_add(t, "subnqn", "%s", subnqn);
		stdout_kv_add(t, "traddr", "%s", traddr);
		stdout_kv_add(t, "eflags", "%s",
			      libnvmf_eflags_str(le16_to_cpu(e->eflags)));

		switch (e->trtype) {
		case NVMF_TRTYPE_RDMA:
			stdout_kv_add(t, "rdma_prtype", "%s",
				      libnvmf_prtype_str(e->tsas.rdma.prtype));
			stdout_kv_add(t, "rdma_qptype", "%s",
				      libnvmf_qptype_str(e->tsas.rdma.qptype));
			stdout_kv_add(t, "rdma_cms", "%s",
				      libnvmf_cms_str(e->tsas.rdma.cms));
			stdout_kv_add(t, "rdma_pkey", "%#04x",
				      le16_to_cpu(e->tsas.rdma.pkey));
			break;
		case NVMF_TRTYPE_TCP:
			stdout_kv_add(t, "sectype", "%s",
				      libnvmf_sectype_str(e->tsas.tcp.sectype));
			break;
		}

		stdout_kv_table_finish(t, "discovery-log");
	}
}

#endif /* CONFIG_FABRICS */
