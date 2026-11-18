// SPDX-License-Identifier: GPL-2.0-or-later

#include <inttypes.h>
#include <stdio.h>

#include <libnvme.h>

#include <ccan/endian/endian.h>
#include <shared/string-util.h>
#include <shared/table-util.h>

#include "cleanup.h"
#include "fabrics-print.h"
#include "nvme-print.h"
#include "nvme-print-stdout.h"

static void stdout_discovery_log(const struct nvmf_discovery_log *log,
				 int numrec)
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

/*
 * libnvmf_connect_args_emit() callback for "nvme config show": print each
 * formatted "--option=value" straight to stdout as part of the running
 * "nvme connect" line.
 */
static void stdout_print_conn_arg(const char *arg, void *user_data)
{
	printf(" %s", arg);
}

static void stdout_print_conn_field(const char *name, const char *value)
{
	if (value)
		printf(" --%s=%s", name, value);
}

/*
 * libnvmf_config_conn_for_each() callback for "nvme config show": render
 * one resolved connection as its equivalent "nvme connect" command line.
 *
 * Identity is deliberately left unresolved here (unlike build_conn_tid()'s
 * connect-time callers): a persona with no hostnqn/hostid falls back to the
 * system default at connect time, not parse time, so showing the concrete
 * value here would suggest a fixed identity the config doesn't actually pin.
 *
 * Addressing is not resolved either, and no TID is built for a hostname:
 * "show" must never touch the network, and a hostname traddr is legitimate
 * INI content a TID (numeric-only) can't represent. The canonicalized TID
 * rendering is used when the address is already numeric; a raw hostname
 * falls back to printing the field as configured.
 */
static void stdout_print_conn(const struct libnvmf_config_conn *conn,
			       void *user_data)
{
	bool is_dc = libnvmf_config_conn_is_dc(conn);
	const char *hostnqn = libnvmf_config_conn_get_hostnqn(conn);
	const char *hostid = libnvmf_config_conn_get_hostid(conn);
	const struct libnvmf_params *params =
		libnvmf_config_conn_get_params(conn);
	__cleanup_nvmf_tid struct libnvmf_tid *tid = NULL;

	printf("# %s: %s\n", libnvmf_config_conn_get_source(conn),
		is_dc ? "Discovery Controller" : "I/O Controller");

	libnvmf_tid_from_fields(
			libnvmf_config_conn_get_transport(conn),
			libnvmf_config_conn_get_traddr(conn),
			libnvmf_config_conn_get_trsvcid(conn),
			libnvmf_config_conn_get_subsysnqn(conn),
			libnvmf_config_conn_get_host_traddr(conn),
			libnvmf_config_conn_get_host_iface(conn),
			hostnqn, hostid, &tid);

	/*
	 * A DC entry is consumed via libnvmf_discover() (log in, fetch the
	 * discovery log, connect everything returned) -- "nvme connect-all"
	 * is its real equivalent, not a bare "nvme connect" (which would
	 * only open the admin queue, matching just the niche "connect -J"
	 * mode instead of the primary discover/connect-all consumption
	 * path this command documents).
	 */
	printf("nvme %s", is_dc ? "connect-all" : "connect");
	if (tid) {
		libnvmf_connect_args_emit(tid, params, stdout_print_conn_arg,
					   NULL);
	} else {
		const char *transport = libnvmf_config_conn_get_transport(conn);
		const char *traddr = libnvmf_config_conn_get_traddr(conn);
		const char *trsvcid = libnvmf_config_conn_get_trsvcid(conn);
		const char *subsysnqn = libnvmf_config_conn_get_subsysnqn(conn);
		const char *host_traddr =
			libnvmf_config_conn_get_host_traddr(conn);
		const char *host_iface =
			libnvmf_config_conn_get_host_iface(conn);

		stdout_print_conn_field("transport", transport);
		stdout_print_conn_field("traddr", traddr);
		stdout_print_conn_field("trsvcid", trsvcid);
		stdout_print_conn_field("nqn", subsysnqn);
		stdout_print_conn_field("host-traddr", host_traddr);
		stdout_print_conn_field("host-iface", host_iface);
		stdout_print_conn_field("hostnqn", hostnqn);
		stdout_print_conn_field("hostid", hostid);
		libnvmf_connect_args_emit(NULL, params, stdout_print_conn_arg,
					   NULL);
	}
	printf("\n");
	if (!hostnqn || !hostid)
		printf("    (hostnqn/hostid: system default)\n");
	printf("\n");
}

static void stdout_config_conn_list(struct libnvmf_config *config)
{
	libnvmf_config_conn_for_each(config, stdout_print_conn, NULL);
}

static struct fabrics_print_ops stdout_fabrics_print_ops = {
	.discovery_log		= stdout_discovery_log,
	.config_conn_list	= stdout_config_conn_list,
};

struct fabrics_print_ops *
fabrics_get_stdout_print_ops(nvme_print_flags_t flags)
{
	stdout_fabrics_print_ops.flags = flags;
	return &stdout_fabrics_print_ops;
}
