// SPDX-License-Identifier: GPL-2.0-or-later

#include <libnvme.h>

#include <ccan/endian/endian.h>
#include <shared/string-util.h>

#include "cleanup.h"
#include "fabrics-print.h"
#include "nvme-print.h"
#include "nvme-print-json.h"

static void json_discovery_log(const struct nvmf_discovery_log *log, int numrec)
{
	struct json_object *r = json_root();
	struct json_object *entries = json_create_array();
	int i;

	obj_add_uint64(r, "genctr", le64_to_cpu(log->genctr));
	obj_add_array(r, "records", entries);

	for (i = 0; i < numrec; i++) {
		const struct nvmf_disc_log_entry *e = &log->entries[i];
		struct json_object *entry = json_create_object();
		/*
		 * e->trsvcid/subnqn/traddr are fixed-width fields off the wire,
		 * not guaranteed NUL-terminated. json_object_new_string()
		 * needs a NUL-terminated C string, so make NUL-terminated
		 * copies and trim trailing spaces (if any). Members of e
		 * cannot be modified directly (we do not own that data).
		 */
		__cleanup_free char *trsvcid = NULL;
		__cleanup_free char *traddr = NULL;
		__cleanup_free char *subnqn = NULL;

		trsvcid = shr_buf2str(e->trsvcid, sizeof(e->trsvcid));
		traddr = shr_buf2str(e->traddr, sizeof(e->traddr));
		subnqn = shr_buf2str(e->subnqn, sizeof(e->subnqn));

		obj_add_str(entry, "trtype", libnvmf_trtype_str(e->trtype));
		obj_add_str(entry, "adrfam", libnvmf_adrfam_str(e->adrfam));
		obj_add_str(entry, "subtype", libnvmf_subtype_str(e->subtype));
		obj_add_str(entry, "treq", libnvmf_treq_str(e->treq));
		obj_add_uint(entry, "portid", le16_to_cpu(e->portid));
		obj_add_str(entry, "trsvcid", trsvcid);
		obj_add_str(entry, "subnqn", subnqn);
		obj_add_str(entry, "traddr", traddr);
		obj_add_str(entry, "eflags",
			    libnvmf_eflags_str(le16_to_cpu(e->eflags)));

		switch (e->trtype) {
		case NVMF_TRTYPE_RDMA:
			obj_add_str(entry, "rdma_prtype",
				    libnvmf_prtype_str(e->tsas.rdma.prtype));
			obj_add_str(entry, "rdma_qptype",
				    libnvmf_qptype_str(e->tsas.rdma.qptype));
			obj_add_str(entry, "rdma_cms",
				    libnvmf_cms_str(e->tsas.rdma.cms));
			obj_add_uint(entry, "rdma_pkey",
				     le16_to_cpu(e->tsas.rdma.pkey));
			break;
		case NVMF_TRTYPE_TCP:
			obj_add_str(entry, "sectype",
				    libnvmf_sectype_str(e->tsas.tcp.sectype));
			break;
		default:
			break;
		}
		array_add_obj(entries, entry);
	}
}

static void json_add_param(const char *key, const char *value, void *user_data)
{
	obj_add_str(user_data, key, value);
}

/*
 * libnvmf_config_conn_for_each() callback for "nvme config show -o json".
 * Reports fields as configured, not canonicalized through a TID (which has
 * no per-field accessors). hostnqn/hostid are null when a persona falls
 * back to the system default, not the value it would resolve to.
 */
static void json_add_conn(const struct libnvmf_config_conn *c, void *user_data)
{
	struct json_object *entries = user_data;
	struct json_object *entry = json_create_object();
	struct json_object *params_obj = json_create_object();
	const struct libnvmf_params *params = libnvmf_config_conn_get_params(c);

	obj_add_str(entry, "source", libnvmf_config_conn_get_source(c));
	obj_add_bool(entry, "is_dc", libnvmf_config_conn_is_dc(c));
	obj_add_str(entry, "transport", libnvmf_config_conn_get_transport(c));
	obj_add_str(entry, "traddr", libnvmf_config_conn_get_traddr(c));
	obj_add_str(entry, "trsvcid", libnvmf_config_conn_get_trsvcid(c));
	obj_add_str(entry, "nqn", libnvmf_config_conn_get_subsysnqn(c));
	obj_add_str(entry, "host-traddr",
		    libnvmf_config_conn_get_host_traddr(c));
	obj_add_str(entry, "host-iface", libnvmf_config_conn_get_host_iface(c));
	obj_add_str(entry, "hostnqn", libnvmf_config_conn_get_hostnqn(c));
	obj_add_str(entry, "hostid", libnvmf_config_conn_get_hostid(c));

	libnvmf_params_for_each(params, json_add_param, params_obj);
	obj_add_obj(entry, "params", params_obj);

	array_add_obj(entries, entry);
}

static void json_config_conn_list(struct libnvmf_config *config)
{
	struct json_object *r = json_root();
	struct json_object *entries = json_create_array();

	obj_add_array(r, "connections", entries);
	libnvmf_config_conn_for_each(config, json_add_conn, entries);
}

static struct fabrics_print_ops json_fabrics_print_ops = {
	.discovery_log		= json_discovery_log,
	.config_conn_list	= json_config_conn_list,
};

struct fabrics_print_ops *
fabrics_get_json_print_ops(nvme_print_flags_t flags)
{
	json_fabrics_print_ops.flags = flags;
	return &json_fabrics_print_ops;
}
