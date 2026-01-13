// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libnvme.
 * Copyright (c) 2025 Micron Technology, Inc.
 *
 * Windows stub implementations for Linux-specific functionality
 * that is excluded from the Windows build (fabrics, MI, tree, filters, etc.)
 */

#include <errno.h>
#include <stdio.h>
#include <nvme/types.h>

/* Forward declarations for Linux-specific structures */
struct nvme_host;
struct nvme_subsystem;
struct nvme_ctrl;
struct nvme_path;
struct nvme_ns;

/* Logging control for stub calls */
static int stub_log_enabled = 0;

static void stub_log(const char *func)
{
	if (stub_log_enabled)
		fprintf(stderr, "libnvme-stub: %s() called (not supported on Windows)\n", func);
}

void nvme_stubs_set_debug(int enable)
{
	stub_log_enabled = enable;
}

/*
 * Stub implementations for fabrics functions (fabrics.c)
 * These are not supported on Windows
 */

/* Fabrics configuration stubs - just return errors */
void nvmf_default_config(void *cfg)
{
	stub_log(__func__);
	(void)cfg;
}

void nvmf_update_config(void *c, const void *cfg)
{
	stub_log(__func__);
	(void)c;
	(void)cfg;
}

int nvmf_add_ctrl(void *h, void *c, const void *cfg)
{
	stub_log(__func__);
	(void)h;
	(void)c;
	(void)cfg;
	errno = ENOTSUP;
	return -1;
}

int nvmf_connect_ctrl(void *c)
{
	stub_log(__func__);
	(void)c;
	errno = ENOTSUP;
	return -1;
}

int nvmf_get_discovery_log(void *c, void **logp, int max_retries)
{
	stub_log(__func__);
	(void)c;
	(void)logp;
	(void)max_retries;
	errno = ENOTSUP;
	return -1;
}

int nvmf_get_discovery_wargs(void *args, void **logp)
{
	stub_log(__func__);
	(void)args;
	(void)logp;
	errno = ENOTSUP;
	return -1;
}

int nvmf_connect_disc_entry(void *h, void *e, const void *defcfg, int *discover, void **c)
{
	stub_log(__func__);
	(void)h;
	(void)e;
	(void)defcfg;
	(void)discover;
	(void)c;
	errno = ENOTSUP;
	return -1;
}

int nvmf_is_registration_supported(void *c)
{
	stub_log(__func__);
	(void)c;
	return 0; /* Not supported */
}

int nvmf_register_ctrl(void *c, int tas, __u32 *result)
{
	stub_log(__func__);
	(void)c;
	(void)tas;
	(void)result;
	errno = ENOTSUP;
	return -1;
}

int nvme_parse_uri(const char *str, void **uri)
{
	stub_log(__func__);
	(void)str;
	(void)uri;
	errno = ENOTSUP;
	return -1;
}

void nvme_free_uri(void *uri)
{
	stub_log(__func__);
	(void)uri;
}

/*
 * Stub implementations for tree functions (tree.c)
 * Minimal support - just return NULL/errors
 */

void nvme_release_fds(void *r)
{
	stub_log(__func__);
	(void)r;
}

void *nvme_create_root(const char *config_file, int log_level)
{
	stub_log(__func__);
	(void)config_file;
	(void)log_level;
	/* Return NULL - tree operations not supported on Windows */
	return NULL;
}

void nvme_free_tree(void *r)
{
	stub_log(__func__);
	(void)r;
}

void nvme_free_global_ctx(struct nvme_global_ctx *ctx)
{
	stub_log(__func__);
	(void)ctx;
}

const char *nvme_root_get_application(void *r)
{
	stub_log(__func__);
	(void)r;
	return "";
}

void nvme_root_set_application(void *r, const char *a)
{
	stub_log(__func__);
	(void)r;
	(void)a;
}

void *nvme_scan(const char *config_file, int log_level)
{
	stub_log(__func__);
	(void)config_file;
	(void)log_level;
	/* Scanning not supported on Windows */
	return NULL;
}

struct nvme_global_ctx *nvme_create_global_ctx(FILE *fp, int log_level)
{
	stub_log(__func__);
	(void)fp;
	(void)log_level;
	/* Return NULL - global context not supported on Windows */
	return NULL;
}

void *nvme_scan_ctrl(void *ctx, const char *name)
{
	stub_log(__func__);
	(void)ctx;
	(void)name;
	return NULL;
}

int nvme_scan_topology(void *r, void *f, void *f_args)
{
	stub_log(__func__);
	(void)r;
	(void)f;
	(void)f_args;
	errno = ENOTSUP;
	return -1;
}

void *nvme_first_host(void *r)
{
	stub_log(__func__);
	(void)r;
	return NULL;
}

void *nvme_next_host(void *r, void *h)
{
	stub_log(__func__);
	(void)r;
	(void)h;
	return NULL;
}

void *nvme_lookup_host(void *r, const char *hostnqn, const char *hostid)
{
	stub_log(__func__);
	(void)r;
	(void)hostnqn;
	(void)hostid;
	return NULL;
}

void *nvme_default_host(void *r)
{
	stub_log(__func__);
	(void)r;
	return NULL;
}

void *nvme_first_subsystem(void *h)
{
	stub_log(__func__);
	(void)h;
	return NULL;
}

void *nvme_next_subsystem(void *h, void *s)
{
	stub_log(__func__);
	(void)h;
	(void)s;
	return NULL;
}

void *nvme_lookup_subsystem(struct nvme_host *h, const char *name, const char *subsysnqn)
{
	stub_log(__func__);
	(void)h;
	(void)name;
	(void)subsysnqn;
	return NULL;
}

void *nvme_first_ctrl(void *s)
{
	stub_log(__func__);
	(void)s;
	return NULL;
}

void *nvme_next_ctrl(void *s, void *c)
{
	stub_log(__func__);
	(void)s;
	(void)c;
	return NULL;
}

void *nvme_lookup_ctrl(void *s, const char *transport, const char *traddr,
		       const char *trsvcid, const char *subsysnqn,
		       const char *host_traddr, const char *host_iface)
{
	stub_log(__func__);
	(void)s;
	(void)transport;
	(void)traddr;
	(void)trsvcid;
	(void)subsysnqn;
	(void)host_traddr;
	(void)host_iface;
	return NULL;
}

void *nvme_ctrl_first_ns(void *c)
{
	stub_log(__func__);
	(void)c;
	return NULL;
}

void *nvme_ctrl_next_ns(void *c, void *ns)
{
	stub_log(__func__);
	(void)c;
	(void)ns;
	return NULL;
}

void *nvme_ctrl_first_path(void *c)
{
	stub_log(__func__);
	(void)c;
	return NULL;
}

void *nvme_ctrl_next_path(void *c, void *p)
{
	stub_log(__func__);
	(void)c;
	(void)p;
	return NULL;
}

void *nvme_subsys_first_ns(void *s)
{
	stub_log(__func__);
	(void)s;
	return NULL;
}

void *nvme_subsys_next_ns(void *s, void *ns)
{
	stub_log(__func__);
	(void)s;
	(void)ns;
	return NULL;
}

void *nvme_ns_get_subsystem(void *ns)
{
	stub_log(__func__);
	(void)ns;
	return NULL;
}

void *nvme_ns_get_ctrl(void *ns)
{
	stub_log(__func__);
	(void)ns;
	return NULL;
}

int nvme_ns_get_fd(void *ns)
{
	stub_log(__func__);
	(void)ns;
	return -1;
}

int nvme_ns_get_nsid(void *ns)
{
	stub_log(__func__);
	(void)ns;
	return 0;
}

int nvme_ns_get_csi(void *ns)
{
	stub_log(__func__);
	(void)ns;
	return 0;
}

const unsigned char *nvme_ns_get_eui64(void *ns)
{
	stub_log(__func__);
	(void)ns;
	return NULL;
}

const unsigned char *nvme_ns_get_nguid(void *ns)
{
	stub_log(__func__);
	(void)ns;
	return NULL;
}

const unsigned char *nvme_ns_get_uuid(void *ns)
{
	stub_log(__func__);
	(void)ns;
	return NULL;
}

void *nvme_ns_get_transport_handle(void *ns)
{
	stub_log(__func__);
	(void)ns;
	return NULL;
}

int nvme_ns_identify(void *ns, void *ns_id)
{
	stub_log(__func__);
	(void)ns;
	(void)ns_id;
	errno = ENOTSUP;
	return -1;
}

const char *nvme_ns_get_sysfs_dir(void *ns)
{
	stub_log(__func__);
	(void)ns;
	return "";
}

const char *nvme_ns_get_name(void *ns)
{
	stub_log(__func__);
	(void)ns;
	return "";
}

const char *nvme_ns_get_generic_name(void *ns)
{
	stub_log(__func__);
	(void)ns;
	return "";
}

int nvme_ns_get_lba_size(void *ns)
{
	stub_log(__func__);
	(void)ns;
	return 0;
}

unsigned long long nvme_ns_get_lba_count(void *ns)
{
	stub_log(__func__);
	(void)ns;
	return 0;
}

unsigned long long nvme_ns_get_lba_util(void *ns)
{
	stub_log(__func__);
	(void)ns;
	return 0;
}

const char *nvme_path_get_name(void *p)
{
	stub_log(__func__);
	(void)p;
	return "";
}

const char *nvme_path_get_sysfs_dir(void *p)
{
	stub_log(__func__);
	(void)p;
	return "";
}

const char *nvme_path_get_ana_state(void *p)
{
	stub_log(__func__);
	(void)p;
	return "";
}

void *nvme_path_get_ctrl(void *p)
{
	stub_log(__func__);
	(void)p;
	return NULL;
}

void *nvme_path_get_ns(void *p)
{
	stub_log(__func__);
	(void)p;
	return NULL;
}

const char *nvme_ctrl_get_name(void *c)
{
	stub_log(__func__);
	(void)c;
	return "";
}

const char *nvme_ctrl_get_sysfs_dir(void *c)
{
	stub_log(__func__);
	(void)c;
	return "";
}

const char *nvme_ctrl_get_address(void *c)
{
	stub_log(__func__);
	(void)c;
	return "";
}

const char *nvme_ctrl_get_transport(void *c)
{
	stub_log(__func__);
	(void)c;
	return "";
}

const char *nvme_ctrl_get_state(void *c)
{
	stub_log(__func__);
	(void)c;
	return "";
}

void *nvme_ctrl_get_config(void *c)
{
	stub_log(__func__);
	(void)c;
	return NULL;
}

int nvme_ctrl_get_fd(void *c)
{
	stub_log(__func__);
	(void)c;
	return -1;
}

void *nvme_ctrl_get_subsystem(void *c)
{
	stub_log(__func__);
	(void)c;
	return NULL;
}

void *nvme_ctrl_get_transport_handle(void *c)
{
	stub_log(__func__);
	(void)c;
	return NULL;
}

void nvme_free_ctrl(void *c)
{
	stub_log(__func__);
	(void)c;
}

int nvme_disconnect_ctrl(void *c)
{
	stub_log(__func__);
	(void)c;
	errno = ENOTSUP;
	return -1;
}

void nvme_unlink_ctrl(void *c)
{
	stub_log(__func__);
	(void)c;
}

const char *nvme_subsys_get_name(void *s)
{
	stub_log(__func__);
	(void)s;
	return "";
}

const char *nvme_subsys_get_nqn(void *s)
{
	stub_log(__func__);
	(void)s;
	return "";
}

const char *nvme_subsys_get_sysfs_dir(void *s)
{
	stub_log(__func__);
	(void)s;
	return "";
}

void *nvme_subsys_get_host(void *s)
{
	stub_log(__func__);
	(void)s;
	return NULL;
}

/* Subsystem functions (full name) - same as subsys */
const char *nvme_subsystem_get_name(void *s)
{
	return nvme_subsys_get_name(s);
}

const char *nvme_subsystem_get_nqn(void *s)
{
	return nvme_subsys_get_nqn(s);
}

const char *nvme_subsystem_get_sysfs_dir(void *s)
{
	return nvme_subsys_get_sysfs_dir(s);
}

void *nvme_subsystem_get_host(void *s)
{
	return nvme_subsys_get_host(s);
}

void *nvme_subsystem_first_ctrl(void *s)
{
	return nvme_first_ctrl(s);
}

void *nvme_subsystem_next_ctrl(void *s, void *c)
{
	return nvme_next_ctrl(s, c);
}

void *nvme_subsystem_first_ns(void *s)
{
	return nvme_subsys_first_ns(s);
}

void *nvme_subsystem_next_ns(void *s, void *ns)
{
	return nvme_subsys_next_ns(s, ns);
}

const char *nvme_host_get_hostnqn(void *h)
{
	stub_log(__func__);
	(void)h;
	return "";
}

const char *nvme_host_get_hostid(void *h)
{
	stub_log(__func__);
	(void)h;
	return "";
}

void *nvme_host_get_root(void *h)
{
	stub_log(__func__);
	(void)h;
	return NULL;
}

int nvme_dump_tree(void *r)
{
	stub_log(__func__);
	(void)r;
	errno = ENOTSUP;
	return -1;
}

int nvme_dump_config(void *r)
{
	stub_log(__func__);
	(void)r;
	errno = ENOTSUP;
	return -1;
}

/*
 * Stub implementations for filter functions (filters.c)
 */

void *nvme_for_each_host_safe(void *r, void *h)
{
	stub_log(__func__);
	(void)r;
	(void)h;
	return NULL;
}

void *nvme_for_each_subsystem_safe(void *h, void *s)
{
	stub_log(__func__);
	(void)h;
	(void)s;
	return NULL;
}

void *nvme_for_each_ctrl_safe(void *s, void *c)
{
	stub_log(__func__);
	(void)s;
	(void)c;
	return NULL;
}

void *nvme_for_each_ns_safe(void *s, void *ns)
{
	stub_log(__func__);
	(void)s;
	(void)ns;
	return NULL;
}

void *nvme_for_each_path_safe(void *c, void *p)
{
	stub_log(__func__);
	(void)c;
	(void)p;
	return NULL;
}

/*
 * Stub implementations for MI functions (mi.c and mi-mctp.c)
 */

int nvme_mi_admin_admin_passthru(void *hdl, __u8 opcode, __u8 flags,
				 __u16 rsvd, __u32 nsid, __u32 cdw2, __u32 cdw3,
				 __u32 cdw10, __u32 cdw11, __u32 cdw12,
				 __u32 cdw13, __u32 cdw14, __u32 cdw15,
				 __u32 data_len, void *data, __u32 metadata_len,
				 void *metadata, __u32 timeout_ms, __u32 *result)
{
	stub_log(__func__);
	(void)hdl;
	(void)opcode;
	(void)flags;
	(void)rsvd;
	(void)nsid;
	(void)cdw2;
	(void)cdw3;
	(void)cdw10;
	(void)cdw11;
	(void)cdw12;
	(void)cdw13;
	(void)cdw14;
	(void)cdw15;
	(void)data_len;
	(void)data;
	(void)metadata_len;
	(void)metadata;
	(void)timeout_ms;
	(void)result;
	errno = ENOTSUP;
	return -1;
}

void *nvme_mi_create_root(void *fp, int log_level)
{
	stub_log(__func__);
	(void)fp;
	(void)log_level;
	return NULL;
}

void nvme_mi_free_root(void *root)
{
	stub_log(__func__);
	(void)root;
}

void *nvme_mi_first_endpoint(void *root)
{
	stub_log(__func__);
	(void)root;
	return NULL;
}

void *nvme_mi_next_endpoint(void *root, void *ep)
{
	stub_log(__func__);
	(void)root;
	(void)ep;
	return NULL;
}

int nvme_mi_scan_ep(void *ep, int force_rescan)
{
	stub_log(__func__);
	(void)ep;
	(void)force_rescan;
	errno = ENOTSUP;
	return -1;
}

void *nvme_mi_first_ctrl(void *ep)
{
	stub_log(__func__);
	(void)ep;
	return NULL;
}

void *nvme_mi_next_ctrl(void *ep, void *c)
{
	stub_log(__func__);
	(void)ep;
	(void)c;
	return NULL;
}

void nvme_mi_close(void *ep)
{
	stub_log(__func__);
	(void)ep;
}

/*
 * Stub for Linux-specific includes
 */
int nvme_linux_status_to_errno(int status)
{
	stub_log(__func__);
	/* Simple passthrough - proper implementation would need status code mapping */
	return status < 0 ? -status : status;
}

/*
 * TLS/PSK key management stubs (linux.c functions)
 */
int nvme_export_tls_key_versioned(unsigned char version, unsigned char hmac,
				  const unsigned char *key_data,
				  size_t key_len, char **encoded_keyp)
{
	stub_log(__func__);
	(void)version;
	(void)hmac;
	(void)key_data;
	(void)key_len;
	(void)encoded_keyp;
	errno = ENOTSUP;
	return -1;
}

int nvme_export_tls_key(const unsigned char *key_data, int key_len, char **key)
{
	stub_log(__func__);
	(void)key_data;
	(void)key_len;
	(void)key;
	errno = ENOTSUP;
	return -1;
}

int nvme_import_tls_key_versioned(const char *encoded_key,
				  unsigned char *version,
				  unsigned char *hmac,
				  size_t *key_len,
				  unsigned char **keyp)
{
	stub_log(__func__);
	(void)encoded_key;
	(void)version;
	(void)hmac;
	(void)key_len;
	(void)keyp;
	errno = ENOTSUP;
	return -1;
}

int nvme_import_tls_key(const char *encoded_key, int *key_len,
			unsigned char **keyp)
{
	stub_log(__func__);
	(void)encoded_key;
	(void)key_len;
	(void)keyp;
	errno = ENOTSUP;
	return -1;
}

/*
 * Additional stubs for nvme-cli linking
 */

/* Transport handle operations (linux.c) */
int nvme_open(void *ctx, const char *name, void **hdlp)
{
	stub_log(__func__);
	(void)ctx;
	(void)name;
	(void)hdlp;
	errno = ENOTSUP;
	return -1;
}

void nvme_close(void *hdl)
{
	stub_log(__func__);
	(void)hdl;
}

int nvme_transport_handle_get_fd(void *hdl)
{
	stub_log(__func__);
	(void)hdl;
	return -1;
}

const char *nvme_transport_handle_get_name(void *hdl)
{
	stub_log(__func__);
	(void)hdl;
	return "";
}

int nvme_transport_handle_is_blkdev(void *hdl)
{
	stub_log(__func__);
	(void)hdl;
	return 0;
}

int nvme_transport_handle_is_chardev(void *hdl)
{
	stub_log(__func__);
	(void)hdl;
	return 0;
}

int nvme_transport_handle_is_direct(void *hdl)
{
	stub_log(__func__);
	(void)hdl;
	return 0;
}

/* Controller property getters (tree.c) */
const char *nvme_ctrl_get_cntlid(void *c)
{
	stub_log(__func__);
	(void)c;
	return "";
}

const char *nvme_ctrl_get_firmware(void *c)
{
	stub_log(__func__);
	(void)c;
	return "";
}

const char *nvme_ctrl_get_model(void *c)
{
	stub_log(__func__);
	(void)c;
	return "";
}

const char *nvme_ctrl_get_phy_slot(void *c)
{
	stub_log(__func__);
	(void)c;
	return "";
}

const char *nvme_ctrl_get_serial(void *c)
{
	stub_log(__func__);
	(void)c;
	return "";
}

/* Subsystem property getters (tree.c) */
const char *nvme_subsystem_get_fw_rev(void *s)
{
	stub_log(__func__);
	(void)s;
	return "";
}

const char *nvme_subsystem_get_iopolicy(void *s)
{
	stub_log(__func__);
	(void)s;
	return "";
}

const char *nvme_subsystem_get_model(void *s)
{
	stub_log(__func__);
	(void)s;
	return "";
}

const char *nvme_subsystem_get_serial(void *s)
{
	stub_log(__func__);
	(void)s;
	return "";
}

const char *nvme_subsystem_get_type(void *s)
{
	stub_log(__func__);
	(void)s;
	return "";
}

/* Namespace property getters (tree.c) */
const char *nvme_ns_get_firmware(void *ns)
{
	stub_log(__func__);
	(void)ns;
	return "";
}

int nvme_ns_get_meta_size(void *ns)
{
	stub_log(__func__);
	(void)ns;
	return 0;
}

const char *nvme_ns_get_model(void *ns)
{
	stub_log(__func__);
	(void)ns;
	return "";
}

const char *nvme_ns_get_serial(void *ns)
{
	stub_log(__func__);
	(void)ns;
	return "";
}

/* Namespace path iteration (tree.c) */
void *nvme_namespace_first_path(void *ns)
{
	stub_log(__func__);
	(void)ns;
	return NULL;
}

void *nvme_namespace_next_path(void *ns, void *p)
{
	stub_log(__func__);
	(void)ns;
	(void)p;
	return NULL;
}

/* ANA log utilities (linux.c) */
unsigned long nvme_get_ana_log_len_from_id_ctrl(const void *id_ctrl, int rgo)
{
	stub_log(__func__);
	(void)id_ctrl;
	(void)rgo;
	return 0;
}

/* MI status string (mi.c) */
const char *nvme_mi_status_to_string(int status)
{
	stub_log(__func__);
	(void)status;
	return "MI not supported on Windows";
}