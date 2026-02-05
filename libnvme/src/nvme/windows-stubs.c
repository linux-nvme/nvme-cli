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
#include "private.h"

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
void nvmf_default_config(struct nvme_fabrics_config *cfg)
{
	stub_log(__func__);
	(void)cfg;
}

void nvmf_update_config(nvme_ctrl_t c, const struct nvme_fabrics_config *cfg)
{
	stub_log(__func__);
	(void)c;
	(void)cfg;
}

int nvmf_add_ctrl(nvme_host_t h, nvme_ctrl_t c,
		  const struct nvme_fabrics_config *cfg)
{
	stub_log(__func__);
	(void)h;
	(void)c;
	(void)cfg;
	errno = ENOTSUP;
	return -1;
}

int nvmf_connect_ctrl(nvme_ctrl_t c)
{
	stub_log(__func__);
	(void)c;
	errno = ENOTSUP;
	return -1;
}

int nvmf_get_discovery_log(nvme_ctrl_t c, struct nvmf_discovery_log **logp, int max_retries)
{
	stub_log(__func__);
	(void)c;
	(void)logp;
	(void)max_retries;
	errno = ENOTSUP;
	return -1;
}

int nvmf_get_discovery_wargs(struct nvme_get_discovery_args *args, struct nvmf_discovery_log **logp)
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

bool nvmf_is_registration_supported(nvme_ctrl_t c)
{
	stub_log(__func__);
	(void)c;
	return false; /* Not supported */
}

int nvmf_register_ctrl(nvme_ctrl_t c, enum nvmf_dim_tas tas, __u32 *result)
{
	stub_log(__func__);
	(void)c;
	(void)tas;
	(void)result;
	errno = ENOTSUP;
	return -1;
}

int nvme_parse_uri(const char *str, struct nvme_fabrics_uri **uri)
{
	stub_log(__func__);
	(void)str;
	(void)uri;
	errno = ENOTSUP;
	return -1;
}

void nvme_free_uri(struct nvme_fabrics_uri *uri)
{
	stub_log(__func__);
	(void)uri;
}

/*
 * Stub implementations for tree functions (tree.c)
 * Minimal support - just return NULL/errors
 */

void nvme_release_fds(struct nvme_global_ctx *ctx)
{
	stub_log(__func__);
	(void)ctx;
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

int nvme_scan(const char *config_file, struct nvme_global_ctx **ctx)
{
	stub_log(__func__);
	(void)config_file;
	(void)ctx;
	/* Scanning not supported on Windows */
	errno = ENOTSUP;
	return -1;
}

struct nvme_global_ctx *nvme_create_global_ctx(FILE *fp, int log_level)
{
	stub_log(__func__);
	(void)fp;
	(void)log_level;
	/* Return NULL - global context not supported on Windows */
	return NULL;
}

int nvme_scan_ctrl(struct nvme_global_ctx *ctx, const char *name, nvme_ctrl_t *c)
{
	stub_log(__func__);
	(void)ctx;
	(void)name;
	(void)c;
	errno = ENOTSUP;
	return -1;
}

int nvme_scan_topology(struct nvme_global_ctx *ctx, nvme_scan_filter_t f, void *f_args)
{
	stub_log(__func__);
	(void)ctx;
	(void)f;
	(void)f_args;
	errno = ENOTSUP;
	return -1;
}

nvme_host_t nvme_first_host(struct nvme_global_ctx *ctx)
{
	stub_log(__func__);
	(void)ctx;
	return NULL;
}

nvme_host_t nvme_next_host(struct nvme_global_ctx *ctx, nvme_host_t h)
{
	stub_log(__func__);
	(void)ctx;
	(void)h;
	return NULL;
}

nvme_host_t nvme_lookup_host(struct nvme_global_ctx *ctx, const char *hostnqn, const char *hostid)
{
	stub_log(__func__);
	(void)ctx;
	(void)hostnqn;
	(void)hostid;
	return NULL;
}

int nvme_default_host(struct nvme_global_ctx *ctx, nvme_host_t *h)
{
	stub_log(__func__);
	(void)ctx;
	(void)h;
	errno = ENOTSUP;
	return -1;
}

nvme_subsystem_t nvme_first_subsystem(nvme_host_t h)
{
	stub_log(__func__);
	(void)h;
	return NULL;
}

nvme_subsystem_t nvme_next_subsystem(nvme_host_t h, nvme_subsystem_t s)
{
	stub_log(__func__);
	(void)h;
	(void)s;
	return NULL;
}

nvme_subsystem_t nvme_lookup_subsystem(struct nvme_host *h, const char *name, const char *subsysnqn)
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

nvme_ctrl_t nvme_lookup_ctrl(nvme_subsystem_t s, const char *transport,
			     const char *traddr, const char *host_traddr,
			     const char *host_iface, const char *trsvcid,
			     nvme_ctrl_t p)
{
	stub_log(__func__);
	(void)s;
	(void)transport;
	(void)traddr;
	(void)host_traddr;
	(void)host_iface;
	(void)trsvcid;
	(void)p;
	return NULL;
}

nvme_ns_t nvme_ctrl_first_ns(nvme_ctrl_t c)
{
	stub_log(__func__);
	(void)c;
	return NULL;
}

nvme_ns_t nvme_ctrl_next_ns(nvme_ctrl_t c, nvme_ns_t n)
{
	stub_log(__func__);
	(void)c;
	(void)n;
	return NULL;
}

nvme_path_t nvme_ctrl_first_path(nvme_ctrl_t c)
{
	stub_log(__func__);
	(void)c;
	return NULL;
}

nvme_path_t nvme_ctrl_next_path(nvme_ctrl_t c, nvme_path_t p)
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

nvme_subsystem_t nvme_ns_get_subsystem(nvme_ns_t n)
{
	stub_log(__func__);
	(void)n;
	return NULL;
}

nvme_ctrl_t nvme_ns_get_ctrl(nvme_ns_t n)
{
	stub_log(__func__);
	(void)n;
	return NULL;
}

int nvme_ns_get_fd(void *ns)
{
	stub_log(__func__);
	(void)ns;
	return -1;
}

int nvme_ns_get_nsid(nvme_ns_t n)
{
	stub_log(__func__);
	(void)n;
	return 0;
}

enum nvme_csi nvme_ns_get_csi(nvme_ns_t n)
{
	stub_log(__func__);
	(void)n;
	return 0;
}

const uint8_t *nvme_ns_get_eui64(nvme_ns_t n)
{
	stub_log(__func__);
	(void)n;
	return NULL;
}

const uint8_t *nvme_ns_get_nguid(nvme_ns_t n)
{
	stub_log(__func__);
	(void)n;
	return NULL;
}

void nvme_ns_get_uuid(nvme_ns_t n, unsigned char out[NVME_UUID_LEN])
{
	stub_log(__func__);
	(void)n;
	(void)out;
}

struct nvme_transport_handle *nvme_ns_get_transport_handle(nvme_ns_t n)
{
	stub_log(__func__);
	(void)n;
	return NULL;
}

int nvme_ns_identify(nvme_ns_t n, struct nvme_id_ns *ns)
{
	stub_log(__func__);
	(void)n;
	(void)ns;
	errno = ENOTSUP;
	return -1;
}

const char *nvme_ns_get_sysfs_dir(nvme_ns_t n)
{
	stub_log(__func__);
	(void)n;
	return "";
}

const char *nvme_ns_get_name(nvme_ns_t n)
{
	stub_log(__func__);
	(void)n;
	return "";
}

const char *nvme_ns_get_generic_name(nvme_ns_t n)
{
	stub_log(__func__);
	(void)n;
	return "";
}

int nvme_ns_get_lba_size(nvme_ns_t n)
{
	stub_log(__func__);
	(void)n;
	return 0;
}

uint64_t nvme_ns_get_lba_count(nvme_ns_t n)
{
	stub_log(__func__);
	(void)n;
	return 0;
}

uint64_t nvme_ns_get_lba_util(nvme_ns_t n)
{
	stub_log(__func__);
	(void)n;
	return 0;
}

const char *nvme_path_get_name(nvme_path_t p)
{
	stub_log(__func__);
	(void)p;
	return "";
}

const char *nvme_path_get_sysfs_dir(nvme_path_t p)
{
	stub_log(__func__);
	(void)p;
	return "";
}

const char *nvme_path_get_ana_state(nvme_path_t p)
{
	stub_log(__func__);
	(void)p;
	return "";
}

nvme_ctrl_t nvme_path_get_ctrl(nvme_path_t p)
{
	stub_log(__func__);
	(void)p;
	return NULL;
}

nvme_ns_t nvme_path_get_ns(nvme_path_t p)
{
	stub_log(__func__);
	(void)p;
	return NULL;
}

const char *nvme_ctrl_get_name(nvme_ctrl_t c)
{
	stub_log(__func__);
	(void)c;
	return "";
}

const char *nvme_ctrl_get_sysfs_dir(nvme_ctrl_t c)
{
	stub_log(__func__);
	(void)c;
	return "";
}

const char *nvme_ctrl_get_address(nvme_ctrl_t c)
{
	stub_log(__func__);
	(void)c;
	return "";
}

const char *nvme_ctrl_get_transport(nvme_ctrl_t c)
{
	stub_log(__func__);
	(void)c;
	return "";
}

const char *nvme_ctrl_get_state(nvme_ctrl_t c)
{
	stub_log(__func__);
	(void)c;
	return "";
}

struct nvme_fabrics_config *nvme_ctrl_get_config(nvme_ctrl_t c)
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

nvme_subsystem_t nvme_ctrl_get_subsystem(nvme_ctrl_t c)
{
	stub_log(__func__);
	(void)c;
	return NULL;
}

struct nvme_transport_handle *nvme_ctrl_get_transport_handle(nvme_ctrl_t c)
{
	stub_log(__func__);
	(void)c;
	return NULL;
}

void nvme_free_ctrl(struct nvme_ctrl *c)
{
	stub_log(__func__);
	(void)c;
}

int nvme_disconnect_ctrl(nvme_ctrl_t c)
{
	stub_log(__func__);
	(void)c;
	errno = ENOTSUP;
	return -1;
}

void nvme_unlink_ctrl(struct nvme_ctrl *c)
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
const char *nvme_subsystem_get_name(nvme_subsystem_t s)
{
	return nvme_subsys_get_name(s);
}

const char *nvme_subsystem_get_nqn(nvme_subsystem_t s)
{
	return nvme_subsys_get_nqn(s);
}

const char *nvme_subsystem_get_sysfs_dir(nvme_subsystem_t s)
{
	return nvme_subsys_get_sysfs_dir(s);
}

nvme_host_t nvme_subsystem_get_host(nvme_subsystem_t s)
{
	return nvme_subsys_get_host(s);
}

nvme_ctrl_t nvme_subsystem_first_ctrl(nvme_subsystem_t s)
{
	return nvme_first_ctrl(s);
}

nvme_ctrl_t nvme_subsystem_next_ctrl(nvme_subsystem_t s, nvme_ctrl_t c)
{
	return nvme_next_ctrl(s, c);
}

nvme_ns_t nvme_subsystem_first_ns(nvme_subsystem_t s)
{
	return nvme_subsys_first_ns(s);
}

nvme_ns_t nvme_subsystem_next_ns(nvme_subsystem_t s, nvme_ns_t n)
{
	return nvme_subsys_next_ns(s, n);
}

const char *nvme_host_get_hostnqn(nvme_host_t h)
{
	stub_log(__func__);
	(void)h;
	return "";
}

const char *nvme_host_get_hostid(nvme_host_t h)
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

int nvme_dump_tree(struct nvme_global_ctx *ctx)
{
	stub_log(__func__);
	(void)ctx;
	errno = ENOTSUP;
	return -1;
}

int nvme_dump_config(struct nvme_global_ctx *ctx, const char *config_file)
{
	stub_log(__func__);
	(void)ctx;
	(void)config_file;
	errno = ENOTSUP;
	return -1;
}

/*
 * Stub implementations for MI functions (mi.c and mi-mctp.c)
 */

int nvme_mi_admin_admin_passthru(struct nvme_transport_handle *hdl,
				 struct nvme_passthru_cmd *cmd)
{
	stub_log(__func__);
	(void)hdl;
	(void)cmd;
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

nvme_mi_ep_t nvme_mi_first_endpoint(struct nvme_global_ctx *ctx)
{
	stub_log(__func__);
	(void)ctx;
	return NULL;
}

nvme_mi_ep_t nvme_mi_next_endpoint(struct nvme_global_ctx *ctx, nvme_mi_ep_t e)
{
	stub_log(__func__);
	(void)ctx;
	(void)e;
	return NULL;
}

int nvme_mi_scan_ep(nvme_mi_ep_t ep, bool force_rescan)
{
	stub_log(__func__);
	(void)ep;
	(void)force_rescan;
	errno = ENOTSUP;
	return -1;
}

struct nvme_transport_handle *nvme_mi_first_transport_handle(nvme_mi_ep_t ep)
{
	stub_log(__func__);
	(void)ep;
	return NULL;
}

struct nvme_transport_handle *nvme_mi_next_transport_handle(nvme_mi_ep_t ep,
	struct nvme_transport_handle *hdl)
{
	stub_log(__func__);
	(void)ep;
	(void)hdl;
	return NULL;
}

void nvme_mi_close(nvme_mi_ep_t ep)
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
int nvme_export_tls_key_versioned(struct nvme_global_ctx *ctx,
				  unsigned char version, unsigned char hmac,
				  const unsigned char *key_data,
				  size_t key_len, char **identity)
{
	stub_log(__func__);
	(void)ctx;
	(void)version;
	(void)hmac;
	(void)key_data;
	(void)key_len;
	(void)identity;
	errno = ENOTSUP;
	return -1;
}

int nvme_export_tls_key(struct nvme_global_ctx *ctx,
	const unsigned char *key_data, int key_len, char **identity)
{
	stub_log(__func__);
	(void)ctx;
	(void)key_data;
	(void)key_len;
	(void)identity;
	errno = ENOTSUP;
	return -1;
}

int nvme_import_tls_key_versioned(struct nvme_global_ctx *ctx,
				  const char *encoded_key,
				  unsigned char *version,
				  unsigned char *hmac,
				  size_t *key_len,
				  unsigned char **key)
{
	stub_log(__func__);
	(void)ctx;
	(void)encoded_key;
	(void)version;
	(void)hmac;
	(void)key_len;
	(void)key;
	errno = ENOTSUP;
	return -1;
}

int nvme_import_tls_key(struct nvme_global_ctx *ctx, const char *encoded_key,
			int *key_len, unsigned int *hmac, unsigned char **key)
{
	stub_log(__func__);
	(void)ctx;
	(void)encoded_key;
	(void)key_len;
	(void)hmac;
	(void)key;
	errno = ENOTSUP;
	return -1;
}

/*
 * Additional stubs for nvme-cli linking
 */

/* Transport handle operations (linux.c) */
int nvme_open(struct nvme_global_ctx *ctx, const char *name,
	      struct nvme_transport_handle **hdlp)
{
	stub_log(__func__);
	(void)ctx;
	(void)name;
	(void)hdlp;
	errno = ENOTSUP;
	return -1;
}

void nvme_close(struct nvme_transport_handle *hdl)
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

bool nvme_transport_handle_is_blkdev(struct nvme_transport_handle *hdl)
{
	stub_log(__func__);
	(void)hdl;
	return false;
}

bool nvme_transport_handle_is_chardev(struct nvme_transport_handle *hdl)
{
	stub_log(__func__);
	(void)hdl;
	return false;
}

bool nvme_transport_handle_is_direct(struct nvme_transport_handle *hdl)
{
	stub_log(__func__);
	(void)hdl;
	return false;
}

/* Controller property getters (tree.c) */
const char *nvme_ctrl_get_cntlid(nvme_ctrl_t c)
{
	stub_log(__func__);
	(void)c;
	return "";
}

const char *nvme_ctrl_get_firmware(nvme_ctrl_t c)
{
	stub_log(__func__);
	(void)c;
	return "";
}

const char *nvme_ctrl_get_model(nvme_ctrl_t c)
{
	stub_log(__func__);
	(void)c;
	return "";
}

const char *nvme_ctrl_get_phy_slot(nvme_ctrl_t c)
{
	stub_log(__func__);
	(void)c;
	return "";
}

const char *nvme_ctrl_get_serial(nvme_ctrl_t c)
{
	stub_log(__func__);
	(void)c;
	return "";
}

/* Subsystem property getters (tree.c) */
const char *nvme_subsystem_get_fw_rev(nvme_subsystem_t s)
{
	stub_log(__func__);
	(void)s;
	return "";
}

const char *nvme_subsystem_get_iopolicy(nvme_subsystem_t s)
{
	stub_log(__func__);
	(void)s;
	return "";
}

const char *nvme_subsystem_get_model(nvme_subsystem_t s)
{
	stub_log(__func__);
	(void)s;
	return "";
}

const char *nvme_subsystem_get_serial(nvme_subsystem_t s)
{
	stub_log(__func__);
	(void)s;
	return "";
}

const char *nvme_subsystem_get_type(nvme_subsystem_t s)
{
	stub_log(__func__);
	(void)s;
	return "";
}

/* Namespace property getters (tree.c) */
const char *nvme_ns_get_firmware(nvme_ns_t n)
{
	stub_log(__func__);
	(void)n;
	return "";
}

int nvme_ns_get_meta_size(nvme_ns_t n)
{
	stub_log(__func__);
	(void)n;
	return 0;
}

const char *nvme_ns_get_model(nvme_ns_t n)
{
	stub_log(__func__);
	(void)n;
	return "";
}

const char *nvme_ns_get_serial(nvme_ns_t n)
{
	stub_log(__func__);
	(void)n;
	return "";
}

/* Namespace path iteration (tree.c) */
nvme_path_t nvme_namespace_first_path(nvme_ns_t ns)
{
	stub_log(__func__);
	(void)ns;
	return NULL;
}

nvme_path_t nvme_namespace_next_path(nvme_ns_t ns, nvme_path_t p)
{
	stub_log(__func__);
	(void)ns;
	(void)p;
	return NULL;
}

/* ANA log utilities (linux.c) */
size_t nvme_get_ana_log_len_from_id_ctrl(const struct nvme_id_ctrl *id_ctrl,
	bool rgo)
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

/*
 * Linux keyring and TLS key management stubs (linux.c)
 * These are used by nvme-cli security commands
 */
int nvme_read_key(long keyring_id, long key_id, int *key_len, unsigned char **key_data)
{
	stub_log(__func__);
	(void)keyring_id;
	(void)key_id;
	(void)key_len;
	(void)key_data;
	errno = ENOTSUP;
	return -1;
}

int nvme_lookup_keyring(const char *keyring, long *kr_id)
{
	stub_log(__func__);
	(void)keyring;
	(void)kr_id;
	errno = ENOTSUP;
	return -1;
}

int nvme_update_key(long keyring_id, long key_id, const unsigned char *key_data, int key_len)
{
	stub_log(__func__);
	(void)keyring_id;
	(void)key_id;
	(void)key_data;
	(void)key_len;
	errno = ENOTSUP;
	return -1;
}

int nvme_revoke_tls_key(const char *keyring, const char *key_type, const char *identity)
{
	stub_log(__func__);
	(void)keyring;
	(void)key_type;
	(void)identity;
	errno = ENOTSUP;
	return -1;
}

int nvme_scan_tls_keys(const char *keyring)
{
	stub_log(__func__);
	(void)keyring;
	errno = ENOTSUP;
	return -1;
}

int nvme_describe_key_serial(long key_id)
{
	stub_log(__func__);
	(void)key_id;
	errno = ENOTSUP;
	return -1;
}

int nvme_insert_tls_key_versioned(const char *keyring, const char *key_type, const char *hostnqn,
				 const char *subsysnqn, int version, int hmac,
				 unsigned char *configured_key, int key_len)
{
	stub_log(__func__);
	(void)keyring;
	(void)key_type;
	(void)hostnqn;
	(void)subsysnqn;
	(void)version;
	(void)hmac;
	(void)configured_key;
	(void)key_len;
	errno = ENOTSUP;
	return -1;
}

char *nvme_generate_tls_key_identity_compat(const char *hostnqn, const char *subsysnqn,
					   int version, int hmac,
					   unsigned char *configured_key, int key_len)
{
	stub_log(__func__);
	(void)hostnqn;
	(void)subsysnqn;
	(void)version;
	(void)hmac;
	(void)configured_key;
	(void)key_len;
	return NULL;
}

int nvme_insert_tls_key_compat(const char *keyring, const char *key_type, const char *identity,
			       unsigned char *key_data, int key_len)
{
	stub_log(__func__);
	(void)keyring;
	(void)key_type;
	(void)identity;
	(void)key_data;
	(void)key_len;
	errno = ENOTSUP;
	return -1;
}

char *nvme_generate_tls_key_identity(const char *hostnqn, const char *subsysnqn,
				    int version, int hmac,
				    unsigned char *configured_key, int key_len)
{
	stub_log(__func__);
	(void)hostnqn;
	(void)subsysnqn;
	(void)version;
	(void)hmac;
	(void)configured_key;
	(void)key_len;
	return NULL;
}

char *nvmf_hostnqn_from_file(void)
{
	stub_log(__func__);
	/* No /etc/nvme/hostnqn equivalent on Windows */
	return NULL;
}

int nvme_gen_dhchap_key(char *hostnqn, unsigned int hmac, unsigned int key_len,
		       unsigned char *secret, unsigned char *key)
{
	stub_log(__func__);
	(void)hostnqn;
	(void)hmac;
	(void)key_len;
	(void)secret;
	(void)key;
	errno = ENOTSUP;
	return -1;
}

/* Hostnqn generation (fabrics.c) */
char *nvmf_hostnqn_generate(void)
{
	stub_log(__func__);
	/* Could implement UUID-based generation, but for now just fail */
	return NULL;
}

char *nvmf_hostnqn_generate_from_hostid(char *hostid)
{
	stub_log(__func__);
	(void)hostid;
	return NULL;
}

/* Dry run and other global state functions (linux.c) */
void nvme_set_dry_run(void *ctx, int enable)
{
	stub_log(__func__);
	(void)ctx;
	(void)enable;
}

/* Extended Telemetry (linux.c) */
int nvme_set_etdas(void *hdl, int *changed)
{
	stub_log(__func__);
	(void)hdl;
	(void)changed;
	errno = ENOTSUP;
	return -1;
}

int nvme_clear_etdas(void *hdl, int *changed)
{
	stub_log(__func__);
	(void)hdl;
	(void)changed;
	errno = ENOTSUP;
	return -1;
}

/* Transport handle callbacks (linux.c) */
void nvme_transport_handle_set_submit_entry(void *hdl, void *fn)
{
	stub_log(__func__);
	(void)hdl;
	(void)fn;
}

void nvme_transport_handle_set_submit_exit(void *hdl, void *fn)
{
	stub_log(__func__);
	(void)hdl;
	(void)fn;
}

void nvme_transport_handle_set_decide_retry(void *hdl, void *fn)
{
	stub_log(__func__);
	(void)hdl;
	(void)fn;
}

/* Path property getters (tree.c) */
const char *nvme_path_get_numa_nodes(struct nvme_path *p)
{
	stub_log(__func__);
	(void)p;
	return "";
}

int nvme_path_get_queue_depth(struct nvme_path *p)
{
	stub_log(__func__);
	(void)p;
	return 0;
}

/* Fabrics string conversion functions (fabrics.c) */
const char *nvmf_trtype_str(__u8 trtype)
{
	stub_log(__func__);
	(void)trtype;
	return "unknown";
}

const char *nvmf_eflags_str(__u16 eflags)
{
	stub_log(__func__);
	(void)eflags;
	return "unknown";
}

const char *nvmf_sectype_str(__u8 sectype)
{
	stub_log(__func__);
	(void)sectype;
	return "unknown";
}

const char *nvmf_cms_str(__u8 cms)
{
	stub_log(__func__);
	(void)cms;
	return "unknown";
}

const char *nvmf_qptype_str(__u8 qptype)
{
	stub_log(__func__);
	(void)qptype;
	return "unknown";
}

const char *nvmf_prtype_str(__u8 prtype)
{
	stub_log(__func__);
	(void)prtype;
	return "unknown";
}

const char *nvmf_adrfam_str(__u8 adrfam)
{
	stub_log(__func__);
	(void)adrfam;
	return "unknown";
}

const char *nvmf_subtype_str(__u8 subtype)
{
	stub_log(__func__);
	(void)subtype;
	return "unknown";
}

const char *nvmf_treq_str(__u8 treq)
{
	stub_log(__func__);
	(void)treq;
	return "unknown";
}

/* NBFT functions (nbft.c) */
int nvmf_nbft_read_files(struct nvme_global_ctx *ctx, char *path,
			  struct nbft_file_entry **nbft_list)
{
	stub_log(__func__);
	(void)ctx;
	(void)path;
	(void)nbft_list;
	errno = ENOTSUP;
	return -1;
}

void nvmf_nbft_free(struct nvme_global_ctx *ctx, struct nbft_file_entry *head)
{
	stub_log(__func__);
	(void)ctx;
	(void)head;
}