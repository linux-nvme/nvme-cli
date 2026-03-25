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

#include <nvme/linux.h>
#include <nvme/types.h>

#include "private.h"
#include "compiler_attributes.h"

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
 * Stub implementations for tree functions (tree.c)
 * Minimal support - just return NULL/errors
 */
void __nvme_free_host(struct nvme_host *h)
{
	stub_log(__func__);
	(void)h;
}

__public int nvme_scan_ctrl(struct nvme_global_ctx *ctx, const char *name, nvme_ctrl_t *c)
{
	stub_log(__func__);
	(void)ctx;
	(void)name;
	(void)c;
	errno = ENOTSUP;
	return -1;
}

__public int nvme_scan_namespace(struct nvme_global_ctx *ctx,
		const char *name, nvme_ns_t *ns)
{
	stub_log(__func__);
	(void)ctx;
	(void)name;
	if (ns)
		*ns = NULL;
	return -ENOTSUP;
}

__public int nvme_scan_topology(struct nvme_global_ctx *ctx, nvme_scan_filter_t f, void *f_args)
{
	stub_log(__func__);
	(void)ctx;
	(void)f;
	(void)f_args;
	errno = ENOTSUP;
	return -1;
}

__public nvme_host_t nvme_first_host(struct nvme_global_ctx *ctx)
{
	stub_log(__func__);
	(void)ctx;
	return NULL;
}

__public nvme_host_t nvme_next_host(struct nvme_global_ctx *ctx, nvme_host_t h)
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

__public nvme_subsystem_t nvme_first_subsystem(nvme_host_t h)
{
	stub_log(__func__);
	(void)h;
	return NULL;
}

__public nvme_subsystem_t nvme_next_subsystem(nvme_host_t h, nvme_subsystem_t s)
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

nvme_ctrl_t nvme_lookup_ctrl(nvme_subsystem_t s,
			     struct nvmf_context *fctx,
			     nvme_ctrl_t p)
{
	stub_log(__func__);
	(void)s;
	(void)fctx;
	(void)p;
	return NULL;
}

__public nvme_ns_t nvme_ctrl_first_ns(nvme_ctrl_t c)
{
	stub_log(__func__);
	(void)c;
	return NULL;
}

__public nvme_ns_t nvme_ctrl_next_ns(nvme_ctrl_t c, nvme_ns_t n)
{
	stub_log(__func__);
	(void)c;
	(void)n;
	return NULL;
}

__public nvme_path_t nvme_ctrl_first_path(nvme_ctrl_t c)
{
	stub_log(__func__);
	(void)c;
	return NULL;
}

__public nvme_path_t nvme_ctrl_next_path(nvme_ctrl_t c, nvme_path_t p)
{
	stub_log(__func__);
	(void)c;
	(void)p;
	return NULL;
}

__public nvme_subsystem_t nvme_ns_get_subsystem(nvme_ns_t n)
{
	stub_log(__func__);
	(void)n;
	return NULL;
}

__public nvme_ctrl_t nvme_ns_get_ctrl(nvme_ns_t n)
{
	stub_log(__func__);
	(void)n;
	return NULL;
}

__public enum nvme_csi nvme_ns_get_csi(nvme_ns_t n)
{
	stub_log(__func__);
	(void)n;
	return 0;
}

__public const uint8_t *nvme_ns_get_eui64(nvme_ns_t n)
{
	stub_log(__func__);
	(void)n;
	return NULL;
}

__public const uint8_t *nvme_ns_get_nguid(nvme_ns_t n)
{
	stub_log(__func__);
	(void)n;
	return NULL;
}

__public void nvme_ns_get_uuid(nvme_ns_t n, unsigned char out[NVME_UUID_LEN])
{
	stub_log(__func__);
	(void)n;
	(void)out;
}

int nvme_ns_get_transport_handle(nvme_ns_t n,
		struct nvme_transport_handle **hdl)
{
	stub_log(__func__);
	(void)n;
	(void)hdl;
	return -ENOTSUP;
}

__public int nvme_ns_identify(nvme_ns_t n, struct nvme_id_ns *ns)
{
	stub_log(__func__);
	(void)n;
	(void)ns;
	errno = ENOTSUP;
	return -1;
}

__public const char *nvme_ns_get_generic_name(nvme_ns_t n)
{
	stub_log(__func__);
	(void)n;
	return "";
}

__public nvme_ctrl_t nvme_path_get_ctrl(nvme_path_t p)
{
	stub_log(__func__);
	(void)p;
	return NULL;
}

__public nvme_ns_t nvme_path_get_ns(nvme_path_t p)
{
	stub_log(__func__);
	(void)p;
	return NULL;
}

__public const char *nvme_ctrl_get_state(nvme_ctrl_t c)
{
	stub_log(__func__);
	(void)c;
	return "";
}

__public struct nvme_fabrics_config *nvme_ctrl_get_config(nvme_ctrl_t c)
{
	stub_log(__func__);
	(void)c;
	return NULL;
}

__public nvme_subsystem_t nvme_ctrl_get_subsystem(nvme_ctrl_t c)
{
	stub_log(__func__);
	(void)c;
	return NULL;
}

__public struct nvme_transport_handle *nvme_ctrl_get_transport_handle(nvme_ctrl_t c)
{
	stub_log(__func__);
	(void)c;
	return NULL;
}

__public void nvme_free_ctrl(struct nvme_ctrl *c)
{
	stub_log(__func__);
	(void)c;
}

__public int nvme_disconnect_ctrl(nvme_ctrl_t c)
{
	stub_log(__func__);
	(void)c;
	errno = ENOTSUP;
	return -1;
}

__public void nvme_unlink_ctrl(struct nvme_ctrl *c)
{
	stub_log(__func__);
	(void)c;
}

/* Subsystem functions (full name) - same as subsys */
__public nvme_host_t nvme_subsystem_get_host(nvme_subsystem_t s)
{
	stub_log(__func__);
	(void)s;
	return NULL;
}

__public nvme_ctrl_t nvme_subsystem_first_ctrl(nvme_subsystem_t s)
{
	stub_log(__func__);
	(void)s;
	return NULL;
}

__public nvme_ctrl_t nvme_subsystem_next_ctrl(nvme_subsystem_t s, nvme_ctrl_t c)
{
	stub_log(__func__);
	(void)s;
	(void)c;
	return NULL;
}

__public nvme_ns_t nvme_subsystem_first_ns(nvme_subsystem_t s)
{
	stub_log(__func__);
	(void)s;
	return NULL;
}

__public nvme_ns_t nvme_subsystem_next_ns(nvme_subsystem_t s, nvme_ns_t n)
{
	stub_log(__func__);
	(void)s;
	(void)n;
	return NULL;
}

__public int nvme_dump_tree(struct nvme_global_ctx *ctx)
{
	stub_log(__func__);
	(void)ctx;
	errno = ENOTSUP;
	return -1;
}

__public int nvme_dump_config(struct nvme_global_ctx *ctx, int fd)
{
	stub_log(__func__);
	(void)ctx;
	(void)fd;
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

__public nvme_mi_ep_t nvme_mi_first_endpoint(struct nvme_global_ctx *ctx)
{
	stub_log(__func__);
	(void)ctx;
	return NULL;
}

__public nvme_mi_ep_t nvme_mi_next_endpoint(struct nvme_global_ctx *ctx, nvme_mi_ep_t e)
{
	stub_log(__func__);
	(void)ctx;
	(void)e;
	return NULL;
}

__public int nvme_mi_scan_ep(nvme_mi_ep_t ep, bool force_rescan)
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

__public void nvme_mi_close(nvme_mi_ep_t ep)
{
	stub_log(__func__);
	(void)ep;
}

/*
 * TLS/PSK key management stubs (linux.c functions)
 */
__public int nvme_export_tls_key_versioned(struct nvme_global_ctx *ctx,
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

__public int nvme_export_tls_key(struct nvme_global_ctx *ctx,
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

__public int nvme_import_tls_key_versioned(struct nvme_global_ctx *ctx,
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

__public int nvme_import_tls_key(struct nvme_global_ctx *ctx, const char *encoded_key,
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
/* Namespace property getters (tree.c) */
__public const char *nvme_ns_get_firmware(nvme_ns_t n)
{
	stub_log(__func__);
	(void)n;
	return "";
}

__public const char *nvme_ns_get_model(nvme_ns_t n)
{
	stub_log(__func__);
	(void)n;
	return "";
}

__public const char *nvme_ns_get_serial(nvme_ns_t n)
{
	stub_log(__func__);
	(void)n;
	return "";
}

/* Namespace path iteration (tree.c) */
__public nvme_path_t nvme_namespace_first_path(nvme_ns_t ns)
{
	stub_log(__func__);
	(void)ns;
	return NULL;
}

__public nvme_path_t nvme_namespace_next_path(nvme_ns_t ns, nvme_path_t p)
{
	stub_log(__func__);
	(void)ns;
	(void)p;
	return NULL;
}

/* MI status string (mi.c) */
__public const char *nvme_mi_status_to_string(int status)
{
	stub_log(__func__);
	(void)status;
	return "MI not supported on Windows";
}

/*
 * Linux keyring and TLS key management stubs (linux.c)
 * These are used by nvme-cli security commands
 */
__public int nvme_read_key(struct nvme_global_ctx *ctx, long keyring_id,
		long key_id, int *len, unsigned char **key)
{
	stub_log(__func__);
	(void)ctx;
	(void)keyring_id;
	(void)key_id;
	(void)len;
	(void)key;
	errno = ENOTSUP;
	return -1;
}

__public int nvme_lookup_keyring(struct nvme_global_ctx *ctx,
		const char *keyring, long *key)
{
	stub_log(__func__);
	(void)ctx;
	(void)keyring;
	(void)key;
	errno = ENOTSUP;
	return -1;
}

__public int nvme_update_key(struct nvme_global_ctx *ctx, long keyring_id,
		const char *key_type, const char *identity,
		unsigned char *key_data, int key_len, long *key)
{
	stub_log(__func__);
	(void)ctx;
	(void)keyring_id;
	(void)key_type;
	(void)identity;
	(void)key_data;
	(void)key_len;
	(void)key;
	errno = ENOTSUP;
	return -1;
}

__public int nvme_revoke_tls_key(struct nvme_global_ctx *ctx, const char *keyring,
		const char *key_type, const char *identity)
{
	stub_log(__func__);
	(void)ctx;
	(void)keyring;
	(void)key_type;
	(void)identity;
	errno = ENOTSUP;
	return -1;
}

__public int nvme_scan_tls_keys(struct nvme_global_ctx *ctx, const char *keyring,
		nvme_scan_tls_keys_cb_t cb, void *data)
{
	stub_log(__func__);
	(void)ctx;
	(void)keyring;
	(void)cb;
	(void)data;
	errno = ENOTSUP;
	return -1;
}

__public char *nvme_describe_key_serial(struct nvme_global_ctx *ctx,
		long key_id)
{
	stub_log(__func__);
	(void)ctx;
	(void)key_id;
	return NULL;
}

__public int nvme_insert_tls_key_versioned(struct nvme_global_ctx *ctx,
		const char *keyring, const char *key_type,
		const char *hostnqn, const char *subsysnqn,
		int version, int hmac,
		unsigned char *configured_key, int key_len,
		long *key)
{
	stub_log(__func__);
	(void)ctx;
	(void)keyring;
	(void)key_type;
	(void)hostnqn;
	(void)subsysnqn;
	(void)version;
	(void)hmac;
	(void)configured_key;
	(void)key_len;
	(void)key;
	errno = ENOTSUP;
	return -1;
}

__public int nvme_generate_tls_key_identity_compat(struct nvme_global_ctx *ctx,
		const char *hostnqn, const char *subsysnqn,
		int version, int hmac, unsigned char *configured_key,
		int key_len, char **identity)
{
	stub_log(__func__);
	(void)ctx;
	(void)hostnqn;
	(void)subsysnqn;
	(void)version;
	(void)hmac;
	(void)configured_key;
	(void)key_len;
	(void)identity;
	errno = ENOTSUP;
	return -1;
}

__public int nvme_insert_tls_key_compat(struct nvme_global_ctx *ctx,
		const char *keyring, const char *key_type,
		const char *hostnqn, const char *subsysnqn,
		int version, int hmac,
		unsigned char *configured_key, int key_len,
		long *key)
{
	stub_log(__func__);
	(void)ctx;
	(void)keyring;
	(void)key_type;
	(void)hostnqn;
	(void)subsysnqn;
	(void)version;
	(void)hmac;
	(void)configured_key;
	(void)key_len;
	(void)key;
	errno = ENOTSUP;
	return -1;
}

__public int nvme_generate_tls_key_identity(struct nvme_global_ctx *ctx,
		const char *hostnqn, const char *subsysnqn,
		int version, int hmac,
		unsigned char *configured_key, int key_len,
		char **identity)
{
	stub_log(__func__);
	(void)ctx;
	(void)hostnqn;
	(void)subsysnqn;
	(void)version;
	(void)hmac;
	(void)configured_key;
	(void)key_len;
	(void)identity;
	errno = ENOTSUP;
	return -1;
}

__public char *nvme_read_hostnqn(void)
{
	stub_log(__func__);
	/* No /etc/nvme/hostnqn equivalent on Windows */
	return NULL;
}

__public int nvme_gen_dhchap_key(struct nvme_global_ctx *ctx,
		char *hostnqn, enum nvme_hmac_alg hmac,
		unsigned int key_len, unsigned char *secret,
		unsigned char *key)
{
	stub_log(__func__);
	(void)ctx;
	(void)hostnqn;
	(void)hmac;
	(void)key_len;
	(void)secret;
	(void)key;
	errno = ENOTSUP;
	return -1;
}

/* Hostnqn generation (fabrics.c) */
__public char *nvme_generate_hostnqn(void)
{
	stub_log(__func__);
	/* Could implement UUID-based generation, but for now just fail */
	return NULL;
}

/* Path property getters (tree.c) */
__public int nvme_path_get_queue_depth(struct nvme_path *p)
{
	stub_log(__func__);
	(void)p;
	return 0;
}

/* Fabrics string conversion functions (fabrics.c) */
__public const char *nvmf_trtype_str(__u8 trtype)
{
	stub_log(__func__);
	(void)trtype;
	return "unknown";
}

__public const char *nvmf_eflags_str(__u16 eflags)
{
	stub_log(__func__);
	(void)eflags;
	return "unknown";
}

__public const char *nvmf_sectype_str(__u8 sectype)
{
	stub_log(__func__);
	(void)sectype;
	return "unknown";
}

__public const char *nvmf_cms_str(__u8 cms)
{
	stub_log(__func__);
	(void)cms;
	return "unknown";
}

__public const char *nvmf_qptype_str(__u8 qptype)
{
	stub_log(__func__);
	(void)qptype;
	return "unknown";
}

__public const char *nvmf_prtype_str(__u8 prtype)
{
	stub_log(__func__);
	(void)prtype;
	return "unknown";
}

__public const char *nvmf_adrfam_str(__u8 adrfam)
{
	stub_log(__func__);
	(void)adrfam;
	return "unknown";
}

__public const char *nvmf_subtype_str(__u8 subtype)
{
	stub_log(__func__);
	(void)subtype;
	return "unknown";
}

__public const char *nvmf_treq_str(__u8 treq)
{
	stub_log(__func__);
	(void)treq;
	return "unknown";
}

/* NBFT functions (nbft.c) */
__public int nvmf_nbft_read_files(struct nvme_global_ctx *ctx, char *path,
			  struct nbft_file_entry **nbft_list)
{
	stub_log(__func__);
	(void)ctx;
	(void)path;
	(void)nbft_list;
	errno = ENOTSUP;
	return -1;
}

__public void nvmf_nbft_free(struct nvme_global_ctx *ctx, struct nbft_file_entry *head)
{
	stub_log(__func__);
	(void)ctx;
	(void)head;
}
