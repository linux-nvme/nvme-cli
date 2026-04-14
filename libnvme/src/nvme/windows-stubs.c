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

void libnvme_stubs_set_debug(int enable)
{
	stub_log_enabled = enable;
}

/*
 * Stub implementations for tree functions (tree.c)
 * Minimal support - just return NULL/errors
 */
void __libnvme_free_host(struct libnvme_host *h)
{
	stub_log(__func__);
	(void)h;
}

__public int libnvme_scan_ctrl(struct libnvme_global_ctx *ctx, const char *name, libnvme_ctrl_t *c)
{
	stub_log(__func__);
	(void)ctx;
	(void)name;
	(void)c;
	errno = ENOTSUP;
	return -1;
}

__public int libnvme_scan_namespace(struct libnvme_global_ctx *ctx,
		const char *name, libnvme_ns_t *ns)
{
	stub_log(__func__);
	(void)ctx;
	(void)name;
	if (ns)
		*ns = NULL;
	return -ENOTSUP;
}

__public int libnvme_scan_topology(struct libnvme_global_ctx *ctx, libnvme_scan_filter_t f, void *f_args)
{
	stub_log(__func__);
	(void)ctx;
	(void)f;
	(void)f_args;
	errno = ENOTSUP;
	return -1;
}

__public libnvme_host_t libnvme_first_host(struct libnvme_global_ctx *ctx)
{
	stub_log(__func__);
	(void)ctx;
	return NULL;
}

__public libnvme_host_t libnvme_next_host(struct libnvme_global_ctx *ctx, libnvme_host_t h)
{
	stub_log(__func__);
	(void)ctx;
	(void)h;
	return NULL;
}

libnvme_host_t libnvme_lookup_host(struct libnvme_global_ctx *ctx, const char *hostnqn, const char *hostid)
{
	stub_log(__func__);
	(void)ctx;
	(void)hostnqn;
	(void)hostid;
	return NULL;
}

__public libnvme_subsystem_t libnvme_first_subsystem(libnvme_host_t h)
{
	stub_log(__func__);
	(void)h;
	return NULL;
}

__public libnvme_subsystem_t libnvme_next_subsystem(libnvme_host_t h, libnvme_subsystem_t s)
{
	stub_log(__func__);
	(void)h;
	(void)s;
	return NULL;
}

libnvme_subsystem_t libnvme_lookup_subsystem(struct libnvme_host *h, const char *name, const char *subsysnqn)
{
	stub_log(__func__);
	(void)h;
	(void)name;
	(void)subsysnqn;
	return NULL;
}

libnvme_ctrl_t libnvme_lookup_ctrl(libnvme_subsystem_t s,
			     struct libnvmf_context *fctx,
			     libnvme_ctrl_t p)
{
	stub_log(__func__);
	(void)s;
	(void)fctx;
	(void)p;
	return NULL;
}

__public libnvme_ns_t libnvme_ctrl_first_ns(libnvme_ctrl_t c)
{
	stub_log(__func__);
	(void)c;
	return NULL;
}

__public libnvme_ns_t libnvme_ctrl_next_ns(libnvme_ctrl_t c, libnvme_ns_t n)
{
	stub_log(__func__);
	(void)c;
	(void)n;
	return NULL;
}

__public libnvme_path_t libnvme_ctrl_first_path(libnvme_ctrl_t c)
{
	stub_log(__func__);
	(void)c;
	return NULL;
}

__public libnvme_path_t libnvme_ctrl_next_path(libnvme_ctrl_t c, libnvme_path_t p)
{
	stub_log(__func__);
	(void)c;
	(void)p;
	return NULL;
}

__public libnvme_subsystem_t libnvme_ns_get_subsystem(libnvme_ns_t n)
{
	stub_log(__func__);
	(void)n;
	return NULL;
}

__public libnvme_ctrl_t libnvme_ns_get_ctrl(libnvme_ns_t n)
{
	stub_log(__func__);
	(void)n;
	return NULL;
}

__public enum nvme_csi libnvme_ns_get_csi(libnvme_ns_t n)
{
	stub_log(__func__);
	(void)n;
	return 0;
}

__public const uint8_t *libnvme_ns_get_eui64(libnvme_ns_t n)
{
	stub_log(__func__);
	(void)n;
	return NULL;
}

__public const uint8_t *libnvme_ns_get_nguid(libnvme_ns_t n)
{
	stub_log(__func__);
	(void)n;
	return NULL;
}

__public void libnvme_ns_get_uuid(libnvme_ns_t n, unsigned char out[NVME_UUID_LEN])
{
	stub_log(__func__);
	(void)n;
	(void)out;
}

int libnvme_ns_get_transport_handle(libnvme_ns_t n,
		struct libnvme_transport_handle **hdl)
{
	stub_log(__func__);
	(void)n;
	(void)hdl;
	return -ENOTSUP;
}

__public int libnvme_ns_identify(libnvme_ns_t n, struct nvme_id_ns *ns)
{
	stub_log(__func__);
	(void)n;
	(void)ns;
	errno = ENOTSUP;
	return -1;
}

__public const char *libnvme_ns_get_generic_name(libnvme_ns_t n)
{
	stub_log(__func__);
	(void)n;
	return "";
}

__public libnvme_ctrl_t libnvme_path_get_ctrl(libnvme_path_t p)
{
	stub_log(__func__);
	(void)p;
	return NULL;
}

__public libnvme_ns_t libnvme_path_get_ns(libnvme_path_t p)
{
	stub_log(__func__);
	(void)p;
	return NULL;
}

__public const char *libnvme_ctrl_get_state(libnvme_ctrl_t c)
{
	stub_log(__func__);
	(void)c;
	return "";
}

__public struct libnvme_fabrics_config *libnvme_ctrl_get_config(libnvme_ctrl_t c)
{
	stub_log(__func__);
	(void)c;
	return NULL;
}

__public libnvme_subsystem_t libnvme_ctrl_get_subsystem(libnvme_ctrl_t c)
{
	stub_log(__func__);
	(void)c;
	return NULL;
}

__public struct libnvme_transport_handle *libnvme_ctrl_get_transport_handle(libnvme_ctrl_t c)
{
	stub_log(__func__);
	(void)c;
	return NULL;
}

__public void libnvme_free_ctrl(struct libnvme_ctrl *c)
{
	stub_log(__func__);
	(void)c;
}

__public int libnvme_disconnect_ctrl(libnvme_ctrl_t c)
{
	stub_log(__func__);
	(void)c;
	errno = ENOTSUP;
	return -1;
}

__public void libnvme_unlink_ctrl(struct libnvme_ctrl *c)
{
	stub_log(__func__);
	(void)c;
}

/* Subsystem functions (full name) - same as subsys */
__public libnvme_host_t libnvme_subsystem_get_host(libnvme_subsystem_t s)
{
	stub_log(__func__);
	(void)s;
	return NULL;
}

__public libnvme_ctrl_t libnvme_subsystem_first_ctrl(libnvme_subsystem_t s)
{
	stub_log(__func__);
	(void)s;
	return NULL;
}

__public libnvme_ctrl_t libnvme_subsystem_next_ctrl(libnvme_subsystem_t s, libnvme_ctrl_t c)
{
	stub_log(__func__);
	(void)s;
	(void)c;
	return NULL;
}

__public libnvme_ns_t libnvme_subsystem_first_ns(libnvme_subsystem_t s)
{
	stub_log(__func__);
	(void)s;
	return NULL;
}

__public libnvme_ns_t libnvme_subsystem_next_ns(libnvme_subsystem_t s, libnvme_ns_t n)
{
	stub_log(__func__);
	(void)s;
	(void)n;
	return NULL;
}

__public int libnvme_dump_tree(struct libnvme_global_ctx *ctx)
{
	stub_log(__func__);
	(void)ctx;
	errno = ENOTSUP;
	return -1;
}

__public int libnvme_dump_config(struct libnvme_global_ctx *ctx, int fd)
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

int libnvme_mi_admin_admin_passthru(struct libnvme_transport_handle *hdl,
				 struct libnvme_passthru_cmd *cmd)
{
	stub_log(__func__);
	(void)hdl;
	(void)cmd;
	errno = ENOTSUP;
	return -1;
}

__public libnvme_mi_ep_t libnvme_mi_first_endpoint(struct libnvme_global_ctx *ctx)
{
	stub_log(__func__);
	(void)ctx;
	return NULL;
}

__public libnvme_mi_ep_t libnvme_mi_next_endpoint(struct libnvme_global_ctx *ctx, libnvme_mi_ep_t e)
{
	stub_log(__func__);
	(void)ctx;
	(void)e;
	return NULL;
}

__public int libnvme_mi_scan_ep(libnvme_mi_ep_t ep, bool force_rescan)
{
	stub_log(__func__);
	(void)ep;
	(void)force_rescan;
	errno = ENOTSUP;
	return -1;
}

struct libnvme_transport_handle *libnvme_mi_first_transport_handle(libnvme_mi_ep_t ep)
{
	stub_log(__func__);
	(void)ep;
	return NULL;
}

struct libnvme_transport_handle *libnvme_mi_next_transport_handle(libnvme_mi_ep_t ep,
	struct libnvme_transport_handle *hdl)
{
	stub_log(__func__);
	(void)ep;
	(void)hdl;
	return NULL;
}

__public void libnvme_mi_close(libnvme_mi_ep_t ep)
{
	stub_log(__func__);
	(void)ep;
}

/*
 * TLS/PSK key management stubs (linux.c functions)
 */
__public int libnvme_export_tls_key_versioned(struct libnvme_global_ctx *ctx,
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

__public int libnvme_export_tls_key(struct libnvme_global_ctx *ctx,
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

__public int libnvme_import_tls_key_versioned(struct libnvme_global_ctx *ctx,
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

__public int libnvme_import_tls_key(struct libnvme_global_ctx *ctx, const char *encoded_key,
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
__public const char *libnvme_ns_get_firmware(libnvme_ns_t n)
{
	stub_log(__func__);
	(void)n;
	return "";
}

__public const char *libnvme_ns_get_model(libnvme_ns_t n)
{
	stub_log(__func__);
	(void)n;
	return "";
}

__public const char *libnvme_ns_get_serial(libnvme_ns_t n)
{
	stub_log(__func__);
	(void)n;
	return "";
}

/* Namespace path iteration (tree.c) */
__public libnvme_path_t libnvme_namespace_first_path(libnvme_ns_t ns)
{
	stub_log(__func__);
	(void)ns;
	return NULL;
}

__public libnvme_path_t libnvme_namespace_next_path(libnvme_ns_t ns, libnvme_path_t p)
{
	stub_log(__func__);
	(void)ns;
	(void)p;
	return NULL;
}

/* MI status string (mi.c) */
__public const char *libnvme_mi_status_to_string(int status)
{
	stub_log(__func__);
	(void)status;
	return "MI not supported on Windows";
}

/*
 * Linux keyring and TLS key management stubs (linux.c)
 * These are used by nvme-cli security commands
 */
__public int libnvme_read_key(struct libnvme_global_ctx *ctx, long keyring_id,
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

__public int libnvme_lookup_keyring(struct libnvme_global_ctx *ctx,
		const char *keyring, long *key)
{
	stub_log(__func__);
	(void)ctx;
	(void)keyring;
	(void)key;
	errno = ENOTSUP;
	return -1;
}

__public int libnvme_update_key(struct libnvme_global_ctx *ctx, long keyring_id,
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

__public int libnvme_revoke_tls_key(struct libnvme_global_ctx *ctx, const char *keyring,
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

__public int libnvme_scan_tls_keys(struct libnvme_global_ctx *ctx, const char *keyring,
		libnvme_scan_tls_keys_cb_t cb, void *data)
{
	stub_log(__func__);
	(void)ctx;
	(void)keyring;
	(void)cb;
	(void)data;
	errno = ENOTSUP;
	return -1;
}

__public char *libnvme_describe_key_serial(struct libnvme_global_ctx *ctx,
		long key_id)
{
	stub_log(__func__);
	(void)ctx;
	(void)key_id;
	return NULL;
}

__public int libnvme_insert_tls_key_versioned(struct libnvme_global_ctx *ctx,
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

__public int libnvme_generate_tls_key_identity_compat(struct libnvme_global_ctx *ctx,
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

__public int libnvme_insert_tls_key_compat(struct libnvme_global_ctx *ctx,
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

__public int libnvme_generate_tls_key_identity(struct libnvme_global_ctx *ctx,
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

__public char *libnvme_read_hostnqn(void)
{
	stub_log(__func__);
	/* No /etc/nvme/hostnqn equivalent on Windows */
	return NULL;
}

__public int libnvme_gen_dhchap_key(struct libnvme_global_ctx *ctx,
		char *hostnqn, enum libnvme_hmac_alg hmac,
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

__public int libnvme_create_raw_secret(struct libnvme_global_ctx *ctx,
		const char *secret, size_t key_len, unsigned char **raw_secret)
{
	stub_log(__func__);
	return -ENOTSUP;
}

/* Hostnqn generation (fabrics.c) */
__public char *libnvme_generate_hostnqn(void)
{
	stub_log(__func__);
	/* Could implement UUID-based generation, but for now just fail */
	return NULL;
}

/* Path property getters (tree.c) */
__public int libnvme_path_get_queue_depth(struct libnvme_path *p)
{
	stub_log(__func__);
	(void)p;
	return 0;
}

/* Fabrics string conversion functions (fabrics.c) */
__public const char *libnvmf_trtype_str(__u8 trtype)
{
	stub_log(__func__);
	(void)trtype;
	return "unknown";
}

__public const char *libnvmf_eflags_str(__u16 eflags)
{
	stub_log(__func__);
	(void)eflags;
	return "unknown";
}

__public const char *libnvmf_sectype_str(__u8 sectype)
{
	stub_log(__func__);
	(void)sectype;
	return "unknown";
}

__public const char *libnvmf_cms_str(__u8 cms)
{
	stub_log(__func__);
	(void)cms;
	return "unknown";
}

__public const char *libnvmf_qptype_str(__u8 qptype)
{
	stub_log(__func__);
	(void)qptype;
	return "unknown";
}

__public const char *libnvmf_prtype_str(__u8 prtype)
{
	stub_log(__func__);
	(void)prtype;
	return "unknown";
}

__public const char *libnvmf_adrfam_str(__u8 adrfam)
{
	stub_log(__func__);
	(void)adrfam;
	return "unknown";
}

__public const char *libnvmf_subtype_str(__u8 subtype)
{
	stub_log(__func__);
	(void)subtype;
	return "unknown";
}

__public const char *libnvmf_treq_str(__u8 treq)
{
	stub_log(__func__);
	(void)treq;
	return "unknown";
}

/* NBFT functions (nbft.c) */
__public int libnvmf_nbft_read_files(struct libnvme_global_ctx *ctx, char *path,
			  struct nbft_file_entry **nbft_list)
{
	stub_log(__func__);
	(void)ctx;
	(void)path;
	(void)nbft_list;
	errno = ENOTSUP;
	return -1;
}

__public void libnvmf_nbft_free(struct libnvme_global_ctx *ctx, struct nbft_file_entry *head)
{
	stub_log(__func__);
	(void)ctx;
	(void)head;
}
