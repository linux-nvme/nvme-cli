/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * This file is part of libnvme.
 * Copyright (c) 2026, Dell Technologies Inc. or its subsidiaries.
 *
 * Authors: Martin Belanger <Martin.Belanger@dell.com>
 */
#pragma once

#if defined(NVME_HAVE_NETDB) || defined(CONFIG_FABRICS)
#include <ifaddrs.h>
#endif

#include <nvme/fabrics.h>
#include <nvme/tree.h>

#include "nvme/private.h"

struct libnvmf_hooks {
	/* common hooks */
	bool (*decide_retry)(struct libnvmf_context *fctx, int err,
			void *user_data);
	void (*connected)(struct libnvmf_context *fctx, struct libnvme_ctrl *c,
			void *user_data);
	void (*already_connected)(struct libnvmf_context *fctx,
			struct libnvme_host *host, const char *subsysnqn,
			const char *transport, const char *traddr,
			const char *trsvcid, void *user_data);

	/* discovery hooks */
	void (*discovery_log)(struct libnvmf_context *fctx,
			bool connect,
			struct nvmf_discovery_log *log,
			uint64_t numrec, void *user_data);
	int (*parser_init)(struct libnvmf_context *fctx,
			void *user_data);
	void (*parser_cleanup)(struct libnvmf_context *fctx,
			void *user_data);
	int (*parser_next_line)(struct libnvmf_context *fctx,
			void *user_data);

	void *user_data;
};

struct libnvmf_context { // !generate-accessors:read=generated,write=generated
	struct libnvme_global_ctx *ctx;
	struct libnvmf_hooks hooks; // !access:read=none,write=none

	/* NVMe controller parameters */
	struct libnvme_ctrl_params ctrl_params; // !access:nested

	/* discovery defaults */
	int default_max_discovery_retries;
	int default_keep_alive_timeout;

	/* common fabrics configuration */
	const char *device;
	bool persistent;

	/* host configuration */
	const char *hostnqn; // !access:write=custom
	const char *hostid;  // !access:write=custom

	/* authentication and transport encryption configuration */
	const char *hostkey;          // !access:write=custom
	const char *ctrlkey;          // !access:write=custom
	const char *keyring;          // !access:write=custom
	char *tls_key;                // !access:write=custom
	const char *tls_key_identity; // !access:write=custom
};

/**
 * NVMe-oF private struct definitions.
 *
 * Structs in this file are NVMe-oF-specific (fabrics layer). They are kept
 * separate from private.h so that PCIe-only builds can exclude this entire
 * file and its generated accessors (accessors-fabrics.{h,c}) along with the
 * rest of the fabrics layer.
 */

/**
 * struct libnvmf_tid - Transport ID: identifies a full path between a host and
 * an NVMe-oF controller (an NVMe-oF *association*).
 *
 * The identity is the NVMe Transport tuple (transport, traddr, trsvcid, and
 * the host-side host_traddr / host_iface) plus the subsysnqn and the host's
 * hostnqn and hostid. The host identity matters: the same physical machine
 * connecting to the same target under a different Host NQN -- or a different
 * Host Identifier -- is a different host, hence a different path.
 *
 * Both hostnqn AND hostid are part of the identity. The NVMe Base
 * Specification (revision 2.3, section 6.3 "Connect Command") allows a single
 * Host NQN to present multiple Host Identifiers as independent "elements" of a
 * host, each a separate association -- so the pair, not the Host NQN alone, is
 * the host identity. The Linux kernel agrees: nvmf_ctlr_matches_baseopts()
 * compares subsysnqn, host nqn and host id. Linux currently enforces a 1:1
 * Host NQN <-> Host Identifier mapping (nvmf_host_add() rejects a mismatch), so
 * the multi-hostid case is unreachable there today, but that is kernel policy
 * rather than a spec guarantee; carrying hostid keeps the TID correct anyway.
 *
 * This is deliberately a separate type from struct libnvme_ctrl_params, not a
 * reuse of it. libnvmf_tid is a pure, owned *identity*: it owns its strings,
 * caches derived values (canonical form, string rendering), and carries
 * hostnqn/hostid, which libnvme_ctrl_params does not. libnvme_ctrl_params is a
 * controller-*creation* parameter bag: borrowed pointers and it carries the
 * fabrics tuning config (struct libnvme_fabrics_config) that the TID
 * intentionally excludes. Merging them would force one role onto the other.
 *
 * Addressing is numeric-only: a traddr/host_traddr must be a numeric IP (the
 * constructors reject a hostname). Resolving a name can block on DNS and is a
 * policy choice about which address to use, so it belongs to the caller, not
 * the library (see design/INTEGRATION.md). The caller resolves and hands the
 * TID a numeric address.
 *
 * All string fields are owned (strdup'd) by the struct. The leading-underscore
 * members cache derived values (canonical form, string rendering), recomputed
 * lazily and cleared by any identity change.
 */
struct libnvmf_tid { // !generate-accessors !generate-lifecycle
	/*
	 * Addressing is construction-only (from_fields/parse/dup); the identity
	 * triplet is set together via libnvmf_tid_set_identity(). No per-field
	 * setters, so every mutation goes through a sanitizing path.
	 */
	char *transport;    // !access:write=none
	char *traddr;       // !access:write=none
	char *trsvcid;      // !access:write=none
	char *subsysnqn;    // !access:write=none
	char *host_traddr;  // !access:write=none
	char *host_iface;   // !access:write=none
	char *hostnqn;      // !access:write=none
	char *hostid;       // !access:write=none
	/* cached values; recomputed lazily, cleared on identity edits */
	char *_canonical;   // !access:read=none,write=none
	char *_str;         // !access:read=none,write=none
};

struct libnvmf_discovery_args { // !generate-accessors !generate-lifecycle
	int max_retries; // !default:6
	__u8 lsp;        // !default:NVMF_LOG_DISC_LSP_NONE
};

/**
 * struct libnvmf_uri - Parsed URI structure
 * @scheme:		Scheme name (typically 'nvme')
 * @protocol:		Optional protocol/transport (e.g. 'tcp')
 * @userinfo:		Optional user information component of the URI authority
 * @host:		Host transport address
 * @port:		The port subcomponent or 0 if not specified
 * @path_segments:	NULL-terminated array of path segments
 * @query:		Optional query string component (separated by '?')
 * @fragment:		Optional fragment identifier component
 *			(separated by '#')
 */
struct libnvmf_uri { // !generate-accessors
	char *scheme;
	char *protocol;
	char *userinfo;
	char *host;
	int port;
	char **path_segments;
	char *query;
	char *fragment;
};

/**
 * libnvmf_exat_len() - Return length rounded up by 4
 * @val_len: Value length
 *
 * Calculate the size in bytes, rounded to a multiple of 4 (e.g., size of
 * __u32), of the buffer needed to hold the exat value of size
 * @val_len.
 *
 * Return: Length rounded up by 4
 */
static inline __u16 libnvmf_exat_len(size_t val_len)
{
	return (__u16)round_up(val_len, sizeof(__u32));
}

/**
 * libnvmf_exat_size - Return min aligned size to hold value
 * @val_len: This is the length of the data to be copied to the "exatval"
 *           field of a "struct nvmf_ext_attr".
 *
 * Calculate the size of the "struct nvmf_ext_attr" needed to hold
 * a value of size @val_len.
 *
 * Return: The size in bytes, rounded to a multiple of 4 (i.e. size of
 * __u32), of the "struct nvmf_ext_attr" required to hold a string of
 * length @val_len.
 */
static inline __u16 libnvmf_exat_size(size_t val_len)
{
	return (__u16)(sizeof(struct nvmf_ext_attr) + libnvmf_exat_len(val_len));
}

#if defined(NVME_HAVE_NETDB) || defined(CONFIG_FABRICS)
/**
 * libnvmf_getifaddrs - Cached wrapper around getifaddrs()
 * @ctx: pointer to the global context
 *
 * On the first call, this function invokes the POSIX getifaddrs()
 * and caches the result in the global context. Subsequent calls
 * return the cached data. The caller must NOT call freeifaddrs()
 * on the returned data. The cache will be freed when the global
 * context is freed.
 *
 * Return: Pointer to I/F data, NULL on error.
 */
const struct ifaddrs *libnvmf_getifaddrs(struct libnvme_global_ctx *ctx);
#endif /* NVME_HAVE_NETDB || CONFIG_FABRICS */

/**
 * struct candidate_args - Parameters used to match an existing controller
 * @transport:		Transport type: loop, fc, rdma, tcp
 * @traddr:		Transport address (destination address)
 * @trsvcid:		Transport service ID
 * @subsysnqn:		Subsystem NQN
 * @host_traddr:	Host transport address (source address)
 * @host_iface:		Host interface for connection (tcp only)
 * @iface_list:		Interface list (tcp only)
 * @addreq:		Address comparison function (for traddr, host_traddr)
 * @well_known_nqn:	Set to true when @subsysnqn is the well-known NQN
 */
struct candidate_args {
	const char *transport;
	const char *traddr;
	const char *trsvcid;
	const char *subsysnqn;
	const char *host_traddr;
	const char *host_iface;
#if defined(NVME_HAVE_NETDB) || defined(CONFIG_FABRICS)
	const struct ifaddrs *iface_list;
#endif
	bool (*addreq)(const char *, const char *);
	bool well_known_nqn;
};
typedef bool (*ctrl_match_t)(struct libnvme_ctrl *c,
		struct candidate_args *candidate);

bool libnvmf_ctrl_match_config(struct libnvme_ctrl *c,
		struct libnvmf_context *fctx);
struct libnvme_ctrl *libnvmf_ctrl_find(struct libnvme_subsystem *s,
		struct libnvmf_context *fctx);

/**
 * libnvmf_get_entity_name - Get Entity Name (ENAME).
 * @buffer: The buffer where the ENAME will be saved as an ASCII string.
 * @bufsz:  The size of @buffer.
 *
 * Per TP8010, ENAME is defined as the name associated with the host (i.e.
 * hostname).
 *
 * Return: Number of characters copied to @buffer.
 */
size_t libnvmf_get_entity_name(char *buffer, size_t bufsz);

/**
 * libnvmf_get_entity_version - Get Entity Version (EVER).
 * @buffer: The buffer where the EVER will be saved as an ASCII string.
 * @bufsz:  The size of @buffer.
 *
 * EVER is defined as the operating system name and version as an ASCII
 * string. This function reads different files from the file system and
 * builds a string as follows: [os type] [os release] [distro release]
 *
 *     E.g. "Linux 5.17.0-rc1 SLES 15.4"
 *
 * Return: Number of characters copied to @buffer.
 */
size_t libnvmf_get_entity_version(char *buffer, size_t bufsz);

/* File-access and misc helpers (util-fabrics.c). */
int libnvmf_mkdir_p(const char *path, mode_t mode);
int libnvmf_mkstemp(char *template);
void libnvmf_fsync_dir(const char *path);
bool libnvmf_valid_name(const char *s);
uint64_t libnvmf_fnv1a_64(const void *buf, size_t len);

/*
 * libnvmf_trim() - strip leading/trailing whitespace in place; returns a
 * pointer into @s.
 */
char *libnvmf_trim(char *s);

/**
 * libnvmf_registry_create_instance - Write a registry entry for a freshly
 * connected controller.  Called from the connect path once the kernel returns
 * instance=N.
 */
int libnvmf_registry_create_instance(struct libnvme_global_ctx *ctx,
				     int instance, const char *owner);

/**
 * libnvmf_registry_delete_instance - Remove the registry entry for a
 * controller identified by instance number.  Called from the connect path
 * when owner is NULL to clear any stale entry left by a previous owner that
 * held the same instance number before it was recycled.  ENOENT is silently
 * ignored.
 */
int libnvmf_registry_delete_instance(struct libnvme_global_ctx *ctx,
				     int instance);

/**
 * libnvmf_host_get_ids - Retrieve host ids from various sources
 *
 * @ctx:		struct libnvme_global_ctx object
 * @hostnqn_arg:	Input hostnqn (command line) argument
 * @hostid_arg:		Input hostid (command line) argument
 * @hostnqn:		Output hostnqn
 * @hostid:		Output hostid
 *
 * libnvmf_host_get_ids figures out which hostnqn/hostid is to be used.
 * There are several sources where this information can be retrieved.
 *
 * The order is:
 *
 *  - Start with informartion from DMI or device-tree
 *  - Override hostnqn and hostid from /etc/nvme files
 *  - Override hostnqn or hostid with values from JSON
 *    configuration file. The first host entry in the file is
 *    considered the default host.
 *  - Override hostnqn or hostid with values from the command line
 *    (@hostnqn_arg, @hostid_arg).
 *
 *  If the IDs are still NULL after the lookup algorithm, the function
 *  will generate random IDs.
 *
 *  The function also verifies that hostnqn and hostid matches. The Linux
 *  NVMe implementation expects a 1:1 matching between the IDs.
 *
 *  Return: 0 on success (@hostnqn and @hostid contain valid strings
 *  which the caller needs to free), or negative error code otherwise.
 */
int libnvmf_host_get_ids(struct libnvme_global_ctx *ctx,
		      const char *hostnqn_arg, const char *hostid_arg,
		      char **hostnqn, char **hostid);
