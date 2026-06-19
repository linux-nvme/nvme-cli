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
