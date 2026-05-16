// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libnvme.
 * Copyright (c) 2026, Dell Technologies Inc. or its subsidiaries.
 *
 * Authors: Martin Belanger <Martin.Belanger@dell.com>
 */

#include <arpa/inet.h>
#include <stdlib.h>

#include <libnvme.h>

#include "cleanup.h"
#include "private.h"
#include "private-fabrics.h"

/**
 * _tcp_ctrl_match_host_traddr_no_src_addr() - Match host_traddr w/o src_addr
 * @c:		An existing controller instance
 * @candidate:	Candidate ctrl we're trying to match with @c.
 *
 * On kernels prior to 6.1 (i.e. src_addr is not available), try to match
 * a candidate controller's host_traddr to that of an existing controller.
 *
 * This function takes an optimistic approach. In doubt, it will declare a
 * match and return true.
 *
 * Return: true if @c->host_traddr matches @candidate->host_traddr,
 *         false otherwise.
 */
static bool _tcp_ctrl_match_host_traddr_no_src_addr(struct libnvme_ctrl *c,
		struct candidate_args *candidate)
{
	if (c->host_traddr)
		return candidate->addreq(candidate->host_traddr,
			c->host_traddr);

	/* If c->cfg.host_traddr is NULL, then the controller (c)
	 * uses the interface's primary address as the source
	 * address. If c->cfg.host_iface is defined we can
	 * determine the primary address associated with that
	 * interface and compare that to the candidate->host_traddr.
	 */
	if (c->host_iface)
		return libnvme_iface_primary_addr_matches(candidate->iface_list,
			c->host_iface, candidate->host_traddr);

	/* If both c->cfg.host_traddr and c->cfg.host_iface are
	 * NULL, we don't have enough information to make a
	 * 100% positive match. Regardless, let's be optimistic
	 * and assume that we have a match.
	 */
	libnvme_msg(c->ctx, LIBNVME_LOG_DEBUG,
		"Not enough data, but assume %s matches candidate's host_traddr: %s\n",
		libnvme_ctrl_get_name(c), candidate->host_traddr);

	return true;
}

/**
 * _tcp_ctrl_match_host_iface_no_src_addr() - Match host_iface w/o src_addr
 * @c:		An existing controller instance
 * @candidate:	Candidate ctrl we're trying to match with @c.
 *
 * On kernels prior to 6.1 (i.e. src_addr is not available), try to match
 * a candidate controller's host_iface to that of an existing controller.
 *
 * This function takes an optimistic approach. In doubt, it will declare a
 * match and return true.
 *
 * Return: true if @c->host_iface matches @candidate->host_iface,
 *         false otherwise.
 */
static bool _tcp_ctrl_match_host_iface_no_src_addr(struct libnvme_ctrl *c,
		struct candidate_args *candidate)
{
	if (c->host_iface)
		return streq0(candidate->host_iface, c->host_iface);

	/* If c->cfg.host_traddr is not NULL we can infer the controller's (c)
	 * interface from it and compare it to the candidate->host_iface.
	 */
	if (c->host_traddr) {
		const char *c_host_iface;

		c_host_iface =
			libnvme_iface_matching_addr(candidate->iface_list,
				c->host_traddr);
		return streq0(candidate->host_iface, c_host_iface);
	}

	/* If both c->cfg.host_traddr and c->cfg.host_iface are
	 * NULL, we don't have enough information to make a
	 * 100% positive match. Regardless, let's be optimistic
	 * and assume that we have a match.
	 */
	libnvme_msg(c->ctx, LIBNVME_LOG_DEBUG,
		"Not enough data, but assume %s matches candidate's host_iface: %s\n",
		libnvme_ctrl_get_name(c), candidate->host_iface);

	return true;
}

/**
 * _tcp_opt_params_match_no_src_addr() - Match optional
 * host_traddr/host_iface w/o src_addr
 * @c:		An existing controller instance
 * @candidate:	Candidate ctrl we're trying to match with @c.
 *
 * Before kernel 6.1, the src_addr was not reported by the kernel which makes
 * it hard to match a candidate's host_traddr and host_iface to an existing
 * controller if that controller was created without specifying the
 * host_traddr and/or host_iface. This function tries its best in the absense
 * of a src_addr to match @c to @candidate. This may not be 100% accurate.
 * Only the src_addr can provide 100% accuracy.
 *
 * This function takes an optimistic approach. In doubt, it will declare a
 * match and return true.
 *
 * Return: true if @c matches @candidate. false otherwise.
 */
static bool _tcp_opt_params_match_no_src_addr(struct libnvme_ctrl *c,
		struct candidate_args *candidate)
{
	/* Check host_traddr only if candidate is interested */
	if (candidate->host_traddr) {
		if (!_tcp_ctrl_match_host_traddr_no_src_addr(c, candidate))
			return false;
	}

	/* Check host_iface only if candidate is interested */
	if (candidate->host_iface) {
		if (!_tcp_ctrl_match_host_iface_no_src_addr(c, candidate))
			return false;
	}

	return true;
}

/**
 * _tcp_opt_params_match() - Match optional host_traddr/host_iface
 * @c:		An existing controller instance
 * @candidate:	Candidate ctrl we're trying to match with @c.
 *
 * The host_traddr and host_iface are optional for TCP. When they are not
 * specified, the kernel looks up the destination IP address (traddr) in the
 * routing table to determine the best interface for the connection. The
 * kernel then retrieves the primary IP address assigned to that interface
 * and uses that as the connection's source address.
 *
 * An interface's primary address is the default source address used for
 * all connections made on that interface unless host-traddr is used to
 * override the default. Kernel-selected interfaces and/or source addresses
 * are hidden from user-space applications unless the kernel makes that
 * information available through the "src_addr" attribute in the
 * sysfs (kernel 6.1 or later).
 *
 * Sometimes, an application may force the interface by specifying the
 * "host-iface" or may force a different source address (instead of the
 * primary address) by providing the "host-traddr".
 *
 * If the candidate specifies the host_traddr and/or host_iface but they
 * do not match the existing controller's host_traddr and/or host_iface
 * (they could be NULL), we may still be able to find a match by taking
 * the existing controller's src_addr into consideration since that
 * parameter identifies the actual source address of the connection and
 * therefore can be used to infer the interface of the connection. However,
 * the src_addr can only be read from the nvme device's sysfs "address"
 * attribute starting with kernel 6.1 (or kernels that backported the
 * src_addr patch).
 *
 * For legacy kernels that do not provide the src_addr we must use a
 * different algorithm to match the host_traddr and host_iface, but
 * it's not 100% accurate.
 *
 * Return: true if @c matches @candidate. false otherwise.
 */
static bool _tcp_opt_params_match(struct libnvme_ctrl *c,
		struct candidate_args *candidate)
{
	char *src_addr, buffer[INET6_ADDRSTRLEN];
	const char *c_iface;

	/* Check if src_addr is available (kernel 6.1 or later) */
	src_addr = libnvme_ctrl_get_src_addr(c, buffer, sizeof(buffer));
	if (!src_addr)
		return _tcp_opt_params_match_no_src_addr(c, candidate);

	/* Check host_traddr only if candidate is interested */
	if (candidate->host_traddr &&
	    !candidate->addreq(candidate->host_traddr, src_addr))
		return false;

	/* Check host_iface only if candidate is interested */
	c_iface = libnvme_iface_matching_addr(candidate->iface_list, src_addr);
	if (candidate->host_iface && !streq0(candidate->host_iface, c_iface))
		return false;

	return true;
}

/**
 * _tcp_match_ctrl() - Check if controller matches candidate (TCP only)
 * @c:		An existing controller instance
 * @candidate:	Candidate ctrl we're trying to match with @c.
 *
 * We want to determine if an existing controller can be re-used
 * for the candidate controller we're trying to instantiate.
 *
 * For TCP, we do not have a match if the candidate's transport, traddr,
 * trsvcid are not identical to those of the existing controller.
 * These 3 parameters are mandatory for a match.
 *
 * The host_traddr and host_iface are optional. When the candidate does
 * not specify them (both NULL), we can ignore them. Otherwise, we must
 * employ advanced investigation techniques to determine if there's a match.
 *
 * Return: true if a match is found, false otherwise.
 */
static bool _tcp_match_ctrl(struct libnvme_ctrl *c,
		struct candidate_args *candidate)
{
	if (!streq0(c->transport, candidate->transport))
		return false;

	if (!streq0(c->trsvcid, candidate->trsvcid))
		return false;

	if (!candidate->addreq(c->traddr, candidate->traddr))
		return false;

	if (candidate->well_known_nqn && !libnvme_ctrl_get_discovery_ctrl(c))
		return false;

	if (candidate->subsysnqn && !streq0(c->subsysnqn, candidate->subsysnqn))
		return false;

	/* Check host_traddr / host_iface only if candidate is interested */
	if ((candidate->host_iface || candidate->host_traddr) &&
	    !_tcp_opt_params_match(c, candidate))
		return false;

	return true;
}

ctrl_match_t libnvmf_candidate_init(struct libnvme_global_ctx *ctx,
		struct candidate_args *candidate,
		const struct libnvmf_context *fctx)
{
	if (streq0(fctx->transport, "tcp")) {
		candidate->iface_list = libnvmf_getifaddrs(ctx);
		candidate->addreq = libnvme_ipaddrs_eq;
		return _tcp_match_ctrl;
	}

	if (streq0(fctx->transport, "rdma")) {
		candidate->addreq = libnvme_ipaddrs_eq;
		return libnvme_tree_ctrl_match;
	}

	return NULL;
}

static void libnvmf_read_sysfs_dhchap(struct libnvme_global_ctx *ctx,
		libnvme_ctrl_t c)
{
	char *host_key, *ctrl_key;

	host_key = libnvme_get_ctrl_attr(c, "dhchap_secret");
	if (host_key && !strcmp(host_key, "none")) {
		free(host_key);
		host_key = NULL;
	}
	if (host_key) {
		libnvme_ctrl_set_dhchap_host_key(c, NULL);
		c->dhchap_host_key = host_key;
	}

	ctrl_key = libnvme_get_ctrl_attr(c, "dhchap_ctrl_secret");
	if (ctrl_key && !strcmp(ctrl_key, "none")) {
		free(ctrl_key);
		ctrl_key = NULL;
	}
	if (ctrl_key) {
		libnvme_ctrl_set_dhchap_ctrl_key(c, NULL);
		c->dhchap_ctrl_key = ctrl_key;
	}
}

static void libnvmf_read_sysfs_tls(struct libnvme_global_ctx *ctx,
		libnvme_ctrl_t c)
{
	char *endptr;
	long key_id;
	char *key, *keyring;

	key = libnvme_get_ctrl_attr(c, "tls_key");
	if (!key) {
		/* tls_key is only present if --tls or --concat has been used */
		return;
	}

	keyring = libnvme_get_ctrl_attr(c, "tls_keyring");
	libnvme_ctrl_set_keyring(c, keyring);
	free(keyring);

	/* the sysfs entry is not prefixing the id but it's in hex */
	key_id = strtol(key, &endptr, 16);
	if (endptr != key)
		c->cfg.tls_key_id = key_id;

	free(key);

	key = libnvme_get_ctrl_attr(c, "tls_configured_key");
	if (!key)
		return;

	/* the sysfs entry is not prefixing the id but it's in hex */
	key_id = strtol(key, &endptr, 16);
	if (endptr != key)
		c->cfg.tls_configured_key_id = key_id;

	free(key);
}

static void libnvmf_read_sysfs_tls_mode(struct libnvme_global_ctx *ctx,
		libnvme_ctrl_t c)
{
	__cleanup_free char *mode = NULL;

	mode = libnvme_get_ctrl_attr(c, "tls_mode");
	if (!mode)
		return;

	if (!strcmp(mode, "tls"))
		c->cfg.tls = true;
	else if (!strcmp(mode, "concat"))
		c->cfg.concat = true;
}

void libnvmf_read_sysfs_fabrics_attrs(struct libnvme_global_ctx *ctx,
		libnvme_ctrl_t c)
{
	libnvmf_read_sysfs_dhchap(ctx, c);
	libnvmf_read_sysfs_tls(ctx, c);
	libnvmf_read_sysfs_tls_mode(ctx, c);
}

bool libnvmf_ctrl_match_config(struct libnvme_ctrl *c,
		struct libnvmf_context *fctx)
{
	struct candidate_args candidate = {};
	ctrl_match_t ctrl_match;

	ctrl_match = libnvme_candidate_init(c->ctx, &candidate, fctx);

	return ctrl_match(c, &candidate);
}

libnvme_ctrl_t libnvmf_ctrl_find(libnvme_subsystem_t s,
		struct libnvmf_context *fctx)
{
	return libnvme_ctrl_find(s, fctx, NULL/*p*/);
}
