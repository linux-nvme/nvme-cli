// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libnvme.
 * Copyright (c) 2026 Dell Technologies Inc. or its subsidiaries.
 *
 * Authors: Martin Belanger <martin.belanger@dell.com>
 */

#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "compiler-attributes.h"
#include "nvme/accessors-fabrics.h"
#include "nvme/lib.h"
#include "nvme/tid.h"
#include "private-fabrics.h"

static void invalidate_cache(struct libnvmf_tid *p)
{
	free(p->_canonical);
	p->_canonical = NULL;
	free(p->_str);
	p->_str = NULL;
}

/*
 * Canonicalize a numeric IP so one endpoint always spells the same way (a
 * compressed vs. expanded IPv6, an IPv4-mapped form, ... all collapse to one
 * string).  Non-blocking: inet_pton()/inet_ntop() only, never DNS.
 *
 * Returns 0 and stores a malloc'd canonical form in *out when @in is numeric;
 * -EINVAL (with *out = NULL) when @in is not numeric -- i.e. a hostname;
 * -ENOMEM on allocation failure.  An IPv6 scope suffix ("fe80::1%eth0") is
 * kept verbatim -- as a name, not an interface index -- so the result stays
 * reproducible.  (That verbatim scope is why inet_pton_with_scope() is not
 * reused here: it numericizes the scope via if_nametoindex() and yields a
 * sockaddr, not a stable string.)
 */
static int canon_ip(const char *in, char **out)
{
	char host[INET6_ADDRSTRLEN];
	char canon[INET6_ADDRSTRLEN];
	unsigned char addr6[16];
	struct in_addr addr4;
	const char *scope;
	size_t hostlen;

	*out = NULL;

	scope = strchr(in, '%');
	hostlen = scope ? (size_t)(scope - in) : strlen(in);
	if (hostlen >= sizeof(host))
		return -EINVAL;
	memcpy(host, in, hostlen);
	host[hostlen] = '\0';

	if (inet_pton(AF_INET, host, &addr4) == 1) {
		if (!inet_ntop(AF_INET, &addr4, canon, sizeof(canon)))
			return -EINVAL;
		*out = strdup(canon);	/* IPv4 has no scope */
		return *out ? 0 : -ENOMEM;
	}

	if (inet_pton(AF_INET6, host, addr6) == 1) {
		if (!inet_ntop(AF_INET6, addr6, canon, sizeof(canon)))
			return -EINVAL;
		if (asprintf(out, "%s%s", canon, scope ? scope : "") < 0) {
			*out = NULL;
			return -ENOMEM;
		}
		return 0;
	}

	return -EINVAL;
}

/*
 * A lightweight structural check for FC addressing: "nn-0x<hex>:pn-0x<hex>"
 * (node name + port name, each up to a 64-bit WWN in hex) -- the same shape
 * sanitize_discovery_log_entry() already normalizes discovery-log traddr
 * into.  Not a deep WWN semantic check (OUI bits etc.), the same spirit as
 * canon_ip() below for tcp/rdma: catch a malformed value, not police it.
 */
static bool fc_wwn_is_valid(const char *in)
{
	char nn[17], pn[17];
	int len = 0;

	if (sscanf(in, "nn-0x%16[0-9a-fA-F]:pn-0x%16[0-9a-fA-F]%n",
		   nn, pn, &len) != 2)
		return false;

	return (size_t)len == strlen(in);
}

/*
 * Sanitize the addressing fields once the transport is known.  IP
 * transports: canonicalize a numeric traddr/host_traddr via canon_ip(); a
 * hostname is rejected outright -- resolving one is the caller's job, not
 * libnvme's.  FC: validate the "nn-0x:pn-0x" shape via fc_wwn_is_valid();
 * left as-is on success, since it's already in canonical form once it
 * matches. loop is left untouched.
 *
 * Return: 0 on success; -EINVAL if traddr or host_traddr is set but
 * malformed for the transport; -ENOMEM on allocation failure.
 */
static int tid_sanitize_addr(struct libnvmf_tid *t)
{
	char *canon;
	int rc;

	if (!t->transport)
		return 0;

	if (!strcmp(t->transport, "fc")) {
		if (t->traddr && !fc_wwn_is_valid(t->traddr))
			return -EINVAL;
		if (t->host_traddr && !fc_wwn_is_valid(t->host_traddr))
			return -EINVAL;
		return 0;
	}

	if (strcmp(t->transport, "tcp") && strcmp(t->transport, "rdma"))
		return 0;

	if (t->traddr) {
		rc = canon_ip(t->traddr, &canon);
		if (rc)
			return rc;
		free(t->traddr);
		t->traddr = canon;
	}

	if (t->host_traddr) {
		rc = canon_ip(t->host_traddr, &canon);
		if (rc)
			return rc;
		free(t->host_traddr);
		t->host_traddr = canon;
	}

	return 0;
}

__libnvme_public struct libnvmf_tid *libnvmf_tid_from_fields(
		const char *transport, const char *traddr,
		const char *trsvcid, const char *subsysnqn,
		const char *host_traddr, const char *host_iface,
		const char *hostnqn, const char *hostid)
{
	struct libnvmf_tid *t;

	if (libnvmf_tid_new(&t) < 0)
		return NULL;

	t->transport   = xstrdup(transport);
	t->traddr      = xstrdup(traddr);
	t->trsvcid     = xstrdup(trsvcid);
	t->subsysnqn   = xstrdup(subsysnqn);
	t->host_traddr = xstrdup(host_traddr);
	t->host_iface  = xstrdup(host_iface);
	t->hostnqn     = xstrdup(hostnqn);
	t->hostid      = xstrdup(hostid);

	if (tid_sanitize_addr(t)) {
		libnvmf_tid_free(t);
		return NULL;
	}

	return t;
}

/*
 * Set the subsysnqn/hostnqn/hostid identity in one call (a NULL argument
 * leaves that field unchanged).  There are no per-field setters -- addressing
 * is construction-only -- so this is the sole post-construction mutator.
 */
__libnvme_public int libnvmf_tid_set_identity(struct libnvmf_tid *tid,
					      const char *subsysnqn,
					      const char *hostnqn,
					      const char *hostid)
{
	char *new_subsysnqn, *new_hostnqn, *new_hostid;
	const char *eff_hostnqn, *eff_hostid;
	char *derived = NULL;

	if (!tid)
		return -EINVAL;

	/* The hostnqn/hostid this call will end up with (before deriving). */
	eff_hostnqn = hostnqn ? hostnqn : tid->hostnqn;
	eff_hostid  = hostid ? hostid : tid->hostid;

	/*
	 * No hostid but a UUID-format hostnqn: derive the hostid from it
	 * (TP4126) -- deterministic and unique per host, never random.
	 */
	if (!eff_hostid && eff_hostnqn) {
		derived = libnvme_hostid_from_hostnqn(eff_hostnqn);
		eff_hostid = derived;
	}

	/* One host is one (hostnqn, hostid) pair. */
	if (eff_hostid && !eff_hostnqn) {
		free(derived);
		return -EINVAL;
	}

	/* Stage every copy up front so a failure leaves the TID untouched. */
	new_subsysnqn = xstrdup(subsysnqn);
	new_hostnqn   = xstrdup(hostnqn);
	new_hostid    = xstrdup(hostid);
	if ((subsysnqn && !new_subsysnqn) || (hostnqn && !new_hostnqn) ||
	    (hostid && !new_hostid)) {
		free(new_subsysnqn);
		free(new_hostnqn);
		free(new_hostid);
		free(derived);
		return -ENOMEM;
	}

	invalidate_cache(tid);
	if (new_subsysnqn) {
		free(tid->subsysnqn);
		tid->subsysnqn = new_subsysnqn;
	}
	if (new_hostnqn) {
		free(tid->hostnqn);
		tid->hostnqn = new_hostnqn;
	}
	if (new_hostid) {
		free(tid->hostid);
		tid->hostid = new_hostid;
	} else if (derived) {
		free(tid->hostid);
		tid->hostid = derived;	/* transfer ownership */
		derived = NULL;
	}
	free(derived);

	return 0;
}

__libnvme_public struct libnvmf_tid *libnvmf_tid_dup(
		const struct libnvmf_tid *tid)
{
	struct libnvmf_tid *t;

	if (!tid)
		return NULL;
	if (libnvmf_tid_new(&t) < 0)
		return NULL;

	/*
	 * Copy verbatim: the source is already sanitized, so re-running it
	 * through from_fields() would only re-canonicalize and re-allocate
	 * addresses that are already in their canonical form.
	 */
	t->transport   = xstrdup(tid->transport);
	t->traddr      = xstrdup(tid->traddr);
	t->trsvcid     = xstrdup(tid->trsvcid);
	t->subsysnqn   = xstrdup(tid->subsysnqn);
	t->host_traddr = xstrdup(tid->host_traddr);
	t->host_iface  = xstrdup(tid->host_iface);
	t->hostnqn     = xstrdup(tid->hostnqn);
	t->hostid      = xstrdup(tid->hostid);

	return t;
}

/*
 * Shared parser.  In strict mode a malformed token -- a non-empty bare token
 * (no '='), an empty value, or an unrecognized key -- fails the whole parse
 * (returns NULL); in lenient mode such tokens are logged and skipped.  Empty
 * tokens (from ";;" or a trailing ';') are always benign and skipped.
 */
static struct libnvmf_tid *tid_parse(struct libnvme_global_ctx *ctx,
				     const char *str, bool strict)
{
	struct libnvmf_tid *t;
	char *buf, *tok, *save;
	bool bad = false;

	if (!str)
		return NULL;

	if (libnvmf_tid_new(&t) < 0)
		return NULL;

	buf = strdup(str);
	if (!buf) {
		libnvmf_tid_free(t);
		return NULL;
	}

	tok = strtok_r(buf, ";", &save);
	while (tok && !bad) {
		char *eq = strchr(tok, '=');

		if (!eq) {
			if (*libnvmf_trim(tok)) {
				libnvme_msg(ctx, LIBNVME_LOG_WARN,
					    "tid_parse: ignoring \"%s\": missing '='\n",
					    tok);
				bad = strict;
			}
		} else {
			const char *key, *val;

			*eq = '\0';
			key = libnvmf_trim(tok);
			val = libnvmf_trim(eq + 1);

			if (!*val) {
				libnvme_msg(ctx, LIBNVME_LOG_WARN,
					    "tid_parse: ignoring empty value for \"%s\"\n",
					    key);
				bad = strict;
			} else if (!strcmp(key, "transport")) {
				free(t->transport);
				t->transport = strdup(val);
			} else if (!strcmp(key, "traddr")) {
				free(t->traddr);
				t->traddr = strdup(val);
			} else if (!strcmp(key, "trsvcid")) {
				free(t->trsvcid);
				t->trsvcid = strdup(val);
			} else if (!strcmp(key, "nqn")) {
				free(t->subsysnqn);
				t->subsysnqn = strdup(val);
			} else if (!strcmp(key, "host-traddr")) {
				free(t->host_traddr);
				t->host_traddr = strdup(val);
			} else if (!strcmp(key, "host-iface")) {
				free(t->host_iface);
				t->host_iface = strdup(val);
			} else if (!strcmp(key, "hostnqn")) {
				free(t->hostnqn);
				t->hostnqn = strdup(val);
			} else if (!strcmp(key, "hostid")) {
				free(t->hostid);
				t->hostid = strdup(val);
			} else {
				libnvme_msg(ctx, LIBNVME_LOG_WARN,
					    "tid_parse: ignoring unknown key \"%s\"\n",
					    key);
				bad = strict;
			}
		}
		tok = strtok_r(NULL, ";", &save);
	}

	free(buf);
	if (bad || tid_sanitize_addr(t)) {
		libnvmf_tid_free(t);
		return NULL;
	}
	return t;
}

__libnvme_public struct libnvmf_tid *libnvmf_tid_parse(
		struct libnvme_global_ctx *ctx, const char *str)
{
	return tid_parse(ctx, str, false);
}

__libnvme_public struct libnvmf_tid *libnvmf_tid_parse_strict(
		struct libnvme_global_ctx *ctx, const char *str)
{
	return tid_parse(ctx, str, true);
}

/*
 * libnvmf_traddr_is_numeric() - Would this address survive TID construction?
 * @traddr: A candidate traddr/host_traddr, or NULL.
 *
 * The TID constructors accept a numeric IP only and reject a hostname; this
 * lets a caller check a candidate address before resolving it, using the same
 * definition of "numeric" the constructors use internally (including an IPv6
 * scope suffix, which is numeric).
 *
 * Return: true if @traddr is a numeric address, false otherwise (including a
 * NULL @traddr or an allocation failure while checking).
 */
__libnvme_public bool libnvmf_traddr_is_numeric(const char *traddr)
{
	char *canon;
	int rc;

	if (!traddr)
		return false;

	rc = canon_ip(traddr, &canon);
	free(canon);

	return rc == 0;
}

__libnvme_public bool libnvmf_tid_is_empty(const struct libnvmf_tid *tid)
{
	if (!tid)
		return true;

	return !tid->transport && !tid->traddr && !tid->trsvcid &&
	       !tid->subsysnqn && !tid->host_traddr && !tid->host_iface &&
	       !tid->hostnqn && !tid->hostid;
}

/*
 * Build "key=val;key=val;..." in fixed field order, skipping NULL fields.
 * Max canonical length: 2 NQNs (223 chars each) + short fields + keys +
 * separators = ~700 chars.  CANONICAL_MAX of 1024 is a safe upper bound.
 */
#define CANONICAL_MAX 1024

__libnvme_public const char *libnvmf_tid_get_canonical(
		const struct libnvmf_tid *tid)
{
	struct libnvmf_tid *p = (struct libnvmf_tid *)tid;
	char buf[CANONICAL_MAX];
	int n = 0;

	if (!tid)
		return NULL;

	if (p->_canonical)
		return p->_canonical;

	/* n stays < CANONICAL_MAX so (CANONICAL_MAX - n) cannot wrap. */
#define APPEND(key, field) \
	do { \
		if (p->field && n < (int)CANONICAL_MAX) \
			n += snprintf(buf + n, CANONICAL_MAX - n, "%s%s=%s", \
				      n ? ";" : "", key, p->field); \
	} while (0)

	APPEND("transport",   transport);
	APPEND("traddr",      traddr);
	APPEND("trsvcid",     trsvcid);
	APPEND("nqn",         subsysnqn);
	APPEND("host-traddr", host_traddr);
	APPEND("host-iface",  host_iface);
	APPEND("hostnqn",     hostnqn);
	APPEND("hostid",      hostid);

#undef APPEND

	p->_canonical = strdup(buf);
	return p->_canonical;
}

/*
 * Human-readable, log-friendly rendering of a TID:
 * "(transport, traddr, trsvcid[, subsysnqn][, host_iface][, host_traddr])".
 * Matches nvme-stas's TID string form so the two tools' journals line up.
 * hostnqn and hostid are intentionally omitted -- they are rarely the
 * distinguishing field and would only add noise.  Cached like the other
 * derived values.
 */
__libnvme_public const char *libnvmf_tid_str(const struct libnvmf_tid *tid)
{
	struct libnvmf_tid *p = (struct libnvmf_tid *)tid;
	char buf[CANONICAL_MAX];
	const char *sep = "";
	int n = 1;

	if (!tid)
		return NULL;

	if (p->_str)
		return p->_str;

	buf[0] = '(';

#define APPEND(field) \
	do { \
		if (p->field && p->field[0] && n < (int)CANONICAL_MAX) { \
			n += snprintf(buf + n, CANONICAL_MAX - n, "%s%s", \
				      sep, p->field); \
			sep = ", "; \
		} \
	} while (0)

	APPEND(transport);
	APPEND(traddr);
	APPEND(trsvcid);
	APPEND(subsysnqn);
	APPEND(host_iface);
	APPEND(host_traddr);
	if (n < (int)CANONICAL_MAX)
		snprintf(buf + n, CANONICAL_MAX - n, ")");

#undef APPEND

	p->_str = strdup(buf);
	return p->_str;
}
