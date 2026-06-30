// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libnvme.
 * Copyright (c) 2026 Dell Technologies Inc. or its subsidiaries.
 *
 * Authors: Martin Belanger <martin.belanger@dell.com>
 */

#include <inttypes.h>
#include <stdint.h>
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
	free(p->_hash);
	p->_hash = NULL;
	free(p->_str);
	p->_str = NULL;
}

// Custom setters: strdup the new value and invalidate the derived-value cache

__libnvme_public void libnvmf_tid_set_transport(
		struct libnvmf_tid *p, const char *val)
{
	invalidate_cache(p);
	free(p->transport);
	p->transport = xstrdup(val);
}

__libnvme_public void libnvmf_tid_set_traddr(
		struct libnvmf_tid *p, const char *val)
{
	invalidate_cache(p);
	free(p->traddr);
	p->traddr = xstrdup(val);
}

__libnvme_public void libnvmf_tid_set_trsvcid(
		struct libnvmf_tid *p, const char *val)
{
	invalidate_cache(p);
	free(p->trsvcid);
	p->trsvcid = xstrdup(val);
}

__libnvme_public void libnvmf_tid_set_subsysnqn(
		struct libnvmf_tid *p, const char *val)
{
	invalidate_cache(p);
	free(p->subsysnqn);
	p->subsysnqn = xstrdup(val);
}

__libnvme_public void libnvmf_tid_set_host_traddr(
		struct libnvmf_tid *p, const char *val)
{
	invalidate_cache(p);
	free(p->host_traddr);
	p->host_traddr = xstrdup(val);
}

__libnvme_public void libnvmf_tid_set_host_iface(
		struct libnvmf_tid *p, const char *val)
{
	invalidate_cache(p);
	free(p->host_iface);
	p->host_iface = xstrdup(val);
}

__libnvme_public void libnvmf_tid_set_hostnqn(
		struct libnvmf_tid *p, const char *val)
{
	invalidate_cache(p);
	free(p->hostnqn);
	p->hostnqn = xstrdup(val);
}

__libnvme_public void libnvmf_tid_set_hostid(
		struct libnvmf_tid *p, const char *val)
{
	invalidate_cache(p);
	free(p->hostid);
	p->hostid = xstrdup(val);
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

__libnvme_public const char *libnvmf_tid_get_hash(
		const struct libnvmf_tid *tid)
{
	struct libnvmf_tid *p = (struct libnvmf_tid *)tid;
	const char *canon;
	uint64_t h;

	if (!tid)
		return NULL;

	if (p->_hash)
		return p->_hash;

	canon = libnvmf_tid_get_canonical(tid);
	if (!canon)
		return NULL;

	/*
	 * Truncate the 64-bit FNV-1a value to 48 bits / 12 hex chars.  This
	 * keeps the derived unit name short while keeping collisions negligible
	 * at realistic scale: for ~200 concurrently-connected controllers the
	 * birthday-bound collision probability is on the order of 1 in 1e10.
	 */
	h = libnvmf_fnv1a_64(canon, strlen(canon)) & 0xffffffffffffULL;
	if (asprintf(&p->_hash, "%012" PRIx64, h) < 0) {
		p->_hash = NULL;
		return NULL;
	}
	return p->_hash;
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

__libnvme_public struct libnvmf_tid *libnvmf_tid_dup(
		const struct libnvmf_tid *tid)
{
	if (!tid)
		return NULL;

	return libnvmf_tid_from_fields(tid->transport, tid->traddr,
				       tid->trsvcid, tid->subsysnqn,
				       tid->host_traddr, tid->host_iface,
				       tid->hostnqn, tid->hostid);
}

__libnvme_public bool libnvmf_tid_equal(
		const struct libnvmf_tid *a, const struct libnvmf_tid *b)
{
	if (a == b)
		return true;
	if (!a || !b)
		return false;

	return streq0(a->transport, b->transport) &&
	       streq0(a->traddr, b->traddr) &&
	       streq0(a->trsvcid, b->trsvcid) &&
	       streq0(a->subsysnqn, b->subsysnqn) &&
	       streq0(a->host_traddr, b->host_traddr) &&
	       streq0(a->host_iface, b->host_iface) &&
	       streq0(a->hostnqn, b->hostnqn) &&
	       streq0(a->hostid, b->hostid);
}

__libnvme_public bool libnvmf_tid_is_empty(const struct libnvmf_tid *tid)
{
	if (!tid)
		return true;

	return !tid->transport && !tid->traddr && !tid->trsvcid &&
	       !tid->subsysnqn && !tid->host_traddr && !tid->host_iface &&
	       !tid->hostnqn && !tid->hostid;
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
	if (bad) {
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
