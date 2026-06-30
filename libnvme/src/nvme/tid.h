/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * This file is part of libnvme.
 * Copyright (c) 2026 Dell Technologies Inc. or its subsidiaries.
 *
 * Authors: Martin Belanger <martin.belanger@dell.com>
 */
#pragma once

#include <stdbool.h>
#include <nvme/accessors-fabrics.h>

struct libnvme_global_ctx;

/**
 * Custom setters for struct libnvmf_tid.
 *
 * Each setter strdup()s the new value, frees the previous one, and invalidates
 * the cached canonical string and hash.  NULL is accepted and stored as NULL.
 */
void libnvmf_tid_set_transport(struct libnvmf_tid *p, const char *val);
void libnvmf_tid_set_traddr(struct libnvmf_tid *p, const char *val);
void libnvmf_tid_set_trsvcid(struct libnvmf_tid *p, const char *val);
void libnvmf_tid_set_subsysnqn(struct libnvmf_tid *p, const char *val);
void libnvmf_tid_set_host_traddr(struct libnvmf_tid *p, const char *val);
void libnvmf_tid_set_host_iface(struct libnvmf_tid *p, const char *val);
void libnvmf_tid_set_hostnqn(struct libnvmf_tid *p, const char *val);
void libnvmf_tid_set_hostid(struct libnvmf_tid *p, const char *val);

/**
 * libnvmf_tid_dup() - Allocate a copy of an existing TID.
 * @tid: Source TID, or NULL.
 *
 * Return: Allocated copy, or NULL if @tid is NULL or on allocation failure.
 */
struct libnvmf_tid *libnvmf_tid_dup(const struct libnvmf_tid *tid);

/**
 * libnvmf_tid_equal() - Compare two TIDs for equality.
 * @a: First TID, or NULL.
 * @b: Second TID, or NULL.
 *
 * Compares all eight fields with exact string equality.  Two NULL TIDs are
 * considered equal.
 *
 * Return: true if all fields match, false otherwise.
 */
bool libnvmf_tid_equal(const struct libnvmf_tid *a,
		       const struct libnvmf_tid *b);

/**
 * libnvmf_tid_is_empty() - Test whether a TID sets no fields.
 * @tid: The transport ID, or NULL.
 *
 * Return: true if @tid is NULL or every field is unset, false otherwise.
 */
bool libnvmf_tid_is_empty(const struct libnvmf_tid *tid);

/**
 * libnvmf_tid_from_fields() - Allocate a TID from individual field strings.
 * @transport:   Transport type (e.g. "tcp", "rdma", "fc").
 * @traddr:      Transport address.
 * @trsvcid:     Transport service ID (e.g. "8009").
 * @subsysnqn:   Subsystem NQN.
 * @host_traddr: Host transport address, or NULL.
 * @host_iface:  Host interface name, or NULL.
 * @hostnqn:     Host NQN, or NULL.
 * @hostid:      Host Identifier, or NULL.
 *
 * Convenience constructor.  NULL fields are stored as NULL.
 *
 * Return: Allocated TID, or NULL on allocation failure.
 */
struct libnvmf_tid *libnvmf_tid_from_fields(const char *transport,
					    const char *traddr,
					    const char *trsvcid,
					    const char *subsysnqn,
					    const char *host_traddr,
					    const char *host_iface,
					    const char *hostnqn,
					    const char *hostid);

/**
 * libnvmf_tid_parse() - Allocate a TID from a semicolon-separated key=value
 * string.
 * @ctx: Global context used only for logging the diagnostics below; may be NULL
 *       to parse silently.
 * @str: Input string, e.g. "transport=tcp;traddr=1.2.3.4;trsvcid=8009".
 *
 * Recognized keys are the "nvme connect" option names: transport, traddr,
 * trsvcid, nqn, host-traddr, host-iface, hostnqn, hostid.  (The "nqn",
 * "host-traddr", and "host-iface" string keys map onto the struct's
 * subsysnqn, host_traddr, and host_iface fields, whose names follow the
 * C-identifier convention.)  Unknown keys, bare keys (no '='), and empty
 * values are logged at WARN level (when @ctx is non-NULL) and skipped.
 * Whitespace around keys and values is trimmed.  NULL input returns NULL.
 *
 * Return: Allocated TID, or NULL on allocation failure.
 */
struct libnvmf_tid *libnvmf_tid_parse(struct libnvme_global_ctx *ctx,
				      const char *str);

/**
 * libnvmf_tid_parse_strict() - Like libnvmf_tid_parse(), but reject malformed
 * input.
 * @ctx: Global context for logging; may be NULL to parse silently.
 * @str: Input string.
 *
 * Same as libnvmf_tid_parse() except that a malformed token -- a non-empty bare
 * token (no '='), an empty value, or an unrecognized key -- fails the whole
 * parse instead of being skipped.  Empty tokens (from ";;" or a trailing ';')
 * are still benign.  Useful when an unrecognized key should be treated as an
 * error (e.g. a typo in a hand-edited config) rather than silently ignored.
 *
 * Return: Allocated TID, or NULL on a malformed token or allocation failure.
 */
struct libnvmf_tid *libnvmf_tid_parse_strict(struct libnvme_global_ctx *ctx,
					     const char *str);

/**
 * libnvmf_tid_get_canonical() - Return the canonical string form of a TID.
 * @tid: The transport ID.
 *
 * Returns a deterministic, fixed-field-order semicolon-separated key=value
 * string (e.g. "transport=tcp;traddr=1.2.3.4;trsvcid=8009").  Only non-NULL
 * fields are included.  The string is lazily computed and cached; it is
 * invalidated by any setter call.
 *
 * Stability is the whole point of this form, because the hash returned by
 * libnvmf_tid_get_hash() is computed directly from this string.  The fixed
 * field order makes the output independent of the order fields were set, so
 * the same logical TID always yields the same canonical string and therefore
 * the same hash.  Conversely, *any* difference in the bytes here -- a field
 * present vs. absent, or the same field spelled differently -- changes the
 * hash.  Two producers (e.g. discoverd and a udev helper) only agree on a
 * TID's hash if they build the TID with byte-identical field values.
 *
 * IMPORTANT -- address text is a known foot-gun here.  This function does no
 * normalization: it hashes the address exactly as stored.  The same endpoint
 * can be written several ways that are semantically equal but textually
 * different, e.g. a hostname vs. its resolved IP, an IPv4-mapped IPv6 address
 * ("::ffff:1.2.3.4") vs. dotted IPv4 ("1.2.3.4"), or a compressed vs.
 * fully-expanded IPv6 address.  Each spelling produces a different canonical
 * string and hash.
 *
 * This variation comes from *user space*, not the kernel.  The nvme fabrics
 * driver stores traddr/host_traddr verbatim and reports them back through
 * sysfs unchanged; it parses numeric addresses only (inet_pton) and never
 * resolves hostnames.  So a value read from sysfs matches exactly what was
 * written to /dev/nvme-fabrics -- the divergence is strictly between producers
 * that spell the same endpoint differently (e.g. a daemon that resolves a
 * hostname, or normalizes IPv6) before handing it to the kernel.  Callers that
 * rely on hashes matching across producers (or across a connect/reconnect)
 * must build the TID from the same textual form that is handed to the kernel.
 *
 * Return: Cached canonical string, or NULL on allocation failure.
 */
const char *libnvmf_tid_get_canonical(const struct libnvmf_tid *tid);

/**
 * libnvmf_tid_get_hash() - Return a stable hash string for a TID.
 * @tid: The transport ID.
 *
 * Returns a 12-character lowercase hex string derived from the FNV-1a 64-bit
 * hash (truncated to 48 bits) of the canonical TID string.  The hash is lazily
 * computed and cached; it is invalidated by any setter call.
 *
 * Suitable for use as a dictionary key or compact log identifier.
 *
 * Return: Cached hash string, or NULL on allocation failure.
 */
const char *libnvmf_tid_get_hash(const struct libnvmf_tid *tid);

/**
 * libnvmf_tid_str() - Human-readable string form of a TID, for logging.
 * @tid: The transport ID.
 *
 * Returns "(transport, traddr, trsvcid[, subsysnqn][, host_iface][, host_traddr])"
 * — the same rendering nvme-stas uses, so logs from both tools line up.
 * hostnqn and hostid are omitted.  Lazily computed and cached; invalidated by
 * any setter.
 *
 * Return: Cached string, or NULL if @tid is NULL or on allocation failure.
 */
const char *libnvmf_tid_str(const struct libnvmf_tid *tid);
