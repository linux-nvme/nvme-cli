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
 * Convenience constructor.  NULL fields are stored as NULL.  For an IP
 * transport (tcp, rdma) a numeric traddr/host_traddr is canonicalized; a
 * hostname is rejected -- resolving it is the caller's job, not libnvme's.
 *
 * Return: Allocated TID, or NULL if traddr/host_traddr is not numeric on an
 * IP transport, or on allocation failure.
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
 * libnvmf_tid_set_identity() - Set the subsystem and host identity together.
 * @tid:       The transport ID.
 * @subsysnqn: Subsystem NQN, or NULL to leave it unchanged.
 * @hostnqn:   Host NQN, or NULL to leave it unchanged.
 * @hostid:    Host Identifier, or NULL to leave it unchanged (or derive it).
 *
 * Identity is applied after addressing -- which subsystem, and which host
 * persona, are decided by context.  A NULL argument leaves that field as-is,
 * which is why the three are set through one call rather than per-field
 * setters (addressing has none: it is construction-only).
 *
 * hostid is never left to chance: when no hostid is set but the resulting
 * hostnqn carries a UUID (nqn.2014-08.org.nvmexpress:uuid:<X>), the hostid is
 * derived from it -- the deterministic, per-host value (TP4126), never a
 * random one.  A hostid without a hostnqn is rejected: one host is one
 * (hostnqn, hostid) pair.
 *
 * Return: 0 on success; -EINVAL for a NULL @tid or a hostid without a hostnqn;
 * -ENOMEM on allocation failure.
 */
int libnvmf_tid_set_identity(struct libnvmf_tid *tid, const char *subsysnqn,
			     const char *hostnqn, const char *hostid);

/**
 * libnvmf_tid_dup() - Allocate a copy of an existing TID.
 * @tid: Source TID, or NULL.
 *
 * Return: Allocated copy, or NULL if @tid is NULL or on allocation failure.
 */
struct libnvmf_tid *libnvmf_tid_dup(const struct libnvmf_tid *tid);

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
 * Like libnvmf_tid_from_fields(), a traddr/host-traddr that is not numeric on
 * an IP transport fails the whole parse.
 *
 * Return: Allocated TID, or NULL on a non-numeric address or allocation
 * failure.
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
 * libnvmf_traddr_is_numeric() - Would this address survive TID construction?
 * @traddr: A candidate traddr/host_traddr, or NULL.
 *
 * The TID constructors accept a numeric IP only and reject a hostname; this
 * lets a caller check a candidate address -- and decide whether it must
 * resolve it first -- before building the TID, using the same definition of
 * "numeric" the constructors use internally (including an IPv6 scope
 * suffix, which is numeric).
 *
 * Return: true if @traddr is a numeric address, false otherwise (including a
 * NULL @traddr or an allocation failure while checking).
 */
bool libnvmf_traddr_is_numeric(const char *traddr);

/**
 * libnvmf_tid_is_empty() - Test whether a TID sets no fields.
 * @tid: The transport ID, or NULL.
 *
 * Return: true if @tid is NULL or every field is unset, false otherwise.
 */
bool libnvmf_tid_is_empty(const struct libnvmf_tid *tid);

/**
 * libnvmf_tid_get_canonical() - Return the canonical string form of a TID.
 * @tid: The transport ID.
 *
 * Returns a deterministic, fixed-field-order semicolon-separated key=value
 * string (e.g. "transport=tcp;traddr=1.2.3.4;trsvcid=8009").  Only non-NULL
 * fields are included.  The string is lazily computed and cached; it is
 * invalidated by any identity change.
 *
 * The fixed field order makes the output independent of the order fields
 * were set, so the same logical TID always yields the same canonical string.
 * This is the stable primitive libnvme provides for naming a connection; a
 * caller that wants a compact hash (e.g. for a systemd unit name) derives it
 * from this string itself -- libnvme does not hash it.
 *
 * IMPORTANT -- address text is a known foot-gun here.  This function does no
 * normalization beyond what the constructors already applied: the address is
 * numeric (constructors reject a hostname), but a compressed vs.
 * fully-expanded IPv6 address, or an IPv4-mapped IPv6 address
 * ("::ffff:1.2.3.4") vs. dotted IPv4 ("1.2.3.4"), can still spell the same
 * endpoint differently and yield different canonical strings.  Two producers
 * only agree on a TID's canonical form if they build the TID from
 * byte-identical field values.
 *
 * Return: Cached canonical string, or NULL on allocation failure.
 */
const char *libnvmf_tid_get_canonical(const struct libnvmf_tid *tid);

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
