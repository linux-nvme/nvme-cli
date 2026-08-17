/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * This file is part of libnvme.
 * Copyright (c) 2026 SUSE Software Solutions
 *
 * Authors: Daniel Wagner <dwagner@suse.de>
 */
#pragma once

#include <stddef.h>
#include <stdint.h>

struct libnvme_global_ctx;
struct libnvme_transport_handle;
struct libnvme_passthru_cmd;

/**
 * struct libnvme_loopback_cmd - an expected NVMe passthru command for the
 * loopback transport
 * @opcode: expected `opcode`
 * @flags: expected `flags`
 * @nsid: expected `nsid`
 * @cdw2: expected `cdw2`
 * @cdw3: expected `cdw3`
 * @metadata: expected `metadata` buffer of length `metadata_len`
 * @in_data: expected `addr` buffer of length `data_len`.
 *           Set to NULL to skip checking the data, e.g. for commands in
 *           the read direction.
 * @metadata_len: expected `metadata_len`
 * @data_len: expected `data_len`
 * @cdw10: expected `cdw10`
 * @cdw11: expected `cdw11`
 * @cdw12: expected `cdw12`
 * @cdw13: expected `cdw13`
 * @cdw14: expected `cdw14`
 * @cdw15: expected `cdw15`
 * @timeout_ms: expected `timeout_ms`
 * @out_data: if not NULL, bytes to copy into the caller's data buffer
 * @out_data_len: length of `out_data`. If 0, `data_len` is used instead.
 * @result: copied into the caller's `result`
 * @err: value returned by the simulated passthru call
 */
struct libnvme_loopback_cmd {
	uint8_t opcode;
	uint8_t flags;
	uint32_t nsid;
	uint32_t cdw2;
	uint32_t cdw3;
	const void *metadata;
	const void *in_data;
	uint32_t metadata_len;
	uint32_t data_len;
	uint32_t cdw10;
	uint32_t cdw11;
	uint32_t cdw12;
	uint32_t cdw13;
	uint32_t cdw14;
	uint32_t cdw15;
	uint32_t timeout_ms;
	const void *out_data;
	uint32_t out_data_len;
	uint64_t result;
	int err;
};

/**
 * libnvme_open_loopback() - Open an in-process loopback transport handle
 * @ctx: Library context
 * @hdlp: On success, set to the new transport handle
 *
 * Creates a transport handle that never touches a real device: admin and
 * IO passthru commands are matched and answered in-process against the
 * sequences installed with libnvme_loopback_set_admin_cmds() and
 * libnvme_loopback_set_io_cmds(). Intended for unit tests.
 *
 * Return: 0 on success, negative error code otherwise (e.g. -ENOTSUP if
 * the library was built without loopback support).
 */
int libnvme_open_loopback(struct libnvme_global_ctx *ctx,
		struct libnvme_transport_handle **hdlp);

/**
 * libnvme_loopback_set_admin_cmds() - Install expected admin passthru commands
 * @hdl: Loopback transport handle
 * @cmds: Pointer to the start of the expected command sequence
 * @len: Number of commands in the sequence
 *
 * Each admin passthru executed against @hdl consumes the next command from
 * the sequence. Its arguments are checked against the expected arguments,
 * aborting the process on mismatch. The mock results (return value, NVMe
 * result and data) are returned from the passthru call.
 *
 * Analogous to libnvme_loopback_set_io_cmds(), but for admin commands. Both
 * admin and IO sequences can be installed on the same handle at once.
 */
void libnvme_loopback_set_admin_cmds(struct libnvme_transport_handle *hdl,
		const struct libnvme_loopback_cmd *cmds, size_t len);

/**
 * libnvme_loopback_set_io_cmds() - Install expected IO passthru commands
 * @hdl: Loopback transport handle
 * @cmds: Pointer to the start of the expected command sequence
 * @len: Number of commands in the sequence
 *
 * Analogous to libnvme_loopback_set_admin_cmds(), but for IO commands.
 */
void libnvme_loopback_set_io_cmds(struct libnvme_transport_handle *hdl,
		const struct libnvme_loopback_cmd *cmds, size_t len);

/**
 * libnvme_loopback_end() - Finish loopback command matching
 * @hdl: Loopback transport handle
 *
 * Checks that all installed admin and IO commands were executed, aborting
 * the process otherwise.
 */
void libnvme_loopback_end(struct libnvme_transport_handle *hdl);

int __libnvme_loopback_admin_passthru(struct libnvme_transport_handle *hdl,
		struct libnvme_passthru_cmd *cmd);
int __libnvme_loopback_io_passthru(struct libnvme_transport_handle *hdl,
		struct libnvme_passthru_cmd *cmd);
