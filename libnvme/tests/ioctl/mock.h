/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/**
 * struct mock_cmd - a mock NVMe passthru ioctl() invocation
 * @opcode: the expected `opcode` passed to ioctl()
 * @flags: the expected `flags` passed to ioctl()
 * @nsid: the expected `nsid` passed to ioctl()
 * @cdw2: the expected `cdw2` passed to ioctl()
 * @cdw3: the expected `cdw3` passed to ioctl()
 * @metadata: the expected `metadata` of length `metadata_len` passed to ioctl()
 * @in_data: the expected `addr` of length `data_len` passed to ioctl().
 *           Set this to NULL to skip checking the data,
 *           for example if the command is in the read direction.
 * @metadata_len: the expected `metadata_len` passed to ioctl()
 * @data_len: the expected `data_len` passed to ioctl()
 * @cdw10: the expected `cdw10` passed to ioctl()
 * @cdw11: the expected `cdw11` passed to ioctl()
 * @cdw12: the expected `cdw12` passed to ioctl()
 * @cdw13: the expected `cdw13` passed to ioctl()
 * @cdw14: the expected `cdw14` passed to ioctl()
 * @cdw15: the expected `cdw15` passed to ioctl()
 * @timeout_ms: the expected `timeout_ms` passed to ioctl()
 * @out_data: if not NULL, bytes to copy to the caller's `addr`
 * @out_data_len: length of `out_data` buffer to return.
 *                If 0, `data_len` is used instead.
 * @result: copied to the caller's `result`.
 *       If `result` doesn't fit in a u32, the ioctl() must be the 64-bit one.
 * @err: If negative, ioctl() returns -1 and sets `errno` to `-err`.
 *       Otherwise, ioctl() returns `err`, representing a NVMe status code.
 * @win_err: What libnvme returns for this command on Windows, when that
 *           differs from `err`. 0 means Windows behaves the same.
 *           Ignored on every other platform. See mock_err().
 * @win_no_ioctl: Set alongside `win_err` when Windows rejects the command
 *           before issuing any IOCTL, so no mock is consumed. The mock layer
 *           accounts for this itself, so a test declares the mock normally and
 *           end_mock_cmds() does not report it as unexecuted.
 */
struct mock_cmd {
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
	int win_err;
	bool win_no_ioctl;
};

/*
 * Declares a command that the Windows implementation refuses to issue because
 * it names a Command Set other than NVM. No IOCTL is seen and no mock is
 * consumed.
 */
#define WIN_CSI_UNSUPPORTED	.win_err = -ENOTSUP, .win_no_ioctl = true

/**
 * mock_err() - the error a mocked command is expected to produce
 * @mock: the mock whose expectation is being read
 *
 * Returns @mock->err everywhere except Windows, where a non-zero
 * @mock->win_err overrides it. Use this in place of a bare @err comparison so
 * a test states one expectation per platform instead of branching.
 */
static inline int mock_err(const struct mock_cmd *mock)
{
#ifdef _WIN32
	if (mock->win_err)
		return mock->win_err;
#endif
	return mock->err;
}

/**
 * mock_ok() - whether the command is expected to succeed on this platform
 * @mock: the mock being considered
 *
 * Guard checks on returned data with this: a command that fails transfers
 * nothing, so comparing the caller's buffer would assert against a value the
 * command never produced.
 */
static inline bool mock_ok(const struct mock_cmd *mock)
{
	return mock_err(mock) == 0;
}

/**
 * mock_result() - the CQE result a mocked command is expected to leave behind
 * @mock: the mock whose expectation is being read
 *
 * On Windows, CQE data is not available for failing commands, so the result
 * value will be 0. Everywhere else the mock's result is delivered even on
 * failure.
 */
static inline uint64_t mock_result(const struct mock_cmd *mock)
{
#ifdef _WIN32
	if (!mock_ok(mock))
		return 0;
#endif
	return mock->result;
}

/**
 * set_mock_fd() - sets the expected file descriptor for NVMe passthru ioctls()
 * @fd: file descriptor expected to be passed to ioctl()
 */
void set_mock_fd(libnvme_fd_t fd);

/**
 * set_mock_admin_cmds() - mocks NVMe admin passthru ioctl() invocations
 * @cmds: pointer to start of the mock_cmd slice
 * @len: length of the mock_cmd slice (number of ioctl() invocations)
 *
 * Provides a sequence of mocks for NVMe admin passthru ioctl() invocations.
 * Each ioctl() consumes the next mock from the sequence.
 * Its arguments are checked against the mock's expected arguments,
 * aborting the process if unexpected arguments are passed.
 * The mock results (return value, NVMe result and data)
 * are returned from the ioctl().
 *
 * Analogous to set_mock_io_cmds(), but for admin commands.
 * Both admin and IO mocks can be active at the same time.
 */
void set_mock_admin_cmds(const struct mock_cmd *cmds, size_t len);

/**
 * set_mock_io_cmds() - mocks NVMe IO passthru ioctl() invocations
 * @cmds: pointer to start of the mock_cmd slice
 * @len: length of the mock_cmd slice (number of ioctl() invocations)
 *
 * Provides a sequence of mocks for NVMe IO passthru ioctl() invocations.
 * Each ioctl() consumes the next mock from the sequence.
 * Its arguments are checked against the mock's expected arguments,
 * aborting the process if unexpected arguments are passed.
 * The mock results (return value, NVMe result and data)
 * are returned from the ioctl().
 *
 * Analogous to set_mock_admin_cmds(), but for IO commands.
 * Both admin and IO mocks can be active at the same time.
 */
void set_mock_io_cmds(const struct mock_cmd *cmds, size_t len);

/**
 * end_mock_cmds() - finishes mocking NVMe passthru ioctl() invocations
 *
 * Checks that all mock ioctl() invocations were performed.
 */
void end_mock_cmds(void);
