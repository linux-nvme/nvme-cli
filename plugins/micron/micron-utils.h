/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (c) 2025 Micron Technology, Inc.
 *
 * Authors: Broc Going <bgoing@micron.com>
 */
#pragma once

#include <stddef.h>

#include <nvme/lib-types.h>

/**
 * micron_get_ctrl_name() - Get the controller name from the device
 * transport handle
 * @hdl:	Transport handle
 *
 * Returns the controller name for the handle (e.g., "nvme0").
 * For namespace handles, the namespace indicator is stripped from the
 * name to derive the controller name.
 *
 * Return: Allocated string containing the controller name on success,
 * or NULL on failure. The caller is responsible for freeing the returned
 * string.
 */
char *micron_get_ctrl_name(struct libnvme_transport_handle *hdl);

/**
 * micron_get_ns_name() - Get the namespace name from a transport handle
 * @hdl:	Transport handle
 *
 * Returns the namespace name for the handle. For controller handles,
 * "n1" is appended to derive a default namespace name.
 *
 * Return: Allocated string containing the namespace name on success,
 * or NULL on failure. The caller is responsible for freeing the returned
 * string.
 */
char *micron_get_ns_name(struct libnvme_transport_handle *hdl);

/**
 * micron_get_pcie_aer_errors() - Retrieve PCIe AER error counts
 * @hdl:			Transport handle
 * @correctable_errors:		Output correctable error register value
 * @uncorrectable_errors:	Output uncorrectable error register value
 *
 * Reads the PCIe Advanced Error Reporting (AER) correctable and
 * uncorrectable error registers for the device associated with @hdl
 * directly from its PCI config space (no setpci process involved).
 *
 * Return: 0 on success, negative errno on failure.
 */
int micron_get_pcie_aer_errors(struct libnvme_transport_handle *hdl,
		__u32 *correctable_errors, __u32 *uncorrectable_errors);

/**
 * micron_clear_pcie_aer_correctable_errors() - Clear PCIe correctable errors
 * @hdl:	Transport handle
 *
 * Clears the PCIe AER correctable error register for the device
 * associated with @hdl by writing all ones directly to the register in
 * its PCI config space.
 *
 * Return: 0 on success, negative error code on failure.
 */
int micron_clear_pcie_aer_correctable_errors(
		struct libnvme_transport_handle *hdl);

/**
 * micron_write_os_config_to_file() - Dump OS configuration to a file
 * @file_name:	Path of the output file
 *
 * Writes platform-appropriate system configuration details (kernel version,
 * modules, memory, interrupts, CPU info, dmesg, etc.) to the specified file.
 */
void micron_write_os_config_to_file(const char *file_name);

/**
 * micron_get_os_string() - Get a one-line description of the host OS
 * @buf:	Output buffer
 * @len:	Size of @buf in bytes
 *
 * Builds a short human-readable identification of the operating system and
 * architecture, e.g. "Windows 10.0 (build 26100), 64-bit" or
 * "Linux 6.8.0-51-generic x86_64". @buf is set to an empty string if the
 * information cannot be determined.
 */
void micron_get_os_string(char *buf, size_t len);
