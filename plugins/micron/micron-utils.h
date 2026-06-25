/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (c) 2025 Micron Technology, Inc.
 *
 * Authors: Broc Going <bgoing@micron.com>
 */
#pragma once

#include <stdbool.h>
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
 * micron_get_ctrl_sysfs_dir() - Get the sysfs directory path for a controller
 * @ctx:	struct libnvme_global_ctx object
 * @hdl:	Transport handle
 *
 * Looks up the sysfs directory for the controller associated with @hdl
 * by scanning the NVMe subsystem.
 *
 * Return: Allocated string containing the sysfs directory path on
 * success, or NULL on failure. The caller is responsible for freeing
 * the returned string.
 */
char *micron_get_ctrl_sysfs_dir(struct libnvme_global_ctx *ctx,
				struct libnvme_transport_handle *hdl);

/**
 * micron_get_pci_ids() - Read PCI vendor and device IDs for a controller
 * @ctx:	struct libnvme_global_ctx object
 * @hdl:	Transport handle
 * @vid:	Output PCI vendor ID
 * @did:	Output PCI device ID
 *
 * Gets the PCI vendor and device IDs for the controller associated with @hdl.
 *
 * Return: 0 on success, negative errno on failure.
 */
int micron_get_pci_ids(struct libnvme_global_ctx *ctx,
			struct libnvme_transport_handle *hdl,
			unsigned short *vid, unsigned short *did);

/**
 * micron_get_pcie_aer_errors() - Retrieve PCIe AER error counts
 * @hdl:			Transport handle
 * @correctable_errors:		Output correctable error register value
 * @uncorrectable_errors:	Output uncorrectable error register value
 *
 * Reads the PCIe Advanced Error Reporting (AER) correctable and
 * uncorrectable error registers for the device associated with @hdl using
 * setpci.
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
 * associated with @hdl by writing all ones to the register via setpci.
 *
 * Return: 0 on success, negative error code on failure.
 */
int micron_clear_pcie_aer_correctable_errors(
		struct libnvme_transport_handle *hdl);

/**
 * micron_run_spawn() - Run a command without invoking a shell
 * @argv:	NULL-terminated argument vector (argv[0] is the program)
 * @outfile:	If non-NULL, redirect stdout and stderr to this file
 * @append:	If true, append to outfile; if false, truncate it
 *
 * Executes the program specified by argv[0] with the given arguments.
 * The program is searched in PATH. No shell is invoked, preventing
 * command injection via metacharacters in arguments.
 *
 * Return: 0 on success, negative errno on failure.
 */
int micron_run_spawn(char *const argv[], const char *outfile, bool append);

/**
 * micron_write_os_config_to_file() - Dump OS configuration to a file
 * @file_name:	Path of the output file
 *
 * Writes platform-appropriate system configuration details (kernel version,
 * modules, memory, interrupts, CPU info, dmesg, etc.) to the specified file.
 */
void micron_write_os_config_to_file(const char *file_name);
