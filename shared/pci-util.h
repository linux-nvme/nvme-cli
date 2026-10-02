/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 SUSE LLC
 *
 * Authors: Daniel Wagner <dwagner@suse.de>
 */
#pragma once

#include <stdint.h>

/*
 * These operate on a PCI device's configuration space -- including the
 * extended region starting at byte offset 0x100 -- through an fd the
 * caller already has open, e.g. on the kernel's sysfs "config" attribute,
 * which supports pread()/pwrite() at arbitrary offsets. That means no
 * helper like setpci needs to be spawned to read or write a register, and
 * callers stay free to resolve that fd however suits them (a path under
 * /sys/bus/pci/devices/<bdf>, a controller's sysfs "device" symlink, ...).
 */

/*
 * Reads a 32-bit register from a device's config space.
 * Return: 0 on success, -errno on failure.
 */
int shr_pci_config_read32(int fd, unsigned int offset, uint32_t *val);

/*
 * Writes a 32-bit register to a device's config space (fd must be open
 * O_RDWR).
 * Return: 0 on success, -errno on failure.
 */
int shr_pci_config_write32(int fd, unsigned int offset, uint32_t val);

/*
 * Walks a device's PCI Express Extended Capability list (config space
 * offset 0x100 onward; each entry is a 32-bit header whose low 16 bits
 * are a capability ID and whose top 12 bits point to the next entry, 0
 * ending the list) looking for cap_id.
 *
 * Return: the capability's config-space offset (>= 0x100) on success,
 * -ENOENT if the device has no such capability, -errno on a read failure.
 */
int shr_pci_find_ext_cap(int fd, uint16_t cap_id);

/*
 * Opens the PCI config space of the device that a sysfs class directory's
 * "device" entry symlinks to (e.g. "/sys/class/nvme/nvme0/device", which
 * resolves the same way "/sys/bus/pci/devices/<bdf>" would) -- so a caller
 * never needs to separately resolve the device's BDF just to read or write
 * one of its registers. Pair with shr_pci_find_ext_cap() on the result to
 * locate a capability; keeping the two separate lets a caller tell "no
 * such device/config" apart from "no such capability", which collapsing
 * them into one call cannot.
 *
 * @dev_class_dir: a sysfs class device directory whose "device" entry
 *                 symlinks to a PCI device directory.
 * @flags:         open() flags; O_RDONLY to only read the space, O_RDWR to
 *                 also write it.
 *
 * Return: an open fd on success, -errno otherwise.
 */
int shr_pci_open_class_config(const char *dev_class_dir, int flags);

/*
 * PCI Express Extended Capability ID for Advanced Error Reporting (AER),
 * and the byte offsets of its Correctable/Uncorrectable Error Status
 * Registers within that capability structure -- all from the PCIe Base
 * Specification. setpci's "ECAP_AER+0x10.L"/"ECAP_AER+0x4.L" name the
 * same two registers.
 */
#define SHR_PCI_EXT_CAP_ID_AER         0x0001
#define SHR_PCI_AER_UNCOR_STATUS_OFF   0x04
#define SHR_PCI_AER_COR_STATUS_OFF     0x10
