/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 Dell Technologies Inc. or its subsidiaries.
 *
 * Authors: Martin Belanger <martin.belanger@dell.com>
 */
#pragma once

#include <ifaddrs.h>
#include <stdbool.h>

/*
 * ipaddrs_eq - Check if 2 IP addresses are equal.
 * @addr1: IP address (can be IPv4 or IPv6)
 * @addr2: IP address (can be IPv4 or IPv6)
 *
 * Return: true if addr1 == addr2. false otherwise.
 */
bool ipaddrs_eq(const char *addr1, const char *addr2);

/*
 * iface_matching_addr - Get interface matching @addr
 * @iface_list: Interface list returned by getifaddrs()
 * @addr: Address to match
 *
 * Parse the interface list pointed to by @iface_list looking
 * for the interface that has @addr as one of its assigned
 * addresses.
 *
 * Return: The name of the interface that owns @addr or NULL.
 */
const char *iface_matching_addr(const struct ifaddrs *iface_list,
		const char *addr);

/*
 * iface_primary_addr_matches - Check that interface's primary
 * address matches
 * @iface_list: Interface list returned by getifaddrs()
 * @iface: Interface to match
 * @addr: Address to match
 *
 * Parse the interface list pointed to by @iface_list and looking for
 * interface @iface. Then get its primary address and check if it matches
 * @addr.
 *
 * Return: true if a match is found, false otherwise.
 */
bool iface_primary_addr_matches(const struct ifaddrs *iface_list,
		const char *iface, const char *addr);
