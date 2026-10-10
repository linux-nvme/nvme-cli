/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 Dell Technologies Inc. or its subsidiaries.
 *
 * Authors: Martin Belanger <martin.belanger@dell.com>
 */
#pragma once

#include <ifaddrs.h>
#include <inttypes.h>
#include <stdbool.h>

/*
 * shr_ipaddrs_eq - Check if 2 IP addresses are equal.
 * @addr1: IP address (can be IPv4 or IPv6)
 * @addr2: IP address (can be IPv4 or IPv6)
 *
 * Return: true if addr1 == addr2. false otherwise.
 */
bool shr_ipaddrs_eq(const char *addr1, const char *addr2);

/*
 * shr_ipv6_is_link_local - Check if an address is an IPv6 link-local address.
 * @addr: IP address, with or without a scope suffix ("fe80::1%eth0")
 *
 * Return: true if @addr is an IPv6 link-local address. false otherwise.
 */
bool shr_ipv6_is_link_local(const char *addr);

/*
 * shr_iface_matching_addr - Get interface matching @addr
 * @iface_list: Interface list returned by getifaddrs()
 * @addr: Address to match
 *
 * Parse the interface list pointed to by @iface_list looking
 * for the interface that has @addr as one of its assigned
 * addresses.
 *
 * Return: The name of the interface that owns @addr or NULL.
 */
const char *shr_iface_matching_addr(const struct ifaddrs *iface_list,
		const char *addr);

/*
 * shr_iface_primary_addr_matches - Check that interface's primary
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
bool shr_iface_primary_addr_matches(const struct ifaddrs *iface_list,
		const char *iface, const char *addr);

/*
 * shr_route_get_egress_iface - Lookup route table and find egress interface
 *
 * @saddr: optional source address
 * @daddr: destination address
 * @ifname: buffer to hold the matching iface name
 * @iflen: length of ifname buffer (must be greater or equal to IF_NAMESIZE)
 *
 * Lookup route table using specified saddr and daddr and find the egress
 * interface. The saddr is optional however daddr is mandatory.
 *
 * Return: 0 on success and negative errno on failure.
 */
int shr_route_get_egress_iface(const char *saddr, const char *daddr,
		char *ifname, size_t iflen);

/*
 * shr_netdev_get_hw_queues - Get h/w queues details for a netdevice
 *
 * @ifname: Name of network interface
 * @combined_count: combined h/w queue count
 * @tx_count: tx queue count
 * @rx_count: rx queue count
 *
 * Retrieves the NIC h/w queue details.
 *
 * Return: 0 on success and negative errno on failure.
 */
int shr_netdev_get_hw_queues(const char *ifname, uint32_t *combined_count,
		uint32_t *tx_count, uint32_t *rx_count);
