// SPDX-License-Identifier: LGPL-2.1-or-later
/**
 * This file is part of libnvme.
 * Copyright (c) 2023 Martin Belanger, Dell Technologies Inc.
 */
#include <sys/types.h>
#include <ifaddrs.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <netinet/in.h>
#include <net/if.h>
#include <arpa/inet.h>

struct ifaddrs_storage {
	struct ifaddrs ifa;
	union {
		/* Reserve space for the biggest of the sockaddr types */
		struct sockaddr_in  s4;
		struct sockaddr_in6 s6;
	} addr, netmask, broadaddr;
	char name[IF_NAMESIZE + 1];
};

static void init_entry(struct ifaddrs_storage *storage,
		       const char *ifname,
		       int family,
		       uint32_t addr1,
		       uint32_t addr2,
		       uint32_t addr3,
		       uint32_t addr4,
		       bool last)
{
	struct ifaddrs *p;

	p = &storage->ifa;
	p->ifa_next = last ? NULL : &storage[1].ifa;
	p->ifa_name = storage->name;
	strcpy(p->ifa_name, ifname);
	p->ifa_flags = 0;

	if (family == AF_INET) {
		struct sockaddr_in *ipv4;

		ipv4 = &storage->addr.s4;
		ipv4->sin_family = family;
		ipv4->sin_port = 0;
		ipv4->sin_addr.s_addr = htonl(addr1);
		p->ifa_addr = (struct sockaddr *)ipv4;

		ipv4 = &storage->netmask.s4;
		ipv4->sin_family = family;
		ipv4->sin_port = 0;
		ipv4->sin_addr.s_addr = 0xffffff00;
		p->ifa_netmask = (struct sockaddr *)ipv4;

		ipv4 = &storage->broadaddr.s4;
		ipv4->sin_family = family;
		ipv4->sin_port = 0;
		ipv4->sin_addr.s_addr = 0;
		p->ifa_broadaddr = (struct sockaddr *)ipv4;;
	} else {
		struct sockaddr_in6 *ipv6;

		ipv6 = &storage->addr.s6;
		ipv6->sin6_family = family;
		ipv6->sin6_port = 0;
		ipv6->sin6_flowinfo = 0;
		ipv6->sin6_addr.s6_addr32[0] = htonl(addr1);
		ipv6->sin6_addr.s6_addr32[1] = htonl(addr2);
		ipv6->sin6_addr.s6_addr32[2] = htonl(addr3);
		ipv6->sin6_addr.s6_addr32[3] = htonl(addr4);
		ipv6->sin6_scope_id = 0;
		p->ifa_addr = (struct sockaddr *)ipv6;

		ipv6 = &storage->netmask.s6;
		ipv6->sin6_family = family;
		ipv6->sin6_port = 0;
		ipv6->sin6_flowinfo = 0;
		ipv6->sin6_addr.s6_addr32[0] = 0xffffffff;
		ipv6->sin6_addr.s6_addr32[1] = 0xffffffff;
		ipv6->sin6_addr.s6_addr32[2] = 0xffffffff;
		ipv6->sin6_addr.s6_addr32[3] = 0;
		ipv6->sin6_scope_id = 0;
		p->ifa_netmask = (struct sockaddr *)ipv6;

		ipv6 = &storage->broadaddr.s6;
		ipv6->sin6_family = family;
		ipv6->sin6_port = 0;
		ipv6->sin6_flowinfo = 0;
		ipv6->sin6_addr.s6_addr32[0] = 0;
		ipv6->sin6_addr.s6_addr32[1] = 0;
		ipv6->sin6_addr.s6_addr32[2] = 0;
		ipv6->sin6_addr.s6_addr32[3] = 0;
		ipv6->sin6_scope_id = 0;
		p->ifa_broadaddr = (struct sockaddr *)ipv6;
	}

	p->ifa_data = NULL;
}

int getifaddrs(struct ifaddrs **ifap) {
	struct ifaddrs_storage *storage;

	/* Allocate memory for 4 interfaces */
	storage = (struct ifaddrs_storage *)calloc(4, sizeof(struct ifaddrs_storage));
	*ifap = &storage[0].ifa;

	init_entry(&storage[0], "eth0", AF_INET, 0xc0a80114, 0, 0, 0, false); /* 192.168.1.20 */
	init_entry(&storage[1], "eth0", AF_INET6, 0xfe800000, 0, 0, 0xdeadbeef, false); /* fe80::dead:beef */

	/* Loopback interface */
	init_entry(&storage[2], "lo", AF_INET, 0x7f000001, 0, 0, 0, false); /* 127.0.0.1 */
	init_entry(&storage[3], "lo", AF_INET6, 0, 0, 0, 1, true); /* ::1 */

	return 0;
}

void freeifaddrs(struct ifaddrs *ifa) {
	free(ifa);
}

