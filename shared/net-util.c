// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 Dell Technologies Inc. or its subsidiaries.
 *
 * Authors: Martin Belanger <martin.belanger@dell.com>
 */

#include <arpa/inet.h>
#include <errno.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#include "net-util.h"

/*
 * Parse @addr (IPv4, or IPv6 with an optional "%scope" suffix on a
 * link-local address) into @ss. @addr is never a hostname -- resolving one
 * is the caller's job, done before this is reached.
 *
 * Return: 0 on success; -EINVAL if @addr is not numeric; -ENOMEM on
 * allocation failure.
 */
static int parse_numeric_addr(const char *addr, struct sockaddr_storage *ss)
{
	struct sockaddr_in *addr4 = (struct sockaddr_in *)ss;
	struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)ss;
	char *tmp;
	char *scope;
	int ret = 0;

	memset(ss, 0, sizeof(*ss));

	if (inet_pton(AF_INET, addr, &addr4->sin_addr) == 1) {
		addr4->sin_family = AF_INET;
		return 0;
	}

	tmp = strdup(addr);
	if (!tmp)
		return -ENOMEM;

	scope = strchr(tmp, '%');
	if (scope)
		*scope++ = '\0';

	if (inet_pton(AF_INET6, tmp, &addr6->sin6_addr) != 1) {
		ret = -EINVAL;
		goto out;
	}

	addr6->sin6_family = AF_INET6;
	if (scope && IN6_IS_ADDR_LINKLOCAL(&addr6->sin6_addr))
		addr6->sin6_scope_id = if_nametoindex(scope);

out:
	free(tmp);
	return ret;
}

static bool sockaddrs_eq(struct sockaddr *addr1, struct sockaddr *addr2)
{
	struct sockaddr_in *sockaddr_v4;
	struct sockaddr_in6 *sockaddr_v6;

	if (addr1->sa_family == AF_INET && addr2->sa_family == AF_INET) {
		struct sockaddr_in *sockaddr1 = (struct sockaddr_in *)addr1;
		struct sockaddr_in *sockaddr2 = (struct sockaddr_in *)addr2;

		return sockaddr1->sin_addr.s_addr == sockaddr2->sin_addr.s_addr;
	}

	if (addr1->sa_family == AF_INET6 && addr2->sa_family == AF_INET6) {
		struct sockaddr_in6 *sockaddr1 = (struct sockaddr_in6 *)addr1;
		struct sockaddr_in6 *sockaddr2 = (struct sockaddr_in6 *)addr2;

		return !memcmp(&sockaddr1->sin6_addr, &sockaddr2->sin6_addr,
			       sizeof(struct in6_addr));
	}

	switch (addr1->sa_family) {
	case AF_INET:
		sockaddr_v6 = (struct sockaddr_in6 *)addr2;
		if (IN6_IS_ADDR_V4MAPPED(&sockaddr_v6->sin6_addr)) {
			sockaddr_v4 = (struct sockaddr_in *)addr1;
			return sockaddr_v4->sin_addr.s_addr ==
				sockaddr_v6->sin6_addr.s6_addr32[3];
		}
		break;

	case AF_INET6:
		sockaddr_v6 = (struct sockaddr_in6 *)addr1;
		if (IN6_IS_ADDR_V4MAPPED(&sockaddr_v6->sin6_addr)) {
			sockaddr_v4 = (struct sockaddr_in *)addr2;
			return sockaddr_v4->sin_addr.s_addr ==
				sockaddr_v6->sin6_addr.s6_addr32[3];
		}
		break;

	default:
		break;
	}

	return false;
}

bool ipaddrs_eq(const char *addr1, const char *addr2)
{
	struct sockaddr_storage ss1, ss2;

	if (addr1 == addr2)
		return true;

	if (!addr1 || !addr2)
		return false;

	if (parse_numeric_addr(addr1, &ss1))
		return false;

	if (parse_numeric_addr(addr2, &ss2))
		return false;

	return sockaddrs_eq((struct sockaddr *)&ss1, (struct sockaddr *)&ss2);
}

const char *iface_matching_addr(const struct ifaddrs *iface_list,
		const char *addr)
{
	const struct ifaddrs *iface_it;
	struct sockaddr_storage ss;
	const char *iface_name = NULL;

	if (!iface_list || !addr || parse_numeric_addr(addr, &ss))
		return NULL;

	/* Walk through the linked list */
	for (iface_it = iface_list; iface_it; iface_it = iface_it->ifa_next) {
		struct sockaddr *ifaddr = iface_it->ifa_addr;
		bool is_inet = ifaddr && (ifaddr->sa_family == AF_INET ||
					  ifaddr->sa_family == AF_INET6);

		if (is_inet && sockaddrs_eq((struct sockaddr *)&ss, ifaddr)) {
			iface_name = iface_it->ifa_name;
			break;
		}
	}

	return iface_name;
}

bool iface_primary_addr_matches(const struct ifaddrs *iface_list,
		const char *iface, const char *addr)
{
	const struct ifaddrs *iface_it;
	struct sockaddr_storage ss;
	bool match_found = false;

	if (!iface_list || !addr || parse_numeric_addr(addr, &ss))
		return false;

	/* Walk through the linked list */
	for (iface_it = iface_list; iface_it; iface_it = iface_it->ifa_next) {
		if (strcmp(iface, iface_it->ifa_name))
			continue; /* Not the interface we're looking for*/

		/* The interface list is ordered in a way that the primary
		 * address is listed first. As soon as the parsed address
		 * matches the family of the address we're looking for, we
		 * have found the primary address for that family.
		 */
		if (iface_it->ifa_addr &&
		    (iface_it->ifa_addr->sa_family == ss.ss_family)) {
			match_found = sockaddrs_eq((struct sockaddr *)&ss,
					iface_it->ifa_addr);
			break;
		}
	}

	return match_found;
}
