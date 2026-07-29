// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 Dell Technologies Inc. or its subsidiaries.
 *
 * Authors: Martin Belanger <martin.belanger@dell.com>
 */

#include <arpa/inet.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#include <net-util.h>

static bool check_bool(const char *name, bool got, bool want)
{
	if (got == want) {
		printf(" - %s [PASS]\n", name);
		return true;
	}

	printf(" - %s: got %d, want %d [FAIL]\n", name, got, want);
	return false;
}

static bool check_str(const char *name, const char *got, const char *want)
{
	bool eq = (got == want) || (got && want && !strcmp(got, want));

	if (eq) {
		printf(" - %s [PASS]\n", name);
		return true;
	}

	printf(" - %s: got \"%s\", want \"%s\" [FAIL]\n",
	       name, got ? got : "(null)", want ? want : "(null)");
	return false;
}

static bool test_ipaddrs_eq(void)
{
	/*
	 * Two distinct buffers with identical content -- guards against the
	 * compiler pooling two identical string literals into one address,
	 * which would trigger the addr1 == addr2 pointer shortcut instead of
	 * exercising the "hostnames are never numeric" rejection path below.
	 */
	char hostname1[] = "example.com";
	char hostname2[] = "example.com";
	bool pass = true;

	printf("test_ipaddrs_eq:\n");

	pass &= check_bool("NULL == NULL", shr_ipaddrs_eq(NULL, NULL), true);
	pass &= check_bool("NULL != a real address",
			    shr_ipaddrs_eq(NULL, "1.2.3.4"), false);
	pass &= check_bool("identical IPv4 strings",
			    shr_ipaddrs_eq("1.2.3.4", "1.2.3.4"), true);
	pass &= check_bool("different IPv4 addresses",
			    shr_ipaddrs_eq("1.2.3.4", "1.2.3.5"), false);
	pass &= check_bool("compressed vs. expanded IPv6, same address",
			    shr_ipaddrs_eq("2001:db8::1",
					   "2001:0db8:0000:0000:0000:0000:0000:0001"),
			    true);
	pass &= check_bool("IPv4-mapped IPv6 matches its plain IPv4 form",
			    shr_ipaddrs_eq("::ffff:192.168.1.1", "192.168.1.1"),
			    true);
	pass &= check_bool("a hostname is never treated as equal to anything",
			    shr_ipaddrs_eq(hostname1, hostname2), false);

	return pass;
}

/* Build a 3-entry synthetic interface list, no real NICs required. */
struct fake_iface {
	struct ifaddrs pub;
	struct sockaddr_storage ss;
};

static void set_addr(struct fake_iface *f, const char *name,
		     sa_family_t family, const char *addr)
{
	f->pub.ifa_name = (char *)name;
	f->pub.ifa_addr = (struct sockaddr *)&f->ss;

	if (family == AF_INET) {
		struct sockaddr_in *s4 = (struct sockaddr_in *)&f->ss;

		s4->sin_family = AF_INET;
		inet_pton(AF_INET, addr, &s4->sin_addr);
	} else {
		struct sockaddr_in6 *s6 = (struct sockaddr_in6 *)&f->ss;

		s6->sin6_family = AF_INET6;
		inet_pton(AF_INET6, addr, &s6->sin6_addr);
	}
}

static struct ifaddrs *build_fake_ifaddrs(struct fake_iface *nodes, int n)
{
	int i;

	for (i = 0; i < n - 1; i++)
		nodes[i].pub.ifa_next = &nodes[i + 1].pub;
	nodes[n - 1].pub.ifa_next = NULL;

	return &nodes[0].pub;
}

static bool test_iface_matching_addr(void)
{
	struct fake_iface nodes[3] = { 0 };
	struct ifaddrs *list;
	bool pass = true;

	printf("test_iface_matching_addr:\n");

	set_addr(&nodes[0], "eth0", AF_INET, "10.0.0.1");
	set_addr(&nodes[1], "eth1", AF_INET6, "2001:db8::2");
	set_addr(&nodes[2], "eth2", AF_INET, "10.0.0.3");
	list = build_fake_ifaddrs(nodes, 3);

	pass &= check_str("finds the IPv4 owner",
			   shr_iface_matching_addr(list, "10.0.0.1"), "eth0");
	pass &= check_str("finds the IPv6 owner",
			   shr_iface_matching_addr(list, "2001:db8::2"),
			   "eth1");
	pass &= check_str("no owner for an address not in the list",
			   shr_iface_matching_addr(list, "10.0.0.99"), NULL);
	pass &= check_str("NULL list → NULL",
			   shr_iface_matching_addr(NULL, "10.0.0.1"), NULL);

	return pass;
}

static bool test_iface_primary_addr_matches(void)
{
	struct fake_iface nodes[3] = { 0 };
	struct ifaddrs *list;
	bool pass = true;

	printf("test_iface_primary_addr_matches:\n");

	/* eth0's primary IPv4, a secondary IPv4, then its primary IPv6. */
	set_addr(&nodes[0], "eth0", AF_INET, "10.0.0.1");
	set_addr(&nodes[1], "eth0", AF_INET, "10.0.0.99");
	set_addr(&nodes[2], "eth0", AF_INET6, "2001:db8::5");
	list = build_fake_ifaddrs(nodes, 3);

	pass &= check_bool("matches the primary (first-listed) IPv4",
			    shr_iface_primary_addr_matches(list, "eth0",
							   "10.0.0.1"),
			    true);
	pass &= check_bool("the secondary IPv4 is not the primary",
			    shr_iface_primary_addr_matches(list, "eth0",
							   "10.0.0.99"),
			    false);
	pass &= check_bool("matches the primary IPv6",
			    shr_iface_primary_addr_matches(list, "eth0",
							   "2001:db8::5"),
			    true);
	pass &= check_bool("no such interface",
			    shr_iface_primary_addr_matches(list, "eth9",
							   "10.0.0.1"),
			    false);

	return pass;
}

int main(void)
{
	bool pass = true;

	pass &= test_ipaddrs_eq();
	pass &= test_iface_matching_addr();
	pass &= test_iface_primary_addr_matches();

	fflush(stdout);
	exit(pass ? EXIT_SUCCESS : EXIT_FAILURE);
}
