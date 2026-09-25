// SPDX-License-Identifier: GPL-2.0-or-later
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

#include "tid.h"

#define DC_NQN		"nqn.2014-08.org.nvmexpress.discovery"
#define UNIQUE_DC_NQN	"nqn.1988-11.com.dell:PowerSANN111:NVMe:cdc"
#define IOC_NQN		"nqn.1992-08.com.example:sn.xxxx:subsystem.vol1"
#define HOST_NQN	"nqn.2014-08.org.nvmexpress:uuid:c0ffee00-0000-0000-0000-000000000001"

/* Build a fixture TID. A NULL here means the test itself is wrong. */
static struct libnvmf_tid *mk(const char *transport, const char *traddr,
			      const char *trsvcid, const char *subsysnqn,
			      const char *host_traddr, const char *host_iface,
			      const char *hostnqn, bool is_dc)
{
	struct libnvmf_tid *t = tid_new(transport, traddr, trsvcid, subsysnqn,
					host_traddr, host_iface, hostnqn,
					NULL, is_dc);

	if (!t) {
		printf(" - tid_new(%s, %s, %s, %s) returned NULL [FAIL]\n",
		       transport, traddr, trsvcid ? trsvcid : "(null)",
		       host_traddr ? host_traddr : "(null)");
		fflush(stdout);
		exit(EXIT_FAILURE);
	}

	return t;
}

static bool check(const char *name, bool got, bool want)
{
	if (got == want) {
		printf(" - %s [PASS]\n", name);
		return true;
	}

	printf(" - %s: got %d, want %d [FAIL]\n", name, got, want);
	return false;
}

/* Synthetic interface list, no real NICs required. */
struct fake_iface {
	struct ifaddrs pub;
	struct sockaddr_in ss;
};

static struct ifaddrs *fake_ifaddrs(struct fake_iface *nodes, int n)
{
	int i;

	for (i = 0; i < n - 1; i++)
		nodes[i].pub.ifa_next = &nodes[i + 1].pub;
	nodes[n - 1].pub.ifa_next = NULL;

	return &nodes[0].pub;
}

static void set_iface(struct fake_iface *f, const char *name, const char *addr)
{
	f->pub.ifa_name = (char *)name;
	f->pub.ifa_addr = (struct sockaddr *)&f->ss;
	f->ss.sin_family = AF_INET;
	inet_pton(AF_INET, addr, &f->ss.sin_addr);
}

/*
 * enp1s0 owns 10.0.0.48, enp2s0 owns 10.0.1.7. A connection reporting
 * 10.0.0.48 as its source address was therefore made on enp1s0.
 */
static struct ifaddrs *test_ifaces(struct fake_iface *nodes)
{
	set_iface(&nodes[0], "enp1s0", "10.0.0.48");
	set_iface(&nodes[1], "enp2s0", "10.0.1.7");

	return fake_ifaddrs(nodes, 2);
}

/*
 * The case mDNS produces: the candidate forces only host_iface, and the
 * kernel reports back the source address it picked. tid_same() cannot
 * match these two, since one field is set on each side.
 */
static bool test_tcp_host_iface_vs_src_addr(void)
{
	struct fake_iface nodes[2] = { 0 };
	struct ifaddrs *iface_list = test_ifaces(nodes);
	__cleanup_tid struct libnvmf_tid *candidate = NULL;
	__cleanup_tid struct libnvmf_tid *existing = NULL;
	__cleanup_tid struct libnvmf_tid *other = NULL;
	bool pass = true;

	printf("test_tcp_host_iface_vs_src_addr:\n");

	candidate = mk("tcp", "10.0.0.200", "8009", DC_NQN, NULL, "enp1s0",
		       HOST_NQN, true);
	existing = mk("tcp", "10.0.0.200", "8009", DC_NQN, "10.0.0.48", NULL,
		       HOST_NQN, true);
	other = mk("tcp", "10.0.0.200", "8009", DC_NQN, "10.0.1.7", NULL,
			HOST_NQN, true);

	pass &= check("source address on the requested interface matches",
		      tid_matches_existing(candidate, existing, true,
					   iface_list), true);
	pass &= check("source address on another interface does not match",
		      tid_matches_existing(candidate, other, true,
					   iface_list), false);
	pass &= check("tid_same() misses the same pair",
		      tid_same(candidate, existing), false);

	return pass;
}

/* The host ID is compared only when both sides have one. */
static bool test_hostid(void)
{
	static const char *nqn = "nqn.2014-08.com.example:host1";
	static const char *id = "c0ffee00-0000-0000-0000-000000000001";
	static const char *id_upper = "C0FFEE00-0000-0000-0000-000000000001";
	static const char *other_id = "c0ffee00-0000-0000-0000-000000000002";
	__cleanup_tid struct libnvmf_tid *candidate = NULL;
	__cleanup_tid struct libnvmf_tid *no_id = NULL;
	__cleanup_tid struct libnvmf_tid *same = NULL;
	__cleanup_tid struct libnvmf_tid *upper = NULL;
	__cleanup_tid struct libnvmf_tid *other = NULL;
	bool pass = true;

	printf("test_hostid:\n");

	candidate = tid_new("tcp", "10.0.0.200", "4420", IOC_NQN, NULL, NULL,
			    nqn, id, false);
	no_id = tid_new("tcp", "10.0.0.200", "4420", IOC_NQN, NULL, NULL,
			nqn, NULL, false);
	same = tid_new("tcp", "10.0.0.200", "4420", IOC_NQN, NULL, NULL,
		       nqn, id, false);
	upper = tid_new("tcp", "10.0.0.200", "4420", IOC_NQN, NULL, NULL,
			nqn, id_upper, false);
	other = tid_new("tcp", "10.0.0.200", "4420", IOC_NQN, NULL, NULL,
			nqn, other_id, false);
	if (!candidate || !no_id || !same || !upper || !other) {
		printf(" - tid_new() returned NULL [FAIL]\n");
		return false;
	}

	pass &= check("same host ID matches",
		      tid_matches_existing(candidate, same, false, NULL), true);
	pass &= check("host ID compared without case",
		      tid_matches_existing(candidate, upper, false, NULL),
		      true);
	pass &= check("different host ID does not match",
		      tid_matches_existing(candidate, other, false, NULL),
		      false);
	pass &= check("candidate without host ID matches",
		      tid_matches_existing(no_id, other, false, NULL), true);
	pass &= check("existing without host ID matches",
		      tid_matches_existing(candidate, no_id, false, NULL),
		      true);

	return pass;
}

/* A candidate that names no host-side field accepts either connection. */
static bool test_tcp_no_host_side_requested(void)
{
	struct fake_iface nodes[2] = { 0 };
	struct ifaddrs *iface_list = test_ifaces(nodes);
	__cleanup_tid struct libnvmf_tid *candidate = NULL;
	__cleanup_tid struct libnvmf_tid *existing = NULL;
	bool pass = true;

	printf("test_tcp_no_host_side_requested:\n");

	candidate = mk("tcp", "10.0.0.200", "4420", IOC_NQN, NULL, NULL,
		       HOST_NQN, false);
	existing = mk("tcp", "10.0.0.200", "4420", IOC_NQN, "10.0.1.7", NULL,
		       HOST_NQN, false);

	pass &= check("host-side fields ignored when unrequested",
		      tid_matches_existing(candidate, existing, false,
					   iface_list), true);

	return pass;
}

/* An explicit host_traddr must match the reported source address. */
static bool test_tcp_host_traddr(void)
{
	struct fake_iface nodes[2] = { 0 };
	struct ifaddrs *iface_list = test_ifaces(nodes);
	__cleanup_tid struct libnvmf_tid *candidate = NULL;
	__cleanup_tid struct libnvmf_tid *existing = NULL;
	__cleanup_tid struct libnvmf_tid *other = NULL;
	bool pass = true;

	printf("test_tcp_host_traddr:\n");

	candidate = mk("tcp", "10.0.0.200", "4420", IOC_NQN, "10.0.0.48", NULL,
		       HOST_NQN, false);
	existing = mk("tcp", "10.0.0.200", "4420", IOC_NQN, "10.0.0.48", NULL,
		       HOST_NQN, false);
	other = mk("tcp", "10.0.0.200", "4420", IOC_NQN, "10.0.1.7", NULL,
			HOST_NQN, false);

	pass &= check("same source address matches",
		      tid_matches_existing(candidate, existing, false,
					   iface_list), true);
	pass &= check("different source address does not match",
		      tid_matches_existing(candidate, other, false,
					   iface_list), false);

	return pass;
}

/*
 * TP8013: a DC reached with the well-known NQN may report a unique NQN
 * once connected. A candidate asking for the well-known NQN accepts any
 * DC, but never an IOC.
 */
static bool test_well_known_nqn(void)
{
	struct fake_iface nodes[2] = { 0 };
	struct ifaddrs *iface_list = test_ifaces(nodes);
	__cleanup_tid struct libnvmf_tid *candidate = NULL;
	__cleanup_tid struct libnvmf_tid *existing = NULL;
	bool pass = true;

	printf("test_well_known_nqn:\n");

	candidate = mk("tcp", "10.0.0.200", "8009", DC_NQN, NULL, NULL,
		       HOST_NQN, true);
	existing = mk("tcp", "10.0.0.200", "8009", UNIQUE_DC_NQN, NULL, NULL,
		       HOST_NQN, true);

	pass &= check("unique NQN accepted from a DC",
		      tid_matches_existing(candidate, existing, true,
					   iface_list), true);
	pass &= check("unique NQN rejected from an IOC",
		      tid_matches_existing(candidate, existing, false,
					   iface_list), false);

	return pass;
}

/* A candidate naming a specific subsystem still requires an exact NQN. */
static bool test_unique_nqn_must_match(void)
{
	struct fake_iface nodes[2] = { 0 };
	struct ifaddrs *iface_list = test_ifaces(nodes);
	__cleanup_tid struct libnvmf_tid *candidate = NULL;
	__cleanup_tid struct libnvmf_tid *existing = NULL;
	bool pass = true;

	printf("test_unique_nqn_must_match:\n");

	candidate = mk("tcp", "10.0.0.200", "4420", IOC_NQN, NULL, NULL,
		       HOST_NQN, false);
	existing = mk("tcp", "10.0.0.200", "4420", UNIQUE_DC_NQN, NULL, NULL,
		       HOST_NQN, false);

	pass &= check("a different subsystem NQN does not match",
		      tid_matches_existing(candidate, existing, false,
					   iface_list), false);

	return pass;
}

/* Target-side fields are mandatory whatever the candidate omits. */
static bool test_target_side_mandatory(void)
{
	struct fake_iface nodes[2] = { 0 };
	struct ifaddrs *iface_list = test_ifaces(nodes);
	__cleanup_tid struct libnvmf_tid *candidate = NULL;
	__cleanup_tid struct libnvmf_tid *traddr = NULL;
	__cleanup_tid struct libnvmf_tid *trsvcid = NULL;
	__cleanup_tid struct libnvmf_tid *hostnqn = NULL;
	bool pass = true;

	printf("test_target_side_mandatory:\n");

	candidate = mk("tcp", "10.0.0.200", "4420", IOC_NQN, NULL, NULL,
		       HOST_NQN, false);
	traddr = mk("tcp", "10.0.0.201", "4420", IOC_NQN, NULL, NULL,
			 HOST_NQN, false);
	trsvcid = mk("tcp", "10.0.0.200", "4421", IOC_NQN, NULL, NULL,
			  HOST_NQN, false);
	hostnqn = mk("tcp", "10.0.0.200", "4420", IOC_NQN, NULL, NULL,
			  "nqn.2014-08.org.nvmexpress:uuid:c0ffee00-0000-0000-0000-000000000002",
			  false);

	pass &= check("traddr must match",
		      tid_matches_existing(candidate, traddr, false,
					   iface_list), false);
	pass &= check("trsvcid must match",
		      tid_matches_existing(candidate, trsvcid, false,
					   iface_list), false);
	pass &= check("hostnqn must match",
		      tid_matches_existing(candidate, hostnqn, false,
					   iface_list), false);

	return pass;
}

/* An IPv4-mapped IPv6 address is the same address. */
/*
 * Two spellings of one address match. mk() canonicalizes both through
 * libnvmf_tid_from_fields(), so this covers the constructor and the
 * matcher together -- tid_addr_eq()'s numeric comparison is defensive and
 * a literal one would pass here too.
 */
static bool test_address_forms(void)
{
	struct fake_iface nodes[2] = { 0 };
	struct ifaddrs *iface_list = test_ifaces(nodes);
	__cleanup_tid struct libnvmf_tid *candidate = NULL;
	__cleanup_tid struct libnvmf_tid *existing = NULL;
	bool pass = true;

	printf("test_address_forms:\n");

	candidate = mk("tcp", "10.0.0.200", "4420", IOC_NQN, NULL, NULL,
		       HOST_NQN, false);
	existing = mk("tcp", "::ffff:10.0.0.200", "4420", IOC_NQN, NULL, NULL,
		       HOST_NQN, false);

	pass &= check("an IPv4-mapped IPv6 traddr matches its IPv4 form",
		      tid_matches_existing(candidate, existing, false,
					   iface_list), true);

	return pass;
}

/*
 * Kernels older than 6.1 report no source address. The candidate's
 * host_iface is then compared against the interface the connection
 * recorded.
 */
static bool test_tcp_no_src_addr(void)
{
	struct fake_iface nodes[2] = { 0 };
	struct ifaddrs *iface_list = test_ifaces(nodes);
	__cleanup_tid struct libnvmf_tid *candidate = NULL;
	__cleanup_tid struct libnvmf_tid *existing = NULL;
	__cleanup_tid struct libnvmf_tid *other = NULL;
	__cleanup_tid struct libnvmf_tid *bare = NULL;
	bool pass = true;

	printf("test_tcp_no_src_addr:\n");

	candidate = mk("tcp", "10.0.0.200", "8009", DC_NQN, NULL, "enp1s0",
		       HOST_NQN, true);
	existing = mk("tcp", "10.0.0.200", "8009", DC_NQN, NULL, "enp1s0",
		       HOST_NQN, true);
	other = mk("tcp", "10.0.0.200", "8009", DC_NQN, NULL, "enp2s0",
			HOST_NQN, true);
	bare = mk("tcp", "10.0.0.200", "8009", DC_NQN, NULL, NULL,
		       HOST_NQN, true);

	pass &= check("same recorded interface matches",
		      tid_matches_existing(candidate, existing, true,
					   iface_list), true);
	pass &= check("different recorded interface does not match",
		      tid_matches_existing(candidate, other, true,
					   iface_list), false);
	pass &= check("no interface recorded: assumed to match",
		      tid_matches_existing(candidate, bare, true,
					   iface_list), true);

	return pass;
}

/*
 * Transport must always match. FC carries a WWN rather than an IP
 * address, and host_traddr is only checked when both sides name one.
 */
static bool test_transport(void)
{
	struct fake_iface nodes[2] = { 0 };
	struct ifaddrs *iface_list = test_ifaces(nodes);
	__cleanup_tid struct libnvmf_tid *tcp = NULL;
	__cleanup_tid struct libnvmf_tid *rdma = NULL;
	__cleanup_tid struct libnvmf_tid *fc = NULL;
	__cleanup_tid struct libnvmf_tid *fc_same = NULL;
	__cleanup_tid struct libnvmf_tid *fc_other = NULL;
	bool pass = true;

	printf("test_transport:\n");

	tcp = mk("tcp", "10.0.0.200", "4420", IOC_NQN, NULL, NULL,
		 HOST_NQN, false);
	rdma = mk("rdma", "10.0.0.200", "4420", IOC_NQN, NULL, NULL,
		  HOST_NQN, false);
	fc = mk("fc", "nn-0x201700a09890f5bf:pn-0x201900a09890f5bf", NULL,
		IOC_NQN, "nn-0x200000109b579ef3:pn-0x100000109b579ef3", NULL,
		HOST_NQN, false);
	fc_same = mk("fc", "nn-0x201700a09890f5bf:pn-0x201900a09890f5bf",
		     NULL, IOC_NQN,
		     "nn-0x200000109b579ef3:pn-0x100000109b579ef3", NULL,
		     HOST_NQN, false);
	fc_other = mk("fc", "nn-0x201700a09890f5bf:pn-0x201900a09890f5bf",
		      NULL, IOC_NQN,
		      "nn-0x200000109b579ef3:pn-0x100000109b579ef4", NULL,
		      HOST_NQN, false);

	pass &= check("tcp does not match rdma",
		      tid_matches_existing(tcp, rdma, false,
					   iface_list), false);
	pass &= check("same FC WWNs match",
		      tid_matches_existing(fc, fc_same, false,
					   iface_list), true);
	pass &= check("a different FC host WWN does not match",
		      tid_matches_existing(fc, fc_other, false,
					   iface_list), false);

	return pass;
}

/*
 * A candidate must name the host its connection used. One that names none
 * never matches, which is why every candidate gets the default identity.
 */
static bool test_hostless_candidate(void)
{
	__cleanup_tid struct libnvmf_tid *candidate = NULL;
	__cleanup_tid struct libnvmf_tid *existing = NULL;
	bool pass = true;

	printf("test_hostless_candidate:\n");

	candidate = mk("tcp", "10.0.0.200", "4420", IOC_NQN, NULL, NULL, NULL,
		       false);
	existing = mk("tcp", "10.0.0.200", "4420", IOC_NQN, NULL, NULL,
		      HOST_NQN, false);

	pass &= check("a hostless candidate does not match",
		      tid_matches_existing(candidate, existing, false, NULL),
		      false);

	return pass;
}

int main(void)
{
	bool pass = true;

	pass &= test_tcp_host_iface_vs_src_addr();
	pass &= test_tcp_no_host_side_requested();
	pass &= test_tcp_host_traddr();
	pass &= test_well_known_nqn();
	pass &= test_unique_nqn_must_match();
	pass &= test_target_side_mandatory();
	pass &= test_address_forms();
	pass &= test_tcp_no_src_addr();
	pass &= test_transport();
	pass &= test_hostless_candidate();
	pass &= test_hostid();

	fflush(stdout);
	exit(pass ? EXIT_SUCCESS : EXIT_FAILURE);
}
