// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 Dell Technologies Inc. or its subsidiaries.
 *
 * Authors: Martin Belanger <martin.belanger@dell.com>
 */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#include "inventory.h"
#include "tid.h"

#define HOST_NQN "nqn.2014-08.org.nvmexpress:uuid:c0ffee00-0000-0000-0000-000000000001"
#define DISC_NQN "nqn.2014-08.org.nvmexpress.discovery"
#define IOC_NQN  "nqn.1992-08.com.example:sn.xxxx:subsystem.vol1"

static struct libnvmf_tid *dc(const char *traddr)
{
	struct libnvmf_tid *t = tid_new("tcp", traddr, "8009", DISC_NQN, NULL,
					NULL, HOST_NQN, NULL, true);

	if (!t) {
		printf(" - tid_new(%s) returned NULL [FAIL]\n", traddr);
		exit(EXIT_FAILURE);
	}
	return t;
}

static struct libnvmf_tid *ioc(const char *traddr)
{
	struct libnvmf_tid *t = tid_new("tcp", traddr, "4420", IOC_NQN, NULL,
					NULL, HOST_NQN, NULL, false);

	if (!t) {
		printf(" - tid_new(%s) returned NULL [FAIL]\n", traddr);
		exit(EXIT_FAILURE);
	}
	return t;
}

/* A NULL-terminated array holding a copy of @tid, or no TID. */
static struct libnvmf_tid **one(const struct libnvmf_tid *tid)
{
	struct libnvmf_tid **tids = calloc(2, sizeof(*tids));

	if (!tids)
		exit(EXIT_FAILURE);
	if (tid)
		tids[0] = libnvmf_tid_dup(tid);
	return tids;
}

/* Cache a DLP for @parent that lists @ioc and @referral (either NULL). */
static void cache_dlp(struct inventory *inv, const struct libnvmf_tid *parent,
		      const struct libnvmf_tid *ioc,
		      const struct libnvmf_tid *referral)
{
	inventory_update_dlp(inv, parent, one(ioc), one(referral));
}

static bool check(const char *name, bool got, bool want)
{
	bool pass = got == want;

	printf(" - %s [%s]\n", name, pass ? "PASS" : "FAIL");
	return pass;
}

/* A discovered DC is desired, and so is everything its DLP lists. */
static bool test_discovered_dc(void)
{
	struct inventory *inv = inventory_new();
	__cleanup_tid struct libnvmf_tid *dc1 = dc("10.0.0.1");
	__cleanup_tid struct libnvmf_tid *io1 = ioc("10.0.0.2");
	bool pass = true;

	printf("test_discovered_dc:\n");

	pass &= check("unknown DC is not desired",
		      inventory_is_desired(inv, dc1), false);
	inventory_add_discovered_dc(inv, dc1);
	cache_dlp(inv, dc1, io1, NULL);
	pass &= check("discovered DC is desired",
		      inventory_is_desired(inv, dc1), true);
	pass &= check("its IOC is desired",
		      inventory_is_desired(inv, io1), true);

	inventory_forget_dc(inv, dc1);
	pass &= check("forgotten DC is not desired",
		      inventory_is_desired(inv, dc1), false);
	pass &= check("its IOC is not desired",
		      inventory_is_desired(inv, io1), false);

	inventory_free(inv);
	return pass;
}

/* A cached DLP counts only while its DC has a source. */
static bool test_cached_dlp_needs_source(void)
{
	struct inventory *inv = inventory_new();
	__cleanup_tid struct libnvmf_tid *dc1 = dc("10.0.0.1");
	__cleanup_tid struct libnvmf_tid *io1 = ioc("10.0.0.2");
	bool pass = true;

	printf("test_cached_dlp_needs_source:\n");

	cache_dlp(inv, dc1, io1, NULL);
	pass &= check("DC with only a cached DLP is not desired",
		      inventory_is_desired(inv, dc1), false);
	pass &= check("its IOC is not desired",
		      inventory_is_desired(inv, io1), false);

	inventory_free(inv);
	return pass;
}

/* A referral is desired through its parent, and so is what it lists. */
static bool test_referral_chain(void)
{
	struct inventory *inv = inventory_new();
	__cleanup_tid struct libnvmf_tid *dc1 = dc("10.0.0.1");
	__cleanup_tid struct libnvmf_tid *ref = dc("10.0.0.3");
	__cleanup_tid struct libnvmf_tid *io1 = ioc("10.0.0.4");
	bool pass = true;

	printf("test_referral_chain:\n");

	inventory_add_discovered_dc(inv, dc1);
	cache_dlp(inv, dc1, NULL, ref);
	cache_dlp(inv, ref, io1, NULL);
	pass &= check("referral is desired",
		      inventory_is_desired(inv, ref), true);
	pass &= check("the referral's IOC is desired",
		      inventory_is_desired(inv, io1), true);

	/* The parent's DLP drops the referral. */
	cache_dlp(inv, dc1, NULL, NULL);
	pass &= check("dropped referral is not desired",
		      inventory_is_desired(inv, ref), false);
	pass &= check("the dropped referral's IOC is not desired",
		      inventory_is_desired(inv, io1), false);

	inventory_free(inv);
	return pass;
}

/* Two DCs that refer to each other, with no source: no endless loop. */
static bool test_referral_loop(void)
{
	struct inventory *inv = inventory_new();
	__cleanup_tid struct libnvmf_tid *dc1 = dc("10.0.0.1");
	__cleanup_tid struct libnvmf_tid *dc2 = dc("10.0.0.2");
	bool pass = true;

	printf("test_referral_loop:\n");

	cache_dlp(inv, dc1, NULL, dc2);
	cache_dlp(inv, dc2, NULL, dc1);
	pass &= check("DCs in a referral loop are not desired",
		      inventory_is_desired(inv, dc1), false);

	inventory_add_discovered_dc(inv, dc2);
	pass &= check("a loop member with a source is desired",
		      inventory_is_desired(inv, dc2), true);
	pass &= check("so is the DC it refers to",
		      inventory_is_desired(inv, dc1), true);

	inventory_free(inv);
	return pass;
}

/*
 * A DC 8 referral hops past its source is desired, and so is its IOC. A
 * referral one hop further is not.
 */
static bool test_referral_hop_limit(void)
{
	struct inventory *inv = inventory_new();
	struct libnvmf_tid *chain[INVENTORY_MAX_REFERRAL_HOPS + 2];
	__cleanup_tid struct libnvmf_tid *io1 = ioc("10.0.1.1");
	bool pass = true;
	char addr[32];
	size_t i;

	printf("test_referral_hop_limit:\n");

	for (i = 0; i < INVENTORY_MAX_REFERRAL_HOPS + 2; i++) {
		snprintf(addr, sizeof(addr), "10.0.0.%zu", i + 1);
		chain[i] = dc(addr);
	}
	inventory_add_discovered_dc(inv, chain[0]);
	for (i = 0; i < INVENTORY_MAX_REFERRAL_HOPS + 1; i++)
		cache_dlp(inv, chain[i], NULL, chain[i + 1]);
	cache_dlp(inv, chain[INVENTORY_MAX_REFERRAL_HOPS], io1, chain[9]);

	pass &= check("DC at the hop limit is desired",
		      inventory_is_desired(inv,
					   chain[INVENTORY_MAX_REFERRAL_HOPS]),
		      true);
	pass &= check("its hop count is the limit",
		      inventory_referral_hops(inv,
				chain[INVENTORY_MAX_REFERRAL_HOPS]) ==
		      INVENTORY_MAX_REFERRAL_HOPS, true);
	pass &= check("its IOC is desired",
		      inventory_is_desired(inv, io1), true);
	pass &= check("the referral past the limit is not desired",
		      inventory_is_desired(inv,
				chain[INVENTORY_MAX_REFERRAL_HOPS + 1]),
		      false);

	for (i = 0; i < INVENTORY_MAX_REFERRAL_HOPS + 2; i++)
		tid_free(chain[i]);
	inventory_free(inv);
	return pass;
}

int main(void)
{
	bool pass = true;

	pass &= test_discovered_dc();
	pass &= test_cached_dlp_needs_source();
	pass &= test_referral_chain();
	pass &= test_referral_loop();
	pass &= test_referral_hop_limit();

	fflush(stdout);
	exit(pass ? EXIT_SUCCESS : EXIT_FAILURE);
}
