// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 Dell Technologies Inc. or its subsidiaries.
 *
 * Authors: Martin Belanger <martin.belanger@dell.com>
 */

#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>

#include "netif.h"

static bool check(bool cond, const char *what)
{
	printf(" - %s [%s]\n", what, cond ? "PASS" : "FAIL");
	return cond;
}

int main(void)
{
	bool pass = true;

	printf("test_netif_is_candidate:\n");

	pass &= check(
		netif_is_candidate(IFF_UP | IFF_MULTICAST | IFF_BROADCAST),
		"up, multicast, broadcast: candidate");
	pass &= check(!netif_is_candidate(IFF_UP | IFF_LOOPBACK),
		      "up loopback (no multicast): not a candidate");
	pass &= check(!netif_is_candidate(
			      IFF_UP | IFF_MULTICAST | IFF_LOOPBACK),
		      "up, multicast, but loopback: not a candidate");
	pass &= check(!netif_is_candidate(IFF_MULTICAST | IFF_BROADCAST),
		      "down (no IFF_UP): not a candidate");
	pass &= check(!netif_is_candidate(IFF_UP | IFF_BROADCAST),
		      "up but no multicast: not a candidate");
	pass &= check(!netif_is_candidate(0), "no flags: not a candidate");

	fflush(stdout);
	exit(pass ? EXIT_SUCCESS : EXIT_FAILURE);
}
