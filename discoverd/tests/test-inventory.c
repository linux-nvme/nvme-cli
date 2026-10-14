// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 Dell Technologies Inc. or its subsidiaries.
 *
 * Authors: Martin Belanger <martin.belanger@dell.com>
 */

#include <limits.h>
#include <netdb.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <daemon-util/resolve.h>
#include <nvme/config.h>
#include <nvme/lib.h>

#include "ctx.h"
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

/* The TID in @tids with @traddr and @subsysnqn, or NULL. */
static const struct libnvmf_tid *find(struct libnvmf_tid **tids,
				      const char *traddr,
				      const char *subsysnqn)
{
	int i;

	for (i = 0; tids && tids[i]; i++) {
		if (shr_streq0(libnvmf_tid_get_traddr(tids[i]), traddr) &&
		    shr_streq0(libnvmf_tid_get_subsysnqn(tids[i]), subsysnqn))
			return tids[i];
	}

	return NULL;
}

static void free_tids(struct libnvmf_tid **tids)
{
	int i;

	for (i = 0; tids && tids[i]; i++)
		tid_free(tids[i]);
	free(tids);
}

static bool check_tid(const char *name, const struct libnvmf_tid *t,
		      const char *trsvcid, const char *host_traddr,
		      const char *hostnqn, const char *hostid)
{
	bool pass = t &&
		shr_streq0(libnvmf_tid_get_transport(t), "tcp") &&
		shr_streq0(libnvmf_tid_get_trsvcid(t), trsvcid) &&
		shr_streq0(libnvmf_tid_get_host_traddr(t), host_traddr) &&
		shr_streq0(libnvmf_tid_get_hostnqn(t), hostnqn) &&
		shr_streq0(libnvmf_tid_get_hostid(t), hostid);

	printf(" - %s [%s]\n", name, pass ? "PASS" : "FAIL");
	if (t && !pass)
		printf("   got %s %s:%s host_traddr=%s hostnqn=%s hostid=%s\n",
		       libnvmf_tid_get_transport(t),
		       libnvmf_tid_get_traddr(t),
		       libnvmf_tid_get_trsvcid(t),
		       libnvmf_tid_get_host_traddr(t),
		       libnvmf_tid_get_hostnqn(t),
		       libnvmf_tid_get_hostid(t));
	return pass;
}

/*
 * Load the NBFT test table @name from libnvme's test data. The loader reads
 * every NBFT* file in a directory, so the table is linked alone into a
 * temporary one.
 */
static struct inventory *load_nbft(struct discoverd_ctx *dctx,
				   const char *name)
{
	char dir[] = "test-nbft-XXXXXX";
	char table[PATH_MAX], link[PATH_MAX + 8];
	struct inventory *inv = inventory_new();

	snprintf(table, sizeof(table), "%s/%s", NBFT_TABLES, name);
	if (!inv || !mkdtemp(dir)) {
		printf(" - setup for %s [FAIL]\n", name);
		exit(EXIT_FAILURE);
	}
	snprintf(link, sizeof(link), "%s/NBFT", dir);
	if (symlink(table, link) < 0 ||
	    inventory_load_nbft(inv, dctx, dir) < 0) {
		printf(" - load %s [FAIL]\n", name);
		exit(EXIT_FAILURE);
	}
	unlink(link);
	rmdir(dir);

	return inv;
}

#define R660_HOSTNQN "nqn.2014-08.org.nvmexpress:uuid:4c4c4544-0044-4410-8030-b8c04f445833"
#define R660_HOSTID  "44454c4c-4400-1044-8030-b8c04f445833"
#define POWERSTORE   "nqn.1988-11.com.dell:powerstore:00:88b402df2d762AA7AF94"

/* NBFT DCs and IOCs, with the Host Descriptor's identity and each HFI. */
static bool test_nbft_ipv4(struct discoverd_ctx *dctx)
{
	struct inventory *inv = load_nbft(dctx,
		"NBFT-Dell.PowerEdge.R660-fw1.5.5-mpath+discovery");
	struct libnvmf_tid **dcs = inventory_desired_dcs(inv);
	struct libnvmf_tid **iocs = inventory_desired_iocs(inv);
	const struct libnvmf_tid *t;
	bool pass = true;

	printf("test_nbft_ipv4:\n");
	t = find(dcs, "172.18.240.70", DISC_NQN);
	pass &= check_tid("DC on HFI 1", t, "8009", "172.18.240.1",
			  R660_HOSTNQN, R660_HOSTID);
	pass &= check("DC on HFI 1 comes from the NBFT",
		      t && inventory_is_nbft(inv, t), true);
	t = find(dcs, "172.18.230.70", DISC_NQN);
	pass &= check_tid("DC on HFI 2", t, "8009", "172.18.230.2",
			  R660_HOSTNQN, R660_HOSTID);
	t = find(iocs, "172.18.240.60", POWERSTORE);
	pass &= check_tid("IOC on HFI 1", t, "4420", "172.18.240.1",
			  R660_HOSTNQN, R660_HOSTID);
	t = find(iocs, "172.18.230.61", POWERSTORE);
	pass &= check_tid("IOC on HFI 2", t, "4420", "172.18.230.2",
			  R660_HOSTNQN, R660_HOSTID);

	free_tids(dcs);
	free_tids(iocs);
	inventory_free(inv);
	return pass;
}

/* An IPv6 address in a discovery URI is in brackets. */
static bool test_nbft_ipv6_uri(struct discoverd_ctx *dctx)
{
	struct inventory *inv = load_nbft(dctx,
		"NBFT-mpath+disc-ipv4+6_half");
	struct libnvmf_tid **dcs = inventory_desired_dcs(inv);
	const struct libnvmf_tid *t;
	bool pass = true;

	printf("test_nbft_ipv6_uri:\n");
	t = find(dcs, "192.168.122.1", DISC_NQN);
	pass &= check("IPv4 DC", t != NULL, true);
	t = find(dcs, "4321::bbbb:1", DISC_NQN);
	pass &= check("IPv6 DC", t != NULL, true);
	pass &= check("IPv6 DC port", t &&
		      shr_streq0(libnvmf_tid_get_trsvcid(t), "4420"), true);

	free_tids(dcs);
	inventory_free(inv);
	return pass;
}

/*
 * Fake name lookups. "slow.example" answers after SLOW_MS, "fail.example"
 * never resolves, and any other name is 192.0.2.<n>, with <n> taken from
 * the name ("ioc20.example" is 192.0.2.20).
 */
#define SLOW_MS 300

static int nr_fail_lookups;

static int fake_lookup(const char *host, const char *service,
		       const struct addrinfo *hints __attribute__((unused)),
		       struct addrinfo **res)
{
	static const struct addrinfo numeric = {
		.ai_flags = AI_NUMERICHOST,
		.ai_family = AF_INET,
		.ai_socktype = SOCK_STREAM,
	};
	char addr[32];
	int n = 0;

	if (!strcmp(host, "fail.example")) {
		__atomic_add_fetch(&nr_fail_lookups, 1, __ATOMIC_SEQ_CST);
		return EAI_AGAIN;
	}
	if (!strcmp(host, "slow.example")) {
		usleep(SLOW_MS * 1000);
		n = 30;
	} else {
		if (sscanf(host, "%*[a-z]%d", &n) != 1)
			n = 0;
	}
	snprintf(addr, sizeof(addr), "192.0.2.%d", n);

	return getaddrinfo(addr, service, &numeric, res);
}

static int nr_callbacks, nr_added;

static void on_lookup(bool added, void *user_data __attribute__((unused)))
{
	nr_callbacks++;
	nr_added += added;
}

// The hostid that the default host identity derives from HOST_NQN.
#define HOST_ID "c0ffee00-0000-0000-0000-000000000001"

/* Is the configured connection to @traddr desired? */
static bool cfg_desired(struct inventory *inv, const char *traddr,
			bool is_dc)
{
	struct libnvmf_tid *t;
	bool desired;

	t = tid_new("tcp", traddr, is_dc ? "8009" : "4420",
		    is_dc ? DISC_NQN : IOC_NQN, NULL, NULL, HOST_NQN, HOST_ID,
		    is_dc);
	if (!t) {
		printf(" - tid_new(%s) returned NULL [FAIL]\n", traddr);
		exit(EXIT_FAILURE);
	}
	desired = inventory_is_desired(inv, t);
	tid_free(t);

	return desired;
}

/* Run the event loop until @done() or @limit_ms. */
static void run_until(sd_event *event, bool (*done)(void *), void *arg,
		      unsigned int limit_ms)
{
	unsigned int waited;

	for (waited = 0; !done(arg) && waited < limit_ms; waited += 20)
		sd_event_run(event, 20 * 1000);
}

static bool lookups_ended(void *arg)
{
	return !inventory_config_pending(arg);
}

static bool ioc20_added(void *arg)
{
	return cfg_desired(arg, "192.0.2.20", false);
}

static bool fail_retried(void *arg __attribute__((unused)))
{
	return __atomic_load_n(&nr_fail_lookups, __ATOMIC_SEQ_CST) >= 2;
}

/* Write @text to a new nvme-fabrics.conf and read it. */
static struct libnvmf_config *read_config(struct discoverd_ctx *dctx,
					  const char *text)
{
	char path[] = "/tmp/discoverd-inventory-XXXXXX";
	struct libnvmf_config *cfg = NULL;
	int fd;

	fd = mkstemp(path);
	if (fd < 0 || write(fd, text, strlen(text)) != (ssize_t)strlen(text) ||
	    libnvmf_config_read(dctx->nvme_ctx, path, &cfg) < 0) {
		printf(" - read the configuration [FAIL]\n");
		exit(EXIT_FAILURE);
	}
	close(fd);
	unlink(path);

	return cfg;
}

#define CFG_DC(addr)							\
	"[Discovery Controller]\n"					\
	"controller = transport=tcp;traddr=" addr ";trsvcid=8009\n"
#define CFG_IOC(addr)							\
	"[Subsystem]\n"							\
	"nqn = " IOC_NQN "\n"						\
	"controller = transport=tcp;traddr=" addr ";trsvcid=4420\n"

/*
 * A numeric traddr is added at once. Host names are resolved in parallel,
 * without blocking, and the connections are added when the lookups end.
 */
static bool test_config_lookup(struct discoverd_ctx *dctx)
{
	struct libnvmf_config *cfg;
	struct inventory *inv;
	bool pass = true;

	printf("test_config_lookup:\n");
	inv = inventory_new();
	if (!inv)
		exit(EXIT_FAILURE);
	inventory_set_lookup_callback(inv, on_lookup, NULL);
	nr_callbacks = nr_added = 0;
	nr_fail_lookups = 0;

	cfg = read_config(dctx, CFG_DC("192.0.2.1") CFG_DC("slow.example")
			  CFG_IOC("ioc20.example") CFG_IOC("fail.example"));
	dctx->fabrics_cfg = cfg;
	inventory_load_config(inv, dctx);

	pass &= check("numeric DC added at once",
		      cfg_desired(inv, "192.0.2.1", true), true);
	pass &= check("host name not added before its lookup",
		      cfg_desired(inv, "192.0.2.20", false), false);
	pass &= check("lookups pending", inventory_config_pending(inv), true);

	run_until(dctx->event, ioc20_added, inv, 5000);
	pass &= check("fast lookup does not wait for the slow one",
		      cfg_desired(inv, "192.0.2.30", true), false);

	run_until(dctx->event, lookups_ended, inv, 5000);
	pass &= check("lookups ended", inventory_config_pending(inv), false);
	pass &= check("IOC added after its lookup",
		      cfg_desired(inv, "192.0.2.20", false), true);
	pass &= check("slow DC added after its lookup",
		      cfg_desired(inv, "192.0.2.30", true), true);
	pass &= check("one callback per lookup", nr_callbacks == 3, true);
	pass &= check("two connections added", nr_added == 2, true);

	run_until(dctx->event, fail_retried, NULL, 3000);
	pass &= check("failed lookup tried again", fail_retried(NULL), true);

	inventory_free(inv);
	libnvmf_config_free(cfg);
	dctx->fabrics_cfg = NULL;

	return pass;
}

/*
 * Loading the configuration again cancels the lookups of the previous
 * one: their callbacks never run, and the previous configuration can be
 * freed while a lookup is still in a worker.
 */
static bool test_config_reload(struct discoverd_ctx *dctx)
{
	struct libnvmf_config *cfg;
	struct inventory *inv;
	bool pass = true;

	printf("test_config_reload:\n");
	inv = inventory_new();
	if (!inv)
		exit(EXIT_FAILURE);
	inventory_set_lookup_callback(inv, on_lookup, NULL);
	nr_callbacks = nr_added = 0;

	cfg = read_config(dctx, CFG_DC("slow.example"));
	dctx->fabrics_cfg = cfg;
	inventory_load_config(inv, dctx);

	// As reload_config() does: free the old configuration, then load.
	libnvmf_config_free(cfg);
	cfg = read_config(dctx, CFG_IOC("ioc21.example"));
	dctx->fabrics_cfg = cfg;
	inventory_load_config(inv, dctx);

	run_until(dctx->event, lookups_ended, inv, 5000);
	usleep(2 * SLOW_MS * 1000);
	sd_event_run(dctx->event, 0);
	pass &= check("new host name added",
		      cfg_desired(inv, "192.0.2.21", false), true);
	pass &= check("old host name not added",
		      cfg_desired(inv, "192.0.2.30", true), false);
	pass &= check("no callback for the old lookup", nr_callbacks == 1,
		      true);

	// Freed while a lookup runs: no callback, no access to @inv.
	cfg = read_config(dctx, CFG_DC("slow.example"));
	libnvmf_config_free(dctx->fabrics_cfg);
	dctx->fabrics_cfg = cfg;
	inventory_load_config(inv, dctx);
	inventory_free(inv);
	usleep(2 * SLOW_MS * 1000);
	sd_event_run(dctx->event, 0);
	pass &= check("no callback after inventory_free()", nr_callbacks == 1,
		      true);

	libnvmf_config_free(cfg);
	dctx->fabrics_cfg = NULL;

	return pass;
}

#define FC_TRADDR      "nn-0x20000090fae0b5f5:pn-0x10000090fae0b5f5"
#define FC_HOST_TRADDR "nn-0x20000090fa979f2b:pn-0x10000090fa979f2b"

/* An FC address is not a host name: it is added as it is. */
static bool test_config_fc(struct discoverd_ctx *dctx)
{
	struct libnvmf_config *cfg;
	struct inventory *inv;
	struct libnvmf_tid *fc;
	bool pass = true;

	printf("test_config_fc:\n");
	inv = inventory_new();
	if (!inv)
		exit(EXIT_FAILURE);

	cfg = read_config(dctx,
		"[Discovery Controller]\n"
		"controller = transport=fc;traddr=" FC_TRADDR
		";host-traddr=" FC_HOST_TRADDR "\n");
	dctx->fabrics_cfg = cfg;
	inventory_load_config(inv, dctx);

	fc = tid_new("fc", FC_TRADDR, NULL, DISC_NQN, FC_HOST_TRADDR, NULL,
		     HOST_NQN, HOST_ID, true);
	if (!fc) {
		printf(" - tid_new(%s) returned NULL [FAIL]\n", FC_TRADDR);
		exit(EXIT_FAILURE);
	}
	pass &= check("FC DC added", inventory_is_desired(inv, fc), true);
	pass &= check("no lookup", inventory_config_pending(inv), false);

	tid_free(fc);
	inventory_free(inv);
	libnvmf_config_free(cfg);
	dctx->fabrics_cfg = NULL;

	return pass;
}

int main(void)
{
	struct discoverd_ctx dctx = {
		.hostnqn = HOST_NQN,
	};
	bool pass = true;

	pass &= test_discovered_dc();
	pass &= test_cached_dlp_needs_source();
	pass &= test_referral_chain();
	pass &= test_referral_loop();
	pass &= test_referral_hop_limit();

	dctx.nvme_ctx = libnvme_create_global_ctx();
	if (!dctx.nvme_ctx)
		exit(EXIT_FAILURE);
	pass &= test_nbft_ipv4(&dctx);
	pass &= test_nbft_ipv6_uri(&dctx);

	if (sd_event_new(&dctx.event) < 0 ||
	    dmn_resolver_new(dctx.event, 8, &dctx.resolver) < 0)
		exit(EXIT_FAILURE);
	dmn_resolver_set_lookup(dctx.resolver, fake_lookup);
	pass &= test_config_lookup(&dctx);
	pass &= test_config_reload(&dctx);
	pass &= test_config_fc(&dctx);
	dmn_resolver_free(dctx.resolver);
	sd_event_unref(dctx.event);
	// Let the idle workers exit, so that valgrind finds no thread left.
	usleep(2 * SLOW_MS * 1000);

	libnvme_free_global_ctx(dctx.nvme_ctx);

	fflush(stdout);
	exit(pass ? EXIT_SUCCESS : EXIT_FAILURE);
}
