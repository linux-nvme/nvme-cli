// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 Dell Technologies Inc. or its subsidiaries.
 *
 * Authors: Martin Belanger <martin.belanger@dell.com>
 */

#include <endian.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <nvme/nvme-types-fabrics.h>

#include "dlp.h"

#define DC_NQN		"nqn.2014-08.org.nvmexpress.discovery"
#define IOC_NQN		"nqn.1992-08.com.example:sn.xxxx:subsystem.vol1"
#define REFERRAL_NQN	"nqn.2014-08.org.example:cdc.other"

struct counters {
	unsigned int ioc;
	unsigned int dc;
	unsigned int self;
	bool dc_epcsd;
	bool self_epcsd;
	char last_ioc_subnqn[NVME_NQN_LENGTH];
};

static void ioc_cb(const struct libnvmf_tid *t, void *user_data)
{
	struct counters *c = user_data;
	const char *nqn = libnvmf_tid_get_subsysnqn(t);

	c->ioc++;
	snprintf(c->last_ioc_subnqn, sizeof(c->last_ioc_subnqn), "%s",
		 nqn ? nqn : "");
}

static void dc_cb(const struct libnvmf_tid *t, bool epcsd, void *user_data)
{
	struct counters *c = user_data;

	c->dc++;
	c->dc_epcsd = epcsd;
}

static void self_cb(bool epcsd, void *user_data)
{
	struct counters *c = user_data;

	c->self++;
	c->self_epcsd = epcsd;
}

/*
 * A Discovery Log Page holding @numrec entries. The entries[] flexible array
 * member is sized here so the whole page is one allocation, as it is on the
 * wire.
 */
static struct nvmf_discovery_log *make_log(unsigned int numrec)
{
	struct nvmf_discovery_log *log;
	size_t size;

	size = sizeof(*log) + numrec * sizeof(struct nvmf_disc_log_entry);
	log = calloc(1, size);
	if (!log) {
		fprintf(stderr, "out of memory\n");
		exit(EXIT_FAILURE);
	}

	log->numrec = htole64(numrec);

	return log;
}

static void set_entry(struct nvmf_discovery_log *log, unsigned int i,
		      __u8 subtype, __u16 eflags, const char *traddr,
		      const char *trsvcid, const char *subnqn)
{
	struct nvmf_disc_log_entry *e = &log->entries[i];

	e->trtype = NVMF_TRTYPE_TCP;
	e->adrfam = NVMF_ADDR_FAMILY_IP4;
	e->subtype = subtype;
	e->eflags = htole16(eflags);
	snprintf(e->traddr, sizeof(e->traddr), "%s", traddr);
	snprintf(e->trsvcid, sizeof(e->trsvcid), "%s", trsvcid);
	snprintf(e->subnqn, sizeof(e->subnqn), "%s", subnqn);
}

static bool check(bool cond, const char *what)
{
	printf(" - %s [%s]\n", what, cond ? "PASS" : "FAIL");
	return cond;
}

/*
 * DUPRETINFO must not gate dispatch.
 *
 * The bit is defined for Current Discovery Subsystem entries only. NVMe Base
 * Specification 2.4, Figure 320: "For entries with the SUBTYPE field set to a
 * value other than 3h, this bit shall be cleared to '0'." On such an entry it
 * means a set of this Discovery subsystem's ports return the same log page,
 * so a host need not read the log page from all of them. It does not mean the
 * entry is uninteresting.
 *
 * Reading it as "skip this entry" hid a Discovery controller's own EPCSD
 * report from the caller, which then parked a controller that does support
 * persistent connections.
 */
static bool test_dupretinfo_does_not_drop_entries(void)
{
	__u16 both = NVMF_DISC_EFLAGS_EPCSD | NVMF_DISC_EFLAGS_DUPRETINFO;
	struct nvmf_discovery_log *log;
	struct counters c = { 0 };
	bool pass = true;

	printf("test_dupretinfo_does_not_drop_entries:\n");

	log = make_log(3);
	set_entry(log, 0, NVME_NQN_CURR, both, "192.168.1.116", "8009",
		  DC_NQN);
	set_entry(log, 1, NVME_NQN_NVME, NVMF_DISC_EFLAGS_DUPRETINFO,
		  "192.168.1.116", "4420", IOC_NQN);
	set_entry(log, 2, NVME_NQN_DISC, both, "192.168.1.117", "8009",
		  REFERRAL_NQN);

	dlp_process_log(log, NULL, ioc_cb, dc_cb, self_cb, &c);

	pass &= check(c.self == 1,
		      "self entry with EPCSD|DUPRETINFO dispatched");
	pass &= check(c.self_epcsd, "self entry reports EPCSD=1");
	pass &= check(c.ioc == 1, "I/O entry with DUPRETINFO dispatched");
	pass &= check(c.dc == 1, "referral with EPCSD|DUPRETINFO dispatched");
	pass &= check(c.dc_epcsd, "referral reports EPCSD=1");

	free(log);

	return pass;
}

/* Each subtype reaches its own callback, and EPCSD is passed through. */
static bool test_subtype_dispatch(void)
{
	struct nvmf_discovery_log *log;
	struct counters c = { 0 };
	bool pass = true;

	printf("test_subtype_dispatch:\n");

	log = make_log(4);
	set_entry(log, 0, NVME_NQN_CURR, 0, "192.168.1.116", "8009", DC_NQN);
	set_entry(log, 1, NVME_NQN_NVME, 0, "192.168.1.116", "4420", IOC_NQN);
	set_entry(log, 2, NVME_NQN_DISC, 0, "192.168.1.117", "8009",
		  REFERRAL_NQN);
	/* A reserved subtype is ignored rather than dispatched anywhere. */
	set_entry(log, 3, 0, 0, "192.168.1.118", "8009", IOC_NQN);

	dlp_process_log(log, NULL, ioc_cb, dc_cb, self_cb, &c);

	pass &= check(c.self == 1, "one self callback");
	pass &= check(c.ioc == 1, "one I/O callback");
	pass &= check(c.dc == 1, "one referral callback");
	pass &= check(!c.self_epcsd, "self entry reports EPCSD=0");
	pass &= check(!c.dc_epcsd, "referral reports EPCSD=0");
	pass &= check(!strcmp(c.last_ioc_subnqn, IOC_NQN),
		      "I/O callback carries the entry's subnqn");

	free(log);

	return pass;
}

/*
 * A multi-port Discovery controller may publish several self entries. Base
 * Specification 2.4, Figure 320, subtype 03: "Multiple Current Discovery
 * Subsystem entries may be reported for this Discovery subsystem if the
 * current Discovery subsystem has multiple NVM subsystem ports."
 */
static bool test_multiple_self_entries(void)
{
	struct nvmf_discovery_log *log;
	struct counters c = { 0 };
	bool pass = true;

	printf("test_multiple_self_entries:\n");

	log = make_log(2);
	set_entry(log, 0, NVME_NQN_CURR, NVMF_DISC_EFLAGS_EPCSD,
		  "192.168.1.116", "8009", DC_NQN);
	set_entry(log, 1, NVME_NQN_CURR, NVMF_DISC_EFLAGS_EPCSD,
		  "192.168.2.116", "8009", DC_NQN);

	dlp_process_log(log, NULL, ioc_cb, dc_cb, self_cb, &c);

	pass &= check(c.self == 2, "both self entries dispatched");

	free(log);

	return pass;
}

/* An empty log page dispatches nothing. */
static bool test_no_entries(void)
{
	struct nvmf_discovery_log *log;
	struct counters c = { 0 };
	bool pass = true;

	printf("test_no_entries:\n");

	log = make_log(0);
	dlp_process_log(log, NULL, ioc_cb, dc_cb, self_cb, &c);

	pass &= check(c.self == 0 && c.ioc == 0 && c.dc == 0,
		      "no callbacks for an empty log page");

	free(log);

	return pass;
}

/* Every callback is optional. */
static bool test_null_callbacks(void)
{
	struct nvmf_discovery_log *log;
	bool pass = true;

	printf("test_null_callbacks:\n");

	log = make_log(3);
	set_entry(log, 0, NVME_NQN_CURR, 0, "192.168.1.116", "8009", DC_NQN);
	set_entry(log, 1, NVME_NQN_NVME, 0, "192.168.1.116", "4420", IOC_NQN);
	set_entry(log, 2, NVME_NQN_DISC, 0, "192.168.1.117", "8009",
		  REFERRAL_NQN);

	dlp_process_log(log, NULL, NULL, NULL, NULL, NULL);

	pass &= check(true, "no callbacks installed: no crash");

	free(log);

	return pass;
}

int main(void)
{
	bool pass = true;

	pass &= test_dupretinfo_does_not_drop_entries();
	pass &= test_subtype_dispatch();
	pass &= test_multiple_self_entries();
	pass &= test_no_entries();
	pass &= test_null_callbacks();

	fflush(stdout);
	exit(pass ? EXIT_SUCCESS : EXIT_FAILURE);
}
