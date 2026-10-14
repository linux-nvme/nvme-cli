// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 Dell Technologies Inc. or its subsidiaries.
 *
 * Authors: Martin Belanger <martin.belanger@dell.com>
 */

#include <endian.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <daemon-util/log.h>
#include <daemon-util/work.h>
#include <nvme/fabrics.h>
#include <nvme/lib.h>
#include <nvme/nvme-types-fabrics.h>
#include <nvme/tree.h>

#include "dlp.h"
#include "tid.h"

/*
 * Build a TID for one DLPE. Host-side parameters (host_traddr, host_iface,
 * hostnqn, hostid) are inherited from the DC's TID since the IOC is reached
 * via the same physical interface as the DC.
 */
static struct libnvmf_tid *tid_from_dlpe(const struct nvmf_disc_log_entry *e,
					 const struct libnvmf_tid *dc_tid)
{
	const char *scope = dc_tid ? tid_link_local_scope(dc_tid) : NULL;
	__cleanup_free char *traddr = NULL;
	const char *transport;

	transport = libnvmf_trtype_str(e->trtype);
	if (!transport)
		return NULL;

	/*
	 * A DC reached through a scoped link-local address can only report
	 * link-local addresses on that same link.
	 */
	traddr = tid_scope_link_local(e->traddr, scope);
	if (!traddr)
		return NULL;

	return tid_new(transport,
		       traddr,
		       e->trsvcid[0] ? e->trsvcid : NULL,
		       e->subnqn,
		       dc_tid ? libnvmf_tid_get_host_traddr(dc_tid) : NULL,
		       dc_tid ? libnvmf_tid_get_host_iface(dc_tid) : NULL,
		       dc_tid ? libnvmf_tid_get_hostnqn(dc_tid) : NULL,
		       dc_tid ? libnvmf_tid_get_hostid(dc_tid) : NULL,
		       e->subtype == NVME_NQN_DISC);
}

void dlp_process_log(const struct nvmf_discovery_log *log,
		     const struct libnvmf_tid *dc_tid,
		     void (*ioc_callback)(const struct libnvmf_tid *t,
					  void *user_data),
		     void (*dc_callback)(const struct libnvmf_tid *t,
					 bool epcsd, void *user_data),
		     void (*self_callback)(bool epcsd, void *user_data),
		     void *user_data)
{
	uint64_t numrec = le64toh((__u64)log->numrec);
	uint64_t i;

	for (i = 0; i < numrec; i++) {
		const struct nvmf_disc_log_entry *e = &log->entries[i];
		uint16_t eflags = le16toh((__u16)e->eflags);
		__cleanup_tid struct libnvmf_tid *t;

		t = tid_from_dlpe(e, dc_tid);
		if (!t)
			continue;

		/*
		 * A DLPE carries no host-side addressing, so host_traddr and
		 * host_iface are always inherited from the DC (dc_tid). This
		 * ensures the connection to the DLPE follows the same path
		 * used to connect to the DC.
		 *
		 * Inheriting host_traddr and host_iface from the DC is only
		 * valid if the DLPE's transport type matches the DC's. Here
		 * we filter out any DLPE with a transport type that doesn't.
		 *
		 * One exception is the self entry (the entry that matches
		 * the DC). We need to extract the EFLAGS of the DC's own
		 * entry, and therefore cannot filter it out. A DC with
		 * multiple ports may report more than one self entry in the
		 * DLP (Base spec 2.4, Figure 320, subtype 03), so we only
		 * keep the one that precisely matches the DC (dc_tid) and
		 * eliminate all others.
		 */
		if (dc_tid && e->subtype == NVME_NQN_CURR) {
			if (!tid_target_same(dc_tid, t)) {
				log_warn("%s | skipping %s - other-interface self entry",
					 libnvmf_tid_str(dc_tid),
					 libnvmf_tid_str(t));
				continue;
			}
		} else if (dc_tid &&
			   strcmp(libnvmf_tid_get_transport(dc_tid),
				  libnvmf_tid_get_transport(t))) {
			log_warn("%s | skipping %s - transport mismatch",
				 libnvmf_tid_str(dc_tid), libnvmf_tid_str(t));
			continue;
		}

		switch (e->subtype) {
		case NVME_NQN_NVME:
			if (ioc_callback)
				ioc_callback(t, user_data);
			break;
		case NVME_NQN_DISC:
			if (dc_callback)
				dc_callback(t, eflags & NVMF_DISC_EFLAGS_EPCSD,
					    user_data);
			break;
		case NVME_NQN_CURR:
			if (self_callback)
				self_callback(eflags & NVMF_DISC_EFLAGS_EPCSD,
					      user_data);
			break;
		default:
			break;
		}
	}
}

struct dlp_read_job {
	char *devname;
	int log_level;
	dlp_read_callback cb;
	void *user_data;
	// Written by the worker.
	struct nvmf_discovery_log *log;
	const char *failed;	// the step that failed
	int ret;
};

static void read_job_free(void *data)
{
	struct dlp_read_job *j = data;

	free(j->log);
	free(j->devname);
	free(j);
}

/*
 * Runs in a worker. The global context is its own: libnvme objects are not
 * shared with the event loop.
 */
static void read_log(void *data)
{
	struct dlp_read_job *j = data;
	struct libnvme_global_ctx *nctx;
	struct libnvme_ctrl *ctrl = NULL;

	nctx = libnvme_create_global_ctx();
	if (!nctx) {
		j->failed = "create_global_ctx";
		j->ret = -ENOMEM;
		return;
	}
	libnvme_set_logging_level(nctx, j->log_level, false, false);

	j->ret = libnvme_scan_ctrl(nctx, j->devname, &ctrl);
	if (j->ret < 0)
		j->failed = "scan_ctrl";
	else
		j->ret = libnvmf_get_discovery_log(ctrl, NULL, &j->log);
	if (j->ret < 0 && !j->failed)
		j->failed = "get_discovery_log";

	libnvme_free_ctrl(ctrl);
	libnvme_free_global_ctx(nctx);
}

static void read_done(void *data, bool timed_out __attribute__((unused)))
{
	struct dlp_read_job *j = data;

	if (j->ret < 0)
		log_dbg("%s - %s failed: %s", j->devname, j->failed,
			strerror(-j->ret));
	j->cb(j->ret < 0 ? j->ret : 0, j->log, j->user_data);
}

int dlp_read(struct dmn_work_pool *pool, const char *devname, int log_level,
	     dlp_read_callback cb, void *user_data, struct dmn_work **ret)
{
	struct dlp_read_job *j;
	int err;

	if (!pool || !devname || !cb)
		return -EINVAL;

	j = calloc(1, sizeof(*j));
	if (!j)
		return -ENOMEM;
	j->devname = strdup(devname);
	if (!j->devname) {
		free(j);
		return -ENOMEM;
	}
	j->log_level = log_level;
	j->cb = cb;
	j->user_data = user_data;

	err = dmn_work_submit(pool, read_log, read_done, read_job_free, j, 0,
			      ret);
	if (err < 0)
		read_job_free(j);

	return err;
}
