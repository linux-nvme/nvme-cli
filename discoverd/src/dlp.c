// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 Dell Technologies Inc. or its subsidiaries.
 *
 * Authors: Martin Belanger <martin.belanger@dell.com>
 */

#include <endian.h>
#include <stdlib.h>
#include <string.h>

#include <nvme/fabrics.h>
#include <nvme/lib.h>
#include <nvme/nvme-types-fabrics.h>
#include <nvme/tree.h>

#include "dlp.h"
#include "log.h"
#include "tid.h"

/*
 * Build a TID for one DLPE. Host-side parameters (host_traddr, host_iface,
 * hostnqn) are inherited from the DC's TID since the IOC is reached via the
 * same physical interface as the DC.
 */
static struct libnvmf_tid *tid_from_dlpe(const struct nvmf_disc_log_entry *e,
					 const struct libnvmf_tid *dc_tid)
{
	const char *transport;

	transport = libnvmf_trtype_str(e->trtype);
	if (!transport)
		return NULL;

	return tid_new(transport,
		       e->traddr,
		       e->trsvcid[0] ? e->trsvcid : NULL,
		       e->subnqn,
		       dc_tid ? libnvmf_tid_get_host_traddr(dc_tid) : NULL,
		       dc_tid ? libnvmf_tid_get_host_iface(dc_tid) : NULL,
		       dc_tid ? libnvmf_tid_get_hostnqn(dc_tid) : NULL,
		       e->subtype == NVME_NQN_DISC);
}

int dlp_fetch(struct discoverd_ctx *ctx, const char *devname,
	      const struct libnvmf_tid *dc_tid,
	      void (*ioc_cback)(const struct libnvmf_tid *t, void *user_data),
	      void (*dc_cback)(const struct libnvmf_tid *t, void *user_data),
	      void *user_data)
{
	libnvme_ctrl_t ctrl = NULL;
	struct nvmf_discovery_log *log = NULL;
	uint64_t numrec;
	uint64_t i;
	int ret;

	ret = libnvme_scan_ctrl(ctx->nvme_ctx, devname, &ctrl);
	if (ret < 0) {
		disc_warn("%s | %s - scan_ctrl failed: %s",
			  libnvmf_tid_str(dc_tid), devname, strerror(-ret));
		goto out;
	}

	ret = libnvmf_get_discovery_log(ctrl, NULL, &log);
	if (ret < 0) {
		disc_warn("%s | %s - get_discovery_log failed: %s",
			  libnvmf_tid_str(dc_tid), devname, strerror(-ret));
		goto out;
	}

	numrec = le64toh((__u64)log->numrec);

	for (i = 0; i < numrec; i++) {
		const struct nvmf_disc_log_entry *e = &log->entries[i];
		uint16_t eflags = le16toh((__u16)e->eflags);
		struct libnvmf_tid *t;

		if (eflags & NVMF_DISC_EFLAGS_DUPRETINFO)
			continue;

		t = tid_from_dlpe(e, dc_tid);
		if (!t)
			continue;

		switch (e->subtype) {
		case NVME_NQN_NVME:
			if (ioc_cback)
				ioc_cback(t, user_data);
			break;
		case NVME_NQN_DISC:
			if (dc_cback)
				dc_cback(t, user_data);
			break;
		default:
			break;
		}

		tid_free(t);
	}

	ret = 0;
out:
	free(log);
	libnvme_free_ctrl(ctrl); // detach from the global-ctx tree; NULL-safe
	return ret;
}
