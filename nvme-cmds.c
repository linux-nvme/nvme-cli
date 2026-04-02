// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libnvme.
 * Copyright (c) 2020 Western Digital Corporation or its affiliates.
 *
 * Authors: Keith Busch <keith.busch@wdc.com>
 *	    Chaitanya Kulkarni <chaitanya.kulkarni@wdc.com>
 */

#include <libnvme.h>

#include "nvme-cmds.h"

static int nvme_ns_attachment(struct libnvme_transport_handle *hdl, bool ish,
		__u32 nsid, __u16 num_ctrls, __u16 *ctrlist, bool attach)
{
	struct nvme_ctrl_list cntlist = { 0 };
	struct libnvme_passthru_cmd cmd;

	nvme_init_ctrl_list(&cntlist, num_ctrls, ctrlist);
	if (ish && libnvme_transport_handle_is_mi(hdl))
		nvme_init_mi_cmd_flags(&cmd, ish);

	if (attach)
		nvme_init_ns_attach_ctrls(&cmd, nsid, &cntlist);
	else
		nvme_init_ns_detach_ctrls(&cmd, nsid, &cntlist);

	return libnvme_submit_admin_passthru(hdl, &cmd);
}

int nvme_namespace_attach_ctrls(struct libnvme_transport_handle *hdl, bool ish,
		__u32 nsid, __u16 num_ctrls, __u16 *ctrlist)
{
	return nvme_ns_attachment(hdl, ish, nsid, num_ctrls, ctrlist, true);
}

int nvme_namespace_detach_ctrls(struct libnvme_transport_handle *hdl, bool ish,
		__u32 nsid, __u16 num_ctrls, __u16 *ctrlist)
{
	return nvme_ns_attachment(hdl, ish, nsid, num_ctrls, ctrlist, false);
}


