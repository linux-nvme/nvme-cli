// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libnvme.
 * Copyright (c) 2020 Western Digital Corporation or its affiliates.
 *
 * Authors: Keith Busch <keith.busch@wdc.com>
 * 	    Chaitanya Kulkarni <chaitanya.kulkarni@wdc.com>
 */
#include "private.h"

void *__libnvme_submit_entry(struct libnvme_transport_handle *hdl,
		struct libnvme_passthru_cmd *cmd)
{
	return NULL;
}

void __libnvme_submit_exit(struct libnvme_transport_handle *hdl,
		struct libnvme_passthru_cmd *cmd, int err, void *user_data)
{
}

bool __libnvme_decide_retry(struct libnvme_transport_handle *hdl,
		struct libnvme_passthru_cmd *cmd, int err)
{
	return false;
}

int __libnvme_exec_dry_run(struct libnvme_transport_handle *hdl,
		struct libnvme_passthru_cmd *cmd)
{
	void *user_data;

	user_data = hdl->submit_entry(hdl, cmd);
	hdl->submit_exit(hdl, cmd, 0, user_data);

	return 0;
}
