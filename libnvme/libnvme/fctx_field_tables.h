/* SPDX-License-Identifier: LGPL-2.1-or-later */

/*
 * This file is part of libnvme.
 *
 * Copyright (c) 2025, Dell Technologies Inc. or its subsidiaries.
 * Authors: Martin Belanger <Martin.Belanger@dell.com>
 *
 *   ____                           _           _    ____          _
 *  / ___| ___ _ __   ___ _ __ __ _| |_ ___  __| |  / ___|___   __| | ___
 * | |  _ / _ \ '_ \ / _ \ '__/ _` | __/ _ \/ _` | | |   / _ \ / _` |/ _ \
 * | |_| |  __/ | | |  __/ | | (_| | ||  __/ (_| | | |__| (_) | (_| |  __/
 *  \____|\___|_| |_|\___|_|  \__,_|\__\___|\__,_|  \____\___/ \__,_|\___|
 *
 * Auto-generated struct member accessors (setter/getter)
 *
 * To update run: meson compile -C [BUILD-DIR] update-accessors
 * Or:            make update-accessors
 */

#ifndef _FCTX_FIELD_TABLES_H_
#define _FCTX_FIELD_TABLES_H_

#include <stddef.h>

struct fctx_field {
	const char *key;
	size_t off;
};

/* Derived from struct libnvme_fabrics_config in private.h. */

#define _OFF(m) offsetof(struct libnvme_fabrics_config, m)

static const struct fctx_field libnvme_fabrics_config_int_fields[] = {
	{ "queue_size", _OFF(queue_size) },
	{ "nr_io_queues", _OFF(nr_io_queues) },
	{ "reconnect_delay", _OFF(reconnect_delay) },
	{ "ctrl_loss_tmo", _OFF(ctrl_loss_tmo) },
	{ "fast_io_fail_tmo", _OFF(fast_io_fail_tmo) },
	{ "keep_alive_tmo", _OFF(keep_alive_tmo) },
	{ "nr_write_queues", _OFF(nr_write_queues) },
	{ "nr_poll_queues", _OFF(nr_poll_queues) },
	{ "tos", _OFF(tos) },
	{ NULL, 0 },
};

static const struct fctx_field libnvme_fabrics_config_long_fields[] = {
	{ "keyring_id", _OFF(keyring_id) },
	{ "tls_key_id", _OFF(tls_key_id) },
	{ "tls_configured_key_id", _OFF(tls_configured_key_id) },
	{ NULL, 0 },
};

static const struct fctx_field libnvme_fabrics_config_bool_fields[] = {
	{ "duplicate_connect", _OFF(duplicate_connect) },
	{ "disable_sqflow", _OFF(disable_sqflow) },
	{ "hdr_digest", _OFF(hdr_digest) },
	{ "data_digest", _OFF(data_digest) },
	{ "tls", _OFF(tls) },
	{ "concat", _OFF(concat) },
	{ NULL, 0 },
};

#undef _OFF

static const char * const libnvme_fabrics_config_keys[] = {
	"queue_size",
	"nr_io_queues",
	"reconnect_delay",
	"ctrl_loss_tmo",
	"fast_io_fail_tmo",
	"keep_alive_tmo",
	"nr_write_queues",
	"nr_poll_queues",
	"tos",
	"keyring_id",
	"tls_key_id",
	"tls_configured_key_id",
	"duplicate_connect",
	"disable_sqflow",
	"hdr_digest",
	"data_digest",
	"tls",
	"concat",
	NULL,
};

#endif /* _FCTX_FIELD_TABLES_H_ */
