/* SPDX-License-Identifier: GPL-2.0-or-later */
#pragma once

#include <libnvme.h>

struct libnvmf_config_emitter;

/*
 * Parse @json_file in the legacy config.json format and add each connection
 * to @emitter. This function does not install the generated configuration.
 *
 * Requires json-c. Returns -ENOTSUP if json-c support is not available.
 */
int nvme_config_convert_json(struct libnvmf_config_emitter *emitter,
		const char *json_file);
