/* SPDX-License-Identifier: GPL-2.0-or-later */
#pragma once

#include <libnvme.h>

struct libnvmf_config_emitter;
struct nvmf_args;

/*
 * Parse @json_file in the legacy config.json format and add each connection
 * to @emitter. This function does not install the generated configuration.
 *
 * Requires json-c. Returns -ENOTSUP if json-c support is not available.
 */
int nvme_config_convert_json(struct libnvmf_config_emitter *emitter,
		const char *json_file);

/*
 * Parse @disc_file in the legacy discovery.conf format and add each entry
 * to @emitter. This function does not install the generated configuration.
 * Malformed entries are logged and skipped.
 */
int nvme_config_convert_discovery(struct libnvmf_config_emitter *emitter,
		const char *disc_file);

/*
 * Add one parsed discovery.conf entry to @emitter.
 *
 * The caller is responsible for parsing the input line into @fa. Invalid
 * entries are logged and skipped. Only -ENOMEM is treated as a fatal error.
 */
int nvme_config_convert_discovery_args(struct libnvmf_config_emitter *emitter,
		const struct nvmf_args *fa);

/*
 * Implement the "nvme config-convert" command.
 *
 * Convert the legacy config.json and/or discovery.conf configuration files
 * to the INI format, matching "nvme connect-all"'s own default behavior:
 * discovery.conf is always converted when it exists, regardless of whether
 * --config points at a non-default config.json. Write the result to
 * --output or, if omitted, to the default location. Refuse to overwrite an
 * existing target unless --force is used.
 */
int nvme_config_convert(const char *desc, int argc, char **argv);
