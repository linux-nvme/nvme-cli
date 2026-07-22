// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2026, Dell Technologies Inc. or its subsidiaries.
 *
 * Authors: Martin Belanger <Martin.Belanger@dell.com>
 */

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <libnvme.h>

#include "common.h"
#include "config-convert.h"
#include "fabrics.h"
#include "logging.h"
#include "nvme-print.h"
#include "util/argconfig.h"
#include "util/cleanup.h"

#ifdef CONFIG_JSONC
#include <json.h>

struct legacy_key {
	const char *json_key;
	const char *ini_key;
};

/* Map config.json keys from underscore to hyphen notation. */
static const struct legacy_key int_keys[] = {
	{ "nr_io_queues",     "nr-io-queues" },
	{ "nr_write_queues",  "nr-write-queues" },
	{ "nr_poll_queues",   "nr-poll-queues" },
	{ "queue_size",       "queue-size" },
	{ "keep_alive_tmo",   "keep-alive-tmo" },
	{ "reconnect_delay",  "reconnect-delay" },
	{ "ctrl_loss_tmo",    "ctrl-loss-tmo" },
	{ "fast_io_fail_tmo", "fast-io-fail-tmo" },
	{ "tos",              "tos" },
};

static const struct legacy_key bool_keys[] = {
	{ "duplicate_connect", "duplicate-connect" },
	{ "disable_sqflow",    "disable-sqflow" },
	{ "hdr_digest",        "hdr-digest" },
	{ "data_digest",       "data-digest" },
	{ "tls",               "tls" },
	{ "concat",            "concat" },
};

static const struct legacy_key string_keys[] = {
	{ "tls_key",          "tls-key" },
	{ "tls_key_identity", "tls-key-identity" },
	{ "keyring",          "keyring" },
	{ "dhchap_key",       "dhchap-secret" },
	{ "dhchap_ctrl_key",  "dhchap-ctrl-secret" },
};

static const char *map_key(const struct legacy_key *table, size_t n,
		const char *json_key)
{
	size_t i;

	for (i = 0; i < n; i++)
		if (!strcmp(table[i].json_key, json_key))
			return table[i].ini_key;

	return NULL;
}

#define MAP_KEY(table, json_key) map_key(table, ARRAY_SIZE(table), json_key)

static const char *json_get_string(struct json_object *obj, const char *key)
{
	struct json_object *val = json_object_object_get(obj, key);

	return val ? json_object_get_string(val) : NULL;
}

static bool json_get_bool(struct json_object *obj, const char *key)
{
	struct json_object *val = json_object_object_get(obj, key);

	return val && json_object_get_boolean(val);
}

/* Copy supported tunable and security parameters into @params. */
static void apply_port_params(struct libnvmf_params *params,
		struct json_object *port_obj)
{
	json_object_object_foreach(port_obj, key_str, val_obj) {
		const char *ini_key;
		char buf[32];

		ini_key = MAP_KEY(int_keys, key_str);
		if (ini_key) {
			snprintf(buf, sizeof(buf), "%d",
				 json_object_get_int(val_obj));
			libnvmf_params_set(params, ini_key, buf);
			continue;
		}
		ini_key = MAP_KEY(bool_keys, key_str);
		if (ini_key) {
			libnvmf_params_set(params, ini_key,
					   json_object_get_boolean(val_obj) ?
					   "true" : "false");
			continue;
		}
		ini_key = MAP_KEY(string_keys, key_str);
		if (ini_key)
			libnvmf_params_set(params, ini_key,
					   json_object_get_string(val_obj));
	}
}

/*
 * The DH-HMAC-CHAP secret is defined per (hostnqn, subsysnqn), not per path
 * (NVMe Base Specification 2.3, section 8.3.5.5.7). If a port does not
 * specify a secret, inherit the host-level default. If both are present but
 * differ, keep the port-specific value and log the mismatch.
 */
static void apply_dhchap_default(struct libnvmf_params *params,
		struct json_object *port_obj, const char *host_default)
{
	const char *port_value = json_get_string(port_obj, "dhchap_key");

	if (!host_default)
		return;

	if (!port_value) {
		libnvmf_params_set(params, "dhchap-secret", host_default);
	} else if (strcmp(port_value, host_default)) {
		nvme_show_verbose_info(
			"config convert: dhchap_key differs between host default and one connection; keeping the connection's own value");
	}
}

static int convert_port(struct libnvmf_config_emitter *emitter,
		const char *hostnqn, const char *hostid,
		const char *hostsymname, const char *host_dhchap_key,
		const char *subsysnqn, struct json_object *port_obj)
{
	struct libnvmf_params *params;
	bool is_dc = json_get_bool(port_obj, "discovery");
	int ret;

	params = libnvmf_params_new();
	if (!params)
		return -ENOMEM;

	apply_port_params(params, port_obj);
	apply_dhchap_default(params, port_obj, host_dhchap_key);

	ret = libnvmf_config_emit_add(emitter, is_dc,
			json_get_string(port_obj, "transport"),
			json_get_string(port_obj, "traddr"),
			json_get_string(port_obj, "trsvcid"),
			subsysnqn,
			json_get_string(port_obj, "host_traddr"),
			json_get_string(port_obj, "host_iface"),
			hostnqn, hostid, params, hostsymname);

	libnvmf_params_free(params);

	/*
	 * A rejected entry (for example, invalid addressing or a conflicting
	 * persona) affects only that entry. Log the error and continue
	 * converting, matching json_parse_port()'s own tolerance. Stop only
	 * if memory allocation fails.
	 */
	if (ret == -ENOMEM)
		return ret;
	if (ret)
		nvme_show_error(
			"config convert: skipping an entry that could not be added: %s",
			libnvme_strerror(-ret));

	return 0;
}

static int convert_subsys(struct libnvmf_config_emitter *emitter,
		const char *hostnqn, const char *hostid,
		const char *hostsymname, const char *host_dhchap_key,
		struct json_object *subsys_obj)
{
	struct json_object *port_array;
	const char *nqn = json_get_string(subsys_obj, "nqn");
	int p, ret;

	/* The well-known discovery NQN is the emitter's default value. */
	if (nqn && (!*nqn || !strcmp(nqn, NVME_DISC_SUBSYS_NAME)))
		nqn = NULL;

	port_array = json_object_object_get(subsys_obj, "ports");
	if (!port_array)
		return 0;

	for (p = 0; p < json_object_array_length(port_array); p++) {
		struct json_object *port_obj =
			json_object_array_get_idx(port_array, p);

		if (!port_obj)
			continue;
		ret = convert_port(emitter, hostnqn, hostid, hostsymname,
				   host_dhchap_key, nqn, port_obj);
		if (ret)
			return ret;
	}

	return 0;
}

static int convert_host(struct libnvmf_config_emitter *emitter,
		struct json_object *host_obj)
{
	struct json_object *subsys_array;
	const char *hostnqn = json_get_string(host_obj, "hostnqn");
	const char *hostid = json_get_string(host_obj, "hostid");
	const char *hostsymname = json_get_string(host_obj, "hostsymname");
	const char *host_dhchap_key = json_get_string(host_obj, "dhchap_key");
	int s, ret;

	subsys_array = json_object_object_get(host_obj, "subsystems");
	if (!subsys_array)
		return 0;

	for (s = 0; s < json_object_array_length(subsys_array); s++) {
		struct json_object *subsys_obj =
			json_object_array_get_idx(subsys_array, s);

		if (!subsys_obj)
			continue;
		ret = convert_subsys(emitter, hostnqn, hostid, hostsymname,
				     host_dhchap_key, subsys_obj);
		if (ret)
			return ret;
	}

	return 0;
}

int nvme_config_convert_json(struct libnvmf_config_emitter *emitter,
		const char *json_file)
{
	struct json_object *json_root, *host_array, *host_obj;
	int h, ret;

	json_root = json_object_from_file(json_file);
	if (!json_root) {
		nvme_show_error("failed to parse %s: %s", json_file,
				 json_util_get_last_err());
		return -EPROTO;
	}

	if (json_object_is_type(json_root, json_type_object)) {
		/* Current format: { "hosts": [ ... ] } */
		host_array = json_object_object_get(json_root, "hosts");
		if (!host_array ||
		    !json_object_is_type(host_array, json_type_array)) {
			nvme_show_error("%s: expected a 'hosts' array",
					 json_file);
			json_object_put(json_root);
			return -EPROTO;
		}
	} else if (json_object_is_type(json_root, json_type_array)) {
		/* Legacy pre-3.0 format: a bare top-level array of hosts. */
		host_array = json_root;
	} else {
		nvme_show_error("%s: expected a JSON object or array",
				 json_file);
		json_object_put(json_root);
		return -EPROTO;
	}

	for (h = 0; h < json_object_array_length(host_array); h++) {
		host_obj = json_object_array_get_idx(host_array, h);
		if (!host_obj)
			continue;
		ret = convert_host(emitter, host_obj);
		if (ret) {
			json_object_put(json_root);
			return ret;
		}
	}

	json_object_put(json_root);

	return 0;
}

#else /* CONFIG_JSONC */

int nvme_config_convert_json(struct libnvmf_config_emitter *emitter,
		const char *json_file)
{
	nvme_show_error(
		"built without json-c; config.json conversion unavailable");
	return -ENOTSUP;
}

#endif /* CONFIG_JSONC */

static void add_tunable_params(struct libnvmf_params *params,
		const struct nvmf_args *fa)
{
	char buf[32];

	if (fa->nr_io_queues) {
		snprintf(buf, sizeof(buf), "%d", fa->nr_io_queues);
		libnvmf_params_set(params, "nr-io-queues", buf);
	}
	if (fa->nr_write_queues) {
		snprintf(buf, sizeof(buf), "%d", fa->nr_write_queues);
		libnvmf_params_set(params, "nr-write-queues", buf);
	}
	if (fa->nr_poll_queues) {
		snprintf(buf, sizeof(buf), "%d", fa->nr_poll_queues);
		libnvmf_params_set(params, "nr-poll-queues", buf);
	}
	if (fa->queue_size) {
		snprintf(buf, sizeof(buf), "%d", fa->queue_size);
		libnvmf_params_set(params, "queue-size", buf);
	}
	if (fa->keep_alive_tmo) {
		snprintf(buf, sizeof(buf), "%d", fa->keep_alive_tmo);
		libnvmf_params_set(params, "keep-alive-tmo", buf);
	}
	if (fa->reconnect_delay) {
		snprintf(buf, sizeof(buf), "%d", fa->reconnect_delay);
		libnvmf_params_set(params, "reconnect-delay", buf);
	}
	if (fa->ctrl_loss_tmo != NVMF_DEF_CTRL_LOSS_TMO) {
		snprintf(buf, sizeof(buf), "%d", fa->ctrl_loss_tmo);
		libnvmf_params_set(params, "ctrl-loss-tmo", buf);
	}
	if (fa->fast_io_fail_tmo) {
		snprintf(buf, sizeof(buf), "%d", fa->fast_io_fail_tmo);
		libnvmf_params_set(params, "fast-io-fail-tmo", buf);
	}
	if (fa->tos != -1) {
		snprintf(buf, sizeof(buf), "%d", fa->tos);
		libnvmf_params_set(params, "tos", buf);
	}
	if (fa->duplicate_connect)
		libnvmf_params_set(params, "duplicate-connect", "true");
	if (fa->disable_sqflow)
		libnvmf_params_set(params, "disable-sqflow", "true");
	if (fa->hdr_digest)
		libnvmf_params_set(params, "hdr-digest", "true");
	if (fa->data_digest)
		libnvmf_params_set(params, "data-digest", "true");
	if (fa->tls)
		libnvmf_params_set(params, "tls", "true");
	if (fa->concat)
		libnvmf_params_set(params, "concat", "true");
	if (fa->hostkey)
		libnvmf_params_set(params, "dhchap-secret", fa->hostkey);
	if (fa->ctrlkey)
		libnvmf_params_set(params, "dhchap-ctrl-secret", fa->ctrlkey);
	if (fa->keyring)
		libnvmf_params_set(params, "keyring", fa->keyring);
	if (fa->tls_key)
		libnvmf_params_set(params, "tls-key", fa->tls_key);
	if (fa->tls_key_identity)
		libnvmf_params_set(params, "tls-key-identity",
				   fa->tls_key_identity);
}

int nvme_config_convert_discovery_args(struct libnvmf_config_emitter *emitter,
		const struct nvmf_args *fa)
{
	struct libnvmf_params *params;
	int ret;

	params = libnvmf_params_new();
	if (!params)
		return -ENOMEM;

	add_tunable_params(params, fa);

	ret = libnvmf_config_emit_add(emitter, true, fa->transport, fa->traddr,
			fa->trsvcid, fa->subsysnqn, fa->host_traddr,
			fa->host_iface, fa->hostnqn, fa->hostid, params, NULL);

	libnvmf_params_free(params);

	/*
	 * A rejected entry affects only that entry. Log the error and
	 * continue converting. Stop only if memory allocation fails.
	 */
	if (ret == -ENOMEM)
		return ret;
	if (ret)
		nvme_show_error(
			"discovery.conf: skipping a line that could not be added: %s",
			libnvme_strerror(-ret));

	return 0;
}

int nvme_config_convert_discovery(struct libnvmf_config_emitter *emitter,
		const char *disc_file)
{
	__cleanup_file FILE *f = NULL;
	static char line[4096];
	int ret;

	f = fopen(disc_file, "r");
	if (!f) {
		nvme_show_error("failed to open %s: %s", disc_file,
				 strerror(errno));
		return -errno;
	}

	while (fgets(line, sizeof(line), f)) {
		ret = nvmf_convert_discovery_line(emitter, line);
		if (ret)
			return ret;
	}

	return 0;
}

/* Best effort. The configuration has already been installed. */
static void rename_to_converted(const char *path)
{
	__cleanup_free char *dst = NULL;

	if (asprintf(&dst, "%s.converted", path) < 0)
		return;

	if (rename(path, dst))
		nvme_show_error(
			"converted %s but failed to rename it to %s: %s",
			path, dst, strerror(errno));
}

/* True if @path is gone because a prior run already renamed it away. */
static bool already_converted(const char *path)
{
	__cleanup_free char *converted = NULL;

	if (asprintf(&converted, "%s.converted", path) < 0)
		return false;

	return !access(converted, F_OK);
}

static int install_converted(struct libnvmf_config_emitter *emitter,
		const char *output_file, const char *json_path,
		const char *disc_path, bool converted_json,
		bool converted_disc, bool force)
{
	int ret;

	ret = libnvmf_config_emit_install(emitter, output_file, force);
	if (ret == -EEXIST) {
		nvme_show_error("%s already exists; refusing to overwrite",
				 output_file);
		return ret;
	}
	if (ret) {
		nvme_show_error("failed to write %s: %s", output_file,
				 libnvme_strerror(-ret));
		return ret;
	}

	if (converted_json)
		rename_to_converted(json_path);
	if (converted_disc)
		rename_to_converted(disc_path);

	return 0;
}

int nvme_config_convert_auto(struct libnvme_global_ctx *ctx,
		const char *config_file, char **ini_path)
{
	struct libnvmf_config_emitter *emitter;
	const char *json_path = config_file;
	const char *ext;
	bool is_default;
	bool have_json, have_disc;
	bool converted_json = false, converted_disc = false;
	int ret;

	*ini_path = NULL;

	is_default = !strcmp(config_file, PATH_NVMF_INI) ||
		     !strcmp(config_file, PATH_NVMF_CONFIG);
	if (is_default) {
		json_path = PATH_NVMF_CONFIG;
		*ini_path = strdup(PATH_NVMF_INI);
	} else {
		ext = strrchr(config_file, '.');
		if (!ext || strcmp(ext, ".json")) {
			*ini_path = strdup(config_file);
			return *ini_path ? 0 : -ENOMEM;
		}

		if (asprintf(ini_path, "%.*s.conf",
			     (int)(ext - config_file), config_file) < 0)
			return -ENOMEM;
	}
	if (!*ini_path)
		return -ENOMEM;

	if (!access(*ini_path, F_OK))
		return 0;

	have_json = !access(json_path, F_OK);
	have_disc = is_default && !access(PATH_NVMF_DISC, F_OK);
	if (!have_json && !have_disc) {
		/* Default path: nothing to convert is fine, proceed empty.
		 * Custom path: never existed and never converted is a
		 * real error, not silent-empty.
		 */
		if (!is_default && !already_converted(json_path)) {
			nvme_show_error("%s: no such file", json_path);
			return -ENOENT;
		}
		return 0;
	}

	emitter = libnvmf_config_emit_new(ctx);
	if (!emitter)
		return -ENOMEM;

	if (have_json) {
		ret = nvme_config_convert_json(emitter, json_path);
		if (ret)
			goto out;
		converted_json = true;
	}

	if (have_disc) {
		ret = nvme_config_convert_discovery(emitter, PATH_NVMF_DISC);
		if (ret)
			goto out;
		converted_disc = true;
	}

	ret = install_converted(emitter, *ini_path, json_path, PATH_NVMF_DISC,
				 converted_json, converted_disc, false);
	if (ret)
		goto out;

	nvme_show_error(
		"no %s found; converted legacy %s%s%s to it -- the original is renamed to *.converted, use %s from now on",
		*ini_path, converted_json ? json_path : "",
		(converted_json && converted_disc) ? " and " : "",
		converted_disc ? PATH_NVMF_DISC : "", *ini_path);

out:
	libnvmf_config_emit_free(emitter);

	return ret;
}

int nvme_config_convert(const char *desc, int argc, char **argv)
{
	char *config_file = NULL;
	char *output_file = NULL;
	const char *target;
	const char *json_path;
	bool verbose = false;
	bool force = false;
	bool converted_json = false, converted_disc = false;
	bool json_already_done = false, disc_already_done = false;
	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	struct libnvmf_config_emitter *emitter = NULL;
	int ret;

	OPT_ARGS(opts) = {
		OPT_STRING("config", 'J', "FILE", &config_file,
			   "convert this JSON file (default: config.json)"),
		OPT_STRING("output", 'o', "FILE", &output_file,
			   "write result here (default: nvme-fabrics.conf)"),
		OPT_FLAG("force", 0, &force,
			 "overwrite an existing target"),
		OPT_FLAG("verbose", 'v', &verbose, "increase output verbosity"),
		OPT_END()
	};

	ret = argconfig_parse(argc, argv, desc, opts);
	if (ret)
		return ret;

	nvme_show_init();

	log_level = map_log_level(verbose ? 1 : 0, false);

	ret = nvme_create_global_ctx(&ctx);
	if (ret) {
		nvme_show_error("Failed to create topology root: %s",
				 libnvme_strerror(-ret));
		return ret;
	}
	libnvme_set_logging_level(ctx, log_level, false, false);

	emitter = libnvmf_config_emit_new(ctx);
	if (!emitter)
		return -ENOMEM;

	json_path = config_file ? config_file : PATH_NVMF_CONFIG;
	if (!access(json_path, F_OK)) {
		ret = nvme_config_convert_json(emitter, json_path);
		if (ret)
			goto out;
		converted_json = true;
	} else if (already_converted(json_path)) {
		json_already_done = true;
	} else if (config_file) {
		/*
		 * An explicit --config to a file that neither exists nor was
		 * ever converted: let the JSON parser produce its own
		 * "failed to parse" error instead of silently no-op'ing,
		 * since this was an explicit ask.
		 */
		ret = nvme_config_convert_json(emitter, json_path);
		if (ret)
			goto out;
		converted_json = true;
	}

	if (!access(PATH_NVMF_DISC, F_OK)) {
		ret = nvme_config_convert_discovery(emitter, PATH_NVMF_DISC);
		if (ret)
			goto out;
		converted_disc = true;
	} else if (already_converted(PATH_NVMF_DISC)) {
		disc_already_done = true;
	}

	if (!converted_json && !converted_disc) {
		if (json_already_done || disc_already_done) {
			nvme_show_result("already converted; nothing to do");
			ret = 0;
			goto out;
		}
		nvme_show_error("nothing to convert: neither %s nor %s exists",
				 json_path, PATH_NVMF_DISC);
		ret = -ENOENT;
		goto out;
	}

	target = output_file ? output_file : PATH_NVMF_INI;
	ret = install_converted(emitter, target, json_path, PATH_NVMF_DISC,
				 converted_json, converted_disc, force);

out:
	libnvmf_config_emit_free(emitter);

	return ret;
}
