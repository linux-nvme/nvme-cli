// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2026, Dell Technologies Inc. or its subsidiaries.
 *
 * Authors: Martin Belanger <Martin.Belanger@dell.com>
 */

#include <errno.h>
#include <string.h>

#include <libnvme.h>

#include "common.h"
#include "config-convert.h"
#include "nvme-print.h"

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
