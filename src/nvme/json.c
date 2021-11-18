// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libnvme.
 * Copyright (c) 2021 SUSE Software Solutions
 *
 * Authors: Hannes Reinecke <hare@suse.de>
 */

#include <stdio.h>
#include <errno.h>
#include <string.h>

#include <json.h>

#include "fabrics.h"
#include "log.h"

#define json_object_add_value_string(o, k, v)			\
	json_object_object_add(o, k, json_object_new_string(v))
#define json_object_add_value_int(o, k, v) \
	json_object_object_add(o, k, json_object_new_int(v))
#define json_object_add_value_bool(o, k, v) \
	json_object_object_add(o, k, json_object_new_boolean(v))
#define json_object_add_value_string(o, k, v) \
	json_object_object_add(o, k, json_object_new_string(v))

#define JSON_UPDATE_INT_OPTION(c, k, a, o)				\
	if (!strcmp(# a, k ) && !c->a) c->a = json_object_get_int(o);
#define JSON_UPDATE_BOOL_OPTION(c, k, a, o)				\
	if (!strcmp(# a, k ) && !c->a) c->a = json_object_get_boolean(o);

static void json_update_attributes(nvme_ctrl_t c,
				   struct json_object *ctrl_obj)
{
	struct nvme_fabrics_config *cfg = nvme_ctrl_get_config(c);

	json_object_object_foreach(ctrl_obj, key_str, val_obj) {
		JSON_UPDATE_INT_OPTION(cfg, key_str,
				       nr_io_queues, val_obj);
		JSON_UPDATE_INT_OPTION(cfg, key_str,
				       nr_write_queues, val_obj);
		JSON_UPDATE_INT_OPTION(cfg, key_str,
				       nr_poll_queues, val_obj);
		JSON_UPDATE_INT_OPTION(cfg, key_str,
				       queue_size, val_obj);
		JSON_UPDATE_INT_OPTION(cfg, key_str,
				       keep_alive_tmo, val_obj);
		JSON_UPDATE_INT_OPTION(cfg, key_str,
				       reconnect_delay, val_obj);
		if (!strcmp("ctrl_loss_tmo", key_str) &&
		    cfg->ctrl_loss_tmo != NVMF_DEF_CTRL_LOSS_TMO)
			cfg->ctrl_loss_tmo = json_object_get_int(val_obj);
		JSON_UPDATE_INT_OPTION(cfg, key_str,
				       fast_io_fail_tmo, val_obj);
		if (!strcmp("tos", key_str) && cfg->tos != -1)
			cfg->tos = json_object_get_int(val_obj);
		JSON_UPDATE_BOOL_OPTION(cfg, key_str,
					duplicate_connect, val_obj);
		JSON_UPDATE_BOOL_OPTION(cfg, key_str,
					disable_sqflow, val_obj);
		JSON_UPDATE_BOOL_OPTION(cfg, key_str,
					hdr_digest, val_obj);
		JSON_UPDATE_BOOL_OPTION(cfg, key_str,
					data_digest, val_obj);
		if (!strcmp("persistent", key_str) &&
		    !nvme_ctrl_is_persistent(c))
			nvme_ctrl_set_persistent(c, true);
		if (!strcmp("discovery", key_str) &&
		    !nvme_ctrl_is_discovery_ctrl(c))
			nvme_ctrl_set_discovery_ctrl(c, true);
	}
}

static void json_parse_port(nvme_subsystem_t s, struct json_object *port_obj)
{
	nvme_ctrl_t c;
	struct json_object *attr_obj;
	const char *transport, *traddr = NULL;
	const char *host_traddr = NULL, *host_iface = NULL, *trsvcid = NULL;

	attr_obj = json_object_object_get(port_obj, "transport");
	if (!attr_obj)
		return;
	transport = json_object_get_string(attr_obj);
	attr_obj = json_object_object_get(port_obj, "traddr");
	if (attr_obj)
		traddr = json_object_get_string(attr_obj);
	attr_obj = json_object_object_get(port_obj, "host_traddr");
	if (attr_obj)
		host_traddr = json_object_get_string(attr_obj);
	attr_obj = json_object_object_get(port_obj, "host_iface");
	if (attr_obj)
		host_iface = json_object_get_string(attr_obj);
	attr_obj = json_object_object_get(port_obj, "trsvcid");
	if (attr_obj)
		trsvcid = json_object_get_string(attr_obj);
	c = nvme_lookup_ctrl(s, transport, traddr, host_traddr,
			     host_iface, trsvcid);
	if (c) {
		attr_obj = json_object_object_get(port_obj, "dhchap_key");
		if (attr_obj)
			nvme_ctrl_set_dhchap_key(c, json_object_get_string(attr_obj));
		json_update_attributes(c, port_obj);
	}
}

static void json_parse_subsys(nvme_host_t h, struct json_object *subsys_obj)
{
	struct json_object *nqn_obj, *port_array;
	nvme_subsystem_t s;
	const char *nqn;
	int p;

	nqn_obj = json_object_object_get(subsys_obj, "nqn");
	if (!nqn_obj)
		return;
	nqn = json_object_get_string(nqn_obj);
	s = nvme_lookup_subsystem(h, NULL, nqn);
	port_array = json_object_object_get(subsys_obj, "ports");
	if (!port_array)
		return;
	for (p = 0; p < json_object_array_length(port_array); p++) {
		struct json_object *port_obj;

		port_obj = json_object_array_get_idx(port_array, p);
		json_parse_port(s, port_obj);
	}
}

static void json_parse_host(nvme_root_t r, struct json_object *host_obj)
{
	struct json_object *attr_obj, *subsys_array, *subsys_obj;
	nvme_host_t h;
	const char *hostnqn, *hostid = NULL;
	int s;

	attr_obj = json_object_object_get(host_obj, "hostnqn");
	if (!attr_obj)
		return;
	hostnqn = json_object_get_string(attr_obj);
	attr_obj = json_object_object_get(host_obj, "hostid");
	if (attr_obj)
		hostid = json_object_get_string(attr_obj);
	h = nvme_lookup_host(r, hostnqn, hostid);
	attr_obj = json_object_object_get(host_obj, "dhchap_key");
	if (attr_obj)
		nvme_host_set_dhchap_key(h, json_object_get_string(attr_obj));
	subsys_array = json_object_object_get(host_obj, "subsystems");
	if (!subsys_array)
		return;
	for (s = 0; s < json_object_array_length(subsys_array); s++) {
		subsys_obj = json_object_array_get_idx(subsys_array, s);
		json_parse_subsys(h, subsys_obj);
	}
}

void json_read_config(nvme_root_t r, const char *config_file)
{
	struct json_object *json_root, *host_obj;
	int h;

	json_root = json_object_from_file(config_file);
	if (!json_root) {
		nvme_msg(LOG_DEBUG, "Failed to read %s, %s\n",
			config_file, json_util_get_last_err());
		return;
	}
	for (h = 0; h < json_object_array_length(json_root); h++) {
		host_obj = json_object_array_get_idx(json_root, h);
		json_parse_host(r, host_obj);
	}
	json_object_put(json_root);
}

#define JSON_STRING_OPTION(c, p, o)				\
	if ((c)->o && strcmp((c)->o, "none"))			\
		json_object_add_value_string((p), # o , (c)->o)
#define JSON_INT_OPTION(c, p, o, d)					\
	if ((c)->o != d) json_object_add_value_int((p), # o , (c)->o)
#define JSON_BOOL_OPTION(c, p, o)					\
	if ((c)->o) json_object_add_value_bool((p), # o , (c)->o)

static void json_update_port(struct json_object *ctrl_array, nvme_ctrl_t c)
{
	struct nvme_fabrics_config *cfg = nvme_ctrl_get_config(c);
	struct json_object *port_obj = json_object_new_object();
	const char *transport, *value;

	transport = nvme_ctrl_get_transport(c);
	json_object_add_value_string(port_obj, "transport", transport);
	value = nvme_ctrl_get_traddr(c);
	if (value)
		json_object_add_value_string(port_obj, "traddr", value);
	value = nvme_ctrl_get_host_traddr(c);
	if (value)
		json_object_add_value_string(port_obj, "host_traddr", value);
	value = nvme_ctrl_get_host_iface(c);
	if (value)
		json_object_add_value_string(port_obj, "host_iface", value);
	value = nvme_ctrl_get_trsvcid(c);
	if (value)
		json_object_add_value_string(port_obj, "trsvcid", value);
	value = nvme_ctrl_get_dhchap_key(c);
	if (value)
		json_object_add_value_string(port_obj, "dhchap_key",
					     value);
	JSON_INT_OPTION(cfg, port_obj, nr_io_queues, 0);
	JSON_INT_OPTION(cfg, port_obj, nr_write_queues, 0);
	JSON_INT_OPTION(cfg, port_obj, nr_poll_queues, 0);
	JSON_INT_OPTION(cfg, port_obj, queue_size, 0);
	JSON_INT_OPTION(cfg, port_obj, keep_alive_tmo, 0);
	JSON_INT_OPTION(cfg, port_obj, reconnect_delay, 0);
	if (strcmp(transport, "loop")) {
		JSON_INT_OPTION(cfg, port_obj, ctrl_loss_tmo,
				NVMF_DEF_CTRL_LOSS_TMO);
		JSON_INT_OPTION(cfg, port_obj, fast_io_fail_tmo, 0);
	}
	JSON_INT_OPTION(cfg, port_obj, tos, -1);
	JSON_BOOL_OPTION(cfg, port_obj, duplicate_connect);
	JSON_BOOL_OPTION(cfg, port_obj, disable_sqflow);
	JSON_BOOL_OPTION(cfg, port_obj, hdr_digest);
	JSON_BOOL_OPTION(cfg, port_obj, data_digest);
	if (nvme_ctrl_is_persistent(c))
		json_object_add_value_bool(port_obj, "persistent", true);
	if (nvme_ctrl_is_discovery_ctrl(c))
		json_object_add_value_bool(port_obj, "discovery", true);
	json_object_array_add(ctrl_array, port_obj);
}

static void json_update_subsys(struct json_object *subsys_array,
			       nvme_subsystem_t s)
{
	nvme_ctrl_t c;
	const char *subsysnqn = nvme_subsystem_get_nqn(s);
	struct json_object *subsys_obj = json_object_new_object();
	struct json_object *port_array;

	/* Skip discovery subsystems as the nqn is not unique */
	if (!strcmp(subsysnqn, NVME_DISC_SUBSYS_NAME))
		return;

	json_object_add_value_string(subsys_obj, "nqn",
				     nvme_subsystem_get_nqn(s));
	port_array = json_object_new_array();
	nvme_subsystem_for_each_ctrl(s, c) {
		json_update_port(port_array, c);
	}
	if (json_object_array_length(port_array))
		json_object_object_add(subsys_obj, "ports", port_array);
	else
		json_object_put(port_array);
	json_object_array_add(subsys_array, subsys_obj);
}

int json_update_config(nvme_root_t r, const char *config_file)
{
	nvme_host_t h;
	struct json_object *json_root, *host_obj;
	struct json_object *subsys_array;
	int ret = 0;

	json_root = json_object_new_array();
	nvme_for_each_host(r, h) {
		nvme_subsystem_t s;
		const char *hostid, *dhchap_key;

		host_obj = json_object_new_object();
		json_object_add_value_string(host_obj, "hostnqn",
					     nvme_host_get_hostnqn(h));
		hostid = nvme_host_get_hostid(h);
		if (hostid)
			json_object_add_value_string(host_obj, "hostid",
						     hostid);
		dhchap_key = nvme_host_get_dhchap_key(h);
		if (dhchap_key)
			json_object_add_value_string(host_obj, "dhchap_key",
						     dhchap_key);
		subsys_array = json_object_new_array();
		nvme_for_each_subsystem(h, s) {
			json_update_subsys(subsys_array, s);
		}
		if (json_object_array_length(subsys_array))
			json_object_object_add(host_obj, "subsystems",
						    subsys_array);
		else
			json_object_put(subsys_array);
		json_object_array_add(json_root, host_obj);
	}
	if (!config_file)
		ret = json_object_to_fd(1, json_root, JSON_C_TO_STRING_PRETTY);
	else
		ret = json_object_to_file_ext(config_file, json_root,
					      JSON_C_TO_STRING_PRETTY);
	if (ret < 0) {
		nvme_msg(LOG_ERR, "Failed to write to %s, %s\n",
			 config_file ? "stdout" : config_file,
			 json_util_get_last_err());
		ret = -1;
		errno = EIO;
	}
	json_object_put(json_root);

	return ret;
}
