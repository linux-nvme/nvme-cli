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
#include <unistd.h>
#include <fcntl.h>

#include <json.h>

#include "cleanup.h"
#include "fabrics.h"
#include "log.h"
#include "private.h"
#include "linux.h"

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
		JSON_UPDATE_BOOL_OPTION(cfg, key_str,
					tls, val_obj);
		JSON_UPDATE_BOOL_OPTION(cfg, key_str,
					concat, val_obj);
		if (!strcmp("persistent", key_str) &&
		    !nvme_ctrl_is_persistent(c))
			nvme_ctrl_set_persistent(c, true);
		if (!strcmp("discovery", key_str) &&
		    !nvme_ctrl_is_discovery_ctrl(c))
			nvme_ctrl_set_discovery_ctrl(c, true);
		if (!strcmp("keyring", key_str))
			nvme_ctrl_set_keyring(c,
				json_object_get_string(val_obj));
		if (!strcmp("tls_key_identity", key_str)) {
			nvme_ctrl_set_tls_key_identity(c,
				json_object_get_string(val_obj));
		}
		if (!strcmp("tls_key", key_str)) {
			nvme_ctrl_set_tls_key(c,
				json_object_get_string(val_obj));
		}
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
			     host_iface, trsvcid, NULL);
	if (!c)
		return;
	json_update_attributes(c, port_obj);
	attr_obj = json_object_object_get(port_obj, "dhchap_key");
	if (attr_obj)
		nvme_ctrl_set_dhchap_host_key(c, json_object_get_string(attr_obj));
	attr_obj = json_object_object_get(port_obj, "dhchap_ctrl_key");
	if (attr_obj)
		nvme_ctrl_set_dhchap_key(c, json_object_get_string(attr_obj));
	attr_obj = json_object_object_get(port_obj, "keyring");
	if (attr_obj)
		nvme_ctrl_set_keyring(c, json_object_get_string(attr_obj));
	attr_obj = json_object_object_get(port_obj, "tls_key_identity");
	if (attr_obj) {
		nvme_ctrl_set_tls_key_identity(c,
			json_object_get_string(attr_obj));
	}
	attr_obj = json_object_object_get(port_obj, "tls_key");
	if (attr_obj) {
		nvme_ctrl_set_tls_key(c,
			json_object_get_string(attr_obj));
	}
}

static void json_parse_subsys(nvme_host_t h, struct json_object *subsys_obj)
{
	struct json_object *nqn_obj, *app_obj, *port_array;
	nvme_subsystem_t s;
	const char *nqn;
	int p;

	nqn_obj = json_object_object_get(subsys_obj, "nqn");
	if (!nqn_obj)
		return;
	nqn = json_object_get_string(nqn_obj);
	s = nvme_lookup_subsystem(h, NULL, nqn);
	if (!s)
		return;
	app_obj = json_object_object_get(subsys_obj, "application");
	if (app_obj)
		nvme_subsystem_set_application(s, json_object_get_string(app_obj));

	port_array = json_object_object_get(subsys_obj, "ports");
	if (!port_array)
		return;
	for (p = 0; p < json_object_array_length(port_array); p++) {
		struct json_object *port_obj;

		port_obj = json_object_array_get_idx(port_array, p);
		if (port_obj)
			json_parse_port(s, port_obj);
	}
}

static void json_parse_host(struct nvme_global_ctx *ctx, struct json_object *host_obj)
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
	h = nvme_lookup_host(ctx, hostnqn, hostid);
	attr_obj = json_object_object_get(host_obj, "dhchap_key");
	if (attr_obj)
		nvme_host_set_dhchap_key(h, json_object_get_string(attr_obj));
	attr_obj = json_object_object_get(host_obj, "hostsymname");
	if (attr_obj)
		nvme_host_set_hostsymname(h, json_object_get_string(attr_obj));
	attr_obj = json_object_object_get(host_obj, "persistent_discovery_ctrl");
	if (attr_obj)
		nvme_host_set_pdc_enabled(h, json_object_get_boolean(attr_obj));
	subsys_array = json_object_object_get(host_obj, "subsystems");
	if (!subsys_array)
		return;
	for (s = 0; s < json_object_array_length(subsys_array); s++) {
		subsys_obj = json_object_array_get_idx(subsys_array, s);
		if (subsys_obj)
			json_parse_subsys(h, subsys_obj);
	}
}

static DEFINE_CLEANUP_FUNC(cleanup_tokener, json_tokener *, json_tokener_free)
#define _cleanup_tokener_ __cleanup__(cleanup_tokener)

static struct json_object *parse_json(struct nvme_global_ctx *ctx, int fd)
{
	char buf[JSON_FILE_BUF_SIZE];
	struct json_object *obj;
	char *str = NULL;
	_cleanup_tokener_ json_tokener *tok = NULL;
	int ret;
	_cleanup_free_ void *ptr = NULL;
	int len = 0;

	while ((ret = read(fd, buf, JSON_FILE_BUF_SIZE)) > 0) {
		str = realloc(ptr, len + ret);
		if (!str)
			return NULL;
		memcpy(&str[len], buf, ret);
		len += ret;
		ptr = str;
	}

	if (ret < 0 || !len)
		return NULL;

	tok = json_tokener_new_ex(JSON_TOKENER_DEFAULT_DEPTH);
	if (!tok)
		return NULL;

	/* Enforce correctly formatted JSON */
	tok->flags = JSON_TOKENER_STRICT;

	obj = json_tokener_parse_ex(tok, str, len);
	if (!obj)
		nvme_msg(ctx, LOG_DEBUG, "JSON parsing failed: %s\n",
			 json_util_get_last_err());

	return obj;
}

int json_read_config(struct nvme_global_ctx *ctx, const char *config_file)
{
	struct json_object *json_root, *host_obj;
	int fd, h;

	fd = open(config_file, O_RDONLY);
	if (fd < 0) {
		nvme_msg(ctx, LOG_DEBUG, "Error opening %s, %s\n",
			 config_file, strerror(errno));
		return fd;
	}
	json_root = parse_json(ctx, fd);
	close(fd);
	if (!json_root) {
		errno = EPROTO;
		return -1;
	}
	if (!json_object_is_type(json_root, json_type_array)) {
		nvme_msg(ctx, LOG_DEBUG, "Wrong format, expected array\n");
		json_object_put(json_root);
		errno = EPROTO;
		return -1;
	}
	for (h = 0; h < json_object_array_length(json_root); h++) {
		host_obj = json_object_array_get_idx(json_root, h);
		if (host_obj)
			json_parse_host(ctx, host_obj);
	}
	json_object_put(json_root);
	return 0;
}

#define JSON_STRING_OPTION(c, p, o)					\
	if ((c)->o && strcmp((c)->o, "none"))				\
		json_object_object_add((p), # o ,			\
				       json_object_new_string((c)->o))
#define JSON_INT_OPTION(c, p, o, d)					\
	if ((c)->o != d)						\
		json_object_object_add((p), # o ,			\
				       json_object_new_int((c)->o))
#define JSON_BOOL_OPTION(c, p, o)					\
	if ((c)->o)							\
		json_object_object_add((p), # o ,			\
				       json_object_new_boolean((c)->o))

static void json_update_port(struct json_object *ctrl_array, nvme_ctrl_t c)
{
	struct nvme_fabrics_config *cfg = nvme_ctrl_get_config(c);
	struct json_object *port_obj = json_object_new_object();
	const char *transport, *value;

	transport = nvme_ctrl_get_transport(c);
	if (!strcmp(transport, "pcie")) {
		json_object_put(port_obj);
		return;
	}

	json_object_object_add(port_obj, "transport",
			       json_object_new_string(transport));
	value = nvme_ctrl_get_traddr(c);
	if (value)
		json_object_object_add(port_obj, "traddr",
				       json_object_new_string(value));
	value = nvme_ctrl_get_host_traddr(c);
	if (value)
		json_object_object_add(port_obj, "host_traddr",
				       json_object_new_string(value));
	value = nvme_ctrl_get_host_iface(c);
	if (value)
		json_object_object_add(port_obj, "host_iface",
				       json_object_new_string(value));
	value = nvme_ctrl_get_trsvcid(c);
	if (value)
		json_object_object_add(port_obj, "trsvcid",
				       json_object_new_string(value));
	value = nvme_ctrl_get_dhchap_host_key(c);
	if (value)
		json_object_object_add(port_obj, "dhchap_key",
				       json_object_new_string(value));
	value = nvme_ctrl_get_dhchap_key(c);
	if (value)
		json_object_object_add(port_obj, "dhchap_ctrl_key",
				       json_object_new_string(value));
	JSON_BOOL_OPTION(cfg, port_obj, tls);
	value = nvme_ctrl_get_keyring(c);
	if (value)
		json_object_object_add(port_obj, "keyring",
				       json_object_new_string(value));
	value = nvme_ctrl_get_tls_key_identity(c);
	if (value)
		json_object_object_add(port_obj, "tls_key_identity",
				       json_object_new_string(value));
	value = nvme_ctrl_get_tls_key(c);
	if (value)
		json_object_object_add(port_obj, "tls_key",
				       json_object_new_string(value));
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
	JSON_BOOL_OPTION(cfg, port_obj, concat);
	if (nvme_ctrl_is_persistent(c))
		json_object_object_add(port_obj, "persistent",
				       json_object_new_boolean(true));
	if (nvme_ctrl_is_discovery_ctrl(c))
		json_object_object_add(port_obj, "discovery",
				       json_object_new_boolean(true));

	json_object_array_add(ctrl_array, port_obj);
}

static void json_update_subsys(struct json_object *subsys_array,
			       nvme_subsystem_t s)
{
	nvme_ctrl_t c;
	const char *subsysnqn = nvme_subsystem_get_nqn(s), *app;
	struct json_object *subsys_obj = json_object_new_object();
	struct json_object *port_array;

	/* Skip discovery subsystems as the nqn is not unique */
	if (!strcmp(subsysnqn, NVME_DISC_SUBSYS_NAME))
		return;

	json_object_object_add(subsys_obj, "nqn",
			       json_object_new_string(subsysnqn));
	app = nvme_subsystem_get_application(s);
	if (app)
		json_object_object_add(subsys_obj, "application",
				       json_object_new_string(app));
	port_array = json_object_new_array();
	nvme_subsystem_for_each_ctrl(s, c) {
		json_update_port(port_array, c);
	}
	if (json_object_array_length(port_array)) {
		json_object_object_add(subsys_obj, "ports", port_array);
		json_object_array_add(subsys_array, subsys_obj);
	} else {
		json_object_put(port_array);
		json_object_put(subsys_obj);
	}
}

int json_update_config(struct nvme_global_ctx *ctx, const char *config_file)
{
	nvme_host_t h;
	struct json_object *json_root, *host_obj;
	struct json_object *subsys_array;
	int ret = 0;

	json_root = json_object_new_array();
	nvme_for_each_host(ctx, h) {
		nvme_subsystem_t s;
		const char *hostnqn, *hostid, *dhchap_key, *hostsymname;

		host_obj = json_object_new_object();
		if (!host_obj)
			continue;
		hostnqn = nvme_host_get_hostnqn(h);
		json_object_object_add(host_obj, "hostnqn",
				       json_object_new_string(hostnqn));
		hostid = nvme_host_get_hostid(h);
		if (hostid)
			json_object_object_add(host_obj, "hostid",
					       json_object_new_string(hostid));
		dhchap_key = nvme_host_get_dhchap_key(h);
		if (dhchap_key)
			json_object_object_add(host_obj, "dhchap_key",
					       json_object_new_string(dhchap_key));
		hostsymname = nvme_host_get_hostsymname(h);
		if (hostsymname)
			json_object_object_add(host_obj, "hostsymname",
					       json_object_new_string(hostsymname));
		if (h->pdc_enabled_valid)
			json_object_object_add(host_obj, "persistent_discovery_ctrl",
					       json_object_new_boolean(h->pdc_enabled));
		subsys_array = json_object_new_array();
		nvme_for_each_subsystem(h, s) {
			json_update_subsys(subsys_array, s);
		}
		if (json_object_array_length(subsys_array)) {
			json_object_object_add(host_obj, "subsystems",
					       subsys_array);
			json_object_array_add(json_root, host_obj);
		} else {
			json_object_put(subsys_array);
			json_object_put(host_obj);
		}
	}
	if (!config_file) {
		ret = json_object_to_fd(1, json_root,
					JSON_C_TO_STRING_PRETTY |
					JSON_C_TO_STRING_NOSLASHESCAPE);
		printf("\n");
	} else
		ret = json_object_to_file_ext(config_file, json_root,
					      JSON_C_TO_STRING_PRETTY |
					      JSON_C_TO_STRING_NOSLASHESCAPE);
	if (ret < 0) {
		nvme_msg(ctx, LOG_ERR, "Failed to write to %s, %s\n",
			 config_file ? "stdout" : config_file,
			 json_util_get_last_err());
		ret = -1;
		errno = EIO;
	}
	json_object_put(json_root);

	return ret;
}

static void json_dump_ctrl(struct json_object *ctrl_array, nvme_ctrl_t c)
{
	struct nvme_fabrics_config *cfg = nvme_ctrl_get_config(c);
	struct json_object *ctrl_obj = json_object_new_object();
	const char *name, *transport, *value;

	name = nvme_ctrl_get_name(c);
	if (name && strlen(name))
		json_object_object_add(ctrl_obj, "name",
				       json_object_new_string(name));
	transport = nvme_ctrl_get_transport(c);
	json_object_object_add(ctrl_obj, "transport",
			       json_object_new_string(transport));
	value = nvme_ctrl_get_traddr(c);
	if (value)
		json_object_object_add(ctrl_obj, "traddr",
				       json_object_new_string(value));
	value = nvme_ctrl_get_host_traddr(c);
	if (value)
		json_object_object_add(ctrl_obj, "host_traddr",
				       json_object_new_string(value));
	value = nvme_ctrl_get_host_iface(c);
	if (value)
		json_object_object_add(ctrl_obj, "host_iface",
				       json_object_new_string(value));
	value = nvme_ctrl_get_trsvcid(c);
	if (value)
		json_object_object_add(ctrl_obj, "trsvcid",
				       json_object_new_string(value));
	value = nvme_ctrl_get_dhchap_host_key(c);
	if (value)
		json_object_object_add(ctrl_obj, "dhchap_key",
				       json_object_new_string(value));
	value = nvme_ctrl_get_dhchap_key(c);
	if (value)
		json_object_object_add(ctrl_obj, "dhchap_ctrl_key",
				       json_object_new_string(value));
	JSON_INT_OPTION(cfg, ctrl_obj, nr_io_queues, 0);
	JSON_INT_OPTION(cfg, ctrl_obj, nr_write_queues, 0);
	JSON_INT_OPTION(cfg, ctrl_obj, nr_poll_queues, 0);
	JSON_INT_OPTION(cfg, ctrl_obj, queue_size, 0);
	JSON_INT_OPTION(cfg, ctrl_obj, keep_alive_tmo, 0);
	JSON_INT_OPTION(cfg, ctrl_obj, reconnect_delay, 0);
	if (strcmp(transport, "loop")) {
		JSON_INT_OPTION(cfg, ctrl_obj, ctrl_loss_tmo,
				NVMF_DEF_CTRL_LOSS_TMO);
		JSON_INT_OPTION(cfg, ctrl_obj, fast_io_fail_tmo, 0);
	}
	JSON_INT_OPTION(cfg, ctrl_obj, tos, -1);
	JSON_BOOL_OPTION(cfg, ctrl_obj, duplicate_connect);
	JSON_BOOL_OPTION(cfg, ctrl_obj, disable_sqflow);
	JSON_BOOL_OPTION(cfg, ctrl_obj, hdr_digest);
	JSON_BOOL_OPTION(cfg, ctrl_obj, data_digest);
	if (!strcmp(transport, "tcp")) {
		JSON_BOOL_OPTION(cfg, ctrl_obj, tls);

		value = nvme_ctrl_get_keyring(c);
		if (value)
			json_object_object_add(ctrl_obj, "keyring",
					       json_object_new_string(value));
		value = nvme_ctrl_get_tls_key_identity(c);
		if (value)
			json_object_object_add(ctrl_obj, "tls_key_identity",
					       json_object_new_string(value));
		value = nvme_ctrl_get_tls_key(c);
		if (value)
			json_object_object_add(ctrl_obj, "tls_key",
					       json_object_new_string(value));
	}
	JSON_BOOL_OPTION(cfg, ctrl_obj, concat);
	if (nvme_ctrl_is_persistent(c))
		json_object_object_add(ctrl_obj, "persistent",
				       json_object_new_boolean(true));
	if (nvme_ctrl_is_discovery_ctrl(c))
		json_object_object_add(ctrl_obj, "discovery",
				       json_object_new_boolean(true));
	json_object_array_add(ctrl_array, ctrl_obj);
}

static unsigned int json_dump_subsys_multipath(nvme_subsystem_t s,
				struct json_object *ns_array)
{
	nvme_ns_t n;
	nvme_path_t p;
	unsigned int i = 0;

	nvme_subsystem_for_each_ns(s, n) {
		struct json_object *ns_obj;
		struct json_object *path_array;

		ns_obj = json_object_new_object();
		json_object_object_add(ns_obj, "nsid",
				json_object_new_int(nvme_ns_get_nsid(n)));
		json_object_object_add(ns_obj, "name",
				json_object_new_string(nvme_ns_get_name(n)));

		path_array = json_object_new_array();
		nvme_namespace_for_each_path(n, p) {
			struct json_object *path_obj;
			struct json_object *ctrl_array;
			nvme_ctrl_t c;

			path_obj = json_object_new_object();
			json_object_object_add(path_obj, "path",
				json_object_new_string(nvme_path_get_name(p)));
			json_object_object_add(path_obj, "ANAState",
				json_object_new_string(nvme_path_get_ana_state(p)));
			json_object_object_add(path_obj, "NUMANodes",
				json_object_new_string(nvme_path_get_numa_nodes(p)));
			json_object_object_add(path_obj, "qdepth",
				json_object_new_int(nvme_path_get_queue_depth(p)));

			c = nvme_path_get_ctrl(p);
			ctrl_array = json_object_new_array();
			json_dump_ctrl(ctrl_array, c);
			json_object_object_add(path_obj, "controller", ctrl_array);
			json_object_array_add(path_array, path_obj);
		}
		json_object_object_add(ns_obj, "paths", path_array);
		json_object_array_add(ns_array, ns_obj);
		i++;
	}
	return i;
}

static void json_dump_subsys_non_multipath(nvme_subsystem_t s,
		struct json_object *ns_array)
{
	nvme_ctrl_t c;
	nvme_ns_t n;

	nvme_subsystem_for_each_ctrl(s, c) {
		nvme_ctrl_for_each_ns(c, n) {
			struct json_object *ctrl_array;
			struct json_object *ns_obj;

			ns_obj = json_object_new_object();
			json_object_object_add(ns_obj, "nsid",
				json_object_new_int(nvme_ns_get_nsid(n)));
			json_object_object_add(ns_obj, "name",
				json_object_new_string(nvme_ns_get_name(n)));

			ctrl_array = json_object_new_array();
			json_dump_ctrl(ctrl_array, c);
			json_object_object_add(ns_obj, "controller", ctrl_array);

			json_object_array_add(ns_array, ns_obj);
		}
	}
}

static void json_dump_subsys(struct json_object *subsys_array,
			       nvme_subsystem_t s)
{
	struct json_object *subsys_obj = json_object_new_object();
	struct json_object *ns_array;

	json_object_object_add(subsys_obj, "name",
			       json_object_new_string(nvme_subsystem_get_name(s)));
	json_object_object_add(subsys_obj, "nqn",
			       json_object_new_string(nvme_subsystem_get_nqn(s)));

	ns_array = json_object_new_array();
	if (!json_dump_subsys_multipath(s, ns_array))
		json_dump_subsys_non_multipath(s, ns_array);

	if (json_object_array_length(ns_array))
		json_object_object_add(subsys_obj, "namespaces", ns_array);
	else
		json_object_put(ns_array);
	json_object_array_add(subsys_array, subsys_obj);
}

int json_dump_tree(struct nvme_global_ctx *ctx)
{
	nvme_host_t h;
	struct json_object *json_root, *host_obj;
	struct json_object *host_array, *subsys_array;
	int ret = 0;

	json_root = json_object_new_object();
	host_array = json_object_new_array();
	nvme_for_each_host(ctx, h) {
		nvme_subsystem_t s;
		const char *hostid, *dhchap_key;

		host_obj = json_object_new_object();
		json_object_object_add(host_obj, "hostnqn",
				       json_object_new_string(nvme_host_get_hostnqn(h)));
		hostid = nvme_host_get_hostid(h);
		if (hostid)
			json_object_object_add(host_obj, "hostid",
					       json_object_new_string(hostid));
		dhchap_key = nvme_host_get_dhchap_key(h);
		if (dhchap_key)
			json_object_object_add(host_obj, "dhchap_key",
					       json_object_new_string(dhchap_key));
		if (h->pdc_enabled_valid)
			json_object_object_add(host_obj, "persistent_discovery_ctrl",
					       json_object_new_boolean(h->pdc_enabled));
		subsys_array = json_object_new_array();
		nvme_for_each_subsystem(h, s) {
			json_dump_subsys(subsys_array, s);
		}
		if (json_object_array_length(subsys_array))
			json_object_object_add(host_obj, "subsystems",
					       subsys_array);
		else
			json_object_put(subsys_array);
		json_object_array_add(host_array, host_obj);
	}
	json_object_object_add(json_root, "hosts", host_array);

	ret = json_object_to_fd(ctx->log.fd, json_root,
				JSON_C_TO_STRING_PRETTY |
				JSON_C_TO_STRING_NOSLASHESCAPE);
	if (ret < 0) {
		nvme_msg(ctx, LOG_ERR, "Failed to write, %s\n",
			 json_util_get_last_err());
		ret = -1;
		errno = EIO;
	}
	json_object_put(json_root);

	return ret;
}
