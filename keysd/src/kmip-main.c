// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 Dell Technologies Inc. or its subsidiaries.
 *
 * Authors: Martin Belanger <martin.belanger@dell.com>
 */

/*
 * nvme-keysd-kmip: gets a PSK from a KMIP server for nvme-keysd. systemd
 * starts one instance per connection to the Varlink socket.
 */

#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>

#include <systemd/sd-daemon.h>
#include <systemd/sd-json.h>
#include <systemd/sd-varlink.h>
#include <systemd/sd-varlink-idl.h>

#include <daemon-util/log.h>
#include <daemon-util/resolve.h>
#include <nvme/lib.h>

#include "config.h"
#include "kmip-psk.h"
#include "kmip-varlink.h"

/* KMIP Name values are short. Refuse anything that cannot be one. */
#define KEY_NAME_MAX 256

// Enough to try every server of a KMS while one name lookup hangs.
#define RESOLVE_WORKERS 8

static SD_VARLINK_DEFINE_METHOD(
	GetKey,
	SD_VARLINK_FIELD_COMMENT("Name of a [kmip:<name>] section"),
	SD_VARLINK_DEFINE_INPUT(kms, SD_VARLINK_STRING, 0),
	SD_VARLINK_FIELD_COMMENT("KMIP Name of the key"),
	SD_VARLINK_DEFINE_INPUT(name, SD_VARLINK_STRING, 0),
	SD_VARLINK_FIELD_COMMENT("Index of the server to try first"),
	SD_VARLINK_DEFINE_INPUT(server, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
	SD_VARLINK_FIELD_COMMENT("The PSK in the PSK interchange format"),
	SD_VARLINK_DEFINE_OUTPUT(key, SD_VARLINK_STRING, 0),
	SD_VARLINK_FIELD_COMMENT("Index of the server that answered"),
	SD_VARLINK_DEFINE_OUTPUT(server, SD_VARLINK_INT, 0));

static SD_VARLINK_DEFINE_ERROR(NoSuchKms);
static SD_VARLINK_DEFINE_ERROR(NoSuchKey);
static SD_VARLINK_DEFINE_ERROR(KeyNotUnique);
static SD_VARLINK_DEFINE_ERROR(InvalidKey);
static SD_VARLINK_DEFINE_ERROR(KmsFailed);

static SD_VARLINK_DEFINE_INTERFACE(
	io_nvme_keysd_Kmip,
	KMIP_VARLINK_INTERFACE,
	SD_VARLINK_INTERFACE_COMMENT("Get TLS PSKs from a KMIP server"),
	SD_VARLINK_SYMBOL_COMMENT("Get the Active key with a name"),
	&vl_method_GetKey,
	SD_VARLINK_SYMBOL_COMMENT("The KMS is not configured"),
	&vl_error_NoSuchKms,
	SD_VARLINK_SYMBOL_COMMENT("No Active key has this name"),
	&vl_error_NoSuchKey,
	SD_VARLINK_SYMBOL_COMMENT("Several Active keys have this name"),
	&vl_error_KeyNotUnique,
	SD_VARLINK_SYMBOL_COMMENT("The key is not a valid PSK"),
	&vl_error_InvalidKey,
	SD_VARLINK_SYMBOL_COMMENT("No server of the KMS can answer"),
	&vl_error_KmsFailed);

struct helper_ctx {
	struct libnvme_global_ctx *nvme_ctx;	// PSK encoding
	struct keysd_config *cfg;
	struct dmn_resolver *resolver;
	// The call in progress. Varlink sends one call at a time.
	struct kmip_get *get;
	sd_varlink *link;
	const char *kms;
	char *name;
};

struct get_key_params {
	const char *kms;
	const char *name;
	uint64_t server;
};

/*
 * The client private key of @kms. systemd decrypts the files of
 * KEYSD_KMIP_CREDS_DIR into $CREDENTIALS_DIRECTORY, as "kmip_<file>".
 */
static int client_key_path(const struct keysd_kmip *kms, char **path)
{
	const char *dir;

	*path = NULL;
	if (!kms->client_key)
		return 0;

	dir = getenv("CREDENTIALS_DIRECTORY");
	if (!dir) {
		log_err("KMS '%s': no credentials directory", kms->name);
		return -ENOKEY;
	}
	if (asprintf(path, "%s/kmip_%s", dir, kms->client_key) < 0) {
		*path = NULL;
		return -ENOMEM;
	}

	return 0;
}

static int reply_key(sd_varlink *link, const char *psk, size_t server)
{
	sd_json_variant *v = NULL;
	int r;

	r = sd_json_buildo(&v, SD_JSON_BUILD_PAIR_STRING("key", psk),
			   SD_JSON_BUILD_PAIR_UNSIGNED("server", server));
	if (r < 0)
		return r;
	sd_json_variant_sensitive(v);

	r = sd_varlink_reply(link, v);
	sd_json_variant_unref(v);

	return r;
}

static const char *error_id(int err)
{
	switch (err) {
	case -ENOENT:
		return KMIP_VARLINK_NO_SUCH_KEY;
	case -ENOTUNIQ:
		return KMIP_VARLINK_KEY_NOT_UNIQUE;
	case -EMEDIUMTYPE:
		return KMIP_VARLINK_INVALID_KEY;
	default:
		return KMIP_VARLINK_KMS_FAILED;
	}
}

static void end_call(struct helper_ctx *hc)
{
	hc->get = NULL;
	hc->link = sd_varlink_unref(hc->link);
	free(hc->name);
	hc->name = NULL;
}

static void on_psk(int ret, const char *psk, size_t server, void *user_data)
{
	struct helper_ctx *hc = user_data;
	const struct keysd_kmip *kms = config_find_kmip(hc->cfg, hc->kms);
	int r;

	if (ret) {
		log_err("KMS '%s': key '%s': %s", hc->kms, hc->name,
			strerror(-ret));
		r = sd_varlink_error(hc->link, error_id(ret), NULL);
	} else {
		log_info("KMS '%s': key '%s' sent, from %s", hc->kms,
			 hc->name, kms->servers[server]);
		r = reply_key(hc->link, psk, server);
	}
	if (r < 0)
		log_err("KMS '%s': key '%s': reply: %s", hc->kms, hc->name,
			strerror(-r));
	end_call(hc);
}

static int method_get_key(sd_varlink *link, sd_json_variant *params,
		sd_varlink_method_flags_t flags, void *userdata)
{
	static const sd_json_dispatch_field table[] = {
		{ "kms", SD_JSON_VARIANT_STRING, sd_json_dispatch_const_string,
		  offsetof(struct get_key_params, kms), SD_JSON_MANDATORY },
		{ "name", SD_JSON_VARIANT_STRING, sd_json_dispatch_const_string,
		  offsetof(struct get_key_params, name), SD_JSON_MANDATORY },
		{ "server", SD_JSON_VARIANT_UNSIGNED, sd_json_dispatch_uint64,
		  offsetof(struct get_key_params, server), 0 },
		{}
	};
	struct helper_ctx *hc = userdata;
	struct get_key_params p = {};
	const struct keysd_kmip *kms;
	char *key_path;
	int r;

	r = sd_varlink_dispatch(link, params, table, &p);
	if (r)
		return r;

	if (!p.name[0] || strlen(p.name) >= KEY_NAME_MAX)
		return sd_varlink_error_invalid_parameter_name(link, "name");

	kms = config_find_kmip(hc->cfg, p.kms);
	if (!kms) {
		log_err("KMS '%s' is not configured", p.kms);
		return sd_varlink_error(link, KMIP_VARLINK_NO_SUCH_KMS, NULL);
	}

	hc->name = strdup(p.name);
	if (!hc->name)
		return -ENOMEM;
	hc->kms = kms->name;
	hc->link = sd_varlink_ref(link);

	// The reply is sent from on_psk().
	r = client_key_path(kms, &key_path);
	if (!r)
		r = kmip_get_psk(hc->resolver, hc->nvme_ctx, kms, p.server,
				 key_path, p.name, on_psk, hc, &hc->get);
	free(key_path);
	if (r) {
		log_err("KMS '%s': key '%s': %s", kms->name, p.name,
			strerror(-r));
		r = sd_varlink_error(link, error_id(r), NULL);
		end_call(hc);
	}

	return r;
}

static int run_server(struct helper_ctx *hc)
{
	sd_varlink_server *s = NULL;
	sd_event *event = NULL;
	int r;

	r = sd_event_new(&event);
	if (r < 0)
		return r;

	r = dmn_resolver_new(event, RESOLVE_WORKERS, &hc->resolver);
	if (r < 0)
		goto out;

	// Root (nvme-keysd) or our own user (a test).
	r = sd_varlink_server_new(&s, SD_VARLINK_SERVER_ROOT_ONLY |
				  SD_VARLINK_SERVER_MYSELF_ONLY |
				  SD_VARLINK_SERVER_INHERIT_USERDATA |
				  SD_VARLINK_SERVER_INPUT_SENSITIVE);
	if (r < 0)
		goto out;
	sd_varlink_server_set_userdata(s, hc);

	r = sd_varlink_server_add_interface(s,
					    &vl_interface_io_nvme_keysd_Kmip);
	if (r >= 0)
		r = sd_varlink_server_bind_method(s, KMIP_VARLINK_GET_KEY,
						  method_get_key);
	// Exit when nvme-keysd closes the connection.
	if (r >= 0)
		r = sd_varlink_server_set_exit_on_idle(s, true);
	if (r >= 0)
		r = sd_varlink_server_attach_event(s, event, 0);
	if (r >= 0)
		r = sd_varlink_server_listen_auto(s);
	if (r >= 0)
		r = sd_event_loop(event);

	kmip_get_cancel(hc->get);
	end_call(hc);

out:
	sd_varlink_server_unref(s);
	dmn_resolver_free(hc->resolver);
	sd_event_unref(event);

	return r;
}

static void usage(const char *prog)
{
	printf("Usage: %s [OPTIONS]\n"
	       "\n"
	       "Started by systemd through nvme-keysd-kmip.socket.\n"
	       "\n"
	       "  --config FILE, -c FILE  nvme-keysd configuration file\n"
	       "                          (default: " KEYSD_CONF_PATH ")\n"
	       "  --debug, -d             enable debug logging\n"
	       "  --help, -h              show this help and exit\n",
	       prog);
}

int main(int argc, char **argv)
{
	static const struct option long_opts[] = {
		{ "config", required_argument, NULL, 'c' },
		{ "debug",  no_argument,       NULL, 'd' },
		{ "help",   no_argument,       NULL, 'h' },
		{ NULL, 0,  NULL, 0 },
	};
	struct helper_ctx hc = {};
	const char *conf_path = KEYSD_CONF_PATH;
	bool debug = false;
	int r, c;

	while ((c = getopt_long(argc, argv, "c:dh", long_opts, NULL)) != -1) {
		switch (c) {
		case 'c':
			conf_path = optarg;
			break;
		case 'd':
			debug = true;
			break;
		case 'h':
			usage(argv[0]);
			return 0;
		default:
			fprintf(stderr, "Try '%s --help'.\n", argv[0]);
			return 1;
		}
	}

	if (sd_listen_fds(0) <= 0) {
		fprintf(stderr, "%s: must be started by socket activation\n",
			argv[0]);
		return 1;
	}

	// Key material must never end up in a core dump.
	if (prctl(PR_SET_DUMPABLE, 0) < 0) {
		fprintf(stderr, "prctl(PR_SET_DUMPABLE): %s\n",
			strerror(errno));
		return 1;
	}
	// A write to a closed TLS connection must fail, not kill us.
	signal(SIGPIPE, SIG_IGN);

	hc.cfg = config_load(conf_path);
	hc.nvme_ctx = libnvme_create_global_ctx();
	if (!hc.cfg || !hc.nvme_ctx) {
		log_err("out of memory");
		r = -ENOMEM;
		goto out;
	}
	dmn_log_set_level(debug ? DMN_LOG_DEBUG : hc.cfg->debug_level);

	r = run_server(&hc);
	if (r < 0)
		log_err("Varlink server: %s", strerror(-r));

out:
	if (hc.nvme_ctx)
		libnvme_free_global_ctx(hc.nvme_ctx);
	config_free(hc.cfg);

	return r < 0 ? 1 : 0;
}
