// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * NVM-Express command line utility.
 *
 * Copyright (c) 2014-2015, Intel Corporation.
 *
 * Written by Keith Busch <kbusch@kernel.org>
 */

/**
 * This program uses NVMe IOCTLs to run native nvme commands to a device.
 */
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <inttypes.h>
#include <libgen.h>
#include <locale.h>
#include <math.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifdef NVME_HAVE_MMAP
#include <sys/mman.h>
#endif
#include <sys/stat.h>
#include <sys/types.h>

#include <libnvme-mi.h>
#include <libnvme.h>

#include <ccan/array_size/array_size.h>
#include <ccan/endian/endian.h>
#include <ccan/minmax/minmax.h>
#include <shared/compiler-attributes-util.h>
#include <shared/fs-util.h>
#include <shared/mmio-util.h>
#include <shared/parse-util.h>
#include <shared/sig-util.h>
#include <shared/suffix-util.h>
#include <shared/time-util.h>

#include "argconfig.h"
#include "cleanup.h"
#include "nvme-print.h"
#include "plugin.h"

#ifdef CONFIG_DEPRECATED_CMDS

#ifdef CONFIG_FABRICS
static struct plugin *find_keys_plugin(void)
{
	struct plugin *keys = builtin.next;

	while (keys && (!keys->name || strcmp(keys->name, "keys")))
		keys = keys->next;

	return keys;
}

static int forward_to_keys_plugin(const char *old_name, const char *subcmd,
		int argc, char **argv)
{
	struct plugin *keys = find_keys_plugin();
	__cleanup_free char **sub_argv = NULL;

	if (!keys) {
		fprintf(stderr, "ERROR: '%s' is deprecated and requires the 'keys' plugin, which is not available in this build; use 'nvme keys %s'\n",
			old_name, subcmd);
		return -ENOTTY;
	}

	fprintf(stderr, "WARNING: '%s' is deprecated and will be removed in the next major version, use 'nvme keys %s' instead\n",
		old_name, subcmd);

	/*
	 * handle_plugin() expects argv[0] to be a throwaway name (its own
	 * global-option parsing skips it like a program name) and argv[1]
	 * to be the subcommand it dispatches on, so forwarding into the
	 * 'keys' plugin needs both slots, not just a renamed argv[0].
	 */
	sub_argv = calloc(argc + 1, sizeof(*sub_argv));
	if (!sub_argv)
		return -ENOMEM;

	sub_argv[0] = (char *)keys->name;
	sub_argv[1] = (char *)subcmd;
	memcpy(&sub_argv[2], &argv[1], (argc - 1) * sizeof(*argv));

	return handle_plugin(argc + 1, sub_argv, keys);
}

/*
 * gen-kxchap-secret dropped --nqn with the transform that used it. Take
 * it here anyway, warn, and drop it, so a 2.x command line still works.
 */
static int gen_dhchap_key(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc =
	    "Generate a KX-HMAC-CHAP secret in the DHHC-1 representation, usable for\n"
	    "NVMe In-Band Authentication.\n"
	    "Deprecated; use 'nvme keys gen-kxchap-secret' instead.";
	const char *secret =
	    "Optional secret (in hexadecimal characters) to be placed in the representation.";
	const char *key_len = "Length of the secret (32, 48, or 64 bytes).";
	const char *hmac =
	    "Hash function the consumer is to apply to the secret (0 = none, 1 = SHA-256, 2 = SHA-384, 3 = SHA-512).";
	const char *nqn =
	    "Accepted and ignored; nvme-cli 2.x keyed the transform with it.";

	char key_len_buf[16], hmac_buf[16];
	char *args[8] = { argv[0] };
	int nargs = 1, err;

	struct config {
		char		*secret;
		unsigned int	key_len;
		char		*nqn;
		unsigned int	hmac;
	};

	struct config cfg = {
		.secret		= NULL,
		.key_len	= 0,
		.nqn		= NULL,
		.hmac		= 0,
	};

	NVME_ARGS(opts,
		  OPT_STR("secret",		's', &cfg.secret,	secret),
		  OPT_UINT("key-length",	'l', &cfg.key_len,	key_len),
		  OPT_STR("nqn",		'n', &cfg.nqn,		nqn),
		  OPT_UINT("hmac",		'm', &cfg.hmac,		hmac));

	err = argconfig_parse(argc, argv, desc, opts);
	if (err)
		return err;

	if (argconfig_parse_seen(opts, "nqn"))
		fprintf(stderr,
			"WARNING: '--nqn' is ignored, the DHHC-1 string carries the secret itself, which no NQN takes part in deriving\n");

	if (argconfig_parse_seen(opts, "secret")) {
		args[nargs++] = "--secret";
		args[nargs++] = cfg.secret;
	}
	if (argconfig_parse_seen(opts, "key-length")) {
		snprintf(key_len_buf, sizeof(key_len_buf), "%u", cfg.key_len);
		args[nargs++] = "--secret-length";
		args[nargs++] = key_len_buf;
	}
	if (argconfig_parse_seen(opts, "hmac")) {
		snprintf(hmac_buf, sizeof(hmac_buf), "%u", cfg.hmac);
		args[nargs++] = "--hmac";
		args[nargs++] = hmac_buf;
	}

	return forward_to_keys_plugin("gen-dhchap-key", "gen-kxchap-secret", nargs, args);
}

/*
 * 2.x took the secret in --key/-k, which the command this forwards to
 * gives to --keyring. Take the 2.x option here and pass it as --keydata.
 */
static int check_dhchap_key(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc =
	    "Check a KX-HMAC-CHAP host secret for usability for NVMe In-Band Authentication.\n"
	    "Deprecated; use 'nvme keys check-kxchap-secret' instead.";
	const char *key =
	    "KX-HMAC-CHAP secret (in DHHC-1 interchange format) to be validated. Reads from stdin if not given.";

	char *args[4] = { argv[0] };
	int nargs = 1, err;

	struct config {
		char	*key;
	};

	struct config cfg = {
		.key	= NULL,
	};

	NVME_ARGS(opts,
		  OPT_STR("key", 'k', &cfg.key, key));

	err = argconfig_parse(argc, argv, desc, opts);
	if (err)
		return err;

	if (argconfig_parse_seen(opts, "key")) {
		args[nargs++] = "--keydata";
		args[nargs++] = cfg.key;
	}

	return forward_to_keys_plugin("check-dhchap-key", "check-kxchap-secret", nargs, args);
}

static int gen_tls_key(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	return forward_to_keys_plugin("gen-tls-key", "gen-tls-psk", argc, argv);
}

static int check_tls_key(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	return forward_to_keys_plugin("check-tls-key", "check-tls-psk", argc, argv);
}

/*
 * The old 'tls-key' command bundled import/export/revoke behind
 * -i/-e/-r mode flags sharing -k/-t/-f; the 'keys' plugin split these
 * into separate subcommands with their own option sets, so unlike the
 * other legacy aliases this one has to translate argv instead of just
 * renaming argv[0].
 */
static int tls_key(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	static const struct option opts[] = {
		{ "keyring",	required_argument,	NULL, 'k' },
		{ "keytype",	required_argument,	NULL, 't' },
		{ "keyfile",	required_argument,	NULL, 'f' },
		{ "import",	no_argument,		NULL, 'i' },
		{ "export",	no_argument,		NULL, 'e' },
		{ "revoke",	required_argument,	NULL, 'r' },
		{ NULL, 0, NULL, 0 },
	};
	__cleanup_free char *keyring_opt = NULL;
	__cleanup_free char *keytype_opt = NULL;
	__cleanup_free char *keyfile_opt = NULL;
	__cleanup_free char *identity_opt = NULL;
	__cleanup_free char **sub_argv = NULL;
	const char *keyring = NULL, *keytype = NULL, *keyfile = NULL, *revoke = NULL;
	const char *subcmd = NULL;
	struct plugin *keys;
	int nsub = 0, c;

	optind = 1;
	while ((c = getopt_long(argc, argv, "k:t:f:ier:", opts, NULL)) != -1) {
		switch (c) {
		case 'k':
			keyring = optarg;
			break;
		case 't':
			keytype = optarg;
			break;
		case 'f':
			keyfile = optarg;
			break;
		case 'i':
		case 'e':
			if (subcmd) {
				fprintf(stderr, "ERROR: only one of --import, --export, or --revoke may be given\n");
				return -EINVAL;
			}
			subcmd = c == 'i' ? "import" : "export";
			break;
		case 'r':
			if (subcmd) {
				fprintf(stderr, "ERROR: only one of --import, --export, or --revoke may be given\n");
				return -EINVAL;
			}
			subcmd = "revoke";
			revoke = optarg;
			break;
		default:
			return -EINVAL;
		}
	}

	if (!subcmd) {
		fprintf(stderr, "ERROR: 'tls-key' requires one of --import, --export, or --revoke\n");
		return -EINVAL;
	}

	keys = find_keys_plugin();
	if (!keys) {
		fprintf(stderr, "ERROR: 'tls-key' is deprecated and requires the 'keys' plugin, which is not available in this build; use 'nvme keys %s'\n",
			subcmd);
		return -ENOTTY;
	}

	sub_argv = calloc(6, sizeof(*sub_argv));
	if (!sub_argv)
		return -ENOMEM;

	sub_argv[nsub++] = (char *)keys->name;
	sub_argv[nsub++] = (char *)subcmd;

	if (keyring) {
		if (asprintf(&keyring_opt, "--keyring=%s", keyring) < 0)
			return -ENOMEM;
		sub_argv[nsub++] = keyring_opt;
	}

	if (!strcmp(subcmd, "revoke")) {
		if (keytype) {
			if (asprintf(&keytype_opt, "--keytype=%s", keytype) < 0)
				return -ENOMEM;
			sub_argv[nsub++] = keytype_opt;
		}
		if (asprintf(&identity_opt, "--identity=%s", revoke) < 0)
			return -ENOMEM;
		sub_argv[nsub++] = identity_opt;
	} else if (keyfile) {
		if (asprintf(&keyfile_opt, "--keyfile=%s", keyfile) < 0)
			return -ENOMEM;
		sub_argv[nsub++] = keyfile_opt;
	}

	fprintf(stderr, "WARNING: 'tls-key' is deprecated and will be removed in the next major version, use 'nvme keys %s' instead\n",
		subcmd);

	return handle_plugin(nsub, sub_argv, keys);
}
#endif /* CONFIG_FABRICS */

static struct plugin *find_log_plugin(void)
{
	struct plugin *log = builtin.next;

	while (log && (!log->name || strcmp(log->name, "log")))
		log = log->next;

	return log;
}

static int forward_to_log_plugin(const char *old_name, const char *subcmd,
		int argc, char **argv)
{
	struct plugin *log = find_log_plugin();
	__cleanup_free char **sub_argv = NULL;

	if (!log) {
		fprintf(stderr, "ERROR: '%s' is deprecated and requires the 'log' plugin, which is not available in this build; use 'nvme log %s'\n",
			old_name, subcmd);
		return -ENOTTY;
	}

	fprintf(stderr, "WARNING: '%s' is deprecated and will be removed in the next major version, use 'nvme log %s' instead\n",
		old_name, subcmd);

	sub_argv = calloc(argc + 1, sizeof(*sub_argv));
	if (!sub_argv)
		return -ENOMEM;

	sub_argv[0] = (char *)log->name;
	sub_argv[1] = (char *)subcmd;
	memcpy(&sub_argv[2], &argv[1], (argc - 1) * sizeof(*argv));

	return handle_plugin(argc + 1, sub_argv, log);
}

static int get_supported_log_pages(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	return forward_to_log_plugin("supported-log-pages", "supported-pages", argc, argv);
}

static int get_telemetry_log(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	return forward_to_log_plugin("telemetry-log", "telemetry", argc, argv);
}

static int get_fw_log(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	return forward_to_log_plugin("fw-log", "fw", argc, argv);
}

static int get_changed_attach_ns_list_log(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	return forward_to_log_plugin("changed-ns-list-log", "changed-ns-list", argc, argv);
}

static int get_smart_log(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	return forward_to_log_plugin("smart-log", "smart", argc, argv);
}

static int get_ana_log(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	return forward_to_log_plugin("ana-log", "ana", argc, argv);
}

static int get_error_log(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	return forward_to_log_plugin("error-log", "error", argc, argv);
}

static int get_effects_log(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	return forward_to_log_plugin("effects-log", "effects", argc, argv);
}

static int get_endurance_log(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	return forward_to_log_plugin("endurance-log", "endurance", argc, argv);
}

static int get_pred_lat_per_nvmset_log(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	return forward_to_log_plugin("predictable-lat-log", "predictable-lat", argc, argv);
}

static int get_pred_lat_event_agg_log(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	return forward_to_log_plugin("pred-lat-event-agg-log", "pred-lat-event-agg", argc, argv);
}

static int get_persistent_event_log(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	return forward_to_log_plugin("persistent-event-log", "persistent-event", argc, argv);
}

static int get_endurance_event_agg_log(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	return forward_to_log_plugin("endurance-event-agg-log", "endurance-event-agg", argc, argv);
}

static int get_lba_status_log(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	return forward_to_log_plugin("lba-status-log", "lba-status", argc, argv);
}

static int get_resv_notif_log(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	return forward_to_log_plugin("resv-notif-log", "resv-notif", argc, argv);
}

static int get_boot_part_log(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	return forward_to_log_plugin("boot-part-log", "boot-part", argc, argv);
}

static int get_phy_rx_eom_log(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	return forward_to_log_plugin("phy-rx-eom-log", "phy-rx-eom", argc, argv);
}

static int self_test_log(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	return forward_to_log_plugin("self-test-log", "self-test", argc, argv);
}

static int get_fid_support_effects_log(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	return forward_to_log_plugin("fid-support-effects-log", "fid-support-effects", argc, argv);
}

static int get_mi_cmd_support_effects_log(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	return forward_to_log_plugin("mi-cmd-support-effects-log", "mi-cmd-support-effects", argc, argv);
}

static int get_media_unit_stat_log(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	return forward_to_log_plugin("media-unit-stat-log", "media-unit-stat", argc, argv);
}

static int get_supp_cap_config_log(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	return forward_to_log_plugin("supported-cap-config-log", "supported-cap-config", argc, argv);
}

static int get_mgmt_addr_list_log(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	return forward_to_log_plugin("mgmt-addr-list-log", "mgmt-addr-list", argc, argv);
}

static int get_rotational_media_info_log(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	return forward_to_log_plugin("rotational-media-info-log", "rotational-media-info", argc, argv);
}

static int get_changed_alloc_ns_list_log(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	return forward_to_log_plugin("changed-alloc-ns-list-log", "changed-alloc-ns-list", argc, argv);
}

static int get_dispersed_ns_participating_nss_log(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	return forward_to_log_plugin("dispersed-ns-participating-nss-log", "dispersed-ns-participating-nss", argc, argv);
}

static int get_reachability_groups_log(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	return forward_to_log_plugin("reachability-groups-log", "reachability-groups", argc, argv);
}

static int get_reachability_associations_log(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	return forward_to_log_plugin("reachability-associations-log", "reachability-associations", argc, argv);
}

static int get_host_discovery_log(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	return forward_to_log_plugin("host-discovery-log", "host-discovery", argc, argv);
}

static int get_ave_discovery_log(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	return forward_to_log_plugin("ave-discovery-log", "ave-discovery", argc, argv);
}

static int get_pull_model_ddc_req_log(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	return forward_to_log_plugin("pull-model-ddc-req-log", "pull-model-ddc-req", argc, argv);
}

static int get_power_measurement_log(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	return forward_to_log_plugin("power-measurement-log", "power-measurement", argc, argv);
}

static int sanitize_log(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	return forward_to_log_plugin("sanitize-log", "sanitize", argc, argv);
}


static struct plugin *find_id_plugin(void)
{
	struct plugin *id = builtin.next;

	while (id && (!id->name || strcmp(id->name, "id")))
		id = id->next;

	return id;
}

static int forward_to_id_plugin(const char *old_name, const char *subcmd,
		int argc, char **argv)
{
	struct plugin *id = find_id_plugin();
	__cleanup_free char **sub_argv = NULL;

	if (!id) {
		fprintf(stderr, "ERROR: '%s' is deprecated and requires the 'id' plugin, which is not available in this build; use 'nvme id %s'\n",
			old_name, subcmd);
		return -ENOTTY;
	}

	fprintf(stderr, "WARNING: '%s' is deprecated and will be removed in the next major version, use 'nvme id %s' instead\n",
		old_name, subcmd);

	sub_argv = calloc(argc + 1, sizeof(*sub_argv));
	if (!sub_argv)
		return -ENOMEM;

	sub_argv[0] = (char *)id->name;
	sub_argv[1] = (char *)subcmd;
	memcpy(&sub_argv[2], &argv[1], (argc - 1) * sizeof(*argv));

	return handle_plugin(argc + 1, sub_argv, id);
}

static int id_ctrl(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	return forward_to_id_plugin("id-ctrl", "ctrl", argc, argv);
}

static int id_ns(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	return forward_to_id_plugin("id-ns", "ns", argc, argv);
}

static int id_ns_granularity(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	return forward_to_id_plugin("id-ns-granularity", "ns-granularity", argc, argv);
}

static int id_ns_lba_format(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	return forward_to_id_plugin("id-ns-lba-format", "ns-lba-format", argc, argv);
}

static int list_ns(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	return forward_to_id_plugin("list-ns", "ns-list", argc, argv);
}

static int list_ctrl(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	return forward_to_id_plugin("list-ctrl", "ctrl-list", argc, argv);
}

static int nvm_id_ctrl(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	return forward_to_id_plugin("nvm-id-ctrl", "nvm-ctrl", argc, argv);
}

static int nvm_id_ns(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	return forward_to_id_plugin("nvm-id-ns", "nvm-ns", argc, argv);
}

static int nvm_id_ns_lba_format(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	return forward_to_id_plugin("nvm-id-ns-lba-format", "nvm-ns-lba-format", argc, argv);
}

static int primary_ctrl_caps(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	return forward_to_id_plugin("primary-ctrl-caps", "primary-ctrl-caps", argc, argv);
}

static int list_secondary_ctrl(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	return forward_to_id_plugin("list-secondary", "secondary-ctrl-list", argc, argv);
}

static int cmd_set_independent_id_ns(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	return forward_to_id_plugin("cmdset-ind-id-ns", "ns-ind", argc, argv);
}

static int ns_descs(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	return forward_to_id_plugin("ns-descs", "ns-descs", argc, argv);
}

static int id_nvmset(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	return forward_to_id_plugin("id-nvmset", "nvmset", argc, argv);
}

static int id_uuid(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	return forward_to_id_plugin("id-uuid", "uuid", argc, argv);
}

static int id_iocs(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	return forward_to_id_plugin("id-iocs", "iocs", argc, argv);
}

static int id_domain(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	return forward_to_id_plugin("id-domain", "domain", argc, argv);
}

static int id_endurance_grp_list(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	return forward_to_id_plugin("list-endgrp", "endgrp-list", argc, argv);
}


static struct plugin *find_ns_plugin(void)
{
	struct plugin *ns = builtin.next;

	while (ns && (!ns->name || strcmp(ns->name, "ns")))
		ns = ns->next;

	return ns;
}

static int forward_to_ns_plugin(const char *old_name, const char *subcmd,
		int argc, char **argv)
{
	struct plugin *ns = find_ns_plugin();
	__cleanup_free char **sub_argv = NULL;

	if (!ns) {
		fprintf(stderr, "ERROR: '%s' is deprecated and requires the 'ns' plugin, which is not available in this build; use 'nvme ns %s'\n",
			old_name, subcmd);
		return -ENOTTY;
	}

	fprintf(stderr, "WARNING: '%s' is deprecated and will be removed in the next major version, use 'nvme ns %s' instead\n",
		old_name, subcmd);

	sub_argv = calloc(argc + 1, sizeof(*sub_argv));
	if (!sub_argv)
		return -ENOMEM;

	sub_argv[0] = (char *)ns->name;
	sub_argv[1] = (char *)subcmd;
	memcpy(&sub_argv[2], &argv[1], (argc - 1) * sizeof(*argv));

	return handle_plugin(argc + 1, sub_argv, ns);
}

static int create_ns(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	return forward_to_ns_plugin("create-ns", "create", argc, argv);
}

static int delete_ns(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	return forward_to_ns_plugin("delete-ns", "delete", argc, argv);
}

static int attach_ns(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	return forward_to_ns_plugin("attach-ns", "attach", argc, argv);
}

static int detach_ns(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	return forward_to_ns_plugin("detach-ns", "detach", argc, argv);
}

static int get_ns_id(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	return forward_to_ns_plugin("get-ns-id", "get-id", argc, argv);
}


static struct plugin *find_resv_plugin(void)
{
	struct plugin *resv = builtin.next;

	while (resv && (!resv->name || strcmp(resv->name, "resv")))
		resv = resv->next;

	return resv;
}

static int forward_to_resv_plugin(const char *old_name, const char *subcmd,
		int argc, char **argv)
{
	struct plugin *resv = find_resv_plugin();
	__cleanup_free char **sub_argv = NULL;

	if (!resv) {
		fprintf(stderr, "ERROR: '%s' is deprecated and requires the 'resv' plugin, which is not available in this build; use 'nvme resv %s'\n",
			old_name, subcmd);
		return -ENOTTY;
	}

	fprintf(stderr, "WARNING: '%s' is deprecated and will be removed in the next major version, use 'nvme resv %s' instead\n",
		old_name, subcmd);

	sub_argv = calloc(argc + 1, sizeof(*sub_argv));
	if (!sub_argv)
		return -ENOMEM;

	sub_argv[0] = (char *)resv->name;
	sub_argv[1] = (char *)subcmd;
	memcpy(&sub_argv[2], &argv[1], (argc - 1) * sizeof(*argv));

	return handle_plugin(argc + 1, sub_argv, resv);
}

static int resv_acquire(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	return forward_to_resv_plugin("resv-acquire", "acquire", argc, argv);
}

static int resv_register(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	return forward_to_resv_plugin("resv-register", "register", argc, argv);
}

static int resv_release(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	return forward_to_resv_plugin("resv-release", "release", argc, argv);
}

static int resv_report(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	return forward_to_resv_plugin("resv-report", "report", argc, argv);
}


static struct plugin *find_nvme_mi_plugin(void)
{
	struct plugin *nvme_mi = builtin.next;

	while (nvme_mi && (!nvme_mi->name || strcmp(nvme_mi->name, "nvme-mi")))
		nvme_mi = nvme_mi->next;

	return nvme_mi;
}

static int forward_to_nvme_mi_plugin(const char *old_name, const char *subcmd,
		int argc, char **argv)
{
	struct plugin *nvme_mi = find_nvme_mi_plugin();
	__cleanup_free char **sub_argv = NULL;

	if (!nvme_mi) {
		fprintf(stderr, "ERROR: '%s' is deprecated and requires the 'nvme-mi' plugin, which is not available in this build; use 'nvme nvme-mi %s'\n",
			old_name, subcmd);
		return -ENOTTY;
	}

	fprintf(stderr, "WARNING: '%s' is deprecated and will be removed in the next major version, use 'nvme nvme-mi %s' instead\n",
		old_name, subcmd);

	sub_argv = calloc(argc + 1, sizeof(*sub_argv));
	if (!sub_argv)
		return -ENOMEM;

	sub_argv[0] = (char *)nvme_mi->name;
	sub_argv[1] = (char *)subcmd;
	memcpy(&sub_argv[2], &argv[1], (argc - 1) * sizeof(*argv));

	return handle_plugin(argc + 1, sub_argv, nvme_mi);
}

static int nmi_recv(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	return forward_to_nvme_mi_plugin("nvme-mi-recv", "recv", argc, argv);
}

static int nmi_send(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	return forward_to_nvme_mi_plugin("nvme-mi-send", "send", argc, argv);
}


static struct plugin *find_io_mgmt_plugin(void)
{
	struct plugin *io_mgmt = builtin.next;

	while (io_mgmt && (!io_mgmt->name || strcmp(io_mgmt->name, "io-mgmt")))
		io_mgmt = io_mgmt->next;

	return io_mgmt;
}

static int forward_to_io_mgmt_plugin(const char *old_name, const char *subcmd,
		int argc, char **argv)
{
	struct plugin *io_mgmt = find_io_mgmt_plugin();
	__cleanup_free char **sub_argv = NULL;

	if (!io_mgmt) {
		fprintf(stderr, "ERROR: '%s' is deprecated and requires the 'io-mgmt' plugin, which is not available in this build; use 'nvme io-mgmt %s'\n",
			old_name, subcmd);
		return -ENOTTY;
	}

	fprintf(stderr, "WARNING: '%s' is deprecated and will be removed in the next major version, use 'nvme io-mgmt %s' instead\n",
		old_name, subcmd);

	sub_argv = calloc(argc + 1, sizeof(*sub_argv));
	if (!sub_argv)
		return -ENOMEM;

	sub_argv[0] = (char *)io_mgmt->name;
	sub_argv[1] = (char *)subcmd;
	memcpy(&sub_argv[2], &argv[1], (argc - 1) * sizeof(*argv));

	return handle_plugin(argc + 1, sub_argv, io_mgmt);
}

static int io_mgmt_recv(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	return forward_to_io_mgmt_plugin("io-mgmt-recv", "recv", argc, argv);
}

static int io_mgmt_send(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	return forward_to_io_mgmt_plugin("io-mgmt-send", "send", argc, argv);
}


static struct plugin *find_dir_plugin(void)
{
	struct plugin *dir = builtin.next;

	while (dir && (!dir->name || strcmp(dir->name, "dir")))
		dir = dir->next;

	return dir;
}

static int forward_to_dir_plugin(const char *old_name, const char *subcmd,
		int argc, char **argv)
{
	struct plugin *dir = find_dir_plugin();
	__cleanup_free char **sub_argv = NULL;

	if (!dir) {
		fprintf(stderr, "ERROR: '%s' is deprecated and requires the 'dir' plugin, which is not available in this build; use 'nvme dir %s'\n",
			old_name, subcmd);
		return -ENOTTY;
	}

	fprintf(stderr, "WARNING: '%s' is deprecated and will be removed in the next major version, use 'nvme dir %s' instead\n",
		old_name, subcmd);

	sub_argv = calloc(argc + 1, sizeof(*sub_argv));
	if (!sub_argv)
		return -ENOMEM;

	sub_argv[0] = (char *)dir->name;
	sub_argv[1] = (char *)subcmd;
	memcpy(&sub_argv[2], &argv[1], (argc - 1) * sizeof(*argv));

	return handle_plugin(argc + 1, sub_argv, dir);
}

static int dir_receive(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	return forward_to_dir_plugin("dir-receive", "receive", argc, argv);
}

static int dir_send(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	return forward_to_dir_plugin("dir-send", "send", argc, argv);
}


static struct plugin *find_security_plugin(void)
{
	struct plugin *security = builtin.next;

	while (security && (!security->name || strcmp(security->name, "security")))
		security = security->next;

	return security;
}

static int forward_to_security_plugin(const char *old_name, const char *subcmd,
		int argc, char **argv)
{
	struct plugin *security = find_security_plugin();
	__cleanup_free char **sub_argv = NULL;

	if (!security) {
		fprintf(stderr, "ERROR: '%s' is deprecated and requires the 'security' plugin, which is not available in this build; use 'nvme security %s'\n",
			old_name, subcmd);
		return -ENOTTY;
	}

	fprintf(stderr, "WARNING: '%s' is deprecated and will be removed in the next major version, use 'nvme security %s' instead\n",
		old_name, subcmd);

	sub_argv = calloc(argc + 1, sizeof(*sub_argv));
	if (!sub_argv)
		return -ENOMEM;

	sub_argv[0] = (char *)security->name;
	sub_argv[1] = (char *)subcmd;
	memcpy(&sub_argv[2], &argv[1], (argc - 1) * sizeof(*argv));

	return handle_plugin(argc + 1, sub_argv, security);
}

static int sec_send(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	return forward_to_security_plugin("security-send", "send", argc, argv);
}

static int sec_recv(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	return forward_to_security_plugin("security-recv", "recv", argc, argv);
}


static struct plugin *find_fw_plugin(void)
{
	struct plugin *fw = builtin.next;

	while (fw && (!fw->name || strcmp(fw->name, "fw")))
		fw = fw->next;

	return fw;
}

static int forward_to_fw_plugin(const char *old_name, const char *subcmd,
		int argc, char **argv)
{
	struct plugin *fw = find_fw_plugin();
	__cleanup_free char **sub_argv = NULL;

	if (!fw) {
		fprintf(stderr, "ERROR: '%s' is deprecated and requires the 'fw' plugin, which is not available in this build; use 'nvme fw %s'\n",
			old_name, subcmd);
		return -ENOTTY;
	}

	fprintf(stderr, "WARNING: '%s' is deprecated and will be removed in the next major version, use 'nvme fw %s' instead\n",
		old_name, subcmd);

	sub_argv = calloc(argc + 1, sizeof(*sub_argv));
	if (!sub_argv)
		return -ENOMEM;

	sub_argv[0] = (char *)fw->name;
	sub_argv[1] = (char *)subcmd;
	memcpy(&sub_argv[2], &argv[1], (argc - 1) * sizeof(*argv));

	return handle_plugin(argc + 1, sub_argv, fw);
}

static int fw_commit(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	return forward_to_fw_plugin("fw-commit", "commit", argc, argv);
}

static int fw_download(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	return forward_to_fw_plugin("fw-download", "download", argc, argv);
}

static struct command id_ctrl_cmd = {
	.name = "id-ctrl",
	.help = "Send NVMe Identify Controller (deprecated, use 'nvme id ctrl')",
	.fn = id_ctrl,
	.deprecated = true,
};

static struct command id_ns_cmd = {
	.name = "id-ns",
	.help = "Send NVMe Identify Namespace, display structure (deprecated, use 'nvme id ns')",
	.fn = id_ns,
	.deprecated = true,
};

static struct command id_ns_granularity_cmd = {
	.name = "id-ns-granularity",
	.help = "Send NVMe Identify Namespace Granularity List, display structure (deprecated, use 'nvme "
		"id ns-granularity')",
	.fn = id_ns_granularity,
	.deprecated = true,
};

static struct command id_ns_lba_format_cmd = {
	.name = "id-ns-lba-format",
	.help = "Send NVMe Identify Namespace for the specified LBA Format index, display structure "
		"(deprecated, use 'nvme id ns-lba-format')",
	.fn = id_ns_lba_format,
	.deprecated = true,
};

static struct command list_ns_cmd = {
	.name = "list-ns",
	.help = "Send NVMe Identify List, display structure (deprecated, use 'nvme id ns-list')",
	.fn = list_ns,
	.deprecated = true,
};

static struct command list_ctrl_cmd = {
	.name = "list-ctrl",
	.help = "Send NVMe Identify Controller List, display structure (deprecated, use 'nvme id "
		"ctrl-list')",
	.fn = list_ctrl,
	.deprecated = true,
};

static struct command nvm_id_ctrl_cmd = {
	.name = "nvm-id-ctrl",
	.help = "Send NVMe Identify Controller NVM Command Set, display structure (deprecated, use 'nvme "
		"id nvm-ctrl')",
	.fn = nvm_id_ctrl,
	.deprecated = true,
};

static struct command nvm_id_ns_cmd = {
	.name = "nvm-id-ns",
	.help = "Send NVMe Identify Namespace NVM Command Set, display structure (deprecated, use 'nvme "
		"id nvm-ns')",
	.fn = nvm_id_ns,
	.deprecated = true,
};

static struct command nvm_id_ns_lba_format_cmd = {
	.name = "nvm-id-ns-lba-format",
	.help = "Send NVMe Identify Namespace NVM Command Set for the specified LBA Format index, display "
		"structure (deprecated, use 'nvme id nvm-ns-lba-format')",
	.fn = nvm_id_ns_lba_format,
	.deprecated = true,
};

static struct command primary_ctrl_caps_cmd = {
	.name = "primary-ctrl-caps",
	.help = "Send NVMe Identify Primary Controller Capabilities (deprecated, use 'nvme id "
		"primary-ctrl-caps')",
	.fn = primary_ctrl_caps,
	.deprecated = true,
};

static struct command list_secondary_ctrl_cmd = {
	.name = "list-secondary",
	.help = "List Secondary Controllers associated with a Primary Controller (deprecated, use 'nvme "
		"id secondary-ctrl-list')",
	.fn = list_secondary_ctrl,
	.deprecated = true,
};

static struct command cmd_set_independent_id_ns_cmd = {
	.name = "cmdset-ind-id-ns",
	.help = "I/O Command Set Independent Identify Namespace (deprecated, use 'nvme id ns-ind')",
	.fn = cmd_set_independent_id_ns,
	.deprecated = true,
};

static struct command ns_descs_cmd = {
	.name = "ns-descs",
	.help = "Send NVMe Namespace Descriptor List, display structure (deprecated, use 'nvme id "
		"ns-descs')",
	.fn = ns_descs,
	.deprecated = true,
};

static struct command id_nvmset_cmd = {
	.name = "id-nvmset",
	.help = "Send NVMe Identify NVM Set List, display structure (deprecated, use 'nvme id nvmset')",
	.fn = id_nvmset,
	.deprecated = true,
};

static struct command id_uuid_cmd = {
	.name = "id-uuid",
	.help = "Send NVMe Identify UUID List, display structure (deprecated, use 'nvme id uuid')",
	.fn = id_uuid,
	.deprecated = true,
};

static struct command id_iocs_cmd = {
	.name = "id-iocs",
	.help = "Send NVMe Identify I/O Command Set, display structure (deprecated, use 'nvme id iocs')",
	.fn = id_iocs,
	.deprecated = true,
};

static struct command id_domain_cmd = {
	.name = "id-domain",
	.help = "Send NVMe Identify Domain List, display structure (deprecated, use 'nvme id domain')",
	.fn = id_domain,
	.deprecated = true,
};

static struct command id_endurance_grp_list_cmd = {
	.name = "list-endgrp",
	.help = "Send NVMe Identify Endurance Group List, display structure (deprecated, use 'nvme id "
		"endgrp-list')",
	.fn = id_endurance_grp_list,
	.deprecated = true,
};

static struct command create_ns_cmd = {
	.name = "create-ns",
	.help = "Creates a namespace with the provided parameters (deprecated, use 'nvme ns create')",
	.fn = create_ns,
	.deprecated = true,
};

static struct command delete_ns_cmd = {
	.name = "delete-ns",
	.help = "Deletes a namespace from the controller (deprecated, use 'nvme ns delete')",
	.fn = delete_ns,
	.deprecated = true,
};

static struct command attach_ns_cmd = {
	.name = "attach-ns",
	.help = "Attaches a namespace to requested controller(s) (deprecated, use 'nvme ns attach')",
	.fn = attach_ns,
	.deprecated = true,
};

static struct command detach_ns_cmd = {
	.name = "detach-ns",
	.help = "Detaches a namespace from requested controller(s) (deprecated, use 'nvme ns detach')",
	.fn = detach_ns,
	.deprecated = true,
};

static struct command get_ns_id_cmd = {
	.name = "get-ns-id",
	.help = "Retrieve the namespace ID of opened block device (deprecated, use 'nvme ns get-id')",
	.fn = get_ns_id,
	.deprecated = true,
};

static struct command get_supported_log_pages_cmd = {
	.name = "supported-log-pages",
	.help = "Retrieve the Supported Log pages details, show it (deprecated, use 'nvme log "
		"supported-pages')",
	.fn = get_supported_log_pages,
	.deprecated = true,
};

static struct command get_telemetry_log_cmd = {
	.name = "telemetry-log",
	.help = "Retrieve FW Telemetry log write to file (deprecated, use 'nvme log telemetry')",
	.fn = get_telemetry_log,
	.deprecated = true,
};

static struct command get_fw_log_cmd = {
	.name = "fw-log",
	.help = "Retrieve FW Log, show it (deprecated, use 'nvme log fw')",
	.fn = get_fw_log,
	.deprecated = true,
};

static struct command get_changed_attach_ns_list_log_cmd = {
	.name = "changed-ns-list-log",
	.help = "Retrieve Changed Attached Namespace List, show it (deprecated, use 'nvme log "
		"changed-ns-list')",
	.fn = get_changed_attach_ns_list_log,
	.deprecated = true,
};

static struct command get_smart_log_cmd = {
	.name = "smart-log",
	.help = "Retrieve SMART Log, show it (deprecated, use 'nvme log smart')",
	.fn = get_smart_log,
	.deprecated = true,
};

static struct command get_ana_log_cmd = {
	.name = "ana-log",
	.help = "Retrieve ANA Log, show it (deprecated, use 'nvme log ana')",
	.fn = get_ana_log,
	.deprecated = true,
};

static struct command get_error_log_cmd = {
	.name = "error-log",
	.help = "Retrieve Error Log, show it (deprecated, use 'nvme log error')",
	.fn = get_error_log,
	.deprecated = true,
};

static struct command get_effects_log_cmd = {
	.name = "effects-log",
	.help = "Retrieve Command Effects Log, show it (deprecated, use 'nvme log effects')",
	.fn = get_effects_log,
	.deprecated = true,
};

static struct command get_endurance_log_cmd = {
	.name = "endurance-log",
	.help = "Retrieve Endurance Group Log, show it (deprecated, use 'nvme log endurance')",
	.fn = get_endurance_log,
	.deprecated = true,
};

static struct command get_pred_lat_per_nvmset_log_cmd = {
	.name = "predictable-lat-log",
	.help = "Retrieve Predictable Latency per Nvmset Log, show it (deprecated, use 'nvme log "
		"predictable-lat')",
	.fn = get_pred_lat_per_nvmset_log,
	.deprecated = true,
};

static struct command get_pred_lat_event_agg_log_cmd = {
	.name = "pred-lat-event-agg-log",
	.help = "Retrieve Predictable Latency Event Aggregate Log, show it (deprecated, use 'nvme log "
		"pred-lat-event-agg')",
	.fn = get_pred_lat_event_agg_log,
	.deprecated = true,
};

static struct command get_persistent_event_log_cmd = {
	.name = "persistent-event-log",
	.help = "Retrieve Persistent Event Log, show it (deprecated, use 'nvme log persistent-event')",
	.fn = get_persistent_event_log,
	.deprecated = true,
};

static struct command get_endurance_event_agg_log_cmd = {
	.name = "endurance-event-agg-log",
	.help = "Retrieve Endurance Group Event Aggregate Log, show it (deprecated, use 'nvme log "
		"endurance-event-agg')",
	.fn = get_endurance_event_agg_log,
	.deprecated = true,
};

static struct command get_lba_status_log_cmd = {
	.name = "lba-status-log",
	.help = "Retrieve LBA Status Information Log, show it (deprecated, use 'nvme log lba-status')",
	.fn = get_lba_status_log,
	.deprecated = true,
};

static struct command get_resv_notif_log_cmd = {
	.name = "resv-notif-log",
	.help = "Retrieve Reservation Notification Log, show it (deprecated, use 'nvme log resv-notif')",
	.fn = get_resv_notif_log,
	.deprecated = true,
};

static struct command get_boot_part_log_cmd = {
	.name = "boot-part-log",
	.help = "Retrieve Boot Partition Log, show it (deprecated, use 'nvme log boot-part')",
	.fn = get_boot_part_log,
	.deprecated = true,
};

static struct command get_phy_rx_eom_log_cmd = {
	.name = "phy-rx-eom-log",
	.help = "Retrieve Physical Interface Receiver Eye Opening Measurement, show it (deprecated, use "
		"'nvme log phy-rx-eom')",
	.fn = get_phy_rx_eom_log,
	.deprecated = true,
};

static struct command self_test_log_cmd = {
	.name = "self-test-log",
	.help = "Retrieve the SELF-TEST Log, show it (deprecated, use 'nvme log self-test')",
	.fn = self_test_log,
	.deprecated = true,
};

static struct command get_fid_support_effects_log_cmd = {
	.name = "fid-support-effects-log",
	.help = "Retrieve FID Support and Effects log and show it (deprecated, use 'nvme log "
		"fid-support-effects')",
	.fn = get_fid_support_effects_log,
	.deprecated = true,
};

static struct command get_mi_cmd_support_effects_log_cmd = {
	.name = "mi-cmd-support-effects-log",
	.help = "Retrieve MI Command Support and Effects log and show it (deprecated, use 'nvme log "
		"mi-cmd-support-effects')",
	.fn = get_mi_cmd_support_effects_log,
	.deprecated = true,
};

static struct command get_media_unit_stat_log_cmd = {
	.name = "media-unit-stat-log",
	.help = "Retrieve the configuration and wear of media units, show it (deprecated, use 'nvme log "
		"media-unit-stat')",
	.fn = get_media_unit_stat_log,
	.deprecated = true,
};

static struct command get_supp_cap_config_log_cmd = {
	.name = "supported-cap-config-log",
	.help = "Retrieve the list of Supported Capacity Configuration Descriptors (deprecated, use 'nvme "
		"log supported-cap-config')",
	.fn = get_supp_cap_config_log,
	.deprecated = true,
};

static struct command get_mgmt_addr_list_log_cmd = {
	.name = "mgmt-addr-list-log",
	.help = "Retrieve Management Address List Log, show it (deprecated, use 'nvme log "
		"mgmt-addr-list')",
	.fn = get_mgmt_addr_list_log,
	.deprecated = true,
};

static struct command get_rotational_media_info_log_cmd = {
	.name = "rotational-media-info-log",
	.help = "Retrieve Rotational Media Information Log, show it (deprecated, use 'nvme log "
		"rotational-media-info')",
	.fn = get_rotational_media_info_log,
	.deprecated = true,
};

static struct command get_changed_alloc_ns_list_log_cmd = {
	.name = "changed-alloc-ns-list-log",
	.help = "Retrieve Changed Allocated Namespace List, show it (deprecated, use 'nvme log "
		"changed-alloc-ns-list')",
	.fn = get_changed_alloc_ns_list_log,
	.deprecated = true,
};

static struct command get_dispersed_ns_participating_nss_log_cmd = {
	.name = "dispersed-ns-participating-nss-log",
	.help = "Retrieve Dispersed Namespace Participating NVM Subsystems Log, show it (deprecated, use "
		"'nvme log dispersed-ns-participating-nss')",
	.fn = get_dispersed_ns_participating_nss_log,
	.deprecated = true,
};

static struct command get_reachability_groups_log_cmd = {
	.name = "reachability-groups-log",
	.help = "Retrieve Reachability Groups Log, show it (deprecated, use 'nvme log "
		"reachability-groups')",
	.fn = get_reachability_groups_log,
	.deprecated = true,
};

static struct command get_reachability_associations_log_cmd = {
	.name = "reachability-associations-log",
	.help = "Retrieve Reachability Associations Log, show it (deprecated, use 'nvme log "
		"reachability-associations')",
	.fn = get_reachability_associations_log,
	.deprecated = true,
};

static struct command get_host_discovery_log_cmd = {
	.name = "host-discovery-log",
	.help = "Retrieve Host Discovery Log, show it (deprecated, use 'nvme log host-discovery')",
	.fn = get_host_discovery_log,
	.deprecated = true,
};

static struct command get_ave_discovery_log_cmd = {
	.name = "ave-discovery-log",
	.help = "Retrieve AVE Discovery Log, show it (deprecated, use 'nvme log ave-discovery')",
	.fn = get_ave_discovery_log,
	.deprecated = true,
};

static struct command get_pull_model_ddc_req_log_cmd = {
	.name = "pull-model-ddc-req-log",
	.help = "Retrieve Pull Model DDC Request Log, show it (deprecated, use 'nvme log "
		"pull-model-ddc-req')",
	.fn = get_pull_model_ddc_req_log,
	.deprecated = true,
};

static struct command get_power_measurement_log_cmd = {
	.name = "power-measurement-log",
	.help = "Retrieve Power Measurement Log, show it (deprecated, use 'nvme log power-measurement')",
	.fn = get_power_measurement_log,
	.deprecated = true,
};

static struct command fw_commit_cmd = {
	.name = "fw-commit",
	.help = "Verify and commit firmware to a specific slot (fw-activate in old version < 1.2) "
		"(deprecated, use 'nvme fw commit')",
	.fn = fw_commit,
	.alias = "fw-activate",
	.deprecated = true,
};

static struct command fw_download_cmd = {
	.name = "fw-download",
	.help = "Download new firmware (deprecated, use 'nvme fw download')",
	.fn = fw_download,
	.deprecated = true,
};

static struct command sec_send_cmd = {
	.name = "security-send",
	.help = "Submit a Security Send command, return results (deprecated, use 'nvme security send')",
	.fn = sec_send,
	.deprecated = true,
};

static struct command sec_recv_cmd = {
	.name = "security-recv",
	.help = "Submit a Security Receive command, return results (deprecated, use 'nvme security recv')",
	.fn = sec_recv,
	.deprecated = true,
};

static struct command resv_acquire_cmd = {
	.name = "resv-acquire",
	.help = "Submit a Reservation Acquire, return results (deprecated, use 'nvme resv acquire')",
	.fn = resv_acquire,
	.deprecated = true,
};

static struct command resv_register_cmd = {
	.name = "resv-register",
	.help = "Submit a Reservation Register, return results (deprecated, use 'nvme resv register')",
	.fn = resv_register,
	.deprecated = true,
};

static struct command resv_release_cmd = {
	.name = "resv-release",
	.help = "Submit a Reservation Release, return results (deprecated, use 'nvme resv release')",
	.fn = resv_release,
	.deprecated = true,
};

static struct command resv_report_cmd = {
	.name = "resv-report",
	.help = "Submit a Reservation Report, return results (deprecated, use 'nvme resv report')",
	.fn = resv_report,
	.deprecated = true,
};

static struct command sanitize_log_cmd = {
	.name = "sanitize-log",
	.help = "Retrieve sanitize log, show it (deprecated, use 'nvme log sanitize')",
	.fn = sanitize_log,
	.deprecated = true,
};

#ifdef CONFIG_FABRICS

static struct command gen_dhchap_key_cmd = {
	.name = "gen-dhchap-key",
	.help = "Generate NVMeoF DH-HMAC-CHAP host secret (deprecated, use 'nvme keys gen-kxchap-secret')",
	.fn = gen_dhchap_key,
	.deprecated = true,
	.no_device = true,
};

static struct command check_dhchap_key_cmd = {
	.name = "check-dhchap-key",
	.help = "Validate NVMeoF DH-HMAC-CHAP host secret (deprecated, use 'nvme keys "
		"check-kxchap-secret')",
	.fn = check_dhchap_key,
	.deprecated = true,
	.no_device = true,
};

static struct command gen_tls_key_cmd = {
	.name = "gen-tls-key",
	.help = "Generate NVMeoF TLS PSK (deprecated, use 'nvme keys gen-tls-psk')",
	.fn = gen_tls_key,
	.deprecated = true,
	.no_device = true,
};

static struct command check_tls_key_cmd = {
	.name = "check-tls-key",
	.help = "Validate NVMeoF TLS PSK (deprecated, use 'nvme keys check-tls-psk')",
	.fn = check_tls_key,
	.deprecated = true,
	.no_device = true,
};

static struct command tls_key_cmd = {
	.name = "tls-key",
	.help = "Manage NVMeoF TLS PSKs (deprecated, use 'nvme keys import/export/revoke')",
	.fn = tls_key,
	.deprecated = true,
	.no_device = true,
};

#endif /* CONFIG_FABRICS */

static struct command dir_receive_cmd = {
	.name = "dir-receive",
	.help = "Submit a Directive Receive command, return results (deprecated, use 'nvme dir receive')",
	.fn = dir_receive,
	.deprecated = true,
};

static struct command dir_send_cmd = {
	.name = "dir-send",
	.help = "Submit a Directive Send command, return results (deprecated, use 'nvme dir send')",
	.fn = dir_send,
	.deprecated = true,
};

static struct command io_mgmt_recv_cmd = {
	.name = "io-mgmt-recv",
	.help = "I/O Management Receive (deprecated, use 'nvme io-mgmt recv')",
	.fn = io_mgmt_recv,
	.deprecated = true,
};

static struct command io_mgmt_send_cmd = {
	.name = "io-mgmt-send",
	.help = "I/O Management Send (deprecated, use 'nvme io-mgmt send')",
	.fn = io_mgmt_send,
	.deprecated = true,
};

static struct command nmi_recv_cmd = {
	.name = "nvme-mi-recv",
	.help = "Submit a NVMe-MI Receive command, return results (deprecated, use 'nvme nvme-mi recv')",
	.fn = nmi_recv,
	.deprecated = true,
};

static struct command nmi_send_cmd = {
	.name = "nvme-mi-send",
	.help = "Submit a NVMe-MI Send command, return results (deprecated, use 'nvme nvme-mi send')",
	.fn = nmi_send,
	.deprecated = true,
};

static struct command *commands[] = {
	&id_ctrl_cmd,
	&id_ns_cmd,
	&id_ns_granularity_cmd,
	&id_ns_lba_format_cmd,
	&list_ns_cmd,
	&list_ctrl_cmd,
	&nvm_id_ctrl_cmd,
	&nvm_id_ns_cmd,
	&nvm_id_ns_lba_format_cmd,
	&primary_ctrl_caps_cmd,
	&list_secondary_ctrl_cmd,
	&cmd_set_independent_id_ns_cmd,
	&ns_descs_cmd,
	&id_nvmset_cmd,
	&id_uuid_cmd,
	&id_iocs_cmd,
	&id_domain_cmd,
	&id_endurance_grp_list_cmd,
	&create_ns_cmd,
	&delete_ns_cmd,
	&attach_ns_cmd,
	&detach_ns_cmd,
	&get_ns_id_cmd,
	&get_supported_log_pages_cmd,
	&get_telemetry_log_cmd,
	&get_fw_log_cmd,
	&get_changed_attach_ns_list_log_cmd,
	&get_smart_log_cmd,
	&get_ana_log_cmd,
	&get_error_log_cmd,
	&get_effects_log_cmd,
	&get_endurance_log_cmd,
	&get_pred_lat_per_nvmset_log_cmd,
	&get_pred_lat_event_agg_log_cmd,
	&get_persistent_event_log_cmd,
	&get_endurance_event_agg_log_cmd,
	&get_lba_status_log_cmd,
	&get_resv_notif_log_cmd,
	&get_boot_part_log_cmd,
	&get_phy_rx_eom_log_cmd,
	&self_test_log_cmd,
	&get_fid_support_effects_log_cmd,
	&get_mi_cmd_support_effects_log_cmd,
	&get_media_unit_stat_log_cmd,
	&get_supp_cap_config_log_cmd,
	&get_mgmt_addr_list_log_cmd,
	&get_rotational_media_info_log_cmd,
	&get_changed_alloc_ns_list_log_cmd,
	&get_dispersed_ns_participating_nss_log_cmd,
	&get_reachability_groups_log_cmd,
	&get_reachability_associations_log_cmd,
	&get_host_discovery_log_cmd,
	&get_ave_discovery_log_cmd,
	&get_pull_model_ddc_req_log_cmd,
	&get_power_measurement_log_cmd,
	&fw_commit_cmd,
	&fw_download_cmd,
	&sec_send_cmd,
	&sec_recv_cmd,
	&resv_acquire_cmd,
	&resv_register_cmd,
	&resv_release_cmd,
	&resv_report_cmd,
	&sanitize_log_cmd,
#ifdef CONFIG_FABRICS
	&gen_dhchap_key_cmd,
	&check_dhchap_key_cmd,
	&gen_tls_key_cmd,
	&check_tls_key_cmd,
	&tls_key_cmd,
#endif /* CONFIG_FABRICS */
	&dir_receive_cmd,
	&dir_send_cmd,
	&io_mgmt_recv_cmd,
	&io_mgmt_send_cmd,
	&nmi_recv_cmd,
	&nmi_send_cmd,
	NULL,
};

static void __shr_constructor register_group(void)
{
	plugin_add_group(&builtin, NULL, commands);
}

#endif /* CONFIG_DEPRECATED_CMDS */
