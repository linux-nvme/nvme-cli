// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * NVM-Express command line utility.
 *
 * Copyright (c) 2014-2015, Intel Corporation.
 *
 * Written by Keith Busch <kbusch@kernel.org>
 */

/*
 * The deprecated commands, which run the commands that replace them.
 */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <shared/compiler-attributes-util.h>

#include "argconfig.h"
#include "args.h"
#include "cleanup.h"
#include "plugin.h"

#ifdef CONFIG_DEPRECATED_CMDS

#ifdef CONFIG_FABRICS
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

	err = parse_cmdline(argc, argv, desc, opts);
	if (err)
		return err;

	if (argconfig_given(opts, &cfg.nqn))
		fprintf(stderr,
			"WARNING: '--nqn' is ignored, the DHHC-1 string carries the secret itself, which no NQN takes part in deriving\n");

	if (argconfig_given(opts, &cfg.secret)) {
		args[nargs++] = "--secret";
		args[nargs++] = cfg.secret;
	}
	if (argconfig_given(opts, &cfg.key_len)) {
		snprintf(key_len_buf, sizeof(key_len_buf), "%u", cfg.key_len);
		args[nargs++] = "--secret-length";
		args[nargs++] = key_len_buf;
	}
	if (argconfig_given(opts, &cfg.hmac)) {
		snprintf(hmac_buf, sizeof(hmac_buf), "%u", cfg.hmac);
		args[nargs++] = "--hmac";
		args[nargs++] = hmac_buf;
	}

	return run_replacement_command(plugin, acmd, acmd->replacement.command,
				       nargs, args);
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

	err = parse_cmdline(argc, argv, desc, opts);
	if (err)
		return err;

	if (argconfig_given(opts, &cfg.key)) {
		args[nargs++] = "--keydata";
		args[nargs++] = cfg.key;
	}

	return run_replacement_command(plugin, acmd, acmd->replacement.command,
				       nargs, args);
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
	const char *desc =
	    "Import, export or revoke NVMe TLS PSKs.\n"
	    "Deprecated; use 'nvme keys import', 'export' or 'revoke' instead.";
	const char *keyring = "Keyring of the PSKs.";
	const char *keytype = "Key type of the PSK to revoke.";
	const char *keyfile = "File to import the PSKs from or export them to.";
	const char *import = "Import the PSKs from the file.";
	const char *export = "Export the PSKs to the file.";
	const char *revoke = "Revoke the PSK of this identity.";

	char *args[7] = { argv[0] };
	const char *subcmd = NULL;
	int nargs = 1, err;

	struct config {
		char	*keyring;
		char	*keytype;
		char	*keyfile;
		bool	import;
		bool	export;
		char	*revoke;
	};

	struct config cfg = { 0 };

	NVME_ARGS(opts,
		  OPT_STR("keyring",	'k', &cfg.keyring,	keyring),
		  OPT_STR("keytype",	't', &cfg.keytype,	keytype),
		  OPT_STR("keyfile",	'f', &cfg.keyfile,	keyfile),
		  OPT_FLAG("import",	'i', &cfg.import,	import),
		  OPT_FLAG("export",	'e', &cfg.export,	export),
		  OPT_STR("revoke",	'r', &cfg.revoke,	revoke));

	err = parse_cmdline(argc, argv, desc, opts);
	if (err)
		return err;

	if (cfg.import + cfg.export + argconfig_given(opts, &cfg.revoke) > 1) {
		fprintf(stderr,
			"ERROR: only one of --import, --export, or --revoke may be given\n");
		return -EINVAL;
	}
	if (cfg.import)
		subcmd = "import";
	else if (cfg.export)
		subcmd = "export";
	else if (argconfig_given(opts, &cfg.revoke))
		subcmd = "revoke";

	if (!subcmd) {
		fprintf(stderr, "ERROR: 'tls-key' requires one of --import, --export, or --revoke\n");
		return -EINVAL;
	}

	if (argconfig_given(opts, &cfg.keyring)) {
		args[nargs++] = "--keyring";
		args[nargs++] = cfg.keyring;
	}

	if (!strcmp(subcmd, "revoke")) {
		if (argconfig_given(opts, &cfg.keytype)) {
			args[nargs++] = "--keytype";
			args[nargs++] = cfg.keytype;
		}
		args[nargs++] = "--identity";
		args[nargs++] = cfg.revoke;
	} else if (argconfig_given(opts, &cfg.keyfile)) {
		args[nargs++] = "--keyfile";
		args[nargs++] = cfg.keyfile;
	}

	return run_replacement_command(plugin, acmd, subcmd, nargs, args);
}
#endif /* CONFIG_FABRICS */

/*
 * A deprecated command which runs "nvme <p> <c>" instead, with function
 * f. The help names the replacement.
 */
#define DEPRECATED_FN(n, h, p, c, f, ...)				\
	(&(struct command){						\
		.name = n,						\
		.help = h " (deprecated, use 'nvme " p " " c "')",	\
		.fn = f,						\
		.deprecated = true,					\
		.replacement = { p, c },				\
		__VA_ARGS__						\
	})

/* A deprecated command which only forwards to "nvme <p> <c>" */
#define DEPRECATED(n, h, p, c)						\
	DEPRECATED_FN(n, h, p, c, run_replacement)

static struct command *commands[] = {
	DEPRECATED("id-ctrl", "Send NVMe Identify Controller", "id", "ctrl"),
	DEPRECATED("id-ns", "Send NVMe Identify Namespace, display structure",
		   "id", "ns"),
	DEPRECATED("id-ns-granularity",
		   "Send NVMe Identify Namespace Granularity List, display structure",
		   "id", "ns-granularity"),
	DEPRECATED("id-ns-lba-format",
		   "Send NVMe Identify Namespace for the specified LBA Format index, display structure",
		   "id", "ns-lba-format"),
	DEPRECATED("list-ns", "Send NVMe Identify List, display structure",
		   "id", "ns-list"),
	DEPRECATED("list-ctrl",
		   "Send NVMe Identify Controller List, display structure",
		   "id", "ctrl-list"),
	DEPRECATED("nvm-id-ctrl",
		   "Send NVMe Identify Controller NVM Command Set, display structure",
		   "id", "nvm-ctrl"),
	DEPRECATED("nvm-id-ns",
		   "Send NVMe Identify Namespace NVM Command Set, display structure",
		   "id", "nvm-ns"),
	DEPRECATED("nvm-id-ns-lba-format",
		   "Send NVMe Identify Namespace NVM Command Set for the specified LBA Format index, display structure",
		   "id", "nvm-ns-lba-format"),
	DEPRECATED("primary-ctrl-caps",
		   "Send NVMe Identify Primary Controller Capabilities",
		   "id", "primary-ctrl-caps"),
	DEPRECATED("list-secondary",
		   "List Secondary Controllers associated with a Primary Controller",
		   "id", "secondary-ctrl-list"),
	DEPRECATED("cmdset-ind-id-ns",
		   "I/O Command Set Independent Identify Namespace",
		   "id", "ns-ind"),
	DEPRECATED("ns-descs",
		   "Send NVMe Namespace Descriptor List, display structure",
		   "id", "ns-descs"),
	DEPRECATED("id-nvmset",
		   "Send NVMe Identify NVM Set List, display structure",
		   "id", "nvmset"),
	DEPRECATED("id-uuid", "Send NVMe Identify UUID List, display structure",
		   "id", "uuid"),
	DEPRECATED("id-iocs",
		   "Send NVMe Identify I/O Command Set, display structure",
		   "id", "iocs"),
	DEPRECATED("id-domain",
		   "Send NVMe Identify Domain List, display structure",
		   "id", "domain"),
	DEPRECATED("list-endgrp",
		   "Send NVMe Identify Endurance Group List, display structure",
		   "id", "endgrp-list"),
	DEPRECATED("create-ns",
		   "Creates a namespace with the provided parameters",
		   "ns", "create"),
	DEPRECATED("delete-ns", "Deletes a namespace from the controller",
		   "ns", "delete"),
	DEPRECATED("attach-ns",
		   "Attaches a namespace to requested controller(s)",
		   "ns", "attach"),
	DEPRECATED("detach-ns",
		   "Detaches a namespace from requested controller(s)",
		   "ns", "detach"),
	DEPRECATED("get-ns-id",
		   "Retrieve the namespace ID of opened block device",
		   "ns", "get-id"),
	DEPRECATED("supported-log-pages",
		   "Retrieve the Supported Log pages details, show it",
		   "log", "supported-pages"),
	DEPRECATED("telemetry-log", "Retrieve FW Telemetry log write to file",
		   "log", "telemetry"),
	DEPRECATED("fw-log", "Retrieve FW Log, show it", "log", "fw"),
	DEPRECATED("changed-ns-list-log",
		   "Retrieve Changed Attached Namespace List, show it",
		   "log", "changed-ns-list"),
	DEPRECATED("smart-log", "Retrieve SMART Log, show it", "log", "smart"),
	DEPRECATED("ana-log", "Retrieve ANA Log, show it", "log", "ana"),
	DEPRECATED("error-log", "Retrieve Error Log, show it", "log", "error"),
	DEPRECATED("effects-log", "Retrieve Command Effects Log, show it",
		   "log", "effects"),
	DEPRECATED("endurance-log", "Retrieve Endurance Group Log, show it",
		   "log", "endurance"),
	DEPRECATED("predictable-lat-log",
		   "Retrieve Predictable Latency per Nvmset Log, show it",
		   "log", "predictable-lat"),
	DEPRECATED("pred-lat-event-agg-log",
		   "Retrieve Predictable Latency Event Aggregate Log, show it",
		   "log", "pred-lat-event-agg"),
	DEPRECATED("persistent-event-log",
		   "Retrieve Persistent Event Log, show it",
		   "log", "persistent-event"),
	DEPRECATED("endurance-event-agg-log",
		   "Retrieve Endurance Group Event Aggregate Log, show it",
		   "log", "endurance-event-agg"),
	DEPRECATED("lba-status-log",
		   "Retrieve LBA Status Information Log, show it",
		   "log", "lba-status"),
	DEPRECATED("resv-notif-log",
		   "Retrieve Reservation Notification Log, show it",
		   "log", "resv-notif"),
	DEPRECATED("boot-part-log", "Retrieve Boot Partition Log, show it",
		   "log", "boot-part"),
	DEPRECATED("phy-rx-eom-log",
		   "Retrieve Physical Interface Receiver Eye Opening Measurement, show it",
		   "log", "phy-rx-eom"),
	DEPRECATED("self-test-log", "Retrieve the SELF-TEST Log, show it",
		   "log", "self-test"),
	DEPRECATED("fid-support-effects-log",
		   "Retrieve FID Support and Effects log and show it",
		   "log", "fid-support-effects"),
	DEPRECATED("mi-cmd-support-effects-log",
		   "Retrieve MI Command Support and Effects log and show it",
		   "log", "mi-cmd-support-effects"),
	DEPRECATED("media-unit-stat-log",
		   "Retrieve the configuration and wear of media units, show it",
		   "log", "media-unit-stat"),
	DEPRECATED("supported-cap-config-log",
		   "Retrieve the list of Supported Capacity Configuration Descriptors",
		   "log", "supported-cap-config"),
	DEPRECATED("mgmt-addr-list-log",
		   "Retrieve Management Address List Log, show it",
		   "log", "mgmt-addr-list"),
	DEPRECATED("rotational-media-info-log",
		   "Retrieve Rotational Media Information Log, show it",
		   "log", "rotational-media-info"),
	DEPRECATED("changed-alloc-ns-list-log",
		   "Retrieve Changed Allocated Namespace List, show it",
		   "log", "changed-alloc-ns-list"),
	DEPRECATED("dispersed-ns-participating-nss-log",
		   "Retrieve Dispersed Namespace Participating NVM Subsystems Log, show it",
		   "log", "dispersed-ns-participating-nss"),
	DEPRECATED("reachability-groups-log",
		   "Retrieve Reachability Groups Log, show it",
		   "log", "reachability-groups"),
	DEPRECATED("reachability-associations-log",
		   "Retrieve Reachability Associations Log, show it",
		   "log", "reachability-associations"),
	DEPRECATED("host-discovery-log", "Retrieve Host Discovery Log, show it",
		   "log", "host-discovery"),
	DEPRECATED("ave-discovery-log", "Retrieve AVE Discovery Log, show it",
		   "log", "ave-discovery"),
	DEPRECATED("pull-model-ddc-req-log",
		   "Retrieve Pull Model DDC Request Log, show it",
		   "log", "pull-model-ddc-req"),
	DEPRECATED("power-measurement-log",
		   "Retrieve Power Measurement Log, show it",
		   "log", "power-measurement"),
	DEPRECATED_FN("fw-commit",
		      "Verify and commit firmware to a specific slot (fw-activate in old version < 1.2)",
		      "fw", "commit", run_replacement, .alias = "fw-activate"),
	DEPRECATED("fw-download", "Download new firmware", "fw", "download"),
	DEPRECATED("security-send",
		   "Submit a Security Send command, return results",
		   "security", "send"),
	DEPRECATED("security-recv",
		   "Submit a Security Receive command, return results",
		   "security", "recv"),
	DEPRECATED("resv-acquire",
		   "Submit a Reservation Acquire, return results",
		   "resv", "acquire"),
	DEPRECATED("resv-register",
		   "Submit a Reservation Register, return results",
		   "resv", "register"),
	DEPRECATED("resv-release",
		   "Submit a Reservation Release, return results",
		   "resv", "release"),
	DEPRECATED("resv-report", "Submit a Reservation Report, return results",
		   "resv", "report"),
	DEPRECATED("sanitize-log", "Retrieve sanitize log, show it",
		   "log", "sanitize"),
#ifdef CONFIG_FABRICS
	DEPRECATED_FN("gen-dhchap-key",
		      "Generate NVMeoF DH-HMAC-CHAP host secret",
		      "keys", "gen-kxchap-secret", gen_dhchap_key,
		      .device = COMMAND_NO_DEVICE),
	DEPRECATED_FN("check-dhchap-key",
		      "Validate NVMeoF DH-HMAC-CHAP host secret",
		      "keys", "check-kxchap-secret", check_dhchap_key,
		      .device = COMMAND_NO_DEVICE),
	DEPRECATED_FN("gen-tls-key", "Generate NVMeoF TLS PSK",
		      "keys", "gen-tls-psk", run_replacement,
		      .device = COMMAND_NO_DEVICE),
	DEPRECATED_FN("check-tls-key", "Validate NVMeoF TLS PSK",
		      "keys", "check-tls-psk", run_replacement,
		      .device = COMMAND_NO_DEVICE),
	DEPRECATED_FN("tls-key", "Manage NVMeoF TLS PSKs",
		      "keys", "import/export/revoke", tls_key,
		      .device = COMMAND_NO_DEVICE),
#endif /* CONFIG_FABRICS */
	DEPRECATED("dir-receive",
		   "Submit a Directive Receive command, return results",
		   "dir", "receive"),
	DEPRECATED("dir-send",
		   "Submit a Directive Send command, return results",
		   "dir", "send"),
	DEPRECATED("io-mgmt-recv", "I/O Management Receive", "io-mgmt", "recv"),
	DEPRECATED("io-mgmt-send", "I/O Management Send", "io-mgmt", "send"),
	DEPRECATED("nvme-mi-recv",
		   "Submit a NVMe-MI Receive command, return results",
		   "nvme-mi", "recv"),
	DEPRECATED("nvme-mi-send",
		   "Submit a NVMe-MI Send command, return results",
		   "nvme-mi", "send"),
	NULL,
};

static void __shr_constructor register_group(void)
{
	plugin_add_group(&builtin, NULL, commands);
}

#endif /* CONFIG_DEPRECATED_CMDS */
