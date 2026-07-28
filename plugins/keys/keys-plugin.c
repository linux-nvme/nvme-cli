// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 SUSE Software Solutions
 *
 * Authors: Daniel Wagner <dwagner@suse.de>
 */

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

#include <base64.h>
#include <crc32.h>
#include <libnvme.h>

#include "fabrics.h"
#include "logging.h"
#include "nvme-print.h"
#include "nvme.h"

#define CREATE_CMD
#include "keys-plugin.h"

static int gen_dhchap(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc =
	    "Generate a DH-HMAC-CHAP host key usable for NVMe In-Band Authentication.";
	const char *secret =
	    "Optional secret (in hexadecimal characters) to be used to initialize the host key.";
	const char *key_len = "Length of the resulting key (32, 48, or 64 bytes).";
	const char *hmac =
	    "HMAC function to use for key transformation (0 = none, 1 = SHA-256, 2 = SHA-384, 3 = SHA-512).";
	const char *nqn = "Host NQN to use for key transformation.";

	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	__cleanup_free unsigned char *raw_secret = NULL;
	__cleanup_free char *hnqn = NULL;
	unsigned char key[68];
	char encoded_key[128];
	unsigned long crc = shr_crc32(0L, NULL, 0);
	int err = 0;

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

	err = parse_args(argc, argv, desc, opts);
	if (err)
		return err;

	err = nvme_create_global_ctx(&ctx);
	if (err)
		return err;

	if (cfg.hmac > 3) {
		nvme_show_error("Invalid HMAC identifier %u", cfg.hmac);
		return -EINVAL;
	}
	if (cfg.hmac > 0) {
		switch (cfg.hmac) {
		case 1:
			if (!cfg.key_len) {
				cfg.key_len = 32;
			} else if (cfg.key_len != 32) {
				nvme_show_error("Invalid key length %d for SHA(256)", cfg.key_len);
				return -EINVAL;
			}
			break;
		case 2:
			if (!cfg.key_len) {
				cfg.key_len = 48;
			} else if (cfg.key_len != 48) {
				nvme_show_error("Invalid key length %d for SHA(384)", cfg.key_len);
				return -EINVAL;
			}
			break;
		case 3:
			if (!cfg.key_len) {
				cfg.key_len = 64;
			} else if (cfg.key_len != 64) {
				nvme_show_error("Invalid key length %d for SHA(512)", cfg.key_len);
				return -EINVAL;
			}
			break;
		default:
			break;
		}
	} else if (!cfg.key_len) {
		cfg.key_len = 32;
	}

	err = libnvmf_create_raw_secret(ctx, cfg.secret, cfg.key_len, &raw_secret);
	if (err)
		return err;

	if (!cfg.nqn) {
		err = libnvmf_host_get_ids(ctx, NULL, NULL, &hnqn, NULL);
		if (err)
			return err;
		cfg.nqn = hnqn;
	}

	err = libnvmf_gen_dhchap_key(ctx, cfg.nqn, cfg.hmac,
		cfg.key_len, raw_secret, key);
	if (err)
		return err;

	crc = shr_crc32(crc, key, cfg.key_len);
	key[cfg.key_len++] = crc & 0xff;
	key[cfg.key_len++] = (crc >> 8) & 0xff;
	key[cfg.key_len++] = (crc >> 16) & 0xff;
	key[cfg.key_len++] = (crc >> 24) & 0xff;

	memset(encoded_key, 0, sizeof(encoded_key));
	shr_base64_encode(key, cfg.key_len, encoded_key);

	nvme_show_result("DHHC-1:%02x:%s:", cfg.hmac, encoded_key);
	return 0;
}

static int check_dhchap(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc =
	    "Check a DH-HMAC-CHAP host key for usability for NVMe In-Band Authentication.";
	const char *key = "DH-HMAC-CHAP key (in hexadecimal characters) to be validated.";

	unsigned char decoded_key[128];
	unsigned int decoded_len;
	uint32_t crc = shr_crc32(0L, NULL, 0);
	uint32_t key_crc;
	int err = 0, hmac;
	struct config {
		char	*key;
	};

	struct config cfg = {
		.key	= NULL,
	};

	NVME_ARGS(opts,
		  OPT_STR("key", 'k', &cfg.key, key));

	err = parse_args(argc, argv, desc, opts);
	if (err)
		return err;

	if (!cfg.key) {
		nvme_show_error("Key not specified");
		return -EINVAL;
	}

	if (sscanf(cfg.key, "DHHC-1:%02x:*s", &hmac) != 1) {
		nvme_show_error("Invalid key header '%s'", cfg.key);
		return -EINVAL;
	}
	switch (hmac) {
	case 0:
		break;
	case 1:
		if (strlen(cfg.key) != 59) {
			nvme_show_error("Invalid key length for SHA(256)");
			return -EINVAL;
		}
		break;
	case 2:
		if (strlen(cfg.key) != 83) {
			nvme_show_error("Invalid key length for SHA(384)");
			return -EINVAL;
		}
		break;
	case 3:
		if (strlen(cfg.key) != 103) {
			nvme_show_error("Invalid key length for SHA(512)");
			return -EINVAL;
		}
		break;
	default:
		nvme_show_error("Invalid HMAC identifier %d", hmac);
		return -EINVAL;
	}

	err = shr_base64_decode(cfg.key + 10, strlen(cfg.key) - 11,
				 decoded_key);
	if (err < 0) {
		nvme_show_error("Base64 decoding failed, error %d");
		return err;
	}
	decoded_len = err;
	if (decoded_len < 32) {
		nvme_show_error("Base64 decoding failed (%s, size %u)", cfg.key + 10, decoded_len);
		return -EINVAL;
	}
	decoded_len -= 4;
	if (decoded_len != 32 && decoded_len != 48 && decoded_len != 64) {
		nvme_show_error("Invalid key length %d", decoded_len);
		return -EINVAL;
	}
	crc = shr_crc32(crc, decoded_key, decoded_len);
	key_crc = ((uint32_t)decoded_key[decoded_len]) |
		   ((uint32_t)decoded_key[decoded_len + 1] << 8) |
		   ((uint32_t)decoded_key[decoded_len + 2] << 16) |
		   ((uint32_t)decoded_key[decoded_len + 3] << 24);
	if (key_crc != crc) {
		nvme_show_error("CRC mismatch (key %08x, crc %08x)", key_crc, crc);
		return -EINVAL;
	}
	nvme_show_result("Key is valid (HMAC %d, length %d, CRC %08x)", hmac, decoded_len, crc);
	return 0;
}

static int append_keyfile(struct libnvme_global_ctx *ctx, const char *keyring,
		long id, const char *keyfile)
{
	__cleanup_free unsigned char *key_data = NULL;
	__cleanup_free char *exported_key = NULL;
	__cleanup_free char *identity = NULL;
	__cleanup_file FILE *fd = NULL;
	int err, ver, hmac, key_len;
	mode_t old_umask;
	long kr_id;
	char type;

	err = libnvmf_lookup_keyring(ctx, keyring, &kr_id);
	if (err) {
		nvme_show_error("Failed to lookup keyring '%s', %s",
				keyring, libnvme_strerror(-err));
		return err;
	}

	identity = libnvmf_describe_key_serial(ctx, id);
	if (!identity) {
		nvme_show_error("Failed to get identity info");
		return -EINVAL;
	}

	if (sscanf(identity, "NVMe%01d%c%02d %*s", &ver, &type, &hmac) != 3) {
		nvme_show_error("Failed to parse identity\n");
		return -EINVAL;
	}

	err = libnvmf_read_key(ctx, kr_id, id, &key_len, &key_data);
	if (err) {
		nvme_show_error("Failed to read back derive TLS PSK, %s",
			libnvme_strerror(-err));
		return err;
	}

	err = libnvmf_export_tls_key_versioned(ctx, ver, hmac, key_data,
					    key_len, &exported_key);
	if (err) {
		nvme_show_error("Failed to export key, %s",
			libnvme_strerror(-err));
		return err;
	}

	old_umask = umask(0);

	fd = fopen(keyfile, "a");
	if (!fd) {
		nvme_show_error("Failed to open '%s', %s",
				keyfile, libnvme_strerror(errno));
		err = -errno;
		goto out;
	}

	err = fprintf(fd, "%s %s\n", identity, exported_key);
	if (err < 0) {
		nvme_show_error("Failed to append key to '%s', %s",
				keyfile, libnvme_strerror(errno));
		err = -errno;
	} else {
		err = 0;
	}

out:
	chmod(keyfile, 0600);
	umask(old_umask);

	return err;
}

static int gen_tls(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc = "Generate a TLS key in NVMe PSK Interchange format.";
	const char *secret =
	    "Optional secret (in hexadecimal characters) to be used for the TLS key.";
	const char *hmac = "HMAC function to use for the retained key (1 = SHA-256, 2 = SHA-384).";
	const char *version = "TLS identity version to use (0 = NVMe TCP 1.0c, 1 = NVMe TCP 2.0";
	const char *hostnqn = "Host NQN for the retained key.";
	const char *subsysnqn = "Subsystem NQN for the retained key.";
	const char *keyring = "Keyring for the retained key.";
	const char *keytype = "Key type of the retained key.";
	const char *insert = "Insert retained key into the keyring.";
	const char *keyfile = "Update key file with the derive TLS PSK.";
	const char *compat = "Use non-RFC 8446 compliant algorithm for deriving TLS PSK for older implementations";

	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	__cleanup_free unsigned char *raw_secret = NULL;
	__cleanup_free char *encoded_key = NULL;
	__cleanup_free char *hnqn = NULL;
	int key_len = 32;
	int err;
	long tls_key;

	struct config {
		char		*keyring;
		char		*keytype;
		char		*hostnqn;
		char		*subsysnqn;
		char		*secret;
		char		*keyfile;
		unsigned char	hmac;
		unsigned char	version;
		bool		insert;
		bool		compat;
	};

	struct config cfg = {
		.keyring	= ".nvme",
		.keytype	= "psk",
		.hostnqn	= NULL,
		.subsysnqn	= NULL,
		.secret		= NULL,
		.keyfile	= NULL,
		.hmac		= 1,
		.version	= 0,
		.insert		= false,
		.compat		= false,
	};

	NVME_ARGS(opts,
		  OPT_STR("keyring",	'k', &cfg.keyring,	keyring),
		  OPT_STR("keytype",	't', &cfg.keytype,	keytype),
		  OPT_STR("hostnqn",	'n', &cfg.hostnqn,	hostnqn),
		  OPT_STR("subsysnqn",	'c', &cfg.subsysnqn,	subsysnqn),
		  OPT_STR("secret",	's', &cfg.secret,	secret),
		  OPT_STR("keyfile",	'f', &cfg.keyfile,	keyfile),
		  OPT_BYTE("hmac",	'm', &cfg.hmac,		hmac),
		  OPT_BYTE("identity",	'I', &cfg.version,	version),
		  OPT_FLAG("insert",	'i', &cfg.insert,	insert),
		  OPT_FLAG("compat",	'C', &cfg.compat,	compat));

	err = parse_args(argc, argv, desc, opts);
	if (err)
		return err;
	if (cfg.hmac < 1 || cfg.hmac > 2) {
		nvme_show_error("Invalid HMAC identifier %u", cfg.hmac);
		return -EINVAL;
	}
	if (cfg.version > 1) {
		nvme_show_error("Invalid TLS identity version %u",
				cfg.version);
		return -EINVAL;
	}
	if (cfg.insert) {
		if (!cfg.subsysnqn) {
			nvme_show_error("No subsystem NQN specified");
			return -EINVAL;
		}
	}
	if (cfg.hmac == 2)
		key_len = 48;

	err = nvme_create_global_ctx(&ctx);
	if (err)
		return err;

	err = libnvmf_create_raw_secret(ctx, cfg.secret, key_len, &raw_secret);
	if (err)
		return err;

	err = libnvmf_export_tls_key(ctx, raw_secret, key_len, &encoded_key);
	if (err) {
		nvme_show_error("Failed to export key, %s", libnvme_strerror(-err));
		return err;
	}
	nvme_show_result("%s", encoded_key);

	if (cfg.insert) {
		if (!cfg.hostnqn) {
			err = libnvmf_host_get_ids(ctx, NULL, NULL, &hnqn, NULL);
			if (err)
				return err;
			cfg.hostnqn = hnqn;
		}

		if (cfg.compat)
			err = libnvmf_insert_tls_key_compat(ctx, cfg.keyring,
				cfg.keytype, cfg.hostnqn,
				cfg.subsysnqn, cfg.version,
				cfg.hmac, raw_secret, key_len, &tls_key);
		else
			err = libnvmf_insert_tls_key_versioned(ctx, cfg.keyring,
				cfg.keytype, cfg.hostnqn,
				cfg.subsysnqn, cfg.version,
				cfg.hmac, raw_secret, key_len, &tls_key);
		if (err) {
			nvme_show_error("Failed to insert key, error %d");
			return err;
		}

		nvme_show_result("Inserted TLS key %08x", (unsigned int)tls_key);

		if (cfg.keyfile) {
			err = append_keyfile(ctx, cfg.keyring,
				tls_key, cfg.keyfile);
			if (err)
				return err;
		}
	}

	return 0;
}

static int check_tls(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc = "Check a TLS key for NVMe PSK Interchange format.\n";
	const char *keydata = "TLS key (in PSK Interchange format) to be validated.";
	const char *identity = "TLS identity version to use (0 = NVMe TCP 1.0c, 1 = NVMe TCP 2.0)";
	const char *hostnqn = "Host NQN for the retained key.";
	const char *subsysnqn = "Subsystem NQN for the retained key.";
	const char *keyring = "Keyring for the retained key.";
	const char *keytype = "Key type of the retained key.";
	const char *insert = "Insert retained key into the keyring.";
	const char *keyfile = "Update key file with the derive TLS PSK.";
	const char *compat = "Use non-RFC 8446 compliant algorithm for checking TLS PSK for older implementations.";

	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	__cleanup_free unsigned char *decoded_key = NULL;
	__cleanup_free char *hnqn = NULL;
	int decoded_len, err = 0;
	unsigned int hmac;
	long tls_key;
	struct config {
		char		*keyring;
		char		*keytype;
		char		*hostnqn;
		char		*subsysnqn;
		char		*keydata;
		char		*keyfile;
		unsigned char	identity;
		bool		insert;
		bool		compat;
	};

	struct config cfg = {
		.keyring	= ".nvme",
		.keytype	= "psk",
		.hostnqn	= NULL,
		.subsysnqn	= NULL,
		.keydata	= NULL,
		.keyfile	= NULL,
		.identity	= 0,
		.insert		= false,
		.compat		= false,
	};

	NVME_ARGS(opts,
		  OPT_STR("keyring",	'k', &cfg.keyring,	keyring),
		  OPT_STR("keytype",	't', &cfg.keytype,	keytype),
		  OPT_STR("hostnqn",	'n', &cfg.hostnqn,	hostnqn),
		  OPT_STR("subsysnqn",	'c', &cfg.subsysnqn,	subsysnqn),
		  OPT_STR("keydata",	'd', &cfg.keydata,	keydata),
		  OPT_STR("keyfile",	'f', &cfg.keyfile,	keyfile),
		  OPT_BYTE("identity",	'I', &cfg.identity,	identity),
		  OPT_FLAG("insert",	'i', &cfg.insert,	insert),
		  OPT_FLAG("compat",	'C', &cfg.compat,	compat));

	err = parse_args(argc, argv, desc, opts);
	if (err)
		return err;

	if (!cfg.keydata) {
		nvme_show_error("No key data");
		return -EINVAL;
	}
	if (cfg.identity > 1) {
		nvme_show_error("Invalid TLS identity version %u",
				cfg.identity);
		return -EINVAL;
	}

	err = nvme_create_global_ctx(&ctx);
	if (err) {
		nvme_show_error("Failed to create global context");
		return err;
	}
	libnvme_set_logging_level(ctx, log_level, false, false);

	err = libnvmf_import_tls_key(ctx, cfg.keydata, &decoded_len,
		&hmac, &decoded_key);
	if (err) {
		nvme_show_error("Key decoding failed, error %d\n");
		return err;
	}

	if (cfg.subsysnqn) {
		if (!cfg.hostnqn) {
			err = libnvmf_host_get_ids(ctx, NULL, NULL, &hnqn, NULL);
			if (err)
				return err;
			cfg.hostnqn = hnqn;
		}
	} else {
		nvme_show_error("Need to specify a subsystem NQN");
		return -EINVAL;
	}

	if (cfg.insert) {
		if (cfg.compat)
			err = libnvmf_insert_tls_key_compat(ctx, cfg.keyring,
				cfg.keytype, cfg.hostnqn,
				cfg.subsysnqn, cfg.identity,
				hmac, decoded_key, decoded_len,
				&tls_key);
		else
			err = libnvmf_insert_tls_key_versioned(ctx, cfg.keyring,
				cfg.keytype, cfg.hostnqn,
				cfg.subsysnqn, cfg.identity,
				hmac, decoded_key, decoded_len,
				&tls_key);
		if (err) {
			nvme_show_error("Failed to insert key, error %d");
			return err;
		}
		nvme_show_result("Inserted TLS key %08x", (unsigned int)tls_key);

		if (cfg.keyfile) {
			err = append_keyfile(ctx, cfg.keyring,
				tls_key, cfg.keyfile);
			if (err)
				return err;
		}
	} else {
		__cleanup_free char *tls_id = NULL;

		if (cfg.compat)
			err = libnvmf_generate_tls_key_identity_compat(ctx,
				cfg.hostnqn, cfg.subsysnqn, cfg.identity,
				hmac, decoded_key, decoded_len,
				&tls_id);
		else
			err = libnvmf_generate_tls_key_identity(ctx,
				cfg.hostnqn, cfg.subsysnqn, cfg.identity,
				hmac, decoded_key, decoded_len,
				&tls_id);
		if (err) {
			nvme_show_error("Failed to generate identity, error %d",
					err);
			return err;
		}
		nvme_show_result("%s", tls_id);
	}
	return 0;
}

static void __scan_tls_key(struct libnvme_global_ctx *ctx, long keyring_id,
		long key_id, char *desc, int desc_len, void *data)
{
	FILE *fd = data;
	__cleanup_free unsigned char *key_data = NULL;
	__cleanup_free char *encoded_key = NULL;
	int key_len;
	int ver, hmac;
	char type;
	int err;

	err = libnvmf_read_key(ctx, keyring_id, key_id, &key_len, &key_data);
	if (err)
		return;

	if (sscanf(desc, "NVMe%01d%c%02d %*s", &ver, &type, &hmac) != 3)
		return;

	err = libnvmf_export_tls_key_versioned(ctx, ver, hmac, key_data, key_len,
		&encoded_key);
	if (err)
		return;
	fprintf(fd, "%s %s\n", desc, encoded_key);
}

static int key_export(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc = "Export NVMeoF TLS PSKs from a keyring.\n";
	const char *keyring = "Keyring to export the retained keys from.";
	const char *keyfile = "File to write the exported keys to (default: stdout).";

	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	__cleanup_file FILE *fd = NULL;
	mode_t old_umask = 0;
	int err = 0;

	struct config {
		char *keyring;
		char *keyfile;
	};

	struct config cfg = {
		.keyring = ".nvme",
		.keyfile = NULL,
	};

	NVME_ARGS(opts,
		  OPT_STR("keyring", 'k', &cfg.keyring, keyring),
		  OPT_STR("keyfile", 'f', &cfg.keyfile, keyfile));

	err = parse_args(argc, argv, desc, opts);
	if (err)
		return err;

	err = nvme_create_global_ctx(&ctx);
	if (err) {
		nvme_show_error("Failed to create global context");
		return err;
	}
	libnvme_set_logging_level(ctx, log_level, false, false);

	if (cfg.keyfile) {
		old_umask = umask(0);

		fd = fopen(cfg.keyfile, "w");
		if (!fd) {
			nvme_show_error("Cannot open keyfile %s, error %d",
					cfg.keyfile, errno);
			umask(old_umask);
			return -errno;
		}
	} else {
		fd = freopen(NULL, "w", stdout);
	}

	err = libnvmf_scan_tls_keys(ctx, cfg.keyring, __scan_tls_key, fd);
	if (err < 0) {
		nvme_show_error("Export of TLS keys failed with '%s'",
			libnvme_strerror(-err));
		return err;
	}

	nvme_show_verbose_info("exporting to %s", cfg.keyfile);

	if (cfg.keyfile) {
		umask(old_umask);
		chmod(cfg.keyfile, 0600);
	}

	return 0;
}

static int import_key(struct libnvme_global_ctx *ctx, const char *keyring,
		FILE *fd)
{
	long keyring_id, key;
	char tls_str[512];
	char *tls_key;
	unsigned char *psk;
	unsigned int hmac;
	int linenum = -1, key_len;
	int err;

	err = libnvmf_lookup_keyring(ctx, keyring, &keyring_id);
	if (err) {
		nvme_show_error("Invalid keyring '%s'", keyring);
		return err;
	}

	while (fgets(tls_str, 512, fd)) {
		linenum++;
		tls_key = strrchr(tls_str, ' ');
		if (!tls_key) {
			nvme_show_error("Parse error in line %d",
					linenum);
			continue;
		}
		*tls_key = '\0';
		tls_key++;
		tls_key[strcspn(tls_key, "\n")] = 0;
		err = libnvmf_import_tls_key(ctx, tls_key, &key_len, &hmac, &psk);
		if (err) {
			nvme_show_error("Failed to import key in line %d",
					linenum);
			continue;
		}
		err = libnvmf_update_key(ctx, keyring_id, "psk", tls_str,
				psk, key_len, &key);
		if (err)
			continue;
		free(psk);
	}

	return 0;
}

static int key_import(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc = "Import NVMeoF TLS PSKs into a keyring.\n";
	const char *keyring = "Keyring to import the keys into.";
	const char *keyfile = "File to read the keys from (default: stdin).";

	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	__cleanup_file FILE *fd = NULL;
	int err = 0;

	struct config {
		char *keyring;
		char *keyfile;
	};

	struct config cfg = {
		.keyring = ".nvme",
		.keyfile = NULL,
	};

	NVME_ARGS(opts,
		  OPT_STR("keyring", 'k', &cfg.keyring, keyring),
		  OPT_STR("keyfile", 'f', &cfg.keyfile, keyfile));

	err = parse_args(argc, argv, desc, opts);
	if (err)
		return err;

	err = nvme_create_global_ctx(&ctx);
	if (err) {
		nvme_show_error("Failed to create global context");
		return err;
	}
	libnvme_set_logging_level(ctx, log_level, false, false);

	if (cfg.keyfile) {
		fd = fopen(cfg.keyfile, "r");
		if (!fd) {
			nvme_show_error("Cannot open keyfile %s, error %d",
					cfg.keyfile, errno);
			return -errno;
		}
	} else {
		fd = freopen(NULL, "r", stdin);
	}

	err = import_key(ctx, cfg.keyring, fd);
	if (err) {
		nvme_show_error("Import of TLS keys failed with '%s'",
				libnvme_strerror(err));
		return err;
	}

	nvme_show_verbose_info("importing from %s", cfg.keyfile);

	return 0;
}

static int key_revoke(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc = "Revoke an NVMeoF TLS PSK from a keyring.\n";
	const char *keyring = "Keyring to revoke the key from.";
	const char *keytype = "Key type of the key to revoke.";
	const char *identity = "Identity (description) of the key to revoke.";

	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	int err = 0;

	struct config {
		char *keyring;
		char *keytype;
		char *identity;
	};

	struct config cfg = {
		.keyring = ".nvme",
		.keytype = "psk",
		.identity = NULL,
	};

	NVME_ARGS(opts,
		  OPT_STR("keyring", 'k', &cfg.keyring, keyring),
		  OPT_STR("keytype", 't', &cfg.keytype, keytype),
		  OPT_STR("identity", 'i', &cfg.identity, identity));

	err = parse_args(argc, argv, desc, opts);
	if (err)
		return err;

	if (!cfg.identity) {
		nvme_show_error("Must specify --identity");
		return -EINVAL;
	}

	err = nvme_create_global_ctx(&ctx);
	if (err) {
		nvme_show_error("Failed to create global context");
		return err;
	}
	libnvme_set_logging_level(ctx, log_level, false, false);

	err = libnvmf_revoke_tls_key(ctx, cfg.keyring, cfg.keytype, cfg.identity);
	if (err) {
		nvme_show_error("Failed to revoke key '%s'",
				libnvme_strerror(err));
		return err;
	}

	nvme_show_verbose_info("revoking key");

	return 0;
}
