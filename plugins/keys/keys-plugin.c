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

static int read_key_value(const char *inline_value, char **out)
{
	char line[512];

	if (inline_value) {
		*out = strdup(inline_value);
		return *out ? 0 : -ENOMEM;
	}

	if (!fgets(line, sizeof(line), stdin))
		return -EINVAL;
	line[strcspn(line, "\n")] = '\0';

	*out = strdup(line);
	return *out ? 0 : -ENOMEM;
}

static int gen_kxchap(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc =
	    "Generate a KX-HMAC-CHAP host key usable for NVMe In-Band Authentication.";
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

	err = libnvmf_gen_kxchap_key(ctx, cfg.nqn, cfg.hmac,
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

static int validate_kxchap_key(const char *key, int *hmac_out,
		unsigned char *decoded_key, int *decoded_len_out, uint32_t *crc_out)
{
	uint32_t crc = shr_crc32(0L, NULL, 0);
	uint32_t key_crc;
	int decoded_len, hmac, err;

	if (sscanf(key, "DHHC-1:%02x:%*s", &hmac) != 1) {
		nvme_show_error("Invalid key header '%s'", key);
		return -EINVAL;
	}
	switch (hmac) {
	case 0:
		break;
	case 1:
		if (strlen(key) != 59) {
			nvme_show_error("Invalid key length for SHA(256)");
			return -EINVAL;
		}
		break;
	case 2:
		if (strlen(key) != 83) {
			nvme_show_error("Invalid key length for SHA(384)");
			return -EINVAL;
		}
		break;
	case 3:
		if (strlen(key) != 103) {
			nvme_show_error("Invalid key length for SHA(512)");
			return -EINVAL;
		}
		break;
	default:
		nvme_show_error("Invalid HMAC identifier %d", hmac);
		return -EINVAL;
	}

	if (key[strlen(key) - 1] != ':') {
 		nvme_show_error("Invalid key format (missing trailing ':')");
 		return -EINVAL;
 	}

	err = shr_base64_decode(key + 10, strlen(key) - 11, decoded_key);
	if (err < 0) {
		nvme_show_error("Base64 decoding failed, error %d", err);
		return err;
	}
	decoded_len = err;
	if (decoded_len < 32) {
		nvme_show_error("Base64 decoding failed (%s, size %u)", key + 10, decoded_len);
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

	*hmac_out = hmac;
	*decoded_len_out = decoded_len;
	*crc_out = crc;
	return 0;
}

static int check_kxchap(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc =
	    "Check a KX-HMAC-CHAP host key for usability for NVMe In-Band Authentication,\n"
	    "and, if --identity is given, check whether it is already loaded into a keyring.";
	const char *keydata = "KX-HMAC-CHAP key (in DHHC-1 interchange format) to be validated. Reads from stdin if not given.";
	const char *keyring = "Keyring to check for an already loaded key.";
	const char *keytype = "Key type of the key to look up.";
	const char *identity = "Identity to look up in the keyring to check if the key is already loaded.";

	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	__cleanup_free char *key = NULL;
	__cleanup_free unsigned char *stored = NULL;
	unsigned char decoded_key[128];
	long keyring_id = 0, key_id = 0;
	int decoded_len, hmac, err, stored_len;
	uint32_t crc;
	struct config {
		char	*keydata;
		char	*keyring;
		char	*keytype;
		char	*identity;
	};

	struct config cfg = {
		.keydata	= NULL,
		.keyring	= ".nvme",
		.keytype	= "kxchap",
		.identity	= NULL,
	};

	NVME_ARGS(opts,
		  OPT_STR("keydata",	'd', &cfg.keydata,	keydata),
		  OPT_STR("keyring",	'k', &cfg.keyring,	keyring),
		  OPT_STR("keytype",	't', &cfg.keytype,	keytype),
		  OPT_STR("identity",	'i', &cfg.identity,	identity));

	err = parse_args(argc, argv, desc, opts);
	if (err)
		return err;

	err = read_key_value(cfg.keydata, &key);
	if (err) {
		nvme_show_error("No key data");
		return err;
	}

	err = validate_kxchap_key(key, &hmac, decoded_key, &decoded_len, &crc);
	if (err)
		return err;

	nvme_show_result("Key is valid (HMAC %d, length %d, CRC %08x)", hmac, decoded_len, crc);

	if (!cfg.identity)
		return 0;

	err = nvme_create_global_ctx(&ctx);
	if (err) {
		nvme_show_error("Failed to create global context");
		return err;
	}
	libnvme_set_logging_level(ctx, log_level, false, false);

	err = libnvmf_lookup_keyring(ctx, cfg.keyring, &keyring_id);
	if (err) {
		nvme_show_error("Failed to lookup keyring '%s', %s",
				cfg.keyring, libnvme_strerror(-err));
		return err;
	}

	err = libnvmf_set_keyring(ctx, keyring_id);
	if (err) {
		nvme_show_error("Failed to link keyring '%s', %s",
				cfg.keyring, libnvme_strerror(-err));
		return err;
	}

	err = libnvmf_lookup_key(ctx, cfg.keytype, cfg.identity, &key_id);
	if (err) {
		nvme_show_result("Key is not loaded for identity '%s'", cfg.identity);
		return 0;
	}

	err = libnvmf_read_key(ctx, keyring_id, key_id, &stored_len, &stored);
	if (err) {
		nvme_show_error("Failed to read back loaded key, %s",
				libnvme_strerror(-err));
		return err;
	}

	if ((size_t)stored_len == strlen(key) && !memcmp(stored, key, stored_len))
		nvme_show_result("Key is loaded (serial %08x) and matches", (unsigned int)key_id);
	else
		nvme_show_result("Key is loaded (serial %08x) but differs", (unsigned int)key_id);

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

static int do_insert_tls_key(struct libnvme_global_ctx *ctx, const char *keyring,
		const char *keytype, const char *hostnqn, const char *subsysnqn,
		int identity, int hmac, unsigned char *key_data, int key_len,
		bool compat, const char *keyfile, long *tls_key)
{
	int err;

	if (compat)
		err = libnvmf_insert_tls_key_compat(ctx, keyring, keytype, hostnqn,
			subsysnqn, identity, hmac, key_data, key_len, tls_key);
	else
		err = libnvmf_insert_tls_key_versioned(ctx, keyring, keytype, hostnqn,
			subsysnqn, identity, hmac, key_data, key_len, tls_key);
	if (err) {
		nvme_show_error("Failed to insert key, %s", libnvme_strerror(-err));
		return err;
	}
	nvme_show_result("Inserted TLS key %08x", (unsigned int)*tls_key);

	if (keyfile) {
		err = append_keyfile(ctx, keyring, *tls_key, keyfile);
		if (err)
			return err;
	}

	return 0;
}

static int gen_tls(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc = "Generate a TLS key in NVMe PSK Interchange format.";
	const char *secret =
	    "Optional secret (in hexadecimal characters) to be used for the TLS key.";
	const char *hmac = "HMAC function to use for the retained key (1 = SHA-256, 2 = SHA-384).";
	const char *version = "TLS identity version to use (0 = NVMe TCP 1.0c, 1 = NVMe TCP 2.0)";
	const char *hostnqn = "Host NQN for the retained key.";
	const char *subsysnqn = "Subsystem NQN for the retained key.";
	const char *keyring = "Keyring for the retained key.";
	const char *keytype = "Key type of the retained key.";
	const char *insert = "Insert retained key into the keyring.";
	const char *keyfile = "Update key file with the derived TLS PSK.";
	const char *compat = "Use non-RFC 8446 compliant algorithm for deriving TLS PSK for older implementations.";

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

		err = do_insert_tls_key(ctx, cfg.keyring, cfg.keytype,
				cfg.hostnqn, cfg.subsysnqn, cfg.version,
				cfg.hmac, raw_secret, key_len, cfg.compat,
				cfg.keyfile, &tls_key);
		if (err)
			return err;
	}

	return 0;
}

static int check_tls(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc =
	    "Check a TLS key for NVMe PSK Interchange format, and, if a subsystem\n"
	    "NQN is given, check whether the corresponding retained key is already\n"
	    "loaded into a keyring.";
	const char *keydata = "TLS key (in PSK Interchange format) to be validated. Reads from stdin if not given.";
	const char *identity = "TLS identity version to use (0 = NVMe TCP 1.0c, 1 = NVMe TCP 2.0)";
	const char *hostnqn = "Host NQN to use when checking whether the key is already loaded.";
	const char *subsysnqn = "Subsystem NQN to use when checking whether the key is already loaded.";
	const char *keyring = "Keyring to check for an already loaded key.";
	const char *keytype = "Key type of the key to look up.";
	const char *compat = "Use non-RFC 8446 compliant algorithm for checking TLS PSK for older implementations.";

	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	__cleanup_free char *key_value = NULL;
	__cleanup_free unsigned char *decoded_key = NULL;
	__cleanup_free char *hnqn = NULL;
	__cleanup_free char *tls_id = NULL;
	int decoded_len, err = 0;
	unsigned int hmac;
	long keyring_id, key_id;
	struct config {
		char		*keyring;
		char		*keytype;
		char		*hostnqn;
		char		*subsysnqn;
		char		*keydata;
		unsigned char	identity;
		bool		compat;
	};

	struct config cfg = {
		.keyring	= ".nvme",
		.keytype	= "psk",
		.hostnqn	= NULL,
		.subsysnqn	= NULL,
		.keydata	= NULL,
		.identity	= 0,
		.compat		= false,
	};

	NVME_ARGS(opts,
		  OPT_STR("keyring",	'k', &cfg.keyring,	keyring),
		  OPT_STR("keytype",	't', &cfg.keytype,	keytype),
		  OPT_STR("hostnqn",	'n', &cfg.hostnqn,	hostnqn),
		  OPT_STR("subsysnqn",	'c', &cfg.subsysnqn,	subsysnqn),
		  OPT_STR("keydata",	'd', &cfg.keydata,	keydata),
		  OPT_BYTE("identity",	'I', &cfg.identity,	identity),
		  OPT_FLAG("compat",	'C', &cfg.compat,	compat));

	err = parse_args(argc, argv, desc, opts);
	if (err)
		return err;

	if (cfg.identity > 1) {
		nvme_show_error("Invalid TLS identity version %u",
				cfg.identity);
		return -EINVAL;
	}

	err = read_key_value(cfg.keydata, &key_value);
	if (err) {
		nvme_show_error("No key data");
		return err;
	}

	err = nvme_create_global_ctx(&ctx);
	if (err) {
		nvme_show_error("Failed to create global context");
		return err;
	}
	libnvme_set_logging_level(ctx, log_level, false, false);

	err = libnvmf_import_tls_key(ctx, key_value, &decoded_len,
		&hmac, &decoded_key);
	if (err) {
		nvme_show_error("Key decoding failed, %s", libnvme_strerror(-err));
		return err;
	}
	nvme_show_result("Key is valid (HMAC %u, length %d)", hmac, decoded_len);

	if (!cfg.subsysnqn)
		return 0;

	if (!cfg.hostnqn) {
		err = libnvmf_host_get_ids(ctx, NULL, NULL, &hnqn, NULL);
		if (err)
			return err;
		cfg.hostnqn = hnqn;
	}

	if (cfg.compat)
		err = libnvmf_generate_tls_key_identity_compat(ctx,
			cfg.hostnqn, cfg.subsysnqn, cfg.identity,
			hmac, decoded_key, decoded_len, &tls_id);
	else
		err = libnvmf_generate_tls_key_identity(ctx,
			cfg.hostnqn, cfg.subsysnqn, cfg.identity,
			hmac, decoded_key, decoded_len, &tls_id);
	if (err) {
		nvme_show_error("Failed to generate identity, %s",
				libnvme_strerror(-err));
		return err;
	}
	nvme_show_result("%s", tls_id);

	err = libnvmf_lookup_keyring(ctx, cfg.keyring, &keyring_id);
	if (err) {
		nvme_show_error("Failed to lookup keyring '%s', %s",
				cfg.keyring, libnvme_strerror(-err));
		return err;
	}

	err = libnvmf_set_keyring(ctx, keyring_id);
	if (err) {
		nvme_show_error("Failed to link keyring '%s', %s",
				cfg.keyring, libnvme_strerror(-err));
		return err;
	}

	err = libnvmf_lookup_key(ctx, cfg.keytype, tls_id, &key_id);
	if (err) {
		nvme_show_result("Key is not loaded");
		return 0;
	}

	nvme_show_result("Key is loaded (serial %08x)", (unsigned int)key_id);
	return 0;
}

static int insert_tls(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc = "Insert a TLS key (in NVMe PSK Interchange format) into a keyring.\n";
	const char *keydata = "TLS key (in PSK Interchange format) to be inserted. Reads from stdin if not given.";
	const char *identity = "TLS identity version to use (0 = NVMe TCP 1.0c, 1 = NVMe TCP 2.0)";
	const char *hostnqn = "Host NQN for the retained key.";
	const char *subsysnqn = "Subsystem NQN for the retained key.";
	const char *keyring = "Keyring for the retained key.";
	const char *keytype = "Key type of the retained key.";
	const char *keyfile = "Append the derived TLS PSK to keyfile.";
	const char *compat = "Use non-RFC 8446 compliant algorithm for older implementations.";

	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	__cleanup_free char *key_value = NULL;
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
		  OPT_FLAG("compat",	'C', &cfg.compat,	compat));

	err = parse_args(argc, argv, desc, opts);
	if (err)
		return err;

	if (!cfg.subsysnqn) {
		nvme_show_error("Need to specify a subsystem NQN");
		return -EINVAL;
	}
	if (cfg.identity > 1) {
		nvme_show_error("Invalid TLS identity version %u",
				cfg.identity);
		return -EINVAL;
	}

	err = read_key_value(cfg.keydata, &key_value);
	if (err) {
		nvme_show_error("No key data");
		return err;
	}

	err = nvme_create_global_ctx(&ctx);
	if (err) {
		nvme_show_error("Failed to create global context");
		return err;
	}
	libnvme_set_logging_level(ctx, log_level, false, false);

	err = libnvmf_import_tls_key(ctx, key_value, &decoded_len,
		&hmac, &decoded_key);
	if (err) {
		nvme_show_error("Key decoding failed, %s", libnvme_strerror(-err));
		return err;
	}

	if (!cfg.hostnqn) {
		err = libnvmf_host_get_ids(ctx, NULL, NULL, &hnqn, NULL);
		if (err)
			return err;
		cfg.hostnqn = hnqn;
	}

	return do_insert_tls_key(ctx, cfg.keyring, cfg.keytype, cfg.hostnqn,
			cfg.subsysnqn, cfg.identity, hmac, decoded_key, decoded_len,
			cfg.compat, cfg.keyfile, &tls_key);
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

static bool is_kxchap_key(const char *key)
{
	return !strncmp(key, "DHHC-1:", 7);
}

static int import_one_key(struct libnvme_global_ctx *ctx, long keyring_id,
		const char *identity, const char *key_str)
{
	__cleanup_free unsigned char *psk = NULL;
	unsigned char decoded_key[128];
	long key_serial;
	int decoded_len, kxchap_hmac, err;
	unsigned int tls_hmac;
	uint32_t crc;

	if (is_kxchap_key(key_str)) {
		err = validate_kxchap_key(key_str, &kxchap_hmac, decoded_key,
				&decoded_len, &crc);
		if (err)
			return err;

		return libnvmf_update_key(ctx, keyring_id, "kxchap", identity,
				(unsigned char *)key_str, strlen(key_str),
				&key_serial);
	}

	err = libnvmf_import_tls_key(ctx, key_str, &decoded_len, &tls_hmac, &psk);
	if (err)
		return err;

	return libnvmf_update_key(ctx, keyring_id, "psk", identity, psk,
			decoded_len, &key_serial);
}

static int import_key(struct libnvme_global_ctx *ctx, const char *keyring,
		FILE *fd)
{
	long keyring_id;
	char line[512];
	char *key_str;
	int linenum = 0;
	int err;

	err = libnvmf_lookup_keyring(ctx, keyring, &keyring_id);
	if (err) {
		nvme_show_error("Invalid keyring '%s'", keyring);
		return err;
	}

	while (fgets(line, sizeof(line), fd)) {
		linenum++;
		key_str = strrchr(line, ' ');
		if (!key_str) {
			nvme_show_error("Parse error in line %d",
					linenum);
			continue;
		}
		*key_str = '\0';
		key_str++;
		key_str[strcspn(key_str, "\n")] = 0;

		err = import_one_key(ctx, keyring_id, line, key_str);
		if (err)
			nvme_show_error("Failed to import key in line %d, %s",
					linenum, libnvme_strerror(-err));
	}

	return 0;
}

static int key_import(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc = "Import NVMeoF TLS PSKs and KX-HMAC-CHAP keys into a keyring.\n";
	const char *keyring = "Keyring to import the keys into.";
	const char *keyfile = "File to read the keys from (default: stdin).";
	const char *keydata = "Key to insert directly under --identity. Reads from stdin if not given.";
	const char *identity = "Identity to store a single key under. If given, --keydata (or stdin) is read as a single key instead of a bulk <identity> <key> list.";

	__cleanup_nvme_global_ctx struct libnvme_global_ctx *ctx = NULL;
	__cleanup_file FILE *fd = NULL;
	__cleanup_free char *key = NULL;
	long keyring_id;
	int err = 0;

	struct config {
		char *keyring;
		char *keyfile;
		char *keydata;
		char *identity;
	};

	struct config cfg = {
		.keyring	= ".nvme",
		.keyfile	= NULL,
		.keydata	= NULL,
		.identity	= NULL,
	};

	NVME_ARGS(opts,
		  OPT_STR("keyring",	'k', &cfg.keyring,	keyring),
		  OPT_STR("keyfile",	'f', &cfg.keyfile,	keyfile),
		  OPT_STR("keydata",	'd', &cfg.keydata,	keydata),
		  OPT_STR("identity",	'i', &cfg.identity,	identity));

	err = parse_args(argc, argv, desc, opts);
	if (err)
		return err;

	err = nvme_create_global_ctx(&ctx);
	if (err) {
		nvme_show_error("Failed to create global context");
		return err;
	}
	libnvme_set_logging_level(ctx, log_level, false, false);

	if (!cfg.identity) {
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
			nvme_show_error("Import of keys failed with '%s'",
					libnvme_strerror(err));
			return err;
		}

		nvme_show_verbose_info("importing from %s", cfg.keyfile);
		return 0;
	}

	err = read_key_value(cfg.keydata, &key);
	if (err) {
		nvme_show_error("No key data");
		return err;
	}

	err = libnvmf_lookup_keyring(ctx, cfg.keyring, &keyring_id);
	if (err) {
		nvme_show_error("Failed to lookup keyring '%s', %s",
				cfg.keyring, libnvme_strerror(-err));
		return err;
	}

	err = import_one_key(ctx, keyring_id, cfg.identity, key);
	if (err) {
		nvme_show_error("Failed to insert key, %s", libnvme_strerror(-err));
		return err;
	}

	nvme_show_result("Inserted key for identity '%s'", cfg.identity);
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
