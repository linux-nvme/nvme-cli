// SPDX-License-Identifier: LGPL-2.1-or-later
/**
 * This file is part of libnvme.
 * Copyright (c) 2026 Dell Technologies Inc. or its subsidiaries.
 * Authors: Martin Belanger <martin.belanger@dell.com>
 *
 * Unit tests for the INI connection-config building blocks (config-ini.c):
 * the three-state parameter bag, the key table, and the typed value
 * validators.
 */

#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "nvme/config-ini.h"

static bool test_params_tristate(void)
{
	struct libnvmf_params *p = libnvmf_params_new();
	bool pass = true;

	printf("test_params_tristate:\n");
	assert(p);

	/* Absent key -> unset (NULL). */
	if (libnvmf_params_get(p, "ctrl-loss-tmo")) {
		printf(" - absent key reads as NULL [FAIL]\n");
		pass = false;
	} else {
		printf(" - absent key reads as NULL (unset) [PASS]\n");
	}

	/* Set, overwrite, reset. */
	assert(libnvmf_params_set(p, "ctrl-loss-tmo", "600") == 0);
	assert(libnvmf_params_set(p, "keep-alive-tmo", "30") == 0);
	assert(libnvmf_params_set(p, "ctrl-loss-tmo", "1800") == 0);
	if (strcmp(libnvmf_params_get(p, "ctrl-loss-tmo"), "1800")) {
		printf(" - set + overwrite [FAIL]\n");
		pass = false;
	} else {
		printf(" - set + overwrite (last wins) [PASS]\n");
	}

	assert(libnvmf_params_set(p, "keep-alive-tmo", "") == 0);
	if (strcmp(libnvmf_params_get(p, "keep-alive-tmo"), "")) {
		printf(" - reset reads as \"\" [FAIL]\n");
		pass = false;
	} else {
		printf(" - reset (\"\") is distinct from unset (NULL) [PASS]\n");
	}

	libnvmf_params_free(p);
	return pass;
}

struct order {
	char seen[256];
};

static void record_order(const char *key, const char *value, void *user_data)
{
	struct order *o = user_data;

	snprintf(o->seen + strlen(o->seen), sizeof(o->seen) - strlen(o->seen),
		 "%s=%s;", key, value);
}

static bool test_params_merge(void)
{
	struct libnvmf_params *base = libnvmf_params_new();
	struct libnvmf_params *over = libnvmf_params_new();
	struct libnvmf_params *copy;
	struct order o = { "" };
	bool pass = true;

	printf("test_params_merge:\n");
	assert(base && over);

	/* base: the outer cascade level; over: the more-specific one. */
	assert(libnvmf_params_set(base, "ctrl-loss-tmo", "600") == 0);
	assert(libnvmf_params_set(base, "tls", "true") == 0);
	assert(libnvmf_params_set(over, "ctrl-loss-tmo", "1800") == 0);
	assert(libnvmf_params_set(over, "keep-alive-tmo", "") == 0);

	assert(libnvmf_params_merge(base, over) == 0);
	if (strcmp(libnvmf_params_get(base, "ctrl-loss-tmo"), "1800") ||
	    strcmp(libnvmf_params_get(base, "tls"), "true") ||
	    strcmp(libnvmf_params_get(base, "keep-alive-tmo"), "")) {
		printf(" - merge precedence [FAIL]\n");
		pass = false;
	} else {
		printf(" - merge: src wins, dst-only keys survive, reset carries [PASS]\n");
	}

	/* Iteration preserves first-insertion order. */
	libnvmf_params_for_each(base, record_order, &o);
	if (strcmp(o.seen, "ctrl-loss-tmo=1800;tls=true;keep-alive-tmo=;")) {
		printf(" - iteration order: %s [FAIL]\n", o.seen);
		pass = false;
	} else {
		printf(" - iteration preserves insertion order [PASS]\n");
	}

	/* dup produces an equal, independent bag. */
	copy = libnvmf_params_dup(base);
	assert(copy);
	assert(libnvmf_params_set(copy, "tls", "false") == 0);
	if (strcmp(libnvmf_params_get(base, "tls"), "true") ||
	    strcmp(libnvmf_params_get(copy, "tls"), "false")) {
		printf(" - dup independence [FAIL]\n");
		pass = false;
	} else {
		printf(" - dup is deep (independent copies) [PASS]\n");
	}

	libnvmf_params_free(base);
	libnvmf_params_free(over);
	libnvmf_params_free(copy);
	return pass;
}

static bool test_key_table(void)
{
	static const struct {
		const char *name;
		enum libnvmf_key_class class;
	} expect[] = {
		{ "ctrl-loss-tmo",	LIBNVMF_KEY_TUNABLE },
		{ "hdr-digest",		LIBNVMF_KEY_TUNABLE },
		{ "tls-key",		LIBNVMF_KEY_SECURITY },
		{ "dhchap-secret",	LIBNVMF_KEY_SECURITY },
		{ "hostnqn",		LIBNVMF_KEY_IDENTITY },
		{ "hostsymname",	LIBNVMF_KEY_IDENTITY },
		{ "nqn",		LIBNVMF_KEY_NQN },
		{ "controller",		LIBNVMF_KEY_CONTROLLER },
	};
	bool pass = true;
	size_t i;

	printf("test_key_table:\n");

	for (i = 0; i < sizeof(expect) / sizeof(expect[0]); i++) {
		const struct libnvmf_key *k = libnvmf_key_lookup(expect[i].name);

		if (!k || k->class != expect[i].class) {
			printf(" - key %s [FAIL]\n", expect[i].name);
			pass = false;
		}
	}
	if (pass)
		printf(" - classes for a sample of every kind [PASS]\n");

	/* One spelling per key: no aliases, no underscore variants. */
	if (libnvmf_key_lookup("fast_io_fail_tmo") ||
	    libnvmf_key_lookup("subsysnqn") ||
	    libnvmf_key_lookup("bogus")) {
		printf(" - unknown/alias spellings rejected [FAIL]\n");
		pass = false;
	} else {
		printf(" - unknown keys and alias spellings -> NULL [PASS]\n");
	}
	if (!libnvmf_key_lookup("fast-io-fail-tmo")) {
		printf(" - fast-io-fail-tmo (hyphenated) known [FAIL]\n");
		pass = false;
	} else {
		printf(" - fast-io-fail-tmo uses the hyphenated spelling [PASS]\n");
	}

	return pass;
}

static bool test_value_check(void)
{
	const struct libnvmf_key *i = libnvmf_key_lookup("ctrl-loss-tmo");
	const struct libnvmf_key *b = libnvmf_key_lookup("tls");
	const struct libnvmf_key *s = libnvmf_key_lookup("tls-key");
	static const char * const good_bools[] = {
		"1", "yes", "Y", "TRUE", "t", "On", "0", "no", "N", "False",
		"f", "OFF",
	};
	bool pass = true;
	size_t n;

	printf("test_value_check:\n");
	assert(i && b && s);

	/* Integers: decimals including -1; garbage rejected. */
	if (libnvmf_key_check_value(i, "600") || libnvmf_key_check_value(i, "-1") ||
	    !libnvmf_key_check_value(i, "12x") || !libnvmf_key_check_value(i, "1.5") ||
	    !libnvmf_key_check_value(i, "tomorrow")) {
		printf(" - int validation [FAIL]\n");
		pass = false;
	} else {
		printf(" - int values (incl. -1) accepted, garbage rejected [PASS]\n");
	}

	/* Hex/octal accepted too -- base 0, matching the kernel's match_int()
	 * and nvme-cli's own argconfig.c parsing of the same options.
	 */
	if (libnvmf_key_check_value(i, "0x1E") ||
	    libnvmf_key_check_value(i, "030")) {
		printf(" - hex/octal int values [FAIL]\n");
		pass = false;
	} else {
		printf(" - hex/octal int values accepted (base 0) [PASS]\n");
	}

	/* Booleans: the systemd spellings, case-insensitive. */
	for (n = 0; n < sizeof(good_bools) / sizeof(good_bools[0]); n++) {
		if (libnvmf_key_check_value(b, good_bools[n])) {
			printf(" - bool %s rejected [FAIL]\n", good_bools[n]);
			pass = false;
		}
	}
	if (!libnvmf_key_check_value(b, "maybe") ||
	    !libnvmf_key_check_value(b, "2")) {
		printf(" - bad bool accepted [FAIL]\n");
		pass = false;
	} else if (pass) {
		printf(" - boolean spellings (case-insensitive) [PASS]\n");
	}

	/* The reset form is valid for every type. */
	if (libnvmf_key_check_value(i, "") || libnvmf_key_check_value(b, "") ||
	    libnvmf_key_check_value(s, "")) {
		printf(" - reset (\"\") accepted everywhere [FAIL]\n");
		pass = false;
	} else {
		printf(" - reset (\"\") accepted for every type [PASS]\n");
	}

	return pass;
}

int main(void)
{
	bool pass = true;

	pass &= test_params_tristate();
	pass &= test_params_merge();
	pass &= test_key_table();
	pass &= test_value_check();

	fflush(stdout);
	exit(pass ? EXIT_SUCCESS : EXIT_FAILURE);
}
