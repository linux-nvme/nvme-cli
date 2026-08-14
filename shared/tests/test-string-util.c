// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 Dell Technologies Inc. or its subsidiaries.
 *
 * Authors: Martin Belanger <martin.belanger@dell.com>
 */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <shared/string-util.h>

static bool check_str(const char *name, const char *got, const char *want)
{
	bool eq = (got == want) || (got && want && !strcmp(got, want));

	if (eq) {
		printf(" - %s [PASS]\n", name);
		return true;
	}

	printf(" - %s: got \"%s\", want \"%s\" [FAIL]\n",
	       name, got ? got : "(null)", want ? want : "(null)");
	return false;
}

static bool check_bool(const char *name, bool got, bool want)
{
	if (got == want) {
		printf(" - %s [PASS]\n", name);
		return true;
	}

	printf(" - %s: got %d, want %d [FAIL]\n", name, got, want);
	return false;
}

static bool test_streq0(void)
{
	bool pass = true;

	printf("test_streq0:\n");

	pass &= check_bool("NULL == NULL", shr_streq0(NULL, NULL), true);
	pass &= check_bool("NULL != non-NULL",
			    shr_streq0(NULL, "a"), false);
	pass &= check_bool("non-NULL != NULL",
			    shr_streq0("a", NULL), false);
	pass &= check_bool("equal strings", shr_streq0("abc", "abc"), true);
	pass &= check_bool("different strings",
			    shr_streq0("abc", "abd"), false);
	pass &= check_bool("case differs, not equal",
			    shr_streq0("ABC", "abc"), false);

	return pass;
}

static bool test_streqcase0(void)
{
	bool pass = true;

	printf("test_streqcase0:\n");

	pass &= check_bool("NULL == NULL", shr_streqcase0(NULL, NULL), true);
	pass &= check_bool("NULL != non-NULL",
			    shr_streqcase0(NULL, "a"), false);
	pass &= check_bool("case differs, still equal",
			    shr_streqcase0("ABC", "abc"), true);
	pass &= check_bool("different strings",
			    shr_streqcase0("abc", "abd"), false);

	return pass;
}

static bool test_xstrdup(void)
{
	char input[] = "hello";
	char *dup;
	bool pass = true;

	printf("test_xstrdup:\n");

	pass &= check_str("NULL in → NULL out", shr_xstrdup(NULL), NULL);

	dup = shr_xstrdup(input);
	pass &= check_bool("returns a new allocation, not the input pointer",
			    dup != NULL && dup != input, true);
	pass &= check_str("copy has the same content", dup, "hello");
	free(dup);

	return pass;
}

static bool test_startswith(void)
{
	bool pass = true;

	printf("test_startswith:\n");

	pass &= check_str("matching prefix returns the remainder",
			   shr_startswith("keyword", "key"), "word");
	pass &= check_str("exact match returns the empty remainder",
			   shr_startswith("key", "key"), "");
	pass &= check_str("non-matching prefix returns NULL",
			   shr_startswith("value", "key"), NULL);
	pass &= check_str("empty prefix always matches, full string remains",
			   shr_startswith("anything", ""), "anything");

	return pass;
}

static bool test_trim(void)
{
	char buf1[] = "  hello world  ";
	char buf2[] = "no-padding";
	char buf3[] = "   ";
	char buf4[] = "\t\n leading only";
	char buf5[] = "trailing only \t\n";
	bool pass = true;

	printf("test_trim:\n");

	pass &= check_str("both sides trimmed", shr_trim(buf1), "hello world");
	pass &= check_str("no padding is a no-op",
			   shr_trim(buf2), "no-padding");
	pass &= check_str("all-whitespace trims to empty", shr_trim(buf3), "");
	pass &= check_str("leading whitespace only",
			   shr_trim(buf4), "leading only");
	pass &= check_str("trailing whitespace only",
			   shr_trim(buf5), "trailing only");

	return pass;
}

static bool test_valid_name(void)
{
	bool pass = true;

	printf("test_valid_name:\n");

	pass &= check_bool("alnum + '_' + '-' accepted",
			    shr_valid_name("Valid_Name-123"), true);
	pass &= check_bool("NULL rejected", shr_valid_name(NULL), false);
	pass &= check_bool("empty string rejected", shr_valid_name(""), false);
	pass &= check_bool("space rejected", shr_valid_name("bad name"), false);
	pass &= check_bool("'.' rejected", shr_valid_name("bad.name"), false);
	pass &= check_bool("'/' rejected", shr_valid_name("bad/name"), false);

	return pass;
}

static bool test_kv_strip(void)
{
	char buf1[] = "  key = value \x20\n";
	char buf2[] = "key = value # a trailing comment";
	char buf3[] = "# a whole-line comment\n";
	char buf4[] = "\n";
	char buf5[] = "key=value#nospacecomment";
	bool pass = true;

	printf("test_kv_strip:\n");

	pass &= check_str("leading/trailing whitespace and newline stripped",
			   shr_kv_strip(buf1), "key = value");
	pass &= check_str("trailing comment (with its leading spaces) stripped",
			   shr_kv_strip(buf2), "key = value");
	pass &= check_str("whole-line comment strips to empty",
			   shr_kv_strip(buf3), "");
	pass &= check_str("blank line strips to empty", shr_kv_strip(buf4), "");
	pass &= check_str("comment with no preceding space still stripped",
			   shr_kv_strip(buf5), "key=value");

	return pass;
}

static bool test_kv_keymatch(void)
{
	bool pass = true;

	printf("test_kv_keymatch:\n");

	pass &= check_str("'key = value' matches key, returns value",
			   shr_kv_keymatch("key = value", "key"), "value");
	pass &= check_str("'key=value' (no spaces) matches too",
			   shr_kv_keymatch("key=value", "key"), "value");
	pass &= check_str("wrong key does not match",
			   shr_kv_keymatch("otherkey = value", "key"), NULL);
	pass &= check_str("key as a prefix of a longer word does not match",
			   shr_kv_keymatch("keyword = value", "key"), NULL);

	return pass;
}

int main(void)
{
	bool pass = true;

	pass &= test_streq0();
	pass &= test_streqcase0();
	pass &= test_xstrdup();
	pass &= test_startswith();
	pass &= test_trim();
	pass &= test_valid_name();
	pass &= test_kv_strip();
	pass &= test_kv_keymatch();

	fflush(stdout);
	exit(pass ? EXIT_SUCCESS : EXIT_FAILURE);
}
