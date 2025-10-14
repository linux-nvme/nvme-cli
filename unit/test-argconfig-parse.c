// SPDX-License-Identifier: GPL-2.0-or-later

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <locale.h>

#include "../util/argconfig.h"
#include "../util/cleanup.h"

#define ARRAY_SIZE(a) (sizeof(a) / sizeof(a[0]))

static int test_rc;

union val {
	bool flag;
	__u64 suffix;
	__u32 uint;
	int int_val;
	__u64 long_val;
	double double_val;
	__u8 byte;
	__u16 shrt;
	int incr;
	char *string;
	char *fmt;
	char *file;
	char *list;
	char *str;
	__u8 val;
};

struct toval_test {
	char *arg;
	void *val;
	union val exp;
	int size;
	int ret;
};

static void check_val(const char *arg, void *exp, void *val, int size)
{
	if ((size && !memcmp(exp, val, size)) ||
	    (!size && !strcmp(*(char **)exp, *(char **)val)))
		return;

	switch (size) {
	case 0:
		printf("ERROR: printing {%s}, got '%s', expected '%s'\n",
		       arg, *(char **)val, *(char **)exp);
		break;
	default:
		printf("ERROR: printing {%s}, got '%llu', expected '%llu'\n",
		       arg, *(unsigned long long *)val, *(unsigned long long *)exp);
		break;
	}

	test_rc = 1;
}

struct cfg {
	bool flag;
	__u64 suffix;
	__u32 uint;
	int int_val;
	__u64 long_val;
	double double_val;
	__u8 byte;
	__u16 shrt;
	int incr;
	char *string;
	char *fmt;
	char *file;
	char *list;
	char *str;
	__u8 val;
};

static struct cfg cfg;

#define VAL_TEST(a, c, v, l, r) \
	{ a, &cfg.c, { .c = v }, l ? sizeof(cfg.c) : 0, r }

static struct toval_test toval_tests[] = {
	VAL_TEST("--flag", flag, true, true, 0),
	VAL_TEST("--flag=1", flag, false, true, -EINVAL),
	VAL_TEST("--suffix=0", suffix, 0, true, 0),
	VAL_TEST("--suffix=1", suffix, 1, true, 0),
	VAL_TEST("--suffix=1234", suffix, 1234, true, 0),
	VAL_TEST("--suffix=4096", suffix, 4096, true, 0),
	VAL_TEST("--suffix=1Ki", suffix, 1024, true, 0),
	VAL_TEST("--suffix=34Gi", suffix, 36507222016, true, 0),
	VAL_TEST("--suffix=34.9Ki", suffix, 0, true, -EINVAL),
	VAL_TEST("--suffix=32Gii", suffix, 0, true, -EINVAL),
	VAL_TEST("--uint=1", uint, 1, true, 0),
	VAL_TEST("--int=1", int_val, 1, true, 0),
	VAL_TEST("--long=1", long_val, 1, true, 0),
	VAL_TEST("--double=1", double_val, 1, true, 0),
	VAL_TEST("--byte=1", byte, 1, true, 0),
	VAL_TEST("--byte=256", byte, 0, true, -EINVAL),
	VAL_TEST("--shrt=1", shrt, 1, true, 0),
	VAL_TEST("--incr", incr, 1, true, 0),
	VAL_TEST("--incr=1", incr, 0, true, -EINVAL),
	VAL_TEST("--string=string", string, "string", false, 0),
	VAL_TEST("--fmt=fmt", fmt, "fmt", false, 0),
	VAL_TEST("--file=file", file, "file", false, 0),
	VAL_TEST("--list=list", list, "list", false, 0),
	VAL_TEST("--str=str", str, "str", false, 0),
	VAL_TEST("--val=", val, 0, true, -EINVAL),
	VAL_TEST("--val=o", val, 1, true, 0),
	VAL_TEST("--val=t", val, 0, true, -EINVAL),
	VAL_TEST("--val=tw", val, 2, true, 0),
	VAL_TEST("--val=two", val, 2, true, 0),
	VAL_TEST("--val=twoo", val, 0, true, -EINVAL),
	VAL_TEST("--val=th", val, 3, true, 0),
	VAL_TEST("--val=three", val, 3, true, 0),
	VAL_TEST("--val=threed", val, 0, true, -EINVAL),
	VAL_TEST("--val=123", val, 123, true, 0),
	VAL_TEST("--val=1234", val, 0, true, -EINVAL),
};

void toval_test(struct toval_test *test)
{
	const char *desc = "Test argconfig parse";
	int ret;
	char *argv[] = { "test-argconfig", test->arg };

	OPT_VALS(opt_vals) = {
		VAL_BYTE("one", 1),
		VAL_BYTE("two", 2),
		VAL_BYTE("three", 3),
		VAL_END()
	};

	OPT_ARGS(opts) = {
		OPT_FLAG("flag",'f', &cfg.flag, "flag"),
		OPT_SUFFIX("suffix", 's', &cfg.suffix, "suffix"),
		OPT_UINT("uint", 'u', &cfg.uint, "uint"),
		OPT_INT("int", 'i', &cfg.int_val, "int"),
		OPT_LONG("long", 'l', &cfg.long_val, "long"),
		OPT_DOUBLE("double", 'd', &cfg.double_val, "double"),
		OPT_BYTE("byte", 'b', &cfg.byte, "byte"),
		OPT_SHRT("shrt", 'S', &cfg.shrt, "shrt"),
		OPT_INCR("incr", 'I', &cfg.incr, "incr"),
		OPT_STRING("string", 't', "STRING", &cfg.string, "string"),
		OPT_FMT("fmt", 'F', &cfg.fmt, "fmt"),
		OPT_FILE("file", 'L', &cfg.file, "file"),
		OPT_LIST("list", 'T', &cfg.list, "list"),
		OPT_STR("str", 'r', &cfg.str, "str"),
		OPT_BYTE("val", 'v', &cfg.val, "val", opt_vals),
		OPT_END()
	};

	ret = argconfig_parse(2, argv, desc, opts);
	if (ret != test->ret) {
		printf("ERROR: converting {%s} failed\n", test->arg);
		test_rc = 1;
		return;
	}
	if (ret)
		return;

	check_val(test->arg, &test->exp, test->val, test->size);
}

#define COMMA_SEP_ARRAY_MAX_VALUES 4

struct comma_sep_array_test {
	const char *input;
	int ret;
	__u32 values[COMMA_SEP_ARRAY_MAX_VALUES];
};

const struct comma_sep_array_test comma_sep_array_tests[] = {
	{"", 0},
	{",,,", 0},
	{" ", -1},
	{"abc", -1},
	{"0xFFFFFFFF", 1, {0xFFFFFFFF}},
	{"0x100000000", -1},
	{"123,0x456", 2, {123, 0x456}},
	{",1,,2,", 2, {1, 2}},
	{"1,22,333,4444", 4, {1, 22, 333, 4444}},
	{"1,2,3,4,5", -1},
};

void comma_sep_array_test(const struct comma_sep_array_test *test)
{
	_cleanup_free_ char *input = strdup(test->input);
	__u32 values[COMMA_SEP_ARRAY_MAX_VALUES] = {};
	int ret = argconfig_parse_comma_sep_array_u32(
		input, values, COMMA_SEP_ARRAY_MAX_VALUES);
	int i;

	if (ret != test->ret) {
		printf("ERROR: input '%s' return value %d != %d\n",
		       test->input, ret, test->ret);
		test_rc = 1;
		return;
	}

	for (i = 0; i < ret; i++) {
		if (values[i] != test->values[i]) {
			printf("ERROR: input '%s' values[%d] = %u != %u\n",
			       test->input, i, values[i], test->values[i]);
			test_rc = 1;
			return;
		}
	}
}

int main(void)
{
	unsigned int i;
	FILE *f;

	test_rc = 0;
	setlocale(LC_NUMERIC, "C");
	f = freopen("/dev/null", "w", stderr);
	if (!f)
		printf("ERROR: reopening stderr failed: %s\n", strerror(errno));

	for (i = 0; i < ARRAY_SIZE(toval_tests); i++)
		toval_test(&toval_tests[i]);

	for (i = 0; i < ARRAY_SIZE(comma_sep_array_tests); i++)
		comma_sep_array_test(&comma_sep_array_tests[i]);

	if (f)
		fclose(f);

	return test_rc ? EXIT_FAILURE : EXIT_SUCCESS;
}
