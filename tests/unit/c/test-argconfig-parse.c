// SPDX-License-Identifier: GPL-2.0-or-later

#include <errno.h>
#include <locale.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <ccan/array_size/array_size.h>
#include <shared/fs-util.h>
#include <shared/parse-util.h>

#include "../src/argconfig.h"
#include "../src/cleanup.h"

const char *libnvme_strerror(int errnum);

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

/* Distinct from NULL so we can tell "not parsed at all" apart from
 * "parsed as --optstr with no attached value" (which sets it to NULL).
 */
static char optstr_unset[] = "unset";

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
	char *optstr;
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
	VAL_TEST("--long=0x123456789abcdef0", long_val, 0x123456789abcdef0,
		 true, 0),
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

	/* Short-option forms: the CLI accepts these interchangeably with
	 * the long forms exercised above.
	 */
	VAL_TEST("-f", flag, true, true, 0),
	VAL_TEST("-s1234", suffix, 1234, true, 0),
	VAL_TEST("-u42", uint, 42, true, 0),
	VAL_TEST("-b7", byte, 7, true, 0),
	VAL_TEST("-tstr", string, "str", false, 0),

	/* Help requests short-circuit parsing and report failure so the
	 * caller doesn't proceed as if real options were parsed.
	 */
	{ "--help", &cfg.flag, { .flag = false }, 0, -EINVAL },
	{ "-h", &cfg.flag, { .flag = false }, 0, -EINVAL },
	{ "-?", &cfg.flag, { .flag = false }, 0, -EINVAL },

	/* required_argument option with no value attached and no further
	 * argv token to supply one.
	 */
	{ "--suffix", &cfg.suffix, { .suffix = 0 }, 0, -EINVAL },

	/* Unrecognized long option. */
	{ "--bogus", &cfg.flag, { .flag = false }, 0, -EINVAL },

	/*
	 * Long options need two dashes and their full name: "-flag" is
	 * the short options -f -l with "ag" as value of -l, which is not a
	 * number.
	 */
	{ "--fla", &cfg.flag, { .flag = false }, 0, -EINVAL },
	{ "--stri=x", &cfg.string, { .string = NULL }, 0, -EINVAL },
	{ "-flag", &cfg.flag, { .flag = false }, 0, -EINVAL },
	{ "-string=x", &cfg.string, { .string = NULL }, 0, -EINVAL },
	/* An exact name wins over a longer name it is a prefix of. */
	VAL_TEST("--str=exact", str, "exact", false, 0),
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

/*
 * OPT_STRING_OPTIONAL is the one type where the CLI must distinguish three
 * outcomes: the flag never appeared, appeared with "--optstr=value", or
 * appeared bare as "--optstr" (optarg is NULL, per getopt_long_only rules).
 */
static void optional_string_test(void)
{
	const char *desc = "Test optional string argument";
	int ret;

	OPT_ARGS(opts) = {
		OPT_STRING_OPTIONAL("optstr", 'O', "STR", &cfg.optstr, "optional string"),
		OPT_END()
	};

	{
		char *argv[] = { "test-argconfig" };

		cfg.optstr = optstr_unset;
		ret = argconfig_parse(1, argv, desc, opts);
		if (ret || cfg.optstr != optstr_unset) {
			printf("ERROR: optional string: omitted flag was touched\n");
			test_rc = 1;
		}
	}

	{
		char *argv[] = { "test-argconfig", "--optstr=given" };

		cfg.optstr = optstr_unset;
		ret = argconfig_parse(2, argv, desc, opts);
		if (ret || !cfg.optstr || strcmp(cfg.optstr, "given")) {
			printf("ERROR: optional string: '--optstr=given' not applied\n");
			test_rc = 1;
		}
	}

	{
		char *argv[] = { "test-argconfig", "--optstr" };

		cfg.optstr = optstr_unset;
		ret = argconfig_parse(2, argv, desc, opts);
		if (ret || cfg.optstr) {
			printf("ERROR: optional string: bare '--optstr' should set NULL\n");
			test_rc = 1;
		}
	}
}

/*
 * Real command lines pass several options together; the per-option tests
 * above each parse exactly one token, so exercise a realistic multi-flag
 * invocation here, mixed with an OPT_GROUP() separator (as real commands
 * do) and a check of argconfig_parse_seen(), the public "was this option
 * given" query used throughout the plugins.
 */
static void combined_opts_test(void)
{
	const char *desc = "Test combined options";
	char *argv[] = { "test-argconfig", "--flag", "--suffix=42", "--uint=7" };
	int ret;

	cfg.flag = false;
	cfg.suffix = 0;
	cfg.uint = 0;
	cfg.int_val = -1;

	OPT_ARGS(opts) = {
		OPT_GROUP("Options"),
		OPT_FLAG("flag", 'f', &cfg.flag, "flag"),
		OPT_SUFFIX("suffix", 's', &cfg.suffix, "suffix"),
		OPT_UINT("uint", 'u', &cfg.uint, "uint"),
		OPT_INT("int", 'i', &cfg.int_val, "int"),
		OPT_END()
	};

	ret = argconfig_parse(ARRAY_SIZE(argv), argv, desc, opts);
	if (ret) {
		printf("ERROR: combined options: parse failed: %d\n", ret);
		test_rc = 1;
		return;
	}

	if (!cfg.flag || cfg.suffix != 42 || cfg.uint != 7 || cfg.int_val != -1) {
		printf("ERROR: combined options: values not all applied correctly\n");
		test_rc = 1;
	}

	if (!argconfig_parse_seen(opts, "flag") ||
	    !argconfig_parse_seen(opts, "suffix") ||
	    !argconfig_parse_seen(opts, "uint") ||
	    argconfig_parse_seen(opts, "int")) {
		printf("ERROR: combined options: argconfig_parse_seen() mismatch\n");
		test_rc = 1;
	}
}

/* Number of arguments in a NULL terminated argument vector */
static int argv_len(char **argv)
{
	int argc = 0;

	while (argv[argc])
		argc++;

	return argc;
}

/*
 * The non-option arguments are available through argconfig_operand(), in
 * the order they were given, wherever they appear between the options.
 */
static void operands_test(void)
{
	const char *desc = "Test operands";
	char **argv = (char *[]){ "test-argconfig", "dev0", "--flag", "dev1",
				  "--uint", "3", "dev2", "--", "--flag",
				  NULL };
	int ret;

	OPT_ARGS(opts) = {
		OPT_FLAG("flag", 'f', &cfg.flag, "flag"),
		OPT_UINT("uint", 'u', &cfg.uint, "uint"),
		OPT_END()
	};

	ret = argconfig_parse(argv_len(argv), argv, desc, opts);
	if (ret || argconfig_nr_operands() != 4 ||
	    strcmp(argconfig_operand(0), "dev0") ||
	    strcmp(argconfig_operand(1), "dev1") ||
	    strcmp(argconfig_operand(2), "dev2") ||
	    strcmp(argconfig_operand(3), "--flag") ||
	    argconfig_operand(4) || argconfig_operand(-1)) {
		printf("ERROR: operands: unexpected operands\n");
		test_rc = 1;
	}

	{
		char **bad = (char *[]){ "test-argconfig", "dev0", "--bogus",
					 NULL };

		ret = argconfig_parse(argv_len(bad), bad, desc, opts);
		if (!ret || argconfig_nr_operands()) {
			printf("ERROR: operands: kept after a failed parse\n");
			test_rc = 1;
		}
	}
}

/*
 * Options registered with argconfig_set_global_options() are accepted by
 * every command after the command's own options, which take precedence.
 * Their seen flags are kept across parses: the global options may already
 * have been given before the command name.
 */
static void global_options_test(void)
{
	const char *desc = "Test global options";
	int verbose = 0;
	bool dry_run = false;
	char *format = NULL;
	int argind, ret;

	OPT_ARGS(globals) = {
		OPT_INCR("verbose", 'v', &verbose, "verbose"),
		OPT_FLAG("dry-run", 'd', &dry_run, "dry run"),
		OPT_FMT("output-format", 'o', &format, "format"),
		OPT_END()
	};
	OPT_ARGS(opts) = {
		OPT_FLAG("flag", 'f', &cfg.flag, "flag"),
		/* shadows -d of the global options */
		OPT_UINT("uint", 'd', &cfg.uint, "uint"),
		OPT_END()
	};
	OPT_ARGS(local) = {
		OPT_FLAG("flag", 'f', &cfg.flag, "flag"),
		OPT_END()
	};

	argconfig_set_global_options(globals);

	{
		char **argv = (char *[]){ "prog", "-v", "list", NULL };

		ret = argconfig_parse_global(argv_len(argv), argv, local,
					     &argind);
		if (ret || argind != 2 || verbose != 1) {
			printf("ERROR: global options: global parse failed\n");
			test_rc = 1;
		}
	}

	{
		char **argv = (char *[]){ "list", "-f", "--verbose", "-d", "7",
					  "-o", "json", "dev", NULL };

		cfg.flag = false;
		cfg.uint = 0;
		ret = argconfig_parse(argv_len(argv), argv, desc, opts);
		if (ret || !cfg.flag || cfg.uint != 7 || verbose != 2 ||
		    dry_run || !format || strcmp(format, "json") ||
		    argconfig_nr_operands() != 1) {
			printf("ERROR: global options: command parse failed\n");
			test_rc = 1;
		}
		if (!argconfig_parse_seen(opts, "output-format") ||
		    !argconfig_parse_seen(opts, "verbose") ||
		    argconfig_parse_seen(opts, "dry-run")) {
			printf("ERROR: global options: seen mismatch\n");
			test_rc = 1;
		}
	}

	{
		/* a later parse keeps the seen flags of the global options */
		char **argv = (char *[]){ "list", "--dry-run", NULL };

		ret = argconfig_parse(argv_len(argv), argv, desc, local);
		if (ret || !dry_run ||
		    !argconfig_parse_seen(local, "output-format") ||
		    !argconfig_parse_seen(local, "dry-run")) {
			printf("ERROR: global options: seen not kept\n");
			test_rc = 1;
		}
	}

	argconfig_set_global_options(NULL);
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
	__cleanup_free char *input = strdup(test->input);
	__u32 values[COMMA_SEP_ARRAY_MAX_VALUES] = {};
	int ret = shr_parse_csv_u32(
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

struct global_cfg {
	int verbose;
	bool dry_run;
};

static struct global_cfg gcfg;

struct global_parse_test {
	const char *desc;
	char *argv[8];
	int argc;
	/*
	 * Expected argind value after argconfig_parse_global() returns.
	 * This is the index of the first non-option argument (the subcommand)
	 * in argv, i.e. 1-based because argv[0] is the program name.
	 */
	int expected_argind;
	int expected_ret;
	int expected_verbose;
	bool expected_dry_run;
	const char *stderr_must_not_contain;
};

static const struct global_parse_test global_parse_tests[] = {
	{
		"no global opts: subcommand only",
		{"prog", "list"},
		2, 1, 0, 0, false,
	},
	{
		"short -v before subcommand",
		{"prog", "-v", "list"},
		3, 2, 0, 1, false,
	},
	{
		"long --verbose before subcommand",
		{"prog", "--verbose", "list"},
		3, 2, 0, 1, false,
	},
	{
		"two -v flags before subcommand",
		{"prog", "-v", "-v", "list"},
		4, 3, 0, 2, false,
	},
	{
		"bundled -vv (single token) before subcommand",
		{"prog", "-vv", "list"},
		3, 2, 0, 2, false,
	},
	{
		"--dry-run before subcommand",
		{"prog", "--dry-run", "list"},
		3, 2, 0, 0, true,
	},
	{
		"multiple global opts before subcommand",
		{"prog", "-v", "--dry-run", "list"},
		4, 3, 0, 1, true,
	},
	{
		/*
		 * The '+' prefix in the short-opts string causes getopt to stop
		 * at the first non-option argument.  Global opts that appear
		 * *after* the subcommand must be left for the subcommand's own
		 * argconfig_parse() call to handle.
		 */
		"subcommand before option: stop at first non-option",
		{"prog", "list", "-v"},
		3, 1, 0, 0, false,
	},
	{
		"only program name",
		{"prog"},
		1, 1, 0, 0, false,
	},
	{
		"option with no following subcommand",
		{"prog", "--verbose"},
		2, 2, 0, 1, false,
	},
 	{
 		"unknown option before subcommand should fail",
 		{"prog", "--no-such-opt", "list"},
 		3, 0, -EINVAL, 0, false,
 	},
	{
		"abbreviated long option fails",
		{"prog", "--verb", "list"},
		3, 0, -EINVAL, 0, false,
	},
	{
		/* -v is applied before 'e' is rejected, as with getopt */
		"single-dash long option fails",
		{"prog", "-verbose", "list"},
		3, 0, -EINVAL, 1, false,
	},
	{
		"-- ends the global options",
		{"prog", "--", "-v"},
		3, 2, 0, 0, false,
	},
};

static int parse_global_capture_stderr(int argc, char *argv[],
				       struct argconfig_commandline_options *opts,
				       int *argind, char *buf, size_t buf_size)
{
	FILE *tmp = NULL;
	int ret;
	int saved_stderr;
	size_t n;

	tmp = tmpfile();
	if (!tmp) {
		printf("ERROR: tmpfile failed: %s\n", libnvme_strerror(errno));
		test_rc = 1;
		return -errno;
	}

	saved_stderr = dup(STDERR_FILENO);
	if (saved_stderr < 0) {
		printf("ERROR: dup stderr failed: %s\n", libnvme_strerror(errno));
		test_rc = 1;
		fclose(tmp);
		return -errno;
	}

	fflush(stderr);
	if (dup2(fileno(tmp), STDERR_FILENO) < 0) {
		printf("ERROR: redirect stderr failed: %s\n", libnvme_strerror(errno));
		close(saved_stderr);
		test_rc = 1;
		fclose(tmp);
		return -errno;
	}

	ret = argconfig_parse_global(argc, argv, opts, argind);
	fflush(stderr);

	if (fseek(tmp, 0, SEEK_SET) != 0) {
		printf("ERROR: rewind captured stderr failed: %s\n",
		       libnvme_strerror(errno));
		close(saved_stderr);
		test_rc = 1;
		fclose(tmp);
		return -errno;
	}

	n = fread(buf, 1, buf_size - 1, tmp);
	buf[n] = '\0';

	if (dup2(saved_stderr, STDERR_FILENO) < 0) {
		printf("ERROR: restoring stderr failed: %s\n", libnvme_strerror(errno));
		test_rc = 1;
		close(saved_stderr);
		fclose(tmp);
		return -errno;
	}
	close(saved_stderr);
	fclose(tmp);

	return ret;
}

static void do_global_parse_test(const struct global_parse_test *test)
{
	int ret, argind = -1;
	char stderr_buf[512] = "";

	OPT_ARGS(opts) = {
		OPT_INCR("verbose", 'v', &gcfg.verbose, "increase verbosity"),
		OPT_FLAG("dry-run", 0, &gcfg.dry_run, "dry run mode"),
		OPT_END()
	};

	gcfg.verbose = 0;
	gcfg.dry_run = false;

	if (test->stderr_must_not_contain)
		ret = parse_global_capture_stderr(test->argc, (char **)test->argv,
						  opts, &argind, stderr_buf,
						  sizeof(stderr_buf));
	else
		ret = argconfig_parse_global(test->argc, (char **)test->argv,
					     opts, &argind);

	if (ret != test->expected_ret) {
		printf("ERROR: global_parse {%s}: ret=%d expected=%d\n",
		       test->desc, ret, test->expected_ret);
		test_rc = 1;
		return;
	}

	if (test->expected_ret == 0 && argind != test->expected_argind) {
		printf("ERROR: global_parse {%s}: argind=%d expected=%d\n",
		       test->desc, argind, test->expected_argind);
		test_rc = 1;
		return;
	}

	if (test->stderr_must_not_contain &&
	    strstr(stderr_buf, test->stderr_must_not_contain)) {
		printf("ERROR: global_parse {%s}: stderr unexpectedly contains '%s'\n",
		       test->desc, test->stderr_must_not_contain);
		test_rc = 1;
		return;
	}

	if (gcfg.verbose != test->expected_verbose) {
		printf("ERROR: global_parse {%s}: verbose=%d expected=%d\n",
		       test->desc, gcfg.verbose, test->expected_verbose);
		test_rc = 1;
		return;
	}

	if (gcfg.dry_run != test->expected_dry_run) {
		printf("ERROR: global_parse {%s}: dry_run=%d expected=%d\n",
		       test->desc, gcfg.dry_run, test->expected_dry_run);
		test_rc = 1;
	}
}

/*
 * A global option that takes a required argument but is given none (no
 * "=value" and nothing left in argv to supply it) must fail the same way
 * an unknown option does, rather than silently leaving the default in
 * place.
 */
static void global_parse_missing_arg_test(void)
{
	char *argv[] = { "prog", "--count" };
	unsigned int count = 0;
	int ret, argind;

	OPT_ARGS(opts) = {
		OPT_UINT("count", 'c', &count, "count"),
		OPT_END()
	};

	ret = argconfig_parse_global(ARRAY_SIZE(argv), argv, opts, &argind);
	if (ret != -EINVAL) {
		printf("ERROR: global_parse: '--count' with no value: ret=%d expected=%d\n",
		       ret, -EINVAL);
		test_rc = 1;
	}
}

/*
 * The global parse accepts -h, --help, -V and --version unless the table
 * has its own, reports them with ARGCONFIG_HELP and ARGCONFIG_VERSION and
 * still parses the other options up to the subcommand.
 */
static void global_parse_help_test(void)
{
	bool own_help = false;
	int verbose = 0, argind, ret;

	OPT_ARGS(opts) = {
		OPT_INCR("verbose", 'v', &verbose, "increase verbosity"),
		OPT_END()
	};
	OPT_ARGS(help_opts) = {
		OPT_FLAG("help", 'h', &own_help, "help"),
		OPT_END()
	};

	{
		char **argv = (char *[]){ "prog", "-h", "-v", "list", NULL };

		ret = argconfig_parse_global(argv_len(argv), argv, opts,
					     &argind);
		if (ret != ARGCONFIG_HELP || argind != 3 || verbose != 1) {
			printf("ERROR: global help: -h -v list\n");
			test_rc = 1;
		}
	}

	{
		char **argv = (char *[]){ "prog", "-vh", "--help", NULL };

		verbose = 0;
		ret = argconfig_parse_global(argv_len(argv), argv, opts,
					     &argind);
		if (ret != ARGCONFIG_HELP || argind != 3 || verbose != 1) {
			printf("ERROR: global help: -vh --help\n");
			test_rc = 1;
		}
	}

	{
		char **argv = (char *[]){ "prog", "-h", "list", NULL };

		ret = argconfig_parse_global(argv_len(argv), argv, help_opts,
					     &argind);
		if (ret || argind != 2 || !own_help) {
			printf("ERROR: global help: own -h of the table\n");
			test_rc = 1;
		}
	}

	{
		char **argv = (char *[]){ "prog", "-vV", "list", NULL };

		verbose = 0;
		ret = argconfig_parse_global(argv_len(argv), argv, opts,
					     &argind);
		if (ret != ARGCONFIG_VERSION || argind != 2 || verbose != 1) {
			printf("ERROR: global version: -vV list\n");
			test_rc = 1;
		}
	}

	{
		char **argv = (char *[]){ "prog", "--help", "--version", NULL };

		ret = argconfig_parse_global(argv_len(argv), argv, NULL,
					     &argind);
		if (ret != (ARGCONFIG_HELP | ARGCONFIG_VERSION) ||
		    argind != 3) {
			printf("ERROR: global version: --help --version\n");
			test_rc = 1;
		}
	}
}

int main(void)
{
	unsigned int i;
	FILE *f;

	test_rc = 0;
	setlocale(LC_NUMERIC, "C");
	f = freopen(shr_dev_null(), "w", stderr);
	if (!f) {
		printf("ERROR: reopening stderr failed: %s\n", libnvme_strerror(errno));
		test_rc = 1;
	}

	for (i = 0; i < ARRAY_SIZE(toval_tests); i++)
		toval_test(&toval_tests[i]);

	optional_string_test();
	combined_opts_test();
	operands_test();
	global_options_test();

	for (i = 0; i < ARRAY_SIZE(comma_sep_array_tests); i++)
		comma_sep_array_test(&comma_sep_array_tests[i]);

	for (i = 0; i < ARRAY_SIZE(global_parse_tests); i++)
		do_global_parse_test(&global_parse_tests[i]);

	global_parse_missing_arg_test();
	global_parse_help_test();

	if (f)
		fclose(f);

	return test_rc ? EXIT_FAILURE : EXIT_SUCCESS;
}
