// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Compare argconfig_parse() and argconfig_parse_global() with a frozen copy
 * of the getopt based parser (argconfig-getopt-ref.c) on generated command
 * lines: the return value, all option values, the seen flags and the
 * operands must be identical.
 *
 * Two kinds of input are deliberately not supported anymore and are
 * filtered out: single-dash long options ("-flag", which getopt_long_only()
 * accepted) and abbreviated long options ("--fla"). They are tested in
 * test-argconfig-parse.
 *
 * getopt's permutation and error handling differ between C libraries, the
 * reference is only meaningful with glibc.
 */

#include <errno.h>
#include <locale.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

#include <ccan/array_size/array_size.h>
#include <shared/fs-util.h>

#include "../../../src/argconfig.h"
#include "argconfig-getopt-ref.h"

const char *libnvme_strerror(int errnum);

#ifdef __GLIBC__

struct diff_cfg {
	bool flag;
	uint64_t suffix;
	uint32_t uint;
	int int_val;
	uint64_t long_val;
	double double_val;
	uint8_t byte;
	uint16_t shrt;
	int incr;
	char *string;
	char *str;
	char *optstr;
	uint32_t longonly;
	bool dup1;
	bool dup2;
	bool noval;
};

struct global_cfg {
	int verbose;
	bool dry_run;
	char *format;
	uint32_t timeout;
	bool help;
};

/* The report; stdout gets the help argconfig prints */
static FILE *report;

#define MAX_OPTS 32
#define MAX_ARGS 8

struct result {
	int ret;
	struct diff_cfg cfg;
	struct global_cfg gcfg;
	bool seen[MAX_OPTS];
	char *operands[MAX_ARGS];
	int nr_operands;
	int argind;
};

static struct argconfig_opt_val byte_vals[] = {
	VAL_BYTE("one", 1),
	VAL_BYTE("two", 2),
	VAL_BYTE("three", 3),
	VAL_END()
};

static const char * const long_names[] = {
	"flag", "suffix", "uint", "int", "long", "double", "byte", "shrt",
	"incr", "string", "str", "optstr", "noval", "longonly", "dup1",
	"dup2", "help", "verbose", "dry-run", "format", "timeout",
};

static const char * const vocabulary[] = {
	"--flag", "-f", "--flag=1",
	"--suffix=4Ki", "--suffix", "-s", "-s1", "4Ki",
	"--uint=5", "--uint", "-u", "-u7", "--uint=", "5",
	"--int=-3", "-i", "-3",
	"--long=0x10", "--double=1.5",
	"--byte=two", "--byte=tw", "--byte=t", "--byte=300", "-b", "one",
	"--shrt=65535", "--shrt=65536",
	"--incr", "-I", "-II", "-fI", "-fu9", "-fu",
	"--string=x", "--string", "-t", "-tval", "--str=y", "--str",
	"--optstr", "--optstr=z", "-O", "-Oval",
	"--noval", "-n", "--longonly=4", "--dup1", "--dup2", "-D",
	"--", "-", "dev", "", "=x",
	"--bogus", "-z", "--help", "-h", "-?", "-fh",
	"-v", "-vv", "--verbose", "--dry-run", "-o", "--format=json",
	"--timeout", "--timeout=10", "list",
};

static void diff_opts(struct argconfig_commandline_options *opts,
		      struct diff_cfg *cfg)
{
	struct argconfig_commandline_options o[] = {
		OPT_FLAG("flag", 'f', &cfg->flag, "flag"),
		OPT_SUFFIX("suffix", 's', &cfg->suffix, "suffix"),
		OPT_UINT("uint", 'u', &cfg->uint, "uint"),
		OPT_INT("int", 'i', &cfg->int_val, "int"),
		OPT_LONG("long", 'l', &cfg->long_val, "long"),
		OPT_DOUBLE("double", 'd', &cfg->double_val, "double"),
		OPT_BYTE("byte", 'b', &cfg->byte, "byte", byte_vals),
		OPT_GROUP("More options"),
		OPT_SHRT("shrt", 'S', &cfg->shrt, "shrt"),
		OPT_INCR("incr", 'I', &cfg->incr, "incr"),
		OPT_STRING("string", 't', "STRING", &cfg->string, "string"),
		OPT_STR("str", 'r', &cfg->str, "str"),
		OPT_STRING_OPTIONAL("optstr", 'O', "STR", &cfg->optstr,
				    "optstr"),
		OPT_FLAG("noval", 'n', &cfg->noval, "noval"),
		OPT_UINT("longonly", 0, &cfg->longonly, "longonly"),
		OPT_FLAG("dup1", 'D', &cfg->dup1, "dup1"),
		OPT_FLAG("dup2", 'D', &cfg->dup2, "dup2"),
		OPT_END()
	};

	memcpy(opts, o, sizeof(o));
}

static void global_opts(struct argconfig_commandline_options *opts,
			struct global_cfg *cfg)
{
	struct argconfig_commandline_options o[] = {
		OPT_INCR("verbose", 'v', &cfg->verbose, "verbose"),
		OPT_FLAG("dry-run", 0, &cfg->dry_run, "dry-run"),
		OPT_FMT("format", 'o', &cfg->format, "format"),
		OPT_UINT("timeout", 0, &cfg->timeout, "timeout"),
		OPT_FLAG("help", 'h', &cfg->help, "help"),
		OPT_END()
	};

	memcpy(opts, o, sizeof(o));
}

/* The short options of diff_opts() and the implicit help options */
static const char command_shorts[] = "fsuildbSItrnODh?";

/*
 * True if getopt would treat the argument as a single-dash long option or
 * as an abbreviated long option, which are not supported anymore. For the
 * command options getopt_long_only() also took "-x" for an abbreviated
 * long option if x is not a short option.
 */
static bool unsupported(const char *arg, bool global)
{
	const char *name, *eq;
	size_t len;
	unsigned int i;

	if (arg[0] != '-' || !arg[1])
		return false;
	if (arg[1] == '-') {
		name = arg + 2;
		if (!*name)
			return false;
	} else {
		name = arg + 1;
		if (global)
			return false;
		if (!name[1] && strchr(command_shorts, name[0]))
			return false;
	}

	eq = strchr(name, '=');
	len = eq ? (size_t)(eq - name) : strlen(name);

	/* "--name" is fine even if a longer name starts with it */
	if (arg[1] == '-') {
		for (i = 0; i < ARRAY_SIZE(long_names); i++) {
			if (strlen(long_names[i]) == len &&
			    !strncmp(long_names[i], name, len))
				return false;
		}
	}

	/* "-name", "-nam" and "--nam" are not */
	for (i = 0; i < ARRAY_SIZE(long_names); i++) {
		if (!strncmp(long_names[i], name, len))
			return true;
	}

	return false;
}

/* The filter must not skip the supported forms of the comparison */
static bool filter_test(void)
{
	static const struct {
		const char *arg;
		bool global;
		bool unsupported;
	} tests[] = {
		/* exact names, also when a longer name starts with them */
		{ "--str", false, false },
		{ "--str=y", false, false },
		{ "--long=0x10", false, false },
		{ "--string=x", false, false },
		{ "-f", false, false },
		{ "-fu9", false, false },
		{ "dev", false, false },
		{ "-verbose", true, false },
		/* abbreviations and single-dash long options */
		{ "--stri", false, true },
		{ "--lon", false, true },
		{ "--verb", true, true },
		{ "-str", false, true },
		{ "-o", false, true },
		{ "-flag", false, true },
	};
	bool ok = true;
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(tests); i++) {
		if (unsupported(tests[i].arg, tests[i].global) ==
		    tests[i].unsupported)
			continue;
		fprintf(report, "ERROR: filter: '%s' %s taken as unsupported\n",
			tests[i].arg, tests[i].unsupported ? "not" : "wrongly");
		ok = false;
	}

	return ok;
}

static void collect_seen(struct argconfig_commandline_options *opts,
			 bool *seen)
{
	int i;

	for (i = 0; opts[i].option && i < MAX_OPTS; i++)
		seen[i] = opts[i].seen;
}

static void run(char **args, int nargs, bool ref, bool global,
		struct result *r)
{
	struct argconfig_commandline_options opts[MAX_OPTS];
	char *argv[MAX_ARGS + 2];
	char **operands;
	int i;

	memset(r, 0, sizeof(*r));
	argv[0] = "test-argconfig-diff";
	for (i = 0; i < nargs; i++)
		argv[i + 1] = args[i];
	argv[nargs + 1] = NULL;

	if (global) {
		global_opts(opts, &r->gcfg);
		if (ref)
			r->ret = ref_argconfig_parse_global(nargs + 1, argv,
							    opts, &r->argind);
		else
			r->ret = argconfig_parse_global(nargs + 1, argv, opts,
							&r->argind);
		if (r->ret)
			r->argind = 0;
		collect_seen(opts, r->seen);
		return;
	}

	diff_opts(opts, &r->cfg);
	if (ref) {
		r->ret = ref_argconfig_parse(nargs + 1, argv, opts,
					     &operands, &r->nr_operands);
		for (i = 0; !r->ret && i < r->nr_operands; i++)
			r->operands[i] = operands[i];
	} else {
		r->ret = argconfig_parse(nargs + 1, argv, "diff", opts);
		/* the getopt parser reported the help as an error */
		if (r->ret == ARGCONFIG_HELP)
			r->ret = -EINVAL;
		r->nr_operands = argconfig_nr_operands();
		for (i = 0; !r->ret && i < r->nr_operands; i++)
			r->operands[i] = argconfig_operand(i);
	}
	if (r->ret)
		r->nr_operands = 0;
	collect_seen(opts, r->seen);
}

static unsigned long nr_cases, nr_skipped;

static bool compare(char **args, int nargs, bool global)
{
	struct result ref, cur;
	int i;

	for (i = 0; i < nargs; i++) {
		if (unsupported(args[i], global)) {
			nr_skipped++;
			return true;
		}
	}

	nr_cases++;
	run(args, nargs, true, global, &ref);
	run(args, nargs, false, global, &cur);

	if (!memcmp(&ref, &cur, sizeof(ref)))
		return true;

	fprintf(report, "ERROR: %s parse differs for:",
		global ? "global" : "command");
	for (i = 0; i < nargs; i++)
		fprintf(report, " '%s'", args[i]);
	fprintf(report, "\n  ret %d/%d argind %d/%d operands %d/%d\n",
		ref.ret, cur.ret, ref.argind, cur.argind,
		ref.nr_operands, cur.nr_operands);

	return false;
}

/*
 * Time budgets in seconds. The tests run in an emulator for cross builds
 * and under valgrind, so the larger parts are limited by time, not by a
 * number of cases.
 */
#define BUDGET_THREE_WORDS	2.0
#define BUDGET_RANDOM		1.0

static double now(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec + ts.tv_nsec / 1e9;
}

static bool expired(double end, unsigned long i)
{
	/* reading the clock for every case would dominate the runtime */
	return !(i % 256) && now() > end;
}

/* All sequences of up to two words from the vocabulary */
static bool two_words(bool global)
{
	unsigned int n = ARRAY_SIZE(vocabulary), i, j;
	char *args[2];
	bool ok = compare(args, 0, global);

	for (i = 0; i < n; i++) {
		args[0] = (char *)vocabulary[i];
		ok &= compare(args, 1, global);
		for (j = 0; j < n; j++) {
			args[1] = (char *)vocabulary[j];
			ok &= compare(args, 2, global);
		}
	}

	return ok;
}

/* Sequences of three words, in a fixed order until the time is up */
static bool three_words(bool global, unsigned long *count)
{
	unsigned int n = ARRAY_SIZE(vocabulary), i;
	double end = now() + BUDGET_THREE_WORDS;
	char *args[3];
	bool ok = true;

	for (i = 0; i < n * n * n && !expired(end, i); i++) {
		args[0] = (char *)vocabulary[i / (n * n)];
		args[1] = (char *)vocabulary[i / n % n];
		args[2] = (char *)vocabulary[i % n];
		ok &= compare(args, 3, global);
	}
	*count += i;

	return ok;
}

/*
 * Longer sequences until the time is up. The seed is fixed and a failure
 * prints its arguments, so it can be reproduced.
 */
static bool random_cases(bool global, unsigned long *count)
{
	unsigned int n = ARRAY_SIZE(vocabulary);
	double end = now() + BUDGET_RANDOM;
	unsigned int seed = 0x6e766d65;
	char *args[MAX_ARGS];
	unsigned long i;
	bool ok = true;
	int nargs, j;

	for (i = 0; !expired(end, i); i++) {
		seed = seed * 1103515245 + 12345;
		nargs = 4 + (seed >> 16) % (MAX_ARGS - 3);
		for (j = 0; j < nargs; j++) {
			seed = seed * 1103515245 + 12345;
			args[j] = (char *)vocabulary[(seed >> 16) % n];
		}
		ok &= compare(args, nargs, global);
	}
	*count += i;

	return ok;
}

int main(void)
{
	unsigned int n = ARRAY_SIZE(vocabulary);
	unsigned long nr_three = 0, nr_random = 0;
	bool ok = true;
	FILE *f;

	setlocale(LC_NUMERIC, "C");
	unsetenv("POSIXLY_CORRECT");
	report = fdopen(dup(STDOUT_FILENO), "w");
	if (!report || !freopen(shr_dev_null(), "w", stdout)) {
		printf("ERROR: redirecting stdout failed: %s\n",
		       libnvme_strerror(errno));
		return EXIT_FAILURE;
	}
	f = freopen(shr_dev_null(), "w", stderr);
	if (!f) {
		fprintf(report, "ERROR: reopening stderr failed: %s\n",
			libnvme_strerror(errno));
		return EXIT_FAILURE;
	}

	ok &= filter_test();
	ok &= two_words(false);
	ok &= two_words(true);
	ok &= three_words(false, &nr_three);
	ok &= three_words(true, &nr_three);
	ok &= random_cases(false, &nr_random);
	ok &= random_cases(true, &nr_random);

	fprintf(report, "%lu cases compared, %lu skipped\n", nr_cases,
		nr_skipped);
	fprintf(report, "three words: %lu of %u, random: %lu\n",
		nr_three, 2 * n * n * n, nr_random);
	fclose(f);
	fclose(report);

	return ok ? EXIT_SUCCESS : EXIT_FAILURE;
}

#else /* __GLIBC__ */

int main(void)
{
	return 77;
}

#endif /* __GLIBC__ */
