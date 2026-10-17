// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 SUSE Software Solutions
 *
 * Authors: Daniel Wagner <dwagner@suse.de>
 */

/*
 * A sandboxed option parser hands back what it wrote, and the caller
 * keeps it only if a parser could have written it. Feed
 * argconfig_valid_result() states a parser of the command line or of a
 * text can and cannot produce.
 */
#include "../../../src/argconfig.c"

#include <ccan/array_size/array_size.h>

static int test_rc;

static bool flag;
static char *str;
static uint8_t byte;
static int type;
static uint32_t types;
static const char foreign[] = "foreign";

static OPT_VALS(str_vals) = {
	VAL_STRING("alpha", NULL, "ALPHA"),
	VAL_END()
};

static OPT_VALS(byte_vals) = {
	VAL_BYTE("max", 200),
	VAL_END()
};

static OPT_VALS(type_vals) = {
	VAL_ENUM("one", 1),
	VAL_ENUM("two", 2),
	VAL_END()
};

static OPT_VALS(types_vals) = {
	VAL_ENUM("a", 0x1),
	VAL_ENUM("b", 0x4),
	VAL_END()
};

static struct argconfig_commandline_options opts[] = {
	OPT_FLAG("flag", 'f', &flag, "flag"),
	OPT_STRING("str", 's', "STR", &str, "str", str_vals),
	OPT_BYTE("byte", 'b', &byte, "byte", byte_vals, .min = 1, .max = 4),
	OPT_ENUM("type", 't', &type, "type", type_vals),
	OPT_ENUM_LIST("types", 'T', &types, "types", types_vals),
	OPT_END()
};

static char *argv[] = { "test", "--str=value", "dev", NULL };
static const char text[] = "str=value\nbyte=3\n";
static char *operands_buf[3];
static struct argconfig_parser p = {
	.argc = 3,
	.argv = argv,
	.operands = operands_buf,
};
static struct argconfig_commandline_options *leaves[ARRAY_SIZE(opts)];
static uint64_t orig[ARRAY_SIZE(opts)];
static struct argconfig_job job = {
	.p = &p,
	.opts = leaves,
	.orig = orig,
};

/* The state before a parse: nothing given */
static void reset(void)
{
	unsigned int i;

	flag = false;
	str = "default";
	byte = 0;
	type = 0;
	types = 0x2;
	for (i = 0; opts[i].option; i++)
		opts[i].seen = false;
	p.ind = 1;
	p.help = false;
	p.version = false;
	p.nr_operands = 0;
	for (i = 0; i < job.nr; i++)
		memcpy(&orig[i], leaves[i]->default_value,
		       argconfig_value_size(leaves[i]));
}

/* Option @i was given */
static void given(unsigned int i)
{
	opts[i].seen = true;
}

static void check(bool cond, const char *desc)
{
	printf(" - %s [%s]\n", desc, cond ? "PASS" : "FAIL");
	if (!cond)
		test_rc = 1;
}

int main(void)
{
	printf("argconfig sandbox result:\n");
	argconfig_root(p.root, opts);
	job.nr = argconfig_leaves(p.root, leaves, 0);

	reset();
	check(argconfig_valid_result(&job), "unchanged");
	p.ind = 3;
	p.nr_operands = 1;
	operands_buf[0] = argv[2];
	check(argconfig_valid_result(&job), "an operand");
	reset();
	given(1);
	str = argv[1] + 6;
	check(argconfig_valid_result(&job), "string in an argument");
	str = (char *)str_vals[0].val.string;
	check(argconfig_valid_result(&job), "string of the value table");
	str = NULL;
	check(argconfig_valid_result(&job), "no string");
	reset();
	given(0);
	flag = true;
	given(2);
	byte = 4;
	given(3);
	type = 2;
	given(4);
	types = 0x7;
	check(argconfig_valid_result(&job), "values of given options");
	byte = 200;
	check(argconfig_valid_result(&job), "a named number out of range");

	reset();
	given(1);
	str = (char *)foreign;
	check(!argconfig_valid_result(&job), "string elsewhere");
	reset();
	str = argv[1];
	check(!argconfig_valid_result(&job), "value of an option not given");
	reset();
	given(2);
	byte = 5;
	check(!argconfig_valid_result(&job), "number out of range");
	reset();
	given(3);
	type = 3;
	check(!argconfig_valid_result(&job), "no value of the enum");
	reset();
	given(4);
	types = 0x8;
	check(!argconfig_valid_result(&job), "no bit of the list");
	reset();
	given(0);
	*(unsigned char *)&flag = 2;
	check(!argconfig_valid_result(&job), "flag not a boolean");
	reset();
	*(unsigned char *)&opts[0].seen = 2;
	check(!argconfig_valid_result(&job), "seen not a boolean");
	reset();
	*(unsigned char *)&p.help = 2;
	check(!argconfig_valid_result(&job), "help not a boolean");
	reset();
	p.ind = 4;
	check(!argconfig_valid_result(&job), "position beyond the arguments");
	reset();
	p.ind = 0;
	check(!argconfig_valid_result(&job), "position before the arguments");
	reset();
	p.nr_operands = 4;
	check(!argconfig_valid_result(&job), "more operands than arguments");
	reset();
	p.nr_operands = 1;
	operands_buf[0] = argv[1] + 2;
	check(!argconfig_valid_result(&job), "operand inside an argument");
	reset();
	p.nr_operands = 1;
	operands_buf[0] = (char *)foreign;
	check(!argconfig_valid_result(&job), "foreign operand");

	/* A parser of a text sets options without a command line */
	job.p = NULL;
	job.buf = (char *)text;
	job.size = sizeof(text);
	reset();
	str = (char *)text + 4;
	byte = 3;
	check(argconfig_valid_result(&job), "values of a text");
	str = argv[1];
	check(!argconfig_valid_result(&job), "string outside the text");
	reset();
	byte = 9;
	check(!argconfig_valid_result(&job), "number of a text out of range");

	return test_rc ? EXIT_FAILURE : EXIT_SUCCESS;
}
