// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 SUSE Software Solutions
 *
 * Authors: Daniel Wagner <dwagner@suse.de>
 */
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <ccan/array_size/array_size.h>

#include <shared/fs-util.h>
#include <shared/assert-util.h>
#include <shared/table-util.h>

static bool check_bool(const char *name, bool got)
{
	printf(" - %s [%s]\n", name, got ? "PASS" : "FAIL");
	return got;
}

static bool test_basic_table(void)
{
	struct shr_table_column columns[] = {
		{ "Name", LEFT, AUTO_WIDTH },
		{ "Count", RIGHT, 8 },
	};
	char template[] = "shr-test-table-XXXXXX";
	struct shr_table *t;
	char *buf;
	FILE *stream;
	bool pass = true;
	long size;
	int row, fd;

	printf("test_basic_table:\n");

	t = shr_table_init_with_columns(columns, 2);
	pass &= check_bool("table allocated", t != NULL);
	if (!t)
		return pass;

	row = shr_table_get_row_id(t);
	pass &= check_bool("row id is non-negative", row >= 0);
	if (row < 0) {
		shr_table_free(t);
		return pass;
	}
	pass &= check_bool("set string value succeeds",
			    shr_table_set_value_str(t, 0, row, "widgets", LEFT) == 0);
	pass &= check_bool("set int value succeeds",
			    shr_table_set_value_int(t, 1, row, 42, RIGHT) == 0);
	shr_table_add_row(t, row);

	fd = shr_mkstemp(template);
	shr_assert(fd >= 0);
	stream = fdopen(fd, "w");
	shr_assert(stream != NULL);

	shr_table_print_stream(stream, t);
	fclose(stream);

	shr_assert(shr_read_file_as_string(NULL, template, &size, &buf) == 0);
	shr_unlink(template);

	pass &= check_bool("output contains the column header",
			    strstr(buf, "Name") != NULL);
	pass &= check_bool("output contains the row string value",
			    strstr(buf, "widgets") != NULL);
	pass &= check_bool("output contains the row int value",
			    strstr(buf, "42") != NULL);
	free(buf);

	shr_table_free(t);

	return pass;
}

static bool always_false(const char *name, void *arg)
{
	return false;
}

static bool test_add_columns_filter(void)
{
	struct shr_table_column columns[] = {
		{ "A", LEFT, AUTO_WIDTH },
		{ "B", LEFT, AUTO_WIDTH },
	};
	struct shr_table *t;
	bool pass = true;
	int ret;

	printf("test_add_columns_filter:\n");

	t = shr_table_create();
	pass &= check_bool("table allocated", t != NULL);
	if (!t)
		return pass;

	ret = shr_table_add_columns_filter(t, columns, 2, always_false, NULL);
	pass &= check_bool("filtering out every column succeeds", ret == 0);
	pass &= check_bool("no columns were added", t->num_columns == 0);

	shr_table_free(t);

	return pass;
}

static bool keep_even(const char *name, void *arg)
{
	int *idx = arg;
	bool keep = (*idx % 2) == 0;

	(*idx)++;
	return keep;
}

static bool test_add_columns_filter_partial(void)
{
	struct shr_table_column columns[] = {
		{ "Keep0", LEFT, AUTO_WIDTH },
		{ "Skip1", LEFT, AUTO_WIDTH },
		{ "Keep2", LEFT, 10 },
	};
	struct shr_table *t;
	bool pass = true;
	int idx = 0;
	int ret;

	printf("test_add_columns_filter_partial:\n");

	t = shr_table_create();
	pass &= check_bool("table allocated", t != NULL);
	if (!t)
		return pass;

	ret = shr_table_add_columns_filter(t, columns, 3, keep_even, &idx);
	pass &= check_bool("filtering some columns succeeds", ret == 0);
	pass &= check_bool("only the kept columns were added", t->num_columns == 2);
	if (t->num_columns == 2) {
		pass &= check_bool("first kept column name matches",
				    strcmp(t->columns[0].name, "Keep0") == 0);
		pass &= check_bool("first kept column has auto width",
				    t->columns[0].auto_adjust);
		pass &= check_bool("second kept column name matches",
				    strcmp(t->columns[1].name, "Keep2") == 0);
		pass &= check_bool("second kept column has fixed width",
				    !t->columns[1].auto_adjust && t->columns[1].width == 10);
	}

	shr_table_free(t);

	return pass;
}

static bool test_add_columns_filter_null(void)
{
	struct shr_table_column columns[] = {
		{ "Only", LEFT, AUTO_WIDTH },
	};
	struct shr_table *t;
	bool pass = true;
	int ret;

	printf("test_add_columns_filter_null:\n");

	t = shr_table_create();
	pass &= check_bool("table allocated", t != NULL);
	if (!t)
		return pass;

	ret = shr_table_add_columns_filter(t, columns, 1, NULL, NULL);
	pass &= check_bool("NULL filter delegates and succeeds", ret == 0);
	pass &= check_bool("column was added", t->num_columns == 1);

	shr_table_free(t);

	return pass;
}

static bool always_true(const char *name, void *arg)
{
	return true;
}

static bool test_add_columns_invalid_width(void)
{
	struct shr_table_column columns[] = {
		{ "AAAA", LEFT, 10 },
		{ "B", LEFT, 0 },
	};
	struct shr_table *t;
	bool pass = true;

	printf("test_add_columns_invalid_width:\n");

	t = shr_table_init_with_columns(columns, 2);
	pass &= check_bool("fixed width smaller than name length fails",
			    t == NULL);
	if (t)
		shr_table_free(t);

	return pass;
}

static bool test_add_columns_filter_invalid_width(void)
{
	struct shr_table_column columns[] = {
		{ "A", LEFT, AUTO_WIDTH },
		{ "BB", LEFT, 1 },
	};
	struct shr_table *t;
	bool pass = true;
	int ret;

	printf("test_add_columns_filter_invalid_width:\n");

	t = shr_table_create();
	pass &= check_bool("table allocated", t != NULL);
	if (!t)
		return pass;

	ret = shr_table_add_columns_filter(t, columns, 2, always_true, NULL);
	pass &= check_bool("fixed width smaller than name length fails", ret == -EINVAL);
	pass &= check_bool("columns were rolled back", t->num_columns == 0 && t->columns == NULL);

	shr_table_free(t);

	return pass;
}

static bool test_multi_type_and_centered(void)
{
	struct shr_table_column columns[] = {
		{ "Str",    LEFT,     AUTO_WIDTH },
		{ "Int",    RIGHT,    AUTO_WIDTH },
		{ "UInt",   RIGHT,    AUTO_WIDTH },
		{ "Long",   RIGHT,    AUTO_WIDTH },
		{ "ULong",  RIGHT,    AUTO_WIDTH },
		{ "Float",  RIGHT,    AUTO_WIDTH },
		{ "Double", CENTERED, AUTO_WIDTH },
	};
	char template[] = "shr-test-table-XXXXXX";
	struct shr_table *t;
	char *buf;
	FILE *stream;
	bool pass = true;
	long size;
	int ra, rb, fd;

	printf("test_multi_type_and_centered:\n");

	t = shr_table_init_with_columns(columns, 7);
	pass &= check_bool("table allocated", t != NULL);
	if (!t)
		return pass;

	/* Row A: every value centered, exercising every value type. */
	ra = shr_table_get_row_id(t);
	pass &= check_bool("row A id is non-negative", ra >= 0);
	if (ra < 0) {
		shr_table_free(t);
		return pass;
	}
	shr_table_set_value_str(t, 0, ra, "abc", CENTERED);
	shr_table_set_value_int(t, 1, ra, -5, CENTERED);
	shr_table_set_value_unsigned(t, 2, ra, 7, CENTERED);
	shr_table_set_value_long(t, 3, ra, -12345, CENTERED);
	shr_table_set_value_unsigned_long(t, 4, ra, 99999, CENTERED);
	shr_table_set_value_float(t, 5, ra, 3.14f, CENTERED);
	shr_table_set_value_double(t, 6, ra, 2.71, CENTERED);
	shr_table_add_row(t, ra);

	/* Row B: mix of left/right alignment, same set of types. */
	rb = shr_table_get_row_id(t);
	pass &= check_bool("row B id is non-negative", rb >= 0);
	if (rb < 0) {
		shr_table_free(t);
		return pass;
	}
	shr_table_set_value_str(t, 0, rb, "xyz", LEFT);
	shr_table_set_value_int(t, 1, rb, 42, RIGHT);
	shr_table_set_value_unsigned(t, 2, rb, 3, LEFT);
	shr_table_set_value_long(t, 3, rb, -7, RIGHT);
	shr_table_set_value_unsigned_long(t, 4, rb, 123, LEFT);
	shr_table_set_value_float(t, 5, rb, 1.5f, RIGHT);
	shr_table_set_value_double(t, 6, rb, 9.99, LEFT);
	shr_table_add_row(t, rb);

	fd = shr_mkstemp(template);
	shr_assert(fd >= 0);
	stream = fdopen(fd, "w");
	shr_assert(stream != NULL);

	shr_table_print_stream(stream, t);
	fclose(stream);

	shr_assert(shr_read_file_as_string(NULL, template, &size, &buf) == 0);
	shr_unlink(template);

	pass &= check_bool("output contains the centered column header",
			    strstr(buf, "Double") != NULL);
	pass &= check_bool("output contains the centered string value",
			    strstr(buf, "abc") != NULL);
	pass &= check_bool("output contains the centered negative int value",
			    strstr(buf, "-5") != NULL);
	pass &= check_bool("output contains the centered float value",
			    strstr(buf, "3.14") != NULL);
	pass &= check_bool("output contains the left-aligned string value",
			    strstr(buf, "xyz") != NULL);
	pass &= check_bool("output contains the right-aligned int value",
			    strstr(buf, "42") != NULL);
	pass &= check_bool("output contains the double value",
			    strstr(buf, "9.99") != NULL);
	free(buf);

	shr_table_free(t);

	return pass;
}

static bool test_invalid_format_type(void)
{
	struct shr_table_column columns[] = {
		{ "Centered", CENTERED, AUTO_WIDTH },
		{ "Plain",    RIGHT,    AUTO_WIDTH },
	};
	char template[] = "shr-test-table-XXXXXX";
	struct shr_table *t;
	unsigned char *buf = NULL;
	FILE *stream;
	bool pass = true;
	long size;
	int row, fd;

	printf("test_invalid_format_type:\n");

	t = shr_table_init_with_columns(columns, 2);
	pass &= check_bool("table allocated", t != NULL);
	if (!t)
		return pass;

	row = shr_table_get_row_id(t);
	pass &= check_bool("row id is non-negative", row >= 0);
	if (row < 0) {
		shr_table_free(t);
		return pass;
	}
	shr_table_set_value_int(t, 0, row, 0, CENTERED);
	shr_table_set_value_int(t, 1, row, 0, RIGHT);
	/* Force an out-of-range format type to exercise the defensive
	 * "unknown format" branches in table-util.c.
	 */
	t->rows[row].val[0].type = (enum fmt_type)99;
	t->rows[row].val[1].type = (enum fmt_type)99;
	shr_table_add_row(t, row);

	fd = shr_mkstemp(template);
	shr_assert(fd >= 0);
	stream = fdopen(fd, "w");
	shr_assert(stream != NULL);

	/* Should not crash even though the format type is bogus. */
	shr_table_print_stream(stream, t);
	fclose(stream);

	pass &= check_bool("output was still produced",
			    shr_read_file(NULL, template, &size, &buf) == 0);
	shr_unlink(template);
	free(buf);

	shr_table_free(t);

	return pass;
}

static bool test_key_value_style(void)
{
	struct shr_table_column columns[] = {
		{ "", LEFT, AUTO_WIDTH },
		{ "", LEFT, AUTO_WIDTH },
	};
	static const struct {
		const char *name;
		const char *val;
	} fields[] = {
		{ "vid",    "0x1234" },
		{ "ssvid",  "0x5678" },
		{ "cntlid", "0xabcd" },
	};
	char template[] = "shr-test-table-XXXXXX";
	struct shr_table *t;
	char *buf;
	FILE *stream;
	bool pass = true;
	long size;
	int row, fd, i, name_width = 0, val_width = 0;
	char expected[64];

	printf("test_key_value_style:\n");

	/*
	 * A key/value listing (as used for e.g. identify-structure dumps)
	 * has no real header and uses ": " rather than a bare space between
	 * the field name and its value. Both are supported without
	 * touching the row/column printing model itself.
	 */
	t = shr_table_init_with_columns(columns, 2);
	pass &= check_bool("table allocated", t != NULL);
	if (!t)
		return pass;

	shr_table_set_column_sep(t, " : ");
	shr_table_set_no_header(t, true);

	for (i = 0; i < (int)ARRAY_SIZE(fields); i++) {
		row = shr_table_get_row_id(t);
		pass &= check_bool("row id is non-negative", row >= 0);
		if (row < 0) {
			shr_table_free(t);
			return pass;
		}
		shr_table_set_value_str(t, 0, row, fields[i].name, LEFT);
		shr_table_set_value_str(t, 1, row, fields[i].val, LEFT);
		shr_table_add_row(t, row);

		if ((int)strlen(fields[i].name) > name_width)
			name_width = (int)strlen(fields[i].name);
		if ((int)strlen(fields[i].val) > val_width)
			val_width = (int)strlen(fields[i].val);
	}

	fd = shr_mkstemp(template);
	shr_assert(fd >= 0);
	stream = fdopen(fd, "w");
	shr_assert(stream != NULL);

	shr_table_print_stream(stream, t);
	fclose(stream);

	shr_assert(shr_read_file_as_string(NULL, template, &size, &buf) == 0);
	shr_unlink(template);

	pass &= check_bool("no header/dash line is printed",
			    strstr(buf, "----") == NULL);

	/* Every field name is padded to the width of the longest one
	 * ("cntlid"), even the shorter names added earlier, proving the
	 * width reflects all collected rows rather than a hand-picked
	 * constant.
	 */
	for (i = 0; i < (int)ARRAY_SIZE(fields); i++) {
		snprintf(expected, sizeof(expected), "%-*s : %-*s\n",
			 name_width, fields[i].name, val_width, fields[i].val);
		pass &= check_bool(fields[i].name,
				    strstr(buf, expected) != NULL);
	}

	free(buf);
	shr_table_free(t);

	return pass;
}

static bool test_print_row_interleaved(void)
{
	struct shr_table_column columns[] = {
		{ "", LEFT, AUTO_WIDTH },
		{ "", LEFT, AUTO_WIDTH },
	};
	char template[] = "shr-test-table-XXXXXX";
	struct shr_table *t;
	char *buf;
	FILE *stream;
	bool pass = true;
	long size;
	int row_vid, row_cntlid, fd, name_width;
	char expected[128];

	printf("test_print_row_interleaved:\n");

	/*
	 * Mirrors how a verbose identify-structure dump wants to print a
	 * field and immediately follow it with extra decoded bit-field
	 * text, instead of the whole table being emitted as one block at
	 * the end. shr_table_print_row() lets the caller drive that, while
	 * still benefiting from the width already computed across all rows
	 * added so far.
	 */
	t = shr_table_init_with_columns(columns, 2);
	pass &= check_bool("table allocated", t != NULL);
	if (!t)
		return pass;

	shr_table_set_column_sep(t, " : ");
	shr_table_set_no_header(t, true);

	row_vid = shr_table_get_row_id(t);
	pass &= check_bool("vid row id is non-negative", row_vid >= 0);
	shr_table_set_value_str(t, 0, row_vid, "vid", LEFT);
	shr_table_set_value_str(t, 1, row_vid, "0x1234", LEFT);
	shr_table_add_row(t, row_vid);

	row_cntlid = shr_table_get_row_id(t);
	pass &= check_bool("cntlid row id is non-negative", row_cntlid >= 0);
	shr_table_set_value_str(t, 0, row_cntlid, "cntlid", LEFT);
	shr_table_set_value_str(t, 1, row_cntlid, "0xabcd", LEFT);
	shr_table_add_row(t, row_cntlid);

	fd = shr_mkstemp(template);
	shr_assert(fd >= 0);
	stream = fdopen(fd, "w");
	shr_assert(stream != NULL);

	/* Print "vid" now, with a decoded line right after it, then
	 * "cntlid" later -- even though "cntlid" (added after "vid") is
	 * what determines the name column's width.
	 */
	shr_table_print_row(stream, t, row_vid);
	fprintf(stream, "  [decoded: vendor id]\n");
	shr_table_print_row(stream, t, row_cntlid);

	fclose(stream);

	shr_assert(shr_read_file_as_string(NULL, template, &size, &buf) == 0);
	shr_unlink(template);

	name_width = (int)strlen("cntlid");

	snprintf(expected, sizeof(expected),
		 "%-*s : %-*s\n  [decoded: vendor id]\n",
		 name_width, "vid", (int)strlen("0x1234"), "0x1234");
	pass &= check_bool("decoded text follows its row, already padded",
			    strstr(buf, expected) != NULL);

	snprintf(expected, sizeof(expected), "%-*s : %-*s\n",
		 name_width, "cntlid", (int)strlen("0xabcd"), "0xabcd");
	pass &= check_bool("cntlid row follows the interleaved text",
			    strstr(buf, expected) != NULL);

	free(buf);
	shr_table_free(t);

	return pass;
}

static bool test_shr_table_print(void)
{
	struct shr_table_column columns[] = {
		{ "Name", LEFT, AUTO_WIDTH },
	};
	char template[] = "shr-test-table-XXXXXX";
	struct shr_table *t;
	char *buf;
	bool pass = true;
	long size;
	int row, fd, saved_stdout;

	printf("test_shr_table_print:\n");

	t = shr_table_init_with_columns(columns, 1);
	pass &= check_bool("table allocated", t != NULL);
	if (!t)
		return pass;

	row = shr_table_get_row_id(t);
	pass &= check_bool("row id is non-negative", row >= 0);
	if (row < 0) {
		shr_table_free(t);
		return pass;
	}
	shr_table_set_value_str(t, 0, row, "stdout-target", LEFT);
	shr_table_add_row(t, row);

	fd = shr_mkstemp(template);
	shr_assert(fd >= 0);

	fflush(stdout);
	saved_stdout = dup(STDOUT_FILENO);
	shr_assert(saved_stdout >= 0);
	shr_assert(dup2(fd, STDOUT_FILENO) >= 0);
	close(fd);

	shr_table_print(t);
	fflush(stdout);

	shr_assert(dup2(saved_stdout, STDOUT_FILENO) >= 0);
	close(saved_stdout);

	shr_assert(shr_read_file_as_string(NULL, template, &size, &buf) == 0);
	shr_unlink(template);

	pass &= check_bool("shr_table_print wrote to stdout",
			    strstr(buf, "stdout-target") != NULL);
	free(buf);

	shr_table_free(t);

	return pass;
}

int main(void)
{
	bool pass = true;

	pass &= test_basic_table();
	pass &= test_add_columns_filter();
	pass &= test_add_columns_filter_partial();
	pass &= test_add_columns_filter_null();
	pass &= test_add_columns_invalid_width();
	pass &= test_add_columns_filter_invalid_width();
	pass &= test_multi_type_and_centered();
	pass &= test_invalid_format_type();
	pass &= test_key_value_style();
	pass &= test_print_row_interleaved();
	pass &= test_shr_table_print();

	fflush(stdout);
	exit(pass ? EXIT_SUCCESS : EXIT_FAILURE);
}
