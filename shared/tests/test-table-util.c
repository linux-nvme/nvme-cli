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

/*
 * Builds a tiny 2-column "bit : description" table, the shape a bit-field
 * decode breakdown would use as a row's nested extra table.
 */
static struct shr_table *build_decode_table(void)
{
	struct shr_table_column columns[] = {
		{ "", RIGHT, AUTO_WIDTH },
		{ "", LEFT, AUTO_WIDTH },
	};
	struct shr_table *sub = shr_table_init_with_columns(columns, 2);
	int row;

	shr_table_set_column_sep(sub, " : ");
	shr_table_set_no_header(sub, true);
	shr_table_set_indent(sub, 2);

	row = shr_table_get_row_id(sub);
	shr_table_set_value_str(sub, 0, row, "[0:0]", RIGHT);
	shr_table_set_value_str(sub, 1, row, "Multi Port", LEFT);
	shr_table_add_row(sub, row);

	return sub;
}

static bool test_row_extra(void)
{
	struct shr_table_column columns[] = {
		{ "", LEFT, AUTO_WIDTH },
		{ "", LEFT, AUTO_WIDTH },
	};
	char template[] = "shr-test-table-XXXXXX";
	struct shr_table *t;
	struct shr_table *sub;
	FILE *stream;
	char *buf;
	bool pass = true;
	long size;
	int plain_row, tagged_row, row, fd;

	printf("test_row_extra:\n");

	t = shr_table_init_with_columns(columns, 2);
	pass &= check_bool("table allocated", t != NULL);
	if (!t)
		return pass;

	plain_row = shr_table_get_row_id(t);
	shr_table_set_value_str(t, 0, plain_row, "plain", LEFT);
	shr_table_set_value_str(t, 1, plain_row, "v1", LEFT);
	shr_table_add_row(t, plain_row);

	tagged_row = shr_table_get_row_id(t);
	shr_table_set_value_str(t, 0, tagged_row, "tagged", LEFT);
	shr_table_set_value_str(t, 1, tagged_row, "v2", LEFT);
	shr_table_add_row(t, tagged_row);

	pass &= check_bool("plain row has no extra table by default",
			    shr_table_get_row_subtable(t, plain_row) == NULL);

	shr_table_set_row_subtable(t, tagged_row, build_decode_table());
	pass &= check_bool("tagged row's extra table reads back",
			    shr_table_get_row_subtable(t, tagged_row) != NULL);

	/* A second set_row_subtable() replaces (and frees) the first. */
	shr_table_set_row_subtable(t, tagged_row, build_decode_table());
	sub = shr_table_get_row_subtable(t, tagged_row);
	pass &= check_bool("set_row_subtable overwrites the previous sub-table",
			    sub != NULL);

	/* Render like a caller would: print the row, then its extra table
	 * indented, whenever one is attached.
	 */
	fd = shr_mkstemp(template);
	shr_assert(fd >= 0);
	stream = fdopen(fd, "w");
	shr_assert(stream != NULL);

	for (row = 0; row < t->num_rows; row++) {
		shr_table_print_row(stream, t, row);
		sub = shr_table_get_row_subtable(t, row);
		if (sub)
			shr_table_print_stream(stream, sub);
	}
	fclose(stream);

	shr_assert(shr_read_file_as_string(NULL, template, &size, &buf) == 0);
	shr_unlink(template);

	pass &= check_bool("plain row's line has no nested content below it",
			    strstr(buf, "plain") != NULL);
	pass &= check_bool("tagged row's nested table is indented and printed",
			    strstr(buf, "  [0:0] : Multi Port") != NULL);
	free(buf);

	shr_table_free(t);

	return pass;
}

static bool test_align_column_including_outer(void)
{
	struct shr_table_column kv_columns[] = {
		{ "", LEFT, AUTO_WIDTH },
		{ "", LEFT, AUTO_WIDTH },
		{ "", LEFT, AUTO_WIDTH },
	};
	struct shr_table_column sub_columns[] = {
		{ "", RIGHT, AUTO_WIDTH },
		{ "", LEFT, AUTO_WIDTH },
		{ "", LEFT, AUTO_WIDTH },
	};
	char template[] = "shr-test-table-XXXXXX";
	char label[32];
	struct shr_table *t, *sub_a, *sub_b, *sub;
	FILE *stream;
	char *buf;
	bool pass = true;
	long size;
	int vid_row, cntlid_row, sub_row, fd, row;

	printf("test_align_column_including_outer:\n");

	t = shr_table_init_with_columns(kv_columns, 3);
	pass &= check_bool("table allocated", t != NULL);
	if (!t)
		return pass;
	shr_table_set_no_header(t, true);

	vid_row = shr_table_get_row_id(t);
	shr_table_set_value_str(t, 0, vid_row, "vid", LEFT);
	shr_table_set_value_str(t, 1, vid_row, ":", LEFT);
	shr_table_set_value_str(t, 2, vid_row, "0x1", LEFT);
	shr_table_add_row(t, vid_row);

	cntlid_row = shr_table_get_row_id(t);
	shr_table_set_value_str(t, 0, cntlid_row, "cntlid", LEFT);
	shr_table_set_value_str(t, 1, cntlid_row, ":", LEFT);
	shr_table_set_value_str(t, 2, cntlid_row, "0x2", LEFT);
	shr_table_add_row(t, cntlid_row);

	/* Narrower subtable, attached to the shorter "vid" row. */
	sub_a = shr_table_init_with_columns(sub_columns, 3);
	shr_table_set_no_header(sub_a, true);
	shr_table_set_indent(sub_a, 2);
	sub_row = shr_table_get_row_id(sub_a);
	shr_table_set_value_str(sub_a, 0, sub_row, "[0:0]", RIGHT);
	shr_table_set_value_str(sub_a, 1, sub_row, ":", LEFT);
	shr_table_set_value_str(sub_a, 2, sub_row, "bit zero", LEFT);
	shr_table_add_row(sub_a, sub_row);
	shr_table_set_row_subtable(t, vid_row, sub_a);

	/* Wider subtable, attached to the longer "cntlid" row -- forces
	 * both the outer table and the narrower subtable to grow.
	 */
	sub_b = shr_table_init_with_columns(sub_columns, 3);
	shr_table_set_no_header(sub_b, true);
	shr_table_set_indent(sub_b, 2);
	sub_row = shr_table_get_row_id(sub_b);
	shr_table_set_value_str(sub_b, 0, sub_row, "[100:100]", RIGHT);
	shr_table_set_value_str(sub_b, 1, sub_row, ":", LEFT);
	shr_table_set_value_str(sub_b, 2, sub_row, "a wide bit range", LEFT);
	shr_table_add_row(sub_b, sub_row);
	shr_table_set_row_subtable(t, cntlid_row, sub_b);

	shr_table_align_column(t, 0, 0);

	fd = shr_mkstemp(template);
	shr_assert(fd >= 0);
	stream = fdopen(fd, "w");
	shr_assert(stream != NULL);

	for (row = 0; row < t->num_rows; row++) {
		shr_table_print_row(stream, t, row);
		sub = shr_table_get_row_subtable(t, row);
		if (sub)
			shr_table_print_stream(stream, sub);
	}
	fclose(stream);

	shr_assert(shr_read_file_as_string(NULL, template, &size, &buf) == 0);
	shr_unlink(template);

	/*
	 * The widest label is "[100:100]" (9 chars), indented by 2, so the
	 * shared column has to reach 11 -- wider than either the outer
	 * table's own "cntlid" (6) or the narrower subtable's "[0:0]" (5)
	 * would need alone.
	 */
	snprintf(label, sizeof(label), "%-11s : ", "vid");
	pass &= check_bool("outer 'vid' row's ':' is pushed out to match",
			    strstr(buf, label) != NULL);

	snprintf(label, sizeof(label), "%-11s : ", "cntlid");
	pass &= check_bool("outer 'cntlid' row's ':' is pushed out to match",
			    strstr(buf, label) != NULL);

	/* Both subtables' bits column is RIGHT-aligned, unlike the outer
	 * table's LEFT-aligned name column above.
	 */
	snprintf(label, sizeof(label), "  %9s : ", "[0:0]");
	pass &= check_bool("narrower subtable's ':' is pushed out to match",
			    strstr(buf, label) != NULL);

	snprintf(label, sizeof(label), "  %9s : ", "[100:100]");
	pass &= check_bool("widest subtable's ':' lands at the shared column",
			    strstr(buf, label) != NULL);

	free(buf);
	shr_table_free(t);

	return pass;
}

static struct shr_table *build_bits_subtable(const char *bits,
		const char *val, const char *desc)
{
	struct shr_table_column columns[] = {
		{ "", RIGHT, AUTO_WIDTH },
		{ "", LEFT, AUTO_WIDTH },
		{ "", RIGHT, AUTO_WIDTH },
		{ "", LEFT, AUTO_WIDTH },
	};
	struct shr_table *sub = shr_table_init_with_columns(columns, 4);
	int row;

	shr_table_set_no_header(sub, true);
	shr_table_set_indent(sub, 2);

	row = shr_table_get_row_id(sub);
	shr_table_set_value_str(sub, 0, row, bits, RIGHT);
	shr_table_set_value_str(sub, 1, row, ":", LEFT);
	shr_table_set_value_str(sub, 2, row, val, RIGHT);
	shr_table_set_value_str(sub, 3, row, desc, LEFT);
	shr_table_add_row(sub, row);

	return sub;
}

static bool test_align_column_subtables_only(void)
{
	struct shr_table_column kv_columns[] = {
		{ "", LEFT, AUTO_WIDTH },
		{ "", LEFT, AUTO_WIDTH },
		{ "", LEFT, AUTO_WIDTH },
	};
	char template[] = "shr-test-table-XXXXXX";
	char expected[64];
	struct shr_table *t;
	FILE *stream;
	char *buf;
	bool pass = true;
	long size;
	int narrow_row, wide_row, fd, row;
	struct shr_table *sub;

	printf("test_align_column_subtables_only:\n");

	t = shr_table_init_with_columns(kv_columns, 3);
	pass &= check_bool("table allocated", t != NULL);
	if (!t)
		return pass;
	shr_table_set_no_header(t, true);

	narrow_row = shr_table_get_row_id(t);
	shr_table_set_value_str(t, 0, narrow_row, "cmic", LEFT);
	shr_table_set_value_str(t, 1, narrow_row, ":", LEFT);
	shr_table_set_value_str(t, 2, narrow_row, "0", LEFT);
	shr_table_add_row(t, narrow_row);
	/* Every value in this subtable is a single digit. */
	shr_table_set_row_subtable(t, narrow_row,
			build_bits_subtable("[0:0]", "0", "Single Port"));

	wide_row = shr_table_get_row_id(t);
	shr_table_set_value_str(t, 0, wide_row, "elpe", LEFT);
	shr_table_set_value_str(t, 1, wide_row, ":", LEFT);
	shr_table_set_value_str(t, 2, wide_row, "63", LEFT);
	shr_table_add_row(t, wide_row);
	/* This subtable's value column needs to be wider than "cmic"'s. */
	shr_table_set_row_subtable(t, wide_row,
			build_bits_subtable("[7:0]", "0x3f", "ELPE"));

	shr_table_align_subtable_column(t, 2);

	fd = shr_mkstemp(template);
	shr_assert(fd >= 0);
	stream = fdopen(fd, "w");
	shr_assert(stream != NULL);

	for (row = 0; row < t->num_rows; row++) {
		shr_table_print_row(stream, t, row);
		sub = shr_table_get_row_subtable(t, row);
		if (sub)
			shr_table_print_stream(stream, sub);
	}
	fclose(stream);

	shr_assert(shr_read_file_as_string(NULL, template, &size, &buf) == 0);
	shr_unlink(template);

	/* "0x3f" (4 chars) is the widest value, so the narrower subtable's
	 * "0" must be padded out to the same width for its description to
	 * start at the same column as the wide subtable's.
	 */
	snprintf(expected, sizeof(expected), "%4s Single Port", "0");
	pass &= check_bool("narrow subtable's value is padded to match",
			    strstr(buf, expected) != NULL);
	snprintf(expected, sizeof(expected), "%4s ELPE", "0x3f");
	pass &= check_bool("wide subtable's value keeps its own width",
			    strstr(buf, expected) != NULL);

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
	pass &= test_row_extra();
	pass &= test_align_column_including_outer();
	pass &= test_align_column_subtables_only();
	pass &= test_shr_table_print();

	fflush(stdout);
	exit(pass ? EXIT_SUCCESS : EXIT_FAILURE);
}
