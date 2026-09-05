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
	unsigned char *buf;
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

	buf = shr_read_file(NULL, template, &size, 1);
	shr_unlink(template);
	shr_assert(buf != NULL);

	pass &= check_bool("output contains the column header",
			    strstr((char *)buf, "Name") != NULL);
	pass &= check_bool("output contains the row string value",
			    strstr((char *)buf, "widgets") != NULL);
	pass &= check_bool("output contains the row int value",
			    strstr((char *)buf, "42") != NULL);
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
	unsigned char *buf;
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

	buf = shr_read_file(NULL, template, &size, 1);
	shr_unlink(template);
	shr_assert(buf != NULL);

	pass &= check_bool("output contains the centered column header",
			    strstr((char *)buf, "Double") != NULL);
	pass &= check_bool("output contains the centered string value",
			    strstr((char *)buf, "abc") != NULL);
	pass &= check_bool("output contains the centered negative int value",
			    strstr((char *)buf, "-5") != NULL);
	pass &= check_bool("output contains the centered float value",
			    strstr((char *)buf, "3.14") != NULL);
	pass &= check_bool("output contains the left-aligned string value",
			    strstr((char *)buf, "xyz") != NULL);
	pass &= check_bool("output contains the right-aligned int value",
			    strstr((char *)buf, "42") != NULL);
	pass &= check_bool("output contains the double value",
			    strstr((char *)buf, "9.99") != NULL);
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
	unsigned char *buf;
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

	buf = shr_read_file(NULL, template, &size, 1);
	shr_unlink(template);
	pass &= check_bool("output was still produced", buf != NULL);
	free(buf);

	shr_table_free(t);

	return pass;
}

static bool test_null_string_value(void)
{
	struct shr_table_column columns[] = {
		{ "FW Rev", LEFT, AUTO_WIDTH },
	};
	struct shr_table *t;
	bool pass = true;
	int row;

	printf("test_null_string_value:\n");

	t = shr_table_init_with_columns(columns, 1);
	shr_assert(t != NULL);
	row = shr_table_get_row_id(t);
	shr_assert(row >= 0);

	/* A missing device attribute reaches the table as a NULL string. */
	pass &= check_bool("set NULL string value succeeds",
			    shr_table_set_value_str(t, 0, row, NULL, LEFT) == 0);
	pass &= check_bool("NULL string value stored as empty string",
			    t->rows[row].val[0].s && !t->rows[row].val[0].s[0]);

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
	unsigned char *buf;
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

	buf = shr_read_file(NULL, template, &size, 1);
	shr_unlink(template);
	shr_assert(buf != NULL);

	pass &= check_bool("shr_table_print wrote to stdout",
			    strstr((char *)buf, "stdout-target") != NULL);
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
	pass &= test_null_string_value();
	pass &= test_shr_table_print();

	fflush(stdout);
	exit(pass ? EXIT_SUCCESS : EXIT_FAILURE);
}
