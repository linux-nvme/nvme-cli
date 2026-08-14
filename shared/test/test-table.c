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

#include <shared/fs-util.h>
#include <shared/shr-assert.h>
#include <shared/table.h>

static bool check_bool(const char *name, bool got)
{
	printf(" - %s [%s]\n", name, got ? "PASS" : "FAIL");
	return got;
}

static bool test_basic_table(void)
{
	struct shr_table_column columns[] = {
		{ "Name", LEFT, AUTO_WIDTH },
		{ "Count", RIGHT, AUTO_WIDTH },
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

int main(void)
{
	bool pass = true;

	pass &= test_basic_table();
	pass &= test_add_columns_filter();

	fflush(stdout);
	exit(pass ? EXIT_SUCCESS : EXIT_FAILURE);
}
