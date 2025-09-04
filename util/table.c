// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * table.c : Common APIs for printing tabular format output.
 *
 * Copyright (c) 2025 Nilay Shroff, IBM
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>

#include "table.h"

static int table_get_value_width(struct value *v)
{
	char buf[64];
	int len = 0;

	switch (v->type) {
	case FMT_STRING:
		len = strlen((const char *)v->s);
		break;
	case FMT_INT:
		len = snprintf(buf, sizeof(buf), "%d", v->i);
		break;
	default:
		printf("Invalid print format!\n");
		break;
	}
	return len;
}

static void table_print_centered(struct value *val, int width, enum fmt_type type)
{
	int i, len, left_pad, right_pad;
	char buf[64];

	if (type == FMT_STRING)
		len = strlen(val->s);
	else if (type == FMT_INT)
		len = snprintf(buf, sizeof(buf), "%d", val->i);
	else if (type == FMT_UNSIGNED)
		len = snprintf(buf, sizeof(buf), "%u", val->u);
	else if (type == FMT_LONG)
		len = snprintf(buf, sizeof(buf), "%ld", val->ld);
	else if (type == FMT_UNSIGNED_LONG)
		len = snprintf(buf, sizeof(buf), "%lu", val->lu);
	else {
		fprintf(stderr, "Invalid format!\n");
		return;
	}

	left_pad = (width - len) / 2;
	right_pad = width - len - left_pad;

	/* add left padding */
	for (i = 0; i < left_pad; i++)
		putchar(' ');

	/* print value */
	if (type == FMT_STRING)
		printf("%s ", val->s);
	else if (type == FMT_INT)
		printf("%d ", val->i);
	else if (type == FMT_UNSIGNED)
		printf("%u ", val->u);
	else if (type == FMT_LONG)
		printf("%ld ", val->ld);
	else if (type == FMT_UNSIGNED_LONG)
		printf("%lu", val->lu);

	/* add right padding */
	for (i = 0; i < right_pad; i++)
		putchar(' ');
}

static void table_print_columns(const struct table *t)
{
	int col, j, width;
	struct table_column *c;
	struct value v;

	for (col = 0; col < t->num_columns; col++) {
		c = &t->columns[col];
		width = c->width;
		if (c->align == LEFT)
			width *= -1;

		if (c->align == CENTERED) {
			v.s = c->name;
			v.align = c->align;
			table_print_centered(&v, width, FMT_STRING);
		} else
			printf("%*s ", width, c->name);
	}

	printf("\n");

	for (col = 0; col < t->num_columns; col++) {
		for (j = 0; j < t->columns[col].width; j++)
			putchar('-');
		printf(" ");
	}

	printf("\n");
}

static void table_print_rows(const struct table *t)
{
	int row, col;
	struct table_column *c;
	struct table_row *r;
	int width;
	struct value *v;

	for (row = 0; row < t->num_rows; row++) {
		for (col = 0; col < t->num_columns; col++) {
			c = &t->columns[col];
			r = &t->rows[row];
			v = &r->val[col];

			width = c->width;
			if (v->align == LEFT)
				width *= -1;

			if (v->align == CENTERED)
				table_print_centered(v, width, v->type);
			else {
				switch (v->type) {
				case FMT_STRING:
					printf("%*s ", width, v->s);
					break;

				case FMT_INT:
					printf("%*d ", width, v->i);
					break;

				case FMT_UNSIGNED:
					printf("%*u ", width, v->u);
					break;

				case FMT_LONG:
					printf("%*ld ", width, v->ld);
					break;

				case FMT_UNSIGNED_LONG:
					printf("%*lu ", width, v->lu);
					break;

				default:
					fprintf(stderr, "Invalid format!\n");
					break;
				}
			}
		}
		printf("\n");
	}
}

void table_print(struct table *t)
{
	/* first print columns */
	table_print_columns(t);

	/* next print rows */
	table_print_rows(t);
}

int table_get_row_id(struct table *t)
{
	struct table_row *new_rows;
	int row = t->num_rows;

	new_rows = reallocarray(t->rows, (row + 1), sizeof(struct table_row));
	if (!new_rows)
		return -ENOMEM;

	t->rows = new_rows;
	t->rows[row].val = calloc(t->num_columns, sizeof(struct value));
	if (!t->rows->val)
		return -ENOMEM;

	t->num_rows++;
	return row;
}

void table_add_row(struct table *t, int row_id)
{
	int col, max_width, width;
	struct table_row *row = &t->rows[row_id];

	/* Adjust the column width based on the row value. */
	for (col = 0; col < t->num_columns; col++) {
		max_width = t->columns[col].width;
		width = table_get_value_width(&row->val[col]);
		if (width > max_width)
			t->columns[col].width = width;
	}
}

struct table *table_init(void)
{
	struct table *t;

	t = malloc(sizeof(struct table));
	if (!t)
		return NULL;

	memset(t, 0, sizeof(struct table));
	return t;
}

static int table_add_column(struct table *t, struct table_column *c)
{
	struct table_column *new_columns;
	int col = t->num_columns;

	new_columns = reallocarray(t->columns, t->num_columns + 1,
			sizeof(struct table_column));
	if (!new_columns)
		return -ENOMEM;

	t->columns = new_columns;
	t->columns[col].name = strdup(c->name);
	if (!t->columns[col].name)
		return -ENOMEM;
	t->columns[col].align = c->align;
	t->columns[col].width = strlen(c->name);
	t->num_columns++;

	return 0;
}

int table_add_columns_filter(struct table *t, struct table_column *c,
			int num_columns,
			bool (*filter)(const char *name, void *arg),
			void *arg)
{
	int col;

	if (!filter)
		return table_add_columns(t, c, num_columns);

	for (col = 0; col < num_columns; col++) {
		if (!filter(c[col].name, arg))
			continue;	/* skip this column */

		if (table_add_column(t, &c[col]))
			goto out;
	}
	return 0;
out:
	return -ENOMEM;
}

int table_add_columns(struct table *t, struct table_column *c, int num_columns)
{
	int col;

	t->columns = calloc(num_columns, sizeof(struct table_column));
	if (!t->columns)
		return -ENOMEM;

	for (col = 0; col < num_columns; col++) {
		t->columns[col].name = strdup(c[col].name);
		if (!t->columns[col].name)
			goto free_col;

		t->columns[col].align = c[col].align;
		t->columns[col].width = strlen(t->columns[col].name);
	}
	t->num_columns = num_columns;

	return 0;
free_col:
	while (--col >= 0)
		free(t->columns[col].name);
	free(t->columns);
	t->columns = NULL;
	return -ENOMEM;
}

void table_free(struct table *t)
{
	int row, col;
	struct table_row *r;
	struct value *v;

	/* free rows */
	for (row = 0; row < t->num_rows; row++) {
		r = &t->rows[row];
		for (col = 0; col < t->num_columns; col++) {
			v = &r->val[col];

			if (v->type == FMT_STRING)
				free(v->s);
		}
		free(r->val);
	}
	free(t->rows);

	/* free columns */
	for (col = 0; col < t->num_columns; col++)
		free(t->columns[col].name);
	free(t->columns);

	/* free table */
	free(t);
}
