// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * table.c : Common APIs for printing tabular format output.
 *
 * This file is part of nvme-cli.
 * Copyright (c) 2025 Nilay Shroff, IBM
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>

#include "table-util.h"

#if !NVME_HAVE_REALLOCARRAY
#include <stdint.h>

static void *reallocarray(void *ptr, size_t nmemb, size_t size)
{
	if (nmemb != 0 && size > SIZE_MAX / nmemb) {
		errno = ENOMEM;
		return NULL;
	}

	return realloc(ptr, nmemb * size);
}
#endif

static int table_get_value_width(struct shr_table_value *v)
{
	char buf[64];
	int len = -1;

	switch (v->type) {
	case FMT_STRING:
		len = strlen((const char *)v->s);
		break;
	case FMT_INT:
		len = snprintf(buf, sizeof(buf), "%d", v->i);
		break;
	case FMT_UNSIGNED:
		len = snprintf(buf, sizeof(buf), "%u", v->u);
		break;
	case FMT_UNSIGNED_LONG:
		len = snprintf(buf, sizeof(buf), "%lu", v->lu);
		break;
	case FMT_LONG:
		len = snprintf(buf, sizeof(buf), "%ld", v->ld);
		break;
	case FMT_FLOAT:
		len = snprintf(buf, sizeof(buf), "%.2f", v->f);
		break;
	case FMT_DOUBLE:
		len = snprintf(buf, sizeof(buf), "%.2f", v->d);
		break;
	default:
		fprintf(stderr, "Invalid print format!\n");
		break;
	}
	return len;
}

static void table_print_centered(FILE *stream, struct shr_table_value *val, int width)
{
	int i, len, left_pad, right_pad;

	len = table_get_value_width(val);
	if (len < 0)
		return;

	left_pad = (width - len) / 2;
	right_pad = width - len - left_pad;

	/* add left padding */
	for (i = 0; i < left_pad; i++)
		fputc(' ', stream);

	/* print value */
	switch (val->type) {
	case FMT_STRING:
		fprintf(stream, "%s", val->s);
		break;
	case FMT_INT:
		fprintf(stream, "%d", val->i);
		break;
	case FMT_UNSIGNED:
		fprintf(stream, "%u", val->u);
		break;
	case FMT_LONG:
		fprintf(stream, "%ld", val->ld);
		break;
	case FMT_UNSIGNED_LONG:
		fprintf(stream, "%lu", val->lu);
		break;
	case FMT_FLOAT:
		fprintf(stream, "%.2f", val->f);
		break;
	case FMT_DOUBLE:
		fprintf(stream, "%.2f", val->d);
		break;
	default:
		fprintf(stderr, "Invalid print format!\n");
		break;
	}

	/* add right padding */
	for (i = 0; i < right_pad; i++)
		fputc(' ', stream);
}

static void table_print_columns(FILE *stream, const struct shr_table *t)
{
	int col, j, width;
	struct shr_table_column *c;
	struct shr_table_value v;

	for (col = 0; col < t->num_columns; col++) {
		c = &t->columns[col];
		width = c->width;
		switch (c->align) {
		case CENTERED:
			v.s = c->name;
			v.align = c->align;
			v.type = FMT_STRING;
			table_print_centered(stream, &v, width);
			break;
		case LEFT:
			width *= -1;
			fallthrough;
		default:
			fprintf(stream, "%*s", width, c->name);
			break;
		}
		if (col + 1 != t->num_columns)
			fputc(' ', stream);
	}

	fprintf(stream, "\n");

	for (col = 0; col < t->num_columns; col++) {
		for (j = 0; j < t->columns[col].width; j++)
			fputc('-', stream);
		if (col + 1 != t->num_columns)
			fputc(' ', stream);
	}

	fprintf(stream, "\n");
}

static void table_print_rows(FILE *stream, const struct shr_table *t)
{
	int row, col;
	struct shr_table_column *c;
	struct shr_table_row *r;
	int width;
	struct shr_table_value *v;

	for (row = 0; row < t->num_rows; row++) {
		r = &t->rows[row];
		for (col = 0; col < t->num_columns; col++) {
			c = &t->columns[col];
			v = &r->val[col];

			width = c->width;
			switch (v->align) {
			case CENTERED:
				table_print_centered(stream, v, width);
				break;
			case LEFT:
				width *= -1;
				fallthrough;
			default:
				switch (v->type) {
				case FMT_STRING:
					fprintf(stream, "%*s", width, v->s);
					break;
				case FMT_INT:
					fprintf(stream, "%*d", width, v->i);
					break;
				case FMT_UNSIGNED:
					fprintf(stream, "%*u", width, v->u);
					break;
				case FMT_LONG:
					fprintf(stream, "%*ld", width, v->ld);
					break;
				case FMT_UNSIGNED_LONG:
					fprintf(stream, "%*lu", width, v->lu);
					break;
				case FMT_FLOAT:
					fprintf(stream, "%*.2f", width, v->f);
					break;
				case FMT_DOUBLE:
					fprintf(stream, "%*.2f", width, v->d);
					break;
				default:
					fprintf(stderr, "Invalid format!\n");
					break;
				}
				break;
			}
			if (col + 1 != t->num_columns)
				fputc(' ', stream);
		}

		fprintf(stream, "\n");
	}
}

void shr_table_print_stream(FILE *stream, struct shr_table *t)
{
	/* first print columns */
	table_print_columns(stream, t);

	/* next print rows */
	table_print_rows(stream, t);
}

void shr_table_print(struct shr_table *t)
{
	shr_table_print_stream(stdout, t);
}

int shr_table_get_row_id(struct shr_table *t)
{
	struct shr_table_row *new_rows;
	int row = t->num_rows;

	new_rows = reallocarray(t->rows, (row + 1), sizeof(struct shr_table_row));
	if (!new_rows)
		return -ENOMEM;

	t->rows = new_rows;
	t->rows[row].val = calloc(t->num_columns, sizeof(struct shr_table_value));
	if (!t->rows[row].val)
		return -ENOMEM;

	t->num_rows++;
	return row;
}

void shr_table_add_row(struct shr_table *t, int row_id)
{
	int col, max_width, width;
	struct shr_table_row *row = &t->rows[row_id];

	/* Adjust the column width based on the row value. */
	for (col = 0; col < t->num_columns; col++) {
		if (!t->columns[col].auto_adjust)
			continue;

		max_width = t->columns[col].width;
		width = table_get_value_width(&row->val[col]);
		if (width > max_width)
			t->columns[col].width = width;
	}
}

struct shr_table *shr_table_create(void)
{
	return calloc(1, sizeof(struct shr_table));
}

struct shr_table *shr_table_init_with_columns(struct shr_table_column *c, int num_columns)
{
	struct shr_table *t = shr_table_create();

	if (!t)
		return NULL;

	if (shr_table_add_columns(t, c, num_columns)) {
		shr_table_free(t);
		return NULL;
	}

	return t;
}

static int table_add_column(struct shr_table *t, struct shr_table_column *c)
{
	struct shr_table_column *new_columns;
	int col = t->num_columns;

	new_columns = reallocarray(t->columns, t->num_columns + 1,
			sizeof(struct shr_table_column));
	if (!new_columns)
		return -ENOMEM;

	t->num_columns++;
	t->columns = new_columns;
	t->columns[col].name = strdup(c->name);
	if (!t->columns[col].name)
		return -ENOMEM;
	t->columns[col].align = c->align;

	if (c->width == AUTO_WIDTH) {
		t->columns[col].width = strlen(c->name);
		t->columns[col].auto_adjust = true;
	} else {
		if (c->width < strlen(c->name))
			return -EINVAL;

		t->columns[col].width = c->width;
		t->columns[col].auto_adjust = false;
	}

	return 0;
}

int shr_table_add_columns_filter(struct shr_table *t, struct shr_table_column *c,
			int num_columns,
			bool (*filter)(const char *name, void *arg),
			void *arg)
{
	int ret = 0, col;

	if (!filter)
		return shr_table_add_columns(t, c, num_columns);

	for (col = 0; col < num_columns; col++) {
		if (!filter(c[col].name, arg))
			continue;	/* skip this column */

		ret = table_add_column(t, &c[col]);
		if (ret < 0)
			goto free_col;
	}

	return ret;

free_col:
	while (t->num_columns > 0)
		free(t->columns[--t->num_columns].name);
	free(t->columns);
	t->columns = NULL;
	return ret;
}

int shr_table_add_columns(struct shr_table *t, struct shr_table_column *c, int num_columns)
{
	int ret = 0, col;

	t->columns = calloc(num_columns, sizeof(struct shr_table_column));
	if (!t->columns)
		return -ENOMEM;

	for (col = 0; col < num_columns; col++) {
		t->columns[col].name = strdup(c[col].name);
		if (!t->columns[col].name) {
			ret = -ENOMEM;
			goto free_col;
		}

		t->columns[col].align = c[col].align;

		if (c[col].width == AUTO_WIDTH) {
			t->columns[col].width = strlen(t->columns[col].name);
			t->columns[col].auto_adjust = true;
		} else {
			if (c[col].width < strlen(t->columns[col].name)) {
				ret = -EINVAL;
				goto free_col;
			}
			t->columns[col].width = c[col].width;
			t->columns[col].auto_adjust = false;
		}
	}
	t->num_columns = num_columns;

	return ret;
free_col:
	while (col >= 0) {
		free(t->columns[col].name);
		col--;
	}
	free(t->columns);
	t->columns = NULL;
	return ret;
}

void shr_table_free(struct shr_table *t)
{
	int row, col;
	struct shr_table_row *r;
	struct shr_table_value *v;

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
