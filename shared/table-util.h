/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * table.h : Common APIs for printing tabular format output.
 *
 * This file is part of nvme-cli.
 * Copyright (c) 2025 Nilay Shroff, IBM
 */
#pragma once

#include <errno.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

#define AUTO_WIDTH	INT_MAX

enum fmt_type {
	FMT_STRING,
	FMT_INT,
	FMT_UNSIGNED,
	FMT_LONG,
	FMT_UNSIGNED_LONG,
	FMT_FLOAT,
	FMT_DOUBLE,
};

enum alignment {
	RIGHT,
	LEFT,
	CENTERED
};

struct shr_table_value {
	union {
		char *s;
		int i;
		unsigned int u;
		long ld;
		unsigned long lu;
		float f;
		double d;
	};
	enum alignment align;
	enum fmt_type type;
};

struct shr_table_row {
	struct shr_table_value *val;
};

struct shr_table_column {
	char *name;		/* column name */
	enum alignment align;	/* column value alignment */

	/*
	 * The table supports both fixed and auto column width. Auto width could
	 * be specified by setting @width to AUTO_WIDTH. Fixed width must be at-
	 * least strlen(@name) or more.
	 */
	int width;
	/*
	 * Controls whether to auto adjust column width or not.
	 * NOTE: This field is internally used by table APIs and it should not
	 * be used by the users of table APIs.
	 */
	bool auto_adjust;
};

struct shr_table {
	struct shr_table_column *columns;
	int num_columns;
	struct shr_table_row *rows;
	int num_rows;
};

static inline int shr_table_set_value_str(struct shr_table *t, int col, int row,
		const char *str, enum alignment align)
{
	struct shr_table_row *r;
	struct shr_table_value *v;
	char *s;

	if (col >= t->num_columns || row >= t->num_rows)
		return -EINVAL;

	s = strdup(str);
	if (!s)
		return -ENOMEM;

	r = &t->rows[row];
	v = &r->val[col];
	v->s = s;
	v->align = align;
	v->type = FMT_STRING;

	return 0;
}

static inline int shr_table_set_value_int(struct shr_table *t, int col, int row,
		int i, enum alignment align)
{
	struct shr_table_row *r;
	struct shr_table_value *v;

	if (col >= t->num_columns || row >= t->num_rows)
		return -EINVAL;

	r = &t->rows[row];
	v = &r->val[col];
	v->i = i;
	v->align = align;
	v->type = FMT_INT;

	return 0;
}

static inline int shr_table_set_value_unsigned(struct shr_table *t, int col, int row,
		int u, enum alignment align)
{
	struct shr_table_row *r;
	struct shr_table_value *v;

	if (col >= t->num_columns || row >= t->num_rows)
		return -EINVAL;

	r = &t->rows[row];
	v = &r->val[col];
	v->u = u;
	v->align = align;
	v->type = FMT_UNSIGNED;

	return 0;
}

static inline int shr_table_set_value_long(struct shr_table *t, int col, int row,
		long ld, enum alignment align)
{
	struct shr_table_row *r;
	struct shr_table_value *v;

	if (col >= t->num_columns || row >= t->num_rows)
		return -EINVAL;

	r = &t->rows[row];
	v = &r->val[col];
	v->ld = ld;
	v->align = align;
	v->type = FMT_LONG;

	return 0;
}

static inline void shr_table_set_value_unsigned_long(struct shr_table *t, int col,
		int row, long lu, enum alignment align)
{
	struct shr_table_row *r = &t->rows[row];
	struct shr_table_value *v = &r->val[col];

	v->lu = lu;
	v->align = align;
	v->type = FMT_UNSIGNED_LONG;
}

static inline void shr_table_set_value_float(struct shr_table *t, int col,
		int row, float f, enum alignment align)
{
	struct shr_table_row *r = &t->rows[row];
	struct shr_table_value *v = &r->val[col];

	v->f = f;
	v->align = align;
	v->type = FMT_FLOAT;
}

static inline void shr_table_set_value_double(struct shr_table *t, int col,
		int row, double d, enum alignment align)
{
	struct shr_table_row *r = &t->rows[row];
	struct shr_table_value *v = &r->val[col];

	v->d = d;
	v->align = align;
	v->type = FMT_DOUBLE;
}

struct shr_table *shr_table_create(void);
int shr_table_add_columns(struct shr_table *t, struct shr_table_column *c, int num_columns);
int shr_table_add_columns_filter(struct shr_table *t, struct shr_table_column *c,
			int num_columns,
			bool (*filter)(const char *name, void *arg),
			void *arg);
int shr_table_get_row_id(struct shr_table *t);
void shr_table_add_row(struct shr_table *t, int row);
void shr_table_print_stream(FILE *stream, struct shr_table *t);
void shr_table_print(struct shr_table *t);
void shr_table_free(struct shr_table *t);

/**
 * shr_table_init_with_columns() - Allocate a table instance with column definitions
 * @c:		Column definitions
 * @num_columns:Number of columns
 *
 * This is a function combined shr_table_create() and shr_table_add_columns().
 *
 * Return: The table instance, or NULL if unsuccessful. If allocated, the caller
 * is responsible to free the table.
 */
struct shr_table *shr_table_init_with_columns(struct shr_table_column *c, int num_columns);
