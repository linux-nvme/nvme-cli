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

struct shr_table;

struct shr_table_row {
	struct shr_table_value *val;
	struct shr_table *subtable;
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
	/*
	 * When true, shr_table_align_column() excludes this column from
	 * alignment. Its width is neither used to widen same-indexed columns
	 * in other tables nor widened by them. Set this when the column does
	 * not have the same meaning as the corresponding column in sibling
	 * tables. Defaults to false.
	 */
	bool no_widen;
};

struct shr_table {
	struct shr_table_column *columns;
	int num_columns;
	struct shr_table_row *rows;
	int num_rows;
	char *col_sep;
	bool no_header;
	int indent;
	bool error;
};

static inline bool shr_table_value_valid(const struct shr_table *t, int col,
					  int row)
{
	return col >= 0 && col < t->num_columns &&
	       row >= 0 && row < t->num_rows;
}

static inline int shr_table_set_value_str(struct shr_table *t, int col, int row,
		const char *str, enum alignment align)
{
	struct shr_table_row *r;
	struct shr_table_value *v;
	char *s;

	if (!shr_table_value_valid(t, col, row))
		return -EINVAL;

	s = strdup(str);
	if (!s) {
		t->error = true;
		return -ENOMEM;
	}

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

	if (!shr_table_value_valid(t, col, row))
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

	if (!shr_table_value_valid(t, col, row))
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

	if (!shr_table_value_valid(t, col, row))
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
 * shr_table_has_error() - Check whether building @t ever failed to allocate
 * @t:		Table instance
 *
 * Checks @t and, recursively, every row's subtable. Call before
 * printing/rendering @t; on true, free @t instead.
 *
 * Return: true if @t or any subtable reachable from it hit an allocation
 * failure while being built.
 */
bool shr_table_has_error(const struct shr_table *t);

/**
 * shr_table_set_column_sep() - Change the separator printed between columns
 * @t:		Table instance
 * @sep:	Separator string, e.g. " : ". Copied, so @sep need not outlive
 *		@t. Pass NULL to restore the default single space.
 *
 * Return: 0 on success, or -ENOMEM if the copy could not be allocated (@t
 * keeps its previous separator in that case).
 */
int shr_table_set_column_sep(struct shr_table *t, const char *sep);

/**
 * shr_table_set_no_header() - Enable/disable the header and separator line
 * @t:		Table instance
 * @no_header:	If true, shr_table_print_stream() prints only the data rows,
 *		useful for key/value style listings that have no real header.
 */
void shr_table_set_no_header(struct shr_table *t, bool no_header);

/**
 * shr_table_set_indent() - Left-margin spaces printed before every line
 * @t:		Table instance
 * @indent:	Number of spaces; 0 (the default) prints no margin.
 */
void shr_table_set_indent(struct shr_table *t, int indent);

/**
 * shr_table_print_row() - Print a single data row
 * @stream:	Output stream
 * @t:		Table instance
 * @row:	Row id, as returned by shr_table_get_row_id()
 *
 * Lets a caller drive the row-by-row output itself (e.g. to interleave
 * extra, non-tabular output after specific rows) instead of using
 * shr_table_print_stream() to print the whole table in one go. Column
 * widths reflect all rows added so far, not just @row, so call this only
 * after every row that should influence the width has been added.
 */
void shr_table_print_row(FILE *stream, struct shr_table *t, int row);

/**
 * shr_table_get_row_subtable() - Get the subtable attached to a row
 * @t:		Table instance
 * @row:	Row id
 *
 * @t does not print the subtable itself; a caller driving output with
 * shr_table_print_row() decides whether and how to use it (e.g. printed,
 * indented, right after the row, whenever it is non-NULL).
 *
 * Return: the subtable attached to @row, or NULL if none.
 */
struct shr_table *shr_table_get_row_subtable(struct shr_table *t, int row);

/**
 * shr_table_set_row_subtable() - Attach a subtable to a row
 * @t:		Table instance
 * @row:	Row id
 * @subtable:	Nested table to associate with @row, or NULL to clear it.
 *		@t takes ownership: it is freed by shr_table_free(t) (or by
 *		a later shr_table_set_row_subtable() call on the same row),
 *		so the caller must not free it separately.
 *
 * If @row is out of range, @subtable is freed and @t is left untouched.
 */
void shr_table_set_row_subtable(struct shr_table *t, int row,
		struct shr_table *subtable);

/**
 * shr_table_get_column_width() - Get a column's current width
 * @t:		Table instance
 * @col:	Column index
 *
 * Return: the column's width, whether auto-computed or explicitly set.
 */
int shr_table_get_column_width(struct shr_table *t, int col);

/**
 * shr_table_set_column_width() - Explicitly override a column's width
 * @t:		Table instance
 * @col:	Column index
 * @width:	New width. Overrides whatever auto-width computed so far
 *		and stops the column from auto-growing for any row added
 *		after this call.
 */
void shr_table_set_column_width(struct shr_table *t, int col, int width);

/**
 * shr_table_align_column() - Line up one column across every row's nested
 * subtable, optionally including @t's own column too
 * @t:		Table instance
 * @col:	Column index in @t to widen along with the subtables, or -1
 *		to align the subtables with each other only, leaving @t
 *		untouched
 * @sub_col:	The same-role column index in each row's subtable
 *
 * Widen column @sub_col in all attached subtables. If @col >= 0, also
 * widen column @col in @t. Include each table's indent so the column
 * starts at the same absolute output position in all tables.
 *
 * This is useful for aligning a label column, including its trailing ':'.
 * If the column only exists in the subtables, use
 * shr_table_align_subtable_column() instead.
 *
 * A subtable whose column @sub_col has shr_table_column.no_widen set is
 * left out: neither considered when computing the widened width, nor
 * widened itself. Use this for a subtable at an index that happens to
 * collide with @col/@sub_col without sharing its meaning (e.g. a wide
 * multi-column table dropped in next to "name : value : desc" subtables).
 *
 * Call this after adding all rows and before printing.
 */
void shr_table_align_column(struct shr_table *t, int col, int sub_col);

/**
 * shr_table_align_subtable_column() - Line up one column across every
 * row's nested subtable, without involving @t's own columns
 * @t:		Table instance
 * @sub_col:	Column index within each row's subtable
 *
 * Shorthand for shr_table_align_column(t, -1, sub_col): there is usually
 * no reason a table's own column should share a width with a column
 * nested many levels down in unrelated subtables, so this is the more
 * common case in practice.
 */
static inline void shr_table_align_subtable_column(struct shr_table *t,
		int sub_col)
{
	shr_table_align_column(t, -1, sub_col);
}

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
