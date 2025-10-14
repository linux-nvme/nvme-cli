/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _TABLE_H_
#define _TABLE_H_

#include <stdbool.h>

enum fmt_type {
	FMT_STRING,
	FMT_INT,
	FMT_UNSIGNED,
	FMT_LONG,
	FMT_UNSIGNED_LONG,
};

enum alignment {
	RIGHT,
	LEFT,
	CENTERED
};

struct value {
	union {
		char *s;
		int i;
		unsigned int u;
		long ld;
		unsigned long lu;
	};
	enum alignment align;
	enum fmt_type type;
};

struct table_row {
	struct value *val;
};

struct table_column {
	char *name;
	enum alignment align;
	int width;		/* auto populated */
};

struct table {
	struct table_column *columns;
	int num_columns;
	struct table_row *rows;
	int num_rows;
};

static inline int table_set_value_str(struct table *t, int col, int row,
		const char *str, enum alignment align)
{
	struct table_row *r;
	struct value *v;
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

static inline int table_set_value_int(struct table *t, int col, int row,
		int i, enum alignment align)
{
	struct table_row *r;
	struct value *v;

	if (col >= t->num_columns || row >= t->num_rows)
		return -EINVAL;

	r = &t->rows[row];
	v = &r->val[col];
	v->i = i;
	v->align = align;
	v->type = FMT_INT;

	return 0;
}

static inline int table_set_value_unsigned(struct table *t, int col, int row,
		int u, enum alignment align)
{
	struct table_row *r;
	struct value *v;

	if (col >= t->num_columns || row >= t->num_rows)
		return -EINVAL;

	r = &t->rows[row];
	v = &r->val[col];
	v->u = u;
	v->align = align;
	v->type = FMT_UNSIGNED;

	return 0;
}

static inline int table_set_value_long(struct table *t, int col, int row,
		long ld, enum alignment align)
{
	struct table_row *r;
	struct value *v;

	if (col >= t->num_columns || row >= t->num_rows)
		return -EINVAL;

	r = &t->rows[row];
	v = &r->val[col];
	v->ld = ld;
	v->align = align;
	v->type = FMT_LONG;

	return 0;
}

static inline void table_set_value_unsigned_long(struct table *t, int col,
		int row, long lu, enum alignment align)
{
	struct table_row *r = &t->rows[row];
	struct value *v = &r->val[col];

	v->lu = lu;
	v->align = align;
	v->type = FMT_UNSIGNED_LONG;
}

struct table *table_create(void);
int table_add_columns(struct table *t, struct table_column *c, int num_columns);
int table_add_columns_filter(struct table *t, struct table_column *c,
			int num_columns,
			bool (*filter)(const char *name, void *arg),
			void *arg);
int table_get_row_id(struct table *t);
void table_add_row(struct table *t, int row);
void table_print(struct table *t);
void table_free(struct table *t);

/**
 * table_init_with_columns() - Allocate a table instance with column definitions
 * @c:		Column definitions
 * @num_columns:Number of columns
 *
 * This is a function combined table_create() and table_add_columns().
 *
 * Return: The table instance, or NULL if unsuccessful. If allocated, the caller
 * is responsible to free the table.
 */
struct table *table_init_with_columns(struct table_column *c, int num_columns);

#endif /* _TABLE_H_ */
