/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _DELAY_H
#define _DELAY_H

struct delay_args {
	double time;
	int row;
	int col;
	int index;
	int last_row;
	int last_col;
	int last_index;
	bool changed;
	char *copy;
	size_t copy_len;
	FILE *fp;
	char *buf;
	size_t len;
	FILE *stdout;
};

int delay_set_stdout_file(struct delay_args *args);
bool delay_handle(struct delay_args *args);

#endif /* _DELAY_H */
