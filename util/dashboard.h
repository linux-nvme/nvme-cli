/* SPDX-License-Identifier: GPL-2.0-or-later */

#ifndef _DASHBOARD_H_
#define _DASHBOARD_H_

#include <stdio.h>

struct dashboard_ctx;

enum event_type {
	EVENT_TYPE_ERROR = -1,	/* error waiting for event */
	EVENT_TYPE_TIMEOUT,	/* timed out waiting for event */

	EVENT_TYPE_KEY_PRESS,	/* key pressed event */
	EVENT_TYPE_KEY_ESC,	/* ESC key is pressed*/
	EVENT_TYPE_KEY_UP,	/* UP arrow key is pressed */
	EVENT_TYPE_KEY_DOWN,	/* DOWN arrow key is pressed */
	EVENT_TYPE_KEY_RETURN,	/* Return/Enter key is pressed */
	EVENT_TYPE_KEY_QUIT,	/* q is pressed */

	EVENT_TYPE_NVME_UEVENT,	/* kobject uevent received; rescan topology */
	EVENT_TYPE_SIGWINCH,	/* SIGWINCH received */
};

int dashboard_get_interval(struct dashboard_ctx *db_ctx);
int dashboard_get_header_rows(struct dashboard_ctx *db_ctx);

void dashboard_set_header_rows(struct dashboard_ctx *db_ctx, int rows);
int dashboard_get_footer_rows(struct dashboard_ctx *db_ctx);

void dashboard_set_footer_rows(struct dashboard_ctx *db_ctx, int rows);
int dashboard_get_data_rows(struct dashboard_ctx *db_ctx);

int dashboard_get_data_start(struct dashboard_ctx *db_ctx);
int dashboard_set_data_start(struct dashboard_ctx *db_ctx, int off);

int dashboard_get_frame_data_rows(struct dashboard_ctx *db_ctx);

void dashboard_set_data_row_reverse(struct dashboard_ctx *db_ctx, int row);
void dashboard_reset_data_row_reverse(struct dashboard_ctx *db_ctx);

void dashboard_set_header_row_reverse(struct dashboard_ctx *db_ctx, int row);
void dashboard_reset_header_row_reverse(struct dashboard_ctx *db_ctx);

void dashboard_set_footer_row_reverse(struct dashboard_ctx *db_ctx, int row);
void dashboard_reset_footer_row_reverse(struct dashboard_ctx *db_ctx);

int dashboard_draw_frame(struct dashboard_ctx *db_ctx, int scroll);
enum event_type dashboard_wait_for_event(struct dashboard_ctx *db_ctx);

FILE *dashboard_init(struct dashboard_ctx **db_ctx, int refresh_interval);
void dashboard_reset(struct dashboard_ctx *db_ctx);
void dashboard_exit(struct dashboard_ctx *db_ctx);

#endif /* _DASHBOARD_H_ */
