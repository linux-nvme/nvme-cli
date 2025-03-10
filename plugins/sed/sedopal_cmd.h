/* SPDX-License-Identifier: GPL-2.0-or-later */

#ifndef _SED_OPAL_CMD_H
#define _SED_OPAL_CMD_H

#define	SEDOPAL_CURRENT_PW_PROMPT	"Password: "
#define	SEDOPAL_NEW_PW_PROMPT		"New Password: "
#define	SEDOPAL_REENTER_PW_PROMPT	"Re-enter New Password: "
#define	SEDOPAL_PSID_PROMPT		"PSID: "

#define	SEDOPAL_MIN_PASSWORD_LEN	8
#define	SEDOPAL_MAX_PASSWORD_LEN	32

#define NVME_DEV_PATH			"/dev/nvme"

extern bool sedopal_ask_key;
extern bool sedopal_ask_new_key;
extern bool sedopal_destructive_revert;
extern bool sedopal_psid_revert;
extern bool sedopal_lock_ro;
extern bool sedopal_discovery_verbose;
extern bool sedopal_discovery_udev;

/*
 * Sub-commands supported by the sedopal command
 */
enum sedopal_cmds {
	SEDOPAL_CMD_NOT_SPECIFIED =	-1,
	SEDOPAL_CMD_INITIALIZE =	0,
	SEDOPAL_CMD_LOCK =		1,
	SEDOPAL_CMD_UNLOCK =		2,
	SEDOPAL_CMD_REVERT =		3,
	SEDOPAL_CMD_PASSWORD =		4,
	SEDOPAL_CMD_DISCOVER =		5,
};

struct cmd_table {
	int (*cmd_handler)(int fd);
};

/*
 * command handlers
 */
int sedopal_cmd_initialize(int fd);
int sedopal_cmd_lock(int fd);
int sedopal_cmd_unlock(int fd);
int sedopal_cmd_revert(int fd);
int sedopal_cmd_password(int fd);
int sedopal_cmd_discover(int fd);

/*
 * utility functions
 */
int sedopal_open_nvme_device(char *device);
int sedopal_lock_unlock(int fd, int lock_state);
const char *sedopal_error_to_text(int code);
int sedopal_locking_state(int fd);

#endif /* _SED_OPAL_CMD_H */
