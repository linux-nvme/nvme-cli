#ifndef _SED_OPAL_H
#define _SED_OPAL_H

#include <linux/types.h>
#include <linux/ioctl.h>
#include <inttypes.h>

typedef unsigned char u8;

#define OPAL_KEY_MAX 256

enum opal_mbr {
	OPAL_MBR_ENABLE,
	OPAL_MBR_DISABLE,
};

enum opal_user {
	OPAL_ADMIN1,
	OPAL_USER1,
	OPAL_USER2,
	OPAL_USER3,
	OPAL_USER4,
	OPAL_USER5,
	OPAL_USER6,
	OPAL_USER7,
	OPAL_USER8,
	OPAL_USER9,
};

enum opal_lock_state {
	OPAL_RO = 0x01, /* 0001 */
	OPAL_RW = 0x02, /* 0010 */
	OPAL_LK = 0x04, /* 0100 */
};

struct opal_key {
	uint8_t	lr;
	uint8_t	key_len;
	char	key[OPAL_KEY_MAX];
};

struct opal_session_info {
	int sum;
	struct opal_key opal_key;
	enum opal_user who;
};

struct opal_user_lr_setup {
	struct opal_session_info session;
	size_t range_start;
	size_t range_length;
	int    RLE; /* Read Lock enabled */
	int    WLE; /* Write Lock Enabled */
};

struct opal_lock_unlock {
	struct opal_session_info session;
	enum opal_lock_state l_state;
};

struct opal_new_pw {
	struct opal_session_info session;

	/* When we're not operating in sum, and we first set
	 * passwords we need to set them via ADMIN authority.
	 * After passwords are changed, we can set them via,
	 * User authorities.
	 * Because of this restriction we need to know about
	 * Two different users. One in 'session' which we will use
	 * to start the session and new_userr_pw as the user we're
	 * chaning the pw for.
	 */
	struct opal_session_info new_user_pw;
};

struct opal_mbr_data {
	u8 enable_disable;
	struct opal_key key;
};

#define IOC_OPAL_SAVE		    _IOW('p', 220, struct opal_lock_unlock)
#define IOC_OPAL_LOCK_UNLOCK	    _IOW('p', 221, struct opal_lock_unlock)
#define IOC_OPAL_TAKE_OWNERSHIP	    _IOW('p', 222, struct opal_key)
#define IOC_OPAL_ACTIVATE_LSP       _IOW('p', 223, struct opal_key)
#define IOC_OPAL_SET_PW             _IOW('p', 224, struct opal_new_pw)
#define IOC_OPAL_ACTIVATE_USR       _IOW('p', 225, struct opal_session_info)
#define IOC_OPAL_REVERT_TPR         _IOW('p', 226, struct opal_key)
#define IOC_OPAL_LR_SETUP           _IOW('p', 227, struct opal_user_lr_setup)
#define IOC_OPAL_ADD_USR_TO_LR      _IOW('p', 228, struct opal_lock_unlock)
#define IOC_OPAL_ENABLE_DISABLE_MBR _IOW('p', 229, struct opal_mbr_data)
#define IOC_OPAL_ERASE_LR           _IOW('p', 230, struct opal_session_info)
#define IOC_OPAL_SECURE_ERASE_LR    _IOW('p', 231, struct opal_session_info)

#endif /* _SED_OPAL_H */
