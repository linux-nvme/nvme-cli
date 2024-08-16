// SPDX-License-Identifier: GPL-2.0-or-later

#include <ctype.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <linux/sed-opal.h>
#include "sedopal_spec.h"
#include "sedopal_cmd.h"

/*
 * ask user for key rather than obtaining it from kernel keyring
 */
bool sedopal_ask_key;

/*
 * initiate dialog to ask for and confirm new password
 */
bool sedopal_ask_new_key;

/*
 * perform a destructive drive revert
 */
bool sedopal_destructive_revert;

/*
 * perform a PSID drive revert
 */
bool sedopal_psid_revert;

/*
 * Map method status codes to error text
 */
static const char * const sedopal_errors[] = {
	[SED_STATUS_SUCCESS] =			"Success",
	[SED_STATUS_NOT_AUTHORIZED] =		"Host Not Authorized",
	[SED_STATUS_OBSOLETE_1] =		"Obsolete",
	[SED_STATUS_SP_BUSY] =			"SP Session Busy",
	[SED_STATUS_SP_FAILED] =		"SP Failed",
	[SED_STATUS_SP_DISABLED] =		"SP Disabled",
	[SED_STATUS_SP_FROZEN] =		"SP Frozen",
	[SED_STATUS_NO_SESSIONS_AVAILABLE] =	"No Sessions Available",
	[SED_STATUS_UNIQUENESS_CONFLICT] =	"Uniqueness Conflict",
	[SED_STATUS_INSUFFICIENT_SPACE] =	"Insufficient Space",
	[SED_STATUS_INSUFFICIENT_ROWS] =	"Insufficient Rows",
	[SED_STATUS_OBSOLETE_2] =		"Obsolete",
	[SED_STATUS_INVALID_PARAMETER] =	"Invalid Parameter",
	[SED_STATUS_OBSOLETE_3] =		"Obsolete",
	[SED_STATUS_OBSOLETE_4] =		"Obsolete",
	[SED_STATUS_TPER_MALFUNCTION] =		"TPER Malfunction",
	[SED_STATUS_TRANSACTION_FAILURE] =	"Transaction Failure",
	[SED_STATUS_RESPONSE_OVERFLOW] =	"Response Overflow",
	[SED_STATUS_AUTHORITY_LOCKED_OUT] =	"Authority Locked Out",
};

const char *sedopal_error_to_text(int code)
{
	if (code == SED_STATUS_FAIL)
		return "Failed";

	if (code == SED_STATUS_NO_METHOD_STATUS)
		return "Method returned no status";

	if (code < SED_STATUS_SUCCESS ||
	    code > SED_STATUS_AUTHORITY_LOCKED_OUT)
		return("Unknown Error");

	return sedopal_errors[code];
}

/*
 * Read a user entered password and do some basic validity checks.
 */
char *sedopal_get_password(char *prompt)
{
	char *pass;
	int len;

	pass = getpass(prompt);
	if (pass == NULL)
		return NULL;

	len = strlen(pass);
	if (len < SEDOPAL_MIN_PASSWORD_LEN)
		return NULL;

	if (len > SEDOPAL_MAX_PASSWORD_LEN)
		return NULL;

	return pass;
}

/*
 * Initialize a SED Opal key. The key can either specify that the actual
 * key should be looked up in the kernel keyring, or it should be
 * populated in the key by prompting the user.
 */
int sedopal_set_key(struct opal_key *key)
{
#if !HAVE_KEY_TYPE
	/*
	 * If key_type isn't avaialable, force key prompt
	 */
	sedopal_ask_key = true;
#endif

	if (sedopal_ask_key) {
		char *pass;
		char *prompt;

		/*
		 * set proper prompt
		 */
		if (sedopal_ask_new_key)
			prompt = SEDOPAL_NEW_PW_PROMPT;
		else {
			if (sedopal_psid_revert)
				prompt = SEDOPAL_PSID_PROMPT;
			else
				prompt = SEDOPAL_CURRENT_PW_PROMPT;
		}

		pass = sedopal_get_password(prompt);
		if (pass == NULL)
			return -EINVAL;

#if HAVE_KEY_TYPE
		key->key_type = OPAL_INCLUDED;
#endif
		key->key_len = strlen(pass);
		memcpy(key->key, pass, key->key_len + 1);

		/*
		 * If getting a new key, ask for it to be re-entered
		 * and verify the two entries are the same.
		 */
		if (sedopal_ask_new_key) {
			pass = sedopal_get_password(SEDOPAL_REENTER_PW_PROMPT);
			if (strncmp((char *)key->key, pass, key->key_len)) {
				fprintf(stderr,
					"Error: passwords don't match\n");
				return -EINVAL;
			}
		}
	} else {
#if HAVE_KEY_TYPE
		key->key_type = OPAL_KEYRING;
#endif
		key->key_len = 0;
	}

	key->lr = 0;

	return 0;
}

/*
 * Prepare a drive for SED Opal locking.
 */
int sedopal_cmd_initialize(int fd)
{
	int rc;
	struct opal_key key;
	struct opal_lr_act lr_act = {};
	struct opal_user_lr_setup lr_setup = {};
	struct opal_new_pw new_pw = {};

	sedopal_ask_key = true;
	sedopal_ask_new_key = true;
	rc = sedopal_set_key(&key);
	if (rc != 0)
		return rc;

	/*
	 * take ownership of the device
	 */
	rc = ioctl(fd, IOC_OPAL_TAKE_OWNERSHIP, &key);
	if (rc != 0) {
		fprintf(stderr,
			"Error: failed to take device ownership - %d\n", rc);
		return rc;
	}

	/*
	 * activate lsp
	 */
	lr_act.num_lrs = 1;
	lr_act.sum = false;
	lr_act.key = key;

	rc = ioctl(fd, IOC_OPAL_ACTIVATE_LSP, &lr_act);
	if (rc != 0) {
		fprintf(stderr, "Error: failed to activate LSP - %d\n", rc);
		return rc;
	}

	/*
	 * setup global locking range
	 */
	lr_setup.range_start = 0;
	lr_setup.range_length = 0;
	lr_setup.RLE = true;
	lr_setup.WLE = true;

	lr_setup.session.opal_key = key;
	lr_setup.session.sum = 0;
	lr_setup.session.who = OPAL_ADMIN1;

	rc = ioctl(fd, IOC_OPAL_LR_SETUP, &lr_setup);
	if (rc != 0) {
		fprintf(stderr,
			"Error: failed to setup locking range - %d\n", rc);
		return rc;
	}

	/*
	 * set password
	 */
	new_pw.new_user_pw.who = OPAL_ADMIN1;
	new_pw.new_user_pw.opal_key.lr = 0;
	new_pw.session.who = OPAL_ADMIN1;
	new_pw.session.sum = 0;
	new_pw.session.opal_key.lr = 0;
	new_pw.session.opal_key = key;
	new_pw.new_user_pw.opal_key = key;

	rc = ioctl(fd, IOC_OPAL_SET_PW, &new_pw);
	if (rc != 0)
		fprintf(stderr, "Error: failed setting password - %d\n", rc);

	return rc;
}

/*
 * Lock a SED Opal drive
 */
int sedopal_cmd_lock(int fd)
{

	return sedopal_lock_unlock(fd, OPAL_LK);
}

/*
 * Unlock a SED Opal drive
 */
int sedopal_cmd_unlock(int fd)
{
	int rc;

	rc = sedopal_lock_unlock(fd, OPAL_RW);

	/*
	 * If the unlock was successful, force a re-read of the
	 * partition table. Return rc of unlock operation.
	 */
	if (rc == 0) {
		if (ioctl(fd, BLKRRPART, 0) != 0)
			fprintf(stderr,
				"Warning: failed re-reading partition\n");
	}

	return rc;
}

/*
 * Prepare and issue an ioctl to lock/unlock a drive
 */
int sedopal_lock_unlock(int fd, int lock_state)
{
	int rc;
	struct opal_lock_unlock opal_lu = {};

	rc = sedopal_set_key(&opal_lu.session.opal_key);
	if (rc != 0)
		return rc;

	opal_lu.session.sum = 0;
	opal_lu.session.who = OPAL_ADMIN1;
	opal_lu.l_state = lock_state;

	rc = ioctl(fd, IOC_OPAL_LOCK_UNLOCK, &opal_lu);
	if (rc != 0)
		fprintf(stderr,
			"Error: failed locking or unlocking - %d\n", rc);
	return rc;
}

/*
 * Confirm a destructive drive so that data is inadvertently erased
 */
static bool sedopal_confirm_revert(void)
{
	int rc;
	char ans;
	bool confirmed = false;

	/*
	 * verify that destructive revert is really the intention
	 */
	fprintf(stdout,
		"Destructive revert erases drive data. Continue (y/n)? ");
	rc = fscanf(stdin, " %c", &ans);
	if ((rc == 1) && (ans == 'y' || ans == 'Y')) {
		fprintf(stdout, "Are you sure (y/n)? ");
		rc = fscanf(stdin, " %c", &ans);
		if ((rc == 1) && (ans == 'y' || ans == 'Y'))
			confirmed = true;
	}

	return confirmed;
}

/*
 * perform a destructive drive revert
 */
static int sedopal_revert_destructive(int fd)
{
	struct opal_key key;
	int rc;

	if (!sedopal_confirm_revert()) {
		fprintf(stderr, "Aborting destructive revert\n");
		return -1;
	}

	/*
	 * for destructive revert, require that key is provided
	 */
	sedopal_ask_key = true;

	rc = sedopal_set_key(&key);
	if (rc == 0)
		rc = ioctl(fd, IOC_OPAL_REVERT_TPR, &key);

	return rc;
}

/*
 * perform a PSID drive revert
 */
static int sedopal_revert_psid(int fd)
{
#ifdef IOC_OPAL_PSID_REVERT_TPR
	struct opal_key key;
	int rc;

	if (!sedopal_confirm_revert()) {
		fprintf(stderr, "Aborting PSID revert\n");
		return -1;
	}

	rc = sedopal_set_key(&key);
	if (rc == 0) {
		rc = ioctl(fd, IOC_OPAL_PSID_REVERT_TPR, &key);
		if (rc != 0)
			fprintf(stderr, "PSID_REVERT_TPR rc %d\n", rc);
	}

	return rc;
#else
	fprintf(stderr, "ERROR : PSID revert is not supported\n");
	return -EOPNOTSUPP;
#endif /* IOC_OPAL_PSID_REVERT_TPR */
}

/*
 * revert a drive from the provisioned state to a state where locking
 * is disabled.
 */
int sedopal_cmd_revert(int fd)
{
	int rc;

	/*
	 * for revert, require that key/PSID is provided
	 */
	sedopal_ask_key = true;

	if (sedopal_psid_revert) {
		rc = sedopal_revert_psid(fd);
	} else if (sedopal_destructive_revert) {
		rc = sedopal_revert_destructive(fd);
	} else {
#ifdef IOC_OPAL_REVERT_LSP
		struct opal_revert_lsp revert_lsp;

		rc = sedopal_set_key(&revert_lsp.key);
		if (rc != 0)
			return rc;

		revert_lsp.options = OPAL_PRESERVE;
		revert_lsp.__pad = 0;

		rc = ioctl(fd, IOC_OPAL_REVERT_LSP, &revert_lsp);
		if (rc == 0) {
			/*
			 * TPER must also be reverted.
			 */
			rc = ioctl(fd, IOC_OPAL_REVERT_TPR, &revert_lsp.key);
			if (rc != 0)
				fprintf(stderr, "Error: revert TPR - %d\n", rc);
		}
#else
		rc = -EOPNOTSUPP;
#endif
	}

	if (rc != 0)
		fprintf(stderr, "Error: failed reverting drive - %d\n", rc);

	return rc;
}

/*
 * Change the password of a drive. The existing password must be
 * provided and the new password is confirmed by re-entry.
 */
int sedopal_cmd_password(int fd)
{
	int rc;
	struct opal_new_pw new_pw = {};

	new_pw.new_user_pw.who = OPAL_ADMIN1;
	new_pw.new_user_pw.opal_key.lr = 0;
	new_pw.session.who = OPAL_ADMIN1;
	new_pw.session.sum = 0;
	new_pw.session.opal_key.lr = 0;

	/*
	 * get current key
	 */
	sedopal_ask_key = true;
	if (sedopal_set_key(&new_pw.session.opal_key) != 0)
		return -EINVAL;

	/*
	 * get new key
	 */
	sedopal_ask_new_key = true;
	if (sedopal_set_key(&new_pw.new_user_pw.opal_key) != 0)
		return -EINVAL;

	/*
	 * set admin1 password
	 */
	rc = ioctl(fd, IOC_OPAL_SET_PW, &new_pw);
	if (rc != 0) {
		fprintf(stderr, "Error: failed setting password - %d\n", rc);
		return rc;
	}

#ifdef IOC_OPAL_SET_SID_PW
	/*
	 * set sid password
	 */
	rc = ioctl(fd, IOC_OPAL_SET_SID_PW, &new_pw);
	if (rc != 0)
		fprintf(stderr, "Error: failed setting SID password - %d\n", rc);
#endif

	return rc;
}

/*
 * Print the state of locking features.
 */
void sedopal_print_locking_features(uint8_t features)
{
	printf("Locking Features:\n");
	printf("\tLocking Supported:         %s\n",
		(features & OPAL_FEATURE_LOCKING_SUPPORTED) ? "Yes" : "No");
	printf("\tLocking Feature Enabled:   %s\n",
		(features & OPAL_FEATURE_LOCKING_ENABLED) ? "Yes" : "No");
	printf("\tLocked:                    %s\n",
		(features & OPAL_FEATURE_LOCKED) ? "Yes" : "No");
}

/*
 * Query a drive to determine if it's SED Opal capable and
 * it's current locking status.
 */
int sedopal_cmd_discover(int fd)
{
#ifdef IOC_OPAL_DISCOVERY
	int rc;
	bool sedopal_locking_supported = false;
	struct opal_discovery discover;
	struct level_0_discovery_header *dh;
	struct level_0_discovery_features *feat;
	struct level_0_discovery_features *feat_end;
	uint16_t code;
	uint8_t locking_flags = 0;
	char buf[4096];

	discover.data = (__u64)buf;
	discover.size = sizeof(buf);

	rc = ioctl(fd, IOC_OPAL_DISCOVERY, &discover);
	if (rc < 0) {
		fprintf(stderr, "Error: ioctl IOC_OPAL_DISCOVERY failed\n");
		return rc;
	}

	/*
	 * The returned buffer contains a level 0 discovery header
	 * folowed by an array of level 0 feature records.
	 *
	 * TCG Opal Specification v2.0.2 section 3.1.1
	 */
	dh = (struct level_0_discovery_header *)buf;
	feat = (struct level_0_discovery_features *)(dh + 1);
	feat_end = (struct level_0_discovery_features *)
		(buf + be32toh(dh->parameter_length));

	/*
	 * iterate through all the features that were returned
	 */
	while (feat < feat_end) {
		code = be16toh(feat->code);
		switch (code) {
		case OPAL_FEATURE_CODE_LOCKING:
			locking_flags = feat->feature;
			break;
		case OPAL_FEATURE_CODE_OPALV2:
			sedopal_locking_supported = true;
			break;
		default:
			break;
		}

		feat++;
	}

	rc = 0;
	if (!sedopal_locking_supported) {
		fprintf(stderr, "Error: device does not support SED Opal\n");
		rc = -1;
	} else
		sedopal_print_locking_features(locking_flags);

	return rc;
#else /* IOC_OPAL_DISCOVERY */
	fprintf(stderr, "ERROR : NVMe device discovery is not supported\n");
	return -EOPNOTSUPP;
#endif
}
