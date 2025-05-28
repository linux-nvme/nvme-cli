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

#include <libnvme.h>

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
 * Lock read-only
 */
bool sedopal_lock_ro;

/*
 * Verbose discovery
 */
bool sedopal_discovery_verbose;

/*
 * discovery with udev output
 */
bool sedopal_discovery_udev;

/*
 * level 0 discovery buffer
 */
char level0_discovery_buf[4096];

struct sedopal_feature_parser {
	uint32_t	features;
	void		*tper_desc;
	void		*locking_desc;
	void		*geometry_reporting_desc;
	void		*opalv1_desc;
	void		*single_user_mode_desc;
	void		*datastore_desc;
	void		*opalv2_desc;
	void		*opalite_desc;
	void		*pyrite_v1_desc;
	void		*pyrite_v2_desc;
	void		*ruby_desc;
	void		*locking_lba_desc;
	void		*block_sid_auth_desc;
	void		*config_ns_desc;
	void		*data_removal_desc;
	void		*ns_geometry_desc;
};

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
	if (len < SEDOPAL_MIN_PASSWORD_LEN) {
		fprintf(stderr, "Error: password is not long enough\n");
		return NULL;
	}

	if (len > SEDOPAL_MAX_PASSWORD_LEN) {
		fprintf(stderr, "Error: password is too long\n");
		return NULL;
	}

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
	uint8_t locking_state;

	locking_state = sedopal_locking_state(fd);

	if (locking_state & OPAL_FEATURE_LOCKING_ENABLED) {
		fprintf(stderr,
			"Error: cannot initialize an initialized drive\n");
		return -EOPNOTSUPP;
	}

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
	if (!sedopal_lock_ro)
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
	int lock_state = OPAL_LK;

	if (sedopal_lock_ro)
		lock_state = OPAL_RO;

	return sedopal_lock_unlock(fd, lock_state);
}

/*
 * Unlock a SED Opal drive
 */
int sedopal_cmd_unlock(int fd)
{
	int rc;
	int lock_state = OPAL_RW;

	if (sedopal_lock_ro)
		lock_state = OPAL_RO;

	rc = sedopal_lock_unlock(fd, lock_state);

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
	uint8_t locking_state;

	locking_state = sedopal_locking_state(fd);

	if (!(locking_state & OPAL_FEATURE_LOCKING_ENABLED)) {
		fprintf(stderr,
			"Error: cannot lock/unlock an uninitialized drive\n");
		return -EOPNOTSUPP;
	}

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
		if (rc != 0) {
			if (rc == EPERM)
				fprintf(stderr, "Error: incorrect password\n");
			else
				fprintf(stderr, "PSID_REVERT_TPR rc %d\n", rc);
		}
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
		uint8_t locking_state;
		char *revert = "LSP";

		locking_state = sedopal_locking_state(fd);

		if (!(locking_state & OPAL_FEATURE_LOCKING_ENABLED)) {
			fprintf(stderr,
				"Error: can't revert an uninitialized drive\n");
			return -EOPNOTSUPP;
		}

		if (locking_state & OPAL_FEATURE_LOCKED) {
			fprintf(stderr,
				"Error: cannot revert drive while locked\n");
			return -EOPNOTSUPP;
		}

		rc = sedopal_set_key(&revert_lsp.key);
		if (rc != 0)
			return rc;

		revert_lsp.options = OPAL_PRESERVE;
		revert_lsp.__pad = 0;

		rc = ioctl(fd, IOC_OPAL_REVERT_LSP, &revert_lsp);
		if (rc == 0) {
			revert = "TPER";
			/*
			 * TPER must also be reverted.
			 */
			rc = ioctl(fd, IOC_OPAL_REVERT_TPR, &revert_lsp.key);
			if (rc != 0)
				fprintf(stderr, "Error: revert TPR - %d\n", rc);
		}

		if (rc != 0) {
			if (rc == EPERM)
				fprintf(stderr, "Error: incorrect password\n");
			else
				fprintf(stderr, "Error: revert %s - %d\n",
					revert, rc);
		}
#else
		rc = -EOPNOTSUPP;
#endif
	}

	if ((rc != 0) && (rc != EPERM))
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
		if (rc == EPERM)
			fprintf(stderr, "Error: incorrect password\n");
		else
			fprintf(stderr, "Error: setting password - %d\n", rc);
		return rc;
	}

#ifdef IOC_OPAL_SET_SID_PW
	/*
	 * set sid password
	 */
	rc = ioctl(fd, IOC_OPAL_SET_SID_PW, &new_pw);
	if (rc != 0) {
		if (rc == EPERM)
			fprintf(stderr, "Error: incorrect password\n");
		else
			fprintf(stderr, "Error: setting SID pw - %d\n", rc);
	}
#endif

	return rc;
}

/*
 * Print the state of locking features.
 */
void sedopal_print_locking_features(void *data)
{
	struct locking_desc *ld = (struct locking_desc *)data;
	uint8_t features = ld->features;

	if (!sedopal_discovery_udev) {
		printf("Locking Features:\n");
		printf("\tLocking Supported               : %s\n",
			(features & OPAL_FEATURE_LOCKING_SUPPORTED) ?
			"yes" : "no");
		printf("\tLocking Feature Enabled         : %s\n",
			(features & OPAL_FEATURE_LOCKING_ENABLED) ?
			"yes" : "no");
		printf("\tLocked                          : %s\n",
			(features & OPAL_FEATURE_LOCKED) ? "yes" : "no");
		printf("\tMedia Encryption                : %s\n",
			(features & OPAL_FEATURE_MEDIA_ENCRYPT) ? "yes" : "no");
		printf("\tMBR Enabled                     : %s\n",
			(features & OPAL_FEATURE_MBR_ENABLED) ? "yes" : "no");
		printf("\tMBR Done                        : %s\n",
			(features & OPAL_FEATURE_MBR_DONE) ? "yes" : "no");
	} else {
		printf("DEV_SED_LOCKED=%s\n",
			(features & OPAL_FEATURE_LOCKING_ENABLED) ?
			"ENABLED" : "DISABLED");
		printf("DEV_SED_LOCKING=%s\n",
			(features & OPAL_FEATURE_LOCKING_ENABLED) ?
			"ENABLED" : "DISABLED");
		printf("DEV_SED_LOCKING_SUPP=%s\n",
			(features & OPAL_FEATURE_LOCKING_SUPPORTED) ?
			"ENABLED" : "DISABLED");
		printf("DEV_SED_LOCKING_LOCKED=%s\n",
			(features & OPAL_FEATURE_LOCKED) ?
			"ENABLED" : "DISABLED");
	}
}

/*
 * Print the TPer feature.
 */
void sedopal_print_tper(void *data)
{
	struct tper_desc *td = (struct tper_desc *)data;

	printf("\nSED TPER:\n");
	printf("\tSync Supported                  : %s\n",
		(td->feature & TPER_FEATURE_SYNC) ? "yes" : "no");
	printf("\tAsync Supported                 : %s\n",
		(td->feature & TPER_FEATURE_ASYNC) ? "yes" : "no");
	printf("\tACK/NAK Supported               : %s\n",
		(td->feature & TPER_FEATURE_ACKNAK) ? "yes" : "no");
	printf("\tBuffer Management Supported     : %s\n",
		(td->feature & TPER_FEATURE_BUF_MGMT) ? "yes" : "no");
	printf("\tStreaming Supported             : %s\n",
		(td->feature & TPER_FEATURE_STREAMING) ? "yes" : "no");
	printf("\tComID Management Supported      : %s\n",
		(td->feature & TPER_FEATURE_COMID_MGMT) ? "yes" : "no");
}

/*
 * Print the Geometry feature.
 */
void sedopal_print_geometry(void *data)
{
	struct geometry_reporting_desc *gd;

	gd = (struct geometry_reporting_desc *)data;

	printf("\nSED Geometry:\n");
	printf("\tAlignment Required              : %s\n",
		(gd->align & GEOMETRY_ALIGNMENT_REQUIRED) ? "yes" : "no");
	printf("\tLogical Block Size              : %u\n",
		be32toh(gd->logical_block_size));
	printf("\tAlignment Granularity           : %llx\n",
		(unsigned long long)(be64toh(gd->alignment_granularity)));
	printf("\tLowest Aligned LBA              : %llx\n",
		(unsigned long long)(be64toh(gd->lowest_aligned_lba)));
}

/*
 * Print the opal v1 feature.
 */
void sedopal_print_opal_v1(void *data)
{
	struct opalv1_desc *v1d = (struct opalv1_desc *)data;

	printf("\nSED OPAL V1.0:\n");
	printf("\tBase Comid                      : %d\n",
		be16toh(v1d->base_comid));
	printf("\tNumber of Comids                : %d\n",
		be16toh(v1d->num_comids));
}

/*
 * Print the opal v2 feature.
 */
void sedopal_print_opal_v2(void *data)
{
	struct opalv2_desc *v2d = (struct opalv2_desc *)data;

	printf("\nSED OPAL V2.0:\n");
	printf("\tRange Crossing                  : %d\n",
		!(v2d->flags & OPAL_V2_RANGE_CROSSING));
	printf("\tBase Comid                      : %d\n",
		be16toh(v2d->base_comid));
	printf("\tNumber of Comids                : %d\n",
		be16toh(v2d->num_comids));
	printf("\tNumber of Admin Authorities     : %d\n",
		be16toh(v2d->num_locking_sp_admin_auth));
	printf("\tNumber of User Authorities      : %d\n",
		be16toh(v2d->num_locking_sp_user_auth));
	printf("\tInit pin                        : %d\n",
		v2d->initial_cpin_sid_ind);
	printf("\tRevert pin                      : %d\n",
		v2d->initial_cpin_sid_revert);
}

/*
 * Print the ruby feature.
 */
void sedopal_print_ruby(void *data)
{
	struct ruby_desc *rd = (struct ruby_desc *)data;

	printf("\nRuby:\n");
	printf("\tRange Crossing                  : %d\n",
		!(rd->flags & RUBY_RANGE_CROSSING));
	printf("\tBase Comid                      : %d\n",
		be16toh(rd->base_comid));
	printf("\tNumber of Comids                : %d\n",
		be16toh(rd->num_comids));
	printf("\tNumber of Admin Authorities     : %d\n",
		be16toh(rd->num_locking_sp_admin_auth));
	printf("\tNumber of User Authorities      : %d\n",
		be16toh(rd->num_locking_sp_user_auth));
	printf("\tInit pin                        : %d\n",
		rd->initial_cpin_sid_ind);
	printf("\tRevert pin                      : %d\n",
		rd->initial_cpin_sid_revert);
}

/*
 * Print the opalite feature.
 */
void sedopal_print_opalite(void *data)
{
	struct opalite_desc *old = (struct opalite_desc *)data;

	printf("\nSED Opalite:\n");
	printf("\tBase Comid                      : %d\n",
		be16toh(old->base_comid));
	printf("\tNumber of Comids                : %d\n",
		be16toh(old->num_comids));
	printf("\tInit pin                        : %d\n",
		old->initial_cpin_sid_ind);
	printf("\tRevert pin                      : %d\n",
		old->initial_cpin_sid_revert);
}

/*
 * Print the pyrite v1 feature.
 */
void sedopal_print_pyrite_v1(void *data)
{
	struct pyrite_v1_desc *p1d = (struct pyrite_v1_desc *)data;

	printf("\nPyrite V1:\n");
	printf("\tBase Comid                      : %d\n",
		be16toh(p1d->base_comid));
	printf("\tNumber of Comids                : %d\n",
		be16toh(p1d->num_comids));
	printf("\tInit pin                        : %d\n",
		p1d->initial_cpin_sid_ind);
	printf("\tRevert pin                      : %d\n",
		p1d->initial_cpin_sid_revert);
}

/*
 * Print the pyrite v2 feature.
 */
void sedopal_print_pyrite_v2(void *data)
{
	struct pyrite_v2_desc *p2d = (struct pyrite_v2_desc *)data;

	printf("\nPyrite V2:\n");
	printf("\tBase Comid                      : %d\n",
		be16toh(p2d->base_comid));
	printf("\tNumber of Comids                : %d\n",
		be16toh(p2d->num_comids));
	printf("\tInit pin                        : %d\n",
		p2d->initial_cpin_sid_ind);
	printf("\tRevert pin                      : %d\n",
		p2d->initial_cpin_sid_revert);
}

/*
 * Print the single user mode feature.
 */
void sedopal_print_sum(void *data)
{
	struct single_user_mode_desc *sumd;

	sumd = (struct single_user_mode_desc *)data;

	printf("\nSingle User Mode (SUM):\n");
	printf("\tNumber of Locking Objects       : %u\n",
		be32toh(sumd->num_locking_objects));
	printf("\tAny Locking Objects in SUM?     : %s\n",
		(sumd->flags & SUM_FEATURE_ANY) ? "yes" : "no");
	printf("\tAll Locking Objects in SUM?     : %s\n",
		(sumd->flags & SUM_FEATURE_ALL) ? "yes" : "no");
	printf("\tUser Authority of Objects       : %s\n",
		(sumd->flags & SUM_FEATURE_POLICY) ? "yes" : "no");
}

/*
 * Print the data store table feature.
 */
void sedopal_print_datastore(void *data)
{
	struct datastore_desc *dsd = (struct datastore_desc *)data;

	printf("\nData Store Table:\n");
	printf("\tNumber of Tables Supported      : %u\n",
		be16toh(dsd->max_tables));
	printf("\tMax Size of Tables              : %u\n",
		be32toh(dsd->max_table_size));
	printf("\tTable Size Alignment            : %u\n",
		be32toh(dsd->table_alignment));
}

/*
 * Print the block SID authentication feature.
 */
void sedopal_print_sid_auth(void *data)
{
	struct block_sid_auth_desc *sid_auth_d;

	sid_auth_d = (struct block_sid_auth_desc *)data;

	printf("\nSED Block SID Authentication:\n");
	printf("\tSID value equal MSID            : %s\n",
		(sid_auth_d->states & BLOCK_SID_VALUE_STATE) ? "yes" : "no");
	printf("\tSID auth blocked                : %s\n",
		(sid_auth_d->states & BLOCK_SID_BLOCKED_STATE) ? "yes" : "no");
	printf("\tHW reset selected               : %s\n",
		(sid_auth_d->hw_reset & BLOCK_SID_HW_RESET) ? "yes" : "no");
}

/*
 * Print the Locking LBA Ranges Control feature
 */
void sedopal_print_locking_lba(void *data)
{
	/*
	 * There currently isn't any definition of the level 0 content
	 * of this feature, so defer any printing.
	 */
}

/*
 * Print the configurable namespace locking feature.
 */
void sedopal_print_config_ns(void *data)
{
	struct config_ns_desc *nsd = (struct config_ns_desc *)data;

	printf("\nSED Configurable Namespace Locking:\n");
	printf("\tNon-global Locking Support      : %s\n",
		(nsd->flags & CONFIG_NS_RANGE_C) ? "yes" : "no");
	printf("\tNon-global Lock objects exist   : %s\n",
		(nsd->flags & CONFIG_NS_RANGE_P) ? "yes" : "no");
	printf("\tMaximum Key Count               : %d\n",
		be32toh(nsd->max_key_count));
	printf("\tUnused Key Count                : %d\n",
		be32toh(nsd->unused_key_count));
}

/*
 * Print the data removal mechanism feature.
 */
void sedopal_print_data_removal(void *data)
{
	struct data_removal_desc *drd = (struct data_removal_desc *)data;

	printf("\nSED Data Removal Mechanism:\n");
	printf("\tRemoval Operation Processing    : %s\n",
		(drd->flags & DATA_REMOVAL_OPER_PROCESSING) ? "yes" : "no");
	printf("\tRemoval Operation Interrupted   : %s\n",
		(drd->flags & DATA_REMOVAL_OPER_INTERRUPTED) ? "yes" : "no");
	printf("\tData Removal Mechanism          : %x\n",
		drd->removal_mechanism);
	printf("\tData Removal Format             : %x\n",
		drd->format);
	printf("\tData Removal Time (Bit 0)       : %x\n",
		be16toh(drd->time_mechanism_bit0));
	printf("\tData Removal Time (Bit 1)       : %x\n",
		be16toh(drd->time_mechanism_bit1));
	printf("\tData Removal Time (Bit 2)       : %x\n",
		be16toh(drd->time_mechanism_bit2));
	printf("\tData Removal Time (Bit 5)       : %x\n",
		be16toh(drd->time_mechanism_bit5));
}

/*
 * Print the namespace geometry feature.
 */
void sedopal_print_ns_geometry(void *data)
{
	struct ns_geometry_desc *nsgd = (struct ns_geometry_desc *)data;

	printf("\nSED Namespace Geometry:\n");
	printf("\tAlignment Required              : %s\n",
		(nsgd->align & NS_GEOMETRY_ALIGNMENT_REQUIRED) ? "yes" : "no");
	printf("\tLogical Block Size              : %x\n",
		be32toh(nsgd->logical_block_size));
	printf("\tAlignment Granularity           : %llx\n",
		(unsigned long long)(be64toh(nsgd->alignment_granularity)));
	printf("\tLowest Aligned LBA              : %llx\n",
		(unsigned long long)(be64toh(nsgd->lowest_aligned_lba)));
}

void sedopal_parse_features(struct level_0_discovery_features *feat,
		struct sedopal_feature_parser *sfp)
{
	uint16_t code = be16toh(feat->code);

	switch (code) {
	case OPAL_FEATURE_CODE_LOCKING:
		sfp->features |= OPAL_FEATURE_LOCKING;
		sfp->locking_desc = (void *)(feat + 1);
		break;
	case OPAL_FEATURE_CODE_OPALV1:
		sfp->features |= OPAL_FEATURE_OPALV1;
		sfp->opalv1_desc = (void *)(feat + 1);
		break;
	case OPAL_FEATURE_CODE_OPALV2:
		sfp->features |= OPAL_FEATURE_OPALV2;
		sfp->opalv2_desc = (void *)(feat + 1);
		break;
	case OPAL_FEATURE_CODE_TPER:
		sfp->features |= OPAL_FEATURE_TPER;
		sfp->tper_desc = (void *)(feat + 1);
		break;
	case OPAL_FEATURE_CODE_GEOMETRY:
		sfp->features |= OPAL_FEATURE_GEOMETRY;
		sfp->geometry_reporting_desc = (void *)(feat + 1);
		break;
	case OPAL_FEATURE_CODE_SINGLE_USER_MODE:
		sfp->features |= OPAL_FEATURE_SINGLE_USER_MODE;
		sfp->single_user_mode_desc = (void *)(feat + 1);
		break;
	case OPAL_FEATURE_CODE_DATA_STORE:
		sfp->features |= OPAL_FEATURE_DATA_STORE;
		sfp->datastore_desc = (void *)(feat + 1);
		break;
	case OPAL_FEATURE_CODE_OPALITE:
		sfp->features |= OPAL_FEATURE_OPALITE;
		sfp->opalite_desc = (void *)(feat + 1);
		break;
	case OPAL_FEATURE_CODE_PYRITE_V1:
		sfp->features |= OPAL_FEATURE_PYRITE_V1;
		sfp->pyrite_v1_desc = (void *)(feat + 1);
		break;
	case OPAL_FEATURE_CODE_PYRITE_V2:
		sfp->features |= OPAL_FEATURE_PYRITE_V2;
		sfp->pyrite_v2_desc = (void *)(feat + 1);
		break;
	case OPAL_FEATURE_CODE_RUBY:
		sfp->features |= OPAL_FEATURE_RUBY;
		sfp->ruby_desc = (void *)(feat + 1);
		break;
	case OPAL_FEATURE_CODE_LOCKING_LBA:
		sfp->features |= OPAL_FEATURE_LOCKING_LBA;
		sfp->locking_lba_desc = (void *)(feat + 1);
		break;
	case OPAL_FEATURE_CODE_BLOCK_SID_AUTH:
		sfp->features |= OPAL_FEATURE_BLOCK_SID_AUTH;
		sfp->block_sid_auth_desc = (void *)(feat + 1);
		break;
	case OPAL_FEATURE_CODE_CONFIG_NS_LOCKING:
		sfp->features |= OPAL_FEATURE_CONFIG_NS_LOCKING;
		sfp->config_ns_desc = (void *)(feat + 1);
		break;
	case OPAL_FEATURE_CODE_DATA_REMOVAL:
		sfp->features |= OPAL_FEATURE_DATA_REMOVAL;
		sfp->data_removal_desc = (void *)(feat + 1);
		break;
	case OPAL_FEATURE_CODE_NS_GEOMETRY:
		sfp->features |= OPAL_FEATURE_NS_GEOMETRY;
		sfp->ns_geometry_desc = (void *)(feat + 1);
		break;

	default:
		break;
	}
}

void sedopal_print_features(struct sedopal_feature_parser *sfp)
{
	if (sfp->features & OPAL_FEATURE_OPALV1)
		sedopal_print_opal_v1(sfp->opalv1_desc);

	if (sfp->features & OPAL_FEATURE_OPALV2)
		sedopal_print_opal_v2(sfp->opalv2_desc);

	if (sfp->features & OPAL_FEATURE_TPER)
		sedopal_print_tper(sfp->tper_desc);

	if (sfp->features & OPAL_FEATURE_GEOMETRY)
		sedopal_print_geometry(sfp->geometry_reporting_desc);

	if (sfp->features & OPAL_FEATURE_OPALITE)
		sedopal_print_opalite(sfp->opalite_desc);

	if (sfp->features & OPAL_FEATURE_SINGLE_USER_MODE)
		sedopal_print_sum(sfp->single_user_mode_desc);

	if (sfp->features & OPAL_FEATURE_DATA_STORE)
		sedopal_print_datastore(sfp->datastore_desc);

	if (sfp->features & OPAL_FEATURE_BLOCK_SID_AUTH)
		sedopal_print_sid_auth(sfp->block_sid_auth_desc);

	if (sfp->features & OPAL_FEATURE_RUBY)
		sedopal_print_ruby(sfp->ruby_desc);

	if (sfp->features & OPAL_FEATURE_PYRITE_V1)
		sedopal_print_pyrite_v1(sfp->pyrite_v1_desc);

	if (sfp->features & OPAL_FEATURE_PYRITE_V2)
		sedopal_print_pyrite_v2(sfp->pyrite_v2_desc);

	if (sfp->features & OPAL_FEATURE_LOCKING_LBA)
		sedopal_print_locking_lba(sfp->locking_lba_desc);

	if (sfp->features & OPAL_FEATURE_CONFIG_NS_LOCKING)
		sedopal_print_config_ns(sfp->config_ns_desc);

	if (sfp->features & OPAL_FEATURE_NS_GEOMETRY)
		sedopal_print_ns_geometry(sfp->ns_geometry_desc);
}

/*
 * Query a drive to retrieve it's level 0 features.
 */
int sedopal_discover_device(int fd, struct level_0_discovery_features **feat,
		struct level_0_discovery_features **feat_end)
{
#ifdef IOC_OPAL_DISCOVERY
	int rc;
	struct opal_discovery discover;
	struct level_0_discovery_header *dh;

	discover.data = (uintptr_t)level0_discovery_buf;
	discover.size = sizeof(level0_discovery_buf);

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
	dh = (struct level_0_discovery_header *)level0_discovery_buf;
	*feat = (struct level_0_discovery_features *)(dh + 1);
	*feat_end = (struct level_0_discovery_features *)
		(level0_discovery_buf + be32toh(dh->parameter_length));

	return 0
		;
#else /* IOC_OPAL_DISCOVERY */
	fprintf(stderr, "ERROR : NVMe device discovery is not supported\n");
	return -EOPNOTSUPP;
#endif
}

/*
 * Query a drive to determine if it's SED Opal capable and
 * it's current locking status.
 */
int sedopal_cmd_discover(int fd)
{
	int rc, feat_length;
	struct level_0_discovery_features *feat;
	struct level_0_discovery_features *feat_end;
	struct sedopal_feature_parser sfp = {};

	rc = sedopal_discover_device(fd, &feat, &feat_end);
	if (rc != 0)
		return rc;

	/*
	 * iterate through all the features that were returned
	 */
	while (feat < feat_end) {
		sedopal_parse_features(feat, &sfp);
		feat_length = feat->length + 4 /* hdr */;
		feat = (struct level_0_discovery_features *)
			((char *)feat + feat_length);
	}

	rc = 0;
	if (!(sfp.features & OPAL_SED_LOCKING_SUPPORT)) {
		fprintf(stderr, "Error: device does not support SED Opal\n");
		rc = -1;
	} else
		sedopal_print_locking_features(sfp.locking_desc);

	if (!sedopal_discovery_verbose)
		return rc;

	sedopal_print_features(&sfp);


	return rc;
}

/*
 * Query a drive to determine its locking state
 */
int sedopal_locking_state(int fd)
{
	int rc, feat_length;
	struct level_0_discovery_features *feat;
	struct level_0_discovery_features *feat_end;

	rc = sedopal_discover_device(fd, &feat, &feat_end);
	if (rc != 0)
		return rc;

	/*
	 * iterate through all the features that were returned
	 */
	while (feat < feat_end) {
		uint16_t code = be16toh(feat->code);

		if (code == OPAL_FEATURE_CODE_LOCKING) {
			struct locking_desc *ld = (struct locking_desc *) (feat + 1);

			return ld->features;
		}

		feat_length = feat->length + 4 /* hdr */;
		feat = (struct level_0_discovery_features *)
			((char *)feat + feat_length);
	}

	return 0;
}
