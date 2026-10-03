// SPDX-License-Identifier: GPL-2.0-or-later

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include <libnvme.h>
#include <libnvme-sed.h>

#include <shared/term-util.h>

#include "nvme-print.h"
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
 * level 0 feature flags
 */
#define OPAL_FEATURE_TPER                       0x0001
#define OPAL_FEATURE_LOCKING                    0x0002
#define OPAL_FEATURE_GEOMETRY                   0x0004
#define OPAL_FEATURE_OPALV1                     0x0008
#define OPAL_FEATURE_SINGLE_USER_MODE           0x0010
#define OPAL_FEATURE_DATA_STORE                 0x0020
#define OPAL_FEATURE_OPALV2                     0x0040
#define OPAL_FEATURE_OPALITE                    0x0080
#define OPAL_FEATURE_PYRITE_V1                  0x0100
#define OPAL_FEATURE_PYRITE_V2                  0x0200
#define OPAL_FEATURE_RUBY                       0x0400
#define OPAL_FEATURE_LOCKING_LBA                0x0800
#define OPAL_FEATURE_BLOCK_SID_AUTH             0x1000
#define OPAL_FEATURE_CONFIG_NS_LOCKING          0x2000
#define OPAL_FEATURE_DATA_REMOVAL               0x4000
#define OPAL_FEATURE_NS_GEOMETRY                0x8000

#define OPAL_SED_LOCKING_SUPPORT \
		(OPAL_FEATURE_OPALV1 | OPAL_FEATURE_OPALV2 |  \
		OPAL_FEATURE_RUBY | OPAL_FEATURE_PYRITE_V1 | \
		OPAL_FEATURE_PYRITE_V2 | OPAL_FEATURE_LOCKING)

/*
 * level 0 discovery buffer size
 */
#define SEDOPAL_DISCOVERY_BUF_SIZE		4096

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
	[TCG_METHOD_STATUS_SUCCESS] =			"Success",
	[TCG_METHOD_STATUS_NOT_AUTHORIZED] =		"Host Not Authorized",
	[TCG_METHOD_STATUS_OBSOLETE_1] =		"Obsolete",
	[TCG_METHOD_STATUS_SP_BUSY] =			"SP Session Busy",
	[TCG_METHOD_STATUS_SP_FAILED] =			"SP Failed",
	[TCG_METHOD_STATUS_SP_DISABLED] =		"SP Disabled",
	[TCG_METHOD_STATUS_SP_FROZEN] =			"SP Frozen",
	[TCG_METHOD_STATUS_NO_SESSIONS_AVAILABLE] =	"No Sessions Available",
	[TCG_METHOD_STATUS_UNIQUENESS_CONFLICT] =	"Uniqueness Conflict",
	[TCG_METHOD_STATUS_INSUFFICIENT_SPACE] =	"Insufficient Space",
	[TCG_METHOD_STATUS_INSUFFICIENT_ROWS] =		"Insufficient Rows",
	[TCG_METHOD_STATUS_OBSOLETE_2] =		"Obsolete",
	[TCG_METHOD_STATUS_INVALID_PARAMETER] =		"Invalid Parameter",
	[TCG_METHOD_STATUS_OBSOLETE_3] =		"Obsolete",
	[TCG_METHOD_STATUS_OBSOLETE_4] =		"Obsolete",
	[TCG_METHOD_STATUS_TPER_MALFUNCTION] =		"TPER Malfunction",
	[TCG_METHOD_STATUS_TRANSACTION_FAILURE] =	"Transaction Failure",
	[TCG_METHOD_STATUS_RESPONSE_OVERFLOW] =		"Response Overflow",
	[TCG_METHOD_STATUS_AUTHORITY_LOCKED_OUT] =	"Authority Locked Out",
};

const char *sedopal_error_to_text(int code)
{
	if (code == TCG_METHOD_STATUS_FAIL)
		return "Failed";

	if (code == TCG_METHOD_STATUS_NO_METHOD_STATUS)
		return "Method returned no status";

	if (code < TCG_METHOD_STATUS_SUCCESS ||
	    code > TCG_METHOD_STATUS_AUTHORITY_LOCKED_OUT)
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

	pass = shr_getpass(prompt);
	if (pass == NULL)
		return NULL;

	len = strlen(pass);
	if (len < SEDOPAL_MIN_PASSWORD_LEN) {
		nvme_show_error("Error: password is not long enough");
		return NULL;
	}

	if (len > SEDOPAL_MAX_PASSWORD_LEN) {
		nvme_show_error("Error: password is too long");
		return NULL;
	}

	return pass;
}

/*
 * Initialize a SED Opal key. The key can either specify that the actual
 * key should be looked up in the kernel keyring, or it should be
 * populated in the key by prompting the user.
 */
int sedopal_set_key(struct libnvme_sed_key *key)
{
#if !NVME_HAVE_KEY_TYPE
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

		key->type = LIBNVME_SED_KEY_INCLUDED;
		key->len = strlen(pass);
		memcpy(key->key, pass, key->len + 1);

		/*
		 * If getting a new key, ask for it to be re-entered
		 * and verify the two entries are the same.
		 */
		if (sedopal_ask_new_key) {
			pass = sedopal_get_password(SEDOPAL_REENTER_PW_PROMPT);
			if (pass == NULL)
				return -EINVAL;
			if (strcmp((char *)key->key, pass)) {
				nvme_show_error(
					"Error: passwords don't match\n");
				return -EINVAL;
			}
		}
	} else {
		key->type = LIBNVME_SED_KEY_KEYRING;
		key->len = 0;
	}

	return 0;
}

/*
 * Prepare a drive for SED Opal locking.
 */
int sedopal_cmd_initialize(struct libnvme_transport_handle *hdl)
{
	int rc;
	struct libnvme_sed_key key;
	int locking_state;

	locking_state = sedopal_locking_state(hdl);
	if (locking_state < 0)
		return locking_state;

	if (locking_state & TCG_L0_LOCKING_ENABLED) {
		nvme_show_error(
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
	rc = libnvme_sed_take_ownership(hdl, &key);
	if (rc != 0) {
		nvme_show_error(
			"Error: failed to take device ownership - %d\n", rc);
		return rc;
	}

	/*
	 * activate lsp
	 */
	rc = libnvme_sed_activate_lsp(hdl, &key);
	if (rc != 0) {
		nvme_show_error("Error: failed to activate LSP - %d", rc);
		return rc;
	}

	/*
	 * setup global locking range
	 */
	rc = libnvme_sed_setup_range(hdl, &key, true, !sedopal_lock_ro);
	if (rc != 0) {
		nvme_show_error(
			"Error: failed to setup locking range - %d\n", rc);
		return rc;
	}

	/*
	 * set password
	 */
	rc = libnvme_sed_set_password(hdl, &key, &key);
	if (rc != 0)
		nvme_show_error("Error: failed setting password - %d", rc);

	return rc;
}

/*
 * Lock a SED Opal drive
 */
int sedopal_cmd_lock(struct libnvme_transport_handle *hdl)
{
	int lock_state = LIBNVME_SED_LOCK_LK;

	if (sedopal_lock_ro)
		lock_state = LIBNVME_SED_LOCK_RO;

	return sedopal_lock_unlock(hdl, lock_state);
}

/*
 * Unlock a SED Opal drive
 */
int sedopal_cmd_unlock(struct libnvme_transport_handle *hdl)
{
	int rc;
	int lock_state = LIBNVME_SED_LOCK_RW;

	if (sedopal_lock_ro)
		lock_state = LIBNVME_SED_LOCK_RO;

	rc = sedopal_lock_unlock(hdl, lock_state);

	/*
	 * If the unlock was successful, force a re-read of the
	 * partition table. Return rc of unlock operation.
	 */
	if (rc == 0) {
		if (libnvme_reread_partitions(hdl) != 0)
			nvme_show_error(
				"Warning: failed re-reading partition\n");
	}

	return rc;
}

/*
 * Lock or unlock a drive
 */
int sedopal_lock_unlock(struct libnvme_transport_handle *hdl, int lock_state)
{
	int rc;
	struct libnvme_sed_key key;
	int locking_state;

	locking_state = sedopal_locking_state(hdl);
	if (locking_state < 0)
		return locking_state;

	if (!(locking_state & TCG_L0_LOCKING_ENABLED)) {
		nvme_show_error(
			"Error: cannot lock/unlock an uninitialized drive\n");
		return -EOPNOTSUPP;
	}

	rc = sedopal_set_key(&key);
	if (rc != 0)
		return rc;

	rc = libnvme_sed_lock_unlock(hdl, &key, lock_state);
	if (rc != 0)
		nvme_show_error(
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
static int sedopal_revert_destructive(struct libnvme_transport_handle *hdl)
{
	struct libnvme_sed_key key;
	int rc;

	if (!sedopal_confirm_revert()) {
		nvme_show_error("Aborting destructive revert");
		return -1;
	}

	/*
	 * for destructive revert, require that key is provided
	 */
	sedopal_ask_key = true;

	rc = sedopal_set_key(&key);
	if (rc == 0)
		rc = libnvme_sed_revert_tper(hdl, &key);

	return rc;
}

/*
 * perform a PSID drive revert
 */
static int sedopal_revert_psid(struct libnvme_transport_handle *hdl)
{
	struct libnvme_sed_key key;
	int rc;

	if (!sedopal_confirm_revert()) {
		nvme_show_error("Aborting PSID revert");
		return -1;
	}

	rc = sedopal_set_key(&key);
	if (rc == 0) {
		rc = libnvme_sed_revert_psid(hdl, &key);
		if (rc == -ENOTSUP)
			nvme_show_error("ERROR : PSID revert is not supported");
		else if (rc == EPERM)
			nvme_show_error("Error: incorrect password");
		else if (rc != 0)
			nvme_show_error("PSID_REVERT_TPR rc %d", rc);
	}

	return rc;
}

/*
 * revert a drive from the provisioned state to a state where locking
 * is disabled.
 */
int sedopal_cmd_revert(struct libnvme_transport_handle *hdl)
{
	int rc;

	/*
	 * for revert, require that key/PSID is provided
	 */
	sedopal_ask_key = true;

	if (sedopal_psid_revert) {
		rc = sedopal_revert_psid(hdl);
	} else if (sedopal_destructive_revert) {
		rc = sedopal_revert_destructive(hdl);
	} else {
		struct libnvme_sed_key key;
		int locking_state;
		char *revert = "LSP";

		locking_state = sedopal_locking_state(hdl);
		if (locking_state < 0)
			return locking_state;

		if (!(locking_state & TCG_L0_LOCKING_ENABLED)) {
			nvme_show_error(
				"Error: can't revert an uninitialized drive\n");
			return -EOPNOTSUPP;
		}

		if (locking_state & TCG_L0_LOCKING_LOCKED) {
			nvme_show_error(
				"Error: cannot revert drive while locked\n");
			return -EOPNOTSUPP;
		}

		rc = sedopal_set_key(&key);
		if (rc != 0)
			return rc;

		rc = libnvme_sed_revert_lsp(hdl, &key, true);
		if (rc == 0) {
			revert = "TPER";
			/*
			 * TPER must also be reverted.
			 */
			rc = libnvme_sed_revert_tper(hdl, &key);
			if (rc != 0)
				nvme_show_error("Error: revert TPR - %d", rc);
		}

		if (rc != 0) {
			if (rc == EPERM)
				nvme_show_error("Error: incorrect password");
			else
				nvme_show_error("Error: revert %s - %d",
					revert, rc);
		}
	}

	if ((rc != 0) && (rc != EPERM))
		nvme_show_error("Error: failed reverting drive - %d", rc);

	return rc;
}

/*
 * Change the password of a drive. The existing password must be
 * provided and the new password is confirmed by re-entry.
 */
int sedopal_cmd_password(struct libnvme_transport_handle *hdl)
{
	int rc;
	struct libnvme_sed_key key, new_key;

	/*
	 * get current key
	 */
	sedopal_ask_key = true;
	if (sedopal_set_key(&key) != 0)
		return -EINVAL;

	/*
	 * get new key
	 */
	sedopal_ask_new_key = true;
	if (sedopal_set_key(&new_key) != 0)
		return -EINVAL;

	/*
	 * set admin1 password
	 */
	rc = libnvme_sed_set_password(hdl, &key, &new_key);
	if (rc != 0) {
		if (rc == EPERM)
			nvme_show_error("Error: incorrect password");
		else
			nvme_show_error("Error: setting password - %d", rc);
		return rc;
	}

	/*
	 * set sid password, if supported by the kernel
	 */
	rc = libnvme_sed_set_sid_password(hdl, &key, &new_key);
	if (rc == -ENOTSUP)
		rc = 0;
	else if (rc == EPERM)
		nvme_show_error("Error: incorrect password");
	else if (rc != 0)
		nvme_show_error("Error: setting SID pw - %d", rc);

	return rc;
}

/*
 * Print the state of locking features.
 */
void sedopal_print_locking_features(void *data)
{
	struct tcg_l0_locking *ld = (struct tcg_l0_locking *)data;
	uint8_t features;

	if (!ld) {
		nvme_show_error("Error retrieving details about locking features");
		return;
	}

	features = ld->features;

	if (!sedopal_discovery_udev) {
		printf("Locking Features:\n");
		printf("\tLocking Supported               : %s\n",
			(features & TCG_L0_LOCKING_SUPPORTED) ?
			"yes" : "no");
		printf("\tLocking Feature Enabled         : %s\n",
			(features & TCG_L0_LOCKING_ENABLED) ?
			"yes" : "no");
		printf("\tLocked                          : %s\n",
			(features & TCG_L0_LOCKING_LOCKED) ? "yes" : "no");
		printf("\tMedia Encryption                : %s\n",
			(features & TCG_L0_LOCKING_MEDIA_ENCRYPT) ?
			"yes" : "no");
		printf("\tMBR Enabled                     : %s\n",
			(features & TCG_L0_LOCKING_MBR_ENABLED) ? "yes" : "no");
		printf("\tMBR Done                        : %s\n",
			(features & TCG_L0_LOCKING_MBR_DONE) ? "yes" : "no");
	} else {
		printf("DEV_SED_LOCKED=%s\n",
			(features & TCG_L0_LOCKING_ENABLED) ?
			"ENABLED" : "DISABLED");
		printf("DEV_SED_LOCKING=%s\n",
			(features & TCG_L0_LOCKING_ENABLED) ?
			"ENABLED" : "DISABLED");
		printf("DEV_SED_LOCKING_SUPP=%s\n",
			(features & TCG_L0_LOCKING_SUPPORTED) ?
			"ENABLED" : "DISABLED");
		printf("DEV_SED_LOCKING_LOCKED=%s\n",
			(features & TCG_L0_LOCKING_LOCKED) ?
			"ENABLED" : "DISABLED");
	}
}

/*
 * Print the TPer feature.
 */
void sedopal_print_tper(void *data)
{
	struct tcg_l0_tper *td = (struct tcg_l0_tper *)data;

	printf("\nSED TPER:\n");
	printf("\tSync Supported                  : %s\n",
		(td->features & TCG_L0_TPER_SYNC) ? "yes" : "no");
	printf("\tAsync Supported                 : %s\n",
		(td->features & TCG_L0_TPER_ASYNC) ? "yes" : "no");
	printf("\tACK/NAK Supported               : %s\n",
		(td->features & TCG_L0_TPER_ACKNAK) ? "yes" : "no");
	printf("\tBuffer Management Supported     : %s\n",
		(td->features & TCG_L0_TPER_BUF_MGMT) ? "yes" : "no");
	printf("\tStreaming Supported             : %s\n",
		(td->features & TCG_L0_TPER_STREAMING) ? "yes" : "no");
	printf("\tComID Management Supported      : %s\n",
		(td->features & TCG_L0_TPER_COMID_MGMT) ? "yes" : "no");
}

/*
 * Print the Geometry feature.
 */
void sedopal_print_geometry(void *data)
{
	struct tcg_l0_geometry *gd;

	gd = (struct tcg_l0_geometry *)data;

	printf("\nSED Geometry:\n");
	printf("\tAlignment Required              : %s\n",
		(gd->align & TCG_L0_GEOMETRY_ALIGN) ? "yes" : "no");
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
	struct tcg_l0_opal_v1 *v1d = (struct tcg_l0_opal_v1 *)data;

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
	struct tcg_l0_opal_v2 *v2d = (struct tcg_l0_opal_v2 *)data;

	printf("\nSED OPAL V2.0:\n");
	printf("\tRange Crossing                  : %d\n",
		!(v2d->flags & TCG_L0_OPAL_V2_RANGE_CROSSING));
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
	struct tcg_l0_ruby *rd = (struct tcg_l0_ruby *)data;

	printf("\nRuby:\n");
	printf("\tRange Crossing                  : %d\n",
		!(rd->flags & TCG_L0_RUBY_RANGE_CROSSING));
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
	struct tcg_l0_opalite *old = (struct tcg_l0_opalite *)data;

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
	struct tcg_l0_pyrite_v1 *p1d = (struct tcg_l0_pyrite_v1 *)data;

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
	struct tcg_l0_pyrite_v2 *p2d = (struct tcg_l0_pyrite_v2 *)data;

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
	struct tcg_l0_sum *sumd;

	sumd = (struct tcg_l0_sum *)data;

	printf("\nSingle User Mode (SUM):\n");
	printf("\tNumber of Locking Objects       : %u\n",
		be32toh(sumd->num_locking_objects));
	printf("\tAny Locking Objects in SUM?     : %s\n",
		(sumd->flags & TCG_L0_SUM_ANY) ? "yes" : "no");
	printf("\tAll Locking Objects in SUM?     : %s\n",
		(sumd->flags & TCG_L0_SUM_ALL) ? "yes" : "no");
	printf("\tUser Controls Locking Range     : %s\n",
		(sumd->flags & TCG_L0_SUM_POLICY) ? "no" : "yes");
}

/*
 * Print the data store table feature.
 */
void sedopal_print_datastore(void *data)
{
	struct tcg_l0_datastore *dsd = (struct tcg_l0_datastore *)data;

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
	struct tcg_l0_block_sid_auth *sid_auth_d;

	sid_auth_d = (struct tcg_l0_block_sid_auth *)data;

	printf("\nSED Block SID Authentication:\n");
	printf("\tSID value equal MSID            : %s\n",
		(sid_auth_d->states & TCG_L0_BLOCK_SID_VALUE_STATE) ?
		"no" : "yes");
	printf("\tSID auth blocked                : %s\n",
		(sid_auth_d->states & TCG_L0_BLOCK_SID_BLOCKED_STATE) ?
		"yes" : "no");
	printf("\tHW reset selected               : %s\n",
		(sid_auth_d->hw_reset & TCG_L0_BLOCK_SID_HW_RESET) ?
		"yes" : "no");
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
	struct tcg_l0_cnl *nsd = (struct tcg_l0_cnl *)data;

	printf("\nSED Configurable Namespace Locking:\n");
	printf("\tNon-global Locking Support      : %s\n",
		(nsd->flags & TCG_L0_CNL_RANGE_C) ? "yes" : "no");
	printf("\tNon-global Lock objects exist   : %s\n",
		(nsd->flags & TCG_L0_CNL_RANGE_P) ? "yes" : "no");
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
	struct tcg_l0_data_removal *drd = (struct tcg_l0_data_removal *)data;

	printf("\nSED Data Removal Mechanism:\n");
	printf("\tRemoval Operation Processing    : %s\n",
		(drd->flags & TCG_L0_DATA_REMOVAL_PROCESSING) ? "yes" : "no");
	printf("\tRemoval Operation Interrupted   : %s\n",
		(drd->flags & TCG_L0_DATA_REMOVAL_INTERRUPTED) ? "yes" : "no");
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
	struct tcg_l0_ns_geometry *nsgd = (struct tcg_l0_ns_geometry *)data;

	printf("\nSED Namespace Geometry:\n");
	printf("\tAlignment Required              : %s\n",
		(nsgd->align & TCG_L0_NS_GEOMETRY_ALIGN) ? "yes" : "no");
	printf("\tLogical Block Size              : %x\n",
		be32toh(nsgd->logical_block_size));
	printf("\tAlignment Granularity           : %llx\n",
		(unsigned long long)(be64toh(nsgd->alignment_granularity)));
	printf("\tLowest Aligned LBA              : %llx\n",
		(unsigned long long)(be64toh(nsgd->lowest_aligned_lba)));
}

void sedopal_parse_features(struct tcg_l0_desc *feat,
		struct sedopal_feature_parser *sfp)
{
	uint32_t feature;
	size_t size;
	void **desc;

	switch (be16toh(feat->code)) {
	case TCG_L0_CODE_LOCKING:
		feature = OPAL_FEATURE_LOCKING;
		desc = &sfp->locking_desc;
		size = sizeof(struct tcg_l0_locking);
		break;
	case TCG_L0_CODE_OPAL_V1:
		feature = OPAL_FEATURE_OPALV1;
		desc = &sfp->opalv1_desc;
		size = sizeof(struct tcg_l0_opal_v1);
		break;
	case TCG_L0_CODE_OPAL_V2:
		feature = OPAL_FEATURE_OPALV2;
		desc = &sfp->opalv2_desc;
		size = sizeof(struct tcg_l0_opal_v2);
		break;
	case TCG_L0_CODE_TPER:
		feature = OPAL_FEATURE_TPER;
		desc = &sfp->tper_desc;
		size = sizeof(struct tcg_l0_tper);
		break;
	case TCG_L0_CODE_GEOMETRY:
		feature = OPAL_FEATURE_GEOMETRY;
		desc = &sfp->geometry_reporting_desc;
		size = sizeof(struct tcg_l0_geometry);
		break;
	case TCG_L0_CODE_SUM:
		feature = OPAL_FEATURE_SINGLE_USER_MODE;
		desc = &sfp->single_user_mode_desc;
		size = sizeof(struct tcg_l0_sum);
		break;
	case TCG_L0_CODE_DATASTORE:
		feature = OPAL_FEATURE_DATA_STORE;
		desc = &sfp->datastore_desc;
		size = sizeof(struct tcg_l0_datastore);
		break;
	case TCG_L0_CODE_OPALITE:
		feature = OPAL_FEATURE_OPALITE;
		desc = &sfp->opalite_desc;
		size = sizeof(struct tcg_l0_opalite);
		break;
	case TCG_L0_CODE_PYRITE_V1:
		feature = OPAL_FEATURE_PYRITE_V1;
		desc = &sfp->pyrite_v1_desc;
		size = sizeof(struct tcg_l0_pyrite_v1);
		break;
	case TCG_L0_CODE_PYRITE_V2:
		feature = OPAL_FEATURE_PYRITE_V2;
		desc = &sfp->pyrite_v2_desc;
		size = sizeof(struct tcg_l0_pyrite_v2);
		break;
	case TCG_L0_CODE_RUBY:
		feature = OPAL_FEATURE_RUBY;
		desc = &sfp->ruby_desc;
		size = sizeof(struct tcg_l0_ruby);
		break;
	case TCG_L0_CODE_LOCKING_LBA:
		feature = OPAL_FEATURE_LOCKING_LBA;
		desc = &sfp->locking_lba_desc;
		size = sizeof(struct tcg_l0_locking_lba);
		break;
	case TCG_L0_CODE_BLOCK_SID_AUTH:
		feature = OPAL_FEATURE_BLOCK_SID_AUTH;
		desc = &sfp->block_sid_auth_desc;
		size = sizeof(struct tcg_l0_block_sid_auth);
		break;
	case TCG_L0_CODE_CNL:
		feature = OPAL_FEATURE_CONFIG_NS_LOCKING;
		desc = &sfp->config_ns_desc;
		size = sizeof(struct tcg_l0_cnl);
		break;
	case TCG_L0_CODE_DATA_REMOVAL:
		feature = OPAL_FEATURE_DATA_REMOVAL;
		desc = &sfp->data_removal_desc;
		size = sizeof(struct tcg_l0_data_removal);
		break;
	case TCG_L0_CODE_NS_GEOMETRY:
		feature = OPAL_FEATURE_NS_GEOMETRY;
		desc = &sfp->ns_geometry_desc;
		size = sizeof(struct tcg_l0_ns_geometry);
		break;
	default:
		return;
	}

	if (feat->length < size)
		return;

	sfp->features |= feature;
	*desc = libnvme_sed_l0_data(feat);
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
static int sedopal_discover_device(struct libnvme_transport_handle *hdl,
		void *buf, size_t len)
{
	int rc;

	rc = libnvme_sed_discover(hdl, buf, len);
	if (rc) {
		nvme_show_err(rc, "level 0 discovery");
		/*
		 * Callers interpret positive values as TCG method status,
		 * don't leak the NVMe status.
		 */
		return rc > 0 ? -EIO : rc;
	}

	return 0;
}

/*
 * Query a drive to determine if it's SED Opal capable and
 * it's current locking status.
 */
int sedopal_cmd_discover(struct libnvme_transport_handle *hdl)
{
	char buf[SEDOPAL_DISCOVERY_BUF_SIZE];
	struct sedopal_feature_parser sfp = {};
	struct tcg_l0_desc *feat;
	int rc;

	rc = sedopal_discover_device(hdl, buf, sizeof(buf));
	if (rc != 0)
		return rc;

	libnvme_sed_l0_for_each(feat, buf, sizeof(buf))
		sedopal_parse_features(feat, &sfp);

	rc = 0;
	if (!(sfp.features & OPAL_SED_LOCKING_SUPPORT)) {
		nvme_show_error("Error: device does not support SED Opal");
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
int sedopal_locking_state(struct libnvme_transport_handle *hdl)
{
	char buf[SEDOPAL_DISCOVERY_BUF_SIZE];
	struct tcg_l0_locking *ld;
	struct tcg_l0_desc *feat;
	int rc;

	rc = sedopal_discover_device(hdl, buf, sizeof(buf));
	if (rc != 0)
		return rc;

	feat = libnvme_sed_l0_find(buf, sizeof(buf), TCG_L0_CODE_LOCKING);
	if (!feat || feat->length < sizeof(*ld))
		return 0;

	ld = libnvme_sed_l0_data(feat);
	return ld->features;
}
