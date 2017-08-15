#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/types.h>

#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <unistd.h>
#include <errno.h>

#include "argconfig.h"
#include "sed-opal.h"
#include "nvme.h"
#include "nvme-builtin.h"


static const char *lr_d = "The locking range we wish to unlock.";
static const char *user_d = "User Authority to unlock as User[1..9] or Admin1";
static const char *pw_d = "The password up to 254 characters";
static const char *sum_d = "Specify whether to unlock in sum or in Opal SSC mode";
static const char *key_d = "Specify whether to store the password in secure Kernel Key Ring";
static const char *lt_d = "String specifying how to lock/unlock/etc: RW/RO/LK";


static int get_user(char *user, enum opal_user *who)
{
	unsigned int unum = 0;
	char *error;

	if (strlen(user) < 5) {
		fprintf(stderr, "Incorrect User, please provide userN/Admin1\n");
		return -EINVAL;
	}
	if (!strncasecmp(user, "admin", 5))
		*who = OPAL_ADMIN1;
	else if (!strncasecmp(user, "user", 4)) {
		unum = strtol(&user[4], &error, 10);
		if (error == &user[4]) {
			fprintf(stderr, "Failed to parse user # from string\n");
			return -EINVAL;
		}
		if (unum < OPAL_USER1 || unum > OPAL_USER9) {
			fprintf(stderr, "Incorrect User, please provide userN/Admin1\n");
			return -EINVAL;
		}
		*who = unum;
	}
	else {
		fprintf(stderr, "Incorrect User, please provide userN/Admin1\n");
		return -EINVAL;
	}
	return 0;
}

static int get_lock(char *lock, enum opal_lock_state *lstate)
{
	if (strlen(lock) < 2) {
		fprintf(stderr, "Invalid Lock state\n");
		return EINVAL;
	}

	if (!strncasecmp(lock, "RW", 2))
		*lstate = OPAL_RW;
	else if(!strncasecmp(lock, "RO", 2))
		*lstate = OPAL_RO;
	else if(!strncasecmp(lock, "LK", 2))
		*lstate = OPAL_LK;
	else {
		fprintf(stderr, "Invalid Lock state\n");
		return EINVAL;
	}
	return 0;
}

static int do_generic_lkul(int argc, char **argv, struct command *cmd,
			   struct plugin *plugin, const char *desc,
			   unsigned long ioctl_cmd)
{
	struct config {
		u8 lr;
		char *user;
		char *lock_type;
		char *password;
		bool sum;
	};

	struct config cfg = { 0 };
	const struct argconfig_commandline_options command_line_options[] = {
		{"lr", 'l', "NUM",       CFG_POSITIVE, &cfg.lr, required_argument, lr_d},
		{"user", 'u', "FMT",     CFG_STRING, &cfg.user, required_argument, user_d},
		{"locktype", 't', "FMT", CFG_STRING, &cfg.lock_type, required_argument, lt_d},
		{"password", 'p', "FMT", CFG_STRING, &cfg.password, required_argument, pw_d},
		{"sum",      's', ""   , CFG_NONE, &cfg.sum, no_argument, sum_d},
		{NULL}
	};

	struct opal_lock_unlock oln = { };
	int fd;

	fd = parse_and_open(argc, argv, desc, command_line_options, &cfg, sizeof(cfg));

	if ( (!cfg.sum && cfg.user == NULL) || cfg.lock_type == NULL || cfg.password == NULL) {
		fprintf(stderr, "Need to supply user, lock type and password!\n");
		return EINVAL;
	}

	oln.session.sum = cfg.sum;
	if (!cfg.sum)
		if (get_user(cfg.user, &oln.session.who))
			return EINVAL;

	if (get_lock(cfg.lock_type, &oln.l_state))
		return EINVAL;

	oln.session.opal_key.key_len = snprintf(oln.session.opal_key.key,
						sizeof(oln.session.opal_key.key),
						"%s", cfg.password);
	if (oln.session.opal_key.key_len == 0) {
		oln.session.opal_key.key_len = 1;
		oln.session.opal_key.key[0] = 0;
	}
	oln.session.opal_key.lr = cfg.lr;
	return ioctl(fd, ioctl_cmd, &oln);
}

static int do_generic_opal(int argc, char **argv, struct command *cmd,
			   struct plugin *plugin, const char *desc,
			   unsigned long ioctl_cmd)
{
	struct opal_key pw = { };
	struct config {
		u8 lr;
		char *password;
	};
	struct config cfg = { };
	const struct argconfig_commandline_options command_line_options[] = {
		{"lr", 'l', "NUM",       CFG_POSITIVE, &cfg.lr, required_argument, lr_d},
		{"password", 'p', "FMT", CFG_STRING, &cfg.password, required_argument, pw_d},
		{NULL}
	};
	int fd;

	fd = parse_and_open(argc, argv, desc, command_line_options, &cfg, sizeof(cfg));

	if (cfg.password == NULL) {
		fprintf(stderr, "Must Provide a password for this command\n");
		return EINVAL;
	}

	pw.key_len = snprintf(pw.key, sizeof(pw.key), "%s", cfg.password);
	pw.lr = cfg.lr;
	return ioctl(fd, ioctl_cmd, &pw);
}

int sed_save(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{

	const char *desc = "This method saves our password in the kernel. " \
		"This allows us to unlock the device after a suspent-to-ram";

	return do_generic_lkul(argc, argv, cmd, plugin, desc, IOC_OPAL_SAVE);
}


int sed_lock_unlock(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Lock Or Unlock a locking range.";

	key_d = "ARGUMENT NOT USED";
	return do_generic_lkul(argc, argv, cmd, plugin, desc, IOC_OPAL_LOCK_UNLOCK);
}

int sed_ownership(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Bring a controller out of a Factory inactive state by setting the ADMIN CPIN password\n";

	return do_generic_opal(argc, argv, cmd, plugin, desc, IOC_OPAL_TAKE_OWNERSHIP);
}

int sed_activatelsp(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	char *desc = "Activate the Locking SP. If you want to activate in sum provide a LR  > 0";

	return do_generic_opal(argc, argv, cmd, plugin, desc, IOC_OPAL_ACTIVATE_LSP);
}

int sed_reverttper(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	char *desc = "Revert the TPer to factory State. *THIS WILL ERASE ALL YOUR DATA*";
	return do_generic_opal(argc, argv, cmd, plugin, desc, IOC_OPAL_REVERT_TPR);
}

int sed_setuplr(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	const char *desc = "Set up a locking range.";
	const char *rle_d = "Enable read locking on this LR";
	const char *wle_d = "Enable Write locking on this LR";
	const char *rs_d = "Where the Locking range should start";
	const char *rl_d = "Length of the Locking range";

	int fd;
	struct opal_user_lr_setup setup = { };
	struct config {
		u8 lr;
		char *user;
		char *password;
		bool sum;
		bool RLE;
		bool WLE;
		size_t range_start;
		size_t range_length;
	};

	struct config cfg = {
		.range_start = 0,
		.range_length = 0,
		.WLE = false,
		.RLE = false
	};
	const struct argconfig_commandline_options command_line_options[] = {
		{"lr", 'l', "NUM",       CFG_POSITIVE, &cfg.lr, required_argument, lr_d},
		{"user", 'u', "FMT",     CFG_STRING, &cfg.user, required_argument, user_d},
		{"password", 'p', "FMT", CFG_STRING, &cfg.password, required_argument, pw_d},
		{"sum",      's', ""   , CFG_NONE, &cfg.sum, no_argument, sum_d},
		{"readLockEnabled", 'r', "", CFG_NONE, &cfg.RLE, no_argument, rle_d},
		{"writeLockEnabled", 'w', "", CFG_NONE, &cfg.WLE, no_argument, wle_d},
		{"rangeStart", 'z', "NUM", CFG_POSITIVE, &cfg.range_start, required_argument, rs_d},
		{"rangeLength", 'y', "NUM", CFG_POSITIVE, &cfg.range_length, required_argument, rl_d},
		{NULL}
	};

	fd = parse_and_open(argc, argv, desc, command_line_options, &cfg, sizeof(cfg));

	if (cfg.range_start == ~0 || cfg.range_length == ~0 || (!cfg.sum && cfg.user == NULL) ||
	    cfg.password == NULL) {

		    fprintf(stderr, "Incorrect parameters, please try again\n");
		    return EINVAL;
	}

	if (!cfg.sum)
		if (get_user(cfg.user, &setup.session.who))
			return -EINVAL;

	setup.session.sum = cfg.sum;

	setup.RLE = cfg.RLE;
	setup.WLE = cfg.WLE;

	setup.range_start = cfg.range_start;
	setup.range_length = cfg.range_length;

	setup.session.opal_key.key_len = snprintf(setup.session.opal_key.key,
						  sizeof(setup.session.opal_key.key),
						  "%s", cfg.password);
	if (setup.session.opal_key.key_len == 0) {
		setup.session.opal_key.key_len = 1;
		setup.session.opal_key.key[0] = 0;
	}
	setup.session.opal_key.lr = cfg.lr;
	return ioctl(fd, IOC_OPAL_LR_SETUP, &setup);
}

int sed_add_usr_to_lr(int argc, char **argv, struct command *cmd,
			     struct plugin *plugin)
{
        const char *desc = "Add user to Locking range. Non-sum only!";
	user_d = "User to add to the locking range";
	pw_d = "Admin1 Password";
	sum_d = key_d = "THIS FLAG IS UNUSED";

	return do_generic_lkul(argc, argv, cmd, plugin, desc, IOC_OPAL_ADD_USR_TO_LR);
}

int sed_shadowmbr(int argc, char **argv, struct command *cmd,
			 struct plugin *plugin)
{

	const char *desc = "Enable or Disable the MBR Shadow";
	const char *mbr_d = "Enable or Disable the MBR Shadow";
	struct opal_mbr_data mbr = { };
	struct config {
		char *password;
		bool enable_mbr;
	};
	struct config cfg = { };
	const struct argconfig_commandline_options command_line_options[] = {
		{"password", 'p', "FMT", CFG_STRING, &cfg.password, required_argument, pw_d},
		{"enable_mbr", 'e', "NUM", CFG_NONE, &cfg.enable_mbr, no_argument, mbr_d},
		{NULL}
	};
	int fd;

	fd = parse_and_open(argc, argv, desc, command_line_options, &cfg, sizeof(cfg));

	if (cfg.password == NULL) {
		fprintf(stderr, "Need ADMIN1 password for mbr shadow enable/disable\n");
		return EINVAL;
	}

	if (cfg.enable_mbr)
		mbr.enable_disable = OPAL_MBR_ENABLE;
	else
		mbr.enable_disable = OPAL_MBR_DISABLE;


	mbr.key.key_len = snprintf((char *)mbr.key.key,
				   sizeof(mbr.key.key),
				   "%s", cfg.password);
	return ioctl(fd, IOC_OPAL_ENABLE_DISABLE_MBR, &mbr);
}

int sed_setpw(int argc, char **argv, struct command *cmd,
	      struct plugin *plugin)
{
	const char *newpw_d = "The new password";
	const char *lspa_d  = "The Authority to use when starting a session to the Locking SP";
	const char *apw_d   = "The Password for the Authority when starting a session to the Locking SP";
	const char *_user_d = "The User to change the password for";
	const char *desc = "Set password for a specific User/Admin. See Man page/Documentation on how to properly use this command";
	sum_d = "Whether to set the password for a sum user or a Opal SSC user";

	struct opal_new_pw pw = { };
	struct config {
		char *lsp_authority;
		char *user_for_pw;
		char *new_password;
		char *authority_pw;
		bool sum;
	};

	struct config cfg = { 0 };
	const struct argconfig_commandline_options command_line_options[] = {
		{"user", 'u', "FMT",     CFG_STRING, &cfg.user_for_pw, required_argument, _user_d},
		{"newUserPW", 'n', "FMT", CFG_STRING, &cfg.new_password, required_argument, newpw_d},
		{"lspAuthority", 'p', "FMT", CFG_STRING, &cfg.lsp_authority, required_argument, lspa_d},
		{"authorityPW", 'a', "FMT", CFG_STRING, &cfg.authority_pw, required_argument, apw_d},
		{"sum",      's', ""   , CFG_NONE, &cfg.sum, no_argument, sum_d},
		{NULL}
	};
	int fd;

	fd = parse_and_open(argc, argv, desc, command_line_options, &cfg, sizeof(cfg));

	if (cfg.user_for_pw == NULL || cfg.lsp_authority == NULL ||
	    cfg.new_password == NULL || cfg.authority_pw == NULL) {
		fprintf(stderr, "Invalid arguments, please try again\n");
		return EINVAL;
	}

	if (get_user(cfg.user_for_pw, &pw.new_user_pw.who))
		return -EINVAL;
	if (get_user(cfg.lsp_authority, &pw.session.who))
		return -EINVAL;

	pw.session.sum = cfg.sum;

	pw.session.opal_key.lr = pw.session.who - 1;
	pw.session.opal_key.key_len = snprintf((char *)pw.session.opal_key.key,
					       sizeof(pw.session.opal_key.key),
					       "%s", cfg.authority_pw);
	/* In sum When we want to set a password as a user we start a
	 * session as that user. The user, however doesn't have a password.
	 * The spec states we send a NULL password. It's hard to send the NULL
	 * Character from cmd line so we let them leave the pw blank and fix
	 * it up here.
	 */
	if (pw.session.opal_key.key_len == 0) {
		pw.session.opal_key.key_len = 1;
		pw.session.opal_key.key[0] = 0;
	}

	pw.new_user_pw.opal_key.lr = pw.new_user_pw.who - 1;
	pw.new_user_pw.opal_key.key_len =
		snprintf((char *)pw.new_user_pw.opal_key.key,
			 sizeof(pw.new_user_pw.opal_key.key),
			 "%s", cfg.new_password);

	return ioctl(fd, IOC_OPAL_SET_PW, &pw);
}

int sed_enable_user(int argc, char **argv, struct command *cmd,
			   struct plugin *plugin)
{
	const char *desc = "Enable a user in the Locking SP";
	struct opal_session_info usr = { };
	struct config {
		char *user;
		char *password;
	};
	struct config cfg = { };
	user_d = "User we want to enable";
	pw_d = "Admin1 Password";
	const struct argconfig_commandline_options command_line_options[] = {
		{"user", 'u', "FMT",     CFG_STRING, &cfg.user, required_argument, user_d},
		{"password", 'p', "FMT", CFG_STRING, &cfg.password, required_argument, pw_d},
		{NULL}
	};
	int fd;

	fd = parse_and_open(argc, argv, desc, command_line_options, &cfg, sizeof(cfg));

	if (cfg.user == NULL || cfg.password == NULL) {
		fprintf(stderr, "Invalid arguments for %s\n", __func__);
		return EINVAL;
	}

	if (get_user(cfg.user, &usr.who))
		return EINVAL;

	if (usr.who == OPAL_ADMIN1) {
		fprintf(stderr, "Opal Admin is already activated by default!\n");
		return EINVAL;
	}
	usr.opal_key.key_len = snprintf(usr.opal_key.key, sizeof(usr.opal_key.key),
				   "%s", cfg.password);
	usr.opal_key.lr = 0;
	return ioctl(fd, IOC_OPAL_ACTIVATE_USR, &usr);
}

int sed_erase_lr(int argc, char **argv, struct command *cmd,
		 struct plugin *plugin)
{
	const char *desc = "Erase a Locking Range: *THIS ERASES YOUR DATA!*";
	struct config {
		u8 lr;
		char *user;
		char *password;
		bool sum;
	};

	struct config cfg = { 0 };
	const struct argconfig_commandline_options command_line_options[] = {
		{"lr", 'l', "NUM",       CFG_POSITIVE, &cfg.lr, required_argument, lr_d},
		{"user", 'u', "FMT",     CFG_STRING, &cfg.user, required_argument, user_d},
		{"password", 'p', "FMT", CFG_STRING, &cfg.password, required_argument, pw_d},
		{"sum",      's', ""   , CFG_NONE, &cfg.sum, no_argument, sum_d},
		{NULL}
	};

	struct opal_session_info session;
	int fd = parse_and_open(argc, argv, desc, command_line_options, &cfg, sizeof(cfg));

	if ( (!cfg.sum && cfg.user == NULL) || cfg.password == NULL) {
		fprintf(stderr, "Need to supply user, lock type and password!\n");
		return EINVAL;
	}

	session.sum = cfg.sum;
	if (!cfg.sum)
		if (get_user(cfg.user, &session.who))
			return EINVAL;


	session.opal_key.key_len = snprintf(session.opal_key.key,
					    sizeof(session.opal_key.key),
					    "%s", cfg.password);
	session.opal_key.lr = cfg.lr;
	return ioctl(fd, IOC_OPAL_ERASE_LR, &session);
}

int sed_secure_erase_lr(int argc, char **argv, struct command *cmd,
			struct plugin *plugin)
{
	const char *desc = "Secure erase a Locking Range: *THIS DELETES YOUR DATA*";
	struct opal_session_info usr = { };
	struct config {
		char *user;
		char *password;
		u8   lr;
		bool sum;
	};
	struct config cfg = {  };
	user_d = "Authority to start the session as.";
	pw_d = "Authority Password.";
	const struct argconfig_commandline_options command_line_options[] = {
		{"user", 'u', "FMT",     CFG_STRING, &cfg.user, required_argument, user_d},
		{"password", 'p', "FMT", CFG_STRING, &cfg.password, required_argument, pw_d},
		{"lr", 'l', "NUM",       CFG_POSITIVE, &cfg.lr, required_argument, lr_d},
		{"sum",      's', ""   , CFG_NONE, &cfg.sum, no_argument, sum_d},
		{NULL}
	};
	int fd = parse_and_open(argc, argv, desc, command_line_options, &cfg, sizeof(cfg));

	if (cfg.user == NULL || cfg.password == NULL) {
		fprintf(stderr, "Invalid arguments for %s\n", __func__);
		return EINVAL;
	}

	if (get_user(cfg.user, &usr.who))
		return EINVAL;

	usr.opal_key.key_len = snprintf(usr.opal_key.key, sizeof(usr.opal_key.key),
				   "%s", cfg.password);
	usr.opal_key.lr = 0;
	return ioctl(fd, IOC_OPAL_SECURE_ERASE_LR, &usr);
}
