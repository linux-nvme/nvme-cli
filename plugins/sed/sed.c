// SPDX-License-Identifier: GPL-2.0-or-later
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>
#include <inttypes.h>
#include <linux/fs.h>
#include <sys/stat.h>

#include "common.h"
#include "nvme.h"
#include "libnvme.h"
#include "nvme-print.h"
#include "sedopal_cmd.h"
#include <linux/sed-opal.h>

#define CREATE_CMD
#include "sed.h"

OPT_ARGS(no_opts) = {
	OPT_END()
};

OPT_ARGS(init_opts) = {
	OPT_FLAG("read-only", 'r', &sedopal_lock_ro,
		 "Set locking range to read-only"),
	OPT_END()
};

OPT_ARGS(key_opts) = {
	OPT_FLAG("ask-key", 'k', &sedopal_ask_key,
			"prompt for SED authentication key"),
	OPT_END()
};

OPT_ARGS(revert_opts) = {
	OPT_FLAG("destructive", 'e', &sedopal_destructive_revert,
			"destructive revert"),
	OPT_FLAG("psid", 'p', &sedopal_psid_revert, "PSID revert"),
	OPT_END()
};

OPT_ARGS(lock_opts) = {
	OPT_FLAG("read-only", 'r', &sedopal_lock_ro,
		 "Set locking range to read-only"),
	OPT_FLAG("ask-key", 'k', &sedopal_ask_key,
			"prompt for SED authentication key"),
	OPT_END()
};

OPT_ARGS(discovery_opts) = {
	OPT_FLAG("verbose", 'v', &sedopal_discovery_verbose,
		"Print extended discovery information"),
	OPT_FLAG("udev", 'u', &sedopal_discovery_udev,
		"Print locking information in form suitable for udev rules"),
	OPT_END()
};

/*
 * Open the NVMe device specified on the command line. It must be the
 * NVMe block device (e.g. /dev/nvme0n1).
 */
static int sed_opal_open_device(struct nvme_dev **dev, int argc, char **argv,
		const char *desc, struct argconfig_commandline_options *opts)
{
	int err;

	err = parse_and_open(dev, argc, argv, desc, opts);
	if (err)
		return err;

	if (!S_ISBLK((*dev)->direct.stat.st_mode)) {
		fprintf(stderr,
			"ERROR : The NVMe block device must be specified\n");
		err = -EINVAL;
		dev_close(*dev);
	}

	return err;
}

static int sed_opal_discover(int argc, char **argv, struct command *cmd,
		struct plugin *plugin)
{
	int err;
	const char *desc = "Query SED device and display locking features";
	struct nvme_dev *dev;

	err = sed_opal_open_device(&dev, argc, argv, desc, discovery_opts);
	if (err)
		return err;

	err = sedopal_cmd_discover(dev->direct.fd);

	dev_close(dev);
	return err;
}

static int sed_opal_initialize(int argc, char **argv, struct command *cmd,
		struct plugin *plugin)
{
	int err;
	const char *desc = "Initialize a SED device for locking";
	struct nvme_dev *dev;

	err = sed_opal_open_device(&dev, argc, argv, desc, init_opts);
	if (err)
		return err;

	err = sedopal_cmd_initialize(dev->direct.fd);
	if ((err != 0) && (err != -EOPNOTSUPP))
		fprintf(stderr, "initialize: SED error -  %s\n",
				sedopal_error_to_text(err));

	dev_close(dev);
	return err;
}

static int sed_opal_revert(int argc, char **argv, struct command *cmd,
		struct plugin *plugin)
{
	int err;
	const char *desc = "Revert a SED device from locking state";
	struct nvme_dev *dev;

	err = sed_opal_open_device(&dev, argc, argv, desc, revert_opts);
	if (err)
		return err;

	err = sedopal_cmd_revert(dev->direct.fd);
	if ((err != 0) && (err != -EOPNOTSUPP) && (err != EPERM))
		fprintf(stderr, "revert: SED error -  %s\n",
				sedopal_error_to_text(err));

	dev_close(dev);
	return err;
}

static int sed_opal_lock(int argc, char **argv, struct command *cmd,
		struct plugin *plugin)
{
	int err;
	const char *desc = "Lock a SED device";
	struct nvme_dev *dev;

	err = sed_opal_open_device(&dev, argc, argv, desc, lock_opts);
	if (err)
		return err;

	err = sedopal_cmd_lock(dev->direct.fd);
	if ((err != 0) && (err != -EOPNOTSUPP))
		fprintf(stderr, "lock: SED error -  %s\n",
				sedopal_error_to_text(err));

	dev_close(dev);
	return err;
}

static int sed_opal_unlock(int argc, char **argv, struct command *cmd,
		struct plugin *plugin)
{
	int err;
	const char *desc = "Unlock a SED device";
	struct nvme_dev *dev;

	err = sed_opal_open_device(&dev, argc, argv, desc, lock_opts);
	if (err)
		return err;

	err = sedopal_cmd_unlock(dev->direct.fd);
	if ((err != 0) && (err != -EOPNOTSUPP))
		fprintf(stderr, "unlock: SED error -  %s\n",
				sedopal_error_to_text(err));

	dev_close(dev);
	return err;
}

static int sed_opal_password(int argc, char **argv, struct command *cmd,
		struct plugin *plugin)
{
	int err;
	const char *desc = "Change the locking password of a SED device";
	struct nvme_dev *dev;

	err = sed_opal_open_device(&dev, argc, argv, desc, no_opts);
	if (err)
		return err;

	err = sedopal_cmd_password(dev->direct.fd);
	if ((err != 0) && (err != EPERM))
		fprintf(stderr, "password: SED error -  %s\n",
				sedopal_error_to_text(err));

	dev_close(dev);
	return err;
}
