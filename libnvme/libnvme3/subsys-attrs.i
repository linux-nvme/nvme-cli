// SPDX-License-Identifier: LGPL-2.1-or-later

/*
 * This file is part of libnvme.
 *
 * Copyright (c) 2025, Dell Technologies Inc. or its subsidiaries.
 * Authors: Martin Belanger <Martin.Belanger@dell.com>
 *
 *   ____                           _           _    ____          _
 *  / ___| ___ _ __   ___ _ __ __ _| |_ ___  __| |  / ___|___   __| | ___
 * | |  _ / _ \ '_ \ / _ \ '__/ _` | __/ _ \/ _` | | |   / _ \ / _` |/ _ \
 * | |_| |  __/ | | |  __/ | | (_| | ||  __/ (_| | | |__| (_) | (_| |  __/
 *  \____|\___|_| |_|\___|_|  \__,_|\__\___|\__,_|  \____\___/ \__,_|\___|
 *
 * Auto-generated struct member accessors (setter/getter)
 *
 * To update run: meson compile -C [BUILD-DIR] update-accessors
 * Or:            make update-accessors
 */

/* struct libnvme_subsystem -- lazily-loaded properties */
%rename(libnvme_subsystem_model_set) libnvme_subsystem_set_model;
%rename(libnvme_subsystem_serial_set) libnvme_subsystem_set_serial;
%rename(libnvme_subsystem_firmware_set) libnvme_subsystem_set_firmware;
%{
	#define libnvme_subsystem_model_set libnvme_subsystem_set_model
	#define libnvme_subsystem_serial_set libnvme_subsystem_set_serial
	#define libnvme_subsystem_firmware_set libnvme_subsystem_set_firmware
	static const char *libnvme_subsystem_model_get(const struct libnvme_subsystem *p)
	{
		const char *val;
		int ret = libnvme_subsystem_get_model(p, &val, NULL);

		if (ret == 0)
			return val;
		if (ret == -ENOENT)
			return NULL;

		raise_nvme(NvmeError, ret);
		return NULL;
	}
	static const char *libnvme_subsystem_serial_get(const struct libnvme_subsystem *p)
	{
		const char *val;
		int ret = libnvme_subsystem_get_serial(p, &val, NULL);

		if (ret == 0)
			return val;
		if (ret == -ENOENT)
			return NULL;

		raise_nvme(NvmeError, ret);
		return NULL;
	}
	static const char *libnvme_subsystem_firmware_get(const struct libnvme_subsystem *p)
	{
		const char *val;
		int ret = libnvme_subsystem_get_firmware(p, &val, NULL);

		if (ret == 0)
			return val;
		if (ret == -ENOENT)
			return NULL;

		raise_nvme(NvmeError, ret);
		return NULL;
	}
	static const char *libnvme_subsystem_iopolicy_get(const struct libnvme_subsystem *p)
	{
		const char *val;
		int ret = libnvme_subsystem_get_iopolicy(p, &val, NULL);

		if (ret == 0)
			return val;
		if (ret == -ENOENT)
			return NULL;

		raise_nvme(NvmeError, ret);
		return NULL;
	}
%}

%exception libnvme_subsystem::model {
	$action
	if (PyErr_Occurred()) SWIG_fail;
}
%exception libnvme_subsystem::serial {
	$action
	if (PyErr_Occurred()) SWIG_fail;
}
%exception libnvme_subsystem::firmware {
	$action
	if (PyErr_Occurred()) SWIG_fail;
}
%exception libnvme_subsystem::iopolicy {
	$action
	if (PyErr_Occurred()) SWIG_fail;
}

%extend struct libnvme_subsystem {
	const char * model;
	const char * serial;
	const char * firmware;
	%immutable iopolicy;
	const char * iopolicy;
}
