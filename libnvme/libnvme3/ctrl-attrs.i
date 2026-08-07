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

/* struct libnvme_ctrl -- lazily-loaded properties */
%rename(libnvme_ctrl_firmware_set) libnvme_ctrl_set_firmware;
%rename(libnvme_ctrl_model_set) libnvme_ctrl_set_model;
%rename(libnvme_ctrl_serial_set) libnvme_ctrl_set_serial;
%rename(libnvme_ctrl_cntrltype_set) libnvme_ctrl_set_cntrltype;
%rename(libnvme_ctrl_cntlid_set) libnvme_ctrl_set_cntlid;
%rename(libnvme_ctrl_dctype_set) libnvme_ctrl_set_dctype;
%rename(libnvme_ctrl_dhchap_host_key_set) libnvme_ctrl_set_dhchap_host_key;
%rename(libnvme_ctrl_dhchap_ctrl_key_set) libnvme_ctrl_set_dhchap_ctrl_key;
%rename(libnvme_ctrl_keyring_set) libnvme_ctrl_set_keyring;
%{
	#define libnvme_ctrl_firmware_set libnvme_ctrl_set_firmware
	#define libnvme_ctrl_model_set libnvme_ctrl_set_model
	#define libnvme_ctrl_serial_set libnvme_ctrl_set_serial
	#define libnvme_ctrl_cntrltype_set libnvme_ctrl_set_cntrltype
	#define libnvme_ctrl_cntlid_set libnvme_ctrl_set_cntlid
	#define libnvme_ctrl_dctype_set libnvme_ctrl_set_dctype
	#define libnvme_ctrl_dhchap_host_key_set libnvme_ctrl_set_dhchap_host_key
	#define libnvme_ctrl_dhchap_ctrl_key_set libnvme_ctrl_set_dhchap_ctrl_key
	#define libnvme_ctrl_keyring_set libnvme_ctrl_set_keyring
	static const char *libnvme_ctrl_numa_node_get(const struct libnvme_ctrl *p)
	{
		const char *val;
		int ret = libnvme_ctrl_get_numa_node(p, &val, NULL);

		if (ret == 0)
			return val;
		if (ret == -ENOENT)
			return NULL;

		raise_nvme(NvmeError, ret);
		return NULL;
	}
	static const char *libnvme_ctrl_queue_count_get(const struct libnvme_ctrl *p)
	{
		const char *val;
		int ret = libnvme_ctrl_get_queue_count(p, &val, NULL);

		if (ret == 0)
			return val;
		if (ret == -ENOENT)
			return NULL;

		raise_nvme(NvmeError, ret);
		return NULL;
	}
	static const char *libnvme_ctrl_sqsize_get(const struct libnvme_ctrl *p)
	{
		const char *val;
		int ret = libnvme_ctrl_get_sqsize(p, &val, NULL);

		if (ret == 0)
			return val;
		if (ret == -ENOENT)
			return NULL;

		raise_nvme(NvmeError, ret);
		return NULL;
	}
	static PyObject *libnvme_ctrl_command_error_count_get(const struct libnvme_ctrl *p)
	{
		long val;
		int ret = libnvme_ctrl_get_command_error_count(p, &val, 0);

		if (ret == -ENOENT)
			Py_RETURN_NONE;
		if (ret) {
			raise_nvme(NvmeError, ret);
			return NULL;
		}

		return PyLong_FromLong(val);
	}
	static PyObject *libnvme_ctrl_reset_count_get(const struct libnvme_ctrl *p)
	{
		long val;
		int ret = libnvme_ctrl_get_reset_count(p, &val, 0);

		if (ret == -ENOENT)
			Py_RETURN_NONE;
		if (ret) {
			raise_nvme(NvmeError, ret);
			return NULL;
		}

		return PyLong_FromLong(val);
	}
	static PyObject *libnvme_ctrl_reconnect_count_get(const struct libnvme_ctrl *p)
	{
		long val;
		int ret = libnvme_ctrl_get_reconnect_count(p, &val, 0);

		if (ret == -ENOENT)
			Py_RETURN_NONE;
		if (ret) {
			raise_nvme(NvmeError, ret);
			return NULL;
		}

		return PyLong_FromLong(val);
	}
	static const char *libnvme_ctrl_firmware_get(const struct libnvme_ctrl *p)
	{
		const char *val;
		int ret = libnvme_ctrl_get_firmware(p, &val, NULL);

		if (ret == 0)
			return val;
		if (ret == -ENOENT)
			return NULL;

		raise_nvme(NvmeError, ret);
		return NULL;
	}
	static const char *libnvme_ctrl_model_get(const struct libnvme_ctrl *p)
	{
		const char *val;
		int ret = libnvme_ctrl_get_model(p, &val, NULL);

		if (ret == 0)
			return val;
		if (ret == -ENOENT)
			return NULL;

		raise_nvme(NvmeError, ret);
		return NULL;
	}
	static const char *libnvme_ctrl_serial_get(const struct libnvme_ctrl *p)
	{
		const char *val;
		int ret = libnvme_ctrl_get_serial(p, &val, NULL);

		if (ret == 0)
			return val;
		if (ret == -ENOENT)
			return NULL;

		raise_nvme(NvmeError, ret);
		return NULL;
	}
	static const char *libnvme_ctrl_cntrltype_get(const struct libnvme_ctrl *p)
	{
		const char *val;
		int ret = libnvme_ctrl_get_cntrltype(p, &val, NULL);

		if (ret == 0)
			return val;
		if (ret == -ENOENT)
			return NULL;

		raise_nvme(NvmeError, ret);
		return NULL;
	}
	static const char *libnvme_ctrl_cntlid_get(const struct libnvme_ctrl *p)
	{
		const char *val;
		int ret = libnvme_ctrl_get_cntlid(p, &val, NULL);

		if (ret == 0)
			return val;
		if (ret == -ENOENT)
			return NULL;

		raise_nvme(NvmeError, ret);
		return NULL;
	}
	static const char *libnvme_ctrl_dctype_get(const struct libnvme_ctrl *p)
	{
		const char *val;
		int ret = libnvme_ctrl_get_dctype(p, &val, NULL);

		if (ret == 0)
			return val;
		if (ret == -ENOENT)
			return NULL;

		raise_nvme(NvmeError, ret);
		return NULL;
	}
	static const char *libnvme_ctrl_phy_slot_get(const struct libnvme_ctrl *p)
	{
		const char *val;
		int ret = libnvme_ctrl_get_phy_slot(p, &val, NULL);

		if (ret == 0)
			return val;
		if (ret == -ENOENT)
			return NULL;

		raise_nvme(NvmeError, ret);
		return NULL;
	}
	static const char *libnvme_ctrl_dhchap_host_key_get(const struct libnvme_ctrl *p)
	{
		const char *val;
		int ret = libnvme_ctrl_get_dhchap_host_key(p, &val, NULL);

		if (ret == 0)
			return val;
		if (ret == -ENOENT)
			return NULL;

		raise_nvme(NvmeError, ret);
		return NULL;
	}
	static const char *libnvme_ctrl_dhchap_ctrl_key_get(const struct libnvme_ctrl *p)
	{
		const char *val;
		int ret = libnvme_ctrl_get_dhchap_ctrl_key(p, &val, NULL);

		if (ret == 0)
			return val;
		if (ret == -ENOENT)
			return NULL;

		raise_nvme(NvmeError, ret);
		return NULL;
	}
	static const char *libnvme_ctrl_keyring_get(const struct libnvme_ctrl *p)
	{
		const char *val;
		int ret = libnvme_ctrl_get_keyring(p, &val, NULL);

		if (ret == 0)
			return val;
		if (ret == -ENOENT)
			return NULL;

		raise_nvme(NvmeError, ret);
		return NULL;
	}
%}

%exception libnvme_ctrl::numa_node {
	$action
	if (PyErr_Occurred()) SWIG_fail;
}
%exception libnvme_ctrl::queue_count {
	$action
	if (PyErr_Occurred()) SWIG_fail;
}
%exception libnvme_ctrl::sqsize {
	$action
	if (PyErr_Occurred()) SWIG_fail;
}
%exception libnvme_ctrl::command_error_count {
	$action
	if (PyErr_Occurred()) SWIG_fail;
}
%exception libnvme_ctrl::reset_count {
	$action
	if (PyErr_Occurred()) SWIG_fail;
}
%exception libnvme_ctrl::reconnect_count {
	$action
	if (PyErr_Occurred()) SWIG_fail;
}
%exception libnvme_ctrl::firmware {
	$action
	if (PyErr_Occurred()) SWIG_fail;
}
%exception libnvme_ctrl::model {
	$action
	if (PyErr_Occurred()) SWIG_fail;
}
%exception libnvme_ctrl::serial {
	$action
	if (PyErr_Occurred()) SWIG_fail;
}
%exception libnvme_ctrl::cntrltype {
	$action
	if (PyErr_Occurred()) SWIG_fail;
}
%exception libnvme_ctrl::cntlid {
	$action
	if (PyErr_Occurred()) SWIG_fail;
}
%exception libnvme_ctrl::dctype {
	$action
	if (PyErr_Occurred()) SWIG_fail;
}
%exception libnvme_ctrl::phy_slot {
	$action
	if (PyErr_Occurred()) SWIG_fail;
}
%exception libnvme_ctrl::dhchap_host_key {
	$action
	if (PyErr_Occurred()) SWIG_fail;
}
%exception libnvme_ctrl::dhchap_ctrl_key {
	$action
	if (PyErr_Occurred()) SWIG_fail;
}
%exception libnvme_ctrl::keyring {
	$action
	if (PyErr_Occurred()) SWIG_fail;
}

%extend struct libnvme_ctrl {
	%immutable numa_node;
	const char * numa_node;
	%immutable queue_count;
	const char * queue_count;
	%immutable sqsize;
	const char * sqsize;
	%immutable command_error_count;
	PyObject * command_error_count;
	%immutable reset_count;
	PyObject * reset_count;
	%immutable reconnect_count;
	PyObject * reconnect_count;
	const char * firmware;
	const char * model;
	const char * serial;
	const char * cntrltype;
	const char * cntlid;
	const char * dctype;
	%immutable phy_slot;
	const char * phy_slot;
	const char * dhchap_host_key;
	const char * dhchap_ctrl_key;
	const char * keyring;
}
