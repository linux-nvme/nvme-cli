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

/* struct libnvme_ns -- sysfs-backed properties */
%{
	static PyObject *libnvme_ns_lba_size_get(const struct libnvme_ns *p)
	{
		int val;
		int ret = libnvme_ns_get_lba_size(p, &val, 0);

		if (ret == -ENOENT)
			Py_RETURN_NONE;
		if (ret) {
			raise_nvme(NvmeError, ret);
			return NULL;
		}

		return PyLong_FromLong(val);
	}
	static PyObject *libnvme_ns_lba_shift_get(const struct libnvme_ns *p)
	{
		int val;
		int ret = libnvme_ns_get_lba_shift(p, &val, 0);

		if (ret == -ENOENT)
			Py_RETURN_NONE;
		if (ret) {
			raise_nvme(NvmeError, ret);
			return NULL;
		}

		return PyLong_FromLong(val);
	}
	static PyObject *libnvme_ns_lba_count_get(const struct libnvme_ns *p)
	{
		uint64_t val;
		int ret = libnvme_ns_get_lba_count(p, &val, 0);

		if (ret == -ENOENT)
			Py_RETURN_NONE;
		if (ret) {
			raise_nvme(NvmeError, ret);
			return NULL;
		}

		return PyLong_FromUnsignedLongLong(val);
	}
	static PyObject *libnvme_ns_lba_util_get(const struct libnvme_ns *p)
	{
		uint64_t val;
		int ret = libnvme_ns_get_lba_util(p, &val, 0);

		if (ret == -ENOENT)
			Py_RETURN_NONE;
		if (ret) {
			raise_nvme(NvmeError, ret);
			return NULL;
		}

		return PyLong_FromUnsignedLongLong(val);
	}
	static PyObject *libnvme_ns_meta_size_get(const struct libnvme_ns *p)
	{
		int val;
		int ret = libnvme_ns_get_meta_size(p, &val, 0);

		if (ret == -ENOENT)
			Py_RETURN_NONE;
		if (ret) {
			raise_nvme(NvmeError, ret);
			return NULL;
		}

		return PyLong_FromLong(val);
	}
	static PyObject *libnvme_ns_csi_get(const struct libnvme_ns *p)
	{
		enum nvme_csi val;
		int ret = libnvme_ns_get_csi(p, &val, 0);

		if (ret == -ENOENT)
			Py_RETURN_NONE;
		if (ret) {
			raise_nvme(NvmeError, ret);
			return NULL;
		}

		return PyLong_FromLong(val);
	}
	static PyObject *libnvme_ns_command_retry_count_get(const struct libnvme_ns *p)
	{
		long val;
		int ret = libnvme_ns_get_command_retry_count(p, &val, 0);

		if (ret == -ENOENT)
			Py_RETURN_NONE;
		if (ret) {
			raise_nvme(NvmeError, ret);
			return NULL;
		}

		return PyLong_FromLong(val);
	}
	static PyObject *libnvme_ns_command_error_count_get(const struct libnvme_ns *p)
	{
		long val;
		int ret = libnvme_ns_get_command_error_count(p, &val, 0);

		if (ret == -ENOENT)
			Py_RETURN_NONE;
		if (ret) {
			raise_nvme(NvmeError, ret);
			return NULL;
		}

		return PyLong_FromLong(val);
	}
	static PyObject *libnvme_ns_io_requeue_no_usable_path_count_get(const struct libnvme_ns *p)
	{
		long val;
		int ret = libnvme_ns_get_io_requeue_no_usable_path_count(p, &val, 0);

		if (ret == -ENOENT)
			Py_RETURN_NONE;
		if (ret) {
			raise_nvme(NvmeError, ret);
			return NULL;
		}

		return PyLong_FromLong(val);
	}
	static PyObject *libnvme_ns_io_fail_no_available_path_count_get(const struct libnvme_ns *p)
	{
		long val;
		int ret = libnvme_ns_get_io_fail_no_available_path_count(p, &val, 0);

		if (ret == -ENOENT)
			Py_RETURN_NONE;
		if (ret) {
			raise_nvme(NvmeError, ret);
			return NULL;
		}

		return PyLong_FromLong(val);
	}
%}

%exception libnvme_ns::lba_size {
	$action
	if (PyErr_Occurred()) SWIG_fail;
}
%exception libnvme_ns::lba_shift {
	$action
	if (PyErr_Occurred()) SWIG_fail;
}
%exception libnvme_ns::lba_count {
	$action
	if (PyErr_Occurred()) SWIG_fail;
}
%exception libnvme_ns::lba_util {
	$action
	if (PyErr_Occurred()) SWIG_fail;
}
%exception libnvme_ns::meta_size {
	$action
	if (PyErr_Occurred()) SWIG_fail;
}
%exception libnvme_ns::csi {
	$action
	if (PyErr_Occurred()) SWIG_fail;
}
%exception libnvme_ns::command_retry_count {
	$action
	if (PyErr_Occurred()) SWIG_fail;
}
%exception libnvme_ns::command_error_count {
	$action
	if (PyErr_Occurred()) SWIG_fail;
}
%exception libnvme_ns::io_requeue_no_usable_path_count {
	$action
	if (PyErr_Occurred()) SWIG_fail;
}
%exception libnvme_ns::io_fail_no_available_path_count {
	$action
	if (PyErr_Occurred()) SWIG_fail;
}

%extend struct libnvme_ns {
	%immutable lba_size;
	PyObject * lba_size;
	%immutable lba_shift;
	PyObject * lba_shift;
	%immutable lba_count;
	PyObject * lba_count;
	%immutable lba_util;
	PyObject * lba_util;
	%immutable meta_size;
	PyObject * meta_size;
	%immutable csi;
	PyObject * csi;
	%immutable command_retry_count;
	PyObject * command_retry_count;
	%immutable command_error_count;
	PyObject * command_error_count;
	%immutable io_requeue_no_usable_path_count;
	PyObject * io_requeue_no_usable_path_count;
	%immutable io_fail_no_available_path_count;
	PyObject * io_fail_no_available_path_count;
}
