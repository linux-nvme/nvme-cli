// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 SUSE Software Solutions
 *
 * Authors: Daniel Wagner <dwagner@suse.de>
 */
#include <archive.h>
#include <archive_entry.h>
#include <dirent.h>
#ifdef CONFIG_LIBARCHIVE_DLOPEN
#include <dlfcn.h>
#endif
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <ccan/array_size/array_size.h>
#include <ccan/str/str.h>

#include "archive-util.h"
#include "cleanup-util.h"
#include "fs-util.h"

#ifdef CONFIG_LIBARCHIVE_DLOPEN
/*
 * libarchive is loaded when the first archive is created, so that nvme
 * doesn't depend on it (and on its compression libraries) for a feature of a
 * few vendor plugins. The functions below are called through pointers of the
 * same type, taken from libarchive's headers.
 */
static typeof(archive_entry_free) *sym_archive_entry_free;
static typeof(archive_entry_new) *sym_archive_entry_new;
static typeof(archive_entry_set_filetype) *sym_archive_entry_set_filetype;
static typeof(archive_entry_set_mtime) *sym_archive_entry_set_mtime;
static typeof(archive_entry_set_pathname) *sym_archive_entry_set_pathname;
static typeof(archive_entry_set_perm) *sym_archive_entry_set_perm;
static typeof(archive_entry_set_size) *sym_archive_entry_set_size;
static typeof(archive_write_add_filter_gzip) *sym_archive_write_add_filter_gzip;
static typeof(archive_write_close) *sym_archive_write_close;
static typeof(archive_write_data) *sym_archive_write_data;
static typeof(archive_write_free) *sym_archive_write_free;
static typeof(archive_write_header) *sym_archive_write_header;
static typeof(archive_write_new) *sym_archive_write_new;
static typeof(archive_write_open_filename) *sym_archive_write_open_filename;
static typeof(archive_write_set_format_pax_restricted)
	*sym_archive_write_set_format_pax_restricted;
static typeof(archive_write_set_format_zip) *sym_archive_write_set_format_zip;

static const struct {
	const char *name;
	void **ptr;
} archive_syms[] = {
	{ "archive_entry_free", (void **)&sym_archive_entry_free },
	{ "archive_entry_new", (void **)&sym_archive_entry_new },
	{ "archive_entry_set_filetype",
	  (void **)&sym_archive_entry_set_filetype },
	{ "archive_entry_set_mtime", (void **)&sym_archive_entry_set_mtime },
	{ "archive_entry_set_pathname",
	  (void **)&sym_archive_entry_set_pathname },
	{ "archive_entry_set_perm", (void **)&sym_archive_entry_set_perm },
	{ "archive_entry_set_size", (void **)&sym_archive_entry_set_size },
	{ "archive_write_add_filter_gzip",
	  (void **)&sym_archive_write_add_filter_gzip },
	{ "archive_write_close", (void **)&sym_archive_write_close },
	{ "archive_write_data", (void **)&sym_archive_write_data },
	{ "archive_write_free", (void **)&sym_archive_write_free },
	{ "archive_write_header", (void **)&sym_archive_write_header },
	{ "archive_write_new", (void **)&sym_archive_write_new },
	{ "archive_write_open_filename",
	  (void **)&sym_archive_write_open_filename },
	{ "archive_write_set_format_pax_restricted",
	  (void **)&sym_archive_write_set_format_pax_restricted },
	{ "archive_write_set_format_zip",
	  (void **)&sym_archive_write_set_format_zip },
};

#define archive_entry_free (*sym_archive_entry_free)
#define archive_entry_new (*sym_archive_entry_new)
#define archive_entry_set_filetype (*sym_archive_entry_set_filetype)
#define archive_entry_set_mtime (*sym_archive_entry_set_mtime)
#define archive_entry_set_pathname (*sym_archive_entry_set_pathname)
#define archive_entry_set_perm (*sym_archive_entry_set_perm)
#define archive_entry_set_size (*sym_archive_entry_set_size)
#define archive_write_add_filter_gzip (*sym_archive_write_add_filter_gzip)
#define archive_write_close (*sym_archive_write_close)
#define archive_write_data (*sym_archive_write_data)
#define archive_write_free (*sym_archive_write_free)
#define archive_write_header (*sym_archive_write_header)
#define archive_write_new (*sym_archive_write_new)
#define archive_write_open_filename (*sym_archive_write_open_filename)
#define archive_write_set_format_pax_restricted \
	(*sym_archive_write_set_format_pax_restricted)
#define archive_write_set_format_zip (*sym_archive_write_set_format_zip)

/*
 * The optional dependency for packaging tools and initrd generators, see
 * https://uapi-group.org/specifications/specs/elf_dlopen_metadata/
 */
#define DLOPEN_NOTE_OWNER "FDO"
#define DLOPEN_NOTE_TYPE 0x407c0c0a
#define DLOPEN_NOTE_JSON						\
	"[{\"feature\":\"archive\","					\
	"\"description\":\"Log archives of vendor plugins\","		\
	"\"priority\":\"suggested\","					\
	"\"soname\":[\"" LIBARCHIVE_SONAME "\"]}]"

static const struct {
	uint32_t n_namesz;
	uint32_t n_descsz;
	uint32_t n_type;
	char name[sizeof(DLOPEN_NOTE_OWNER)];
	char desc[sizeof(DLOPEN_NOTE_JSON)] __attribute__((aligned(4)));
} dlopen_note __attribute__((used, section(".note.dlopen"), aligned(4))) = {
	.n_namesz = sizeof(DLOPEN_NOTE_OWNER),
	.n_descsz = sizeof(DLOPEN_NOTE_JSON),
	.n_type = DLOPEN_NOTE_TYPE,
	.name = DLOPEN_NOTE_OWNER,
	.desc = DLOPEN_NOTE_JSON,
};

/*
 * Load libarchive once and keep it loaded.
 *
 * Return: 0 on success, -ENOTSUP when libarchive is not installed or lacks a
 * function.
 */
static int archive_load(void)
{
	static int ret = 1;
	void *handle;
	size_t i;

	if (ret <= 0)
		return ret;

	ret = -ENOTSUP;
	handle = dlopen(LIBARCHIVE_SONAME, RTLD_NOW | RTLD_LOCAL);
	if (!handle)
		return ret;

	for (i = 0; i < ARRAY_SIZE(archive_syms); i++) {
		*archive_syms[i].ptr = dlsym(handle, archive_syms[i].name);
		if (!*archive_syms[i].ptr) {
			dlclose(handle);
			return ret;
		}
	}

	ret = 0;
	return ret;
}
#else
static int archive_load(void)
{
	return 0;
}
#endif

static inline void cleanup_archive_write(struct archive **a)
{
	if (*a)
		archive_write_free(*a);
}
#define __cleanup_archive_write __cleanup(cleanup_archive_write)

static inline void cleanup_archive_entry(struct archive_entry **e)
{
	if (*e)
		archive_entry_free(*e);
}
#define __cleanup_archive_entry __cleanup(cleanup_archive_entry)

static inline void cleanup_dir(DIR **d)
{
	if (*d)
		closedir(*d);
}
#define __cleanup_dir __cleanup(cleanup_dir)

/* tar strips a leading '/' from member names instead of storing them. */
static const char *entry_name_of(const char *path)
{
	while (*path == '/')
		path++;
	return path;
}

static int add_file(struct archive *a, const char *path, const char *entry_name)
{
	__cleanup_fd int fd = shr_open_rawdata(path, O_RDONLY);
	__cleanup_archive_entry struct archive_entry *entry = NULL;
	struct stat st;
	char buf[64 * 1024];
	ssize_t n;

	if (fd < 0)
		return -errno;
	if (fstat(fd, &st))
		return -errno;

	entry = archive_entry_new();
	if (!entry)
		return -ENOMEM;

	archive_entry_set_pathname(entry, entry_name);
	archive_entry_set_size(entry, st.st_size);
	archive_entry_set_filetype(entry, AE_IFREG);
	archive_entry_set_perm(entry, st.st_mode & 0777);
	archive_entry_set_mtime(entry, st.st_mtime, 0);

	if (archive_write_header(a, entry) != ARCHIVE_OK)
		return -EIO;

	while ((n = read(fd, buf, sizeof(buf))) > 0) {
		if (archive_write_data(a, buf, n) < (ssize_t)n)
			return -EIO;
	}

	return n < 0 ? -errno : 0;
}

/*
 * Recurse into dir_path, adding every regular file found. prefix is
 * prepended to each member name (with a '/' joiner), or may be "" to add
 * entries without a wrapping directory name. Symlinks and other non-regular,
 * non-directory entries are skipped.
 */
static int add_dir_recursive(struct archive *a, const char *dir_path,
			     const char *prefix)
{
	__cleanup_dir DIR *d = opendir(dir_path);
	struct dirent *ent;
	int ret = 0;

	if (!d)
		return -errno;

	for (;;) {
		__cleanup_free char *child_path = NULL;
		__cleanup_free char *child_name = NULL;

		errno = 0;
		ent = readdir(d);
		if (!ent) {
			ret = -errno;
			break;
		}

		if (streq(ent->d_name, ".") || streq(ent->d_name, ".."))
			continue;

		if (asprintf(&child_path, "%s/%s", dir_path, ent->d_name) < 0 ||
		    asprintf(&child_name, *prefix ? "%s/%s" : "%s%s", prefix,
			     ent->d_name) < 0) {
			ret = -ENOMEM;
			break;
		}

		if (shr_isdir(child_path))
			ret = add_dir_recursive(a, child_path, child_name);
		else if (shr_isreg(child_path))
			ret = add_file(a, child_path, child_name);

		if (ret)
			break;
	}

	return ret;
}

static int tar_create(const char *tar_file, const char *const *paths,
		       size_t n_paths, bool gzip)
{
	__cleanup_archive_write struct archive *a = NULL;
	size_t i;
	int ret;

	ret = archive_load();
	if (ret)
		return ret;

	a = archive_write_new();
	if (!a)
		return -ENOMEM;

	if (gzip)
		archive_write_add_filter_gzip(a);
	archive_write_set_format_pax_restricted(a);

	if (archive_write_open_filename(a, tar_file) != ARCHIVE_OK)
		return -EIO;

	for (i = 0; i < n_paths; i++) {
		ret = add_file(a, paths[i], entry_name_of(paths[i]));
		if (ret)
			return ret;
	}

	return archive_write_close(a) == ARCHIVE_OK ? 0 : -EIO;
}

int shr_tar_create(const char *tar_file, const char *const *paths,
		    size_t n_paths)
{
	return tar_create(tar_file, paths, n_paths, false);
}

int shr_tar_gz_create(const char *tar_file, const char *const *paths,
		       size_t n_paths)
{
	return tar_create(tar_file, paths, n_paths, true);
}

int shr_archive_create_dir(const char *archive_file, const char *dir_path,
			    const char *wrap_name, enum shr_archive_format fmt)
{
	__cleanup_archive_write struct archive *a = NULL;
	int ret;

	ret = archive_load();
	if (ret)
		return ret;

	a = archive_write_new();
	if (!a)
		return -ENOMEM;

	switch (fmt) {
	case SHR_ARCHIVE_ZIP:
		archive_write_set_format_zip(a);
		break;
	case SHR_ARCHIVE_TAR_GZ:
		archive_write_add_filter_gzip(a);
		archive_write_set_format_pax_restricted(a);
		break;
	case SHR_ARCHIVE_TAR:
	default:
		archive_write_set_format_pax_restricted(a);
		break;
	}

	if (archive_write_open_filename(a, archive_file) != ARCHIVE_OK)
		return -EIO;

	ret = add_dir_recursive(a, dir_path, wrap_name ? wrap_name : "");
	if (ret)
		return ret;

	return archive_write_close(a) == ARCHIVE_OK ? 0 : -EIO;
}
