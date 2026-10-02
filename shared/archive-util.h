/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 SUSE Software Solutions
 *
 * Authors: Daniel Wagner <dwagner@suse.de>
 */
#pragma once

#include <stddef.h>

/*
 * Create a tar archive at tar_file containing exactly the regular files
 * named by paths (n_paths entries). No directory recursion: callers list the
 * files themselves (e.g. with scandir()). Each archive member is named after
 * its path with any leading '/' stripped, matching how "tar -cf tar_file
 * path..." would name it.
 *
 * No external process is spawned; this links directly against libarchive.
 * When nvme-cli was built without libarchive, this is a stub that always
 * fails, so the feature is disabled rather than falling back to a shell.
 *
 * Return: 0 on success, -ENOTSUP when built without libarchive, -errno
 * otherwise (a path could not be read, or the archive could not be written).
 */
int shr_tar_create(const char *tar_file, const char *const *paths,
		    size_t n_paths);

/* Like shr_tar_create(), but gzip-compress the result ("tar -czf"). */
int shr_tar_gz_create(const char *tar_file, const char *const *paths,
		       size_t n_paths);

enum shr_archive_format {
	SHR_ARCHIVE_TAR,
	SHR_ARCHIVE_TAR_GZ,
	SHR_ARCHIVE_ZIP,
};

/*
 * Recursively archive the regular files under dir_path in the given format.
 * Each entry is named wrap_name (if non-NULL and non-empty) followed by the
 * file's path relative to dir_path, joined with '/' -- e.g. wrap_name
 * "mydir" turns dir_path/a/b.bin into the member "mydir/a/b.bin", matching
 * "zip -r out.zip mydir" run with mydir's parent as the working directory.
 * A NULL or empty wrap_name omits the prefix, matching "zip -r out.zip ."
 * run with dir_path itself as the working directory.
 *
 * Symlinks and other non-regular, non-directory entries are skipped.
 *
 * No external process is spawned; this links directly against libarchive.
 * When nvme-cli was built without libarchive, this is a stub that always
 * fails, so the feature is disabled rather than falling back to a shell.
 *
 * Return: 0 on success, -ENOTSUP when built without libarchive, -errno
 * otherwise.
 */
int shr_archive_create_dir(const char *archive_file, const char *dir_path,
			    const char *wrap_name, enum shr_archive_format fmt);
