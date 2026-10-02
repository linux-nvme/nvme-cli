// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 SUSE Software Solutions
 *
 * Authors: Daniel Wagner <dwagner@suse.de>
 *
 * Linked instead of archive-util.c when nvme-cli is built without
 * libarchive, so archive creation is disabled rather than falling back to
 * spawning an external tar process.
 */
#include <errno.h>

#include "archive-util.h"

int shr_tar_create(const char *tar_file, const char *const *paths,
		    size_t n_paths)
{
	return -ENOTSUP;
}

int shr_tar_gz_create(const char *tar_file, const char *const *paths,
		       size_t n_paths)
{
	return -ENOTSUP;
}

int shr_archive_create_dir(const char *archive_file, const char *dir_path,
			    const char *wrap_name, enum shr_archive_format fmt)
{
	return -ENOTSUP;
}
