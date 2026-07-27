/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 Dell Technologies Inc. or its subsidiaries.
 *
 * Authors: Martin Belanger <martin.belanger@dell.com>
 */
#pragma once

#include <sys/types.h>

/*
 * Create path and every missing parent directory, like "mkdir -p".
 * Return: 0 on success (including if path already exists as a directory),
 * -errno otherwise.
 */
int mkdir_p(const char *path, mode_t mode);

/*
 * mkstemp(), with O_CLOEXEC set atomically where possible.
 * Return: an open fd on success, -errno otherwise.
 */
int mkstemp_cloexec(char *template);

/* fsync() path, to make a preceding rename()/unlink() inside it durable. */
void fsync_dir(const char *path);

/*
 * The final path component (the part after the last '/'), or path itself
 * if there's no '/'. Unlike POSIX basename(), never modifies path and
 * never returns a pointer to static storage.
 */
char *path_basename(const char *path);
