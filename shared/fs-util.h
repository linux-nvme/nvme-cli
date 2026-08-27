/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 Dell Technologies Inc. or its subsidiaries.
 *
 * Authors: Martin Belanger <martin.belanger@dell.com>
 */
#pragma once

#include <fcntl.h>
#include <stdbool.h>
#include <sys/types.h>

/*
 * Create a single directory.
 * Return: 0 on success, -errno otherwise.
 */
int shr_mkdir(const char *path, mode_t mode);

/*
 * Create path and every missing parent directory, like "mkdir -p".
 * Return: 0 on success (including if path already exists as a directory),
 * -errno otherwise.
 */
int shr_mkdir_p(const char *path, mode_t mode);

/*
 * Create path and every missing parent directory using shr_mkdir_p
 * from a full path including a filename. A path ending in '/' carries no
 * filename and is created in full.
 */
int shr_mkdir_from_fname(const char *file, mode_t mode);

/*
 * Remove an empty directory.
 * Return: 0 on success, -errno otherwise.
 */
int shr_rmdir(const char *path);

/*
 * mkstemp(), with O_CLOEXEC set atomically where possible.
 * Return: an open fd on success, -errno otherwise.
 */
int shr_mkstemp(char *template);

/* fsync() path, to make a preceding rename()/unlink() inside it durable. */
void shr_fsync_dir(const char *path);

/* Return true if fd is still an open file descriptor, false once closed. */
bool shr_fd_is_open(int fd);

/*
 * Close a file descriptor.
 * Return: 0 on success, -errno otherwise.
 */
int shr_close(int fd);

/*
 * Remove a file.
 * Return: 0 on success, -errno otherwise.
 */
int shr_unlink(const char *path);

/*
 * The final path component (the part after the last '/'), or path itself
 * if there's no '/'. Unlike POSIX basename(), never modifies path and
 * never returns a pointer to static storage.
 */
char *shr_basename(const char *path);

/*
 * The length of the leading directory part of path, including the '/' that
 * ends it, or 0 when path holds no '/'. The counterpart of shr_basename():
 *
 *	path + shr_dir_prefix_len(path) == shr_basename(path)
 *
 * Unlike dirname(), a trailing '/' keeps its meaning, so the directory part
 * of "a/b/" is "a/b/" rather than "a".
 */
size_t shr_dir_prefix_len(const char *path);

/*
 * dirname returns the string up to, but not including, the final '/', and
 * basename returns the component following the final '/'. Trailing '/'
 * characters are not counted as part of the pathname.
 */
char *shr_dirname(char *path);

/*
 * Read an entire file into a newly allocated buffer.
 *
 * If dir is non-NULL, the file opened is dir + "/" + path (or just dir, if
 * path is empty). Otherwise, path is used as-is.
 *
 * If retries > 1, a failed open is retried up to retries times, sleeping
 * 1 second between attempts.
 *
 * Return: allocated buffer with *size set to its length (caller must
 * free), or NULL on error.
 */
unsigned char *shr_read_file(const char *dir, const char *path, long *size, int retries);

/* Path to the platform's null device, for e.g. open(). */
const char *shr_dev_null(void);

/*
 * fsync() a regular file, to make preceding writes to it durable.
 * Return: 0 on success, -errno otherwise.
 */
int shr_fsync(int fd);

/* Return: the size in bytes of a virtual memory page. */
int shr_getpagesize(void);

/*
 * open() for reading or writing raw data with no line-ending translation
 * or other interpretation/decoding -- i.e. O_BINARY where the platform has
 * one, a no-op everywhere else.
 */
#ifdef O_BINARY
#define shr_open_rawdata(path, flags, ...) open((path), (flags) | O_BINARY, ##__VA_ARGS__)
#else
#define shr_open_rawdata(path, flags, ...) open((path), (flags), ##__VA_ARGS__)
#endif
