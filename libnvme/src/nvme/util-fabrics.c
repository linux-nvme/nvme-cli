// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libnvme.
 * Copyright (c) 2026, Dell Technologies Inc. or its subsidiaries.
 *
 * Authors: Martin Belanger <Martin.Belanger@dell.com>
 */

#include <unistd.h>

#include <ccan/endian/endian.h>
#include <ccan/minmax/minmax.h>

#include <libnvme.h>

#include "cleanup-linux.h"
#include "private-fabrics.h"
#include "util.h"

#include "compiler-attributes.h"

__libnvme_public struct nvmf_ext_attr *libnvmf_exat_ptr_next(
		struct nvmf_ext_attr *p)
{
	__u16 size = libnvmf_exat_size(le16_to_cpu(p->exatlen));

	return (struct nvmf_ext_attr *)((uintptr_t)p + (ptrdiff_t)size);
}

const struct ifaddrs *libnvmf_getifaddrs(struct libnvme_global_ctx *ctx)
{
	if (!ctx->ifaddrs_cache) {
		struct ifaddrs *p;

		if (!getifaddrs(&p))
			ctx->ifaddrs_cache = p;
	}

	return ctx->ifaddrs_cache;
}

/**
 * read_file - read contents of file into @buffer.
 * @fname:  File name
 * @buffer: Where to save file's contents
 * @bufsz:  Size of @buffer. On success, @bufsz gets decremented by the
 *          number of characters that were writtent to @buffer.
 *
 * Return: The number of characters read. If the file cannot be opened or
 * nothing is read from the file, then this function returns 0.
 */
static size_t read_file(const char * fname, char *buffer, size_t *bufsz)
{
	char   *p;
	__cleanup_file FILE *file = NULL;
	size_t len;

	file = fopen(fname, "re");
	if (!file)
		return 0;

	p = fgets(buffer, *bufsz, file);

	if (!p)
		return 0;

	 /* Strip unwanted trailing chars */
	len = strcspn(buffer, " \t\n\r");
	*bufsz -= len;

	return len;
}

static size_t copy_value(char *buf, size_t buflen, const char *value)
{
	size_t val_len;

	memset(buf, 0, buflen);

	/* Remove leading " */
	if (value[0] == '"')
		value++;

	 /* Remove trailing " */
	val_len = strcspn(value, "\"");

	memcpy(buf, value, min(val_len, buflen-1));

	return val_len;
}

size_t libnvmf_get_entity_name(char *buffer, size_t bufsz)
{
	size_t len = !gethostname(buffer, bufsz) ? strlen(buffer) : 0;

	/* Fill the rest of buffer with zeros */
	memset(&buffer[len], '\0', bufsz-len);

	return len;
}

size_t libnvmf_get_entity_version(char *buffer, size_t bufsz)
{
	__cleanup_file FILE *file = NULL;
	size_t  num_bytes = 0;

	/* /proc/sys/kernel/ostype typically contains the string "Linux" */
	num_bytes += read_file("/proc/sys/kernel/ostype",
			       &buffer[num_bytes], &bufsz);

	/* /proc/sys/kernel/osrelease contains the Linux
	 * version (e.g. 5.8.0-63-generic)
	 */
	buffer[num_bytes++] = ' '; /* Append a space */
	num_bytes += read_file("/proc/sys/kernel/osrelease",
			       &buffer[num_bytes], &bufsz);

	/* /etc/os-release contains Key-Value pairs. We only care about the key
	 * PRETTY_NAME, which contains the Distro's version. For example:
	 * "SUSE Linux Enterprise Server 15 SP4", "Ubuntu 20.04.3 LTS", or
	 * "Fedora Linux 35 (Server Edition)"
	 */
	file = fopen("/etc/os-release", "re");
	if (file) {
		char    name[64] = {0};
		size_t  name_len = 0;
		char    ver_id[64] = {0};
		size_t  ver_id_len = 0;
		char    line[LINE_MAX];
		char    *p;
		char    *s;

		/* Read key-value pairs one line at a time */
		while ((!name_len || !ver_id_len) &&
		       (p = fgets(line, sizeof(line), file)) != NULL) {
			/* Clean up string by removing leading/trailing blanks
			 * and new line characters. Also eliminate trailing
			 * comments, if any.
			 */
			p = kv_strip(p);

			 /* Empty string? */
			if (*p == '\0')
				continue;

			s = kv_keymatch(p, "NAME");
			if (s)
				name_len = copy_value(name, sizeof(name), s);

			s = kv_keymatch(p, "VERSION_ID");
			if (s)
				ver_id_len = copy_value(ver_id, sizeof(ver_id), s);
		}

		if (name_len) {
			/* Append a space */
			buffer[num_bytes++] = ' ';
			name_len = min(name_len, bufsz);
			memcpy(&buffer[num_bytes], name, name_len);
			bufsz -= name_len;
			num_bytes += name_len;
		}

		if (ver_id_len) {
			/* Append a space */
			buffer[num_bytes++] = ' ';
			ver_id_len = min(ver_id_len, bufsz);
			memcpy(&buffer[num_bytes], ver_id, ver_id_len);
			bufsz -= ver_id_len;
			num_bytes += ver_id_len;
		}
	}

	/* Fill the rest of buffer with zeros */
	memset(&buffer[num_bytes], '\0', bufsz);

	return num_bytes;
}
