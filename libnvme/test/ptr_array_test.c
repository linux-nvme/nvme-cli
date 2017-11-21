/*
 * Copyright (C) 2017 Red Hat, Inc.
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; If not, see <http://www.gnu.org/licenses/>.
 *
 * Author: Gris Ge <fge@redhat.com>
 */

#include <stdint.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <inttypes.h>
#include <errno.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>

#include "ptr_array.h"

#define _TEST_STRING_COUNT	10000
#define _TEST_STRING_MAX_LEN	127
#define _TEST_STRING_MIN_LEN	1

static const char _ALPHABET[] =
	"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	"~!@#$%^&*()_+-=[];',./{}|\\\":<>?";
static const size_t _ALPHABET_LEN = sizeof(_ALPHABET) / sizeof(char);

static const char *gen_random_string(void);

static int _gen_test_strings(const char ***test_strings, uint32_t count);

static void _free_test_strings(const char **test_strings, uint32_t count);

static const char *gen_random_string(void)
{
	char *rc_str = NULL;
	int fd = -1;
	uint8_t random_num = 0;
	size_t str_len = 0;
	size_t got = 0;
	ssize_t cur_got = 0;

	fd = open("/dev/urandom", O_RDONLY);
	if (fd < 0) {
		printf("Failed to open urandom: %d\n", errno);
		goto out;
	}

	while(got < 1) {
		cur_got = read(fd, &random_num, 1);
		got += cur_got;
		if (cur_got < 0) {
			printf("failed to read random %d\n", errno);
			goto out;
		}
	}
	got = 0;
	cur_got = 0;

	/* Use /dev/urandom to get a random string length */

	str_len = random_num % _TEST_STRING_MAX_LEN;
	if (str_len < _TEST_STRING_MIN_LEN)
		str_len = _TEST_STRING_MIN_LEN;

	rc_str = (char *) calloc(1, sizeof(char) * str_len);
	if (rc_str == NULL) {
		printf("malloc failed\n");
		goto out;
	}

	while(got < str_len - 1) {
		cur_got = read(fd, &random_num, 1);
		if (cur_got < 0) {
			printf("failed to read random %d\n", errno);
			free(rc_str);
			rc_str = NULL;
			goto out;
		}
		rc_str[got] = _ALPHABET[random_num % _ALPHABET_LEN];
		got += cur_got;
	}

out:
	if (fd >= 0)
		close(fd);
	return rc_str;
}

static int _gen_test_strings(const char ***test_strings, uint32_t count)
{
	int rc = 0;
	uint32_t i = 0;

	assert(test_strings != NULL);

	*test_strings = (const char **) calloc(count, sizeof(char *));
	if (*test_strings == NULL)
		goto nomem;

	for (; i < count; ++i) {
		(*test_strings)[i] = gen_random_string();
		if ((*test_strings)[i] == NULL)
			goto nomem;
	}

	return rc;
nomem:
	printf("_gen_test_strings(): No memory\n");
	_free_test_strings(*test_strings, count);
	return ENOMEM;
}

static void _free_test_strings(const char **test_strings, uint32_t count)
{
	uint32_t i = 0;

	assert(test_strings != NULL);

	for (; i < count; ++i)
		free((void *) test_strings[i]);
	free(test_strings);
}

int main(void) {
	const char *tmp_str = NULL;
	const char *test_string = NULL;
	struct ptr_array *pa = NULL;
	uint32_t i = 0;
	const char **test_strings = NULL;
	uint32_t test_string_size = _TEST_STRING_COUNT;

	assert(_gen_test_strings(&test_strings, test_string_size) == 0);

	pa = ptr_array_new(_TEST_STRING_COUNT);

	for (i = 0; i < test_string_size; ++i) {
		ptr_array_update(pa, i, (void *) test_strings[i]);
	}
	/* Add a dup into to test grow */
	for (i = 0; i < test_string_size; ++i) {
		ptr_array_insert(pa, (void *) test_strings[i]);
	}

	assert(ptr_array_size(pa) == test_string_size * 2);

	for (i = 0; i < test_string_size * 2; ++i) {
		tmp_str = ptr_array_get(pa, i);
		assert(tmp_str != NULL);
		if (i >= test_string_size)
			test_string = test_strings[i - test_string_size];
		else
			test_string = test_strings[i];
		assert(strcmp(tmp_str, test_string) == 0);
	}
	ptr_array_free(pa);
	printf("PASS with %" PRIu32 " strings\n", test_string_size);
	exit(EXIT_SUCCESS);
}
