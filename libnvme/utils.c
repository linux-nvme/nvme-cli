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

#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <assert.h>

#include "utils.h"

const char *_u8_data_to_ascii(uint8_t *data, size_t size)
{
	char *rc_str = NULL;

	assert(data != NULL);
	assert(size != 0);

	rc_str = (char *) calloc(size + 1, sizeof(char));
	if (rc_str == NULL) {
		errno = ENOMEM;
		return NULL;
	}

	/* Remove trailing white space */
	while(size > 0) {
		if ((data[size - 1] == ' ') || (data[size - 1] == '\0'))
			--size;
		else
			break;
	}

	if (size > 0)
		memcpy(rc_str, data, size);

	errno = 0;
	return rc_str;
}
