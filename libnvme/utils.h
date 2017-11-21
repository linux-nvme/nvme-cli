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

#ifndef _NVME_UTILS_H_
#define _NVME_UTILS_H_

#include <libnvme/libnvme.h>

#include <stdio.h>

#define _NVME_ERR_MSG_BUFF_LEN		512

#define _nvme_err_msg_clear(err_msg) \
	do { \
		if (err_msg != NULL) \
			memset(err_msg, 0, _NVME_ERR_MSG_BUFF_LEN); \
	} while(0)

#define _nvme_err_msg_set(err_msg, format, ...) \
	do { \
		if (err_msg != NULL) \
			snprintf(err_msg, _NVME_ERR_MSG_BUFF_LEN, \
				 format " (%s:%d)", ##__VA_ARGS__, __FILE__, \
				 __LINE__); \
	} while(0)

#define _good(rc, rc_val, out) \
	do { \
		rc_val = rc; \
		if (rc_val != NVME_OK) \
			goto out; \
	} while(0)

#define _alloc_null_check(err_msg, ptr, rc, goto_out) \
	do { \
		if (ptr == NULL) { \
			rc = NVME_ERR_NO_MEMORY; \
			_nvme_err_msg_set(err_msg, "NO MEMORY"); \
			goto goto_out; \
		} \
	} while(0)

#define _getter_func_gen_str(struct_name, prop_name) \
	const char *struct_name ##_## prop_name ##_get(struct struct_name *s) \
	{ \
		assert(s != NULL); \
		errno = 0; \
		return s->strs.prop_name; \
	}

#define _getter_func_gen_uint8_t(struct_name, prop_name) \
	uint8_t struct_name ##_## prop_name ##_get(struct struct_name *s) \
	{ \
		assert(s != NULL); \
		errno = 0; \
		return s->raw_data.prop_name; \
	}

#define _getter_func_gen_uint16_t(struct_name, prop_name) \
	uint16_t struct_name ##_## prop_name ##_get(struct struct_name *s) \
	{ \
		assert(s != NULL); \
		errno = 0; \
		return le16toh(*((uint16_t *) &s->raw_data.prop_name)); \
	}

#define _getter_func_gen_uint32_t(struct_name, prop_name) \
	uint32_t struct_name ##_## prop_name ##_get(struct struct_name *s) \
	{ \
		assert(s != NULL); \
		errno = 0; \
		return le32toh(*((uint32_t *) &s->raw_data.prop_name)); \
	}

#define _bit_field_extract(i, end_include, start_include) \
	(i >> start_include) & ((1 << (end_include - start_include + 1)) - 1)


#define _getter_func_gen_bit_field(struct_name, prop_name, bf_prop_name, \
				   end_bit_include, start_bit_include) \
	uint8_t struct_name ##_## prop_name ##_get(struct struct_name *s) \
	{ \
		assert(s != NULL); \
		errno = 0; \
		return _bit_field_extract(s->raw_data.bf_prop_name, \
					  end_bit_include, \
					  start_bit_include); \
	}

#define _str_prop_init(struct_name, struct_ptr, prop_name, err_msg, \
		       rc, goto_out) \
	do { \
		(struct_ptr)->strs.prop_name =  _u8_data_to_ascii( \
			(struct_ptr)->raw_data.prop_name, \
			sizeof((struct_ptr)->raw_data.prop_name)/ \
			sizeof(uint8_t)); \
		_alloc_null_check(err_msg, (struct_ptr)->strs.prop_name, \
				  rc, goto_out); \
	} while(0)

/*
 * Returned string should be freed by free().
 */
const char *_u8_data_to_ascii(uint8_t *data, size_t size);


#endif	/* End of _NVME_UTILS_H_ */
