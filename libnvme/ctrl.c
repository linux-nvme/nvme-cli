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

#include <libnvme/libnvme.h>

#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <stdio.h> /* only for printf */
#include <endian.h>
#include <stdbool.h>
#include <inttypes.h>
#include <limits.h>
#include <unistd.h>

#include "libnvme/libnvme.h"

#include "ctrl.h"
#include "utils.h"
#include "ioctl.h"
#include "sysfs.h"

#define _NVME_ADMIN_CMD_IDENTIFY_CNS_ALL_CTRL	0x01

#define _NVME_VER_STR_MAX_LEN			14
/* The maximum version is 65536.256.256 */

struct _nvme_ctrl_strs {
	const char *sn;
	const char *mn;
	const char *fr;
	const char *ver;
	const char *subnqn;
	const char *fguid;
};

struct nvme_psd {
	struct _nvme_spec_psd raw_data;
};

struct nvme_ctrl {
	const char *dev_path;
	struct _nvme_ctrl_strs strs;
	struct _nvme_spec_id_ctrl_data raw_data;
	struct nvme_psd **psds;
};

static int _nvme_psds_new(struct nvme_ctrl *cnt, char *err_msg);
static int _init_ver_str(struct nvme_ctrl *cnt, char *err_msg);

_getter_func_gen_uint16_t(nvme_ctrl, vid);
_getter_func_gen_uint16_t(nvme_ctrl, ssvid);
_getter_func_gen_str(nvme_ctrl, sn);
_getter_func_gen_str(nvme_ctrl, mn);
_getter_func_gen_str(nvme_ctrl, fr);
_getter_func_gen_uint8_t(nvme_ctrl, rab);
_getter_func_gen_uint8_t(nvme_ctrl, cmic);
_getter_func_gen_uint8_t(nvme_ctrl, mdts);
_getter_func_gen_uint16_t(nvme_ctrl, cntlid);
_getter_func_gen_uint32_t(nvme_ctrl, ver);
_getter_func_gen_uint32_t(nvme_ctrl, rtd3r);
_getter_func_gen_uint32_t(nvme_ctrl, rtd3e);
_getter_func_gen_uint16_t(nvme_ctrl, oaes);
_getter_func_gen_uint32_t(nvme_ctrl, ctratt);
_getter_func_gen_str(nvme_ctrl, fguid);
_getter_func_gen_uint16_t(nvme_ctrl, oacs);
_getter_func_gen_uint8_t(nvme_ctrl, acl);
_getter_func_gen_uint8_t(nvme_ctrl, aerl);
_getter_func_gen_uint8_t(nvme_ctrl, frmw);
_getter_func_gen_uint8_t(nvme_ctrl, lpa);
_getter_func_gen_uint8_t(nvme_ctrl, elpe);
_getter_func_gen_uint8_t(nvme_ctrl, npss);
_getter_func_gen_uint8_t(nvme_ctrl, avscc);
_getter_func_gen_uint8_t(nvme_ctrl, apsta);
_getter_func_gen_uint16_t(nvme_ctrl, wctemp);
_getter_func_gen_uint16_t(nvme_ctrl, cctemp);
_getter_func_gen_uint16_t(nvme_ctrl, mtfa);
_getter_func_gen_uint32_t(nvme_ctrl, hmpre);
_getter_func_gen_uint32_t(nvme_ctrl, hmmin);
_getter_func_gen_uint32_t(nvme_ctrl, rpmbs);
_getter_func_gen_uint16_t(nvme_ctrl, edstt);
_getter_func_gen_uint8_t(nvme_ctrl, esto);
_getter_func_gen_uint8_t(nvme_ctrl, fwug);
_getter_func_gen_uint16_t(nvme_ctrl, kas);
_getter_func_gen_uint16_t(nvme_ctrl, hctma);
_getter_func_gen_uint16_t(nvme_ctrl, mntmt);
_getter_func_gen_uint16_t(nvme_ctrl, mxtmt);
_getter_func_gen_uint32_t(nvme_ctrl, sanicap);
_getter_func_gen_uint8_t(nvme_ctrl, sqes);
_getter_func_gen_uint8_t(nvme_ctrl, cqes);
_getter_func_gen_uint16_t(nvme_ctrl, maxcmd);
_getter_func_gen_uint32_t(nvme_ctrl, nn);
_getter_func_gen_uint16_t(nvme_ctrl, oncs);
_getter_func_gen_uint16_t(nvme_ctrl, fuses);
_getter_func_gen_uint8_t(nvme_ctrl, fna);
_getter_func_gen_uint8_t(nvme_ctrl, vwc);
_getter_func_gen_uint16_t(nvme_ctrl, awun);
_getter_func_gen_uint16_t(nvme_ctrl, awupf);
_getter_func_gen_uint8_t(nvme_ctrl, nvscc);
_getter_func_gen_uint16_t(nvme_ctrl, acwu);
_getter_func_gen_uint32_t(nvme_ctrl, sgls);
_getter_func_gen_str(nvme_ctrl, subnqn);
_getter_func_gen_uint32_t(nvme_ctrl, ioccsz);
_getter_func_gen_uint32_t(nvme_ctrl, iorcsz);
_getter_func_gen_uint16_t(nvme_ctrl, icdoff);
_getter_func_gen_uint8_t(nvme_ctrl, ctrattr);
_getter_func_gen_uint8_t(nvme_ctrl, msdbd);

_getter_func_gen_uint16_t(nvme_psd, mp);
_getter_func_gen_bit_field(nvme_psd, mxps, _bit_field_0, 24 % 8, 24 % 8);
_getter_func_gen_bit_field(nvme_psd, nops, _bit_field_0, 25 % 8, 25 % 8);
_getter_func_gen_uint32_t(nvme_psd, enlat);
_getter_func_gen_uint32_t(nvme_psd, exlat);
_getter_func_gen_bit_field(nvme_psd, rrt, _bit_field_1, 100 % 8, 96 % 8);
_getter_func_gen_bit_field(nvme_psd, rrl, _bit_field_2, 108 % 8, 104 % 8);
_getter_func_gen_bit_field(nvme_psd, rwt, _bit_field_3, 116 % 8, 112 % 8);
_getter_func_gen_bit_field(nvme_psd, rwl, _bit_field_4, 124 % 8, 120 % 8);
_getter_func_gen_uint16_t(nvme_psd, idlp);
_getter_func_gen_bit_field(nvme_psd, ips, _bit_field_5, 151 % 8, 150 % 8);
_getter_func_gen_uint16_t(nvme_psd, actp);
_getter_func_gen_bit_field(nvme_psd, apw, _bit_field_6, 178 % 8, 176 % 8);
_getter_func_gen_bit_field(nvme_psd, aps, _bit_field_6, 183 % 8, 182 % 8);

int _nvme_ctrl_get_by_fd(int fd, struct nvme_ctrl **cnt, const char *dev_path,
			 char *err_msg)
{
	int rc = NVME_OK;

	assert(cnt != NULL);

	*cnt = (struct nvme_ctrl *) calloc(1, sizeof(struct nvme_ctrl));
	_alloc_null_check(err_msg, *cnt, rc, out);

	_good(_nvme_ioctl_identify(fd, (uint8_t *) &((*cnt)->raw_data),
				   _NVME_ADMIN_CMD_IDENTIFY_CNS_ALL_CTRL,
				   0, err_msg),
	      rc, out);
	_good(_nvme_psds_new(*cnt, err_msg), rc, out);

	if (dev_path != NULL) {
		(*cnt)->dev_path = strdup(dev_path);
		_alloc_null_check(err_msg, (*cnt)->dev_path, rc, out);
	}

	_str_prop_init(nvme_ctrl, *cnt, sn, err_msg, rc, out);
	_str_prop_init(nvme_ctrl, *cnt, mn, err_msg, rc, out);
	_str_prop_init(nvme_ctrl, *cnt, fr, err_msg, rc, out);
	_str_prop_init(nvme_ctrl, *cnt, fguid, err_msg, rc, out);
	_str_prop_init(nvme_ctrl, *cnt, subnqn, err_msg, rc, out);
	_good(_init_ver_str(*cnt, err_msg), rc, out);

out:
	if (rc != NVME_OK) {
		nvme_ctrl_free(*cnt);
		*cnt = NULL;
	}
	return rc;
}

void nvme_ctrl_free(struct nvme_ctrl *cnt)
{
	uint8_t i = 0;
	if (cnt == NULL)
		return;

	if (cnt->psds != NULL)
		for (i = 0; i <= nvme_ctrl_npss_get(cnt); ++i)
			free(cnt->psds[i]);
	free(cnt->psds);
	free((void *) cnt->dev_path);
	free((void *) cnt->strs.ver);
	free((void *) cnt->strs.sn);
	free((void *) cnt->strs.mn);
	free((void *) cnt->strs.fr);
	free((void *) cnt->strs.subnqn);
	free((void *) cnt->strs.fguid);
	memset(cnt, 0, sizeof(struct nvme_ctrl));
	/* ^ Just ensure there will be no dangling pointer */
	free(cnt);
}

const char *nvme_ctrl_dev_path_get(struct nvme_ctrl *cnt)
{
	assert(cnt != NULL);
	errno = 0;
	return cnt->dev_path;
}
static int _init_ver_str(struct nvme_ctrl *cnt, char *err_msg)
{
	int rc = NVME_OK;
	struct _nvme_spec_ver *ver = NULL;
	char *ver_str = NULL;

	assert(cnt != NULL);

	ver_str = (char *) calloc(_NVME_VER_STR_MAX_LEN, sizeof(char));
	_alloc_null_check(err_msg, ver_str, rc, out);

	ver = (struct _nvme_spec_ver *) &(cnt->raw_data.ver);

	snprintf(ver_str, _NVME_VER_STR_MAX_LEN,
		 "%" PRIu16 ".%" PRIu8 ".%" PRIu8 "",
		 le16toh(ver->mjr), ver->mnr, ver->ter);

	if (strcmp(ver_str, "0.0.0") == 0)
		snprintf(ver_str, _NVME_VER_STR_MAX_LEN, "1.0.0");
	/* ^ There is no version 0.0.0, only 1.0.0 which does not define this
	 *   field.
	 */
	cnt->strs.ver = ver_str;

out:
	return rc;
}

const char *nvme_ctrl_ver_str_get(struct nvme_ctrl *cnt)
{
	assert(cnt != NULL);
	errno = 0;

	return cnt->strs.ver;
}

const uint8_t *nvme_ctrl_raw_id_data_get(struct nvme_ctrl *cnt)
{
	assert(cnt != NULL);
	errno = 0;
	return (uint8_t *) &(cnt->raw_data);
}

uint32_t nvme_ctrl_ieee_get(struct nvme_ctrl *cnt)
{
	uint8_t ieee_raw[4];
	assert(cnt != NULL);
	errno = 0;
	memset(&ieee_raw, 0, sizeof(ieee_raw));
	memcpy(ieee_raw, cnt->raw_data.ieee, 3/* IEEE only have 3 bytes */);

	return le32toh(* (uint32_t *) &ieee_raw);
}

const uint8_t *nvme_ctrl_tnvmcap_get(struct nvme_ctrl *cnt)
{
	assert(cnt != NULL);
	errno = 0;
	return cnt->raw_data.tnvmcap;
}

const uint8_t *nvme_ctrl_unvmcap_get(struct nvme_ctrl *cnt)
{
	assert(cnt != NULL);
	errno = 0;
	return cnt->raw_data.unvmcap;
}

static int _nvme_psds_new(struct nvme_ctrl *cnt, char *err_msg)
{
	uint8_t psd_count = 0;
	uint8_t i = 0;
	struct nvme_psd **psds = NULL;
	struct nvme_psd *psd = NULL;

	errno = 0;

	assert(cnt != NULL);
	assert(cnt->psds == NULL);

	psd_count = nvme_ctrl_npss_get(cnt) + 1;

	if (psd_count > 32) {
		_nvme_err_msg_set(err_msg, "Invalid NVMe data, got "
				  "%" PRIu8 "(should be less than 32) PSD",
				  psd_count);
		errno = NVME_ERR_BUG;
		return NVME_ERR_BUG;
	}

	psds = (struct nvme_psd **) calloc(psd_count,
					   sizeof(struct nvme_psd *));

	if (psds == NULL)
		goto nomem;

	for (i = 0; i < psd_count; ++i) {
		psd = (struct nvme_psd *) calloc(1, sizeof(struct nvme_psd));
		if (psd == NULL)
			goto nomem;
		psds[i] = psd;
		memcpy(&(psd->raw_data),
		       &(cnt->raw_data.psds[i]),
		       sizeof(struct _nvme_spec_psd));
	}
	cnt->psds = psds;
	return NVME_OK;

nomem:
	if (psds != NULL)
		for (i = 0; i < psd_count; ++i)
			free(psds[i]);
	free(psds);
	cnt->psds = NULL;
	errno = ENOMEM;
	return NVME_ERR_NO_MEMORY;
}

struct nvme_psd **nvme_ctrl_psds_get(struct nvme_ctrl *cnt)
{
	assert(cnt != NULL);
	errno = 0;
	return cnt->psds;
}

const uint8_t *nvme_ctrl_vendor_specfic_get(struct nvme_ctrl *cnt)
{
	assert(cnt != NULL);
	errno = 0;
	return cnt->raw_data.vendor_specific;
}
