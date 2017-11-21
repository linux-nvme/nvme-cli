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
#include <inttypes.h>
#include <stdio.h>
#include <assert.h>
#include <endian.h>

#include <libnvme/libnvme.h>

#define _ctrl_print_pro_char(cnt, prop_name) \
	printf(# prop_name ": '%s'\n", nvme_ctrl_ ## prop_name ##_get(cnt))

#define _ctrl_print_pro_u8(cnt, prop_name) \
	printf(# prop_name ": %" PRIu8 "\n", \
	       nvme_ctrl_ ## prop_name ## _get(cnt))

#define _ctrl_print_pro_u16(cnt, prop_name) \
	printf(# prop_name ": %" PRIu16 "\n", \
	       nvme_ctrl_ ## prop_name ## _get(cnt))

#define _ctrl_print_pro_u32(cnt, prop_name) \
	printf(# prop_name ": %" PRIu32 "\n", \
	       nvme_ctrl_ ## prop_name ## _get(cnt))

#define _psd_print_pro_u8(p, prop_name) \
	printf(# prop_name ": %" PRIu8 "\n", \
	       nvme_psd_ ## prop_name ## _get(p))

#define _psd_print_pro_u16(p, prop_name) \
	printf(# prop_name ": %" PRIu16 "\n", \
	       nvme_psd_ ## prop_name ## _get(p))

#define _psd_print_pro_u32(p, prop_name) \
	printf(# prop_name ": %" PRIu32 "\n", \
	       nvme_psd_ ## prop_name ## _get(p))

static void _test_nvme_ctrl_pro_query(struct nvme_ctrl *cnt);

static void _test_nvme_psd_pro_query(struct nvme_psd *psd);

static void _test_nvme_ctrl_raw_id_data(struct nvme_ctrl *cnt);

static void _test_nvme_psd_pro_query(struct nvme_psd *psd)
{
	_psd_print_pro_u16(psd, mp);
	_psd_print_pro_u8(psd, mxps);
	_psd_print_pro_u8(psd, nops);
	_psd_print_pro_u32(psd, enlat);
	_psd_print_pro_u32(psd, exlat);
	_psd_print_pro_u8(psd, rrt);
	_psd_print_pro_u8(psd, rrl);
	_psd_print_pro_u8(psd, rwt);
	_psd_print_pro_u8(psd, rwl);
	_psd_print_pro_u16(psd, idlp);
	_psd_print_pro_u8(psd, ips);
	_psd_print_pro_u16(psd, actp);
	_psd_print_pro_u8(psd, apw);
	_psd_print_pro_u8(psd, aps);
}

static void _test_nvme_ctrl_pro_query(struct nvme_ctrl *cnt)
{
	struct nvme_psd **psds = NULL;
	uint8_t i = 0;
	uint8_t psd_count = 0;

	_ctrl_print_pro_char(cnt, dev_path);
	_ctrl_print_pro_u16(cnt, vid);
	_ctrl_print_pro_u16(cnt, ssvid);
	_ctrl_print_pro_char(cnt, sn);
	_ctrl_print_pro_char(cnt, mn);
	_ctrl_print_pro_char(cnt, fr);
	_ctrl_print_pro_u8(cnt, rab);
	_ctrl_print_pro_u32(cnt, ieee);
	_ctrl_print_pro_u8(cnt, cmic);
	_ctrl_print_pro_u8(cnt, mdts);
	_ctrl_print_pro_u16(cnt, cntlid);
	_ctrl_print_pro_u32(cnt, ver);
	_ctrl_print_pro_char(cnt, ver_str);
	_ctrl_print_pro_u32(cnt, rtd3r);
	_ctrl_print_pro_u32(cnt, rtd3e);
	_ctrl_print_pro_u16(cnt, oaes);
	_ctrl_print_pro_u32(cnt, ctratt);
	_ctrl_print_pro_char(cnt, fguid);
	_ctrl_print_pro_u16(cnt, oacs);
	_ctrl_print_pro_u8(cnt, acl);
	_ctrl_print_pro_u8(cnt, aerl);
	_ctrl_print_pro_u8(cnt, frmw);
	_ctrl_print_pro_u8(cnt, lpa);
	_ctrl_print_pro_u8(cnt, elpe);
	_ctrl_print_pro_u8(cnt, npss);
	_ctrl_print_pro_u8(cnt, avscc);
	_ctrl_print_pro_u8(cnt, apsta);
	_ctrl_print_pro_u16(cnt, wctemp);
	_ctrl_print_pro_u16(cnt, cctemp);
	_ctrl_print_pro_u16(cnt, mtfa);
	_ctrl_print_pro_u32(cnt, hmpre);
	_ctrl_print_pro_u32(cnt, hmmin);
	printf("tnvmcap: %" PRIu64 "\n",
	       le64toh(*((uint64_t *) nvme_ctrl_tnvmcap_get(cnt))));
	printf("unvmcap: %" PRIu64 "\n",
	       le64toh(*((uint64_t *) nvme_ctrl_unvmcap_get(cnt))));
	_ctrl_print_pro_u32(cnt, rpmbs);
	_ctrl_print_pro_u16(cnt, edstt);
	_ctrl_print_pro_u8(cnt, esto);
	_ctrl_print_pro_u8(cnt, fwug);
	_ctrl_print_pro_u16(cnt, kas);
	_ctrl_print_pro_u16(cnt, hctma);
	_ctrl_print_pro_u16(cnt, mntmt);
	_ctrl_print_pro_u16(cnt, mxtmt);
	_ctrl_print_pro_u32(cnt, sanicap);
	_ctrl_print_pro_u8(cnt, sqes);
	_ctrl_print_pro_u8(cnt, cqes);
	_ctrl_print_pro_u16(cnt, maxcmd);
	_ctrl_print_pro_u32(cnt, nn);
	_ctrl_print_pro_u16(cnt, oncs);
	_ctrl_print_pro_u16(cnt, fuses);
	_ctrl_print_pro_u8(cnt, fna);
	_ctrl_print_pro_u8(cnt, vwc);
	_ctrl_print_pro_u16(cnt, awun);
	_ctrl_print_pro_u16(cnt, awupf);
	_ctrl_print_pro_u8(cnt, nvscc);
	_ctrl_print_pro_u16(cnt, acwu);
	_ctrl_print_pro_u16(cnt, sgls);
	_ctrl_print_pro_char(cnt, subnqn);
	_ctrl_print_pro_u32(cnt, ioccsz);
	_ctrl_print_pro_u32(cnt, iorcsz);
	_ctrl_print_pro_u16(cnt, icdoff);
	_ctrl_print_pro_u8(cnt, ctrattr);
	_ctrl_print_pro_u8(cnt, msdbd);

	psds = nvme_ctrl_psds_get(cnt);
	psd_count = nvme_ctrl_npss_get(cnt) + 1;
	printf("Got %" PRIu8 " PSD\n", psd_count);

	for (i = 0; i < psd_count; ++i) {
		_test_nvme_psd_pro_query(psds[i]);
	}
}

static void _test_nvme_ctrl_raw_id_data(struct nvme_ctrl *cnt)
{
	const uint8_t *raw_id_data = NULL;
	size_t i = 0;
	int j = 0;

	raw_id_data = nvme_ctrl_raw_id_data_get(cnt);

	printf("control identify raw data:\n");

	for(; i < NVME_CTRL_RAW_IDENTIFY_DATA_LEN; ++i) {
		++j;
		if (j >= 50) {
			printf("%02x\n", raw_id_data[i]);
			j = 0;
		} else {
			printf("%02x", raw_id_data[i]);
		}
	}
	printf("\n");
}

int main(void) {
	int rc = NVME_OK;
	uint32_t cnt_count = 0;
	struct nvme_ctrl **cnts = NULL;
	const char *err_msg = NULL;
	uint32_t i = 0;

	rc = nvme_ctrls_get(&cnts, &cnt_count, &err_msg);
	if (rc != NVME_OK) {
		printf("FAIL: Cannot get NVMe controller list %d: %s\n",
		       rc, err_msg);
		free((char *) err_msg);
		goto out;
	} else {
		printf("PASS: Got %" PRIu32 " NVMe controller(s)\n", cnt_count);
	}

	for (i = 0; i < cnt_count; ++i) {
		_test_nvme_ctrl_raw_id_data(cnts[i]);
		_test_nvme_ctrl_pro_query(cnts[i]);
		if (nvme_ctrl_ver_get(cnts[i]) >= NVME_SPEC_VERSION(1, 2, 0))
			printf("INFO: We are facing 1.2.0+ NVMe "
			       "implementation.\n");
	}

out:
	nvme_ctrls_free(cnts, cnt_count);
	if (rc == NVME_OK)
		exit(EXIT_SUCCESS);
	else
		exit(EXIT_FAILURE);
}
