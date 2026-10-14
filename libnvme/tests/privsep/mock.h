/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

/* LIBNVME_TEST_FD */
#define MOCK_FD		0xfd
#define MOCK_OPC_ERROR	0xc2
#define MOCK_STATUS	0x4002
#define MOCK_OPC_EXIT	0xc6
#define MOCK_NSID	7
#define MOCK_BLOCK_SIZE	4096
#define MOCK_SED_PASSWORD	"password"
#define MOCK_TCG_NOT_AUTHORIZED	0x01
#define MOCK_TCG_INVALID_PARAM	0x0c
#define MOCK_FABRICS_OPTIONS	"instance=-1,cntlid=-1,transport=%s," \
				"traddr=%s,trsvcid=%s,nqn=%s,hostnqn=%s," \
				"hostid=%pU,host_traddr=%s,host_iface=%s," \
				"ctrl_loss_tmo=%d\n"
#define MOCK_INSTANCE		5
#define MOCK_FABRICS_RESPONSE	"instance=5,cntlid=1\n"
#define MOCK_NQN		"nqn.2026-10.io.example:mock"
#define MOCK_NQN_REFUSED	"nqn.2026-10.io.example:refused"
