// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libnvme.
 * Copyright (c) 2021 Code Construct Pty Ltd
 *
 * Authors: Jeremy Kerr <jk@codeconstruct.com.au>
 */
#pragma once

#include <stdint.h>

#include <nvme/types.h>

/**
 * NVME_MI_MSGTYPE_NVME - MCTP message type for NVMe-MI messages.
 *
 * This is defined by MCTP, but is referenced as part of the NVMe-MI message
 * spec. This is the MCTP NVMe message type (0x4), with the message-integrity
 * bit (0x80) set.
 */
#define NVME_MI_MSGTYPE_NVME 0x84

/* Basic MI message definitions */

/**
 * enum nvme_mi_message_type - NVMe-MI message type field.
 * @NVME_MI_MT_CONTROL: NVME-MI Control Primitive
 * @NVME_MI_MT_MI: NVMe-MI command
 * @NVME_MI_MT_ADMIN: NVMe Admin command
 * @NVME_MI_MT_PCIE: PCIe command
 * @NVME_MI_MT_AE: Asynchronous Event
 *
 * Used as byte 1 of both request and response messages (NMIMT bits of NMP
 * byte). Not to be confused with the MCTP message type in byte 0.
 */
enum nvme_mi_message_type {
	NVME_MI_MT_CONTROL = 0,
	NVME_MI_MT_MI = 1,
	NVME_MI_MT_ADMIN = 2,
	NVME_MI_MT_PCIE = 4,
	NVME_MI_MT_AE = 5,
};

/**
 * enum nvme_mi_ror: Request or response field.
 * @NVME_MI_ROR_REQ: request message
 * @NVME_MI_ROR_RSP: response message
 */
enum nvme_mi_ror {
	NVME_MI_ROR_REQ = 0,
	NVME_MI_ROR_RSP = 1,
};

/**
 * enum nvme_mi_resp_status - values for the response status field
 * @NVME_MI_RESP_SUCCESS: success
 * @NVME_MI_RESP_MPR: More Processing Required
 * @NVME_MI_RESP_INTERNAL_ERR: Internal Error
 * @NVME_MI_RESP_INVALID_OPCODE: Invalid command opcode
 * @NVME_MI_RESP_INVALID_PARAM: Invalid command parameter
 * @NVME_MI_RESP_INVALID_CMD_SIZE: Invalid command size
 * @NVME_MI_RESP_INVALID_INPUT_SIZE: Invalid command input data size
 * @NVME_MI_RESP_ACCESS_DENIED: Access Denied
 * @NVME_MI_RESP_VPD_UPDATES_EXCEEDED: More VPD updates than allowed
 * @NVME_MI_RESP_PCIE_INACCESSIBLE: PCIe functionality currently unavailable
 * @NVME_MI_RESP_MEB_SANITIZED: MEB has been cleared due to sanitize
 * @NVME_MI_RESP_ENC_SERV_FAILURE: Enclosure services process failed
 * @NVME_MI_RESP_ENC_SERV_XFER_FAILURE: Transfer with enclosure services failed
 * @NVME_MI_RESP_ENC_FAILURE: Unreoverable enclosure failure
 * @NVME_MI_RESP_ENC_XFER_REFUSED: Enclosure services transfer refused
 * @NVME_MI_RESP_ENC_FUNC_UNSUP: Unsupported enclosure services function
 * @NVME_MI_RESP_ENC_SERV_UNAVAIL: Enclosure services unavailable
 * @NVME_MI_RESP_ENC_DEGRADED: Noncritical failure detected by enc. services
 * @NVME_MI_RESP_SANITIZE_IN_PROGRESS: Command prohibited during sanitize
 */
enum nvme_mi_resp_status {
	NVME_MI_RESP_SUCCESS = 0x00,
	NVME_MI_RESP_MPR = 0x01,
	NVME_MI_RESP_INTERNAL_ERR = 0x02,
	NVME_MI_RESP_INVALID_OPCODE = 0x03,
	NVME_MI_RESP_INVALID_PARAM = 0x04,
	NVME_MI_RESP_INVALID_CMD_SIZE = 0x05,
	NVME_MI_RESP_INVALID_INPUT_SIZE = 0x06,
	NVME_MI_RESP_ACCESS_DENIED = 0x07,
	/* 0x08 - 0x1f: reserved */
	NVME_MI_RESP_VPD_UPDATES_EXCEEDED = 0x20,
	NVME_MI_RESP_PCIE_INACCESSIBLE = 0x21,
	NVME_MI_RESP_MEB_SANITIZED = 0x22,
	NVME_MI_RESP_ENC_SERV_FAILURE = 0x23,
	NVME_MI_RESP_ENC_SERV_XFER_FAILURE = 0x24,
	NVME_MI_RESP_ENC_FAILURE = 0x25,
	NVME_MI_RESP_ENC_XFER_REFUSED = 0x26,
	NVME_MI_RESP_ENC_FUNC_UNSUP = 0x27,
	NVME_MI_RESP_ENC_SERV_UNAVAIL = 0x28,
	NVME_MI_RESP_ENC_DEGRADED = 0x29,
	NVME_MI_RESP_SANITIZE_IN_PROGRESS = 0x2a,
	/* 0x2b - 0xdf: reserved */
	/* 0xe0 - 0xff: vendor specific */
};

/**
 * struct nvme_mi_msg_hdr - General MI message header.
 * @type: MCTP message type, will always be NVME_MI_MSGTYPE_NVME
 * @nmp: NVMe-MI message parameters (including MI message type)
 * @meb: Management Endpoint Buffer flag; unused for libnvme-mi implementation
 * @rsvd0: currently reserved
 *
 * Wire format shared by both request and response messages, per NVMe-MI
 * section 3.1. This is used for all message types, MI and Admin.
 */
struct nvme_mi_msg_hdr {
	__u8	type;
	__u8	nmp;
	__u8	meb;
	__u8	rsvd0;
} __attribute__((packed));

/**
 * struct nvme_mi_msg_resp - Generic response type.
 * @hdr: the general request/response message header
 * @status: response status value (see &enum nvme_mi_resp_status)
 * @rsvd0: reserved data, may be defined by specific response
 *
 * Every response will start with one of these; command-specific responses
 * will define parts of the reserved data, and may add further fields.
 */
struct nvme_mi_msg_resp {
	struct nvme_mi_msg_hdr hdr;
	__u8	status;
	__u8	rsvd0[3];
};

/**
 * enum nvme_mi_mi_opcode - Operation code for supported NVMe-MI commands.
 * @nvme_mi_mi_opcode_mi_data_read: Read NVMe-MI Data Structure
 * @nvme_mi_mi_opcode_subsys_health_status_poll: Subsystem Health Status Poll
 * @nvme_mi_mi_opcode_configuration_set: MI Configuration Set
 * @nvme_mi_mi_opcode_configuration_get: MI Configuration Get
 */
enum nvme_mi_mi_opcode {
	nvme_mi_mi_opcode_mi_data_read = 0x00,
	nvme_mi_mi_opcode_subsys_health_status_poll = 0x01,
	nvme_mi_mi_opcode_configuration_set = 0x03,
	nvme_mi_mi_opcode_configuration_get = 0x04,
};

/**
 * struct nvme_mi_mi_req_hdr - MI request message header.
 * @hdr: generic MI message header
 * @opcode: opcode (OPC) for the specific MI command
 * @rsvd0: reserved bytes
 * @cdw0: Management Request Doubleword 0 - command specific usage
 * @cdw1: Management Request Doubleword 1 - command specific usage
 *
 * Wire format for MI request message headers, defined in section 5 of NVMe-MI.
 */
struct nvme_mi_mi_req_hdr {
	struct nvme_mi_msg_hdr hdr;
	__u8	opcode;
	__u8	rsvd0[3];
	__le32	cdw0, cdw1;
};

/**
 * struct nvme_mi_mi_resp_hdr - MI response message header.
 * @hdr: generic MI message header
 * @status: generic response status from command; non-zero on failure.
 * @nmresp: NVMe Management Response: command-type-specific response data
 *
 * Wire format for MI response message header, defined in section 5 of NVMe-MI.
 */
struct nvme_mi_mi_resp_hdr {
	struct nvme_mi_msg_hdr hdr;
	__u8	status;
	__u8	nmresp[3];
};

/**
 * enum nvme_mi_dtyp - Data Structure Type field.
 * @nvme_mi_dtyp_subsys_info: NVM Subsystem Information
 * @nvme_mi_dtyp_port_info: Port information
 * @nvme_mi_dtyp_ctrl_list: Controller List
 * @nvme_mi_dtyp_ctrl_info: Controller Information
 * @nvme_mi_dtyp_opt_cmd_support: Optionally Supported Command List
 * @nvme_mi_dtyp_meb_support: Management Endpoint Buffer Command Support List
 *
 * Data Structure Type field for Read NVMe-MI Data Structure command, used to
 * indicate the particular structure to query from the endpoint.
 */
enum nvme_mi_dtyp {
	nvme_mi_dtyp_subsys_info = 0x00,
	nvme_mi_dtyp_port_info = 0x01,
	nvme_mi_dtyp_ctrl_list = 0x02,
	nvme_mi_dtyp_ctrl_info = 0x03,
	nvme_mi_dtyp_opt_cmd_support = 0x04,
	nvme_mi_dtyp_meb_support = 0x05,
};

/**
 * enum nvme_mi_config_id - NVMe-MI Configuration identifier.
 * @NVME_MI_CONFIG_SMBUS_FREQ: Current SMBus/I2C frequency
 * @NVME_MI_CONFIG_HEALTH_STATUS_CHANGE: Health Status change - used to clear
 *                                       health status bits in CCS bits of
 *                                       status poll. Only for Set ops.
 * @NVME_MI_CONFIG_MCTP_MTU: MCTP maximum transmission unit size of port
 *                           specified in dw 0
 * @NVME_MI_CONFIG_AE: Asynchronous Events configuration
 * Configuration parameters for the MI Get/Set Configuration commands.
 *
 * See &nvme_mi_mi_config_get() and &nvme_mi_config_set().
 */
enum nvme_mi_config_id {
	NVME_MI_CONFIG_SMBUS_FREQ = 0x1,
	NVME_MI_CONFIG_HEALTH_STATUS_CHANGE = 0x2,
	NVME_MI_CONFIG_MCTP_MTU = 0x3,
	NVME_MI_CONFIG_AE = 0x4,
};

/**
 * enum nvme_mi_config_smbus_freq - SMBus/I2C frequency values
 * @NVME_MI_CONFIG_SMBUS_FREQ_100kHz: 100kHz
 * @NVME_MI_CONFIG_SMBUS_FREQ_400kHz: 400kHz
 * @NVME_MI_CONFIG_SMBUS_FREQ_1MHz: 1MHz
 *
 * Values used in the SMBus Frequency device configuration. See
 * &nvme_mi_mi_config_get_smbus_freq() and &nvme_mi_mi_config_set_smbus_freq().
 */
enum nvme_mi_config_smbus_freq {
	NVME_MI_CONFIG_SMBUS_FREQ_100kHz = 0x1,
	NVME_MI_CONFIG_SMBUS_FREQ_400kHz = 0x2,
	NVME_MI_CONFIG_SMBUS_FREQ_1MHz = 0x3,
};

/* Asynchronous Event Message definitions*/

/**
 * struct nvme_mi_aem_supported_list_header - Asynchronous Event Supported List Header.
 * @numaes: Number of AE supported data structures that follow the header
 * @aeslver: AE Supported List Version
 * @aest: AE Supported list length (including this header)
 * @aeslhl: AE Supported list header length
 *
 * This header preceeds a number, (&numaes), of AE supported data structures
 */
struct nvme_mi_aem_supported_list_header {
	__u8 numaes;
	__u8 aeslver;//Should be zero
	__le16 aest;
	__u8 aeslhl; //Should be 5
} __attribute__((packed));

/**
 * struct nvme_mi_aem_supported_item - AE Supported List Item
 * @aesl: AE supported list item length
 * @aesi: AE supported info
 *
 * Following this header should be hdr.numaes entries of
 * nvme_mi_aem_supported_item structures
 */
struct nvme_mi_aem_supported_item {
	__u8 aesl;//Length of this item.  Set to 3
	__le16 aesi;
} __attribute__((packed));

/**
 * nvme_mi_aem_aesi_get_aese() - return aese from aesi field
 * @aesi: aesi field from @nvme_mi_aem_supported_item
 *
 * Returns: A bool representing the aese value
 */
bool nvme_mi_aem_aesi_get_aese(__le16 aesi);

/**
 * nvme_mi_aem_aesi_get_aesid() - return aesid from aesi field
 * @aesi: aesi field from @nvme_mi_aem_supported_item
 *
 * Returns: aesid value
 */
__u8 nvme_mi_aem_aesi_get_aesid(__le16 aesi);

/**
 * nvme_mi_aem_aesi_set_aesid() - set aesid in the aesi field
 * @item: Pointer to @nvme_mi_aem_supported_item to update the aesi field
 * @aesid: aesid value to use
 */
void nvme_mi_aem_aesi_set_aesid(struct nvme_mi_aem_supported_item *item, __u8 aesid);

/**
 * nvme_mi_aem_aesi_set_aee() - set aee in the aesi field
 * @item: Pointer to @nvme_mi_aem_supported_item to update the aesi field
 * @enabled: aee value to use
 */
void nvme_mi_aem_aesi_set_aee(struct nvme_mi_aem_supported_item *item, bool enabled);

/**
 * struct nvme_mi_aem_supported_list - AE Supported List received with GET CONFIG Asynchronous Event
 * @hdr: AE supported list header
 *
 * Following this header should be hdr.numaes entries of
 * nvme_mi_aem_supported_item structures
 */
struct nvme_mi_aem_supported_list {
	struct nvme_mi_aem_supported_list_header hdr;
} __attribute__((packed));

/**
 * struct nvme_mi_aem_enable_item - AE Enabled item entry
 * @aeel: AE Enable Length (length of this structure which is 3)
 * @aeei: AE Enable Info
 *
 */
struct nvme_mi_aem_enable_item {
	__u8 aeel;
	__le16 aeei;
} __attribute__((packed));

/**
 * nvme_mi_aem_aeei_get_aee() - return aee from aeei field
 * @aeei: aeei field from @nvme_mi_aem_enable_item
 *
 * Returns: aee value
 */
bool nvme_mi_aem_aeei_get_aee(__le16 aeei);

/**
 * nvme_mi_aem_aeei_get_aeeid() - return aeeid from aeei field
 * @aeei: aeei field from @nvme_mi_aem_enable_item
 *
 * Returns: aeeid value
 */
__u8 nvme_mi_aem_aeei_get_aeeid(__le16 aeei);

/**
 * nvme_mi_aem_aeei_set_aeeid() - set aeeid in the aeei field
 * @item: Pointer to @nvme_mi_aem_enable_item to update the aeei field
 * @aeeid: aeeid value to use
 */
void nvme_mi_aem_aeei_set_aeeid(struct nvme_mi_aem_enable_item *item, __u8 aeeid);

/**
 * nvme_mi_aem_aeei_set_aee() - set aee in the aeei field
 * @item: Pointer to @nvme_mi_aem_enable_item to update the aee field
 * @enabled: aee value to use
 */
void nvme_mi_aem_aeei_set_aee(struct nvme_mi_aem_enable_item *item, bool enabled);

/**
 * struct nvme_mi_aem_enable_list_header - AE Enable list header
 * @numaee: Number of AE enable items following the header
 * @aeelver: Version of the AE enable list (zero)
 * @aeetl: Total length of the AE enable list including header and items
 * @aeelhl: Header length of this header (5)
 */
struct nvme_mi_aem_enable_list_header {
	__u8 numaee;
	__u8 aeelver;
	__le16 aeetl;
	__u8 aeelhl;
} __attribute__((packed));

/**
 * struct nvme_mi_aem_enable_list - AE enable list sent with SET CONFIG Asyncronous Event
 * @hdr: AE enable list header
 *
 * Following this header should be hdr.numaee entries of nvme_mi_aem_enable_item structures
 */
struct nvme_mi_aem_enable_list {
	struct nvme_mi_aem_enable_list_header hdr;
} __attribute__((packed));

/**
 * struct nvme_mi_aem_occ_data - AEM Message definition.
 * @aelhlen: AE Occurrence Header Length
 * @aeosil: AE Occurrence Specific Info Length
 * @aeovsil: AE Occurrence Vendor Specific Info Length
 * @aeoui: AE Occurrence Unique ID made up of other subfields
 *
 * A single entry of ae occurrence data that comes with an nvme_aem_msg.
 * Following this structure is variable length AEOSI (occurrence specific
 * info) and variable length AEVSI (vendor specific info).  The length of
 * AEOSI is specified by aeosil and the length of AEVSI is specified by
 * AEVSI.  Neither field is mandatory and shall be omitted if their length
 * parameter is set to zero.
 */
struct nvme_mi_aem_occ_data {
	__u8 aelhlen;
	__u8 aeosil;
	__u8 aeovsil;
	struct {
		__u8 aeoi;
		__le32 aeocidi;
		__u8 aessi;
	} __attribute__((packed)) aeoui;
} __attribute__((packed));

/**
 * struct nvme_mi_aem_occ_list_hdr - AE occurrence list header
 * @numaeo: Number of AE Occurrence Data Structures
 * @aelver: AE Occurrence List Version Number
 * @aeolli: AE Occurrence List Length Info (AEOLLI)
 * @aeolhl: AE Occurrence List Header Length (shall be set to 7)
 * @aemti: AEM Transmission Info
 *
 * The header for the occurrence list.  numaeo defines how many
 * nvme_mi_aem_occ_data structures (including variable payaloads) are included.
 * Following this header is each of the numaeo occurrence data structures.
 */
struct nvme_mi_aem_occ_list_hdr {
	__u8 numaeo;
	__u8 aelver;
	__u8 aeolli[3];//24-bits
	__u8 aeolhl;
	__u8 aemti;
} __attribute__((packed));

/**
 * nvme_mi_aem_aemti_get_aemgn() - return aemgn from aemti field
 * @aemti: aemti field from @nvme_mi_aem_occ_list_hdr
 *
 * Returns: aemgn value
 */
__u8 nvme_mi_aem_aemti_get_aemgn(__u8 aemti);

/**
 * nvme_mi_aem_aeolli_get_aeoltl() - return aeoltl from aeolli field
 * @aeolli: Pointer to 3 byte aeolli field from @nvme_mi_aem_occ_list_hdr
 *
 * Returns: aeoltl value
 */
__u32 nvme_mi_aem_aeolli_get_aeoltl(__u8 *aeolli);

/**
 * nvme_mi_aem_aeolli_set_aeoltl() - set aeoltl in the aeolli field
 * @hdr:Pointer to @nvme_mi_aem_occ_list_hdr to set the aeolli field
 * @aeoltl: aeoltl value to use
 */
void nvme_mi_aem_aeolli_set_aeoltl(struct nvme_mi_aem_occ_list_hdr *hdr, __u32 aeoltl);

/**
 * struct nvme_mi_aem_msg - AEM Message definition.
 * @hdr: the general response message header
 * @occ_list_hdr: ae occurrence list header.
 *
 * Every ae message will start with one of these.  The occ_list_hder wil define
 * information about how many ae occ data entries are included.  Each entry is
 * defined by the nvme_mi_aem_occ_data structure which will follow the
 * occ_list_hdr.  Each nvme_mi_aem_occ_data structure has a fixed length header
 * but a variable length payload ude to occurrence specific and vendor specific
 * info.  For this reason, do not index the nvme_mi_ae_occ data structures by
 * array or fixed offset.
 */
struct nvme_mi_aem_msg {
	struct nvme_mi_msg_hdr hdr;
	struct nvme_mi_aem_occ_list_hdr occ_list_hdr;
} __attribute__((packed));

/* Admin command definitions */

/**
 * struct nvme_mi_admin_req_hdr - Admin command request header.
 * @hdr: Generic MI message header
 * @opcode: Admin command opcode (using enum nvme_admin_opcode)
 * @flags: Command Flags, indicating dlen and doff validity; Only defined in
 *         NVMe-MI version 1.1, no fields defined in 1.2 (where the dlen/doff
 *         are always considered valid).
 * @ctrl_id: Controller ID target of command
 * @cdw1: Submission Queue Entry doubleword 1
 * @cdw2: Submission Queue Entry doubleword 2
 * @cdw3: Submission Queue Entry doubleword 3
 * @cdw4: Submission Queue Entry doubleword 4
 * @cdw5: Submission Queue Entry doubleword 5
 * @doff: Offset of data to return from command
 * @dlen: Length of sent/returned data
 * @rsvd0: Reserved
 * @rsvd1: Reserved
 * @cdw10: Submission Queue Entry doubleword 10
 * @cdw11: Submission Queue Entry doubleword 11
 * @cdw12: Submission Queue Entry doubleword 12
 * @cdw13: Submission Queue Entry doubleword 13
 * @cdw14: Submission Queue Entry doubleword 14
 * @cdw15: Submission Queue Entry doubleword 15
 *
 * Wire format for Admin command message headers, defined in section 6 of
 * NVMe-MI.
 */
struct nvme_mi_admin_req_hdr {
	struct nvme_mi_msg_hdr hdr;
	__u8	opcode;
	__u8	flags;
	__le16	ctrl_id;
	__le32	cdw1, cdw2, cdw3, cdw4, cdw5;
	__le32	doff;
	__le32	dlen;
	__le32	rsvd0, rsvd1;
	__le32	cdw10, cdw11, cdw12, cdw13, cdw14, cdw15;
} __attribute((packed));

/**
 * struct nvme_mi_admin_resp_hdr - Admin command response header.
 * @hdr: Generic MI message header
 * @status: Generic response code, non-zero on failure
 * @rsvd0: Reserved
 * @cdw0: Completion Queue Entry doubleword 0
 * @cdw1: Completion Queue Entry doubleword 1
 * @cdw3: Completion Queue Entry doubleword 3
 *
 * This is the generic response format with the three doublewords of completion
 * queue data, plus optional response data.
 */
struct nvme_mi_admin_resp_hdr {
	struct nvme_mi_msg_hdr hdr;
	__u8	status;
	__u8	rsvd0[3];
	__le32	cdw0, cdw1, cdw3;
} __attribute__((packed));

/**
 * enum nvme_mi_control_opcode - Operation code for Control Primitives.
 * @nvme_mi_control_opcode_pause: Suspend response transmission/timeout
 * @nvme_mi_control_opcode_resume: Resume from a paused condition
 * @nvme_mi_control_opcode_abort: Re-initialize a Command Slot to the Idle state
 * @nvme_mi_control_opcode_get_state: Get the state of a Command Slot
 * @nvme_mi_control_opcode_replay: Retransmit the Response Message
 */
enum nvme_mi_control_opcode {
	nvme_mi_control_opcode_pause			= 0x00,
	nvme_mi_control_opcode_resume			= 0x01,
	nvme_mi_control_opcode_abort			= 0x02,
	nvme_mi_control_opcode_get_state	= 0x03,
	nvme_mi_control_opcode_replay			= 0x04,
};

/**
 * struct nvme_mi_control_req - The Control Primitive request.
 * @hdr: Generic MI message header
 * @opcode: Control Primitive Opcodes (using &enum nvme_mi_control_opcode)
 * @tag: flag - Opaque value passed from request to response
 * @cpsp: Control Primitive Specific Parameter
 *
 */
struct nvme_mi_control_req {
	struct nvme_mi_msg_hdr hdr;
	__u8	opcode;
	__u8	tag;
	__le16	cpsp;
} __attribute((packed));

/** struct nvme_mi_control_resp - The Control Primitive response.
 * @hdr: Generic MI message header
 * @status: Generic response code, non-zero on failure
 * @tag: flag - Opaque value passed from request to response
 * @cpsr: Control Primitive Specific Response
 *
 */
struct nvme_mi_control_resp {
	struct nvme_mi_msg_hdr hdr;
	__u8	status;
	__u8	tag;
	__le16	cpsr;
} __attribute((packed));
