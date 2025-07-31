// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libnvme.
 * Copyright (c) 2021 Code Construct Pty Ltd
 *
 * Authors: Jeremy Kerr <jk@codeconstruct.com.au>
 */

/**
 * DOC: mi.h - NVMe Management Interface library (libnvme-mi) definitions.
 *
 * These provide an abstraction for the MI messaging between controllers
 * and a host, typically over an MCTP-over-i2c link to a NVMe device, used
 * as part of the out-of-band management of a system.
 *
 * We have a few data structures define here to reflect the topology
 * of a MI connection with an NVMe subsystem:
 *
 *  - &nvme_mi_ep_t: an MI endpoint - our mechanism of communication with a
 *    NVMe subsystem. For MCTP, an endpoint will be the component that
 *    holds the MCTP address (EID), and receives our request message.
 *
 *    endpoints are defined in the NVMe-MI spec, and are specific to the MI
 *    interface.
 *
 *    Each endpoint will provide access to one or more of:
 *
 *  - &nvme_mi_ctrl_t: a NVMe controller, as defined by the NVMe base spec.
 *    The controllers are responsible for processing any NVMe standard
 *    commands (eg, the Admin command set). An endpoint (&nvme_mi_ep_t)
 *    may provide access to multiple controllers - so each of the controller-
 *    type commands will require a &nvme_mi_ctrl_t to be specified, rather than
 *    an endpoint
 *
 * A couple of conventions with the libnvme-mi API:
 *
 *  - All types and functions have the nvme_mi prefix, to distinguish from
 *    the libnvme core.
 *
 *  - We currently support either MI commands and Admin commands. The
 *    former adds a _mi prefix, the latter an _admin prefix. [This does
 *    result in the MI functions having a double _mi, like
 *    &nvme_mi_mi_subsystem_health_status_poll, which is apparently amusing
 *    for our German-speaking readers]
 *
 * For return values: unless specified in the per-function documentation,
 * all functions:
 *
 *  - return 0 on success
 *
 *  - return -1, with errno set, for errors communicating with the MI device,
 *    either in request or response data
 *
 *  - return >1 on MI status errors. This value is the 8-bit MI status
 *    value, represented by &enum nvme_mi_resp_status. Note that the
 *    status values may be vendor-defined above 0xe0.
 *
 * For the second case, we have a few conventions for errno values:
 *
 *  - EPROTO: response data violated the MI protocol, and libnvme cannot
 *    validly interpret the response
 *
 *  - EIO: Other I/O error communicating with device (eg., valid but
 *    unexpected response data)
 *
 *  - EINVAL: invalid input arguments for a command
 *
 * In line with the core NVMe API, the Admin command functions take an
 * `_args` structure to provide the command-specific parameters. However,
 * for the MI interface, the fd and timeout members of these _args structs
 * are ignored.
 *
 * References to the specifications here will either to be the NVM Express
 * Management Interface ("NVMe-MI") or the NVM Express Base specification
 * ("NVMe"). At the time of writing, the versions we're referencing here
 * are:
 *  - NVMe-MI 1.2b
 *  - NVMe 2.0b
 * with a couple of accommodations for older spec types, particularly NVMe-MI
 * 1.1, where possible.
 *
 */

#ifndef _LIBNVME_MI_MI_H
#define _LIBNVME_MI_MI_H

#include <endian.h>
#include <stdint.h>

#include <nvme/types.h>
#include <nvme/tree.h>
#include <nvme/api-types.h>

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

/**
 * nvme_mi_status_to_string() - return a string representation of the MI
 * status.
 * @status: MI response status
 *
 * Gives a string description of @status, as per section 4.1.2 of the NVMe-MI
 * spec. The status value should be of type NVME_STATUS_MI, and extracted
 * from the return value using nvme_status_get_value().
 *
 * Returned string is const, and should not be free()ed.
 *
 * Returns: A string representing the status value
 */
const char *nvme_mi_status_to_string(int status);

/**
 * nvme_mi_create_global_ctx() - Create top-level MI (ctx) handle.
 * @fp:		File descriptor for logging messages
 * @log_level:	Logging level to use
 *
 * Create the top-level (library) handle for creating subsequent endpoint
 * objects. Similar to nvme_create_global_ctx(), but we provide this to
 * allow linking without the core libnvme.
 *
 * Return: new nvme_global_ctx object, or NULL on failure.
 *
 * See &nvme_create_global_ctx.
 */
struct nvme_global_ctx *nvme_mi_create_global_ctx(FILE *fp, int log_level);

/**
 * nvme_mi_free_global_ctx() - Free nvme_global_ctx object.
 * @ctx:	&struct nvme_global_ctx object
 */
void nvme_mi_free_global_ctx(struct nvme_global_ctx *ctx);

/**
 * nvme_mi_set_probe_enabled() - enable/disable the probe for new endpoints
 * @ctx:	&struct nvme_global_ctx object
 * @enabled: whether to probe new endpoints
 *
 * Controls whether newly-created endpoints are probed for quirks on creation.
 * Defaults to enabled, which results in some initial messaging with the
 * endpoint to determine model-specific details.
 */
void nvme_mi_set_probe_enabled(struct nvme_global_ctx *ctx, bool enabled);

/* Top level management object: NVMe-MI Management Endpoint */
struct nvme_mi_ep;

/**
 * typedef nvme_mi_ep_t - MI Endpoint object.
 *
 * Represents our communication endpoint on the remote MI-capable device.
 * To be used for direct MI commands for the endpoint (through the
 * nvme_mi_mi_* functions(), or to communicate with individual controllers
 * (see &nvme_mi_init_ctrl).
 *
 * Endpoints are created through a transport-specific constructor; currently
 * only MCTP-connected endpoints are supported, through &nvme_mi_open_mctp.
 * Subsequent operations on the endpoint (and related controllers) are
 * transport-independent.
 */
typedef struct nvme_mi_ep * nvme_mi_ep_t;

/**
 * nvme_mi_set_csi - Assign a CSI to an endpoint.
 * @ep: Endpoint
 * @csi: value to use for CSI bit in NMP (0 or 1) for this endpoint
 *
 * Return: 0 if successful, -1 otherwise (some endpoints may not support)
 *
 */
int nvme_mi_set_csi(nvme_mi_ep_t ep, uint8_t csi);

/**
 * nvme_mi_first_endpoint - Start endpoint iterator
 * @ctx:	&struct nvme_global_ctx object
 *
 * Return: first MI endpoint object under this root, or NULL if no endpoints
 *         are present.
 *
 * See: &nvme_mi_next_endpoint, &nvme_mi_for_each_endpoint
 */
nvme_mi_ep_t nvme_mi_first_endpoint(struct nvme_global_ctx *ctx);

/**
 * nvme_mi_next_endpoint - Continue endpoint iterator
 * @ctx:	&struct nvme_global_ctx object
 * @e: &nvme_mi_ep_t current position of iterator
 *
 * Return: next endpoint MI endpoint object after @e under this root, or NULL
 *         if no further endpoints are present.
 *
 * See: &nvme_mi_first_endpoint, &nvme_mi_for_each_endpoint
 */
nvme_mi_ep_t nvme_mi_next_endpoint(struct nvme_global_ctx *ctx, nvme_mi_ep_t e);

/**
 * nvme_mi_for_each_endpoint - Iterator for NVMe-MI endpoints.
 * @c: &struct nvme_global_ctx object
 * @e: &nvme_mi_ep_t object, set on each iteration
 */
#define nvme_mi_for_each_endpoint(c, e)			\
	for (e = nvme_mi_first_endpoint(c); e != NULL;	\
	     e = nvme_mi_next_endpoint(c, e))

/**
 * nvme_mi_for_each_endpoint_safe - Iterator for NVMe-MI endpoints, allowing
 * deletion during traversal
 * @c: &struct nvme_global_ctx object
 * @e: &nvme_mi_ep_t object, set on each iteration
 * @_e: &nvme_mi_ep_t object used as temporary storage
 */
#define nvme_mi_for_each_endpoint_safe(c, e, _e)			      \
	for (e = nvme_mi_first_endpoint(c), _e = nvme_mi_next_endpoint(c, e); \
	     e != NULL;							      \
	     e = _e, _e = nvme_mi_next_endpoint(c, e))

/**
 * nvme_mi_ep_set_timeout - set a timeout for NVMe-MI responses
 * @ep: MI endpoint object
 * @timeout_ms: Timeout for MI responses, given in milliseconds
 */
int nvme_mi_ep_set_timeout(nvme_mi_ep_t ep, unsigned int timeout_ms);

/**
 * nvme_mi_ep_set_mprt_max - set the maximum wait time for a More Processing
 * Required response
 * @ep: MI endpoint object
 * @mprt_max_ms: Maximum more processing required wait time
 *
 * NVMe-MI endpoints may respond to a request with a "More Processing Required"
 * response; this also includes a hint on the worst-case processing time for
 * the eventual response data, with a specification-defined maximum of 65.535
 * seconds.
 *
 * This function provides a way to limit the maximum time we're prepared to
 * wait for the final response. Specify zero in @mprt_max_ms for no limit.
 * This should be larger than the command/response timeout set in
 * &nvme_mi_ep_set_timeout().
 */
void nvme_mi_ep_set_mprt_max(nvme_mi_ep_t ep, unsigned int mprt_max_ms);

/**
 * nvme_mi_ep_get_timeout - get the current timeout value for NVMe-MI responses
 * @ep: MI endpoint object
 *
 * Returns the current timeout value, in milliseconds, for this endpoint.
 */
unsigned int nvme_mi_ep_get_timeout(nvme_mi_ep_t ep);

/**
 * nvme_mi_first_transport_handle - Start transport handle iterator
 * @ep: &nvme_mi_ep_t object
 *
 * Return: first transport handle to a MI controller object under this
 *         root, or NULL if no controllers are present.
 *
 * See: &nvme_mi_next_transport_handle, &nvme_mi_for_each_transport_handle
 */
struct nvme_transport_handle *nvme_mi_first_transport_handle(nvme_mi_ep_t ep);

/**
 * nvme_mi_next_transport_handle - Continue transport handle iterator
 * @ep: &nvme_mi_ep_t object
 * @hdl: &nvme_transport_handle current position of iterator
 *
 * Return: next transport handle to MI controller object after @c under
 *         this endpoint, or NULL if no further controllers are present.
 *
 * See: &nvme_mi_first_transport_handle, &nvme_mi_for_each_transport_handle
 */
struct nvme_transport_handle *nvme_mi_next_transport_handle(nvme_mi_ep_t ep,
							    struct nvme_transport_handle *hdl);

/**
 * nvme_mi_for_each_transport_handle - Iterator for transport handle to NVMe-MI controllers.
 * @ep: &nvme_mi_ep_t containing endpoints
 * @hdl: &nvme_trasnport_handle object, set on each iteration
 *
 * Allows iteration of the list of controllers behind an endpoint. Unless the
 * controllers have already been created explicitly, you'll probably want to
 * call &nvme_mi_scan_ep() to scan for the controllers first.
 *
 * See: &nvme_mi_scan_ep()
 */
#define nvme_mi_for_each_transport_handle(ep, hdl)			\
	for (hdl = nvme_mi_first_transport_handle(ep); hdl != NULL;	\
	     hdl = nvme_mi_next_transport_handle(ep, hdl))

/**
 * nvme_mi_for_each_transport_handle_safe - Iterator for transport handle to NVMe-MI controllers, allowing
 * deletion during traversal
 * @ep: &nvme_mi_ep_t containing controllers
 * @hdl: &nvme_transport_handle object, set on each iteration
 * @_hdl: &nvme_transport_handle object used as temporary storage
 *
 * Allows iteration of the list of controllers behind an endpoint, safe against
 * deletion during iteration. Unless the controllers have already been created
 * explicitly (or you're just iterating to destroy controllers) you'll probably
 * want to call &nvme_mi_scan_ep() to scan for the controllers first.
 *
 * See: &nvme_mi_scan_ep()
 */
#define nvme_mi_for_each_transport_handle_safe(ep, hdl, _hdl)		\
	for (hdl = nvme_mi_first_transport_handle(ep),			\
	     _hdl = nvme_mi_next_transport_handle(ep, hdl);		\
	     hdl != NULL;						\
	     hdl = _hdl, _hdl = nvme_mi_next_transport_handle(ep, hdl))

/**
 * nvme_mi_open_mctp() - Create an endpoint using a MCTP connection.
 * @ctx: &struct nvme_global_ctx object
 * @netid: MCTP network ID on this system
 * @eid: MCTP endpoint ID
 *
 * Transport-specific endpoint initialization for MI-connected endpoints. Once
 * an endpoint is created, the rest of the API is transport-independent.
 *
 * Return: New endpoint object for @netid & @eid, or NULL on failure.
 *
 * See &nvme_mi_close
 */
nvme_mi_ep_t nvme_mi_open_mctp(struct nvme_global_ctx *ctx,
			       unsigned int netid, uint8_t eid);

/**
 * nvme_mi_aem_open() - Prepare an existing endpoint to receive AEMs
 * @ep: Endpoint to configure for AEMs
 *
 * Return: 0 if success, -1 otherwise
 */
int nvme_mi_aem_open(nvme_mi_ep_t ep);

/**
 * nvme_mi_close() - Close an endpoint connection and release resources,
 * including controller objects.
 *
 * @ep: Endpoint object to close
 */
void nvme_mi_close(nvme_mi_ep_t ep);

/**
 * nvme_mi_scan_mctp - look for MCTP-connected NVMe-MI endpoints.
 *
 * Description: This function queries the system MCTP daemon ("mctpd") over
 * D-Bus, to find MCTP endpoints that report support for NVMe-MI over MCTP.
 *
 * This requires libvnme-mi to be compiled with D-Bus support; if not, this
 * will return NULL.
 *
 * Return: A @struct nvme_global_ctx populated with a set of
 *         MCTP-connected endpoints, or NULL on failure
 */
struct nvme_global_ctx *nvme_mi_scan_mctp(void);

/**
 * nvme_mi_scan_ep - query an endpoint for its NVMe controllers.
 * @ep: Endpoint to scan
 * @force_rescan: close existing controllers and rescan
 *
 * This function queries an MI endpoint for the controllers available, by
 * performing an MI Read MI Data Structure command (requesting the
 * controller list). The controllers are stored in the endpoint's internal
 * list, and can be iterated with nvme_mi_for_each_ctrl.
 *
 * This will only scan the endpoint once, unless @force_rescan is set. If
 * so, all existing controller objects will be freed - the caller must not
 * hold a reference to those across this call.
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 *
 * See: &nvme_mi_for_each_ctrl
 */
int nvme_mi_scan_ep(nvme_mi_ep_t ep, bool force_rescan);

/**
 * nvme_mi_init_transport_handle() - initialise a transport handle to NVMe controller.
 * @ep: Endpoint to create under
 * @ctrl_id: ID of controller to initialize.
 *
 * Create a connection to a controller behind the endpoint specified in @ep.
 * Controller IDs may be queried from the endpoint through
 * &nvme_mi_mi_read_mi_data_ctrl_list.
 *
 * Return: New transport handle object, or NULL on failure.
 *
 * See &nvme_mi_close_transport_handle
 */
struct nvme_transport_handle *nvme_mi_init_transport_handle(nvme_mi_ep_t ep, __u16 ctrl_id);

/**
 * nvme_mi_ctrl_id() - get the ID of a controller
 * @hdl: transport handle to controller to query
 *
 * Retrieve the ID of the controller, as defined by hardware, and available
 * in the Identify (Controller List) data. This is the value passed to
 * @nvme_mi_init_transport_handle, but may have been created internally via
 * @nvme_mi_scan_ep.
 *
 * Return: the (locally-stored) ID of this controller.
 */
__u16 nvme_mi_ctrl_id(struct nvme_transport_handle *hdl);

/**
 * nvme_mi_endpoint_desc - Get a string describing a MI endpoint.
 * @ep: endpoint to describe
 *
 * Generates a human-readable string describing the endpoint, with possibly
 * transport-specific data. The string is allocated during the call, and the
 * caller is responsible for free()-ing the string.
 *
 * Return: a newly-allocated string containing the endpoint description, or
 *         NULL on failure.
 */
char *nvme_mi_endpoint_desc(nvme_mi_ep_t ep);

/* MI Command API: nvme_mi_mi_ prefix */

/**
 * nvme_mi_mi_xfer() -  Raw mi transfer interface.
 * @ep: endpoint to send the MI command to
 * @mi_req: request data
 * @req_data_size: size of request data payload
 * @mi_resp: buffer for response data
 * @resp_data_size: size of response data buffer, updated to received size
 *
 * Performs an arbitrary NVMe MI command, using the provided request data,
 * in @mi_req. The size of the request data *payload* is specified in
 * @req_data_size - this does not include the standard header length (so a
 * header-only request would have a size of 0). Note that the Management
 * Request Doublewords are considered part of the header data.
 *
 * On success, response data is stored in @mi_resp, which has an optional
 * appended payload buffer of @resp_data_size bytes. The actual payload
 * size transferred will be stored in @resp_data_size. This size does not
 * include the MI response header, so 0 represents no payload.
 *
 * See: &struct nvme_mi_mi_req_hdr and &struct nvme_mi_mi_resp_hdr.
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise..
 */
int nvme_mi_mi_xfer(nvme_mi_ep_t ep,
		       struct nvme_mi_mi_req_hdr *mi_req,
		       size_t req_data_size,
		       struct nvme_mi_mi_resp_hdr *mi_resp,
		       size_t *resp_data_size);

/**
 * nvme_mi_mi_read_mi_data_subsys() - Perform a Read MI Data Structure command,
 * retrieving subsystem data.
 * @ep: endpoint for MI communication
 * @s: subsystem information to populate
 *
 * Retrieves the Subsystem information - number of external ports and
 * NVMe version information. See &struct nvme_mi_read_nvm_ss_info.
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise..
 */
int nvme_mi_mi_read_mi_data_subsys(nvme_mi_ep_t ep,
				   struct nvme_mi_read_nvm_ss_info *s);

/**
 * nvme_mi_mi_read_mi_data_port() - Perform a Read MI Data Structure command,
 * retrieving port data.
 * @ep: endpoint for MI communication
 * @portid: id of port data to retrieve
 * @p: port information to populate
 *
 * Retrieves the Port information, for the specified port ID. The subsystem
 * data (from &nvme_mi_mi_read_mi_data_subsys) nmp field contains the allowed
 * range of port IDs.
 *
 * See &struct nvme_mi_read_port_info.
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise..
 */
int nvme_mi_mi_read_mi_data_port(nvme_mi_ep_t ep, __u8 portid,
				 struct nvme_mi_read_port_info *p);

/**
 * nvme_mi_mi_read_mi_data_ctrl_list() - Perform a Read MI Data Structure
 * command, retrieving the list of attached controllers.
 * @ep: endpoint for MI communication
 * @start_ctrlid: starting controller ID
 * @list: controller list to populate
 *
 * Retrieves the list of attached controllers, with IDs greater than or
 * equal to @start_ctrlid.
 *
 * See &struct nvme_ctrl_list.
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise..
 */
int nvme_mi_mi_read_mi_data_ctrl_list(nvme_mi_ep_t ep, __u8 start_ctrlid,
				      struct nvme_ctrl_list *list);

/**
 * nvme_mi_mi_read_mi_data_ctrl() - Perform a Read MI Data Structure command,
 * retrieving controller information
 * @ep: endpoint for MI communication
 * @ctrl_id: ID of controller to query
 * @ctrl: controller data to populate
 *
 * Retrieves the Controller Information Data Structure for the attached
 * controller with ID @ctrlid.
 *
 * See &struct nvme_mi_read_ctrl_info.
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise..
 */
int nvme_mi_mi_read_mi_data_ctrl(nvme_mi_ep_t ep, __u16 ctrl_id,
				 struct nvme_mi_read_ctrl_info *ctrl);

/**
 * nvme_mi_mi_subsystem_health_status_poll() - Read the Subsystem Health
 * Data Structure from the NVM subsystem
 * @ep: endpoint for MI communication
 * @clear: flag to clear the Composite Controller Status state
 * @nshds: subsystem health status data to populate
 *
 * Retrieves the Subsystem Health Data Structure into @nshds. If @clear is
 * set, requests that the Composite Controller Status bits are cleared after
 * the read. See NVMe-MI section 5.6 for details on the CCS bits.
 *
 * See &struct nvme_mi_nvm_ss_health_status.
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise..
 */
int nvme_mi_mi_subsystem_health_status_poll(nvme_mi_ep_t ep, bool clear,
					    struct nvme_mi_nvm_ss_health_status *nshds);

/**
 * nvme_mi_mi_config_get - query a configuration parameter
 * @ep: endpoint for MI communication
 * @dw0: management doubleword 0, containing configuration identifier, plus
 *       config-specific fields
 * @dw1: management doubleword 0, config-specific.
 * @nmresp: set to queried configuration data in NMRESP field of response.
 *
 * Performs a MI Configuration Get command, with the configuration identifier
 * as the LSB of @dw0. Other @dw0 and @dw1 data is configuration-identifier
 * specific.
 *
 * On a successful Configuration Get, the @nmresp pointer will be populated with
 * the bytes from the 3-byte NMRESP field, converted to native endian.
 *
 * See &enum nvme_mi_config_id for identifiers.
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise..
 */
int nvme_mi_mi_config_get(nvme_mi_ep_t ep, __u32 dw0, __u32 dw1,
			  __u32 *nmresp);

/**
 * nvme_mi_mi_config_set - set a configuration parameter
 * @ep: endpoint for MI communication
 * @dw0: management doubleword 0, containing configuration identifier, plus
 *       config-specific fields
 * @dw1: management doubleword 0, config-specific.
 *
 * Performs a MI Configuration Set command, with the command as the LSB of
 * @dw0. Other @dw0 and @dw1 data is configuration-identifier specific.
 *
 * See &enum nvme_mi_config_id for identifiers.
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise..
 */
int nvme_mi_mi_config_set(nvme_mi_ep_t ep, __u32 dw0, __u32 dw1);

/**
 * nvme_mi_mi_config_get_smbus_freq - get configuration: SMBus port frequency
 * @ep: endpoint for MI communication
 * @port: port ID to query
 * @freq: output value for current frequency configuration
 *
 * Performs a MI Configuration Get, to query the current SMBus frequency of
 * the port specified in @port. On success, populates @freq with the port
 * frequency
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise..
 */
static inline int nvme_mi_mi_config_get_smbus_freq(nvme_mi_ep_t ep, __u8 port,
						   enum nvme_mi_config_smbus_freq *freq)
{
	__u32 tmp, dw0;
	int rc;

	dw0 = port << 24 | NVME_MI_CONFIG_SMBUS_FREQ;

	rc = nvme_mi_mi_config_get(ep, dw0, 0, &tmp);
	if (!rc)
		*freq = (enum nvme_mi_config_smbus_freq)(tmp & 0x3);
	return rc;
}

/**
 * nvme_mi_mi_config_set_smbus_freq - set configuration: SMBus port frequency
 * @ep: endpoint for MI communication
 * @port: port ID to set
 * @freq: new frequency configuration
 *
 * Performs a MI Configuration Set, to update the current SMBus frequency of
 * the port specified in @port.
 *
 * See &struct nvme_mi_read_port_info for the maximum supported SMBus frequency
 * for the port.
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise..
 */
static inline int nvme_mi_mi_config_set_smbus_freq(nvme_mi_ep_t ep, __u8 port,
						   enum nvme_mi_config_smbus_freq freq)
{
	__u32 dw0 = port << 24 |
		(freq & 0x3) << 8 |
		NVME_MI_CONFIG_SMBUS_FREQ;

	return nvme_mi_mi_config_set(ep, dw0, 0);
}

/**
 * nvme_mi_mi_config_set_health_status_change - clear CCS bits in health status
 * @ep: endpoint for MI communication
 * @mask: bitmask to clear
 *
 * Performs a MI Configuration Set, to update the current health status poll
 * values of the Composite Controller Status bits. Bits set in @mask will
 * be cleared from future health status poll data, and may be re-triggered by
 * a future health change event.
 *
 * See &nvme_mi_mi_subsystem_health_status_poll(), &enum nvme_mi_ccs for
 * values in @mask.
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise..
 */
static inline int nvme_mi_mi_config_set_health_status_change(nvme_mi_ep_t ep,
							     __u32 mask)
{
	return nvme_mi_mi_config_set(ep, NVME_MI_CONFIG_HEALTH_STATUS_CHANGE,
				     mask);
}

/**
 * nvme_mi_mi_config_get_mctp_mtu - get configuration: MCTP MTU
 * @ep: endpoint for MI communication
 * @port: port ID to query
 * @mtu: output value for current MCTP MTU configuration
 *
 * Performs a MI Configuration Get, to query the current MCTP Maximum
 * Transmission Unit size (MTU) of the port specified in @port. On success,
 * populates @mtu with the MTU.
 *
 * The default reset value is 64, corresponding to the MCTP baseline MTU.
 *
 * Some controllers may also use this as the maximum receive unit size, and
 * may not accept MCTP messages larger than the configured MTU.
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise..
 */
static inline int nvme_mi_mi_config_get_mctp_mtu(nvme_mi_ep_t ep, __u8 port,
						 __u16 *mtu)
{
	__u32 tmp, dw0;
	int rc;

	dw0 = port << 24 | NVME_MI_CONFIG_MCTP_MTU;

	rc = nvme_mi_mi_config_get(ep, dw0, 0, &tmp);
	if (!rc)
		*mtu = tmp & 0xffff;
	return rc;
}

/**
 * nvme_mi_mi_config_set_mctp_mtu - set configuration: MCTP MTU
 * @ep: endpoint for MI communication
 * @port: port ID to set
 * @mtu: new MTU configuration
 *
 * Performs a MI Configuration Set, to update the current MCTP MTU value for
 * the port specified in @port.
 *
 * Some controllers may also use this as the maximum receive unit size, and
 * may not accept MCTP messages larger than the configured MTU. When setting
 * this value, you will likely need to change the MTU of the local MCTP
 * interface(s) to match.
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise..
 */
static inline int nvme_mi_mi_config_set_mctp_mtu(nvme_mi_ep_t ep, __u8 port,
						 __u16 mtu)
{
	__u32 dw0 = port << 24 | NVME_MI_CONFIG_MCTP_MTU;

	return nvme_mi_mi_config_set(ep, dw0, mtu);
}


/**
 * nvme_mi_mi_config_get_async_event - get configuration: Asynchronous Event
 * @ep: endpoint for MI communication
 * @aeelver: Asynchronous Event Enable List Version Number
 * @list: AE Supported list header and list contents
 * @list_num_bytes: number of bytes in the list header and contents buffer.
 * This will be populated with returned size of list and contents if successful.
 *
 * Performs a MI Configuration Get, to query the current enable Asynchronous
 * Events.  On success, populates @aeelver and the @list with current info,
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise..
 */
int nvme_mi_mi_config_get_async_event(nvme_mi_ep_t ep,
				__u8 *aeelver,
				struct nvme_mi_aem_supported_list *list,
				size_t *list_num_bytes);

/**
 * nvme_mi_mi_config_set_async_event - set configuration: Asynchronous Event
 * @ep: endpoint for MI communication
 * @envfa: Enable SR-IOV Virtual Functions AE
 * @empfa: Enable SR-IOV Physical Functions AE
 * @encfa: Enable PCI Functions AE.
 * @aemd: AEM Delay Interval (for Sync only)
 * @aerd: AEM Retry Delay (for Sync only; time in 100s of ms)
 * @enable_list: nvme_mi_aem_enable_listucture containing header and items
 * of events to be enabled or disabled.  This is taken as a delta change
 * from the current configuration.
 * @enable_list_size: Size of the enable_list including header and data.
 * Meant to catch overrun issues.
 * @occ_list: Pointer to populate with the occurrence list (header and data)
 * @occ_list_size: Total size of provided occ_list buffer.  Will be updated
 * with received size if successful
 *
 * Performs a MI Configuration Set, to ACK (sent after an AEM) or Sync (at anytime to enable
 * or disable Asynchronous Events).
 *
 * On success, populates @occ_list.  See TP6035a for details on how occ_list is populated in
 * ACK versus Sync conditions
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise..
 */
int nvme_mi_mi_config_set_async_event(nvme_mi_ep_t ep,
				bool envfa,
				bool empfa,
				bool encfa,
				__u8 aemd,
				__u8 aerd,
				struct nvme_mi_aem_enable_list *enable_list,
				size_t enable_list_size,
				struct nvme_mi_aem_occ_list_hdr *occ_list,
				size_t *occ_list_size);

static inline int nvme_mi_aem_ack(nvme_mi_ep_t ep,
				struct nvme_mi_aem_occ_list_hdr *occ_list,
				size_t *occ_list_size)
{
	//An AEM Ack is defined as a SET CONFIG AE with no AE enable items
	struct nvme_mi_aem_enable_list list = {0};

	list.hdr.aeelhl = sizeof(struct nvme_mi_aem_enable_list_header);
	list.hdr.aeelver = 0;
	list.hdr.aeetl = sizeof(struct nvme_mi_aem_enable_list_header);
	list.hdr.numaee = 0;

	return nvme_mi_mi_config_set_async_event(ep, false, false, false, 0, 0,
						&list, sizeof(list), occ_list,
						occ_list_size);
}

/* Admin channel functions */

/**
 * nvme_mi_admin_xfer() -  Raw admin transfer interface.
 * @hdl: transport handle to send the admin command to
 * @admin_req: request data
 * @req_data_size: size of request data payload
 * @admin_resp: buffer for response data
 * @resp_data_offset: offset into request data to retrieve from controller
 * @resp_data_size: size of response data buffer, updated to received size
 *
 * Performs an arbitrary NVMe Admin command, using the provided request data,
 * in @admin_req. The size of the request data *payload* is specified in
 * @req_data_size - this does not include the standard header length (so a
 * header-only request would have a size of 0).
 *
 * On success, response data is stored in @admin_resp, which has an optional
 * appended payload buffer of @resp_data_size bytes. The actual payload
 * transferred will be stored in @resp_data_size. These sizes do not include
 * the Admin request header, so 0 represents no payload.
 *
 * As with all Admin commands, we can request partial data from the Admin
 * Response payload, offset by @resp_data_offset.
 *
 * See: &struct nvme_mi_admin_req_hdr and &struct nvme_mi_admin_resp_hdr.
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise..
 */
int nvme_mi_admin_xfer(struct nvme_transport_handle *hdl,
		       struct nvme_mi_admin_req_hdr *admin_req,
		       size_t req_data_size,
		       struct nvme_mi_admin_resp_hdr *admin_resp,
		       off_t resp_data_offset,
		       size_t *resp_data_size);

/**
 * nvme_mi_admin_admin_passthru() - Submit an nvme admin passthrough command
 * @hdl:	Transport handle to send command to
 * @opcode:	The nvme admin command to send
 * @flags:	NVMe command flags (not used)
 * @rsvd:	Reserved for future use
 * @nsid:	Namespace identifier
 * @cdw2:	Command dword 2
 * @cdw3:	Command dword 3
 * @cdw10:	Command dword 10
 * @cdw11:	Command dword 11
 * @cdw12:	Command dword 12
 * @cdw13:	Command dword 13
 * @cdw14:	Command dword 14
 * @cdw15:	Command dword 15
 * @data_len:	Length of the data transferred in this command in bytes
 * @data:	Pointer to user address of the data buffer
 * @metadata_len:Length of metadata transferred in this command(not used)
 * @metadata:	Pointer to user address of the metadata buffer(not used)
 * @timeout_ms:	How long to wait for the command to complete
 * @result:	Optional field to return the result from the CQE dword 0
 *
 * Send a customized NVMe Admin command request message and get the corresponding
 * response message.
 *
 * This interface supports no data, host to controller and controller to
 * host but it doesn't support bidirectional data transfer.
 * Also this interface only supports data transfer size range [0, 4096] (bytes)
 * so the & data_len parameter must be less than 4097.
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 */
int nvme_mi_admin_admin_passthru(struct nvme_transport_handle *hdl, __u8 opcode, __u8 flags,
				 __u16 rsvd, __u32 nsid, __u32 cdw2, __u32 cdw3,
				 __u32 cdw10, __u32 cdw11, __u32 cdw12,
				 __u32 cdw13, __u32 cdw14, __u32 cdw15,
				 __u32 data_len, void *data, __u32 metadata_len,
				 void *metadata, __u32 timeout_ms, __u32 *result);

/**
 * nvme_mi_control() - Perform a Control Primitive command
 * @ep: endpoint for MI communication
 * @opcode: Control Primitive opcode (using &enum nvme_mi_control_opcode)
 * @cpsp: Control Primitive Specific Parameter
 * @result_cpsr: Optional field to return the result from the CPSR field
 *
 * Perform a Control Primitive command, using the opcode specified in @opcode
 * Stores the result from the CPSR field in @result_cpsr if set.
 *
 * Return: 0 on success, non-zero on failure
 *
 * See: &enum nvme_mi_control_opcode
 *
 */
int nvme_mi_control(nvme_mi_ep_t ep, __u8 opcode,
		    __u16 cpsp, __u16 *result_cpsr);

/**
 * enum nvme_mi_aem_handler_next_action - Next action for the AEM state machine handler
 * @NVME_MI_AEM_HNA_ACK: Send an ack for the AEM
 * @NVME_MI_AEM_HNA_NONE: No further action
 *
 * Used as return value for the AE callback generated when calling nvme_mi_aem_process
 */
enum nvme_mi_aem_handler_next_action {
	NVME_MI_AEM_HNA_ACK,
	NVME_MI_AEM_HNA_NONE,
};

/**
 * struct nvme_mi_event - AE event information structure
 * @aeoi: Event identifier
 * @aessi: Event occurrence scope info
 * @aeocidi: Event occurrence scope ID info
 * @spec_info: Specific info buffer
 * @spec_info_len: Length of specific info buffer
 * @vend_spec_info: Vendor specific info buffer
 * @vend_spec_info_len: Length of vendor specific info buffer
 *
 * Application callbacks for nvme_mi_aem_process will be able to call
 * nvme_mi_aem_get_next_event which will return a pointer to such an identifier
 * for the next event the application should parse
 */
struct nvme_mi_event {
	uint8_t aeoi;
	uint8_t aessi;
	uint32_t aeocidi;
	void *spec_info;
	size_t spec_info_len;
	void *vend_spec_info;
	size_t vend_spec_info_len;
};

/**
 * nvme_mi_aem_get_next_event() - Get details for the next event to parse
 * @ep: The endpoint with the event
 *
 * When inside a aem_handler, call this and a returned struct pointer
 * will provide details of event information.  Will return NULL when end of parsing is occurred.
 * spec_info and vend_spec_info must be copied to persist as they will not be valid
 * after the handler_next_action has returned.
 *
 * Return: Pointer no next nvme_mi_event or NULL if this is the last one
 */
struct nvme_mi_event *nvme_mi_aem_get_next_event(nvme_mi_ep_t ep);

struct nvme_mi_aem_enabled_map {
	bool enabled[256];
};

/**
 * struct nvme_mi_aem_config - Provided for nvme_mi_aem_enable
 * @aem_handler: Callback function for application processing of events
 * @enabled_map: Map indicating which AE should be enabled on the endpoint
 * @envfa: Enable SR-IOV virtual functions AE
 * @empfa: Enable SR-IOV physical functions AE
 * @encfa: Enable PCIe functions AE
 * @aemd: AEM Delay (time in seconds from when event happens to AEM being batched and sent)
 * @aerd: AEM Retry Delay (time in 100s of ms between AEM retries from the endpoint)
 *
 * Application callbacks for nvme_mi_aem_process will be able to call
 * nvme_mi_aem_get_next_event which will return a pointer to such an identifier
 * for the next event the application should parse
 */
struct nvme_mi_aem_config {
	/*
	 * This is called from inside nvme_mi_process when a payload has been validated and
	 * can be parsed.  The application may call nvme_mi_aem_get_next_event from inside
	 *  the callback to parse event data.
	 */
	enum nvme_mi_aem_handler_next_action (*aem_handler)(
							nvme_mi_ep_t ep,
							size_t num_events,
							void *userdata);

	struct nvme_mi_aem_enabled_map enabled_map;

	bool envfa;
	bool empfa;
	bool encfa;
	__u8 aemd;
	__u8 aerd;
};

/**
 * nvme_mi_aem_get_fd() - Returns the pollable fd for AEM data available
 * @ep: The endpoint being monitored for asynchronous data
 *
 * This populated structure can be polled from the application to understand if
 * a call to nvme_mi_aem_process() is required (when a poll returns > 0).
 *
 * Return: The fd value or -1 if error
 */
int nvme_mi_aem_get_fd(nvme_mi_ep_t ep);

/**
 * nvme_mi_aem_enable() - Enable AE on the provided endpoint
 * @ep: Endpoint to enable AEs
 * @config: AE configuraiton including which events are enabled and the callback function
 * @userdata: Application provided context pointer for callback function
 *
 * This function is called to enable AE on the endpoint.  Endpoint will provide initial state
 * (if any) of enabled AEs and application can parse those via the aem_handler fn pointer in
 * callbacks.  Thes can be obtained in the callback by calling nvme_mi_aem_get_next_event().
 *
 * Application should poll the fd that can be obtained from nvme_mi_aem_get_fd and then call
 * nvme_mi_aem_process() when poll() indicates data available.
 *
 * A call to nvme_mi_aem_process() will grab AEM data and call the aem_handler fn pointer.
 * At this point the application can call nvme_mi_aem_get_next_event() to get information for
 * each triggered event.
 *
 * Return: 0 is a success, nonzero is an error and errno may be read for further details
 */
int nvme_mi_aem_enable(nvme_mi_ep_t ep,
	struct nvme_mi_aem_config *config,
	void *userdata);


/**
 * nvme_mi_aem_get_enabled() - Return information on which AEs are enabled
 * @ep: Endpoint to check enabled status
 * @enabled: nvme_mi_aem_enabled_map indexed by AE event ID of enabled state
 *
 * Return: 0 is a success, nonzero is an error and errno may be read for further details
 */
int nvme_mi_aem_get_enabled(nvme_mi_ep_t ep,
	struct nvme_mi_aem_enabled_map *enabled);

/**
 * nvme_mi_aem_disable() - Disable AE on the provided endpoint
 * @ep: Endpoint to disable AEs
 *
 * Return: 0 is a success, nonzero is an error and errno may be read for further details
 */
int nvme_mi_aem_disable(nvme_mi_ep_t ep);

/**
 * nvme_mi_aem_process() - Process AEM on the provided endpoint
 * @ep: Endpoint to process
 * @userdata: Application provided context pointer for callback function
 *
 * Call this if poll() indicates data is available on the fd provided by nvme_mi_aem_get_fd()
 *
 * This will call the fn pointer, aem_handler, provided with nvme_mi_aem_config and the
 * application can call nvme_mi_aem_get_next_event() from within this callback to get
 * aem event data.  The callback function should return NVME_MI_AEM_HNA_ACK for normal operation.
 *
 * Return: 0 is a success, nonzero is an error and errno may be read for further details
 */
int nvme_mi_aem_process(nvme_mi_ep_t ep, void *userdata);

#endif /* _LIBNVME_MI_MI_H */
