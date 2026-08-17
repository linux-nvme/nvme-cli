// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libnvme.
 * Copyright (c) 2020 Western Digital Corporation or its affiliates.
 *
 * Authors: Keith Busch <keith.busch@wdc.com>
 *          Chaitanya Kulkarni <chaitanya.kulkarni@wdc.com>
 *          Daniel Wagner <dwagner@suse.de>
 *
 * NVMe over Fabrics type definitions
 */
#pragma once

#include <stdbool.h>
#include <stdint.h>

#include <nvme/types.h>
#include <nvme/nvme-types-base.h>

/**
 * DOC: nvme-types-fabrics.h
 *
 * NVMe over Fabrics type definitions
 *
 * Based on:
 * - NVM Express over RDMA Transport Specification, Revision 1.2,
 *   August 1, 2025 (Ratified)
 * - NVM Express over TCP Transport Specification, Revision 1.2,
 *   August 1, 2025 (Ratified)
 * - NVM Express Base Specification (Fabrics command set sections)
 *
 * This file is organized by functional area:
 * - Discovery: Discovery log entries and log pages
 * - Transport Configuration: Transport types, addressing, requirements
 * - RDMA-Specific: RDMA queue pairs, providers, connection management
 * - TCP-Specific: TCP security types
 * - Discovery Information Model (DIM): Extended discovery attributes
 * - Connection: Connect command data structures
 * - Authentication: KX-HMAC-CHAP in-band authentication protocol
 */

#define NVME_DISC_SUBSYS_NAME	"nqn.2014-08.org.nvmexpress.discovery"
#define NVME_RDMA_IP_PORT	4420
#define NVME_DISC_IP_PORT	8009

/* However the max length of a qualified name is another size */
#define NVMF_NQN_SIZE		223
#define NVMF_TRSVCID_SIZE	32

#define NVMF_DISC_EFLAGS_BOTH (NVMF_DISC_EFLAGS_DUPRETINFO | NVMF_DISC_EFLAGS_EPCSD)
#define NVMF_ENAME_LEN	256
#define NVMF_EVER_LEN	64

/**
 * enum nvme_subsys_type - Type of the NVM subsystem.
 * @NVME_NQN_DISC: Discovery type target subsystem. Describes a referral to another
 *		   Discovery Service composed of Discovery controllers that provide
 *		   additional discovery records. Multiple Referral entries may
 *		   be reported for each Discovery Service (if that Discovery Service
 *		   has multiple NVM subsystem ports or supports multiple protocols).
 * @NVME_NQN_NVME: NVME type target subsystem. Describes an NVM subsystem whose
 *		   controllers may have attached namespaces (an NVM subsystem
 *		   that is not composed of Discovery controllers). Multiple NVM
 *		   Subsystem entries may be reported for each NVM subsystem if
 *		   that NVM subsystem has multiple NVM subsystem ports.
 * @NVME_NQN_CURR: Current Discovery type target subsystem. Describes this Discovery
 *		   subsystem (the Discovery Service that contains the controller
 *		   processing the Get Log Page command). Multiple Current Discovery
 *		   Subsystem entries may be reported for this Discovery subsystem
 *		   if the current Discovery subsystem has multiple NVM subsystem
 *		   ports.
 */
enum nvme_subsys_type {
	NVME_NQN_DISC	= 1,
	NVME_NQN_NVME	= 2,
	NVME_NQN_CURR	= 3,
};

/**
 * enum nvmf_disc_eflags - Discovery Log Page entry flags.
 * @NVMF_DISC_EFLAGS_NONE:	 Indicates that none of the DUPRETINFO or EPCSD
 *				 features are supported.
 * @NVMF_DISC_EFLAGS_DUPRETINFO: Duplicate Returned Information (DUPRETINFO):
 *				 Indicates that using the content of this entry
 *				 to access this Discovery Service returns the same
 *				 information that is returned by using the content
 *				 of other entries in this log page that also have
 *				 this flag set.
 * @NVMF_DISC_EFLAGS_EPCSD:	 Explicit Persistent Connection Support for Discovery (EPCSD):
 *				 Indicates that Explicit Persistent Connections are
 *      			 supported for the Discovery controller.
 * @NVMF_DISC_EFLAGS_NCC:	 No CDC Connectivity (NCC): If set to
 *      			 '1', then no DDC that describes this entry
 *      			 is currently connected to the CDC. If
 *      			 cleared to '0', then at least one DDC that
 *      			 describes this entry is currently
 *      			 connected to the CDC. If the Discovery
 *      			 controller returning this log page is not
 *      			 a CDC, then this bit shall be cleared to
 *      			 '0' and should be ignored by the host.
 */
enum nvmf_disc_eflags {
	NVMF_DISC_EFLAGS_NONE		= 0,
	NVMF_DISC_EFLAGS_DUPRETINFO	= 1 << 0,
	NVMF_DISC_EFLAGS_EPCSD		= 1 << 1,
	NVMF_DISC_EFLAGS_NCC		= 1 << 2,
};

/**
 * union nvmf_tsas - Transport Specific Address Subtype
 * @common:  Common transport specific attributes
 * @rdma:    RDMA transport specific attribute settings
 * @qptype:  RDMA QP Service Type (RDMA_QPTYPE): Specifies the type of RDMA
 *	     Queue Pair. See &enum nvmf_rdma_qptype.
 * @prtype:  RDMA Provider Type (RDMA_PRTYPE): Specifies the type of RDMA
 *	     provider. See &enum nvmf_rdma_prtype.
 * @cms:     RDMA Connection Management Service (RDMA_CMS): Specifies the type
 *	     of RDMA IP Connection Management Service. See &enum nvmf_rdma_cms.
 * @pkey:    RDMA_PKEY: Specifies the Partition Key when AF_IB (InfiniBand)
 *	     address family type is used.
 * @tcp:     TCP transport specific attribute settings
 * @sectype: Security Type (SECTYPE): Specifies the type of security used by the
 *	     NVMe/TCP port. If SECTYPE is a value of 0h (No Security), then the
 *	     host shall set up a normal TCP connection. See &enum nvmf_tcp_sectype.
 */
union nvmf_tsas {
	char		common[NVMF_TSAS_SIZE];
	struct rdma {
		__u8	qptype;
		__u8	prtype;
		__u8	cms;
		__u8	rsvd3[5];
		__le16	pkey;
		__u8	rsvd10[246];
	} rdma;
	struct tcp {
		__u8	sectype;
	} tcp;
};

/**
 * struct nvmf_disc_log_entry - Discovery Log Page Entry
 * @trtype:	Transport Type (see &enum nvmf_trtype)
 * @adrfam:	Address Family (see &enum nvmf_addr_family)
 * @subtype:	Subsystem Type
 * @treq:	Transport Requirements (see &enum nvmf_treq)
 * @portid:	Port ID
 * @cntlid:	Controller ID
 * @asqsz:	Admin Submission Queue Size
 * @eflags:	Entry Flags (see &enum nvmf_disc_eflags)
 * @rsvd12:	Reserved
 * @trsvcid:	Transport Service Identifier
 * @rsvd64:	Reserved
 * @subnqn:	NVM Subsystem Qualified Name
 * @traddr:	Transport Address
 * @tsas:	Transport Specific Address Subtype (see &union nvmf_tsas)
 */
struct nvmf_disc_log_entry {
	__u8		trtype;
	__u8		adrfam;
	__u8		subtype;
	__u8		treq;
	__le16		portid;
	__le16		cntlid;
	__le16		asqsz;
	__le16		eflags;
	__u8		rsvd12[20];
	char		trsvcid[NVMF_TRSVCID_SIZE];
	__u8		rsvd64[192];
	char		subnqn[NVME_NQN_LENGTH];
	char		traddr[NVMF_TRADDR_SIZE];
	union nvmf_tsas	tsas;
};

/**
 * enum nvmf_trtype - Transport Type codes for Discovery Log Page entry TRTYPE field
 * @NVMF_TRTYPE_UNSPECIFIED:	Not indicated
 * @NVMF_TRTYPE_RDMA:		RDMA
 * @NVMF_TRTYPE_FC:		Fibre Channel
 * @NVMF_TRTYPE_TCP:		TCP
 * @NVMF_TRTYPE_LOOP:		Intra-host Transport (i.e., loopback), reserved
 *				for host usage.
 * @NVMF_TRTYPE_MAX:		Maximum value for &enum nvmf_trtype
 */
enum nvmf_trtype {
	NVMF_TRTYPE_UNSPECIFIED	= 0,
	NVMF_TRTYPE_RDMA	= 1,
	NVMF_TRTYPE_FC		= 2,
	NVMF_TRTYPE_TCP		= 3,
	NVMF_TRTYPE_LOOP	= 254,
	NVMF_TRTYPE_MAX,
};

/**
 * enum nvmf_addr_family - Address Family codes for Discovery Log Page entry ADRFAM field
 * @NVMF_ADDR_FAMILY_PCI:	PCIe
 * @NVMF_ADDR_FAMILY_IP4:	AF_INET: IPv4 address family.
 * @NVMF_ADDR_FAMILY_IP6:	AF_INET6: IPv6 address family.
 * @NVMF_ADDR_FAMILY_IB:	AF_IB: InfiniBand address family.
 * @NVMF_ADDR_FAMILY_FC:	Fibre Channel address family.
 * @NVMF_ADDR_FAMILY_LOOP:	Intra-host Transport (i.e., loopback), reserved
 *				for host usage.
 */
enum nvmf_addr_family {
	NVMF_ADDR_FAMILY_PCI	= 0,
	NVMF_ADDR_FAMILY_IP4	= 1,
	NVMF_ADDR_FAMILY_IP6	= 2,
	NVMF_ADDR_FAMILY_IB	= 3,
	NVMF_ADDR_FAMILY_FC	= 4,
	NVMF_ADDR_FAMILY_LOOP	= 254,
};

/**
 * enum nvmf_treq - Transport Requirements codes for Discovery Log Page entry TREQ field
 * @NVMF_TREQ_SECTYPE_SHIFT:	Shift amount to get Secure Channel requirement
 * @NVMF_TREQ_SECTYPE_MASK:	Mask to get Secure Channel requirement
 * @NVMF_TREQ_NOT_SPECIFIED:	Not specified
 * @NVMF_TREQ_REQUIRED:		Required
 * @NVMF_TREQ_NOT_REQUIRED:	Not Required
 * @NVMF_TREQ_DISABLE_SQFLOW_SHIFT: Shift amount to get SQ flow control disable
 * @NVMF_TREQ_DISABLE_SQFLOW_MASK:  Mask to get SQ flow control disable
 * @NVMF_TREQ_DISABLE_SQFLOW:	SQ flow control disable supported
 */
enum nvmf_treq {
	NVMF_TREQ_SECTYPE_SHIFT		= 0,
	NVMF_TREQ_SECTYPE_MASK		= 0x3,
	NVMF_TREQ_NOT_SPECIFIED		= 0,
	NVMF_TREQ_REQUIRED		= 1,
	NVMF_TREQ_NOT_REQUIRED		= 2,
	NVMF_TREQ_DISABLE_SQFLOW_SHIFT	= 2,
	NVMF_TREQ_DISABLE_SQFLOW_MASK	= 0x1,
	NVMF_TREQ_DISABLE_SQFLOW	= 1 << 2,
};

#define NVMF_TREQ_SECTYPE(treq)		NVMF_GET(treq, TREQ_SECTYPE)
#define NVMF_TREQ_DISABLE_SQFLOW_BIT(treq) NVMF_GET(treq, TREQ_DISABLE_SQFLOW)

/**
 * enum nvmf_rdma_qptype - RDMA QP Service Type codes for Discovery Log Page
 *	   entry TSAS RDMA_QPTYPE field
 * @NVMF_RDMA_QPTYPE_CONNECTED:	Reliable Connected
 * @NVMF_RDMA_QPTYPE_DATAGRAM:	Reliable Datagram
 */
enum nvmf_rdma_qptype {
	NVMF_RDMA_QPTYPE_CONNECTED	= 1,
	NVMF_RDMA_QPTYPE_DATAGRAM	= 2,
};

/**
 * enum nvmf_rdma_prtype - RDMA Provider Type codes for Discovery Log Page
 *	  entry TSAS RDMA_PRTYPE field
 * @NVMF_RDMA_PRTYPE_NOT_SPECIFIED: No Provider Specified
 * @NVMF_RDMA_PRTYPE_IB:	    InfiniBand
 * @NVMF_RDMA_PRTYPE_ROCE:	    InfiniBand RoCE
 * @NVMF_RDMA_PRTYPE_ROCEV2:	    InfiniBand RoCEV2
 * @NVMF_RDMA_PRTYPE_IWARP:	    iWARP
 */
enum nvmf_rdma_prtype {
	NVMF_RDMA_PRTYPE_NOT_SPECIFIED	= 1,
	NVMF_RDMA_PRTYPE_IB		= 2,
	NVMF_RDMA_PRTYPE_ROCE		= 3,
	NVMF_RDMA_PRTYPE_ROCEV2		= 4,
	NVMF_RDMA_PRTYPE_IWARP		= 5,
};

/**
 * enum nvmf_rdma_cms - RDMA Connection Management Service Type codes for
 *	  Discovery Log Page entry TSAS RDMA_CMS field
 * @NVMF_RDMA_CMS_RDMA_CM: Sockets based endpoint addressing
 *
 */
enum nvmf_rdma_cms {
	NVMF_RDMA_CMS_RDMA_CM	= 1,
};

/**
 * enum nvmf_tcp_sectype - Transport Specific Address Subtype Definition for
 *	  NVMe/TCP Transport
 * @NVMF_TCP_SECTYPE_NONE:  No Security
 * @NVMF_TCP_SECTYPE_TLS:   Transport Layer Security version 1.2
 * @NVMF_TCP_SECTYPE_TLS13: Transport Layer Security version 1.3 or a subsequent
 *			    version. The TLS protocol negotiates the version and
 *			    cipher suite for each TCP connection.
 */
enum nvmf_tcp_sectype {
	NVMF_TCP_SECTYPE_NONE	= 0,
	NVMF_TCP_SECTYPE_TLS	= 1,
	NVMF_TCP_SECTYPE_TLS13	= 2,
};

/**
 * enum nvmf_log_discovery_lid_support - Discovery log specific support
 * @NVMF_LOG_DISC_LID_NONE:	None
 * @NVMF_LOG_DISC_LID_EXTDLPES:	Extended Discovery Log Page Entries Supported
 * @NVMF_LOG_DISC_LID_PLEOS:	Port Local Entries Only Supported
 * @NVMF_LOG_DISC_LID_ALLSUBES:	All NVM Subsystem Entries Supported
 */
enum nvmf_log_discovery_lid_support {
	NVMF_LOG_DISC_LID_NONE		= 0,
	NVMF_LOG_DISC_LID_EXTDLPES	= (1 << 0),
	NVMF_LOG_DISC_LID_PLEOS		= (1 << 1),
	NVMF_LOG_DISC_LID_ALLSUBES	= (1 << 2),
};

/**
 * enum nvmf_log_discovery_lsp - Discovery log specific field
 * @NVMF_LOG_DISC_LSP_NONE:	None
 * @NVMF_LOG_DISC_LSP_EXTDLPE:	Extended Discovery Log Page Entries
 * @NVMF_LOG_DISC_LSP_PLEO:	Port Local Entries Only
 * @NVMF_LOG_DISC_LSP_ALLSUBE:	All NVM Subsystem Entries
 */
enum nvmf_log_discovery_lsp {
	NVMF_LOG_DISC_LSP_NONE		= 0,
	NVMF_LOG_DISC_LSP_EXTDLPE	= (1 << 0),
	NVMF_LOG_DISC_LSP_PLEO		= (1 << 1),
	NVMF_LOG_DISC_LSP_ALLSUBE	= (1 << 2),
};

/**
 * struct nvmf_discovery_log - Discovery Log Page (Log Identifier 70h)
 * @genctr:  Generation Counter (GENCTR): Indicates the version of the discovery
 *	     information, starting at a value of 0h. For each change in the
 *	     Discovery Log Page, this counter is incremented by one. If the value
 *	     of this field is FFFFFFFF_FFFFFFFFh, then the field shall be cleared
 *	     to 0h when incremented (i.e., rolls over to 0h).
 * @numrec:  Number of Records (NUMREC): Indicates the number of records
 *	     contained in the log.
 * @recfmt:  Record Format (RECFMT): Specifies the format of the Discovery Log
 *	     Page. If a new format is defined, this value is incremented by one.
 *	     The format of the record specified in this definition shall be 0h.
 * @rsvd14:  Reserved
 * @entries: Discovery Log Page Entries - see &struct nvmf_disc_log_entry.
 */
struct nvmf_discovery_log {
	__le64		genctr;
	__le64		numrec;
	__le16		recfmt;
	__u8		rsvd14[1006];
	struct nvmf_disc_log_entry entries[];
};

/**
 * enum nvmf_dim_tas - Discovery Information Management Task
 * @NVMF_DIM_TAS_REGISTER:   Register
 * @NVMF_DIM_TAS_DEREGISTER: Deregister
 * @NVMF_DIM_TAS_UPDATE:     Update
 */
enum nvmf_dim_tas {
	NVMF_DIM_TAS_REGISTER	= 0x00,
	NVMF_DIM_TAS_DEREGISTER	= 0x01,
	NVMF_DIM_TAS_UPDATE	= 0x02,
};

/**
 * enum nvmf_dim_entfmt - Discovery Information Management Entry Format
 * @NVMF_DIM_ENTFMT_BASIC:    Basic discovery information entry
 * @NVMF_DIM_ENTFMT_EXTENDED: Extended discovery information entry
 */
enum nvmf_dim_entfmt {
	NVMF_DIM_ENTFMT_BASIC		= 0x01,
	NVMF_DIM_ENTFMT_EXTENDED	= 0x02,
};

/**
 * enum nvmf_dim_etype -Discovery Information Management Entity Type
 * @NVMF_DIM_ETYPE_HOST: Host
 * @NVMF_DIM_ETYPE_DDC:	 Direct Discovery controller
 * @NVMF_DIM_ETYPE_CDC:	 Centralized Discovery controller
 */
enum nvmf_dim_etype {
	NVMF_DIM_ETYPE_HOST	= 0x01,
	NVMF_DIM_ETYPE_DDC	= 0x02,
	NVMF_DIM_ETYPE_CDC	= 0x03,
};

/**
 * enum nvmf_exattype - Extended Attribute Type
 * @NVMF_EXATTYPE_HOSTID:  Host Identifier
 * @NVMF_EXATTYPE_SYMNAME: Symblic Name
 */
enum nvmf_exattype {
	NVMF_EXATTYPE_HOSTID	= 0x01,
	NVMF_EXATTYPE_SYMNAME	= 0x02,
};

/**
 * struct nvmf_ext_attr - Extended Attribute (EXAT)
 * @exattype: Extended Attribute Type (EXATTYPE) - see @enum nvmf_exattype
 * @exatlen:  Extended Attribute Length (EXATLEN)
 * @exatval:  Extended Attribute Value (EXATVAL) - size allocated for array
 *	      must be a multiple of 4 bytes
 */
struct nvmf_ext_attr {
	__le16	exattype;
	__le16	exatlen;
	__u8	exatval[];
};

/**
 * struct nvmf_ext_die - Extended Discovery Information Entry (DIE)
 * @trtype:   Transport Type (&enum nvmf_trtype)
 * @adrfam:   Address Family (&enum nvmf_addr_family)
 * @subtype:  Subsystem Type (&enum nvme_subsys_type)
 * @treq:     Transport Requirements (&enum nvmf_treq)
 * @portid:   Port ID
 * @cntlid:   Controller ID
 * @asqsz:    Admin Max SQ Size
 * @rsvd10:   Reserved
 * @trsvcid:  Transport Service Identifier
 * @resv64:   Reserved
 * @nqn:      NVM Qualified Name
 * @traddr:   Transport Address
 * @tsas:     Transport Specific Address Subtype (&union nvmf_tsas)
 * @tel:      Total Entry Length
 * @numexat:  Number of Extended Attributes
 * @resv1030: Reserved
 * @exat:     Extended Attributes 0 (&struct nvmf_ext_attr)
 */
struct nvmf_ext_die {
	__u8			trtype;
	__u8			adrfam;
	__u8			subtype;
	__u8			treq;
	__le16			portid;
	__le16			cntlid;
	__le16			asqsz;
	__u8			rsvd10[22];
	char			trsvcid[NVMF_TRSVCID_SIZE];
	__u8			resv64[192];
	char			nqn[NVME_NQN_LENGTH];
	char			traddr[NVMF_TRADDR_SIZE];
	union nvmf_tsas		tsas;
	__le32			tel;
	__le16			numexat;
	__u8			resv1030[2];
	struct nvmf_ext_attr	exat[];
};

/**
 * union nvmf_die - Discovery Information Entry (DIE)
 * @basic:    Basic format (&struct nvmf_disc_log_entry)
 * @extended: Extended format (&struct nvmf_ext_die)
 *
 * Depending on the ENTFMT specified in the DIM, DIEs can be entered
 * with the Basic or Extended formats. For Basic format, each entry
 * has a fixed length. Therefore, the "basic" field defined below can
 * be accessed as a C array. For the Extended format, however, each
 * entry is of variable length (TEL). Therefore, the "extended" field
 * defined below cannot be accessed as a C array. Instead, the
 * "extended" field is akin to a linked-list, where one can "walk"
 * through the list. To move to the next entry, one simply adds the
 * current entry's length (TEL) to the "walk" pointer. The number of
 * entries in the list is specified by NUMENT.	Although extended
 * entries are of a variable lengths (TEL), TEL is always a multiple of
 * 4 bytes.
 */
union nvmf_die {
	struct nvmf_disc_log_entry	basic[0];
	struct nvmf_ext_die		extended;
};

/**
 * struct nvmf_dim_data - Discovery Information Management (DIM) - Data
 * @tdl:     Total Data Length
 * @rsvd4:   Reserved
 * @nument:  Number of entries
 * @entfmt:  Entry Format (&enum nvmf_dim_entfmt)
 * @etype:   Entity Type (&enum nvmf_dim_etype)
 * @portlcl: Port Local
 * @rsvd21:  Reserved
 * @ektype:  Entry Key Type
 * @eid:     Entity Identifier (e.g. Host NQN)
 * @ename:   Entity Name (e.g. hostname)
 * @ever:    Entity Version (e.g. OS Name/Version)
 * @rsvd600: Reserved
 * @die:     Discovery Information Entry (see @nument above)
 */
struct nvmf_dim_data {
	__le32		tdl;
	__u8		rsvd4[4];
	__le64		nument;
	__le16		entfmt;
	__le16		etype;
	__u8		portlcl;
	__u8		rsvd21;
	__le16		ektype;
	char		eid[NVME_NQN_LENGTH];
	char		ename[NVMF_ENAME_LEN];
	char		ever[NVMF_EVER_LEN];
	__u8		rsvd600[424];
	union nvmf_die	die[];
};

/**
 * struct nvmf_connect_data - Data payload for the 'connect' command
 * @hostid:	Host ID of the connecting host
 * @cntlid:	Requested controller ID
 * @rsvd4:	Reserved
 * @subsysnqn:	Subsystem NQN to connect to
 * @hostnqn:	Host NQN of the connecting host
 * @rsvd5:	Reserved
 */
struct nvmf_connect_data {
	__u8		hostid[16];
	__le16		cntlid;
	char		rsvd4[238];
	char		subsysnqn[NVME_NQN_LENGTH];
	char		hostnqn[NVME_NQN_LENGTH];
	char		rsvd5[256];
};

/**
 * struct nvme_host_ext_discovery_log - Host Extended Discovery Log
 * @trtype:	Transport Type
 * @adrfam:	Address Family
 * @rsvd2:	Reserved
 * @eflags:	Entry Flags
 * @rsvd12:	Reserved
 * @hostnqn:	Host NVMe Qualified Name
 * @traddr:	Transport Address
 * @tsas:	Transport Specific Address Subtype
 * @tel:	Total Entry Length
 * @numexat:	Number of Extended Attributes
 * @rsvd1030:	Reserved
 * @exat:	Extended Attributes List
 */
struct nvme_host_ext_discovery_log {
	__u8			trtype;
	__u8			adrfam;
	__u8			rsvd2[8];
	__le16			eflags;
	__u8			rsvd12[244];
	char			hostnqn[NVME_NQN_LENGTH];
	char			traddr[NVMF_TRADDR_SIZE];
	union nvmf_tsas		tsas;
	__le32			tel;
	__le16			numexat;
	__u8			rsvd1030[2];
	struct nvmf_ext_attr	exat[];
};

/**
 * struct nvme_host_discovery_log - Host Discovery Log
 * @genctr:	Generation Counter
 * @numrec:	Number of Records
 * @recfmt:	Record Format
 * @hdlpf:	Host Discovery Log Page Flags
 * @rsvd19:	Reserved
 * @thdlpl:	Total Host Discovery Log Page Length
 * @rsvd24:	Reserved
 * @hedlpe:	Host Extended Discovery Log Page Entry List
 */
struct nvme_host_discovery_log {
	__le64					genctr;
	__le64					numrec;
	__le16					recfmt;
	__u8					hdlpf;
	__u8					rsvd19;
	__le32					thdlpl;
	__u8					rsvd24[1000];
	struct nvme_host_ext_discovery_log	hedlpe[];
};

/**
 * struct nvme_ave_tr_record - AVE Transport Record
 * @aveadrfam:	AVE Address Family
 * @rsvd1:	Reserved
 * @avetrsvcid:	AVE Transport Service Identifier
 * @avetraddr:	AVE Transport Address
 */
struct nvme_ave_tr_record {
	__u8	aveadrfam;
	__u8	rsvd1;
	__le16	avetrsvcid;
	__u8	avetraddr[16];
};

/**
 * struct nvme_ave_discovery_log_entry - AVE Discovery Log Entry
 * @tel:	Total Entry Length
 * @avenqn:	AVE NQN
 * @numatr:	Number of AVE Transport Records
 * @rsvd229:	Reserved
 * @atr:	AVE Transport Record List
 */
struct nvme_ave_discovery_log_entry {
	__le32				tel;
	char				avenqn[224];
	__u8				numatr;
	__u8				rsvd229[3];
	struct nvme_ave_tr_record	atr[];
};

/**
 * struct nvme_ave_discovery_log - AVE Discovery Log
 * @genctr:	Generation Counter
 * @numrec:	Number of Records
 * @recfmt:	Record Format
 * @rsvd18:	Reserved
 * @tadlpl:	Total AVE Discovery Log Page Length
 * @rsvd24:	Reserved
 * @adlpe:	AVE Discovery Log Page Entry List
 */
struct nvme_ave_discovery_log {
	__le64					genctr;
	__le64					numrec;
	__le16					recfmt;
	__u8					rsvd18[2];
	__le32					tadlpl;
	__u8					rsvd24[1000];
	struct nvme_ave_discovery_log_entry	adlpe[];
};

/**
 * enum nvme_ave_pdu_type - KX-HMAC-CHAP AVE Access Protocol PDU Types
 * @NVME_AVE_PDU_TYPE_ACCESS_REQUEST:	KX-HMAC-CHAP_Access-Request
 * @NVME_AVE_PDU_TYPE_ACCESS_RESULT:	KX-HMAC-CHAP_Access-Result
 */
enum nvme_ave_pdu_type {
	NVME_AVE_PDU_TYPE_ACCESS_REQUEST	= 0xae,
	NVME_AVE_PDU_TYPE_ACCESS_RESULT		= 0xaf,
};

/**
 * struct nvme_ave_access_request - KX-HMAC-CHAP_Access-Request PDU, sent by
 *	an NVMe entity (host or controller) to an AVE over the AVE's TLS
 *	connection
 * @pdu_type:	PDU Type, see &enum nvme_ave_pdu_type
 * @flags:	Reserved
 * @hlen:	Header Length: fixed length of 8 bytes (08h)
 * @pdo:	PDU Data Offset, reserved
 * @plen:	PDU Length: total length of the PDU in bytes
 * @id:		Identifier used to match this PDU with the corresponding
 *		&struct nvme_ave_access_result PDU
 * @hl:		Hash Length: length in bytes of the selected hash function
 * @hashid:	Hash Identifier, see &enum libnvmf_hmac_alg
 * @t_id:	Transaction Identifier
 * @sc_c:	Secure Channel Concatenation, see &enum nvmf_auth_sc_c
 * @respr:	Responder's Role: 'H' (48h) if host, 'C' (43h) if controller
 * @nqnrlen:	NQN Responder Length: length in bytes of @acv_respv_nqnr's
 *		NQNR component
 * @rsvd23:	Reserved
 * @seqnum:	Sequence Number (S)
 * @acv_respv_nqnr: Augmented Challenge Value (Ca, @hl bytes), followed by
 *		the Response Value (R, @hl bytes), followed by the NQN of the
 *		Responder (NQNR, @nqnrlen bytes)
 */
struct nvme_ave_access_request {
	__u8	pdu_type;
	__u8	flags;
	__u8	hlen;
	__u8	pdo;
	__le32	plen;
	__le64	id;
	__u8	hl;
	__u8	hashid;
	__le16	t_id;
	__u8	sc_c;
	__u8	respr;
	__u8	nqnrlen;
	__u8	rsvd23;
	__le32	seqnum;
	__u8	acv_respv_nqnr[];
};

/**
 * enum nvme_ave_authres - KX-HMAC-CHAP AVE Authentication Verification
 *	Result (AuthRes)
 * @NVME_AVE_AUTHRES_SUCCESS:	Authentication Verification Successful
 * @NVME_AVE_AUTHRES_FAILED:	Authentication Verification Failed
 */
enum nvme_ave_authres {
	NVME_AVE_AUTHRES_SUCCESS	= 0x01,
	NVME_AVE_AUTHRES_FAILED		= 0x02,
};

/**
 * enum nvme_ave_rcode - KX-HMAC-CHAP AVE Access-Result Reason Code (RCODE)
 * @NVME_AVE_RCODE_NONE:		No additional explanation
 * @NVME_AVE_RCODE_AUTH_FAILURE:	Authentication failure
 * @NVME_AVE_RCODE_HASH_UNUSABLE:	Selected hash function unusable
 */
enum nvme_ave_rcode {
	NVME_AVE_RCODE_NONE		= 0x00,
	NVME_AVE_RCODE_AUTH_FAILURE	= 0x01,
	NVME_AVE_RCODE_HASH_UNUSABLE	= 0x02,
};

/**
 * struct nvme_ave_access_result - KX-HMAC-CHAP_Access-Result PDU, sent by
 *	an AVE in response to a &struct nvme_ave_access_request PDU
 * @pdu_type:	PDU Type, see &enum nvme_ave_pdu_type
 * @flags:	Reserved
 * @hlen:	Header Length: fixed length of 8 bytes (08h)
 * @pdo:	PDU Data Offset, reserved
 * @plen:	PDU Length: fixed length of 20 bytes (14h)
 * @id:		Identifier matching the corresponding
 *		&struct nvme_ave_access_request PDU
 * @authres:	Authentication Verification Result, see &enum nvme_ave_authres
 * @rcode:	Reason Code, see &enum nvme_ave_rcode
 * @rsvd18:	Reserved
 */
struct nvme_ave_access_result {
	__u8	pdu_type;
	__u8	flags;
	__u8	hlen;
	__u8	pdo;
	__le32	plen;
	__le64	id;
	__u8	authres;
	__u8	rcode;
	__u16	rsvd18;
};

/**
 * enum nvmf_auth_protocol_id - Authentication Protocol Identifiers
 * @NVMF_AUTH_PROTOCOL_COMMON:	Common messages
 * @NVMF_AUTH_PROTOCOL_KXCHAP:	KX-HMAC-CHAP
 */
enum nvmf_auth_protocol_id {
	NVMF_AUTH_PROTOCOL_COMMON	= 0x00,
	NVMF_AUTH_PROTOCOL_KXCHAP	= 0x01,
};

/**
 * enum nvmf_auth_id - Common Authentication Identifiers (AUTH_ID)
 * @NVMF_AUTH_ID_NEGOTIATE:	AUTH_Negotiate
 * @NVMF_AUTH_ID_FAILURE2:	AUTH_Failure2
 * @NVMF_AUTH_ID_FAILURE1:	AUTH_Failure1
 */
enum nvmf_auth_id {
	NVMF_AUTH_ID_NEGOTIATE	= 0x00,
	NVMF_AUTH_ID_FAILURE2	= 0xf0,
	NVMF_AUTH_ID_FAILURE1	= 0xf1,
};

/**
 * enum nvmf_auth_sc_c - Secure Channel Concatenation values (SC_C)
 * @NVMF_AUTH_SCC_NOSC:		No secure channel concatenation. Allowed on
 *				any Admin or I/O Queue; does not generate a
 *				PSK.
 * @NVMF_AUTH_SCC_NEWTLSPSK:	Generate a PSK and associated PSK identity on
 *				an Admin Queue over a TCP channel without TLS,
 *				for use setting up TLS secure channels for
 *				subsequent Admin and I/O queues. 0x01 is
 *				obsolete (refer to NVM Express Base
 *				Specification 2.0).
 * @NVMF_AUTH_SCC_REPLACETLSPSK: Generate a PSK and associated PSK identity
 *				on an Admin Queue over a TLS secure channel,
 *				replacing the PSK used to set up that secure
 *				channel.
 */
enum nvmf_auth_sc_c {
	NVMF_AUTH_SCC_NOSC		= 0x00,
	NVMF_AUTH_SCC_NEWTLSPSK		= 0x02,
	NVMF_AUTH_SCC_REPLACETLSPSK	= 0x03,
};

/**
 * struct nvmf_auth_negotiate - AUTH_Negotiate message, host to controller
 * @auth_type:	Authentication Type, see &enum nvmf_auth_protocol_id.
 *		Cleared to 0h (i.e., common messages).
 * @auth_id:	Authentication Identifier, see &enum nvmf_auth_id.
 *		Cleared to 0h (i.e., AUTH_Negotiate).
 * @rsvd2:	Reserved
 * @t_id:	Transaction Identifier
 * @sc_c:	Secure Channel Concatenation, see &enum nvmf_auth_sc_c
 * @napd:	Number of Authentication Protocol Descriptors
 * @apd:	Authentication Protocol Descriptor list, @napd entries of 64
 *		bytes each. Currently always a
 *		&struct nvmf_auth_kxchap_protocol_descriptor, the only
 *		authentication protocol defined.
 */
struct nvmf_auth_negotiate {
	__u8	auth_type;
	__u8	auth_id;
	__u16	rsvd2;
	__le16	t_id;
	__u8	sc_c;
	__u8	napd;
	__u8	apd[];
};

/**
 * enum nvmf_auth_rcode - AUTH_Failure Reason Codes (RCODE)
 * @NVMF_AUTH_RCODE_FAILURE:	Authentication failure: the authentication
 *				transaction failed
 */
enum nvmf_auth_rcode {
	NVMF_AUTH_RCODE_FAILURE	= 0x01,
};

/**
 * enum nvmf_auth_rcodeex - AUTH_Failure Reason Code Explanations (RCODEEX)
 * @NVMF_AUTH_RCODEEX_FAILED:			Authentication failed:
 *		authentication of the involved host or NVM subsystem failed
 * @NVMF_AUTH_RCODEEX_PROTOCOL_NOT_USABLE:	Authentication protocol not
 *		usable: the protocol descriptors proposed by the host do not
 *		satisfy the security requirements of the controller
 * @NVMF_AUTH_RCODEEX_SCC_MISMATCH:		Secure channel concatenation
 *		mismatch: the SC_C value specified by the host does not
 *		satisfy the security requirements of the controller
 * @NVMF_AUTH_RCODEEX_HASH_NOT_USABLE:		Hash function not usable: the
 *		HashIDList proposed by the host does not satisfy the security
 *		requirements of the controller
 * @NVMF_AUTH_RCODEEX_KXGROUP_NOT_USABLE:	Key exchange group not usable:
 *		the KXgIDList proposed by the host does not satisfy the
 *		security requirements of the controller
 * @NVMF_AUTH_RCODEEX_INCORRECT_PAYLOAD:	Incorrect payload: the payload
 *		of the received message is not correct
 * @NVMF_AUTH_RCODEEX_INCORRECT_MESSAGE:	Incorrect protocol message: the
 *		received message is not the expected next message in the
 *		authentication protocol sequence
 */
enum nvmf_auth_rcodeex {
	NVMF_AUTH_RCODEEX_FAILED		= 0x01,
	NVMF_AUTH_RCODEEX_PROTOCOL_NOT_USABLE	= 0x02,
	NVMF_AUTH_RCODEEX_SCC_MISMATCH		= 0x03,
	NVMF_AUTH_RCODEEX_HASH_NOT_USABLE	= 0x04,
	NVMF_AUTH_RCODEEX_KXGROUP_NOT_USABLE	= 0x05,
	NVMF_AUTH_RCODEEX_INCORRECT_PAYLOAD	= 0x06,
	NVMF_AUTH_RCODEEX_INCORRECT_MESSAGE	= 0x07,
};

/**
 * struct nvmf_auth_failure - AUTH_Failure1 message, controller to host, or
 *	AUTH_Failure2 message, host to controller
 * @auth_type:	Authentication Type, see &enum nvmf_auth_protocol_id.
 *		Cleared to 0h (i.e., common messages).
 * @auth_id:	Authentication Identifier, see &enum nvmf_auth_id.
 *		NVMF_AUTH_ID_FAILURE1 for AUTH_Failure1, NVMF_AUTH_ID_FAILURE2
 *		for AUTH_Failure2.
 * @rsvd2:	Reserved
 * @t_id:	Transaction Identifier
 * @rcode:	Reason Code, see &enum nvmf_auth_rcode
 * @rcodeex:	Reason Code Explanation, see &enum nvmf_auth_rcodeex
 */
struct nvmf_auth_failure {
	__u8	auth_type;
	__u8	auth_id;
	__u16	rsvd2;
	__le16	t_id;
	__u8	rcode;
	__u8	rcodeex;
};

/**
 * enum nvmf_auth_kxchap_id - KX-HMAC-CHAP Authentication Identifiers (AUTH_ID)
 * @NVMF_AUTH_KXCHAP_ID_CHALLENGE:	KX-HMAC-CHAP_Challenge
 * @NVMF_AUTH_KXCHAP_ID_REPLY:		KX-HMAC-CHAP_Reply
 * @NVMF_AUTH_KXCHAP_ID_SUCCESS1:	KX-HMAC-CHAP_Success1
 * @NVMF_AUTH_KXCHAP_ID_SUCCESS2:	KX-HMAC-CHAP_Success2
 */
enum nvmf_auth_kxchap_id {
	NVMF_AUTH_KXCHAP_ID_CHALLENGE	= 0x01,
	NVMF_AUTH_KXCHAP_ID_REPLY	= 0x02,
	NVMF_AUTH_KXCHAP_ID_SUCCESS1	= 0x03,
	NVMF_AUTH_KXCHAP_ID_SUCCESS2	= 0x04,
};

/**
 * enum nvmf_auth_kxgid - KX-HMAC-CHAP Key Exchange Group Identifiers
 * @NVMF_AUTH_KXGID_NULL:		No key exchange performed
 * @NVMF_AUTH_KXGID_FFDHE2048:		Finite Field Diffie-Hellman Ephemeral,
 *					2048-bit group (refer to RFC 7919)
 * @NVMF_AUTH_KXGID_FFDHE3072:		Finite Field Diffie-Hellman Ephemeral,
 *					3072-bit group (refer to RFC 7919)
 * @NVMF_AUTH_KXGID_FFDHE4096:		Finite Field Diffie-Hellman Ephemeral,
 *					4096-bit group (refer to RFC 7919)
 * @NVMF_AUTH_KXGID_FFDHE6144:		Finite Field Diffie-Hellman Ephemeral,
 *					6144-bit group (refer to RFC 7919)
 * @NVMF_AUTH_KXGID_FFDHE8192:		Finite Field Diffie-Hellman Ephemeral,
 *					8192-bit group (refer to RFC 7919)
 * @NVMF_AUTH_KXGID_SECP256R1:		Elliptic Curve Diffie-Hellman Ephemeral,
 *					curve secp256r1 (refer to RFC 8422,
 *					NIST SP 800-186)
 * @NVMF_AUTH_KXGID_SECP384R1:		Elliptic Curve Diffie-Hellman Ephemeral,
 *					curve secp384r1 (refer to RFC 8422,
 *					NIST SP 800-186)
 * @NVMF_AUTH_KXGID_MLKEM768:		Module-Lattice Key-Encapsulation Mechanism,
 *					security category 3 (refer to NIST FIPS 203)
 * @NVMF_AUTH_KXGID_MLKEM1024:		Module-Lattice Key-Encapsulation Mechanism,
 *					security category 5 (refer to NIST FIPS 203)
 * @NVMF_AUTH_KXGID_SECP256R1MLKEM768:	Hybrid key exchange using secp256r1 and
 *					ML-KEM-768 (refer to draft-ietf-tls-ecdhe-mlkem)
 * @NVMF_AUTH_KXGID_SECP384R1MLKEM1024: Hybrid key exchange using secp384r1 and
 *					ML-KEM-1024 (refer to draft-ietf-tls-ecdhe-mlkem)
 */
enum nvmf_auth_kxgid {
	NVMF_AUTH_KXGID_NULL			= 0x00,
	NVMF_AUTH_KXGID_FFDHE2048		= 0x01,
	NVMF_AUTH_KXGID_FFDHE3072		= 0x02,
	NVMF_AUTH_KXGID_FFDHE4096		= 0x03,
	NVMF_AUTH_KXGID_FFDHE6144		= 0x04,
	NVMF_AUTH_KXGID_FFDHE8192		= 0x05,
	NVMF_AUTH_KXGID_SECP256R1		= 0x10,
	NVMF_AUTH_KXGID_SECP384R1		= 0x11,
	NVMF_AUTH_KXGID_MLKEM768		= 0x20,
	NVMF_AUTH_KXGID_MLKEM1024		= 0x21,
	NVMF_AUTH_KXGID_SECP256R1MLKEM768	= 0x30,
	NVMF_AUTH_KXGID_SECP384R1MLKEM1024	= 0x31,
};

/**
 * struct nvmf_auth_kxchap_protocol_descriptor - KX-HMAC-CHAP Authentication
 *	Protocol Descriptor
 * @authid:	Authentication Protocol Identifier, see
 *		&enum nvmf_auth_protocol_id
 * @rsvd1:	Reserved
 * @halen:	HashIDList Length: number of hash function identifiers (1 to 30)
 * @kxlen:	KXgIDList Length: number of key exchange group identifiers (1 to 30)
 * @hashidlist:	Hash Function Identifier List, one byte per identifier,
 *		see &enum libnvmf_hmac_alg. Unused trailing bytes are padding
 *		cleared to 0h.
 * @kxgidlist:	Key Exchange Group Identifier List, one byte per identifier,
 *		see &enum nvmf_auth_kxgid. Unused trailing bytes are padding
 *		cleared to 0h.
 */
struct nvmf_auth_kxchap_protocol_descriptor {
	__u8	authid;
	__u8	rsvd1;
	__u8	halen;
	__u8	kxlen;
	__u8	hashidlist[30];
	__u8	kxgidlist[30];
};

/**
 * struct nvmf_auth_kxchap_challenge - KX-HMAC-CHAP_Challenge message,
 *	controller to host
 * @auth_type:	Authentication Type, see &enum nvmf_auth_protocol_id
 * @auth_id:	Authentication Identifier, see &enum nvmf_auth_kxchap_id
 * @rsvd2:	Reserved
 * @t_id:	Transaction Identifier
 * @hl:		Hash Length: length in bytes of the selected hash function
 * @rsvd7:	Reserved
 * @hashid:	Hash Identifier, see &enum libnvmf_hmac_alg
 * @kxgid:	Key Exchange Group Identifier, see &enum nvmf_auth_kxgid.
 *		Cleared to 0h if no key exchange is performed.
 * @kxvlen:	KX Value Length: length in bytes of the KX Value carried in
 *		@cval_kxv, cleared to 0h if @kxgid is cleared to 0h.
 * @seqnum:	Sequence Number (S1)
 * @cval_kxv:	Challenge Value (C1, @hl bytes) followed by the KX Value
 *		(KXc, @kxvlen bytes). The KX Value is absent if @kxvlen is
 *		cleared to 0h.
 */
struct nvmf_auth_kxchap_challenge {
	__u8	auth_type;
	__u8	auth_id;
	__u16	rsvd2;
	__le16	t_id;
	__u8	hl;
	__u8	rsvd7;
	__u8	hashid;
	__u8	kxgid;
	__le16	kxvlen;
	__le32	seqnum;
	__u8	cval_kxv[];
};

/**
 * struct nvmf_auth_kxchap_reply - KX-HMAC-CHAP_Reply message,
 *	host to controller
 * @auth_type:	Authentication Type, see &enum nvmf_auth_protocol_id
 * @auth_id:	Authentication Identifier, see &enum nvmf_auth_kxchap_id
 * @rsvd2:	Reserved
 * @t_id:	Transaction Identifier
 * @hl:		Hash Length: length in bytes of the selected hash function
 * @rsvd7:	Reserved
 * @cvalid:	Challenge Valid: 01h if the Challenge Value in @rval_cval_kxv
 *		is valid (bidirectional authentication requested), 00h otherwise.
 * @rsvd9:	Reserved
 * @kxvlen:	KX Value Length: length in bytes of the KX Value carried in
 *		@rval_cval_kxv, cleared to 0h if no key exchange is performed.
 * @seqnum:	Sequence Number (S2)
 * @rval_cval_kxv: Response Value (R1, @hl bytes), followed by the Challenge
 *		Value (C2, @hl bytes, cleared to 0h if @cvalid is 00h),
 *		followed by the KX Value (KXh, @kxvlen bytes). The KX Value
 *		is absent if @kxvlen is cleared to 0h.
 */
struct nvmf_auth_kxchap_reply {
	__u8	auth_type;
	__u8	auth_id;
	__u16	rsvd2;
	__le16	t_id;
	__u8	hl;
	__u8	rsvd7;
	__u8	cvalid;
	__u8	rsvd9;
	__le16	kxvlen;
	__le32	seqnum;
	__u8	rval_cval_kxv[];
};

/**
 * struct nvmf_auth_kxchap_success1 - KX-HMAC-CHAP_Success1 message,
 *	controller to host
 * @auth_type:	Authentication Type, see &enum nvmf_auth_protocol_id
 * @auth_id:	Authentication Identifier, see &enum nvmf_auth_kxchap_id
 * @rsvd2:	Reserved
 * @t_id:	Transaction Identifier
 * @hl:		Hash Length: length in bytes of the selected hash function
 * @rsvd7:	Reserved
 * @rvalid:	Response Valid: 01h if @rval carries a valid Response Value
 *		(bidirectional authentication was requested), 00h otherwise.
 * @rsvd9:	Reserved
 * @rval:	Response Value (R2, @hl bytes), cleared to 0h if @rvalid is 00h.
 */
struct nvmf_auth_kxchap_success1 {
	__u8	auth_type;
	__u8	auth_id;
	__u16	rsvd2;
	__le16	t_id;
	__u8	hl;
	__u8	rsvd7;
	__u8	rvalid;
	__u8	rsvd9[7];
	__u8	rval[];
};

/**
 * struct nvmf_auth_kxchap_success2 - KX-HMAC-CHAP_Success2 message,
 *	host to controller
 * @auth_type:	Authentication Type, see &enum nvmf_auth_protocol_id
 * @auth_id:	Authentication Identifier, see &enum nvmf_auth_kxchap_id
 * @rsvd2:	Reserved
 * @t_id:	Transaction Identifier
 * @rsvd6:	Reserved
 */
struct nvmf_auth_kxchap_success2 {
	__u8	auth_type;
	__u8	auth_id;
	__u16	rsvd2;
	__le16	t_id;
	__u8	rsvd6[10];
};

