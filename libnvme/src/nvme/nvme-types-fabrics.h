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
 * struct nvme_host_ext_discover_log - Host Extended Discovery Log
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
struct nvme_host_ext_discover_log {
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
 * struct nvme_host_discover_log - Host Discovery Log
 * @genctr:	Generation Counter
 * @numrec:	Number of Records
 * @recfmt:	Record Format
 * @hdlpf:	Host Discovery Log Page Flags
 * @rsvd19:	Reserved
 * @thdlpl:	Total Host Discovery Log Page Length
 * @rsvd24:	Reserved
 * @hedlpe:	Host Extended Discovery Log Page Entry List
 */
struct nvme_host_discover_log {
	__le64					genctr;
	__le64					numrec;
	__le16					recfmt;
	__u8					hdlpf;
	__u8					rsvd19;
	__le32					thdlpl;
	__u8					rsvd24[1000];
	struct nvme_host_ext_discover_log	hedlpe[];
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
 * struct nvme_ave_discover_log_entry - AVE Discovery Log Entry
 * @tel:	Total Entry Length
 * @avenqn:	AVE NQN
 * @numatr:	Number of AVE Transport Records
 * @rsvd229:	Reserved
 * @atr:	AVE Transport Record List
 */
struct nvme_ave_discover_log_entry {
	__le32				tel;
	char				avenqn[224];
	__u8				numatr;
	__u8				rsvd229[3];
	struct nvme_ave_tr_record	atr[];
};

/**
 * struct nvme_ave_discover_log - AVE Discovery Log
 * @genctr:	Generation Counter
 * @numrec:	Number of Records
 * @recfmt:	Record Format
 * @rsvd18:	Reserved
 * @tadlpl:	Total AVE Discovery Log Page Length
 * @rsvd24:	Reserved
 * @adlpe:	AVE Discovery Log Page Entry List
 */
struct nvme_ave_discover_log {
	__le64					genctr;
	__le64					numrec;
	__le16					recfmt;
	__u8					rsvd18[2];
	__le32					tadlpl;
	__u8					rsvd24[1000];
	struct nvme_ave_discover_log_entry	adlpe[];
};

