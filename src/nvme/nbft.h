/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * This file is part of libnvme.
 * Copyright (c) 2021-2022, Dell Inc. or its subsidiaries.  All Rights Reserved.
 *
 * Authors: Stuart Hayes <Stuart_Hayes@Dell.com>
 *
 */
#ifndef _NBFT_H
#define _NBFT_H

#include <sys/types.h>
#include "util.h"

/*
 *  ACPI NBFT table structures (TP8012 Boot Specification rev. 1.0)
 */

/**
 * enum nbft_desc_type - NBFT Elements - Descriptor Types (Figure 5)
 * @NBFT_DESC_HEADER:	     Header: an ACPI structure header with some additional
 *			     NBFT specific info.
 * @NBFT_DESC_CONTROL:	     Control Descriptor: indicates the location of host,
 *			     HFI, SSNS, security, and discovery descriptors.
 * @NBFT_DESC_HOST:	     Host Descriptor: host information.
 * @NBFT_DESC_HFI:	     HFI Descriptor: an indexable table of HFI Descriptors,
 *			     one for each fabric interface on the host.
 * @NBFT_DESC_SSNS:	     Subsystem Namespace Descriptor: an indexable table
 *			     of SSNS Descriptors.
 * @NBFT_DESC_SECURITY:	     Security Descriptor: an indexable table of Security
 *			     descriptors.
 * @NBFT_DESC_DISCOVERY:     Discovery Descriptor: an indexable table of Discovery
 *			     Descriptors.
 * @NBFT_DESC_HFI_TRINFO:    HFI Transport Descriptor: indicated by an HFI Descriptor,
 *			     corresponds to a specific transport for a single HFI.
 * @NBFT_DESC_RESERVED_8:    Reserved.
 * @NBFT_DESC_SSNS_EXT_INFO: SSNS Extended Info Descriptor: indicated by an SSNS
 *			     Descriptor if required.
 */
enum nbft_desc_type {
	NBFT_DESC_HEADER	= 0,
	NBFT_DESC_CONTROL	= 1,
	NBFT_DESC_HOST		= 2,
	NBFT_DESC_HFI		= 3,
	NBFT_DESC_SSNS		= 4,
	NBFT_DESC_SECURITY	= 5,
	NBFT_DESC_DISCOVERY	= 6,
	NBFT_DESC_HFI_TRINFO	= 7,
	NBFT_DESC_RESERVED_8	= 8,
	NBFT_DESC_SSNS_EXT_INFO	= 9,
};

/**
 * enum nbft_trtype - NBFT Interface Transport Types (Figure 7)
 * @NBFT_TRTYPE_TCP: NVMe/TCP (802.3 + TCP/IP). String Designator "tcp".
 */
enum nbft_trtype {
	NBFT_TRTYPE_TCP	= 3,
};

#define NBFT_HEADER_SIG		"NBFT"

/**
 * struct nbft_heap_obj - NBFT Header Driver Signature
 * @offset: Offset in bytes of the heap object, if any, from byte offset 0h
 *	    of the NBFT Table Header.
 * @length: Length in bytes of the heap object, if any.
 */
struct nbft_heap_obj {
	__le32 offset;
	__le16 length;
} __attribute__((packed));

/**
 * struct nbft_header - NBFT Table - Header (Figure 8)
 * @signature:		 Signature: An ASCII string representation of the table
 *			 identifier. This field shall be set to the value 4E424654h
 *			 (i.e. "NBFT", see #NBFT_HEADER_SIG).
 * @length:		 Length: The length of the table, in bytes, including the
 *			 header, starting from offset 0h. This field is used to record
 *			 the size of the entire table.
 * @major_revision:	 Major Revision: The major revision of the structure
 *			 corresponding to the Signature field. Larger major revision
 *			 numbers should not be assumed backward compatible to lower
 *			 major revision numbers with the same signature.
 * @checksum:		 Checksum: The entire table, including the Checksum field,
 *			 shall sum to 0h to be considered valid.
 * @oem_id:		 OEMID shall be populated by the NBFT driver writer by
 *			 an OEM-supplied string that identifies the OEM. All
 *			 trailing bytes shall be NULL.
 * @oem_table_id:	 OEM Table ID: This field shall be populated by the NBFT
 *			 driver writer with an OEM-supplied string that the OEM
 *			 uses to identify the particular data table. This field is
 *			 particularly useful when defining a definition block to
 *			 distinguish definition block functions. The OEM assigns
 *			 each dissimilar table a new OEM Table ID.
 * @oem_revision:	 OEM Revision: An OEM-supplied revision number. Larger
 *			 numbers are assumed to be newer revisions.
 * @creator_id:		 Creator ID: Vendor ID of utility that created the table.
 *			 For instance, this may be the ID for the ASL Compiler.
 * @creator_revision:	 Creator Revision: Revision of utility that created the
 *			 table. For instance, this may be the ID for the ASL Compiler.
 * @heap_offset:	 Heap Offset (HO): This field indicates the offset in bytes
 *			 of the heap, if any, from byte offset 0h of the NBFT
 *			 Table Header.
 * @heap_length:	 Heap Length (HL): The length of the heap, if any.
 * @driver_dev_path_sig: Driver Signature Heap Object Reference: This field indicates
 *			 the offset in bytes of a heap object containing the Driver
 *			 Signature, if any, from byte offset 0h of the NBFT Table
 *			 Header.
 * @minor_revision:	 Minor Revision: The minor revision of the structure
 *			 corresponding to the Signature field. If the major revision
 *			 numbers are the same, any minor revision number differences
 *			 shall be backwards compatible with the same signature.
 * @reserved:		 Reserved.
 */
struct nbft_header {
	char signature[4];
	__le32 length;
	__u8 major_revision;
	__u8 checksum;
	char oem_id[6];
	char oem_table_id[8];
	__le32 oem_revision;
	__le32 creator_id;
	__le32 creator_revision;
	__le32 heap_offset;
	__le32 heap_length;
	struct nbft_heap_obj driver_dev_path_sig;
	__u8 minor_revision;
	__u8 reserved[13];
};

/**
 * struct nbft_control - NBFT Table - Control Descriptor (Figure 8)
 * @structure_id:   Structure ID: This field specifies the element (refer to
 *		    &enum nbft_desc_type). This field shall be set to 1h (i.e.,
 *		    Control, #NBFT_DESC_CONTROL).
 * @major_revision: Major Revision: The major revision of the structure corresponding
 *		    to the Signature field. Larger major revision numbers should
 *		    not be assumed backward compatible to lower major revision
 *		    numbers with the same signature.
 * @minor_revision: Minor Revision: The minor revision of the structure corresponding
 *		    to the signature field. If the major revision numbers are
 *		    the same, any minor revision number differences shall be backwards
 *		    compatible with the same signature.
 * @reserved1:	    Reserved.
 * @csl:	    Control Structure Length (CSL): This field indicates the length
 *		    in bytes of the Control Descriptor.
 * @flags:	    Flags, see &enum nbft_control_flags.
 * @reserved2:	    Reserved.
 * @hdesc:	    Host Descriptor (HDESC): This field indicates the location
 *		    and length of the Host Descriptor (see &struct nbft_host).
 * @hsv:	    Host Descriptor Version (HSV): This field indicates the version
 *		    of the Host Descriptor.
 * @reserved3:	    Reserved.
 * @hfio:	    HFI Descriptor List Offset (HFIO): If this field is set to
 *		    a non-zero value, then this field indicates the offset in bytes
 *		    of the HFI Descriptor List, if any, from byte offset 0h of the
 *		    NBFT Table Header. If the @num_hfi field is cleared to 0h,
 *		    then this field is reserved.
 * @hfil:	    HFI Descriptor Length (HFIL): This field indicates the length
 *		    in bytes of each HFI Descriptor, if any. If the @num_hfi field
 *		    is cleared to 0h, then this field is reserved.
 * @hfiv:	    HFI Descriptor Version (HFIV): This field indicates the version
 *		    of each HFI Descriptor.
 * @num_hfi:	    Number of Host Fabric Interface Descriptors (NumHFI): This field
 *		    indicates the number of HFI Descriptors (see &struct nbft_hfi)
 *		    in the HFI Descriptor List, if any. If no interfaces have been
 *		    configured, then this field shall be cleared to 0h.
 * @ssnso:	    SSNS Descriptor List Offset (SSNSO):: This field indicates
 *		    the offset in bytes of the SSNS Descriptor List, if any, from
 *		    byte offset 0h of the NBFT Table Header. If the @num_ssns field
 *		    is cleared to 0h, then this field is reserved.
 * @ssnsl:	    SSNS Descriptor Length (SSNSL): This field indicates the length
 *		    in bytes of each SSNS Descriptor, if any. If the @num_ssns
 *		    field is cleared to 0h, then this field is reserved.
 * @ssnsv:	    SSNS Descriptor Version (SSNSV): This field indicates the version
 *		    of the SSNS Descriptor.
 * @num_ssns:	    Number of Subsystem and Namespace Descriptors (NumSSNS): This
 *		    field indicates the number of Subsystem Namespace (SSNS)
 *		    Descriptors (see &struct nbft_ssns) in the SSNS Descriptor List,
 *		    if any.
 * @seco:	    Security Profile Descriptor List Offset (SECO): This field
 *		    indicates the offset in bytes of the Security Profile Descriptor
 *		    List, if any, from byte offset 0h of the NBFT Table Header.
 *		    If the @num_sec field is cleared to 0h, then this field
 *		    is reserved.
 * @secl:	    Security Profile Descriptor Length (SECL): This field indicates
 *		    the length in bytes of each Security Profile Descriptor, if any.
 *		    If the @num_sec field is cleared to 0h, then this field
 *		    is reserved.
 * @secv:	    Security Profile Descriptor Version (SECV): This field indicates
 *		    the version of the Security Profile Descriptor.
 * @num_sec:	    Number of Security Profile Descriptors (NumSec): This field
 *		    indicates the number of Security Profile Descriptors
 *		    (see &struct nbft_security), if any, in the Security Profile
 *		    Descriptor List.
 * @disco:	    Discovery Descriptor Offset (DISCO): This field indicates
 *		    the offset in bytes of the Discovery Descriptor List, if any,
 *		    from byte offset 0h of the NBFT Table Header. If the @num_disc
 *		    field is cleared to 0h, then this field is reserved.
 * @discl:	    Discovery Descriptor Length (DISCL): This field indicates
 *		    the length in bytes of each Discovery Descriptor, if any.
 *		    If the @num_disc field is cleared to 0h, then this field
 *		    is reserved.
 * @discv:	    Discovery Descriptor Version (DISCV): This field indicates
 *		    the version of the Discovery Descriptor.
 * @num_disc:	    Number of Discovery Descriptors (NumDisc): This field indicates
 *		    the number of Discovery Descriptors (see &struct nbft_discovery),
 *		    if any, in the Discovery Descriptor List, if any.
 * @reserved4:	    Reserved.
 */
struct nbft_control {
	__u8 structure_id;
	__u8 major_revision;
	__u8 minor_revision;
	__u8 reserved1;
	__le16 csl;
	__u8 flags;
	__u8 reserved2;
	struct nbft_heap_obj hdesc;
	__u8 hsv;
	__u8 reserved3;
	__le32 hfio;
	__le16 hfil;
	__u8 hfiv;
	__u8 num_hfi;
	__le32 ssnso;
	__le16 ssnsl;
	__u8 ssnsv;
	__u8 num_ssns;
	__le32 seco;
	__le16 secl;
	__u8 secv;
	__u8 num_sec;
	__le32 disco;
	__le16 discl;
	__u8 discv;
	__u8 num_disc;
	__u8 reserved4[16];
};

/**
 * enum nbft_control_flags - Control Descriptor Flags
 * @NBFT_CONTROL_VALID:	Block Valid: indicates that the structure is valid.
 */
enum nbft_control_flags {
	NBFT_CONTROL_VALID	= 1 << 0,
};

/**
 * struct nbft_host - Host Descriptor (Figure 9)
 * @structure_id: Structure ID: This field shall be set to 2h (i.e.,
 *		  Host Descriptor; #NBFT_DESC_HOST).
 * @flags:	  Host Flags, see &enum nbft_host_flags.
 * @host_id:	  Host ID: This field shall be set to the Host Identifier. This
 *		  field shall not be empty if the NBFT and NVMe Boot are supported
 *		  by the Platform.
 * @host_nqn_obj: Host NQN Heap Object Reference: this field indicates a heap
 *		  object containing a Host NQN. This object shall not be empty
 *		  if the NBFT and NVMe Boot are supported by the Platform.
 * @reserved:	  Reserved.
 */
struct nbft_host {
	__u8 structure_id;
	__u8 flags;
	__u8 host_id[16];
	struct nbft_heap_obj host_nqn_obj;
	__u8 reserved[8];
};

/**
 * enum nbft_host_flags - Host Flags
 * @NBFT_HOST_VALID:			   Descriptor Valid: If set to 1h, then this
 *					   descriptor is valid. If cleared to 0h, then
 *					   this descriptor is reserved.
 * @NBFT_HOST_HOSTID_CONFIGURED:	   HostID Configured: If set to 1h, then the
 *					   Host ID field contains an administratively-configured
 *					   value. If cleared to 0h, then the Host ID
 *					   field contains a driver default value.
 * @NBFT_HOST_HOSTNQN_CONFIGURED:	   Host NQN Configured: If set to 1h, then the
 *					   Host NQN indicated by the Host NQN Heap Object
 *					   Reference field (&struct nbft_host.host_nqn)
 *					   contains an administratively-configured value.
 *					   If cleared to 0h, then the Host NQN indicated
 *					   by the Host NQN Offset field contains a driver
 *					   default value.
 * @NBFT_HOST_PRIMARY_ADMIN_MASK:	   Mask to get Primary Administrative Host Descriptor:
 *					   indicates whether the Host Descriptor in this
 *					   NBFT was selected as the primary NBFT for
 *					   administrative purposes of platform identity
 *					   as a hint to the OS. If multiple NBFT tables
 *					   are present, only one NBFT should be administratively
 *					   selected. There is no enforcement mechanism
 *					   for this to be coordinated between multiple NBFT
 *					   tables, but this field should be set to Selected
 *					   (#NBFT_HOST_PRIMARY_ADMIN_SELECTED) if
 *					   more than one NBFT is present.
 * @NBFT_HOST_PRIMARY_ADMIN_NOT_INDICATED: Not Indicated by Driver: The driver that created
 *					   this NBFT provided no administrative priority
 *					   hint for this NBFT.
 * @NBFT_HOST_PRIMARY_ADMIN_UNSELECTED:	   Unselected: The driver that created this NBFT
 *					   explicitly indicated that this NBFT should
 *					   not be prioritized over any other NBFT.
 * @NBFT_HOST_PRIMARY_ADMIN_SELECTED:	   Selected: The driver that created this NBFT
 *					   explicitly indicated that this NBFT should
 *					   be prioritized over any other NBFT.
 */
enum nbft_host_flags {
	NBFT_HOST_VALID				= 1 << 0,
	NBFT_HOST_HOSTID_CONFIGURED		= 1 << 1,
	NBFT_HOST_HOSTNQN_CONFIGURED		= 1 << 2,
	NBFT_HOST_PRIMARY_ADMIN_MASK		= 0x18,
	NBFT_HOST_PRIMARY_ADMIN_NOT_INDICATED	= 0x00,
	NBFT_HOST_PRIMARY_ADMIN_UNSELECTED	= 0x08,
	NBFT_HOST_PRIMARY_ADMIN_SELECTED	= 0x10,
};

/**
 * struct nbft_hfi - Host Fabric Interface (HFI) Descriptor (Figure 11)
 * @structure_id: Structure ID: This field shall be set to 3h (i.e., Host Fabric
 *		  Interface Descriptor; #NBFT_DESC_HFI).
 * @index:	  HFI Descriptor Index: This field indicates the number of this
 *		  HFI Descriptor in the Host Fabric Interface Descriptor List.
 * @flags:	  HFI Descriptor Flags, see &enum nbft_hfi_flags.
 * @trtype:	  HFI Transport Type, see &enum nbft_trtype.
 * @reserved1:	  Reserved.
 * @trinfo_obj:	  HFI Transport Info Descriptor Heap Object Reference: If this
 *		  field is set to a non-zero value, then this field indicates
 *		  the location and size of a heap object containing
 *		  a HFI Transport Info.
 * @reserved2:	  Reserved.
 */
struct nbft_hfi {
	__u8 structure_id;
	__u8 index;
	__u8 flags;
	__u8 trtype;
	__u8 reserved1[12];
	struct nbft_heap_obj trinfo_obj;
	__u8 reserved2[10];
};

/**
 * enum nbft_hfi_flags - HFI Descriptor Flags
 * @NBFT_HFI_VALID: Descriptor Valid: If set to 1h, then this descriptor is valid.
 *		    If cleared to 0h, then this descriptor is reserved.
 */
enum nbft_hfi_flags {
	NBFT_HFI_VALID	= 1 << 0,
};

/**
 * struct nbft_hfi_info_tcp - HFI Transport Info Descriptor - NVMe/TCP (Figure 13)
 * @structure_id:	Structure ID: This field shall be set to 7h (i.e.,
 *			HFI Transport Info; #NBFT_DESC_HFI_TRINFO).
 * @version:		Version: This field shall be set to 1h.
 * @trtype:		HFI Transport Type, see &enum nbft_trtype: This field
 *			shall be set to 03h (i.e., NVMe/TCP; #NBFT_TRTYPE_TCP).
 * @trinfo_version:	Transport Info Version: Implementations compliant to this
 *			specification shall set this field to 1h.
 * @hfi_index:		HFI Descriptor Index: The value of the HFI Descriptor Index
 *			field of the HFI Descriptor (see &struct nbft_hfi.index)
 *			whose HFI Transport Info Descriptor Heap Object Reference
 *			field indicates this HFI Transport Info Descriptor.
 * @flags:		HFI Transport Flags, see &enum nbft_hfi_info_tcp_flags.
 * @pci_sbdf:		PCI Express Routing ID for the HFI Transport Function:
 *			This field indicates the PCI Express Routing ID as specified
 *			in the PCI Express Base Specification.
 * @mac_addr:		MAC Address: The MAC address of this HFI, in EUI-48TM format,
 *			as defined in the IEEE Guidelines for Use of Extended Unique
 *			Identifiers. This field shall be set to a non-zero value.
 * @vlan:		VLAN: If this field is set to a non-zero value, then this
 *			field contains the VLAN identifier if the VLAN associated
 *			with this HFI, as defined in IEEE 802.1q-2018. If no VLAN
 *			is associated with this HFI, then this field shall be cleared
 *			to 0h.
 * @ip_origin:		IP Origin: If this field is set to a non-zero value, then
 *			this field indicates the source of Ethernet L3 configuration
 *			information used by the driver for this interface. Valid
 *			values are defined in the Win 32 API: NL_PREFIX_ORIGIN
 *			enumeration specification. This field should be cleared
 *			to 0h if the IP Origin field is unused by driver.
 * @ip_address:		IP Address: This field indicates the IPv4 or IPv6 address
 *			of this HFI. This field shall be set to a non-zero value.
 * @subnet_mask_prefix:	Subnet Mask Prefix: This field indicates the IPv4 or IPv6
 *			subnet mask in CIDR routing prefix notation.
 * @ip_gateway:		IP Gateway: If this field is set to a non-zero value, this
 *			field indicates the IPv4 or IPv6 address of the IP gateway
 *			for this HFI. If this field is cleared to 0h, then
 *			no IP gateway is specified.
 * @reserved1:		Reserved.
 * @route_metric:	Route Metric: If this field is set to a non-zero value,
 *			this field indicates the cost value for the route indicated
 *			by this HF. This field contains the value utilized by the
 *			pre-OS driver when chosing among all available routes. Lower
 *			values relate to higher priority. Refer to IETF RFC 4249.
 *			If the pre-OS driver supports routing and did not configure
 *			a specific route metric for this interface, then the pre-OS
 *			driver should set this value to 500. If the pre-OS driver
 *			does not support routing, then this field should be cleared
 *			to 0h.
 * @primary_dns:	Primary DNS: If this field is set to a non-zero value,
 *			this field indicates the IPv4 or IPv6 address of the
 *			Primary DNS server for this HFI, if any, from byte offset
 *			0h of the NBFT Table Header. If this field is cleared to 0h,
 *			then no Primary DNS is specified.
 * @secondary_dns:	Secondary DNS: If this field is set to a non-zero value,
 *			this field indicates the IPv4 or IPv6 address of
 *			the Secondary DNS server for this HFI, if any, from byte
 *			offset 0h of the NBFT Table Header. If this field is
 *			cleared to 0h, then no Secondary DNS is specified.
 * @dhcp_server:	DHCP Server: If the DHCP Override bit is set to 1h, then
 *			this field indicates the IPv4 or IPv6 address of the DHCP
 *			server used to assign this HFI address. If that bit is
 *			cleared to 0h, then this field is reserved.
 * @host_name_obj:	Host Name Heap Object Reference: If this field is set
 *			to a non-zero value, then this field indicates the location
 *			and size of a heap object containing a Host Name string.
 * @reserved2:		Reserved.
 */
struct nbft_hfi_info_tcp {
	__u8 structure_id;
	__u8 version;
	__u8 trtype;
	__u8 trinfo_version;
	__le16 hfi_index;
	__u8 flags;
	__le32 pci_sbdf;
	__u8 mac_addr[6];
	__le16 vlan;
	__u8 ip_origin;
	__u8 ip_address[16];
	__u8 subnet_mask_prefix;
	__u8 ip_gateway[16];
	__u8 reserved1;
	__le16 route_metric;
	__u8 primary_dns[16];
	__u8 secondary_dns[16];
	__u8 dhcp_server[16];
	struct nbft_heap_obj host_name_obj;
	__u8 reserved2[18];
} __attribute__((packed));

/**
 * enum nbft_hfi_info_tcp_flags - HFI Transport Flags
 * @NBFT_HFI_INFO_TCP_VALID:	     Descriptor Valid: if set to 1h, then this
 *				     descriptor is valid. If cleared to 0h, then
 *				     this descriptor is reserved.
 * @NBFT_HFI_INFO_TCP_GLOBAL_ROUTE:  Global Route vs. Link Local Override Flag:
 *				     if set to 1h, then the BIOS utilized this
 *				     interface described by HFI to be the default
 *				     route with highest priority. If cleared to 0h,
 *				     then routes are local to their own scope.
 * @NBFT_HFI_INFO_TCP_DHCP_OVERRIDE: DHCP Override: if set to 1, then HFI information
 *				     was populated by consuming the DHCP on this
 *				     interface. If cleared to 0h, then the HFI
 *				     information was set administratively by
 *				     a configuration interface to the driver and
 *				     pre-OS envrionment.
 */
enum nbft_hfi_info_tcp_flags {
	NBFT_HFI_INFO_TCP_VALID		= 1 << 0,
	NBFT_HFI_INFO_TCP_GLOBAL_ROUTE	= 1 << 1,
	NBFT_HFI_INFO_TCP_DHCP_OVERRIDE	= 1 << 2,
};

/**
 * struct nbft_ssns - Subsystem Namespace (SSNS) Descriptor (Figure 15)
 * @structure_id:		  Structure ID: This field shall be set to 4h
 *				  (i.e., SSNS; #NBFT_DESC_SSNS).
 * @index:			  SSNS Descriptor Index: This field indicates the number
 *				  of this Subsystem Namespace Descriptor in the
 *				  Subsystem Namespace Descriptor List.
 * @flags:			  SSNS Flags, see &enum nbft_ssns_flags.
 * @trtype:			  Transport Type, see &enum nbft_trtype.
 * @trflags:			  Transport Specific Flags, see &enum nbft_ssns_trflags.
 * @primary_discovery_ctrl_index: Primary Discovery Controller Index: The Discovery
 *				  Descriptor Index field of the Discovery Descriptor
 *				  (see &struct nbft_discovery) that is associated with
 *				  this SSNS Descriptor. If a Discovery controller was
 *				  used to establish this record this value shall
 *				  be set to a non-zero value. If this namespace was
 *				  associated with multiple Discovery controllers,
 *				  those Discovery controllers shall have records
 *				  in the Discovery Descriptor to facilitate multi-path
 *				  rediscovery as required. If no Discovery controller
 *				  was utilized to inform this namespace record,
 *				  this field shall be cleared to 0h.
 * @reserved1:			  Reserved.
 * @subsys_traddr_obj:		  Subsystem Transport Address Heap Object Reference:
 *				  This field indicates the location and size of a heap
 *				  object containing the Subsystem Transport Address.
 *				  For IP based transports types, shall be an IP Address.
 * @subsys_trsvcid_obj:		  Subsystem Transport Service Identifier Heap Object Reference:
 *				  This field indicates the location and size of a heap
 *				  object containing an array of bytes indicating
 *				  the Subsystem Transport Service Identifier.
 *				  See &enum nbft_trtype.
 * @subsys_port_id:		  Subsystem Port ID: Port in the NVM subsystem
 *				  associated with this transport address used by
 *				  the pre-OS driver.
 * @nsid:			  Namespace ID: This field indicates the namespace
 *				  identifier (NSID) of the namespace indicated by
 *				  this descriptor. This field shall be cleared to 0h
 *				  if not specified by the user. If this value is cleared
 *				  to 0h, then consumers of the NBFT shall rely
 *				  on the NID.
 * @nidt:			  Namespace Identifier Type (NIDT): This field
 *				  contains the value of the Namespace Identifier Type (NIDT)
 *				  field in the Namespace Identification Descriptor
 *				  for the namespace indicated by this descriptor.
 *				  If a namespace supports multiple NIDT entries
 *				  for uniqueness, the order of preference is NIDT field
 *				  value of 3h (i.e., UUID) before 2h (i.e., NSGUID),
 *				  and 2h before 1h (i.e., EUI-64).
 * @nid:			  Namespace Identifier (NID): This field contains
 *				  the value of the Namespace Identifier (NID) field
 *				  in the Namespace Identification Descriptor for
 *				  the namespace indicated by this descriptor.
 * @security_desc_index:	  Security Profile Descriptor Index: If the Use Security
 *				  Flag bit in the SSNS Flags field is set to 1h, then
 *				  this field indicates the value of the Security Profile
 *				  Descriptor Index field of the Security Profile
 *				  Descriptor (see &struct nbft_security) associated
 *				  with this namespace. If the Use Security Flag bit
 *				  is cleared to 0h, then no Security Profile Descriptor
 *				  is associated with this namespace and this field
 *				  is reserved.
 * @primary_hfi_desc_index:	  Primary HFI Descriptor Index: This field indicates
 *				  the value of the HFI Descriptor Index field of the
 *				  HFI Descriptor (see &struct nbft_hfi) for the
 *				  interface associated with this namespace. If multiple
 *				  HFIs are associated with this record, subsequent
 *				  interfaces should be populated in the Secondary
 *				  HFI Associations field.
 * @reserved2:			  Reserved.
 * @secondary_hfi_assoc_obj:	  Secondary HFI Associations Heap Object Reference:
 *				  If this field is set to a non-zero value, then
 *				  this field indicates an array of bytes, in which
 *				  each byte contains the value of the HFI Descriptor
 *				  Index field of an HFI Descriptor in the HFI Descriptor
 *				  List. If this field is cleared to 0h, then no
 *				  secondary HFI associations are specified.
 * @subsys_ns_nqn_obj:		  Subsystem and Namespace NQN Heap Object Reference:
 *				  This field indicates the location and size of
 *				  a heap object containing the Subsystem and Namespace NQN.
 * @ssns_extended_info_desc_obj:  SSNS Extended Information Descriptor Heap Object
 *				  Reference: If the SSNS Extended Info In-use Flag
 *				  bit is set to 1h, then this field indicates the
 *				  offset in bytes of a heap object containing an
 *				  SSNS Extended Information Descriptor
 *				  (see &struct nbft_ssns_ext_info) heap object
 *				  from byte offset 0h of the NBFT Table Header.
 *				  If the SSNS Extended Info In-use Flag bit is cleared
 *				  to 0h, then this field is reserved.
 * @reserved3:			  Reserved.
 */
struct nbft_ssns {
	__u8 structure_id;
	__le16 index;
	__le16 flags;
	__u8 trtype;
	__le16 trflags;
	__u8 primary_discovery_ctrl_index;
	__u8 reserved1;
	struct nbft_heap_obj subsys_traddr_obj;
	struct nbft_heap_obj subsys_trsvcid_obj;
	__le16 subsys_port_id;
	__le32 nsid;
	__u8 nidt;
	__u8 nid[16];
	__u8 security_desc_index;
	__u8 primary_hfi_desc_index;
	__u8 reserved2;
	struct nbft_heap_obj secondary_hfi_assoc_obj;
	struct nbft_heap_obj subsys_ns_nqn_obj;
	struct nbft_heap_obj ssns_extended_info_desc_obj;
	__u8 reserved3[62];
} __attribute__((packed));

/**
 * enum nbft_ssns_flags - Subsystem and Namespace Specific Flags Field (Figure 16)
 * @NBFT_SSNS_VALID:			 Descriptor Valid: If set to 1h, then this descriptor
 *					 is valid. If cleared to 0h, then this descriptor
 *					 is not valid. A host that supports NVMe-oF Boot,
 *					 but does not currently have a remote Subsystem
 *					 and Namespace assigned may clear this bit to 0h.
 * @NBFT_SSNS_NON_BOOTABLE_ENTRY:	 Non-bootable Entry Flag: If set to 1h, this flag
 *					 indicates that this SSNS Descriptor contains
 *					 a namespace of administrative purpose to the boot
 *					 process, but the pre-OS may not have established
 *					 connectivity to or evaluated the contents of this
 *					 Descriptor. Such namespaces may contain supplemental
 *					 data deemed relevant by the Administrator as part
 *					 of the pre-OS to OS hand off. This may include
 *					 properties such as a UEFI device path that may
 *					 not have been created for this namespace. This means
 *					 an OS runtime may still require the contents
 *					 of such a namespace to complete later stages
 *					 of boot. If cleared to 0h, then this namespace did
 *					 not have any special administrative intent.
 * @NBFT_SSNS_USE_SECURITY_FIELD:	 Use Security Flag: If set to 1h, then there is
 *					 a Security Profile Descriptor associated with this
 *					 SSNS record and the Security Profile Descriptor Index
 *					 field is valid. If cleared to 0h, then there is
 *					 no Security Profile Descriptor associated with this
 *					 SSNS record and the Security Profile Descriptor Index
 *					 field is not valid.
 * @NBFT_SSNS_DHCP_ROOT_PATH_OVERRIDE:	 DHCP Root-Path Override Flag: If set to 1h, then
 *					 this SSNS descriptor was populated by consuming
 *					 the DHCP Root-Path on this interface. If cleared
 *					 to 0h, then the DHCP Root-Path was not used
 *					 in populating the SSNS descriptor.
 * @NBFT_SSNS_EXTENDED_INFO_IN_USE:	 SSNS Extended Info In-use Flag: If set to 1h,
 *					 then the SSNS Extended Information Offset field
 *					 and the SSNS Extended Information Length field
 *					 are valid. This flag, if set to 1h, indicates
 *					 that a Subsystem and Namespace Extended Information
 *					 Descriptor corresponding to this descriptor is present.
 * @NBFT_SSNS_SEPARATE_DISCOVERY_CTRL:	 Separate Discovery Controller Flag: If set to 1h,
 *					 then the Discovery controller associated with
 *					 this volume is on a different transport address
 *					 than the specified in the Subsystem Transport
 *					 Address Heap Object Reference. If cleared to 0h,
 *					 then the Discovery controller is the same as the
 *					 Subsystem Transport Address Heap Object Reference.
 * @NBFT_SSNS_DISCOVERED_NAMESPACE:	 Discovered Namespace Flag: If set to 1h, then
 *					 this namespace was acquired through discovery.
 *					 If cleared to 0h, then this namespace was
 *					 explicitly configured in the system.
 * @NBFT_SSNS_UNAVAIL_NAMESPACE_MASK:	 Mask to get Unavailable Namespace Flag: This
 *					 field indicates the availability of the namespace
 *					 at a specific point in time. Such use is only
 *					 a hint and its use does not guarantee the availability
 *					 of that referenced namespace at any future point in time.
 * @NBFT_SSNS_UNAVAIL_NAMESPACE_NOTIND:	 Not Indicated by Driver: No information is provided.
 * @NBFT_SSNS_UNAVAIL_NAMESPACE_AVAIL:	 Available: A referenced namespace described by this
 *					 flag was previously accessible by the pre-OS driver.
 * @NBFT_SSNS_UNAVAIL_NAMESPACE_UNAVAIL: Unavailable: This namespace was administratively
 *					 configured but unattempted, unavailable or
 *					 inaccessible when establishing connectivity
 *					 by the pre-OS driver.
 */
enum nbft_ssns_flags {
	NBFT_SSNS_VALID				= 1 << 0,
	NBFT_SSNS_NON_BOOTABLE_ENTRY		= 1 << 1,
	NBFT_SSNS_USE_SECURITY_FIELD		= 1 << 2,
	NBFT_SSNS_DHCP_ROOT_PATH_OVERRIDE	= 1 << 3,
	NBFT_SSNS_EXTENDED_INFO_IN_USE		= 1 << 4,
	NBFT_SSNS_SEPARATE_DISCOVERY_CTRL	= 1 << 5,
	NBFT_SSNS_DISCOVERED_NAMESPACE		= 1 << 6,
	NBFT_SSNS_UNAVAIL_NAMESPACE_MASK	= 0x0180,
	NBFT_SSNS_UNAVAIL_NAMESPACE_NOTIND	= 0x0000,
	NBFT_SSNS_UNAVAIL_NAMESPACE_AVAIL	= 0x0080,
	NBFT_SSNS_UNAVAIL_NAMESPACE_UNAVAIL	= 0x0100,
};

/**
 * enum nbft_ssns_trflags - SSNS Transport Specific Flags Field (Figure 17)
 * @NBFT_SSNS_TRFLAG_VALID:	 Transport Specific Flags in Use: If set to 1h, then
 *				 this descriptor is valid. If cleared to 0h, then
 *				 this descriptor is not valid.
 * @NBFT_SSNS_PDU_HEADER_DIGEST: PDU Header Digest (HDGST) Flag: If set to 1h, then
 *				 the host or administrator required the connection
 *				 described by this Subsystem and Namespace Descriptor
 *				 to use the NVM Header Digest Enabled. A consumer
 *				 of this information should attempt to use NVM Header
 *				 Digest when recreating this connection if enabled.
 *				 If cleared to 0h, then the host or administrator
 *				 did not require the connection described by this
 *				 Subsystem and Namespace Descriptor to use the
 *				 NVM Header Digest Enabled.
 * @NBFT_SSNS_DATA_DIGEST:	 Data Digest (DDGST) Flag: If set to 1h, then
 *				 the host or administrator required the connection
 *				 described by this Subsystem and Namespace Descriptor
 *				 to use the NVM Data Digest Enabled. If cleared
 *				 to 0h, then the host or administrator did not
 *				 require the connection described by this Subsystem
 *				 and Namespace Descriptor to use the NVM Data Digest
 *				 Enabled. A consumer of this field should attempt
 *				 to use NVM Data Digest when recreating this
 *				 connection if enabled.
 */
enum nbft_ssns_trflags {
	NBFT_SSNS_TRFLAG_VALID		= 1 << 0,
	NBFT_SSNS_PDU_HEADER_DIGEST	= 1 << 1,
	NBFT_SSNS_DATA_DIGEST		= 1 << 2,
};

/**
 * struct nbft_ssns_ext_info - Subsystem and Namespace Extended Information
 *			       Descriptor (Figure 19)
 * @structure_id:	    Structure ID: This field shall be set to 9h
 *			    (i.e., SSNS Extended Info; #NBFT_DESC_SSNS_EXT_INFO).
 * @version:		    Version: This field shall be set to 1h.
 * @ssns_index:		    SSNS Descriptor Index: This field indicates the value
 *			    of the SSNS Descriptor Index field of the Subsystem
 *			    and Namespace Descriptor (see &struct nbft_ssns) whose
 *			    SSNS Extended Information Descriptor Heap Object
 *			    Reference field indicates this descriptor.
 * @flags:		    Flags, see &enum nbft_ssns_ext_info_flags.
 * @cntlid:		    Controller ID: The controller identifier of the first
 *			    controller associated with the Admin Queue by the driver.
 *			    If a controller identifier is not administratively
 *			    specified or direct configuration is not supported
 *			    by the driver, then this field shall be cleared to 0h.
 * @asqsz:		    Admin Submission Queue Size (ASQSZ): The Admin Submission
 *			    Queue Size utilized for the respective SSNS by the driver.
 * @dhcp_root_path_str_obj: DHCP Root Path String Heap Object Reference: If the
 *			    SSNS DHCP Root Path Override (#NBFT_SSNS_DHCP_ROOT_PATH_OVERRIDE)
 *			    flag bit is set to 1h, then this field indicates
 *			    the offset in bytes of a heap object containing
 *			    an DHCP Root Path String used by the driver. If the
 *			    SNSS DHCP Root Path Override flag bit is cleared to 0h,
 *			    then this field is reserved.
 */
struct nbft_ssns_ext_info {
	__u8 structure_id;
	__u8 version;
	__le16 ssns_index;
	__le32 flags;
	__le16 cntlid;
	__le16 asqsz;
	struct nbft_heap_obj dhcp_root_path_str_obj;
} __attribute__((packed));

/**
 * enum nbft_ssns_ext_info_flags - Subsystem and Namespace Extended Information
 *				   Descriptor Flags
 * @NBFT_SSNS_EXT_INFO_VALID:	    Descriptor Valid: If set to 1h, then this descriptor
 *				    is valid. If cleared to 0h, then this descriptor
 *				    is reserved.
 * @NBFT_SSNS_EXT_INFO_ADMIN_ASQSZ: Administrative ASQSZ: If set to 1h, then the value
 *				    of the ASQSZ field was provided by administrative
 *				    configuration for this SSNS record. If cleared
 *				    to 0h, then the value of the ASQSZ field was
 *				    either obtained by discovery or assumed
 *				    by the driver.
 */
enum nbft_ssns_ext_info_flags {
	NBFT_SSNS_EXT_INFO_VALID	= 1 << 0,
	NBFT_SSNS_EXT_INFO_ADMIN_ASQSZ	= 1 << 1,
};

/**
 * struct nbft_security - Security Profile Descriptor (Figure 21)
 * @structure_id:      Structure ID: This field shall be set to 5h
 *		       (i.e., Security; #NBFT_DESC_SECURITY).
 * @index:	       Security Profile Descriptor Index: This field indicates
 *		       the number of this Security Profile Descriptor in the
 *		       Security Profile Descriptor List.
 * @flags:	       Security Profile Descriptor Flags, see &enum nbft_security_flags.
 * @secret_type:       Secret Type, see &enum nbft_security_secret_type.
 * @reserved1:	       Reserved.
 * @sec_chan_alg_obj:  Secure Channel Algorithm Heap Object Reference: If the
 *		       Security Policy List field is set to 1h, then this field
 *		       indicates the location and size of a heap object containing
 *		       a list of secure channel algorithms. The list is an array
 *		       of bytes and the values are defined in the Security Type
 *		       (SECTYPE) field in the Transport Specific Address Subtype
 *		       Definition in the NVMe TCP Transport Specification.
 *		       If the Security Policy List field is cleared to 0h, then
 *		       this field is reserved.
 * @auth_proto_obj:    Authentication Protocols Heap Object Reference: If the
 *		       Authentication Policy List field is set to 1h, then this
 *		       field indicates the location and size of a heap object
 *		       containing a list of authentication protocol identifiers.
 *		       If the Authentication Policy List field is cleared to 0h,
 *		       then this field is reserved.
 * @cipher_suite_obj:  Cipher Suite Offset Heap Object Reference: If the Cipher
 *		       Suites Restricted by Policy bit is set to 1h, then this
 *		       field indicates the location and size of a heap object
 *		       containing a list of cipher suite identifiers. The list,
 *		       if any, is an array of bytes and the values are defined
 *		       in the IANA TLS Parameters Registry. If the Cipher Suites
 *		       Restricted by Policy bit is cleared to 0h, then this field
 *		       is reserved.
 * @dh_grp_obj:	       DH Groups Heap Object Reference: If the Authentication DH Groups
 *		       Restricted by Policy List bit is set to 1h, then this field
 *		       indicates the location and size of a heap object containing
 *		       a list of DH-HMAC-CHAP Diffie-Hellman (DH) group identifiers.
 *		       If the Authentication DH Groups Restricted by Policy List
 *		       bit is cleared to 0h, then this field is reserved.
 * @sec_hash_func_obj: Secure Hash Functions Offset Heap Object Reference: If the
 *		       Secure Hash Functions Policy List bit is set to 1h, then
 *		       this field indicates the offset in bytes of a heap object
 *		       containing a list of DH-HMAC-CHAP hash function identifiers.
 *		       The list is an array of bytes and the values are defined
 *		       in the NVM Express Base Specification. If the Secure Hash
 *		       Functions Policy List bit is cleared to 0h, then this
 *		       field is reserved.
 * @sec_keypath_obj:   Secret Keypath Offset Heap Object Reference: if this field
 *		       is set to a non-zero value, then this field indicates
 *		       the location and size of a heap object containing a URI.
 *		       The type of the URI is specified in the Secret Type field.
 *		       If this field is cleared to 0h, then this field is reserved.
 * @reserved2:	       Reserved.
 */
struct nbft_security {
	__u8 structure_id;
	__u8 index;
	__le16 flags;
	__u8 secret_type;
	__u8 reserved1;
	struct nbft_heap_obj sec_chan_alg_obj;
	struct nbft_heap_obj auth_proto_obj;
	struct nbft_heap_obj cipher_suite_obj;
	struct nbft_heap_obj dh_grp_obj;
	struct nbft_heap_obj sec_hash_func_obj;
	struct nbft_heap_obj sec_keypath_obj;
	__u8 reserved2[22];
};

/**
 * enum nbft_security_flags - Security Profile Descriptor Flags (Figure 22)
 * @NBFT_SECURITY_VALID:			  Descriptor Valid: If set to 1h, then
 *						  this descriptor is valid. If cleared
 *						  to 0h, then this descriptor is not valid.
 * @NBFT_SECURITY_IN_BAND_AUTH_MASK:		  Mask to get the In-Band Authentication
 *						  Required field.
 * @NBFT_SECURITY_IN_BAND_AUTH_NOT_SUPPORTED:	  In-band authentication is not supported
 *						  by the NVM subsystem.
 * @NBFT_SECURITY_IN_BAND_AUTH_NOT_REQUIRED:	  In-band authentication is supported by
 *						  the NVM subsystem and is not required.
 * @NBFT_SECURITY_IN_BAND_AUTH_REQUIRED:	  In-band authentication is supported by
 *						  the NVM subsystem and is required.
 * @NBFT_SECURITY_AUTH_POLICY_LIST_MASK:	  Mask to get the Authentication Policy List
 *						  flag: This field indicates whether
 *						  authentication protocols were indicated
 *						  by policy from driver defaults or
 *						  administrative configuration.
 * @NBFT_SECURITY_AUTH_POLICY_LIST_NOT_SUPPORTED: Authentication Protocols Heap Object Reference
 *						  field Offset and Length are reserved.
 * @NBFT_SECURITY_AUTH_POLICY_LIST_DRIVER:	  Authentication Protocols Offset field and
 *						  the Authentication Protocols Length field
 *						  indicate a list of authentication protocols
 *						  used by the driver.
 * @NBFT_SECURITY_AUTH_POLICY_LIST_ADMIN:	  Authentication Protocols Offset field and
 *						  the Authentication Protocols Length field
 *						  indicate a list of authentication protocols
 *						  that were administratively set and used
 *						  by the driver.
 * @NBFT_SECURITY_SEC_CHAN_NEG_MASK:		  Mask to get the Secure Channel Negotiation
 *						  Required flag: This field indicates whether
 *						  secure channel negotiation (e.g. TLS)
 *						  is required.
 * @NBFT_SECURITY_SEC_CHAN_NEG_NOT_SUPPORTED:	  Secure channel negotiation is not supported
 *						  by the NVM subsystem.
 * @NBFT_SECURITY_SEC_CHAN_NEG_NOT_REQUIRED:	  Secure channel negotiation is supported
 *						  by the NVM subsystem and is not required.
 * @NBFT_SECURITY_SEC_CHAN_NEG_REQUIRED:	  Secure channel negotiation is supported
 *						  by the NVM subsystem and is required.
 * @NBFT_SECURITY_SEC_POLICY_LIST_MASK:		  Mask to get the Security Policy List flag:
 *						  This field indicates whether secure channel
 *						  protocols were indicated by policy from driver
 *						  defaults or administrative configuration.
 * @NBFT_SECURITY_SEC_POLICY_LIST_NOT_SUPPORTED:  The Offset field and Length field in the
 *						  Secure Channel Algorithm Heap Object Reference
 *						  field are reserved.
 * @NBFT_SECURITY_SEC_POLICY_LIST_DRIVER:	  The Heap Object specified by the Secure Channel
 *						  Algorithm Heap Object Reference field indicates
 *						  a list of authentication protocols used
 *						  by the driver.
 * @NBFT_SECURITY_SEC_POLICY_LIST_ADMIN:	  The Heap Object specified by the Secure Channel
 *						  Algorithm Heap Object Reference field indicates
 *						  a list of authentication protocols that were
 *						  administratively set and used by the driver.
 * @NBFT_SECURITY_CIPHER_RESTRICTED:		  Cipher Suites Restricted by Policy: If set to 1h,
 *						  then the Cipher Suite Offset field and the
 *						  Ciper Suite Length field indicate a list
 *						  of supported cipher suites by the driver.
 *						  If cleared to 0h, then the Cipher Suite Offset
 *						  field and the Cipher Suite Length field
 *						  are reserved.
 * @NBFT_SECURITY_AUTH_DH_GROUPS_RESTRICTED:	  Authentication DH Groups Restricted
 *						  by Policy List: If set to 1h, then connections
 *						  shall use one of the authentication DH groups
 *						  in the Authentication DH Groups List is required.
 *						  If cleared to 0h, then no Authentication DH Groups
 *						  List is indicated and use of an authentication
 *						  DH Group is not required.
 * @NBFT_SECURITY_SEC_HASH_FUNC_POLICY_LIST:	  Secure Hash Functions Policy List: If set to 1h,
 *						  then connections shall use one of the secure
 *						  hash functions in the Secure Hash Functions
 *						  Policy List is required. If cleared to 0h,
 *						  then no Secure Hash Functions Policy
 *						  List is indicated and use of a secure
 *						  hash function is not required.
 */
enum nbft_security_flags {
	NBFT_SECURITY_VALID				= 1 << 0,
	NBFT_SECURITY_IN_BAND_AUTH_MASK			= 0x0006,
	NBFT_SECURITY_IN_BAND_AUTH_NOT_SUPPORTED	= 0x0000,
	NBFT_SECURITY_IN_BAND_AUTH_NOT_REQUIRED		= 0x0002,
	NBFT_SECURITY_IN_BAND_AUTH_REQUIRED		= 0x0004,
	NBFT_SECURITY_AUTH_POLICY_LIST_MASK		= 0x0018,
	NBFT_SECURITY_AUTH_POLICY_LIST_NOT_SUPPORTED	= 0x0000,
	NBFT_SECURITY_AUTH_POLICY_LIST_DRIVER		= 0x0008,
	NBFT_SECURITY_AUTH_POLICY_LIST_ADMIN		= 0x0010,
	NBFT_SECURITY_SEC_CHAN_NEG_MASK			= 0x0060,
	NBFT_SECURITY_SEC_CHAN_NEG_NOT_SUPPORTED	= 0x0000,
	NBFT_SECURITY_SEC_CHAN_NEG_NOT_REQUIRED		= 0x0020,
	NBFT_SECURITY_SEC_CHAN_NEG_REQUIRED		= 0x0040,
	NBFT_SECURITY_SEC_POLICY_LIST_MASK		= 0x0180,
	NBFT_SECURITY_SEC_POLICY_LIST_NOT_SUPPORTED	= 0x0000,
	NBFT_SECURITY_SEC_POLICY_LIST_DRIVER		= 0x0080,
	NBFT_SECURITY_SEC_POLICY_LIST_ADMIN		= 0x0100,
	NBFT_SECURITY_CIPHER_RESTRICTED			= 1 << 9,
	NBFT_SECURITY_AUTH_DH_GROUPS_RESTRICTED		= 1 << 10,
	NBFT_SECURITY_SEC_HASH_FUNC_POLICY_LIST		= 1 << 11,
};

/**
 * enum nbft_security_secret_type - Security Profile Descriptor Secret Type
 * @NBFT_SECURITY_SECRET_REDFISH_HOST_IFACE_URI: Redfish Host Interface URI:
 *						 If set to 1h, then the Secret Keypath
 *						 Object Reference is a URI pointing
 *						 to a Redfish Key Collection Object
 *						 that contains the PSK.
 */
enum nbft_security_secret_type {
	NBFT_SECURITY_SECRET_REDFISH_HOST_IFACE_URI	= 1 << 1,
};

/**
 * struct nbft_discovery - Discovery Descriptor (Figure 24)
 * @structure_id:	     Structure ID: This field shall be set to 6h
 *			     (i.e., Discovery Descriptor; #NBFT_DESC_DISCOVERY).
 * @flags:		     Discovery Descriptor Flags, see &enum nbft_discovery_flags.
 * @index:		     Discovery Descriptor Index: This field indicates
 *			     the number of this Discovery Descriptor in
 *			     the Discovery Descriptor List.
 * @hfi_index:		     HFI Descriptor Index: This field indicates the value
 *			     of the HFI Descriptor Index field of the HFI Descriptor
 *			     associated with this Discovery Descriptor. If multiple
 *			     HFIs share a common Discovery controller, there shall
 *			     be multiple Discovery Descriptor entries with one per HFI.
 * @sec_index:		     Security Profile Descriptor Index: This field indicates
 *			     the value of the Security Profile Descriptor Index
 *			     field of the Security Descriptor associated with
 *			     this Discovery Descriptor.
 * @reserved1:		     Reserved.
 * @discovery_ctrl_addr_obj: Discovery Controller Address Heap Object Reference:
 *			     This field indicates the location and size of a heap
 *			     object containing a URI which indicates an NVMe Discovery
 *			     controller associated with this Discovery Descriptor.
 *			     If this field is cleared to 0h, then no URI is specified.
 * @discovery_ctrl_nqn_obj:  Discovery Controller NQN Heap Object Reference:
 *			     If set to a non-zero value, this field indicates
 *			     the location and size of a heap object containing
 *			     an NVMe Discovery controller NQN. If the NVMe Discovery
 *			     controller referenced by this record requires secure
 *			     authentication with a well known Subsystem NQN, this
 *			     field indicates the unique NQN for that NVMe Discovery
 *			     controller. This record is involved formatted as an NQN
 *			     string. If this field is cleared to 0h, then this
 *			     field is reserved and the OS shall use the well
 *			     known discovery NQN for this record.
 * @reserved2:		     Reserved.
 */
struct nbft_discovery {
	__u8 structure_id;
	__u8 flags;
	__u8 index;
	__u8 hfi_index;
	__u8 sec_index;
	__u8 reserved1;
	struct nbft_heap_obj discovery_ctrl_addr_obj;
	struct nbft_heap_obj discovery_ctrl_nqn_obj;
	__u8 reserved2[14];
};

/**
 * enum nbft_discovery_flags - Discovery Descriptor Flags
 * @NBFT_DISCOVERY_VALID: Descriptor Valid: if set to 1h, then this descriptor
 *			  is valid. If cleared to 0h, then this descriptor
 *			  is reserved.
 */
enum nbft_discovery_flags {
	NBFT_DISCOVERY_VALID	= 1 << 0,
};

/*
 *  End of NBFT ACPI table definitions
 */


/*
 *  Convenient NBFT table parser ('nbft_info' prefix)
 */

/**
 * enum nbft_info_primary_admin_host_flag - Primary Administrative Host Descriptor Flags
 * @NBFT_INFO_PRIMARY_ADMIN_HOST_FLAG_NOT_INDICATED: Not Indicated by Driver: The driver
 * 						     that created this NBFT provided no
 * 						     administrative priority hint for
 * 						     this NBFT.
 * @NBFT_INFO_PRIMARY_ADMIN_HOST_FLAG_UNSELECTED:    Unselected: The driver that created
 * 						     this NBFT explicitly indicated that
 * 						     this NBFT should not be prioritized
 * 						     over any other NBFT.
 * @NBFT_INFO_PRIMARY_ADMIN_HOST_FLAG_SELECTED:	     Selected: The driver that created
 * 						     this NBFT explicitly indicated that
 * 						     this NBFT should be prioritized over
 * 						     any other NBFT.
 * @NBFT_INFO_PRIMARY_ADMIN_HOST_FLAG_RESERVED:	     Reserved.
 */
enum nbft_info_primary_admin_host_flag {
	NBFT_INFO_PRIMARY_ADMIN_HOST_FLAG_NOT_INDICATED,
	NBFT_INFO_PRIMARY_ADMIN_HOST_FLAG_UNSELECTED,
	NBFT_INFO_PRIMARY_ADMIN_HOST_FLAG_SELECTED,
	NBFT_INFO_PRIMARY_ADMIN_HOST_FLAG_RESERVED,
};

/**
 * struct nbft_info_host - Host Descriptor
 * @id:			 Host ID (raw UUID, length = 16 bytes).
 * @nqn:		 Host NQN.
 * @host_id_configured:	 HostID Configured Flag: value of True indicates that @id
 * 			 contains administratively-configured value, or driver
 * 			 default value if False.
 * @host_nqn_configured: Host NQN Configured Flag: value of True indicates that
 * 			 @nqn contains administratively-configured value,
 * 			 or driver default value if False.
 * @primary:		 Primary Administrative Host Descriptor, see
 * 			 &enum nbft_info_primary_admin_host_flag.
 */
struct nbft_info_host {
	unsigned char *id;
	char *nqn;
	bool host_id_configured;
	bool host_nqn_configured;
	enum nbft_info_primary_admin_host_flag primary;
};

/**
 * struct nbft_info_hfi_info_tcp - HFI Transport Info Descriptor - NVMe/TCP
 * @pci_sbdf:		       PCI Express Routing ID for the HFI Transport Function.
 * @mac_addr:		       MAC Address: The MAC address of this HFI,
 * 			       in EUI-48TM format.
 * @vlan:		       The VLAN identifier if the VLAN is associated with
 * 			       this HFI, as defined in IEEE 802.1q-2018 or zeroes
 * 			       if no VLAN is associated with this HFI.
 * @ip_origin:		       The source of Ethernet L3 configuration information
 * 			       used by the driver or 0 if not used.
 * @ipaddr:		       The IPv4 or IPv6 address of this HFI.
 * @subnet_mask_prefix:	       The IPv4 or IPv6 subnet mask in CIDR routing prefix
 * 			       notation.
 * @gateway_ipaddr:	       The IPv4 or IPv6 address of the IP gateway for this
 * 			       HFI or zeroes if no IP gateway is specified.
 * @route_metric:	       The cost value for the route indicated by this HFI.
 * @primary_dns_ipaddr:	       The IPv4 or IPv6 address of the Primary DNS server
 * 			       for this HFI.
 * @secondary_dns_ipaddr:      The IPv4 or IPv6 address of the Secondary DNS server
 * 			       for this HFI.
 * @dhcp_server_ipaddr:	       The IPv4 or IPv6 address of the DHCP server used
 * 			       to assign this HFI address.
 * @host_name:		       The Host Name string.
 * @this_hfi_is_default_route: If True, then the BIOS utilized this interface
 * 			       described by HFI to be the default route with highest
 * 			       priority. If False, then routes are local to their
 * 			       own scope.
 * @dhcp_override:	       If True, then HFI information was populated
 * 			       by consuming the DHCP on this interface. If False,
 * 			       then the HFI information was set administratively
 * 			       by a configuration interface to the driver and
 * 			       pre-OS envrionment.
 */
struct nbft_info_hfi_info_tcp {
	__u32 pci_sbdf;
	__u8 mac_addr[6];
	__u16 vlan;
	__u8 ip_origin;
	char ipaddr[40];
	__u8 subnet_mask_prefix;
	char gateway_ipaddr[40];
	__u16 route_metric;
	char primary_dns_ipaddr[40];
	char secondary_dns_ipaddr[40];
	char dhcp_server_ipaddr[40];
	char *host_name;
	bool this_hfi_is_default_route;
	bool dhcp_override;
};

/**
 * struct nbft_info_hfi - Host Fabric Interface (HFI) Descriptor
 * @index:     HFI Descriptor Index: indicates the number of this HFI Descriptor
 * 	       in the Host Fabric Interface Descriptor List.
 * @transport: Transport Type string (e.g. 'tcp').
 * @tcp_info:  The HFI Transport Info Descriptor, see &struct nbft_info_hfi_info_tcp.
 */
struct nbft_info_hfi {
	int index;
	char transport[8];
	struct nbft_info_hfi_info_tcp tcp_info;
};

/**
 * struct nbft_info_discovery - Discovery Descriptor
 * @index:    The number of this Discovery Descriptor in the Discovery
 * 	      Descriptor List.
 * @security: The Security Profile Descriptor, see &struct nbft_info_security.
 * @hfi:      The HFI Descriptor associated with this Discovery Descriptor.
 * 	      See &struct nbft_info_hfi.
 * @uri:      A URI which indicates an NVMe Discovery controller associated
 * 	      with this Discovery Descriptor.
 * @nqn:      An NVMe Discovery controller NQN.
 */
struct nbft_info_discovery {
	int index;
	struct nbft_info_security *security;
	struct nbft_info_hfi *hfi;
	char *uri;
	char *nqn;
};

/**
 * struct nbft_info_security - Security Profile Descriptor
 * @index: The number of this Security Profile Descriptor in the Security
 * 	   Profile Descriptor List.
 */
struct nbft_info_security {
	int index;
	/* TODO add fields */
};

/**
 * enum nbft_info_nid_type - Namespace Identifier Type (NIDT)
 * @NBFT_INFO_NID_TYPE_NONE:	No identifier available.
 * @NBFT_INFO_NID_TYPE_EUI64:	The EUI-64 identifier.
 * @NBFT_INFO_NID_TYPE_NGUID:	The NSGUID identifier.
 * @NBFT_INFO_NID_TYPE_NS_UUID:	The UUID identifier.
 */
enum nbft_info_nid_type {
	NBFT_INFO_NID_TYPE_NONE		= 0,
	NBFT_INFO_NID_TYPE_EUI64	= 1,
	NBFT_INFO_NID_TYPE_NGUID	= 2,
	NBFT_INFO_NID_TYPE_NS_UUID	= 3,
};

/**
 * struct nbft_info_subsystem_ns - Subsystem Namespace (SSNS) info
 * @index: 			SSNS Descriptor Index in the descriptor list.
 * @discovery:			Primary Discovery Controller associated with
 * 				this SSNS Descriptor.
 * @security:			Security Profile Descriptor associated with
 * 				this namespace.
 * @num_hfis:			Number of HFIs.
 * @hfis:			List of HFIs associated with this namespace.
 * 				Includes the primary HFI at the first position
 * 				and all secondary HFIs. This array is null-terminated.
 * @transport:			Transport Type string (e.g. 'tcp').
 * @traddr:			Subsystem Transport Address.
 * @trsvcid:			Subsystem Transport Service Identifier.
 * @subsys_port_id:		The Subsystem Port ID.
 * @nsid:			The Namespace ID of this descriptor or when @nid
 * 				should be used instead.
 * @nid_type:			Namespace Identifier Type, see &enum nbft_info_nid_type.
 * @nid:			The Namespace Identifier value.
 * @subsys_nqn:			Subsystem and Namespace NQN.
 * @pdu_header_digest_required:	PDU Header Digest (HDGST) Flag: the use of NVM Header
 * 				Digest Enabled is required.
 * @data_digest_required: 	Data Digest (DDGST) Flag: the use of NVM Data Digest
 * 				Enabled is required.
 * @controller_id:		Controller ID (SSNS Extended Information Descriptor):
 * 				The controller ID associated with the Admin Queue
 * 				or 0 if not supported.
 * @asqsz:			Admin Submission Queue Size (SSNS Extended Information
 * 				Descriptor) or 0 if not supported.
 * @dhcp_root_path_string:	DHCP Root Path Override string (SSNS Extended
 * 				Information Descriptor).
 */
struct nbft_info_subsystem_ns {
	int index;
	struct nbft_info_discovery *discovery;
	struct nbft_info_security *security;
	int num_hfis;
	struct nbft_info_hfi **hfis;
	char transport[8];
	char traddr[40];
	char *trsvcid;
	__u16 subsys_port_id;
	__u32 nsid;
	enum nbft_info_nid_type nid_type;
	__u8 *nid;
	char *subsys_nqn;
	bool pdu_header_digest_required;
	bool data_digest_required;
	int controller_id;
	int asqsz;
	char *dhcp_root_path_string;
};

/**
 * struct nbft_info - The parsed NBFT table data.
 * @filename:	       Path to the NBFT table.
 * @raw_nbft:	       The original NBFT table contents.
 * @raw_nbft_size:     Size of @raw_nbft.
 * @host:	       The Host Descriptor (should match other NBFTs).
 * @hfi_list:	       The HFI Descriptor List (null-terminated array).
 * @security_list:     The Security Profile Descriptor List (null-terminated array).
 * @discovery_list:    The Discovery Descriptor List (null-terminated array).
 * @subsystem_ns_list: The SSNS Descriptor List (null-terminated array).
 */
struct nbft_info {
	char *filename;
	__u8 *raw_nbft;
	ssize_t raw_nbft_size;
	struct nbft_info_host host;
	struct nbft_info_hfi **hfi_list;
	struct nbft_info_security **security_list;
	struct nbft_info_discovery **discovery_list;
	struct nbft_info_subsystem_ns **subsystem_ns_list;
};

/**
 * nvme_nbft_read() - Read and parse contents of an ACPI NBFT table
 *
 * @nbft:     Parsed NBFT table data.
 * @filename: Filename of the raw NBFT table to read.
 *
 * Read and parse the specified NBFT file into a struct nbft_info.
 * Free with nvme_nbft_free().
 *
 * Return: 0 on success, errno otherwise.
 */
int nvme_nbft_read(struct nbft_info **nbft, const char *filename);

/**
 * nvme_nbft_free() - Free the struct nbft_info and its contents
 * @nbft: Parsed NBFT table data.
 */
void nvme_nbft_free(struct nbft_info *nbft);

#endif
