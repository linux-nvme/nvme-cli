/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * This file is part of libnvme.
 * Copyright (c) 2021-2022, Dell Inc. or its subsidiaries.  All Rights Reserved.
 *
 * Authors: Stuart Hayes <Stuart_Hayes@Dell.com>
 *
 */
#pragma once

#include <stdbool.h>

#include <sys/types.h>

#include <nvme/nbft-types.h>

/**
 * enum nbft_info_primary_admin_host_flag - Primary Administrative Host Descriptor Flags
 * @NBFT_INFO_PRIMARY_ADMIN_HOST_FLAG_NOT_INDICATED: Not Indicated by Driver: The driver
 *						     that created this NBFT provided no
 *						     administrative priority hint for
 *						     this NBFT.
 * @NBFT_INFO_PRIMARY_ADMIN_HOST_FLAG_UNSELECTED:    Unselected: The driver that created
 *						     this NBFT explicitly indicated that
 *						     this NBFT should not be prioritized
 *						     over any other NBFT.
 * @NBFT_INFO_PRIMARY_ADMIN_HOST_FLAG_SELECTED:	     Selected: The driver that created
 *						     this NBFT explicitly indicated that
 *						     this NBFT should be prioritized over
 *						     any other NBFT.
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
 *			 contains administratively-configured value, or driver
 *			 default value if False.
 * @host_nqn_configured: Host NQN Configured Flag: value of True indicates that
 *			 @nqn contains administratively-configured value,
 *			 or driver default value if False.
 * @primary:		 Primary Administrative Host Descriptor, see
 *			 &enum nbft_info_primary_admin_host_flag.
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
 *			       in EUI-48TM format.
 * @vlan:		       The VLAN identifier if the VLAN is associated with
 *			       this HFI, as defined in IEEE 802.1q-2018 or zeroes
 *			       if no VLAN is associated with this HFI.
 * @ip_origin:		       The source of Ethernet L3 configuration information
 *			       used by the driver or 0 if not used.
 * @ipaddr:		       The IPv4 or IPv6 address of this HFI.
 * @subnet_mask_prefix:	       The IPv4 or IPv6 subnet mask in CIDR routing prefix
 *			       notation.
 * @gateway_ipaddr:	       The IPv4 or IPv6 address of the IP gateway for this
 *			       HFI or zeroes if no IP gateway is specified.
 * @route_metric:	       The cost value for the route indicated by this HFI.
 * @primary_dns_ipaddr:	       The IPv4 or IPv6 address of the Primary DNS server
 *			       for this HFI.
 * @secondary_dns_ipaddr:      The IPv4 or IPv6 address of the Secondary DNS server
 *			       for this HFI.
 * @dhcp_server_ipaddr:	       The IPv4 or IPv6 address of the DHCP server used
 *			       to assign this HFI address.
 * @host_name:		       The Host Name string.
 * @this_hfi_is_default_route: If True, then the BIOS utilized this interface
 *			       described by HFI to be the default route with highest
 *			       priority. If False, then routes are local to their
 *			       own scope.
 * @dhcp_override:	       If True, then HFI information was populated
 *			       by consuming the DHCP on this interface. If False,
 *			       then the HFI information was set administratively
 *			       by a configuration interface to the driver and
 *			       pre-OS envrionment.
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
 *	       in the Host Fabric Interface Descriptor List.
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
 *	      Descriptor List.
 * @security: The Security Profile Descriptor, see &struct nbft_info_security.
 * @hfi:      The HFI Descriptor associated with this Discovery Descriptor.
 *	      See &struct nbft_info_hfi.
 * @uri:      A URI which indicates an NVMe Discovery controller associated
 *	      with this Discovery Descriptor.
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
 *	   Profile Descriptor List.
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
 * @index:			SSNS Descriptor Index in the descriptor list.
 * @discovery:			Primary Discovery Controller associated with
 *				this SSNS Descriptor.
 * @security:			Security Profile Descriptor associated with
 *				this namespace.
 * @num_hfis:			Number of HFIs.
 * @hfis:			List of HFIs associated with this namespace.
 *				Includes the primary HFI at the first position
 *				and all secondary HFIs. This array is null-terminated.
 * @transport:			Transport Type string (e.g. 'tcp').
 * @traddr:			Subsystem Transport Address.
 * @trsvcid:			Subsystem Transport Service Identifier.
 * @subsys_port_id:		The Subsystem Port ID.
 * @nsid:			The Namespace ID of this descriptor or when @nid
 *				should be used instead.
 * @nid_type:			Namespace Identifier Type, see &enum nbft_info_nid_type.
 * @nid:			The Namespace Identifier value.
 * @subsys_nqn:			Subsystem and Namespace NQN.
 * @pdu_header_digest_required:	PDU Header Digest (HDGST) Flag: the use of NVM Header
 *				Digest Enabled is required.
 * @data_digest_required:	Data Digest (DDGST) Flag: the use of NVM Data Digest
 *				Enabled is required.
 * @controller_id:		Controller ID (SSNS Extended Information Descriptor):
 *				The controller ID associated with the Admin Queue
 *				or 0 if not supported.
 * @asqsz:			Admin Submission Queue Size (SSNS Extended Information
 *				Descriptor) or 0 if not supported.
 * @dhcp_root_path_string:	DHCP Root Path Override string (SSNS Extended
 *				Information Descriptor).
 * @discovered:			Indicates that this namespace was acquired
 *				through discovery.
 * @unavailable:		Namespace is unavailable as indicated by
 *				the pre-OS driver.
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
	bool discovered;
	bool unavailable;
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
 * libnvme_read_nbft() - Read and parse contents of an ACPI NBFT table
 *
 * @ctx:      struct libnvme_global_ctx object
 * @nbft:     Parsed NBFT table data.
 * @filename: Filename of the raw NBFT table to read.
 *
 * Read and parse the specified NBFT file into a struct nbft_info.
 * Free with libnvme_free_nbft().
 *
 * Return: 0 on success, errno otherwise.
 */
int libnvme_read_nbft(struct libnvme_global_ctx *ctx, struct nbft_info **nbft,
		const char *filename);

/**
 * libnvme_free_nbft() - Free the struct nbft_info and its contents
 * @ctx: struct libnvme_global_ctx object
 * @nbft: Parsed NBFT table data.
 */
void libnvme_free_nbft(struct libnvme_global_ctx *ctx, struct nbft_info *nbft);

/**
 * struct nbft_file_entry - Linked list entry for NBFT files
 * @next: Pointer to next entry
 * @nbft: Pointer to NBFT info structure
 */
struct nbft_file_entry {
	struct nbft_file_entry *next;
	struct nbft_info *nbft;
};
