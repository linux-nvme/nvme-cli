/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * This file is part of libnvme.
 * Copyright (c) 2021-2022, Dell Inc. or its subsidiaries.  All Rights Reserved.
 *
 * Authors: Stuart Hayes <Stuart_Hayes@Dell.com>
 *
 */
#pragma once

#include <sys/types.h>

#include <nvme/nvme-types-nbft.h>

/**
 * struct libnbft_host - Host Descriptor
 * @id:	   Host ID (raw UUID, length = 16 bytes).
 * @nqn:   Host NQN.
 * @flags: Host Descriptor Flags bitmask, see &enum nbft_host_flags.
 */
struct libnbft_host {
	unsigned char *id;
	char *nqn;
	__u8 flags;
};

/**
 * struct libnbft_hfi_info_tcp - HFI Transport Info Descriptor - NVMe/TCP
 * @pci_sbdf:		  PCI Express Routing ID for the HFI Transport Function.
 * @mac_addr:		  MAC Address: The MAC address of this HFI,
 *			  in EUI-48TM format.
 * @vlan:		  The VLAN identifier if the VLAN is associated with
 *			  this HFI, as defined in IEEE 802.1q-2018 or zeroes
 *			  if no VLAN is associated with this HFI.
 * @ip_origin:		  The source of Ethernet L3 configuration information
 *			  used by the driver or 0 if not used.
 * @ipaddr:		  The IPv4 or IPv6 address of this HFI.
 * @subnet_mask_prefix:	  The IPv4 or IPv6 subnet mask in CIDR routing prefix
 *			  notation.
 * @gateway_ipaddr:	  The IPv4 or IPv6 address of the IP gateway for this
 *			  HFI or zeroes if no IP gateway is specified.
 * @route_metric:	  The cost value for the route indicated by this HFI.
 * @primary_dns_ipaddr:	  The IPv4 or IPv6 address of the Primary DNS server
 *			  for this HFI.
 * @secondary_dns_ipaddr: The IPv4 or IPv6 address of the Secondary DNS server
 *			  for this HFI.
 * @dhcp_server_ipaddr:	  The IPv4 or IPv6 address of the DHCP server used
 *			  to assign this HFI address.
 * @host_name:		  The Host Name string.
 * @flags:		  HFI Transport Flags bitmask,
 *			  see &enum nbft_hfi_info_tcp_flags.
 * @pcie_seg_num:	  The PCIe Segment Number for the HFI Transport
 *			  Function when the PCI Express Link is in Flit mode.
 *			  Zero if not in Flit mode, not supported, or the NBFT
 *			  data originates from a pre-NBFT rev. 1.1 driver.
 * @dhcp_iaid:		  The DHCP Identity Association Identifier (IAID)
 *			  as defined in RFC 4361. The IAID is a 32-bit value
 *			  that uniquely identifies the client's network
 *			  interface for DHCP purposes. NBFT rev. 1.1+;
 *			  meaningful when @dhcp_duid_len is non-zero.
 * @dhcp_duid:		  The raw DHCP Unique Identifier (DUID) as defined
 *			  in RFC 8415 section 11 (NBFT rev. 1.1+).
 *			  This is the complete DUID including its
 *			  leading 2-byte type code followed by up to 128
 *			  bytes of type-specific identifier data.
 *			  Known DUID type codes are: 1 (DUID-LLT, link-layer
 *			  address plus time), 2 (DUID-EN, vendor-assigned
 *			  based on enterprise number), 3 (DUID-LL, link-layer
 *			  address), 4 (DUID-UUID, universally unique
 *			  identifier). Multi-byte fields within the DUID are
 *			  stored in little-endian byte order as specified by
 *			  the NVMe Boot Specification. The consumer is
 *			  responsible for parsing the type code and the
 *			  type-specific data. This is a local copy of the
 *			  data from the NBFT heap. This array is zero-filled
 *			  when the DUID is not present; check @dhcp_duid_len.
 * @dhcp_duid_len:	  The number of valid bytes in @dhcp_duid, ranging
 *			  from 3 (minimum: 2-byte type code plus at least
 *			  1 byte of data) to 130 (maximum per RFC 8415).
 *			  NBFT rev. 1.1+. A value of zero indicates that
 *			  no DUID is present and both @dhcp_duid and
 *			  @dhcp_iaid should be ignored.
 */
struct libnbft_hfi_info_tcp {
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
	__u8 flags;
	__u8 pcie_seg_num;
	__u32 dhcp_iaid;
	__u8 dhcp_duid[130];
	__u8 dhcp_duid_len;
};

/**
 * struct libnbft_hfi - Host Fabric Interface (HFI) Descriptor
 * @index:     HFI Descriptor Index: indicates the number of this HFI Descriptor
 *	       in the Host Fabric Interface Descriptor List.
 * @transport: Transport Type string (e.g. 'tcp').
 * @tcp_info:  The HFI Transport Info Descriptor, see &struct libnbft_hfi_info_tcp.
 */
struct libnbft_hfi {
	int index;
	char transport[8];
	struct libnbft_hfi_info_tcp tcp_info;
};

/**
 * struct libnbft_discovery - Discovery Descriptor
 * @index:    The number of this Discovery Descriptor in the Discovery
 *	      Descriptor List.
 * @security: The Security Profile Descriptor, see &struct libnbft_security.
 * @hfi:      The HFI Descriptor associated with this Discovery Descriptor.
 *	      See &struct libnbft_hfi.
 * @uri:      A URI which indicates an NVMe Discovery controller associated
 *	      with this Discovery Descriptor.
 * @nqn:      An NVMe Discovery controller NQN.
 */
struct libnbft_discovery {
	int index;
	struct libnbft_security *security;
	struct libnbft_hfi *hfi;
	char *uri;
	char *nqn;
};

/**
 * struct libnbft_security - Security Profile Descriptor
 * @index:              The number of this Security Profile Descriptor in the
 *                      Security Profile Descriptor List.
 * @flags:              Security Profile Descriptor Flags bitmask,
 *                      see &enum nbft_security_flags.
 * @secret_type:        Secret Type, see &enum nbft_security_secret_type.
 * @sec_chan_algs:      Secure Channel Algorithm list: an array of bytes
 *                      whose values are the Security Type (SECTYPE) field,
 *                      see &enum nvmf_tcp_sectype. NULL if not present
 *                      in the NBFT heap.
 * @sec_chan_algs_len:  Length in bytes of @sec_chan_algs.
 * @auth_protocols:     Authentication Protocol identifier list. Values
 *                      are Authentication Protocol Identifiers as defined
 *                      in the NVM Express Base Specification. NULL if not
 *                      present in the NBFT heap.
 * @auth_protocols_len: Length in bytes of @auth_protocols.
 * @cipher_suites:      Cipher Suite identifier list: raw byte data containing
 *                      cipher suite identifiers as defined in the IANA TLS
 *                      Parameters Registry. Each entry is a 16-bit value;
 *                      the number of entries is @cipher_suites_len / 2.
 *                      NULL if not present in the NBFT heap.
 * @cipher_suites_len:  Length in bytes of @cipher_suites.
 * @dh_groups:          DH-HMAC-CHAP Diffie-Hellman group identifier list.
 *                      Values are DH Group Identifiers as defined in the
 *                      NVM Express Base Specification. NULL if not present
 *                      in the NBFT heap.
 * @dh_groups_len:      Length in bytes of @dh_groups.
 * @sec_hash_funcs:     DH-HMAC-CHAP hash function identifier list,
 *                      see &enum libnvmf_hmac_alg. NULL if not present
 *                      in the NBFT heap.
 * @sec_hash_funcs_len: Length in bytes of @sec_hash_funcs.
 * @secret_keypath:     URI string for the secret key path. The type of
 *                      the URI is specified by @secret_type.
 *                      NULL if not present.
 */
struct libnbft_security {
	int index;
	__u16 flags;
	__u8 secret_type;
	__u8 *sec_chan_algs;
	__u16 sec_chan_algs_len;
	__u8 *auth_protocols;
	__u16 auth_protocols_len;
	__u8 *cipher_suites;
	__u16 cipher_suites_len;
	__u8 *dh_groups;
	__u16 dh_groups_len;
	__u8 *sec_hash_funcs;
	__u16 sec_hash_funcs_len;
	char *secret_keypath;
};

/**
 * enum libnbft_nid_type - Namespace Identifier Type (NIDT)
 * @LIBNBFT_NID_TYPE_NONE:	No identifier available.
 * @LIBNBFT_NID_TYPE_EUI64:	The EUI-64 identifier.
 * @LIBNBFT_NID_TYPE_NGUID:	The NSGUID identifier.
 * @LIBNBFT_NID_TYPE_NS_UUID:	The UUID identifier.
 */
enum libnbft_nid_type {
	LIBNBFT_NID_TYPE_NONE	 = 0,
	LIBNBFT_NID_TYPE_EUI64	 = 1,
	LIBNBFT_NID_TYPE_NGUID	 = 2,
	LIBNBFT_NID_TYPE_NS_UUID = 3,
};

/**
 * struct libnbft_subsystem_ns - Subsystem Namespace (SSNS) info
 * @index:		   SSNS Descriptor Index in the descriptor list.
 * @discovery:		   Primary Discovery Controller associated with
 *			   this SSNS Descriptor.
 * @security:		   Security Profile Descriptor associated with
 *			   this namespace.
 * @num_hfis:		   Number of HFIs.
 * @hfis:		   List of HFIs associated with this namespace.
 *			   Includes the primary HFI at the first position
 *			   and all secondary HFIs. This array is null-terminated.
 * @transport:		   Transport Type string (e.g. 'tcp').
 * @traddr:		   Subsystem Transport Address.
 * @trsvcid:		   Subsystem Transport Service Identifier.
 * @subsys_port_id:	   The Subsystem Port ID.
 * @nsid:		   The Namespace ID of this descriptor or when @nid
 *			   should be used instead.
 * @nid_type:		   Namespace Identifier Type, see &enum libnbft_nid_type.
 * @nid:		   The Namespace Identifier value.
 * @subsys_nqn:		   Subsystem and Namespace NQN.
 * @trflags:		   Transport Specific Flags bitmask,
 *			   see &enum nbft_ssns_trflags.
 * @controller_id:	   Controller ID (SSNS Extended Information Descriptor):
 *			   The controller ID associated with the Admin Queue
 *			   or 0 if not supported.
 * @asqsz:		   Admin Submission Queue Size (SSNS Extended Information
 *			   Descriptor) or 0 if not supported.
 * @dhcp_root_path_string: DHCP Root Path Override string (SSNS Extended
 *			   Information Descriptor).
 * @naed:		   Namespace Availability Enhanced Diagnostic
 *			   (SSNS Extended Information Descriptor). Provides
 *			   additional status codes from the pre-OS driver when
 *			   the namespace is unavailable.
 *			   See &enum nbft_ssns_ext_info_naed for values.
 *			   Zero indicates no additional information.
 *			   Only present in NBFT rev. 1.1+, zero otherwise.
 * @cipeec:		   Connect Invalid Parameters Extended Error Code
 *			   (SSNS Extended Information Descriptor). Provides
 *			   additional error detail when the pre-OS driver
 *			   received a Connect Invalid Parameters status.
 *			   See &enum nbft_ssns_ext_info_cipeec for values.
 *			   Zero indicates no extended error.
 *			   Only present in NBFT rev. 1.1+, zero otherwise.
 * @cto:		   Connection Timeout in seconds (SSNS Extended
 *			   Information Descriptor). The timeout value used
 *			   by the pre-OS driver for connecting to the object
 *			   specified with this SSNS descriptor. A value of
 *			   0xFFFF indicates that no timeout was specified.
 *			   Zero indicates either a timeout of zero seconds
 *			   or that the field is not present (NBFT rev. 1.0).
 * @nceec:		   Network and Connection Extended Error Code
 *			   (SSNS Extended Information Descriptor). Provides
 *			   error codes specific to network and connection
 *			   errors encountered by the pre-OS driver.
 *			   See &enum nbft_ssns_ext_info_nceec for values.
 *			   Zero indicates no extended error.
 *			   Only present in NBFT rev. 1.1+, zero otherwise.
 * @flags:		   SSNS Flags bitmask, see &enum nbft_ssns_flags.
 */
struct libnbft_subsystem_ns {
	int index;
	struct libnbft_discovery *discovery;
	struct libnbft_security *security;
	int num_hfis;
	struct libnbft_hfi **hfis;
	char transport[8];
	char traddr[40];
	char *trsvcid;
	__u16 subsys_port_id;
	__u32 nsid;
	enum libnbft_nid_type nid_type;
	__u8 *nid;
	char *subsys_nqn;
	__u16 trflags;
	int controller_id;
	int asqsz;
	char *dhcp_root_path_string;
	__u8 naed;
	__u8 cipeec;
	__u16 cto;
	__u8 nceec;
	__u16 flags;
};

/**
 * struct libnbft_info - The parsed NBFT table data.
 * @filename:	       Path to the NBFT table.
 * @raw_nbft:	       The original NBFT table contents.
 * @raw_nbft_size:     Size of @raw_nbft.
 * @host:	       The Host Descriptor (should match other NBFTs).
 * @hfi_list:	       The HFI Descriptor List (null-terminated array).
 * @security_list:     The Security Profile Descriptor List (null-terminated array).
 * @discovery_list:    The Discovery Descriptor List (null-terminated array).
 * @subsystem_ns_list: The SSNS Descriptor List (null-terminated array).
 */
struct libnbft_info {
	char *filename;
	__u8 *raw_nbft;
	ssize_t raw_nbft_size;
	struct libnbft_host host;
	struct libnbft_hfi **hfi_list;
	struct libnbft_security **security_list;
	struct libnbft_discovery **discovery_list;
	struct libnbft_subsystem_ns **subsystem_ns_list;
};

/**
 * libnvmf_read_nbft() - Read and parse contents of an ACPI NBFT table
 *
 * @ctx:      struct libnvme_global_ctx object
 * @nbft:     Parsed NBFT table data.
 * @filename: Filename of the raw NBFT table to read.
 *
 * Read and parse the specified NBFT file into a struct libnbft_info.
 * Free with libnvmf_free_nbft().
 *
 * Return: 0 on success, negative error code otherwise.
 */
int libnvmf_read_nbft(struct libnvme_global_ctx *ctx, struct libnbft_info **nbft,
		const char *filename);

/**
 * libnvmf_free_nbft() - Free the struct libnbft_info and its contents
 * @ctx: struct libnvme_global_ctx object
 * @nbft: Parsed NBFT table data.
 */
void libnvmf_free_nbft(struct libnvme_global_ctx *ctx, struct libnbft_info *nbft);

/**
 * struct nbft_file_entry - Linked list entry for NBFT files
 * @next: Pointer to next entry
 * @nbft: Pointer to NBFT info structure
 */
struct nbft_file_entry {
	struct nbft_file_entry *next;
	struct libnbft_info *nbft;
};
