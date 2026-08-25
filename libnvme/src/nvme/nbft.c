// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libnvme.
 * Copyright (c) 2021-2022, Dell Inc. or its subsidiaries.  All Rights Reserved.
 *
 * Authors: Stuart Hayes <Stuart_Hayes@Dell.com>
 *
 */

#include <stdio.h>
#include <stdlib.h>

#include <arpa/inet.h>

#include <ccan/endian/endian.h>

#include <shared/compiler-attributes-util.h>

#include <libnvme.h>

#include "private.h"

static __u8 csum(const __u8 *buffer, ssize_t length)
{
	int n;
	__u8 sum = 0;

	for (n = 0; n < length; n++)
		sum = (__u8)(sum + ((__u8 *)buffer)[n]);
	return sum;
}

static void format_ip_addr(char *buf, size_t buflen, __u8 *addr)
{
	struct in6_addr addr_ipv6;

	memcpy(&addr_ipv6, addr, sizeof(addr_ipv6));
	if (IN6_IS_ADDR_V4MAPPED(&addr_ipv6))
		/* ipv4 */
		inet_ntop(AF_INET, &addr_ipv6.s6_addr32[3], buf, buflen);
	else
		/* ipv6 */
		inet_ntop(AF_INET6, &addr_ipv6, buf, buflen);
}

static bool range_valid(size_t offset, size_t length, size_t limit)
{
	return offset <= limit && length <= limit - offset;
}

static bool in_heap(struct nbft_header *header, struct nbft_heap_obj obj)
{
	size_t heap_offset = le32_to_cpu(header->heap_offset);
	size_t heap_length = le32_to_cpu(header->heap_length);
	size_t obj_offset = le32_to_cpu(obj.offset);
	size_t obj_length = le16_to_cpu(obj.length);
	size_t table_length = le32_to_cpu(header->length);

	if (obj_length == 0)
		return true;
	if (!range_valid(heap_offset, heap_length, table_length))
		return false;
	if (obj_offset < heap_offset)
		return false;

	return range_valid(obj_offset - heap_offset, obj_length, heap_length);
}

static bool descriptor_list_valid(struct nbft_header *header, __le32 offset,
		__le16 length, __u8 count, size_t minimum_length)
{
	size_t table_length = le32_to_cpu(header->length);
	size_t list_offset = le32_to_cpu(offset);
	size_t descriptor_length = le16_to_cpu(length);

	if (descriptor_length < minimum_length || list_offset == 0 ||
	    list_offset > table_length)
		return false;

	return count <= (table_length - list_offset) / descriptor_length;
}

static void *descriptor_at(__u8 *array, size_t index, size_t length)
{
	return array + index * length;
}

/*
 *  Return transport_type string (NBFT Table 2)
 */
static char *trtype_to_string(__u8 transport_type)
{
	switch (transport_type) {
	case 3:
		return "tcp";
	default:
		return "invalid";
	}
}

#define verify(ctx, condition, message)					\
	do {								\
		if (!(condition)) {					\
			libnvme_msg(ctx, LIBNVME_LOG_DEBUG, "file %s: " message "\n", \
				 nbft->filename);			\
			return -EINVAL;					\
		}							\
	} while (0)

static int __get_heap_obj(struct libnvme_global_ctx *ctx,
		struct nbft_header *header, const char *filename,
		const char *descriptorname, const char *fieldname,
		struct nbft_heap_obj obj, bool is_string,
		size_t min_len, char **output, __u16 *length)
{
	__u16 obj_length = le16_to_cpu(obj.length);

	*output = NULL;
	if (length)
		*length = 0;
	if (obj_length == 0)
		return -ENOENT;

	if (!in_heap(header, obj)) {
		libnvme_msg(ctx, LIBNVME_LOG_DEBUG,
			"file %s: field '%s' in descriptor '%s' has invalid offset or length\n",
			filename, fieldname, descriptorname);
		return -EINVAL;
	}

	if (!is_string && obj_length < min_len) {
		libnvme_msg(ctx, LIBNVME_LOG_DEBUG,
			"file %s: object '%s' in descriptor '%s' is too short (%d, expected %zu)\n",
			filename, fieldname, descriptorname,
			obj_length, min_len);
		return -EINVAL;
	}

	/* check that string is zero terminated correctly */
	*output = (char *)header + le32_to_cpu(obj.offset);

	if (is_string) {
		if (strnlen(*output, obj_length + 1) < obj_length) {
			libnvme_msg(ctx, LIBNVME_LOG_DEBUG,
				"file %s: string '%s' in descriptor '%s' is shorter (%zd) than specified length (%d)\n",
				filename, fieldname, descriptorname,
				strnlen(*output, obj_length + 1), obj_length);
		} else if (strnlen(*output, obj_length + 1) > obj_length) {
			libnvme_msg(ctx, LIBNVME_LOG_DEBUG,
				"file %s: string '%s' in descriptor '%s' is not zero terminated\n",
				filename, fieldname, descriptorname);
			return -EINVAL;
		}
	}

	if (length)
		*length = obj_length;
	return 0;
}

/*
 * Heap objects with structured (non-string) content are dereferenced as a
 * struct by the caller, so make sure the object is at least as large as the
 * structure it is interpreted as.  String and plain byte-array objects
 * have no minimum.  The SSNS extended-info reader performs its own
 * spec-length validation, so it is exempt here too.
 */
#define get_heap_obj(ctx, descriptor, obj, is_string, output)		\
	__get_heap_obj(ctx, header, nbft->filename,			\
		       stringify(descriptor), stringify(obj),		\
		       descriptor->obj, is_string,			\
		       _Generic((output),				\
			   char **: 0,				\
			   __u8 **: 0,				\
			   struct nbft_hfi_info_tcp **:		\
				   sizeof(**(output)),			\
			   struct nbft_hfi_info_ext **:		\
				   sizeof(**(output)),			\
			   struct nbft_ssns_ext_info **: 0),		\
		       (char **)(output), NULL)

#define get_heap_obj_len(ctx, descriptor, obj, is_string, output, length) \
	__get_heap_obj(ctx, header, nbft->filename,			\
		       stringify(descriptor), stringify(obj),		\
		       descriptor->obj, is_string, 0, output, length)

static struct libnbft_discovery *discovery_from_index(struct libnbft_info *nbft,
		int i)
{
	struct libnbft_discovery **d;

	for (d = nbft->discovery_list; d && *d; d++) {
		if ((*d)->index == i)
			return *d;
	}
	return NULL;
}

static struct libnbft_hfi *hfi_from_index(struct libnbft_info *nbft, int i)
{
	struct libnbft_hfi **h;

	for (h = nbft->hfi_list; h && *h; h++) {
		if ((*h)->index == i)
			return *h;
	}
	return NULL;
}

static struct libnbft_security *security_from_index(struct libnbft_info *nbft,
		int i)
{
	struct libnbft_security **s;

	for (s = nbft->security_list; s && *s; s++) {
		if ((*s)->index == i)
			return *s;
	}
	return NULL;
}

static int read_ssns_exended_info(struct libnvme_global_ctx *ctx,
		struct libnbft_info *nbft, struct libnbft_subsystem_ns *ssns,
		struct nbft_ssns_ext_info *raw_ssns_ei, __u16 descriptor_len)
{
	struct nbft_header *header = (struct nbft_header *)nbft->raw_nbft;

	/* Verify minimum size of the NBFT rev. 1.0 ssns_ext_info structure */
	verify(ctx, descriptor_len >= offsetof(struct nbft_ssns_ext_info, naed),
	       "SSNS extended info descriptor too short");
	verify(ctx, raw_ssns_ei->structure_id == NBFT_DESC_SSNS_EXT_INFO,
	       "invalid ID in SSNS extended info descriptor");
	verify(ctx, raw_ssns_ei->version == 1,
	       "invalid version in SSNS extended info descriptor");
	verify(ctx, le16_to_cpu(raw_ssns_ei->ssns_index) == ssns->index,
	       "SSNS index doesn't match extended info descriptor index");

	if (!(le32_to_cpu(raw_ssns_ei->flags) & NBFT_SSNS_EXT_INFO_VALID))
		return -EINVAL;

	if (le32_to_cpu(raw_ssns_ei->flags) & NBFT_SSNS_EXT_INFO_ADMIN_ASQSZ)
		ssns->asqsz = le16_to_cpu(raw_ssns_ei->asqsz);
	ssns->controller_id = le16_to_cpu(raw_ssns_ei->cntlid);
	get_heap_obj(ctx, raw_ssns_ei, dhcp_root_path_str_obj, 1,
		&ssns->dhcp_root_path_string);

	/* NBFT rev. 1.1 structure fields */
	if (descriptor_len >= sizeof(struct nbft_ssns_ext_info)) {
		ssns->naed = raw_ssns_ei->naed;
		ssns->cipeec = raw_ssns_ei->cipeec;
		ssns->cto = le16_to_cpu(raw_ssns_ei->cto);
		ssns->nceec = raw_ssns_ei->nceec;
	}

	return 0;
}

static int read_ssns(struct libnvme_global_ctx *ctx,
		struct libnbft_info *nbft, struct nbft_ssns *raw_ssns,
		struct libnbft_subsystem_ns **s)
{
	struct nbft_header *header = (struct nbft_header *)nbft->raw_nbft;
	struct libnbft_subsystem_ns *ssns;
	__u8 *ss_hfi_indexes = NULL;
	__u8 *tmp = NULL;
	int i, ret;

	if (!(le16_to_cpu(raw_ssns->flags) & NBFT_SSNS_VALID))
		return -EINVAL;

	verify(ctx, raw_ssns->structure_id == NBFT_DESC_SSNS,
	       "invalid ID in SSNS descriptor");

	/* verify transport type */
	verify(ctx, raw_ssns->trtype == NBFT_TRTYPE_TCP,
	       "invalid transport type in SSNS descriptor");

	ssns = calloc(1, sizeof(*ssns));
	if (!ssns)
		return -ENOMEM;

	ssns->index = le16_to_cpu(raw_ssns->index);
	strncpy(ssns->transport, trtype_to_string(raw_ssns->trtype),
		sizeof(ssns->transport) - 1);
	ssns->transport[sizeof(ssns->transport) - 1] = '\0';

	/* transport specific flags */
	ssns->trflags = le16_to_cpu(raw_ssns->trflags);

	/* primary discovery controller */
	if (raw_ssns->primary_discovery_ctrl_index) {
		ssns->discovery = discovery_from_index(nbft,
			raw_ssns->primary_discovery_ctrl_index);
		if (!ssns->discovery)
			libnvme_msg(ctx, LIBNVME_LOG_DEBUG,
				 "file %s: namespace %d discovery controller not found\n",
				 nbft->filename, ssns->index);
	}

	/* subsystem transport address */
	ret = get_heap_obj(ctx, raw_ssns, subsys_traddr_obj, 0, &tmp);
	if (ret)
		goto fail;

	/* format_ip_addr() always reads a full 16 bytes of IP address */
	if (le16_to_cpu(raw_ssns->subsys_traddr_obj.length) < sizeof(struct in6_addr)) {
		libnvme_msg(ctx, LIBNVME_LOG_DEBUG,
			"file %s: SSNS %d transport address heap object too short (%d bytes)\n",
			nbft->filename, ssns->index,
			le16_to_cpu(raw_ssns->subsys_traddr_obj.length));
		ret = -EINVAL;
		goto fail;
	}

	format_ip_addr(ssns->traddr, sizeof(ssns->traddr), tmp);

	/* subsystem transport service identifier */
	ret = get_heap_obj(ctx, raw_ssns, subsys_trsvcid_obj,
		1, &ssns->trsvcid);
	if (ret)
		goto fail;

	/* subsystem port ID */
	ssns->subsys_port_id = le16_to_cpu(raw_ssns->subsys_port_id);

	/* NSID, NID type, & NID */
	ssns->nsid = le32_to_cpu(raw_ssns->nsid);
	ssns->nid_type = raw_ssns->nidt;
	ssns->nid = raw_ssns->nid;

	/* flags */
	ssns->flags = le16_to_cpu(raw_ssns->flags);

	/* security profile */
	if (raw_ssns->security_desc_index) {
		ssns->security = security_from_index(nbft,
			raw_ssns->security_desc_index);
		if (!ssns->security) {
			libnvme_msg(ctx, LIBNVME_LOG_WARN,
				 "file %s: namespace %d security descriptor %d not found, skipping entry\n",
				 nbft->filename, ssns->index,
				 raw_ssns->security_desc_index);
			ret = -EINVAL;
			goto fail;
		}
	}

	/* HFI descriptors */
	ret = get_heap_obj(ctx, raw_ssns, secondary_hfi_assoc_obj,
		0, &ss_hfi_indexes);
	if (ret)
		goto fail;

	ssns->hfis =
		calloc(le16_to_cpu(raw_ssns->secondary_hfi_assoc_obj.length) +
			2, sizeof(*ssns->hfis));
	if (!ssns->hfis) {
		ret = -ENOMEM;
		goto fail;
	}
	ssns->hfis[0] = hfi_from_index(nbft, raw_ssns->primary_hfi_desc_index);
	if (!ssns->hfis[0]) {
		libnvme_msg(ctx, LIBNVME_LOG_DEBUG,
			"file %s: SSNS %d: HFI %d not found\n",
			nbft->filename, ssns->index,
			raw_ssns->primary_hfi_desc_index);
		ret = -EINVAL;
		goto fail;
	}
	ssns->num_hfis = 1;
	for (i = 0; i < le16_to_cpu(raw_ssns->secondary_hfi_assoc_obj.length);
			i++) {
		struct libnbft_hfi *hfi;
		bool duplicate = false;
		int j;

		for (j = 0; j < i; j++) {
			if (ss_hfi_indexes[i] == ss_hfi_indexes[j]) {
				duplicate = true;
				break;
			}
		}

		if (!duplicate &&
		    ss_hfi_indexes[i] == raw_ssns->primary_hfi_desc_index)
			duplicate = true;

		if (duplicate) {
			libnvme_msg(ctx, LIBNVME_LOG_DEBUG,
				"file %s: SSNS %d skipping duplicate HFI index %d\n",
				nbft->filename, ssns->index, ss_hfi_indexes[i]);
			continue;
		}

		hfi = hfi_from_index(nbft, ss_hfi_indexes[i]);
		if (!hfi) {
			if (!ss_hfi_indexes[i])
				continue;
			libnvme_msg(ctx, LIBNVME_LOG_DEBUG,
				"file %s: SSNS %d HFI %d not found\n",
				nbft->filename, ssns->index, ss_hfi_indexes[i]);
			continue;
		}

		ssns->hfis[ssns->num_hfis++] = hfi;
	}

	/* SSNS NQN */
	ret = get_heap_obj(ctx, raw_ssns, subsys_ns_nqn_obj,
		1, &ssns->subsys_nqn);
	if (ret)
		goto fail;

	/* SSNS extended info */
	if (le16_to_cpu(raw_ssns->flags) & NBFT_SSNS_EXTENDED_INFO_IN_USE) {
		struct nbft_ssns_ext_info *ssns_extended_info;

		if (!get_heap_obj(ctx, raw_ssns, ssns_extended_info_desc_obj,
				0, &ssns_extended_info)) {
			read_ssns_exended_info(ctx, nbft, ssns,
				ssns_extended_info,
				le16_to_cpu(raw_ssns->ssns_extended_info_desc_obj.length));
		}
	}

	*s = ssns;
	return 0;

fail:
	free(ssns->hfis);
	free(ssns);
	return ret;
}

static void read_hfi_info_dhcp(struct libnvme_global_ctx *ctx,
		struct libnbft_info *nbft,
		struct nbft_hfi_info_ext *hfi_ext_info,
		struct libnbft_hfi *hfi)
{
	struct nbft_header *header = (struct nbft_header *)nbft->raw_nbft;
	char *iaid_raw = NULL;
	char *duid_raw = NULL;
	__u16 duid_len;

	if (hfi_ext_info->structure_id != NBFT_DESC_HFI_EXT_INFO ||
	    hfi_ext_info->version != 1)
		return;
	if (!(le32_to_cpu(hfi_ext_info->flags) & NBFT_HFI_INFO_EXT_VALID))
		return;
	if (!(le32_to_cpu(hfi_ext_info->flags) & NBFT_HFI_INFO_EXT_DCI))
		return;

	if (!get_heap_obj(ctx, hfi_ext_info, dhcp_iaid_obj, 0, &iaid_raw))
		hfi->tcp_info.dhcp_iaid = le32_to_cpu(*(__le32 *)iaid_raw);
	if (!get_heap_obj(ctx, hfi_ext_info, dhcp_duid_obj, 0, &duid_raw)) {
		duid_len = le16_to_cpu(hfi_ext_info->dhcp_duid_obj.length);
		if (duid_len > sizeof(hfi->tcp_info.dhcp_duid))
			duid_len = sizeof(hfi->tcp_info.dhcp_duid);
		memcpy(hfi->tcp_info.dhcp_duid, duid_raw, duid_len);
		hfi->tcp_info.dhcp_duid_len = duid_len;
	}
}

static int read_hfi_info_tcp(struct libnvme_global_ctx *ctx,
		struct libnbft_info *nbft,
		struct nbft_hfi_info_tcp *raw_hfi_info_tcp,
		struct libnbft_hfi *hfi)
{
	struct nbft_header *header = (struct nbft_header *)nbft->raw_nbft;

	if ((raw_hfi_info_tcp->flags & NBFT_HFI_INFO_TCP_VALID) == 0)
		return -EINVAL;

	verify(ctx, raw_hfi_info_tcp->structure_id == NBFT_DESC_HFI_TRINFO,
	       "invalid ID in HFI transport descriptor");
	verify(ctx, raw_hfi_info_tcp->version == 1,
	       "invalid version in HFI transport descriptor");
	if (le16_to_cpu(raw_hfi_info_tcp->hfi_index) != hfi->index)
		libnvme_msg(ctx, LIBNVME_LOG_DEBUG,
			"file %s: HFI descriptor index %d does not match index in HFI transport descriptor\n",
			nbft->filename, hfi->index);

	hfi->tcp_info.pci_sbdf = le32_to_cpu(raw_hfi_info_tcp->pci_sbdf);
	memcpy(hfi->tcp_info.mac_addr, raw_hfi_info_tcp->mac_addr,
		sizeof(raw_hfi_info_tcp->mac_addr));
	hfi->tcp_info.vlan = le16_to_cpu(raw_hfi_info_tcp->vlan);
	hfi->tcp_info.ip_origin = raw_hfi_info_tcp->ip_origin;
	format_ip_addr(hfi->tcp_info.ipaddr, sizeof(hfi->tcp_info.ipaddr),
		raw_hfi_info_tcp->ip_address);
	hfi->tcp_info.subnet_mask_prefix = raw_hfi_info_tcp->subnet_mask_prefix;
	format_ip_addr(hfi->tcp_info.gateway_ipaddr,
		sizeof(hfi->tcp_info.ipaddr), raw_hfi_info_tcp->ip_gateway);
	hfi->tcp_info.route_metric =
		le16_to_cpu(raw_hfi_info_tcp->route_metric);
	format_ip_addr(hfi->tcp_info.primary_dns_ipaddr,
		sizeof(hfi->tcp_info.primary_dns_ipaddr),
		raw_hfi_info_tcp->primary_dns);
	format_ip_addr(hfi->tcp_info.secondary_dns_ipaddr,
		sizeof(hfi->tcp_info.secondary_dns_ipaddr),
		raw_hfi_info_tcp->secondary_dns);
	hfi->tcp_info.flags = raw_hfi_info_tcp->flags;
	if (raw_hfi_info_tcp->flags & NBFT_HFI_INFO_TCP_DHCP_OVERRIDE)
		format_ip_addr(hfi->tcp_info.dhcp_server_ipaddr,
			sizeof(hfi->tcp_info.dhcp_server_ipaddr),
			raw_hfi_info_tcp->dhcp_server);
	get_heap_obj(ctx, raw_hfi_info_tcp, host_name_obj,
		1, &hfi->tcp_info.host_name);

	if (raw_hfi_info_tcp->trinfo_version >= 2) {
		struct nbft_hfi_info_ext *hfi_ext_info;

		hfi->tcp_info.pcie_seg_num = raw_hfi_info_tcp->pcie_seg_num;

		if (!get_heap_obj(ctx, raw_hfi_info_tcp, hfi_ext_info_obj,
				0, &hfi_ext_info))
			read_hfi_info_dhcp(ctx, nbft, hfi_ext_info, hfi);
	}

	return 0;
}

static int read_hfi(struct libnvme_global_ctx *ctx, struct libnbft_info *nbft,
		struct nbft_hfi *raw_hfi, struct libnbft_hfi **h)
{
	int ret;
	struct libnbft_hfi *hfi;
	struct nbft_header *header = (struct nbft_header *)nbft->raw_nbft;

	if (!(raw_hfi->flags & NBFT_HFI_VALID))
		return -EINVAL;

	verify(ctx, raw_hfi->structure_id == NBFT_DESC_HFI,
		"invalid ID in HFI descriptor");

	hfi = calloc(1, sizeof(struct libnbft_hfi));
	if (!hfi)
		return -ENOMEM;

	hfi->index = raw_hfi->index;

	/*
	 * read HFI transport descriptor for this HFI
	 */
	if (raw_hfi->trtype == NBFT_TRTYPE_TCP) {
		/* TCP */
		struct nbft_hfi_info_tcp *raw_hfi_info_tcp;

		strncpy(hfi->transport, trtype_to_string(raw_hfi->trtype),
			sizeof(hfi->transport) - 1);
		hfi->transport[sizeof(hfi->transport) - 1] = '\0';

		ret = get_heap_obj(ctx, raw_hfi, trinfo_obj,
			0, &raw_hfi_info_tcp);
		if (ret)
			goto fail;

		ret = read_hfi_info_tcp(ctx, nbft, raw_hfi_info_tcp, hfi);
		if (ret)
			goto fail;
	} else {
		libnvme_msg(ctx, LIBNVME_LOG_DEBUG,
			 "file %s: invalid transport type %d\n",
			 nbft->filename, raw_hfi->trtype);
		ret = -EINVAL;
		goto fail;
	}

	*h = hfi;
	return 0;

fail:
	free(hfi);
	return ret;
}

static int read_discovery(struct libnvme_global_ctx *ctx,
		struct libnbft_info *nbft,
		struct nbft_discovery *raw_discovery,
		struct libnbft_discovery **d)
{
	struct libnbft_discovery *discovery = NULL;
	struct nbft_header *header = (struct nbft_header *)nbft->raw_nbft;
	int r = -EINVAL;

	if (!(raw_discovery->flags & NBFT_DISCOVERY_VALID))
		goto error;

	verify(ctx, raw_discovery->structure_id == NBFT_DESC_DISCOVERY,
	       "invalid ID in discovery descriptor");

	discovery = calloc(1, sizeof(struct libnbft_discovery));
	if (!discovery) {
		r = -ENOMEM;
		goto error;
	}

	discovery->index = raw_discovery->index;

	if (get_heap_obj(ctx, raw_discovery, discovery_ctrl_addr_obj,
			1, &discovery->uri))
		goto error;

	/*
	 * A DCNQNHOR cleared to 0h is spec-legal: it means "no unique NQN,
	 * use the well-known Discovery NQN" (Boot Specification rev 1.4).
	 * get_heap_obj() reports that as -ENOENT, not a parse failure --
	 * only a genuinely malformed reference (-EINVAL) should drop the
	 * whole descriptor.
	 */
	r = get_heap_obj(ctx, raw_discovery, discovery_ctrl_nqn_obj,
			1, &discovery->nqn);
	if (r && r != -ENOENT)
		goto error;

	discovery->hfi = hfi_from_index(nbft, raw_discovery->hfi_index);
	if (!discovery->hfi) {
		libnvme_msg(ctx, LIBNVME_LOG_DEBUG,
			 "file %s: discovery %d HFI not found\n",
			 nbft->filename, discovery->index);
		r = -EINVAL;
		goto error;
	}

	if (raw_discovery->sec_index) {
		discovery->security =
			security_from_index(nbft, raw_discovery->sec_index);
		if (!discovery->security) {
			libnvme_msg(ctx, LIBNVME_LOG_WARN,
				 "file %s: discovery %d security descriptor %d not found, skipping entry\n",
				 nbft->filename, discovery->index,
				 raw_discovery->sec_index);
			r = -EINVAL;
			goto error;
		}
	}

	*d = discovery;
	r = 0;

error:
	if (r)
		free(discovery);
	return r;
}

static int read_security(struct libnvme_global_ctx *ctx, struct libnbft_info *nbft,
		struct nbft_security *raw_security,
		struct libnbft_security **s)
{
	struct nbft_header *header = (struct nbft_header *)nbft->raw_nbft;
	struct libnbft_security *security;
	__u16 flags = le16_to_cpu(raw_security->flags);
	char *policy_list;
	int ret;

	if (!(flags & NBFT_SECURITY_VALID))
		return -EINVAL;
	verify(ctx, raw_security->structure_id == NBFT_DESC_SECURITY,
	       "invalid ID in security descriptor");

	security = calloc(1, sizeof(*security));
	if (!security)
		return -ENOMEM;

	security->index = raw_security->index;
	security->flags = flags;
	security->secret_type = raw_security->secret_type;

	/* Policy lists point into the raw NBFT heap when enabled. */
	ret = 0;
	if ((flags & NBFT_SECURITY_SEC_POLICY_LIST_MASK) !=
	    NBFT_SECURITY_SEC_POLICY_LIST_NOT_SUPPORTED &&
	    le16_to_cpu(raw_security->sec_chan_alg_obj.length)) {
		ret = get_heap_obj_len(ctx, raw_security, sec_chan_alg_obj, 0,
				       &policy_list,
				       &security->sec_chan_algs_len);
		if (!ret)
			security->sec_chan_algs = (__u8 *)policy_list;
	}
	if (!ret && (flags & NBFT_SECURITY_AUTH_POLICY_LIST_MASK) !=
	    NBFT_SECURITY_AUTH_POLICY_LIST_NOT_SUPPORTED &&
	    le16_to_cpu(raw_security->auth_proto_obj.length)) {
		ret = get_heap_obj_len(ctx, raw_security, auth_proto_obj, 0,
				       &policy_list,
				       &security->auth_protocols_len);
		if (!ret)
			security->auth_protocols = (__u8 *)policy_list;
	}
	if (!ret && (flags & NBFT_SECURITY_CIPHER_RESTRICTED) &&
	    le16_to_cpu(raw_security->cipher_suite_obj.length)) {
		ret = get_heap_obj_len(ctx, raw_security, cipher_suite_obj, 0,
				       &policy_list,
				       &security->cipher_suites_len);
		if (!ret)
			security->cipher_suites = (__u8 *)policy_list;
	}
	if (!ret && (flags & NBFT_SECURITY_AUTH_KX_GROUPS_RESTRICTED) &&
	    le16_to_cpu(raw_security->kx_grp_obj.length)) {
		ret = get_heap_obj_len(ctx, raw_security, kx_grp_obj, 0,
				       &policy_list,
				       &security->kx_groups_len);
		if (!ret)
			security->kx_groups = (__u8 *)policy_list;
	}
	if (!ret && (flags & NBFT_SECURITY_SEC_HASH_FUNC_POLICY_LIST) &&
	    le16_to_cpu(raw_security->sec_hash_func_obj.length)) {
		ret = get_heap_obj_len(ctx, raw_security, sec_hash_func_obj, 0,
				       &policy_list,
				       &security->sec_hash_funcs_len);
		if (!ret)
			security->sec_hash_funcs = (__u8 *)policy_list;
	}
	if (ret) {
		free(security);
		return ret;
	}

	/* The key URI also points into the heap. An absent URI is valid. */
	ret = get_heap_obj(ctx, raw_security, sec_keypath_obj, 1,
			   &security->secret_keypath);
	if (ret && ret != -ENOENT) {
		free(security);
		return ret;
	}

	*s = security;
	return 0;
}

static void read_hfi_descriptors(struct libnvme_global_ctx *ctx,
		struct libnbft_info *nbft, int num_hfi,
		__u8 *raw_hfi_array, size_t hfi_len)
{
	int i, cnt;

	nbft->hfi_list = calloc(num_hfi + 1, sizeof(struct libnbft_hfi *));
	for (i = 0, cnt = 0; i < num_hfi; i++) {
		struct nbft_hfi *raw_hfi = descriptor_at(raw_hfi_array, i,
							 hfi_len);

		if (read_hfi(ctx, nbft, raw_hfi,
				&nbft->hfi_list[cnt]) == 0)
			cnt++;
	}
}

static void read_security_descriptors(struct libnvme_global_ctx *ctx,
		struct libnbft_info *nbft, int num_sec,
		__u8 *raw_sec_array, size_t sec_len)
{
	int i, cnt;

	nbft->security_list = calloc(num_sec + 1,
		sizeof(struct libnbft_security *));
	for (i = 0, cnt = 0; i < num_sec; i++) {
		struct nbft_security *raw_security =
			descriptor_at(raw_sec_array, i, sec_len);

		if (read_security(ctx, nbft, raw_security,
				&nbft->security_list[cnt]) == 0)
			cnt++;
	}
}

static void read_discovery_descriptors(struct libnvme_global_ctx *ctx,
		struct libnbft_info *nbft, int num_disc,
		__u8 *raw_disc_array, size_t disc_len)
{
	int i, cnt;

	nbft->discovery_list =
		calloc(num_disc + 1, sizeof(struct libnbft_discovery *));
	for (i = 0, cnt = 0; i < num_disc; i++) {
		struct nbft_discovery *raw_discovery =
			descriptor_at(raw_disc_array, i, disc_len);

		if (read_discovery(ctx, nbft, raw_discovery,
				&nbft->discovery_list[cnt]) == 0)
			cnt++;
	}
}

static void read_ssns_descriptors(struct libnvme_global_ctx *ctx,
		struct libnbft_info *nbft, int num_ssns,
		__u8 *raw_ssns_array, size_t ssns_len)
{
	int i, cnt;

	nbft->subsystem_ns_list =
		 calloc(num_ssns + 1, sizeof(struct libnbft_subsystem_ns *));
	for (i = 0, cnt = 0; i < num_ssns; i++) {
		struct nbft_ssns *raw_ssns =
			descriptor_at(raw_ssns_array, i, ssns_len);

		if (read_ssns(ctx, nbft, raw_ssns,
				&nbft->subsystem_ns_list[cnt]) == 0)
			cnt++;
	}
}

/**
 * parse_raw_nbft - parses raw ACPI NBFT table and fill in abstracted libnbft_info structure
 * @nbft: libnbft_info struct containing only raw_nbft and raw_nbft_size
 *
 * Returns 0 on success, errno otherwise.
 */
static int parse_raw_nbft(struct libnvme_global_ctx *ctx, struct libnbft_info *nbft)
{
	__u8 *raw_nbft = nbft->raw_nbft;
	int raw_nbft_size = nbft->raw_nbft_size;

	struct nbft_header *header;
	struct nbft_control *control;
	struct nbft_host *host;

	verify(ctx, raw_nbft_size >=
		sizeof(struct nbft_header) + sizeof(struct nbft_control),
	       "table is too short");
	verify(ctx, csum(raw_nbft, raw_nbft_size) == 0, "invalid checksum");

	/*
	 * header
	 */
	header = (struct nbft_header *)raw_nbft;

	verify(ctx, strncmp(header->signature, NBFT_HEADER_SIG, 4) == 0,
		"invalid signature");
	verify(ctx, le32_to_cpu(header->length) >=
		sizeof(struct nbft_header) + sizeof(struct nbft_control),
		"length in header is too short");
	verify(ctx, le32_to_cpu(header->length) <= raw_nbft_size,
		"length in header exceeds table length");
	verify(ctx, header->major_revision == 1,
		"unsupported major revision");
	verify(ctx, header->minor_revision <= 1,
		"unsupported minor revision");
	verify(ctx, range_valid(le32_to_cpu(header->heap_offset),
		le32_to_cpu(header->heap_length),
		le32_to_cpu(header->length)),
		"heap exceeds table length");

	/*
	 * control
	 */
	control =
		(struct nbft_control *)(raw_nbft + sizeof(struct nbft_header));

	verify(ctx, control->flags & NBFT_CONTROL_VALID,
	       "control descriptor valid flag not set");
	verify(ctx, control->structure_id == NBFT_DESC_CONTROL,
	       "invalid ID in control structure");

	/*
	 * host
	 */
	verify(ctx, range_valid(le32_to_cpu(control->hdesc.offset),
		sizeof(struct nbft_host), le32_to_cpu(header->length)) &&
		le32_to_cpu(control->hdesc.offset) >= sizeof(struct nbft_host),
		"host descriptor offset/length is invalid");
	host = (struct nbft_host *)(raw_nbft +
		le32_to_cpu(control->hdesc.offset));

	verify(ctx, host->flags & NBFT_HOST_VALID,
		"host descriptor valid flag not set");
	verify(ctx, host->structure_id == NBFT_DESC_HOST,
		"invalid ID in HOST descriptor");
	nbft->host.id = (unsigned char *) &(host->host_id);
	if (get_heap_obj(ctx, host, host_nqn_obj, 1, &nbft->host.nqn) != 0)
		return -EINVAL;
	nbft->host.flags = host->flags;

	/*
	 * HFI
	 */
	if (control->num_hfi > 0) {
		__u8 *raw_hfi_array;

		verify(ctx, descriptor_list_valid(header, control->hfio,
			control->hfil, control->num_hfi,
			sizeof(struct nbft_hfi)),
		       "invalid hfi descriptor list offset");
		raw_hfi_array = raw_nbft + le32_to_cpu(control->hfio);
		read_hfi_descriptors(ctx, nbft, control->num_hfi, raw_hfi_array,
				     le16_to_cpu(control->hfil));
	}

	/*
	 * security
	 */
	if (control->num_sec > 0) {
		__u8 *raw_security_array;

		verify(ctx, descriptor_list_valid(header, control->seco,
			control->secl, control->num_sec,
			sizeof(struct nbft_security)),
		       "invalid security profile descriptor list offset");
		raw_security_array = raw_nbft + le32_to_cpu(control->seco);
		read_security_descriptors(ctx, nbft, control->num_sec,
					  raw_security_array,
					  le16_to_cpu(control->secl));
	}

	/*
	 * discovery
	 */
	if (control->num_disc > 0) {
		__u8 *raw_discovery_array;

		verify(ctx, descriptor_list_valid(header, control->disco,
			control->discl, control->num_disc,
			sizeof(struct nbft_discovery)),
		       "invalid discovery profile descriptor list offset");
		raw_discovery_array = raw_nbft + le32_to_cpu(control->disco);
		read_discovery_descriptors(ctx, nbft, control->num_disc,
			raw_discovery_array, le16_to_cpu(control->discl));
	}

	/*
	 * subsystem namespace
	 */
	if (control->num_ssns > 0) {
		__u8 *raw_ssns_array;

		verify(ctx, descriptor_list_valid(header, control->ssnso,
			control->ssnsl, control->num_ssns,
			sizeof(struct nbft_ssns)),
		       "invalid subsystem namespace descriptor list offset");
		raw_ssns_array = raw_nbft + le32_to_cpu(control->ssnso);
		read_ssns_descriptors(ctx, nbft, control->num_ssns,
			raw_ssns_array, le16_to_cpu(control->ssnsl));
	}

	return 0;
}

__shr_public void libnvmf_free_nbft(
		struct libnvme_global_ctx *ctx, struct libnbft_info *nbft)
{
	struct libnbft_hfi **hfi;
	struct libnbft_security **sec;
	struct libnbft_discovery **disc;
	struct libnbft_subsystem_ns **ns;

	for (hfi = nbft->hfi_list; hfi && *hfi; hfi++)
		free(*hfi);
	free(nbft->hfi_list);
	for (disc = nbft->discovery_list; disc && *disc; disc++)
		free(*disc);
	free(nbft->discovery_list);
	for (sec = nbft->security_list; sec && *sec; sec++)
		free(*sec);
	free(nbft->security_list);
	for (ns = nbft->subsystem_ns_list; ns && *ns; ns++) {
		free((*ns)->hfis);
		free(*ns);
	}
	free(nbft->subsystem_ns_list);
	free(nbft->raw_nbft);
	free(nbft->filename);
	free(nbft);
}

__shr_public int libnvmf_read_nbft(
		struct libnvme_global_ctx *ctx, struct libnbft_info **nbft,
		const char *filename)
{
	__u8 *raw_nbft = NULL;
	size_t raw_nbft_size;
	FILE *raw_nbft_fp = NULL;
	int i;

	/*
	 * read in raw nbft file
	 */
	raw_nbft_fp = fopen(filename, "rb");
	if (raw_nbft_fp == NULL) {
		libnvme_msg(ctx, LIBNVME_LOG_ERR, "Failed to open %s: %s\n",
			 filename, libnvme_strerror(errno));
		return -EINVAL;
	}

	i = fseek(raw_nbft_fp, 0L, SEEK_END);
	if (i) {
		libnvme_msg(ctx, LIBNVME_LOG_ERR, "Failed to read from %s: %s\n",
			 filename, libnvme_strerror(errno));
		fclose(raw_nbft_fp);
		return -EINVAL;
	}

	raw_nbft_size = ftell(raw_nbft_fp);
	if (raw_nbft_size == (size_t)-1L) {
		libnvme_msg(ctx, LIBNVME_LOG_ERR,
			"Failed to get file size for %s: %s\n",
			filename, libnvme_strerror(errno));
		fclose(raw_nbft_fp);
		return -EINVAL;
	}
	errno = 0;
	rewind(raw_nbft_fp);
	if (errno) {
		libnvme_msg(ctx, LIBNVME_LOG_ERR, "Failed to seek in %s: %s\n",
			filename, libnvme_strerror(errno));
		fclose(raw_nbft_fp);
		return -EINVAL;
	}
	raw_nbft = malloc(raw_nbft_size);
	if (!raw_nbft) {
		libnvme_msg(ctx, LIBNVME_LOG_ERR,
			"Failed to allocate memory for NBFT table");
		fclose(raw_nbft_fp);
		return -ENOMEM;
	}

	i = fread(raw_nbft, sizeof(*raw_nbft), raw_nbft_size, raw_nbft_fp);
	if (i != raw_nbft_size) {
		libnvme_msg(ctx, LIBNVME_LOG_ERR, "Failed to read from %s: %s\n",
			 filename, libnvme_strerror(errno));
		fclose(raw_nbft_fp);
		free(raw_nbft);
		return -EINVAL;
	}
	fclose(raw_nbft_fp);

	/*
	 * alloc new struct libnbft_info, add raw nbft & filename to it,
	 * and add it to the list
	 */
	*nbft = calloc(1, sizeof(struct libnbft_info));
	if (!*nbft) {
		libnvme_msg(ctx, LIBNVME_LOG_ERR, "Could not allocate memory for NBFT\n");
		free(raw_nbft);
		return -ENOMEM;
	}

	(*nbft)->filename = strdup(filename);
	(*nbft)->raw_nbft = raw_nbft;
	(*nbft)->raw_nbft_size = raw_nbft_size;

	if (parse_raw_nbft(ctx, *nbft)) {
		libnvme_msg(ctx, LIBNVME_LOG_ERR, "Failed to parse %s\n", filename);
		libnvmf_free_nbft(ctx, *nbft);
		return -EINVAL;
	}
	return 0;
}
