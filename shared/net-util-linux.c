// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 Dell Technologies Inc. or its subsidiaries.
 *
 * Authors: Martin Belanger <martin.belanger@dell.com>
 */

#include <arpa/inet.h>
#include <asm/types.h>
#include <errno.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "net-util.h"

#define NETLINK_BUFFER_SIZE	4096
#define NETLINK_SEQ_NUM	1

/*
 * Parse @addr (IPv4, or IPv6 with an optional "%scope" suffix on a
 * link-local address) into @ss. @addr is never a hostname -- resolving one
 * is the caller's job, done before this is reached.
 *
 * Return: 0 on success; -EINVAL if @addr is not numeric; -ENOMEM on
 * allocation failure.
 */
static int parse_numeric_addr(const char *addr, struct sockaddr_storage *ss)
{
	struct sockaddr_in *addr4 = (struct sockaddr_in *)ss;
	struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)ss;
	char *tmp;
	char *scope;
	int ret = 0;

	memset(ss, 0, sizeof(*ss));

	if (inet_pton(AF_INET, addr, &addr4->sin_addr) == 1) {
		addr4->sin_family = AF_INET;
		return 0;
	}

	tmp = strdup(addr);
	if (!tmp)
		return -ENOMEM;

	scope = strchr(tmp, '%');
	if (scope)
		*scope++ = '\0';

	if (inet_pton(AF_INET6, tmp, &addr6->sin6_addr) != 1) {
		ret = -EINVAL;
		goto out;
	}

	addr6->sin6_family = AF_INET6;
	if (scope && IN6_IS_ADDR_LINKLOCAL(&addr6->sin6_addr))
		addr6->sin6_scope_id = if_nametoindex(scope);

out:
	free(tmp);
	return ret;
}

static bool sockaddrs_eq(struct sockaddr *addr1, struct sockaddr *addr2)
{
	struct sockaddr_in *sockaddr_v4;
	struct sockaddr_in6 *sockaddr_v6;

	if (addr1->sa_family == AF_INET && addr2->sa_family == AF_INET) {
		struct sockaddr_in *sockaddr1 = (struct sockaddr_in *)addr1;
		struct sockaddr_in *sockaddr2 = (struct sockaddr_in *)addr2;

		return sockaddr1->sin_addr.s_addr == sockaddr2->sin_addr.s_addr;
	}

	if (addr1->sa_family == AF_INET6 && addr2->sa_family == AF_INET6) {
		struct sockaddr_in6 *sockaddr1 = (struct sockaddr_in6 *)addr1;
		struct sockaddr_in6 *sockaddr2 = (struct sockaddr_in6 *)addr2;

		return !memcmp(&sockaddr1->sin6_addr, &sockaddr2->sin6_addr,
			       sizeof(struct in6_addr));
	}

	switch (addr1->sa_family) {
	case AF_INET:
		sockaddr_v6 = (struct sockaddr_in6 *)addr2;
		if (IN6_IS_ADDR_V4MAPPED(&sockaddr_v6->sin6_addr)) {
			sockaddr_v4 = (struct sockaddr_in *)addr1;
			return sockaddr_v4->sin_addr.s_addr ==
				sockaddr_v6->sin6_addr.s6_addr32[3];
		}
		break;

	case AF_INET6:
		sockaddr_v6 = (struct sockaddr_in6 *)addr1;
		if (IN6_IS_ADDR_V4MAPPED(&sockaddr_v6->sin6_addr)) {
			sockaddr_v4 = (struct sockaddr_in *)addr2;
			return sockaddr_v4->sin_addr.s_addr ==
				sockaddr_v6->sin6_addr.s6_addr32[3];
		}
		break;

	default:
		break;
	}

	return false;
}

bool shr_ipaddrs_eq(const char *addr1, const char *addr2)
{
	struct sockaddr_storage ss1, ss2;

	if (addr1 == addr2)
		return true;

	if (!addr1 || !addr2)
		return false;

	if (parse_numeric_addr(addr1, &ss1))
		return false;

	if (parse_numeric_addr(addr2, &ss2))
		return false;

	return sockaddrs_eq((struct sockaddr *)&ss1, (struct sockaddr *)&ss2);
}

bool shr_ipv6_is_link_local(const char *addr)
{
	char host[INET6_ADDRSTRLEN];
	struct in6_addr in6;
	size_t len;

	if (!addr)
		return false;

	len = strcspn(addr, "%");
	if (len >= sizeof(host))
		return false;
	memcpy(host, addr, len);
	host[len] = '\0';

	return inet_pton(AF_INET6, host, &in6) == 1 &&
	       IN6_IS_ADDR_LINKLOCAL(&in6);
}

const char *shr_iface_matching_addr(const struct ifaddrs *iface_list,
		const char *addr)
{
	const struct ifaddrs *iface_it;
	struct sockaddr_storage ss;
	const char *iface_name = NULL;

	if (!iface_list || !addr || parse_numeric_addr(addr, &ss))
		return NULL;

	/* Walk through the linked list */
	for (iface_it = iface_list; iface_it; iface_it = iface_it->ifa_next) {
		struct sockaddr *ifaddr = iface_it->ifa_addr;
		bool is_inet = ifaddr && (ifaddr->sa_family == AF_INET ||
					  ifaddr->sa_family == AF_INET6);

		if (is_inet && sockaddrs_eq((struct sockaddr *)&ss, ifaddr)) {
			iface_name = iface_it->ifa_name;
			break;
		}
	}

	return iface_name;
}

bool shr_iface_primary_addr_matches(const struct ifaddrs *iface_list,
		const char *iface, const char *addr)
{
	const struct ifaddrs *iface_it;
	struct sockaddr_storage ss;
	bool match_found = false;

	if (!iface_list || !addr || parse_numeric_addr(addr, &ss))
		return false;

	/* Walk through the linked list */
	for (iface_it = iface_list; iface_it; iface_it = iface_it->ifa_next) {
		if (strcmp(iface, iface_it->ifa_name))
			continue; /* Not the interface we're looking for*/

		/* The interface list is ordered in a way that the primary
		 * address is listed first. As soon as the parsed address
		 * matches the family of the address we're looking for, we
		 * have found the primary address for that family.
		 */
		if (iface_it->ifa_addr &&
		    (iface_it->ifa_addr->sa_family == ss.ss_family)) {
			match_found = sockaddrs_eq((struct sockaddr *)&ss,
					iface_it->ifa_addr);
			break;
		}
	}

	return match_found;
}

static int rtattr_append(struct nlmsghdr *nlh, char *buf, size_t buflen,
		unsigned short type, void *attrval, int attrlen)
{
	struct rtattr *rta;
	int nlen = NLMSG_ALIGN(nlh->nlmsg_len);
	int rlen = RTA_LENGTH(attrlen);

	if (nlen + rlen >= buflen)
		return -ENOSPC;

	rta = (struct rtattr *)(buf + nlen);
	rta->rta_type = type;
	rta->rta_len = rlen;
	memcpy(RTA_DATA(rta), attrval, attrlen);

	nlh->nlmsg_len = nlen + rlen;

	return 0;
}

int shr_route_get_egress_iface(const char *saddr, const char *daddr,
		char *ifname, size_t iflen)
{
	struct sockaddr_nl nl = {.nl_family = AF_NETLINK};
	struct sockaddr_storage ss_src, ss_dst;
	char buf[NETLINK_BUFFER_SIZE] = {};
	struct sockaddr_in6 *src6, *dst6;
	struct sockaddr_in *src, *dst;
	struct msghdr msg = {};
	struct nlmsghdr *nlh;
	struct rtmsg *rtmsg;
	struct rtattr *rta;
	int nlen, attrlen;
	struct iovec iov;
	int fd, ret = 0;

	if (!daddr)
		return -EINVAL;

	ret = parse_numeric_addr(daddr, &ss_dst);
	if (ret < 0)
		return ret;

	if (saddr) {
		ret = parse_numeric_addr(saddr, &ss_src);
		if (ret < 0)
			return ret;

		if (ss_src.ss_family != ss_dst.ss_family)
			return -EINVAL;
	}

	if (iflen < IF_NAMESIZE)
		return -EINVAL;

	fd = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);
	if (fd < 0)
		return -errno;

	/* encode nlmsghdr */
	nlh = (struct nlmsghdr *)buf;

	nlh->nlmsg_type = RTM_GETROUTE;
	nlh->nlmsg_flags = NLM_F_REQUEST;
	nlh->nlmsg_pid = 0; /* to kernel */
	nlh->nlmsg_seq = NETLINK_SEQ_NUM;
	nlh->nlmsg_len = sizeof(struct nlmsghdr);

	/* append rtmsg */
	nlh->nlmsg_len = NLMSG_ALIGN(nlh->nlmsg_len);

	rtmsg = (struct rtmsg *)(buf + nlh->nlmsg_len);
	rtmsg->rtm_family = ss_dst.ss_family;
	rtmsg->rtm_dst_len = (ss_dst.ss_family == AF_INET) ? 32 : 128;

	nlh->nlmsg_len += sizeof(struct rtmsg);

	/* append attribute RTA_DST */
	if (ss_dst.ss_family == AF_INET) {
		dst = (struct sockaddr_in *)&ss_dst;

		ret = rtattr_append(nlh, buf, sizeof(buf), RTA_DST,
				&dst->sin_addr, sizeof(struct in_addr));
		if (ret)
			goto out;
	} else {
		dst6 = (struct sockaddr_in6 *)&ss_dst;

		ret = rtattr_append(nlh, buf, sizeof(buf), RTA_DST,
				&dst6->sin6_addr, sizeof(struct in6_addr));
		if (ret)
			goto out;
	}

	if (saddr) {
		/* append attribute RTA_SRC */
		if (ss_src.ss_family == AF_INET) {
			src = (struct sockaddr_in *)&ss_src;

			ret = rtattr_append(nlh, buf, sizeof(buf), RTA_SRC,
				&src->sin_addr, sizeof(struct in_addr));
			if (ret)
				goto out;
		} else {
			src6 = (struct sockaddr_in6 *)&ss_src;

			ret = rtattr_append(nlh, buf, sizeof(buf), RTA_SRC,
				&src6->sin6_addr, sizeof(struct in6_addr));
			if (ret)
				goto out;
		}
	}

	/* construct sendmsg and send to kernel */
	iov.iov_base = buf;
	iov.iov_len = nlh->nlmsg_len;

	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_name = &nl;
	msg.msg_namelen = sizeof(nl);

	if (sendmsg(fd, &msg, 0) < 0) {
		ret = -errno;
		goto out;
	}

	/* construct recvmsg buffer and wait for the response from kernel */
	memset(&msg, 0, sizeof(msg));
	memset(buf, 0, sizeof(buf));

	iov.iov_base = buf;
	iov.iov_len = sizeof(buf);

	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_name = &nl;
	msg.msg_namelen = sizeof(nl);

	nlen = recvmsg(fd, &msg, 0);
	if (nlen < 0) {
		ret = -errno;
		goto out;
	}
	close(fd);

	nlh = msg.msg_iov->iov_base;

	for (; NLMSG_OK(nlh, nlen); nlh = NLMSG_NEXT(nlh, nlen)) {

		if (nlh->nlmsg_type == NLMSG_ERROR) {
			struct nlmsgerr *err = NLMSG_DATA(nlh);

			/*
			 * Netlink error message is sent as an ack when user
			 * explicitly requested for it and in which case
			 * err->error is set to zero.
			 */
			if (!err->error)
				continue;

			break;
		}

		if (nlh->nlmsg_type == NLMSG_DONE)
			break;

		/*
		 * RTM_GETROUTE reply is expected to be of type RTM_NEWROUTE.
		 */
		if (nlh->nlmsg_type != RTM_NEWROUTE)
			continue;

		if (nlh->nlmsg_seq != NETLINK_SEQ_NUM)
			continue;

		/* parse and decode received netlink message */
		rtmsg = NLMSG_DATA(nlh);
		rta = RTM_RTA(rtmsg);
		attrlen = RTM_PAYLOAD(nlh);

		for (; RTA_OK(rta, attrlen); rta = RTA_NEXT(rta, attrlen)) {

			switch (rta->rta_type) {
			case RTA_OIF: {
				int ifindex;

				ifindex = *((int *)RTA_DATA(rta));
				if (!if_indextoname(ifindex, ifname))
					return -errno;

				return 0;
			}
			default:
				break;
			}
		}
	}

	return -ENOENT;
out:
	close(fd);
	return ret;
}
