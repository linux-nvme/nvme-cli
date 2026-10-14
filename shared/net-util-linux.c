// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 Dell Technologies Inc. or its subsidiaries.
 *
 * Authors: Martin Belanger <martin.belanger@dell.com>
 */

#include <arpa/inet.h>
#include <errno.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#ifdef __linux__
#include <asm/types.h>
#include <linux/ethtool.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/sockios.h>
#endif

#include "net-util.h"

/*
 * The members share their storage. Read a member that was written as
 * another only through the union: other accesses break strict aliasing.
 */
union sockaddr_any {
	struct sockaddr sa;
	struct sockaddr_in in4;
	struct sockaddr_in6 in6;
};

/*
 * Parse @addr (IPv4, or IPv6 with an optional "%scope" suffix on a
 * link-local address) into @sa. @addr is never a hostname -- resolving one
 * is the caller's job, done before this is reached.
 *
 * Return: 0 on success; -EINVAL if @addr is not numeric; -ENOMEM on
 * allocation failure.
 */
static int parse_numeric_addr(const char *addr, union sockaddr_any *sa)
{
	char *tmp;
	char *scope;
	int ret = 0;

	memset(sa, 0, sizeof(*sa));

	if (inet_pton(AF_INET, addr, &sa->in4.sin_addr) == 1) {
		sa->in4.sin_family = AF_INET;
		return 0;
	}

	tmp = strdup(addr);
	if (!tmp)
		return -ENOMEM;

	scope = strchr(tmp, '%');
	if (scope)
		*scope++ = '\0';

	if (inet_pton(AF_INET6, tmp, &sa->in6.sin6_addr) != 1) {
		ret = -EINVAL;
		goto out;
	}

	sa->in6.sin6_family = AF_INET6;
	if (scope && IN6_IS_ADDR_LINKLOCAL(&sa->in6.sin6_addr))
		sa->in6.sin6_scope_id = if_nametoindex(scope);

out:
	free(tmp);
	return ret;
}

/* Copy @addr, from libc, into @sa. Return false if it is not IP. */
static bool sockaddr_copy(const struct sockaddr *addr, union sockaddr_any *sa)
{
	memset(sa, 0, sizeof(*sa));

	switch (addr->sa_family) {
	case AF_INET:
		memcpy(&sa->in4, addr, sizeof(sa->in4));
		return true;
	case AF_INET6:
		memcpy(&sa->in6, addr, sizeof(sa->in6));
		return true;
	default:
		return false;
	}
}

static bool sockaddrs_eq(const union sockaddr_any *a1,
		const union sockaddr_any *a2)
{
	sa_family_t f1 = a1->sa.sa_family;
	sa_family_t f2 = a2->sa.sa_family;

	if (f1 == AF_INET && f2 == AF_INET)
		return a1->in4.sin_addr.s_addr == a2->in4.sin_addr.s_addr;

	if (f1 == AF_INET6 && f2 == AF_INET6)
		return !memcmp(&a1->in6.sin6_addr, &a2->in6.sin6_addr,
			       sizeof(struct in6_addr));

	if (f1 == AF_INET && f2 == AF_INET6)
		return IN6_IS_ADDR_V4MAPPED(&a2->in6.sin6_addr) &&
		       a1->in4.sin_addr.s_addr ==
		       a2->in6.sin6_addr.s6_addr32[3];

	if (f1 == AF_INET6 && f2 == AF_INET)
		return IN6_IS_ADDR_V4MAPPED(&a1->in6.sin6_addr) &&
		       a2->in4.sin_addr.s_addr ==
		       a1->in6.sin6_addr.s6_addr32[3];

	return false;
}

bool shr_ipaddrs_eq(const char *addr1, const char *addr2)
{
	union sockaddr_any sa1, sa2;

	if (addr1 == addr2)
		return true;

	if (!addr1 || !addr2)
		return false;

	if (parse_numeric_addr(addr1, &sa1))
		return false;

	if (parse_numeric_addr(addr2, &sa2))
		return false;

	return sockaddrs_eq(&sa1, &sa2);
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
	union sockaddr_any sa, ifaddr;
	const char *iface_name = NULL;

	if (!iface_list || !addr || parse_numeric_addr(addr, &sa))
		return NULL;

	/* Walk through the linked list */
	for (iface_it = iface_list; iface_it; iface_it = iface_it->ifa_next) {
		if (iface_it->ifa_addr &&
		    sockaddr_copy(iface_it->ifa_addr, &ifaddr) &&
		    sockaddrs_eq(&sa, &ifaddr)) {
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
	union sockaddr_any sa, ifaddr;
	bool match_found = false;

	if (!iface_list || !addr || parse_numeric_addr(addr, &sa))
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
		    iface_it->ifa_addr->sa_family == sa.sa.sa_family) {
			match_found = sockaddr_copy(iface_it->ifa_addr,
						    &ifaddr) &&
				      sockaddrs_eq(&sa, &ifaddr);
			break;
		}
	}

	return match_found;
}

#ifdef __linux__
#define NETLINK_BUFFER_SIZE	4096
#define NETLINK_SEQ_NUM	1

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
	char buf[NETLINK_BUFFER_SIZE] = {};
	union sockaddr_any src, dst;
	struct msghdr msg = {};
	struct nlmsghdr *nlh;
	struct rtmsg *rtmsg;
	struct rtattr *rta;
	int nlen, attrlen;
	struct iovec iov;
	int fd, ret = 0;

	if (!daddr || !ifname)
		return -EINVAL;

	ret = parse_numeric_addr(daddr, &dst);
	if (ret < 0)
		return ret;

	if (saddr) {
		ret = parse_numeric_addr(saddr, &src);
		if (ret < 0)
			return ret;

		if (src.sa.sa_family != dst.sa.sa_family)
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
	rtmsg->rtm_family = dst.sa.sa_family;
	rtmsg->rtm_dst_len = (dst.sa.sa_family == AF_INET) ? 32 : 128;

	nlh->nlmsg_len += sizeof(struct rtmsg);

	/* append attribute RTA_DST */
	if (dst.sa.sa_family == AF_INET) {
		ret = rtattr_append(nlh, buf, sizeof(buf), RTA_DST,
				&dst.in4.sin_addr, sizeof(struct in_addr));
		if (ret)
			goto out;
	} else {
		ret = rtattr_append(nlh, buf, sizeof(buf), RTA_DST,
				&dst.in6.sin6_addr, sizeof(struct in6_addr));
		if (ret)
			goto out;
	}

	if (saddr) {
		/* append attribute RTA_SRC */
		if (src.sa.sa_family == AF_INET) {
			ret = rtattr_append(nlh, buf, sizeof(buf), RTA_SRC,
				&src.in4.sin_addr, sizeof(struct in_addr));
			if (ret)
				goto out;
		} else {
			ret = rtattr_append(nlh, buf, sizeof(buf), RTA_SRC,
				&src.in6.sin6_addr, sizeof(struct in6_addr));
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

			return err->error;
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

int shr_netdev_get_hw_queues(const char *ifname, uint32_t *combined_count,
		uint32_t *tx_count, uint32_t *rx_count)
{
	struct ethtool_channels chan = {};
	struct ifreq ifr = {};
	int fd, ret = 0;

	if (!ifname || !combined_count || !tx_count || !rx_count)
		return -EINVAL;

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0)
		return -errno;

	chan.cmd = ETHTOOL_GCHANNELS;
	snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", ifname);
	ifr.ifr_data = (void *)&chan;

	if (ioctl(fd, SIOCETHTOOL, &ifr) < 0) {
		ret = -errno;
		goto out;
	}

	*combined_count = chan.combined_count;
	*tx_count = chan.tx_count;
	*rx_count = chan.rx_count;
out:
	close(fd);
	return ret;
}
#endif /* __linux__ */
