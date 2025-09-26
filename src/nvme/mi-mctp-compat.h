/* SPDX-License-Identifier: LGPL-2.1-or-later */

#ifndef _MI_MCTP_COMPAT_H
#define _MI_MCTP_COMPAT_H

#include <linux/types.h>

/* As of kernel v5.15, these AF_MCTP-related definitions are provided by
 * linux/mctp.h. However, we provide a set here while that header percolates
 * through to standard includes.
 *
 * These were all introduced in the same version as AF_MCTP was defined,
 * so we can key off the presence of that.
 */

typedef __u8			mctp_eid_t;

struct mctp_addr {
	mctp_eid_t		s_addr;
};

struct sockaddr_mctp {
	unsigned short int	smctp_family;
	__u16			__smctp_pad0;
	unsigned int		smctp_network;
	struct mctp_addr	smctp_addr;
	__u8			smctp_type;
	__u8			smctp_tag;
	__u8			__smctp_pad1;
};

#define MCTP_NET_ANY		0x0

#define MCTP_ADDR_NULL		0x00
#define MCTP_ADDR_ANY		0xff

#define MCTP_TAG_MASK		0x07
#define MCTP_TAG_OWNER		0x08

#endif /* _MI_MCTP_COMPAT_H */
