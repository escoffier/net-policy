/*
 * (C) 2005-2011 by Pablo Neira Ayuso <pablo@netfilter.org>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include "internal/internal.h"

/* these arrays are used by snprintf_default.c and snprintf_xml.c */
const char *const l3proto2str[AF_MAX] = {
	[AF_INET]			= "ipv4",
	[AF_INET6]			= "ipv6",
};

const char *const proto2str[IPPROTO_MAX] = {
	[IPPROTO_TCP]			= "tcp",
	[IPPROTO_UDP]			= "udp",
	[IPPROTO_UDPLITE]		= "udplite",
	[IPPROTO_ICMP]			= "icmp",
	[IPPROTO_ICMPV6]		= "icmpv6",
	[IPPROTO_SCTP]			= "sctp",
	[IPPROTO_GRE]			= "gre",
	[IPPROTO_DCCP]			= "dccp",
};

const char *const states[TCP_CONNTRACK_MAX] = {
	[TCP_CONNTRACK_NONE]		= "NONE",
	[TCP_CONNTRACK_SYN_SENT]	= "SYN_SENT",
	[TCP_CONNTRACK_SYN_RECV]	= "SYN_RECV",
	[TCP_CONNTRACK_ESTABLISHED]	= "ESTABLISHED",
	[TCP_CONNTRACK_FIN_WAIT]	= "FIN_WAIT",
	[TCP_CONNTRACK_CLOSE_WAIT]	= "CLOSE_WAIT",
	[TCP_CONNTRACK_LAST_ACK]	= "LAST_ACK",
	[TCP_CONNTRACK_TIME_WAIT]	= "TIME_WAIT",
	[TCP_CONNTRACK_CLOSE]		= "CLOSE",
	[TCP_CONNTRACK_SYN_SENT2]	= "SYN_SENT2",
};

int __snprintf_conntrack(char *buf,
			 unsigned int len,
			 const struct nf_conntrack *ct,
			 unsigned int type,
			 unsigned int msg_output,
			 unsigned int flags,
			 struct nfct_labelmap *map)
{
	int size = __snprintf_conntrack_default(buf, len, ct, type, flags, map);

	/* NULL terminated string */
	buf[size+1 > len ? len-1 : size] = '\0';

	return size;
}
