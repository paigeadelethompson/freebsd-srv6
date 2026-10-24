/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef _SRV6_H_
#define _SRV6_H_

#include <sys/param.h>
#include <sys/types.h>
#include <sys/mbuf.h>
#include <sys/mutex.h>
#include <sys/queue.h>
#include <sys/socket.h>

#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip6.h>

#include <netgraph/ng_message.h>
#include <netgraph/netgraph.h>

/*
 * SRv6 netgraph node type name and hooks.
 *
 * "in" is the default ingress hook, "out" is the default egress hook.
 * Additional hooks may be created and named in adjacency entries; they
 * are used by End.X and End.DX* behaviors.
 */
#define	NG_SRV6_NODE_TYPE	"srv6"
#define	NG_SRV6_HOOK_IN		"in"
#define	NG_SRV6_HOOK_OUT	"out"

/*
 * Netgraph control message cookie for the srv6 node type.
 */
#define	NG_SRV6_COOKIE		0x53525636	/* "SRV6" */

/*
 * SRv6 control message types.
 */
enum {
	NGM_SRV6_ADD_SID	= 1,	/* add or replace a local SID */
	NGM_SRV6_DEL_SID	= 2,	/* remove a local SID */
	NGM_SRV6_ADD_ADJ	= 3,	/* add or replace an L3 adjacency */
	NGM_SRV6_DEL_ADJ	= 4,	/* remove an L3 adjacency */
	NGM_SRV6_SET_SRC	= 5,	/* set default encapsulation source */
	NGM_SRV6_GET_STATS	= 6,	/* get node statistics */
	NGM_SRV6_GET_SID	= 7,	/* get one local SID */
	NGM_SRV6_GET_ADJ	= 8,	/* get one adjacency */
	NGM_SRV6_CLR_STATS	= 9,	/* clear all statistics */
};

/*
 * Maximum number of segments in an End.B6.Encaps policy.  This bounds the
 * size of a control message and the SRH pushed by the node.
 */
#define	SRV6_MAX_SEGMENTS	16

/*
 * Maximum number of local SID processing steps for one packet.  This is a
 * safety valve for CSID chains and misconfigured local SID loops.
 */
#define	SRV6_MAX_LOOPS		16

/*
 * On-wire constants.
 */
#define	SRV6_HDR_LEN		40	/* IPv6 header length */
#define	SRV6_SRH_MIN_LEN	8	/* fixed part of the SRH */
#define	SRV6_SID_LEN		16	/* 128-bit IPv6 address */
#define	SRV6_IPPROTO_ETHERNET	143	/* IANA "Ethernet" next header */

/*
 * SRv6 SID format: LOC:FUNCT:ARG (RFC 8986 Section 3.1).
 *
 * The SID is stored as a struct in6_addr (128 bits).  The lengths are used
 * by the NEXT-CSID and REPLACE-CSID flavors defined in RFC 9800.
 */
struct srv6_sid {
	struct in6_addr	addr;
	uint8_t		loc_len;
	uint8_t		funct_len;
	uint8_t		arg_len;
};

/*
 * IANA SRv6 endpoint behavior codepoints used by this driver.  The full
 * registry is in RFC 8986 Section 10.2 and RFC 9800 Section 12.1.  A
 * configuration carries the codepoint, not a private enum value.
 */
#define	SRV6_BEH_END			1
#define	SRV6_BEH_END_X			5
#define	SRV6_BEH_END_T			9
#define	SRV6_BEH_END_B6_ENCAPS		14
#define	SRV6_BEH_END_BM			15
#define	SRV6_BEH_END_DX6		16
#define	SRV6_BEH_END_DX4		17
#define	SRV6_BEH_END_DT6		18
#define	SRV6_BEH_END_DT4		19
#define	SRV6_BEH_END_DT46		20
#define	SRV6_BEH_END_DX2		21
#define	SRV6_BEH_END_DX2V		22
#define	SRV6_BEH_END_DT2U		23
#define	SRV6_BEH_END_DT2M		24
#define	SRV6_BEH_END_B6_ENCAPS_RED	27
#define	SRV6_BEH_END_NEXT_CSID		43
#define	SRV6_BEH_END_X_NEXT_CSID	52
#define	SRV6_BEH_END_T_NEXT_CSID	85
#define	SRV6_BEH_END_B6_NEXT_CSID	93
#define	SRV6_BEH_END_B6_RED_NEXT_CSID	94
#define	SRV6_BEH_END_BM_NEXT_CSID	95
#define	SRV6_BEH_END_LBS_NEXT_CSID	96
#define	SRV6_BEH_END_XLBS_NEXT_CSID	97
#define	SRV6_BEH_END_REPLACE_CSID	101
#define	SRV6_BEH_END_X_REPLACE_CSID	105
#define	SRV6_BEH_END_T_REPLACE_CSID	109
#define	SRV6_BEH_END_B6_REPLACE_CSID	114
#define	SRV6_BEH_END_BM_REPLACE_CSID	115
#define	SRV6_BEH_END_DX6_REPLACE	116
#define	SRV6_BEH_END_DX4_REPLACE	117
#define	SRV6_BEH_END_DT6_REPLACE	118
#define	SRV6_BEH_END_DT4_REPLACE	119
#define	SRV6_BEH_END_DT46_REPLACE	120
#define	SRV6_BEH_END_DX2_REPLACE	121
#define	SRV6_BEH_END_DX2V_REPLACE	122
#define	SRV6_BEH_END_DT2U_REPLACE	123
#define	SRV6_BEH_END_DT2M_REPLACE	124
#define	SRV6_BEH_END_B6_RED_REPLACE	127
#define	SRV6_BEH_END_LBS_REPLACE	140
#define	SRV6_BEH_END_XLBS_REPLACE	141

/*
 * Flavor bits.  PSP/USP/USD are encoded in the IANA codepoint; CSID flavor
 * bits are decoded from the codepoint as well.
 */
#define	SRV6_FLAVOR_PSP		0x01
#define	SRV6_FLAVOR_USP		0x02
#define	SRV6_FLAVOR_USD		0x04
#define	SRV6_FLAVOR_NEXT_CSID	0x08
#define	SRV6_FLAVOR_REPLACE_CSID 0x10

/*
 * Segment Routing Header (SRH) per RFC 8754 Section 2.  Routing Type is 4.
 * The Segment List follows as a variable-length array of 128-bit addresses.
 */
struct srv6_srh_hdr {
	uint8_t		next_header;
	uint8_t		hdr_ext_len;
	uint8_t		routing_type;
	uint8_t		segments_left;
	uint8_t		last_entry;
	uint8_t		flags;
	uint16_t	tag;
} __packed;

struct srv6_srh {
	uint8_t		next_header;
	uint8_t		hdr_ext_len;
	uint8_t		routing_type;
	uint8_t		segments_left;
	uint8_t		last_entry;
	uint8_t		flags;
	uint16_t	tag;
	struct in6_addr	segment_list[];
} __packed;

/*
 * SRH TLV (Type Length Value) per RFC 8754 Section 2.1.
 */
struct srv6_tlv {
	uint8_t	type;
	uint8_t	length;
	/* variable-length data follows */
} __packed;

/* TLV types */
#define	SRV6_TLV_PAD1		0	/* Padding TLV, 1 byte */
#define	SRV6_TLV_PADN		4	/* Padding TLV, variable */
#define	SRV6_TLV_HMAC		5	/* HMAC TLV */

/* Flag: HMAC D bit (Destination Address verification disabled) */
#define	SRV6_HMAC_D_BIT		0x80

/*
 * Local SID configuration passed through ngctl.
 *
 * "behavior" is the IANA codepoint.  "loc_len", "funct_len" and "arg_len"
 * describe the CSID layout for RFC 9800 flavors; they are ignored by
 * non-CSID behaviors.  "segments" is the SR Policy used by End.B6.Encaps.
 */
struct srv6_sid_config {
	struct in6_addr	addr;		/* the local SID */
	uint16_t	behavior;	/* IANA endpoint behavior codepoint */
	uint8_t		loc_len;	/* locator length (L) in bits */
	uint8_t		funct_len;	/* function length (F) in bits */
	uint8_t		arg_len;	/* argument length (A) in bits */
	uint8_t		reserved;
	uint32_t	adj_index;	/* adjacency for End.X/DX */
	uint32_t	fib_table;	/* IPv6 FIB table for End.T/DT6 */
	uint32_t	fib_table4;	/* IPv4 FIB table for DT4/DT46 */
	uint16_t	nsegments;	/* policy length for End.B6.Encaps */
	uint16_t	reserved2;
	struct in6_addr	src_addr;	/* encapsulation source */
	struct in6_addr	segments[SRV6_MAX_SEGMENTS];
};

/*
 * L3 adjacency.  "hook" names a netgraph hook on this node; packets for
 * End.X/End.DX* are sent out that hook.
 */
struct srv6_adj_config {
	struct in6_addr	nexthop;
	uint32_t	index;
	uint32_t	fib_table;
	char		hook[NG_HOOKSIZ];
};

/*
 * Node statistics returned by NGM_SRV6_GET_STATS.
 */
struct srv6_stats {
	uint64_t	packets_in;
	uint64_t	packets_out;
	uint64_t	packets_dropped;
	uint64_t	bytes_in;
	uint64_t	errors;
	uint64_t	sids;
	uint64_t	adjs;
};

/*
 * Per-SID/per-adjacency information returned by GET_SID/GET_ADJ.
 */
struct srv6_sid_info {
	struct srv6_sid_config	config;
	uint64_t		packets;
	uint64_t		bytes;
};

struct srv6_adj_info {
	struct srv6_adj_config	config;
	uint64_t		packets;
	uint64_t		bytes;
};

/*
 * Local SID table entry.
 */
struct srv6_sid_entry {
	LIST_ENTRY(srv6_sid_entry)	link;
	struct srv6_sid_config		config;
	uint64_t			packets;
	uint64_t			bytes;
};

/*
 * Adjacency table entry.
 */
struct srv6_adjacency {
	LIST_ENTRY(srv6_adjacency)	link;
	struct srv6_adj_config		config;
	uint64_t			packets;
	uint64_t			bytes;
};

LIST_HEAD(srv6_sid_list, srv6_sid_entry);
LIST_HEAD(srv6_adj_list, srv6_adjacency);

/*
 * SRv6 node private state.
 */
struct srv6_priv {
	node_p				node;
	struct mtx			lock;
	struct srv6_sid_list		sids;
	struct srv6_adj_list		adjs;
	struct in6_addr			default_src;
	uint64_t			packets_in;
	uint64_t			packets_out;
	uint64_t			packets_dropped;
	uint64_t			bytes_in;
	uint64_t			errors;
};

/*
 * Public data path API.
 */
int	srv6_process_packet(struct srv6_priv *, struct mbuf *);
int	srv6_parse_srh(struct mbuf *, int, struct srv6_srh *);
int	srv6_lookup_sid(struct srv6_priv *, const struct in6_addr *,
	    struct srv6_sid_config *);
int	srv6_encapsulate(struct mbuf **, const struct in6_addr *,
	    const struct in6_addr *, const struct in6_addr *, uint16_t, int);
int	srv6_decapsulate(struct mbuf *, int);

#endif /* _SRV6_H_ */
