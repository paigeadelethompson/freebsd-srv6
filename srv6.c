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
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/param.h>
#include <sys/types.h>
#include <sys/kernel.h>
#include <sys/libkern.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/module.h>
#include <sys/mutex.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/systm.h>

#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip6.h>

#include <netgraph/ng_message.h>
#include <netgraph/ng_parse.h>
#include <netgraph/netgraph.h>

#include "srv6.h"

MALLOC_DEFINE(M_SRV6, "srv6", "SRv6 netgraph node");

#define	IP6_OFF_PLEN		4
#define	IP6_OFF_NXT		6
#define	IP6_OFF_HLIM		7
#define	IP6_OFF_SRC		8
#define	IP6_OFF_DST		24

#define	SRV6_LOCK(priv)		mtx_lock(&(priv)->lock)
#define	SRV6_UNLOCK(priv)	mtx_unlock(&(priv)->lock)

/*
 * Debug trace for every error path.  Only prints when bootverbose is set,
 * so it is silent in normal operation.
 */
#define	SRV6_DEBUG(fmt, ...)	do {					\
	if (bootverbose)						\
		printf("srv6: %s: " fmt "\n", __func__, ##__VA_ARGS__);	\
} while (0)

/*
 * Internal packet description.  The flexible-array SRH definition is used
 * for the on-wire structure; a fixed-size copy is kept here.
 */
struct srv6_pkt {
	struct ip6_hdr		ip6;
	int			mlen;
	int			outer_len;
	int			upper_nxt;
	int			srh_off;
	int			srh_len;
	int			srh_prev_off;
	struct srv6_srh_hdr	srh;
};

enum srv6_base_behavior {
	SRV6_BASE_NONE = 0,
	SRV6_BASE_END,
	SRV6_BASE_END_X,
	SRV6_BASE_END_T,
	SRV6_BASE_B6_ENCAPS,
	SRV6_BASE_B6_ENCAPS_RED,
	SRV6_BASE_BM,
	SRV6_BASE_DX6,
	SRV6_BASE_DX4,
	SRV6_BASE_DT6,
	SRV6_BASE_DT4,
	SRV6_BASE_DT46,
	SRV6_BASE_DX2,
	SRV6_BASE_DX2V,
	SRV6_BASE_DT2U,
	SRV6_BASE_DT2M,
	SRV6_BASE_LBS,
	SRV6_BASE_XLBS,
};

enum srv6_action {
	SRV6_ACT_CONTINUE = 0,
	SRV6_ACT_FORWARD_OUT,
	SRV6_ACT_FORWARD_ADJ,
};

struct srv6_result {
	enum srv6_action	action;
	uint32_t		fib_table;
	uint32_t		adj_index;
};

/* Netgraph methods. */
static ng_constructor_t	srv6_ng_constructor;
static ng_rcvmsg_t	srv6_ng_rcvmsg;
static ng_shutdown_t	srv6_ng_shutdown;
static ng_newhook_t	srv6_ng_newhook;
static ng_rcvdata_t	srv6_ng_rcvdata;
static ng_disconnect_t	srv6_ng_disconnect;

/* Parse helpers. */
static int	srv6_ip6_parse(const struct ng_parse_type *, const char *, int *,
		    const u_char *, u_char *, int *);
static int	srv6_ip6_unparse(const struct ng_parse_type *, const u_char *,
		    int *, char *, int);
static int	srv6_ip6_getDefault(const struct ng_parse_type *, const u_char *,
		    u_char *, int *);
static int	srv6_ip6_getAlign(const struct ng_parse_type *);

/* Control and table helpers. */
static int	srv6_validate_sid(const struct srv6_sid_config *);
static int	srv6_lookup_adj(struct srv6_priv *, uint32_t,
		    struct srv6_adj_config *);
static int	srv6_behavior_decode(uint16_t, enum srv6_base_behavior *,
		    uint32_t *);
static int	srv6_csid_layout(const struct srv6_sid_config *, uint32_t,
		    int *, int *, int *);
static int	srv6_pick_src(struct srv6_priv *, const struct srv6_sid_config *,
		    const struct srv6_pkt *, struct in6_addr *);

/* Packet and SRH helpers. */
static int	srv6_parse_packet(struct mbuf *, struct srv6_pkt *);
static int	srv6_srh_valid(const struct srv6_pkt *);
static int	srv6_get_segment(struct mbuf *, const struct srv6_pkt *, int,
		    void *);
static int	srv6_update_da(struct mbuf *, struct srv6_pkt *, const void *);
static int	srv6_update_sl(struct mbuf *, struct srv6_pkt *, int);
static int	srv6_decrement_hlim(struct mbuf *, struct srv6_pkt *);
static int	srv6_pop_srh(struct mbuf *, struct srv6_pkt *);

/* Behavior execution. */
static int	srv6_execute(struct srv6_priv *, struct mbuf **,
		    struct srv6_pkt *, const struct srv6_sid_config *,
		    struct srv6_result *);
static int	srv6_process_end(struct srv6_priv *, struct mbuf *,
		    struct srv6_pkt *, const struct srv6_sid_config *,
		    enum srv6_base_behavior, uint32_t, struct srv6_result *);
static int	srv6_process_upper(struct srv6_priv *, struct mbuf *,
		    struct srv6_pkt *, const struct srv6_sid_config *,
		    enum srv6_base_behavior, uint32_t, struct srv6_result *);
static int	srv6_process_decap(struct srv6_priv *, struct mbuf *,
		    struct srv6_pkt *, const struct srv6_sid_config *,
		    enum srv6_base_behavior, struct srv6_result *);
static int	srv6_decap_and_forward(struct srv6_priv *, struct mbuf *,
		    struct srv6_pkt *, const struct srv6_sid_config *,
		    enum srv6_base_behavior, struct srv6_result *);
static int	srv6_process_b6(struct srv6_priv *, struct mbuf **,
		    struct srv6_pkt *, const struct srv6_sid_config *,
		    enum srv6_base_behavior, uint32_t, struct srv6_result *,
		    int);
static int	srv6_csid_process(struct mbuf *, struct srv6_pkt *,
		    const struct srv6_sid_config *, uint32_t, int *, int *);

/* Bit helpers for compressed SIDs. */
static int	srv6_bit(const uint8_t *, int);
static int	srv6_bits_nonzero(const uint8_t *, int, int);
static uint64_t	srv6_get_bits64(const uint8_t *, int, int);
static void	srv6_copy_bits(uint8_t *, int, const uint8_t *, int, int);
static void	srv6_zero_bits(uint8_t *, int, int);
static void	srv6_put_bits64(uint8_t *, int, int, uint64_t);
static int	srv6_log2ceil(int);
static void	srv6_csid_build(uint8_t *, const uint8_t *, const uint8_t *, int,
		    int, int, int, int);

/* Forwarding and accounting. */
static int	srv6_send(struct srv6_priv *, struct mbuf *, const char *);
static int	srv6_forward_out(struct srv6_priv *, struct mbuf *, uint32_t);
static int	srv6_forward_adj(struct srv6_priv *, struct mbuf *, uint32_t);
static void	srv6_set_fib(struct mbuf *, uint32_t);
static void	srv6_drop(struct srv6_priv *, struct mbuf *, int);
static void	srv6_sid_account(struct srv6_priv *, const struct in6_addr *,
		    uint64_t);

/*
 * IPv6 address parse type.  netgraph has an IPv4 type but no IPv6 type.
 */
static int
srv6_ip6_parse(__unused const struct ng_parse_type *type, const char *s,
    int *off, __unused const u_char *start, u_char *buf, int *buflen)
{
	char tmp[INET6_ADDRSTRLEN];
	size_t len;

	if (*buflen < (int)sizeof(struct in6_addr)) {
		SRV6_DEBUG("ip6 parse: buflen too small");
		return (ERANGE);
	}
	len = strcspn(s + *off, " \t\r\n,}]");
	if (len == 0 || len >= sizeof(tmp)) {
		SRV6_DEBUG("ip6 parse: bad address length");
		return (EINVAL);
	}
	memcpy(tmp, s + *off, len);
	tmp[len] = '\0';
	if (inet_pton(AF_INET6, tmp, buf) != 1) {
		SRV6_DEBUG("ip6 parse: inet_pton failed");
		return (EINVAL);
	}
	*off += len;
	*buflen = sizeof(struct in6_addr);
	return (0);
}

static int
srv6_ip6_unparse(__unused const struct ng_parse_type *type,
    const u_char *data, int *off, char *cbuf, int cbuflen)
{
	char tmp[INET6_ADDRSTRLEN];

	if (inet_ntop(AF_INET6, data + *off, tmp, sizeof(tmp)) == NULL) {
		SRV6_DEBUG("ip6 unparse: inet_ntop failed");
		return (EINVAL);
	}
	if (strlcpy(cbuf, tmp, cbuflen) >= (size_t)cbuflen) {
		SRV6_DEBUG("ip6 unparse: buffer too small");
		return (ERANGE);
	}
	*off += sizeof(struct in6_addr);
	return (0);
}

static int
srv6_ip6_getDefault(__unused const struct ng_parse_type *type,
    __unused const u_char *start, u_char *buf, int *buflen)
{
	if (*buflen < (int)sizeof(struct in6_addr))
		return (ERANGE);
	bzero(buf, sizeof(struct in6_addr));
	*buflen = sizeof(struct in6_addr);
	return (0);
}

static int
srv6_ip6_getAlign(__unused const struct ng_parse_type *type)
{
	return (4);
}

static const struct ng_parse_type srv6_ip6_type = {
	NULL,
	NULL,
	NULL,
	srv6_ip6_parse,
	srv6_ip6_unparse,
	srv6_ip6_getDefault,
	srv6_ip6_getAlign
};

static const struct ng_parse_fixedarray_info srv6_segments_info = {
	&srv6_ip6_type,
	SRV6_MAX_SEGMENTS,
	NULL
};

static const struct ng_parse_type srv6_segments_type = {
	&ng_parse_fixedarray_type,
	&srv6_segments_info
};

static const struct ng_parse_struct_field srv6_sid_config_fields[] = {
	{ "addr", &srv6_ip6_type },
	{ "behavior", &ng_parse_uint16_type },
	{ "loc_len", &ng_parse_uint8_type },
	{ "funct_len", &ng_parse_uint8_type },
	{ "arg_len", &ng_parse_uint8_type },
	{ "reserved", &ng_parse_uint8_type },
	{ "adj_index", &ng_parse_uint32_type },
	{ "fib_table", &ng_parse_uint32_type },
	{ "fib_table4", &ng_parse_uint32_type },
	{ "nsegments", &ng_parse_uint16_type },
	{ "reserved2", &ng_parse_uint16_type },
	{ "src_addr", &srv6_ip6_type },
	{ "segments", &srv6_segments_type },
	{ NULL }
};

static const struct ng_parse_type srv6_sid_config_type = {
	&ng_parse_struct_type,
	&srv6_sid_config_fields
};

static const struct ng_parse_fixedstring_info srv6_hook_info = {
	NG_HOOKSIZ
};

static const struct ng_parse_type srv6_hook_type = {
	&ng_parse_fixedstring_type,
	&srv6_hook_info
};

static const struct ng_parse_struct_field srv6_adj_config_fields[] = {
	{ "nexthop", &srv6_ip6_type },
	{ "index", &ng_parse_uint32_type },
	{ "fib_table", &ng_parse_uint32_type },
	{ "hook", &srv6_hook_type },
	{ NULL }
};

static const struct ng_parse_type srv6_adj_config_type = {
	&ng_parse_struct_type,
	&srv6_adj_config_fields
};

static const struct ng_parse_struct_field srv6_stats_fields[] = {
	{ "packets_in", &ng_parse_uint64_type },
	{ "packets_out", &ng_parse_uint64_type },
	{ "packets_dropped", &ng_parse_uint64_type },
	{ "bytes_in", &ng_parse_uint64_type },
	{ "errors", &ng_parse_uint64_type },
	{ "sids", &ng_parse_uint64_type },
	{ "adjs", &ng_parse_uint64_type },
	{ NULL }
};

static const struct ng_parse_type srv6_stats_type = {
	&ng_parse_struct_type,
	&srv6_stats_fields
};

static const struct ng_parse_struct_field srv6_sid_info_fields[] = {
	{ "config", &srv6_sid_config_type },
	{ "packets", &ng_parse_uint64_type },
	{ "bytes", &ng_parse_uint64_type },
	{ NULL }
};

static const struct ng_parse_type srv6_sid_info_type = {
	&ng_parse_struct_type,
	&srv6_sid_info_fields
};

static const struct ng_parse_struct_field srv6_adj_info_fields[] = {
	{ "config", &srv6_adj_config_type },
	{ "packets", &ng_parse_uint64_type },
	{ "bytes", &ng_parse_uint64_type },
	{ NULL }
};

static const struct ng_parse_type srv6_adj_info_type = {
	&ng_parse_struct_type,
	&srv6_adj_info_fields
};

/*
 * Control message table.
 */
static const struct ng_cmdlist srv6_cmdlist[] = {
	{
		NG_SRV6_COOKIE,
		NGM_SRV6_ADD_SID,
		"addsid",
		&srv6_sid_config_type,
		NULL
	},
	{
		NG_SRV6_COOKIE,
		NGM_SRV6_DEL_SID,
		"delsid",
		&srv6_ip6_type,
		NULL
	},
	{
		NG_SRV6_COOKIE,
		NGM_SRV6_ADD_ADJ,
		"addadj",
		&srv6_adj_config_type,
		NULL
	},
	{
		NG_SRV6_COOKIE,
		NGM_SRV6_DEL_ADJ,
		"deladj",
		&ng_parse_uint32_type,
		NULL
	},
	{
		NG_SRV6_COOKIE,
		NGM_SRV6_SET_SRC,
		"setsrc",
		&srv6_ip6_type,
		NULL
	},
	{
		NG_SRV6_COOKIE,
		NGM_SRV6_GET_STATS,
		"getstats",
		NULL,
		&srv6_stats_type
	},
	{
		NG_SRV6_COOKIE,
		NGM_SRV6_GET_SID,
		"getsid",
		&srv6_ip6_type,
		&srv6_sid_info_type
	},
	{
		NG_SRV6_COOKIE,
		NGM_SRV6_GET_ADJ,
		"getadj",
		&ng_parse_uint32_type,
		&srv6_adj_info_type
	},
	{
		NG_SRV6_COOKIE,
		NGM_SRV6_CLR_STATS,
		"clrstats",
		NULL,
		NULL
	},
	{ 0 }
};

/*
 * Decode an IANA endpoint behavior codepoint into a base behavior and
 * flavor bits.
 */
static int
srv6_behavior_decode(uint16_t cp, enum srv6_base_behavior *base,
    uint32_t *flags)
{
	*base = SRV6_BASE_NONE;
	*flags = 0;

	switch (cp) {
	case 1:
	case 2:
	case 3:
	case 4:
		*base = SRV6_BASE_END;
		*flags = cp - 1;
		return (0);
	case 5:
	case 6:
	case 7:
	case 8:
		*base = SRV6_BASE_END_X;
		*flags = cp - 5;
		return (0);
	case 9:
	case 10:
	case 11:
	case 12:
		*base = SRV6_BASE_END_T;
		*flags = cp - 9;
		return (0);
	case 14:
		*base = SRV6_BASE_B6_ENCAPS;
		return (0);
	case 15:
		*base = SRV6_BASE_BM;
		return (0);
	case 16:
		*base = SRV6_BASE_DX6;
		return (0);
	case 17:
		*base = SRV6_BASE_DX4;
		return (0);
	case 18:
		*base = SRV6_BASE_DT6;
		return (0);
	case 19:
		*base = SRV6_BASE_DT4;
		return (0);
	case 20:
		*base = SRV6_BASE_DT46;
		return (0);
	case 21:
		*base = SRV6_BASE_DX2;
		return (0);
	case 22:
		*base = SRV6_BASE_DX2V;
		return (0);
	case 23:
		*base = SRV6_BASE_DT2U;
		return (0);
	case 24:
		*base = SRV6_BASE_DT2M;
		return (0);
	case 27:
		*base = SRV6_BASE_B6_ENCAPS_RED;
		return (0);
	case 28:
	case 29:
	case 30:
	case 31:
		*base = SRV6_BASE_END;
		*flags = SRV6_FLAVOR_USD | (cp - 28);
		return (0);
	case 32:
	case 33:
	case 34:
	case 35:
		*base = SRV6_BASE_END_X;
		*flags = SRV6_FLAVOR_USD | (cp - 32);
		return (0);
	case 36:
	case 37:
	case 38:
	case 39:
		*base = SRV6_BASE_END_T;
		*flags = SRV6_FLAVOR_USD | (cp - 36);
		return (0);
	case 43:
	case 44:
	case 45:
	case 46:
	case 47:
	case 48:
	case 49:
	case 50:
		*base = SRV6_BASE_END;
		*flags = SRV6_FLAVOR_NEXT_CSID | (cp - 43);
		return (0);
	case 52:
	case 53:
	case 54:
	case 55:
	case 56:
	case 57:
	case 58:
	case 59:
		*base = SRV6_BASE_END_X;
		*flags = SRV6_FLAVOR_NEXT_CSID | (cp - 52);
		return (0);
	case 85:
	case 86:
	case 87:
	case 88:
	case 89:
	case 90:
	case 91:
	case 92:
		*base = SRV6_BASE_END_T;
		*flags = SRV6_FLAVOR_NEXT_CSID | (cp - 85);
		return (0);
	case 93:
		*base = SRV6_BASE_B6_ENCAPS;
		*flags = SRV6_FLAVOR_NEXT_CSID;
		return (0);
	case 94:
		*base = SRV6_BASE_B6_ENCAPS_RED;
		*flags = SRV6_FLAVOR_NEXT_CSID;
		return (0);
	case 95:
		*base = SRV6_BASE_BM;
		*flags = SRV6_FLAVOR_NEXT_CSID;
		return (0);
	case 96:
		*base = SRV6_BASE_LBS;
		*flags = SRV6_FLAVOR_NEXT_CSID;
		return (0);
	case 97:
		*base = SRV6_BASE_XLBS;
		*flags = SRV6_FLAVOR_NEXT_CSID;
		return (0);
	case 101:
	case 102:
	case 103:
	case 104:
		*base = SRV6_BASE_END;
		*flags = SRV6_FLAVOR_REPLACE_CSID | (cp - 101);
		return (0);
	case 105:
	case 106:
	case 107:
	case 108:
		*base = SRV6_BASE_END_X;
		*flags = SRV6_FLAVOR_REPLACE_CSID | (cp - 105);
		return (0);
	case 109:
	case 110:
	case 111:
	case 112:
		*base = SRV6_BASE_END_T;
		*flags = SRV6_FLAVOR_REPLACE_CSID | (cp - 109);
		return (0);
	case 114:
		*base = SRV6_BASE_B6_ENCAPS;
		*flags = SRV6_FLAVOR_REPLACE_CSID;
		return (0);
	case 115:
		*base = SRV6_BASE_BM;
		*flags = SRV6_FLAVOR_REPLACE_CSID;
		return (0);
	case 116:
		*base = SRV6_BASE_DX6;
		*flags = SRV6_FLAVOR_REPLACE_CSID;
		return (0);
	case 117:
		*base = SRV6_BASE_DX4;
		*flags = SRV6_FLAVOR_REPLACE_CSID;
		return (0);
	case 118:
		*base = SRV6_BASE_DT6;
		*flags = SRV6_FLAVOR_REPLACE_CSID;
		return (0);
	case 119:
		*base = SRV6_BASE_DT4;
		*flags = SRV6_FLAVOR_REPLACE_CSID;
		return (0);
	case 120:
		*base = SRV6_BASE_DT46;
		*flags = SRV6_FLAVOR_REPLACE_CSID;
		return (0);
	case 121:
		*base = SRV6_BASE_DX2;
		*flags = SRV6_FLAVOR_REPLACE_CSID;
		return (0);
	case 122:
		*base = SRV6_BASE_DX2V;
		*flags = SRV6_FLAVOR_REPLACE_CSID;
		return (0);
	case 123:
		*base = SRV6_BASE_DT2U;
		*flags = SRV6_FLAVOR_REPLACE_CSID;
		return (0);
	case 124:
		*base = SRV6_BASE_DT2M;
		*flags = SRV6_FLAVOR_REPLACE_CSID;
		return (0);
	case 127:
		*base = SRV6_BASE_B6_ENCAPS_RED;
		*flags = SRV6_FLAVOR_REPLACE_CSID;
		return (0);
	case 128:
	case 129:
	case 130:
	case 131:
		*base = SRV6_BASE_END;
		*flags = SRV6_FLAVOR_REPLACE_CSID | SRV6_FLAVOR_USD |
		    (cp - 128);
		return (0);
	case 132:
	case 133:
	case 134:
	case 135:
		*base = SRV6_BASE_END_X;
		*flags = SRV6_FLAVOR_REPLACE_CSID | SRV6_FLAVOR_USD |
		    (cp - 132);
		return (0);
	case 136:
	case 137:
	case 138:
	case 139:
		*base = SRV6_BASE_END_T;
		*flags = SRV6_FLAVOR_REPLACE_CSID | SRV6_FLAVOR_USD |
		    (cp - 136);
		return (0);
	case 140:
		*base = SRV6_BASE_LBS;
		*flags = SRV6_FLAVOR_REPLACE_CSID;
		return (0);
	case 141:
		*base = SRV6_BASE_XLBS;
		*flags = SRV6_FLAVOR_REPLACE_CSID;
		return (0);
	case 32767:
		*base = SRV6_BASE_END;
		return (0);
	default:
		SRV6_DEBUG("behavior decode: unknown codepoint %u", cp);
		return (EINVAL);
	}
}

static int
srv6_validate_sid(const struct srv6_sid_config *cfg)
{
	enum srv6_base_behavior base;
	uint32_t flags;
	int error;

	error = srv6_behavior_decode(cfg->behavior, &base, &flags);
	if (error != 0) {
		SRV6_DEBUG("validate sid: behavior decode failed: %d", error);
		return (error);
	}

	switch (base) {
	case SRV6_BASE_BM:
	case SRV6_BASE_DX2V:
	case SRV6_BASE_DT2U:
	case SRV6_BASE_DT2M:
	case SRV6_BASE_LBS:
	case SRV6_BASE_XLBS:
		SRV6_DEBUG("validate sid: behavior %u not supported", base);
		return (EOPNOTSUPP);
	default:
		break;
	}

	if (cfg->nsegments > SRV6_MAX_SEGMENTS) {
		SRV6_DEBUG("validate sid: too many segments %u", cfg->nsegments);
		return (EINVAL);
	}

	if ((base == SRV6_BASE_B6_ENCAPS ||
	    base == SRV6_BASE_B6_ENCAPS_RED) && cfg->nsegments == 0) {
		SRV6_DEBUG("validate sid: B6 encap with no segments");
		return (EINVAL);
	}

	if ((base == SRV6_BASE_END_X || base == SRV6_BASE_DX6 ||
	    base == SRV6_BASE_DX4 || base == SRV6_BASE_DX2) &&
	    cfg->adj_index == 0) {
		SRV6_DEBUG("validate sid: End.X/DX with no adjacency");
		return (EINVAL);
	}

	if ((flags & (SRV6_FLAVOR_NEXT_CSID | SRV6_FLAVOR_REPLACE_CSID)) != 0 &&
	    (base == SRV6_BASE_END || base == SRV6_BASE_END_X ||
	    base == SRV6_BASE_END_T || base == SRV6_BASE_B6_ENCAPS ||
	    base == SRV6_BASE_B6_ENCAPS_RED)) {
		int A, F, L;

		error = srv6_csid_layout(cfg, flags, &L, &F, &A);
		if (error != 0) {
			SRV6_DEBUG("validate sid: csid layout failed: %d", error);
			return (error);
		}
	}

	return (0);
}

static int
srv6_lookup_adj(struct srv6_priv *priv, uint32_t index,
    struct srv6_adj_config *out)
{
	struct srv6_adjacency *adj;
	int error;

	error = ENOENT;
	SRV6_LOCK(priv);
	LIST_FOREACH(adj, &priv->adjs, link) {
		if (adj->config.index == index) {
			*out = adj->config;
			error = 0;
			break;
		}
	}
	SRV6_UNLOCK(priv);
	if (error != 0)
		SRV6_DEBUG("lookup adj: index %u not found", index);
	return (error);
}

int
srv6_lookup_sid(struct srv6_priv *priv, const struct in6_addr *addr,
    struct srv6_sid_config *out)
{
	struct srv6_sid_entry *sid;
	int error;

	error = ENOENT;
	SRV6_LOCK(priv);
	LIST_FOREACH(sid, &priv->sids, link) {
		if (IN6_ARE_ADDR_EQUAL(addr, &sid->config.addr)) {
			*out = sid->config;
			error = 0;
			break;
		}
	}
	SRV6_UNLOCK(priv);
	return (error);
}

/*
 * Parse an IPv6 header and its extension header chain.  The parser stops at
 * the first non-extension header, which is the upper-layer header for the
 * purposes of SRv6 decapsulation.
 */
static int
srv6_parse_packet(struct mbuf *m, struct srv6_pkt *pkt)
{
	struct ip6_ext ext;
	struct srv6_srh_hdr srh;
	int hlen, max_le, mlen, nxt, off, prev_off, slen;

	memset(pkt, 0, sizeof(*pkt));
	pkt->srh_off = -1;
	pkt->srh_prev_off = -1;

	mlen = m_length(m, NULL);
	if (mlen < (int)sizeof(struct ip6_hdr)) {
		SRV6_DEBUG("parse packet: too short %d", mlen);
		return (EMSGSIZE);
	}
	m_copydata(m, 0, sizeof(struct ip6_hdr), &pkt->ip6);
	if ((pkt->ip6.ip6_vfc & IPV6_VERSION_MASK) != IPV6_VERSION) {
		SRV6_DEBUG("parse packet: not IPv6");
		return (EINVAL);
	}

	pkt->mlen = mlen;
	off = sizeof(struct ip6_hdr);
	nxt = pkt->ip6.ip6_nxt;
	prev_off = -1;

	for (;;) {
		if (nxt == IPPROTO_NONE || nxt == IPPROTO_ESP) {
			pkt->outer_len = off;
			pkt->upper_nxt = nxt;
			return (0);
		}
		if (off + (int)sizeof(struct ip6_ext) > mlen) {
			SRV6_DEBUG("parse packet: extension header too short");
			return (EMSGSIZE);
		}
		m_copydata(m, off, sizeof(struct ip6_ext), &ext);

		switch (nxt) {
		case IPPROTO_FRAGMENT:
			hlen = 8;
			break;
		case IPPROTO_AH:
			hlen = (ext.ip6e_len + 2) * 4;
			break;
		case IPPROTO_HOPOPTS:
		case IPPROTO_ROUTING:
		case IPPROTO_DSTOPTS:
			hlen = (ext.ip6e_len + 1) * 8;
			break;
		default:
			pkt->outer_len = off;
			pkt->upper_nxt = nxt;
			return (0);
		}

		if (hlen < 8 || off + hlen > mlen) {
			SRV6_DEBUG("parse packet: invalid extension length");
			return (EMSGSIZE);
		}

		if (nxt == IPPROTO_ROUTING) {
			m_copydata(m, off, sizeof(srh), &srh);
			if (srh.routing_type == 4 && pkt->srh_off < 0) {
				slen = (srh.hdr_ext_len + 1) * 8;
				if (slen != hlen || (srh.hdr_ext_len & 1) != 0) {
					SRV6_DEBUG("parse packet: bad SRH length");
					return (EINVAL);
				}
				max_le = srh.hdr_ext_len / 2 - 1;
				if (max_le < 0 || srh.last_entry > max_le) {
					SRV6_DEBUG("parse packet: bad SRH last_entry");
					return (EINVAL);
				}
				if ((int)sizeof(srh) +
				    (srh.last_entry + 1) * SRV6_SID_LEN > slen) {
					SRV6_DEBUG("parse packet: SRH segment list overflow");
					return (EINVAL);
				}
				pkt->srh_off = off;
				pkt->srh_len = slen;
				pkt->srh = srh;
				pkt->srh_prev_off = prev_off;
			}
		}

		prev_off = off;
		nxt = ext.ip6e_nxt;
		off += hlen;
	}
}

int
srv6_parse_srh(struct mbuf *m, int off, struct srv6_srh *srh)
{
	int max_le, mlen, slen;

	mlen = m_length(m, NULL);
	if (off < 0 || off + (int)sizeof(struct srv6_srh) > mlen) {
		SRV6_DEBUG("parse srh: offset out of range off=%d", off);
		return (EMSGSIZE);
	}
	m_copydata(m, off, sizeof(struct srv6_srh), srh);
	if (srh->routing_type != 4 || (srh->hdr_ext_len & 1) != 0) {
		SRV6_DEBUG("parse srh: bad routing type or ext len");
		return (EINVAL);
	}
	slen = (srh->hdr_ext_len + 1) * 8;
	if (off + slen > mlen) {
		SRV6_DEBUG("parse srh: SRH extends past mbuf");
		return (EMSGSIZE);
	}
	max_le = srh->hdr_ext_len / 2 - 1;
	if (max_le < 0 || srh->last_entry > max_le) {
		SRV6_DEBUG("parse srh: bad last_entry %u", srh->last_entry);
		return (EINVAL);
	}
	if ((int)sizeof(struct srv6_srh) +
	    (srh->last_entry + 1) * SRV6_SID_LEN > slen) {
		SRV6_DEBUG("parse srh: segment list overflow");
		return (EINVAL);
	}
	return (0);
}

static int
srv6_srh_valid(const struct srv6_pkt *pkt)
{
	int max_le;

	if (pkt->srh_off < 0)
		return (0);
	if (pkt->srh.routing_type != 4 || (pkt->srh.hdr_ext_len & 1) != 0) {
		SRV6_DEBUG("srh valid: bad routing type or ext len");
		return (EINVAL);
	}
	max_le = pkt->srh.hdr_ext_len / 2 - 1;
	if (max_le < 0 || pkt->srh.last_entry > max_le) {
		SRV6_DEBUG("srh valid: bad last_entry %u",
		    pkt->srh.last_entry);
		return (EINVAL);
	}
	if (pkt->srh.segments_left > pkt->srh.last_entry + 1) {
		SRV6_DEBUG("srh valid: segments_left %u > last_entry+1",
		    pkt->srh.segments_left);
		return (EINVAL);
	}
	if (pkt->srh_len != (pkt->srh.hdr_ext_len + 1) * 8) {
		SRV6_DEBUG("srh valid: srh_len mismatch");
		return (EINVAL);
	}
	return (0);
}

static int
srv6_get_segment(struct mbuf *m, const struct srv6_pkt *pkt, int index,
    void *seg)
{
	int off;

	if (index < 0 || index > pkt->srh.last_entry) {
		SRV6_DEBUG("get segment: index %d out of range", index);
		return (EINVAL);
	}
	off = pkt->srh_off + sizeof(struct srv6_srh_hdr) +
	    index * SRV6_SID_LEN;
	if (off + SRV6_SID_LEN > pkt->srh_off + pkt->srh_len) {
		SRV6_DEBUG("get segment: index %d extends past SRH", index);
		return (EINVAL);
	}
	m_copydata(m, off, SRV6_SID_LEN, seg);
	return (0);
}

static int
srv6_update_da(struct mbuf *m, struct srv6_pkt *pkt, const void *addr)
{
	m_copyback(m, IP6_OFF_DST, SRV6_SID_LEN, addr);
	memcpy(&pkt->ip6.ip6_dst, addr, SRV6_SID_LEN);
	return (0);
}

static int
srv6_update_sl(struct mbuf *m, struct srv6_pkt *pkt, int sl)
{
	uint8_t v;

	if (sl < 0 || sl > 255) {
		SRV6_DEBUG("update sl: invalid segments_left %d", sl);
		return (EINVAL);
	}
	v = sl;
	m_copyback(m, pkt->srh_off +
	    offsetof(struct srv6_srh_hdr, segments_left), 1, &v);
	pkt->srh.segments_left = v;
	return (0);
}

static int
srv6_decrement_hlim(struct mbuf *m, struct srv6_pkt *pkt)
{
	uint8_t hlim;

	hlim = pkt->ip6.ip6_hlim;
	if (hlim <= 1) {
		SRV6_DEBUG("decrement hlim: hlim too low %u", hlim);
		return (EHOSTUNREACH);
	}
	hlim--;
	m_copyback(m, IP6_OFF_HLIM, 1, &hlim);
	pkt->ip6.ip6_hlim = hlim;
	return (0);
}

/*
 * Remove the SRH from the extension header chain.  The SRH is removed from
 * the middle of the packet, so the tail is shifted left in chunks before
 * trimming the mbuf chain.
 */
static int
srv6_pop_srh(struct mbuf *m, struct srv6_pkt *pkt)
{
	uint8_t buf[256];
	uint8_t nxt;
	uint16_t plen;
	int chunk, off, shift, total;

	if (pkt->srh_off < 0)
		return (0);

	shift = pkt->srh_len;
	total = m_length(m, NULL);
	if (shift <= 0 || pkt->srh_off + shift > total) {
		SRV6_DEBUG("pop srh: invalid shift %d off %d total %d",
		    shift, pkt->srh_off, total);
		return (EINVAL);
	}

	nxt = pkt->srh.next_header;
	if (pkt->srh_prev_off < 0)
		m_copyback(m, IP6_OFF_NXT, 1, &nxt);
	else
		m_copyback(m, pkt->srh_prev_off, 1, &nxt);

	for (off = pkt->srh_off + shift; off < total; off += chunk) {
		chunk = min((int)sizeof(buf), total - off);
		m_copydata(m, off, chunk, buf);
		m_copyback(m, off - shift, chunk, buf);
	}
	m_adj(m, -shift);

	m_copydata(m, IP6_OFF_PLEN, sizeof(plen), &plen);
	plen = ntohs(plen);
	if (plen >= shift)
		plen -= shift;
	else
		plen = 0;
	plen = htons(plen);
	m_copyback(m, IP6_OFF_PLEN, sizeof(plen), &plen);

	return (srv6_parse_packet(m, pkt));
}

/*
 * Bit helpers.  Bit zero is the most significant bit of the first byte.
 */
static int
srv6_bit(const uint8_t *p, int bit)
{
	return ((p[bit / 8] >> (7 - (bit % 8))) & 1);
}

static int
srv6_bits_nonzero(const uint8_t *p, int bit, int nbits)
{
	int i;

	for (i = 0; i < nbits; i++) {
		if (srv6_bit(p, bit + i) != 0)
			return (1);
	}
	return (0);
}

static uint64_t
srv6_get_bits64(const uint8_t *p, int bit, int nbits)
{
	uint64_t v;
	int i;

	v = 0;
	for (i = 0; i < nbits; i++)
		v = (v << 1) | srv6_bit(p, bit + i);
	return (v);
}

static void
srv6_copy_bits(uint8_t *dst, int dbit, const uint8_t *src, int sbit, int nbits)
{
	int b, i;

	for (i = 0; i < nbits; i++) {
		b = srv6_bit(src, sbit + i);
		if (b != 0)
			dst[(dbit + i) / 8] |= 1 << (7 - ((dbit + i) % 8));
		else
			dst[(dbit + i) / 8] &= ~(1 << (7 - ((dbit + i) % 8)));
	}
}

static void
srv6_zero_bits(uint8_t *p, int bit, int nbits)
{
	int i;

	for (i = 0; i < nbits; i++)
		p[(bit + i) / 8] &= ~(1 << (7 - ((bit + i) % 8)));
}

static void
srv6_put_bits64(uint8_t *p, int bit, int nbits, uint64_t v)
{
	int b, i;

	for (i = 0; i < nbits; i++) {
		b = (v >> (nbits - 1 - i)) & 1;
		if (b != 0)
			p[(bit + i) / 8] |= 1 << (7 - ((bit + i) % 8));
		else
			p[(bit + i) / 8] &= ~(1 << (7 - ((bit + i) % 8)));
	}
}

static int
srv6_log2ceil(int v)
{
	int x;

	x = 0;
	while ((1 << x) < v)
		x++;
	return (x);
}

static int
srv6_csid_layout(const struct srv6_sid_config *sid, uint32_t flags,
    int *L, int *F, int *A)
{
	int K, X;

	*L = sid->loc_len;
	*F = sid->funct_len;
	*A = sid->arg_len;
	if (*F <= 0 || *L + *F + *A != 128) {
		SRV6_DEBUG("csid layout: invalid L/F/A lengths");
		return (EINVAL);
	}
	if ((flags & SRV6_FLAVOR_NEXT_CSID) != 0 && *A == 0) {
		SRV6_DEBUG("csid layout: NEXT_CSID with zero arg len");
		return (EINVAL);
	}
	if ((flags & SRV6_FLAVOR_REPLACE_CSID) != 0) {
		if (*F != 16 && *F != 32) {
			SRV6_DEBUG("csid layout: invalid funct len %d", *F);
			return (EINVAL);
		}
		K = 128 / *F;
		X = srv6_log2ceil(K);
		if (*A < X || *L + *F + X > 128) {
			SRV6_DEBUG("csid layout: REPLACE_CSID overflow");
			return (EINVAL);
		}
	}
	return (0);
}

/*
 * Construct a REPLACE-CSID destination address from the current destination
 * address and a packed CSID container.
 */
static void
srv6_csid_build(uint8_t *newda, const uint8_t *oldda, const uint8_t *container,
    int position, int L, int F, int X, int index)
{
	memcpy(newda, oldda, SRV6_SID_LEN);
	srv6_copy_bits(newda, L, container, position * F, F);
	srv6_zero_bits(newda, L + F, 128 - X - (L + F));
	srv6_put_bits64(newda, 128 - X, X, index);
}

/*
 * Apply the NEXT-CSID or REPLACE-CSID flavor.  Returns 1 in *handled if the
 * SID was fully processed, and 1 in *end if the CSID sequence has ended and
 * the upper-layer header should be processed.
 */
static int
srv6_csid_process(struct mbuf *m, struct srv6_pkt *pkt,
    const struct srv6_sid_config *sid, uint32_t flags, int *handled, int *end)
{
	uint8_t container[SRV6_SID_LEN];
	uint8_t newda[SRV6_SID_LEN];
	uint8_t *da;
	int A, F, K, L, X, error, index, newindex, sl;

	*handled = 0;
	*end = 0;
	error = srv6_csid_layout(sid, flags, &L, &F, &A);
	if (error != 0) {
		SRV6_DEBUG("csid process: layout failed: %d", error);
		return (error);
	}

	da = pkt->ip6.ip6_dst.s6_addr;
	if ((flags & SRV6_FLAVOR_NEXT_CSID) != 0) {
		if (!srv6_bits_nonzero(da, L + F, A))
			return (0);
		if (pkt->ip6.ip6_hlim <= 1) {
			SRV6_DEBUG("csid process: hlim too low for NEXT_CSID");
			return (EHOSTUNREACH);
		}
		memcpy(newda, da, SRV6_SID_LEN);
		srv6_copy_bits(newda, L, da, L + F, A);
		srv6_zero_bits(newda, L + A, 128 - (L + A));
		error = srv6_update_da(m, pkt, newda);
		if (error != 0) {
			SRV6_DEBUG("csid process: update da failed: %d", error);
			return (error);
		}
		error = srv6_decrement_hlim(m, pkt);
		if (error != 0) {
			SRV6_DEBUG("csid process: decrement hlim failed: %d", error);
			return (error);
		}
		*handled = 1;
		return (0);
	}

	/* REPLACE-CSID requires an SRH. */
	if (pkt->srh_off < 0)
		return (0);
	error = srv6_srh_valid(pkt);
	if (error != 0) {
		SRV6_DEBUG("csid process: srh invalid: %d", error);
		return (error);
	}

	K = 128 / F;
	X = srv6_log2ceil(K);
	if (A < X || L + F + X > 128) {
		SRV6_DEBUG("csid process: REPLACE_CSID layout invalid");
		return (EINVAL);
	}
	sl = pkt->srh.segments_left;
	index = (int)srv6_get_bits64(da, 128 - X, X);

	/*
	 * S02: if the last container has no more CSIDs, process the
	 * upper-layer header.
	 */
	if (sl == 0) {
		int finished;

		finished = 0;
		if (index == 0) {
			finished = 1;
		} else {
			error = srv6_get_segment(m, pkt, 0, container);
			if (error != 0)
				return (error);
			if (!srv6_bits_nonzero(container, (index - 1) * F, F))
				finished = 1;
		}
		if (finished) {
			if ((flags & (SRV6_FLAVOR_PSP |
			    SRV6_FLAVOR_USP)) != 0) {
				error = srv6_pop_srh(m, pkt);
				if (error != 0) {
					SRV6_DEBUG("csid process: pop srh failed: %d", error);
					return (error);
				}
			}
			*handled = 1;
			*end = 1;
			return (0);
		}
	}

	if (index != 0) {
		if (sl > pkt->srh.last_entry) {
			SRV6_DEBUG("csid process: sl %d > last_entry %d", sl, pkt->srh.last_entry);
			return (EINVAL);
		}
		newindex = index - 1;
		error = srv6_get_segment(m, pkt, sl, container);
		if (error != 0) {
			SRV6_DEBUG("csid process: get segment %d failed: %d", sl, error);
			return (error);
		}
		if (!srv6_bits_nonzero(container, newindex * F, F)) {
			if (sl == 0) {
				if ((flags & (SRV6_FLAVOR_PSP |
				    SRV6_FLAVOR_USP)) != 0) {
					error = srv6_pop_srh(m, pkt);
					if (error != 0) {
						SRV6_DEBUG("csid process: pop srh failed: %d", error);
						return (error);
					}
				}
				*handled = 1;
				*end = 1;
				return (0);
			}
			sl--;
			error = srv6_update_sl(m, pkt, sl);
			if (error != 0) {
				SRV6_DEBUG("csid process: update sl failed: %d", error);
				return (error);
			}
			error = srv6_get_segment(m, pkt, sl, container);
			if (error != 0) {
				SRV6_DEBUG("csid process: get segment %d failed: %d", sl, error);
				return (error);
			}
			error = srv6_update_da(m, pkt, container);
			if (error != 0) {
				SRV6_DEBUG("csid process: update da failed: %d", error);
				return (error);
			}
			error = srv6_decrement_hlim(m, pkt);
			if (error != 0) {
				SRV6_DEBUG("csid process: decrement hlim failed: %d", error);
				return (error);
			}
			*handled = 1;
			return (0);
		}
		srv6_csid_build(newda, da, container, newindex, L, F, X,
		    newindex);
		error = srv6_update_da(m, pkt, newda);
		if (error != 0) {
			SRV6_DEBUG("csid process: update da failed: %d", error);
			return (error);
		}
		error = srv6_decrement_hlim(m, pkt);
		if (error != 0) {
			SRV6_DEBUG("csid process: decrement hlim failed: %d", error);
			return (error);
		}
		*handled = 1;
		return (0);
	}

	/* index == 0 and there are more containers. */
	if (sl > pkt->srh.last_entry + 1) {
		SRV6_DEBUG("csid process: sl %d > last_entry+1 %d", sl, pkt->srh.last_entry + 1);
		return (EINVAL);
	}
	sl--;
	error = srv6_update_sl(m, pkt, sl);
	if (error != 0) {
		SRV6_DEBUG("csid process: update sl failed: %d", error);
		return (error);
	}
	newindex = K - 1;
	error = srv6_get_segment(m, pkt, sl, container);
	if (error != 0) {
		SRV6_DEBUG("csid process: get segment %d failed: %d", sl, error);
		return (error);
	}
	if (!srv6_bits_nonzero(container, newindex * F, F)) {
		if ((flags & (SRV6_FLAVOR_PSP | SRV6_FLAVOR_USP)) != 0) {
			error = srv6_pop_srh(m, pkt);
			if (error != 0) {
				SRV6_DEBUG("csid process: pop srh failed: %d", error);
				return (error);
			}
		}
		*handled = 1;
		*end = 1;
		return (0);
	}
	srv6_csid_build(newda, da, container, newindex, L, F, X, newindex);
	error = srv6_update_da(m, pkt, newda);
	if (error != 0) {
		SRV6_DEBUG("csid process: update da failed: %d", error);
		return (error);
	}
	error = srv6_decrement_hlim(m, pkt);
	if (error != 0) {
		SRV6_DEBUG("csid process: decrement hlim failed: %d", error);
		return (error);
	}
	*handled = 1;
	return (0);
}

static int
srv6_pick_src(struct srv6_priv *priv, const struct srv6_sid_config *sid,
    const struct srv6_pkt *pkt, struct in6_addr *src)
{
	if (!IN6_IS_ADDR_UNSPECIFIED(&sid->src_addr)) {
		*src = sid->src_addr;
		return (0);
	}
	SRV6_LOCK(priv);
	*src = priv->default_src;
	SRV6_UNLOCK(priv);
	if (!IN6_IS_ADDR_UNSPECIFIED(src))
		return (0);
	if (pkt != NULL && !IN6_IS_ADDR_UNSPECIFIED(&pkt->ip6.ip6_src)) {
		*src = pkt->ip6.ip6_src;
		return (0);
	}
	SRV6_DEBUG("pick src: no source address available");
	return (EADDRNOTAVAIL);
}

static int
srv6_process_upper(struct srv6_priv *priv, struct mbuf *m,
    struct srv6_pkt *pkt, const struct srv6_sid_config *sid,
    enum srv6_base_behavior base, uint32_t flags, struct srv6_result *res)
{
	if ((flags & SRV6_FLAVOR_USD) != 0 &&
	    (pkt->upper_nxt == IPPROTO_IPV4 || pkt->upper_nxt == IPPROTO_IPV6))
		return (srv6_decap_and_forward(priv, m, pkt, sid, base, res));

	switch (base) {
	case SRV6_BASE_END_X:
		res->action = SRV6_ACT_FORWARD_ADJ;
		res->adj_index = sid->adj_index;
		break;
	case SRV6_BASE_END_T:
		res->action = SRV6_ACT_FORWARD_OUT;
		res->fib_table = sid->fib_table;
		break;
	case SRV6_BASE_END:
		res->action = SRV6_ACT_FORWARD_OUT;
		break;
	default:
		SRV6_DEBUG("process upper: unsupported base %d", base);
		return (EOPNOTSUPP);
	}
	return (0);
}

static int
srv6_process_end(struct srv6_priv *priv, struct mbuf *m, struct srv6_pkt *pkt,
    const struct srv6_sid_config *sid, enum srv6_base_behavior base,
    uint32_t flags, struct srv6_result *res)
{
	struct in6_addr da;
	int error, sl;

	if (pkt->srh_off < 0)
		return (srv6_process_upper(priv, m, pkt, sid, base, flags,
		    res));

	error = srv6_srh_valid(pkt);
	if (error != 0) {
		SRV6_DEBUG("process end: srh invalid: %d", error);
		return (error);
	}

	if (pkt->srh.segments_left == 0) {
		if ((flags & SRV6_FLAVOR_USP) != 0) {
			error = srv6_pop_srh(m, pkt);
			if (error != 0) {
				SRV6_DEBUG("process end: pop srh failed: %d", error);
				return (error);
			}
		}
		return (srv6_process_upper(priv, m, pkt, sid, base, flags,
		    res));
	}

	if (pkt->ip6.ip6_hlim <= 1) {
		SRV6_DEBUG("process end: hlim too low");
		return (EHOSTUNREACH);
	}

	sl = pkt->srh.segments_left - 1;
	error = srv6_get_segment(m, pkt, sl, &da);
	if (error != 0) {
		SRV6_DEBUG("process end: get segment %d failed: %d", sl, error);
		return (error);
	}
	error = srv6_decrement_hlim(m, pkt);
	if (error != 0) {
		SRV6_DEBUG("process end: decrement hlim failed: %d", error);
		return (error);
	}
	error = srv6_update_sl(m, pkt, sl);
	if (error != 0) {
		SRV6_DEBUG("process end: update sl failed: %d", error);
		return (error);
	}
	error = srv6_update_da(m, pkt, &da);
	if (error != 0) {
		SRV6_DEBUG("process end: update da failed: %d", error);
		return (error);
	}

	if ((flags & SRV6_FLAVOR_PSP) != 0 && sl == 0) {
		error = srv6_pop_srh(m, pkt);
		if (error != 0) {
			SRV6_DEBUG("process end: pop srh failed: %d", error);
			return (error);
		}
		return (srv6_process_upper(priv, m, pkt, sid, base, flags,
		    res));
	}

	if (base == SRV6_BASE_END_X) {
		res->action = SRV6_ACT_FORWARD_ADJ;
		res->adj_index = sid->adj_index;
	} else {
		res->action = SRV6_ACT_CONTINUE;
		if (base == SRV6_BASE_END_T)
			res->fib_table = sid->fib_table;
	}
	return (0);
}

static int
srv6_decap_and_forward(struct srv6_priv *priv, struct mbuf *m,
    struct srv6_pkt *pkt, const struct srv6_sid_config *sid,
    enum srv6_base_behavior base, struct srv6_result *res)
{
	int error, mlen;

	mlen = m_length(m, NULL);
	if (pkt->outer_len <= 0 || pkt->outer_len >= mlen) {
		SRV6_DEBUG("decap and forward: invalid outer_len %d",
		    pkt->outer_len);
		return (EINVAL);
	}
	error = srv6_decapsulate(m, pkt->outer_len);
	if (error != 0) {
		SRV6_DEBUG("decap and forward: decapsulate failed: %d", error);
		return (error);
	}

	switch (base) {
	case SRV6_BASE_END:
		res->action = SRV6_ACT_FORWARD_OUT;
		break;
	case SRV6_BASE_END_X:
		res->action = SRV6_ACT_FORWARD_ADJ;
		res->adj_index = sid->adj_index;
		break;
	case SRV6_BASE_END_T:
		res->action = SRV6_ACT_FORWARD_OUT;
		res->fib_table = sid->fib_table;
		break;
	case SRV6_BASE_DX6:
	case SRV6_BASE_DX4:
	case SRV6_BASE_DX2:
		res->action = SRV6_ACT_FORWARD_ADJ;
		res->adj_index = sid->adj_index;
		break;
	case SRV6_BASE_DT6:
		res->action = SRV6_ACT_FORWARD_OUT;
		res->fib_table = sid->fib_table;
		break;
	case SRV6_BASE_DT4:
		res->action = SRV6_ACT_FORWARD_OUT;
		res->fib_table = sid->fib_table4 != 0 ?
		    sid->fib_table4 : sid->fib_table;
		break;
	case SRV6_BASE_DT46:
		res->action = SRV6_ACT_FORWARD_OUT;
		if (pkt->upper_nxt == IPPROTO_IPV4)
			res->fib_table = sid->fib_table4 != 0 ?
			    sid->fib_table4 : sid->fib_table;
		else
			res->fib_table = sid->fib_table;
		break;
	default:
		SRV6_DEBUG("decap and forward: unsupported base %d", base);
		return (EOPNOTSUPP);
	}
	return (0);
}

static int
srv6_process_decap(struct srv6_priv *priv, struct mbuf *m,
    struct srv6_pkt *pkt, const struct srv6_sid_config *sid,
    enum srv6_base_behavior base, struct srv6_result *res)
{
	int error;

	if (pkt->srh_off >= 0) {
		error = srv6_srh_valid(pkt);
		if (error != 0) {
			SRV6_DEBUG("process decap: srh invalid: %d", error);
			return (error);
		}
		if (pkt->srh.segments_left != 0) {
			SRV6_DEBUG("process decap: segments_left nonzero");
			return (EINVAL);
		}
	}

	switch (base) {
	case SRV6_BASE_DX6:
		if (pkt->upper_nxt != IPPROTO_IPV6) {
			SRV6_DEBUG("process decap: DX6 expects IPv6");
			return (EINVAL);
		}
		return (srv6_decap_and_forward(priv, m, pkt, sid, base, res));
	case SRV6_BASE_DX4:
		if (pkt->upper_nxt != IPPROTO_IPV4) {
			SRV6_DEBUG("process decap: DX4 expects IPv4");
			return (EINVAL);
		}
		return (srv6_decap_and_forward(priv, m, pkt, sid, base, res));
	case SRV6_BASE_DT6:
		if (pkt->upper_nxt != IPPROTO_IPV6) {
			SRV6_DEBUG("process decap: DT6 expects IPv6");
			return (EINVAL);
		}
		return (srv6_decap_and_forward(priv, m, pkt, sid, base, res));
	case SRV6_BASE_DT4:
		if (pkt->upper_nxt != IPPROTO_IPV4) {
			SRV6_DEBUG("process decap: DT4 expects IPv4");
			return (EINVAL);
		}
		return (srv6_decap_and_forward(priv, m, pkt, sid, base, res));
	case SRV6_BASE_DT46:
		if (pkt->upper_nxt != IPPROTO_IPV4 &&
		    pkt->upper_nxt != IPPROTO_IPV6) {
			SRV6_DEBUG("process decap: DT46 expects IPv4 or IPv6");
			return (EINVAL);
		}
		return (srv6_decap_and_forward(priv, m, pkt, sid, base, res));
	case SRV6_BASE_DX2:
		if (pkt->upper_nxt != SRV6_IPPROTO_ETHERNET) {
			SRV6_DEBUG("process decap: DX2 expects Ethernet");
			return (EINVAL);
		}
		return (srv6_decap_and_forward(priv, m, pkt, sid, base, res));
	case SRV6_BASE_DX2V:
	case SRV6_BASE_DT2U:
	case SRV6_BASE_DT2M:
		SRV6_DEBUG("process decap: base %d not supported", base);
		return (EOPNOTSUPP);
	default:
		SRV6_DEBUG("process decap: unsupported base %d", base);
		return (EOPNOTSUPP);
	}
}

static int
srv6_process_b6(struct srv6_priv *priv, struct mbuf **mp,
    struct srv6_pkt *pkt, const struct srv6_sid_config *sid,
    enum srv6_base_behavior base, __unused uint32_t flags,
    struct srv6_result *res, int csid_done)
{
	struct in6_addr da, src;
	int error, reduced, sl;

	reduced = (base == SRV6_BASE_B6_ENCAPS_RED);

	if (csid_done == 0 && pkt->srh_off >= 0) {
		error = srv6_srh_valid(pkt);
		if (error != 0) {
			SRV6_DEBUG("process b6: srh invalid: %d", error);
			return (error);
		}
		if (pkt->srh.segments_left > 0) {
			if (pkt->ip6.ip6_hlim <= 1) {
				SRV6_DEBUG("process b6: hlim too low");
				return (EHOSTUNREACH);
			}
			sl = pkt->srh.segments_left - 1;
			error = srv6_get_segment(*mp, pkt, sl, &da);
			if (error != 0) {
				SRV6_DEBUG("process b6: get segment %d failed: %d", sl, error);
				return (error);
			}
			error = srv6_decrement_hlim(*mp, pkt);
			if (error != 0) {
				SRV6_DEBUG("process b6: decrement hlim failed: %d", error);
				return (error);
			}
			error = srv6_update_sl(*mp, pkt, sl);
			if (error != 0) {
				SRV6_DEBUG("process b6: update sl failed: %d", error);
				return (error);
			}
			error = srv6_update_da(*mp, pkt, &da);
			if (error != 0) {
				SRV6_DEBUG("process b6: update da failed: %d", error);
				return (error);
			}
		}
	}

	if (sid->nsegments == 0 || sid->nsegments > SRV6_MAX_SEGMENTS) {
		SRV6_DEBUG("process b6: invalid segment count %u", sid->nsegments);
		return (EINVAL);
	}
	error = srv6_pick_src(priv, sid, pkt, &src);
	if (error != 0) {
		SRV6_DEBUG("process b6: pick src failed: %d", error);
		return (error);
	}
	error = srv6_encapsulate(mp, &src, &sid->segments[0],
	    sid->segments, sid->nsegments, reduced);
	if (error != 0) {
		SRV6_DEBUG("process b6: encapsulate failed: %d", error);
		return (error);
	}

	res->action = SRV6_ACT_FORWARD_OUT;
	res->fib_table = sid->fib_table;
	return (0);
}

static int
srv6_execute(struct srv6_priv *priv, struct mbuf **mp, struct srv6_pkt *pkt,
    const struct srv6_sid_config *sid, struct srv6_result *res)
{
	enum srv6_base_behavior base;
	uint32_t flags;
	int end, error, handled;

	memset(res, 0, sizeof(*res));
	error = srv6_behavior_decode(sid->behavior, &base, &flags);
	if (error != 0) {
		SRV6_DEBUG("execute: behavior decode failed: %d", error);
		return (error);
	}

	if ((flags & (SRV6_FLAVOR_NEXT_CSID | SRV6_FLAVOR_REPLACE_CSID)) != 0 &&
	    (base == SRV6_BASE_END || base == SRV6_BASE_END_X ||
	    base == SRV6_BASE_END_T || base == SRV6_BASE_B6_ENCAPS ||
	    base == SRV6_BASE_B6_ENCAPS_RED)) {
		error = srv6_csid_process(*mp, pkt, sid, flags, &handled,
		    &end);
		if (error != 0) {
			SRV6_DEBUG("execute: csid process failed: %d", error);
			return (error);
		}
		if (handled != 0) {
			if (base == SRV6_BASE_B6_ENCAPS ||
			    base == SRV6_BASE_B6_ENCAPS_RED)
				return (srv6_process_b6(priv, mp, pkt, sid,
				    base, flags, res, 1));
			if (base == SRV6_BASE_END_X) {
				if (end != 0)
					return (srv6_process_upper(priv, *mp,
					    pkt, sid, base, flags, res));
				res->action = SRV6_ACT_FORWARD_ADJ;
				res->adj_index = sid->adj_index;
				return (0);
			}
			if (end != 0)
				return (srv6_process_upper(priv, *mp, pkt, sid,
				    base, flags, res));
			res->action = SRV6_ACT_CONTINUE;
			if (base == SRV6_BASE_END_T)
				res->fib_table = sid->fib_table;
			return (0);
		}
	}

	switch (base) {
	case SRV6_BASE_END:
	case SRV6_BASE_END_X:
	case SRV6_BASE_END_T:
		return (srv6_process_end(priv, *mp, pkt, sid, base, flags,
		    res));
	case SRV6_BASE_B6_ENCAPS:
	case SRV6_BASE_B6_ENCAPS_RED:
		return (srv6_process_b6(priv, mp, pkt, sid, base, flags, res,
		    0));
	case SRV6_BASE_DX6:
	case SRV6_BASE_DX4:
	case SRV6_BASE_DT6:
	case SRV6_BASE_DT4:
	case SRV6_BASE_DT46:
	case SRV6_BASE_DX2:
	case SRV6_BASE_DX2V:
	case SRV6_BASE_DT2U:
	case SRV6_BASE_DT2M:
		return (srv6_process_decap(priv, *mp, pkt, sid, base, res));
	case SRV6_BASE_BM:
	case SRV6_BASE_LBS:
	case SRV6_BASE_XLBS:
		SRV6_DEBUG("execute: base %d not supported", base);
		return (EOPNOTSUPP);
	default:
		SRV6_DEBUG("execute: unknown base %d", base);
		return (EINVAL);
	}
}

static void
srv6_set_fib(struct mbuf *m, uint32_t fib)
{
	if (fib != 0 && (m->m_flags & M_PKTHDR) != 0)
		M_SETFIB(m, fib);
}

static int
srv6_send(struct srv6_priv *priv, struct mbuf *m, const char *hookname)
{
	hook_p hook;
	int error;

	hook = ng_findhook(priv->node, hookname);
	if (hook == NULL || !NG_HOOK_IS_VALID(hook)) {
		SRV6_DEBUG("send: hook %s not found", hookname);
		srv6_drop(priv, m, ENOTCONN);
		return (ENOTCONN);
	}
	NG_SEND_DATA_ONLY(error, hook, m);
	if (error == 0) {
		SRV6_LOCK(priv);
		priv->packets_out++;
		SRV6_UNLOCK(priv);
	} else {
		SRV6_DEBUG("send: NG_SEND_DATA_ONLY failed: %d", error);
		SRV6_LOCK(priv);
		priv->packets_dropped++;
		priv->errors++;
		SRV6_UNLOCK(priv);
	}
	return (error);
}

static int
srv6_forward_out(struct srv6_priv *priv, struct mbuf *m, uint32_t fib)
{
	srv6_set_fib(m, fib);
	return (srv6_send(priv, m, NG_SRV6_HOOK_OUT));
}

static void
srv6_adj_account(struct srv6_priv *priv, const struct in6_addr *nexthop,
    uint64_t bytes)
{
	struct srv6_adjacency *adj;

	SRV6_LOCK(priv);
	LIST_FOREACH(adj, &priv->adjs, link) {
		if (IN6_ARE_ADDR_EQUAL(nexthop, &adj->config.nexthop)) {
			adj->packets++;
			adj->bytes += bytes;
			break;
		}
	}
	SRV6_UNLOCK(priv);
}

static int
srv6_forward_adj(struct srv6_priv *priv, struct mbuf *m, uint32_t index)
{
	struct srv6_adj_config adj;
	int error;

	error = srv6_lookup_adj(priv, index, &adj);
	if (error != 0) {
		SRV6_DEBUG("forward adj: index %u not found: %d", index, error);
		srv6_drop(priv, m, ENETUNREACH);
		return (ENETUNREACH);
	}
	srv6_set_fib(m, adj.fib_table);
	srv6_adj_account(priv, &adj.nexthop, m_length(m, NULL));
	return (srv6_send(priv, m, adj.hook));
}

static void
srv6_drop(struct srv6_priv *priv, struct mbuf *m, int error)
{
	if (m != NULL)
		m_freem(m);
	SRV6_LOCK(priv);
	priv->packets_dropped++;
	if (error != 0)
		priv->errors++;
	SRV6_UNLOCK(priv);
}

static void
srv6_sid_account(struct srv6_priv *priv, const struct in6_addr *addr,
    uint64_t bytes)
{
	struct srv6_sid_entry *sid;

	SRV6_LOCK(priv);
	LIST_FOREACH(sid, &priv->sids, link) {
		if (IN6_ARE_ADDR_EQUAL(addr, &sid->config.addr)) {
			sid->packets++;
			sid->bytes += bytes;
			break;
		}
	}
	SRV6_UNLOCK(priv);
}

int
srv6_process_packet(struct srv6_priv *priv, struct mbuf *m)
{
	struct srv6_pkt pkt;
	struct srv6_result res;
	struct srv6_sid_config sid;
	uint32_t pending_fib;
	uint64_t bytes;
	int error, loops;
	int processed;

	bytes = m_length(m, NULL);
	pending_fib = 0;
	loops = 0;
	processed = 0;

	for (;;) {
		error = srv6_parse_packet(m, &pkt);
		if (error != 0) {
			SRV6_DEBUG("process packet: parse failed: %d", error);
			srv6_drop(priv, m, error);
			return (error);
		}

		error = srv6_lookup_sid(priv, &pkt.ip6.ip6_dst, &sid);
		if (error != 0) {
			/* Skip the transit hop-limit decrement if the packet
			 * has already been processed locally (SRV6_ACT_CONTINUE
			 * already decremented it).  Otherwise a non-local DA
			 * after a continue would decrement HLIM twice. */
			SRV6_DEBUG("process packet: no local SID for DA: %d", error);
			if (!processed) {
				error = srv6_decrement_hlim(m, &pkt);
				if (error != 0) {
					srv6_drop(priv, m, error);
					return (error);
				}
			}
			return (srv6_forward_out(priv, m, pending_fib));
		}

		error = srv6_execute(priv, &m, &pkt, &sid, &res);
		if (error != 0) {
			SRV6_DEBUG("process packet: execute failed: %d", error);
			srv6_drop(priv, m, error);
			return (error);
		}
		processed = 1;

		srv6_sid_account(priv, &sid.addr, bytes);

		switch (res.action) {
		case SRV6_ACT_CONTINUE:
			if (++loops > SRV6_MAX_LOOPS) {
				SRV6_DEBUG("process packet: max loops exceeded");
				srv6_drop(priv, m, EHOSTUNREACH);
				return (EHOSTUNREACH);
			}
			pending_fib = res.fib_table;
			break;
		case SRV6_ACT_FORWARD_OUT:
			return (srv6_forward_out(priv, m, res.fib_table));
		case SRV6_ACT_FORWARD_ADJ:
			return (srv6_forward_adj(priv, m, res.adj_index));
		default:
			SRV6_DEBUG("process packet: unknown action %d", res.action);
			srv6_drop(priv, m, EINVAL);
			return (EINVAL);
		}
	}
}

static int
srv6_ng_constructor(node_p node)
{
	struct srv6_priv *priv;

	priv = malloc(sizeof(*priv), M_SRV6, M_WAITOK | M_ZERO);
	mtx_init(&priv->lock, "srv6", NULL, MTX_DEF);
	LIST_INIT(&priv->sids);
	LIST_INIT(&priv->adjs);
	priv->node = node;
	NG_NODE_SET_PRIVATE(node, priv);
	return (0);
}

static int
srv6_ng_shutdown(node_p node)
{
	struct srv6_adjacency *adj;
	struct srv6_priv *priv;
	struct srv6_sid_entry *sid;

	priv = NG_NODE_PRIVATE(node);
	if (priv != NULL) {
		SRV6_LOCK(priv);
		while ((sid = LIST_FIRST(&priv->sids)) != NULL) {
			LIST_REMOVE(sid, link);
			free(sid, M_SRV6);
		}
		while ((adj = LIST_FIRST(&priv->adjs)) != NULL) {
			LIST_REMOVE(adj, link);
			free(adj, M_SRV6);
		}
		SRV6_UNLOCK(priv);
		mtx_destroy(&priv->lock);
		NG_NODE_SET_PRIVATE(node, NULL);
		free(priv, M_SRV6);
	}
	NG_NODE_UNREF(node);
	return (0);
}

static int
srv6_ng_newhook(__unused node_p node, hook_p hook, __unused const char *name)
{
	const char *hname;

	hname = NG_HOOK_NAME(hook);
	if (hname == NULL || hname[0] == '\0' ||
	    strlen(hname) >= NG_HOOKSIZ) {
		SRV6_DEBUG("newhook: invalid hook name");
		return (EINVAL);
	}
	return (0);
}

static int
srv6_ng_disconnect(hook_p hook)
{
	node_p node;

	node = NG_HOOK_NODE(hook);
	if (NG_NODE_NUMHOOKS(node) == 0 && NG_NODE_IS_VALID(node) &&
	    NG_NODE_PRIVATE(node) != NULL)
		ng_rmnode_self(node);
	return (0);
}

static int
srv6_ng_rcvdata(hook_p hook, item_p item)
{
	struct srv6_priv *priv;
	struct mbuf *m;
	uint64_t bytes;

	if (strcmp(NG_HOOK_NAME(hook), NG_SRV6_HOOK_OUT) == 0) {
		NGI_GET_M(item, m);
		NG_FREE_ITEM(item);
		if (m != NULL)
			m_freem(m);
		SRV6_DEBUG("rcvdata: packet on out hook, dropping");
		return (EINVAL);
	}

	NGI_GET_M(item, m);
	NG_FREE_ITEM(item);
	if (m == NULL) {
		SRV6_DEBUG("rcvdata: null mbuf");
		return (EINVAL);
	}

	priv = NG_NODE_PRIVATE(NG_HOOK_NODE(hook));
	bytes = m_length(m, NULL);
	SRV6_LOCK(priv);
	priv->packets_in++;
	priv->bytes_in += bytes;
	SRV6_UNLOCK(priv);

	(void)srv6_process_packet(priv, m);
	return (0);
}

static int
srv6_ng_rcvmsg(node_p node, item_p item, __unused hook_p lasthook)
{
	struct srv6_adj_info ainfo;
	struct srv6_adjacency *adj, *newadj;
	struct srv6_priv *priv;
	struct srv6_sid_entry *newsid, *sid;
	struct srv6_sid_info sinfo;
	struct srv6_stats stats;
	struct ng_mesg *msg, *resp;
	struct srv6_adj_config adjcfg;
	struct srv6_sid_config sidcfg;
	struct in6_addr addr;
	uint32_t index;
	int error, found;

	priv = NG_NODE_PRIVATE(node);
	NGI_GET_MSG(item, msg);
	resp = NULL;
	error = 0;

	switch (msg->header.cmd) {
	case NGM_SRV6_ADD_SID:
		if (msg->header.arglen < sizeof(sidcfg)) {
			SRV6_DEBUG("rcvmsg: addsid arglen too small");
			error = EINVAL;
			break;
		}
		memcpy(&sidcfg, msg->data, sizeof(sidcfg));
		error = srv6_validate_sid(&sidcfg);
		if (error != 0) {
			SRV6_DEBUG("rcvmsg: addsid validate failed: %d", error);
			break;
		}

		newsid = malloc(sizeof(*newsid), M_SRV6, M_WAITOK | M_ZERO);
		newsid->config = sidcfg;
		SRV6_LOCK(priv);
		found = 0;
		LIST_FOREACH(sid, &priv->sids, link) {
			if (IN6_ARE_ADDR_EQUAL(&sid->config.addr,
			    &sidcfg.addr)) {
				sid->config = sidcfg;
				found = 1;
				break;
			}
		}
		if (found == 0)
			LIST_INSERT_HEAD(&priv->sids, newsid, link);
		SRV6_UNLOCK(priv);
		if (found != 0)
			free(newsid, M_SRV6);
		break;

	case NGM_SRV6_DEL_SID:
		if (msg->header.arglen < sizeof(addr)) {
			SRV6_DEBUG("rcvmsg: delsid arglen too small");
			error = EINVAL;
			break;
		}
		memcpy(&addr, msg->data, sizeof(addr));
		sid = NULL;
		SRV6_LOCK(priv);
		LIST_FOREACH(sid, &priv->sids, link) {
			if (IN6_ARE_ADDR_EQUAL(&addr, &sid->config.addr)) {
				LIST_REMOVE(sid, link);
				break;
			}
		}
		SRV6_UNLOCK(priv);
		if (sid == NULL) {
			SRV6_DEBUG("rcvmsg: delsid sid not found");
			error = ENOENT;
		} else
			free(sid, M_SRV6);
		break;

	case NGM_SRV6_ADD_ADJ:
		if (msg->header.arglen < sizeof(adjcfg)) {
			SRV6_DEBUG("rcvmsg: addadj arglen too small");
			error = EINVAL;
			break;
		}
		memcpy(&adjcfg, msg->data, sizeof(adjcfg));
		adjcfg.hook[NG_HOOKSIZ - 1] = '\0';
		if (adjcfg.index == 0 || adjcfg.hook[0] == '\0' ||
		    strcmp(adjcfg.hook, NG_SRV6_HOOK_IN) == 0 ||
		    strcmp(adjcfg.hook, NG_SRV6_HOOK_OUT) == 0) {
			SRV6_DEBUG("rcvmsg: addadj invalid config");
			error = EINVAL;
			break;
		}

		newadj = malloc(sizeof(*newadj), M_SRV6, M_WAITOK | M_ZERO);
		newadj->config = adjcfg;
		SRV6_LOCK(priv);
		found = 0;
		LIST_FOREACH(adj, &priv->adjs, link) {
			if (adj->config.index == adjcfg.index) {
				adj->config = adjcfg;
				found = 1;
				break;
			}
		}
		if (found == 0)
			LIST_INSERT_HEAD(&priv->adjs, newadj, link);
		SRV6_UNLOCK(priv);
		if (found != 0)
			free(newadj, M_SRV6);
		break;

	case NGM_SRV6_DEL_ADJ:
		if (msg->header.arglen < sizeof(index)) {
			SRV6_DEBUG("rcvmsg: deladj arglen too small");
			error = EINVAL;
			break;
		}
		memcpy(&index, msg->data, sizeof(index));
		adj = NULL;
		SRV6_LOCK(priv);
		LIST_FOREACH(adj, &priv->adjs, link) {
			if (adj->config.index == index) {
				LIST_REMOVE(adj, link);
				break;
			}
		}
		SRV6_UNLOCK(priv);
		if (adj == NULL) {
			SRV6_DEBUG("rcvmsg: deladj index %u not found", index);
			error = ENOENT;
		} else
			free(adj, M_SRV6);
		break;

	case NGM_SRV6_SET_SRC:
		if (msg->header.arglen < sizeof(addr)) {
			SRV6_DEBUG("rcvmsg: setsrc arglen too small");
			error = EINVAL;
			break;
		}
		memcpy(&addr, msg->data, sizeof(addr));
		SRV6_LOCK(priv);
		priv->default_src = addr;
		SRV6_UNLOCK(priv);
		break;

	case NGM_SRV6_GET_STATS:
		memset(&stats, 0, sizeof(stats));
		SRV6_LOCK(priv);
		stats.packets_in = priv->packets_in;
		stats.packets_out = priv->packets_out;
		stats.packets_dropped = priv->packets_dropped;
		stats.bytes_in = priv->bytes_in;
		stats.errors = priv->errors;
		LIST_FOREACH(sid, &priv->sids, link)
			stats.sids++;
		LIST_FOREACH(adj, &priv->adjs, link)
			stats.adjs++;
		SRV6_UNLOCK(priv);
		NG_MKRESPONSE(resp, msg, sizeof(stats), M_NOWAIT);
		if (resp == NULL) {
			SRV6_DEBUG("rcvmsg: getstats out of memory");
			error = ENOMEM;
			break;
		}
		memcpy(resp->data, &stats, sizeof(stats));
		break;

	case NGM_SRV6_GET_SID:
		if (msg->header.arglen < sizeof(addr)) {
			SRV6_DEBUG("rcvmsg: getsid arglen too small");
			error = EINVAL;
			break;
		}
		memcpy(&addr, msg->data, sizeof(addr));
		memset(&sinfo, 0, sizeof(sinfo));
		found = 0;
		SRV6_LOCK(priv);
		LIST_FOREACH(sid, &priv->sids, link) {
			if (IN6_ARE_ADDR_EQUAL(&addr, &sid->config.addr)) {
				sinfo.config = sid->config;
				sinfo.packets = sid->packets;
				sinfo.bytes = sid->bytes;
				found = 1;
				break;
			}
		}
		SRV6_UNLOCK(priv);
		if (found == 0) {
			SRV6_DEBUG("rcvmsg: getsid sid not found");
			error = ENOENT;
			break;
		}
		NG_MKRESPONSE(resp, msg, sizeof(sinfo), M_NOWAIT);
		if (resp == NULL) {
			SRV6_DEBUG("rcvmsg: getsid out of memory");
			error = ENOMEM;
			break;
		}
		memcpy(resp->data, &sinfo, sizeof(sinfo));
		break;

	case NGM_SRV6_GET_ADJ:
		if (msg->header.arglen < sizeof(index)) {
			SRV6_DEBUG("rcvmsg: getadj arglen too small");
			error = EINVAL;
			break;
		}
		memcpy(&index, msg->data, sizeof(index));
		memset(&ainfo, 0, sizeof(ainfo));
		found = 0;
		SRV6_LOCK(priv);
		LIST_FOREACH(adj, &priv->adjs, link) {
			if (adj->config.index == index) {
				ainfo.config = adj->config;
				ainfo.packets = adj->packets;
				ainfo.bytes = adj->bytes;
				found = 1;
				break;
			}
		}
		SRV6_UNLOCK(priv);
		if (found == 0) {
			SRV6_DEBUG("rcvmsg: getadj index %u not found", index);
			error = ENOENT;
			break;
		}
		NG_MKRESPONSE(resp, msg, sizeof(ainfo), M_NOWAIT);
		if (resp == NULL) {
			SRV6_DEBUG("rcvmsg: getadj out of memory");
			error = ENOMEM;
			break;
		}
		memcpy(resp->data, &ainfo, sizeof(ainfo));
		break;

	case NGM_SRV6_CLR_STATS:
		SRV6_LOCK(priv);
		priv->packets_in = 0;
		priv->packets_out = 0;
		priv->packets_dropped = 0;
		priv->bytes_in = 0;
		priv->errors = 0;
		LIST_FOREACH(sid, &priv->sids, link) {
			sid->packets = 0;
			sid->bytes = 0;
		}
		LIST_FOREACH(adj, &priv->adjs, link) {
			adj->packets = 0;
			adj->bytes = 0;
		}
		SRV6_UNLOCK(priv);
		break;

	default:
		SRV6_DEBUG("rcvmsg: unknown command %u", msg->header.cmd);
		error = EINVAL;
		break;
	}

	if (resp != NULL) {
		NG_RESPOND_MSG(error, node, item, resp);
		NG_FREE_MSG(msg);
	} else {
		NG_FREE_ITEM(item);
		NG_FREE_MSG(msg);
	}
	return (error);
}

int
srv6_decapsulate(struct mbuf *m, int offset)
{
	int mlen;

	mlen = m_length(m, NULL);
	if (offset <= 0 || offset >= mlen) {
		SRV6_DEBUG("decapsulate: invalid offset %d", offset);
		return (EINVAL);
	}
	m_adj(m, offset);
	return (0);
}

int
srv6_encapsulate(struct mbuf **mp, const struct in6_addr *src,
    const struct in6_addr *dst, const struct in6_addr *segments,
    uint16_t nsegments, int reduced)
{
	struct ip6_hdr *ip6;
	struct mbuf *hdr, *m;
	struct srv6_srh *srh;
	uint8_t *p;
	uint8_t v;
	int i, inner_nxt, old_len, outer_len, srh_len, srh_sids;

	if (mp == NULL || (m = *mp) == NULL || src == NULL || dst == NULL ||
	    segments == NULL || nsegments == 0 ||
	    nsegments > SRV6_MAX_SEGMENTS) {
		SRV6_DEBUG("encapsulate: invalid arguments");
		return (EINVAL);
	}
	if ((m->m_flags & M_PKTHDR) == 0) {
		SRV6_DEBUG("encapsulate: mbuf without packet header");
		return (EINVAL);
	}

	m_copydata(m, 0, 1, &v);
	if ((v >> 4) == 6)
		inner_nxt = IPPROTO_IPV6;
	else if ((v >> 4) == 4)
		inner_nxt = IPPROTO_IPV4;
	else {
		SRV6_DEBUG("encapsulate: unsupported IP version %u", v >> 4);
		return (EAFNOSUPPORT);
	}

	srh_sids = reduced != 0 ? nsegments - 1 : nsegments;
	if (srh_sids == 0)
		srh_len = 0;
	else
		srh_len = sizeof(struct srv6_srh_hdr) +
		    srh_sids * SRV6_SID_LEN;
	outer_len = sizeof(struct ip6_hdr) + srh_len;
	old_len = m_length(m, NULL);

	hdr = m_get2(outer_len, M_NOWAIT, MT_DATA, M_PKTHDR);
	if (hdr == NULL) {
		SRV6_DEBUG("encapsulate: out of memory");
		return (ENOMEM);
	}
	m_move_pkthdr(hdr, m);
	hdr->m_next = m;
	hdr->m_len = outer_len;
	hdr->m_pkthdr.len = old_len + outer_len;
	p = mtod(hdr, uint8_t *);
	bzero(p, outer_len);

	ip6 = (struct ip6_hdr *)p;
	ip6->ip6_vfc = IPV6_VERSION;
	ip6->ip6_plen = htons(old_len + srh_len);
	ip6->ip6_nxt = srh_len != 0 ? IPPROTO_ROUTING : inner_nxt;
	ip6->ip6_hlim = 64;
	ip6->ip6_src = *src;
	ip6->ip6_dst = *dst;

	if (srh_len != 0) {
		srh = (struct srv6_srh *)(p + sizeof(struct ip6_hdr));
		srh->next_header = inner_nxt;
		srh->hdr_ext_len = srh_len / 8 - 1;
		srh->routing_type = 4;
		srh->segments_left = nsegments - 1;
		srh->last_entry = srh_sids - 1;
		srh->flags = 0;
		srh->tag = 0;
		for (i = 0; i < srh_sids; i++)
			memcpy(&srh->segment_list[i],
			    &segments[nsegments - 1 - i], SRV6_SID_LEN);
	}

	*mp = hdr;
	return (0);
}

static int
srv6_modevent(module_t mod, int type, void *data)
{
	return (ng_mod_event(mod, type, data));
}

static struct ng_type srv6_ng_type = {
	.version =	NG_ABI_VERSION,
	.name =		NG_SRV6_NODE_TYPE,
	.constructor =	srv6_ng_constructor,
	.rcvmsg =	srv6_ng_rcvmsg,
	.shutdown =	srv6_ng_shutdown,
	.newhook =	srv6_ng_newhook,
	.rcvdata =	srv6_ng_rcvdata,
	.disconnect =	srv6_ng_disconnect,
	.cmdlist =	srv6_cmdlist,
};

static moduledata_t srv6_mod = {
	"srv6",
	srv6_modevent,
	&srv6_ng_type
};

DECLARE_MODULE(srv6, srv6_mod, SI_SUB_PSEUDO, SI_ORDER_MIDDLE);
MODULE_DEPEND(srv6, netgraph, NG_ABI_VERSION, NG_ABI_VERSION,
    NG_ABI_VERSION);
MODULE_VERSION(srv6, 1);
