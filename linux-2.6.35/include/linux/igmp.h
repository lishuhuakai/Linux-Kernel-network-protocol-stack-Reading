﻿/*
 *	Linux NET3:	Internet Group Management Protocol  [IGMP]
 *
 *	Authors:
 *		Alan Cox <alan@lxorguk.ukuu.org.uk>
 *
 *	Extended to talk the BSD extended IGMP protocol of mrouted 3.6
 *
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License
 *	as published by the Free Software Foundation; either version
 *	2 of the License, or (at your option) any later version.
 */

#ifndef _LINUX_IGMP_H
#define _LINUX_IGMP_H

#include <linux/types.h>
#include <asm/byteorder.h>

/*
 *	IGMP protocol structures
 */

/*
 *	Header in on cable format
 */

struct igmphdr {
	__u8 type; /* 类型 -- v1 v2 v3 */
	__u8 code;		/* For newer IGMP */
	__sum16 csum; /* 校验和 */
	__be32 group; /* 组地址 */
};

/* V3 group record types [grec_type] */
#define IGMPV3_MODE_IS_INCLUDE		1
#define IGMPV3_MODE_IS_EXCLUDE		2
#define IGMPV3_CHANGE_TO_INCLUDE	3
#define IGMPV3_CHANGE_TO_EXCLUDE	4
#define IGMPV3_ALLOW_NEW_SOURCES	5
#define IGMPV3_BLOCK_OLD_SOURCES	6

struct igmpv3_grec {
	__u8	grec_type;
	__u8	grec_auxwords;
	__be16	grec_nsrcs; /* 源地址的个数 */
	__be32	grec_mca;
	__be32	grec_src[0];
};

struct igmpv3_report {
	__u8 type;
	__u8 resv1;
	__be16 csum;
	__be16 resv2;
	__be16 ngrec;
	struct igmpv3_grec grec[0];
};

struct igmpv3_query {
	__u8 type;
	__u8 code;
	__be16 csum;
	__be32 group;
#if defined(__LITTLE_ENDIAN_BITFIELD)
	__u8 qrv:3,
	     suppress:1,
	     resv:4;
#elif defined(__BIG_ENDIAN_BITFIELD)
	__u8 resv:4,
	     suppress:1,
	     qrv:3;
#else
#error "Please fix <asm/byteorder.h>"
#endif
	__u8 qqic;
	__be16 nsrcs;
	__be32 srcs[0];
};

#define IGMP_HOST_MEMBERSHIP_QUERY	0x11	/* From RFC1112 */
#define IGMP_HOST_MEMBERSHIP_REPORT	0x12	/* Ditto */
#define IGMP_DVMRP			0x13	/* DVMRP routing */
#define IGMP_PIM			0x14	/* PIM routing */
#define IGMP_TRACE			0x15
#define IGMPV2_HOST_MEMBERSHIP_REPORT	0x16	/* V2 version of 0x11 */
#define IGMP_HOST_LEAVE_MESSAGE 	0x17
#define IGMPV3_HOST_MEMBERSHIP_REPORT	0x22	/* V3 version of 0x11 */

#define IGMP_MTRACE_RESP		0x1e
#define IGMP_MTRACE			0x1f


/*
 *	Use the BSD names for these for compatibility
 */

#define IGMP_DELAYING_MEMBER		0x01
#define IGMP_IDLE_MEMBER		0x02
#define IGMP_LAZY_MEMBER		0x03
#define IGMP_SLEEPING_MEMBER		0x04
#define IGMP_AWAKENING_MEMBER		0x05

#define IGMP_MINLEN			8

#define IGMP_MAX_HOST_REPORT_DELAY	10	/* max delay for response to */
						/* query (in seconds)	*/

#define IGMP_TIMER_SCALE		10	/* denotes that the igmphdr->timer field */
						/* specifies time in 10th of seconds	 */

#define IGMP_AGE_THRESHOLD		400	/* If this host don't hear any IGMP V1	*/
						/* message in this period of time,	*/
						/* revert to IGMP v2 router.		*/

#define IGMP_ALL_HOSTS		htonl(0xE0000001L)
#define IGMP_ALL_ROUTER 	htonl(0xE0000002L)
#define IGMPV3_ALL_MCR	 	htonl(0xE0000016L)
#define IGMP_LOCAL_GROUP	htonl(0xE0000000L)
#define IGMP_LOCAL_GROUP_MASK	htonl(0xFFFFFF00L)

/*
 * struct for keeping the multicast list in
 */

#ifdef __KERNEL__
#include <linux/skbuff.h>
#include <linux/timer.h>
#include <linux/in.h>

static inline struct igmphdr *igmp_hdr(const struct sk_buff *skb)
{
	return (struct igmphdr *)skb_transport_header(skb);
}

static inline struct igmpv3_report *
			igmpv3_report_hdr(const struct sk_buff *skb)
{
	return (struct igmpv3_report *)skb_transport_header(skb);
}

static inline struct igmpv3_query *
			igmpv3_query_hdr(const struct sk_buff *skb)
{
	return (struct igmpv3_query *)skb_transport_header(skb);
}

extern int sysctl_igmp_max_memberships;
extern int sysctl_igmp_max_msf;

struct ip_sf_socklist {
	unsigned int		sl_max; /* 当前分配的空间能存储源地址数上限 */
	unsigned int		sl_count; /* 当前存储的源地址数目 */
	struct rcu_head		rcu;
	__be32			sl_addr[0];
};

#define IP_SFLSIZE(count)	(sizeof(struct ip_sf_socklist) + \
	(count) * sizeof(__be32))

#define IP_SFBLOCK	10	/* allocate this many at once */

/* ip_mc_socklist is real list now. Speed is not argument;
   this list never used in fast path code
 */
/* ip_mc_socklist用于描述套接口已经加入的组播组,
 * 以链表的形式链接在传输控制块(inet_sock)的mc_list上
 */
struct ip_mc_socklist {
	struct ip_mc_socklist	*next;
	struct ip_mreqn		multi; /* 对应组播组信息,包括组播地址,网络接口以及本地地址 */
	unsigned int		sfmode;		/* MCAST_{INCLUDE,EXCLUDE} */
	struct ip_sf_socklist	*sflist; /* 源列表 */
	struct rcu_head		rcu;
};

/* 过滤列表 */
struct ip_sf_list {
	struct ip_sf_list	*sf_next;
	__be32			sf_inaddr;  /* 需要过滤的组播源地址 */
	/* 不同过滤模式(EXCLUDE和INCLUDE)且指定组播源过滤地址的套接口在该接口加入组播组的数量 */
    /* 说白一点,sf_count[exclude] =   2,表示有两个套接口过滤这个源地址
     * sf_count[include] = 1,表示有一个套接口要接收来自这个源的报文
     */
	unsigned long		sf_count[2];	/* include/exclude counts */
	/* 标识当前该组播源地址是否应答指定组或源的查询 */
	unsigned char		sf_gsresp;	/* include in g & s response? */
	/* 组播源地址状态标志 */
	unsigned char		sf_oldin;	/* change state */
	/* 当前还可重传"源列表改变记录"报告的次数 */
	unsigned char		sf_crcount;	/* retrans. left to send */
};

/* ip_mc_list结构描述网络设备加入组播组的配置块,用来维护网络设备组播的状态
 * 包括组播地址,过滤模式,源地址等.
 */
struct ip_mc_list {
	struct in_device	*interface; /* 指向所属网络设备的IP配置块 */
	__be32			multiaddr; /* 网络设备加入的组播地址 */
	struct ip_sf_list	*sources; /* 源地址过滤列表 */
	struct ip_sf_list	*tomb;
	unsigned int		sfmode; /* 所属接口的组播源过滤模式,EXCLUDE或INCLUDE */
	unsigned long		sfcount[2]; /* EXCLUDE或INCLUDE过滤模式的套接口在本接口加入组的播组数 */
	struct ip_mc_list	*next;
	struct timer_list	timer;
	int			users;
	atomic_t		refcnt;
	spinlock_t		lock;
	char			tm_running;
	char			reporter; /* 标志当前是否正要开始发送igmp报告 */
	char			unsolicit_count;
	char			loaded;
	unsigned char		gsquery;	/* check source marks? */
	unsigned char		crcount;
};

/* V3 exponential field decoding */
#define IGMPV3_MASK(value, nb) ((nb)>=32 ? (value) : ((1<<(nb))-1) & (value))
#define IGMPV3_EXP(thresh, nbmant, nbexp, value) \
	((value) < (thresh) ? (value) : \
        ((IGMPV3_MASK(value, nbmant) | (1<<(nbmant))) << \
         (IGMPV3_MASK((value) >> (nbmant), nbexp) + (nbexp))))

#define IGMPV3_QQIC(value) IGMPV3_EXP(0x80, 4, 3, value)
#define IGMPV3_MRC(value) IGMPV3_EXP(0x80, 4, 3, value)

extern int ip_check_mc(struct in_device *dev, __be32 mc_addr, __be32 src_addr, u16 proto);
extern int igmp_rcv(struct sk_buff *);
extern int ip_mc_join_group(struct sock *sk, struct ip_mreqn *imr);
extern int ip_mc_leave_group(struct sock *sk, struct ip_mreqn *imr);
extern void ip_mc_drop_socket(struct sock *sk);
extern int ip_mc_source(int add, int omode, struct sock *sk,
		struct ip_mreq_source *mreqs, int ifindex);
extern int ip_mc_msfilter(struct sock *sk, struct ip_msfilter *msf,int ifindex);
extern int ip_mc_msfget(struct sock *sk, struct ip_msfilter *msf,
		struct ip_msfilter __user *optval, int __user *optlen);
extern int ip_mc_gsfget(struct sock *sk, struct group_filter *gsf,
		struct group_filter __user *optval, int __user *optlen);
extern int ip_mc_sf_allow(struct sock *sk, __be32 local, __be32 rmt, int dif);
extern void ip_mc_init_dev(struct in_device *);
extern void ip_mc_destroy_dev(struct in_device *);
extern void ip_mc_up(struct in_device *);
extern void ip_mc_down(struct in_device *);
extern void ip_mc_unmap(struct in_device *);
extern void ip_mc_remap(struct in_device *);
extern void ip_mc_dec_group(struct in_device *in_dev, __be32 addr);
extern void ip_mc_inc_group(struct in_device *in_dev, __be32 addr);
extern void ip_mc_rejoin_group(struct ip_mc_list *im);

#endif
#endif
