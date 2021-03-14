/*
 *	Linux ethernet bridge
 *
 *	Authors:
 *	Lennert Buytenhek		<buytenh@gnu.org>
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License
 *	as published by the Free Software Foundation; either version
 *	2 of the License, or (at your option) any later version.
 */

#ifndef _BR_PRIVATE_H
#define _BR_PRIVATE_H

#include <linux/netdevice.h>
#include <linux/if_bridge.h>
#include <net/route.h>

#define BR_HASH_BITS 8
#define BR_HASH_SIZE (1 << BR_HASH_BITS)

#define BR_HOLD_TIME (1*HZ)

#define BR_PORT_BITS	10
#define BR_MAX_PORTS	(1<<BR_PORT_BITS)

#define BR_VERSION	"2.3"

/* Path to usermode spanning tree program */
#define BR_STP_PROG	"/sbin/bridge-stp"

typedef struct bridge_id bridge_id;
typedef struct mac_addr mac_addr;
typedef __u16 port_id;

/* BID,也就是2字节的桥优先级加上6字节的ip地址 */
struct bridge_id
{
	unsigned char	prio[2];
	unsigned char	addr[6];
};

struct mac_addr
{
	unsigned char	addr[6];
};

struct br_ip
{
	union {
		__be32	ip4;
#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
		struct in6_addr ip6;
#endif
	} u;
	__be16		proto;
};

/* 网桥端口-mac映射表项 */
struct net_bridge_fdb_entry
{
	struct hlist_node		hlist; /* 用于cam表连接的链表指针 */
	struct net_bridge_port		*dst; /* 桥的端口 */

	struct rcu_head			rcu;
	unsigned long			ageing_timer;
	mac_addr			addr;
	unsigned char			is_local;
	unsigned char			is_static;
};

struct net_bridge_port_group {
	struct net_bridge_port		*port;
	struct net_bridge_port_group	*next;
	struct hlist_node		mglist;
	struct rcu_head			rcu;
	struct timer_list		timer;
	struct timer_list		query_timer;
	struct br_ip			addr;
	u32				queries_sent;
};

struct net_bridge_mdb_entry
{
	struct hlist_node		hlist[2];
	struct hlist_node		mglist;
	struct net_bridge		*br;
	struct net_bridge_port_group	*ports;
	struct rcu_head			rcu;
	struct timer_list		timer;
	struct timer_list		query_timer;
	struct br_ip			addr;
	u32				queries_sent;
};

struct net_bridge_mdb_htable
{
	struct hlist_head		*mhash;
	struct rcu_head			rcu;
	struct net_bridge_mdb_htable	*old;
	u32				size;
	u32				max;
	u32				secret;
	u32				ver;
};

/* 网桥端口数据 */
struct net_bridge_port
{
	struct net_bridge		*br; /* 当前端口所属的网桥设备 */
	struct net_device		*dev; /* 链接到这个端口的物理设备 */
	struct list_head		list; /* 同一桥内的端口连接 */

	/* STP */
	u8				priority;
	u8				state;
	u16				port_no;
	unsigned char			topology_change_ack; /* 拓扑变化确认标志 */
	unsigned char			config_pending;
	port_id				port_id;
	port_id				designated_port; /* 指定端口的id */
	bridge_id			designated_root; /* 对端的根桥 */
	bridge_id			designated_bridge; /*  指定桥的bid */
	u32				path_cost; /* 路径开销 */
	u32				designated_cost; /* 指定端口到根桥的开销 */
    /* 端口定时器,也就是stp控制超时的一些定时器列表 */
	struct timer_list		forward_delay_timer;
	struct timer_list		hold_timer;
	struct timer_list		message_age_timer;
	struct kobject			kobj;
	struct rcu_head			rcu;

	unsigned long 			flags;
#define BR_HAIRPIN_MODE		0x00000001

#ifdef CONFIG_BRIDGE_IGMP_SNOOPING
	u32				multicast_startup_queries_sent;
	unsigned char			multicast_router;
	struct timer_list		multicast_router_timer;
	struct timer_list		multicast_query_timer;
	struct hlist_head		mglist;
	struct hlist_node		rlist;
#endif

#ifdef CONFIG_SYSFS
	char				sysfs_name[IFNAMSIZ];
#endif
};

struct br_cpu_netstats {
	unsigned long	rx_packets;
	unsigned long	rx_bytes;
	unsigned long	tx_packets;
	unsigned long	tx_bytes;
};

/* 网桥的定义 */
struct net_bridge
{
	spinlock_t			lock; /* 自旋锁 */
	struct list_head		port_list; /* 网桥所有端口的链表,每个元素都是net_bridge_port结构 */
	struct net_device		*dev; /* 网桥会建立一个虚拟设备来进行管理,该设备的mac是动态指定的,通常是桥组中的一个物理端口的mac地址 */

	struct br_cpu_netstats __percpu *stats;
	spinlock_t			hash_lock;
    /* 保存forwarding database的一个hash链表(这个也就是地址学习的东东,所以通过hash能 快速定位),这里每个元素都是一个net_bridge_fsb_entry结构  */
	struct hlist_head		hash[BR_HASH_SIZE];
	unsigned long			feature_mask;
#ifdef CONFIG_BRIDGE_NETFILTER
	struct rtable 			fake_rtable;
#endif
	unsigned long			flags;
#define BR_SET_MAC_ADDR		0x00000001

	/* STP */
	bridge_id			designated_root; /* 网桥的根端口标记 */
	bridge_id			bridge_id;  /* 端口自己的bridge id */
	u32				root_path_cost; /* 记录到根桥的开销 */
	unsigned long			max_age;
	unsigned long			hello_time;
	unsigned long			forward_delay; /* 传输延时 */
	unsigned long			bridge_max_age;
	unsigned long			ageing_time;
	unsigned long			bridge_hello_time;
	unsigned long			bridge_forward_delay;

	u8				group_addr[ETH_ALEN];
	u16				root_port; /* 根端口 */
    /* stp使用的协议 */
	enum {
		BR_NO_STP, 		/* no spanning tree */
		BR_KERNEL_STP,		/* old STP in kernel */
		BR_USER_STP,		/* new RSTP in userspace */
	} stp_enabled;

	unsigned char			topology_change; /* 拓扑变化标志 */
	unsigned char			topology_change_detected; /* 是否检测到了拓扑发生更改 */

#ifdef CONFIG_BRIDGE_IGMP_SNOOPING
	unsigned char			multicast_router;

	u8				multicast_disabled:1;

	u32				hash_elasticity;
	u32				hash_max;

	u32				multicast_last_member_count;
	u32				multicast_startup_queries_sent;
	u32				multicast_startup_query_count;

	unsigned long			multicast_last_member_interval;
	unsigned long			multicast_membership_interval;
	unsigned long			multicast_querier_interval;
	unsigned long			multicast_query_interval;
	unsigned long			multicast_query_response_interval;
	unsigned long			multicast_startup_query_interval;

	spinlock_t			multicast_lock;
	struct net_bridge_mdb_htable	*mdb;
	struct hlist_head		router_list;
	struct hlist_head		mglist;

	struct timer_list		multicast_router_timer;
	struct timer_list		multicast_querier_timer;
	struct timer_list		multicast_query_timer;
#endif
    /* stp要用的一些定时器列表 */
	struct timer_list		hello_timer; /* 用于定时发送配置bpdu报文 */
	struct timer_list		tcn_timer;
	struct timer_list		topology_change_timer;
	struct timer_list		gc_timer;
	struct kobject			*ifobj;
};

struct br_input_skb_cb {
	struct net_device *brdev;
#ifdef CONFIG_BRIDGE_IGMP_SNOOPING
	int igmp;
	int mrouters_only;
#endif
};

#define BR_INPUT_SKB_CB(__skb)	((struct br_input_skb_cb *)(__skb)->cb)

#ifdef CONFIG_BRIDGE_IGMP_SNOOPING
# define BR_INPUT_SKB_CB_MROUTERS_ONLY(__skb)	(BR_INPUT_SKB_CB(__skb)->mrouters_only)
#else
# define BR_INPUT_SKB_CB_MROUTERS_ONLY(__skb)	(0)
#endif

#define br_printk(level, br, format, args...)	\
	printk(level "%s: " format, (br)->dev->name, ##args)

#define br_err(__br, format, args...)			\
	br_printk(KERN_ERR, __br, format, ##args)
#define br_warn(__br, format, args...)			\
	br_printk(KERN_WARNING, __br, format, ##args)
#define br_notice(__br, format, args...)		\
	br_printk(KERN_NOTICE, __br, format, ##args)
#define br_info(__br, format, args...)			\
	br_printk(KERN_INFO, __br, format, ##args)

#define br_debug(br, format, args...)			\
	pr_debug("%s: " format,  (br)->dev->name, ##args)

extern struct notifier_block br_device_notifier;
extern const u8 br_group_address[ETH_ALEN];

/* called under bridge lock
 * 判断是否为根桥
 */
static inline int br_is_root_bridge(const struct net_bridge *br)
{
    /* 用自己的bid和BPDU包中的根id相比 */
	return !memcmp(&br->bridge_id, &br->designated_root, 8);
}

/* br_device.c */
extern void br_dev_setup(struct net_device *dev);
extern netdev_tx_t br_dev_xmit(struct sk_buff *skb,
			       struct net_device *dev);
#ifdef CONFIG_NET_POLL_CONTROLLER
extern void br_netpoll_cleanup(struct net_device *dev);
extern void br_netpoll_enable(struct net_bridge *br,
			      struct net_device *dev);
extern void br_netpoll_disable(struct net_bridge *br,
			       struct net_device *dev);
#else
#define br_netpoll_cleanup(br)
#define br_netpoll_enable(br, dev)
#define br_netpoll_disable(br, dev)

#endif

/* br_fdb.c */
extern int br_fdb_init(void);
extern void br_fdb_fini(void);
extern void br_fdb_flush(struct net_bridge *br);
extern void br_fdb_changeaddr(struct net_bridge_port *p,
			      const unsigned char *newaddr);
extern void br_fdb_cleanup(unsigned long arg);
extern void br_fdb_delete_by_port(struct net_bridge *br,
				  const struct net_bridge_port *p, int do_all);
extern struct net_bridge_fdb_entry *__br_fdb_get(struct net_bridge *br,
						 const unsigned char *addr);
extern int br_fdb_test_addr(struct net_device *dev, unsigned char *addr);
extern int br_fdb_fillbuf(struct net_bridge *br, void *buf,
			  unsigned long count, unsigned long off);
extern int br_fdb_insert(struct net_bridge *br,
			 struct net_bridge_port *source,
			 const unsigned char *addr);
extern void br_fdb_update(struct net_bridge *br,
			  struct net_bridge_port *source,
			  const unsigned char *addr);

/* br_forward.c */
extern void br_deliver(const struct net_bridge_port *to,
		struct sk_buff *skb);
extern int br_dev_queue_push_xmit(struct sk_buff *skb);
extern void br_forward(const struct net_bridge_port *to,
		struct sk_buff *skb, struct sk_buff *skb0);
extern int br_forward_finish(struct sk_buff *skb);
extern void br_flood_deliver(struct net_bridge *br, struct sk_buff *skb);
extern void br_flood_forward(struct net_bridge *br, struct sk_buff *skb,
			     struct sk_buff *skb2);

/* br_if.c */
extern void br_port_carrier_check(struct net_bridge_port *p);
extern int br_add_bridge(struct net *net, const char *name);
extern int br_del_bridge(struct net *net, const char *name);
extern void br_net_exit(struct net *net);
extern int br_add_if(struct net_bridge *br,
	      struct net_device *dev);
extern int br_del_if(struct net_bridge *br,
	      struct net_device *dev);
extern int br_min_mtu(const struct net_bridge *br);
extern void br_features_recompute(struct net_bridge *br);

/* br_input.c */
extern int br_handle_frame_finish(struct sk_buff *skb);
extern struct sk_buff *br_handle_frame(struct net_bridge_port *p,
				       struct sk_buff *skb);

/* br_ioctl.c */
extern int br_dev_ioctl(struct net_device *dev, struct ifreq *rq, int cmd);
extern int br_ioctl_deviceless_stub(struct net *net, unsigned int cmd, void __user *arg);

/* br_multicast.c */
#ifdef CONFIG_BRIDGE_IGMP_SNOOPING
extern int br_multicast_rcv(struct net_bridge *br,
			    struct net_bridge_port *port,
			    struct sk_buff *skb);
extern struct net_bridge_mdb_entry *br_mdb_get(struct net_bridge *br,
					       struct sk_buff *skb);
extern void br_multicast_add_port(struct net_bridge_port *port);
extern void br_multicast_del_port(struct net_bridge_port *port);
extern void br_multicast_enable_port(struct net_bridge_port *port);
extern void br_multicast_disable_port(struct net_bridge_port *port);
extern void br_multicast_init(struct net_bridge *br);
extern void br_multicast_open(struct net_bridge *br);
extern void br_multicast_stop(struct net_bridge *br);
extern void br_multicast_deliver(struct net_bridge_mdb_entry *mdst,
				 struct sk_buff *skb);
extern void br_multicast_forward(struct net_bridge_mdb_entry *mdst,
				 struct sk_buff *skb, struct sk_buff *skb2);
extern int br_multicast_set_router(struct net_bridge *br, unsigned long val);
extern int br_multicast_set_port_router(struct net_bridge_port *p,
					unsigned long val);
extern int br_multicast_toggle(struct net_bridge *br, unsigned long val);
extern int br_multicast_set_hash_max(struct net_bridge *br, unsigned long val);

static inline bool br_multicast_is_router(struct net_bridge *br)
{
	return br->multicast_router == 2 ||
	       (br->multicast_router == 1 &&
		timer_pending(&br->multicast_router_timer));
}
#else
static inline int br_multicast_rcv(struct net_bridge *br,
				   struct net_bridge_port *port,
				   struct sk_buff *skb)
{
	return 0;
}

static inline struct net_bridge_mdb_entry *br_mdb_get(struct net_bridge *br,
						      struct sk_buff *skb)
{
	return NULL;
}

static inline void br_multicast_add_port(struct net_bridge_port *port)
{
}

static inline void br_multicast_del_port(struct net_bridge_port *port)
{
}

static inline void br_multicast_enable_port(struct net_bridge_port *port)
{
}

static inline void br_multicast_disable_port(struct net_bridge_port *port)
{
}

static inline void br_multicast_init(struct net_bridge *br)
{
}

static inline void br_multicast_open(struct net_bridge *br)
{
}

static inline void br_multicast_stop(struct net_bridge *br)
{
}

static inline void br_multicast_deliver(struct net_bridge_mdb_entry *mdst,
					struct sk_buff *skb)
{
}

static inline void br_multicast_forward(struct net_bridge_mdb_entry *mdst,
					struct sk_buff *skb,
					struct sk_buff *skb2)
{
}
static inline bool br_multicast_is_router(struct net_bridge *br)
{
	return 0;
}
#endif

/* br_netfilter.c */
#ifdef CONFIG_BRIDGE_NETFILTER
extern int br_netfilter_init(void);
extern void br_netfilter_fini(void);
extern void br_netfilter_rtable_init(struct net_bridge *);
#else
#define br_netfilter_init()	(0)
#define br_netfilter_fini()	do { } while(0)
#define br_netfilter_rtable_init(x)
#endif

/* br_stp.c */
extern void br_log_state(const struct net_bridge_port *p);
extern struct net_bridge_port *br_get_port(struct net_bridge *br,
					   u16 port_no);
extern void br_init_port(struct net_bridge_port *p);
extern void br_become_designated_port(struct net_bridge_port *p);

/* br_stp_if.c */
extern void br_stp_enable_bridge(struct net_bridge *br);
extern void br_stp_disable_bridge(struct net_bridge *br);
extern void br_stp_set_enabled(struct net_bridge *br, unsigned long val);
extern void br_stp_enable_port(struct net_bridge_port *p);
extern void br_stp_disable_port(struct net_bridge_port *p);
extern void br_stp_recalculate_bridge_id(struct net_bridge *br);
extern void br_stp_change_bridge_id(struct net_bridge *br, const unsigned char *a);
extern void br_stp_set_bridge_priority(struct net_bridge *br,
				       u16 newprio);
extern void br_stp_set_port_priority(struct net_bridge_port *p,
				     u8 newprio);
extern void br_stp_set_path_cost(struct net_bridge_port *p,
				 u32 path_cost);
extern ssize_t br_show_bridge_id(char *buf, const struct bridge_id *id);

/* br_stp_bpdu.c */
struct stp_proto;
extern void br_stp_rcv(const struct stp_proto *proto, struct sk_buff *skb,
		       struct net_device *dev);

/* br_stp_timer.c */
extern void br_stp_timer_init(struct net_bridge *br);
extern void br_stp_port_timer_init(struct net_bridge_port *p);
extern unsigned long br_timer_value(const struct timer_list *timer);

/* br.c */
#if defined(CONFIG_ATM_LANE) || defined(CONFIG_ATM_LANE_MODULE)
extern int (*br_fdb_test_addr_hook)(struct net_device *dev, unsigned char *addr);
#endif

/* br_netlink.c */
extern int br_netlink_init(void);
extern void br_netlink_fini(void);
extern void br_ifinfo_notify(int event, struct net_bridge_port *port);

#ifdef CONFIG_SYSFS
/* br_sysfs_if.c */
extern const struct sysfs_ops brport_sysfs_ops;
extern int br_sysfs_addif(struct net_bridge_port *p);
extern int br_sysfs_renameif(struct net_bridge_port *p);

/* br_sysfs_br.c */
extern int br_sysfs_addbr(struct net_device *dev);
extern void br_sysfs_delbr(struct net_device *dev);

#else

#define br_sysfs_addif(p)	(0)
#define br_sysfs_renameif(p)	(0)
#define br_sysfs_addbr(dev)	(0)
#define br_sysfs_delbr(dev)	do { } while(0)
#endif /* CONFIG_SYSFS */

#endif
