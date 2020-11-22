#ifndef _NET_NEIGHBOUR_H
#define _NET_NEIGHBOUR_H

#include <linux/neighbour.h>

/*
 *	Generic neighbour manipulation
 *
 *	Authors:
 *	Pedro Roque		<roque@di.fc.ul.pt>
 *	Alexey Kuznetsov	<kuznet@ms2.inr.ac.ru>
 *
 * 	Changes:
 *
 *	Harald Welte:		<laforge@gnumonks.org>
 *		- Add neighbour cache statistics like rtstat
 */

#include <asm/atomic.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/rcupdate.h>
#include <linux/seq_file.h>

#include <linux/err.h>
#include <linux/sysctl.h>
#include <linux/workqueue.h>
#include <net/rtnetlink.h>

/*
 * NUD stands for "neighbor unreachability detection"
 */

#define NUD_IN_TIMER	(NUD_INCOMPLETE|NUD_REACHABLE|NUD_DELAY|NUD_PROBE)
#define NUD_VALID 	(NUD_PERMANENT|NUD_NOARP|NUD_REACHABLE|NUD_PROBE|NUD_STALE|NUD_DELAY)
#define NUD_CONNECTED	(NUD_PERMANENT|NUD_NOARP|NUD_REACHABLE)

struct neighbo22ur;

struct neigh_22parms {
#ifdef CONFIG_NET_NS
	struct net *net;
#endif
	struct net_device *dev;
	struct neigh_parms *next;
	int	(*neigh_setup)(struct neighbour *);
	void	(*neigh_cleanup)(struct neighbour *);
	struct neigh_table *tbl;

	void	*sysctl_table;

	int dead;
	atomic_t refcnt;
	struct rcu_head rcu_head;

	int	base_reachable_time;
	int	retrans_time;
	int	gc_staletime;
	int	reachable_time;
	int	delay_probe_time;

	int	queue_len;
	int	ucast_probes;
	int	app_probes;
	int	mcast_probes;
	int	anycast_delay;
	int	proxy_delay;
	int	proxy_qlen;
	int	locktime;
};

struct neighbour;

/*
 * 邻居协议参数配置块，用于存储可调节的邻居协议
 * 参数，如重传超时时间、proxy_queue队列长度等。一个
 * 邻居协议对应一个参数配置块，而每一个网络设备
 * 的IPv4的配置块中也存在一个存放默认值的邻居配置
 * 块。
 */
struct neigh_parms
{
#ifdef CONFIG_NET_NS
	struct net *net;
#endif
	/*
	 * 指向该neigh_parms实例所对应的网络设备，
	 * 在通过neigh_parms_alloc()创建neigh_parms实例时
	 * 设置。
	 */
	struct net_device *dev;
	/*
	 * 通过next将属于同一个协议族的所有neigh_parms实例
	 * 链接在一起，每个neigh_table实例都有各自的neigh_parms
	 * 队列。
	 */
	struct neigh_parms *next;
	/*
	 * 提供给那些仍在使用老式接口设备的初始化和销毁
	 * 接口。net_device结构中也有一个neigh_setup成员函数指针，
	 * 不要与之混淆。
	 */
	int	(*neigh_setup)(struct neighbour *);
	void	(*neigh_cleanup)(struct neighbour *);
	/*
	 * 指向该neigh_parms实例所属的邻居表。
	 */
	struct neigh_table *tbl;

	/*
	 * 邻居表的sysctl表，对ARP是在ARP模块初始化函数
	 * arp_init()中对其初始化的，这样用户可以通过
	 * proc文件系统来读写邻居表的参数。
	 */
	void	*sysctl_table;

	/*
	 * 该字段值如果为1，则该邻居参数实例正在被删除，
	 * 不能再使用，也不能再创建对应网络设备的邻居项。
	 * 例如，在网络设备禁用时调用neigh_parms_release()设置。
	 */
	int dead;
	/*
	 * 引用计数。
	 */
	atomic_t refcnt;
	/*
	 * 为控制同步访问而设置的参数。
	 */
	struct rcu_head rcu_head;

	/*
	 * base_reachable_time为计算reachable_time的基准值；而reachable_time
	 * 为NUD_REACHABLE状态超时时间，该值为随机值，介于
	 * base_reachable_time和1.5倍的base_reachable_time之间，通常每300s
	 * 在neigh_periodic_timer()中更新一次。
	 */
	int	base_reachable_time;
	/*
	 * 用于重传ARP请求报文的超时时间。主机在输出一个ARP
	 * 请求报文之后的retrans_time个jiffies内，如果没有接收到应答
	 * 报文，则会重新输出一个新的ARP请求报文。
	 */
	int	retrans_time;
	/*
	 * 一个邻居项如果持续闲置(没有被使用)时间达到gc_staletime，
	 * 且没有被引用，则会将被删除。
	 */
	int	gc_staletime;
	int	reachable_time;
	/*
	 * 邻居项维持在NUD_DELAY状态delay_probe_time之后进入NUD_PROBE状态；
	 * 或者，处于NUD_REACHABLE状态的邻居项闲置时间超过delay_probe_time
	 * 后，直接进入NUD_DELAY状态。
	 */
	int	delay_probe_time;

	/*
	 * proxy_queue队列长度上限。
	 */
	int	queue_len;
	/*
	 * 发送并确认可达的单播ARP请求报文数目。
	 */
	int	ucast_probes;
	/*
	 * 地址解析时，应用程序(通常是arpd)可发送ARP请求报文
	 * 的数目。
	 */
	int	app_probes;
	/*
	 * 为了解析一个邻居地址，可发送的广播ARP请求报文数目。
	 * 需要注意的是app_probes和mcast_probes之间是互斥的，ARP发送的
	 * 是多播报文，而非广播报文。
	 */
	int	mcast_probes;
	/*
	 * 未使用
	 */
	int	anycast_delay;
	/*
	 * 处理代理请求报文可延时的时间
	 */
	int	proxy_delay;
	/*
	 * proxy_queue队列的长度的上限。
	 */
	int	proxy_qlen;
	/*
	 * 当邻居项最近两次更新的时间间隔小于该值时，
	 * 用覆盖的方式来更新邻居项。例如，当有多个
	 * 在同一网段的代理ARP服务器答复对相同地址的
	 * 查询
	 */
	int	locktime;
};

struct neigh_statistics {
	unsigned long allocs;		/* number of allocated neighs */
	unsigned long destroys;		/* number of destroyed neighs */
	unsigned long hash_grows;	/* number of hash resizes */

	unsigned long res_failed;	/* number of failed resolutions */

	unsigned long lookups;		/* number of lookups */
	unsigned long hits;		/* number of hits (among lookups) */

	unsigned long rcv_probes_mcast;	/* number of received mcast ipv6 */
	unsigned long rcv_probes_ucast; /* number of received ucast ipv6 */

	unsigned long periodic_gc_runs;	/* number of periodic GC runs */
	unsigned long forced_gc_runs;	/* number of forced GC runs */

	unsigned long unres_discards;	/* number of unresolved drops */
};

#define NEIGH_CACHE_STAT_INC(tbl, field) this_cpu_inc((tbl)->stats->field)

/* 邻居节点
 *
 */
struct neighbour {
	struct neighbour	*next;
	struct neigh_table	*tbl;   /* 用于指向对应的邻居表 */
	struct neigh_parms	*parms;
	struct net_device		*dev;   /* 通过此网络设备可以访问到该邻居 */
	unsigned long		used;      /* 最近一次被使用的时间 */
	unsigned long		confirmed;  /* 用于记录最近一次确认该邻居可达性的时间,用于描述邻居的可达性 */
	unsigned long		updated; /* 记录最近一次被neigh_update()更新的时间 */
	__u8			flags;
	__u8			nud_state; /* 当前邻居表项的状态     */
	__u8			type;
	__u8			dead;
	atomic_t		probes; /* 尝试发送请求而未能得到应答的次数,该值在定时器处理函数中被检测,
	                          * 当该值达到指定的上限是,该邻居项进入NUD_FAILED状态 */
	rwlock_t		lock;
	unsigned char		ha[ALIGN(MAX_ADDR_LEN, sizeof(unsigned long))]; /* 一般是mac地址 */
	struct hh_cache		*hh;
	atomic_t		refcnt;
	int			(*output)(struct sk_buff *skb);
	struct sk_buff_head	arp_queue; /* 当邻居项状态处于无效时,用来缓存要发送的报文 */
	struct timer_list	timer;
	const struct neigh_ops	*ops;
	u8			primary_key[0];
};

/*
 * neigh_ops结构实际上是一个函数指针表，包含了一组
 * 函数指针，这些函数在一个neighbour实例的整个生命
 * 周期内会被使用到，由此实现了三层和二层的
 * dev_queue_xmit()之间的转接。
 */
struct neigh_ops
{
	/*
	 * 标识所属的地址族，比如ARP为AF_INET等。
	 */
	int			family;
	/*
	 * 发送请求报文函数。在发送第一个报文时，需要
	 * 新的邻居项，发送报文被缓存到arp_queue队列中，
	 * 然后会调用solicit()发送请求报文。
	 */
	void			(*solicit)(struct neighbour *, struct sk_buff*);
	/*
	 * 当邻居项缓存着未发送的报文，而该邻居项又不可达时，
	 * 被调用来向三层报告错误的函数。ARP中为arp_error_report()，
	 * 最终会给报文发送方发送一个主机不可达的ICMP差错报文。
	 */
	void			(*error_report)(struct neighbour *, struct sk_buff*);
	/*
	 * 最通用的输出函数，可用于所有情况。此输出函数实现了
	 * 完整的输出过程，因此存在较多的校验与操作，以确保
	 * 报文的输出，因此该函数相对较消耗资源。此外，不要
	 * 将neigh_ops->output()与neighbour->output()混淆。
	 */
	int			(*output)(struct sk_buff*);
	/*
	 * 在确定邻居可达时，即状态为NUD_CONNECTED时使用的输出函数。
	 * 由于所有输出所需要的信息都已具备，因此该函数只是简单
	 * 地添加二层首部，也因此比output()快得多。
	 */
	int			(*connected_output)(struct sk_buff*);
	/*
	 * 在已缓存了二层首部的情况下使用的输出函数。
	 */
	int			(*hh_output)(struct sk_buff*);
	/*
	 * 实际上，以上几个输出接口，除了hh_output外，并不真正传输
	 * 数据包，只是在准备好二层首部之后，调用queue_xmit接口。
	 */
	int			(*queue_xmit)(struct sk_buff*);
};

/* pneigh_entry用来保存允许代理的条件,只有和结构中的接收设备以及目标地址
 * 相匹配才能代理,所有pneigh_entry实例都存储在邻居表的phash_buckets散列表中,
 * 称之为代理项 */
struct pneigh_entry {
	struct pneigh_entry	*next;
#ifdef CONFIG_NET_NS
	struct net		*net;
#endif
	struct net_device	*dev; /* 通过该网络设备接收到的arp请求报文才能代理 */
	u8			flags;
	u8			key[0];
};

/*
 *	neighbour table manipulation
 */
struct neigh_table {
	struct neigh_table	*next;
	int			family;         /* 邻居协议所属的地址族  ,我们暂时只管ipv4, 也就是AF_INET */
	int			entry_size;   /* 邻居项结构的大小 */
	int			key_len;    /* hash函数所使用的key的长度 */
	__u32			(*hash)(const void *pkey, const struct net_device *); /* hash函数,arp中为arp_hash */
	int			(*constructor)(struct neighbour *);
	int			(*pconstructor)(struct pneigh_entry *);
	void			(*pdestructor)(struct pneigh_entry *);
	void			(*proxy_redo)(struct sk_buff *skb);
	char			*id; /* 用来分配neighbour结构实例的缓冲池名字符串,arp_tlb中该字段为"arp_cache" */
	struct neigh_parms	parms;
	/* HACK. gc_* shoul follow parms without a gap! */
	int			gc_interval;
	int			gc_thresh1;
	int			gc_thresh2;
	int			gc_thresh3;
	unsigned long		last_flush; /* 记录最近一次调用neigh_forced_gc()强制刷新邻居表的时间,
	                                  * 用来作为是否进行垃圾回收的判断条件 */
	struct delayed_work	gc_work;
	struct timer_list 	proxy_timer;
	struct sk_buff_head	proxy_queue; /* 对于接收到的需要进行代理的ARP报文,会先将其缓存到
	                                   * proxy_queue队列中,在定时器处理函数中再对其进行处理    */
	atomic_t		entries;
	rwlock_t		lock;           /* 用于控制邻居表的读写锁 */
	unsigned long		last_rand;
	struct kmem_cache		*kmem_cachep;
	struct neigh_statistics	__percpu *stats;
	struct neighbour	**hash_buckets;
	unsigned int		hash_mask;
	__u32			hash_rnd;
	struct pneigh_entry	**phash_buckets;
};

/* flags for neigh_update() */
#define NEIGH_UPDATE_F_OVERRIDE			0x00000001
#define NEIGH_UPDATE_F_WEAK_OVERRIDE		0x00000002
#define NEIGH_UPDATE_F_OVERRIDE_ISROUTER	0x00000004
#define NEIGH_UPDATE_F_ISROUTER			0x40000000
#define NEIGH_UPDATE_F_ADMIN			0x80000000

extern void			neigh_table_init(struct neigh_table *tbl);
extern void			neigh_table_init_no_netlink(struct neigh_table *tbl);
extern int			neigh_table_clear(struct neigh_table *tbl);
extern struct neighbour *	neigh_lookup(struct neigh_table *tbl,
					     const void *pkey,
					     struct net_device *dev);
extern struct neighbour *	neigh_lookup_nodev(struct neigh_table *tbl,
						   struct net *net,
						   const void *pkey);
extern struct neighbour *	neigh_create(struct neigh_table *tbl,
					     const void *pkey,
					     struct net_device *dev);
extern void			neigh_destroy(struct neighbour *neigh);
extern int			__neigh_event_send(struct neighbour *neigh, struct sk_buff *skb);
extern int			neigh_update(struct neighbour *neigh, const u8 *lladdr, u8 new,
					     u32 flags);
extern void			neigh_changeaddr(struct neigh_table *tbl, struct net_device *dev);
extern int			neigh_ifdown(struct neigh_table *tbl, struct net_device *dev);
extern int			neigh_resolve_output(struct sk_buff *skb);
extern int			neigh_connected_output(struct sk_buff *skb);
extern int			neigh_compat_output(struct sk_buff *skb);
extern struct neighbour 	*neigh_event_ns(struct neigh_table *tbl,
						u8 *lladdr, void *saddr,
						struct net_device *dev);

extern struct neigh_parms	*neigh_parms_alloc(struct net_device *dev, struct neigh_table *tbl);
extern void			neigh_parms_release(struct neigh_table *tbl, struct neigh_parms *parms);

static inline
struct net			*neigh_parms_net(const struct neigh_parms *parms)
{
	return read_pnet(&parms->net);
}

extern unsigned long		neigh_rand_reach_time(unsigned long base);

extern void			pneigh_enqueue(struct neigh_table *tbl, struct neigh_parms *p,
					       struct sk_buff *skb);
extern struct pneigh_entry	*pneigh_lookup(struct neigh_table *tbl, struct net *net, const void *key, struct net_device *dev, int creat);
extern struct pneigh_entry	*__pneigh_lookup(struct neigh_table *tbl,
						 struct net *net,
						 const void *key,
						 struct net_device *dev);
extern int			pneigh_delete(struct neigh_table *tbl, struct net *net, const void *key, struct net_device *dev);

static inline
struct net			*pneigh_net(const struct pneigh_entry *pneigh)
{
	return read_pnet(&pneigh->net);
}

extern void neigh_app_ns(struct neighbour *n);
extern void neigh_for_each(struct neigh_table *tbl, void (*cb)(struct neighbour *, void *), void *cookie);
extern void __neigh_for_each_release(struct neigh_table *tbl, int (*cb)(struct neighbour *));
extern void pneigh_for_each(struct neigh_table *tbl, void (*cb)(struct pneigh_entry *));

struct neigh_seq_state {
	struct seq_net_private p;
	struct neigh_table *tbl;
	void *(*neigh_sub_iter)(struct neigh_seq_state *state,
				struct neighbour *n, loff_t *pos);
	unsigned int bucket;
	unsigned int flags;
#define NEIGH_SEQ_NEIGH_ONLY	0x00000001
#define NEIGH_SEQ_IS_PNEIGH	0x00000002
#define NEIGH_SEQ_SKIP_NOARP	0x00000004
};
extern void *neigh_seq_start(struct seq_file *, loff_t *, struct neigh_table *, unsigned int);
extern void *neigh_seq_next(struct seq_file *, void *, loff_t *);
extern void neigh_seq_stop(struct seq_file *, void *);

extern int			neigh_sysctl_register(struct net_device *dev,
						      struct neigh_parms *p,
						      char *p_name,
						      proc_handler *proc_handler);
extern void			neigh_sysctl_unregister(struct neigh_parms *p);

static inline void __neigh_parms_put(struct neigh_parms *parms)
{
	atomic_dec(&parms->refcnt);
}

static inline struct neigh_parms *neigh_parms_clone(struct neigh_parms *parms)
{
	atomic_inc(&parms->refcnt);
	return parms;
}

/*
 *	Neighbour references
 */

static inline void neigh_release(struct neighbour *neigh)
{
	if (atomic_dec_and_test(&neigh->refcnt))
		neigh_destroy(neigh);
}

static inline struct neighbour * neigh_clone(struct neighbour *neigh)
{
	if (neigh)
		atomic_inc(&neigh->refcnt);
	return neigh;
}

#define neigh_hold(n)	atomic_inc(&(n)->refcnt)

static inline void neigh_confirm(struct neighbour *neigh)
{
	if (neigh)
		neigh->confirmed = jiffies;
}

static inline int neigh_event_send(struct neighbour *neigh, struct sk_buff *skb)
{
	neigh->used = jiffies;
	if (!(neigh->nud_state&(NUD_CONNECTED|NUD_DELAY|NUD_PROBE)))
		return __neigh_event_send(neigh, skb);
	return 0;
}

#ifdef CONFIG_BRIDGE_NETFILTER
static inline int neigh_hh_bridge(struct hh_cache *hh, struct sk_buff *skb)
{
	unsigned seq, hh_alen;

	do {
		seq = read_seqbegin(&hh->hh_lock);
		hh_alen = HH_DATA_ALIGN(ETH_HLEN);
		memcpy(skb->data - hh_alen, hh->hh_data, ETH_ALEN + hh_alen - ETH_HLEN);
	} while (read_seqretry(&hh->hh_lock, seq));
	return 0;
}
#endif

static inline int neigh_hh_output(struct hh_cache *hh, struct sk_buff *skb)
{
	unsigned seq;
	int hh_len;

	do {
		int hh_alen;

		seq = read_seqbegin(&hh->hh_lock);
		hh_len = hh->hh_len;
		hh_alen = HH_DATA_ALIGN(hh_len);
		memcpy(skb->data - hh_alen, hh->hh_data, hh_alen);
	} while (read_seqretry(&hh->hh_lock, seq));

	skb_push(skb, hh_len);
	return hh->hh_output(skb);
}

static inline struct neighbour *
__neigh_lookup(struct neigh_table *tbl, const void *pkey, struct net_device *dev, int creat)
{
	struct neighbour *n = neigh_lookup(tbl, pkey, dev);

	if (n || !creat)
		return n;

	n = neigh_create(tbl, pkey, dev);
	return IS_ERR(n) ? NULL : n;
}

/* 查找邻居
 * @param tbl 邻居表
 * @param pkey 一般是ip地址
 * @param dev 网络设备
 */
static inline struct neighbour *
__neigh_lookup_errno(struct neigh_table *tbl, const void *pkey,
  struct net_device *dev)
{
    /* pkey为一个ip地址 */
	struct neighbour *n = neigh_lookup(tbl, pkey, dev);

	if (n)
		return n;
    /* 如果没有找到的话，构建一个neighbour */
	return neigh_create(tbl, pkey, dev);
}

struct neighbour_cb {
	unsigned long sched_next;
	unsigned int flags;
};

#define LOCALLY_ENQUEUED 0x1

#define NEIGH_CB(skb)	((struct neighbour_cb *)(skb)->cb)

#endif
