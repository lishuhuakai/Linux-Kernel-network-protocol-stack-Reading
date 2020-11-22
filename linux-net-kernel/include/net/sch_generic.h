#ifndef __NET_SCHED_GENERIC_H
#define __NET_SCHED_GENERIC_H

#include <linux/netdevice.h>
#include <linux/types.h>
#include <linux/rcupdate.h>
#include <linux/module.h>
#include <linux/pkt_sched.h>
#include <linux/pkt_cls.h>
#include <net/gen_stats.h>
#include <net/rtnetlink.h>

struct Qdisc_ops;
struct qdisc_walker;
struct tcf_walker;
struct module;

// 流控速率控制表结构 （一）空闲资源流控算法
struct qdisc_rate_table { //所有的都添加到qdisc_rtab_list
	struct tc_ratespec rate;
	u32		data[256];//参考应用层tc_calc_rtable   //这里得到的就是2047个字节所消耗的空闲资源。
	struct qdisc_rate_table *next;
	int		refcnt;
};

//qdisc->state
enum qdisc_state_t {
	__QDISC_STATE_RUNNING,//在__qdisc_run中清除置位。 __QDISC_STATE_RUNNING标志用于保证一个流控对象不会同时被多个例程运行。
	__QDISC_STATE_SCHED,
	__QDISC_STATE_DEACTIVATED,
};

struct qdisc_size_table {
	struct list_head	list;
	struct tc_sizespec	szopts;
	int			refcnt;
	u16			data[];
};
/*
tc可以使用以下命令对QDisc、类和过滤器进行操作：
add，在一个节点里加入一个QDisc、类或者过滤器。添加时，需要传递一个祖先作为参数，传递参数时既可以使用ID也可以直接传递设备的根。如果要建立一个QDisc或者过滤器，可以使用句柄(handle)来命名；如果要建立一个类，可以使用类识别符(classid)来命名。
remove，删除有某个句柄(handle)指定的QDisc，根QDisc(root)也可以删除。被删除QDisc上的所有子类以及附属于各个类的过滤器都会被自动删除。
change，以替代的方式修改某些条目。除了句柄(handle)和祖先不能修改以外，change命令的语法和add命令相同。换句话说，change命令不能一定节点的位置。
replace，对一个现有节点进行近于原子操作的删除／添加。如果节点不存在，这个命令就会建立节点。
link，只适用于DQisc，替代一个现有的节点。
tc qdisc [ add | change | replace | link ] dev DEV [ parent qdisc-id | root ] [ handle qdisc-id ] qdisc [ qdisc specific parameters ]
tc class [ add | change | replace ] dev DEV parent qdisc-id [ classid class-id ] qdisc [ qdisc specific parameters ]
tc filter [ add | change | replace ] dev DEV [ parent qdisc-id | root ] protocol protocol prio priority filtertype [ filtertype specific parameters ] flowid flow-id
tc [-s | -d ] qdisc show [ dev DEV ]
tc [-s | -d ] class show dev DEV tc filter show dev DEV

tc qdisc show dev eth0
tc class show dev eth0
*/
//tc qdisc add dev eth0 parent 22:4 handle 33中的22:4中的4实际上对应的是Qdisc私有数据部分分类信息中的3,parent 22:x中的x是从1开始排，但是对应到分类数组中具体的类的时候，是从0开始排，所以要减1，例如prio参考prio_get
//前言linux内核中提供了流量控制的相关处理功能，相关代码在net/sched目录下；而应用层上的控制是通过iproute2软件包中的tc来实现，tc和sched的关系就好象iptables和netfilter的关系一样，一个是用户层接口，一个是具体实现，关于tc的使用方法可详将Linux Advanced Routing HOWTO，本文主要分析内核中的具体实现。
//该结构中文称呼为:流控对象(队列规定)
//Qdisc开辟空间qdisc_alloc后面跟的是priv_size数据，见pfifo_qdisc_ops prio_qdisc_ops tbf_qdisc_ops sfq_qdisc_ops ingress_qdisc_ops(入口流控对象 ) 等中的priv_size， 图形化参考TC流量控制实现分析（初步） 
/*
队列规程分为无类队列规程和有类对了规程，有类的队列规程可以创建多个子队列规程(可以是分类的也可以是无类的队列规程)，如果只创建一个无类队列规程就相当于一个叶子规程
，SKB直接入队到该队列规程的skb队列中。如果是创建一个分类的队列规程，则第一个创建的队列规程就是跟，下面可以包括多个子队列规程，但所以分类队列规程必须有对应
的叶子无类队列规程，因为分类队列规程里面是没有skb队列的。
当一个SKB到分类队列规程的跟的时候，该选择走那条子队列规程入队呢? 这就是过滤器的作用，过滤器可以通过IP MASK等信息来确定走那个子队列规程分支。如果没有设置
过滤器，则一般根据skb->priority来确定走那个分支。
tc qdisc add dev eth0 root handle 1: htb 创建跟队列规程 (在创建跟分类规程的时候，一般默认是会有自队列规程的，例如pfifo无类规程)
tc class add dev eth0 parent 1: classid 1:2 htb xxxx  在1:队列规程下面的第1:2分支上，用htb创建一个子有类队列规程htb。并且在xxx中指定htb的参数信息
tc class add dev eth0 parent 1: classid 1:1 htb xxxx  在1:队列规程下面的第1:1分支上，用htb创建一个子有类队列规程htb。并且在xxx中指定htb的参数信息
tc filter add dev eth0 protocol ip parent 1: prio 2 u32 match ip dst 4.3.2.1/32 flowid 1:2 如果收到的是ip地址为4.3.2.1的SKB包，则走子队列规程1:2入队，而不是走1:1分子入队
*/ //最好的源码理解参考<<linux内核中流量控制>>
struct Qdisc { /* 参考 TC流量控制实现分析（初步）*/ //prio_sched_data中的queues指向该Qdisc              #注意命令中的ID(parent 1:2 xxx flowid 3:3)参数都被理解为16进制的数
//qdisc_alloc分配中在struct Qdisc结构后面的私有数据为pfifo_qdisc_ops prio_qdisc_ops tbf_qdisc_ops sfq_qdisc_ops ingress_qdisc_ops中的priv_size部分
    //enqueue和dequeue的赋值见qdisc_alloc
	int 			(*enqueue)(struct sk_buff *skb, struct Qdisc *dev); /* 入队接口 */
	struct sk_buff *	(*dequeue)(struct Qdisc *dev);  /* 出对接口 */
	unsigned		flags; //排队规则标志，取值为下面这几种宏定义  TCQ_F_THROTTLED
#define TCQ_F_BUILTIN		1 //表示排队规则是空的排队规则，在删除释放时不需要做过多的资源释放
#define TCQ_F_THROTTLED		2 //标识排队规则正处于由于限制而延时出队的状态中 
#define TCQ_F_INGRESS		4 //表示排队规则为输入排队规则
#define TCQ_F_CAN_BYPASS	8
#define TCQ_F_MQROOT		16
#define TCQ_F_WARN_NONWC	(1 << 16)// 作为已经打印了警告信息的标志
    /*
    由于排队规则的内存需要32字节对齐，而通过动态分配得到的内存起始地址不一定是32字节
    对齐，因此需要通过填充将队列规则对齐到32字节处。
    */
	int			padded;

	/*pfifo_qdisc_ops tbf_qdisc_ops sfq_qdisc_ops这几个都为出口，ingress_qdisc_ops为入口 */
	struct Qdisc_ops	*ops;//prio队列规则ops为pfifo_qdisc_ops，其他还有prio_qdisc_ops tbf_qdisc_ops sfq_qdisc_ops ingress_qdisc_ops(入口流控对象 ) 等， 
	struct qdisc_size_table	*stab;
	struct list_head	list;//连接到所配置的网络设备上

	/*排队规则实例的标识分为主编号部分和副编号部分，其中主编号部分由用户分配，范围从
	0X0001到0X7FFFF，如果用户指定主编号为0，那么内核讲在0X8000到0XFFFF之间分配一个主编号
	标识在单个网络设备是唯一的，但在多个网络设备之间可以由重复*/
	u32			handle; //本Qdisc的句柄，tc qdisc add dev eth0 root handle 22中的22
	u32			parent;//父队列规则的句柄值  tc qdisc add dev eth0 parent 22:4 handle 33 中handle为33 parent为22
	atomic_t		refcnt;//引用计数
	struct gnet_stats_rate_est	rate_est;//队列当前的速率，包括以字节和报文数为单位两种

    /*用于实现更复杂的流量控制机制，很少排队规则会实现此接口。当一个外部队列向内部队列
    传递报文时，可能出现报文必须被丢弃的情况，如当没有可用缓冲区时。如果排队规则实现了该回调
    函数，那么这时就可以被内部排队规则调用*/
	int			(*reshape_fail)(struct sk_buff *skb,
					struct Qdisc *q);

	void			*u32_node;//指向tc_u_common，见u32_init  指向的是指定队列规程的第一个u32过滤器

	/* This field is deprecated, but it is still used by CBQ
	 * and it will live until better solution will be invented.
	 */
	struct Qdisc		*__parent;
	struct netdev_queue	*dev_queue;
	struct Qdisc		*next_sched;

	struct sk_buff		*gso_skb;
	/*
	 * For performance sake on SMP, we put highly modified fields at the end
	 */
	unsigned long		state;
	struct sk_buff_head	q; //SKB就是添加到该队列中的  pfifo是入队的时候直接加入该skb链表，所以是典型的先进先出
	struct gnet_stats_basic_packed bstats;//记录入队报文总字节数和入队报文总数
	struct gnet_stats_queue	qstats;//记录队列相关统计数据
	struct rcu_head     rcu_head;//通过本字节在没有对象再使用该排队规则时释放该排队规则
};

/*
//分类的队列规定，例如prio cbq htb，这些队列规则Qdisc都会对应一个类接口，如果是无类的队列规定，则没有该类操作接口
//prio对应prio_class_ops htb对应htb_class_ops cbq对应cbq_class_ops等等

//分类队列规程Qdisc ops中的Qdisc_class_ops主要是在创建子Qdisc的时候，按照parent 22:4中的22:4对父Qdisc进行分类，从而通过22:4作为参数，
//选出该子Qdisc应该加到那个分类Qdisc后面。可以参考prio_qdisc_ops中的prio_get和prio_graft，就很好明白了
*/ //创建子队列规则或者class的时候，该结构的作用就是通过parent 22:8中的8从prio_get(以prio分类队列规程为例)选出的prize_size私有数据部分数组中的那一个具体信息，
struct Qdisc_class_ops { //主要在qdisc_graft执行下面的相关函数       可以参考prio_qdisc_ops，以prio为例        tc_ctl_tclass
	/* Child qdisc manipulation */
	struct netdev_queue *	(*select_queue)(struct Qdisc *, struct tcmsg *);

	//函数qdisc_graft中调用
	int			(*graft)(struct Qdisc *, unsigned long cl,
					struct Qdisc *, struct Qdisc **);