## 1. HTB(Hierarchical token bucket, 递阶令牌桶)

HTB, 从名称看就是TBF的扩展, 所不同的是TBF就一个节点处理所有数据, 而HTB是基于分类的流控方法, 以前那些流控一般用一个”tc qdisc”命令就可以完成配置, 而要配置好HTB, 通常情况下tc qdisc, class, filter三种命令都要用到, 用于将不同数据包分为不同的类别, 然后针对每种类别数据再设置相应的流控方法, 因此基于分类的流控方法远比以前所述的流控方法复杂。

HTB将各种类别的流控处理节点组合成一个**节点树**, 每个叶节点是一个流控结构, 可在叶子节点使用不同的流控方法，如将pfifo, tbf等。HTB一个重要的特点是能设置每种类型的基本带宽，当本类带宽满而其他类型带宽空闲时可以向其他类型借带宽。注意这个树是**静态**的, 一旦TC命令配置好后就不变了, 而具体的实现是HASH表实现的, 只是逻辑上是树, 而且不是二叉树, 每个节点可以有多个子节点。

HTB**运行过程中**会将不同类别不同优先权的数据包进行有序排列，用到了有序表, 其数据结构实际是一种特殊的**二叉树**, 称为红黑树(Red Black Tree), 这种树的结构是**动态变化**的，而且数量不只一个，最大可有8×8个树。

红黑树的特征是:

- 1) 每个节点不是红的就是黑的;
- 2) 根节点必须是黑的;
- 3) 所有叶子节点必须也是黑的;
- 4) 每个红节点的子节点必须是黑的, 也就是红节点的父节点必须是黑节点;
- 5) 从每个节点到最底层节点的所有路径必须包含相同数量的黑节点;

关于红黑树的数据结构和操作在include/linux/rbtree.h和lib/rbtree.c中定义.

对于HTB的原理理解，可以参考

- 1.[Linux TC(Traffic Control) 简介](https://yq.aliyun.com/articles/4000)
- 2.[linux网络流控-htb算法简析](https://www.cnblogs.com/acool/p/7779159.html)
- 3.[分层令牌桶原理](https://guanjunjian.github.io/2017/11/16/study-9-hierachical-token-bucket-theory/)

总结来说，原理为：

某个时刻每个类可以处于三种状态中的一种:

- 1.CAN_SEND
- 2.MAY_BORROW
- 3.CANT_SEND

决策哪个类出包算法：

- 1.htb算法从类树的底部开始往上找CAN_SEND状态的class.如果找到某一层有CAN_SEND状态的类则停止.
- 2.如果该层中有多个class处于CAN_SEND状态则选取优先级最高(priority最小)的class.如果最高优先级还是有多个class,那就在这些类中轮训处理.每个类每发送自己的quantum个字节后,轮到下一个类发送.
- 3.上面有讲到只有leafclass才可以缓存网络包,innerclass是没有网络包的.如果步骤1,2最终选到了innerclass怎么处理？既然是innerclass,肯定有自己的subclass.innerclass会顺着树往下找,找到一个子孙leafclass.并且该leafclass处于MAY_BORROW状态,将自己富余的令牌借给该leafclass让其出包.同样的道理,可能会有多个子孙leafclass处于MAY_BORROW状态,这里的处理跟步骤2是一样的.

## 2. HTB操作结构定义

- `htb_cmode`：HTB操作数据包模式。HTB_CAN_SEND，可以发送, 没有阻塞；HTB_CANT_SEND，阻塞，不能发生数据包；HTB_MAY_BORROW，阻塞，可以向其他类借带宽来发送
- `htb_class`:HTB类别, 用于定义HTB的节点,包括`htb_class_leaf(叶子节点)`,`htb_class_inner(非叶子节点)`
- `htb_sched`:HTB私有数据结构
- `htb_class_ops`:HTB类别操作结构，对应于Qdisc_class_ops。有htb_graft(设置叶子节点的流控方法)、htb_leaf(增加子节点)、htb_walk(遍历)等
- `htb_qdisc_ops`:HTB流控操作结构

各种流控算法是通过流控操作结构（Qdisc_ops）实现，在构建新的Qdisc时，需要传入Qdisc_ops（`qdisc_alloc(struct net_device *dev, struct Qdisc_ops *ops)`），所以来看看HTB流控队列的基本操作结构，Qdisc_ops——–`htb_qdisc_ops`：

```c
static struct Qdisc_ops htb_qdisc_ops = {  
 .next  = NULL,  
 .cl_ops  = &htb_class_ops,  
 .id  = "htb",  
 .priv_size = sizeof(struct htb_sched),  
 .enqueue = htb_enqueue,  
 .dequeue = htb_dequeue,  
 .requeue = htb_requeue,  
 .drop  = htb_drop,  
 .init  = htb_init,  
 .reset  = htb_reset,  
 .destroy = htb_destroy,  
// 更改操作为空  
 .change  = NULL /* htb_change */,  
 .dump  = htb_dump,  
 .owner  = THIS_MODULE,  
}; 
```

接着是HTB流控队列类别操作结构，Qdisc_class_ops——–`htb_class_ops`：

```c
static struct Qdisc_class_ops htb_class_ops = {  
 .graft  = htb_graft,  
 .leaf  = htb_leaf,  
 .get  = htb_get,  
 .put  = htb_put,  
 .change  = htb_change_class,  
 .delete  = htb_delete,  
 .walk  = htb_walk,  
 .tcf_chain = htb_find_tcf,  
 .bind_tcf = htb_bind_filter,  
 .unbind_tcf = htb_unbind_filter,  
 .dump  = htb_dump_class,  
 .dump_stats = htb_dump_class_stats,  
}; 
```

## 3. HTB的TC操作命令

为了更好理解HTB各处理函数，先用HTB的配置实例过程来说明各种操作调用了哪些HTB处理函数，以下的配置实例取自HTB Manual, 属于最简单分类配置:

**3.1 配置网卡的根流控节点为HTB**

```
#根节点ID是0x10000, 缺省类别是0x10012,  
#handle x:y, x定义的是类别ID的高16位, y定义低16位  
#注意命令中的ID参数都被理解为16进制的数
tc qdisc add dev eth0 root handle 1: htb default 12
```

在内核中将调用`htb_init()`函数初始化HTB流控结构。

**3.2 建立分类树**

```
#根节点总流量带宽100kbps, 内部类别ID是0x10001  
tc class add dev eth0 parent 1: classid 1:1 htb rate 100kbps ceil 100kbps  
#第一类别数据分30kbps, 最大可用100kbps, 内部类别ID是0x10010(注意这里确实是16进制的10)  
tc class add dev eth0 parent 1:1 classid 1:10 htb rate 30kbps ceil 100kbps  
#第二类别数据分30kbps, 最大可用100kbps, 内部类别ID是0x10011  
tc class add dev eth0 parent 1:1 classid 1:11 htb rate 10kbps ceil 100kbps  
#第三类别(缺省类别)数据分60kbps, 最大可用100kbps, 内部类别ID是0x10012  
tc class add dev eth0 parent 1:1 classid 1:12 htb rate 60kbps ceil 100kbps
```

在内核中将调用`htb_change_class()`函数来修改HTB参数

**3.3 数据包分类**

```
#对源地址为1.2.3.4, 目的端口是80的数据包为第一类, 0x10010  
tc filter add dev eth0 protocol ip parent 1:0 prio 1 u32 match ip src 1.2.3.4 match ip  
dport 80 0xffff flowid 1:10  
#对源地址是1.2.3.4的其他类型数据包是第2类, 0x10011  
tc filter add dev eth0 protocol ip parent 1:0 prio 1 u32 match ip src 1.2.3.4 flowid  
1:11  
#其他数据包将作为缺省类, 0x10012
```

在内核中将调用`htb_find_tcf()`, `htb_bind_filter()`函数来将为HTB绑定过滤表

**3.4 设置每个叶子节点的流控方法**

```
# 1:10节点为pfifo  
tc qdisc add dev eth0 parent 1:10 handle 20: pfifo limit 10  
# 1:11节点也为pfifo  
tc qdisc add dev eth0 parent 1:11 handle 30: pfifo limit 10  
# 1:12节点使用sfq, 扰动时间10秒  
tc qdisc add dev eth0 parent 1:12 handle 40: sfq perturb 10
```

在内核中会使用`htb_leaf()`查找HTB叶子节点, 使用`htb_graft()`函数来设置叶子节点的流控方法。

## 4. HTB类别操作

- `htb_graft`:嫁接,设置HTB叶子节点的流控方法
- `htb_leaf`:获取叶子节点
- `htb_get`:根据classid获取类，并增加引用计数
- `htb_put`:减少类别引用计数，如果减到0，释放该类别
- `htb_destroy_class`:释放类别,由于使用了递归处理, 因此HTB树不能太大, 否则就会使内核堆栈溢出而导致内核崩溃, HTB定
  义的最大深度是8层
- `htb_change_class`:更改类别结构内部参数,如普通速率和峰值速率
- `htb_find_tcf`:查找过滤规则表
- `htb_bind_filter`:绑定过滤器
- `htb_unbind_filter`:解开过滤器
- `htb_walk`:遍历HTB
- `htb_dump_class`:类别参数输出,如速率、优先权值、定额(quantum)、层次值
- `htb_dump_class_stats`:类别统计信息输出

## 5. HTB一些操作函数

**转换函数**

- `L2T`:将长度转换为令牌数
- `htb_hash`:HTB哈希计算, 限制哈希结果小于16, 因为只有16个HASH表, 这个大小是定死的

**查询函数**

- `htb_find`:根据句柄handle查找HTB节点

**分类函数**

- `htb_classid`:获取HTB类别结构的ID
- `htb_classify`:HTB分类操作, 对数据包进行分类, 然后根据类别进行相关操作，返回NULL表示没找到, 返回-1表示是直接通过(不分类)的数据包

**激活类别**

- `htb_activate`:激活类别结构, 将该类别节点作为数据包提供者, 而数据类别表提供是一个有序表, 以RB树形式实现
- `htb_activate_prios(struct htb_sched *q, struct htb_class *cl)`:激活操作, 建立数据提供树。cl->prio_activity为0时就是一个空函数, 不过从前面看prio_activity似乎是不会为0的
- `htb_add_to_id_tree`:将类别添加到红黑树中
- `htb_add_class_to_row`:将类别添加到self feed(row)

**关闭类别**

- `htb_deactivate`:将类别叶子节点从活动的数据包提供树中去掉
- `htb_deactivate_prios`:将类别从inner feed中移除（feed chains）
- `htb_remove_class_from_row`:将类别从self feed中移除(row)

**初始化**

- `htb_init`:初始化函数
- `htb_timer`:HTB定时器函数
- `htb_rate_timer`:HTB速率定时器函数

**丢包**

- `htb_drop`:丢包函数，try to drop from each class (by prio) until one succee

**复位**

- `htb_reset`:复位函数，reset all classes

**释放**

- `htb_destroy`:释放函数，always caled under BH & queue lock

**输出HTB参数**

- `htb_dump`

**入队**

- `htb_enqueue`

**重入队**

- `htb_requeue`

**出队**

- `htb_dequeue`
- `htb_dequeue_tree`:从指定的层次和优先权的RB树节点中取数据包
- `htb_lookup_leaf`:查找叶子分类节点
- `htb_charge_class`:关于类别节点的令牌和缓冲区数据的更新计算, 调整类别节点的模式
- `htb_change_class_mode`:调整类别节点的发送模式
- `htb_class_mode`:计算类别节点的模式
- `htb_add_to_wait_tree`:将类别节点添加到等待树(white slot)
- `htb_do_events`:对第level号等待树的类别节点进行模式调整
- `htb_delay_by`:HTB延迟处理



以下仔细分析比较重要的函数。



### 5.1 入队

**htb_enqueue()**

```c
htb_enqueue() <-----
static int htb_enqueue(struct sk_buff *skb, struct Qdisc *sch)  
{
	int ret;
	// HTB私有数据结构  
	struct htb_sched *q = qdisc_priv(sch);
	/** 对数据包进行分类
	  * NULL，数据包drop
	  * -1，数据包直接发送，下文中#define HTB_DIRECT (struct htb_class*)-1
	  * leaf class,其他情况
	  */
	struct htb_class *cl = htb_classify(skb, sch, &ret);
	if (cl == HTB_DIRECT) {
	// 分类结果是直接发送
		/* enqueue to helper queue */
		// 如果直接发送队列中的数据包长度小于直接发送队列长度最大值, 将数据包添加到队列末尾
		if (q->direct_queue.qlen < q->direct_qlen) {
			__skb_queue_tail(&q->direct_queue, skb);
			q->direct_pkts++;
		} else {
			// 否则丢弃数据包
			kfree_skb(skb);
			sch->qstats.drops++;
			return NET_XMIT_DROP;
		}
#ifdef CONFIG_NET_CLS_ACT
	// 定义了NET_CLS_ACT的情况(支持分类动作)
	} else if (!cl) {
		// 分类没有结果, 丢包
		if (ret == NET_XMIT_BYPASS)
			sch->qstats.drops++;
		kfree_skb(skb);
		return ret;
#endif
	// 有分类结果, 进行分类相关的叶子节点流控结构（是指3.4中为叶子节点设置的流控，例如pfifo）的入队操作
	} else if (cl->un.leaf.q->enqueue(skb, cl->un.leaf.q) !=
		   NET_XMIT_SUCCESS) {
		// 入队不成功的话丢包
		sch->qstats.drops++;
		cl->qstats.drops++;
		return NET_XMIT_DROP;
	} else {
		// 入队成功, 分类结构的包数字节数的统计数增加
		cl->bstats.packets++;
		cl->bstats.bytes += skb->len;
		// 激活HTB类别, 建立该类别的数据提供树, 这样dequeue时可以从中取数据包
		// 只有类别节点的模式是可发送和可租借的情况下才会激活, 如果节点是阻塞模式, 则不会被激活
		htb_activate(q, cl);
	}
	// HTB流控结构统计数更新, 入队成功
	sch->q.qlen++;
	sch->bstats.packets++;
	sch->bstats.bytes += skb->len;
	return NET_XMIT_SUCCESS;
}
```

大部分情况下数据包都不会进入直接处理队列, 而是进入各类别叶子节点, 因此入队的成功与否就在于叶子节点使用何种流控算法, 大都应该可以入队成功的， 入队不涉及类别节点模式的调整。

接下来再看看`htb_activate(q, cl);`。


**htb_enqueue()—>htb_activate()**

```c
htb_enqueue()
	-> htb_activate(q, cl) <-----
/** 
 * htb_activate - 将叶子节点cl插入适合的active self feed中 
 * 
 * Routine学习(新的)叶子节点优先级，并根据优先级激活feed chain。它可以安全地调用已经激活的叶子
 * 它也可以将叶子节点添加到droplist中
 * 激活类别结构, 将该类别节点作为数据包提供者, 而数据类别表提供是一个有序表, 以RB树形式实现
 */ 
static inline void htb_activate(struct htb_sched *q, struct htb_class *cl)
{
	BUG_TRAP(!cl->level && cl->un.leaf.q && cl->un.leaf.q->q.qlen);
	// 如果类别的prio_activity参数为0才进行操作, 非0表示已经激活了
	// leaf.aprio保存当前的leaf.prio
	if (!cl->prio_activity) {
	// prio_activity是通过叶子节点的prio值来设置的, 至少是1, 最大是1<<7, 非0值
		cl->prio_activity = 1 << (cl->un.leaf.aprio = cl->un.leaf.prio);
		// 进行实际的激活操作
		htb_activate_prios(q, cl);
		// 根据leaf.aprio添加到指定的优先权位置的丢包链表
		list_add_tail(&cl->un.leaf.drop_list,
			      q->drops + cl->un.leaf.aprio);
	}
}
```

接下来再到`htb_activate_prios(q, cl);`。


**htb_enqueue()—>htb_activate()—>htb_activate_prios()**

```c
htb_enqueue()
	-> htb_activate()
		-> htb_activate_prios(q, cl) <-----
/** 
 * htb_activate_prios - 创建active class的feed chain 
 * 
 * 这里的class必须是根据优先级连接到祖先节点的inner self或者合适的rows（self feed）。
 * cl->cmode必须是new (activated) mode。
 * 如果cl->prio_activity == 0,就是一个空函数， 不过从前面看prio_activity似乎是不会为0的
 * 激活操作, 建立数据提供树
 */  
static void htb_activate_prios(struct htb_sched *q, struct htb_class *cl)
{	
	// 父节点
	struct htb_class *p = cl->parent;
	// prio_activity是作为一个掩码, 应该只有一位为1
	long m, mask = cl->prio_activity;
	// 在当前模式是HTB_MAY_BORROW情况下进入循环, 某些情况下这些类别是可以激活的
	// 绝大多数情况p和mask的初始值应该都是非0值
	while (cl->cmode == HTB_MAY_BORROW && p && mask) {
		// 备份mask值
		m = mask;
		while (m) {
			// 掩码取反, 找第一个0位的位置（从0开始计数）, 也就是原来最低为1的位的位置
			// prio越小, 等级越高, 取数据包也是先从prio值小的节点取
			int prio = ffz(~m);
			// 清除该位
			m &= ~(1 << prio);
			// p是父节点, 所以inner结构肯定有效, 不会使用leaf结构的
			// 如果父节点的prio优先权的数据包的提供树已经存在, 在掩码中去掉该位
			if (p->un.inner.feed[prio].rb_node)
				/* parent already has its feed in use so that
				   reset bit in mask as parent is already ok */
				mask &= ~(1 << prio);
			// 将该类别加到父节点的prio优先权提供数据包的节点树中，
			// 即由于子class是yellow，所以将其按优先级添加到父class的inner feed中
			htb_add_to_id_tree(p->un.inner.feed + prio, cl, prio);
		}
		// 父节点的prio_activity或上mask中的置1位, 某位为1表示该位对应的优先权的数据可用
		// 表示inner feed中与该子class的连线
		p->prio_activity |= mask;
		// 循环到上一层, 当前类别更新父节点, 父节点更新为祖父节点 
		// 如果父节点也变yellow，需要将父节点也添加到祖父节点的inner feed中
		cl = p;
		p = cl->parent;
	}
	// 如果cl是HTB_CAN_SEND模式, 将该类别添加到合适的ROW（self feed）中
	// 此时的cl可能已经不是原来的cl了,而是原cl的长辈节点了
	if (cl->cmode == HTB_CAN_SEND && mask)
		htb_add_class_to_row(q, cl, mask);
}
```

接下来需要分别看`htb_add_to_id_tree()`和`htb_add_class_to_row()`


**htb_enqueue()—>htb_activate()—>htb_activate_prios()—>htb_add_to_id_tree()**

```c
htb_enqueue()
	-> htb_activate()
		-> htb_activate_prios()
			//当class是yellow
			-> htb_add_to_id_tree(p->un.inner.feed + prio, cl, prio) <-----
			-> htb_add_class_to_row()
/** 
 * htb_add_to_id_tree - 将class添加到父class的inner feed中 
 * 
 * Routine 将class添加到根据classid存储的list中（实际上是一棵树）
 * 确保给定优先级的class之前没有存储在该list中 
 * @root: 传入的是p->un.inner.feed + prio，inner.feed是rb_boot数组，struct rb_root feed[TC_HTB_NUMPRIO]，
 * +prio表示获得prio优先级对应的feed[]数组元素
 * @cl: 要加入rb数的子节点
 * @prio: 子节点的优先级
 */  
static void htb_add_to_id_tree(struct rb_root *root,
			       struct htb_class *cl, int prio)
{
	struct rb_node **p = &root->rb_node, *parent = NULL;
	// RB树是有序表, 根据类别ID排序, 值大的到右节点, 小的到左节点
	// 循环, 查找树中合适的位置插入类别节点cl
	while (*p) {
		struct htb_class *c;
		parent = *p;
		c = rb_entry(parent, struct htb_class, node[prio]);

		if (cl->classid > c->classid)
			p = &parent->rb_right;
		else
			p = &parent->rb_left;
	}
	// 进行RB树的插入操作, RB树标准函数操作
	rb_link_node(&cl->node[prio], parent, p);
	rb_insert_color(&cl->node[prio], root);
}
```

接着来到`htb_add_class_to_row()`


**htb_enqueue()—>htb_activate()—>htb_activate_prios()—>htb_add_class_to_row()**

```c
htb_enqueue()
	-> htb_activate()
		-> htb_activate_prios()
			-> htb_add_to_id_tree()
			//当class是green
			-> htb_add_class_to_row(q, cl, mask) <-----
/** 
 * htb_add_class_to_row - 将class添加到它所在level的self feed 
 * 
 * 根据优先级掩码，将class添加到它所在level的row，即self feed 
 * 如果mask==0,将什么也不做
 */ 
static inline void htb_add_class_to_row(struct htb_sched *q,
					struct htb_class *cl, int mask)
{
	//htb_sched的row_mask表示该层的哪些优先权值的树有效
	// 将cl层次对应的ROW的row_mask或上新的mask, 表示有对应prio的数据了 
	q->row_mask[cl->level] |= mask;
	// 循环mask, 将cl插入mask每一位对应的prio的树中 
	while (mask) {
		// prio是mask中最低为1的位的位置 
		int prio = ffz(~mask);
		// 清除该位
		mask &= ~(1 << prio);
		// 添加到具体的RB树中，即cl所在层次的self feed对应优先级的RB树
		htb_add_to_id_tree(q->row[cl->level] + prio, cl, prio);
	}
}
```


**入队操作总结**

- 1.判断数据包类型：a.drop，b.直接发送，c.添加到叶子节点。以下只分享添加到叶子节点的类型
- 2.将数据包添加到叶子节点的流控结构体如pfifo
- 3.调用`htb_activate`激活HTB类别，建立该类别的数据提供数，这样dequeue时可以从中取数据包
- 4.获取叶子节点的优先级，调用`htb_activate_prios`进行实际的激活操作
- 5.`htb_activate_prios`中分两类进行：a.对于yellow类型的class，将其添加到父class的feed（inner feed）中，b.对于green类型的class，将其添加到class所在level的row（self feed）中。



### 5.2 出队

HTB的出队是个非常复杂的处理过程, 函数调用过程为:

```c
htb_dequeue <-----
	-> __skb_dequeue  
	-> htb_do_events  
		-> htb_safe_rb_erase  
		-> htb_change_class_mode  
		-> htb_add_to_wait_tree  
	-> htb_dequeue_tree  
		-> htb_lookup_leaf  
		-> htb_deactivate  
		-> q->dequeue  
		-> htb_next_rb_node  
		-> htb_charge_class  
			-> htb_change_class_mode  
			-> htb_safe_rb_erase  
			-> htb_add_to_wait_tree  
	-> htb_delay_by 
```


**htb_dequeue()**

```c
static struct sk_buff *htb_dequeue(struct Qdisc *sch)
{
	struct sk_buff *skb = NULL;
	// HTB私有数据结构
	struct htb_sched *q = qdisc_priv(sch);
	int level;
	long min_delay;
	// 保存当前时间滴答数
	q->jiffies = jiffies;
	/* try to dequeue direct packets as high prio (!) to minimize cpu work */
	// 先从当前直接发送队列取数据包, 直接发送队列中的数据有最高优先级, 可以说没有流量限制 
	skb = __skb_dequeue(&q->direct_queue);
	if (skb != NULL) {
		// 从直接发送队列中取到数据包, 更新参数, 非阻塞, 返回数据包  
		sch->flags &= ~TCQ_F_THROTTLED;
		//sch->q 数据包链表头
		sch->q.qlen--;
		return skb;
	}
	// 如果HTB流控结构队列长度为0, 返回空
	if (!sch->q.qlen)
		goto fin;
	// 获取当前有效时间值
	PSCHED_GET_TIME(q->now);
	// 最小延迟值初始化为最大整数
	min_delay = LONG_MAX;
	q->nwc_hit = 0;
	// 遍历节点树（静态）的所有层次, 从叶子节点开始
	for (level = 0; level < TC_HTB_MAXDEPTH; level++) {
		/* common case optimization - skip event handler quickly */
		int m;
		long delay;
		// 计算延迟值, 是取数据包失败的情况下更新HTB定时器的延迟时间 
		// 比较ROW树中该层节点最近的事件定时时间是否已经到了
		if (time_after_eq(q->jiffies, q->near_ev_cache[level])) {
			// 时间到了, 处理HTB事件, 返回值是下一个事件的延迟时间
			//对第level号等待树的类别节点进行模式调整，即white slot里面的class，一会再详细看
			delay = htb_do_events(q, level);
			// 更新本层最近定时时间,HZ表示1秒钟
			q->near_ev_cache[level] =
			    q->jiffies + (delay ? delay : HZ);
		} else
			// 时间还没到, 计算两者时间差
			delay = q->near_ev_cache[level] - q->jiffies;
		// 更新最小延迟值, 注意这是在循环里面进行更新的, 循环找出最小的延迟时间
		if (delay && min_delay > delay)
			min_delay = delay;
		// 该层次的row_mask取反, 实际是为找到row_mask[level]中为1的位, 为1表示该树有数据包可用
		// row中的节点都是green，也就是CAN_SEND
		m = ~q->row_mask[level];
		while (m != (int)(-1)) {
			// m的数据位中第一个0位的位置作为优先级值, 从低位开始找, 也就是prio越小, 实际数据的优先权越大, 越先出队
			// 找出同一层取优先级高的
			int prio = ffz(m);
			// 将该0位设置为1, 也就是清除该位
			m |= 1 << prio;
			// 从该优先权值的流控树中进行出队操作
			skb = htb_dequeue_tree(q, prio, level);
			if (likely(skb != NULL)) {
				// 数据包出队成功, 更新参数, 退出循环, 返回数据包
				// 取数据包成功就要去掉流控节点的阻塞标志
				sch->q.qlen--;
				sch->flags &= ~TCQ_F_THROTTLED;
				goto fin;
			}
		}
	}
	// 循环结束也没取到数据包, 队列长度非0却不能取出数据包, 表示流控节点阻塞
	// 进行阻塞处理, 调整HTB定时器, 最大延迟5秒
	htb_delay_by(sch, min_delay > 5 * HZ ? 5 * HZ : min_delay);
fin:
	return skb;
}
```

可以看到，`dequeue`主要分为三个部分，下面就从5.2.1、5.2.2和5.2.3分别来看`htb_do_events()`、`htb_dequeue_tree()`和`htb_delay_by()`。

#### 5.2.1 htb_do_events


**htb_dequeue()—>htb_do_events()**

```c
htb_dequeue 
	-> __skb_dequeue  
	-> htb_do_events(q, level) <-----
		-> htb_safe_rb_erase  
		-> htb_change_class_mode  
		-> htb_add_to_wait_tree  
	-> htb_dequeue_tree  
	-> htb_delay_by 
/** 
 * htb_do_events - 对第level号等待树的类别节点进行模式调整 
 * 
 * 扫描event队列,发现pending event然后应用它们。
 * 返回下一个pending event的时间jiffies，如果pq没有event，则返回0
 */  
//  
static long htb_do_events(struct htb_sched *q, int level)
{
	int i;
	// 循环500次, 为什么是500? 表示树里最多有500个节点? 对应500个事件
	for (i = 0; i < 500; i++) {
		struct htb_class *cl;
		long diff;
		//q->wait_pq[]：等待队列，用来挂载哪些带宽超出限制的节点
		// 取等待rb树第一个节点, 每次循环都从树中删除一个节点  
		struct rb_node *p = rb_first(&q->wait_pq[level]);
		// 没节点, 事件空, 返回0表示没延迟
		if (!p)
			return 0;
		// 获取该节点对应的HTB类别
		cl = rb_entry(p, struct htb_class, pq_node);
		// 该类别延迟处理时间是在当前时间后面, 返回时间差作为延迟值
		if (time_after(cl->pq_key, q->jiffies)) {
			return cl->pq_key - q->jiffies;
		}
		// 时间小于当前时间了, 已经超时了
		// 安全地将该节点p从等待RB树中断开
		htb_safe_rb_erase(p, q->wait_pq + level);
		// 当前时间和检查点时间的差值
		// 根据当前时间和上次流控计算时间的时间差来计算可用的令牌量
		// 计算从上次发送数据包到现在的时间里生成的令牌数，然后把diff加上原先桶中的令牌数就为总的令牌数，当然总的令牌数是不能比桶大的
		diff = PSCHED_TDIFF_SAFE(q->now, cl->t_c, (u32) cl->mbuffer);
		// 根据时间差值更改该类别模式
		htb_change_class_mode(q, cl, &diff);
		// 如果不是可发送模式, 重新插入回等待树 
		if (cl->cmode != HTB_CAN_SEND)
			htb_add_to_wait_tree(q, cl, diff);
	}
	// 超过500个事件
	if (net_ratelimit())
		printk(KERN_WARNING "htb: too many events !\n");
	// 返回0.1秒的延迟 
	return HZ / 10;
}
```

接着再来看看`htb_change_class_mode()`


**htb_dequeue()—>htb_do_events()—>htb_change_class_mode()**

```c
htb_dequeue 
	-> __skb_dequeue  
	-> htb_do_events(q, level) 
		-> htb_safe_rb_erase  
		-> htb_change_class_mode(q, cl, &diff) <-----
		-> htb_add_to_wait_tree  
	-> htb_dequeue_tree  
	-> htb_delay_by 
/** 
 * htb_change_class_mode - 调整类别节点的发送模式  
 *  
 * 这个函数应该是在正常情况下唯一的改变class发送模式的方法。R
 * outine会更新self feed list连接关系，改变class的模式或将class添加到合适的wait event队列中。
 *  新模式应该与旧模式不一样，而且如果改变后的模式不是HTB_CAN_SEND（看htb_add_to_wait_tree），那么cl->pq_key必须有效
 */  
static void
htb_change_class_mode(struct htb_sched *q, struct htb_class *cl, long *diff)
{	
	// 根据变化值计算新模式
	enum htb_cmode new_mode = htb_class_mode(cl, diff);
	// 模式没变, 返回
	if (new_mode == cl->cmode)
		return;
	// cl->prio_activity非0表示是活动的节点, 需要停止后再更新模式 
	if (cl->prio_activity) {	/* not necessary: speed optimization */
		// 如原来的模式为可发送数据, 先停该节点
		if (cl->cmode != HTB_CANT_SEND)
			htb_deactivate_prios(q, cl);
		// 更新模式
		cl->cmode = new_mode;
		// 如果新模式不是禁止发送, 重新激活节点 
		if (new_mode != HTB_CANT_SEND)
			htb_activate_prios(q, cl);
	} else
		// 非活动类别节点, 直接更新模式值
		cl->cmode = new_mode;
}
```

接着继续看看`htb_class_mode()`。


**htb_dequeue()—>htb_do_events()—>htb_change_class_mode()—>htb_class_mode()**

```c
htb_dequeue 
	-> __skb_dequeue  
	-> htb_do_events(q, level) 
		-> htb_safe_rb_erase  
		-> htb_change_class_mode() 
			-> htb_class_mode(cl, diff) <-----
		-> htb_add_to_wait_tree  
	-> htb_dequeue_tree  
	-> htb_delay_by 
/** 
 * htb_class_mode - 计算并返回类节点的模式 
 * 
 * 该函数根据cl->tc+diff（tc为检查时间点）计算class的模式。如果模式不是HTB_CAN_SEND，那么cl->pq_key更新为现在时间和class改变状态时间的差
 * class模式不是简单地改变 cl->{c,}tokens == 0，而是滞后地改为0..-cl->{c,}的缓存范围
 * 这意味着限制单位时间内模式改变的次数，速度的增加大概是1/6
 */
static inline enum htb_cmode
htb_class_mode(struct htb_class *cl, long *diff)
{
	long toks;
	/* 计算类别的Ceil令牌，tokens表示当前令牌数，ctokens表示峰值令牌数
	 * htb_lowater():如果cmode是HTB_CANT_SEND,返回0，否则返回 -cl->cbuffer
     * 这里ctokens是租借模式下令牌数，经过一段时间后令牌数就会进行补充。
     * 待补充后仍然小于低水位线，则状态变为HTB_CANT_SEND（不能进行发送），
     * 这里htb_lowater低水位线根据当前类的模式不同而不同，如果当前类模式
     * 为HTB_CANT_SEND，则低水位线的值为-cl->cbuffer，也
     * 就是租借模式下单包最大可传达数据所需要的ticket，其它模块下低水位线的值为0
     */
	if ((toks = (cl->ctokens + *diff)) < htb_lowater(cl)) {
		//返回还需要多少令牌
		*diff = -toks;
		// 如果令牌小于低限, 模式为不可发送
		return HTB_CANT_SEND;
	}
	/* 计算类别的普通令牌
	 * 如果令牌大于高限, 模式为可发送
	 * htb_hiwater():如果cmode是HTB_CAN_SEND，返回-cl->buffer，否则0
	 * 这里tokens是非租借模式下令牌数，经过一段时间补充后，如果高于高水位线，则状态变为HTB_CAN_SEND（可以发送）
	if ((toks = (cl->tokens + *diff)) >= htb_hiwater(cl))
		return HTB_CAN_SEND;
	// 否则模式为可借，返回还需要多少令牌 
	*diff = -toks;
	return HTB_MAY_BORROW;
}
```

下面重新回到`dequeue`主线，往下看，到了`htb_dequeue_tree`。

#### 5.2.2 htb_dequeue_tree


**htb_dequeue()—>htb_dequeue_tree()**

```c
htb_dequeue 
	-> __skb_dequeue  
	-> htb_do_events  
	-> htb_dequeue_tree <-----
		-> htb_lookup_leaf  
		-> htb_deactivate  
		-> q->dequeue  
		-> htb_next_rb_node  
		-> htb_charge_class  
	-> htb_delay_by 
/* 从指定层次和优先级的RB数节点中取数据包
 * 只有在确定该level该优先级可以active时才调用该函数
 */
static struct sk_buff *htb_dequeue_tree(struct htb_sched *q, int prio,
					int level)
{
	struct sk_buff *skb = NULL;
	//cl用于循环中做temp，start是记录首个循环的节点，用来结束循环
	struct htb_class *cl, *start;
	/* look initial class up in the row 
	 * 根据层次和优先权值查找起始类别节点
	 * 找到该level 该priority下的一个leafclass
	 * 如果这个节点是叶子节点，那么它必然是green的
	 * 如果这个节点是inner class，那么它是green的，就会找它的子孙叶子节点，而这个叶子节点必然是yellow的，
	 * 该inner class可以向它的子孙叶子节点“借”出带宽。
     */
	start = cl = htb_lookup_leaf(q->row[level] + prio, prio,
				     q->ptr[level] + prio,
				     q->last_ptr_id[level] + prio);

	do {
next:
		BUG_TRAP(cl);
		// 如果类别为空, 返回数据包为空
		if (!cl)
			return NULL;

		/* 
		 * class队列可以是空的---如果叶子节点的qdisc在入队时就drop掉数据包
		 * 或者如果someone在上一次dequeue时候对叶子节点使用graft操作（）
		 * 如果遇到class队列为空，则deactivate或skip
		 * 如果队列长度为0, 队列空的情况, 可能性较小  
		 */
		if (unlikely(cl->un.leaf.q->q.qlen == 0)) {
			struct htb_class *next;
			// 该类别队列中没数据包了, 停止该类别结构 
			htb_deactivate(q, cl);

			/* row/level might become empty */
			// 掩码该位为0， 表示该层该prio的rb树为空, 没有数据提供树， 返回数据包为空
			// 即该level的self feed的该prio为空
			if ((q->row_mask[level] & (1 << prio)) == 0)
				return NULL;
			// 否则重新查找该层该优先权的RB树节点class，同层级同优先级可以有多个class
			next = htb_lookup_leaf(q->row[level] + prio,
					       prio, q->ptr[level] + prio,
					       q->last_ptr_id[level] + prio);
			// 从新找到的这个类别结构cl开始循环, 找队列非空的节点
			if (cl == start)	/* fix start if we just deleted it */
				start = next;
			cl = next;
			// 这个goto形成了大循环中的小循环, 找队列长度非空的类别节点
			goto next;
		}
		// 以下是队列长度非空的情况, 运行该类别结构的内部流控节点的出队操作,
		// 这主要看该节点使用那种流控算法了, 如tbf之类就可以实现流量限制
		skb = cl->un.leaf.q->dequeue(cl->un.leaf.q);
		// 取得数据包, 中断循环准备返回
		if (likely(skb != NULL))
			break;
		// 没取得数据包, 打印警告信息, 该信息在循环中只打印一次 
		if (!cl->warned) {
			printk(KERN_WARNING
			       "htb: class %X isn't work conserving ?!\n",
			       cl->classid);
			// 作为已经打印了警告信息的标志
			cl->warned = 1;
		}
		// 取到空包计数增加, 表示从非工作类别中取数据包的异常情况次数
		q->nwc_hit++;
		/* 更新到下一个rb树节点，即查找下一个该层级该优先级的节点
         * 如果现在level!=0，就说明进行dequeue_tree操作的是个inner class，那么cl就是这个inner class的子孙叶子节点，
         * 所以传入的是cl父节点的inner class所在的rb数指针
         * level=0则就是叶子节点，传入的是叶子节点所在rb树的指针
         */
		htb_next_rb_node((level ? cl->parent->un.inner.ptr : q->
				  ptr[0]) + prio);
		// 继续查找该层该优先权另一个class的RB树中找叶子类别节点, 循环
		cl = htb_lookup_leaf(q->row[level] + prio, prio,
				     q->ptr[level] + prio,
				     q->last_ptr_id[level] + prio);

	} while (cl != start);
	// 找到数据包的情况, 可能性很大
	if (likely(skb != NULL)) {
		//deficit[level] 扣掉该包的byte数
		// 计算赤字deficit, 减数据包长度, 而deficit是初始化为0的
		//当出队一个数据包时,类对应的deficit[level]扣减包的byte数,
		//当deficit[level]<0时说明该类已经发送了quantum.于是虽然再次给deficit[level]加了quantum,
		//但是htb_next_rb_node((level ? cl->parent->un.inner.ptr : q->ptr[0]) + prio)已经将该
		//层该优先级的出包类指针指向下一个类了.下发出包,将会出另一个类.
		if ((cl->un.leaf.deficit[level] -= skb->len) < 0) {
			// 如果该类别节点的赤字为负, 增加一个定额量, 缺省是物理网卡的队列长度
			cl->un.leaf.deficit[level] += cl->un.leaf.quantum;
			//当deficit[level]<0时说明该类已经发送了quantum.需要发送同层级同优先级的下一个类了.
			//同上，更新到下一个rb树节点，即查找下一个该层级该优先级的节点
			htb_next_rb_node((level ? cl->parent->un.inner.ptr : q->
					  ptr[0]) + prio);
		}
		// 如果赤字为正就不会进行RB数节点的更换 
		/* this used to be after charge_class but this constelation
		   gives us slightly better performance */
		// 如果队列空了, 停止该类别 
		if (!cl->un.leaf.q->q.qlen)
			htb_deactivate(q, cl);
		// 更新令牌.
		// 处理该流控节点以及其所有父节点的令牌情况, 调整该类别的模式cmode 
		htb_charge_class(q, cl, level, skb->len);
	}
	return skb;
}
```

**总结htb_dequeue_tree**

- 1.根据传入的层级和优先级获取class，调用`htb_lookup_leaf()`,如果是叶子节点就返回本身，如果是inner class则找到其子孙叶子节点
- 2.如果以上获得的叶子节点没有数据，则停止该节点，并寻找下一个同层级同优先级的节点，直到找到一个有数据包的节点
- 3.取出数据包，如果包不为空，则”next”中断循环，获得数据包，否则进行4.”next”循环就是为了获得一个队列不是空的节点
- 4.在之前的节点树中都没找到数据包，则换一颗节点树，如果形参中传入的是inner class，则换一个同层级同优先级的inner class，获取它的叶子节点，否则就获得同层级同优先级的叶子节点
- 5.一直循到1.,除非循环到重复的节点或者是找到了数据包，结束循环
- 6.获得要发送的数据包，计算deficit赤字，如果deficit[level]<0时说明该类已经发送了quantum.需要发送同层级同优先级的下一个类
- 7.如果队列空了, 停止该类别
- 8.处理该流控节点以及其所有父节点的令牌情况, 调整该类别的模式cmode

#### 5.2.3 htb_delay_by


**htb_dequeue()—>htb_delay_by()**

```c
htb_dequeue 
	-> __skb_dequeue  
	-> htb_do_events  
	-> htb_dequeue_tree  
	-> htb_delay_by(sch, min_delay > 5 * HZ ? 5 * HZ : min_delay) <-----
//当htb_dequeue循环结束也没取到数据包, 队列长度非0却不能取出数据包, 表示流控节点阻塞  
// 进行阻塞处理, 调整HTB定时器, 最大延迟5秒 
// HTB延迟处理
static void htb_delay_by(struct Qdisc *sch, long delay)
{
	struct htb_sched *q = qdisc_priv(sch);
	// 延迟至少是1个时间片, 1/HZ秒  
	if (delay <= 0)
		delay = 1;
	// 延迟最大是5秒
	if (unlikely(delay > 5 * HZ)) {
		if (net_ratelimit())
			printk(KERN_INFO "HTB delay %ld > 5sec\n", delay);
		delay = 5 * HZ;
	}
	/* why don't use jiffies here ? because expires can be in past */
	// 修改定时器 
	mod_timer(&q->timer, q->jiffies + delay);
	// 设置阻塞标志
	sch->flags |= TCQ_F_THROTTLED;
	// 流量溢出统计增加 
	sch->qstats.overlimits++;
}
```


**5.3 其他操作（不详细介绍）**

- `htb_requeue`:重入队
- `htb_dequeue_tree`:从指定的层次和优先权的RB树节点中取数据包
- `htb_lookup_leaf`:查找叶子分类节点
- `htb_charge_class`:关于类别节点的令牌和缓冲区数据的更新计算, 调整类别节点的模式
- `htb_change_class_mode`:调整类别节点的发送模式
- `htb_class_mode`:计算类别节点的模式
- `htb_add_to_wait_tree`:将类别节点添加到等待树
- `htb_do_events(struct htb_sched *q, int level)`:对第level号等待树的类别节点进行模式调整
- `htb_delay_by`:HTB延迟处理

HTB的流控就体现在通过令牌变化情况计算类别节点的模式, 如果是CAN_SEND就能继续发送数据, 该节点可以留在数据包提供树中; 如果阻塞CANT_SEND该类别节点就会从数据包提供树中拆除而不能发包; 如果模式是CAN_BORROW的则根据其他节点的带宽情况来确定是否能留在数据包提供树而继续发包, 不在提供树中, 即使有数据包也只能阻塞着不能发送, 这样就实现了流控管理。

为理解分类型流控算法的各种参数的含义, 最好去看一下RFC 3290。

## 参考

- *[Linux内核中流量控制(11)](http://cxw06023273.iteye.com/blog/867337)*
- *[Linux内核中流量控制(12)](http://cxw06023273.iteye.com/blog/867338)*
- *[Linux内核中流量控制(13)](http://cxw06023273.iteye.com/blog/867339)*
- *[对linux内核中jiffies+Hz表示一秒钟的理解](http://blog.csdn.net/u012160436/article/details/45530621)*
- *[Linux TC(Traffic Control) 简介](https://yq.aliyun.com/articles/4000)*
- *[linux网络流控-htb算法简析](https://www.cnblogs.com/acool/p/7779159.html)*
- *[分层令牌桶原理](https://guanjunjian.github.io/2017/11/16/study-9-hierachical-token-bucket-theory/)*
- *[HTB分层令牌桶排队规则分析](http://blog.csdn.net/liujianfeng1984/article/details/41922085)*