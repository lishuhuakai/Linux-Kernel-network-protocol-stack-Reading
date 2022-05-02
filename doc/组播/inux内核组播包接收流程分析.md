本文直接分析组播接收的流程细节。由于工作需要，暂且分析2.6.32内核的相关细节，并将分析文档记录于此。

## 驱动层

TCP/IP协议栈是典型的tier架构，对于IP协议来说，其工作就是从链路层接收数据，然后对其进行处理，然后将数据传递给它的上一层协议。所以不难想象其在内核中的实现，即通过链路层的包中存在的某个字段确定该包为IPv4协议包，然后选择对应的handler进行处理。

IPv4包接收的核心逻辑是比较简明易懂的，时间紧张就不多讨论。首先明确驱动和内核网络子系统的界限，即一个sk_buff是如果通过驱动转交给内核的。目前内核保留了两套API，或者说机制，让驱动将接收到的数据包，或者说sk_buff，转交给内核网络子系统。一般称这两个API为legacy和NAPI，这二者的区别为前者是中断驱动的，而后者是中断与轮询机制相结合的。二者的接收入口分别为`netif_rx`以及`netif_receive_skb`。无论哪种情况下，网卡驱动都会自行选择一个API，并创建sk_buff，填入数据，然后通过选择的API将填好数据的sk_buff提交给内核（目前基本上都是用NAPI）。

也就是说，网卡驱动拥有提交sk_buff的自由。一个常见的例子就是网卡的混杂模式，该模式下网卡可以接收到链路中发送给所有地址的数据包，而不是仅仅接收自己绑定IP地址的数据包。这个模式就需要网卡驱动的相关配合。

对于以太网卡驱动，内核提供给其一个比较重要的helper函数就是`eth_type_trans`，该函数用于直接根据ethernet链路层报文header中的字段确定packet类型，并填充到`sk_buffer`的protocol字段中，同时对于组播包一个比较重要的细节就是该函数也根据报文链路地址设置设置`skb->pkt_type`字段，即一个包的类型。

```c
__be16 eth_type_trans(struct sk_buff *skb, struct net_device *dev)
{
        struct ethhdr *eth;
        unsigned char *rawp;

        skb->dev = dev;
        skb_reset_mac_header(skb);
        skb_pull(skb, ETH_HLEN);
        eth = eth_hdr(skb);

        if (unlikely(is_multicast_ether_addr(eth->h_dest))) {
                if (!compare_ether_addr_64bits(eth->h_dest, dev->broadcast))
                        skb->pkt_type = PACKET_BROADCAST;
                else
                        skb->pkt_type = PACKET_MULTICAST;
        }

        /*
         *      This ALLMULTI check should be redundant by 1.4
         *      so don't forget to remove it.
         *
         *      Seems, you forgot to remove it. All silly devices
         *      seems to set IFF_PROMISC.
         */

        else if (1 /*dev->flags&IFF_PROMISC */ ) {
                if (unlikely(compare_ether_addr_64bits(eth->h_dest, dev->dev_addr)))
                        skb->pkt_type = PACKET_OTHERHOST;
        }
```

可以看到`eth_trans_type`函数根据比较sk_buff接收网卡的MAC地址与接收包的目标MAC地址，确定该pkt_type的值。如果是广播地址则设置为`PACKET_BROADCAST`，组播则为`PACKET_MULTICAST`，而目的地非本网卡MAC地址的包则为`PACKET_OTHERHOST`类型（即网卡混杂模式下接收到的链路上目的地不是自己MAC的包）。注意可以从后面看到IP层根本不处理`PACKET_OTHERHOST`类型的包，而是直接丢弃，这个后面继续分析。

无论是legacy还是NAPI，其对驱动发送的sk_buff的处理都是相同的（甚至说legacy相关API在后期已经构建于NAPI之上）。这里主要分析`__netif_recieve_skb`函数，因为netif_rx也是实现在它之上。从内核的角度来看，驱动在其方便的时候调用了这个函数，即用调用这个函数的方式将自己准备好的sk_buff提交给内核。因此，内核首先要帮助处理和建立sk_buff的一些状态，即将sk_buff从链路层切换到网络层，简单来说就是设置一些字段，然后调整一下sk_buff中的数据指针，使其指向网络层的数据，具体细节可以研究一下`sk_buff`的实现。

从这里会碰到内核网络协议栈实现的一个典型pattern，即根据类型对包的分流处理，这也与网络协议的设计相符合。在网络多层设计中，一般情况下，位于位于底层的协议在封装上层协议的数据包时，都会在header中留有一个字段用户确定上层协议类型。例如，以太网的frame header中就留有字段确定该frame中传输的数据是ARP包还是IP包。内核对于该种设计的处理有一个特定的pattern，即定义一个通用的`type + handler`的数据结构，然后将其串起来，根据`type`寻找特定的handler。特化到L3（网络）层，该数据结构就是`struct packet_type`:

```c
struct packet_type {
        __be16                  type;   /* This is really htons(ether_type). */
        struct net_device       *dev;   /* NULL is wildcarded here           */
        int                     (*func) (struct sk_buff *,
                                         struct net_device *,
                                         struct packet_type *,
                                         struct net_device *);
        struct sk_buff          *(*gso_segment)(struct sk_buff *skb,
                                                int features);
        int                     (*gso_send_check)(struct sk_buff *skb);
        struct sk_buff          **(*gro_receive)(struct sk_buff **head,
                                               struct sk_buff *skb);
        int                     (*gro_complete)(struct sk_buff *skb);
        void                    *af_packet_priv;
        struct list_head        list;
};
```

一般情况下，我们只需要定义`type`和`func`回调函数。对于IPv4来说，定义如下：

```c
static struct packet_type ip_packet_type __read_mostly = {
        .type = cpu_to_be16(ETH_P_IP),
        .func = ip_rcv,
};
```

回到`__netif_receive_skb`函数的分析，前面提到`packet_type`是因为该函数对sk_buff的处理多处到了该结构体。除了前面提到的处理，函数还需要经过以下几个过程，这里简要提及：

1. ptype_all
2. handle_bridge
3. handle_macvlan
4. handle_openvswitch
5. ptype_base

其中ptype_all是内核注册的一组packet_type，使得用户态可以在这里截获特定的sk_buff，如tcpdump等工具就是通过这种方式实现的。中间几个函数的处理目前略过。函数最后从系统注册的`ptype_base`列表中找到`skb->protocol`对应的handler，进而进行处理，对于IPv4协议就是前面看到的ip_packet_type，对应的回调函数为`ip_rcv`函数。

## ip_rcv

`ip_rcv`位于`net/ipv4/ip_input.c`中，是IPv4协议输入包的入口。函数开头直接检测该包是否属于本机，也就是说整个IPv4协议栈不负责处理网卡混杂模式下接收到的其他额外的包（即目标地址非本机网卡MAC的包）：

```c
/* When the interface is in promisc. mode, drop all the crap
         * that it receives, do not try to analyse it.
         */
        if (skb->pkt_type == PACKET_OTHERHOST)
                goto drop;
```

随后函数增加IPv4收包计数器。函数对该包进行简单合法性检查后，将其扔进netfilter的`PRE_ROUTING`入口：

```c
return NF_HOOK(PF_INET, NF_INET_PRE_ROUTING, skb, dev, NULL,
                       ip_rcv_finish);
```

这里如果没有iptable规则将包偷走，那么则会传入到下一级`ip_rcv_finish`函数。

## ip_rcv_finish

这个函数是IPv4包处理的中心，由于我们这个sk_buff是从网卡驱动来的，所以它是没有路由缓存的，而函数开头对该情况进行的处理，创建了一个路由表缓存条目。注意2.6.32内核比较古老，路由子系统还是使用的旧的基于路由缓存的实现，新版本内核已经改为基于字典树的路由表实现。

```c
        /*
         *      Initialise the virtual path cache for the packet. It describes
         *      how the packet travels inside Linux networking.
         */
        if (skb_dst(skb) == NULL) {
                int err = ip_route_input(skb, iph->daddr, iph->saddr, iph->tos,
                                         skb->dev);
                if (unlikely(err)) {
                        if (err == -EHOSTUNREACH)
                                IP_INC_STATS_BH(dev_net(skb->dev),
                                                IPSTATS_MIB_INADDRERRORS);
                        else if (err == -ENETUNREACH)
                                IP_INC_STATS_BH(dev_net(skb->dev),
                                                IPSTATS_MIB_INNOROUTES);
                        goto drop;
                }
        }
```

事实上这个初始化路由表缓存条目的行为直接沟通了路由子系统，为该包决定好了去处，后续的任务仅仅是再次检查合法性，更新广播包与组播包的计数器：

```c
        if (iph->ihl > 5 && ip_rcv_options(skb))
                goto drop;

        rt = skb_rtable(skb);
        if (rt->rt_type == RTN_MULTICAST) {
                IP_UPD_PO_STATS_BH(dev_net(rt->u.dst.dev), IPSTATS_MIB_INMCAST,
                                skb->len);
        } else if (rt->rt_type == RTN_BROADCAST)
                IP_UPD_PO_STATS_BH(dev_net(rt->u.dst.dev), IPSTATS_MIB_INBCAST,
                                skb->len);
```

最后将这个sk_buff扔到路由子系统中：

```c
      return dst_input(skb);
```

## 路由子系统相关

前面看到，由于我们扔给`ip_rcv_finish`的包是从网卡驱动直接创建的，所以没有路由缓存条目，需要通过路由子系统给其一个相关联的条目，该操作由`ip_route_input`函数实现，函数位于`net/ipv4/route.c`中。

首先明确函数的目的，即为什么要给一个sk_buff关联一个路由表缓存。IPv4协议中，IP包的路由是非常复杂的，尤其是涉及到具体实现的时候。当我们将一个IP包交给内核的时候，内核需要根据包中记录的相关信息（如源地址，目标地址，IPv4 options）确定该包是否合法，是否需要额外处理，以及其具体去处，比如：

- FORWARD，即传递操作。默认情况下，内核不进行forward操作，否则，内核将自己不应该接收的包通过路由表的设置发送给下一级接收者
- LOCAL DELIVERY，本地分发。内核认为该包是发给自己所运行的这台机器的，将会对其进行分发操作。其本质就是根据包的信息，将其分发给运行在操作系统下的应用程序。

对于我们正在分析的情况，这一套还是比较简单的，因为没有涉及复杂的路由处理逻辑。2.6.32内核的路由缓存实现原理比较简单，但是细节繁杂，其主要思路是通过一个哈希表保存多个条目，起到快速查找的作用，因为路由表性能直接影响内核对于IP包的处理速度。可以看到哈希函数的参数如下：

```c
     hash = rt_hash(daddr, saddr, iif, rt_genid(net));
```

也就是IP包的源地址，目标地址，以及网络接口编号（索引）。函数进行处理时，首先检查路由表中是否已有匹配于该包的路由表项，简单来说，就是根据源地址，目标地址以及网络接口编号算出一个hash值，然后在路由表的哈希表中查找该哈希值是否有对应的表项，最后确定该表项是否适用于该包，如果适用，则将表项与sk_buff进行关联，此时一次查找完成，这个sk_buff就找到了去处。

```c
        tos &= IPTOS_RT_MASK;
        hash = rt_hash(daddr, saddr, iif, rt_genid(net));

        rcu_read_lock();
        for (rth = rcu_dereference(rt_hash_table[hash].chain); rth;
             rth = rcu_dereference(rth->u.dst.rt_next)) {
                if (((rth->fl.fl4_dst ^ daddr) |
                     (rth->fl.fl4_src ^ saddr) |
                     (rth->fl.iif ^ iif) |
                     rth->fl.oif |
                     (rth->fl.fl4_tos ^ tos)) == 0 &&
                    rth->fl.mark == skb->mark &&
                    net_eq(dev_net(rth->u.dst.dev), net) &&
                    !rt_is_expired(rth)) {
                        dst_use(&rth->u.dst, jiffies);
                        RT_CACHE_STAT_INC(in_hit);
                        rcu_read_unlock();
                        skb_dst_set(skb, &rth->u.dst);
                        return 0;
                }
                RT_CACHE_STAT_INC(in_hlist_search);
        }
        rcu_read_unlock();
```

上面原理讲的这么简单，但是内核实际的实现是比较凌乱的。首先明确内核路由表使用了RCU实现，这是因为路由子系统现实中是具有一定容错率的，允许对路由表的更新滞后生效，这完美满足了RCU的使用场景。也就是说，已经拿到的路由表缓存不一定严格反映路由表的更改，有一个非常微小的窗口，使部分包看到的路由表仍然是旧的。

对于没有找到对应路由表缓存的情况，函数需要创建路由表缓存项。对于目标地址为组播地址的sk_buff，函数将该工作委托给`ip_route_input_mc`函数，在此之前，需要进行一个检查。

```c
       if (ipv4_is_multicast(daddr)) {
                struct in_device *in_dev;

                rcu_read_lock();
                if ((in_dev = __in_dev_get_rcu(dev)) != NULL) {
                        int our = ip_check_mc(in_dev, daddr, saddr,
                                ip_hdr(skb)->protocol);
                        if (our
#ifdef CONFIG_IP_MROUTE
                            || (!ipv4_is_local_multicast(daddr) &&
                                IN_DEV_MFORWARD(in_dev))
#endif
                            ) {
                                rcu_read_unlock();
                                return ip_route_input_mc(skb, daddr, saddr,
                                                         tos, dev, our);
                        }
                }
                rcu_read_unlock();
                return -EINVAL;
        }
```

`ip_check_mc`函数检查接收到该sk_buff的网卡是否注册到了该组播组中，如果没有则拒绝创建对应缓存表项，本质上就是拒绝接收。`ip_route_input_mc`函数的本质就是进行一系列合法性检查，并创建对应的路由表项，可以注意到：

```c
        if (our) {
                rth->u.dst.input= ip_local_deliver;
                rth->rt_flags |= RTCF_LOCAL;
        }
```

由于我们是link-local地址，所以our为1，因此路由表项指定的分发函数为`ip_local_deliver`。

从前面的`ip_rcv_finish`可以看到，函数最后调用`dst_input`进行分发，其本质就是调用该回调函数进行分发操作：

```c
/* Input packet from network to transport.  */
static inline int dst_input(struct sk_buff *skb)
{
        return skb_dst(skb)->input(skb);
}
```

## ip_local_deliver

函数如下：

```c
/*
 *      Deliver IP Packets to the higher protocol layers.
 */
int ip_local_deliver(struct sk_buff *skb)
{
        /*
         *      Reassemble IP fragments.
         */

        if (ip_hdr(skb)->frag_off & htons(IP_MF | IP_OFFSET)) {
                if (ip_defrag(skb, IP_DEFRAG_LOCAL_DELIVER))
                        return 0;
        }

        return NF_HOOK(PF_INET, NF_INET_LOCAL_IN, skb, skb->dev, NULL,
                       ip_local_deliver_finish);
}
```

即如果IP包是分片的，则需要调用`ip_defrag`函数进行合并处理，我们这里假定是部分片的。因此这里碰到了netfilter的另一个钩子`INET_LOCAL_IN`，如果包没有被规则拐走，则交由`ip_local_deliver_finish`处理。在该函数中，通过检测IP头中的protocol字段，即可确定是UDP协议报文，进一步交由UDP协议进行处理：

```c
                        ret = ipprot->handler(skb);
```

```c
static const struct net_protocol udp_protocol = {
        .handler =      udp_rcv,
        .err_handler =  udp_err,
        .no_policy =    1,
        .netns_ok =     1,
};
```

