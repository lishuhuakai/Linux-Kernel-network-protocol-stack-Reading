/*
 *	Spanning tree protocol; generic parts
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
#include <linux/kernel.h>
#include <linux/rculist.h>

#include "br_private.h"
#include "br_private_stp.h"

/* since time values in bpdu are in jiffies and then scaled (1/256)
 * before sending, make sure that is at least one.
 */
#define MESSAGE_AGE_INCR	((HZ < 256) ? 1 : (HZ/256))

static const char *const br_port_state_names[] = {
	[BR_STATE_DISABLED] = "disabled",
	[BR_STATE_LISTENING] = "listening",
	[BR_STATE_LEARNING] = "learning",
	[BR_STATE_FORWARDING] = "forwarding",
	[BR_STATE_BLOCKING] = "blocking",
};

void br_log_state(const struct net_bridge_port *p)
{
	br_info(p->br, "port %u(%s) entering %s state\n",
		(unsigned) p->port_no, p->dev->name,
		br_port_state_names[p->state]);
}

/* called under bridge lock */
struct net_bridge_port *br_get_port(struct net_bridge *br, u16 port_no)
{
	struct net_bridge_port *p;

	list_for_each_entry_rcu(p, &br->port_list, list) {
		if (p->port_no == port_no)
			return p;
	}

	return NULL;
}

/* called under bridge lock */
/* 判断端口p是否应该被选举成为根端口
 * 在所有非根桥上的不同端口之间选举出一个到根桥最近的端口
 * @param p 待检测的端口
 * @param root_port 当前最优的端口
 * @return 返回1表示p比当前的root_port优秀
 */
static int br_should_become_root_port(const struct net_bridge_port *p,
				      u16 root_port)
{
	struct net_bridge *br;
	struct net_bridge_port *rp;
	int t;

	br = p->br;
	if (p->state == BR_STATE_DISABLED ||
	    br_is_designated_port(p))
		return 0;

	if (memcmp(&br->bridge_id, &p->designated_root, 8) <= 0) /* 自己比邻居的bid要小,说明端口p不可能成为根端口
	                                                           * */
		return 0;

	if (!root_port)
		return 1;

	rp = br_get_port(br, root_port);

	t = memcmp(&p->designated_root, &rp->designated_root, 8);
	if (t < 0)
		return 1;
	else if (t > 0)
		return 0;

	if (p->designated_cost + p->path_cost <
	    rp->designated_cost + rp->path_cost)
		return 1; /* p更加优秀 */
	else if (p->designated_cost + p->path_cost >
		 rp->designated_cost + rp->path_cost)
		return 0;
    /* 运行到了这里,说明同一个桥上,有两个以上的端口计算得到的开销一致,那么选择收到发送者BID最小的那个端口为根端口 */
	t = memcmp(&p->designated_bridge, &rp->designated_bridge, 8);
	if (t < 0)
		return 1;
	else if (t > 0)
		return 0;
    /* 如果运行到了这里,那就比较端口id */
	if (p->designated_port < rp->designated_port)
		return 1;
	else if (p->designated_port > rp->designated_port)
		return 0;

	if (p->port_id < rp->port_id)
		return 1;

	return 0;
}

/* called under bridge lock
 * 根端口选举
 */
static void br_root_selection(struct net_bridge *br)
{
	struct net_bridge_port *p;
	u16 root_port = 0;

	list_for_each_entry(p, &br->port_list, list) {
		if (br_should_become_root_port(p, root_port))
			root_port = p->port_no;

	}

	br->root_port = root_port;

	if (!root_port) { /* 没有根端口,表明是根桥 */
		br->designated_root = br->bridge_id;
		br->root_path_cost = 0;
	} else {
		p = br_get_port(br, root_port);
		br->designated_root = p->designated_root;
		br->root_path_cost = p->designated_cost + p->path_cost;
	}
}

/* called under bridge lock */
/* 变成根桥之后的相关事宜
 *
 */
void br_become_root_bridge(struct net_bridge *br)
{
	br->max_age = br->bridge_max_age;
	br->hello_time = br->bridge_hello_time;
	br->forward_delay = br->bridge_forward_delay;
	br_topology_change_detection(br);
	del_timer(&br->tcn_timer);

	if (br->dev->flags & IFF_UP) {
		br_config_bpdu_generation(br);
		mod_timer(&br->hello_timer, jiffies + br->hello_time);
	}
}

/* called under bridge lock */
/* 在指定的端口p上发送bpdu报文
 * @param p 待发送bpdu报文的端口
 */
void br_transmit_config(struct net_bridge_port *p)
{
	struct br_config_bpdu bpdu;
	struct net_bridge *br;


	if (timer_pending(&p->hold_timer)) {
		p->config_pending = 1;
		return;
	}

	br = p->br;

	bpdu.topology_change = br->topology_change;
	bpdu.topology_change_ack = p->topology_change_ack;
	bpdu.root = br->designated_root;
	bpdu.root_path_cost = br->root_path_cost; /* 到根桥的开销 */
	bpdu.bridge_id = br->bridge_id; /* 自己的bid */
	bpdu.port_id = p->port_id;
	if (br_is_root_bridge(br))
		bpdu.message_age = 0;
	else {
		struct net_bridge_port *root
			= br_get_port(br, br->root_port);
		bpdu.message_age = br->max_age
			- (root->message_age_timer.expires - jiffies)
			+ MESSAGE_AGE_INCR;
	}
	bpdu.max_age = br->max_age;
	bpdu.hello_time = br->hello_time;
	bpdu.forward_delay = br->forward_delay;

	if (bpdu.message_age < br->max_age) {
		br_send_config_bpdu(p, &bpdu);
		p->topology_change_ack = 0;
		p->config_pending = 0;
		mod_timer(&p->hold_timer,
			  round_jiffies(jiffies + BR_HOLD_TIME));
	}
}

/* called under bridge lock */
/* 记录下相关的配置信息 */
static inline void br_record_config_information(struct net_bridge_port *p,
						const struct br_config_bpdu *bpdu)
{
	p->designated_root = bpdu->root;
	p->designated_cost = bpdu->root_path_cost;
	p->designated_bridge = bpdu->bridge_id;
	p->designated_port = bpdu->port_id;

	mod_timer(&p->message_age_timer, jiffies
		  + (p->br->max_age - bpdu->message_age));
}

/* called under bridge lock */
static inline void br_record_config_timeout_values(struct net_bridge *br,
					    const struct br_config_bpdu *bpdu)
{
	br->max_age = bpdu->max_age;
	br->hello_time = bpdu->hello_time;
	br->forward_delay = bpdu->forward_delay;
	br->topology_change = bpdu->topology_change;
}

/* called under bridge lock */
void br_transmit_tcn(struct net_bridge *br)
{
	br_send_tcn_bpdu(br_get_port(br, br->root_port));
}

/* called under bridge lock */
/* 判断端口是否应该成为指定端口
 * 1. 某网段到根桥的路径开销最小
 * 2. 接收数据时发送方(也就是对端)的桥id最小
 * 3. 发送方端口id最小
 * @param p 待操作的端口
 * @return 1表示应当
 */
static int br_should_become_designated_port(const struct net_bridge_port *p)
{
	struct net_bridge *br;
	int t;

	br = p->br;
	if (br_is_designated_port(p))
		return 1;

	if (memcmp(&p->designated_root, &br->designated_root, 8)) /* 非根桥 */
		return 1;
    /*==1==*/
	if (br->root_path_cost < p->designated_cost)
		return 1;
	else if (br->root_path_cost > p->designated_cost)
		return 0;
    /*==2==*/
	t = memcmp(&br->bridge_id, &p->designated_bridge, 8);
	if (t < 0)
		return 1;
	else if (t > 0)
		return 0;

    /*==3==*/
	if (p->port_id < p->designated_port) /* 在选择指定端口时,两个端口的根路径开销和发送bpdu交换机的bid
	                                       * 都一致的情况下,比较端口的pid,pid较小的为指定端口 */
		return 1;

	return 0;
}

/* called under bridge lock */
/* 指定端口的选举
 *
 */
static void br_designated_port_selection(struct net_bridge *br)
{
	struct net_bridge_port *p;

	list_for_each_entry(p, &br->port_list, list) {
		if (p->state != BR_STATE_DISABLED &&
		    br_should_become_designated_port(p))
			br_become_designated_port(p);

	}
}

/* called under bridge lock */
/* 判断从对端接收到的报文是否比已经存储的消息更加优秀
 * @return 1表示需要进行更新
 */
static int br_supersedes_port_info(struct net_bridge_port *p, struct br_config_bpdu *bpdu)
{
	int t;

	t = memcmp(&bpdu->root, &p->designated_root, 8);
	if (t < 0) /* bpdu中的根桥的bid更小,需要更新 */
		return 1;
	else if (t > 0)
		return 0;
    /* 和原来记录的到根桥的开销相比,变小了 */
	if (bpdu->root_path_cost < p->designated_cost)
		return 1;
	else if (bpdu->root_path_cost > p->designated_cost)
		return 0;
    /* 运行到这里,说明对端和自己到根桥的开销一致 */

    /* 比较桥id和链路上指定桥id */
	t = memcmp(&bpdu->bridge_id, &p->designated_bridge, 8);
	if (t < 0)
		return 1;
	else if (t > 0)
		return 0;
    /* 比较桥id */
	if (memcmp(&bpdu->bridge_id, &p->br->bridge_id, 8))
		return 1;
    /* 比较端口id和本端记录的指定端口id */
	if (bpdu->port_id <= p->designated_port)
		return 1;

	return 0;
}

/* called under bridge lock */
static inline void br_topology_change_acknowledged(struct net_bridge *br)
{
	br->topology_change_detected = 0;
	del_timer(&br->tcn_timer);
}

/* called under bridge lock */
/* 拓扑发生了更改
 *
 */
void br_topology_change_detection(struct net_bridge *br)
{
	int isroot = br_is_root_bridge(br);

	if (br->stp_enabled != BR_KERNEL_STP)
		return;

	br_info(br, "topology change detected, %s\n",
		isroot ? "propagating" : "sending tcn bpdu");

	if (isroot) { /* 如果是根桥 */
		br->topology_change = 1;
		mod_timer(&br->topology_change_timer, jiffies
			  + br->bridge_forward_delay + br->bridge_max_age);
	} else if (!br->topology_change_detected) { /* 非根桥,则通过根端口向根桥转发tcn报文 */
		br_transmit_tcn(br);
		mod_timer(&br->tcn_timer, jiffies + br->bridge_hello_time);
	}

	br->topology_change_detected = 1;
}

/* called under bridge lock */
/* 产生bpdu报文
 *
 */
void br_config_bpdu_generation(struct net_bridge *br)
{
	struct net_bridge_port *p;

	list_for_each_entry(p, &br->port_list, list) {
		if (p->state != BR_STATE_DISABLED &&
		    br_is_designated_port(p))
			br_transmit_config(p);
	}
}

/* called under bridge lock */
static inline void br_reply(struct net_bridge_port *p)
{
	br_transmit_config(p);
}

/* called under bridge lock */
void br_configuration_update(struct net_bridge *br)
{
	br_root_selection(br);
	br_designated_port_selection(br);
}

/* called under bridge lock
 * 将端口设定为指定端口
 */
void br_become_designated_port(struct net_bridge_port *p)
{
	struct net_bridge *br;

	br = p->br;
	p->designated_root = br->designated_root;
	p->designated_cost = br->root_path_cost;
	p->designated_bridge = br->bridge_id;
	p->designated_port = p->port_id;
}


/* called under bridge lock */
static void br_make_blocking(struct net_bridge_port *p)
{
	if (p->state != BR_STATE_DISABLED &&
	    p->state != BR_STATE_BLOCKING) {
		if (p->state == BR_STATE_FORWARDING ||
		    p->state == BR_STATE_LEARNING)
			br_topology_change_detection(p->br);

		p->state = BR_STATE_BLOCKING;
		br_log_state(p);
		del_timer(&p->forward_delay_timer);
	}
}

/* called under bridge lock */
static void br_make_forwarding(struct net_bridge_port *p)
{
	struct net_bridge *br = p->br;

	if (p->state != BR_STATE_BLOCKING)
		return;

	if (br->forward_delay == 0) {
		p->state = BR_STATE_FORWARDING; /* 进入到forwarding状态 */
		br_topology_change_detection(br);
		del_timer(&p->forward_delay_timer);
	}
	else if (p->br->stp_enabled == BR_KERNEL_STP) /* 内核使用了stp协议 */
		p->state = BR_STATE_LISTENING;
	else
		p->state = BR_STATE_LEARNING;

	br_multicast_enable_port(p);

	br_log_state(p);

	if (br->forward_delay != 0)
		mod_timer(&p->forward_delay_timer, jiffies + br->forward_delay);
}

/* called under bridge lock */
/* 根据端口类型,执行相应的行为
 *
 */
void br_port_state_selection(struct net_bridge *br)
{
	struct net_bridge_port *p;

	/* Don't change port states if userspace is handling STP */
	if (br->stp_enabled == BR_USER_STP)
		return;

	list_for_each_entry(p, &br->port_list, list) {
		if (p->state != BR_STATE_DISABLED) {
			if (p->port_no == br->root_port) { /* 端口属于根端口 */
				p->config_pending = 0;
				p->topology_change_ack = 0;
				br_make_forwarding(p);
			} else if (br_is_designated_port(p)) {
				del_timer(&p->message_age_timer);
				br_make_forwarding(p);
			} else { /* 其他端口都需要阻塞掉 */
				p->config_pending = 0;
				p->topology_change_ack = 0;
				br_make_blocking(p);
			}
		}

	}
}

/* called under bridge lock */
/* 上游设备会使用flags字段中的tca标志位置1的配置bpdu报文发给下游设备
 * 告知下游设备停止发送TCN bpdu报文
 */
static inline void br_topology_change_acknowledge(struct net_bridge_port *p)
{
	p->topology_change_ack = 1;
	br_transmit_config(p);
}

/* called under bridge lock
 * 处理接收到的bpdu报文
 * @param p 接收到报文的端口
 * @param bpdu 接收到经过解析后的bpdu报文
 */
void br_received_config_bpdu(struct net_bridge_port *p, struct br_config_bpdu *bpdu)
{
	struct net_bridge *br;
	int was_root;

	br = p->br;
    /* 自己是根桥吗? */
	was_root = br_is_root_bridge(br);
    /* 用已有的信息和bpdu包中的信息做对比 */
	if (br_supersedes_port_info(p, bpdu)) {
        /* 用bpdu中的某些信息更新端口p中存储的信息,因为br_supersedes_port_info表明bpdu中的信息更加优秀 */
		br_record_config_information(p, bpdu);
        /* 信息的更新可能会导致角色的切换 */
		br_configuration_update(br);
        /* 设置端口的状态 */
		br_port_state_selection(br);

		if (!br_is_root_bridge(br) && was_root) { /* 由非根桥变为了根桥 */
			del_timer(&br->hello_timer);
            /* 需要发送tcn包进行通告 */
			if (br->topology_change_detected) {
				del_timer(&br->topology_change_timer);
				br_transmit_tcn(br);

				mod_timer(&br->tcn_timer,
					  jiffies + br->bridge_hello_time);
			}
		}

		if (p->port_no == br->root_port) { /* 根端口 */
			br_record_config_timeout_values(br, bpdu);
            /* 从根端口接收到的bpdu报文,向下游扩散 */
			br_config_bpdu_generation(br);
			if (bpdu->topology_change_ack) /* 一旦接收到了topo变化的ack报文,就停止发送tcn bpdu报文 */
				br_topology_change_acknowledged(br);
		}
	} else if (br_is_designated_port(p)) {
		br_reply(p);
	}
}

/* called under bridge lock */
void br_received_tcn_bpdu(struct net_bridge_port *p)
{
	if (br_is_designated_port(p)) { /* 只有指定端口处理TCN报文 */
		br_info(p->br, "port %u(%s) received tcn bpdu\n",
			(unsigned) p->port_no, p->dev->name);

		br_topology_change_detection(p->br);
        /* 上游设备会使用flags字段中的tca标志位置1的配置bpdu报文发给下游设备
         * 告知下游设备停止发送TCN bpdu报文
         */
		br_topology_change_acknowledge(p);
	}
}
