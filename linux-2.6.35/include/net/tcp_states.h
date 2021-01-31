/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		Definitions for the TCP protocol sk_state field.
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */
#ifndef _LINUX_TCP_STATES_H
#define _LINUX_TCP_STATES_H

enum {
	TCP_ESTABLISHED = 1,
	TCP_SYN_SENT,
	TCP_SYN_RECV,
	TCP_FIN_WAIT1,
	TCP_FIN_WAIT2,
	TCP_TIME_WAIT,
	TCP_CLOSE,
	TCP_CLOSE_WAIT,
	TCP_LAST_ACK,
	TCP_LISTEN,
	TCP_CLOSING,	/* Now a valid state */

	TCP_MAX_STATES	/* Leave at the end! */
};

#define TCP_STATE_MASK	0xF

#define TCP_ACTION_FIN	(1 << 7)

enum {
	TCPF_ESTABLISHED = (1 << 1), /* 连接状态 */
	TCPF_SYN_SENT	 = (1 << 2), /* 处于close状态的客户端发送了一个syn,进入syn_send状态 */
	TCPF_SYN_RECV	 = (1 << 3), /* 处于listen状态的服务端接收到syn,发送了syn,ack进入syn_rcvd状态 */
	TCPF_FIN_WAIT1	 = (1 << 4), /* 处于established状态的一端发送了FIN,进入fin_wait_1状态*/
	TCPF_FIN_WAIT2	 = (1 << 5), /* 处于fin_wait_1状态的一端收到了ack,进入fin_wait_2状态 */
	TCPF_TIME_WAIT	 = (1 << 6), /* 处于fin_wiat_2状态的一端接收了对端的fin,发送了ack,进入time_wait状态 */
	TCPF_CLOSE	 = (1 << 7), /* 处于time_wait状态的一端,精力两倍time_wait超时后,进入close状态
	                          * 处于closing状态的一端,收到了ack,直接进入close状态 */
	TCPF_CLOSE_WAIT	 = (1 << 8), /* 处于establisehd状态的一端,接收到了FIN,发送了ack,进入close_wait状态 */
	TCPF_LAST_ACK	 = (1 << 9), /* 处于close_wait状态的一端,发送了FIN,进入last_ack状态 */
	TCPF_LISTEN	 = (1 << 10), /* 处于close状态的服务端,被动打开,进入listen状态 */
	TCPF_CLOSING	 = (1 << 11) /* 处于fin_wait_1状态的一端,收到了对端的fin,发送ack,进入closing状态 */
};

#endif	/* _LINUX_TCP_STATES_H */
