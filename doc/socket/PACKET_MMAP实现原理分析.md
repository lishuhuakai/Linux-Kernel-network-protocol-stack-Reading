在上一篇文章中，已经提到了在libpcap-1.0.0中已经增加了部分平台的PACKET_MMAP支持，就一直想写一篇关于PACKET_MMAP实现的文章。

PACKET_MMAP实现的代码都在net/packet/af_packet.c中，其中一些宏、结构等定义在include/linux/if_packet.h中。

## PACKET_MMAP的实现原理

PACKET_MMAP在内核空间中分配一块内核缓冲区，然后用户空间程序调用mmap映射到用户空间。将接收到的skb拷贝到那块内核缓冲区中，这样用户空间的程序就可以直接读到捕获的数据包了。

如果没有开启PACKET_MMAP，只是依靠AF_PACKET非常的低效。它有缓冲区的限制，并且每捕获一个报文就需要一个系统调用，如果为了获得packet的时间戳就需要两个系统调用了（获得时间戳还需要一个系统调用，libpcap就是这样做的）。

PACKET_MMAP非常高效，它提供一个映射到用户空间的大小可配置的环形缓冲区。这种方式，读取报文只需要等待报文就可以了，大部分情况下不需要系统调用（其实poll也是一次系统调用）。通过内核空间和用户空间共享的缓冲区还可以起到减少数据拷贝的作用。

当然为了提高捕获的性能，不仅仅只是PACKET_MMAP。如果你在捕获一个高速网络中的数据，你应该检查NIC是否支持一些中断负载缓和机制或者是NAPI，确定开启这些措施。

PACKET_MMAP减少了系统调用，不用recvmsg就可以读取到捕获的报文，相比原始套接字+recvfrom的方式，减少了一次拷贝和一次系统调用。

PACKET_MMAP的使用：

从系统调用的角度来看待如何使用PACKET_MMAP，可以从[libpcap底层实现变化的分析](http://blog.chinaunix.net/u/12592/showart_2207614.html)中strace的分析中看出来：

```shell
[setup]:

	socket()	------> 捕获socket的创建

	setsockopt()	------> 环形缓冲区的分配

	mmap()	------> 将分配的缓冲区映射到用户空间中

[capture]

	poll()	------> 等待新进的报文

[shutdown]

	close	------> 销毁捕获socket和所有相关的资源
```
接下来的这些内容，翻译自Document/networking/packet_mmap.txt，但是根据需要有所删减

1. socket的创建和销毁如下，与不使用PACKET_MMAP是一样的:
```c
int fd;
fd = socket(PF_PACKET, mode, htons(ETH_P_ALL))
```
如果mode设置为SOCK_RAW，链路层信息也会被捕获；如果mode设置为SOCK_DGRAM，那么对应接口的链路层信息捕获就不会被支持，内核会提供一个虚假的头部。

销毁socket和释放相关的资源，可以直接调用一个简单的close()系统调用就可以了。

2. PACKET_MMAP的设置

用户空间设置PACKET_MMAP只需要下面的系统调用就可以了:
```c
setsockopt(fd, SOL_PACKET, PACKET_RX_RING, (void *)&req, sizeof(req));
```

上面系统调用中最重要的就是req参数，其定义如下：
```c
   struct tpacket_req
   {
     unsigned int   tp_block_size;  /* Minimal size of contiguous block */
     unsigned int   tp_block_nr;   /* Number of blocks */
     unsigned int   tp_frame_size;  /* Size of frame */
     unsigned int   tp_frame_nr;   /* Total number of frames */
   };
```
这个结构被定义在include/linux/if_packet.h中，在捕获进程中建立一个不可交换(unswappable)内存的环形缓冲区。通过被映射的内存，捕获进程就可以无需系统调用就可以访问到捕获的报文和报文相关的元信息，像时间戳等。

捕获frame被划分为多个block，每个block是一块物理上连续的内存区域，有tp_block_size/tp_frame_size个frame。block的总数是tp_block_nr。其实tp_frame_nr是多余的，因为我们可以计算出来：
```shell
   frames_per_block = tp_block_size/tp_frame_size
```
实际上，packet_set_ring检查下面的条件是否正确：
```shell
   frames_per_block * tp_block_nr == tp_frame_nr
```
下面我们可以一个例子：
```c
   tp_block_size= 4096
   tp_frame_size= 2048
   tp_block_nr  = 4
   tp_frame_nr  = 8
```

得到的缓冲区结构应该如下：
```c
     block #1         block #2     
+---------+---------+   +---------+---------+   
| frame 1 | frame 2 |   | frame 3 | frame 4 |   
+---------+---------+   +---------+---------+   

     block #3         block #4
+---------+---------+   +---------+---------+
| frame 5 | frame 6 |   | frame 7 | frame 8 |
+---------+---------+   +---------+---------+
```
每个frame必须放在一个block中，每个block保存整数个frame，也就是说一个frame不能跨越两个block。

3. 映射和使用环形缓冲区

在用户空间映射缓冲区可以直接使用方便的mmap()函数。虽然那些buffer在内核中是由多个block组成的，但是映射后它们在用户空间中是连续的。
```shell
   mmap(0, size, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
```
如果tp_frame_size能够整除tp_block_size，那么每个frame都将会是tp_frame_size长度；如果不是，那么tp_block_size/tp_frame_size个frame之间就会有空隙，那是因为一个frame不会跨越两个block。

在每一个frame的开始有一个status域(可以查看struct tpacket_hdr)，这些status定义在include/linux/if_packet.h中：
```c
#define TP_STATUS_KERNEL	0
#define TP_STATUS_USER		1
#define TP_STATUS_COPY		2
#define TP_STATUS_LOSING	4
#define TP_STATUS_CSUMNOTREADY	8
```
这里我们只关心前两个，TP_STATUS_KERNEL和TP_STATUS_USER。如果status为TP_STATUS_KERNEL，表示这个frame可以被kernel使用，实际上就是可以将存放捕获的数据存放在这个frame中；如果status为TP_STATUS_USER，表示这个frame可以被用户空间使用，实际上就是这个frame中存放的是捕获的数据，应该读出来。

内核将所有的frame的status初始化为TP_STATUS_KERNEL，当内核接受到一个报文的时候，就选一个frame，把报文放进去，然后更新它的状态为TP_STATUS_USER（这里假设不出现其他问题，也就是忽略其他的状态）。用户程序读取报文，一旦报文被读取，用户必须将frame对应的status设置为0，也就是设置为TP_STATUS_KERNEL，这样内核就可以再次使用这个frame了。

用户可以通过poll或者是其他机制来检测环形缓冲区中的新报文：
```c
   struct pollfd pfd;
   pfd.fd = fd;
   pfd.revents = 0;
   pfd.events = POLLIN|POLLRDNORM|POLLERR;

   if (status == TP_STATUS_KERNEL)
​     retval = poll(&pfd, 1, timeout);
```
先检查状态值，然后再对frame进行轮循，这样就可以避免竞争条件了（如果status已经是TP_STATUS_USER了，也就是说在调用poll前已经有了一个报文到达。这个时候再调用poll，并且之后不再有新报文到达的话，那么之前的那个报文就无法读取了，这就是所谓的竞争条件）。

在libpcap-1.0.0中是这么设计的：

pcap-linux.c中的pcap_read_linux_mmap:
```c
//如果frame的状态在poll前已经为TP_STATUS_USER了，说明已经在poll前已经有一个数据包被捕获了，如果poll后不再有数据包被捕获，那么这个报文不会被处理，这就是所谓的竞争情况。

if ((handle->md.timeout >= 0) &&
    !pcap_get_ring_frame(handle, TP_STATUS_USER)) { 
        struct pollfd pollinfo;
        int ret; 	
        pollinfo.fd = handle->fd; pollinfo.events = POLLIN;
        do { 	/* poll() requires a negative timeout to wait forever */ 	ret = poll(&pollinfo, 1, (handle->md.timeout > 0)? 	 			handle->md.timeout: -1);
              if ((ret < 0) && (errno != EINTR)) {
                  return -1;
              }
              ...... 
        } while (ret < 0); }

//依次处理捕获的报文
while ((pkts < max_packets) || (max_packets <= 0)) {
     ......
     //如果frame的状态为TP_STATUS_USER就读出数据frame，否则就退出循环。注意这里是环形缓冲区 
     h.raw = pcap_get_ring_frame(handle, TP_STATUS_USER);
     if (!h.raw)
          break;
          ...... 	
       /* pass the packet to the user */ 
       pkts++; 
       callback(user, &pcaphdr, bp); 
       handle->md.packets_read++;
skip:
      /* next packet */ 
      switch (handle->md.tp_version) { 
      case TPACKET_V1:
               //重新设置frame的状态为TP_STATUS_KERNEL
               h.h1->tp_status = TP_STATUS_KERNEL;
               break;
       ...... 
       }
}
```
## PACKET_MMAP源码分析

这里就不再像上一篇文章中那样大段大段的粘贴代码了，只是分析一下流程就可以了，需要的同学可以对照着follow一下代码;-)

数据包进入网卡后，创建了skb，之后会进入软中断处理，调用netif_receive_skb，并调用dev_add_pack注册的一些func。很明显可以看到af_packet.c中的tpacket_rcv和packet_rcv就是我们找的目标。

tpacket_rcv是PACKET_MMAP的实现，packet_rcv是普通AF_PACKET的实现。

tpacket_rcv:

1. 进行些必要的检查
2. 运行run_filter，通过BPF过滤中我们设定条件的报文，得到需要捕获的长度snaplen
3. 在ring buffer中查找TP_STATUS_KERNEL的frame
4. 计算macoff、netoff等信息
5. 如果snaplen+macoff>frame_size，并且skb为共享的，那么就拷贝skb	<一般不会拷贝>
```c
if(skb_shared(skb))
	skb_clone()
```
6. 将数据从skb拷贝到kernel Buffer中	<拷贝>
```c
skb_copy_bits(skb, 0,  h.raw+macoff, snaplen);
```
7. 设置拷贝到frame中报文的头部信息，包括时间戳、长度、状态等信息
8. flush_dcache_page()把某页在data cache中的内容同步回内存。
x86应该不用这个，这个多为RISC架构用的
9. 调用sk_data_ready，通知睡眠进程，调用poll
10. 应用层在调用poll返回后，就会调用pcap_get_ring_frame获得一个frame进行处理。这里面没有拷贝也没有系统调用。

开销分析：1次拷贝+1个系统调用(poll)

packet_rcv:

1. 进行些必要的检查
2. 运行run_filter，通过BPF过滤中我们设定条件的报文，得到需要捕获的长度snaplen
3. 如果skb为共享的，那么就拷贝skb	<一般都会拷贝>
```c
if(skb_shared(skb))
	skb_clone()
```
4. 设置拷贝到frame中报文的头部信息，包括时间戳、长度、状态等信息
5. 将skb追加到socket的sk_receive_queue中
6. 调用sk_data_ready，通知睡眠进程有数据到达
7. 应用层睡眠在recvfrom上，当数据到达，socket可读的时候，调用packet_recvmsg，其中将数据拷贝到用户空间。	<拷贝>
```c
	skb_recv_datagram()从sk_receive_queue中获得skb
	skb_copy_datagram_iovec()将数据拷贝到用户空间
```
开销分析：2次拷贝+1个系统调用(recvfrom)

*注:*其实在packet处理之前还有一次拷贝过程，在NIC Driver中，创建一个skb，然后NIC把数据DMA到skb的data中。

在另外一些ZeroCopy实现中(例如)，如果不希望NIC数据进入协议栈的话，就可以不用考虑skb_shared的问题了，直接将数据从NIC Driver中DMA到制定的一块内存，然后使用mmap到用户空间。这样就只有一次DMA过程，当然DMA也是一种拷贝;-)

关于数据包如何从NIC Driver到packet_rcv/tpacket_rcv，数据包经过中断、软中断等处理，进入netif_receive_skb中对skb进行分发，就会调用dev_add_pack注册的packet_type->func。

关于数据包接受的流程可以阅读一些关于NAPI等相关的资料：

关于如何从sk_data_ready到用户进程的poll，可以阅读：
http://simohayha.javaeye.com/blog/559506