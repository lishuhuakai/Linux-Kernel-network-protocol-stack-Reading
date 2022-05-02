本文来自[http://blog.chinaunix.net/uid-20357359-id-1963685.html](http://blog.chinaunix.net/uid-20357359-id-1963685.html)
根据上一篇文章PACKET_MMAP实现原理分析中PACKET_MMAP使用一节，写了一个简单的演示程序。
```c
#include
#include
#include
#include
#include
#include
#include /* the L2 protocols */

void CallBackPacket(char *data)
{
    printf("Recv A Packet.\n");
}

int main()
{
    int fd = 0, ret = 0;
    char *buff = NULL;

    //fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    //可以使用ARP进行一下测试
    fd = socket(PF_PACKET, SOCK_DGRAM, htons (ETH_P_ARP));
    if(fd<0)
    {
        perror("socket");
        goto failed_2;
    }

//PACKET_VERSION和SO_BINDTODEVICE可以省略
#if 0
    const int tpacket_version = TPACKET_V1;
    /* set tpacket hdr version. */
    ret = setsockopt(fd, SOL_PACKET, PACKET_VERSION, &tpacket_version, sizeof (int));
    if(ret<0)
    {
        perror("setsockopt");
        goto failed_2;
    }

//#define NETDEV_NAME "wlan0"
#define NETDEV_NAME "eth0"
    /* bind to device. */
    ret = setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, NETDEV_NAME, sizeof (NETDEV_NAME));
    if(ret<0)
    {
        perror("setsockopt");
        goto failed_2;
    }
#endif

    struct tpacket_req req;
#define PER_PACKET_SIZE 2048
    const int BUFFER_SIZE = 1024*1024*16; //16MB的缓冲区
    req.tp_block_size = 4096;
    req.tp_block_nr = BUFFER_SIZE/req.tp_block_size;
    req.tp_frame_size = PER_PACKET_SIZE;
    req.tp_frame_nr = BUFFER_SIZE/req.tp_frame_size;

    ret = setsockopt(fd, SOL_PACKET, PACKET_RX_RING, (void *)&req, sizeof(req));
    if(ret<0)
    {
        perror("setsockopt");
        goto failed_2;
    }

    buff = (char *)mmap(0, BUFFER_SIZE, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
    if(buff == MAP_FAILED)
    {
        perror("mmap");
        goto failed_2;
    }

    int nIndex=0, i=0;
    while(1)
    {
        //这里在poll前先检查是否已经有报文被捕获了
        struct tpacket_hdr* pHead = (struct tpacket_hdr*)(buff+ nIndex*PER_PACKET_SIZE);
        //如果frame的状态已经为TP_STATUS_USER了，说明已经在poll前已经有一个数据包被捕获了，如果poll后不再有数据包被捕获，那么这个报文不会被处理，这就是所谓的竞争情况。
        if(pHead->tp_status == TP_STATUS_USER)
            goto process_packet;

        //poll检测报文捕获
        struct pollfd pfd;
        pfd.fd = fd;
        //pfd.events = POLLIN|POLLRDNORM|POLLERR;
        pfd.events = POLLIN;
        pfd.revents = 0;
        ret = poll(&pfd, 1, -1);
        if(ret<0)
        {
            perror("poll");
            goto failed_1;
        }

process_packet:
        //尽力的去处理环形缓冲区中的数据frame，直到没有数据frame了
        for(i=0; i
        {
            struct tpacket_hdr* pHead = (struct tpacket_hdr*)(buff+ nIndex*PER_PACKET_SIZE);

            //XXX: 由于frame都在一个环形缓冲区中，因此如果下一个frame中没有数据了，后面的frame也就没有frame了
            if(pHead->tp_status == TP_STATUS_KERNEL)
                break;

            //处理数据frame
            CallBackPacket((char*)pHead+pHead->tp_net);

            //重新设置frame的状态为TP_STATUS_KERNEL
            pHead->tp_len = 0;
            pHead->tp_status = TP_STATUS_KERNEL;

            //更新环形缓冲区的索引，指向下一个frame
            nIndex++;
            nIndex%=req.tp_frame_nr;
        }

    }

success:
    close(fd);
    munmap(buff, BUFFER_SIZE);
    return 0;

failed_1:
    munmap(buff, BUFFER_SIZE);
    
failed_2:
    close(fd);
    return -1;
}
```


注:没有加filter，感觉直接使用bpf巨麻烦，实际上可以直接使用libpcap的关于bpf的api，就像参考1中实现的那样。

参考：
http://hi.baidu.com/ah__fu/blog/item/8aadf895fad570007af48000.html