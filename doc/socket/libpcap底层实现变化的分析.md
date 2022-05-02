一个很偶然的机会，我看到一个关于Monkey系列开发包的PPT《》。其中讲到了将libevent和libpcap结合起来用。libevent和libpcap都是有自己的loop，要将两个结合起来写代码的话，必须砍掉一个libpcap的loop，将libpcap的fd就绪事件整合到libevent中，这样就可以使用libevent的loop来搞了。

直接从jscan中摘出一段代码来：

```c
ctx.p = pcap_open_live(intf, 1500, (ctx.flags == SCAN_FLAGS_PASSIVE), 500, ebuff);
event_init();
ctx.tv.tv_sec = 0;
ctx.tv.tv_usec = 500;
p_fd = pcap_fileno(ctx.p);
event_set(&ctx.recv_ev, p_fd, EV_READ, _recv, (void *) &ctx);
event_add(&ctx.recv_ev, &ctx.tv);
```



看了这个后，想了解一下libpcap的具体实现，本来猜测是原始套接字，用strace去看了一下。

## strace分析

拿之前那个《[试用pypcap](http://blog.chinaunix.net/u/12592/showart_2079182.html)》中写的那个C代码，进行了一下:

```shell
execve("./t-1.1.0", ["./t-1.1.0", "eth0", "172.16.11.11", "./DHT_nodes.sav"], [/* 52 vars */]) = 0
brk(0)                                  = 0x8a2e000
access("/etc/ld.so.nohwcap", F_OK)      = -1 ENOENT (No such file or directory)
mmap2(NULL, 8192, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0xb7fdf000
access("/etc/ld.so.preload", R_OK)      = -1 ENOENT (No such file or directory)
open("/etc/ld.so.cache", O_RDONLY)      = 3
fstat64(3, {st_mode=S_IFREG|0644, st_size=112216, ...}) = 0
mmap2(NULL, 112216, PROT_READ, MAP_PRIVATE, 3, 0) = 0xb7fc3000
close(3)                                = 0
access("/etc/ld.so.nohwcap", F_OK)      = -1 ENOENT (No such file or directory)
open("/usr/lib/libpcap.so.0.8", O_RDONLY) = 3
read(3, "\177ELF\1\1\1\0\0\0\0\0\0\0\0\0\3\0\3\0\1\0\0\0000-\0\0004\0\0\0"..., 512) = 512
fstat64(3, {st_mode=S_IFREG|0644, st_size=182240, ...}) = 0
mmap2(NULL, 187136, PROT_READ|PROT_EXEC, MAP_PRIVATE|MAP_DENYWRITE, 3, 0) = 0xb7f95000
mmap2(0xb7fc1000, 8192, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x2b) = 0xb7fc1000
close(3)                                = 0
access("/etc/ld.so.nohwcap", F_OK)      = -1 ENOENT (No such file or directory)
open("/lib/i686/cmov/libc.so.6", O_RDONLY) = 3
read(3, "\177ELF\1\1\1\0\0\0\0\0\0\0\0\0\3\0\3\0\1\0\0\0\260l\1\0004\0\0\0"..., 512) = 512
fstat64(3, {st_mode=S_IFREG|0755, st_size=1331684, ...}) = 0
mmap2(NULL, 1337704, PROT_READ|PROT_EXEC, MAP_PRIVATE|MAP_DENYWRITE, 3, 0) = 0xb7e4e000
mmap2(0xb7f8f000, 12288, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x141) = 0xb7f8f000
mmap2(0xb7f92000, 10600, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_ANONYMOUS, -1, 0) = 0xb7f92000
close(3)                                = 0
mmap2(NULL, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0xb7e4d000
mmap2(NULL, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0xb7e4c000
set_thread_area({entry_number:-1 -> 6, base_addr:0xb7e4db10, limit:1048575, seg_32bit:1, contents:0, read_exec_only:0, limit_in_pages:1, seg_not_present:0, useable:1}) = 0
mprotect(0xb7f8f000, 8192, PROT_READ)   = 0
mprotect(0xb7ffe000, 4096, PROT_READ)   = 0
munmap(0xb7fc3000, 112216)              = 0
brk(0)                                  = 0x8a2e000
brk(0x8a4f000)                          = 0x8a4f000
open("./DHT_nodes.sav", O_WRONLY|O_CREAT|O_TRUNC, 0666) = 3
socket(PF_INET, SOCK_DGRAM, IPPROTO_IP) = 4
ioctl(4, SIOCGIFADDR, {ifr_name="eth0", ???}) = -1 EADDRNOTAVAIL (Cannot assign requested address)
close(4)                                = 0
fstat64(1, {st_mode=S_IFCHR|0620, st_rdev=makedev(136, 4), ...}) = 0
mmap2(NULL, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0xb7fde000
write(1, "Device: eth0\n", 13Device: eth0
)          = 13
write(1, "Filter: ip dst 172.16.11.11 and "..., 36Filter: ip dst 172.16.11.11 and udp
) = 36
socket(PF_PACKET, SOCK_RAW, 768)        = 4
ioctl(4, SIOCGIFINDEX, {ifr_name="lo", ifr_index=1}) = 0
ioctl(4, SIOCGIFHWADDR, {ifr_name="eth0", ifr_hwaddr=00:e0:60:b0:a3:f6}) = 0
ioctl(4, SIOCGIFINDEX, {ifr_name="eth0", ifr_index=2}) = 0
bind(4, {sa_family=AF_PACKET, proto=0x03, if2, pkttype=PACKET_HOST, addr(0)={0, }, 20) = 0
getsockopt(4, SOL_SOCKET, SO_ERROR, [0], [4]) = 0
setsockopt(4, SOL_PACKET, PACKET_ADD_MEMBERSHIP, "\2\0\0\0\1\0\0\0\0\0\0\0\0\0\0\0", 16) = 0
setsockopt(4, SOL_PACKET, 0x8 /* PACKET_??? */, [1], 4) = 0
getsockopt(4, SOL_PACKET, 0xb /* PACKET_??? */, [28], [4]) = 0
setsockopt(4, SOL_PACKET, 0xa /* PACKET_??? */, [1], 4) = 0
setsockopt(4, SOL_PACKET, 0xc /* PACKET_??? */, [4], 4) = 0
setsockopt(4, SOL_PACKET, PACKET_RX_RING, "\0@\0\0\376\0\0\0@ \0\0\376\0\0\0", 16) = 0
mmap2(NULL, 4161536, PROT_READ|PROT_WRITE, MAP_SHARED, 4, 0) = 0xb7a54000
setsockopt(4, SOL_SOCKET, SO_ATTACH_FILTER, "\1\0\0\0\204!\374\267", 8) = 0
fcntl64(4, F_GETFL)                     = 0x2 (flags O_RDWR)
fcntl64(4, F_SETFL, O_RDWR|O_NONBLOCK)  = 0
recv(4, 0xbfb8183f, 1, MSG_TRUNC)       = -1 EAGAIN (Resource temporarily unavailable)
fcntl64(4, F_SETFL, O_RDWR)             = 0
setsockopt(4, SOL_SOCKET, SO_ATTACH_FILTER, "\16\0\374\267\240\350\242\10", 8) = 0
poll([{fd=4, events=POLLIN}], 1, -1^C
```

## libpcap-0.9.8源码跟踪

正好手头有一份libpcap-0.9.8的源代码，我就决定follow一下代码，看是不是如strace那样的，但是很失望，虽然我对自己的源码阅读能力很有信心，但是没有找到有调用poll的地方;-(

```c
//pcap.c中的pcap_loop:
/*
 * XXX keep reading until we get something
 * (or an error occurs)
 */
do {
	n = p->read_op(p, cnt, callback, user);
} while (n == 0);

//pcap-linux.c中的pcap_open_live:
handle->read_op = pcap_read_linux;

//pcap-linux.c中的pcap_read_linux:
static int
pcap_read_linux(pcap_t *handle, int max_packets, pcap_handler callback, u_char *user)
{
	/*
	 * Currently, on Linux only one packet is delivered per read,
	 * so we don't loop.
	 */
	return pcap_read_packet(handle, callback, user);
}

//pcap-linux.c中的pcap_read_packet:
do {
	/*
	 * Has "pcap_breakloop()" been called?
	 */
	if (handle->break_loop) {
		/*
		 * Yes - clear the flag that indicates that it
		 * has, and return -2 as an indication that we
		 * were told to break out of the loop.
		 */
		handle->break_loop = 0;
		return -2;
	}
	fromlen = sizeof(from);
	packet_len = recvfrom(
		handle->fd, bp + offset,
		handle->bufsize - offset, MSG_TRUNC,
		(struct sockaddr *) &from, &fromlen);
} while (packet_len == -1 && errno == EINTR);
```

看来libpcap-0.9.8没有想象中那样调用poll，同时查看了系统中的libpcap的版本是libpcap-1.0.0。strace一下用libpcap-0.9.8编译的那个程序：

```shell
execve("./t-0.9.8", ["./t-0.9.8", "eth0", "172.16.11.11", "./DHT_nodes.sav"], [/* 52 vars */]) = 0
brk(0)                                  = 0x84e7000
access("/etc/ld.so.nohwcap", F_OK)      = -1 ENOENT (No such file or directory)
mmap2(NULL, 8192, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0xb7ef9000
access("/etc/ld.so.preload", R_OK)      = -1 ENOENT (No such file or directory)
open("/etc/ld.so.cache", O_RDONLY)      = 3
fstat64(3, {st_mode=S_IFREG|0644, st_size=112216, ...}) = 0
mmap2(NULL, 112216, PROT_READ, MAP_PRIVATE, 3, 0) = 0xb7edd000
close(3)                                = 0
access("/etc/ld.so.nohwcap", F_OK)      = -1 ENOENT (No such file or directory)
open("/lib/i686/cmov/libc.so.6", O_RDONLY) = 3
read(3, "\177ELF\1\1\1\0\0\0\0\0\0\0\0\0\3\0\3\0\1\0\0\0\260l\1\0004\0\0\0"..., 512) = 512
fstat64(3, {st_mode=S_IFREG|0755, st_size=1331684, ...}) = 0
mmap2(NULL, 1337704, PROT_READ|PROT_EXEC, MAP_PRIVATE|MAP_DENYWRITE, 3, 0) = 0xb7d96000
mmap2(0xb7ed7000, 12288, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x141) = 0xb7ed7000
mmap2(0xb7eda000, 10600, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_ANONYMOUS, -1, 0) = 0xb7eda000
close(3)                                = 0
mmap2(NULL, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0xb7d95000
set_thread_area({entry_number:-1 -> 6, base_addr:0xb7d958d0, limit:1048575, seg_32bit:1, contents:0, read_exec_only:0, limit_in_pages:1, seg_not_present:0, useable:1}) = 0
mprotect(0xb7ed7000, 8192, PROT_READ)   = 0
mprotect(0xb7f18000, 4096, PROT_READ)   = 0
munmap(0xb7edd000, 112216)              = 0
brk(0)                                  = 0x84e7000
brk(0x8508000)                          = 0x8508000
open("./DHT_nodes.sav", O_WRONLY|O_CREAT|O_TRUNC, 0666) = 3
socket(PF_INET, SOCK_DGRAM, IPPROTO_IP) = 4
ioctl(4, SIOCGIFADDR, {ifr_name="eth0", ???}) = -1 EADDRNOTAVAIL (Cannot assign requested address)
close(4)                                = 0
fstat64(1, {st_mode=S_IFCHR|0620, st_rdev=makedev(136, 4), ...}) = 0
mmap2(NULL, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0xb7ef8000
write(1, "Device: eth0\n", 13Device: eth0
)          = 13
write(1, "Filter: ip dst 172.16.11.11 and "..., 36Filter: ip dst 172.16.11.11 and udp
) = 36
socket(PF_PACKET, SOCK_RAW, 768)        = 4
ioctl(4, SIOCGIFINDEX, {ifr_name="lo", ifr_index=1}) = 0
ioctl(4, SIOCGIFHWADDR, {ifr_name="eth0", ifr_hwaddr=00:e0:60:b0:a3:f6}) = 0
ioctl(4, SIOCGIFINDEX, {ifr_name="eth0", ifr_index=2}) = 0
bind(4, {sa_family=AF_PACKET, proto=0x03, if2, pkttype=PACKET_HOST, addr(0)={0, }, 20) = 0
getsockopt(4, SOL_SOCKET, SO_ERROR, [0], [4]) = 0
setsockopt(4, SOL_PACKET, PACKET_ADD_MEMBERSHIP, "\2\0\0\0\1\0\0\0\0\0\0\0\0\0\0\0", 16) = 0
setsockopt(4, SOL_SOCKET, SO_ATTACH_FILTER, "\1\0\0\0\250\265\6\10", 8) = 0
fcntl64(4, F_GETFL)                     = 0x2 (flags O_RDWR)
fcntl64(4, F_SETFL, O_RDWR|O_NONBLOCK)  = 0
recv(4, 0xbfebc55b, 1, MSG_TRUNC)       = -1 EAGAIN (Resource temporarily unavailable)
fcntl64(4, F_SETFL, O_RDWR)             = 0
setsockopt(4, SOL_SOCKET, SO_ATTACH_FILTER, "\n\0\4\10H\224N\10", 8) = 0
recvfrom(4, ^C




```

注：查看libpcap的changelog发现
Mon.    October 27, 2008.  ken@netfunctional.ca.  Summary for 1.0.0 libpcap release
	Support for zerocopy BPF on platforms that support it

恩，这样来看，是在libpcap-1.0.0中引入了zerocopy BPF，那么这个zerocopy BPF又是什么呢？

## PACKET_MMAP

查看两个版本libpcap编译的程序的strace的差异，除了poll之外，对于setsockopt还有一个差异：

```shell
setsockopt(4, SOL_PACKET, PACKET_RX_RING, "\0@\0\0\376\0\0\0@ \0\0\376\0\0\0", 16) = 0
mmap2(NULL, 4161536, PROT_READ|PROT_WRITE, MAP_SHARED, 4, 0) = 0xb7a54000
```
恩，我们从字面上来猜猜看：

setsockopt设置socket的PACKET_RX_RING选项，至于这个选项是做什么的，只能够猜测是一个接收环形缓冲区相关的东西，具体其他的要看其他的参数了。

mmap2将一段内核空间地址映射到用户空间，这样用户空间就可以直接操作内核缓冲区中的数据了，至于内核缓冲区中的数据如何来的，就是所谓的zerocopy BPF底层实现的了。

查阅资料后，我们知道这个zerocopy叫做PACKET_MMAP，之前也叫做PACKET_RING，查看kernel的config文件的话是：

CONFIG_PACKET_MMAP=y

以前的时候有一个专门的PACKET_MMAP版本的libpcap，但是在libpcap-1.0.0中已经增加了部分平台的PACKET_MMAP/PACKET_RING支持。之前那个PACKET_MMAP版本的libpcap在:

## llibpcap-1.0.0源码跟踪

*pcap.c中的pcap_loop:*

```c
/*
 \* XXX keep reading until we get something
 \* (or an error occurs)
 */
do {
	n = p->read_op(p, cnt, callback, user);
} while (n == 0);
```
*pcap.c中的pcap_open_live:*
```c
	p = pcap_create(source, errbuf);
     ......
	status = pcap_activate(p);
```
*pcap-linux.c中的pcap_create:*
```c
	handle = pcap_create_common(device, ebuf);
	if (handle == NULL)
		return NULL;
	handle->activate_op = pcap_activate_linux;
```
*pcap-linux.c中的pcap_create_common:*
```c
	p->read_op = (read_op_t)pcap_not_initialized;
```
*pcap.c中的pcap_active:*
```c
int
pcap_activate(pcap_t *p)
{
	int status;
	status = p->activate_op(p);
	if (status >= 0)
		p->activated = 1;
	return (status);
}
```
到这里实际上调用了pcap_create中设置的active_op，即pcap_active_linux了。

*pcap-linux.c中的pcap_active_linux:*
```c
	handle->read_op = pcap_read_linux;
	......
	/*
	 * Current Linux kernels use the protocol family PF_PACKET to
	 * allow direct access to all packets on the network while
	 * older kernels had a special socket type SOCK_PACKET to
	 * implement this feature.
	 * While this old implementation is kind of obsolete we need
	 * to be compatible with older kernels for a while so we are
	 * trying both methods with the newer method preferred.
	 */
	if ((status = activate_new(handle)) == 1) {
		activate_ok = 1;
		/*
		 * Try to use memory-mapped access.
		 */
		if (activate_mmap(handle) == 1)
			return 0;	/* we succeeded; nothing more to do */
	}
	else if (status == 0) {
		/* Non-fatal error; try old way */
		if ((status = activate_old(handle)) == 1)
			activate_ok = 1;
	}
```

关于active_new具体的就不分析了，只不过是创建了一个使用PF_PACKET的socket而已。

*pcap-linux.c中的active_new:*

```c
/*
 * Try to open a packet socket using the new kernel PF_PACKET interface.
 * Returns 1 on success, 0 on an error that means the new interface isn't
 * present (so the old SOCK_PACKET interface should be tried), and a
 * PCAP_ERROR_ value on an error that means that the old mechanism won't
 * work either (so it shouldn't be tried).
 */
static int
activate_new(pcap_t *handle)
```
pcap-linux.c中的active_mmap:
```c
static int 
activate_mmap(pcap_t *handle)
{
#ifdef HAVE_PACKET_RING
	int ret;

	if (handle->opt.buffer_size == 0) {
		/* by default request 2M for the ring buffer */
		handle->opt.buffer_size = 2*1024*1024;
	}
	ret = prepare_tpacket_socket(handle);
	if (ret == 0)
		return ret;
	ret = create_ring(handle);
	if (ret == 0)
		return ret;

	/* override some defaults and inherit the other fields from
	 * activate_new
	 * handle->offset is used to get the current position into the rx ring 
	 * handle->cc is used to store the ring size */
	handle->read_op = pcap_read_linux_mmap;
	handle->cleanup_op = pcap_cleanup_linux_mmap;
	handle->setfilter_op = pcap_setfilter_linux_mmap;
	handle->setnonblock_op = pcap_setnonblock_mmap;
	handle->getnonblock_op = pcap_getnonblock_mmap;
	handle->selectable_fd = handle->fd;
	return 1;
#else /* HAVE_PACKET_RING */
	return 0;
#endif /* HAVE_PACKET_RING */
}
```


到这里，终于找到了pcap_loop运行的read_op了;-)

*pcap-linux.c中的pcap_read_linux_mmap:*

```c
ret = poll(&pollinfo, 1, (handle->md.timeout > 0)? handle->md.timeout: -1);
......
h.raw = pcap_get_ring_frame(handle, TP_STATUS_USER);
......
callback(user, &pcaphdr, bp);
```

当poll检测socket可读，也就是环形缓冲区中有数据的时候，调用pcap_get_ring_frame获得数据，进行些头部处理，然后调用callback进行处理。

至此，整个libpcap-1.0.0的调用流程已经分析结束了，基本上核心内容在active_mmap和后续的调用函数，例如在prepare_tpacket_socket和create_ring中实现的就是正如strace中看到的种种setsockopt。如果自己造轮子的话应该参考这一部分。