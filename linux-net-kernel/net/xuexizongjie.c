/*
TSO，全称是TCP Segmentation Offload，我们知道通常以太网的MTU(除去14字节ETH头和4字节尾部校验值，如果加上ETH头和校验实际上是1518)是1500，除去TCP/IP的包头，TCP的MSS (Max Segment Size)大小是1460，通常情况下协议栈会对超过
1460的TCP payload进行segmentation，保证生成的IP包不超过MTU的大小，但是对于支持TSO/GSO的网卡而言，就没这个必要了，我们可以把最多64K大小的TCP payload
直接往下传给协议栈，此时IP层也不会进行segmentation，一直会传给网卡驱动，支持TSO/GSO的网卡会自己生成TCP/IP包头和帧头，这样可以offload很多协议栈上的
内存操作，checksum计算等原本靠CPU来做的工作都移给了网卡GSO是TSO的增强 http://lwn.net/Articles/188489/ ，GSO不只针对TCP，而是对任意协议，尽可能把
segmentation推后到交给网卡那一刻，此时会判断下网卡是否支持SG和GSO，如果不支持则在协议栈里做segmentation；如果支持则把payload直接发给网卡

TSO:效率的节省源于对大包只走一次协议栈，而不是多次.尽可能晚的推迟分段（segmentation), 最理想的是在网卡驱动里分段，在网卡驱动里把大包（super-packet)
拆开，组成SG list，或在一块预先分配好的内存中重组各段，然后交给网卡。tso功能只能对TCP有效，GSO是增强版本，对所有协议都有效。

参考:http://www.smithfox.com/?e=191
阻塞和非阻塞