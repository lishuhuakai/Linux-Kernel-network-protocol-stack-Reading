# Linux-Kernel-network-protocol-stack-Reading

kernel版本为 2.6.35

参考书籍是<< linux 内核源码剖析 -- tcp,ip实现 >>

个人在[https://github.com/y123456yz/Reading-and-comprehense-linux-Kernel-network-protocol-stack](https://github.com/y123456yz/Reading-and-comprehense-linux-Kernel-network-protocol-stack)注释的基础上再次增加注释.

我个人的工作其实并不涉及到内核的改动,但是同样也涉及到交换和转发,读这份源码纯粹是自己找点事情做而已.

如果你自己不做相关的工作,没有切身的体会,能将这份代码摸得一清二楚,我个人是不太相信的.

我读这份代码也不是这个目的,我只是很好奇这些东西究竟是实现的而已,大致会花半年的闲暇时间在这份代码之上.虽然我知道读完之后,不会有什么立竿见影的效果,但是希望自己读完之后,有足够的能力走出当前的恶性循环.

不要再逆来顺受了,去别的地方看点别的风景.人生不应该是眼前这副模样.



# 接下来的阅读计划

- [x] 聚合口bonding,包括lacp协议
- [x] 组播相关
- [x] igmp
- [x] 网桥以及其中涉及的stp协议
- [ ] 进程调度相关的代码
- [ ] 信号相关的代码
- [ ] tcp协议再次加深理解