# Linux-Kernel-Reading

kernel版本为 2.6.35

协议栈部分的参考书籍是<< linux 内核源码剖析 -- tcp,ip实现 >>

其他方面的参考书籍有:
1. <<奔跑吧,linux内核基于LInux4.x内核源代码问题分析>> -- 内存部分讲解得比较清楚,linux 4.x和2.6.35区别不是很大.
2. <<深入linux内核架构>> -- 比较高屋建瓴的一本书,不怎么适合新手,但是适合反复阅读
3. <\<Understanding the Linux Virtual Memory Manager>> -- 书是好书,但是有些老了
4. <<深入理解linux内核>> -- 可以一读,版本有些老

我个人的工作其实并不涉及到内核的改动,只是稍稍涉及内核协议栈交换和转发,应用的性能优化,查core等,了解一些内核知识肯定是有很多好处的,当然,另外一方面,读这份源码也是为了找点事情做,让自己不再那么无聊.

如果你自己不做相关的工作,没有切身的体会,能将这份代码摸得一清二楚,我个人是不太相信的.但是其实也不需要完全理解所有的细节,有些东西,当做一个黑匣子就行了.

读内核源码,很大一部分来源于我自己的好奇心,大致会花半年的闲暇时间在这份代码之上.虽然我知道读完之后,不会有什么立竿见影的效果,但是希望自己读完之后,有足够的能力以及足够的信息,走出当前所面临的恶性循环.

不要再逆来顺受了,去别的地方看点别的风景.人生不应该是眼前这副模样.

# 读内核的一点建议

1. 尽量带着问题来读,不要漫无目的地从头读到尾,这样效率很差,可以的话,可以尝试跟着书本先过一遍.

2. 不要陷入细节,众所周知,linux内核有着将近无限的细节,一旦陷了进去,就很难爬出来了.

3. 反复读,读内核不是一件一劳永逸的事情,这玩意就像圣经一样,要天天读,日日读,读到深处,自然就品出了味道.

4. 要有大局观,不要追求面面俱到,这个没啥必要,咱一般不参与内核的开发,有一些东西,比如函数,当做一个黑盒子就行了,不用太过深入.

5. 多收集一下优秀的博文,大牛们的读核方法会非常有裨益.

6. 抓住数据结构,内核的所有代码,都是围绕数据结构来的.



# 接下来的阅读计划

- [x] 聚合口bonding,包括lacp协议
- [x] 组播相关
- [x] igmp
- [x] 网桥以及其中涉及的stp协议
- [x] 进程调度相关的代码
- [x] 信号相关的代码
- [x] proc文件系统
- [ ] tcp协议再次加深理解