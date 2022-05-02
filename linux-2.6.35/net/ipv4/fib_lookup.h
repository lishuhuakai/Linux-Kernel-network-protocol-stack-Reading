#ifndef _FIB_LOOKUP_H
#define _FIB_LOOKUP_H

#include <linux/types.h>
#include <linux/list.h>
#include <net/ip_fib.h>

/* fib_alias实例代表一条路由表项 */
struct fib_alias {
	struct list_head	fa_list;
	struct fib_info		*fa_info; /* 记录着如何处理与该路由相匹配的数据报的信息 */
	u8			fa_tos; /* 路由的服务类型比特位字段 */
    /* fa_type 常用值:
     * RTN_LOCAL 目的地址为本地接口
     * RTN_UNICAST 该路由是一条到单播的直连/非直连路由
     * RTN_MULTICAST 目的地址是一个多播地址
     * RTN_BROADCAST 目的地址是一个广播地址,匹配的输入报文以广播方式送往本地,匹配的输出报文以广播方式发送出去
     */
	u8			fa_type; /* 路由表项类型 */
	u8			fa_scope;
	u8			fa_state;
#ifdef CONFIG_IP_FIB_TRIE
	struct rcu_head		rcu;
#endif
};

#define FA_S_ACCESSED	0x01

/* Exported by fib_semantics.c */
extern int fib_semantic_match(struct list_head *head,
			      const struct flowi *flp,
			      struct fib_result *res, int prefixlen);
extern void fib_release_info(struct fib_info *);
extern struct fib_info *fib_create_info(struct fib_config *cfg);
extern int fib_nh_match(struct fib_config *cfg, struct fib_info *fi);
extern int fib_dump_info(struct sk_buff *skb, u32 pid, u32 seq, int event,
			 u32 tb_id, u8 type, u8 scope, __be32 dst,
			 int dst_len, u8 tos, struct fib_info *fi,
			 unsigned int);
extern void rtmsg_fib(int event, __be32 key, struct fib_alias *fa,
		      int dst_len, u32 tb_id, struct nl_info *info,
		      unsigned int nlm_flags);
extern struct fib_alias *fib_find_alias(struct list_head *fah,
					u8 tos, u32 prio);
extern int fib_detect_death(struct fib_info *fi, int order,
			    struct fib_info **last_resort,
			    int *last_idx, int dflt);

static inline void fib_result_assign(struct fib_result *res,
				     struct fib_info *fi)
{
	if (res->fi != NULL)
		fib_info_put(res->fi);
	res->fi = fi;
	if (fi != NULL)
		atomic_inc(&fi->fib_clntref);
}

#endif /* _FIB_LOOKUP_H */
