/*
 *  bootmem - A boot-time physical memory allocator and configurator
 *
 *  Copyright (C) 1999 Ingo Molnar
 *                1999 Kanoj Sarcar, SGI
 *                2008 Johannes Weiner
 *
 * Access to this subsystem has to be serialized externally (which is true
 * for the boot process anyway).
 */
#include <linux/init.h>
#include <linux/pfn.h>
#include <linux/slab.h>
#include <linux/bootmem.h>
#include <linux/module.h>
#include <linux/kmemleak.h>
#include <linux/range.h>

#include <asm/bug.h>
#include <asm/io.h>
#include <asm/processor.h>

#include "internal.h"

unsigned long max_low_pfn;
unsigned long min_low_pfn;
unsigned long max_pfn;

#ifdef CONFIG_CRASH_DUMP
/*
 * If we have booted due to a crash, max_pfn will be a very low value. We need
 * to know the amount of memory that the previous kernel used.
 */
unsigned long saved_max_pfn;
#endif

#ifndef CONFIG_NO_BOOTMEM
bootmem_data_t bootmem_node_data[MAX_NUMNODES] __initdata;

static struct list_head bdata_list __initdata = LIST_HEAD_INIT(bdata_list);

static int bootmem_debug;

static int __init bootmem_debug_setup(char *buf)
{
	bootmem_debug = 1;
	return 0;
}
early_param("bootmem_debug", bootmem_debug_setup);

#define bdebug(fmt, args...) ({				\
	if (unlikely(bootmem_debug))			\
		printk(KERN_INFO			\
			"bootmem::%s " fmt,		\
			__func__, ## args);		\
})

static unsigned long __init bootmap_bytes(unsigned long pages)
{
	unsigned long bytes = (pages + 7) / 8;

	return ALIGN(bytes, sizeof(long));
}

/**
 * bootmem_bootmap_pages - calculate bitmap size in pages
 * 计算位图大小,单位是页
 * @pages: number of pages the bitmap has to represent 页的数目
 */
unsigned long __init bootmem_bootmap_pages(unsigned long pages)
{
	unsigned long bytes = bootmap_bytes(pages);

	return PAGE_ALIGN(bytes) >> PAGE_SHIFT;
}

/*
 * link bdata in order
 * 将bdata按照顺序挂到链表中
 */
static void __init link_bootmem(bootmem_data_t *bdata)
{
	struct list_head *iter;

	list_for_each(iter, &bdata_list) {
		bootmem_data_t *ent;

		ent = list_entry(iter, bootmem_data_t, list);
		if (bdata->node_min_pfn < ent->node_min_pfn)
			break;
	}
	list_add_tail(&bdata->list, iter);
}

/*
 * Called once to set up the allocator itself.
 * 初始化某内存节点的bootmem
 * @param  bdata 待初始化的某节点的bootmem
 * @param mapstart 保存bootmem位图的页块的首页面pfn
 * @param start bootmem内存区的其实pfn
 * @param end bootmem内存区的截止pfn
 */
static unsigned long __init init_bootmem_core(bootmem_data_t *bdata,
	unsigned long mapstart, unsigned long start, unsigned long end)
{
	unsigned long mapsize;

	mminit_validate_memmodel_limits(&start, &end);
    /* node_bootmem_map 保存本节点bootmem位图的虚拟地址 */
	bdata->node_bootmem_map = phys_to_virt(PFN_PHYS(mapstart));
	bdata->node_min_pfn = start;
    /* 全局链表bdata_list保存所有内存节点的bootmem，并且按照pfn，即物理地址有序排列 */
	bdata->node_low_pfn = end;
	link_bootmem(bdata);
    /* 将start与end间（包括空洞）的每一页都初始化为保留的，即位图对应的比特位置1。
     * 对我的开发板而言，start为0，end为0x20000，位图也就对应0至512MB的内存。这是低端内存区，
     * 共128K个页面，也就需要128K个比特位，即16K个字节，从而Mapsize为0x4000，因此位图共占用了4个页面。
     */
	/*
	 * Initially all pages are reserved - setup_arch() has to
	 * register free RAM areas explicitly.
	 */
	mapsize = bootmap_bytes(end - start);
	memset(bdata->node_bootmem_map, 0xff, mapsize);

	bdebug("nid=%td start=%lx map=%lx end=%lx mapsize=%lx\n",
		bdata - bootmem_node_data, start, mapstart, end, mapsize);

	return mapsize;
}

/**
 * init_bootmem_node - register a node as boot memory
 * @pgdat: node to register
 * @freepfn: pfn where the bitmap for this node is to be placed
 *           放置位图的页帧
 * @startpfn: first pfn on the node 起始页帧
 * @endpfn: first pfn after the node
 *
 * Returns the number of bytes needed to hold the bitmap for this node.
 */
unsigned long __init init_bootmem_node(pg_data_t *pgdat, unsigned long freepfn,
				unsigned long startpfn, unsigned long endpfn)
{
	return init_bootmem_core(pgdat->bdata, freepfn, startpfn, endpfn);
}

/**
 * init_bootmem - register boot memory
 * @start: pfn where the bitmap is to be placed
 * @pages: number of available physical pages
 *
 * Returns the number of bytes needed to hold the bitmap.
 */
unsigned long __init init_bootmem(unsigned long start, unsigned long pages)
{
	max_low_pfn = pages;
	min_low_pfn = start;
	return init_bootmem_core(NODE_DATA(0)->bdata, start, 0, pages);
}
#endif
/*
 * free_bootmem_late - free bootmem pages directly to page allocator
 * @addr: starting address of the range
 * @size: size of the range in bytes
 *
 * This is only useful when the bootmem allocator has already been torn
 * down, but we are still initializing the system.  Pages are given directly
 * to the page allocator, no bootmem metadata is updated because it is gone.
 */
void __init free_bootmem_late(unsigned long addr, unsigned long size)
{
	unsigned long cursor, end;

	kmemleak_free_part(__va(addr), size);

	cursor = PFN_UP(addr);
	end = PFN_DOWN(addr + size);

	for (; cursor < end; cursor++) {
		__free_pages_bootmem(pfn_to_page(cursor), 0);
		totalram_pages++;
	}
}

#ifdef CONFIG_NO_BOOTMEM /* 在没有启用bootmem内存分配器的情况下 */

/* 将内存加入伙伴系统
 * @param start,end 起始页帧号
 */
static void __init __free_pages_memory(unsigned long start, unsigned long end)
{
	int i;
	unsigned long start_aligned, end_aligned;
	int order = ilog2(BITS_PER_LONG);

	start_aligned = (start + (BITS_PER_LONG - 1)) & ~(BITS_PER_LONG - 1);
	end_aligned = end & ~(BITS_PER_LONG - 1);

	if (end_aligned <= start_aligned) {
		for (i = start; i < end; i++) /* 一个页一个页的进行加入操作 */
			__free_pages_bootmem(pfn_to_page(i), 0); /* 这个函数很重要,将内存加入伙伴系统 */

		return;
	}

	for (i = start; i < start_aligned; i++)
		__free_pages_bootmem(pfn_to_page(i), 0);

	for (i = start_aligned; i < end_aligned; i += BITS_PER_LONG)
		__free_pages_bootmem(pfn_to_page(i), order);

	for (i = end_aligned; i < end; i++)
		__free_pages_bootmem(pfn_to_page(i), 0);
}

unsigned long __init free_all_memory_core_early(int nodeid)
{
	int i;
	u64 start, end;
	unsigned long count = 0;
	struct range *range = NULL;
	int nr_range;

	nr_range = get_free_all_memory_range(&range, nodeid);

	for (i = 0; i < nr_range; i++) {
		start = range[i].start;
		end = range[i].end;
		count += end - start;
		__free_pages_memory(start, end);
	}

	return count;
}
#else
/* 释放掉bootmem内存节点
 * 返回值是页帧的数目
 */
static unsigned long __init free_all_bootmem_core(bootmem_data_t *bdata)
{
	int aligned;
	struct page *page;
	unsigned long start, end, pages, count = 0;

	if (!bdata->node_bootmem_map)
		return 0;

	start = bdata->node_min_pfn;
	end = bdata->node_low_pfn;

	/*
	 * If the start is aligned to the machines wordsize, we might
	 * be able to free pages in bulks of that order.
	 */
	aligned = !(start & (BITS_PER_LONG - 1));

	bdebug("nid=%td start=%lx end=%lx aligned=%d\n",
		bdata - bootmem_node_data, start, end, aligned);

	while (start < end) {
		unsigned long *map, idx, vec;

		map = bdata->node_bootmem_map;
		idx = start - bdata->node_min_pfn;
		vec = ~map[idx / BITS_PER_LONG];

		if (aligned && vec == ~0UL && start + BITS_PER_LONG < end) {
			int order = ilog2(BITS_PER_LONG);

			__free_pages_bootmem(pfn_to_page(start), order);
			count += BITS_PER_LONG;
		} else {
			unsigned long off = 0;

			while (vec && off < BITS_PER_LONG) {
				if (vec & 1) {
					page = pfn_to_page(start + off);
					__free_pages_bootmem(page, 0);
					count++;
				}
				vec >>= 1;
				off++;
			}
		}
		start += BITS_PER_LONG;
	}

	page = virt_to_page(bdata->node_bootmem_map);
	pages = bdata->node_low_pfn - bdata->node_min_pfn;
	pages = bootmem_bootmap_pages(pages);
	count += pages;
	while (pages--)
		__free_pages_bootmem(page++, 0);

	bdebug("nid=%td released=%lx\n", bdata - bootmem_node_data, count);

	return count;
}
#endif

/**
 * free_all_bootmem_node - release a node's free pages to the buddy allocator
 * @pgdat: node to be released
 *
 * Returns the number of pages actually released.
 */
unsigned long __init free_all_bootmem_node(pg_data_t *pgdat)
{
	register_page_bootmem_info_node(pgdat);
#ifdef CONFIG_NO_BOOTMEM
	/* free_all_memory_core_early(MAX_NUMNODES) will be called later */
	return 0;
#else
	return free_all_bootmem_core(pgdat->bdata);
#endif
}

/**
 * free_all_bootmem - release free pages to the buddy allocator
 *
 * Returns the number of pages actually released.
 */
unsigned long __init free_all_bootmem(void)
{
#ifdef CONFIG_NO_BOOTMEM
	/*
	 * We need to use MAX_NUMNODES instead of NODE_DATA(0)->node_id
	 *  because in some case like Node0 doesnt have RAM installed
	 *  low ram will be on Node1
	 * Use MAX_NUMNODES will make sure all ranges in early_node_map[]
	 *  will be used instead of only Node0 related
	 */
	return free_all_memory_core_early(MAX_NUMNODES);
#else
	unsigned long total_pages = 0;
	bootmem_data_t *bdata;

	list_for_each_entry(bdata, &bdata_list, list)
		total_pages += free_all_bootmem_core(bdata);

	return total_pages;
#endif
}

#ifndef CONFIG_NO_BOOTMEM
static void __init __free(bootmem_data_t *bdata,
			unsigned long sidx, unsigned long eidx)
{
	unsigned long idx;

	bdebug("nid=%td start=%lx end=%lx\n", bdata - bootmem_node_data,
		sidx + bdata->node_min_pfn,
		eidx + bdata->node_min_pfn);

	if (bdata->hint_idx > sidx)
		bdata->hint_idx = sidx;

	for (idx = sidx; idx < eidx; idx++)
		if (!test_and_clear_bit(idx, bdata->node_bootmem_map))
			BUG();
}

static int __init __reserve(bootmem_data_t *bdata, unsigned long sidx,
			unsigned long eidx, int flags)
{
	unsigned long idx;
	int exclusive = flags & BOOTMEM_EXCLUSIVE;

	bdebug("nid=%td start=%lx end=%lx flags=%x\n",
		bdata - bootmem_node_data,
		sidx + bdata->node_min_pfn,
		eidx + bdata->node_min_pfn,
		flags);

	for (idx = sidx; idx < eidx; idx++) /* 一个bit位代表一个页 */
		if (test_and_set_bit(idx, bdata->node_bootmem_map)) {
			if (exclusive) {
				__free(bdata, sidx, idx);
				return -EBUSY;
			}
			bdebug("silent double reserve of PFN %lx\n",
				idx + bdata->node_min_pfn);
		}
	return 0;
}

static int __init mark_bootmem_node(bootmem_data_t *bdata,
				unsigned long start, unsigned long end,
				int reserve, int flags)
{
	unsigned long sidx, eidx;

	bdebug("nid=%td start=%lx end=%lx reserve=%d flags=%x\n",
		bdata - bootmem_node_data, start, end, reserve, flags);

	BUG_ON(start < bdata->node_min_pfn);
	BUG_ON(end > bdata->node_low_pfn);

	sidx = start - bdata->node_min_pfn;
	eidx = end - bdata->node_min_pfn;

	if (reserve)
		return __reserve(bdata, sidx, eidx, flags);
	else
		__free(bdata, sidx, eidx);
	return 0;
}

static int __init mark_bootmem(unsigned long start, unsigned long end,
				int reserve, int flags)
{
	unsigned long pos;
	bootmem_data_t *bdata;

	pos = start;
	list_for_each_entry(bdata, &bdata_list, list) {
		int err;
		unsigned long max;

		if (pos < bdata->node_min_pfn ||
		    pos >= bdata->node_low_pfn) {
			BUG_ON(pos != start);
			continue;
		}

		max = min(bdata->node_low_pfn, end);

		err = mark_bootmem_node(bdata, pos, max, reserve, flags);
		if (reserve && err) {
			mark_bootmem(start, pos, 0, 0);
			return err;
		}

		if (max == end)
			return 0;
		pos = bdata->node_low_pfn;
	}
	BUG();
}
#endif

/**
 * free_bootmem_node - mark a page range as usable
 * @pgdat: node the range resides on
 * @physaddr: starting address of the range
 * @size: size of the range in bytes
 *
 * Partial pages will be considered reserved and left as they are.
 *
 * The range must reside completely on the specified node.
 */
void __init free_bootmem_node(pg_data_t *pgdat, unsigned long physaddr,
			      unsigned long size)
{
#ifdef CONFIG_NO_BOOTMEM
	free_early(physaddr, physaddr + size);
#else
	unsigned long start, end;

	kmemleak_free_part(__va(physaddr), size);

	start = PFN_UP(physaddr);
	end = PFN_DOWN(physaddr + size);

	mark_bootmem_node(pgdat->bdata, start, end, 0, 0);
#endif
}

/**
 * free_bootmem - mark a page range as usable
 * @addr: starting address of the range
 * @size: size of the range in bytes
 *
 * Partial pages will be considered reserved and left as they are.
 *
 * The range must be contiguous but may span node boundaries.
 */
/* 释放一块内存给bootmem分配器
 * @param addr 待释放内存的物理地址
 * @param size 待释放的内存的大小
 */
void __init free_bootmem(unsigned long addr, unsigned long size)
{
#ifdef CONFIG_NO_BOOTMEM
	free_early(addr, addr + size);
#else
	unsigned long start, end;

	kmemleak_free_part(__va(addr), size);

	start = PFN_UP(addr);
	end = PFN_DOWN(addr + size);
    /* 将这部分空间对应的位图比特位清0 */
	mark_bootmem(start, end, 0, 0);
#endif
}

/**
 * reserve_bootmem_node - mark a page range as reserved
 * @pgdat: node the range resides on
 * @physaddr: starting address of the range
 * @size: size of the range in bytes
 * @flags: reservation flags (see linux/bootmem.h)
 *
 * Partial pages will be reserved.
 *
 * The range must reside completely on the specified node.
 */
int __init reserve_bootmem_node(pg_data_t *pgdat, unsigned long physaddr,
				 unsigned long size, int flags)
{
#ifdef CONFIG_NO_BOOTMEM
	panic("no bootmem");
	return 0;
#else
	unsigned long start, end;

	start = PFN_DOWN(physaddr);
	end = PFN_UP(physaddr + size);

	return mark_bootmem_node(pgdat->bdata, start, end, 1, flags);
#endif
}

/**
 * reserve_bootmem - mark a page range as usable
 * @addr: starting address of the range
 * @size: size of the range in bytes
 * @flags: reservation flags (see linux/bootmem.h)
 *
 * Partial pages will be reserved.
 *
 * The range must be contiguous but may span node boundaries.
 */
int __init reserve_bootmem(unsigned long addr, unsigned long size,
			    int flags)
{
#ifdef CONFIG_NO_BOOTMEM
	panic("no bootmem");
	return 0;
#else
	unsigned long start, end;

	start = PFN_DOWN(addr);
	end = PFN_UP(addr + size);

	return mark_bootmem(start, end, 1, flags);
#endif
}

#ifndef CONFIG_NO_BOOTMEM
/* 按照idx进行对齐 */
static unsigned long __init align_idx(struct bootmem_data *bdata,
				      unsigned long idx, unsigned long step)
{
	unsigned long base = bdata->node_min_pfn;

	/*
	 * Align the index with respect to the node start so that the
	 * combination of both satisfies the requested alignment.
	 */

	return ALIGN(base + idx, step) - base;
}

static unsigned long __init align_off(struct bootmem_data *bdata,
				      unsigned long off, unsigned long align)
{
	unsigned long base = PFN_PHYS(bdata->node_min_pfn);

	/* Same as align_idx for byte offsets */

	return ALIGN(base + off, align) - base;
}

/* bootmem分配器核心函数
 * @param bdata 某内存节点的bootmem
 * @param size 分配内存的大小
 * @param align 对齐大小
 * @param goal 限定范围的起始地址
 * @param limit 限定范围的截止地址
 */
static void * __init alloc_bootmem_core(struct bootmem_data *bdata,
					unsigned long size, unsigned long align,
					unsigned long goal, unsigned long limit)
{
	unsigned long fallback = 0;
	unsigned long min, max, start, sidx, midx, step;

	bdebug("nid=%td size=%lx [%lu pages] align=%lx goal=%lx limit=%lx\n",
		bdata - bootmem_node_data, size, PAGE_ALIGN(size) >> PAGE_SHIFT,
		align, goal, limit);

	BUG_ON(!size);
	BUG_ON(align & (align - 1));
    /* 起始地址+申请的内存大小>截止地址，参数错误,这里要求limit不为0 */
	BUG_ON(limit && goal + size > limit);

	if (!bdata->node_bootmem_map)
		return NULL;

	min = bdata->node_min_pfn;   /* min表示bootmem的起始pfn */
	max = bdata->node_low_pfn; /* max表示bootmem的截止pfn */

	goal >>= PAGE_SHIFT; /* 从哪个页开始分配 */
	limit >>= PAGE_SHIFT; /* 需要分配多少个页 */

	if (limit && max > limit)
		max = limit;
	if (max <= min)
		return NULL;
    /* step为扫描位图时，每次递增的页数／pfn偏移数。由对齐大小计算而来，
     * 不足一页时，step为1，表示每次递增一页
     */
	step = max(align >> PAGE_SHIFT, 1UL);

	if (goal && min < goal && goal < max) /* 参数指定的起始pfn更大，根据它计算起始pfn，并按申请的页数对齐*/
		start = ALIGN(goal, step);
	else
		start = ALIGN(min, step);
    /* 计算起始pfn与bootmem起始pfn的偏移,
     * 后面扫描位图时从这个sidx开始
     */
	sidx = start - bdata->node_min_pfn;
    /* 计算截止pfn与bootmem起始pfn的偏移。
     * 扫描的就是sidx至midx之间的这部分bootmem内存区 */
	midx = max - bdata->node_min_pfn;
    /* hint_idx表示优先扫描的偏移，如果大于sidx，则从hint_idx处开始扫描。
     * 何为优先扫描呢？由于分配是从低地址开始，显然下一次扫描时，从上一次
     * 分配的截止地址开始扫描成功率会更高。hint_idx之前的空间可能由于对齐的原因仍是空闲的。
     * 释放bootmem时会更新hint_idx的值，指向释放的位置。仅当优先扫描失败，
     * 才需要回过头来扫描以前分配过的区域。
     */
	if (bdata->hint_idx > sidx) {
		/*
		 * Handle the valid case of sidx being zero and still
		 * catch the fallback below.
		 */
		 /* fallback表示首次扫描是否优先扫描 */
		fallback = sidx + 1;
		sidx = align_idx(bdata, bdata->hint_idx, step);
	}

	while (1) {
		int merge;
		void *region;
		unsigned long eidx, i, start_off, end_off;
        /* 从位图中找到满足对齐要求的,为0的,连续的比特位 */
find_block:
        /* 从位图中找到下一个为0的比特位 */
		sidx = find_next_zero_bit(bdata->node_bootmem_map, midx, sidx); /* sidx以页为单位 */
         /* 将sidx按照申请的页数对齐，对齐后的比特位不一定是0 */
		sidx = align_idx(bdata, sidx, step);
         /* 计算结尾pfn */
		eidx = sidx + PFN_UP(size);
        /* 如果超出了截止pfn，整个位图扫描完毕，未找到符合条件的空闲内存区，跳出循环 */
		if (sidx >= midx || eidx > midx)
			break;

        /* 检查sidx和eidx之间的所有比特位是否全部为0 */
		for (i = sidx; i < eidx; i++)
			if (test_bit(i, bdata->node_bootmem_map)) {
                /* 某比特位为1,这段区间不符合条件,从下一个对齐偏移处继续                         扫描 */
				sidx = align_idx(bdata, i, step);
                /* 前面对齐采用的是入式对齐，如果是第一个比特位为1，即对齐余数为0，
                 * 没有入上去，需要加上step */
				if (sidx == i)
					sidx += step;
				goto find_block;
			}
        /* last_end_off表示上一次分配截止地址的偏移。如果其不是页面大小对齐的，
         * 说明该页中还有空闲的空间。并且如果其所在的页面就是扫描到的内存区的上一页，
         * 则可以利用该页的空闲空间。*/
		if (bdata->last_end_off & (PAGE_SIZE - 1) &&
				PFN_DOWN(bdata->last_end_off) + 1 == sidx)
		    /* start_off表示本次分配的内存区起始处的地址偏移，需要按照指定方式对齐 */
			start_off = align_off(bdata, bdata->last_end_off, align);
		else
            /* 否则的话，就是从新的页面开始分配了，直接通过pfn偏移计算地址偏移 */
			start_off = PFN_PHYS(sidx);
        /* 如果使用了上一页的空闲空间，该页对应的比特位无需置1，已经置过了 */
		merge = PFN_DOWN(start_off) < sidx;
        /* 计算本次分配的截止地址偏移 */
		end_off = start_off + size; /* end_off以及start_off都是物理地址 */

		bdata->last_end_off = end_off;
        /* 计算本次分配的截止地址偏移 */
		bdata->hint_idx = PFN_UP(end_off);

		/*
		 * Reserve the area now:
		 */
		/* 将要分配出去的内存区对应的位图比特位置1，BOOTMEM_EXCLUSIVE表示此次分配是排它的 */
		if (__reserve(bdata, PFN_DOWN(start_off) + merge,
				PFN_UP(end_off), BOOTMEM_EXCLUSIVE))
			BUG();

		region = phys_to_virt(PFN_PHYS(bdata->node_min_pfn) +
				start_off);
        /* 将要分配出去的内存区清0 */
		memset(region, 0, size);
		/*
		 * The min_count is set to 0 so that bootmem allocated blocks
		 * are never reported as leaks.
		 */
		kmemleak_alloc(region, size, 0, 0);
		return region;
	}

	if (fallback) {
		sidx = align_idx(bdata, fallback - 1, step);
		fallback = 0;
		goto find_block;
	}

	return NULL;
}

static void * __init alloc_arch_preferred_bootmem(bootmem_data_t *bdata,
					unsigned long size, unsigned long align,
					unsigned long goal, unsigned long limit)
{
	if (WARN_ON_ONCE(slab_is_available()))
		return kzalloc(size, GFP_NOWAIT);

#ifdef CONFIG_HAVE_ARCH_BOOTMEM
	{
		bootmem_data_t *p_bdata;

		p_bdata = bootmem_arch_preferred_node(bdata, size, align,
							goal, limit);
		if (p_bdata)
			return alloc_bootmem_core(p_bdata, size, align,
							goal, limit);
	}
#endif
	return NULL;
}
#endif

static void * __init ___alloc_bootmem_nopanic(unsigned long size,
					unsigned long align,
					unsigned long goal,
					unsigned long limit)
{
#ifdef CONFIG_NO_BOOTMEM
	void *ptr;

	if (WARN_ON_ONCE(slab_is_available()))
		return kzalloc(size, GFP_NOWAIT);

restart:

	ptr = __alloc_memory_core_early(MAX_NUMNODES, size, align, goal, limit);

	if (ptr)
		return ptr;

	if (goal != 0) {
		goal = 0;
		goto restart;
	}

	return NULL;
#else
	bootmem_data_t *bdata;
	void *region;

restart:
    /* 从体系结构优先选择的节点分配bootmem */
	region = alloc_arch_preferred_bootmem(NULL, size, align, goal, limit);
	if (region)
		return region;
     /* 遍历bdata_list中的bootmem，UMA只有一个节点 */
	list_for_each_entry(bdata, &bdata_list, list) {
	    /* 此节点bootmem的截止pfn在参数指定的起始pfn之下，不符合要求，跳过 */
		if (goal && bdata->node_low_pfn <= PFN_DOWN(goal))
			continue;
        /* 此节点bootmem的起始pfn在参数指定的截止pfn之上，不符合要求，跳过 */
		if (limit && bdata->node_min_pfn >= PFN_DOWN(limit))
			break;
        /* first-fit算法 */
		region = alloc_bootmem_core(bdata, size, align, goal, limit);
		if (region)
			return region;
	}

	if (goal) {
		goal = 0;
		goto restart;
	}

	return NULL;
#endif
}

/**
 * __alloc_bootmem_nopanic - allocate boot memory without panicking
 * @size: size of the request in bytes
 * @align: alignment of the region
 * @goal: preferred starting address of the region
 *
 * The goal is dropped if it can not be satisfied and the allocation will
 * fall back to memory below @goal.
 *
 * Allocation may happen on any node in the system.
 *
 * Returns NULL on failure.
 */
void * __init __alloc_bootmem_nopanic(unsigned long size, unsigned long align,
					unsigned long goal)
{
	unsigned long limit = 0;

#ifdef CONFIG_NO_BOOTMEM
	limit = -1UL;
#endif

	return ___alloc_bootmem_nopanic(size, align, goal, limit);
}

static void * __init ___alloc_bootmem(unsigned long size, unsigned long align,
					unsigned long goal, unsigned long limit)
{
	void *mem = ___alloc_bootmem_nopanic(size, align, goal, limit);

	if (mem)
		return mem;
	/*
	 * Whoops, we cannot satisfy the allocation request.
	 */
	printk(KERN_ALERT "bootmem alloc of %lu bytes failed!\n", size);
	panic("Out of memory");
	return NULL;
}

/**
 * __alloc_bootmem - allocate boot memory
 * @size: size of the request in bytes
 * @align: alignment of the region
 * @goal: preferred starting address of the region
 *
 * The goal is dropped if it can not be satisfied and the allocation will
 * fall back to memory below @goal.
 *
 * Allocation may happen on any node in the system.
 *
 * The function panics if the request can not be satisfied.
 */
 /* 通过bootmem分配器分配内存
  * @param size 请求的大小
  * @param align 数据对齐大小
  * @param goal 指定了开始搜索适当空闲内存区的起始地址
  */
void * __init __alloc_bootmem(unsigned long size, unsigned long align,
			      unsigned long goal)
{
    /* limit为限定范围的截止地址,0表示没有限制 */
	unsigned long limit = 0;

#ifdef CONFIG_NO_BOOTMEM
	limit = -1UL;
#endif

	return ___alloc_bootmem(size, align, goal, limit);
}

#ifndef CONFIG_NO_BOOTMEM
static void * __init ___alloc_bootmem_node(bootmem_data_t *bdata,
				unsigned long size, unsigned long align,
				unsigned long goal, unsigned long limit)
{
	void *ptr;

	ptr = alloc_arch_preferred_bootmem(bdata, size, align, goal, limit);
	if (ptr)
		return ptr;

	ptr = alloc_bootmem_core(bdata, size, align, goal, limit);
	if (ptr)
		return ptr;

	return ___alloc_bootmem(size, align, goal, limit);
}
#endif

/**
 * __alloc_bootmem_node - allocate boot memory from a specific node
 * @pgdat: node to allocate from
 * @size: size of the request in bytes
 * @align: alignment of the region
 * @goal: preferred starting address of the region
 *
 * The goal is dropped if it can not be satisfied and the allocation will
 * fall back to memory below @goal.
 *
 * Allocation may fall back to any node in the system if the specified node
 * can not hold the requested memory.
 *
 * The function panics if the request can not be satisfied.
 */
void * __init __alloc_bootmem_node(pg_data_t *pgdat, unsigned long size,
				   unsigned long align, unsigned long goal)
{
	void *ptr;

	if (WARN_ON_ONCE(slab_is_available()))
		return kzalloc_node(size, GFP_NOWAIT, pgdat->node_id);

#ifdef CONFIG_NO_BOOTMEM
	ptr = __alloc_memory_core_early(pgdat->node_id, size, align,
					 goal, -1ULL);
	if (ptr)
		return ptr;

	ptr = __alloc_memory_core_early(MAX_NUMNODES, size, align,
					 goal, -1ULL);
#else
	ptr = ___alloc_bootmem_node(pgdat->bdata, size, align, goal, 0);
#endif

	return ptr;
}

void * __init __alloc_bootmem_node_high(pg_data_t *pgdat, unsigned long size,
				   unsigned long align, unsigned long goal)
{
#ifdef MAX_DMA32_PFN
	unsigned long end_pfn;

	if (WARN_ON_ONCE(slab_is_available()))
		return kzalloc_node(size, GFP_NOWAIT, pgdat->node_id);

	/* update goal according ...MAX_DMA32_PFN */
	end_pfn = pgdat->node_start_pfn + pgdat->node_spanned_pages;

	if (end_pfn > MAX_DMA32_PFN + (128 >> (20 - PAGE_SHIFT)) &&
	    (goal >> PAGE_SHIFT) < MAX_DMA32_PFN) {
		void *ptr;
		unsigned long new_goal;

		new_goal = MAX_DMA32_PFN << PAGE_SHIFT;
#ifdef CONFIG_NO_BOOTMEM
		ptr =  __alloc_memory_core_early(pgdat->node_id, size, align,
						 new_goal, -1ULL);
#else
		ptr = alloc_bootmem_core(pgdat->bdata, size, align,
						 new_goal, 0);
#endif
		if (ptr)
			return ptr;
	}
#endif

	return __alloc_bootmem_node(pgdat, size, align, goal);

}

#ifdef CONFIG_SPARSEMEM
/**
 * alloc_bootmem_section - allocate boot memory from a specific section
 * @size: size of the request in bytes
 * @section_nr: sparse map section to allocate from
 *
 * Return NULL on failure.
 */
void * __init alloc_bootmem_section(unsigned long size,
				    unsigned long section_nr)
{
#ifdef CONFIG_NO_BOOTMEM
	unsigned long pfn, goal, limit;

	pfn = section_nr_to_pfn(section_nr);
	goal = pfn << PAGE_SHIFT;
	limit = section_nr_to_pfn(section_nr + 1) << PAGE_SHIFT;

	return __alloc_memory_core_early(early_pfn_to_nid(pfn), size,
					 SMP_CACHE_BYTES, goal, limit);
#else
	bootmem_data_t *bdata;
	unsigned long pfn, goal, limit;

	pfn = section_nr_to_pfn(section_nr);
	goal = pfn << PAGE_SHIFT;
	limit = section_nr_to_pfn(section_nr + 1) << PAGE_SHIFT;
	bdata = &bootmem_node_data[early_pfn_to_nid(pfn)];

	return alloc_bootmem_core(bdata, size, SMP_CACHE_BYTES, goal, limit);
#endif
}
#endif

void * __init __alloc_bootmem_node_nopanic(pg_data_t *pgdat, unsigned long size,
				   unsigned long align, unsigned long goal)
{
	void *ptr;

	if (WARN_ON_ONCE(slab_is_available()))
		return kzalloc_node(size, GFP_NOWAIT, pgdat->node_id);

#ifdef CONFIG_NO_BOOTMEM
	ptr =  __alloc_memory_core_early(pgdat->node_id, size, align,
						 goal, -1ULL);
#else
	ptr = alloc_arch_preferred_bootmem(pgdat->bdata, size, align, goal, 0);
	if (ptr)
		return ptr;

	ptr = alloc_bootmem_core(pgdat->bdata, size, align, goal, 0);
#endif
	if (ptr)
		return ptr;

	return __alloc_bootmem_nopanic(size, align, goal);
}

#ifndef ARCH_LOW_ADDRESS_LIMIT
#define ARCH_LOW_ADDRESS_LIMIT	0xffffffffUL
#endif

/**
 * __alloc_bootmem_low - allocate low boot memory
 * @size: size of the request in bytes
 *        请求的内存大小,单位为字节
 * @align: alignment of the region
 * @goal: preferred starting address of the region
 *
 * The goal is dropped if it can not be satisfied and the allocation will
 * fall back to memory below @goal.
 *
 * Allocation may happen on any node in the system.
 *
 * The function panics if the request can not be satisfied.
 */
void * __init __alloc_bootmem_low(unsigned long size, unsigned long align,
				  unsigned long goal)
{
	return ___alloc_bootmem(size, align, goal, ARCH_LOW_ADDRESS_LIMIT);
}

/**
 * __alloc_bootmem_low_node - allocate low boot memory from a specific node
 * @pgdat: node to allocate from
 * @size: size of the request in bytes
 * @align: alignment of the region
 * @goal: preferred starting address of the region
 *
 * The goal is dropped if it can not be satisfied and the allocation will
 * fall back to memory below @goal.
 *
 * Allocation may fall back to any node in the system if the specified node
 * can not hold the requested memory.
 *
 * The function panics if the request can not be satisfied.
 */
void * __init __alloc_bootmem_low_node(pg_data_t *pgdat, unsigned long size,
				       unsigned long align, unsigned long goal)
{
	void *ptr;

	if (WARN_ON_ONCE(slab_is_available()))
		return kzalloc_node(size, GFP_NOWAIT, pgdat->node_id);

#ifdef CONFIG_NO_BOOTMEM
	ptr = __alloc_memory_core_early(pgdat->node_id, size, align,
				goal, ARCH_LOW_ADDRESS_LIMIT);
	if (ptr)
		return ptr;
	ptr = __alloc_memory_core_early(MAX_NUMNODES, size, align,
				goal, ARCH_LOW_ADDRESS_LIMIT);
#else
	ptr = ___alloc_bootmem_node(pgdat->bdata, size, align,
				goal, ARCH_LOW_ADDRESS_LIMIT);
#endif
	return ptr;
}
