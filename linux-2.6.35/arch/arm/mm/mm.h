#ifdef CONFIG_MMU

/* the upper-most page table pointer */
extern pmd_t *top_pmd;

#define TOP_PTE(x)	pte_offset_kernel(top_pmd, x)

static inline pmd_t *pmd_off(pgd_t *pgd, unsigned long virt)
{
	return pmd_offset(pgd, virt);
}

static inline pmd_t *pmd_off_k(unsigned long virt)
{
	return pmd_off(pgd_offset_k(virt), virt);
}

/* mem_type 是用来标记内存页表的权限(protect，实际就是页表除地址部分其余bit的设置)和domain。
 * 源码中用一个数组来记录所有类型内存和IO的访问mem_types[](定义在arch/arm/mm/mmu.c)。
 */
struct mem_type {
	unsigned int prot_pte; /* 二级页表protect标志 */
	unsigned int prot_l1;  /* 一级页表protect标志 */
	unsigned int prot_sect;
	unsigned int domain; /* 映射的页框所属的domain : kernel-0,user-1, io-2 */
};

const struct mem_type *get_mem_type(unsigned int type);

extern void __flush_dcache_page(struct address_space *mapping, struct page *page);

#endif

struct pglist_data;

void __init bootmem_init(void);
void reserve_node_zero(struct pglist_data *pgdat);
