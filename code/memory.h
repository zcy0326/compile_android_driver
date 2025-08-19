// memory.h
#include <linux/sched.h>
#include <linux/tty.h>
#include <linux/io.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#if(LINUX_VERSION_CODE >= KERNEL_VERSION(4,14,83))
#include <linux/sched/mm.h>
#endif
#include <asm/cpu.h>
#include <asm/io.h>
#include <asm/page.h>
#include <asm/pgtable.h>

static bool safe_read_physical(phys_addr_t pa, void *buffer, size_t size)
{
    struct page *page;
    void *mapped;

    page = pfn_to_page(__phys_to_pfn(pa));
    if (!page)
        return false;

    mapped = kmap_atomic(page);
    if (!mapped)
        return false;

    if (copy_to_user(buffer, mapped + offset_in_page(pa), size)) {
        kunmap_atomic(mapped);
        return false;
    }

    kunmap_atomic(mapped);
    return true;
}

static bool safe_write_physical(phys_addr_t pa, void *buffer, size_t size)
{
    struct page *page;
    void *mapped;

    page = pfn_to_page(__phys_to_pfn(pa));
    if (!page)
        return false;

    mapped = kmap_atomic(page);
    if (!mapped)
        return false;

    if (copy_from_user(mapped + offset_in_page(pa), buffer, size)) {
        kunmap_atomic(mapped);
        return false;
    }

    kunmap_atomic(mapped);
    return true;
}

#if(LINUX_VERSION_CODE >= KERNEL_VERSION(5, 4, 61))
phys_addr_t translate_linear_address(struct mm_struct* mm, uintptr_t va) {
    pgd_t *pgd;
    p4d_t *p4d;
    pmd_t *pmd;
    pte_t *pte;
    pud_t *pud;

    phys_addr_t page_addr;
    uintptr_t page_offset;

    pgd = pgd_offset(mm, va);
    if(pgd_none(*pgd) || pgd_bad(*pgd)) {
        return 0;
    }
    p4d = p4d_offset(pgd, va);
    if (p4d_none(*p4d) || p4d_bad(*p4d)) {
        return 0;
    }
    pud = pud_offset(p4d,va);
    if(pud_none(*pud) || pud_bad(*pud)) {
        return 0;
    }
    pmd = pmd_offset(pud,va);
    if(pmd_none(*pmd)) {
        return 0;
    }
    pte = pte_offset_kernel(pmd,va);
    if(pte_none(*pte)) {
        return 0;
    }
    if(!pte_present(*pte)) {
        return 0;
    }
    page_addr = (phys_addr_t)(pte_pfn(*pte) << PAGE_SHIFT);
    page_offset = va & (PAGE_SIZE-1);

    return page_addr + page_offset;
}
#else
phys_addr_t translate_linear_address(struct mm_struct* mm, uintptr_t va) {
    pgd_t *pgd;
    pmd_t *pmd;
    pte_t *pte;
    pud_t *pud;

    phys_addr_t page_addr;
    uintptr_t page_offset;

    pgd = pgd_offset(mm, va);
    if(pgd_none(*pgd) || pgd_bad(*pgd)) {
        return 0;
    }
    pud = pud_offset(pgd,va);
    if(pud_none(*pud) || pud_bad(*pud)) {
        return 0;
    }
    pmd = pmd_offset(pud,va);
    if(pmd_none(*pmd)) {
        return 0;
    }
    pte = pte_offset_kernel(pmd,va);
    if(pte_none(*pte)) {
        return 0;
    }
    if(!pte_present(*pte)) {
        return 0;
    }
    page_addr = (phys_addr_t)(pte_pfn(*pte) << PAGE_SHIFT);
    page_offset = va & (PAGE_SIZE-1);

    return page_addr + page_offset;
}
#endif

bool read_process_memory(pid_t pid, uintptr_t addr, void* buffer, size_t size)
{
    struct task_struct* task;
    struct mm_struct* mm;
    phys_addr_t pa;
    size_t max;
    bool result = true;

    task = pid_task(find_vpid(pid), PIDTYPE_PID);
    if (!task) {
        return false;
    }
    mm = get_task_mm(task);
    if (!mm) {
        return false;
    }
    
    down_read(&mm->mmap_sem);
    while (size > 0) {
        pa = translate_linear_address(mm, addr);
        max = min(PAGE_SIZE - (addr & (PAGE_SIZE - 1)), min(size, PAGE_SIZE));
        if (!pa) {
            result = false;
            break;
        }
        
        if (!safe_read_physical(pa, buffer, max)) {
            result = false;
            break;
        }
        
        size -= max;
        buffer += max;
        addr += max;
    }
    up_read(&mm->mmap_sem);
    mmput(mm);
    return result;
}

bool write_process_memory(pid_t pid, uintptr_t addr, void* buffer, size_t size)
{
    struct task_struct* task;
    struct mm_struct* mm;
    phys_addr_t pa;
    size_t max;
    bool result = true;

    task = pid_task(find_vpid(pid), PIDTYPE_PID);
    if (!task) {
        return false;
    }
    mm = get_task_mm(task);
    if (!mm) {
        return false;
    }
    
    down_read(&mm->mmap_sem);
    while (size > 0) {
        pa = translate_linear_address(mm, addr);
        max = min(PAGE_SIZE - (addr & (PAGE_SIZE - 1)), min(size, PAGE_SIZE));
        if (!pa) {
            result = false;
            break;
        }
        
        if (!safe_write_physical(pa, buffer, max)) {
            result = false;
            break;
        }
        
        size -= max;
        buffer += max;
        addr += max;
    }
    up_read(&mm->mmap_sem);
    mmput(mm);
    return result;
}