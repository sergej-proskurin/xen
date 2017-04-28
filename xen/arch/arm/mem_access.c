/*
 * arch/arm/mem_access.c
 *
 * Architecture-specific mem_access handling routines
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License v2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with this program; If not, see <http://www.gnu.org/licenses/>.
 */

#include <xen/mem_access.h>
#include <xen/monitor.h>
#include <xen/sched.h>
#include <xen/vm_event.h>
#include <xen/domain_page.h>
#include <public/vm_event.h>
#include <asm/event.h>

static int __p2m_get_mem_access(struct domain *d, gfn_t gfn,
                                xenmem_access_t *access)
{
    struct p2m_domain *p2m = p2m_get_hostp2m(d);
    void *i;
    unsigned int index;

    static const xenmem_access_t memaccess[] = {
#define ACCESS(ac) [p2m_access_##ac] = XENMEM_access_##ac
            ACCESS(n),
            ACCESS(r),
            ACCESS(w),
            ACCESS(rw),
            ACCESS(x),
            ACCESS(rx),
            ACCESS(wx),
            ACCESS(rwx),
            ACCESS(rx2rw),
            ACCESS(n2rwx),
#undef ACCESS
    };

    ASSERT(p2m_is_locked(p2m));

    /* If no setting was ever set, just return rwx. */
    if ( !p2m->mem_access_enabled )
    {
        *access = XENMEM_access_rwx;
        return 0;
    }

    /* If request to get default access. */
    if ( gfn_eq(gfn, INVALID_GFN) )
    {
        *access = memaccess[p2m->default_access];
        return 0;
    }

    i = radix_tree_lookup(&p2m->mem_access_settings, gfn_x(gfn));

    if ( !i )
    {
        /*
         * No setting was found in the Radix tree. Check if the
         * entry exists in the page-tables.
         */
        mfn_t mfn = p2m_get_entry(p2m, gfn, NULL, NULL, NULL);

        if ( mfn_eq(mfn, INVALID_MFN) )
            return -ESRCH;

        /* If entry exists then its rwx. */
        *access = XENMEM_access_rwx;
    }
    else
    {
        /* Setting was found in the Radix tree. */
        index = radix_tree_ptr_to_int(i);
        if ( index >= ARRAY_SIZE(memaccess) )
            return -ERANGE;

        *access = memaccess[index];
    }

    return 0;
}

static int
p2m_gva_to_ipa(struct p2m_domain *p2m, vaddr_t gva,
               paddr_t *ipa, unsigned int flags)
{
    int level=0, t0_sz, t1_sz;
    unsigned long t0_max, t1_min;
    lpae_t pte, *table;
    mfn_t root_mfn;
    uint64_t ttbr;
    uint32_t sctlr = READ_SYSREG(SCTLR_EL1);
    register_t ttbcr = READ_SYSREG(TCR_EL1);
    struct domain *d = p2m->domain;

    const unsigned int offsets[4] = {
#ifdef CONFIG_ARM_64
        zeroeth_table_offset(gva),
#endif
        first_table_offset(gva),
        second_table_offset(gva),
        third_table_offset(gva)
    };

    const paddr_t masks[4] = {
#ifdef CONFIG_ARM_64
        ZEROETH_SIZE - 1,
#endif
        FIRST_SIZE - 1,
        SECOND_SIZE - 1,
        THIRD_SIZE - 1
    };

    /* If the MMU is disabled, there is no need to translate the gva. */
    if ( !(sctlr & SCTLR_M) )
    {
        *ipa = gva;

        return 0;
    }

    if ( is_32bit_domain(d) )
    {
        /*
         * XXX: We do not support 32-bit domain translation table walks for
         * domains using the short-descriptor translation table format, yet.
         */
        if ( !(ttbcr & TTBCR_EAE) )
            return -EFAULT;

#ifdef CONFIG_ARM_64
        level = 1;
#endif
    }

#ifdef CONFIG_ARM_64
    if ( is_64bit_domain(d) )
    {
        /* Get the max GVA that can be translated by TTBR0. */
        t0_sz = (ttbcr >> TCR_T0SZ_SHIFT) & TCR_SZ_MASK;
        t0_max = (1UL << (64 - t0_sz)) - 1;

        /* Get the min GVA that can be translated by TTBR1. */
        t1_sz = (ttbcr >> TCR_T1SZ_SHIFT) & TCR_SZ_MASK;
        t1_min = ~0UL - (1UL << (64 - t1_sz)) + 1;
    }
    else
#endif
    {
        /* Get the max GVA that can be translated by TTBR0. */
        t0_sz = (ttbcr >> TCR_T0SZ_SHIFT) & TTBCR_SZ_MASK;
        t0_max = (1U << (32 - t0_sz)) - 1;

        /* Get the min GVA that can be translated by TTBR1. */
        t1_sz = (ttbcr >> TCR_T1SZ_SHIFT) & TTBCR_SZ_MASK;
        t1_min = ~0U - (1U << (32 - t1_sz)) + 1;
    }

    if ( t0_max >= gva )
        /* Use TTBR0 for GVA to IPA translation. */
        ttbr = READ_SYSREG64(TTBR0_EL1);
    else if ( t1_min <= gva )
        /* Use TTBR1 for GVA to IPA translation. */
        ttbr = READ_SYSREG64(TTBR1_EL1);
    else
        /* GVA out of bounds of TTBR(0|1). */
        return -EFAULT;

    /* Bits [63..48] might be used by an ASID. */
    root_mfn = p2m_lookup(d, _gfn(paddr_to_pfn(ttbr & ((1ULL<<48)-1))), NULL);

    /* Check, whether TTBR holds a valid address. */
    if ( mfn_eq(root_mfn, INVALID_MFN) )
        return -EFAULT;

    table = map_domain_page(root_mfn);

    for ( ; ; level++ )
    {
        pte = table[offsets[level]];

        if ( level == 3 || !pte.walk.valid || !pte.walk.table )
            break;

        unmap_domain_page(table);

        root_mfn = p2m_lookup(d, _gfn(pte.walk.base), NULL);
        table = map_domain_page(root_mfn);
    }

    unmap_domain_page(table);

    if ( !pte.walk.valid )
        return -EFAULT;

    /* Make sure the entry holds the requested access attributes. */
    if ( ((flags & GV2M_WRITE) == GV2M_WRITE) && pte.pt.ro )
        return -EFAULT;

    *ipa = pfn_to_paddr(pte.walk.base) | (gva & masks[level]);

    return 0;
}


/*
 * If mem_access is in use it might have been the reason why get_page_from_gva
 * failed to fetch the page, as it uses the MMU for the permission checking.
 * Only in these cases we do a software-based type check and fetch the page if
 * we indeed found a conflicting mem_access setting.
 */
struct page_info*
p2m_mem_access_check_and_get_page(vaddr_t gva, unsigned long flag,
                                  const struct vcpu *v)
{
    long rc;
    paddr_t ipa;
    gfn_t gfn;
    mfn_t mfn;
    xenmem_access_t xma;
    p2m_type_t t;
    struct page_info *page = NULL;
    struct p2m_domain *p2m = &v->domain->arch.p2m;

    ASSERT(p2m->mem_access_enabled);

    rc = gva_to_ipa(gva, &ipa, flag);

    /*
     * In case mem_access is active, hardware-based gva_to_ipa translation
     * might fail. Since gva_to_ipa uses the guest's translation tables, access
     * to which might be restricted by the active VTTBR, we perform a gva to
     * ipa translation in software.
     */
    if ( rc < 0 )
        if ( p2m_gva_to_ipa(p2m, gva, &ipa, flag) < 0 )
            /*
             * The software gva to ipa translation can still fail, if the the
             * gva is not mapped or does not hold the requested access rights.
             */
            goto err;

    gfn = _gfn(paddr_to_pfn(ipa));

    /*
     * We do this first as this is faster in the default case when no
     * permission is set on the page.
     */
    rc = __p2m_get_mem_access(v->domain, gfn, &xma);
    if ( rc < 0 )
        goto err;

    /* Let's check if mem_access limited the access. */
    switch ( xma )
    {
    default:
    case XENMEM_access_rwx:
    case XENMEM_access_rw:
        /*
         * If mem_access contains no rw perm restrictions at all then the original
         * fault was correct.
         */
        goto err;
    case XENMEM_access_n2rwx:
    case XENMEM_access_n:
    case XENMEM_access_x:
        /*
         * If no r/w is permitted by mem_access, this was a fault caused by mem_access.
         */
        break;
    case XENMEM_access_wx:
    case XENMEM_access_w:
        /*
         * If this was a read then it was because of mem_access, but if it was
         * a write then the original get_page_from_gva fault was correct.
         */
        if ( flag == GV2M_READ )
            break;
        else
            goto err;
    case XENMEM_access_rx2rw:
    case XENMEM_access_rx:
    case XENMEM_access_r:
        /*
         * If this was a write then it was because of mem_access, but if it was
         * a read then the original get_page_from_gva fault was correct.
         */
        if ( flag == GV2M_WRITE )
            break;
        else
            goto err;
    }

    /*
     * We had a mem_access permission limiting the access, but the page type
     * could also be limiting, so we need to check that as well.
     */
    mfn = p2m_get_entry(p2m, gfn, &t, NULL, NULL);
    if ( mfn_eq(mfn, INVALID_MFN) )
        goto err;

    if ( !mfn_valid(mfn) )
        goto err;

    /*
     * Base type doesn't allow r/w
     */
    if ( t != p2m_ram_rw )
        goto err;

    page = mfn_to_page(mfn_x(mfn));

    if ( unlikely(!get_page(page, v->domain)) )
        page = NULL;

err:
    return page;
}

bool_t p2m_mem_access_check(paddr_t gpa, vaddr_t gla, const struct npfec npfec)
{
    int rc;
    bool_t violation;
    xenmem_access_t xma;
    vm_event_request_t *req;
    struct vcpu *v = current;
    struct p2m_domain *p2m = p2m_get_hostp2m(v->domain);

    /* Mem_access is not in use. */
    if ( !p2m->mem_access_enabled )
        return true;

    rc = p2m_get_mem_access(v->domain, _gfn(paddr_to_pfn(gpa)), &xma);
    if ( rc )
        return true;

    /* Now check for mem_access violation. */
    switch ( xma )
    {
    case XENMEM_access_rwx:
        violation = false;
        break;
    case XENMEM_access_rw:
        violation = npfec.insn_fetch;
        break;
    case XENMEM_access_wx:
        violation = npfec.read_access;
        break;
    case XENMEM_access_rx:
    case XENMEM_access_rx2rw:
        violation = npfec.write_access;
        break;
    case XENMEM_access_x:
        violation = npfec.read_access || npfec.write_access;
        break;
    case XENMEM_access_w:
        violation = npfec.read_access || npfec.insn_fetch;
        break;
    case XENMEM_access_r:
        violation = npfec.write_access || npfec.insn_fetch;
        break;
    default:
    case XENMEM_access_n:
    case XENMEM_access_n2rwx:
        violation = true;
        break;
    }

    if ( !violation )
        return true;

    /* First, handle rx2rw and n2rwx conversion automatically. */
    if ( npfec.write_access && xma == XENMEM_access_rx2rw )
    {
        rc = p2m_set_mem_access(v->domain, _gfn(paddr_to_pfn(gpa)), 1,
                                0, ~0, XENMEM_access_rw, 0);
        return false;
    }
    else if ( xma == XENMEM_access_n2rwx )
    {
        rc = p2m_set_mem_access(v->domain, _gfn(paddr_to_pfn(gpa)), 1,
                                0, ~0, XENMEM_access_rwx, 0);
    }

    /* Otherwise, check if there is a vm_event monitor subscriber */
    if ( !vm_event_check_ring(&v->domain->vm_event->monitor) )
    {
        /* No listener */
        if ( p2m->access_required )
        {
            gdprintk(XENLOG_INFO, "Memory access permissions failure, "
                                  "no vm_event listener VCPU %d, dom %d\n",
                                  v->vcpu_id, v->domain->domain_id);
            domain_crash(v->domain);
        }
        else
        {
            /* n2rwx was already handled */
            if ( xma != XENMEM_access_n2rwx )
            {
                /* A listener is not required, so clear the access
                 * restrictions. */
                rc = p2m_set_mem_access(v->domain, _gfn(paddr_to_pfn(gpa)), 1,
                                        0, ~0, XENMEM_access_rwx, 0);
            }
        }

        /* No need to reinject */
        return false;
    }

    req = xzalloc(vm_event_request_t);
    if ( req )
    {
        req->reason = VM_EVENT_REASON_MEM_ACCESS;

        /* Send request to mem access subscriber */
        req->u.mem_access.gfn = gpa >> PAGE_SHIFT;
        req->u.mem_access.offset =  gpa & ((1 << PAGE_SHIFT) - 1);
        if ( npfec.gla_valid )
        {
            req->u.mem_access.flags |= MEM_ACCESS_GLA_VALID;
            req->u.mem_access.gla = gla;

            if ( npfec.kind == npfec_kind_with_gla )
                req->u.mem_access.flags |= MEM_ACCESS_FAULT_WITH_GLA;
            else if ( npfec.kind == npfec_kind_in_gpt )
                req->u.mem_access.flags |= MEM_ACCESS_FAULT_IN_GPT;
        }
        req->u.mem_access.flags |= npfec.read_access    ? MEM_ACCESS_R : 0;
        req->u.mem_access.flags |= npfec.write_access   ? MEM_ACCESS_W : 0;
        req->u.mem_access.flags |= npfec.insn_fetch     ? MEM_ACCESS_X : 0;

        if ( monitor_traps(v, (xma != XENMEM_access_n2rwx), req) < 0 )
            domain_crash(v->domain);

        xfree(req);
    }

    return false;
}

/*
 * Set access type for a region of pfns.
 * If gfn == INVALID_GFN, sets the default access type.
 */
long p2m_set_mem_access(struct domain *d, gfn_t gfn, uint32_t nr,
                        uint32_t start, uint32_t mask, xenmem_access_t access,
                        unsigned int altp2m_idx)
{
    struct p2m_domain *p2m = p2m_get_hostp2m(d);
    p2m_access_t a;
    unsigned int order;
    long rc = 0;

    static const p2m_access_t memaccess[] = {
#define ACCESS(ac) [XENMEM_access_##ac] = p2m_access_##ac
        ACCESS(n),
        ACCESS(r),
        ACCESS(w),
        ACCESS(rw),
        ACCESS(x),
        ACCESS(rx),
        ACCESS(wx),
        ACCESS(rwx),
        ACCESS(rx2rw),
        ACCESS(n2rwx),
#undef ACCESS
    };

    switch ( access )
    {
    case 0 ... ARRAY_SIZE(memaccess) - 1:
        a = memaccess[access];
        break;
    case XENMEM_access_default:
        a = p2m->default_access;
        break;
    default:
        return -EINVAL;
    }

    /*
     * Flip mem_access_enabled to true when a permission is set, as to prevent
     * allocating or inserting super-pages.
     */
    p2m->mem_access_enabled = true;

    /* If request to set default access. */
    if ( gfn_eq(gfn, INVALID_GFN) )
    {
        p2m->default_access = a;
        return 0;
    }

    p2m_write_lock(p2m);

    for ( gfn = gfn_add(gfn, start); nr > start;
          gfn = gfn_next_boundary(gfn, order) )
    {
        p2m_type_t t;
        mfn_t mfn = p2m_get_entry(p2m, gfn, &t, NULL, &order);


        if ( !mfn_eq(mfn, INVALID_MFN) )
        {
            order = 0;
            rc = p2m_set_entry(p2m, gfn, 1, mfn, t, a);
            if ( rc )
                break;
        }

        start += gfn_x(gfn_next_boundary(gfn, order)) - gfn_x(gfn);
        /* Check for continuation if it is not the last iteration */
        if ( nr > start && !(start & mask) && hypercall_preempt_check() )
        {
            rc = start;
            break;
        }
    }

    p2m_write_unlock(p2m);

    return rc;
}

long p2m_set_mem_access_multi(struct domain *d,
                              const XEN_GUEST_HANDLE(const_uint64) pfn_list,
                              const XEN_GUEST_HANDLE(const_uint8) access_list,
                              uint32_t nr, uint32_t start, uint32_t mask,
                              unsigned int altp2m_idx)
{
    /* Not yet implemented on ARM. */
    return -EOPNOTSUPP;
}

int p2m_get_mem_access(struct domain *d, gfn_t gfn,
                       xenmem_access_t *access)
{
    int ret;
    struct p2m_domain *p2m = p2m_get_hostp2m(d);

    p2m_read_lock(p2m);
    ret = __p2m_get_mem_access(d, gfn, access);
    p2m_read_unlock(p2m);

    return ret;
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
