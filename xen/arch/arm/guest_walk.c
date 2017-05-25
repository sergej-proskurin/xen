/*
 * Guest page table walk
 * Copyright (c) 2017 Sergej Proskurin <proskurin@sec.in.tum.de>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; If not, see <http://www.gnu.org/licenses/>.
 */

#include <xen/sched.h>
#include <xen/domain_page.h>
#include <asm/guest_walk.h>

/*
 * The function guest_walk_sd translates a given GVA into an IPA using the
 * short-descriptor translation table format in software. This function assumes
 * that the domain is running on the currently active vCPU. To walk the guest's
 * page table on a different vCPU, the following registers would need to be
 * loaded: TCR_EL1, TTBR0_EL1, TTBR1_EL1, and SCTLR_EL1.
 */
static int guest_walk_sd(struct domain *d,
                         vaddr_t gva, paddr_t *ipa,
                         unsigned int *perms)
{
    bool disabled = true;
    int64_t ttbr;
    paddr_t mask, paddr;
    pte_sd_t pte, *table;
    struct page_info *page;
    register_t ttbcr = READ_SYSREG(TCR_EL1);
    unsigned int level = 0, n = ttbcr & TTBCR_N_MASK;

    const paddr_t offsets[2] = {
        ((paddr_t)(gva >> 20) & ((1ULL << (12 - n)) - 1)),
        ((paddr_t)(gva >> 12) & ((1ULL << 8) - 1))
    };

    mask = ((1ULL << REGISTER_WIDTH_32_BIT) - 1) &
           ~((1ULL << (REGISTER_WIDTH_32_BIT - n)) - 1);

    if ( n == 0 || !(gva & mask) )
    {
        /* Use TTBR0 for GVA to IPA translation. */
        ttbr = READ_SYSREG64(TTBR0_EL1);

        /* If TTBCR.PD0 is set, translations using TTBR0 are disabled. */
        disabled = ttbcr & TTBCR_PD0;
    }
    else
    {
        /* Use TTBR1 for GVA to IPA translation. */
        ttbr = READ_SYSREG64(TTBR1_EL1);

        /* If TTBCR.PD1 is set, translations using TTBR1 are disabled. */
        disabled = ttbcr & TTBCR_PD1;

        /*
         * TTBR1 translation always works like n==0 TTBR0 translation (ARM DDI
         * 0487B-a J1-6003).
         */
        n = 0;
    }

    if ( disabled )
        return -EFAULT;

    /*
     * The address of the descriptor for the initial lookup has the following
     * format: [ttbr<31:14-n>:gva<31-n:20>:00] (ARM DDI 0487B-a J1-6003). In
     * this way, the first lookup level might comprise up to four consecutive
     * pages. To avoid mapping all of the pages, we simply map the page that is
     * needed by the first level translation by incorporating up to 2 MSBs of
     * the GVA.
     */
    mask = (1ULL << (14 - n)) - 1;
    paddr = (ttbr & ~mask) | (offsets[level] << 2);

    page = get_page_from_gfn(d, paddr_to_pfn(paddr), NULL, P2M_ALLOC);
    if ( !page )
        return -EFAULT;

    table = __map_domain_page(page);

    /*
     * Consider that the first level address translation does not need to be
     * page-aligned if n > 2.
     */
    if ( n > 2 )
    {
        /* Make sure that we consider the bits ttbr<12:14-n> if n > 2. */
        mask = ((1ULL << 12) - 1) & ~((1ULL << (14 - n)) - 1);
        table = (pte_sd_t *)((unsigned long)table | (unsigned long)(ttbr & mask));
    }

    /*
     * As we have considered up to 2 MSBs of the GVA for mapping the first
     * level translation table, we need to make sure that we limit the table
     * offset that is is indexed by GVA<31-n:20> to max 10 bits to avoid
     * exceeding the page size limit.
     */
    mask = ((1ULL << 10) - 1);
    pte = table[offsets[level] & mask];

    unmap_domain_page(table);
    put_page(page);

    switch ( pte.walk.dt )
    {
    case L1DESC_INVALID:
        return -EFAULT;

    case L1DESC_PAGE_TABLE:
        level++;

        page = get_page_from_gfn(d, (pte.walk.base >> 2), NULL, P2M_ALLOC);
        if ( !page )
            return -EFAULT;

        table = __map_domain_page(page);
        /*
         * The second level translation table is addressed by PTE<31:10>. Hence
         * it does not need to be page aligned. Make sure that we also consider
         * the bits PTE<11:10>.
         */
        table = (pte_sd_t *)((unsigned long)table | ((pte.walk.base & 0x3) << 10));

        pte = table[offsets[level]];

        unmap_domain_page(table);
        put_page(page);

        if ( pte.walk.dt == L2DESC_INVALID )
            return -EFAULT;

        if ( pte.pg.page ) /* Small page. */
        {
            mask = (1ULL << PAGE_SHIFT_4K) - 1;

            *ipa = (pte.pg.base << PAGE_SHIFT_4K) | (gva & mask);

            /* Set execute permissions associated with the small page. */
            if ( !pte.pg.xn )
                *perms = GV2M_EXEC;
        }
        else /* Large page. */
        {
            mask = (1ULL << PAGE_SHIFT_64K) - 1;

            *ipa = (pte.lpg.base << PAGE_SHIFT_64K) | (gva & mask);

            /* Set execute permissions associated with the large page. */
            if ( !pte.lpg.xn )
                *perms = GV2M_EXEC;
        }

        /* Set permissions so that the caller can check the flags by herself. */
        if ( !pte.pg.ro )
            *perms |= GV2M_WRITE;

        break;

    case L1DESC_SECTION:
    case L1DESC_SECTION_PXN:
        if ( !pte.sec.supersec ) /* Section */
        {
            mask = (1ULL << L1DESC_SECTION_SHIFT) - 1;

            *ipa = (pte.sec.base << L1DESC_SECTION_SHIFT) | (gva & mask);
        }
        else /* Supersection */
        {
            mask = (1ULL << L1DESC_SUPERSECTION_SHIFT) - 1;

            *ipa = gva & mask;
            *ipa |= (paddr_t)(pte.supersec.base) << L1DESC_SUPERSECTION_SHIFT;
            *ipa |= (paddr_t)(pte.supersec.extbase1) << L1DESC_SUPERSECTION_EXT_BASE1_SHIFT;
            *ipa |= (paddr_t)(pte.supersec.extbase2) << L1DESC_SUPERSECTION_EXT_BASE2_SHIFT;
        }

        /* Set permissions so that the caller can check the flags by herself. */
        if ( !pte.sec.ro )
            *perms = GV2M_WRITE;
        if ( !pte.sec.xn )
            *perms |= GV2M_EXEC;
    }

    return 0;
}

#ifdef CONFIG_ARM_64
/*
 * Select the TTBR(0|1)_EL1 that will be used for address translation using the
 * long-descriptor translation table format and return the page granularity
 * that is used by the selected TTBR.
 */
static bool get_ttbr_and_gran_64bit(uint64_t *ttbr, unsigned int *gran,
                                    register_t tcr, bool ttbrx)
{
    bool disabled;

    if ( ttbrx == TTBR0_VALID )
    {
        /* Normalize granule size. */
        switch ( tcr & TCR_TG0_MASK )
        {
        case TCR_TG0_16K:
            *gran = GRANULE_SIZE_INDEX_16K;
            break;
        case TCR_TG0_64K:
            *gran = GRANULE_SIZE_INDEX_64K;
            break;
        default:
            *gran = GRANULE_SIZE_INDEX_4K;
        }

        /* Use TTBR0 for GVA to IPA translation. */
        *ttbr = READ_SYSREG64(TTBR0_EL1);

        /* If TCR.EPD0 is set, translations using TTBR0 are disabled. */
        disabled = tcr & TCR_EPD0;
    }
    else
    {
        /* Normalize granule size. */
        switch ( tcr & TCR_EL1_TG1_MASK )
        {
        case TCR_EL1_TG1_16K:
            *gran = GRANULE_SIZE_INDEX_16K;
            break;
        case TCR_EL1_TG1_64K:
            *gran = GRANULE_SIZE_INDEX_64K;
            break;
        default:
            *gran = GRANULE_SIZE_INDEX_4K;
        }

        /* Use TTBR1 for GVA to IPA translation. */
        *ttbr = READ_SYSREG64(TTBR1_EL1);

        /* If TCR.EPD1 is set, translations using TTBR1 are disabled. */
        disabled = tcr & TCR_EPD1;
    }

    return disabled;
}
#endif

/*
 * Get the MSB number of the GVA, according to "AddrTop" pseudocode
 * implementation in ARM DDI 0487B-a J1-6066.
 */
static unsigned int get_top_bit(struct domain *d, vaddr_t gva, register_t tcr)
{
    unsigned int topbit;

    /*
     * IF EL1 is using AArch64 then addresses from EL0 using AArch32 are
     * zero-extended to 64 bits (ARM DDI 0487B-a J1-6066).
     */
    if ( is_32bit_domain(d) )
        topbit = 31;
#ifdef CONFIG_ARM_64
    else if ( is_64bit_domain(d) )
    {
        if ( ((gva & BIT(55)) && (tcr & TCR_EL1_TBI1)) ||
             (!(gva & BIT(55)) && (tcr & TCR_EL1_TBI0)) )
            topbit = 55;
        else
            topbit = 63;
    }
#endif

    return topbit;
}

/*
 * The function guest_walk_ld translates a given GVA into an IPA using the
 * long-descriptor translation table format in software. This function assumes
 * that the domain is running on the currently active vCPU. To walk the guest's
 * page table on a different vCPU, the following registers would need to be
 * loaded: TCR_EL1, TTBR0_EL1, TTBR1_EL1, and SCTLR_EL1.
 */
static int guest_walk_ld(struct domain *d,
                         vaddr_t gva, paddr_t *ipa,
                         unsigned int *perms)
{
    bool disabled = true;
    bool ro_table = false, xn_table = false;
    unsigned int t0_sz, t1_sz;
    unsigned int level, gran;
    unsigned int topbit = 0, input_size = 0, output_size;
    uint64_t ttbr = 0, ips;
    paddr_t mask;
    lpae_t pte, *table;
    struct page_info *page;
    register_t tcr = READ_SYSREG(TCR_EL1);

    const vaddr_t offsets[4][3] = {
        {
#ifdef CONFIG_ARM_64
            zeroeth_guest_table_offset_4k(gva),
            zeroeth_guest_table_offset_16k(gva),
            0, /* There is no zeroeth lookup level with a 64K granule size. */
#endif
        },
        {
            first_guest_table_offset_4k(gva),
#ifdef CONFIG_ARM_64
            first_guest_table_offset_16k(gva),
            first_guest_table_offset_64k(gva),
#endif
        },
        {
            second_guest_table_offset_4k(gva),
#ifdef CONFIG_ARM_64
            second_guest_table_offset_16k(gva),
            second_guest_table_offset_64k(gva),
#endif
        },
        {
            third_guest_table_offset_4k(gva),
#ifdef CONFIG_ARM_64
            third_guest_table_offset_16k(gva),
            third_guest_table_offset_64k(gva),
#endif
        }
    };

    static const paddr_t masks[4][3] = {
        {
            zeroeth_size(4K) - 1,
            zeroeth_size(16K) - 1,
            0 /* There is no zeroeth lookup level with a 64K granule size. */
        },
        {
            first_size(4K) - 1,
            first_size(16K) - 1,
            first_size(64K) - 1
        },
        {
            second_size(4K) - 1,
            second_size(16K) - 1,
            second_size(64K) - 1
        },
        {
            third_size(4K) - 1,
            third_size(16K) - 1,
            third_size(64K) - 1
        }
    };

    static const unsigned int grainsizes[3] = {
        PAGE_SHIFT_4K,
        PAGE_SHIFT_16K,
        PAGE_SHIFT_64K
    };

    t0_sz = (tcr >> TCR_T0SZ_SHIFT) & TCR_SZ_MASK;
    t1_sz = (tcr >> TCR_T1SZ_SHIFT) & TCR_SZ_MASK;

    /* Get the MSB number of the GVA. */
    topbit = get_top_bit(d, gva, tcr);

#ifdef CONFIG_ARM_64
    if ( is_64bit_domain(d) )
    {
        /* Select the TTBR(0|1)_EL1 that will be used for address translation. */

        if ( (gva & BIT(topbit)) == 0 )
        {
            input_size = REGISTER_WIDTH_64_BIT - t0_sz;

            /* Get TTBR0 and configured page granularity. */
            disabled = get_ttbr_and_gran_64bit(&ttbr, &gran, tcr, TTBR0_VALID);
        }
        else
        {
            input_size = REGISTER_WIDTH_64_BIT - t1_sz;

            /* Get TTBR1 and configured page granularity. */
            disabled = get_ttbr_and_gran_64bit(&ttbr, &gran, tcr, TTBR1_VALID);
        }

        /*
         * The current implementation supports intermediate physical address
         * sizes (IPS) up to 48 bit.
         *
         * XXX: Determine whether the IPS_MAX_VAL is 48 or 52 in software.
         */
        if ( (input_size > TCR_EL1_IPS_48_BIT_VAL) ||
             (input_size < TCR_EL1_IPS_MIN_VAL) )
            return -EFAULT;
    }
    else
#endif
    {
        /* Granule size of AArch32 architectures is always 4K. */
        gran = GRANULE_SIZE_INDEX_4K;

        /* Select the TTBR(0|1)_EL1 that will be used for address translation. */

        /*
         * Check if the bits <31:32-t0_sz> of the GVA are set to 0 (DDI 0487B-a
         * J1-5999). If so, TTBR0 shall be used for address translation.
         */
        mask = ((1ULL << REGISTER_WIDTH_32_BIT) - 1) &
               ~((1ULL << (REGISTER_WIDTH_32_BIT - t0_sz)) - 1);

        if ( t0_sz == 0 || !(gva & mask) )
        {
            input_size = REGISTER_WIDTH_32_BIT - t0_sz;

            /* Use TTBR0 for GVA to IPA translation. */
            ttbr = READ_SYSREG64(TTBR0_EL1);

            /* If TCR.EPD0 is set, translations using TTBR0 are disabled. */
            disabled = tcr & TCR_EPD0;
        }

        /*
         * Check if the bits <31:32-t1_sz> of the GVA are set to 1 (DDI 0487B-a
         * J1-6000). If so, TTBR1 shall be used for address translation.
         */
        mask = ((1ULL << REGISTER_WIDTH_32_BIT) - 1) &
               ~((1ULL << (REGISTER_WIDTH_32_BIT - t1_sz)) - 1);

        if ( ((t1_sz == 0) && !ttbr) || (t1_sz && (gva & mask) == mask) )
        {
            input_size = REGISTER_WIDTH_32_BIT - t1_sz;

            /* Use TTBR1 for GVA to IPA translation. */
            ttbr = READ_SYSREG64(TTBR1_EL1);

            /* If TCR.EPD1 is set, translations using TTBR1 are disabled. */
            disabled = tcr & TCR_EPD1;
        }
    }

    if ( disabled )
        return -EFAULT;

    /*
     * The starting level is the number of strides (grainsizes[gran] - 3)
     * needed to consume the input address (DDI 0487B-a J1-5924).
     */
    level = 4 - DIV_ROUND_UP((input_size - grainsizes[gran]), (grainsizes[gran] - 3));

    if ( is_64bit_domain(d) )
    {
        /* Get the intermediate physical address size. */
        ips = (tcr & TCR_EL1_IPS_MASK) >> TCR_EL1_IPS_SHIFT;

        switch (ips)
        {
        case TCR_EL1_IPS_32_BIT:
            output_size = TCR_EL1_IPS_32_BIT_VAL;
            break;
        case TCR_EL1_IPS_36_BIT:
            output_size = TCR_EL1_IPS_36_BIT_VAL;
            break;
        case TCR_EL1_IPS_40_BIT:
            output_size = TCR_EL1_IPS_40_BIT_VAL;
            break;
        case TCR_EL1_IPS_42_BIT:
            output_size = TCR_EL1_IPS_42_BIT_VAL;
            break;
        case TCR_EL1_IPS_44_BIT:
            output_size = TCR_EL1_IPS_44_BIT_VAL;
            break;
        case TCR_EL1_IPS_48_BIT:
            output_size = TCR_EL1_IPS_48_BIT_VAL;
            break;
        case TCR_EL1_IPS_52_BIT:
            /* XXX: 52 bit output_size is not supported yet. */
            return -EFAULT;
        default:
            output_size = TCR_EL1_IPS_48_BIT_VAL;
        }
    }
    else
        output_size = TCR_EL1_IPS_40_BIT_VAL;

    /* Make sure the base address does not exceed its configured size. */
    mask = ((1ULL << TCR_EL1_IPS_48_BIT_VAL) - 1) & ~((1ULL << output_size) - 1);
    if ( output_size < TCR_EL1_IPS_48_BIT_VAL && (ttbr & mask) )
        return -EFAULT;

    mask = ((1ULL << output_size) - 1);
    page = get_page_from_gfn(d, paddr_to_pfn(ttbr & mask), NULL, P2M_ALLOC);
    if ( !page )
        return -EFAULT;

    table = __map_domain_page(page);

    for ( ; ; level++ )
    {
        pte = table[offsets[level][gran]];

        unmap_domain_page(table);
        put_page(page);

        /* Make sure the base address does not exceed its configured size. */
        mask = ((1ULL << TCR_EL1_IPS_48_BIT_VAL) - 1) &
               ~((1ULL << output_size) - 1);

        if ( (output_size < TCR_EL1_IPS_48_BIT_VAL) &&
             (pfn_to_paddr(pte.walk.base) & mask) )
            return -EFAULT;

#ifdef CONFIG_ARM_64
        /*
         * If page granularity is 64K, make sure the address is aligned
         * appropriately.
         */
        if ( (output_size < TCR_EL1_IPS_52_BIT_VAL) &&
             (gran == GRANULE_SIZE_INDEX_64K) &&
             (pte.walk.base & 0xf) )
            return -EFAULT;
#endif

        /*
         * Break if one of the following conditions are true:
         *
         * - We have found the PTE holding the IPA (level == 3).
         * - The PTE is not valid.
         * - If (level < 3) and the PTE is valid, we found a block descriptor.
         */
        if ( level == 3 || !p2m_valid(pte) || !p2m_table(pte) )
            break;

        /*
         * Temporarily store permissions of the table descriptor as they are
         * inherited by page table attributes (ARM DDI 0487B-a J1-5928).
         */
        xn_table = xn_table | !!(pte.pt.xnt);          /* Execute-Never */
        ro_table = ro_table | !!(pte.pt.apt & BIT(1)); /* Read-Only */

#ifdef CONFIG_ARM_64
        if ( output_size == TCR_EL1_IPS_52_BIT_VAL )
        {
            unsigned long gfn;

            /*
             * The GFN must be rearranged according to the following format of
             * the PTE bits [pte<15:12>:pte<47:16>:0000].
             */
            gfn = ((unsigned long)(pte.walk.base & 0xf) << 36) |
                  (pte.walk.base & ~0xf);

            page = get_page_from_gfn(d, gfn, NULL, P2M_ALLOC);
        }
        else
#endif
            page = get_page_from_gfn(d, pte.walk.base, NULL, P2M_ALLOC);

        if ( !page )
            return -EFAULT;

        table = __map_domain_page(page);
    }

    if ( !p2m_valid(pte) || ((level == 3) && !p2m_table(pte)) )
        return -EFAULT;

#ifdef CONFIG_ARM_64
    if ( output_size == TCR_EL1_IPS_52_BIT_VAL )
    {
        unsigned long gfn;

        /*
         * The GFN must be rearranged according to the following format of the
         * PTE bits [pte<15:12>:pte<47:16>:0000].
         */
        gfn = ((unsigned long)(pte.walk.base & 0xf) << 36) |
              (pte.walk.base & ~0xf);

        *ipa = pfn_to_paddr(gfn) | (gva & masks[level][gran]);
    }
    else
#endif
        *ipa = pfn_to_paddr(pte.walk.base) | (gva & masks[level][gran]);

    /*
     * Set permissions so that the caller can check the flags by herself. Note
     * that stage 1 translations also inherit attributes from the tables
     * (ARM DDI 0487B-a J1-5928).
     */
    if ( !pte.pt.ro && !ro_table )
        *perms = GV2M_WRITE;
    if ( !pte.pt.xn && !xn_table )
        *perms |= GV2M_EXEC;

    return 0;
}

int guest_walk_tables(const struct vcpu *v, vaddr_t gva,
                      paddr_t *ipa, unsigned int *perms)
{
    uint32_t sctlr = READ_SYSREG(SCTLR_EL1);
    register_t tcr = READ_SYSREG(TCR_EL1);
    struct domain *d = v->domain;
    unsigned int _perms = GV2M_READ;

    /* We assume that the domain is running on the currently active domain. */
    if ( v != current )
        return -EFAULT;

    /* Allow perms to be NULL. */
    perms = perms ?: &_perms;

    /* If the MMU is disabled, there is no need to translate the gva. */
    if ( !(sctlr & SCTLR_M) )
    {
        *ipa = gva;

        /* Memory can be accessed without any restrictions. */
        *perms = GV2M_READ|GV2M_WRITE|GV2M_EXEC;

        return 0;
    }

    if ( is_32bit_domain(d) )
    {
        if ( !(tcr & TTBCR_EAE) )
            return guest_walk_sd(d, gva, ipa, perms);
    }

    return guest_walk_ld(d, gva, ipa, perms);
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
