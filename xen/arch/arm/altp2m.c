/*
 * arch/arm/altp2m.c
 *
 * Alternate p2m
 * Copyright (c) 2016 Sergej Proskurin <proskurin@sec.in.tum.de>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License, version 2,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; If not, see <http://www.gnu.org/licenses/>.
 */

#include <asm/p2m.h>
#include <asm/altp2m.h>
#include <asm/flushtlb.h>

struct p2m_domain *altp2m_get_altp2m(struct vcpu *v)
{
    unsigned int index = vcpu_altp2m(v).p2midx;

    if ( index == INVALID_ALTP2M )
        return NULL;

    BUG_ON(index >= MAX_ALTP2M);

    return v->domain->arch.altp2m_p2m[index];
}

bool_t altp2m_switch_vcpu_altp2m_by_id(struct vcpu *v, unsigned int idx)
{
    struct domain *d = v->domain;
    bool_t rc = 0;

    if ( idx >= MAX_ALTP2M )
        return rc;

    altp2m_lock(d);

    if ( d->arch.altp2m_vttbr[idx] != INVALID_VTTBR )
    {
        if ( idx != vcpu_altp2m(v).p2midx )
        {
            atomic_dec(&altp2m_get_altp2m(v)->active_vcpus);
            vcpu_altp2m(v).p2midx = idx;
            atomic_inc(&altp2m_get_altp2m(v)->active_vcpus);
        }
        rc = 1;
    }

    altp2m_unlock(d);

    return rc;
}

int altp2m_switch_domain_altp2m_by_id(struct domain *d, unsigned int idx)
{
    struct vcpu *v;
    int rc = -EINVAL;

    if ( idx >= MAX_ALTP2M )
        return rc;

    domain_pause_except_self(d);

    altp2m_lock(d);

    if ( d->arch.altp2m_vttbr[idx] != INVALID_VTTBR )
    {
        for_each_vcpu( d, v )
            if ( idx != vcpu_altp2m(v).p2midx )
            {
                atomic_dec(&altp2m_get_altp2m(v)->active_vcpus);
                vcpu_altp2m(v).p2midx = idx;
                atomic_inc(&altp2m_get_altp2m(v)->active_vcpus);
            }

        rc = 0;
    }

    altp2m_unlock(d);

    domain_unpause_except_self(d);

    return rc;
}

int altp2m_set_mem_access(struct domain *d,
                          struct p2m_domain *hp2m,
                          struct p2m_domain *ap2m,
                          p2m_access_t a,
                          gfn_t gfn)
{
    p2m_type_t p2mt;
    xenmem_access_t xma_old;
    paddr_t gpa = pfn_to_paddr(gfn_x(gfn));
    mfn_t mfn;
    unsigned int level;
    int rc;

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

    altp2m_lock(d);

    /* Check if entry is part of the altp2m view. */
    mfn = p2m_lookup_attr(ap2m, gfn, &p2mt, &level, NULL, NULL);

    /* Check host p2m if no valid entry in ap2m. */
    if ( mfn_eq(mfn, INVALID_MFN) )
    {
        /* Check if entry is part of the host p2m view. */
        mfn = p2m_lookup_attr(hp2m, gfn, &p2mt, &level, NULL, &xma_old);
        if ( mfn_eq(mfn, INVALID_MFN) || p2mt != p2m_ram_rw )
        {
            rc = -ESRCH;
            goto out;
        }

        /* If this is a superpage, copy that first. */
        if ( level != 3 )
        {
            rc = modify_altp2m_entry(d, ap2m, gpa, pfn_to_paddr(mfn_x(mfn)),
                                     level, p2mt, memaccess[xma_old]);
            if ( rc < 0 )
            {
                rc = -ESRCH;
                goto out;
            }
        }
    }

    /* Set mem access attributes - currently supporting only one (4K) page. */
    level = 3;
    rc = modify_altp2m_entry(d, ap2m, gpa, pfn_to_paddr(mfn_x(mfn)),
                             level, p2mt, a);

out:
    altp2m_unlock(d);

    return rc;
}

bool_t altp2m_lazy_copy(struct vcpu *v,
                        paddr_t gpa,
                        unsigned long gva,
                        struct npfec npfec,
                        struct p2m_domain **ap2m)
{
    struct domain *d = v->domain;
    struct p2m_domain *hp2m = p2m_get_hostp2m(v->domain);
    p2m_type_t p2mt;
    xenmem_access_t xma;
    gfn_t gfn = _gfn(paddr_to_pfn(gpa));
    mfn_t mfn;
    unsigned int level;
    int rc = 0;

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

    *ap2m = altp2m_get_altp2m(v);
    if ( *ap2m == NULL)
        return 0;

    /* Check if entry is part of the altp2m view */
    mfn = p2m_lookup_attr(*ap2m, gfn, NULL, NULL, NULL, NULL);
    if ( !mfn_eq(mfn, INVALID_MFN) )
        goto out;

    /* Check if entry is part of the host p2m view */
    mfn = p2m_lookup_attr(hp2m, gfn, &p2mt, &level, NULL, &xma);
    if ( mfn_eq(mfn, INVALID_MFN) )
        goto out;

    rc = modify_altp2m_entry(d, *ap2m, gpa, pfn_to_paddr(mfn_x(mfn)), level,
                             p2mt, memaccess[xma]);
    if ( rc )
    {
        gdprintk(XENLOG_ERR, "failed to set entry for %lx -> %lx p2m %lx\n",
                (unsigned long)gpa, (unsigned long)(paddr_to_pfn(mfn_x(mfn))),
                (unsigned long)*ap2m);
        domain_crash(hp2m->domain);
    }

    rc = 1;

out:
    return rc;
}

static inline void altp2m_reset(struct p2m_domain *p2m)
{
    read_lock(&p2m->lock);

    p2m_flush_table(p2m);
    p2m_flush_tlb(p2m);

    p2m->lowest_mapped_gfn = INVALID_GFN;
    p2m->max_mapped_gfn = _gfn(0);

    read_unlock(&p2m->lock);
}

void altp2m_propagate_change(struct domain *d,
                             gfn_t sgfn,
                             unsigned long nr,
                             mfn_t smfn,
                             uint32_t mask,
                             p2m_type_t p2mt,
                             p2m_access_t p2ma)
{
    struct p2m_domain *p2m;
    mfn_t m;
    unsigned int i;
    unsigned int reset_count = 0;
    unsigned int last_reset_idx = ~0;

    if ( !altp2m_active(d) )
        return;

    altp2m_lock(d);

    for ( i = 0; i < MAX_ALTP2M; i++ )
    {
        if ( d->arch.altp2m_vttbr[i] == INVALID_VTTBR )
            continue;

        p2m = d->arch.altp2m_p2m[i];

        m = p2m_lookup_attr(p2m, sgfn, NULL, NULL, NULL, NULL);

        /* Check for a dropped page that may impact this altp2m. */
        if ( (mfn_eq(smfn, INVALID_MFN) || p2mt == p2m_invalid) &&
             gfn_x(sgfn) >= gfn_x(p2m->lowest_mapped_gfn) &&
             gfn_x(sgfn) <= gfn_x(p2m->max_mapped_gfn) )
        {
            if ( !reset_count++ )
            {
                altp2m_reset(p2m);
                last_reset_idx = i;
            }
            else
            {
                /* At least 2 altp2m's impacted, so reset everything. */
                for ( i = 0; i < MAX_ALTP2M; i++ )
                {
                    if ( i == last_reset_idx ||
                         d->arch.altp2m_vttbr[i] == INVALID_VTTBR )
                        continue;

                    p2m = d->arch.altp2m_p2m[i];
                    altp2m_reset(p2m);
                }
                goto out;
            }
        }
        else if ( !mfn_eq(m, INVALID_MFN) )
            modify_altp2m_range(d, p2m, sgfn, nr, smfn,
                                mask, p2mt, p2ma);
    }

out:
    altp2m_unlock(d);
}

static void altp2m_vcpu_reset(struct vcpu *v)
{
    struct altp2mvcpu *av = &vcpu_altp2m(v);

    av->p2midx = INVALID_ALTP2M;
}

void altp2m_vcpu_initialise(struct vcpu *v)
{
    if ( v != current )
        vcpu_pause(v);

    altp2m_vcpu_reset(v);
    vcpu_altp2m(v).p2midx = 0;
    atomic_inc(&altp2m_get_altp2m(v)->active_vcpus);

    if ( v != current )
        vcpu_unpause(v);
}

void altp2m_vcpu_destroy(struct vcpu *v)
{
    struct p2m_domain *p2m;

    if ( v != current )
        vcpu_pause(v);

    if ( (p2m = altp2m_get_altp2m(v)) )
        atomic_dec(&p2m->active_vcpus);

    altp2m_vcpu_reset(v);

    if ( v != current )
        vcpu_unpause(v);
}

static int altp2m_init_helper(struct domain *d, unsigned int idx)
{
    int rc;
    struct p2m_domain *p2m = d->arch.altp2m_p2m[idx];

    if ( p2m == NULL )
    {
        /* Allocate a new, zeroed altp2m view. */
        p2m = xzalloc(struct p2m_domain);
        if ( p2m == NULL)
        {
            rc = -ENOMEM;
            goto err;
        }
    }

    /* Initialize the new altp2m view. */
    rc = p2m_init_one(d, p2m);
    if ( rc )
        goto err;

    /* Allocate a root table for the altp2m view. */
    rc = p2m_alloc_table(p2m);
    if ( rc )
        goto err;

    p2m->p2m_class = p2m_alternate;
    p2m->access_required = 1;
    _atomic_set(&p2m->active_vcpus, 0);

    d->arch.altp2m_p2m[idx] = p2m;
    d->arch.altp2m_vttbr[idx] = p2m->vttbr.vttbr;

    /*
     * Make sure that all TLBs corresponding to the current VMID are flushed
     * before using it.
     */
    p2m_flush_tlb(p2m);

    return rc;

err:
    if ( p2m )
        xfree(p2m);

    d->arch.altp2m_p2m[idx] = NULL;

    return rc;
}

int altp2m_init_by_id(struct domain *d, unsigned int idx)
{
    int rc = -EINVAL;

    if ( idx >= MAX_ALTP2M )
        return rc;

    altp2m_lock(d);

    if ( d->arch.altp2m_vttbr[idx] == INVALID_VTTBR )
        rc = altp2m_init_helper(d, idx);

    altp2m_unlock(d);

    return rc;
}

int altp2m_init_next(struct domain *d, uint16_t *idx)
{
    int rc = -EINVAL;
    unsigned int i;

    altp2m_lock(d);

    for ( i = 0; i < MAX_ALTP2M; i++ )
    {
        if ( d->arch.altp2m_vttbr[i] != INVALID_VTTBR )
            continue;

        rc = altp2m_init_helper(d, i);
        *idx = (uint16_t) i;

        break;
    }

    altp2m_unlock(d);

    return rc;
}

int altp2m_init(struct domain *d)
{
    unsigned int i;

    spin_lock_init(&d->arch.altp2m_lock);

    for ( i = 0; i < MAX_ALTP2M; i++ )
    {
        d->arch.altp2m_p2m[i] = NULL;
        d->arch.altp2m_vttbr[i] = INVALID_VTTBR;
    }

    return 0;
}

void altp2m_flush(struct domain *d)
{
    unsigned int i;
    struct p2m_domain *p2m;

    /*
     * If altp2m is active, we are not allowed to flush altp2m[0]. This special
     * view is considered as the hostp2m as long as altp2m is active.
     */
    ASSERT(!altp2m_active(d));

    altp2m_lock(d);

    for ( i = 0; i < MAX_ALTP2M; i++ )
    {
        if ( d->arch.altp2m_vttbr[i] == INVALID_VTTBR )
            continue;

        p2m = d->arch.altp2m_p2m[i];

        read_lock(&p2m->lock);

        p2m_flush_table(p2m);

        /*
         * Reset VTTBR.
         *
         * Note that VMID is not freed so that it can be reused later.
         */
        p2m->vttbr.vttbr = INVALID_VTTBR;
        d->arch.altp2m_vttbr[i] = INVALID_VTTBR;

        read_unlock(&p2m->lock);
    }

    altp2m_unlock(d);
}

int altp2m_destroy_by_id(struct domain *d, unsigned int idx)
{
    struct p2m_domain *p2m;
    int rc = -EBUSY;

    /*
     * The altp2m[0] is considered as the hostp2m and is used as a safe harbor
     * to which you can switch as long as altp2m is active. After deactivating
     * altp2m, the system switches back to the original hostp2m view. That is,
     * altp2m[0] should only be destroyed/flushed/freed, when altp2m is
     * deactivated.
     */
    if ( !idx || idx >= MAX_ALTP2M )
        return rc;

    domain_pause_except_self(d);

    altp2m_lock(d);

    if ( d->arch.altp2m_vttbr[idx] != INVALID_VTTBR )
    {
        p2m = d->arch.altp2m_p2m[idx];

        if ( !_atomic_read(p2m->active_vcpus) )
        {
            read_lock(&p2m->lock);

            p2m_flush_table(p2m);

            /*
             * Reset VTTBR.
             *
             * Note that VMID is not freed so that it can be reused later.
             */
            p2m->vttbr.vttbr = INVALID_VTTBR;
            d->arch.altp2m_vttbr[idx] = INVALID_VTTBR;

            read_unlock(&p2m->lock);

            rc = 0;
        }
    }

    altp2m_unlock(d);

    domain_unpause_except_self(d);

    return rc;
}

void altp2m_teardown(struct domain *d)
{
    unsigned int i;
    struct p2m_domain *p2m;

    altp2m_lock(d);

    for ( i = 0; i < MAX_ALTP2M; i++ )
    {
        if ( !d->arch.altp2m_p2m[i] )
            continue;

        p2m = d->arch.altp2m_p2m[i];
        p2m_free_one(p2m);
        xfree(p2m);

        d->arch.altp2m_vttbr[i] = INVALID_VTTBR;
        d->arch.altp2m_p2m[i] = NULL;
    }

    d->arch.altp2m_active = false;

    altp2m_unlock(d);
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
