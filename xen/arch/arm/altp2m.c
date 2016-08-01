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
