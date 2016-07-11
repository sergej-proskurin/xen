#ifndef __ASM_ARM_FLUSHTLB_H__
#define __ASM_ARM_FLUSHTLB_H__

#include <xen/cpumask.h>
/* TEST */
struct p2m_domain;
/* TEST END */

/*
 * Filter the given set of CPUs, removing those that definitely flushed their
 * TLB since @page_timestamp.
 */
/* XXX lazy implementation just doesn't clear anything.... */
#define tlbflush_filter(mask, page_timestamp)                           \
do {                                                                    \
} while ( 0 )

#define tlbflush_current_time()                 (0)

#if defined(CONFIG_ARM_32)
# include <asm/arm32/flushtlb.h>
#elif defined(CONFIG_ARM_64)
# include <asm/arm64/flushtlb.h>
#else
# error "unknown ARM variant"
#endif

/* Flush specified CPUs' TLBs */
void flush_tlb_mask(const cpumask_t *mask);

/* Flush CPU's TLBs for the specified domain */
void flush_tlb_domain(struct domain *d);
void flush_tlb_p2m(struct domain*d, struct p2m_domain *p2m);

#endif /* __ASM_ARM_FLUSHTLB_H__ */
/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
