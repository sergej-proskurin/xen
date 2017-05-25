#ifndef _XEN_GUEST_WALK_H
#define _XEN_GUEST_WALK_H

/* First level translation table descriptor types used by the AArch32
 * short-descriptor translation table format. */
#define L1DESC_INVALID                      (0)
#define L1DESC_PAGE_TABLE                   (1)
#define L1DESC_SECTION                      (2)
#define L1DESC_SECTION_PXN                  (3)

/* Defines for section and supersection shifts. */
#define L1DESC_SECTION_SHIFT                (20)
#define L1DESC_SUPERSECTION_SHIFT           (24)
#define L1DESC_SUPERSECTION_EXT_BASE1_SHIFT (32)
#define L1DESC_SUPERSECTION_EXT_BASE2_SHIFT (36)

/* Second level translation table descriptor types. */
#define L2DESC_INVALID                      (0)

/* Walk the guest's page tables in software. */
int guest_walk_tables(const struct vcpu *v,
                      vaddr_t gva,
                      paddr_t *ipa,
                      unsigned int *perms);

#endif /* _XEN_GUEST_WALK_H */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
