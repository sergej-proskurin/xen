#ifndef _XEN_GUEST_WALK_H
#define _XEN_GUEST_WALK_H

/* Normalized page granule size indices. */
#define GRANULE_SIZE_INDEX_4K               (0)
#define GRANULE_SIZE_INDEX_16K              (1)
#define GRANULE_SIZE_INDEX_64K              (2)

/* Represent whether TTBR0 or TTBR1 is valid. */
#define TTBR0_VALID                         (0)
#define TTBR1_VALID                         (1)

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
