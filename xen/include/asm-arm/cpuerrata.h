#ifndef __ARM_CPUERRATA_H
#define __ARM_CPUERRATA_H

#include <xen/config.h>
#include <asm/cpufeature.h>
#include <asm/alternative.h>

void check_local_cpu_errata(void);

#ifdef CONFIG_ALTERNATIVE

#define CHECK_WORKAROUND_HELPER(erratum, feature, arch)         \
static inline bool_t check_workaround_##erratum(void)           \
{                                                               \
    if ( !IS_ENABLED(arch) )                                    \
        return 0;                                               \
    else                                                        \
    {                                                           \
        bool_t ret;                                             \
                                                                \
        asm volatile (ALTERNATIVE("mov %0, #0",                 \
                                  "mov %0, #1",                 \
                                  feature)                      \
                      : "=r" (ret));                            \
                                                                \
        return unlikely(ret);                                   \
    }                                                           \
}

#else /* CONFIG_ALTERNATIVE */

#define CHECK_WORKAROUND_HELPER(erratum, feature, arch)         \
static inline bool_t check_workaround_##erratum(void)           \
{                                                               \
    if ( !IS_ENABLED(arch) )                                    \
        return 0;                                               \
    else                                                        \
        return unlikely(cpus_have_cap(feature));                \
}

#endif

#undef CHECK_WORKAROUND_HELPER

#endif /* __ARM_CPUERRATA_H */
/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
