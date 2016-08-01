#ifndef __ARM_CPUERRATA_H__
#define __ARM_CPUERRATA_H__

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

CHECK_WORKAROUND_HELPER(766422, ARM32_WORKAROUND_766422, CONFIG_ARM_32)

#undef CHECK_WORKAROUND_HELPER

#endif /* __ARM_CPUERRATA_H__ */
/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
