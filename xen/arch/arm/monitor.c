/*
 * arch/arm/monitor.c
 *
 * Arch-specific monitor_op domctl handler.
 *
 * Copyright (c) 2016 Tamas K Lengyel (tamas.lengyel@zentific.com)
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

#include <xen/vm_event.h>
#include <xen/monitor.h>
#include <asm/monitor.h>
#include <asm/vm_event.h>
#include <public/vm_event.h>

int arch_monitor_domctl_event(struct domain *d,
                              struct xen_domctl_monitor_op *mop)
{
    struct arch_domain *ad = &d->arch;
    bool_t requested_status = (XEN_DOMCTL_MONITOR_OP_ENABLE == mop->op);

    switch ( mop->event )
    {
    case XEN_DOMCTL_MONITOR_EVENT_SINGLESTEP:
    {
        uint32_t mdscr;
        bool_t old_status = ad->monitor.singlestep_enabled;
        struct cpu_user_regs *regs = guest_cpu_user_regs();

        if ( unlikely(old_status == requested_status) )
            return -EEXIST;

        /* XXX: Do we actually need to pause the domain? */
        domain_pause(d);

        ad->monitor.singlestep_enabled = requested_status;

        /*
         * TODO: We need a dynamic activation of routing of debug exceptions to
         * the hypervisor. The current solution simply sets the MDCR_EL2.TDE
         * bit without disabling it.
         */

#define MDSCR_EL1_SS    (1 << 0)
#define SPSR_EL2_SS     (1 << 21)

        mdscr = READ_SYSREG(MDSCR_EL1);

        if ( requested_status )
        {
            mdscr |= MDSCR_EL1_SS;
            regs->cpsr |= SPSR_EL2_SS;
        }
        else
        {
            mdscr &= ~MDSCR_EL1_SS;
            regs->cpsr &= ~SPSR_EL2_SS;
        }

        WRITE_SYSREG(mdscr, MDSCR_EL1);

        domain_unpause(d);

        break;
    }

    case XEN_DOMCTL_MONITOR_EVENT_PRIVILEGED_CALL:
    {
        bool_t old_status = ad->monitor.privileged_call_enabled;

        if ( unlikely(old_status == requested_status) )
            return -EEXIST;

        domain_pause(d);
        ad->monitor.privileged_call_enabled = requested_status;
        domain_unpause(d);
        break;
    }

    default:
        /*
         * Should not be reached unless arch_monitor_get_capabilities() is
         * not properly implemented.
         */
        ASSERT_UNREACHABLE();
        return -EOPNOTSUPP;
    }

    return 0;
}

int monitor_smc(void)
{
    vm_event_request_t req = {
        .reason = VM_EVENT_REASON_PRIVILEGED_CALL
    };

    return monitor_traps(current, 1, &req);
}

int monitor_ss(void)
{
    vm_event_request_t req = {
        .reason = VM_EVENT_REASON_SINGLESTEP
    };

    return monitor_traps(current, 1, &req);
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
