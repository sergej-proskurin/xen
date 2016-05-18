/*
 * include/asm-arm/hvm/hvm.h
 *
 * Copyright (c) 2005, Sergej Proskurin <proskurin@sec.in.tum.de>
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

#ifndef __ASM_ARM_HVM_HVM_H__
#define __ASM_ARM_HVM_HVM_H__

#include <xen/sched.h>

void altp2m_vcpu_update_p2m(struct vcpu *v);

#endif /* __ASM_ARM_HVM_HVM_H__ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
