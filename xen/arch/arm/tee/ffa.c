/* SPDX-License-Identifier: GPL-2.0 */
/*
 * xen/arch/arm/tee/ffa.c
 *
 * Arm Firmware Framework for ARMv8-A (FF-A) mediator
 *
 * Copyright (C) 2023  Linaro Limited
 */

#include <xen/domain_page.h>
#include <xen/errno.h>
#include <xen/init.h>
#include <xen/lib.h>
#include <xen/sched.h>
#include <xen/types.h>
#include <xen/sizes.h>
#include <xen/bitops.h>

#include <asm/smccc.h>
#include <asm/event.h>
#include <asm/tee/tee.h>
#include <asm/tee/ffa.h>
#include <asm/regs.h>

/* Error codes */
#define FFA_RET_OK                      0
#define FFA_RET_NOT_SUPPORTED           -1
#define FFA_RET_INVALID_PARAMETERS      -2
#define FFA_RET_NO_MEMORY               -3
#define FFA_RET_BUSY                    -4
#define FFA_RET_INTERRUPTED             -5
#define FFA_RET_DENIED                  -6
#define FFA_RET_RETRY                   -7
#define FFA_RET_ABORTED                 -8

/* FFA_VERSION helpers */
#define FFA_VERSION_MAJOR_SHIFT         16U
#define FFA_VERSION_MAJOR_MASK          0x7FFFU
#define FFA_VERSION_MINOR_SHIFT         0U
#define FFA_VERSION_MINOR_MASK          0xFFFFU
#define MAKE_FFA_VERSION(major, minor)  \
        ((((major) & FFA_VERSION_MAJOR_MASK) << FFA_VERSION_MAJOR_SHIFT) | \
         ((minor) & FFA_VERSION_MINOR_MASK))

#define FFA_MIN_VERSION         MAKE_FFA_VERSION(1, 0)
#define FFA_VERSION_1_0         MAKE_FFA_VERSION(1, 0)
#define FFA_VERSION_1_1         MAKE_FFA_VERSION(1, 1)

/*
 * This is the version we want to use in communication with guests and SPs.
 * During negotiation with a guest or a SP we may need to lower it for
 * that particular guest or SP.
 */
#define FFA_MY_VERSION_MAJOR    1U
#define FFA_MY_VERSION_MINOR    1U
#define FFA_MY_VERSION          MAKE_FFA_VERSION(FFA_MY_VERSION_MAJOR, \
                                                 FFA_MY_VERSION_MINOR)

/* Function IDs */
#define FFA_ERROR                       0x84000060U
#define FFA_SUCCESS_32                  0x84000061U
#define FFA_VERSION                     0x84000063U

struct ffa_ctx {
    uint32_t guest_vers;
};

/* Negotiated FF-A version to use with the SPMC */
static uint32_t ffa_version __ro_after_init;

static bool ffa_get_version(uint32_t *vers)
{
    const struct arm_smccc_1_2_regs arg = {
        .a0 = FFA_VERSION,
        .a1 = FFA_MY_VERSION,
    };
    struct arm_smccc_1_2_regs resp;

    arm_smccc_1_2_smc(&arg, &resp);
    if ( resp.a0 == FFA_RET_NOT_SUPPORTED )
    {
        gprintk(XENLOG_ERR, "ffa: FFA_VERSION returned not supported\n");
        return false;
    }

    *vers = resp.a0;

    return true;
}

static void set_regs(struct cpu_user_regs *regs, register_t v0, register_t v1,
                     register_t v2, register_t v3, register_t v4, register_t v5,
                     register_t v6, register_t v7)
{
        set_user_reg(regs, 0, v0);
        set_user_reg(regs, 1, v1);
        set_user_reg(regs, 2, v2);
        set_user_reg(regs, 3, v3);
        set_user_reg(regs, 4, v4);
        set_user_reg(regs, 5, v5);
        set_user_reg(regs, 6, v6);
        set_user_reg(regs, 7, v7);
}

static void handle_version(struct cpu_user_regs *regs)
{
    struct domain *d = current->domain;
    struct ffa_ctx *ctx = d->arch.tee;
    uint32_t vers = get_user_reg(regs, 1);

    if ( vers < FFA_VERSION_1_1 )
        vers = FFA_VERSION_1_0;
    else
        vers = FFA_VERSION_1_1;

    ctx->guest_vers = vers;
    set_regs(regs, vers, 0, 0, 0, 0, 0, 0, 0);
}

static bool ffa_handle_call(struct cpu_user_regs *regs)
{
    uint32_t fid = get_user_reg(regs, 0);
    struct domain *d = current->domain;
    struct ffa_ctx *ctx = d->arch.tee;

    if ( !ctx )
        return false;

    switch ( fid )
    {
    case FFA_VERSION:
        handle_version(regs);
        return true;

    default:
        gprintk(XENLOG_ERR, "ffa: unhandled fid 0x%x\n", fid);
        return false;
    }
}

static int ffa_domain_init(struct domain *d)
{
    struct ffa_ctx *ctx;

    if ( !ffa_version )
        return -ENODEV;

    ctx = xzalloc(struct ffa_ctx);
    if ( !ctx )
        return -ENOMEM;

    d->arch.tee = ctx;

    return 0;
}

/* This function is supposed to undo what ffa_domain_init() has done */
static int ffa_relinquish_resources(struct domain *d)
{
    struct ffa_ctx *ctx = d->arch.tee;

    if ( !ctx )
        return 0;

    XFREE(d->arch.tee);

    return 0;
}

static bool ffa_probe(void)
{
    uint32_t vers;
    unsigned int major_vers;
    unsigned int minor_vers;

    /*
     * psci_init_smccc() updates this value with what's reported by EL-3
     * or secure world.
     */
    if ( smccc_ver < ARM_SMCCC_VERSION_1_2 )
    {
        printk(XENLOG_ERR
               "ffa: unsupported SMCCC version %#x (need at least %#x)\n",
               smccc_ver, ARM_SMCCC_VERSION_1_2);
        return false;
    }

    if ( !ffa_get_version(&vers) )
        return false;

    if ( vers < FFA_MIN_VERSION || vers > FFA_MY_VERSION )
    {
        printk(XENLOG_ERR "ffa: Incompatible version %#x found\n", vers);
        return false;
    }

    major_vers = (vers >> FFA_VERSION_MAJOR_SHIFT) & FFA_VERSION_MAJOR_MASK;
    minor_vers = vers & FFA_VERSION_MINOR_MASK;
    printk(XENLOG_INFO "ARM FF-A Mediator version %u.%u\n",
           FFA_MY_VERSION_MAJOR, FFA_MY_VERSION_MINOR);
    printk(XENLOG_INFO "ARM FF-A Firmware version %u.%u\n",
           major_vers, minor_vers);

    ffa_version = vers;

    return true;
}

static const struct tee_mediator_ops ffa_ops =
{
    .probe = ffa_probe,
    .domain_init = ffa_domain_init,
    .relinquish_resources = ffa_relinquish_resources,
    .handle_call = ffa_handle_call,
};

REGISTER_TEE_MEDIATOR(ffa, "FF-A", XEN_DOMCTL_CONFIG_TEE_FFA, &ffa_ops);
