/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2024  Linaro Limited
 */

#include <xen/const.h>
#include <xen/list.h>
#include <xen/spinlock.h>
#include <xen/types.h>

#include <asm/smccc.h>
#include <asm/regs.h>

#include "ffa_private.h"

void ffa_handle_notification_bind(struct cpu_user_regs *regs)
{
    struct domain *d = current->domain;
    uint32_t src_dst = get_user_reg(regs, 1);
    int e;

    if ( !notif_enabled )
    {
        ffa_set_regs_error(regs, FFA_RET_NOT_SUPPORTED);
        return;
    }

    if ( (src_dst & 0xffff) != ffa_get_vm_id(d) )
    {
        ffa_set_regs_error(regs, FFA_RET_INVALID_PARAMETERS);
        return;
    }

    if ( get_user_reg(regs, 2) )
    {
        /* Only global notifications are supported */
        ffa_set_regs_error(regs, FFA_RET_DENIED);
        return;
    }

    /*
     * We only support notifications from SP so no need to check the sender
     * endpoint ID, the SPMC will take care of that for us.
     */
    e = ffa_simple_call(FFA_NOTIFICATION_BIND, src_dst, get_user_reg(regs, 2),
                          get_user_reg(regs, 3), get_user_reg(regs, 4));
    if ( e )
        ffa_set_regs_error(regs, e);
    else
        ffa_set_regs_success(regs, 0, 0);
}

void ffa_handle_notification_unbind(struct cpu_user_regs *regs)
{
    struct domain *d = current->domain;
    uint32_t src_dst = get_user_reg(regs, 1);
    int e;

    if ( !notif_enabled )
    {
        ffa_set_regs_error(regs, FFA_RET_NOT_SUPPORTED);
        return;
    }

    if ( (src_dst & 0xffff) != ffa_get_vm_id(d) )
    {
        ffa_set_regs_error(regs, FFA_RET_INVALID_PARAMETERS);
        return;
    }

    /*
     * We only support notifications from SP so no need to check the sender
     * endpoint ID, the SPMC will take care of that for us.
     */
    e = ffa_simple_call(FFA_NOTIFICATION_UNBIND, src_dst, get_user_reg(regs, 2),
                          get_user_reg(regs, 3), get_user_reg(regs, 4));
    if ( e )
        ffa_set_regs_error(regs, e);
    else
        ffa_set_regs_success(regs, 0, 0);
}

void ffa_handle_notification_info_get(struct cpu_user_regs *regs)
{
    struct domain *d = current->domain;
    struct ffa_ctx *ctx = d->arch.tee;
    bool pending_global;

    if ( !notif_enabled )
    {
        ffa_set_regs_error(regs, FFA_RET_NOT_SUPPORTED);
        return;
    }

    spin_lock(&ctx->notif->lock);
    pending_global = ctx->notif->spm_pending;
    ctx->notif->spm_pending = false;
    spin_unlock(&ctx->notif->lock);

    if ( pending_global )
    {
        /* A pending global notification for the guest */
        ffa_set_regs(regs, FFA_SUCCESS_64, 0,
                     1U << FFA_NOTIF_INFO_GET_ID_COUNT_SHIFT, ffa_get_vm_id(d),
                     0, 0, 0, 0);
    }
    else
    {
        /* Report an error if there where no pending global notification */
        ffa_set_regs_error(regs, FFA_RET_NO_DATA);
    }
}

void ffa_handle_notification_get(struct cpu_user_regs *regs)
{
    struct domain *d = current->domain;
    uint32_t recv = get_user_reg(regs, 1);
    uint32_t flags = get_user_reg(regs, 2);
    uint32_t spm_flags = FFA_NOTIF_FLAG_BITMAP_SP | FFA_NOTIF_FLAG_BITMAP_SPM;
    uint32_t w2 = 0;
    uint32_t w3 = 0;
    uint32_t w4 = 0;
    uint32_t w5 = 0;
    uint32_t w6 = 0;
    uint32_t w7 = 0;

    if ( !notif_enabled )
    {
        ffa_set_regs_error(regs, FFA_RET_NOT_SUPPORTED);
        return;
    }

    if ( (recv & 0xffff) != ffa_get_vm_id(d) )
    {
        ffa_set_regs_error(regs, FFA_RET_INVALID_PARAMETERS);
        return;
    }

    if ( flags & spm_flags )
    {
        struct arm_smccc_1_2_regs arg = {
            .a0 = FFA_NOTIFICATION_GET,
            .a1 = recv,
            .a2 = flags & spm_flags,
        };
        struct arm_smccc_1_2_regs resp;
        int32_t e;

        arm_smccc_1_2_smc(&arg, &resp);
        e = ffa_get_ret_code(&resp);
        if ( e )
        {
            ffa_set_regs_error(regs, e);
            return;
        }

        if ( flags & FFA_NOTIF_FLAG_BITMAP_SP )
        {
            w2 = resp.a2;
            w3 = resp.a3;
        }

        if ( flags & FFA_NOTIF_FLAG_BITMAP_SPM )
            w6 = resp.a6;
    }

    ffa_set_regs(regs, FFA_SUCCESS_32, 0, w2, w3, w4, w5, w6, w7);
}

void ffa_handle_notification_set(struct cpu_user_regs *regs)
{
    struct domain *d = current->domain;
    uint32_t src_dst = get_user_reg(regs, 1);
    int e;

    if ( !notif_enabled )
    {
        ffa_set_regs_error(regs, FFA_RET_NOT_SUPPORTED);
        return;
    }

    if ( (src_dst >> 16) != ffa_get_vm_id(d) )
    {
        ffa_set_regs_error(regs, FFA_RET_INVALID_PARAMETERS);
        return;
    }

    /*
     * We only support notifications from SP so no need to check the sender
     * endpoint ID, the SPMC will take care of that for us.
     */
    e = ffa_simple_call(FFA_NOTIFICATION_SET, src_dst, get_user_reg(regs, 2),
                          get_user_reg(regs, 3), get_user_reg(regs, 4));
    if ( e )
        ffa_set_regs_error(regs, e);
    else
        ffa_set_regs_success(regs, 0, 0);
}

static uint16_t get_id_from_resp(struct arm_smccc_1_2_regs *resp,
                                 unsigned int n)
{
    unsigned int ids_per_reg;
    unsigned int reg_idx;
    unsigned int reg_shift;

    if ( smccc_is_conv_64(resp->a0) )
        ids_per_reg = 4;
    else
        ids_per_reg = 2;

    reg_idx = n / ids_per_reg + 3;
    reg_shift = ( n % ids_per_reg ) * 16;

    switch ( reg_idx )
    {
    case 3:
        return resp->a3 >> reg_shift;
    case 4:
        return resp->a4 >> reg_shift;
    case 5:
        return resp->a5 >> reg_shift;
    case 6:
        return resp->a6 >> reg_shift;
    case 7:
        return resp->a7 >> reg_shift;
    default:
        ASSERT(0); /* "Can't happen" */
        return 0;
    }
}

void ffa_notif_irq_handler(int irq, void *data, struct cpu_user_regs *regs)
{
    const struct arm_smccc_1_2_regs arg = {
        .a0 = FFA_NOTIFICATION_INFO_GET_64,
    };
    struct arm_smccc_1_2_regs resp;
    unsigned int id_pos;
    unsigned int list_count;
    uint64_t ids_count;
    unsigned int n;
    int32_t res;

    do {
        arm_smccc_1_2_smc(&arg, &resp);
        res = ffa_get_ret_code(&resp);
        if ( res )
        {
            if ( res != FFA_RET_NO_DATA )
                printk(XENLOG_ERR "ffa: notification info get failed: error %d\n",
                       res);
            return;
        }

        ids_count = resp.a2 >> FFA_NOTIF_INFO_GET_ID_LIST_SHIFT;
        list_count = ( resp.a2 >> FFA_NOTIF_INFO_GET_ID_COUNT_SHIFT ) &
                     FFA_NOTIF_INFO_GET_ID_COUNT_MASK;

        id_pos = 0;
        for ( n = 0; n < list_count; n++ )
        {
            unsigned int count = ((ids_count >> 2 * n) & 0x3) + 1;
            struct domain *d;

            d = ffa_get_domain_by_vm_id(get_id_from_resp(&resp, id_pos));

            if ( d )
            {
                struct ffa_ctx *ctx = d->arch.tee;

                spin_lock(&ctx->notif->lock);

                if ( count == 1 )
                    ctx->notif->spm_pending = true;

                spin_unlock(&ctx->notif->lock);

		/*
                 * Always deliver to the first vCPU, but it doesn't matter
                 * which we chose, as long as it's available.
		 */
                vgic_inject_irq(d, d->vcpu[0], ctx->notif->intid, true);

                put_domain(d);
            }

            id_pos += count;
        }

    } while (resp.a2 & FFA_NOTIF_INFO_GET_MORE_FLAG);
}