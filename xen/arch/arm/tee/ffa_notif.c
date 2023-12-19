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

struct notif_info_get_state {
    struct cpu_user_regs *regs;
    unsigned int ids_per_reg;
    unsigned int ids_count;
    unsigned int id_pos;
    unsigned int count;
    unsigned int max_list_count;
    unsigned int list_count;
};

static bool add_id_in_regs(struct notif_info_get_state *state,
                           uint16_t id)
{
    unsigned int reg_idx = state->id_pos / state->ids_per_reg + 3;
    unsigned int reg_shift = (state->id_pos % state->ids_per_reg) * 16;
    unsigned long v;

    if ( reg_idx > 7 )
        return false;

    v = get_user_reg(state->regs, reg_idx);
    v &= ~(0xffffUL << reg_shift);
    v |= (unsigned long)id << reg_shift;
    set_user_reg(state->regs, reg_idx, v);

    state->id_pos++;
    state->count++;
    return true;
}

static bool add_id_count(struct notif_info_get_state *state)
{
    ASSERT(state->list_count < state->max_list_count &&
           state->count >= 1 && state->count <= 4);

    state->ids_count |= (state->count - 1) << (state->list_count * 2 + 12);
    state->list_count++;
    state->count = 0;

    return state->list_count < state->max_list_count;
}

void ffa_handle_notification_info_get(struct cpu_user_regs *regs)
{
    struct notif_info_get_state state = { .regs = regs };
    struct domain *d = current->domain;
    struct ffa_ctx *ctx = d->arch.tee;
    unsigned int more_pending_flag;
    bool pending_global;
    unsigned int bit;

    if ( !notif_enabled )
    {
        ffa_set_regs_error(regs, FFA_RET_NOT_SUPPORTED);
        return;
    }

    if ( smccc_is_conv_64(get_user_reg(regs, 0)))
    {
        ffa_set_regs(regs, FFA_SUCCESS_64, 0, 0, 0, 0, 0, 0, 0);
        state.max_list_count = 31;
        state.ids_per_reg = 4;
    }
    else
    {
        ffa_set_regs(regs, FFA_SUCCESS_32, 0, 0, 0, 0, 0, 0, 0);
        state.max_list_count = 15;
        state.ids_per_reg = 2;
    }

    spin_lock(&ctx->notif->lock);
    for_each_set_bit(bit, ctx->notif->spm_pending_vcpus, d->max_vcpus)
    {
        if ( state.count == 4 && !add_id_count(&state) )
                break;
        if ( !state.count && !add_id_in_regs(&state, ffa_get_vm_id(d)) )
                break;
        if ( !add_id_in_regs(&state, bit) )
            break;
        clear_bit(bit, ctx->notif->spm_pending_vcpus);
    }

    pending_global = ctx->notif->spm_pending_global;
    ctx->notif->spm_pending_global = false;
    more_pending_flag = !bitmap_empty(ctx->notif->spm_pending_vcpus,
                                      d->max_vcpus);
    spin_unlock(&ctx->notif->lock);

    if ( !state.id_pos )
    {
        /*
         * Error out if there where no pending global or per-vCPU
         * notifications.
         */
        if ( !pending_global)
        {
            ffa_set_regs_error(regs, FFA_RET_NO_DATA);
            return;
        }

        add_id_in_regs(&state, ffa_get_vm_id(d));
    }

    /* Add the count of the last started list. */
    if ( state.count )
        add_id_count(&state);

    set_user_reg(regs, 2,
                 (state.list_count << FFA_NOTIF_INFO_GET_ID_COUNT_SHIFT) |
                 (state.ids_count << FFA_NOTIF_INFO_GET_ID_LIST_SHIFT) |
                 more_pending_flag);
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
            unsigned int m;

            d = ffa_get_domain_by_vm_id(get_id_from_resp(&resp, id_pos));
            id_pos++;

            if ( d )
            {
                struct ffa_ctx *ctx = d->arch.tee;

                spin_lock(&ctx->notif->lock);

                if ( !count )
                    ctx->notif->spm_pending_global = true;

                for ( m = 0; m < count; m++ )
                    set_bit(get_id_from_resp(&resp, id_pos + m),
                            ctx->notif->spm_pending_vcpus);

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
