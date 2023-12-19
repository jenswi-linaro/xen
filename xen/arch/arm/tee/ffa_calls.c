/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2023  Linaro Limited
 */

#include <xen/const.h>
#include <xen/domain_page.h>
#include <xen/list.h>
#include <xen/mm.h>
#include <xen/sizes.h>
#include <xen/spinlock.h>
#include <xen/types.h>

#include <asm/smccc.h>
#include <asm/regs.h>

#include "ffa_private.h"

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
    ffa_set_regs(regs, vers, 0, 0, 0, 0, 0, 0, 0);
}

static uint32_t handle_rxtx_map(uint32_t fid, register_t tx_addr,
                                register_t rx_addr, uint32_t page_count)
{
    uint32_t ret = FFA_RET_INVALID_PARAMETERS;
    struct domain *d = current->domain;
    struct ffa_ctx *ctx = d->arch.tee;
    struct page_info *tx_pg;
    struct page_info *rx_pg;
    p2m_type_t t;
    void *rx;
    void *tx;

    if ( !smccc_is_conv_64(fid) )
    {
        /*
         * Calls using the 32-bit calling convention must ignore the upper
         * 32 bits in the argument registers.
         */
        tx_addr &= UINT32_MAX;
        rx_addr &= UINT32_MAX;
    }

    if ( page_count > FFA_MAX_RXTX_PAGE_COUNT )
    {
        printk(XENLOG_ERR "ffa: RXTX_MAP: error: %u pages requested (limit %u)\n",
               page_count, FFA_MAX_RXTX_PAGE_COUNT);
        return FFA_RET_INVALID_PARAMETERS;
    }

    /* Already mapped */
    if ( ctx->rx )
        return FFA_RET_DENIED;

    tx_pg = get_page_from_gfn(d, gfn_x(gaddr_to_gfn(tx_addr)), &t, P2M_ALLOC);
    if ( !tx_pg )
        return FFA_RET_INVALID_PARAMETERS;

    /* Only normal RW RAM for now */
    if ( t != p2m_ram_rw )
        goto err_put_tx_pg;

    rx_pg = get_page_from_gfn(d, gfn_x(gaddr_to_gfn(rx_addr)), &t, P2M_ALLOC);
    if ( !tx_pg )
        goto err_put_tx_pg;

    /* Only normal RW RAM for now */
    if ( t != p2m_ram_rw )
        goto err_put_rx_pg;

    tx = __map_domain_page_global(tx_pg);
    if ( !tx )
        goto err_put_rx_pg;

    rx = __map_domain_page_global(rx_pg);
    if ( !rx )
        goto err_unmap_tx;

    ctx->rx = rx;
    ctx->tx = tx;
    ctx->rx_pg = rx_pg;
    ctx->tx_pg = tx_pg;
    ctx->page_count = page_count;
    ctx->rx_is_free = true;
    return FFA_RET_OK;

err_unmap_tx:
    unmap_domain_page_global(tx);
err_put_rx_pg:
    put_page(rx_pg);
err_put_tx_pg:
    put_page(tx_pg);

    return ret;
}

void ffa_ctx_rxtx_unmap(struct ffa_ctx *ctx)
{
    unmap_domain_page_global(ctx->rx);
    unmap_domain_page_global(ctx->tx);
    put_page(ctx->rx_pg);
    put_page(ctx->tx_pg);
    ctx->rx = NULL;
    ctx->tx = NULL;
    ctx->rx_pg = NULL;
    ctx->tx_pg = NULL;
    ctx->page_count = 0;
    ctx->rx_is_free = false;
}

static uint32_t handle_rxtx_unmap(void)
{
    struct domain *d = current->domain;
    struct ffa_ctx *ctx = d->arch.tee;

    if ( !ctx->rx )
        return FFA_RET_INVALID_PARAMETERS;

    ffa_ctx_rxtx_unmap(ctx);

    return FFA_RET_OK;
}

static int32_t handle_partition_info_get(uint32_t w1, uint32_t w2, uint32_t w3,
                                         uint32_t w4, uint32_t w5,
                                         uint32_t *count, uint32_t *fpi_size)
{
    int32_t ret = FFA_RET_DENIED;
    struct domain *d = current->domain;
    struct ffa_ctx *ctx = d->arch.tee;

    /*
     * FF-A v1.0 has w5 MBZ while v1.1 allows
     * FFA_PARTITION_INFO_GET_COUNT_FLAG to be non-zero.
     *
     * FFA_PARTITION_INFO_GET_COUNT is only using registers and not the
     * rxtx buffer so do the partition_info_get directly.
     */
    if ( w5 == FFA_PARTITION_INFO_GET_COUNT_FLAG &&
         ctx->guest_vers == FFA_VERSION_1_1 )
        return ffa_partition_info_get(w1, w2, w3, w4, w5, count, fpi_size);
    if ( w5 )
        return FFA_RET_INVALID_PARAMETERS;

    if ( !ffa_rx )
        return FFA_RET_DENIED;

    if ( !spin_trylock(&ctx->rx_lock) )
        return FFA_RET_BUSY;

    if ( !ctx->page_count || !ctx->rx_is_free )
        goto out;
    spin_lock(&ffa_rx_buffer_lock);
    ret = ffa_partition_info_get(w1, w2, w3, w4, w5, count, fpi_size);
    if ( ret )
        goto out_rx_buf_unlock;
    /*
     * ffa_partition_info_get() succeeded so we now own the RX buffer we
     * share with the SPMC. We must give it back using ffa_rx_release()
     * once we've copied the content.
     */

    if ( ctx->guest_vers == FFA_VERSION_1_0 )
    {
        size_t n;
        struct ffa_partition_info_1_1 *src = ffa_rx;
        struct ffa_partition_info_1_0 *dst = ctx->rx;

        if ( ctx->page_count * FFA_PAGE_SIZE < *count * sizeof(*dst) )
        {
            ret = FFA_RET_NO_MEMORY;
            goto out_rx_release;
        }

        for ( n = 0; n < *count; n++ )
        {
            dst[n].id = src[n].id;
            dst[n].execution_context = src[n].execution_context;
            dst[n].partition_properties = src[n].partition_properties;
        }
    }
    else
    {
        size_t sz = *count * *fpi_size;

        if ( ctx->page_count * FFA_PAGE_SIZE < sz )
        {
            ret = FFA_RET_NO_MEMORY;
            goto out_rx_release;
        }

        memcpy(ctx->rx, ffa_rx, sz);
    }
    ctx->rx_is_free = false;
out_rx_release:
    ffa_rx_release();
out_rx_buf_unlock:
    spin_unlock(&ffa_rx_buffer_lock);
out:
    spin_unlock(&ctx->rx_lock);

    return ret;
}

static int32_t handle_rx_release(void)
{
    int32_t ret = FFA_RET_DENIED;
    struct domain *d = current->domain;
    struct ffa_ctx *ctx = d->arch.tee;

    if ( !spin_trylock(&ctx->rx_lock) )
        return FFA_RET_BUSY;

    if ( !ctx->page_count || ctx->rx_is_free )
        goto out;
    ret = FFA_RET_OK;
    ctx->rx_is_free = true;
out:
    spin_unlock(&ctx->rx_lock);

    return ret;
}

static void handle_msg_send_direct_req(struct cpu_user_regs *regs, uint32_t fid)
{
    struct arm_smccc_1_2_regs arg = { .a0 = fid, };
    struct arm_smccc_1_2_regs resp = { };
    struct domain *d = current->domain;
    uint32_t src_dst;
    uint64_t mask;

    if ( smccc_is_conv_64(fid) )
        mask = GENMASK_ULL(63, 0);
    else
        mask = GENMASK_ULL(31, 0);

    src_dst = get_user_reg(regs, 1);
    if ( (src_dst >> 16) != ffa_get_vm_id(d) )
    {
        resp.a0 = FFA_ERROR;
        resp.a2 = FFA_RET_INVALID_PARAMETERS;
        goto out;
    }

    arg.a1 = src_dst;
    arg.a2 = get_user_reg(regs, 2) & mask;
    arg.a3 = get_user_reg(regs, 3) & mask;
    arg.a4 = get_user_reg(regs, 4) & mask;
    arg.a5 = get_user_reg(regs, 5) & mask;
    arg.a6 = get_user_reg(regs, 6) & mask;
    arg.a7 = get_user_reg(regs, 7) & mask;

    arm_smccc_1_2_smc(&arg, &resp);
    switch ( resp.a0 )
    {
    case FFA_ERROR:
    case FFA_SUCCESS_32:
    case FFA_SUCCESS_64:
    case FFA_MSG_SEND_DIRECT_RESP_32:
    case FFA_MSG_SEND_DIRECT_RESP_64:
        break;
    default:
        /* Bad fid, report back to the caller. */
        memset(&resp, 0, sizeof(resp));
        resp.a0 = FFA_ERROR;
        resp.a1 = src_dst;
        resp.a2 = FFA_RET_ABORTED;
    }

out:
    ffa_set_regs(regs, resp.a0, resp.a1 & mask, resp.a2 & mask, resp.a3 & mask,
                 resp.a4 & mask, resp.a5 & mask, resp.a6 & mask,
                 resp.a7 & mask);
}

static void handle_features(struct cpu_user_regs *regs)
{
    const struct arm_smccc_1_2_regs arg = {
        .a0 = FFA_FEATURES,
        .a1 = get_user_reg(regs, 1),
        .a2 = get_user_reg(regs, 2),
        .a3 = get_user_reg(regs, 3),
        .a4 = get_user_reg(regs, 4),
        .a5 = get_user_reg(regs, 5),
        .a6 = get_user_reg(regs, 6),
        .a7 = get_user_reg(regs, 7),
    };
    struct arm_smccc_1_2_regs resp;

    if ( arg.a2 || arg.a3 || arg.a4 || arg.a5 || arg.a6 || arg.a7 )
    {
            ffa_set_regs_error(regs, FFA_RET_NOT_SUPPORTED);
            return;
    }

    switch ( arg.a1 )
    {
    case FFA_ERROR:
    case FFA_VERSION:
    case FFA_SUCCESS_32:
    case FFA_SUCCESS_64:
    case FFA_FEATURES:
    case FFA_ID_GET:
    case FFA_RX_RELEASE:
    case FFA_MEM_SHARE_64:
    case FFA_MEM_SHARE_32:
        ffa_set_regs_success(regs, 0, 0);
        break;
    /* Function and feature IDs that we need to forward to the SPMC */
    case FFA_RXTX_MAP_64:
    case FFA_RXTX_MAP_32:
    case FFA_RXTX_UNMAP:
    case FFA_MEM_RECLAIM:
    case FFA_PARTITION_INFO_GET:
    case FFA_MSG_SEND_DIRECT_REQ_32:
    case FFA_MSG_SEND_DIRECT_REQ_64:
        arm_smccc_1_2_smc(&arg, &resp);
        ffa_set_regs(regs, resp.a0, resp.a1, resp.a2, resp.a3, resp.a4,
                     resp.a5, resp.a6, resp.a7);
        break;
    default:
        ffa_set_regs_error(regs, FFA_RET_NOT_SUPPORTED);
        break;
    }
}

bool ffa_handle_call(struct cpu_user_regs *regs)
{
    uint32_t fid = get_user_reg(regs, 0);
    struct domain *d = current->domain;
    struct ffa_ctx *ctx = d->arch.tee;
    uint32_t fpi_size;
    uint32_t count;
    int e;

    if ( !ctx )
        return false;

    switch ( fid )
    {
    case FFA_VERSION:
        handle_version(regs);
        return true;
    case FFA_ID_GET:
        ffa_set_regs_success(regs, ffa_get_vm_id(d), 0);
        return true;
    case FFA_FEATURES:
        handle_features(regs);
        return true;
    case FFA_RXTX_MAP_32:
    case FFA_RXTX_MAP_64:
        e = handle_rxtx_map(fid, get_user_reg(regs, 1), get_user_reg(regs, 2),
                            get_user_reg(regs, 3));
        if ( e )
            ffa_set_regs_error(regs, e);
        else
            ffa_set_regs_success(regs, 0, 0);
        return true;
    case FFA_RXTX_UNMAP:
        e = handle_rxtx_unmap();
        if ( e )
            ffa_set_regs_error(regs, e);
        else
            ffa_set_regs_success(regs, 0, 0);
        return true;
    case FFA_PARTITION_INFO_GET:
        e = handle_partition_info_get(get_user_reg(regs, 1),
                                      get_user_reg(regs, 2),
                                      get_user_reg(regs, 3),
                                      get_user_reg(regs, 4),
                                      get_user_reg(regs, 5), &count, &fpi_size);
        if ( e )
            ffa_set_regs_error(regs, e);
        else
            ffa_set_regs_success(regs, count, fpi_size);
        return true;
    case FFA_RX_RELEASE:
        e = handle_rx_release();
        if ( e )
            ffa_set_regs_error(regs, e);
        else
            ffa_set_regs_success(regs, 0, 0);
        return true;
    case FFA_MSG_SEND_DIRECT_REQ_32:
    case FFA_MSG_SEND_DIRECT_REQ_64:
        handle_msg_send_direct_req(regs, fid);
        return true;
    case FFA_MEM_SHARE_32:
    case FFA_MEM_SHARE_64:
        ffa_handle_mem_share(regs);
        return true;
    case FFA_MEM_RECLAIM:
        e = ffa_handle_mem_reclaim(regpair_to_uint64(get_user_reg(regs, 2),
                                                     get_user_reg(regs, 1)),
                                   get_user_reg(regs, 3));
        if ( e )
            ffa_set_regs_error(regs, e);
        else
            ffa_set_regs_success(regs, 0, 0);
        return true;

    default:
        gprintk(XENLOG_ERR, "ffa: unhandled fid 0x%x\n", fid);
        ffa_set_regs_error(regs, FFA_RET_NOT_SUPPORTED);
        return true;
    }
}
