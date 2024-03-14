/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2024  Linaro Limited
 */

#include <xen/const.h>
#include <xen/sizes.h>
#include <xen/types.h>

#include <asm/smccc.h>
#include <asm/regs.h>

#include "ffa_private.h"

/* Partition information descriptor defined in FF-A-1.0-REL */
struct ffa_partition_info_1_0 {
    uint16_t id;
    uint16_t execution_context;
    uint32_t partition_properties;
};

/* Partition information descriptor defined in FF-A-1.1-REL0 */
struct ffa_partition_info_1_1 {
    uint16_t id;
    uint16_t execution_context;
    uint32_t partition_properties;
    uint8_t uuid[16];
};

/* SPs subscribing to VM_CREATE and VM_DESTROYED events */
static uint16_t *subscr_vm_created __read_mostly;
static uint16_t subscr_vm_created_count __read_mostly;
static uint16_t *subscr_vm_destroyed __read_mostly;
static uint16_t subscr_vm_destroyed_count __read_mostly;

static int32_t ffa_partition_info_get(uint32_t w1, uint32_t w2, uint32_t w3,
                                      uint32_t w4, uint32_t w5, uint32_t *count,
                                      uint32_t *fpi_size)
{
    const struct arm_smccc_1_2_regs arg = {
        .a0 = FFA_PARTITION_INFO_GET,
        .a1 = w1,
        .a2 = w2,
        .a3 = w3,
        .a4 = w4,
        .a5 = w5,
    };
    struct arm_smccc_1_2_regs resp;
    uint32_t ret;

    arm_smccc_1_2_smc(&arg, &resp);

    ret = ffa_get_ret_code(&resp);
    if ( !ret )
    {
        *count = resp.a2;
        *fpi_size = resp.a3;
    }

    return ret;
}

int32_t ffa_handle_partition_info_get(uint32_t w1, uint32_t w2, uint32_t w3,
                                      uint32_t w4, uint32_t w5,
                                      uint32_t *count, uint32_t *size)
{
    int32_t ret;
    struct domain *d = current->domain;
    struct ffa_ctx *ctx = d->arch.tee;
    uint32_t src_size, dst_size;
    void *dst_buf;
    uint32_t num_ffa_sp;

    /*
     * FF-A v1.0 has w5 MBZ while v1.1 allows
     * FFA_PARTITION_INFO_GET_COUNT_FLAG to be non-zero.
     *
     * FFA_PARTITION_INFO_GET_COUNT is only using registers and not the
     * rxtx buffer so do the partition_info_get directly.
     */
    if ( w5 == FFA_PARTITION_INFO_GET_COUNT_FLAG &&
         ctx->guest_vers == FFA_VERSION_1_1 )
    {
        ret = FFA_RET_OK;
        *count = 0;

        if ( ffa_fw_support_fid(FFA_PARTITION_INFO_GET) )
            ret = ffa_partition_info_get(w1, w2, w3, w4, w5, count, size);

        return ret;
    }
    if ( w5 )
        return FFA_RET_INVALID_PARAMETERS;

    if ( !spin_trylock(&ctx->rx_lock) )
        return FFA_RET_BUSY;

    /*
     * If the guest is v1.0, he does not get back the entry size so we must
     * use the v1.0 structure size in the destination buffer.
     * Otherwise use the size of the highest version we support, here 1.1.
     */
    if ( ctx->guest_vers == FFA_VERSION_1_0 )
        dst_size = sizeof(struct ffa_partition_info_1_0);
    else
        dst_size = sizeof(struct ffa_partition_info_1_1);

    dst_buf = ctx->rx;

    if ( ffa_fw_support_fid(FFA_PARTITION_INFO_GET) )
    {
        ret = FFA_RET_DENIED;

        if ( !ffa_rx )
            goto out;

        if ( !ctx->page_count || !ctx->rx_is_free )
            goto out;

        spin_lock(&ffa_rx_buffer_lock);

        ret = ffa_partition_info_get(w1, w2, w3, w4, w5, &num_ffa_sp,
                                     &src_size);

        if ( ret )
            goto out_rx_buf_unlock;

        /*
         * ffa_partition_info_get() succeeded so we now own the RX buffer we
         * share with the SPMC. We must give it back using ffa_rx_release()
         * once we've copied the content.
         */

        /* we cannot have a size lower than 1.0 structure */
        if ( src_size < sizeof(struct ffa_partition_info_1_0) )
        {
            ret = FFA_RET_NOT_SUPPORTED;
            goto out_rx_release;
        }
    }
    else
    {
        ret = FFA_RET_OK;
        *count = 0;
        *size = dst_size;
        goto out;
    }

    if ( ctx->page_count * FFA_PAGE_SIZE < num_ffa_sp * dst_size )
    {
        ret = FFA_RET_NO_MEMORY;
        goto out_rx_release;
    }

    if ( num_ffa_sp > 0 )
    {
        uint32_t n, real_num = num_ffa_sp;
        void *src_buf = ffa_rx;

        /* copy the secure partitions info */
        for ( n = 0; n < real_num; n++ )
        {
            struct ffa_partition_info_1_1 *fpi = src_buf;

            /* filter out SP not following bit 15 convention if any */
            if ( FFA_ID_IS_SECURE(fpi->id) )
            {
                memcpy(dst_buf, src_buf, dst_size);
                dst_buf += dst_size;
            }
            else
            {
                printk(XENLOG_INFO "ffa: sp id 0x%04x skipped, bit 15 is 0\n",
                       fpi->id);
                num_ffa_sp--;
            }
            src_buf += src_size;
        }
    }

    ctx->rx_is_free = false;
    *count = num_ffa_sp;
    *size = dst_size;

out_rx_release:
    ffa_rx_release();
out_rx_buf_unlock:
    spin_unlock(&ffa_rx_buffer_lock);
out:
    spin_unlock(&ctx->rx_lock);

    return ret;
}

static int32_t ffa_direct_req_send_vm(uint16_t sp_id, uint16_t vm_id,
                                      uint8_t msg)
{
    uint32_t exp_resp = FFA_MSG_FLAG_FRAMEWORK;
    unsigned int retry_count = 0;
    int32_t res;

    if ( msg == FFA_MSG_SEND_VM_CREATED )
        exp_resp |= FFA_MSG_RESP_VM_CREATED;
    else if ( msg == FFA_MSG_SEND_VM_DESTROYED )
        exp_resp |= FFA_MSG_RESP_VM_DESTROYED;
    else
        return FFA_RET_INVALID_PARAMETERS;

    do {
        const struct arm_smccc_1_2_regs arg = {
            .a0 = FFA_MSG_SEND_DIRECT_REQ_32,
            .a1 = sp_id,
            .a2 = FFA_MSG_FLAG_FRAMEWORK | msg,
            .a5 = vm_id,
        };
        struct arm_smccc_1_2_regs resp;

        arm_smccc_1_2_smc(&arg, &resp);
        if ( resp.a0 != FFA_MSG_SEND_DIRECT_RESP_32 || resp.a2 != exp_resp )
        {
            /*
             * This is an invalid response, likely due to some error in the
             * implementation of the ABI.
             */
            return FFA_RET_INVALID_PARAMETERS;
        }
        res = resp.a3;
        if ( ++retry_count > 10 )
        {
            /*
             * TODO
             * FFA_RET_INTERRUPTED means that the SPMC has a pending
             * non-secure interrupt, we need a way of delivering that
             * non-secure interrupt.
             * FFA_RET_RETRY is the SP telling us that it's temporarily
             * blocked from handling the direct request, we need a generic
             * way to deal with this.
             * For now in both cases, give up after a few retries.
             */
            return res;
        }
    } while ( res == FFA_RET_INTERRUPTED || res == FFA_RET_RETRY );

    return res;
}

static void uninit_subscribers(void)
{
        subscr_vm_created_count = 0;
        subscr_vm_destroyed_count = 0;
        if ( subscr_vm_created )
            XFREE(subscr_vm_created);
        if ( subscr_vm_destroyed )
            XFREE(subscr_vm_destroyed);
}

static bool init_subscribers(uint16_t count, uint32_t fpi_size)
{
    uint16_t n;
    uint16_t c_pos;
    uint16_t d_pos;
    struct ffa_partition_info_1_1 *fpi;

    if ( fpi_size < sizeof(struct ffa_partition_info_1_1) )
    {
        printk(XENLOG_ERR "ffa: partition info size invalid: %u\n", fpi_size);
        return false;
    }

    subscr_vm_created_count = 0;
    subscr_vm_destroyed_count = 0;
    for ( n = 0; n < count; n++ )
    {
        fpi = ffa_rx + n*fpi_size;

        /*
         * We need to have secure partitions using bit 15 set convention for
         * secure partition IDs.
         * Inform the user with a log and discard giving created or destroy
         * event to those IDs.
         */
        if ( !FFA_ID_IS_SECURE(fpi->id) )
        {
            printk(XENLOG_ERR "ffa: Firmware is not using bit 15 convention for IDs !!\n"
                              "ffa: Secure partition with id 0x%04x cannot be used\n",
                              fpi->id);
        }
        else
        {
            if ( fpi->partition_properties & FFA_PART_PROP_NOTIF_CREATED )
                subscr_vm_created_count++;
            if ( fpi->partition_properties & FFA_PART_PROP_NOTIF_DESTROYED )
                subscr_vm_destroyed_count++;
        }
    }

    if ( subscr_vm_created_count )
        subscr_vm_created = xzalloc_array(uint16_t, subscr_vm_created_count);
    if ( subscr_vm_destroyed_count )
        subscr_vm_destroyed = xzalloc_array(uint16_t,
                                            subscr_vm_destroyed_count);
    if ( (subscr_vm_created_count && !subscr_vm_created) ||
         (subscr_vm_destroyed_count && !subscr_vm_destroyed) )
    {
        printk(XENLOG_ERR "ffa: Failed to allocate subscription lists\n");
        uninit_subscribers();
        return false;
    }

    for ( c_pos = 0, d_pos = 0, n = 0; n < count; n++ )
    {
        fpi = ffa_rx + n*fpi_size;

        if ( FFA_ID_IS_SECURE(fpi->id) )
        {
            if ( fpi->partition_properties & FFA_PART_PROP_NOTIF_CREATED )
                subscr_vm_created[c_pos++] = fpi->id;
            if ( fpi->partition_properties & FFA_PART_PROP_NOTIF_DESTROYED )
                subscr_vm_destroyed[d_pos++] = fpi->id;
        }
    }

    return true;
}



bool ffa_partinfo_init(void)
{
    bool ret = false;
    uint32_t fpi_size;
    uint32_t count;
    int e;

    if ( !ffa_fw_support_fid(FFA_PARTITION_INFO_GET) ||
         !ffa_fw_support_fid(FFA_MSG_SEND_DIRECT_REQ_32) ||
         !ffa_rx || !ffa_tx )
        return false;

    e = ffa_partition_info_get(0, 0, 0, 0, 0, &count, &fpi_size);
    if ( e )
    {
        printk(XENLOG_ERR "ffa: Failed to get list of SPs: %d\n", e);
        goto out;
    }

    if ( count >= UINT16_MAX )
    {
        printk(XENLOG_ERR "ffa: Impossible number of SPs: %u\n", count);
        goto out;
    }

    ret = init_subscribers(count, fpi_size);

out:
    ffa_rx_release();
    return ret;
}

static bool is_in_subscr_list(const uint16_t *subscr, uint16_t start,
                              uint16_t end, uint16_t sp_id)
{
    unsigned int n;

    for ( n = start; n < end; n++ )
    {
        if ( subscr[n] == sp_id )
            return true;
    }

    return false;
}

static void vm_destroy_bitmap_init(struct ffa_ctx *ctx,
                                   unsigned int create_signal_count)
{
    unsigned int n;

    for ( n = 0; n < subscr_vm_destroyed_count; n++ )
    {
        /*
         * Skip SPs subscribed to the VM created event that never was
         * notified of the VM creation due to an error during
         * ffa_domain_init().
         */
        if ( is_in_subscr_list(subscr_vm_created, create_signal_count,
                               subscr_vm_created_count,
                               subscr_vm_destroyed[n]) )
            continue;

        set_bit(n, ctx->vm_destroy_bitmap);
    }
}

bool ffa_partinfo_domain_init(struct domain *d)
{
    unsigned int count = BITS_TO_LONGS(subscr_vm_destroyed_count);
    struct ffa_ctx *ctx = d->arch.tee;
    unsigned int n;
    int32_t res;

    if ( !ffa_fw_support_fid(FFA_MSG_SEND_DIRECT_REQ_32) )
        return true;

    ctx->vm_destroy_bitmap = xzalloc_array(unsigned long, count);
    if ( !ctx->vm_destroy_bitmap )
        return false;

    for ( n = 0; n < subscr_vm_created_count; n++ )
    {
        res = ffa_direct_req_send_vm(subscr_vm_created[n], ffa_get_vm_id(d),
                                     FFA_MSG_SEND_VM_CREATED);
        if ( res )
        {
            printk(XENLOG_ERR "ffa: Failed to report creation of vm_id %u to  %u: res %d\n",
                   ffa_get_vm_id(d), subscr_vm_created[n], res);
            break;
        }
    }
    vm_destroy_bitmap_init(ctx, n);

    return n == subscr_vm_created_count;
}

bool ffa_partinfo_domain_destroy(struct domain *d)
{
    struct ffa_ctx *ctx = d->arch.tee;
    unsigned int n;
    int32_t res;

    if ( !ctx->vm_destroy_bitmap )
        return true;

    for ( n = 0; n < subscr_vm_destroyed_count; n++ )
    {
        if ( !test_bit(n, ctx->vm_destroy_bitmap) )
            continue;

        res = ffa_direct_req_send_vm(subscr_vm_destroyed[n], ffa_get_vm_id(d),
                                     FFA_MSG_SEND_VM_DESTROYED);

        if ( res )
        {
            printk(XENLOG_ERR "%pd: ffa: Failed to report destruction of vm_id %u to %u: res %d\n",
                   d, ffa_get_vm_id(d), subscr_vm_destroyed[n], res);
        }

        /*
         * For these two error codes the hypervisor is expected to resend
         * the destruction message. For the rest it is expected that the
         * error is permanent and that is doesn't help to resend the
         * destruction message.
         */
        if ( res != FFA_RET_INTERRUPTED && res != FFA_RET_RETRY )
            clear_bit(n, ctx->vm_destroy_bitmap);
    }

    if ( bitmap_empty(ctx->vm_destroy_bitmap, subscr_vm_destroyed_count) )
        XFREE(ctx->vm_destroy_bitmap);

    return !ctx->vm_destroy_bitmap;
}
