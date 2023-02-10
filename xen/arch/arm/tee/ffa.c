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

/*
 * References:
 * FF-A-1.0-REL: FF-A specification version 1.0 available at
 *               https://developer.arm.com/documentation/den0077/a
 * FF-A-1.1-REL0: FF-A specification version 1.1 available at
 *                https://developer.arm.com/documentation/den0077/e
 */

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

/*
 * The FF-A specification explicitly works with 4K pages as a measure of
 * memory size, for example, FFA_RXTX_MAP takes one parameter "RX/TX page
 * count" which is the number of contiguous 4K pages allocated. Xen may use
 * a different page size depending on the configuration to avoid confusion
 * with PAGE_SIZE use a special define when it's a page size as in the FF-A
 * specification.
 */
#define FFA_PAGE_SIZE                   SZ_4K

/*
 * Limit for shared buffer size. Please note that this define limits
 * number of pages. But user buffer can be not aligned to a page
 * boundary. So it is possible that user would not be able to share
 * exactly FFA_MAX_SHM_BUFFER_PG * FFA_PAGE_SIZE bytes.
 *
 * FF-A doesn't have any direct requirments on GlobalPlatform or vice
 * versa, but an implementation can very well use FF-A in order to provide
 * a GlobalPlatform interface on top.
 *
 * Global Platform specification for TEE requires that any TEE
 * implementation should allow to share buffers with size of at least
 * 512KB. Due to align issue mentioned above, we need to increase this
 * value with one.
 */
#define FFA_MAX_SHM_PAGE_COUNT          (SZ_512K / FFA_PAGE_SIZE + 1)

/*
 * Limits the number of shared buffers that guest can have at once. This
 * is to prevent case, when guests tricks XEN into exhausting its own
 * memory by allocating many small buffers. This value has been chosen
 * arbitrary.
 */
#define FFA_MAX_SHM_COUNT               32

/* FF-A-1.1-REL0 section 10.9.2 Memory region handle, page 167 */
#define FFA_HANDLE_HYP_FLAG             BIT(63, ULL)
#define FFA_HANDLE_INVALID              0xffffffffffffffffULL

/*
 * The bits for FFA_NORMAL_MEM_REG_ATTR FFA_MEM_ACC_RW below are
 * defined in FF-A-1.1-REL0 Table 10.18 at page 175.
 */
 /* Memory attributes: Normal memory, Write-Back cacheable, Inner shareable */
#define FFA_NORMAL_MEM_REG_ATTR         0x2fU
/* Memory access permissions: Read-write */
#define FFA_MEM_ACC_RW                  0x2U

/* FF-A-1.1-REL0 section 10.11.4 Flags usage, page 184-187 */
/* Clear memory before mapping in receiver */
#define FFA_MEMORY_REGION_FLAG_CLEAR            BIT(0, U)
/* Relayer may time slice this operation */
#define FFA_MEMORY_REGION_FLAG_TIME_SLICE       BIT(1, U)
/* Clear memory after receiver relinquishes it */
#define FFA_MEMORY_REGION_FLAG_CLEAR_RELINQUISH BIT(2, U)
/* Share memory transaction */
#define FFA_MEMORY_REGION_TRANSACTION_TYPE_SHARE (1U << 3)


/* Framework direct request/response */
#define FFA_MSG_FLAG_FRAMEWORK          BIT(31, U)
#define FFA_MSG_TYPE_MASK               0xFFU;
#define FFA_MSG_PSCI                    0x0U
#define FFA_MSG_SEND_VM_CREATED         0x4U
#define FFA_MSG_RESP_VM_CREATED         0x5U
#define FFA_MSG_SEND_VM_DESTROYED       0x6U
#define FFA_MSG_RESP_VM_DESTROYED       0x7U

/*
 * Flags used for the FFA_PARTITION_INFO_GET return message:
 * BIT(0): Supports receipt of direct requests
 * BIT(1): Can send direct requests
 * BIT(2): Can send and receive indirect messages
 * BIT(3): Supports receipt of notifications
 * BIT(4-5): Partition ID is a PE endpoint ID
 */
#define FFA_PART_PROP_DIRECT_REQ_RECV   BIT(0, U)
#define FFA_PART_PROP_DIRECT_REQ_SEND   BIT(1, U)
#define FFA_PART_PROP_INDIRECT_MSGS     BIT(2, U)
#define FFA_PART_PROP_RECV_NOTIF        BIT(3, U)
#define FFA_PART_PROP_IS_PE_ID          (0U << 4)
#define FFA_PART_PROP_IS_SEPID_INDEP    (1U << 4)
#define FFA_PART_PROP_IS_SEPID_DEP      (2U << 4)
#define FFA_PART_PROP_IS_AUX_ID         (3U << 4)
#define FFA_PART_PROP_NOTIF_CREATED     BIT(6, U)
#define FFA_PART_PROP_NOTIF_DESTROYED   BIT(7, U)
#define FFA_PART_PROP_AARCH64_STATE     BIT(8, U)

/*
 * Flag used as parameter to FFA_PARTITION_INFO_GET to return partition
 * count only.
 */
#define FFA_PARTITION_INFO_GET_COUNT_FLAG BIT(0, U)

/* Function IDs */
#define FFA_ERROR                       0x84000060U
#define FFA_SUCCESS_32                  0x84000061U
#define FFA_SUCCESS_64                  0xC4000061U
#define FFA_INTERRUPT                   0x84000062U
#define FFA_VERSION                     0x84000063U
#define FFA_FEATURES                    0x84000064U
#define FFA_RX_ACQUIRE                  0x84000084U
#define FFA_RX_RELEASE                  0x84000065U
#define FFA_RXTX_MAP_32                 0x84000066U
#define FFA_RXTX_MAP_64                 0xC4000066U
#define FFA_RXTX_UNMAP                  0x84000067U
#define FFA_PARTITION_INFO_GET          0x84000068U
#define FFA_ID_GET                      0x84000069U
#define FFA_SPM_ID_GET                  0x84000085U
#define FFA_MSG_WAIT                    0x8400006BU
#define FFA_MSG_YIELD                   0x8400006CU
#define FFA_MSG_RUN                     0x8400006DU
#define FFA_MSG_SEND2                   0x84000086U
#define FFA_MSG_SEND_DIRECT_REQ_32      0x8400006FU
#define FFA_MSG_SEND_DIRECT_REQ_64      0xC400006FU
#define FFA_MSG_SEND_DIRECT_RESP_32     0x84000070U
#define FFA_MSG_SEND_DIRECT_RESP_64     0xC4000070U
#define FFA_MEM_DONATE_32               0x84000071U
#define FFA_MEM_DONATE_64               0xC4000071U
#define FFA_MEM_LEND_32                 0x84000072U
#define FFA_MEM_LEND_64                 0xC4000072U
#define FFA_MEM_SHARE_32                0x84000073U
#define FFA_MEM_SHARE_64                0xC4000073U
#define FFA_MEM_RETRIEVE_REQ_32         0x84000074U
#define FFA_MEM_RETRIEVE_REQ_64         0xC4000074U
#define FFA_MEM_RETRIEVE_RESP           0x84000075U
#define FFA_MEM_RELINQUISH              0x84000076U
#define FFA_MEM_RECLAIM                 0x84000077U
#define FFA_MEM_FRAG_RX                 0x8400007AU
#define FFA_MEM_FRAG_TX                 0x8400007BU
#define FFA_MSG_SEND                    0x8400006EU
#define FFA_MSG_POLL                    0x8400006AU

/*
 * Structs below ending with _1_0 are defined in FF-A-1.0-REL and
 * struct ending with _1_1 are defined in FF-A-1.1-REL0.
 */

/* Partition information descriptor */
struct ffa_partition_info_1_0 {
    uint16_t id;
    uint16_t execution_context;
    uint32_t partition_properties;
};

struct ffa_partition_info_1_1 {
    uint16_t id;
    uint16_t execution_context;
    uint32_t partition_properties;
    uint8_t uuid[16];
};

/* Constituent memory region descriptor */
struct ffa_address_range {
    uint64_t address;
    uint32_t page_count;
    uint32_t reserved;
};

/* Composite memory region descriptor */
struct ffa_mem_region {
    uint32_t total_page_count;
    uint32_t address_range_count;
    uint64_t reserved;
    struct ffa_address_range address_range_array[];
};

/* Memory access permissions descriptor */
struct ffa_mem_access_perm {
    uint16_t endpoint_id;
    uint8_t perm;
    uint8_t flags;
};

/* Endpoint memory access descriptor */
struct ffa_mem_access {
    struct ffa_mem_access_perm access_perm;
    uint32_t region_offs;
    uint64_t reserved;
};

/* Lend, donate or share memory transaction descriptor */
struct ffa_mem_transaction_1_0 {
    uint16_t sender_id;
    uint8_t mem_reg_attr;
    uint8_t reserved0;
    uint32_t flags;
    uint64_t global_handle;
    uint64_t tag;
    uint32_t reserved1;
    uint32_t mem_access_count;
    struct ffa_mem_access mem_access_array[];
};

struct ffa_mem_transaction_1_1 {
    uint16_t sender_id;
    uint16_t mem_reg_attr;
    uint32_t flags;
    uint64_t global_handle;
    uint64_t tag;
    uint32_t mem_access_size;
    uint32_t mem_access_count;
    uint32_t mem_access_offs;
    uint8_t reserved[12];
};

/* Endpoint RX/TX descriptor */
struct ffa_endpoint_rxtx_descriptor_1_0 {
    uint16_t sender_id;
    uint16_t reserved;
    uint32_t rx_range_count;
    uint32_t tx_range_count;
};

struct ffa_endpoint_rxtx_descriptor_1_1 {
    uint16_t sender_id;
    uint16_t reserved;
    uint32_t rx_region_offs;
    uint32_t tx_region_offs;
};

struct ffa_ctx {
    void *rx;
    const void *tx;
    struct page_info *rx_pg;
    struct page_info *tx_pg;
    unsigned int page_count;
    uint32_t guest_vers;
    bool tx_is_mine;
    bool interrupted;
    spinlock_t lock;
};
/* Negotiated FF-A version to use with the SPMC */
static uint32_t ffa_version __ro_after_init;

/* SPs subscribing to VM_CREATE and VM_DESTROYED events */
static uint16_t *subscr_vm_created __read_mostly;
static unsigned int subscr_vm_created_count __read_mostly;
static uint16_t *subscr_vm_destroyed __read_mostly;
static unsigned int subscr_vm_destroyed_count __read_mostly;

/*
 * Our rx/tx buffers shared with the SPMC.
 *
 * ffa_page_count is the number of pages used in each of these buffers.
 *
 * The RX buffer is protected from concurrent usage with ffa_rx_buffer_lock.
 * Note that the SPMC is also tracking the ownership of our RX buffer so
 * for calls which uses our RX buffer to deliver a result we must call
 * ffa_rx_release() to let the SPMC know that we're done with the buffer.
 */
static void *ffa_rx __read_mostly;
static void *ffa_tx __read_mostly;
static unsigned int ffa_page_count __read_mostly;
static DEFINE_SPINLOCK(ffa_rx_buffer_lock);

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

static int32_t get_ffa_ret_code(const struct arm_smccc_1_2_regs *resp)
{
    switch ( resp->a0 )
    {
    case FFA_ERROR:
        if ( resp->a2 )
            return resp->a2;
        else
            return FFA_RET_NOT_SUPPORTED;
    case FFA_SUCCESS_32:
    case FFA_SUCCESS_64:
        return FFA_RET_OK;
    default:
        return FFA_RET_NOT_SUPPORTED;
    }
}

static int32_t ffa_simple_call(uint32_t fid, register_t a1, register_t a2,
                               register_t a3, register_t a4)
{
    const struct arm_smccc_1_2_regs arg = {
        .a0 = fid,
        .a1 = a1,
        .a2 = a2,
        .a3 = a3,
        .a4 = a4,
    };
    struct arm_smccc_1_2_regs resp;

    arm_smccc_1_2_smc(&arg, &resp);

    return get_ffa_ret_code(&resp);
}

static int32_t ffa_features(uint32_t id)
{
    return ffa_simple_call(FFA_FEATURES, id, 0, 0, 0);
}

static bool check_mandatory_feature(uint32_t id)
{
    uint32_t ret = ffa_features(id);

    if (ret)
        printk(XENLOG_ERR "ffa: mandatory feature id %#x missing\n", id);

    return !ret;
}

static int32_t ffa_rxtx_map(register_t tx_addr, register_t rx_addr,
                            uint32_t page_count)
{
    uint32_t fid = FFA_RXTX_MAP_32;

    if ( IS_ENABLED(CONFIG_ARM_64) )
        fid = FFA_RXTX_MAP_64;

    return ffa_simple_call(fid, tx_addr, rx_addr, page_count, 0);
}

static int32_t ffa_partition_info_get(uint32_t w1, uint32_t w2, uint32_t w3,
                                      uint32_t w4, uint32_t w5,
                                      uint32_t *count)
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

    ret = get_ffa_ret_code(&resp);
    if ( !ret )
        *count = resp.a2;

    return ret;
}

static int32_t ffa_rx_release(void)
{
    return ffa_simple_call(FFA_RX_RELEASE, 0, 0, 0, 0);
}

static int32_t ffa_direct_req_send_vm(uint16_t sp_id, uint16_t vm_id,
                                      uint8_t msg)
{
    uint32_t exp_resp = FFA_MSG_FLAG_FRAMEWORK;
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
    } while ( res == FFA_RET_INTERRUPTED || res == FFA_RET_RETRY );

    return res;
}

static uint16_t get_vm_id(const struct domain *d)
{
    /* +1 since 0 is reserved for the hypervisor in FF-A */
    return d->domain_id + 1;
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

static void set_regs_error(struct cpu_user_regs *regs, uint32_t error_code)
{
    set_regs(regs, FFA_ERROR, 0, error_code, 0, 0, 0, 0, 0);
}

static void set_regs_success(struct cpu_user_regs *regs, uint32_t w2,
                             uint32_t w3)
{
    set_regs(regs, FFA_SUCCESS_32, 0, w2, w3, 0, 0, 0, 0);
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
        tx_addr &= UINT32_MAX;
        rx_addr &= UINT32_MAX;
    }

    /* For now to keep things simple, only deal with a single page */
    if ( page_count != 1 )
        return FFA_RET_NOT_SUPPORTED;

    /* Already mapped */
    if ( ctx->rx )
        return FFA_RET_DENIED;

    tx_pg = get_page_from_gfn(d, gfn_x(gaddr_to_gfn(tx_addr)), &t, P2M_ALLOC);
    if ( !tx_pg )
        return FFA_RET_INVALID_PARAMETERS;
    /* Only normal RAM for now */
    if ( !p2m_is_ram(t) )
        goto err_put_tx_pg;

    rx_pg = get_page_from_gfn(d, gfn_x(gaddr_to_gfn(rx_addr)), &t, P2M_ALLOC);
    if ( !tx_pg )
        goto err_put_tx_pg;
    /* Only normal RAM for now */
    if ( !p2m_is_ram(t) )
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
    ctx->page_count = 1;
    ctx->tx_is_mine = true;
    return FFA_RET_OK;

err_unmap_tx:
    unmap_domain_page_global(tx);
err_put_rx_pg:
    put_page(rx_pg);
err_put_tx_pg:
    put_page(tx_pg);

    return ret;
}

static void rxtx_unmap(struct ffa_ctx *ctx)
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
    ctx->tx_is_mine = false;
}

static uint32_t handle_rxtx_unmap(void)
{
    struct domain *d = current->domain;
    struct ffa_ctx *ctx = d->arch.tee;

    if ( !ctx->rx )
        return FFA_RET_INVALID_PARAMETERS;

    rxtx_unmap(ctx);

    return FFA_RET_OK;
}

static uint32_t handle_partition_info_get(uint32_t w1, uint32_t w2, uint32_t w3,
                                          uint32_t w4, uint32_t w5,
                                          uint32_t *count)
{
    bool query_count_only = w5 & FFA_PARTITION_INFO_GET_COUNT_FLAG;
    uint32_t w5_mask = 0;
    uint32_t ret = FFA_RET_DENIED;
    struct domain *d = current->domain;
    struct ffa_ctx *ctx = d->arch.tee;

    /*
     * FF-A v1.0 has w5 MBZ while v1.1 allows
     * FFA_PARTITION_INFO_GET_COUNT_FLAG to be non-zero.
     */
    if ( ctx->guest_vers == FFA_VERSION_1_1 )
        w5_mask = FFA_PARTITION_INFO_GET_COUNT_FLAG;
    if ( w5 & ~w5_mask )
        return FFA_RET_INVALID_PARAMETERS;

    if ( query_count_only )
        return ffa_partition_info_get(w1, w2, w3, w4, w5, count);

    if ( !ffa_page_count )
        return FFA_RET_DENIED;

    spin_lock(&ctx->lock);
    spin_lock(&ffa_rx_buffer_lock);
    if ( !ctx->page_count || !ctx->tx_is_mine )
        goto out;
    ret = ffa_partition_info_get(w1, w2, w3, w4, w5, count);
    if ( ret )
        goto out;

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
        size_t sz = *count * sizeof(struct ffa_partition_info_1_1);

        if ( ctx->page_count * FFA_PAGE_SIZE < sz )
        {
            ret = FFA_RET_NO_MEMORY;
            goto out_rx_release;
        }


        memcpy(ctx->rx, ffa_rx, sz);
    }
    ctx->tx_is_mine = false;
out_rx_release:
    ffa_rx_release();
out:
    spin_unlock(&ffa_rx_buffer_lock);
    spin_unlock(&ctx->lock);

    return ret;
}

static uint32_t handle_rx_release(void)
{
    uint32_t ret = FFA_RET_DENIED;
    struct domain *d = current->domain;
    struct ffa_ctx *ctx = d->arch.tee;

    spin_lock(&ctx->lock);
    if ( !ctx->page_count || ctx->tx_is_mine )
        goto out;
    ret = FFA_RET_OK;
    ctx->tx_is_mine = true;
out:
    spin_unlock(&ctx->lock);

    return ret;
}

static void handle_msg_send_direct_req(struct cpu_user_regs *regs, uint32_t fid)
{
    struct arm_smccc_1_2_regs arg = { .a0 = fid, };
    struct arm_smccc_1_2_regs resp = { };
    struct domain *d = current->domain;
    struct ffa_ctx *ctx = d->arch.tee;
    uint32_t src_dst;
    uint64_t mask;

    if ( smccc_is_conv_64(fid) )
        mask = GENMASK_ULL(63, 0);
    else
        mask = GENMASK_ULL(31, 0);

    src_dst = get_user_reg(regs, 1);
    if ( (src_dst >> 16) != get_vm_id(d) )
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

    while ( true )
    {
        arm_smccc_1_2_smc(&arg, &resp);

        switch ( resp.a0 )
        {
        case FFA_INTERRUPT:
            ctx->interrupted = true;
            goto out;
        case FFA_ERROR:
        case FFA_SUCCESS_32:
        case FFA_SUCCESS_64:
        case FFA_MSG_SEND_DIRECT_RESP_32:
        case FFA_MSG_SEND_DIRECT_RESP_64:
            goto out;
        default:
            /* Bad fid, report back. */
            memset(&arg, 0, sizeof(arg));
            arg.a0 = FFA_ERROR;
            arg.a1 = src_dst;
            arg.a2 = FFA_RET_NOT_SUPPORTED;
            continue;
        }
    }

out:
    set_regs(regs, resp.a0, resp.a1 & mask, resp.a2 & mask, resp.a3 & mask,
             resp.a4 & mask, resp.a5 & mask, resp.a6 & mask, resp.a7 & mask);
}

static bool ffa_handle_call(struct cpu_user_regs *regs)
{
    uint32_t fid = get_user_reg(regs, 0);
    struct domain *d = current->domain;
    struct ffa_ctx *ctx = d->arch.tee;
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
        set_regs_success(regs, get_vm_id(d), 0);
        return true;
    case FFA_RXTX_MAP_32:
#ifdef CONFIG_ARM_64
    case FFA_RXTX_MAP_64:
#endif
        e = handle_rxtx_map(fid, get_user_reg(regs, 1), get_user_reg(regs, 2),
                            get_user_reg(regs, 3));
        if ( e )
            set_regs_error(regs, e);
        else
            set_regs_success(regs, 0, 0);
        return true;
    case FFA_RXTX_UNMAP:
        e = handle_rxtx_unmap();
        if ( e )
            set_regs_error(regs, e);
        else
            set_regs_success(regs, 0, 0);
        return true;
    case FFA_PARTITION_INFO_GET:
        e = handle_partition_info_get(get_user_reg(regs, 1),
                                      get_user_reg(regs, 2),
                                      get_user_reg(regs, 3),
                                      get_user_reg(regs, 4),
                                      get_user_reg(regs, 5), &count);
        if ( e )
            set_regs_error(regs, e);
        else
            set_regs_success(regs, count, 0);
        return true;
    case FFA_RX_RELEASE:
        e = handle_rx_release();
        if ( e )
            set_regs_error(regs, e);
        else
            set_regs_success(regs, 0, 0);
        return true;
    case FFA_MSG_SEND_DIRECT_REQ_32:
#ifdef CONFIG_ARM_64
    case FFA_MSG_SEND_DIRECT_REQ_64:
#endif
        handle_msg_send_direct_req(regs, fid);
        return true;

    default:
        gprintk(XENLOG_ERR, "ffa: unhandled fid 0x%x\n", fid);
        return false;
    }
}

static int ffa_domain_init(struct domain *d)
{
    struct ffa_ctx *ctx;
    unsigned int n;
    unsigned int m;
    unsigned int c_pos;
    int32_t res;

     /*
      * We can't use that last possible domain ID or get_vm_id() would cause
      * an overflow.
      */
    if ( !ffa_version || d->domain_id == UINT16_MAX)
        return -ENODEV;

    ctx = xzalloc(struct ffa_ctx);
    if ( !ctx )
        return -ENOMEM;

    for ( n = 0; n < subscr_vm_created_count; n++ )
    {
        res = ffa_direct_req_send_vm(subscr_vm_created[n], get_vm_id(d),
                                     FFA_MSG_SEND_VM_CREATED);
        if ( res )
        {
            printk(XENLOG_ERR "ffa: Failed to report creation of vm_id %u to  %u: res %d\n",
                   get_vm_id(d), subscr_vm_created[n], res);
            c_pos = n;
            goto err;
        }
    }

    d->arch.tee = ctx;

    return 0;

err:
    /* Undo any already sent vm created messaged */
    for ( n = 0; n < c_pos; n++ )
        for ( m = 0; m < subscr_vm_destroyed_count; m++ )
            if ( subscr_vm_destroyed[m] == subscr_vm_created[n] )
                ffa_direct_req_send_vm(subscr_vm_destroyed[n], get_vm_id(d),
                                       FFA_MSG_SEND_VM_DESTROYED);

    return -ENOMEM;
}

/* This function is supposed to undo what ffa_domain_init() has done */
static int ffa_relinquish_resources(struct domain *d)
{
    struct ffa_ctx *ctx = d->arch.tee;
    unsigned int n;
    int32_t res;

    if ( !ctx )
        return 0;

    for ( n = 0; n < subscr_vm_destroyed_count; n++ )
    {
        res = ffa_direct_req_send_vm(subscr_vm_destroyed[n], get_vm_id(d),
                                     FFA_MSG_SEND_VM_DESTROYED);

        if ( res )
            printk(XENLOG_ERR "ffa: Failed to report destruction of vm_id %u to  %u: res %d\n",
                   get_vm_id(d), subscr_vm_destroyed[n], res);
    }

    if ( ctx->rx )
        rxtx_unmap(ctx);

    XFREE(d->arch.tee);

    return 0;
}

static bool init_subscribers(void)
{
    struct ffa_partition_info_1_1 *fpi;
    bool ret = false;
    uint32_t count;
    int e;
    uint32_t n;
    uint32_t c_pos;
    uint32_t d_pos;

    if ( ffa_version < FFA_VERSION_1_1 )
        return true;

    e = ffa_partition_info_get(0, 0, 0, 0, 0, &count);
    if ( e )
    {
        printk(XENLOG_ERR "ffa: Failed to get list of SPs: %d\n", e);
        goto out;
    }

    fpi = ffa_rx;
    subscr_vm_created_count = 0;
    subscr_vm_destroyed_count = 0;
    for ( n = 0; n < count; n++ )
    {
        if (fpi[n].partition_properties & FFA_PART_PROP_NOTIF_CREATED)
            subscr_vm_created_count++;
        if (fpi[n].partition_properties & FFA_PART_PROP_NOTIF_DESTROYED)
            subscr_vm_destroyed_count++;
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
        subscr_vm_created_count = 0;
        subscr_vm_destroyed_count = 0;
        XFREE(subscr_vm_created);
        XFREE(subscr_vm_destroyed);
        goto out;
    }

    for ( c_pos = 0, d_pos = 0, n = 0; n < count; n++ )
    {
        if ( fpi[n].partition_properties & FFA_PART_PROP_NOTIF_CREATED )
            subscr_vm_created[c_pos++] = fpi[n].id;
        if ( fpi[n].partition_properties & FFA_PART_PROP_NOTIF_DESTROYED )
            subscr_vm_destroyed[d_pos++] = fpi[n].id;
    }

    ret = true;
out:
    ffa_rx_release();

    return ret;
}

static bool ffa_probe(void)
{
    uint32_t vers;
    int e;
    unsigned int major_vers;
    unsigned int minor_vers;

    /*
     * FF-A often works in units of 4K pages and currently it's assumed
     * that we can map memory using that granularity. See also the comment
     * above the FFA_PAGE_SIZE define.
     *
     * It is possible to support a PAGE_SIZE larger than 4K in Xen, but
     * until that is fully handled in this code make sure that we only use
     * 4K page sizes.
     */
    BUILD_BUG_ON(PAGE_SIZE != FFA_PAGE_SIZE);

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

    if ( !check_mandatory_feature(FFA_PARTITION_INFO_GET) ||
         !check_mandatory_feature(FFA_RX_RELEASE) ||
#ifdef CONFIG_ARM_64
         !check_mandatory_feature(FFA_RXTX_MAP_64) ||
#endif
#ifdef CONFIG_ARM_32
         !check_mandatory_feature(FFA_RXTX_MAP_32) ||
#endif
         !check_mandatory_feature(FFA_RXTX_UNMAP) ||
         !check_mandatory_feature(FFA_MSG_SEND_DIRECT_REQ_32) )
        return false;

    ffa_rx = alloc_xenheap_pages(0, 0);
    if ( !ffa_rx )
        return false;

    ffa_tx = alloc_xenheap_pages(0, 0);
    if ( !ffa_tx )
        goto err_free_ffa_rx;

    e = ffa_rxtx_map(__pa(ffa_tx), __pa(ffa_rx), 1);
    if ( e )
    {
        printk(XENLOG_ERR "ffa: Failed to map rxtx: error %d\n", e);
        goto err_free_ffa_tx;
    }
    ffa_page_count = 1;
    ffa_version = vers;

    if ( !init_subscribers() )
        goto err_free_ffa_tx;

    return true;

err_free_ffa_tx:
    free_xenheap_pages(ffa_tx, 0);
    ffa_tx = NULL;
err_free_ffa_rx:
    free_xenheap_pages(ffa_rx, 0);
    ffa_rx = NULL;
    ffa_page_count = 0;
    ffa_version = 0;
    XFREE(subscr_vm_created);
    subscr_vm_created_count = 0;
    XFREE(subscr_vm_destroyed);
    subscr_vm_destroyed_count = 0;

    return false;
}

static const struct tee_mediator_ops ffa_ops =
{
    .probe = ffa_probe,
    .domain_init = ffa_domain_init,
    .relinquish_resources = ffa_relinquish_resources,
    .handle_call = ffa_handle_call,
};

REGISTER_TEE_MEDIATOR(ffa, "FF-A", XEN_DOMCTL_CONFIG_TEE_FFA, &ffa_ops);
