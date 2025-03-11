/*
 * vtd.c: VT-d support functions
 *
 * Copyright (c) 2019, Intel Corporation
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above
 *     copyright notice, this list of conditions and the following
 *     disclaimer in the documentation and/or other materials provided
 *     with the distribution.
 *   * Neither the name of the Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <types.h>
#include <stdbool.h>
#include <compiler.h>
#include <processor.h>
#include <printk.h>
#include <tboot.h>
#include <loader.h>
#include <string.h>
#include <acpi.h>
#include <txt/config_regs.h>

#include <vtd.h>

static struct acpi_table_header *g_dmar_table;
static __data bool g_hide_dmar;

bool vtd_bios_enabled(void)
{
    return get_vtd_dmar_table() != NULL; 
}

bool vtd_save_dmar_table(void)
{
    /* find DMAR table and save it */
    g_dmar_table = (struct acpi_table_header *)get_vtd_dmar_table();

    printk(TBOOT_DETA"DMAR table @ %p saved.\n", g_dmar_table);
    return true;
}

bool vtd_restore_dmar_table(void)
{
    struct acpi_table_header *hdr;

    g_hide_dmar = false;

    /* find DMAR table first */
    hdr = (struct acpi_table_header *)get_vtd_dmar_table();
    if ( hdr != NULL ) {
        printk(TBOOT_DETA"DMAR table @ %p is still there, skip restore step.\n", hdr);
        return true;
    }

    /* check saved DMAR table */
    if ( g_dmar_table == NULL ) {
        printk(TBOOT_ERR"No DMAR table saved, abort restore step.\n");
        return false;
    }

    /* restore DMAR if needed */
    tb_memcpy(g_dmar_table->signature, DMAR_SIG, sizeof(g_dmar_table->signature));

    /* need to hide DMAR table while resume from S3 */
    g_hide_dmar = true;
    printk(TBOOT_DETA"DMAR table @ %p restored.\n", hdr);
    return true;
}

bool vtd_remove_dmar_table(void)
{
    struct acpi_table_header *hdr;

    /* check whether it is needed */
    if ( !g_hide_dmar ) {
        printk(TBOOT_DETA"No need to hide DMAR table.\n");
        return true;
    }

    /* find DMAR table */
    hdr = (struct acpi_table_header *)get_vtd_dmar_table();
    if ( hdr == NULL ) {
        printk(TBOOT_DETA"No DMAR table, skip remove step.\n");
        return true;
    }

    /* remove DMAR table */
    hdr->signature[0] = '\0';
    printk(TBOOT_DETA"DMAR table @ %p removed.\n", hdr);
    return true;
}

struct dmar_remapping *vtd_get_dmar_remap(uint32_t *remap_length)
{
    struct acpi_dmar *dmar = get_vtd_dmar_table();

    if (dmar == NULL || remap_length == NULL) {
        return NULL;
    }

    *remap_length = dmar->hdr.length - sizeof(*dmar);
    return (struct dmar_remapping*)(dmar->table_offsets);
}

bool vtd_disable_dma_remap(struct dmar_remapping *rs)
{
    if (rs->type != DMAR_REMAPPING_DRHD) {
        return false;
    }

    uint32_t timeout;
    uint32_t gsts = read_reg32(rs->register_base_address, VTD_GSTS_OFFSET) & 0x96FFFFFF;
    
    if (gsts & TE_STAT) {
        /* Clear TE_STAT bit and write back to GCMD */
        gsts &= ~TE_STAT;
        write_reg32(rs->register_base_address, VTD_GCMD_OFFSET, gsts);

        /* Wait until GSTS indicates that operation is completed */
        timeout = VTD_OPERATION_TIMEOUT;
        while (read_reg32(rs->register_base_address, VTD_GSTS_OFFSET) & TE_STAT) {
            cpu_relax();
            if (--timeout == 0) {
                return false;
            }
        }
    }

    return true;
}

bool vtd_disable_qie(struct dmar_remapping *rs)
{
    if (rs->type != DMAR_REMAPPING_DRHD) {
        return false;
    }

    uint32_t timeout;
    uint32_t gsts = read_reg32(rs->register_base_address, VTD_GSTS_OFFSET) & 0x96FFFFFF;

    if (gsts & QIE_STAT) {
        /* Wait for HW to complete pending invalidation requests */
        timeout = VTD_OPERATION_TIMEOUT;
        while (read_reg64(rs->register_base_address, VTD_IQT_OFFSET) !=
               read_reg64(rs->register_base_address, VTD_IQH_OFFSET)) {
            cpu_relax();
            if (--timeout == 0) {
                return false;
            }
        }

        /* Clear QIE_STAT bit and write back to GCMD */
        gsts &= ~QIE_STAT;
        write_reg32(rs->register_base_address, VTD_GCMD_OFFSET, gsts);

        /* Wait until GSTS indicates that operation is completed */
        timeout = VTD_OPERATION_TIMEOUT;
        while (read_reg32(rs->register_base_address, VTD_GSTS_OFFSET) & QIE_STAT) {
            cpu_relax();
            if (--timeout == 0) {
                return false;
            }
        }

        /* Set IQT to 0 (IQH was set by HW) */
        write_reg64(rs->register_base_address, VTD_IQT_OFFSET, 0);
    }

    return true;
}

bool vtd_disable_ire(struct dmar_remapping *rs)
{
    if (rs->type != DMAR_REMAPPING_DRHD) {
        return false;
    }

    uint32_t timeout;
    uint32_t gsts = read_reg32(rs->register_base_address, VTD_GSTS_OFFSET) & 0x96FFFFFF;
    
    if (gsts & IRE_STAT) {
        /* Clear IRE_STAT bit and write back to GCMD */
        gsts &= ~IRE_STAT;
        write_reg32(rs->register_base_address, VTD_GCMD_OFFSET, gsts);

        /* Wait until GSTS indicates that operation is completed */
        timeout = VTD_OPERATION_TIMEOUT;
        while (read_reg32(rs->register_base_address, VTD_GSTS_OFFSET) & IRE_STAT) {
            cpu_relax();
            if (--timeout == 0) {
                return false;
            }
        }
    }

    return true;
}