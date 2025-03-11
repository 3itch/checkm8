/*
 * acpi.c: ACPI utility fns
 *
 * Copyright (c) 2010, Intel Corporation
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
#include <io.h>
#include <string.h>
#include <printk.h>
#include <tboot.h>
#include <loader.h>
#include <acpi.h>
#include <misc.h>
#include <cmdline.h>
#include <pci_cfgreg.h>

#ifdef ACPI_DEBUG
#define acpi_printk         printk
#else
#define acpi_printk(...)    /* */
#endif

static struct acpi_rsdp *rsdp;

static void dump_gas(const char *reg_name,
                     const tboot_acpi_generic_address_t *reg)
{
    const char *space_id[] = { "memory", "I/O", "PCI config space", "EC",
                               "SMBus" };

    printk(TBOOT_DETA"%s GAS @ %p:\n", reg_name, reg);
    if ( reg == NULL )
        return;

    if ( reg->space_id >= ARRAY_SIZE(space_id) )
        printk(TBOOT_DETA"\t space_id: unsupported (%u)\n", reg->space_id);
    else
        printk(TBOOT_DETA"\t space_id: %s\n", space_id[reg->space_id]);
    printk(TBOOT_DETA"\t bit_width: %u\n", reg->bit_width);
    printk(TBOOT_DETA"\t bit_offset: %u\n", reg->bit_offset);
    printk(TBOOT_DETA"\t access_width: %u\n", reg->access_width);
    printk(TBOOT_DETA"\t address: %Lx\n", reg->address);
}

static inline struct acpi_rsdt *get_rsdt(void)
{
    return (struct acpi_rsdt *)rsdp->rsdp1.rsdt;
}

static inline struct acpi_xsdt *get_xsdt(void)
{
    if ( rsdp->rsdp_xsdt >= 0x100000000ULL ) {
        printk(TBOOT_ERR"XSDT above 4GB\n");
        return NULL;
    }
    return (struct acpi_xsdt *)(uintptr_t)rsdp->rsdp_xsdt;
}

static bool verify_acpi_checksum(uint8_t *start, uint8_t len)
{
    uint8_t sum = 0;
    while ( len ) {
        sum += *start++;
        len--;
    }
    return (sum == 0);
}

static bool find_rsdp_in_range(void *start, void *end)
{
#define RSDP_BOUNDARY    16  /* rsdp ranges on 16-byte boundaries */
#define RSDP_CHKSUM_LEN  20  /* rsdp check sum length, defined in ACPI 1.0 */

    for ( ; start < end; start += RSDP_BOUNDARY ) {
        rsdp = (struct acpi_rsdp *)start;

        if ( tb_memcmp(rsdp->rsdp1.signature, RSDP_SIG,
                    sizeof(rsdp->rsdp1.signature)) == 0 ) {
            if ( verify_acpi_checksum((uint8_t *)rsdp, RSDP_CHKSUM_LEN) ) {
                printk(TBOOT_DETA"RSDP (v%u, %.6s) @ %p\n", rsdp->rsdp1.revision,
                       rsdp->rsdp1.oemid, rsdp);
                return true;
            }
            else {
                printk(TBOOT_ERR"checksum failed.\n");
                return false;
            }
        }
    }
    return false;
}

extern loader_ctx *g_ldr_ctx;

static bool find_rsdp(void)
{
    uint32_t length;
    uint8_t *ldr_rsdp = NULL;

    if ( rsdp != NULL )
        return true;

    /* for grins, let's try asking the loader_ctx if it has a copy */
    ldr_rsdp = get_loader_rsdp(g_ldr_ctx, &length);
    if (ldr_rsdp != NULL){
        rsdp = (struct acpi_rsdp *) ldr_rsdp;
        return true;
    }

    /*  0x00 - 0x400 */
    if ( find_rsdp_in_range(RSDP_SCOPE1_LOW, RSDP_SCOPE1_HIGH) )
        return true;

    /* 0xE0000 - 0x100000 */
    if ( find_rsdp_in_range(RSDP_SCOPE2_LOW, RSDP_SCOPE2_HIGH) )
        return true;

    printk(TBOOT_ERR"can't find RSDP\n");
    rsdp = NULL;
    return false;
}

struct acpi_rsdp
*get_rsdp(loader_ctx *lctx)
{
    if (rsdp != NULL)
        return rsdp;
    if (true == find_rsdp())
        return rsdp;
    /* so far we're striking out.  Must have been an EFI lauch */
    if (false == is_loader_launch_efi(lctx)){
        /* uncle */
        return NULL;
    }
    /* EFI launch, and the loader didn't grace us with an ACPI tag.
     * We can try to find this the hard way, right?
     */
    return NULL;
}

/* this function can find dmar table whether or not it was hidden */
static struct acpi_table_header *find_table(const char *table_name)
{
    if ( !find_rsdp() ) {
        printk(TBOOT_ERR"no rsdp to use\n");
        return NULL;
    }

    struct acpi_table_header *table = NULL;
    struct acpi_xsdt *xsdt = get_xsdt(); /* it is ok even on 1.0 tables */
                                         /* because value will be ignored */

    if ( rsdp->rsdp1.revision >= 2 && xsdt != NULL ) { /*  ACPI 2.0+ */
        for ( uint64_t *curr_table = xsdt->table_offsets;
              curr_table < (uint64_t *)((void *)xsdt + xsdt->hdr.length);
              curr_table++ ) {
            table = (struct acpi_table_header *)(uintptr_t)*curr_table;
            if ( tb_memcmp(table->signature, table_name,
                        sizeof(table->signature)) == 0 )
                return table;
        }
    }
    else {                             /* ACPI 1.0 */
        struct acpi_rsdt *rsdt = get_rsdt();

        if ( rsdt == NULL ) {
            printk(TBOOT_ERR"rsdt is invalid.\n");
            return NULL;
        }

        for ( uint32_t *curr_table = rsdt->table_offsets;
              curr_table < (uint32_t *)((void *)rsdt + rsdt->hdr.length);
              curr_table++ ) {
            table = (struct acpi_table_header *)(uintptr_t)*curr_table;
            if ( tb_memcmp(table->signature, table_name,
                        sizeof(table->signature)) == 0 )
                return table;
        }
    }

    printk(TBOOT_ERR"can't find %s table.\n", table_name);
    return NULL;
}

static struct acpi_madt *get_apic_table(void)
{
    return (struct acpi_madt *)find_table(MADT_SIG);
}

uint32_t get_madt_apic_base(void)
{
    struct acpi_madt *madt = get_apic_table();
    if ( madt == NULL ) {
        printk(TBOOT_ERR"no MADT table found\n");
        return 0;
    }
    return (uint32_t)madt->local_apic_address;
}

struct acpi_table_ioapic *get_acpi_ioapic_table(void)
{
    struct acpi_madt *madt = get_apic_table();
    if ( madt == NULL ) {
        printk(TBOOT_ERR"no MADT table found\n");
        return NULL;
    }

    /* APIC tables begin after MADT */
    union acpi_madt_entry *entry = (union acpi_madt_entry *)(madt + 1);

	while ( (void *)entry < ((void *)madt + madt->hdr.length) ) {
		uint8_t length = entry->madt_lapic.length;

		if ( entry->madt_lapic.apic_type == ACPI_MADT_IOAPIC ) {
			if ( length != sizeof(entry->madt_ioapic) ) {
                printk(TBOOT_ERR"APIC length error.\n");
                return NULL;
            }
            return (struct acpi_table_ioapic *)entry;
        }
		entry = (void *)entry + length;
	}
    printk(TBOOT_ERR"no IOAPIC type.\n");
    return NULL;
}

struct acpi_mcfg *get_acpi_mcfg_table(void)
{
    return (struct acpi_mcfg *)find_table(MCFG_SIG);
}

struct acpi_dmar *get_vtd_dmar_table(void)
{
    return (struct acpi_dmar *)find_table(DMAR_SIG);
}

static bool write_to_reg(const tboot_acpi_generic_address_t *reg,
                         uint32_t val)
{
    if ( reg->address >= 100000000ULL ) {
        printk(TBOOT_ERR"GAS address >4GB (0x%Lx)\n", reg->address);
        return false;
    }
    uint32_t address = (uint32_t)reg->address;

    if ( reg->space_id == GAS_SYSTEM_IOSPACE ) {
        switch ( reg->bit_width ) {
            case 8:
                outb(address, (uint8_t)val);
                return true;
            case 16:
                outw(address, (uint16_t)val);
                return true;
            case 32:
                outl(address, val);
                return true;
            default:
                printk(TBOOT_ERR"unsupported GAS bit width: %u\n", reg->bit_width);
                return false;
        }
    }
    else if ( reg->space_id == GAS_SYSTEM_MEMORY ) {
        switch ( reg->bit_width ) {
            case 8:
                writeb(address, (uint8_t)val);
                return true;
            case 16:
                writew(address, (uint16_t)val);
                return true;
            case 32:
                writel(address, val);
                return true;
            default:
                printk(TBOOT_ERR"unsupported GAS bit width: %u\n", reg->bit_width);
                return false;
        }
    }

    printk(TBOOT_ERR"unsupported GAS addr space ID: %u\n", reg->space_id);
    return false;
}

static bool read_from_reg(const tboot_acpi_generic_address_t *reg,
                          uint32_t *val)
{
    if ( reg->address >= 100000000ULL ) {
        printk(TBOOT_ERR"GAS address >4GB (0x%Lx)\n", reg->address);
        return false;
    }
    uint32_t address = (uint32_t)reg->address;

    if ( reg->space_id == GAS_SYSTEM_IOSPACE ) {
        switch ( reg->bit_width ) {
            case 8:
                *val = inb(address);
                return true;
            case 16:
                *val = inw(address);
                return true;
            case 32:
                *val = inl(address);
                return true; default:
                printk(TBOOT_ERR"unsupported GAS bit width: %u\n", reg->bit_width);
                return false;
        }
    }
    else if ( reg->space_id == GAS_SYSTEM_MEMORY ) {
        switch ( reg->bit_width ) {
            case 8:
                *val = readb(address);
                return true;
            case 16:
                *val = readw(address);
                return true;
            case 32:
                *val = readl(address);
                return true;
            default:
                printk(TBOOT_ERR"unsupported GAS bit width: %u\n", reg->bit_width);
                return false;
        }
    }

    printk(TBOOT_ERR"unsupported GAS addr space ID: %u\n", reg->space_id);
    return false;
}

static void wait_to_sleep(const tboot_acpi_sleep_info_t *acpi_sinfo)
{
#define WAKE_STATUS    0x8000    /* the 15th bit */
    while ( true ) {
        uint32_t pm1a_value = 0, pm1b_value = 0;

        if ( acpi_sinfo->pm1a_evt_blk.address ) {
            if ( read_from_reg(&acpi_sinfo->pm1a_evt_blk, &pm1a_value) &&
                 ( pm1a_value & WAKE_STATUS ) )
                return;
        }

        if ( acpi_sinfo->pm1b_evt_blk.address ) {
            if ( read_from_reg(&acpi_sinfo->pm1b_evt_blk, &pm1b_value) &&
                 ( pm1b_value & WAKE_STATUS ) )
                return;
        }
    }
}

bool machine_sleep(const tboot_acpi_sleep_info_t *acpi_sinfo)
{
    dump_gas("PM1A", &acpi_sinfo->pm1a_cnt_blk);
    dump_gas("PM1B", &acpi_sinfo->pm1b_cnt_blk);

    wbinvd();

    if ( acpi_sinfo->pm1a_cnt_blk.address ) {
        if ( !write_to_reg(&acpi_sinfo->pm1a_cnt_blk, acpi_sinfo->pm1a_cnt_val) )
            return false;;
    }

    if ( acpi_sinfo->pm1b_cnt_blk.address ) {
        if ( !write_to_reg(&acpi_sinfo->pm1b_cnt_blk, acpi_sinfo->pm1b_cnt_val) )
            return false;
    }

    /* just to wait, the machine may shutdown before here */
    wait_to_sleep(acpi_sinfo);
    return true; 
}

void set_s3_resume_vector(const tboot_acpi_sleep_info_t *acpi_sinfo,
                          uint64_t resume_vector)
{
    if ( acpi_sinfo->vector_width <= 32 )
        *(uint32_t *)(unsigned long)(acpi_sinfo->wakeup_vector) =
                                    (uint32_t)resume_vector;
    else if ( acpi_sinfo->vector_width <= 64 )
        *(uint64_t *)(unsigned long)(acpi_sinfo->wakeup_vector) =
                                    resume_vector;
    else
        printk(TBOOT_WARN"vector_width error.\n");

    acpi_printk(TBOOT_DETA"wakeup_vector_address = %llx\n", acpi_sinfo->wakeup_vector);
    acpi_printk(TBOOT_DETA"wakeup_vector_value = %llxx\n", resume_vector);
}

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
