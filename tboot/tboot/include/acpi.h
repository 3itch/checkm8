/*	$OpenBSD: acpireg.h,v 1.17 2009/04/11 08:22:48 kettenis Exp $	*/
/*
 * Copyright (c) 2005 Thorsten Lockert <tholo@sigmasoft.com>
 * Copyright (c) 2005 Marco Peereboom <marco@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
/*
 * Portions copyright (c) 2010, Intel Corporation
 */

#ifndef __ACPI_H__
#define __ACPI_H__

//#define ACPI_DEBUG

#define RSDP_SCOPE1_LOW    (void *)0x000000
#define RSDP_SCOPE1_HIGH   (void *)0x000400
#define RSDP_SCOPE2_LOW    (void *)0x0E0000
#define RSDP_SCOPE2_HIGH   (void *)0x100000

/*	Root System Descriptor Pointer (RSDP) for ACPI 1.0 */
struct acpi_rsdp1 {
	u_int8_t	signature[8];
#define	RSDP_SIG	"RSD PTR "

	u_int8_t	checksum;	/* make sum == 0 */
	u_int8_t	oemid[6];
	u_int8_t	revision;	/* 0 for v1.0, 2 for v2.0 */
	u_int32_t	rsdt;		/* physical */
} __packed;

/*	Root System Descriptor Pointer (RSDP) for ACPI 2.0 */
struct acpi_rsdp {
	struct acpi_rsdp1 rsdp1;
	/*
	 * The following values are only valid
	 * when rsdp_revision == 2
	 */
	u_int32_t	rsdp_length;		/* length of rsdp */
	u_int64_t	rsdp_xsdt;			/* physical */
	u_int8_t	rsdp_extchecksum;	/* entire table */
	u_int8_t	rsdp_reserved[3];	/* must be zero */
} __packed;

/* Common System Description Table Header */
struct acpi_table_header {
	u_int8_t	signature[4];
	u_int32_t	length;
	u_int8_t	revision;
	u_int8_t	checksum;
	u_int8_t	oemid[6];
	u_int8_t	oemtableid[8];
	u_int32_t	oemrevision;

	u_int8_t	aslcompilerid[4];
	u_int32_t	aslcompilerrevision;
} __packed;

/* Root System Description Table (RSDT) */
struct acpi_rsdt {
	struct acpi_table_header	hdr;
#define RSDT_SIG	"RSDT"

	u_int32_t			table_offsets[1];
} __packed;

/* Extended System Descriptiion Table */
struct acpi_xsdt {
	struct acpi_table_header	hdr;
#define XSDT_SIG	"XSDT"

	u_int64_t			table_offsets[1];
} __packed;


/* Generic Address Structure */
struct acpi_gas {
	u_int8_t	address_space_id;
#define GAS_SYSTEM_MEMORY		0
#define GAS_SYSTEM_IOSPACE		1
#define GAS_PCI_CFG_SPACE		2
#define GAS_EMBEDDED			3
#define GAS_SMBUS				4
#define GAS_FUNCTIONAL_FIXED	127
	u_int8_t	register_bit_width;
	u_int8_t	register_bit_offset;
	u_int8_t	access_size;
#define GAS_ACCESS_UNDEFINED	0
#define GAS_ACCESS_BYTE			1
#define GAS_ACCESS_WORD			2
#define GAS_ACCESS_DWORD		3
#define GAS_ACCESS_QWORD		4
	u_int64_t	address;
} __packed;

/* Fixed ACPI Descriptiion Table */
struct acpi_fadt {
	struct acpi_table_header	hdr;
#define	FADT_SIG	"FACP"

	u_int32_t	firmware_ctl;	/* phys addr FACS */
	u_int32_t	dsdt;			/* phys addr DSDT */

  /* int_model is defined in ACPI 1.0, in ACPI 2.0, it should be zero */
	u_int8_t	int_model;		/* interrupt model (hdr_revision < 3) */

#define	FADT_INT_DUAL_PIC	0
#define	FADT_INT_MULTI_APIC	1
	u_int8_t	pm_profile;		/* power mgmt profile */
#define	FADT_PM_UNSPEC		0
#define	FADT_PM_DESKTOP		1
#define	FADT_PM_MOBILE		2
#define	FADT_PM_WORKSTATION	3
#define	FADT_PM_ENT_SERVER	4
#define	FADT_PM_SOHO_SERVER	5
#define	FADT_PM_APPLIANCE	6
#define	FADT_PM_PERF_SERVER	7
	u_int16_t	sci_int;		/* SCI interrupt */
	u_int32_t	smi_cmd;		/* SMI command port */
	u_int8_t	acpi_enable;	/* value to enable */
	u_int8_t	acpi_disable;	/* value to disable */
	u_int8_t	s4bios_req;		/* value for S4 */
	u_int8_t	pstate_cnt;		/* value for performance (hdr_revision > 2) */
	u_int32_t	pm1a_evt_blk;	/* power management 1a */
	u_int32_t	pm1b_evt_blk;	/* power mangement 1b */
	u_int32_t	pm1a_cnt_blk;	/* pm control 1a */
	u_int32_t	pm1b_cnt_blk;	/* pm control 1b */
	u_int32_t	pm2_cnt_blk;	/* pm control 2 */
	u_int32_t	pm_tmr_blk;
	u_int32_t	gpe0_blk;
	u_int32_t	gpe1_blk;
	u_int8_t	pm1_evt_len;
	u_int8_t	pm1_cnt_len;
	u_int8_t	pm2_cnt_len;
	u_int8_t	pm_tmr_len;
	u_int8_t	gpe0_blk_len;
	u_int8_t	gpe1_blk_len;
	u_int8_t	gpe1_base;
	u_int8_t	cst_cnt;		/* (hdr_revision > 2) */
	u_int16_t	p_lvl2_lat;
	u_int16_t	p_lvl3_lat;
	u_int16_t	flush_size;
	u_int16_t	flush_stride;
	u_int8_t	duty_offset;
	u_int8_t	duty_width;
	u_int8_t	day_alrm;
	u_int8_t	mon_alrm;
	u_int8_t	century;
	u_int16_t	iapc_boot_arch;	/* (hdr_revision > 2) */
#define	FADT_LEGACY_DEVICES		0x0001	/* Legacy devices supported */
#define	FADT_i8042				0x0002	/* Keyboard controller present */
#define	FADT_NO_VGA				0x0004	/* Do not probe VGA */
	u_int8_t	reserved1;
	u_int32_t	flags;
#define	FADT_WBINVD						0x00000001
#define	FADT_WBINVD_FLUSH				0x00000002
#define	FADT_PROC_C1					0x00000004
#define	FADT_P_LVL2_UP					0x00000008
#define	FADT_PWR_BUTTON					0x00000010
#define	FADT_SLP_BUTTON					0x00000020
#define	FADT_FIX_RTC					0x00000040
#define	FADT_RTC_S4						0x00000080
#define	FADT_TMR_VAL_EXT				0x00000100
#define	FADT_DCK_CAP					0x00000200
#define	FADT_RESET_REG_SUP				0x00000400
#define	FADT_SEALED_CASE				0x00000800
#define	FADT_HEADLESS					0x00001000
#define	FADT_CPU_SW_SLP					0x00002000
#define	FADT_PCI_EXP_WAK				0x00004000
#define	FADT_USE_PLATFORM_CLOCK			0x00008000
#define	FADT_S4_RTC_STS_VALID			0x00010000
#define	FADT_REMOTE_POWER_ON_CAPABLE	0x00020000
#define	FADT_FORCE_APIC_CLUSTER_MODEL	0x00040000
#define	FADT_FORCE_APIC_PHYS_DEST_MODE	0x00080000
	/*
	 * Following values only exist when rev > 1
	 * If the extended addresses exists, they
	 * must be used in preferense to the non-
	 * extended values above
	 */
	struct acpi_gas	reset_reg;
	u_int8_t	reset_value;

	u_int8_t	reserved2a;
	u_int8_t	reserved2b;
	u_int8_t	reserved2c;

	u_int64_t	x_firmware_ctl;
	u_int64_t	x_dsdt;
	struct acpi_gas	x_pm1a_evt_blk;
	struct acpi_gas	x_pm1b_evt_blk;
	struct acpi_gas	x_pm1a_cnt_blk;
	struct acpi_gas	x_pm1b_cnt_blk;
	struct acpi_gas	x_pm2_cnt_blk;
	struct acpi_gas	x_pm_tmr_blk;
	struct acpi_gas	x_gpe0_blk;
	struct acpi_gas	x_gpe1_blk;
} __packed;

struct acpi_madt {
	struct acpi_table_header	hdr;
#define MADT_SIG	"APIC"

	u_int32_t	local_apic_address;
	u_int32_t	flags;
#define ACPI_APIC_PCAT_COMPAT	0x00000001
} __packed;

struct acpi_madt_lapic {
	u_int8_t	apic_type;
#define	ACPI_MADT_LAPIC		0
	u_int8_t	length;
	u_int8_t	acpi_proc_id;
	u_int8_t	apic_id;
	u_int32_t	flags;
#define	ACPI_PROC_ENABLE	0x00000001
} __packed;

struct acpi_madt_ioapic {
	u_int8_t	apic_type;
#define	ACPI_MADT_IOAPIC	1
	u_int8_t	length;
	u_int8_t	acpi_ioapic_id;
	u_int8_t	reserved;
	u_int32_t	address;
	u_int32_t	global_int_base;
} __packed;
typedef struct acpi_madt_ioapic acpi_table_ioapic_t;

struct acpi_madt_override {
	u_int8_t	apic_type;
#define	ACPI_MADT_OVERRIDE	2
	u_int8_t	length;
	u_int8_t	bus;
#define	ACPI_OVERRIDE_BUS_ISA	0
	u_int8_t	source;
	u_int32_t	global_int;
	u_int16_t	flags;
#define	ACPI_OVERRIDE_POLARITY_BITS	0x3
#define	ACPI_OVERRIDE_POLARITY_BUS		0x0
#define	ACPI_OVERRIDE_POLARITY_HIGH		0x1
#define	ACPI_OVERRIDE_POLARITY_LOW		0x3
#define	ACPI_OVERRIDE_TRIGGER_BITS	0xc
#define	ACPI_OVERRIDE_TRIGGER_BUS		0x0
#define	ACPI_OVERRIDE_TRIGGER_EDGE		0x4
#define	ACPI_OVERRIDE_TRIGGER_LEVEL		0xc
} __packed;

struct acpi_madt_nmi {
	u_int8_t	apic_type;
#define	ACPI_MADT_NMI		3
	u_int8_t	length;
	u_int16_t	flags;		/* Same flags as acpi_madt_override */
	u_int32_t	global_int;
} __packed;

struct acpi_madt_lapic_nmi {
	u_int8_t	apic_type;
#define	ACPI_MADT_LAPIC_NMI	4
	u_int8_t	length;
	u_int8_t	acpi_proc_id;
	u_int16_t	flags;		/* Same flags as acpi_madt_override */
	u_int8_t	local_apic_lint;
} __packed;

struct acpi_madt_lapic_override {
	u_int8_t	apic_type;
#define	ACPI_MADT_LAPIC_OVERRIDE	5
	u_int8_t	length;
	u_int16_t	reserved;
	u_int64_t	lapic_address;
} __packed;

struct acpi_madt_io_sapic {
	u_int8_t	apic_type;
#define	ACPI_MADT_IO_SAPIC	6
	u_int8_t	length;
	u_int8_t	iosapic_id;
	u_int8_t	reserved;
	u_int32_t	global_int_base;
	u_int64_t	iosapic_address;
} __packed;

struct acpi_madt_local_sapic {
	u_int8_t	apic_type;
#define	ACPI_MADT_LOCAL_SAPIC	7
	u_int8_t	length;
	u_int8_t	acpi_proc_id;
	u_int8_t	local_sapic_id;
	u_int8_t	local_sapic_eid;
	u_int8_t	reserved[3];
	u_int32_t	flags;		/* Same flags as acpi_madt_lapic */
	u_int32_t	acpi_proc_uid;
	u_int8_t	acpi_proc_uid_string[1];
} __packed;

struct acpi_madt_platform_int {
	u_int8_t	apic_type;
#define	ACPI_MADT_PLATFORM_INT	8
	u_int8_t	length;
	u_int16_t	flags;		/* Same flags as acpi_madt_override */
	u_int8_t	int_type;
#define	ACPI_MADT_PLATFORM_PMI		1
#define	ACPI_MADT_PLATFORM_INIT		2
#define	ACPI_MADT_PLATFORM_CORR_ERROR	3
	u_int8_t	proc_id;
	u_int8_t	proc_eid;
	u_int8_t	io_sapic_vec;
	u_int32_t	global_int;
	u_int32_t	platform_int_flags;
#define	ACPI_MADT_PLATFORM_CPEI		0x00000001
} __packed;

union acpi_madt_entry {
	struct acpi_madt_lapic		madt_lapic;
	struct acpi_madt_ioapic		madt_ioapic;
	struct acpi_madt_override	madt_override;
	struct acpi_madt_nmi		madt_nmi;
	struct acpi_madt_lapic_nmi	madt_lapic_nmi;
	struct acpi_madt_lapic_override	madt_lapic_override;
	struct acpi_madt_io_sapic	madt_io_sapic;
	struct acpi_madt_local_sapic	madt_local_sapic;
	struct acpi_madt_platform_int	madt_platform_int;
} __packed;

struct device_scope {
    u_int8_t type;
    u_int8_t length;
    u_int16_t reserved;
    u_int8_t enumeration_id;
    u_int8_t start_bus_number;
    u_int16_t path[1];  /* Path starts here */
} __packed;

struct dmar_remapping {
    u_int16_t type;
#define DMAR_REMAPPING_DRHD 0
#define DMAR_REMAPPING_RMRR 1
#define DMAR_REMAPPING_ATSR 2
#define DMAR_REMAPPING_RHSA 3
#define DMAR_REMAPPING_RESERVED 4
    u_int16_t length;
    u_int8_t flags;
#define REMAPPING_INCLUDE_PCI_ALL Ox01

    u_int8_t reserved;
    u_int16_t segment_number;
    u_int64_t register_base_address;
    struct device_scope device_scope_entry[1]; /* Device Scope starts here */
} __packed;

struct acpi_dmar {
    struct acpi_table_header hdr;
#define DMAR_SIG "DMAR"
    u_int8_t host_address_width;
    u_int8_t flags;
#define DMAR_INTR_REMAP 0x01

    u_int8_t reserved[10];
    struct dmar_remapping table_offsets[1]; /* dmar_remapping structure starts here */
} __packed;

struct acpi_mcfg_mmcfg {
    u_int64_t base_address;
    u_int16_t group_number;
    u_int8_t start_bus_number;
    u_int8_t end_bus_number;
    u_int32_t reserved;
} __packed;

struct acpi_mcfg {
    struct acpi_table_header hdr;
#define MCFG_SIG "MCFG"

    u_int64_t reserved;
    /* struct acpi_mcfg_mmcfg table_offsets[1]; */
    u_int32_t base_address;
} __packed;
typedef struct acpi_mcfg acpi_table_mcfg_t;

#if 0

#define ACPI_FREQUENCY	3579545		/* Per ACPI spec */

/*
 * PCI Configuration space
 */
#define ACPI_PCI_BUS(addr) (u_int16_t)((addr) >> 48)
#define ACPI_PCI_DEV(addr) (u_int16_t)((addr) >> 32)
#define ACPI_PCI_FN(addr)  (u_int16_t)((addr) >> 16)
#define ACPI_PCI_REG(addr) (u_int16_t)(addr)
#define ACPI_PCI_ADDR(b,d,f,r) ((u_int64_t)(b)<<48LL | (u_int64_t)(d)<<32LL | (f)<<16LL | (r))

/*
 * PM1 Status Registers Fixed Hardware Feature Status Bits
 */
#define	ACPI_PM1_STATUS			0x00
#define		ACPI_PM1_TMR_STS		0x0001
#define		ACPI_PM1_BM_STS			0x0010
#define		ACPI_PM1_GBL_STS		0x0020
#define		ACPI_PM1_PWRBTN_STS		0x0100
#define		ACPI_PM1_SLPBTN_STS		0x0200
#define		ACPI_PM1_RTC_STS		0x0400
#define		ACPI_PM1_PCIEXP_WAKE_STS	0x4000
#define		ACPI_PM1_WAK_STS		0x8000

/*
 * PM1 Enable Registers
 */
#define	ACPI_PM1_ENABLE			0x02
#define		ACPI_PM1_TMR_EN			0x0001
#define		ACPI_PM1_GBL_EN			0x0020
#define		ACPI_PM1_PWRBTN_EN		0x0100
#define		ACPI_PM1_SLPBTN_EN		0x0200
#define		ACPI_PM1_RTC_EN			0x0400
#define		ACPI_PM1_PCIEXP_WAKE_DIS	0x4000

/*
 * PM1 Control Registers
 */
#define	ACPI_PM1_CONTROL		0x00
#define		ACPI_PM1_SCI_EN			0x0001
#define		ACPI_PM1_BM_RLD			0x0002
#define		ACPI_PM1_GBL_RLS		0x0004
#define		ACPI_PM1_SLP_TYPX(x)		((x) << 10)
#define		ACPI_PM1_SLP_TYPX_MASK		0x1c00
#define		ACPI_PM1_SLP_EN			0x2000

/*
 * PM2 Control Registers
 */
#define ACPI_PM2_CONTROL		0x06
#define	ACPI_PM2_ARB_DIS		0x0001


/*
 * Sleeping States
 */
#define ACPI_STATE_S0		0
#define ACPI_STATE_S1		1
#define ACPI_STATE_S2		2
#define ACPI_STATE_S3		3
#define ACPI_STATE_S4		4
#define ACPI_STATE_S5		5

/*
 * ACPI Device IDs
 */
#define ACPI_DEV_TIM	"PNP0100"	/* System timer */
#define ACPI_DEV_ACPI	"PNP0C08"	/* ACPI device */
#define ACPI_DEV_PCIB	"PNP0A03"	/* PCI bus */
#define ACPI_DEV_GISAB	"PNP0A05"	/* Generic ISA Bus */
#define ACPI_DEV_EIOB	"PNP0A06"	/* Extended I/O Bus */
#define ACPI_DEV_PCIEB	"PNP0A08"	/* PCIe bus */
#define ACPI_DEV_MR	"PNP0C02"	/* Motherboard resources */
#define ACPI_DEV_NPROC	"PNP0C04"	/* Numeric data processor */
#define ACPI_DEV_CS	"PNP0C08"	/* ACPI-Compliant System */
#define ACPI_DEV_ECD	"PNP0C09"	/* Embedded Controller Device */
#define ACPI_DEV_CMB	"PNP0C0A"	/* Control Method Battery */
#define ACPI_DEV_FAN	"PNP0C0B"	/* Fan Device */
#define ACPI_DEV_PBD	"PNP0C0C"	/* Power Button Device */
#define ACPI_DEV_LD	"PNP0C0D"	/* Lid Device */
#define ACPI_DEV_SBD	"PNP0C0E"	/* Sleep Button Device */
#define ACPI_DEV_PILD	"PNP0C0F"	/* PCI Interrupt Link Device */
#define ACPI_DEV_MEMD	"PNP0C80"	/* Memory Device */
#define ACPI_DEV_SHC	"ACPI0001"	/* SMBus 1.0 Host Controller */
#define ACPI_DEV_SMS1	"ACPI0002"	/* Smart Battery Subsystem */
#define ACPI_DEV_AC	"ACPI0003"	/* AC Device */
#define ACPI_DEV_MD	"ACPI0004"	/* Module Device */
#define ACPI_DEV_SMS2	"ACPI0005"	/* SMBus 2.0 Host Controller */
#define ACPI_DEV_GBD	"ACPI0006"	/* GPE Block Device */
#define ACPI_DEV_PD	"ACPI0007"	/* Processor Device */
#define ACPI_DEV_ALSD	"ACPI0008"	/* Ambient Light Sensor Device */
#define ACPI_DEV_IOXA	"ACPI0009"	/* IO x APIC Device */
#define ACPI_DEV_IOA	"ACPI000A"/	/* IO APIC Device */
#define ACPI_DEV_IOSA	"ACPI000B"	/* IO SAPIC Device */
#define ACPI_DEV_THZ	"THERMALZONE"	/* Thermal Zone */
#define ACPI_DEV_FFB	"FIXEDBUTTON"	/* Fixed Feature Button */
#define ACPI_DEV_ASUS	"ASUS010"	/* ASUS Hotkeys */
#define ACPI_DEV_THINKPAD "IBM0068"	/* ThinkPad support */

#endif
extern bool vtd_bios_enabled(void);
extern bool save_vtd_dmar_table(void);
extern bool restore_vtd_dmar_table(void);
extern bool remove_vtd_dmar_table(void);

extern struct acpi_table_ioapic *get_acpi_ioapic_table(void);
extern struct acpi_mcfg *get_acpi_mcfg_table(void);
extern struct acpi_dmar *get_vtd_dmar_table(void);
extern void disable_smis(void);

extern bool machine_sleep(const tboot_acpi_sleep_info_t *);
extern void set_s3_resume_vector(const tboot_acpi_sleep_info_t *, uint64_t);
extern struct acpi_rsdp *get_rsdp(loader_ctx *lctx);
extern uint32_t get_madt_apic_base(void);

#endif	/* __ACPI_H__ */

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
