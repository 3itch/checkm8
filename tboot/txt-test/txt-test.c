/*
 * txt-test: Linux kernel module that will display various information about
 *           the status of TXT.  It also indicates whether the various TXT
 *           memory regions are protected from access by the kernel.
 *
 * Copyright (c) 2006-2007, Intel Corporation
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
 *
 */

#include <stdbool.h>
#include <linux/delay.h>
#include <linux/init.h>
#include <linux/ioport.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/slab.h>
#include <linux/highmem.h>
#include <asm/io.h>
#include <asm/page.h>
#include "../include/config.h"
#include "../include/uuid.h"
#include "../include/tboot.h"
#include "../tboot/include/tpm.h"
#include "../tboot/include/txt/config_regs.h"

/* device name for Intel(r) TXT device we create */
#define DEVICE_NAME       "txt"

static struct file_operations fops;
static int dev_major;

#define TBOOT_MEM_BASE      (TBOOT_START - 4*PAGE_SIZE)
                               /* 0x8c000 is Xen's start of trampoline code */
#define TBOOT_MEM_SIZE      (0x4f000 + 3*PAGE_SIZE)

#define TXT_CONFIG_REGS_SIZE        (NR_TXT_CONFIG_PAGES*PAGE_SIZE)
#define TPM_LOCALITY_SIZE           (NR_TPM_LOCALITY_PAGES*PAGE_SIZE)

#define TPM_REG_ACCESS				0x00000000

static inline uint64_t read_txt_config_reg(void *config_regs_base,
                                           uint32_t reg)
{
    /* these are MMIO so make sure compiler doesn't optimize */
    return *(volatile uint64_t *)(config_regs_base + reg);
}

static inline const char * bit_to_str(uint64_t b)
{
    return b ? "TRUE" : "FALSE";
}

static bool test_access_txt_priv_config(void)
{
    void *ptr = NULL;

    printk("testing for access to TXT private config space...\n");

	/* try to get pointer to TXT private config space */
    ptr = (void *)ioremap_nocache(TXT_PRIV_CONFIG_REGS_BASE,
                                  TXT_CONFIG_REGS_SIZE);
    if ( ptr == NULL )
        printk(KERN_ALERT "ERROR: ioremap_nocache for private space failed\n");
    else {
        printk(KERN_ALERT "ioremap_nocache for private space succeeded\n");
        iounmap(ptr);
    }
    return (ptr == NULL);
#if 0
	/* try using hypercall */
	{
	  struct xen_domctl domctl = { 0 };
	  privcmd_hypercall_t hypercall = { 0 };
	  int ret = -1;

	  domctl.cmd = XEN_DOMCTL_iomem_permission;
	  domctl.domain = DOMID_DOM0;
	  domctl.u.iomem_permission.first_mfn = 0xfed20;
	  domctl.u.iomem_permission.nr_mfns = 0x10;
	  domctl.u.iomem_permission.allow_access = 1;
	  domctl->interface_version = XEN_DOMCTL_INTERFACE_VERSION;

	  hypercall.op     = __HYPERVISOR_domctl;
	  hypercall.arg[0] = (unsigned long)domctl;

	  ret = ioctl(xc_handle, IOCTL_PRIVCMD_HYPERCALL,
			   (unsigned long)hypercall);
	  if ( ret < 0 )
	    printk(KERN_ALERT "\nERROR: failed to set iomem permissions\n");
	  else {
	    if ((PrivatePtr = (void *)ioremap_nocache(0xFED20000, 0x1000)) == NULL)
	      printk(KERN_ALERT "\nERROR: ioremap_nocache for private space failed\n\n");
	    else {
	      printk(KERN_ALERT "ioremap_nocache for private space succeeded\n");
	      iounmap(PrivatePtr);
	    }
	  }
	}
#endif
}

static bool test_access_tpm_localities(void)
{
    int locality;
    void *base, *ptr=NULL;
    int access;

    printk("testing for access to TPM localities "
           "(ff = locality unavailable):\n");

    for ( locality = 0; locality < TPM_NR_LOCALITIES; locality++ ) {
        base = (void *)(unsigned long)TPM_LOCALITY_BASE_N(locality);
        ptr = (void *)ioremap_nocache((unsigned long)base, TPM_LOCALITY_SIZE);
        if ( ptr == NULL ) {
            printk(KERN_ALERT
                   "ERROR: ioremap_nocache for TPM locality %d failed\n",
                   locality);
            return false;
        }

        access = readb(ptr + TPM_REG_ACCESS);
        printk(KERN_ALERT "TPM: Locality %d access = %x\n", locality, access);

        iounmap(ptr);
    }

    return true;
}

static bool test_access_txt_heap(void)
{
    void *txt_pub, *ptr;
    uint64_t base, size;

    printk("testing for access to SINIT and TXT heap memory...\n");

	/* get pointer to TXT public config space */
    txt_pub = (void *)ioremap_nocache(TXT_PUB_CONFIG_REGS_BASE,
                                      TXT_CONFIG_REGS_SIZE);
    if ( txt_pub == NULL ) {
        printk(KERN_ALERT "ERROR: ioremap_nocache for public space failed\n");
        return false;
    }

    /* SINIT */
    base = read_txt_config_reg(txt_pub, TXTCR_SINIT_BASE);
    size = read_txt_config_reg(txt_pub, TXTCR_SINIT_SIZE);
    ptr = (void *)ioremap_nocache(base, size);
    if ( ptr == NULL ) {
        printk(KERN_ALERT
               "ERROR: ioremap_nocache for SINIT failed\n");
    }
    else {
        printk(KERN_ALERT "ioremap_nocache for SINIT succeeded\n");
        iounmap(txt_pub);
        iounmap(ptr);
        return false;
    }

    /* TXT heap */
    base = read_txt_config_reg(txt_pub, TXTCR_HEAP_BASE);
    size = read_txt_config_reg(txt_pub, TXTCR_HEAP_SIZE);
    ptr = (void *)ioremap_nocache(base, size);
    if ( ptr == NULL ) {
        printk(KERN_ALERT
               "ERROR: ioremap_nocache for TXT heap failed\n");
        iounmap(txt_pub);
        return true;
    }
    else {
        printk(KERN_ALERT "ioremap_nocache for TXT heap succeeded\n");
        iounmap(txt_pub);
        iounmap(ptr);
        return false;
    }
}

static bool test_access_tboot(void)
{
    void *ptr;

    printk("testing for access to tboot memory...\n");

    ptr = (void *)ioremap_nocache(TBOOT_MEM_BASE, TBOOT_MEM_SIZE);
    if ( ptr == NULL ) {
        printk(KERN_ALERT
               "ERROR: ioremap_nocache for tboot failed\n");
        return true;
    }
    else {
        printk(KERN_ALERT "ioremap_nocache for tboot succeeded\n");
        iounmap(ptr);
        return false;
    }
}

static bool is_txt_supported(void)
{
    return true;
}

static __init int mod_init(void)
{
    if ( !is_txt_supported() ) {
        printk(KERN_ALERT "Intel(r) TXT is not supported\n");
        return 0;
    }

    /* make sure no one else has grabbed the public config space */
    if ( check_mem_region(TXT_PUB_CONFIG_REGS_BASE, TXT_CONFIG_REGS_SIZE) ) {
        printk(KERN_ALERT
               "ERROR: TXT public config space is already reserved\n");
        return -EBUSY;
    }

    /* register a TXT device (let kernel pick major #) */
	dev_major = register_chrdev(0, DEVICE_NAME, &fops); 
	if ( dev_major < 0 ) {
	    printk (KERN_ALERT "ERROR: failed to create TXT device (%d)\n",
                dev_major); 
	    return 0;
	}

    /*
     * begin tests
     */
    test_access_txt_priv_config();

    test_access_tpm_localities();

    test_access_txt_heap();

    test_access_tboot();

    unregister_chrdev(dev_major, DEVICE_NAME); 
    return 0;
}

static __exit void mod_exit(void)
{
    printk("txt-test module unloading\n");
}

module_init(mod_init);
module_exit(mod_exit);
MODULE_LICENSE("BSD");


/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
