/*
 * Copyright (c) 1997, Stefan Esser <se@freebsd.org>
 * Copyright (c) 2000, Michael Smith <msmith@freebsd.org>
 * Copyright (c) 2000, BSDi
 * Copyright (c) 2004, Scott Long <scottl@freebsd.org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice unmodified, this list of conditions, and the following
 *    disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/* from:
 * $FreeBSD: src/sys/i386/pci/pci_cfgreg.c,v 1.134.2.2.2.1 2010/06/14 02:09:06 kensmith Exp $
 */
/*
 * Portions copyright (c) 2010, Intel Corporation
 */

#include <types.h>
#include <mutex.h>
#include <io.h>
#include <pci_cfgreg.h>

enum {
	CFGMECH_NONE = 0,
	CFGMECH_1,
	CFGMECH_2,
	CFGMECH_PCIE,
};

struct mutex pcicfg_mtx;
static const int cfgmech = CFGMECH_1;

/* 
 * Configuration space access using direct register operations
 */

/* enable configuration space accesses and return data port address */
static int
pci_cfgenable(unsigned bus, unsigned slot, unsigned func, int reg, int bytes)
{
	int dataport = 0;

	if (bus <= PCI_BUSMAX
	    && slot <= PCI_SLOTMAX
	    && func <= PCI_FUNCMAX
	    && (unsigned)reg <= PCI_REGMAX
	    && bytes != 3
	    && (unsigned)bytes <= 4
	    && (reg & (bytes - 1)) == 0) {
		switch (cfgmech) {
		case CFGMECH_PCIE:
		case CFGMECH_1:
			outl(CONF1_ADDR_PORT, (1 << 31)
			    | (bus << 16) | (slot << 11) 
			    | (func << 8) | (reg & ~0x03));
			dataport = CONF1_DATA_PORT + (reg & 0x03);
			break;
		case CFGMECH_2:
			outb(CONF2_ENABLE_PORT, 0xf0 | (func << 1));
			outb(CONF2_FORWARD_PORT, bus);
			dataport = 0xc000 | (slot << 8) | reg;
			break;
        default:
            break;
		}
	}
	return (dataport);
}

/* disable configuration space accesses */
static void
pci_cfgdisable(void)
{
	switch (cfgmech) {
	case CFGMECH_PCIE:
	case CFGMECH_1:
		/*
		 * Do nothing for the config mechanism 1 case.
		 * Writing a 0 to the address port can apparently
		 * confuse some bridges and cause spurious
		 * access failures.
		 */
		break;
	case CFGMECH_2:
		outb(CONF2_ENABLE_PORT, 0);
		break;
    default:
        break;
	}
}

int pcireg_cfgread(int bus, int slot, int func, int reg, int bytes)
{
	int data = -1;
	int port;

	mtx_enter(&pcicfg_mtx);
	port = pci_cfgenable(bus, slot, func, reg, bytes);
	if (port != 0) {
		switch (bytes) {
		case 1:
			data = inb(port);
			break;
		case 2:
			data = inw(port);
			break;
		case 4:
			data = inl(port);
			break;
        default:
            break;
		}
		pci_cfgdisable();
	}
	mtx_leave(&pcicfg_mtx);
	return (data);
}

void pcireg_cfgwrite(int bus, int slot, int func, int reg, int data, int bytes)
{
	int port;

	mtx_enter(&pcicfg_mtx);
	port = pci_cfgenable(bus, slot, func, reg, bytes);
	if (port != 0) {
		switch (bytes) {
		case 1:
			outb(port, data);
			break;
		case 2:
			outw(port, data);
			break;
		case 4:
			outl(port, data);
			break;
        default:
            break;
		}
		pci_cfgdisable();
	}
	mtx_leave(&pcicfg_mtx);
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
