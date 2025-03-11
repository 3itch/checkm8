/*
 * Copyright (c) 1997, Stefan Esser <se@freebsd.org>
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
 *
 * $FreeBSD: src/sys/i386/include/pci_cfgreg.h,v 1.15.2.1.4.1 2010/06/14 02:09:06 kensmith Exp $
 * $FreeBSD: src/sys/dev/pci/pcireg.h,v 1.72.2.4.2.1 2010/06/14 02:09:06 kensmith Exp $
 */
/*
 * Portions copyright (c) 2010, Intel Corporation
 */

#ifndef __PCI_CFGREG_H__
#define __PCI_CFGREG_H__

#define PCI_BUSMAX	255     /* highest supported bus number */
#define PCI_SLOTMAX	31      /* highest supported slot number */
#define PCI_FUNCMAX	7       /* highest supported function number */
#define PCI_REGMAX	255     /* highest supported config register addr. */

#define CONF1_ADDR_PORT    0x0cf8
#define CONF1_DATA_PORT    0x0cfc

#define CONF1_ENABLE       0x80000000ul
#define CONF1_ENABLE_CHK   0x80000000ul
#define CONF1_ENABLE_MSK   0x7f000000ul
#define CONF1_ENABLE_CHK1  0xff000001ul
#define CONF1_ENABLE_MSK1  0x80000001ul
#define CONF1_ENABLE_RES1  0x80000000ul

#define CONF2_ENABLE_PORT  0x0cf8
#define CONF2_FORWARD_PORT 0x0cfa

#define CONF2_ENABLE_CHK   0x0e
#define CONF2_ENABLE_RES   0x0e

#define	PCIR_COMMAND	0x04
#define	PCIR_BARS	0x10
#define	PCIR_IOBASEL_1	0x1c

int pcireg_cfgread(int bus, int slot, int func, int reg, int bytes);
void pcireg_cfgwrite(int bus, int slot, int func, int reg, int data, int bytes);

#endif /* __PCI_CFGREG_H__ */
/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
