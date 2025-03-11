/*-
 * Copyright (c) 1998 Michael Smith (msmith@freebsd.org)
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
/*
 * Portions copyright (c) 2010, Intel Corporation
 */

/*
 * sys/boot/i386/libi386/comconsole.c
 */

#include <types.h>
#include <stdbool.h>
#include <misc.h>
#include <mutex.h>
#include <io.h>
#include <pci_cfgreg.h>
#include <com.h>

#define COMC_TXWAIT	0x40000		/* transmit timeout */
#define COMC_BPS(x)	(115200 / (x))	/* speed to DLAB divisor */
#define COMC_DIV2BPS(x)	(115200 / (x))	/* DLAB divisor to speed */

#define OUTB(add, val)   outb(g_com_port.comc_port + (add), (val))
#define INB(add)         inb(g_com_port.comc_port + (add))

serial_port_t g_com_port = {115200, 0, 0x3, COM1_ADDR}; /* com1,115200,8n1 */

extern bool g_psbdf_enabled;
extern bool g_pbbdf_enabled;
extern struct mutex pcicfg_mtx;

static void comc_putchar(int c)
{
    int wait;

    for ( wait = COMC_TXWAIT; wait > 0; wait-- )
        if ( INB(com_lsr) & LSR_TXRDY ) {
            OUTB(com_data, (u_char)c);
            break;
        }
}

static void comc_setup(int speed)
{
    OUTB(com_cfcr, CFCR_DLAB | g_com_port.comc_fmt);
    OUTB(com_dlbl, COMC_BPS(speed) & 0xff);
    OUTB(com_dlbh, COMC_BPS(speed) >> 8);
    OUTB(com_cfcr, g_com_port.comc_fmt);
    OUTB(com_mcr, MCR_RTS | MCR_DTR);

    for ( int wait = COMC_TXWAIT; wait > 0; wait-- ) {
        INB(com_data);
        if ( !(INB(com_lsr) & LSR_RXRDY) )
            break;
    }
}

static void comc_pci_setup(void)
{
    if ( g_psbdf_enabled ) {
        if ( g_pbbdf_enabled ) {
            pcireg_cfgwrite(g_com_port.comc_pbbdf.bus,
                            g_com_port.comc_pbbdf.slot,
                            g_com_port.comc_pbbdf.func,
                            PCIR_IOBASEL_1,
                            (g_com_port.comc_port & 0xF000)
                            | ((g_com_port.comc_port & 0xF000) >> 8),
                            2);
        }
        pcireg_cfgwrite(g_com_port.comc_psbdf.bus,
                        g_com_port.comc_psbdf.slot,
                        g_com_port.comc_psbdf.func,
                        PCIR_BARS,
                        g_com_port.comc_port | 0x1,
                        4);
        pcireg_cfgwrite(g_com_port.comc_psbdf.bus,
                        g_com_port.comc_psbdf.slot,
                        g_com_port.comc_psbdf.func,
                        PCIR_COMMAND,
                        0x1,
                        2);

        mtx_init(&pcicfg_mtx);
    }
}               

void comc_init(void)
{
    comc_pci_setup(); 
    comc_setup(g_com_port.comc_curspeed);
}

void comc_puts(const char *s, unsigned int cnt)
{
    while ( *s && cnt-- ) {
        if ( *s == '\n' )
            comc_putchar('\r');
        comc_putchar(*s++);
    }
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
