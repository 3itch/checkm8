/*-
 * Copyright (c) 1993 The Regents of the University of California.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */
/*
 * Portions copyright (c) 2010, Intel Corporation
 */

#ifndef __IO_H__
#define __IO_H__

/* from:
 * $FreeBSD: src/sys/i386/include/cpufunc.h,v 1.158 2010/01/01 20:55:11 obrien Exp $
 */

/* modified to use tboot's types */

#define readb(va)	(*(volatile uint8_t *) (va))
#define readw(va)	(*(volatile uint16_t *) (va))
#define readl(va)	(*(volatile uint32_t *) (va))

#define writeb(va, d)	(*(volatile uint8_t *) (va) = (d))
#define writew(va, d)	(*(volatile uint16_t *) (va) = (d))
#define writel(va, d)	(*(volatile uint32_t *) (va) = (d))

static inline uint8_t inb(uint16_t port)
{
	uint8_t	data;

	__asm volatile("inb %w1, %0" : "=a" (data) : "Nd" (port));
	return (data);
}

static inline uint16_t inw(uint16_t port)
{
	uint16_t data;

	__asm volatile("inw %w1, %0" : "=a" (data) : "Nd" (port));
	return (data);
}

static inline uint32_t inl(uint16_t port)
{
	uint32_t data;

	__asm volatile("inl %w1, %0" : "=a" (data) : "Nd" (port));
	return (data);
}

static inline void outb(uint16_t port, uint8_t data)
{
	__asm __volatile("outb %0, %w1" : : "a" (data), "Nd" (port));
}

static inline void outw(uint16_t port, uint16_t data)
{
	__asm volatile("outw %0, %w1" : : "a" (data), "Nd" (port));
}

static inline void outl(uint16_t port, uint32_t data)
{
	__asm volatile("outl %0, %w1" : : "a" (data), "Nd" (port));
}


#endif /* __IO_H__ */
