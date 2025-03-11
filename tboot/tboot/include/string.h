/*-
 * Copyright (c) 1992, 1993
 *	The Regents of the University of California.  All rights reserved.
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
 *	@(#)libkern.h	8.1 (Berkeley) 6/10/93
 * $FreeBSD: src/sys/sys/libkern.h,v 1.60 2009/02/14 11:34:57 rrs Exp $
 */
/*
 * Portions copyright (c) 2010-2018, Intel Corporation
 */

#ifndef __STRING_H__
#define	__STRING_H__

#include <stdarg.h>
#include <types.h>

int	 tb_memcmp(const void *b1, const void *b2, size_t len);
char	*tb_index(const char *, int);
int	 tb_strcmp(const char *, const char *);
size_t	 tb_strlen(const char *);
int	 tb_strncmp(const char *, const char *, size_t);
char	*tb_strncpy(char * __restrict, const char * __restrict, size_t);
void	*tb_memcpy(void *dst, const void *src, size_t len);
int	 tb_snprintf(char *buf, size_t size, const char *fmt, ...);
int	 tb_vscnprintf(char *buf, size_t size, const char *fmt, va_list ap);
unsigned long tb_strtoul(const char *nptr, char **endptr, int base);

static inline void *tb_memset(void *b, int c, size_t len)
{
	char *bb;

	for (bb = (char *)b; len--; )
		*bb++ = c;

	return (b);
}

static inline void *tb_memmove(void *dest, const void *src, size_t n)
{
	return tb_memcpy(dest, src, n);
}

static __inline char *tb_strchr(const char *p, int ch)
{
	return tb_index(p, ch);
}

#endif /* __STRING_H__ */
