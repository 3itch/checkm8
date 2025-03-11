/*
 * printk.h: printk to serial for very early boot stages
 *
 * Copyright (c) 2006-2010, Intel Corporation
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

#ifndef __PRINTK_H__
#define __PRINTK_H__

#include <com.h>
#include <vga.h>

#define TBOOT_LOG_LEVEL_NONE    0x00
#define TBOOT_LOG_LEVEL_ERR     0x01
#define TBOOT_LOG_LEVEL_WARN    0x02
#define TBOOT_LOG_LEVEL_INFO    0x04
#define TBOOT_LOG_LEVEL_DETA    0x08
#define TBOOT_LOG_LEVEL_ALL     0xFF

#define TBOOT_LOG_TARGET_NONE   0x00
#define TBOOT_LOG_TARGET_VGA    0x01
#define TBOOT_LOG_TARGET_SERIAL 0x02
#define TBOOT_LOG_TARGET_MEMORY 0x04

extern uint8_t g_log_level;
extern uint8_t g_log_targets;
extern uint8_t g_vga_delay;
extern serial_port_t g_com_port;

#define serial_init()         comc_init()
#define serial_write(s, n)    comc_puts(s, n)

#define vga_write(s,n)        vga_puts(s, n)

extern void printk_init(bool force_vga_off);
extern void printk_disable_vga(void);
extern void printk_flush(void);
extern void printk(const char *fmt, ...)
                         __attribute__ ((format (printf, 1, 2)));

#endif
