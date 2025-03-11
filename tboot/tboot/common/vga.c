/*
 * vga.c:  fns for outputting strings to VGA display
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
#include <string.h>
#include <misc.h>
#include <io.h>
#include <printk.h>
#include <uuid.h>
#include <multiboot.h>
#include <loader.h>
#include <vga.h>

#define SSFN_CONSOLEBITMAP_TRUECOLOR 
#include <vga/ssfn.h>
#include <vga/font.h>

static uint16_t * const legacy_screen = (uint16_t * const)VGA_BASE;
static __data uint8_t cursor_x, cursor_y;
static __data unsigned int num_lines;
uint8_t g_vga_delay = 0;       /* default to no delay */

static struct mb2_fb g_fb;
static uint32_t __data fb_buff1[FB_SIZE];
static uint32_t __data fb_buff2[FB_SIZE];

typedef enum {
    VGA_NONE = 0,
    VGA_LEGACY,
    VGA_FB,
} vga_type_t;
vga_type_t vga_type;

static inline void legacy_reset_screen(void)
{
    tb_memset(legacy_screen, 0, SCREEN_BUFFER);
    cursor_x = 0;
    cursor_y = 0;
    num_lines = 0;

    outb(CTL_ADDR_REG, START_ADD_HIGH_REG);
    outb(CTL_DATA_REG, 0x00);
    outb(CTL_ADDR_REG, START_ADD_LOW_REG);
    outb(CTL_DATA_REG, 0x00);
}

static void legacy_scroll_screen(void)
{
    for ( int y = 1; y < MAX_LINES; y++ ) {
        for ( int x = 0; x < MAX_COLS; x++ )
            writew(VGA_ADDR(x, y-1), readw(VGA_ADDR(x, y)));
    }
    /* clear last line */
    for ( int x = 0; x < MAX_COLS; x++ )
        writew(VGA_ADDR(x, MAX_LINES-1), 0x720);
}

static void legacy_putc(int c)
{
    bool new_row = false;

    switch ( c ) {
        case '\n':
            cursor_y++;
            cursor_x = 0;
            new_row = true;
            break;
        case '\r':
            cursor_x = 0;
            break;
        case '\t':
            cursor_x += 4;
            break;
        default:
            legacy_screen[(cursor_y * MAX_COLS) + cursor_x] = (COLOR << 8) | c;
            cursor_x++;
            break;
    }

    if ( cursor_x >= MAX_COLS ) {
        cursor_x %= MAX_COLS;
        cursor_y++;
        new_row = true;
    }

    if ( new_row ) {
        num_lines++;
        if ( cursor_y >= MAX_LINES ) {
            legacy_scroll_screen();
            cursor_y--;
        }

        /* (optionally) pause after every screenful */
        if ( (num_lines % (MAX_LINES - 1)) == 0 && g_vga_delay > 0 )
            delay(g_vga_delay * 1000);
    }
}

static void fb_putc(int c)
{
    bool new_row = false;

    switch ( c ) {
        case '\n':
            ssfn_dst.y += ssfn_src->height;
            ssfn_dst.x = 0;
            new_row = true;
            break;
        case '\r':
            ssfn_dst.x = 0;
            break;
        case '\t':
            ssfn_dst.x += 4 * ssfn_src->width;
            break;
        default:
            ssfn_putc(c);
            break;
    }

    if ( new_row ) {
        num_lines++;
        const uint32_t h = g_fb.common.fb_height;
        const uint32_t w = g_fb.common.fb_width;
        const uint32_t fh = ssfn_src->height;
        if ((uint32_t)ssfn_dst.y >= h - fh) {
            tb_memcpy(fb_buff1, &fb_buff1[w*fh], (w*h-w*fh)*sizeof(uint32_t));
            tb_memset(&fb_buff1[(w*h-w*fh)], 0, w*fh*sizeof(uint32_t));
            ssfn_dst.y -= fh;
        }
        for (uint32_t i = 0; i < h*w; ++i) {
            if (fb_buff1[i] != fb_buff2[i]) {
                ((volatile uint32_t*)((uint32_t)g_fb.common.fb_addr))[i] = fb_buff1[i];
                fb_buff2[i] = fb_buff1[i];
            }
        }

        /* (optionally) pause after every screenful */
        uint32_t lines_in_screen = h / fh;
        if ( (num_lines % (lines_in_screen - 1)) == 0 && g_vga_delay > 0 ) {
            delay(g_vga_delay * 1000);
        }
    }
}

static void fb_init(void)
{
    printk(TBOOT_INFO"Framebuffer info:\n");
    printk(TBOOT_INFO"    address: 0x%llx\n", g_fb.common.fb_addr);
    printk(TBOOT_INFO"    pitch: %d\n", g_fb.common.fb_pitch);
    printk(TBOOT_INFO"    width: %d\n", g_fb.common.fb_width);
    printk(TBOOT_INFO"    height: %d\n", g_fb.common.fb_height);
    printk(TBOOT_INFO"    bpp: %d\n", g_fb.common.fb_bpp);
    printk(TBOOT_INFO"    type: %d\n", g_fb.common.fb_type);

    if (g_fb.common.fb_addr > 0xffffffffULL ||
        plus_overflow_u32((uint32_t)g_fb.common.fb_addr,
                          g_fb.common.fb_pitch * g_fb.common.fb_height)) {
        printk(TBOOT_ERR"Framebuffer at >4GB is not supported\n");
        return;
    }

    if (g_fb.common.fb_width > FB_MAX_HRES || g_fb.common.fb_height > FB_MAX_VRES ||
            g_fb.common.fb_bpp != FB_BPP) {
        printk(TBOOT_ERR"Not supported framebuffer size/bpp\n");
        return;
    }

    for (uint32_t i = 0; i < g_fb.common.fb_width * g_fb.common.fb_height; ++i) {
        ((volatile uint32_t*)(uint32_t)g_fb.common.fb_addr)[i] = 0;
        fb_buff1[i] = 0;
        fb_buff2[i] = 0;
    }

    /* set up context by global variables */
    ssfn_src = (ssfn_font_t*)u_vga16_sfn;
    ssfn_dst.ptr = (uint8_t*)fb_buff1;
    ssfn_dst.p = g_fb.common.fb_pitch;
    ssfn_dst.w = g_fb.common.fb_width;
    ssfn_dst.h = g_fb.common.fb_height;
    ssfn_dst.fg = FB_COLOR;
    ssfn_dst.bg = 0;
    ssfn_dst.x = 0;
    ssfn_dst.y = 0;

    vga_type = VGA_FB;
}

static void legacy_init(void)
{
    legacy_reset_screen();
    vga_type = VGA_LEGACY;
}

void vga_init(void)
{
    struct mb2_fb* fb = get_framebuffer_info(g_ldr_ctx); 
    if (fb != NULL) {
        g_fb = *fb;
        fb_init();
    } else {
        legacy_init();
    }
}

void vga_puts(const char *s, unsigned int cnt)
{
    while ( *s && cnt-- ) {
        if (vga_type == VGA_LEGACY) {
            legacy_putc(*s);
        } else if (vga_type == VGA_FB) {
            fb_putc(*s);
        }
        s++;
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
