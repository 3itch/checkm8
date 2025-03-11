/*
 * memlog.h: log messages to memory
 *
 * Copyright (c) 2006-2020, Intel Corporation
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

#include <config.h>
#include <stdbool.h>
#include <stdarg.h>
#include <compiler.h>
#include <string.h>
#include <misc.h>
#include <tboot.h>
#include <lz.h>

#include <memlog.h>

/* memory-based serial log (ensure in .data section so that not cleared) */
__data tboot_log_t *g_log = NULL;

void memlog_init(void)
{
   if ( g_log == NULL ) {
       g_log = (tboot_log_t *)TBOOT_SERIAL_LOG_ADDR;
       uuid_t uuid = (uuid_t)TBOOT_LOG_UUID;
       tb_memcpy((void *) &g_log->uuid, (const void *) &uuid, sizeof(uuid_t));
       g_log->curr_pos = 0;
       g_log->zip_count = 0;
       for ( uint8_t i = 0; i < ZIP_COUNT_MAX; i++ ) g_log->zip_pos[i] = 0;
       for ( uint8_t i = 0; i < ZIP_COUNT_MAX; i++ ) g_log->zip_size[i] = 0;
       }

    /* initialize these post-launch as well, since bad/malicious values */
    /* could compromise environment */
    g_log = (tboot_log_t *)TBOOT_SERIAL_LOG_ADDR;
    g_log->max_size = TBOOT_SERIAL_LOG_SIZE - sizeof(*g_log);

    /* if we're calling this post-launch, verify that curr_pos is valid */
    if ( g_log->zip_pos[g_log->zip_count] > g_log->max_size && g_log != NULL ){
        g_log->curr_pos = 0;
        uint8_t zero = 0;
        tb_memcpy((void *) &g_log->uuid, (const void *) &zero, sizeof(uint8_t));
        for ( uint8_t i = 0; i < ZIP_COUNT_MAX; i++ ) g_log->zip_pos[i] = 0;
        for ( uint8_t i = 0; i < ZIP_COUNT_MAX; i++ ) g_log->zip_size[i] = 0;
    }
    if ( g_log->curr_pos > g_log->max_size )
        g_log->curr_pos = g_log->zip_pos[g_log->zip_count];
}

void memlog_write(const char *str, unsigned int count)
{
    if ( g_log == NULL || count > g_log->max_size ) {
        return;
    }

    /* Check if there is space for the new string and a null terminator  */
    if (g_log->curr_pos + count + 1> g_log->max_size) {
        memlog_compress(count);
    }

    tb_memcpy(&g_log->buf[g_log->curr_pos], str, count);
    g_log->curr_pos += count; 

    /* if the string wasn't NULL-terminated, then NULL-terminate the log */
    if ( str[count-1] != '\0' )
        g_log->buf[g_log->curr_pos] = '\0';
    else {
        /* so that curr_pos will point to the NULL and be overwritten */
        /* on next copy */
        g_log->curr_pos--;
    }
}

void memlog_compress(uint32_t required_space)
{
    /* allocate a 64K temp buffer for compressed log  */
    static char buf[64*1024];
    char *out=buf;
    int zip_size;
    uint32_t zip_pos;
    bool log_reset_flag;

    if (required_space == 0 && g_log->curr_pos < g_log->max_size / 2) {
        /* Flush was requested, but we have over half buffer free, skip it */
        return;
    }

    /* If there are space issues, only then log will be reset */
    log_reset_flag = false;

    /* Check if there is space to add another compressed chunk */
    if(g_log->zip_count >= ZIP_COUNT_MAX)
        log_reset_flag = true;
    else{
        /* Get the start position of the new compressed chunk */
        zip_pos = g_log->zip_pos[g_log->zip_count];

        /*  Compress the last part of the log buffer that is not compressed,
            and put the compressed output in out (buf) */
        zip_size = LZ_Compress(&g_log->buf[zip_pos], out, (g_log->curr_pos - zip_pos), sizeof(buf) );

        /* Check if buf was large enough for LZ_compress to succeed */
        if( zip_size < 0 )
            log_reset_flag = true;
        else{
            /*  Check if there is space to add the compressed string, the
                new string and a null terminator to the log */
            if( (zip_pos + zip_size + required_space + 1) > g_log->max_size )
                log_reset_flag = true;
            else{
                /*  Add the new compressed chunk to the log buffer,
                    over-writing the last part of the log that was just
                    compressed */
                tb_memcpy(&g_log->buf[zip_pos], out, zip_size);
                g_log->zip_size[g_log->zip_count] = zip_size;
                g_log->zip_count++;
                g_log->curr_pos = zip_pos + zip_size;

                /*  Set a NULL ending */
                g_log->buf[g_log->curr_pos] ='\0';

                /*  Only if there is space to add another compressed chunk,
                    prepare its start position. */
                if( g_log->zip_count < ZIP_COUNT_MAX )
                    g_log->zip_pos[g_log->zip_count] = g_log->curr_pos;
            }
        }
    }

    /* There was some space-shortage problem. Reset the log. */
    if ( log_reset_flag ){
        g_log->curr_pos = 0;
        for( uint8_t i = 0; i < ZIP_COUNT_MAX; i++ ) g_log->zip_pos[i] = 0;
        for( uint8_t i = 0; i < ZIP_COUNT_MAX; i++ ) g_log->zip_size[i] = 0;
        g_log->zip_count = 0;
    }
}