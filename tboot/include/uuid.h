/*
 * uuid.h: support functions for UUIDs
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

#ifndef __UUID_H__
#define __UUID_H__

typedef struct __packed {
  uint32_t    data1;
  uint16_t    data2;
  uint16_t    data3;
  uint16_t    data4;
  uint8_t     data5[6];
} uuid_t;

static inline bool are_uuids_equal(const uuid_t *uuid1, const uuid_t *uuid2)
{
    return (uuid1->data1 == uuid2->data1
         && uuid1->data2 == uuid2->data2
         && uuid1->data3 == uuid2->data3
         && uuid1->data4 == uuid2->data4
         && uuid1->data5[0] == uuid2->data5[0]
         && uuid1->data5[1] == uuid2->data5[1]
         && uuid1->data5[2] == uuid2->data5[2]
         && uuid1->data5[3] == uuid2->data5[3]
         && uuid1->data5[4] == uuid2->data5[4]
         && uuid1->data5[5] == uuid2->data5[5]
         );
}

#ifndef PRINT
#define PRINT   printk
#endif

#ifndef TBOOT_DETA
#define TBOOT_DETA  "<4>"
#endif

static inline void print_uuid(const uuid_t *uuid)
{
    PRINT(TBOOT_DETA"{0x%08x, 0x%04x, 0x%04x, 0x%04x,\n"
           "\t\t{0x%02x, 0x%02x, 0x%02x, 0x%02x, 0x%02x, 0x%02x}}",
           uuid->data1, (uint32_t)uuid->data2, (uint32_t)uuid->data3,
           (uint32_t)uuid->data4, (uint32_t)uuid->data5[0],
           (uint32_t)uuid->data5[1], (uint32_t)uuid->data5[2],
           (uint32_t)uuid->data5[3], (uint32_t)uuid->data5[4],
           (uint32_t)uuid->data5[5]);
}

#endif    /* __UUID_H__ */


/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
