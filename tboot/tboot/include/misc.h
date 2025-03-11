/*
 * misc.h:  miscellaneous support fns
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
 *
 */

#ifndef __MISC_H__
#define __MISC_H__

extern void print_hex(const char * buf, const void * prtptr, size_t size);

extern void delay(int millisecs);

/*
 *  These three "plus overflow" functions take a "x" value
 *    and add the "y" value to it and if the two values are
 *    greater than the size of the variable type, they will
 *    overflow the type and end up with a smaller value and
 *    return TRUE - that they did overflow.  i.e.
 *    x + y <= variable type maximum.
 */
static inline bool plus_overflow_u64(uint64_t x, uint64_t y)
{
    return ((((uint64_t)(~0)) - x) < y);
}

static inline bool plus_overflow_u32(uint32_t x, uint32_t y)
{
    return ((((uint32_t)(~0)) - x) < y);
}

/*
 * This checks to see if two numbers multiplied together are larger
 *   than the type that they are.  Returns TRUE if OVERFLOWING.
 *   If the first parameter "x" is greater than zero and
 *   if that is true, that the largest possible value 0xFFFFFFFF / "x"
 *   is less than the second parameter "y".  If "y" is zero then
 *   it will also fail because no unsigned number is less than zero.
 */
static inline bool multiply_overflow_u32(uint32_t x, uint32_t y)
{
    return (x > 0) ? ((((uint32_t)(~0))/x) < y) : false;
}

#define ARRAY_SIZE(a)    (sizeof(a) / sizeof(a[0]))

#define AP_WAKE_TRIGGER_DEF   0xffffffff

#endif    /* __MISC_H__ */


/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
