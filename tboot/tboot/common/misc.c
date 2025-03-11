/*
 * misc.c:  miscellaneous support fns
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

#include <stdbool.h>
#include <types.h>
#include <printk.h>
#include <compiler.h>
#include <processor.h>
#include <io.h>
#include <msr.h>
#include <ctype.h>
#include <misc.h>

/*
 * if 'prefix' != NULL, print it before each line of hex string
 */
void print_hex(const char *prefix, const void *prtptr, size_t size)
{
    for ( size_t i = 0; i < size; i++ ) {
        if ( i % 16 == 0 && prefix != NULL )
            printk(TBOOT_DETA"\n%s", prefix);
        printk(TBOOT_DETA"%02x ", *(uint8_t *)prtptr++);
    }
    printk(TBOOT_DETA"\n");
}

static bool g_calibrated = false;
static uint64_t g_ticks_per_millisec;

#define TIMER_FREQ	1193182
#define TIMER_DIV(hz)	((TIMER_FREQ+(hz)/2)/(hz))

static void wait_tsc_uip(void)
{
    do {
        outb(0x43, 0xe8);
        cpu_relax();
    } while ( !(inb(0x42) & 0x80) );
    do {
        outb(0x43, 0xe8);
        cpu_relax();
    } while ( inb(0x42) & 0x80 );
}

static void calibrate_tsc(void)
{
    if ( g_calibrated )
        return;

    /* disable speeker */
    uint8_t val = inb(0x61);
    val = ((val & ~0x2) | 0x1);
    outb(0x61, val);

    /* 0xb6 - counter2, low then high byte write */
    /* mode 3, binary */
    outb(0x43, 0xb6);

    /* 0x4a9 - divisor to get 1ms period time */
    /* 1.19318 MHz / 1193 = 1000.15Hz */
    uint16_t latch = TIMER_DIV(1000);
    outb(0x42, latch & 0xff);
    outb(0x42, latch >> 8);

    /* 0xe8 - read back command, don't get count */
    /* get status, counter2 select */
    do {
        outb(0x43, 0xe8);
        cpu_relax();
    } while ( inb(0x42) & 0x40 );

    wait_tsc_uip();

    /* get starting TSC val */
    uint64_t start = rdtsc();

    wait_tsc_uip();

    uint64_t end = rdtsc();

    /* # ticks in 1 millisecond */
    g_ticks_per_millisec = end - start;

    /* restore timer 1 programming */
    outb(0x43, 0x54);
    outb(0x41, 0x12);

    g_calibrated = true;
}

void delay(int millisecs)
{
    if ( millisecs <= 0 )
        return;

    calibrate_tsc();

    uint64_t rtc = rdtsc();

    uint64_t end_ticks = rtc + millisecs * g_ticks_per_millisec;
    while ( rtc < end_ticks ) {
        cpu_relax();
        rtc = rdtsc();
    }
}

/* used by isXXX() in ctype.h */
/* originally from:
 * http://fxr.watson.org/fxr/source/dist/acpica/utclib.c?v=NETBSD5
 * re-licensed by Intel Corporation
 */

const uint8_t _ctype[257] = {
    _CN,            /* 0x0      0.     */
    _CN,            /* 0x1      1.     */
    _CN,            /* 0x2      2.     */
    _CN,            /* 0x3      3.     */
    _CN,            /* 0x4      4.     */
    _CN,            /* 0x5      5.     */
    _CN,            /* 0x6      6.     */
    _CN,            /* 0x7      7.     */
    _CN,            /* 0x8      8.     */
    _CN|_SP,        /* 0x9      9.     */
    _CN|_SP,        /* 0xA     10.     */
    _CN|_SP,        /* 0xB     11.     */
    _CN|_SP,        /* 0xC     12.     */
    _CN|_SP,        /* 0xD     13.     */
    _CN,            /* 0xE     14.     */
    _CN,            /* 0xF     15.     */
    _CN,            /* 0x10    16.     */
    _CN,            /* 0x11    17.     */
    _CN,            /* 0x12    18.     */
    _CN,            /* 0x13    19.     */
    _CN,            /* 0x14    20.     */
    _CN,            /* 0x15    21.     */
    _CN,            /* 0x16    22.     */
    _CN,            /* 0x17    23.     */
    _CN,            /* 0x18    24.     */
    _CN,            /* 0x19    25.     */
    _CN,            /* 0x1A    26.     */
    _CN,            /* 0x1B    27.     */
    _CN,            /* 0x1C    28.     */
    _CN,            /* 0x1D    29.     */
    _CN,            /* 0x1E    30.     */
    _CN,            /* 0x1F    31.     */
    _XS|_SP,        /* 0x20    32. ' ' */
    _PU,            /* 0x21    33. '!' */
    _PU,            /* 0x22    34. '"' */
    _PU,            /* 0x23    35. '#' */
    _PU,            /* 0x24    36. '$' */
    _PU,            /* 0x25    37. '%' */
    _PU,            /* 0x26    38. '&' */
    _PU,            /* 0x27    39. ''' */
    _PU,            /* 0x28    40. '(' */
    _PU,            /* 0x29    41. ')' */
    _PU,            /* 0x2A    42. '*' */
    _PU,            /* 0x2B    43. '+' */
    _PU,            /* 0x2C    44. ',' */
    _PU,            /* 0x2D    45. '-' */
    _PU,            /* 0x2E    46. '.' */
    _PU,            /* 0x2F    47. '/' */
    _XD|_DI,        /* 0x30    48. '' */
    _XD|_DI,        /* 0x31    49. '1' */
    _XD|_DI,        /* 0x32    50. '2' */
    _XD|_DI,        /* 0x33    51. '3' */
    _XD|_DI,        /* 0x34    52. '4' */
    _XD|_DI,        /* 0x35    53. '5' */
    _XD|_DI,        /* 0x36    54. '6' */
    _XD|_DI,        /* 0x37    55. '7' */
    _XD|_DI,        /* 0x38    56. '8' */
    _XD|_DI,        /* 0x39    57. '9' */
    _PU,            /* 0x3A    58. ':' */
    _PU,            /* 0x3B    59. ';' */
    _PU,            /* 0x3C    60. '<' */
    _PU,            /* 0x3D    61. '=' */
    _PU,            /* 0x3E    62. '>' */
    _PU,            /* 0x3F    63. '?' */
    _PU,            /* 0x40    64. '@' */
    _XD|_UP,        /* 0x41    65. 'A' */
    _XD|_UP,        /* 0x42    66. 'B' */
    _XD|_UP,        /* 0x43    67. 'C' */
    _XD|_UP,        /* 0x44    68. 'D' */
    _XD|_UP,        /* 0x45    69. 'E' */
    _XD|_UP,        /* 0x46    70. 'F' */
    _UP,            /* 0x47    71. 'G' */
    _UP,            /* 0x48    72. 'H' */
    _UP,            /* 0x49    73. 'I' */
    _UP,            /* 0x4A    74. 'J' */
    _UP,            /* 0x4B    75. 'K' */
    _UP,            /* 0x4C    76. 'L' */
    _UP,            /* 0x4D    77. 'M' */
    _UP,            /* 0x4E    78. 'N' */
    _UP,            /* 0x4F    79. 'O' */
    _UP,            /* 0x50    80. 'P' */
    _UP,            /* 0x51    81. 'Q' */
    _UP,            /* 0x52    82. 'R' */
    _UP,            /* 0x53    83. 'S' */
    _UP,            /* 0x54    84. 'T' */
    _UP,            /* 0x55    85. 'U' */
    _UP,            /* 0x56    86. 'V' */
    _UP,            /* 0x57    87. 'W' */
    _UP,            /* 0x58    88. 'X' */
    _UP,            /* 0x59    89. 'Y' */
    _UP,            /* 0x5A    90. 'Z' */
    _PU,            /* 0x5B    91. '[' */
    _PU,            /* 0x5C    92. '\' */
    _PU,            /* 0x5D    93. ']' */
    _PU,            /* 0x5E    94. '^' */
    _PU,            /* 0x5F    95. '_' */
    _PU,            /* 0x60    96. '`' */
    _XD|_LO,        /* 0x61    97. 'a' */
    _XD|_LO,        /* 0x62    98. 'b' */
    _XD|_LO,        /* 0x63    99. 'c' */
    _XD|_LO,        /* 0x64   100. 'd' */
    _XD|_LO,        /* 0x65   101. 'e' */
    _XD|_LO,        /* 0x66   102. 'f' */
    _LO,            /* 0x67   103. 'g' */
    _LO,            /* 0x68   104. 'h' */
    _LO,            /* 0x69   105. 'i' */
    _LO,            /* 0x6A   106. 'j' */
    _LO,            /* 0x6B   107. 'k' */
    _LO,            /* 0x6C   108. 'l' */
    _LO,            /* 0x6D   109. 'm' */
    _LO,            /* 0x6E   110. 'n' */
    _LO,            /* 0x6F   111. 'o' */
    _LO,            /* 0x70   112. 'p' */
    _LO,            /* 0x71   113. 'q' */
    _LO,            /* 0x72   114. 'r' */
    _LO,            /* 0x73   115. 's' */
    _LO,            /* 0x74   116. 't' */
    _LO,            /* 0x75   117. 'u' */
    _LO,            /* 0x76   118. 'v' */
    _LO,            /* 0x77   119. 'w' */
    _LO,            /* 0x78   120. 'x' */
    _LO,            /* 0x79   121. 'y' */
    _LO,            /* 0x7A   122. 'z' */
    _PU,            /* 0x7B   123. '{' */
    _PU,            /* 0x7C   124. '|' */
    _PU,            /* 0x7D   125. '}' */
    _PU,            /* 0x7E   126. '~' */
    _CN,            /* 0x7F   127.     */

    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,  /* 0x80 to 0x8F    */
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,  /* 0x90 to 0x9F    */
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,  /* 0xA0 to 0xAF    */
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,  /* 0xB0 to 0xBF    */
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,  /* 0xC0 to 0xCF    */
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,  /* 0xD0 to 0xDF    */
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,  /* 0xE0 to 0xEF    */
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 /* 0xF0 to 0x100   */
};

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
