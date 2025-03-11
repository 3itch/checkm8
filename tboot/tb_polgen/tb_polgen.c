/*
 * tb_polgen.c: policy generation tool for tboot
 *
 * Copyright (c) 2006-2008, Intel Corporation
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

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#define PRINT   printf
#include "../include/config.h"
#include "../include/hash.h"
#include "../include/tb_error.h"
#include "../include/tb_policy.h"
#include "tb_polgen.h"

int main (int argc, char *argv[])
{
    param_data_t params;
    bool ret;

    if ( !parse_input_params(argc, argv, &params) )
        return 1;

    print_params(&params);

    switch ( params.cmd ) {
        case POLGEN_CMD_CREATE:
            ret = do_create(&params);
            break;
        case POLGEN_CMD_ADD:
            ret = do_add(&params);
            break;
        case POLGEN_CMD_DEL:
            ret = do_del(&params);
            break;
        case POLGEN_CMD_UNWRAP:
            ret = do_unwrap(&params);
            break;
        case POLGEN_CMD_SHOW:
            ret = do_show(&params);
            break;
        case POLGEN_CMD_HELP:
            display_help_msg();
            ret = true;
            break;
        default:
            ret = false;
            break;
    }

    return (ret ? 0 : 1);
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
