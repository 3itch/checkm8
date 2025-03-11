/*
 * param.c: support functions for parsing command line parameters
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
#include <getopt.h>
#include <errno.h>
#include <safe_lib.h>
#define PRINT   printf
#include "../include/config.h"
#include "../include/hash.h"
#include "../include/tb_error.h"
#include "../include/tb_policy.h"
#include "tb_polgen.h"

static const char *help[] = {
    "tb_polgen --create --type        nonfatal|continue|halt\n",
    "                   [--alg        sha1|sha256 (default)|sha384|sha512]\n",
    "                   [--ctrl       <policy control value>]\n",
    "                   [--verbose]\n",
    "                   <policy file name>\n",
    "tb_polgen --add    --num         <module number>|any\n",
    "                   --pcr         <TPM PCR number>|none\n",
    "                   --hash        any|image\n",
    "                   [--cmdline    \"command line\"]\n",
    "                   [--image      <image file name>]\n",
    "                   [--verbose]\n",
    "                   <policy file name>\n",
    "tb_polgen --del    --num         <module number>|any\n",
    "                   [--pos        <hash number>]\n",
    "                   [--verbose]\n",
    "                   <policy file name>\n",
    "tb_polgen --unwrap --elt         <elt file name>\n",
    "                   [--verbose]\n",
    "                   <policy file name>\n",
    "tb_polgen --show   [--verbose]\n",
    "                   <policy file name>\n",
    "tb_polgen --help\n",
    NULL
};

/*
 * Define storage for user input parameter pointers
 */
bool verbose = false;

static struct option long_options[] =
{
    /* major sub-commands */
    {"help",           no_argument,          NULL,    'H'},

    {"create",         no_argument,          NULL,    'C'},
    {"add",            no_argument,          NULL,    'A'},
    {"del",            no_argument,          NULL,    'D'},
    {"unwrap",         no_argument,          NULL,    'U'},
    {"show",           no_argument,          NULL,    'S'},

    {"type",           required_argument,    NULL,    't'},
    {"ctrl",           required_argument,    NULL,    'c'},
    {"alg",            required_argument,    NULL,    'a'},

    {"num",            required_argument,    NULL,    'n'},
    {"pcr",            required_argument,    NULL,    'p'},
    {"hash",           required_argument,    NULL,    'h'},
    {"cmdline",        required_argument,    NULL,    'l'},
    {"image",          required_argument,    NULL,    'i'},
    {"pos",            required_argument,    NULL,    'o'},
    {"elt",            required_argument,    NULL,    'e'},

    {"verbose",        no_argument,          (int*)&verbose, true},
    {0, 0, 0, 0}
};

typedef struct {
    const char   *name;
    int           int_opt;
} option_table_t;

static option_table_t policy_type_opts[] = {
    {"nonfatal",     int_opt : TB_POLTYPE_CONT_NON_FATAL},
    {"continue",     int_opt : TB_POLTYPE_CONT_VERIFY_FAIL},
    {"halt",         int_opt : TB_POLTYPE_HALT},
    {NULL}
};

static option_table_t hash_type_opts[] = {
    {"image",        int_opt : TB_HTYPE_IMAGE},
    {"any",          int_opt : TB_HTYPE_ANY},
    {NULL}
};

static option_table_t mod_num_opts[] = {
    {"any",          int_opt : TB_POL_MOD_NUM_ANY},
    {""},
    {NULL}
};

static option_table_t pcr_opts[] = {
    {"none",         int_opt : TB_POL_PCR_NONE},
    {""},
    {NULL}
};

static option_table_t alg_opts[] = {
    {"sha1",         int_opt : TB_HALG_SHA1},
    {"sha256",       int_opt : TB_HALG_SHA256},
    {"sha384",       int_opt : TB_HALG_SHA384},
    {"sha512",       int_opt : TB_HALG_SHA512},
    {NULL}
};

static bool strtonum(char *optarg, int *i)
{
    if ( optarg == NULL || i == NULL )
        return false;

    errno = 0;
    char* p;
    unsigned int value = (unsigned int)strtoul(optarg, &p, 0);
    /* error if either no value or extra chars after value or out of range */
    if ( *optarg == '\0' || *p != '\0' || errno != 0)
        return false;

    *i = value;

    return true;
}

static bool parse_int_option(option_table_t *table, char *optarg, int *option)
{
    if ( option == NULL ) {
        info_msg("NULL option\n");
        return false;
    }
    info_msg("optarg = %s\n", optarg);

    while ( table->name != NULL ) {
        /* matches keyword so return its value */
        if ( strcasecmp(table->name, optarg) == 0 ) {
            *option = table->int_opt;
            return true;
        }
        /* no keyword match but numeric arg is allowed, so try to convert */
        else if ( *table->name == '\0' )
            return strtonum(optarg, option);
        table++;
    }
    return false;
}


void print_params(param_data_t *params)
{
    info_msg("params:\n");
    info_msg("\t cmd = %d\n", params->cmd);
    info_msg("\t policy_type = %d\n", params->policy_type);
    info_msg("\t hash_alg = %d\n", params->hash_alg);
    info_msg("\t policy_control = %d\n", params->policy_control);
    info_msg("\t mod_num = %d\n", params->mod_num);
    info_msg("\t pcr = %d\n", params->pcr);
    info_msg("\t hash_type = %d\n", params->hash_type);
    info_msg("\t pos = %d\n", params->pos);
    info_msg("\t cmdline length = %lu\n",
             (unsigned long int)strnlen_s(params->cmdline, sizeof(params->cmdline)));
    info_msg("\t cmdline = %s\n", params->cmdline);
    info_msg("\t image_file = %s\n", params->image_file);
    info_msg("\t elt_file = %s\n", params->elt_file);
    info_msg("\t policy_file = %s\n", params->policy_file);
}

static bool validate_params(param_data_t *params)
{
    const char *msg = NULL;

    switch( params->cmd ) {
        case POLGEN_CMD_NONE:
            msg = "Missing command argument\n";
            goto error;

        case POLGEN_CMD_CREATE:
            /* these are required in all cases */
            if ( strnlen_s(params->policy_file, sizeof(params->policy_file)) == 0 ) {
                msg = "Missing policy file\n";
                goto error;
            }
            if ( params->policy_type == -1 ) {
                msg = "Missing policy type\n";
                goto error;
            }
            if ( params->hash_alg == -1 ) {
                msg = "Invalid --alg option\n";
                goto error;
            }
            if ( (params->policy_control & ~TB_POLCTL_EXTEND_PCR17) != 0 ) {
                msg = "Invalid --ctrl value\n";
                goto error;
            }
            return true;

        case POLGEN_CMD_ADD:
            /* these are required in all cases */
            if ( strnlen_s(params->policy_file, sizeof(params->policy_file)) == 0 ) {
                msg = "Missing policy file\n";
                goto error;
            }
            /* if hash_type is not ANY then need an image file */
            if ( params->hash_type != TB_HTYPE_ANY &&
                 strnlen_s(params->image_file, sizeof(params->image_file)) == 0 ) {
                msg = "Missing --image option\n";
                goto error;
            }
            /* if hash_type is ANY then no need for an image file */
            if ( params->hash_type == TB_HTYPE_ANY &&
                 strnlen_s(params->image_file, sizeof(params->image_file)) != 0 ) {
                msg = "Extra --image option\n";
                goto error;
            }
            if ( params->hash_type == -1 ) {
                msg = "Missing --hash option\n";
                goto error;
            }
            if ( (params->pcr < 0 || params->pcr > TB_POL_MAX_PCR) &&
                 params->pcr != TB_POL_PCR_NONE ) {
                msg = "Invalid --pcr value\n";
                goto error;
            }
            if ( (params->mod_num < 0 ||
                  params->mod_num > TB_POL_MAX_MOD_NUM) &&
                 params->mod_num != TB_POL_MOD_NUM_ANY ) {
                msg = "Invalid --num value\n";
                goto error;
            }
            return true;

        case POLGEN_CMD_DEL:
            /* these are required in all cases */
            if ( strnlen_s(params->policy_file, sizeof(params->policy_file)) == 0 ) {
                msg = "Missing policy file\n";
                goto error;
            }
            if ( (params->mod_num < 0 ||
                  params->mod_num > TB_POL_MAX_MOD_NUM) &&
                 params->mod_num != TB_POL_MOD_NUM_ANY ) {
                msg = "Invalid --num value\n";
                goto error;
            }
            return true;

        case POLGEN_CMD_UNWRAP:
            if ( strnlen_s(params->policy_file, sizeof(params->policy_file)) == 0 ) {
                msg = "Missing policy file\n";
                goto error;
            }
            if ( strnlen_s(params->elt_file, sizeof(params->elt_file)) == 0 ) {
                msg = "Missing elt file\n";
                goto error;
            }
            return true;

        case POLGEN_CMD_SHOW:
            if ( strnlen_s(params->policy_file, sizeof(params->policy_file)) == 0 ) {
                msg = "Missing policy file\n";
                goto error;
            }
            return true;

        case POLGEN_CMD_HELP:
            return true;

        default:
            msg = "Unknown command\n";
            goto error;
    }

error:
    error_msg("%s", msg);
    if ( verbose )
        print_params(params);
    return false;
}

#define HANDLE_MULTIPLE_CMDS(cmd)                              \
    if ( (cmd) != POLGEN_CMD_NONE ) {                          \
        error_msg("Only one command can be specified\n");      \
        return false;                                          \
    }

bool parse_input_params(int argc, char **argv, param_data_t *params)
{
    int c;
    int option_index = 0;

    /* defaults */
    params->cmd = POLGEN_CMD_NONE;
    params->mod_num = -1;
    params->pcr = -1;
    params->hash_alg = TB_HALG_SHA256;
    params->policy_type = -1;
    params->policy_control = TB_POLCTL_EXTEND_PCR17;
    params->hash_type = -1;
    params->policy_file[0] = '\0';
    params->cmdline[0] = '\0';
    params->image_file[0] = '\0';
    params->elt_file[0] = '\0';

    while ( true ) {
        c = getopt_long_only(argc, argv, "HCADUSt:a:c:n:p:h:l:i:o:e:",
                             long_options, &option_index);
        if ( c == -1 )     /* no more args */
            break;

        switch (c) {
            /* commands */
            case 'H':                       /* --help */
                HANDLE_MULTIPLE_CMDS(params->cmd);
                params->cmd = POLGEN_CMD_HELP;
                return true;
            case 'C':                       /* --create */
                HANDLE_MULTIPLE_CMDS(params->cmd);
                params->cmd = POLGEN_CMD_CREATE;
                break;
            case 'A':                       /* --add */
                HANDLE_MULTIPLE_CMDS(params->cmd);
                params->cmd = POLGEN_CMD_ADD;
                break;
            case 'D':                       /* --del */
                HANDLE_MULTIPLE_CMDS(params->cmd);
                params->cmd = POLGEN_CMD_DEL;
                break;
            case 'U':                       /* --unwrap */
                HANDLE_MULTIPLE_CMDS(params->cmd);
                params->cmd = POLGEN_CMD_UNWRAP;
                 break;
            case 'S':                       /* --show */
                HANDLE_MULTIPLE_CMDS(params->cmd);
                params->cmd = POLGEN_CMD_SHOW;
                break;
            /* options */
            case 'n':                       /* --num */
                if ( !parse_int_option(mod_num_opts, optarg,
                                       (int *)&params->mod_num) ) {
                    error_msg("Unknown --num option\n");
                    return false;
                }
                break;
            case 'p':                       /* --pcr */
                if ( !parse_int_option(pcr_opts, optarg,
                                       (int *)&params->pcr) ) {
                    error_msg("Unknown --pcr option\n");
                    return false;
                }
                break;
            case 't':                       /* --type */
                if ( !parse_int_option(policy_type_opts, optarg,
                                       (int *)&params->policy_type) ) {
                    error_msg("Unknown --type option\n");
                    return false;
                }
                break;
            case 'a':                       /* --alg */
                if ( !parse_int_option(alg_opts, optarg,
                                       (int *)&params->hash_alg) ) {
                    error_msg("Unknown --alg option\n");
                    return false;
                }
                break;
            case 'c':                       /* --ctrl */
                if ( !strtonum(optarg, &params->policy_control) ) {
                    error_msg("Unknown --ctrl option\n");
                    return false;
                }
                break;
            case 'h':                       /* --hash */
                if ( !parse_int_option(hash_type_opts, optarg,
                                       (int *)&params->hash_type) ) {
                    error_msg("Unknown --hash option\n");
                    return false;
                }
                break;
            case 'o':                       /* --pos */
                if ( !strtonum(optarg, &params->pos) ) {
                    error_msg("Unknown --pos option\n");
                    return false;
                }
                break;
            case 'i':                       /* --image */
                if ( optarg == NULL ) {
                    error_msg("Missing filename for --image option\n");
                    return false;
                }
                strcpy_s(params->image_file, sizeof(params->image_file), optarg);
                break;
            case 'l':                       /* --cmdline */
                if ( optarg == NULL ) {
                    error_msg("Missing string for --cmdline option\n");
                    return false;
                }
                if (strnlen_s(optarg, sizeof(params->cmdline)) > sizeof(params->cmdline) - 1) {
                    error_msg("Command line length of %lu exceeds %d "
                              "character maximum\n", 
                              (unsigned long int)strnlen_s(optarg, sizeof(params->cmdline)),
                              TBOOT_KERNEL_CMDLINE_SIZE-1);
                    return false;
                }
                    
                strcpy_s(params->cmdline, sizeof(params->cmdline), optarg);
                break;
            case 'e':                       /* --elt */
                if ( optarg == NULL ) {
                    error_msg("Missing filename for --elt option\n");
                    return false;
                }
                strcpy_s(params->elt_file, sizeof(params->elt_file), optarg);
                break;
            default:
                break;
        }
    }

    /* last argument is policy file */
    if ( optind >= argc ){
        error_msg("Missing filename for policy file\n");
        return false;
    }

    strcpy_s(params->policy_file, sizeof(params->policy_file), argv[optind]);

    return validate_params(params);
}

void display_help_msg(void)
{
    for ( int i = 0; help[i] != NULL; i++ )
        printf("%s", help[i]);
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
