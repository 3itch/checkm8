/*
 * crtpolelt.c: Intel(R) TXT policy element (LCP_POLICY_ELEMENT) creation tool
 *
 * Copyright (c) 2014, Intel Corporation
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
#include <unistd.h>
#define _GNU_SOURCE
#include <getopt.h>
#include <string.h>
#include <errno.h>
#include <safe_lib.h>
#define PRINT   printf
#include "../include/config.h"
#include "../include/hash.h"
#include "../include/uuid.h"
#include "../include/lcp3.h"
#include "polelt_plugin.h"
#include "polelt.h"
#include "lcputils.h"

#define TOOL_VER_MAJOR 0x1
#define TOOL_VER_MINOR 0x1
#define MAX_HELP_TEXT       4096

static char help[MAX_HELP_TEXT] =
    "Usage: lcp2_crtpolelt <COMMAND> [OPTION]\n"
    "Create an Intel(R) TXT policy element of specified type.\n\n"
    "--create\n"
    "        --type <type>             type of element; must be first option;\n"
    "                                  see below for type strings and their\n"
    "                                  options\n"
    "        --out <FILE>              output file name\n"
    "        [--ctrl <pol_elt_ctrl>]   PolEltControl field (hex or decimal)\n"
    "--show\n"
    "        <FILE>                    policy element file name\n"
    "--help                            help\n"
    "--verbose                         enable verbose output; can be\n"
    "                                  specified with any command\n"
    "--version                         show tool version.\n"
    "types :\n";

bool verbose = false;

#define MAX_CMDLINE_OPTS    256
static struct option long_opts[MAX_CMDLINE_OPTS] =
{
    /* commands */
    {"help",           no_argument,          NULL,     'H'},
    {"version",        no_argument,          NULL,     'V'},
    {"create",         no_argument,          NULL,     'C'},
    {"show",           no_argument,          NULL,     'S'},

    /* options */
    {"type",           required_argument,    NULL,     't'},
    {"out",            required_argument,    NULL,     'o'},
    {"ctrl",           required_argument,    NULL,     'c'},

    {"verbose",        no_argument,          (int *)&verbose, true},
    {0, 0, 0, 0}
};

static void add_plugins(void)
{
    /* we will add each plugin's opts to end, so find initial last one */
    unsigned int nr_opts = 0;
    struct option *opt = long_opts;
    while ( opt->name != NULL ) {
        opt++;
        nr_opts++;
    }

    for ( unsigned int i = 0; i < nr_polelt_plugins; i++ ) {
        polelt_plugin_t *plugin = polelt_plugins[i];

        LOG("supporting LCP element plugin type \'%s\'\n",
                plugin->type_string);

        /* copy options */
        struct option *plugin_opt = plugin->cmdline_opts;
        while ( plugin_opt != NULL && plugin_opt->name != NULL &&
                nr_opts < ARRAY_SIZE(long_opts) ) {
            *opt++ = *plugin_opt++;
            nr_opts++;
        }
        if ( nr_opts == ARRAY_SIZE(long_opts) )
            ERROR("Error: too many plugin options\n");

        /* copy help text */
        strcat_s(help, MAX_HELP_TEXT, plugin->help_txt);
    }
}

int main (int argc, char *argv[])
{
    int cmd = 0;
    polelt_plugin_t *curr_plugin = NULL;
    bool prev_cmd = false;
    uint32_t pol_elt_ctrl = DEFAULT_POL_ELT_CONTROL;
    char out_file[MAX_PATH] = "";
    int c;

    /* add each plugin's command line option strings and help text */
    add_plugins();

    do {
        c = getopt_long_only(argc, argv, "", long_opts, NULL);

        switch (c) {
        case 'H':            /* help */
        case 'C':            /* create */
        case 'S':            /* show */
        case 'V':            /* version  */
            if ( prev_cmd ) {
                ERROR("Error: only one command can be specified\n");
                return 1;
            }
            prev_cmd = true;
            cmd = c;
            LOG("cmdline opt: command: %c\n", cmd);
            break;

        case 't':            /* type */
            curr_plugin = find_polelt_plugin_by_type_string(optarg);
            if ( curr_plugin == NULL ) {
                ERROR("Error: unknown type \'%s\'\n", optarg);
                return 1;
            }
            LOG("cmdline opt: type: \'%s\'\n", curr_plugin->type_string);
            break;

        case 'o':            /* out */
            strlcpy(out_file, optarg, sizeof(out_file));
            LOG("cmdline opt: out: %s\n", out_file);
            break;

        case 'c':            /* ctrl */
            pol_elt_ctrl = strtoul(optarg, NULL, 0);
            LOG("cmdline opt: ctrl: 0x%x\n", pol_elt_ctrl);
            break;

        case 0:
        case -1:
            break;

        case '?':            /* unknown option */
            return 1;

        default:
            /* assume this is handled by the plugin */
            if ( curr_plugin == NULL ) {
                ERROR("Error: type must be the first option\n");
                return 1;
            }
            if ( !(curr_plugin->cmdline_handler)(c, optarg) )
                return 1;
            break;
        }
    } while ( c != -1 );

    if ( cmd == 0 ) {
        ERROR("Error: no command was specified\n");
        return 1;
    }
    else if ( cmd == 'H' ) {           /* --help */
        DISPLAY("%s", help);
        return 0;
    }
    else if ( cmd == 'S' ) {           /* --show */
        if ( optind == argc ) {
            ERROR("Error: no files specified\n");
            return 1;
        }

        /* process any remaining argv[] items as element files */
        while ( optind < argc ) {
            LOG("cmdline opt: file: %s\n", argv[optind]);
            DISPLAY("policy element file: %s\n", argv[optind]);

            size_t len;
            lcp_policy_element_t *elt = (lcp_policy_element_t *)
                read_file(argv[optind++], &len, false);
            if ( elt == NULL )
                return 1;
            if ( !verify_policy_element(elt, len) )
                return 1;
            display_policy_element("    ", elt, false);
        }
        return 0;
    }
    else if ( cmd == 'C' ) {           /* --create */
        if ( curr_plugin == NULL ) {
            ERROR("Error: no type was specified\n");
            return 1;
        }
        if ( *out_file == '\0' ) {
            ERROR("Error: no output file specified\n");
            return 1;
        }

        /* process any remaining argv[] items in plugin */
        while ( optind < argc ) {
            LOG("cmdline opt: file: %s\n", argv[optind]);
            if ( !(curr_plugin->cmdline_handler)(0, argv[optind]) )
                return 1;
            optind++;
        }

        /*
         * write element to out_file
         */
        lcp_policy_element_t *elt = (curr_plugin->create_elt)();
        if ( elt == NULL ) {
            ERROR("Error: failed to allocate element\n");
            return 1;
        }
        /* size is filled in by create() */
        elt->type = curr_plugin->type;
        elt->policy_elt_control = pol_elt_ctrl;

        if ( !write_file(out_file, elt, elt->size) ) {
            ERROR("Error: error writing element\n");
            free(elt);
            return 1;
        }
        free(elt);
        return 0;
    }

    else if ( cmd == 'V' ) /* --version */ {
        DISPLAY("lcp2_crtpolelt version: %i.%i", TOOL_VER_MAJOR,
                                                 TOOL_VER_MINOR);
        return 0;
    }

    ERROR("Error: unknown command option\n");
    return 1;
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
