/*
 * cmdline.c: command line parsing fns
 *
 * Copyright (c) 2006-2012, Intel Corporation
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
#ifndef IS_INCLUDED
#include <config.h>
#include <types.h>
#include <stdbool.h>
#include <ctype.h>
#include <compiler.h>
#include <string.h>
#include <misc.h>
#include <printk.h>
#include <cmdline.h>
#include <tpm.h>
#include <tboot.h>
#include <mle.h>
#include <txt/mtrrs.h>
#include <multiboot.h>
#include <txt/config_regs.h>
#include <txt/heap.h>
#endif
/*
 * copy of original command line
 * part of tboot measurement (hence in .text section)
 */
__text char g_cmdline[CMDLINE_SIZE] = { 0 };

/* Used for kernel command line parameter setup */
typedef struct {
    const char *name;          /* set to NULL for last item in list */
    const char *def_val;
} cmdline_option_t;

#define MAX_VALUE_LEN 64

/*
 * the option names and default values must be separate from the actual
 * params entered
 * this allows the names and default values to be part of the MLE measurement
 * param_values[] need to be in .bss section so that will get cleared on launch
 */

/* global option array for command line */
static const cmdline_option_t g_tboot_cmdline_options[] = {
    { "loglvl",     "all" },         /* all|err,warn,info|none */
    { "logging",    "serial,vga" },  /* vga,serial,memory|none */
    { "serial",     "115200,8n1,0x3f8" },
    /* serial=<baud>[/<clock_hz>][,<DPS>[,<io-base>[,<irq>[,<serial-bdf>[,<bridge-bdf>]]]]] */
    { "vga_delay",  "0" },           /* # secs */
    { "ap_wake_mwait", "false" },    /* true|false */
    { "pcr_map", "legacy" },         /* legacy|da */
    { "min_ram", "0" },              /* size in bytes | 0 for no min */
    { "call_racm", "false" },        /* true|false|check */
    { "measure_nv", "false" },       /* true|false */
    { "extpol",    "sha256" },         /*agile|embedded|sha1|sha256|sm3|... */
    { "ignore_prev_err", "true"},    /* true|false */
    { "force_tpm2_legacy_log", "false"}, /* true|false */
    { "save_vtd", "false"},          /* true|false */
    { "dump_memmap", "false"},          /* true|false */
    { NULL, NULL }
};
static char g_tboot_param_values[ARRAY_SIZE(g_tboot_cmdline_options)][MAX_VALUE_LEN];

static const cmdline_option_t g_linux_cmdline_options[] = {
    { "vga", "" },
    { "mem", "" },
    { NULL, NULL }
};
static char g_linux_param_values[ARRAY_SIZE(g_linux_cmdline_options)][MAX_VALUE_LEN];

typedef struct {
    const char *log_name;
    uint8_t    log_val;
} tb_loglvl_map_t;

/* map */
static const tb_loglvl_map_t g_loglvl_map[] = {
    { "none",  TBOOT_LOG_LEVEL_NONE  },
    { "err",   TBOOT_LOG_LEVEL_ERR   },
    { "warn",  TBOOT_LOG_LEVEL_WARN  },
    { "info",  TBOOT_LOG_LEVEL_INFO  },
    { "detail",TBOOT_LOG_LEVEL_DETA  },
    { "all",   TBOOT_LOG_LEVEL_ALL   },
};

static const char* get_option_val(const cmdline_option_t *options,  char vals[][MAX_VALUE_LEN],    const char *opt_name)
{
    for ( int i = 0; options[i].name != NULL; i++ ) {
        if ( tb_strcmp(options[i].name, opt_name) == 0 )
            return vals[i];
    }
    printk(TBOOT_ERR"requested unknown option: %s\n", opt_name);
    return NULL;
}

static void cmdline_parse(const char *cmdline, const cmdline_option_t *options,
                          char vals[][MAX_VALUE_LEN])
{
    const char *p = cmdline;
    int i;

    /* copy default values to vals[] */
    for ( i = 0; options[i].name != NULL; i++ ) {
        tb_strncpy(vals[i], options[i].def_val, MAX_VALUE_LEN-1);
        vals[i][MAX_VALUE_LEN-1] = '\0';
    }

    if ( p == NULL )
        return;

    /* parse options */
    while ( true )
    {
        /* skip whitespace */
        while ( isspace(*p) )
            p++;
        if ( *p == '\0' )
            break;

        /* find end of current option */
        const char *opt_start = p;
        const char *opt_end = tb_strchr(opt_start, ' ');
        if ( opt_end == NULL )
            opt_end = opt_start + tb_strlen(opt_start);
        p = opt_end;

        /* find value part; if no value found, use default and continue */
        const char *val_start = tb_strchr(opt_start, '=');
        if ( val_start == NULL || val_start > opt_end )
            continue;
        val_start++;

        unsigned int opt_name_size = val_start - opt_start - 1;
        unsigned int copy_size = opt_end - val_start;
        if ( copy_size > MAX_VALUE_LEN - 1 )
            copy_size = MAX_VALUE_LEN - 1;
        if ( opt_name_size == 0 || copy_size == 0 )
            continue;

        /* value found, so copy it */
        for ( i = 0; options[i].name != NULL; i++ ) {
            if ( tb_strncmp(options[i].name, opt_start, opt_name_size ) == 0 ) {
                tb_strncpy(vals[i], val_start, copy_size);
                vals[i][copy_size] = '\0'; /* add '\0' to the end of string */
                break;
            }
        }
    }
}

void tboot_parse_cmdline(void)
{
    cmdline_parse(g_cmdline, g_tboot_cmdline_options, g_tboot_param_values);
}

void linux_parse_cmdline(const char *cmdline)
{
    cmdline_parse(cmdline, g_linux_cmdline_options, g_linux_param_values);
}

uint8_t get_loglvl_prefix(char **pbuf, int *len)
{
    uint8_t log_level = TBOOT_LOG_LEVEL_ALL;

    if ( *len > 2 && **pbuf == '<' && *(*pbuf+2) == '>'
                  && isdigit(*(*pbuf+1)) ) {
        unsigned int i = *(*pbuf+1) - '0';
        if ( i < ARRAY_SIZE(g_loglvl_map) )
            log_level = g_loglvl_map[i].log_val;
        *pbuf += 3;
        *len = *len - 3;
    }

    return log_level;
}

void get_tboot_loglvl(void)
{
    const char *loglvl = get_option_val(g_tboot_cmdline_options,
                                        g_tboot_param_values, "loglvl");
    if ( loglvl == NULL )
        return;

    /* determine whether the target is set explicitly */
    while ( isspace(*loglvl) )
        loglvl++;

    g_log_level = TBOOT_LOG_LEVEL_NONE;

    while ( *loglvl != '\0' ) {
        unsigned int i;

        for ( i = 0; i < ARRAY_SIZE(g_loglvl_map); i++ ) {
            if ( tb_strncmp(loglvl, g_loglvl_map[i].log_name,
                     tb_strlen(g_loglvl_map[i].log_name)) == 0 ) {
                loglvl += tb_strlen(g_loglvl_map[i].log_name);

                if ( g_loglvl_map[i].log_val == TBOOT_LOG_LEVEL_NONE ) {
                    g_log_level = TBOOT_LOG_LEVEL_NONE;
                    return;
                }
                else {
                    g_log_level |= g_loglvl_map[i].log_val;
                    break;
                }
            }
        }

        if ( i == ARRAY_SIZE(g_loglvl_map) )
            break; /* unrecognized, end loop */

        /* skip ',' */
        if ( *loglvl == ',' )
            loglvl++;
        else
            break; /* unrecognized, end loop */
    }
}

void get_tboot_log_targets(void)
{
    const char *targets = get_option_val(g_tboot_cmdline_options,
                                         g_tboot_param_values, "logging");

    /* nothing set, leave defaults */
    if ( targets == NULL || *targets == '\0' )
        return;

    /* determine if no targets set explicitly */
    if ( tb_strcmp(targets, "none") == 0 ) {
        g_log_targets = TBOOT_LOG_TARGET_NONE; /* print nothing */
        return;
    }

    /* else init to nothing and parse the possible targets */
    g_log_targets = TBOOT_LOG_TARGET_NONE;

    while ( *targets != '\0' ) {
        if ( tb_strncmp(targets, "memory", 6) == 0 ) {
            g_log_targets |= TBOOT_LOG_TARGET_MEMORY;
            targets += 6;
        }
        else if ( tb_strncmp(targets, "serial", 6) == 0 ) {
            g_log_targets |= TBOOT_LOG_TARGET_SERIAL;
            targets += 6;
        }
        else if ( tb_strncmp(targets, "vga", 3) == 0 ) {
            g_log_targets |= TBOOT_LOG_TARGET_VGA;
            targets += 3;
        }
        else 
            break; /* unrecognized, end loop */

        if ( *targets == ',' )
            targets++;
        else
            break; /* unrecognized, end loop */
    }
}

static bool parse_pci_bdf(const char **bdf, uint32_t *bus, uint32_t *slot,
                          uint32_t *func)
{
    *bus = tb_strtoul(*bdf, (char **)bdf, 16);
    if ( **bdf != ':' )
        return false;
    (*bdf)++;
    *slot = tb_strtoul(*bdf, (char **)bdf, 16);
    if ( **bdf != '.' )
        return false;
    (*bdf)++;
    *func = tb_strtoul(*bdf, (char **)bdf, 16);

    return true;
}

bool g_psbdf_enabled = false;
static bool parse_com_psbdf(const char **bdf)
{
    g_psbdf_enabled = parse_pci_bdf(bdf,
                  &g_com_port.comc_psbdf.bus,
                  &g_com_port.comc_psbdf.slot,
                  &g_com_port.comc_psbdf.func);

    return g_psbdf_enabled;
}

bool g_pbbdf_enabled = false;
static bool parse_com_pbbdf(const char **bdf)
{
    g_pbbdf_enabled = parse_pci_bdf(bdf,
                  &g_com_port.comc_pbbdf.bus,
                  &g_com_port.comc_pbbdf.slot,
                  &g_com_port.comc_pbbdf.func);

    return g_pbbdf_enabled;
}

static bool parse_com_fmt(const char **fmt)
{
    /* fmt:  <5|6|7|8><n|o|e|m|s><0|1> */
    /* default 8n1 */
    uint8_t data_bits = 8;
    uint8_t parity = 'n';
    uint8_t stop_bits = 1;


    /* must specify all values */
    if ( tb_strlen(*fmt) < 3 )
        return false;

    /* data bits */
    if ( **fmt >= '5' && **fmt <= '8' )
        data_bits = **fmt - '0';
    else
        return false;
    (*fmt)++;

    /* parity */
    if ( **fmt == 'n' || **fmt == 'o' || **fmt == 'e' || **fmt == 'm' ||
         **fmt == 's' )
        parity = **fmt;
    else
        return false;
    (*fmt)++;

    /* stop bits */
    if ( **fmt == '0' || **fmt == '1' )
        stop_bits = **fmt - '0';
    else
        return false;
    (*fmt)++;

    g_com_port.comc_fmt = GET_LCR_VALUE(data_bits, stop_bits, parity);

    return true;
}

static bool parse_serial_param(const char *com)
{
    /* parse baud */
    g_com_port.comc_curspeed = tb_strtoul(com, (char **)&com, 10);
    if ( (g_com_port.comc_curspeed < 1200) ||
         (g_com_port.comc_curspeed > 115200) )
        return false;

    /* parse clock hz */
    if ( *com == '/' ) {
        ++com;
        g_com_port.comc_clockhz = tb_strtoul(com, (char **)&com, 0) << 4;
        if ( g_com_port.comc_clockhz == 0 )
            return false;
    }

    /* parse data_bits/parity/stop_bits */
    if ( *com != ',' )
        goto exit;
    ++com;
    while ( isspace(*com) )
        com++;
    if ( !parse_com_fmt(&com) )
        return false;

    /* parse IO base */
    if ( *com != ',' )
        goto exit;
    ++com;
    g_com_port.comc_port = tb_strtoul(com, (char **)&com, 0);
    if ( g_com_port.comc_port == 0 )
        return false;

    /* parse irq */
    if ( *com != ',' )
        goto exit;
    ++com;
    g_com_port.comc_irq = tb_strtoul(com, (char **)&com, 10);
    if ( g_com_port.comc_irq == 0 )
        return false;

    /* parse PCI serial controller bdf */
    if ( *com != ',' )
        goto exit;
    ++com;
    if ( !parse_com_psbdf(&com) )
        return false;

    /* parse PCI bridge bdf */
    if ( *com != ',' )
        goto exit;
    ++com;
    if ( !parse_com_pbbdf(&com) )
        return false;

 exit:
    return true;
}

bool get_tboot_serial(void)
{
    const char *serial = get_option_val(g_tboot_cmdline_options,
                                        g_tboot_param_values, "serial");
    if ( serial == NULL || *serial == '\0' )
        return false;

    return parse_serial_param(serial);
}

void get_tboot_vga_delay(void)
{
    const char *vga_delay = get_option_val(g_tboot_cmdline_options,
                                           g_tboot_param_values, "vga_delay");
    if ( vga_delay == NULL )
        return;

    g_vga_delay = tb_strtoul(vga_delay, NULL, 0);
}

bool get_tboot_prefer_da(void)
{
    const char *value = get_option_val(g_tboot_cmdline_options,
                                       g_tboot_param_values, "pcr_map");
    if ( value != NULL && tb_strcmp(value, "da") == 0 )
        return true;

    return false;
}

extern uint32_t g_min_ram;
void get_tboot_min_ram(void)
{
    const char *min_ram = get_option_val(g_tboot_cmdline_options,
                                         g_tboot_param_values, "min_ram");
    if ( min_ram == NULL )
        return;

    g_min_ram = tb_strtoul(min_ram, NULL, 0);
}

bool get_tboot_mwait(void)
{
    const char *mwait = get_option_val(g_tboot_cmdline_options,
                                       g_tboot_param_values, "ap_wake_mwait");
    if ( mwait == NULL || tb_strcmp(mwait, "false") == 0 )
        return false;
    return true;
}

bool get_tboot_call_racm(void)
{
    const char *call_racm = get_option_val(g_tboot_cmdline_options,
                                       g_tboot_param_values, "call_racm");
    if ( call_racm == NULL || tb_strcmp(call_racm, "true") != 0 )
        return false;
    return true;
}

bool get_tboot_call_racm_check(void)
{
    const char *call_racm = get_option_val(g_tboot_cmdline_options,
                                       g_tboot_param_values, "call_racm");
    if ( call_racm == NULL || tb_strcmp(call_racm, "check") != 0 )
        return false;
    return true;
}

bool get_tboot_measure_nv(void)
{
    const char *measure_nv = get_option_val(g_tboot_cmdline_options,
                                       g_tboot_param_values, "measure_nv");
    if ( measure_nv == NULL || tb_strcmp(measure_nv, "true") != 0 )
        return false;
    return true;
}

void get_tboot_extpol(void)
{
    const char *extpol = get_option_val(g_tboot_cmdline_options, g_tboot_param_values, "extpol");
    struct tpm_if *tpm = get_tpm();

    if ( extpol == NULL ) {
        tpm->extpol = TB_EXTPOL_FIXED;
        tpm->cur_alg = TB_HALG_SHA256;
        return;
    }

    if ( tb_strcmp(extpol, "agile") == 0 ) {
        printk(TBOOT_WARN"Warning: \"agile\" selected in extpol, "
                         "this option is deprecated\n");
        tpm->extpol = TB_EXTPOL_FIXED;
        tpm->cur_alg = TB_HALG_SHA256;
    } else if ( tb_strcmp(extpol, "embedded") == 0 ) {
        tpm->extpol = TB_EXTPOL_EMBEDDED;
        tpm->cur_alg = TB_HALG_SHA256;
    } else if ( tb_strcmp(extpol, "sha256") == 0 ) {
        tpm->extpol = TB_EXTPOL_FIXED;
        tpm->cur_alg = TB_HALG_SHA256;
    } else if ( tb_strcmp(extpol, "sha1") == 0 ) {
        printk(TBOOT_WARN"Warning: SHA1 is selected in extpol, this is an unsafe option\n");
        tpm->extpol = TB_EXTPOL_FIXED;
        tpm->cur_alg = TB_HALG_SHA1;
    } else if ( tb_strcmp(extpol, "sm3") == 0 ) {
        tpm->extpol = TB_EXTPOL_FIXED;
        tpm->cur_alg = TB_HALG_SM3;
    } else if ( tb_strcmp(extpol, "sha384") == 0 ) {
        tpm->extpol = TB_EXTPOL_FIXED;
        tpm->cur_alg = TB_HALG_SHA384;
    } else if ( tb_strcmp(extpol, "sha512") == 0 ) {
        tpm->extpol = TB_EXTPOL_FIXED;
        tpm->cur_alg = TB_HALG_SHA512;
    }
}

bool get_tboot_force_tpm2_legacy_log(void)
{
    const char *force_legacy_log =
       get_option_val(g_tboot_cmdline_options,
              g_tboot_param_values,
              "force_tpm2_legacy_log");
    if ( force_legacy_log != NULL && tb_strcmp(force_legacy_log, "true") == 0 )
       return true;
    return false;
}

bool get_tboot_ignore_prev_err(void)
{
    const char *ignore_prev_err = 
	    get_option_val(g_tboot_cmdline_options,
			   g_tboot_param_values,
			   "ignore_prev_err");
    if ( ignore_prev_err == NULL || tb_strcmp(ignore_prev_err, "true") == 0 )
	    return true;
    return false;
}

bool get_tboot_save_vtd(void)
{
    const char *save_vtd =
       get_option_val(g_tboot_cmdline_options,
              g_tboot_param_values,
              "save_vtd");
    if ( save_vtd != NULL && tb_strcmp(save_vtd, "true") == 0 )
       return true;
    return false;
}

bool get_tboot_dump_memmap(void)
{
    const char *dump_memmap =
       get_option_val(g_tboot_cmdline_options,
              g_tboot_param_values,
              "dump_memmap");
    if ( dump_memmap != NULL && tb_strcmp(dump_memmap, "true") == 0 )
       return true;
    return false;
}

/*
 * linux kernel command line parsing
 */

bool get_linux_vga(int *vid_mode)
{
    const char *vga = get_option_val(g_linux_cmdline_options,
                                     g_linux_param_values, "vga");
    if ( vga == NULL || vid_mode == NULL )
        return false;

    if ( tb_strcmp(vga, "normal") == 0 )
        *vid_mode = 0xFFFF;
    else if ( tb_strcmp(vga, "ext") == 0 )
        *vid_mode = 0xFFFE;
    else if ( tb_strcmp(vga, "ask") == 0 )
        *vid_mode = 0xFFFD;
    else
        *vid_mode = tb_strtoul(vga, NULL, 0);

    return true;
}

bool get_linux_mem(uint64_t *max_mem)
{
    char *last = NULL;
    const char *mem = get_option_val(g_linux_cmdline_options,
                                     g_linux_param_values, "mem");
    if ( mem == NULL || max_mem == NULL )
        return false;

    *max_mem = tb_strtoul(mem, &last, 0);
    if ( *max_mem == 0 )
        return false;

    if ( last == NULL )
        return true;

    switch ( *last ) {
        case 'G':
        case 'g':
            *max_mem = *max_mem << 30;
            return true;
        case 'M':
        case 'm':
            *max_mem = *max_mem << 20;
            return true;
        case 'K':
        case 'k':
            *max_mem = *max_mem << 10;
            return true;
        default:
            return false;
    }

    return true;
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
