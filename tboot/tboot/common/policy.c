/*
 * policy.c: support functions for tboot verification launch
 *
 * Copyright (c) 2006-2014, Intel Corporation
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

#include <config.h>
#include <stdarg.h>
#include <types.h>
#include <ctype.h>
#include <stdbool.h>
#include <printk.h>
#include <compiler.h>
#include <string.h>
#include <processor.h>
#include <misc.h>
#include <uuid.h>
#include <loader.h>
#include <hash.h>
#include <tb_error.h>
#define PRINT printk
#include <mle.h>
#include <loader.h>
#include <tboot.h>
#include <integrity.h>
#include <tpm.h>
#include <tb_policy.h>
#include <lcp3.h>
#include <lcp3_hlp.h>
#include <cmdline.h>
#include <txt/config_regs.h>
#include <txt/mtrrs.h>
#include <txt/txt.h>
#include <txt/heap.h>

#define MAJOR_VER(v)      ((v) >> 8)

extern void shutdown(void);
extern void s3_launch(void);

/* MLE/kernel shared data page (in boot.S) */
extern tboot_shared_t _tboot_shared;

extern long s3_flag;

/*
 * policy actions
 */
typedef enum {
    TB_POLACT_CONTINUE,
    TB_POLACT_UNMEASURED_LAUNCH,
    TB_POLACT_HALT,
} tb_policy_action_t;

/* policy map types */
typedef struct {
    tb_error_t         error;
    tb_policy_action_t action;
} tb_policy_map_entry_t;

typedef struct {
    uint8_t                policy_type;
    tb_policy_action_t     default_action;
    tb_policy_map_entry_t  exception_action_table[TB_ERR_MAX];
                           /* have TB_ERR_NONE as last entry */
} tb_policy_map_t;

/* map */
static const tb_policy_map_t g_policy_map[] = {
    { TB_POLTYPE_CONT_NON_FATAL,               TB_POLACT_CONTINUE,
      {
          {TB_ERR_FATAL,                       TB_POLACT_HALT},
          {TB_ERR_PREV_TXT_ERROR,              TB_POLACT_UNMEASURED_LAUNCH}, 
          {TB_ERR_TPM_NOT_READY,               TB_POLACT_UNMEASURED_LAUNCH},
          {TB_ERR_SMX_NOT_SUPPORTED,           TB_POLACT_UNMEASURED_LAUNCH},
          {TB_ERR_VMX_NOT_SUPPORTED,           TB_POLACT_UNMEASURED_LAUNCH},
          {TB_ERR_VTD_NOT_SUPPORTED,           TB_POLACT_UNMEASURED_LAUNCH},
	  {TB_ERR_TXT_NOT_SUPPORTED,           TB_POLACT_UNMEASURED_LAUNCH},
          {TB_ERR_SINIT_NOT_PRESENT,           TB_POLACT_UNMEASURED_LAUNCH},
          {TB_ERR_ACMOD_VERIFY_FAILED,         TB_POLACT_UNMEASURED_LAUNCH},
          {TB_ERR_NONE,                        TB_POLACT_CONTINUE},
      }
    },

    { TB_POLTYPE_CONT_VERIFY_FAIL,             TB_POLACT_HALT,
      {
          {TB_ERR_MODULE_VERIFICATION_FAILED,  TB_POLACT_CONTINUE},
          {TB_ERR_NV_VERIFICATION_FAILED,      TB_POLACT_CONTINUE},
          {TB_ERR_POLICY_NOT_PRESENT,          TB_POLACT_CONTINUE},
          {TB_ERR_POLICY_INVALID,              TB_POLACT_CONTINUE},
          {TB_ERR_NONE,                        TB_POLACT_CONTINUE},
      }
    },

    { TB_POLTYPE_HALT,                         TB_POLACT_HALT,
      {
          {TB_ERR_NONE,                        TB_POLACT_CONTINUE},
      }
    },
};

/* buffer for policy as read from TPM NV */
#define MAX_POLICY_SIZE                             \
    (( MAX_TB_POLICY_SIZE > sizeof(lcp_policy_t) )  \
        ? MAX_TB_POLICY_SIZE                        \
        : sizeof(lcp_policy_t) )
static uint8_t _policy_index_buf[MAX_POLICY_SIZE];

/* default policy */
static const tb_policy_t _def_policy = {
    version        : 2,
    policy_type    : TB_POLTYPE_CONT_NON_FATAL,
    hash_alg       : TB_HALG_SHA256,
    policy_control : TB_POLCTL_EXTEND_PCR17,
    num_entries    : 3,
    entries        : {
        {   /* mod 0 is extended to PCR 18 by default, so don't re-extend it */
            mod_num    : 0,
            pcr        : TB_POL_PCR_NONE,
            hash_type  : TB_HTYPE_ANY,
            num_hashes : 0
        },
        {   /* all other modules are extended to PCR 19 */
            mod_num    : TB_POL_MOD_NUM_ANY,
            pcr        : 19,
            hash_type  : TB_HTYPE_ANY,
            num_hashes : 0
        },
        {   /* NV index for geo-tagging will be extended to PCR 22 */
            mod_num    : TB_POL_MOD_NUM_NV_RAW,
            pcr        : 22,
            hash_type  : TB_HTYPE_ANY,
            nv_index   : 0x40000010,
            num_hashes : 0
        }
    }
};

/* default policy for TPM 1.2 */
static const tb_policy_t _def_policy_12 = {
    version        : 2,
    policy_type    : TB_POLTYPE_CONT_NON_FATAL,
    hash_alg       : TB_HALG_SHA1,
    policy_control : TB_POLCTL_EXTEND_PCR17,
    num_entries    : 3,
    entries        : {
        {   /* mod 0 is extended to PCR 18 by default, so don't re-extend it */
            mod_num    : 0,
            pcr        : TB_POL_PCR_NONE,
            hash_type  : TB_HTYPE_ANY,
            num_hashes : 0
        },
        {   /* all other modules are extended to PCR 19 */
            mod_num    : TB_POL_MOD_NUM_ANY,
            pcr        : 19,
            hash_type  : TB_HTYPE_ANY,
            num_hashes : 0
        },
        {   /* NV index for geo-tagging will be extended to PCR 22 */
            mod_num    : TB_POL_MOD_NUM_NV_RAW,
            pcr        : 22,
            hash_type  : TB_HTYPE_ANY,
            nv_index   : 0x40000010,
            num_hashes : 0
        }
    }
};

/* default policy for Details/Authorities pcr mapping */
static const tb_policy_t _def_policy_da = {
    version        : 2,
    policy_type    : TB_POLTYPE_CONT_NON_FATAL,
    hash_alg       : TB_HALG_SHA256,
    policy_control : TB_POLCTL_EXTEND_PCR17,
    num_entries    : 3,
    entries        : {
        {   /* mod 0 is extended to PCR 17 by default, so don't re-extend it */
            mod_num    : 0,
            pcr        : TB_POL_PCR_NONE,
            hash_type  : TB_HTYPE_ANY,
            num_hashes : 0
        },
        {   /* all other modules are extended to PCR 17 */
            mod_num    : TB_POL_MOD_NUM_ANY,
            pcr        : 17,
            hash_type  : TB_HTYPE_ANY,
            num_hashes : 0
        },
        {   /* NV index for geo-tagging will be extended to PCR 22 */
            mod_num    : TB_POL_MOD_NUM_NV_RAW,
            pcr        : 22,
            hash_type  : TB_HTYPE_ANY,
            nv_index   : 0x40000010,
            num_hashes : 0
        }
    }
};

/* current policy */
static const tb_policy_t* g_policy = &_def_policy;

/*
 * read_policy_from_tpm
 *
 * read policy from TPM NV into buffer
 *
 * policy_index_size is in/out
 */
static bool read_policy_from_tpm(uint32_t index, void* policy_index, size_t *policy_index_size)
{
#define NV_READ_SEG_SIZE    256
    unsigned int offset = 0;
    unsigned int data_size = 0;
    uint32_t ret, index_size;
    struct tpm_if *tpm = get_tpm();
    const struct tpm_if_fp *tpm_fp = get_tpm_fp();

    if ( policy_index_size == NULL ) {
        printk(TBOOT_ERR"size is NULL\n");
        return false;
    }

    ret = tpm_fp->get_nvindex_size(tpm, tpm->cur_loc, index, &index_size);
    if ( !ret )
        return false;

    if ( index_size > *policy_index_size ) {
        printk(TBOOT_WARN"policy in TPM NV %x was too big for buffer\n", index);
        index_size = *policy_index_size;
    }


    do {
        /* get data_size */
        if ( (index_size - offset) > NV_READ_SEG_SIZE )
            data_size = NV_READ_SEG_SIZE;
        else
            data_size = (uint32_t)(index_size - offset);

        /* read! */
        ret = tpm_fp->nv_read(tpm, tpm->cur_loc, index, offset,
                             (uint8_t *)policy_index + offset, &data_size);
        if ( !ret || data_size == 0 )
            break;

        /* adjust offset */
        offset += data_size;
    } while ( offset < index_size );

    if ( offset == 0 && !ret ) {
        printk(TBOOT_ERR"Error: read TPM error: 0x%x from index %x.\n", ret, index);
        return false;
    }

    *policy_index_size = offset;

    return true;
}

bool check_index_attribute(uint32_t index)
{
    uint32_t attribute;
    struct tpm_if *tpm = get_tpm();
    const struct tpm_if_fp *tpm_fp = get_tpm_fp();

    if ( !tpm_fp->get_nvindex_permission(tpm, 0, index, &attribute) ) {
        printk(TBOOT_ERR"\treading nv index permission failed\n");
        return false;
    }
    if (attribute & TPM_NV_PER_PPWRITE) {
        printk(TBOOT_ERR"\tnv index should not be TPMA_NV_PPWRITE\n");
        return false;
    }

    return true;
}

/*
 * unwrap_lcp_policy
 *
 * unwrap custom element in lcp policy into tb policy
 * assume sinit has already verified lcp policy and lcp policy data.
 */
static bool unwrap_lcp_policy(void)
{
    void* lcp_base;
    lcp_policy_element_t *elt;
    uint32_t lcp_size;
    uint16_t list_ver;

    // scaffolding
    printk(TBOOT_INFO"in unwrap_lcp_policy\n");

    if ( txt_is_launched() ) {
        txt_heap_t *txt_heap = get_txt_heap();
        os_sinit_data_t *os_sinit_data = get_os_sinit_data_start(txt_heap);

        lcp_base = (void *)(unsigned long)os_sinit_data->lcp_po_base;
        lcp_size = (uint32_t)os_sinit_data->lcp_po_size;
    }
    else {
        extern loader_ctx *g_ldr_ctx;
        if ( !find_lcp_module(g_ldr_ctx, &lcp_base, &lcp_size) )
            return false;
    }

    /* if lcp policy data version is 2+ */
    if ( tb_memcmp((void *)lcp_base, LCP_POLICY_DATA_FILE_SIGNATURE,
             LCP_FILE_SIG_LENGTH) == 0 ) {
        uint32_t elts_size;
        uint32_t all_elt_size; //Value from lcp list PolicyElementsSize field
        lcp_policy_data_t2 *poldata = (lcp_policy_data_t2 *)lcp_base;
        lcp_list_t *pollist = &poldata->policy_lists[0];

        //Read list version
        tb_memcpy((void*)&list_ver, (const void *)pollist, sizeof(uint16_t));
        for ( int i = 0; i < poldata->num_lists; i++ ) {
            if (MAJOR_VER(list_ver) == MAJOR_VER(LCP_TPM12_POLICY_LIST_VERSION)) {
                elt = pollist->tpm12_policy_list.policy_elements;
                elts_size = 0;
                all_elt_size = pollist->tpm12_policy_list.policy_elements_size;
            }
            else if (MAJOR_VER(list_ver) ==
                        MAJOR_VER(LCP_TPM20_POLICY_LIST_VERSION)) {
                elt = pollist->tpm20_policy_list.policy_elements;
                elts_size = 0;
                all_elt_size = pollist->tpm20_policy_list.policy_elements_size;
            }
            else if (MAJOR_VER(list_ver) ==
                        MAJOR_VER(LCP_TPM20_POLICY_LIST2_1_VERSION_300)) {
                elt = pollist->tpm20_policy_list_2_1.PolicyElements;
                elts_size = 0;
                all_elt_size = pollist->tpm20_policy_list_2_1.PolicyElementsSize;
            }
            else {
                printk(TBOOT_ERR"Error: Policy list version not recognized: 0x%x.\n",
                        list_ver);
                return false;
            }

            while ( elt ) {
                /* check element type */
                if ( elt->type == LCP_POLELT_TYPE_CUSTOM || 
                     elt->type == LCP_POLELT_TYPE_CUSTOM2 ) {
                    lcp_custom_element_t *custom =
                        (lcp_custom_element_t *)&elt->data;

                    /* check uuid in custom element */
                    if ( are_uuids_equal(&custom->uuid,
                             &((uuid_t)LCP_CUSTOM_ELEMENT_TBOOT_UUID)) ) {
                        tb_memcpy(_policy_index_buf, &custom->data,
                            elt->size - sizeof(*elt) - sizeof(uuid_t));
                        return true; /* find tb policy */
                    }
                }

                elts_size += elt->size;
                if ( elts_size >= all_elt_size )
                    break;

                elt = (void *)elt + elt->size;
            }
            //If necessary go to next list.
            if ( MAJOR_VER(list_ver) == MAJOR_VER(LCP_TPM12_POLICY_LIST_VERSION)) {
                pollist = (void *)pollist +
                       get_tpm12_policy_list_size((lcp_policy_list_t *)pollist);
            }
            else if ( MAJOR_VER(list_ver) == MAJOR_VER(LCP_TPM20_POLICY_LIST_VERSION)) {
                pollist = (void *)pollist + 
                      get_tpm20_policy_list_size((lcp_policy_list_t2 *)pollist);
            }
            else if ( MAJOR_VER(list_ver) == MAJOR_VER(LCP_TPM20_POLICY_LIST2_1_VERSION_300) ){
                pollist = (void *)pollist +
                   get_raw_tpm20_list_2_1_size(&pollist->tpm20_policy_list_2_1);
            }
        }
    }

    return false;
}

/*
 * set_policy
 *
 * load policy from TPM NV and validate it, else use default
 *
 */
tb_error_t set_policy(void)
{
    const struct tpm_if *tpm = get_tpm();
    
    /* try to read tboot policy from TB_POLICY_INDEX in TPM NV */
    size_t policy_index_size = sizeof(_policy_index_buf);
    printk(TBOOT_INFO"reading Verified Launch Policy from TPM NV...\n");
    if (read_policy_from_tpm(tpm->tb_policy_index, _policy_index_buf,
                             &policy_index_size) &&
            check_index_attribute(tpm->tb_policy_index)) {
        printk(TBOOT_DETA"\t:%lu bytes read\n", policy_index_size);
        if ( verify_policy((tb_policy_t *)_policy_index_buf,
                 policy_index_size, true) ) {
            goto policy_found;
        }
    }
    printk(TBOOT_WARN"\t:reading failed\n");

    /* tboot policy not found in TB_POLICY_INDEX, so see if it is wrapped
     * in a custom element in the PO policy; if so, SINIT will have verified
     * the policy and policy data for us; we just need to ensure the policy
     * type is LCP_POLTYPE_LIST (since we could have been give a policy data
     * file even though the policy was not a LIST */
    printk(TBOOT_INFO"reading Launch Control Policy from TPM NV...\n");
    if (read_policy_from_tpm(tpm->lcp_own_index, _policy_index_buf,
                             &policy_index_size) &&
            check_index_attribute(tpm->lcp_own_index)) {
        printk(TBOOT_DETA"\t:%lu bytes read\n", policy_index_size);
        /* assume lcp policy has been verified by sinit already */
        lcp_policy_t *pol = (lcp_policy_t *)_policy_index_buf;
        if ( MAJOR_VER(pol->version) == MAJOR_VER(LCP_DEFAULT_POLICY_VERSION_2) &&
             pol->policy_type == LCP_POLTYPE_LIST && unwrap_lcp_policy() ) {
            if ( verify_policy((tb_policy_t *)_policy_index_buf,
                     calc_policy_size((tb_policy_t *)_policy_index_buf),
                     true) )
                goto policy_found;
        }
        lcp_policy_t2 *pol2 = (lcp_policy_t2 *)_policy_index_buf;
        /*Only check if major version is 3, minor is checked by sinit*/
        if ( MAJOR_VER(pol2->version) == MAJOR_VER(LCP_DEFAULT_POLICY_VERSION) &&
             pol2->policy_type == LCP_POLTYPE_LIST && unwrap_lcp_policy() ) {
            if ( verify_policy((tb_policy_t *)_policy_index_buf,
                     calc_policy_size((tb_policy_t *)_policy_index_buf),
                     true) )
                goto policy_found;
        }
    }
    printk(TBOOT_WARN"\t:reading failed\n");

    /* either no policy in TPM NV or policy is invalid, so use default */
    printk(TBOOT_WARN"failed to read policy from TPM NV, using default\n");
    if (g_tpm_ver == TPM_VER_12) {
        g_policy = &_def_policy_12;
    } else {
        g_policy = g_using_da ? &_def_policy_da : &_def_policy;
    }
    policy_index_size = calc_policy_size(g_policy);

    /* sanity check; but if it fails something is really wrong */
    if ( !verify_policy(g_policy, policy_index_size, true) )
        return TB_ERR_FATAL;
    else
        return TB_ERR_POLICY_NOT_PRESENT;

policy_found:
    /* compatible with tb_policy tools for TPM 1.2 */
    {
        tb_policy_t *tmp_policy = (tb_policy_t *)_policy_index_buf;
        if (tmp_policy->hash_alg == 0)
            tmp_policy->hash_alg = TB_HALG_SHA1;
    }
    g_policy = (tb_policy_t *)_policy_index_buf;
    return TB_ERR_NONE;
}

/* hash current policy */
bool hash_policy(tb_hash_t *hash, uint16_t hash_alg)
{
    if ( hash == NULL ) {
        printk(TBOOT_ERR"Error: input parameter is wrong.\n");
        return false;
    }

    return hash_buffer((unsigned char *)g_policy, calc_policy_size(g_policy),
                       hash, hash_alg);
}

/* generate hash by hashing cmdline and module image */
static bool hash_module(hash_list_t *hl,
                        const char* cmdline, void *base,
                        size_t size)
{
    struct tpm_if *tpm = get_tpm();

    if ( hl == NULL ) {
        printk(TBOOT_ERR"Error: input parameter is wrong.\n");
        return false;
    }

    /* final hash is SHA-1( SHA-1(cmdline) | SHA-1(image) ) */
    /* where cmdline is first stripped of leading spaces, file name, then */
    /* any spaces until the next non-space char */
    /* (e.g. "  /foo/bar   baz" -> "baz"; "/foo/bar" -> "") */

    /* hash command line */
    if ( cmdline == NULL )
        cmdline = "";
    // else
    //    cmdline = skip_filename(cmdline);

    switch (tpm->extpol) {
    case TB_EXTPOL_FIXED: 
        hl->count = 1;
        hl->entries[0].alg = tpm->cur_alg;

        if ( !hash_buffer((const unsigned char *)cmdline, tb_strlen(cmdline),
                    &hl->entries[0].hash, tpm->cur_alg) )
            return false;
        /* hash image and extend into cmdline hash */
        tb_hash_t img_hash;
        if ( !hash_buffer(base, size, &img_hash, tpm->cur_alg) )
            return false;
        if ( !extend_hash(&hl->entries[0].hash, &img_hash, tpm->cur_alg) )
            return false;

        break;
    
    case TB_EXTPOL_EMBEDDED: 
    {
        tb_hash_t img_hash;
        hl->count = tpm->alg_count;
        for (unsigned int i=0; i<hl->count; i++) {
            hl->entries[i].alg = tpm->algs[i];
            if ( !hash_buffer((const unsigned char *)cmdline, tb_strlen(cmdline),
                        &hl->entries[i].hash, tpm->algs[i]) )
                return false;

            if ( !hash_buffer(base, size, &img_hash, tpm->algs[i]) )
                return false;
            if ( !extend_hash(&hl->entries[i].hash, &img_hash, tpm->algs[i]) )
                return false;
        }

        break;
    }

    default:
        return false;
    }

    return true;
}

static bool is_hash_in_policy_entry(const tb_policy_entry_t *pol_entry,
                                    tb_hash_t *hash, uint16_t hash_alg)
{
    /* assumes policy entry has been validated */

    if ( pol_entry == NULL || hash == NULL) {
        printk(TBOOT_ERR"Error: input parameter is wrong.\n");
        return false;
    }

    if ( pol_entry->hash_type == TB_HTYPE_ANY )
        return true;
    else if ( pol_entry->hash_type == TB_HTYPE_IMAGE ) {
        for ( int i = 0; i < pol_entry->num_hashes; i++ ) {
            if ( are_hashes_equal(get_policy_entry_hash(pol_entry, hash_alg,
                                                        i), hash, hash_alg) )
                return true;
        }
    }

    return false;
}

/*
 * map policy type + error -> action
 */
static tb_policy_action_t evaluate_error(tb_error_t error)
{
    tb_policy_action_t action = TB_POLACT_HALT;

    if ( error == TB_ERR_NONE )
        return TB_POLACT_CONTINUE;

    for ( unsigned int i = 0; i < ARRAY_SIZE(g_policy_map); i++ ) {
        if ( g_policy_map[i].policy_type == g_policy->policy_type ) {
            action = g_policy_map[i].default_action;
            for ( unsigned int j = 0;
                  j < ARRAY_SIZE(g_policy_map[i].exception_action_table);
                  j++ ) {
                if ( g_policy_map[i].exception_action_table[j].error ==
                     error )
                    action = g_policy_map[i].exception_action_table[j].action;
                if ( g_policy_map[i].exception_action_table[j].error ==
                     TB_ERR_NONE )
                    break;
            }
        }
    }

    return action;
}

/*
 * apply policy according to error happened.
 */
void apply_policy(tb_error_t error)
{
    tb_policy_action_t action;

    /* save the error to TPM NV */
    write_tb_error_code(error);

    if ( error != TB_ERR_NONE )
        print_tb_error_msg(error);

    action = evaluate_error(error);
    switch ( action ) {
        case TB_POLACT_CONTINUE:
            return;
        case TB_POLACT_UNMEASURED_LAUNCH:
            /* restore mtrr state saved before */
            restore_mtrrs(NULL);
            if ( s3_flag )
                s3_launch();
            else
                launch_kernel(false);
            break; /* if launch xen fails, do halt at the end */
        case TB_POLACT_HALT:
            break; /* do halt at the end */
        default:
            printk(TBOOT_ERR"Error: invalid policy action (%d)\n", action);
            /* do halt at the end */
    }

    _tboot_shared.shutdown_type = TB_SHUTDOWN_HALT;
    shutdown();
}

#define VL_ENTRIES(i)    g_pre_k_s3_state.vl_entries[i]
#define NUM_VL_ENTRIES   g_pre_k_s3_state.num_vl_entries

/*
 * verify modules against Verified Launch policy and save hash
 * if pol_entry is NULL, assume it is for module 0, which gets extended
 * to PCR 18
 */
static tb_error_t verify_module(module_t *module, tb_policy_entry_t *pol_entry,
                                uint16_t hash_alg)
{
    /* assumes module is valid */

    void *base = (void *)module->mod_start;
    size_t size = module->mod_end - module->mod_start;
    char *cmdline = get_module_cmd(g_ldr_ctx, module);
    if (cmdline == NULL) {
        printk(TBOOT_ERR"Error: failed to get module cmdline\n");
        return TB_ERR_MODULE_VERIFICATION_FAILED;
    }
    const struct tpm_if *tpm = get_tpm();

    if ( pol_entry != NULL ) {
        /* chunk the command line into 80 byte chunks */
#define CHUNK_SIZE 80
        int      cmdlen = tb_strlen(cmdline);
        char    *cptr = cmdline;
        char     cmdchunk[CHUNK_SIZE+1];
        printk(TBOOT_INFO"verifying module \"");
        while (cmdlen > 0) {
            tb_strncpy(cmdchunk, cptr, CHUNK_SIZE);
            cmdchunk[CHUNK_SIZE] = 0;
            printk(TBOOT_INFO"\n%s", cmdchunk);
            cmdlen -= CHUNK_SIZE;
            cptr += CHUNK_SIZE;
        }
        printk(TBOOT_INFO"\"...\n");
    }

    hash_list_t hl;
    if ( !hash_module(&hl, cmdline, base, size) ) {
        printk(TBOOT_ERR"\t hash cannot be generated.\n");
        return TB_ERR_MODULE_VERIFICATION_FAILED;
    }

    /* add new hash to list (unless it doesn't get put in a PCR)
       we'll just drop it if the list is full, but that will mean S3 resume
       PCRs won't match pre-S3
       NULL pol_entry means this is module 0 which is extended to PCR 18 */
    if ( NUM_VL_ENTRIES >= MAX_VL_HASHES )
        printk(TBOOT_WARN"\t too many hashes to save\n");
    else if ( pol_entry == NULL || pol_entry->pcr != TB_POL_PCR_NONE ) {
        uint8_t pcr = (pol_entry == NULL ) ?
                          (g_using_da ? 17 : 18) : pol_entry->pcr;
        VL_ENTRIES(NUM_VL_ENTRIES).pcr = pcr;
        VL_ENTRIES(NUM_VL_ENTRIES++).hl = hl;
    }

    if ( tpm->extpol != TB_EXTPOL_FIXED )
        return TB_ERR_NONE;

    if ( pol_entry != NULL &&
         !is_hash_in_policy_entry(pol_entry, &hl.entries[0].hash, hash_alg) ) {
        printk(TBOOT_ERR"\t verification failed\n");
        return TB_ERR_MODULE_VERIFICATION_FAILED;
    }

    if ( pol_entry != NULL ) {
        printk(TBOOT_DETA"\t OK : "); print_hash(&hl.entries[0].hash, hash_alg);
    }

    return TB_ERR_NONE;
}

static void verify_g_policy(void)
{
    struct tpm_if *tpm = get_tpm();
   
    /* assumes mbi is valid */
    printk(TBOOT_INFO"verifying policy \n");

    /* add entry for policy control field and (optionally) policy */
    /* hash will be <policy control field (4bytes)> | <hash policy> */
    /* where <hash policy> will be 0s if TB_POLCTL_EXTEND_PCR17 is clear */
    static uint8_t buf[sizeof(tb_hash_t) + sizeof(g_policy->policy_control)];
    tb_memset(buf, 0, sizeof(buf));
    tb_memcpy(buf, &g_policy->policy_control, sizeof(g_policy->policy_control));
    if ( g_policy->policy_control & TB_POLCTL_EXTEND_PCR17 ) {
        if ( !hash_policy((tb_hash_t *)&buf[sizeof(g_policy->policy_control)],
                          tpm->cur_alg) ) {
            printk(TBOOT_ERR"policy hash failed\n");
            apply_policy(TB_ERR_MODULE_VERIFICATION_FAILED);
        }
    }

    u32 size = get_hash_size(tpm->cur_alg) + sizeof(g_policy->policy_control);
    switch (tpm->extpol) {
    case TB_EXTPOL_FIXED: 
        VL_ENTRIES(NUM_VL_ENTRIES).hl.count = 1;
        VL_ENTRIES(NUM_VL_ENTRIES).hl.entries[0].alg = tpm->cur_alg;
        if ( !hash_buffer(buf, size,
                &VL_ENTRIES(NUM_VL_ENTRIES).hl.entries[0].hash, tpm->cur_alg) )
            apply_policy(TB_ERR_MODULE_VERIFICATION_FAILED);

        break;

    case TB_EXTPOL_EMBEDDED: 
    {
        VL_ENTRIES(NUM_VL_ENTRIES).hl.count = tpm->alg_count;
        for (int i=0; i<tpm->alg_count; i++) {
            VL_ENTRIES(NUM_VL_ENTRIES).hl.entries[i].alg = tpm->algs[i];
            if ( !hash_buffer(buf, size, &VL_ENTRIES(NUM_VL_ENTRIES).hl.entries[i].hash,
                        tpm->algs[i]) )
                return;
        }

        break;
    }

    default:
        apply_policy(TB_ERR_MODULE_VERIFICATION_FAILED);
        break;
    }

    VL_ENTRIES(NUM_VL_ENTRIES++).pcr = 17;
    if ( g_using_da ) {
        /* copying hash of policy_control into PCR 18 */
        if ( NUM_VL_ENTRIES >= MAX_VL_HASHES )
            printk(TBOOT_ERR"\t too many hashes to save for DA\n");
        else {
            VL_ENTRIES(NUM_VL_ENTRIES).hl = VL_ENTRIES(NUM_VL_ENTRIES-1).hl;
            VL_ENTRIES(NUM_VL_ENTRIES++).pcr = 18;
        }
    }
} 

void verify_all_modules(loader_ctx *lctx)
{
    if (!verify_loader_context(lctx)) {
        printk(TBOOT_ERR"Error: Invalid loader context\n");
        apply_policy(TB_ERR_FATAL);
    }

    /* assumes mbi is valid */
    verify_g_policy();

    /* module 0 is always extended to PCR 18, so add entry for it */
    apply_policy(verify_module(get_module(lctx, 0), NULL, g_policy->hash_alg));

    /* now verify each module and add its hash */
    for ( unsigned int i = 0; i < get_module_count(lctx); i++ ) {
        module_t *module = get_module(lctx, i);
        tb_policy_entry_t *pol_entry = find_policy_entry(g_policy, i);
        if ( module == NULL ) {
            printk(TBOOT_ERR"missing module entry %u\n", i);
            apply_policy(TB_ERR_MODULE_VERIFICATION_FAILED);
        }
        else if ( pol_entry == NULL ) {
            printk(TBOOT_ERR"policy entry for module %u not found\n", i);
            apply_policy(TB_ERR_MODULES_NOT_IN_POLICY);
        }
        else
            apply_policy(verify_module(module, pol_entry, g_policy->hash_alg));
    }

    printk(TBOOT_INFO"all modules are verified\n");
}

static int find_first_nvpolicy_entry(const tb_policy_t *policy)
{
    if ( policy == NULL ) {
        PRINT(TBOOT_ERR"Error: policy pointer is NULL\n");
        return -1;
    }

    for ( int i = 0; i < policy->num_entries; i++ ) {
        tb_policy_entry_t *pol_entry = get_policy_entry(policy, i);
        if ( pol_entry == NULL )
            return -1;

        if ( pol_entry->mod_num == TB_POL_MOD_NUM_NV ||
             pol_entry->mod_num == TB_POL_MOD_NUM_NV_RAW )
            return i;
    }

    return -1;
}

static int find_next_nvpolicy_entry(const tb_policy_t *policy, int i)
{
    if ( policy == NULL || i < 0 || i >= policy->num_entries )
        return -1;

    for ( i++; i < policy->num_entries; i++ ) {
        tb_policy_entry_t *pol_entry = get_policy_entry(policy, i);
        if ( pol_entry == NULL )
            return -1;

        if ( pol_entry->mod_num == TB_POL_MOD_NUM_NV ||
             pol_entry->mod_num == TB_POL_MOD_NUM_NV_RAW )
            return i;
    }

    return -1;
}

static uint8_t nv_buf[4096];

static tb_error_t verify_nvindex(tb_policy_entry_t *pol_entry,
                                 uint16_t hash_alg)
{
    size_t nv_size = sizeof(nv_buf);
    tb_hash_t digest;
    uint32_t attribute;
    struct tpm_if *tpm = get_tpm();
    const struct tpm_if_fp *tpm_fp = get_tpm_fp();

    if ( pol_entry == NULL )
        return TB_ERR_NV_VERIFICATION_FAILED;

    printk(TBOOT_INFO"verifying nv index 0x%08X\n", pol_entry->nv_index);

    /* check nv attribute */
    if ( !tpm_fp->get_nvindex_permission(tpm, 0, pol_entry->nv_index,
                                                   &attribute) ) {
        printk(TBOOT_ERR"\t :reading nv index permission failed\n");
        return TB_ERR_NV_VERIFICATION_FAILED;
    }
    if ( !(attribute & (TPM_NV_PER_OWNERWRITE | TPM_NV_PER_AUTHWRITE)) ) {
        printk(TBOOT_ERR"\t :nv index should be OWNERWRITE or AUTHWRITE, bad permission!\n");
        return TB_ERR_NV_VERIFICATION_FAILED;
    }

    /* get nv content */
    tb_memset(nv_buf, 0, sizeof(nv_buf));
    if ( !read_policy_from_tpm(pol_entry->nv_index,
                nv_buf, &nv_size) ) {
        printk(TBOOT_ERR"\t :reading nv index 0x%08X failed\n",
               pol_entry->nv_index);
        return TB_ERR_NV_VERIFICATION_FAILED;
    }

    /* hash the buffer if needed */
    switch ( pol_entry->mod_num ) {
    case TB_POL_MOD_NUM_NV:
        if ( !hash_buffer((const uint8_t*)nv_buf, nv_size, &digest,
                          TB_HALG_SHA1) ) {
            printk(TBOOT_ERR"\t :nv content hash failed\n");
            return TB_ERR_NV_VERIFICATION_FAILED;
        }
        break;
    case TB_POL_MOD_NUM_NV_RAW:
        if ( nv_size != sizeof(digest.sha1) ) {
            printk(TBOOT_ERR"\t :raw nv with wrong size (%d), should be %d\n",
                   (int)nv_size, sizeof(digest.sha1));
            return TB_ERR_NV_VERIFICATION_FAILED;
        }
        tb_memcpy(digest.sha1, nv_buf, nv_size);
        break;
    default:
        printk(TBOOT_ERR"\t :bad mod number for NV measuring in policy entry: %d\n",
               pol_entry->mod_num);
        return TB_ERR_NV_VERIFICATION_FAILED;
    }

    /* add new hash to list (unless it doesn't get put in a PCR)
       we'll just drop it if the list is full, but that will mean S3 resume
       PCRs won't match pre-S3 */
    if ( NUM_VL_ENTRIES >= MAX_VL_HASHES )
        printk(TBOOT_WARN"\t too many hashes to save\n");
    else if ( pol_entry->pcr != TB_POL_PCR_NONE ) {
        VL_ENTRIES(NUM_VL_ENTRIES).pcr = pol_entry->pcr;
        VL_ENTRIES(NUM_VL_ENTRIES).hl.count = 1;
        VL_ENTRIES(NUM_VL_ENTRIES).hl.entries[0].alg = TB_HALG_SHA1;
        tb_memcpy(VL_ENTRIES(NUM_VL_ENTRIES++).hl.entries[0].hash.sha1,
                digest.sha1, SHA1_LENGTH);
    }

    /* verify nv content */
    if ( !is_hash_in_policy_entry(pol_entry, &digest, hash_alg) ) {
        printk(TBOOT_ERR"\t verification failed\n");
        return TB_ERR_NV_VERIFICATION_FAILED;
    }

    printk(TBOOT_DETA"\t OK : "); print_hash(&digest, hash_alg);
    return TB_ERR_NONE;
}

void verify_all_nvindices(void)
{
    /* go through nv policies in tb policy */
    for ( int i = find_first_nvpolicy_entry(g_policy);
          i >= 0;
          i = find_next_nvpolicy_entry(g_policy, i) ) {
        tb_policy_entry_t *pol_entry = get_policy_entry(g_policy, i);
        apply_policy(verify_nvindex(pol_entry, g_policy->hash_alg));
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
