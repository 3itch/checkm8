/*
 * pconf_legacy.c: PCONF element (LCP_PCONF_ELEMENT) plugin
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
#include <string.h>
#define _GNU_SOURCE
#include <getopt.h>
#include <arpa/inet.h>

#include <safe_lib.h>

#define PRINT printf

#include "../include/config.h"
#include "../include/hash.h"
#include "../include/uuid.h"
#include "../include/lcp3.h"
#include "polelt_plugin.h"
#include "lcputils.h"

#define MAX_FILES 32
#define MAX_PATH 256
#define MAX_PCRS 8 //PCRs 0-7
#define MAX_PCR_FILES 8;


//This will store pcr-related data
typedef struct pcr_data {
    bool    valid;
    uint8_t num;
    uint8_t locality;
    uint8_t digest[SHA1_DIGEST_SIZE];
} pcr_data;

typedef struct __packed {
    tpm_pcr_selection   pcr_selection;
    uint32_t            size_of_pcrs;   // big endian
    unsigned char       pcrs[][SHA1_DIGEST_SIZE];
} pcr_composite_buffer;

//Global vars:
char pcr_info_files[MAX_FILES][MAX_PATH];
uint8_t num_files = 0;
int prevOpt = 'i';

pcr_data pcrs[8];

static bool read_pcrinfo_file(const char *file)
{
    /*
    Each line in file has the following format:
    locality:value
    pcrNum:digest(no spaces)
    Length max is 47
    Each file is one PCR_INFO_SHORT and num of files
    will be NumPcrInfoShort

    */

    char delim[] = ":";
    char *line = NULL;
    char *token = NULL;
    char *ptr2token = NULL;

    size_t line_size_bytes = 80;
    size_t chars_read;
    unsigned long locality = 0x0;

    line = malloc(line_size_bytes);
    if (line == NULL) {
        return false;
    }

    FILE *fp = NULL;
    fp = fopen(file, "r");
    if (fp == NULL) {
        free(line);
        return false;
    }

    while (getline(&line, &chars_read, fp) != -1 ) {
        pcr_data this_pcr;
        this_pcr.locality = 0xFF; //This is set by first line in file
        this_pcr.num = 0xFF;
        this_pcr.valid = false;

        line_size_bytes = 80;
        if (*line == '\n'|| *line == '#' || *line == '\r' || !*line) { // if empty or # at the beginning skip
            continue;
        }
        //First valid line should be locality
        token = strtok_s(line, &line_size_bytes, delim, &ptr2token);
        if (locality) {
            this_pcr.locality = locality;
        }
        if (strcmp(token, "locality") != 0 && !strisdigit_s(token, 1)) {
            ERROR("Error: in pcrInfo file a line must be 'locality:value' or pcrNum:digest\n");
            goto ERROR;
        }
        if (strcmp(token, "locality") == 0) {
            //Only allowed once in a file
            if (locality) {
                ERROR("Error: locality was already specified.\n");
                goto ERROR;
            }
            locality = strtoul(ptr2token, NULL, 16);
            if (!locality) {
                ERROR("Error: you must select at least one locality.\n");
                goto ERROR;
            }
            if (locality > 0x1F) {
                ERROR("Error: locality mask cannot be greater than 0x1F. Detected: 0x%x\n",
                                                                this_pcr.locality);
                goto ERROR;
            }
            this_pcr.locality = locality;
            continue;
        }
        //PcrNum is a digit 0 to 7
        if (strisdigit_s(token, 1)) {
            this_pcr.num = atoi(token);
            if (this_pcr.num > 7) {
                ERROR("Error: only pcrs 0-7 are supported.\n");
                goto ERROR;
            }
        }
        /*
        Getline also reads up to and including newline. We need to remove it else
        import_hash will fail.
        */
        if (ptr2token == NULL) {
            goto ERROR;
        }
        ptr2token[40] = '\0';
        if (!import_hash(ptr2token, (tb_hash_t *) &this_pcr.digest, LCP_POLHALG_SHA1)) {
            ERROR("Error: failed to import hash. Check digest format.\n");
            goto ERROR;
        }
        if (this_pcr.locality != 0xFF && this_pcr.num != 0xFF) {
            this_pcr.valid = true;
            pcrs[this_pcr.num] = this_pcr;
	    pcrs[0].locality = locality;
        }
        else {
            ERROR("Error: failed to read PCR data. Check input file.\n");
            goto ERROR;
        }
    }
    //SUCCESS:
    fclose(fp);
    free(line);
    return true;
    ERROR:
        fclose(fp);
        free(line);
        return false;
}

static bool cmdline_handler(int c, const char *opt)
{
    if (c) {
        ERROR("Error: pconf element takes no CLI options\n");
        return false;
    }
    if (opt) {
        size_t opt_len = strnlen(opt, MAX_PATH);
        strncpy_s(pcr_info_files[num_files], MAX_PATH, opt, opt_len);
        num_files++;
        return true;
    }
    else {
        ERROR("Error: at least one file must be specified.\n");
        return false;
    }
    if (num_files > MAX_FILES) {
        ERROR("Error: too many files specified. Max is 32.\n");
        return false;
    }
}

static bool generate_composite_hash(tpm_pcr_selection *pcr_selection, pcr_data *pcrs, tb_hash_t *dest, uint8_t no_of_pcrs)
{
    /*
    This function: concatenates pcr values to one blob and hashes it using sha1

    in: array of pcrs, allocated destination buffer, no of pcrs
    out: true/false on success/failure. Dest gets the composite hash

    */
    int count = 0;
    bool result;
    pcr_composite_buffer *buff;
    size_t buff_size = 0;

    if (pcrs == NULL || dest == NULL) {
        ERROR("Error: pcrs or buffer for digest are not defined.\n");
        return false;
    }
    if (no_of_pcrs < 1 || no_of_pcrs > 8) {
        ERROR("Error: at least 1 and at most 8 pcrs must be selected.\n");
        return false;
    }
    buff_size = no_of_pcrs * SHA1_DIGEST_SIZE + sizeof(buff) - sizeof(buff->pcrs[0][0]);
    buff = calloc(1, buff_size);
    if (buff == NULL) {
        ERROR("Error: failed to allocate buffer for composite digest.\n");
        return false;
    }
    memcpy_s(
        &buff->pcr_selection,
        sizeof buff->pcr_selection,
        pcr_selection,
        sizeof buff->pcr_selection
    );
    for (int i = 0; i < MAX_PCRS; i++) {
        if (pcrs[i].valid) {
            if (verbose) {
                DISPLAY("PCR%d value: ", i);
                print_hex("", (const void *) pcrs[i].digest, SHA1_DIGEST_SIZE);
            }
            memcpy_s(
                buff->pcrs[count], //Dest
                SHA1_DIGEST_SIZE, //Dest size
                (const void *) pcrs[i].digest, //Src
                SHA1_DIGEST_SIZE //Src size
            );
            count++;
        }
        if (count == no_of_pcrs)
            break;
    }
    result = hash_buffer((unsigned char *)buff, buff_size, dest, LCP_POLHALG_SHA1);
    if (verbose) {
        DISPLAY("Composite hash value: ");
        print_hex("", (const void *) dest, SHA1_DIGEST_SIZE);
    }
    free(buff);
    return result;
}

static lcp_policy_element_t *create(void)
{
    lcp_policy_element_t *elt = NULL;
    lcp_pconf_element_t *pconf = NULL;
    tpm_pcr_info_short_t *pcr_info = NULL;
    tb_hash_t *digest = NULL;
    uint8_t no_of_pcrs = 0;
    bool result;
    uint8_t pcr_select;

    //First set all pcrs to non-valid
    size_t pconf_data_size = sizeof(lcp_pconf_element_t) +
                                       (sizeof(tpm_pcr_info_short_t) * num_files);
    size_t elt_size = sizeof(lcp_policy_element_t) + pconf_data_size;

    elt = calloc(1, elt_size);
    if (elt == NULL) {
        ERROR("Error: failed to allocate memory for the element.\n");
        return NULL;
    }

    elt->size = elt_size;

    pconf = (lcp_pconf_element_t *) elt->data;
    pcr_info = (tpm_pcr_info_short_t *) &pconf->pcr_infos[0];

    pconf->num_pcr_infos = num_files;

    for (uint8_t i = 0; i < pconf->num_pcr_infos; i++) {
        //First clear all pcr_data values
        pcr_select = 0x0;
        no_of_pcrs = 0x0;
        for (int i = 0; i < MAX_PCRS; i++) {
            memset_s((void *) &pcrs[i], sizeof(pcr_data), 0x0);
        }
        result = read_pcrinfo_file(pcr_info_files[i]);
        if (!result) {
            ERROR("Error: failed to read PCR info file.\n");
            free(elt);
            return NULL;
        }
        for (int i = 0; i < MAX_PCRS; i++) {
            if (pcrs[i].valid) {
                pcr_select |= (1 << i); //Calculate pcr select mask
                no_of_pcrs++;
            }
        }
        if (!pcr_select) {
            ERROR("Error: no pcrs were selected.\n");
            return NULL;
        }
        digest = malloc(SHA1_DIGEST_SIZE);
        if (digest == NULL) {
            ERROR("Error: failed to allocate memory for digest buffer.\n");
            return NULL;
        }
        pcr_info->locality_at_release = pcrs[0].locality;
        pcr_info->pcr_selection.size_of_select = htons(1);
        pcr_info->pcr_selection.pcr_select = pcr_select;
        result = generate_composite_hash(&pcr_info->pcr_selection, pcrs, digest, no_of_pcrs);
        if (!result) {
            ERROR("Error: failed to generate composite hash.\n");
            free(digest);
            free(elt);
            return false;
        }
        memcpy_s((void *)&pcr_info->digest_at_release, SHA1_DIGEST_SIZE,
                                (const void *)&digest->sha1, SHA1_DIGEST_SIZE);
        pcr_info++; //Move to next one
    }
    if (verbose) {
        DISPLAY("PCONF element:\n");
        print_hex("    ", (void *) elt, elt_size);
    }
    free(digest);

    return elt;
}

static void display(const char *prefix, const lcp_policy_element_t *elt)
{
    size_t new_prefix_len = 0;
    lcp_pconf_element_t *pconf = (lcp_pconf_element_t *) elt->data;
    tpm_pcr_info_short_t *pcr_info = (tpm_pcr_info_short_t *) pconf->pcr_infos;
    if (elt == NULL) {
        ERROR("Error: element is not defined.\n");
        return;
    }
    if (*prefix == '\0')
        new_prefix_len = 8;
    else
        new_prefix_len = strnlen_s(prefix, 20) + 8;
    char new_prefix[new_prefix_len];
    strcpy_s(new_prefix, sizeof(new_prefix), prefix);
    strcat_s(new_prefix, sizeof(new_prefix), "\t");
    DISPLAY("%sNumPcrInfos: 0x%x\n", prefix, pconf->num_pcr_infos);
    for (int i = 0; i < pconf->num_pcr_infos; i++) {
        DISPLAY("%sPCRInfos[%d]\n", prefix, i);
        DISPLAY("%s%sTPM_PCR_SELECTION.sizeOfSelect: 0x%x\n", prefix,
                                prefix, ntohs(pcr_info->pcr_selection.size_of_select));
        DISPLAY("%s%sTPM_PCR_SELECTION.pcrSelect: 0x%x\n", prefix, prefix,
                                            pcr_info->pcr_selection.pcr_select);
        DISPLAY("%s%s:PCR-0:PCR-1:PCR-2:PCR-3:PCR-4:PCR-5:PCR-6:PCR-7:\n",
                                                            prefix, new_prefix);
        DISPLAY("%s%s:", prefix, new_prefix);
        for (int j = 0; j < 8; j++) {
            DISPLAY("  %d  :", pcr_info->pcr_selection.pcr_select&(1<<j) ? 1:0);
        }
        DISPLAY("\n%s%sTPM_LOCALITY_SELECTION.locality_at_release: 0x%x\n",
                                    prefix, prefix, pcr_info->locality_at_release);
        DISPLAY("%s%sTPM_COMPOSITE_HASH.digest_at_release:\n", prefix, prefix);
        DISPLAY(prefix);
        print_hex(new_prefix, (void *) pcr_info->digest_at_release, SHA1_DIGEST_SIZE);
        pcr_info++;
    }
}

static struct option opts[] = {
    {0, 0, 0, 0}
};

static polelt_plugin_t plugin = {
    "pconf",
    opts,
    "      pconf\n"
    "        Generate LCP_ELEMENT_PCONF (legacy)\n"
    "        <FILE1> [FILES]\n"
    "                                    Up to 32 files with pcr info data.\n"
    "                                    First line should be: 'locality:<value>.'\n"
    "                                    Locality must be at least 1 and at most 0x1F.\n"
    "                                    Followed by up to 8 lines specifying PCR\n"
    "                                    numbers (0-7) and their contents e.g.:\n"
    "                                    1:518bd167271fbb64589c61e43d8c0165861431d8\n",
    LCP_POLELT_TYPE_PCONF,
    &cmdline_handler,
    &create,
    &display
};

REG_POLELT_PLUGIN(&plugin)

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
