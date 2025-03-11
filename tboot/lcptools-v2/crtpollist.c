/*
 * crtpollist.c: Intel(R) TXT policy list (LCP_POLICY_LIST) creation tool
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
#include <time.h>
#define _GNU_SOURCE
#include <getopt.h>
#include <errno.h>
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/engine.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/bn.h>
#include <openssl/ecdsa.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <safe_lib.h>
#define PRINT   printf
#include "../../include/config.h"
#include "../../include/hash.h"
#include "../../include/uuid.h"
#include "../../include/lcp3.h"
#include "../../include/lcp3_hlp.h"
#include "polelt_plugin.h"
#include "lcputils.h"
#include "pollist2.h"
#include "pollist2_1.h"
#include "polelt.h"
#include "pollist1.h"

#define TOOL_VER_MAJOR 0x1
#define TOOL_VER_MINOR 0x1

static const char help[] =
    "Usage: lcp2_crtpollist <COMMAND> [OPTIONS]\n"
    "Create an Intel(R) TXT policy list.\n\n"
    "Supports:\n"
    "    LCP_POLICY_LIST - legacy list format - major version 0x1.\n"
    "    LCP_POLICY_LIST_2 - current list format for RSA-SSA - major version 0x2\n"
    "    LCP_POLICY_LIST_2_1 - current list format for RSA-PSS and ECDSA - major version 0x1\n"
    "\n--create\n"
    "Creates LCP list version <version> containing elements from [ELT FILES]\n"
    "and writes it to <FILE>.\n\n"
    "To generate LCP_POLICY_LIST_2_1:\n"
    "        --out <FILE>             policy list file\n"
    "        --listver <version>      policy list version must be 0x300\n"
    "        [ELT FILES]...           policy element file(s)\n"
    "To generate LCP_POLICY_LIST_2:\n"
    "        --out <FILE>             policy list file\n"
    "        [--sigalg]               <rsa|ecdsa|sm2> signature algorithm\n"
    "        --listver <version>      policy list version must be 0x200||0x201\n"
    "        [ELT FILES]...           policy element file(s)\n"
    "To generate LCP_POLICY_LIST:\n"
    "        --out <FILE>             policy list file\n"
    "        --listver <version>      policy list version must be 0x100\n\n"
    "        [ELT FILES]...           policy element file(s)\n"
    "\n--sign\n"
    "Signs policy list file\n"
    "        --sigalg                 <rsa|rsapss|ecdsa|sm2> signature algorithm\n"
    "        [--hashalg]              LCP_POLICY_LIST2_1 option:\n"
    "                                 <sha1|sha256|sha384|sha512|sm2> hash algorithm\n"
    "        --pub <key file>         PEM file of public key\n"
    "        [--priv <key file>]      PEM file of private key\n"
    "        [--rev <rev ctr>]        revocation counter value\n"
    "        [--nosig]                don't add SigBlock\n"
    "        --out <FILE>             policy list file to sign\n"
    "\n--addsig\n"
    "Adds signature file to LCP_POLICY_LIST_2 - this option cannot be used\n"
    "with LCP_POLICY_LIST_2_1.\n"
    "        --sig <FILE>             file containing signature (big-endian)\n"
    "        --out <FILE>             policy list file\n"
    "\n--show\n"
    "Displays policy list contents.\n"
    "        <FILE>                   policy list file\n"
    "\n--verify\n"
    "Verifies signed LCP_POLICY_LIST_2_1 signature.\n"
    "        <FILE>                   policy list file with signature\n"
    "\n--help\n"
    "\n--verbose                      enable verbose output; can be\n"
    "                                 specified with any command\n\n"
    "\n--version                      show tool version.\n"
    "The public and private keys can be created as follows:\n"
    "  openssl genrsa -out privkey.pem 2048\n"
    "  openssl rsa -pubout -in privkey.pem -out pubkey.pem\n";

bool verbose = false;

static struct option long_opts[] =
{
    /* commands */
    {"help",           no_argument,          NULL,     'H'},

    {"create",         no_argument,          NULL,     'C'},
    {"sign",           no_argument,          NULL,     'S'},
    {"addsig",         no_argument,          NULL,     'A'},
    {"show",           no_argument,          NULL,     'W'},
    {"verify",         no_argument,          NULL,     'V'},
    {"version",        no_argument,          NULL,     'v'},
    /* options */
    {"out",            required_argument,    NULL,     'o'},
    {"sigalg",         required_argument,    NULL,     'a'},
    {"hashalg",        required_argument,    NULL,     'h'},
    {"pub",            required_argument,    NULL,     'u'},
    {"priv",           required_argument,    NULL,     'i'},
    {"rev",            required_argument,    NULL,     'r'},
    {"nosig",          no_argument,          NULL,     'n'},
    {"sig",            required_argument,    NULL,     's'},
    {"listver",        required_argument,    NULL,     'l'},
    {"verbose",        no_argument,          NULL,     't'},

    {0, 0, 0, 0}
};

#define MAX_FILES   32

static uint16_t       version = 0x0;
static char           pollist_file[MAX_PATH] = "";
static char           sigalg_name[32] = "";
static uint16_t       sigalg_type = TPM_ALG_NULL; // Default
static char           pubkey_file[MAX_PATH] = "";
static char           privkey_file[MAX_PATH] = "";
static char           sig_file[MAX_PATH] = "";
static uint16_t       rev_ctr = 0;
static bool           no_sigblock = false;
static unsigned int   nr_files = 0;
static char           files[MAX_FILES][MAX_PATH];
static char           hash_alg_name[32] = "";
static uint16_t       hash_alg_cli = TPM_ALG_SHA256; //Default

static int create_list_2_1(void)
{
    LOG("create:version=0x0300\n");
    lcp_policy_list_t2_1 *pollist = NULL;
    size_t len;
    lcp_policy_element_t *elt = NULL;
    bool write_ok = false;

    pollist = create_empty_tpm20_policy_list_2_1();
    if ( pollist == NULL )
        return 1;
    if (version && MAJOR_VER(version) == 3)
        pollist->Version = version;
    if (nr_files > MAX_FILES) {
        ERROR("Too many element files specified.\n");
        return 1;
    }
    for ( unsigned int i = 0; i < nr_files; i++ ) {
        elt = read_file(files[i], &len, false);
        if ( elt == NULL ) {
            free(pollist);
            return 1;
        }
        if ( !verify_policy_element(elt, len) ) {
            free(pollist);
            free(elt);
            return 1;
        }
        pollist = add_tpm20_policy_element_2_1(pollist, elt);
        if ( pollist == NULL ) {
            free(elt);
            return 1;
        }
        free(elt);
        elt = NULL;
    }
    write_ok = write_tpm20_policy_list_2_1_file(pollist_file, pollist);

    free(pollist);
    return write_ok ? 0 : 1;
}

static int create(void)
{
    lcp_list_t *pollist;
    bool write_ok = false;

    LOG("[create]\n");
    uint16_t major_ver = MAJOR_VER(version);
    uint16_t minor_ver = MINOR_VER(version);
    if ( major_ver != MAJOR_VER(LCP_TPM12_POLICY_LIST_VERSION) &&
         major_ver != MAJOR_VER(LCP_TPM20_POLICY_LIST_VERSION) &&
         major_ver != MAJOR_VER(LCP_TPM20_POLICY_LIST2_1_VERSION_300) ) {
        ERROR("Error: only list versions 0x100, 0x200, 0x201 or 0x300 are supported\n");
        return 1;
    }

    switch (major_ver)
    {
    case MAJOR_VER(LCP_TPM12_POLICY_LIST_VERSION):
        if (minor_ver > LCP_TPM12_POLICY_LIST_MAX_MINOR) {
            ERROR("Error: minor version 0x%02x not supported\n", minor_ver);
            return 1;
        }
        pollist = (lcp_list_t *) create_empty_tpm12_policy_list();
        if (pollist == NULL)
            return 1;
        break;

    case MAJOR_VER(LCP_TPM20_POLICY_LIST_VERSION):
        if (minor_ver > LCP_TPM20_POLICY_LIST2_MAX_MINOR) {
            ERROR("Error: minor version 0x%02x not supported\n", minor_ver);
            return 1;
        }
        pollist = (lcp_list_t *) create_empty_tpm20_policy_list();
        if ( pollist == NULL )
            return 1;
        pollist->tpm20_policy_list.version = version;
        break;

    case MAJOR_VER(LCP_TPM20_POLICY_LIST2_1_VERSION_300):
        if (minor_ver > LCP_TPM20_POLICY_LIST2_1_MAX_MINOR) {
            ERROR("Error: minor version 0x%02x not supported\n", minor_ver);
            return 1;
        }
        return create_list_2_1();

    default:
        return 1;
    }

    for ( unsigned int i = 0; i < nr_files; i++ ) {
        size_t len;
        lcp_policy_element_t *elt = read_file(files[i], &len, false);
        if ( elt == NULL ) {
            free(pollist);
            return 1;
        }
        if ( !verify_policy_element(elt, len) ) {
            free(pollist);
            return 1;
        }
        if (major_ver == MAJOR_VER(LCP_TPM20_POLICY_LIST_VERSION))
            pollist = (lcp_list_t*) add_tpm20_policy_element(&(pollist->tpm20_policy_list), elt);
        else if (major_ver == MAJOR_VER(LCP_TPM12_POLICY_LIST_VERSION))
            pollist = (lcp_list_t*) add_tpm12_policy_element(&(pollist->tpm12_policy_list), elt);
        if ( pollist == NULL )
            return 1;
    }
    if (major_ver == MAJOR_VER(LCP_TPM20_POLICY_LIST_VERSION))
        write_ok = write_tpm20_policy_list_file(pollist_file,
                                                &(pollist->tpm20_policy_list));
    else if (major_ver == MAJOR_VER(LCP_TPM12_POLICY_LIST_VERSION))
        write_ok = write_tpm12_policy_list_file(pollist_file,
                                                &(pollist->tpm12_policy_list));


    free(pollist);
    return write_ok ? 0 : 1;
}

static int sign(void)
{
    LOG("[sign]\n");
    bool result;
    void *file_data = read_file(pollist_file, NULL, false);
    sign_user_input user_input;
    if ( file_data == NULL ) {
        return 1;
    }
    //List version is first two bytes of the list file
    memcpy_s((void*)&version, sizeof(uint16_t), (const void *)file_data, sizeof(uint16_t));
    free(file_data); //We just need version
    file_data = NULL;
    //sign_user_input is used to pass some data from users to functions in
    //pollis2.c and pollist2_1.c
    user_input.sig_alg = sigalg_type;
    user_input.hash_alg = hash_alg_cli;
    user_input.rev_ctr = rev_ctr;
    if (strcpy_s(user_input.list_file, MAX_PATH, pollist_file) != EOK) {
        ERROR("Error: cannot open file.\n");
        return 1;
    }
    if (strcpy_s(user_input.pubkey_file, MAX_PATH, pubkey_file) != EOK) {
        ERROR("Error: cannot open file.\n");
        return 1;
    }
    if (strcpy_s(user_input.privkey_file, MAX_PATH, privkey_file) != EOK) {
        ERROR("Error: cannot open file.\n");
        return 1;
    }
    if ( MAJOR_VER(version) == MAJOR_VER(LCP_TPM12_POLICY_LIST_VERSION) ) {
        LOG("sign: LCP_POLICY_LIST,sig_alg=LCP_POLSALG_RSA_PKCS_15\n");
        result = sign_lcp_policy_list_t(user_input);
        if (result) {
            DISPLAY("List signed successfully and written to %s\n", user_input.list_file);
            return 0;
        }
        else {
            DISPLAY("Failed to sign and write LCP list.\n");
            return 1;
        }
    }
    else if ( MAJOR_VER(version) == MAJOR_VER(LCP_TPM20_POLICY_LIST_VERSION) ) {
        LOG("sign: LCP_POLICY_LIST2,sig_alg=0x%x\n", user_input.sig_alg);
        result = sign_lcp_policy_list_t2(user_input);
        if (result) {
            DISPLAY("List signed successfully and written to %s\n", user_input.list_file);
            return 0;
        }
        else {
            DISPLAY("Failed to sign and write LCP list.\n");
            return 1;
        }
    }
    else if ( MAJOR_VER(version) == MAJOR_VER(LCP_TPM20_POLICY_LIST2_1_VERSION_300)) {
        LOG("sign: LCP_POLICY_LIST2_1,sig_alg=0x%x\n", user_input.sig_alg);
        result = sign_lcp_policy_list_t2_1(user_input);
        if (result) {
            DISPLAY("List signed successfully and written to %s\n", user_input.list_file);
            return 0;
        }
        else {
            DISPLAY("Failed to sign and write LCP list.\n");
            return 1;
        }
    }
    return 1;
}

static int addsig(void)
{
    /* read existing policy list file */
    bool no_sigblock_ok = true;
    lcp_list_t *pollist = read_policy_list_file(pollist_file, false, &no_sigblock_ok);
    if ( pollist == NULL )
        return 1;

    uint16_t  version ;
    memcpy_s((void*)&version, sizeof(uint16_t), (const void *)pollist, sizeof(uint16_t));
    if ( MAJOR_VER(version) == MAJOR_VER(LCP_TPM20_POLICY_LIST2_1_VERSION_300) ) {
        DISPLAY("Not supported.\n");
        return 0;
    }

    lcp_signature_t2 *sig = get_tpm20_signature(&(pollist->tpm20_policy_list));
    if ( sig == NULL ) {
        free(pollist);
        return 1;
    }
    /* check public key size */
    if ( (sig->rsa_signature.pubkey_size != 128 /* 1024 bits */)
            && (sig->rsa_signature.pubkey_size != 256 /* 2048 bits */)
            && (sig->rsa_signature.pubkey_size != 384 /* 3072 bits */) ) {
        ERROR("Error: public key size is not 1024/2048/3072 bits\n");
        free(pollist);
        return 1;
    }

    /* read signature file */
    size_t len;
    uint8_t *data = read_file(sig_file, &len, false);
    if ( data == NULL ) {
        free(pollist);
        return 1;
    }

    if ( len != sig->rsa_signature.pubkey_size ) {
        ERROR("Error: signature file size doesn't match public key size\n");
        free(pollist);
        free(data);
        return 1;
    }

    /* verify that this sigblock actually matches the policy list */
    LOG("verifying signature block...\n");
    if (!verify_tpm20_pollist_sig(&pollist->tpm20_policy_list)) {
        ERROR("Error: signature file does not match policy list\n");
        free(pollist);
        free(data);
        return 1;
    }
    LOG("signature file verified\n");

    uint8_t *plsigblock = get_tpm20_sig_block(&(pollist->tpm20_policy_list));
    if ( plsigblock == NULL ) {
        ERROR("Error: list sig block not found\n");
        free(pollist);
        free(data);
        return 1;
    }

    /* data is big-endian and policy needs little-endian, so reverse */
    for ( unsigned int i = 0; i < sig->rsa_signature.pubkey_size; i++ )
        *(plsigblock + i) =
                *(data + (sig->rsa_signature.pubkey_size - i - 1));

    if ( verbose ) {
        LOG("signature:\n");
        display_tpm20_signature("    ", sig,
                pollist->tpm20_policy_list.sig_alg, false);
    }

    bool write_ok = write_tpm20_policy_list_file(pollist_file,
                            &(pollist->tpm20_policy_list));

    free(pollist);
    free(data);
    return write_ok ? 0 : 1;
}

static int show(void)
{
    /* read existing file */
    bool no_sigblock_ok = true;
    size_t file_len;
    lcp_list_t *pollist = read_file(files[0], &file_len, true);
    if ( pollist == NULL )
        return 1;

    uint16_t  version;
    memcpy_s((void*)&version, sizeof(uint16_t), (const void *)pollist, sizeof(uint16_t));
    free(pollist);
    if (MAJOR_VER(version) == MAJOR_VER(LCP_TPM12_POLICY_LIST_VERSION) ) {
        pollist = read_policy_list_file(files[0], false, &no_sigblock_ok);
        if (pollist == NULL) {
            ERROR("Error: failed to read policy list file.\n");
            return 1;
        }
        LOG("show: version == 0x0100\n");
        DISPLAY("policy list file: %s\n", files[0]);
        display_tpm12_policy_list("", &(pollist->tpm12_policy_list), false);
        free(pollist);
        return 0;
    }
    if (MAJOR_VER(version) == MAJOR_VER(LCP_TPM20_POLICY_LIST_VERSION) ) {
        pollist = read_policy_list_file(files[0], false, &no_sigblock_ok);
        if (pollist == NULL) {
            ERROR("Error: failed to read policy list file.\n");
            return 1;
        }
        LOG("show: version == 0x0200\n");
        DISPLAY("policy list file: %s\n", files[0]);
        display_tpm20_policy_list("", &(pollist->tpm20_policy_list), false);

        if ( pollist->tpm20_policy_list.sig_alg == TPM_ALG_RSASSA &&
            !no_sigblock_ok ) {
            if ( verify_tpm20_pollist_sig(&(pollist->tpm20_policy_list)) )
                DISPLAY("signature verified\n");
            else
                DISPLAY("failed to verify signature\n");
        }

        free(pollist);
        return 0;
        }
    if (MAJOR_VER(version) == MAJOR_VER(LCP_TPM20_POLICY_LIST2_1_VERSION_300) ) {
        lcp_policy_list_t2_1 *pollist = read_policy_list_2_1_file(false, files[0]);
        if (pollist == NULL) {
            ERROR("Error: failed to read policy list file.\n");
            return 1;
        }
        LOG("show: version == 0x0300\n");
        DISPLAY("policy list file: %s\n", files[0]);
        display_tpm20_policy_list_2_1("", pollist, false);
        return 0;
    }
    return 0;
}

static int verify(void)
{
    LOG("Verify policy list 2.1\n");
    lcp_policy_list_t2_1 *pollist2_1 = NULL;
    void *file_data = NULL;
    size_t file_len;
    uint16_t  version;

    file_data = read_file(files[0], &file_len, true);
    if (file_data == NULL) {
        ERROR("Error: failed to read pollist file.\n");
        return 1;
    }

    memcpy_s((void*)&version, sizeof(uint16_t), file_data, sizeof(uint16_t));
    free(file_data);
    file_data = NULL;
    if ( MAJOR_VER(version) == 1 ) {
        LOG("Unsupported.\n");
        return 0;
    }
    else if ( MAJOR_VER(version) == 2 ){
        LOG("Unsupported.\n");
        return 0;
    }
    else if ( MAJOR_VER(version) == 3 ) {
        bool result;
        pollist2_1 = read_policy_list_2_1_file(false, files[0]);
        if ( pollist2_1 == NULL ) {
            ERROR("Error: failed to get policy list from file.\n");
            return 1;
        }
        if ( pollist2_1->KeySignatureOffset == 0 ) {
            DISPLAY("Verification successful. List is not signed. Exiting.\n");
            free(pollist2_1);
            return 0;
        }
        result = verify_tpm20_pollist_2_1_sig(pollist2_1);
        if (!result) {
            free(pollist2_1);
            DISPLAY("List signature did not verify positively.\n");
            return 0;
        }
        else {
            free(pollist2_1);
            DISPLAY("List signature correct. Verification successful\n");
            return 0;
        }
    }
    ERROR("Error: version unrecognized.\n");
    return 1;
}

int main(int argc, char *argv[])
{
    int cmd = 0;
    bool prev_cmd = false;
    int c;

    do {
        c = getopt_long_only(argc, argv, "", long_opts, NULL);
        LOG("c=%c\n",c);
        switch (c) {
        /* commands */
        case 'H':          /* help */
        case 'C':          /* create */
        case 'S':          /* sign */
        case 'A':          /* addsig */
        case 'W':          /* show */
        case 'V':          /* verify */
        case 'v':          /* version */
            if ( prev_cmd ) {
                ERROR("Error: only one command can be specified\n");
                return 1;
            }
            prev_cmd = true;
            cmd = c;
            LOG("cmdline opt: command: %c\n", cmd);
            break;

        case 'o':            /* out */
            strlcpy(pollist_file, optarg, sizeof(pollist_file));
            LOG("cmdline opt: out: %s\n", pollist_file);
            break;

        case 'h':
            strlcpy(hash_alg_name, optarg, sizeof(hash_alg_name));
            LOG("cmdline opt hash_alg: %s\n", hash_alg_name);
            hash_alg_cli = str_to_hash_alg(hash_alg_name);
            if (hash_alg_cli == TPM_ALG_NULL) {
                ERROR("ERROR: incorrect hash alg specified");
                return 1;
            }
            break;

        case 'a':
            strlcpy(sigalg_name, optarg, sizeof(sigalg_name));
            LOG("cmdline opt: sigalg: %s\n", sigalg_name);
            sigalg_type = str_to_sig_alg(sigalg_name);
            break;

        case 'u':            /* pub */
            strlcpy(pubkey_file, optarg, sizeof(pubkey_file));
            LOG("cmdline opt: pub: %s\n", pubkey_file);
            break;

        case 'i':            /* priv */
            strlcpy(privkey_file, optarg, sizeof(privkey_file));
            LOG("cmdline opt: pub: %s\n", privkey_file);
            break;

        case 'r':            /* rev */
            rev_ctr = strtoul(optarg, NULL, 0);
            LOG("cmdline opt: rev: 0x%x (%u)\n", rev_ctr, rev_ctr);
            break;

        case 'n':            /* nosig */
            no_sigblock = true;
            LOG("cmdline opt: nosig: %u\n", no_sigblock);
            break;

        case 's':            /* sigblock */
            strlcpy(sig_file, optarg, sizeof(sig_file));
            LOG("cmdline opt: sigblock: %s\n", sig_file);
            break;

        case 'l': /* listver */
            version = strtoul(optarg, NULL, 16);
            if (version) {
                break;
            }
            else {
                ERROR("Error: only list versions 0x100, 0x200, 0x201 or 0x300 " \
                                                             "are supported\n");
                return 1;
            }
        case 't':
            verbose = true;
            break;
        case 0:
        case -1:
            break;

        default:
            ERROR("Error: unrecognized option\n");
            return 1;
        }
    } while ( c != -1 );

    /* process any remaining argv[] items */
    while ( optind < argc && nr_files < ARRAY_SIZE(files) ) {
        LOG("cmdline opt: file: %s\n", argv[optind]);
        strlcpy(files[nr_files++], argv[optind], sizeof(files[0]));
        optind++;
    }

    if ( cmd == 0 ) {
        ERROR("Error: no command option was specified\n");
        return 1;
    }
    else if ( cmd == 'H' ) {        /* --help */
        DISPLAY("%s", help);
        return 0;
    }
    else if ( cmd == 'C' ) {        /* --create */
        if ( *pollist_file == '\0' ) {
            ERROR("Error: no policy list output file specified\n");
            return 1;
        }

        if ( !version ) {
            ERROR("ERROR: LCP list version not specified.\n");
            return 1;
        }
        return create();
    }
    else if ( cmd == 'S' ) {        /* --sign */

        if ( *pollist_file == '\0' ) {
            ERROR("Error: no policy list output file specified\n");
            return 1;
        }
        if (sigalg_type == TPM_ALG_NULL) {
            ERROR("Error: signature algorithm must be specified.\n");
            return 1;
        }
        else {
            if ( *pubkey_file == '\0' ) {
                ERROR("Error: no public key file specified\n");
                return 1;
            }
            if ( no_sigblock ) {     /* no signature wanted */
                if ( *privkey_file != '\0' ) {
                    ERROR("Error: private key file specified with --nosig option\n");
                    return 1;
                }
            }
            else {                   /* we generate sig, so need private key */
                if ( *privkey_file == '\0' ) {
                    ERROR("Error: no private key file specified\n");
                    return 1;
                }
            }
            if (sigalg_type != TPM_ALG_RSASSA &&
                sigalg_type != TPM_ALG_ECDSA &&
                sigalg_type != TPM_ALG_RSAPSS &&
                sigalg_type != TPM_ALG_SM3_256 &&
                sigalg_type != LCP_POLSALG_RSA_PKCS_15 &&
                sigalg_type != TPM_ALG_SM2) {
                ERROR("Error: Signature algorithm 0x%x unsupported.\n", sigalg_type);
                return 1;
            }
        }
        return sign();
    }
    else if ( cmd == 'A' ) {        /* --addsig */
        if ( *pollist_file == '\0' ) {
            ERROR("Error: no policy list output file specified\n");
            return 1;
        }
        if ( *sig_file == '\0' ) {
            ERROR("Error: no signature file specified\n");
            return 1;
        }
        return addsig();
    }
    else if ( cmd == 'W' ) {        /* --show */
        if ( nr_files != 1 ) {
            ERROR("Error: no policy list file specified\n");
            return 1;
        }
        return show();
    }
    else if ( cmd == 'V') {  /*--verify*/
        if ( *files[0] == '\0' ) {
            ERROR("ERROR: no policy list file specified.");
            return 1;
        }
        return verify();
    }
    else if ( cmd == 'v' ) { /* --version */
        DISPLAY("lcp2_crtpollist version: %i.%i", TOOL_VER_MAJOR,
                                                  TOOL_VER_MINOR);
        return 0;
    }

    ERROR("Error: unknown command\n");
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
