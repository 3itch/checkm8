/*
 * Copyright 2001 - 2007 Intel Corporation. All Rights Reserved. 
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * Redistributions of source code must retain the above copyright notice, this
 * list of conditions and the following disclaimer.
 * 
 * Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 * 
 * Neither the name Intel Corporation nor the names of its contributors may be
 * used to endorse or promote products derived from this software without
 * specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef __LCPUTILS_H__
#define __LCPUTILS_H__

/*
 * Log message functions
 */
#define log_message(dest, fmt, ...)  fprintf(dest, fmt, ## __VA_ARGS__)

/*
 * Error logging
 */
#define log_error(fmt, ...)      log_message(stderr, fmt, ##__VA_ARGS__)

/*
 * Info Logging
 */
#define log_info(fmt, ...)       log_message(stdout, fmt, ##__VA_ARGS__)

#define LCP_DEBUG 1

#ifdef LCP_DEBUG
#define log_debug(fmt, ...)      log_message(stdout, fmt, ##__VA_ARGS__)
#else
#define log_debug(fmt, ...)
#endif

#define CHECK_TSS_RETURN_VALUE(api_name, result, ret) \
                 do { if ((result) != TSS_SUCCESS) { \
                         log_error("%s failed: %s (0x08%x)\n", (api_name), \
				   Trspi_Error_String((result)),	\
				   (result));				\
                         (ret) = LCP_E_TSS_ERROR; \
                         goto exit; \
                      } \
                 }while (0)

typedef struct {
    const char *param;
    uint32_t option;
} param_option_t;

uint32_t parse_input_option(param_option_t *table, const char *arg);
int strtonum(const char *in_para, unsigned int *num_out);
const char *bool_to_str(int b);
void print_help(const char *usage_str, const char *option_string[]);
void print_error(lcp_result_t ret_value);
lcp_result_t convert_error(TSS_RESULT result);

void print_hexmsg(const char *header_msg,
                  int datalength,
                  const unsigned char *data);

uint16_t lcp_decode_uint16(const unsigned char *in,
                           uint8_t big_endian);
void lcp_uint32toarray(uint32_t i,
                       unsigned char *out,
                       uint8_t big_endian);
void lcp_uint16toarray(uint16_t i,
                       unsigned char *out,
                       uint8_t big_endian);
uint32_t lcp_decode_uint32(const unsigned char *y,
                           uint8_t big_endian);
void lcp_loaddata_uint32(uint32_t in,
                         unsigned char **blob,
                         uint8_t big_endian);
void lcp_loaddata_uint16(uint16_t in,
                         unsigned char **blob,
                         uint8_t big_endian);
void lcp_unloaddata_uint32(uint32_t * out,
                           unsigned char **blob,
                           uint8_t big_endian);
void lcp_unloaddata_uint16(uint16_t *out,
                           unsigned char **blob,
                           uint8_t big_endian);
void lcp_loaddata_byte(unsigned char data,
                       unsigned char **blob);
void lcp_unloaddata_byte(unsigned char *dataout,
                         unsigned char **blob);
void lcp_loaddata(uint32_t size,
                  unsigned char **container,
                  unsigned char *object);
void lcp_unloaddata(uint32_t size,
                    unsigned char **container,
                    unsigned char *object);

TSS_RESULT init_tss_context(TSS_HCONTEXT *hcontext);
void close_tss_context(TSS_HCONTEXT hcontext);
TSS_RESULT set_tpm_secret(TSS_HCONTEXT hcontext,
               TSS_HTPM *htpm,
               TSS_HPOLICY *hpolicy,
               const char *passwd,
               uint32_t passwd_length);
TSS_RESULT set_nv_secret(TSS_HCONTEXT hcontext,
              TSS_HNVSTORE hnvstore,
              TSS_HPOLICY *hpolobj,
              const char *auth,
              uint32_t auth_len);

lcp_result_t
calc_sizeofselect(uint32_t num_indices,
                  uint32_t *indices,
                  TPM_PCR_SELECTION *pselect);

void print_locality(unsigned char loc);
void print_permissions(UINT32 perms, const char *prefix);

void str_split(char *str_in, uint32_t ints[], unsigned int *number);

#endif
