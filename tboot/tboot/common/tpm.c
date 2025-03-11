/*
 * tpm.c: TPM-related support functions
 *
 * Copyright (c) 2006-2010, Intel Corporation
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
#include <types.h>
#include <stdbool.h>
#include <printk.h>
#include <misc.h>
#include <compiler.h>
#include <processor.h>
#include <io.h>
#include <string.h>
#include <tpm.h>
#include <sha1.h>

__data uint8_t g_tpm_ver = TPM_VER_UNKNOWN;
__data struct tpm_if g_tpm = {
    .cur_loc = 0,
    .timeout.timeout_a = TIMEOUT_A,
    .timeout.timeout_b = TIMEOUT_B,
    .timeout.timeout_c = TIMEOUT_C,
    .timeout.timeout_d = TIMEOUT_D,
};

u16 tboot_alg_list[] = {TB_HALG_SHA1, TB_HALG_SHA256, TB_HALG_SHA384, TB_HALG_SHA512};
const uint8_t tboot_alg_list_count = ARRAY_SIZE(tboot_alg_list);

/* Global variables for TPM status register */
static tpm20_reg_sts_t       g_reg_sts, *g_reg_sts_20 = &g_reg_sts;
static tpm12_reg_sts_t       *g_reg_sts_12 = (tpm12_reg_sts_t *)&g_reg_sts;

uint8_t g_tpm_family = 0;

/* TPM_DATA_FIFO_x */
#define TPM_REG_DATA_FIFO        0x24
typedef union {
        uint8_t _raw[1];                      /* 1-byte reg */
} tpm_reg_data_fifo_t;

typedef union {
        uint8_t _raw[1];
} tpm_reg_data_crb_t;

#define TPM_ACTIVE_LOCALITY_TIME_OUT    \
          (TIMEOUT_UNIT *get_tpm()->timeout.timeout_a)  /* according to spec */
#define TPM_CMD_READY_TIME_OUT          \
          (TIMEOUT_UNIT *get_tpm()->timeout.timeout_b)  /* according to spec */
#define TPM_CMD_WRITE_TIME_OUT          \
          (TIMEOUT_UNIT *get_tpm()->timeout.timeout_d)  /* let it long enough */
#define TPM_DATA_AVAIL_TIME_OUT         \
          (TIMEOUT_UNIT *get_tpm()->timeout.timeout_c)  /* let it long enough */
#define TPM_RSP_READ_TIME_OUT           \
          (TIMEOUT_UNIT *get_tpm()->timeout.timeout_d)  /* let it long enough */
#define TPM_VALIDATE_LOCALITY_TIME_OUT  0x100

#define read_tpm_sts_reg(locality) { \
if ( g_tpm_family == 0 ) \
    read_tpm_reg(locality, TPM_REG_STS, g_reg_sts_12); \
else \
    read_tpm_reg(locality, TPM_REG_STS, g_reg_sts_20); \
}

#define write_tpm_sts_reg(locality) { \
if ( g_tpm_family == 0 ) \
    write_tpm_reg(locality, TPM_REG_STS, g_reg_sts_12); \
else \
    write_tpm_reg(locality, TPM_REG_STS, g_reg_sts_20); \
}

static void tpm_send_cmd_ready_status(uint32_t locality)
{
    /* write 1 to TPM_STS_x.commandReady to let TPM enter ready state */
    tb_memset((void *)&g_reg_sts, 0, sizeof(g_reg_sts));
    g_reg_sts.command_ready = 1;
    write_tpm_sts_reg(locality);
}


static bool tpm_send_cmd_ready_status_crb(uint32_t locality)
{
      tpm_reg_ctrl_request_t reg_ctrl_request;
      tpm_reg_ctrl_sts_t reg_ctrl_sts;

      read_tpm_reg(locality, TPM_CRB_CTRL_STS, &reg_ctrl_sts);

#ifdef TPM_TRACE
      printk(TBOOT_INFO"1. reg_ctrl_sts.tpmidle: 0x%x\n", reg_ctrl_sts.tpmidle); 	
      printk(TBOOT_INFO"1. reg_ctrl_sts.tpmsts: 0x%x\n", reg_ctrl_sts.tpmsts); 	
#endif

	if ( reg_ctrl_sts.tpmidle == 1) {
           tb_memset(&reg_ctrl_request,0,sizeof(reg_ctrl_request));
           reg_ctrl_request.cmdReady = 1;
	    write_tpm_reg(locality, TPM_CRB_CTRL_REQ, &reg_ctrl_request);

	    return true;
	}

      tb_memset(&reg_ctrl_request,0,sizeof(reg_ctrl_request));
      reg_ctrl_request.goIdle = 1;
      write_tpm_reg(locality, TPM_CRB_CTRL_REQ, &reg_ctrl_request);
	  
      uint32_t i = 0;
      do {
          read_tpm_reg(locality, TPM_CRB_CTRL_REQ, &reg_ctrl_request);
          if ( reg_ctrl_request.goIdle == 0) 
		break;
          else {
              cpu_relax(); 
	       read_tpm_reg(locality, TPM_CRB_CTRL_REQ, &reg_ctrl_request);

#ifdef TPM_TRACE
		printk(TBOOT_INFO"1. reg_ctrl_request.goIdle: 0x%x\n", reg_ctrl_request.goIdle);
		printk(TBOOT_INFO"1. reg_ctrl_request.cmdReady: 0x%x\n", reg_ctrl_request.cmdReady);
#endif

          }
          i++;
       } while ( i <= TPM_DATA_AVAIL_TIME_OUT);

       if ( i > TPM_DATA_AVAIL_TIME_OUT ) {
            printk(TBOOT_ERR"TPM: reg_ctrl_request.goidle timeout!\n");
            return false;
       }

	read_tpm_reg(locality, TPM_CRB_CTRL_STS, &reg_ctrl_sts);

#ifdef TPM_TRACE
	printk(TBOOT_INFO"2. reg_ctrl_sts.tpmidle: 0x%x\n", reg_ctrl_sts.tpmidle); 	
       printk(TBOOT_INFO"2. reg_ctrl_sts.tpmsts: 0x%x\n", reg_ctrl_sts.tpmsts); 	
#endif

       tb_memset(&reg_ctrl_request,0,sizeof(reg_ctrl_request));
       reg_ctrl_request.cmdReady = 1;
	write_tpm_reg(locality, TPM_CRB_CTRL_REQ, &reg_ctrl_request);

#ifdef TPM_TRACE	
	printk(TBOOT_INFO"2. reg_ctrl_request.goIdle: 0x%x\n", reg_ctrl_request.goIdle);
	printk(TBOOT_INFO"2. reg_ctrl_request.cmdReady: 0x%x\n", reg_ctrl_request.cmdReady);
#endif
 
	read_tpm_reg(locality, TPM_CRB_CTRL_STS, &reg_ctrl_sts);

#ifdef TPM_TRACE
	printk(TBOOT_INFO"2. reg_ctrl_sts.tpmidle: 0x%x\n", reg_ctrl_sts.tpmidle); 	
       printk(TBOOT_INFO"2. reg_ctrl_sts.tpmsts: 0x%x\n", reg_ctrl_sts.tpmsts); 	
#endif

	return true;
	
}

static bool tpm_check_cmd_ready_status_crb(uint32_t locality)
{
    tpm_reg_ctrl_request_t reg_ctrl_request; 
    read_tpm_reg(locality, TPM_CRB_CTRL_REQ, &reg_ctrl_request);

#ifdef TPM_TRACE
    printk(TBOOT_INFO"3. reg_ctrl_request.goIdle: 0x%x\n", reg_ctrl_request.goIdle);
    printk(TBOOT_INFO"3. reg_ctrl_request.cmdReady: 0x%x\n", reg_ctrl_request.cmdReady);
#endif

    if ( reg_ctrl_request.cmdReady == 0) 
		return true;
    else
		return false;

}

static bool tpm_check_cmd_ready_status(uint32_t locality)
{
    read_tpm_sts_reg(locality);
#ifdef TPM_TRACE
    printk(TBOOT_INFO".");
#endif
    return g_reg_sts.command_ready;
}

static void tpm_print_status_register(void)
{
    if ( g_tpm_family == 0 )
    {
        printk(TBOOT_DETA"TPM: status reg content: %02x %02x %02x\n",
            (uint32_t)g_reg_sts_12->_raw[0],
            (uint32_t)g_reg_sts_12->_raw[1],
            (uint32_t)g_reg_sts_12->_raw[2]);
    }
    else
    {
        printk(TBOOT_DETA"TPM: status reg content: %02x %02x %02x %02x\n",
            (uint32_t)g_reg_sts_20->_raw[0],
            (uint32_t)g_reg_sts_20->_raw[1],
            (uint32_t)g_reg_sts_20->_raw[2],
            (uint32_t)g_reg_sts_20->_raw[3]);
    }
}

static u16 tpm_get_burst_count(uint32_t locality)
{
    read_tpm_sts_reg(locality);
    return g_reg_sts.burst_count;
}

static bool tpm_check_expect_status(uint32_t locality)
{
    read_tpm_sts_reg(locality);
#ifdef TPM_TRACE
    printk(TBOOT_INFO"Wait on Expect = 0, Status register %02x\n", g_reg_sts._raw[0]);
#endif
    return g_reg_sts.sts_valid == 1 && g_reg_sts.expect == 0;
}

static bool tpm_check_da_status(uint32_t locality)
{
    read_tpm_sts_reg(locality);
#ifdef TPM_TRACE
    printk(TBOOT_INFO"Waiting for DA Flag, Status register %02x\n", g_reg_sts._raw[0]);
#endif
    return g_reg_sts.sts_valid == 1 && g_reg_sts.data_avail == 1;
}

static void tpm_execute_cmd(uint32_t locality)
{
    tb_memset((void *)&g_reg_sts, 0, sizeof(g_reg_sts));
    g_reg_sts.tpm_go = 1;
    write_tpm_sts_reg(locality);
}

bool tpm_validate_locality(uint32_t locality)
{
    uint32_t i;
    tpm_reg_access_t reg_acc;
    
    for ( i = TPM_VALIDATE_LOCALITY_TIME_OUT; i > 0; i-- ) {
        /*
         * TCG spec defines reg_acc.tpm_reg_valid_sts bit to indicate whether
         * other bits of access reg are valid.( but this bit will also be 1
         * while this locality is not available, so check seize bit too)
         * It also defines that reading reg_acc.seize should always return 0
         */
        read_tpm_reg(locality, TPM_REG_ACCESS, &reg_acc);
        if ( reg_acc.tpm_reg_valid_sts == 1 && reg_acc.seize == 0)
            return true;
        cpu_relax();
    }
    if ( i <= 0 )
        printk(TBOOT_ERR"TPM: tpm_validate_locality timeout\n");

    return false;
}

bool tpm_validate_locality_crb(uint32_t locality)
{
    uint32_t i;
    tpm_reg_loc_state_t reg_loc_state;

    for ( i = TPM_VALIDATE_LOCALITY_TIME_OUT; i > 0; i-- ) {
        /*
         *  Platfrom Tpm  Profile for TPM 2.0 SPEC
         */
        read_tpm_reg(locality, TPM_REG_LOC_STATE, &reg_loc_state);
 	 if ( reg_loc_state.tpm_reg_valid_sts == 1 && reg_loc_state.loc_assigned == 1 && reg_loc_state.active_locality == locality) {
			 printk(TBOOT_INFO"TPM: reg_loc_state._raw[0]:  0x%x\n", reg_loc_state._raw[0]);
			 return true;
        	}
        cpu_relax(); 
    }

    printk(TBOOT_ERR"TPM: tpm_validate_locality_crb timeout\n");
    printk(TBOOT_INFO"TPM: reg_loc_state._raw[0]: 0x%x\n", reg_loc_state._raw[0]);
    return false;
}


bool tpm_wait_cmd_ready(uint32_t locality)
{
    uint32_t            i;
    tpm_reg_access_t    reg_acc;

#if 0 /* some tpms doesn't always return 1 for reg_acc.tpm_reg_valid_sts */
      /* and this bit was checked in tpm_validate_locality() already, */
      /* so safe to skip the check here */
    /* ensure the contents of the ACCESS register are valid */
    read_tpm_reg(locality, TPM_REG_ACCESS, &reg_acc);
#ifdef TPM_TRACE
    printk(TBOOT_INFO"TPM: Access reg content: 0x%02x\n", (uint32_t)reg_acc._raw[0]);
#endif
    if ( reg_acc.tpm_reg_valid_sts == 0 ) {
        printk(TBOOT_ERR"TPM: Access reg not valid\n");
        return false;
    }
#endif
    /* request access to the TPM from locality N */
    reg_acc._raw[0] = 0;
    reg_acc.request_use = 1;
    write_tpm_reg(locality, TPM_REG_ACCESS, &reg_acc);

    i = 0;
    do {
        read_tpm_reg(locality, TPM_REG_ACCESS, &reg_acc);
        if ( reg_acc.active_locality == 1 )
            break;
        else
            cpu_relax();
        i++;
    } while ( i <= TPM_ACTIVE_LOCALITY_TIME_OUT);

    if ( i > TPM_ACTIVE_LOCALITY_TIME_OUT ) {
        printk(TBOOT_ERR"TPM: FIFO_INF access reg request use timeout\n");
        return false;
    }

    /* ensure the TPM is ready to accept a command */
#ifdef TPM_TRACE
    printk(TBOOT_INFO"TPM: wait for cmd ready \n");
#endif
    i = 0;
    do {
        tpm_send_cmd_ready_status(locality);
        cpu_relax();
        /* then see if it has */

        if ( tpm_check_cmd_ready_status(locality) )
            break;
        else
            cpu_relax();
        i++;
    } while ( i <= TPM_CMD_READY_TIME_OUT );
#ifdef TPM_TRACE
    printk(TBOOT_INFO"\n");
#endif

    if ( i > TPM_CMD_READY_TIME_OUT ) {
        tpm_print_status_register();
        printk(TBOOT_INFO"TPM: tpm timeout for command_ready\n");
        goto RelinquishControl;
    }

    return true;

RelinquishControl:
    /* deactivate current locality */
    reg_acc._raw[0] = 0;
    reg_acc.active_locality = 1;
    write_tpm_reg(locality, TPM_REG_ACCESS, &reg_acc);

    return false;
}

static bool tpm_wait_cmd_ready_crb(uint32_t locality)
{
    uint32_t i;

    /* ensure the TPM is ready to accept a command */
#ifdef TPM_TRACE
    printk(TBOOT_INFO"TPM: wait for cmd ready \n");
#endif
    tpm_send_cmd_ready_status_crb(locality);
    i = 0;
    do {
        if ( tpm_check_cmd_ready_status_crb(locality) )
            break;
        else
            cpu_relax();
        i++;
    } while ( i <= TPM_CMD_READY_TIME_OUT );

    if ( i > TPM_CMD_READY_TIME_OUT ) {
        //tpm_print_status_register();
        printk(TBOOT_INFO"TPM: tpm timeout for command_ready\n");
        goto RelinquishControl;
    }

    return true;

RelinquishControl:
    /* deactivate current locality */
	  //tpm_reg_loc_ctrl_t    reg_loc_ctrl;
        //reg_loc_ctrl._raw[0] = 0;
    //reg_loc_ctrl.relinquish = 1;
    //write_tpm_reg(locality, TPM_REG_LOC_CTRL, &reg_loc_ctrl);

    return false;
}

bool tpm_submit_cmd(u32 locality, u8 *in, u32 in_size,  u8 *out, u32 *out_size)
{
    u32 i, rsp_size, offset;
    u16 row_size;
    tpm_reg_access_t    reg_acc;
    bool ret = true;

    if ( locality >= TPM_NR_LOCALITIES ) {
        printk(TBOOT_WARN"TPM: Invalid locality for tpm_write_cmd_fifo()\n");
        return false;
    }
    if ( in == NULL || out == NULL || out_size == NULL ) {
        printk(TBOOT_WARN"TPM: Invalid parameter for tpm_write_cmd_fifo()\n");
        return false;
    }
    if ( in_size < CMD_HEAD_SIZE || *out_size < RSP_HEAD_SIZE ) {
        printk(TBOOT_WARN"TPM: in/out buf size must be larger than 10 bytes\n");
        return false;
    }

    if ( !tpm_validate_locality(locality) ) {
        printk(TBOOT_WARN"TPM: Locality %d is not open\n", locality);
        return false;
    }

    if ( !tpm_wait_cmd_ready(locality) )   return false;

#ifdef TPM_TRACE
    {
        printk(TBOOT_DETA"TPM: cmd size = 0x%x\nTPM: cmd content: ", in_size);
        print_hex("TPM: \t", in, in_size);
    }
#endif

    /* write the command to the TPM FIFO */
    offset = 0;
    do {
        i = 0;
        do {
            /* find out how many bytes the TPM can accept in a row */
            row_size = tpm_get_burst_count(locality);
            if ( row_size > 0 )   break;
            else  cpu_relax();
            i++;
        } while ( i <= TPM_CMD_WRITE_TIME_OUT );
        if ( i > TPM_CMD_WRITE_TIME_OUT ) {
            printk(TBOOT_ERR"TPM: write cmd timeout\n");
            ret = false;
            goto RelinquishControl;
        }

        for ( ; row_size > 0 && offset < in_size; row_size--, offset++ )  write_tpm_reg(locality, TPM_REG_DATA_FIFO,  (tpm_reg_data_fifo_t *)&in[offset]);
    } while ( offset < in_size );

    i = 0;
    do {
        if ( tpm_check_expect_status(locality) )  break;
        else   cpu_relax();
        i++;
    } while ( i <= TPM_DATA_AVAIL_TIME_OUT );
    if ( i > TPM_DATA_AVAIL_TIME_OUT ) {
        printk(TBOOT_ERR"TPM: wait for expect becoming 0 timeout\n");
        ret = false;
        goto RelinquishControl;
    }

    /* command has been written to the TPM, it is time to execute it. */
    tpm_execute_cmd(locality);

    /* check for data available */
    i = 0;
    do {
        if ( tpm_check_da_status(locality) )  break;
        else  cpu_relax();
        i++;
    } while ( i <= TPM_DATA_AVAIL_TIME_OUT );
    if ( i > TPM_DATA_AVAIL_TIME_OUT ) {
        printk(TBOOT_ERR"TPM: wait for data available timeout\n");
        ret = false;
        goto RelinquishControl;
    }

    rsp_size = 0;
    offset = 0;
    do {
        /* find out how many bytes the TPM returned in a row */
        i = 0;
        do {
            row_size = tpm_get_burst_count(locality);
            if ( row_size > 0 )  break;
            else cpu_relax();
            i++;
        } while ( i <= TPM_RSP_READ_TIME_OUT );
        if ( i > TPM_RSP_READ_TIME_OUT ) {
            printk(TBOOT_ERR"TPM: read rsp timeout\n");
            ret = false;
            goto RelinquishControl;
        }

        for ( ; row_size > 0 && offset < *out_size; row_size--, offset++ ) {
            if ( offset < *out_size )  read_tpm_reg(locality, TPM_REG_DATA_FIFO, (tpm_reg_data_fifo_t *)&out[offset]);
            else {
                /* discard the responded bytes exceeding out buf size */
                tpm_reg_data_fifo_t discard;
                read_tpm_reg(locality, TPM_REG_DATA_FIFO,  (tpm_reg_data_fifo_t *)&discard);
            }

            /* get outgoing data size */
            if ( offset == RSP_RST_OFFSET - 1 ) {
                reverse_copy(&rsp_size, &out[RSP_SIZE_OFFSET], sizeof(rsp_size));
            }
        }
    } while ( offset < RSP_RST_OFFSET || (offset < rsp_size && offset < *out_size) );

    *out_size = (*out_size > rsp_size) ? rsp_size : *out_size;

#ifdef TPM_TRACE
    {
        printk(TBOOT_INFO"TPM: response size = %d\n", *out_size);
        printk(TBOOT_DETA"TPM: response content: ");
        print_hex("TPM: \t", out, *out_size);
    }
#endif

    tpm_send_cmd_ready_status(locality);

RelinquishControl:
    /* deactivate current locality */
    reg_acc._raw[0] = 0;
    reg_acc.active_locality = 1;
    write_tpm_reg(locality, TPM_REG_ACCESS, &reg_acc);

    return ret;
}


bool tpm_submit_cmd_crb(u32 locality, u8 *in, u32 in_size,  u8 *out, u32 *out_size)
{
    uint32_t i;
    
    bool ret = true;

    //tpm_reg_loc_ctrl_t reg_loc_ctrl;
    tpm_reg_ctrl_start_t start;

    tpm_reg_ctrl_cmdsize_t  CmdSize;
    tpm_reg_ctrl_cmdaddr_t  CmdAddr;
    tpm_reg_ctrl_rspsize_t  RspSize;
    tpm_reg_ctrl_rspaddr_t  RspAddr;
    uint32_t  tpm_crb_data_buffer_base;
	
    if ( locality >= TPM_NR_LOCALITIES ) {
        printk(TBOOT_WARN"TPM: Invalid locality for tpm_submit_cmd_crb()\n");
        return false;
    }
    if ( in == NULL || out == NULL || out_size == NULL ) {
        printk(TBOOT_WARN"TPM: Invalid parameter for tpm_submit_cmd_crb()\n");
        return false;
    }
    if ( in_size < CMD_HEAD_SIZE || *out_size < RSP_HEAD_SIZE ) {
        printk(TBOOT_WARN"TPM: in/out buf size must be larger than 10 bytes\n");
        return false;
    }

    if ( !tpm_validate_locality_crb(locality) ) {
        printk(TBOOT_WARN"TPM: CRB Interface Locality %d is not open\n", locality);
        return false;
    }

    if ( !tpm_wait_cmd_ready_crb(locality) ) {
        printk(TBOOT_WARN"TPM: tpm_wait_cmd_read_crb failed\n");
	 return false;
    }

#ifdef TPM_TRACE
    {
        printk(TBOOT_DETA"TPM: Before submit, cmd size = 0x%x\nTPM: Before submit, cmd content: ", in_size);
        print_hex("TPM: \t", in, in_size);
    }
#endif

    /* write the command to the TPM CRB  buffer 01-04-2016  */
//copy *in and size to crb buffer



    CmdAddr.cmdladdr = TPM_LOCALITY_CRB_BASE_N(locality) | TPM_CRB_DATA_BUFFER;
    CmdAddr.cmdhaddr = 0;
    RspAddr.rspaddr = TPM_LOCALITY_CRB_BASE_N(locality) | TPM_CRB_DATA_BUFFER;
    CmdSize.cmdsize = TPMCRBBUF_LEN;
    RspSize.rspsize = TPMCRBBUF_LEN;
    tpm_crb_data_buffer_base = TPM_CRB_DATA_BUFFER;
	

 #ifdef TPM_TRACE  
       printk(TBOOT_INFO"CmdAddr.cmdladdr is 0x%x\n",CmdAddr.cmdladdr);
       printk(TBOOT_INFO"CmdAddr.cmdhaddr is 0x%x\n",CmdAddr.cmdhaddr);

	printk(TBOOT_INFO"CmdSize.cmdsize is 0x%x\n",CmdSize.cmdsize);
	printk(TBOOT_INFO"RspAddr.rspaddr is 0x%Lx\n",RspAddr.rspaddr);
	printk(TBOOT_INFO"RspSize.rspsize is 0x%x\n",RspSize.rspsize);
	
#endif
    
    write_tpm_reg(locality, TPM_CRB_CTRL_CMD_ADDR, &CmdAddr);
    write_tpm_reg(locality, TPM_CRB_CTRL_CMD_SIZE, &CmdSize);
    write_tpm_reg(locality, TPM_CRB_CTRL_RSP_ADDR, &RspAddr);
    write_tpm_reg(locality, TPM_CRB_CTRL_RSP_SIZE, &RspSize);
    // write the command to the buffer
    for ( i = 0 ; i< in_size; i++ )  {
        write_tpm_reg(locality, tpm_crb_data_buffer_base++,  (tpm_reg_data_crb_t *)&in[i]);
        //tpm_crb_data_buffer_base++;
    }

    /* command has been written to the TPM, it is time to execute it. */
    start.start = 1;
    write_tpm_reg(locality, TPM_CRB_CTRL_START, &start);
    //read_tpm_reg(locality, TPM_CRB_CTRL_START, &start);
    printk(TBOOT_INFO"tpm_ctrl_start.start is 0x%x\n",start.start);
	
    /* check for data available */
    i = 0;
    do {
	   read_tpm_reg(locality, TPM_CRB_CTRL_START, &start);
        //printk(TBOOT_INFO"tpm_ctrl_start.start is 0x%x\n",start.start);
          if ( start.start == 0 ) break;
          else  cpu_relax();
          i++;
    } while ( i <= TPM_DATA_AVAIL_TIME_OUT );

    if ( i > TPM_DATA_AVAIL_TIME_OUT ) {
        printk(TBOOT_ERR"TPM: wait for data available timeout\n");
        ret = false;
        goto RelinquishControl;
    }

    tpm_crb_data_buffer_base = TPM_CRB_DATA_BUFFER;

    for ( i = 0 ; i< *out_size; i++ )  {
        read_tpm_reg(locality, tpm_crb_data_buffer_base++, (tpm_reg_data_crb_t *)&out[i]);
        //tpm_crb_data_buffer_base++;
    }

  

#ifdef TPM_TRACE
    {
        printk(TBOOT_INFO"TPM: After cmd submit, response size = 0x%x\n", *out_size);
        printk(TBOOT_DETA"TPM: After cmd submit, response content: ");
        print_hex("TPM: \t", out, *out_size);
    }
#endif

    //tpm_send_cmd_ready_status_crb(locality);

RelinquishControl:
    /* deactivate current locality */
   // reg_loc_ctrl._raw[0] = 0;
    //reg_loc_ctrl.relinquish = 1;
    //write_tpm_reg(locality, TPM_REG_LOC_CTRL, &reg_loc_ctrl);

    return ret;

}


bool release_locality(uint32_t locality)
{
    uint32_t i;
#ifdef TPM_TRACE
    printk(TBOOT_DETA"TPM: releasing locality %u\n", locality);
#endif

    if ( !tpm_validate_locality(locality) )   return true;

    tpm_reg_access_t reg_acc;
    read_tpm_reg(locality, TPM_REG_ACCESS, &reg_acc);
    if ( reg_acc.active_locality == 0 )    return true;

    /* make inactive by writing a 1 */
    reg_acc._raw[0] = 0;
    reg_acc.active_locality = 1;
    write_tpm_reg(locality, TPM_REG_ACCESS, &reg_acc);

    i = 0;
    do {
        read_tpm_reg(locality, TPM_REG_ACCESS, &reg_acc);
        if ( reg_acc.active_locality == 0 )
            return true;
        else
            cpu_relax();
        i++;
    } while ( i <= TPM_ACTIVE_LOCALITY_TIME_OUT );

    printk(TBOOT_INFO"TPM: access reg release locality timeout\n");
    return false;
}

bool tpm_relinquish_locality_crb(uint32_t locality)
{
    uint32_t i;
    tpm_reg_loc_state_t reg_loc_state;
    tpm_reg_loc_ctrl_t reg_loc_ctrl;
	
#ifdef TPM_TRACE
    printk(TBOOT_DETA"TPM: releasing CRB_INF locality %u\n", locality);
#endif

    if ( !tpm_validate_locality_crb(locality) )   return true;
    read_tpm_reg(locality, TPM_REG_LOC_STATE, &reg_loc_state);
    if ( reg_loc_state.loc_assigned == 0 )    return true;

    /* make inactive by writing a 1 */
    tb_memset(&reg_loc_ctrl,0,sizeof(reg_loc_ctrl));
    reg_loc_ctrl.relinquish = 1;
    write_tpm_reg(locality, TPM_REG_LOC_CTRL, &reg_loc_ctrl);

    i = 0;
    do {
        read_tpm_reg(locality, TPM_REG_LOC_STATE, &reg_loc_state);
        if ( reg_loc_state.loc_assigned == 0 )    return true;
        else cpu_relax();
        i++;
    } while ( i <= TPM_ACTIVE_LOCALITY_TIME_OUT );

    printk(TBOOT_INFO"TPM: CRB_INF release locality timeout\n");
    return false;
}



bool is_tpm_crb(void)
{      
     tpm_crb_interface_id_t crb_interface;
     read_tpm_reg(0, TPM_INTERFACE_ID, &crb_interface);
     if (crb_interface.interface_type == TPM_INTERFACE_ID_CRB  ) {
	 printk(TBOOT_INFO"TPM: PTP CRB interface is active...\n");
	 if (g_tpm_family != TPM_IF_20_CRB ) g_tpm_family = TPM_IF_20_CRB;
        return true;
     }
     if (crb_interface.interface_type == TPM_INTERFACE_ID_FIFO_20) {
	  printk(TBOOT_INFO"TPM: TPM 2.0 FIFO interface is active...\n");     
	  if (g_tpm_family != TPM_IF_20_FIFO) g_tpm_family = TPM_IF_20_FIFO;
     }
     return false;	
}


bool prepare_tpm(void)
{
    /*
     * must ensure TPM_ACCESS_0.activeLocality bit is clear
     * (: locality is not active)
     */
   if ( is_tpm_crb() ) {
       return tpm_relinquish_locality_crb(0);
   }
   else {
       return release_locality(0);
   }
}

bool tpm_request_locality_crb(uint32_t locality){

    uint32_t            i;
    tpm_reg_loc_state_t  reg_loc_state;
    tpm_reg_loc_ctrl_t    reg_loc_ctrl;
    /* request access to the TPM from locality N */
    tb_memset(&reg_loc_ctrl,0,sizeof(reg_loc_ctrl));
    reg_loc_ctrl.requestAccess = 1;
    write_tpm_reg(locality, TPM_REG_LOC_CTRL, &reg_loc_ctrl);

    i = 0;
    do {
        read_tpm_reg(locality, TPM_REG_LOC_STATE, &reg_loc_state);
        if ( reg_loc_state.active_locality == locality && reg_loc_state.loc_assigned == 1)
            break;
        else
            cpu_relax();
        i++;
    } while ( i <= TPM_ACTIVE_LOCALITY_TIME_OUT);

    if ( i > TPM_ACTIVE_LOCALITY_TIME_OUT ) {
        printk(TBOOT_ERR"TPM: access loc request use timeout\n");
        return false;
    }

    return true;

}

bool tpm_workaround_crb(void)
{
    tpm_reg_ctrl_cmdsize_t  CmdSize;
    tpm_reg_ctrl_cmdaddr_t  CmdAddr;
    tpm_reg_ctrl_rspsize_t  RspSize;
    tpm_reg_ctrl_rspaddr_t  RspAddr;
    u32 locality = 0;

    if (!tpm_request_locality_crb(locality))
        return false;

    CmdAddr.cmdladdr = TPM_LOCALITY_CRB_BASE_N(locality) | TPM_CRB_DATA_BUFFER;
    CmdAddr.cmdhaddr = 0;
    RspAddr.rspaddr = TPM_LOCALITY_CRB_BASE_N(locality) | TPM_CRB_DATA_BUFFER;
    CmdSize.cmdsize = TPMCRBBUF_LEN;
    RspSize.rspsize = TPMCRBBUF_LEN;

    write_tpm_reg(locality, TPM_CRB_CTRL_CMD_ADDR, &CmdAddr);
    write_tpm_reg(locality, TPM_CRB_CTRL_CMD_SIZE, &CmdSize);
    write_tpm_reg(locality, TPM_CRB_CTRL_RSP_ADDR, &RspAddr);
    write_tpm_reg(locality, TPM_CRB_CTRL_RSP_SIZE, &RspSize);

    return true;
}

bool tpm_detect(void)
{
    struct tpm_if *tpm = get_tpm(); /* Don't leave tpm as NULL */
    const struct tpm_if_fp *tpm_fp;
    if (is_tpm_crb()) {
         printk(TBOOT_INFO"TPM: This is Intel PTT, TPM Family 0x%d\n", g_tpm_family);
         if (!txt_is_launched()) {
               if ( tpm_validate_locality_crb(0) ) 
	             printk(TBOOT_INFO"TPM: CRB_INF Locality 0 is open\n");
		 else {
		 	printk(TBOOT_INFO"TPM: CRB_INF request access to Locality 0...\n");
			if (!tpm_request_locality_crb(0)) {
			        printk(TBOOT_ERR"TPM: CRB_INF Locality 0 request failed...\n");
				 return false;
			 }
                }
	  }
    	  else {
              if ( tpm_validate_locality_crb(2) ) 
		     printk(TBOOT_INFO"TPM: CRB_INF Locality 2 is open\n");
		else {	 
		      printk(TBOOT_INFO"TPM: CRB_INF request access to Locality 2...\n");
		      if (!tpm_request_locality_crb(2)) {
		 	     printk(TBOOT_ERR"TPM: CRB_INF Locality 2 request failed...\n");
                          return false;
			}
		}
    	  }
    }
    else {
		g_tpm_ver = TPM_VER_12; 
		tpm_fp = get_tpm_fp(); /* Don't leave tpm_fp as NULL */

		if ( tpm_validate_locality(0) )  printk(TBOOT_INFO"TPM: FIFO_INF Locality 0 is open\n");
		else {	
			printk(TBOOT_ERR"TPM: FIFO_INF Locality 0 is not open\n");
			return false;
			}
		/* determine TPM family from command check */
		if ( tpm_fp->check() )  {
			g_tpm_family = TPM_IF_12;
			printk(TBOOT_INFO"TPM: discrete TPM1.2 Family 0x%d\n", g_tpm_family);	
			}
		else {
			g_tpm_family = TPM_IF_20_FIFO;
			printk(TBOOT_INFO"TPM: discrete TPM2.0 Family 0x%d\n", g_tpm_family);
			}
	}
   
    if (g_tpm_family == TPM_IF_12)  g_tpm_ver = TPM_VER_12;
    if (g_tpm_family == TPM_IF_20_FIFO)  g_tpm_ver = TPM_VER_20;
    if (g_tpm_family == TPM_IF_20_CRB)  g_tpm_ver = TPM_VER_20;

    tpm_fp = get_tpm_fp();
    return tpm_fp->init(tpm);
}

void tpm_print(struct tpm_if *ti)
{
    if ( ti == NULL )
        return;

    printk(TBOOT_INFO"TPM attribute:\n");
    printk(TBOOT_INFO"\t extend policy: %d\n", ti->extpol);
    printk(TBOOT_INFO"\t current alg id: 0x%x\n", ti->cur_alg);
    printk(TBOOT_INFO"\t timeout values: A: %u, B: %u, C: %u, D: %u\n", ti->timeout.timeout_a, ti->timeout.timeout_b, ti->timeout.timeout_c, ti->timeout.timeout_d);
} 

struct tpm_if *get_tpm(void)
{
    return &g_tpm;
}

const struct tpm_if_fp *get_tpm_fp(void)
{
    if ( g_tpm_ver == TPM_VER_12 )
        return &tpm_12_if_fp;
    else if ( g_tpm_ver == TPM_VER_20)
        return &tpm_20_if_fp;

    return NULL;

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
