/* Copyright 2011 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * Stub implementations of disk APIs.
 */

#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

#include "2common.h"
#include "vboot_api.h"

__attribute__((weak))
vb2_error_t VbExDiskRead(vb2ex_disk_handle_t handle, uint64_t lba_start,
			 uint64_t lba_count, void* buffer)
{
	return VB2_SUCCESS;
}

__attribute__((weak))
vb2_error_t VbExDiskWrite(vb2ex_disk_handle_t handle, uint64_t lba_start,
			  uint64_t lba_count, const void* buffer)
{
	return VB2_SUCCESS;
}
