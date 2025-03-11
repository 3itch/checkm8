/* Copyright 2020 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include "crossystem_arch.h"
#include "crossystem.h"
#include "crossystem_vbnv.h"
#include "host_common.h"
#include "vboot_struct.h"

int vb2_read_nv_storage(struct vb2_context *ctx)
{
	return -1;
}


int vb2_write_nv_storage(struct vb2_context *ctx)
{
	return -1;
}

VbSharedDataHeader* VbSharedDataRead(void)
{
	return NULL;
}

int VbGetArchPropertyInt(const char* name)
{
	return -1;
}


const char* VbGetArchPropertyString(const char* name, char* dest,
				    size_t size)
{
	return NULL;
}


int VbSetArchPropertyInt(const char* name, int value)
{
	return -1;
}

int VbSetArchPropertyString(const char* name, const char* value)
{
	return -1;
}
