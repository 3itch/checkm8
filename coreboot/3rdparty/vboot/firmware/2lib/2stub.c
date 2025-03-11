/* Copyright 2014 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * Stub API implementations which should be implemented by the caller.
 */

#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/time.h>

#include "2api.h"
#include "2common.h"
#include "2sysincludes.h"

/*****************************************************************************/
/* General utility stubs */

__attribute__((weak))
void vb2ex_printf(const char *func, const char *fmt, ...)
{
#ifdef VBOOT_DEBUG
	va_list ap;
	va_start(ap, fmt);
	if (func)
		fprintf(stderr, "%s: ", func);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
#endif
}

__attribute__((weak))
void vb2ex_abort(void)
{
	/* Stub simply exits. */
	abort();
}

__attribute__((weak))
vb2_error_t vb2ex_commit_data(struct vb2_context *ctx)
{
	ctx->flags &= ~VB2_CONTEXT_SECDATA_FIRMWARE_CHANGED;
	ctx->flags &= ~VB2_CONTEXT_SECDATA_KERNEL_CHANGED;
	ctx->flags &= ~VB2_CONTEXT_NVDATA_CHANGED;
	return VB2_SUCCESS;
}

__attribute__((weak))
vb2_error_t vb2ex_read_resource(struct vb2_context *ctx,
				enum vb2_resource_index index, uint32_t offset,
				void *buf, uint32_t size)
{
	VB2_DEBUG("function not implemented\n");
	return VB2_ERROR_EX_UNIMPLEMENTED;
}

/*****************************************************************************/
/* TPM-related stubs */

__attribute__((weak))
vb2_error_t vb2ex_tpm_clear_owner(struct vb2_context *ctx)
{
	VB2_DEBUG("function not implemented\n");
	return VB2_ERROR_EX_UNIMPLEMENTED;
}

__attribute__((weak))
vb2_error_t vb2ex_tpm_set_mode(enum vb2_tpm_mode mode_val)
{
	VB2_DEBUG("function not implemented\n");
	return VB2_ERROR_EX_UNIMPLEMENTED;
}

/*****************************************************************************/
/* auxfw and EC-related stubs */

__attribute__((weak))
vb2_error_t vb2ex_ec_running_rw(int *in_rw)
{
	*in_rw = 0;
	return VB2_SUCCESS;
}

__attribute__((weak))
vb2_error_t vb2ex_ec_jump_to_rw(void)
{
	return VB2_SUCCESS;
}

__attribute__((weak))
vb2_error_t vb2ex_ec_disable_jump(void)
{
	return VB2_SUCCESS;
}

__attribute__((weak))
vb2_error_t vb2ex_ec_hash_image(enum vb2_firmware_selection select,
				const uint8_t **hash, int *hash_size)
{
	static const uint8_t fake_hash[32] = {1, 2, 3, 4};

	*hash = fake_hash;
	*hash_size = sizeof(fake_hash);
	return VB2_SUCCESS;
}

__attribute__((weak))
vb2_error_t vb2ex_ec_get_expected_image_hash(enum vb2_firmware_selection select,
					     const uint8_t **hash, int *hash_size)
{
	static const uint8_t fake_hash[32] = {1, 2, 3, 4};

	*hash = fake_hash;
	*hash_size = sizeof(fake_hash);
	return VB2_SUCCESS;
}

__attribute__((weak))
vb2_error_t vb2ex_ec_update_image(enum vb2_firmware_selection select)
{
	return VB2_SUCCESS;
}

__attribute__((weak))
vb2_error_t vb2ex_ec_protect(void)
{
	return VB2_SUCCESS;
}

__attribute__((weak))
vb2_error_t vb2ex_ec_vboot_done(struct vb2_context *ctx)
{
	return VB2_SUCCESS;
}

__attribute__((weak))
vb2_error_t vb2ex_ec_battery_cutoff(void)
{
	return VB2_SUCCESS;
}

__attribute__((weak))
vb2_error_t vb2ex_auxfw_check(enum vb2_auxfw_update_severity *severity)
{
	*severity = VB2_AUXFW_NO_UPDATE;
	return VB2_SUCCESS;
}

__attribute__((weak))
vb2_error_t vb2ex_auxfw_update(void)
{
	return VB2_SUCCESS;
}

__attribute__((weak))
vb2_error_t vb2ex_auxfw_finalize(struct vb2_context *ctx)
{
	return VB2_SUCCESS;
}

/*****************************************************************************/
/* Timer-related stubs */

__attribute__((weak))
uint32_t vb2ex_mtime(void)
{
	struct timeval tv;
	gettimeofday(&tv, NULL);
	return tv.tv_sec * VB2_MSEC_PER_SEC + tv.tv_usec / VB2_USEC_PER_MSEC;
}
