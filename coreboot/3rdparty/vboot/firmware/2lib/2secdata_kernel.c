/* Copyright 2015 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * Secure storage APIs - kernel version space
 */

#include "2common.h"
#include "2crc8.h"
#include "2misc.h"
#include "2secdata.h"
#include "2secdata_struct.h"
#include "2sysincludes.h"

#define MAJOR_VER(x) (((x) & 0xf0) >> 4)
#define MINOR_VER(x) ((x) & 0x0f)

static inline int is_v0(struct vb2_context *ctx)
{
	struct vb2_secdata_kernel_v1 *sec = (void *)ctx->secdata_kernel;
	return MAJOR_VER(sec->struct_version) == 0;
}

/**
 * Calculate crc8 of kernel secure storage.
 *
 * @param ctx		Context pointer
 * @return Calculated crc8 value.
 */
static uint8_t secdata_kernel_crc(struct vb2_context *ctx)
{
	size_t offset, size;

	if (is_v0(ctx)) {
		offset = 0;
		size = offsetof(struct vb2_secdata_kernel_v0, crc8);
	} else {
		struct vb2_secdata_kernel_v1 *sec
			= (void *)ctx->secdata_kernel;
		offset = offsetof(struct vb2_secdata_kernel_v1, flags);
		size = sec->struct_size - offset;
	}

	return vb2_crc8(ctx->secdata_kernel + offset, size);
}

static vb2_error_t secdata_kernel_check_v0(struct vb2_context *ctx,
					   uint8_t *size)
{
	struct vb2_secdata_kernel_v0 *sec = (void *)ctx->secdata_kernel;
	uint8_t ver = sec->struct_version;

	if (MINOR_VER(ver) != MINOR_VER(VB2_SECDATA_KERNEL_VERSION_V02)) {
		VB2_DEBUG("secdata_kernel: bad struct_version (%d.%d)\n",
			  MAJOR_VER(ver), MINOR_VER(ver));
		return VB2_ERROR_SECDATA_KERNEL_VERSION;
	}

	*size = VB2_SECDATA_KERNEL_SIZE_V02;

	/* Verify CRC */
	if (sec->crc8 != secdata_kernel_crc(ctx)) {
		VB2_DEBUG("secdata_kernel: bad CRC\n");
		return VB2_ERROR_SECDATA_KERNEL_CRC;
	}

	/* Verify UID */
	if (sec->uid != VB2_SECDATA_KERNEL_UID) {
		VB2_DEBUG("secdata_kernel: bad UID\n");
		return VB2_ERROR_SECDATA_KERNEL_UID;
	}

	return VB2_SUCCESS;
}

static vb2_error_t secdata_kernel_check_v1(struct vb2_context *ctx,
					   uint8_t *size)
{
	struct vb2_secdata_kernel_v1 *sec = (void *)ctx->secdata_kernel;
	uint8_t ver = sec->struct_version;

	if (MAJOR_VER(ver) != MAJOR_VER(VB2_SECDATA_KERNEL_VERSION_V10)) {
		VB2_DEBUG("secdata_kernel: bad struct_version (%d.%d)\n",
			  MAJOR_VER(ver), MINOR_VER(ver));
		return VB2_ERROR_SECDATA_KERNEL_VERSION;
	}

	if (sec->struct_size < VB2_SECDATA_KERNEL_SIZE_V10 ||
			VB2_SECDATA_KERNEL_MAX_SIZE < sec->struct_size) {
		VB2_DEBUG("secdata_kernel: bad struct_size (%d)\n",
			  sec->struct_size);
		return VB2_ERROR_SECDATA_KERNEL_STRUCT_SIZE;
	}

	if (*size < sec->struct_size) {
		VB2_DEBUG("secdata_kernel: incomplete data (missing %d bytes)\n",
			  sec->struct_size - *size);
		*size = sec->struct_size;
		return VB2_ERROR_SECDATA_KERNEL_INCOMPLETE;
	}

	/*
	 * In case larger data should be passed, kindly let the caller know
	 * the right size.
	 */
	*size = sec->struct_size;

	/* Verify CRC */
	if (sec->crc8 != secdata_kernel_crc(ctx)) {
		VB2_DEBUG("secdata_kernel: bad CRC\n");
		return VB2_ERROR_SECDATA_KERNEL_CRC;
	}

	return VB2_SUCCESS;
}

vb2_error_t vb2api_secdata_kernel_check(struct vb2_context *ctx, uint8_t *size)
{
	if (*size < VB2_SECDATA_KERNEL_MIN_SIZE) {
		VB2_DEBUG("secdata_kernel: data size too small!\n");
		*size = VB2_SECDATA_KERNEL_MIN_SIZE;
		return VB2_ERROR_SECDATA_KERNEL_INCOMPLETE;
	}

	if (is_v0(ctx))
		return secdata_kernel_check_v0(ctx, size);
	else
		return secdata_kernel_check_v1(ctx, size);
}

uint32_t vb2api_secdata_kernel_create(struct vb2_context *ctx)
{
	struct vb2_secdata_kernel_v1 *sec = (void *)ctx->secdata_kernel;

	/* Populate the struct */
	memset(sec, 0, sizeof(*sec));
	sec->struct_version = VB2_SECDATA_KERNEL_VERSION_LATEST;
	sec->struct_size = sizeof(*sec);
	sec->crc8 = secdata_kernel_crc(ctx);

	/* Mark as changed */
	ctx->flags |= VB2_CONTEXT_SECDATA_KERNEL_CHANGED;

	return sizeof(*sec);
}

/* For TPM 1.2 */
uint32_t vb2api_secdata_kernel_create_v0(struct vb2_context *ctx)
{
	struct vb2_secdata_kernel_v0 *sec = (void *)ctx->secdata_kernel;

	/* Clear the entire struct */
	memset(sec, 0, sizeof(*sec));

	/* Set to current version */
	sec->struct_version = VB2_SECDATA_KERNEL_VERSION_V02;

	/* Set UID */
	sec->uid = VB2_SECDATA_KERNEL_UID;

	/* Calculate initial CRC */
	sec->crc8 = vb2_crc8(sec, offsetof(struct vb2_secdata_kernel_v0, crc8));

	/* Mark as changed */
	ctx->flags |= VB2_CONTEXT_SECDATA_KERNEL_CHANGED;

	return sizeof(*sec);
}

vb2_error_t vb2_secdata_kernel_init(struct vb2_context *ctx)
{
	struct vb2_shared_data *sd = vb2_get_sd(ctx);
	uint8_t size = VB2_SECDATA_KERNEL_MAX_SIZE;

	VB2_TRY(vb2api_secdata_kernel_check(ctx, &size));

	/* Set status flag */
	sd->status |= VB2_SD_STATUS_SECDATA_KERNEL_INIT;

	return VB2_SUCCESS;
}

test_mockable
uint32_t vb2_secdata_kernel_get(struct vb2_context *ctx,
				enum vb2_secdata_kernel_param param)
{
	struct vb2_shared_data *sd = vb2_get_sd(ctx);
	const char *msg;
	const struct vb2_secdata_kernel_v0 *v0 = (void *)ctx->secdata_kernel;
	const struct vb2_secdata_kernel_v1 *v1 = (void *)ctx->secdata_kernel;

	if (!(sd->status & VB2_SD_STATUS_SECDATA_KERNEL_INIT)) {
		msg = "get before init";
		goto fail;
	}

	switch (param) {
	case VB2_SECDATA_KERNEL_VERSIONS:
		return is_v0(ctx) ? v0->kernel_versions : v1->kernel_versions;
	case VB2_SECDATA_KERNEL_FLAGS:
		if (is_v0(ctx)) {
			VB2_DEBUG("VB2_SECDATA_KERNEL_FLAGS not supported for "
				  "secdata_kernel v0, return 0\n");
			return 0;
		}
		return v1->flags;
	default:
		msg = "invalid param";
	}

 fail:
	VB2_REC_OR_DIE(ctx, "%s\n", msg);
	return 0;
}

test_mockable
void vb2_secdata_kernel_set(struct vb2_context *ctx,
			    enum vb2_secdata_kernel_param param,
			    uint32_t value)
{
	struct vb2_shared_data *sd = vb2_get_sd(ctx);
	const char *msg;
	struct vb2_secdata_kernel_v0 *v0 = (void *)ctx->secdata_kernel;
	struct vb2_secdata_kernel_v1 *v1 = (void *)ctx->secdata_kernel;
	uint32_t *ptr;

	if (!(sd->status & VB2_SD_STATUS_SECDATA_KERNEL_INIT)) {
		msg = "set before init";
		goto fail;
	}

	/* If not changing the value, just return early */
	if (value == vb2_secdata_kernel_get(ctx, param))
		return;

	switch (param) {
	case VB2_SECDATA_KERNEL_VERSIONS:
		ptr = is_v0(ctx) ? &v0->kernel_versions : &v1->kernel_versions;
		VB2_DEBUG("secdata_kernel versions updated from %#x to %#x\n",
			  *ptr, value);
		*ptr = value;
		break;
	case VB2_SECDATA_KERNEL_FLAGS:
		if (is_v0(ctx)) {
			VB2_DEBUG("VB2_SECDATA_KERNEL_FLAGS not supported for "
				  "secdata_kernel v0, silently ignore\n");
			return;
		}

		/* Make sure flags is in valid range */
		if (value > UINT8_MAX) {
			msg = "flags out of range";
			goto fail;
		}

		VB2_DEBUG("secdata_kernel flags updated from %#x to %#x\n",
			  v1->flags, value);
		v1->flags = value;
		break;
	default:
		msg = "invalid param";
		goto fail;
	}

	if (is_v0(ctx))
		v0->crc8 = secdata_kernel_crc(ctx);
	else
		v1->crc8 = secdata_kernel_crc(ctx);

	ctx->flags |= VB2_CONTEXT_SECDATA_KERNEL_CHANGED;
	return;

 fail:
	VB2_REC_OR_DIE(ctx, "%s\n", msg);
}

test_mockable
const uint8_t *vb2_secdata_kernel_get_ec_hash(struct vb2_context *ctx)
{
	struct vb2_shared_data *sd = vb2_get_sd(ctx);
	struct vb2_secdata_kernel_v1 *sec = (void *)ctx->secdata_kernel;

	if (!(sd->status & VB2_SD_STATUS_SECDATA_KERNEL_INIT)) {
		VB2_REC_OR_DIE(ctx, "Get kernel secdata before init\n");
		return NULL;
	}
	if (is_v0(ctx)) {
		VB2_DEBUG("kernel secdata v.0* doesn't support EC hash\n");
		return NULL;
	}

	return sec->ec_hash;
}

test_mockable
void vb2_secdata_kernel_set_ec_hash(struct vb2_context *ctx,
				    const uint8_t *sha256)
{
	struct vb2_shared_data *sd = vb2_get_sd(ctx);
	struct vb2_secdata_kernel_v1 *sec = (void *)ctx->secdata_kernel;

	if (!(sd->status & VB2_SD_STATUS_SECDATA_KERNEL_INIT)) {
		VB2_REC_OR_DIE(ctx, "Get kernel secdata before init\n");
		return;
	}
	if (is_v0(ctx)) {
		VB2_REC_OR_DIE(ctx, "Invalid version of kernel secdata\n");
		return;
	}

	memcpy(sec->ec_hash, sha256, sizeof(sec->ec_hash));
	sec->crc8 = secdata_kernel_crc(ctx);

	ctx->flags |= VB2_CONTEXT_SECDATA_KERNEL_CHANGED;

	return;
}

uint32_t vb2api_get_kernel_rollback_version(struct vb2_context *ctx)
{
	return vb2_secdata_kernel_get(ctx, VB2_SECDATA_KERNEL_VERSIONS);
}
