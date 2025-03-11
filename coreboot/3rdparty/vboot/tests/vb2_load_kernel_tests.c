/* Copyright 2013 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * Tests for vboot_kernel.c
 */

#include "2api.h"
#include "2common.h"
#include "2misc.h"
#include "2nvstorage.h"
#include "2secdata.h"
#include "2secdata_struct.h"
#include "cgptlib.h"
#include "cgptlib_internal.h"
#include "common/boot_mode.h"
#include "common/tests.h"
#include "gpt.h"
#include "vboot_api.h"

/* Mock kernel partition */
struct mock_part {
	uint32_t start;
	uint32_t size;
	struct vb2_keyblock kbh;
};

/* Partition list; ends with a 0-size partition. */
#define MOCK_PART_COUNT 8
static struct mock_part mock_parts[MOCK_PART_COUNT];
static int mock_part_next;

/* Mock data */
static uint8_t kernel_buffer[80000];
static int disk_read_to_fail;
static int gpt_init_fail;
static int keyblock_verify_fail;  /* 0=ok, 1=sig, 2=hash */
static int preamble_verify_fail;
static int verify_data_fail;
static int unpack_key_fail;
static int gpt_flag_external;

static struct vb2_gbb_header gbb;
static struct vb2_kernel_params lkp;
static struct vb2_disk_info disk_info;
static struct vb2_keyblock cur_kbh;
static struct vb2_kernel_preamble kph;
static struct vb2_secdata_fwmp *fwmp;
static uint8_t mock_digest[VB2_SHA256_DIGEST_SIZE] = {12, 34, 56, 78};
static uint8_t workbuf[VB2_KERNEL_WORKBUF_RECOMMENDED_SIZE]
	__attribute__((aligned(VB2_WORKBUF_ALIGN)));
static struct vb2_context *ctx;
static struct vb2_shared_data *sd;
static struct vb2_packed_key mock_key;

/**
 * Reset mock data (for use before each test)
 */
static void ResetMocks(void)
{
	disk_read_to_fail = -1;

	gpt_init_fail = 0;
	keyblock_verify_fail = 0;
	preamble_verify_fail = 0;
	verify_data_fail = 0;
	unpack_key_fail = 0;

	gpt_flag_external = 0;

	memset(&gbb, 0, sizeof(gbb));
	gbb.major_version = VB2_GBB_MAJOR_VER;
	gbb.minor_version = VB2_GBB_MINOR_VER;
	gbb.flags = 0;

	memset(&lkp, 0, sizeof(lkp));
	lkp.kernel_buffer = kernel_buffer;
	lkp.kernel_buffer_size = sizeof(kernel_buffer);

	memset(&disk_info, 0, sizeof(disk_info));
	disk_info.bytes_per_lba = 512;
	disk_info.streaming_lba_count = 1024;
	disk_info.lba_count = 1024;
	disk_info.handle = (vb2ex_disk_handle_t)1;

	memset(mock_parts, 0, sizeof(mock_parts));
	mock_parts[0].start = 100;
	mock_parts[0].size = 150; /* 75 KB */
	mock_parts[0].kbh = (struct vb2_keyblock){
		.data_key.key_version = 2,
		.keyblock_flags = -1,
		.keyblock_size = sizeof(mock_parts[0].kbh),
	};
	mock_part_next = 0;

	memset(&cur_kbh, 0, sizeof(cur_kbh));

	memset(&kph, 0, sizeof(kph));
	kph.kernel_version = 1;
	kph.preamble_size = 4096 - mock_parts[0].kbh.keyblock_size;
	kph.body_signature.data_size = 70144;
	kph.bootloader_address = 0xbeadd008;
	kph.bootloader_size = 0x1234;

	memset(&mock_key, 0, sizeof(mock_key));

	TEST_SUCC(vb2api_init(workbuf, sizeof(workbuf), &ctx),
		  "vb2api_init failed");
	vb2_nv_init(ctx);

	sd = vb2_get_sd(ctx);
	sd->kernel_version_secdata = 0x20001;

	/* CRC will be invalid after here, but nobody's checking */
	sd->status |= VB2_SD_STATUS_SECDATA_FWMP_INIT;
	fwmp = (struct vb2_secdata_fwmp *)ctx->secdata_fwmp;
	memcpy(&fwmp->dev_key_hash, mock_digest, sizeof(fwmp->dev_key_hash));

	SET_BOOT_MODE(ctx, VB2_BOOT_MODE_NORMAL);

	// TODO: more workbuf fields - flags, secdata_firmware

	vb2api_secdata_kernel_create(ctx);
	vb2_secdata_kernel_init(ctx);
	vb2_secdata_kernel_set(ctx, VB2_SECDATA_KERNEL_FLAGS,
			VB2_SECDATA_KERNEL_FLAG_HWCRYPTO_ALLOWED);
}

/* Mocks */
struct vb2_gbb_header *vb2_get_gbb(struct vb2_context *c)
{
	return &gbb;
}

vb2_error_t vb2ex_read_resource(struct vb2_context *c,
				enum vb2_resource_index index, uint32_t offset,
				void *buf, uint32_t size)
{
	memset(buf, 0, size);
	return VB2_SUCCESS;
}

vb2_error_t vb2_gbb_read_root_key(struct vb2_context *c,
				  struct vb2_packed_key **keyp, uint32_t *size,
				  struct vb2_workbuf *wb)
{
	*keyp = &mock_key;
	return VB2_SUCCESS;
}

vb2_error_t vb2_gbb_read_recovery_key(struct vb2_context *c,
				      struct vb2_packed_key **keyp,
				      uint32_t *size, struct vb2_workbuf *wb)
{
	*keyp = &mock_key;
	return VB2_SUCCESS;
}

vb2_error_t VbExDiskRead(vb2ex_disk_handle_t h, uint64_t lba_start,
			 uint64_t lba_count, void *buffer)
{
	if ((int)lba_start == disk_read_to_fail)
		return VB2_ERROR_MOCK;

	return VB2_SUCCESS;
}

int AllocAndReadGptData(vb2ex_disk_handle_t disk_handle, GptData *gptdata)
{
	return GPT_SUCCESS;
}

int GptInit(GptData *gpt)
{
	return gpt_init_fail;
}

int GptNextKernelEntry(GptData *gpt, uint64_t *start_sector, uint64_t *size)
{
	struct mock_part *p = mock_parts + mock_part_next;

	if (!p->size)
		return GPT_ERROR_NO_VALID_KERNEL;

	if (gpt->flags & GPT_FLAG_EXTERNAL)
		gpt_flag_external++;

	memcpy(&cur_kbh, &mock_parts[mock_part_next].kbh, sizeof(cur_kbh));

	gpt->current_kernel = mock_part_next;
	*start_sector = p->start;
	*size = p->size;
	mock_part_next++;
	return GPT_SUCCESS;
}

int GptUpdateKernelEntry(GptData *gpt, uint32_t update_type)
{
	return GPT_SUCCESS;
}

int WriteAndFreeGptData(vb2ex_disk_handle_t disk_handle, GptData *gptdata)
{
	return GPT_SUCCESS;
}

void GetCurrentKernelUniqueGuid(GptData *gpt, void *dest)
{
	static char fake_guid[] = "FakeGuid";

	memcpy(dest, fake_guid, sizeof(fake_guid));
}

vb2_error_t vb2_unpack_key_buffer(struct vb2_public_key *key,
				  const uint8_t *buf, uint32_t size)
{
	if (--unpack_key_fail == 0)
		return VB2_ERROR_MOCK;

	return VB2_SUCCESS;
}

vb2_error_t vb2_verify_keyblock(struct vb2_keyblock *block, uint32_t size,
				const struct vb2_public_key *key,
				const struct vb2_workbuf *wb)
{
	if (keyblock_verify_fail >= 1)
		return VB2_ERROR_MOCK;

	/* Use this as an opportunity to override the keyblock */
	memcpy((void *)block, &cur_kbh, sizeof(cur_kbh));

	return VB2_SUCCESS;
}

vb2_error_t vb2_verify_keyblock_hash(const struct vb2_keyblock *block,
				     uint32_t size,
				     const struct vb2_workbuf *wb)
{
	if (keyblock_verify_fail >= 2)
		return VB2_ERROR_MOCK;

	/* Use this as an opportunity to override the keyblock */
	memcpy((void *)block, &cur_kbh, sizeof(cur_kbh));

	return VB2_SUCCESS;
}

vb2_error_t vb2_verify_kernel_preamble(struct vb2_kernel_preamble *preamble,
			       uint32_t size, const struct vb2_public_key *key,
			       const struct vb2_workbuf *wb)
{
	if (preamble_verify_fail)
		return VB2_ERROR_MOCK;

	/* Use this as an opportunity to override the preamble */
	memcpy((void *)preamble, &kph, sizeof(kph));
	return VB2_SUCCESS;
}

vb2_error_t vb2_verify_data(const uint8_t *data, uint32_t size,
			    struct vb2_signature *sig,
			    const struct vb2_public_key *key,
			    const struct vb2_workbuf *wb)
{
	if (verify_data_fail)
		return VB2_ERROR_MOCK;

	return VB2_SUCCESS;
}

vb2_error_t vb2_digest_finalize(struct vb2_digest_context *dc, uint8_t *digest,
				uint32_t digest_size)
{
	if (digest_size == sizeof(mock_digest))
		memcpy(digest, mock_digest, digest_size);
	else
		TEST_TRUE(false, "  unexpected digest size");
	return VB2_SUCCESS;
}

/* Make sure nothing tested here ever calls this directly. */
void vb2api_fail(struct vb2_context *c, uint8_t reason, uint8_t subcode)
{
	TEST_TRUE(0, "  called vb2api_fail()");
}

static void test_load_kernel(vb2_error_t expect_retval, const char *test_name)
{
	TEST_EQ(vb2api_load_kernel(ctx, &lkp, &disk_info), expect_retval,
		test_name);
	if (expect_retval == VB2_SUCCESS)
		TEST_PTR_EQ(lkp.disk_handle, disk_info.handle,
			    "  fill disk_handle when success");
}

/**
 * Trivial invalid calls to vb2api_load_kernel()
 */
static void invalid_params_tests(void)
{
	ResetMocks();
	gpt_init_fail = 1;
	test_load_kernel(VB2_ERROR_LK_NO_KERNEL_FOUND, "Bad GPT");

	/* This causes the stream open call to fail */
	ResetMocks();
	disk_info.handle = NULL;
	test_load_kernel(VB2_ERROR_LK_INVALID_KERNEL_FOUND, "Bad disk handle");
}

static void load_kernel_tests(void)
{
	ResetMocks();
	test_load_kernel(VB2_SUCCESS, "First kernel good");
	TEST_EQ(lkp.partition_number, 1, "  part num");
	TEST_EQ(lkp.bootloader_offset, 0xbeadd008, "  bootloader offset");
	TEST_EQ(lkp.bootloader_size, 0x1234, "  bootloader size");
	TEST_STR_EQ((char *)lkp.partition_guid, "FakeGuid", "  guid");
	TEST_EQ(gpt_flag_external, 0, "GPT was internal");
	TEST_NEQ(sd->flags & VB2_SD_FLAG_KERNEL_SIGNED, 0, "  use signature");

	ResetMocks();
	memcpy(&mock_parts[1].kbh, &mock_parts[0].kbh,
	       sizeof(mock_parts[0].kbh));
	mock_parts[1].start = 300;
	mock_parts[1].size = 150;
	test_load_kernel(VB2_SUCCESS, "Two good kernels");
	TEST_EQ(lkp.partition_number, 1, "  part num");
	TEST_EQ(mock_part_next, 1, "  didn't read second one");

	/* Fail if no kernels found */
	ResetMocks();
	mock_parts[0].size = 0;
	test_load_kernel(VB2_ERROR_LK_NO_KERNEL_FOUND, "No kernels");

	/* Skip kernels which are too small */
	ResetMocks();
	mock_parts[0].size = 10;
	test_load_kernel(VB2_ERROR_LK_INVALID_KERNEL_FOUND, "Too small");

	ResetMocks();
	disk_read_to_fail = 100;
	test_load_kernel(VB2_ERROR_LK_INVALID_KERNEL_FOUND,
			 "Fail reading kernel start");

	ResetMocks();
	keyblock_verify_fail = 1;
	test_load_kernel(VB2_ERROR_LK_INVALID_KERNEL_FOUND,
			 "Fail key block sig");

	/* In dev mode, fail if hash is bad too */
	ResetMocks();
	SET_BOOT_MODE(ctx, VB2_BOOT_MODE_DEVELOPER);
	keyblock_verify_fail = 2;
	test_load_kernel(VB2_ERROR_LK_INVALID_KERNEL_FOUND,
			 "Fail key block dev hash");

	/* But just bad sig is ok */
	ResetMocks();
	SET_BOOT_MODE(ctx, VB2_BOOT_MODE_DEVELOPER);
	keyblock_verify_fail = 1;
	test_load_kernel(VB2_SUCCESS, "Succeed keyblock dev sig");
	TEST_EQ(sd->flags & VB2_SD_FLAG_KERNEL_SIGNED, 0, "  use hash");

	/* In dev mode and requiring signed kernel, fail if sig is bad */
	ResetMocks();
	SET_BOOT_MODE(ctx, VB2_BOOT_MODE_DEVELOPER);
	vb2_nv_set(ctx, VB2_NV_DEV_BOOT_SIGNED_ONLY, 1);
	keyblock_verify_fail = 1;
	test_load_kernel(VB2_ERROR_LK_INVALID_KERNEL_FOUND,
			 "Fail key block dev sig");

	ResetMocks();
	SET_BOOT_MODE(ctx, VB2_BOOT_MODE_DEVELOPER);
	fwmp->flags |= VB2_SECDATA_FWMP_DEV_ENABLE_OFFICIAL_ONLY;
	keyblock_verify_fail = 1;
	test_load_kernel(VB2_ERROR_LK_INVALID_KERNEL_FOUND,
			 "Fail key block dev sig fwmp");

	/* Check keyblock flags */
	ResetMocks();
	mock_parts[0].kbh.keyblock_flags = VB2_KEYBLOCK_FLAG_RECOVERY_0 |
					   VB2_KEYBLOCK_FLAG_DEVELOPER_1 |
					   VB2_KEYBLOCK_FLAG_MINIOS_0;
	test_load_kernel(VB2_ERROR_LK_INVALID_KERNEL_FOUND,
			 "Keyblock dev flag mismatch");

	ResetMocks();
	mock_parts[0].kbh.keyblock_flags = VB2_KEYBLOCK_FLAG_RECOVERY_1 |
					   VB2_KEYBLOCK_FLAG_DEVELOPER_0 |
					   VB2_KEYBLOCK_FLAG_MINIOS_0;
	test_load_kernel(VB2_ERROR_LK_INVALID_KERNEL_FOUND,
			 "Keyblock rec flag mismatch");

	ResetMocks();
	mock_parts[0].kbh.keyblock_flags = VB2_KEYBLOCK_FLAG_RECOVERY_0 |
					   VB2_KEYBLOCK_FLAG_DEVELOPER_0 |
					   VB2_KEYBLOCK_FLAG_MINIOS_1;
	test_load_kernel(VB2_ERROR_LK_INVALID_KERNEL_FOUND,
			 "Keyblock minios flag mismatch");

	ResetMocks();
	SET_BOOT_MODE(ctx, VB2_BOOT_MODE_MANUAL_RECOVERY,
		      VB2_RECOVERY_RO_MANUAL);
	mock_parts[0].kbh.keyblock_flags = VB2_KEYBLOCK_FLAG_RECOVERY_1 |
					   VB2_KEYBLOCK_FLAG_DEVELOPER_1 |
					   VB2_KEYBLOCK_FLAG_MINIOS_0;
	test_load_kernel(VB2_ERROR_LK_INVALID_KERNEL_FOUND,
			 "Keyblock recdev flag mismatch");

	ResetMocks();
	SET_BOOT_MODE(ctx, VB2_BOOT_MODE_MANUAL_RECOVERY,
		      VB2_RECOVERY_RO_MANUAL);
	mock_parts[0].kbh.keyblock_flags = VB2_KEYBLOCK_FLAG_RECOVERY_1 |
					   VB2_KEYBLOCK_FLAG_DEVELOPER_0 |
					   VB2_KEYBLOCK_FLAG_MINIOS_0;
	test_load_kernel(VB2_SUCCESS, "Keyblock rec flag okay");

	ResetMocks();
	SET_BOOT_MODE(ctx, VB2_BOOT_MODE_MANUAL_RECOVERY,
		      VB2_RECOVERY_RO_MANUAL);
	ctx->flags |= VB2_CONTEXT_DEVELOPER_MODE;
	mock_parts[0].kbh.keyblock_flags = VB2_KEYBLOCK_FLAG_RECOVERY_1 |
					   VB2_KEYBLOCK_FLAG_DEVELOPER_0 |
					   VB2_KEYBLOCK_FLAG_MINIOS_0;
	test_load_kernel(VB2_ERROR_LK_INVALID_KERNEL_FOUND,
			 "Keyblock rec!dev flag mismatch");

	ResetMocks();
	SET_BOOT_MODE(ctx, VB2_BOOT_MODE_MANUAL_RECOVERY,
		      VB2_RECOVERY_RO_MANUAL);
	ctx->flags |= VB2_CONTEXT_DEVELOPER_MODE;
	mock_parts[0].kbh.keyblock_flags = VB2_KEYBLOCK_FLAG_RECOVERY_1 |
					   VB2_KEYBLOCK_FLAG_DEVELOPER_1 |
					   VB2_KEYBLOCK_FLAG_MINIOS_0;
	test_load_kernel(VB2_SUCCESS, "Keyblock recdev flag okay");

	/* Check keyblock flags (dev mode + signed kernel required) */
	ResetMocks();
	SET_BOOT_MODE(ctx, VB2_BOOT_MODE_DEVELOPER);
	vb2_nv_set(ctx, VB2_NV_DEV_BOOT_SIGNED_ONLY, 1);
	mock_parts[0].kbh.keyblock_flags = VB2_KEYBLOCK_FLAG_RECOVERY_1 |
					   VB2_KEYBLOCK_FLAG_DEVELOPER_0 |
					   VB2_KEYBLOCK_FLAG_MINIOS_0;
	test_load_kernel(VB2_ERROR_LK_INVALID_KERNEL_FOUND,
			 "Keyblock dev flag mismatch (signed kernel required)");

	ResetMocks();
	SET_BOOT_MODE(ctx, VB2_BOOT_MODE_DEVELOPER);
	fwmp->flags |= VB2_SECDATA_FWMP_DEV_ENABLE_OFFICIAL_ONLY;
	mock_parts[0].kbh.keyblock_flags = VB2_KEYBLOCK_FLAG_RECOVERY_1 |
					   VB2_KEYBLOCK_FLAG_DEVELOPER_0 |
					   VB2_KEYBLOCK_FLAG_MINIOS_0;
	test_load_kernel(VB2_ERROR_LK_INVALID_KERNEL_FOUND,
			 "Keyblock dev flag mismatch (signed kernel required)");

	ResetMocks();
	SET_BOOT_MODE(ctx, VB2_BOOT_MODE_DEVELOPER);
	fwmp->flags |= VB2_SECDATA_FWMP_DEV_ENABLE_OFFICIAL_ONLY;
	mock_parts[0].kbh.keyblock_flags = VB2_KEYBLOCK_FLAG_RECOVERY_0 |
					   VB2_KEYBLOCK_FLAG_DEVELOPER_0 |
					   VB2_KEYBLOCK_FLAG_MINIOS_1;
	test_load_kernel(VB2_ERROR_LK_INVALID_KERNEL_FOUND,
			 "Keyblock dev flag mismatch (signed kernel required)");

	ResetMocks();
	SET_BOOT_MODE(ctx, VB2_BOOT_MODE_DEVELOPER);
	vb2_nv_set(ctx, VB2_NV_DEV_BOOT_SIGNED_ONLY, 1);
	mock_parts[0].kbh.keyblock_flags = VB2_KEYBLOCK_FLAG_RECOVERY_0 |
					   VB2_KEYBLOCK_FLAG_DEVELOPER_1 |
					   VB2_KEYBLOCK_FLAG_MINIOS_0;
	test_load_kernel(VB2_SUCCESS,
			 "Keyblock dev flag okay (signed kernel required)");

	/* Check kernel key version */
	ResetMocks();
	mock_parts[0].kbh.data_key.key_version = 1;
	test_load_kernel(VB2_ERROR_LK_INVALID_KERNEL_FOUND,
			 "Keyblock kernel key rollback");

	ResetMocks();
	mock_parts[0].kbh.data_key.key_version = 0x10000;
	test_load_kernel(VB2_ERROR_LK_INVALID_KERNEL_FOUND,
			 "Keyblock kernel key version too big");

	ResetMocks();
	mock_parts[0].kbh.data_key.key_version = 3;
	test_load_kernel(VB2_SUCCESS, "Keyblock version roll forward");
	TEST_EQ(sd->kernel_version, 0x30001, "  SD version");
	TEST_EQ(sd->kernel_version_secdata, 0x30001, "  SD write back");

	ResetMocks();
	memcpy(&mock_parts[1].kbh, &mock_parts[0].kbh,
	       sizeof(mock_parts[0].kbh));
	mock_parts[0].kbh.data_key.key_version = 4;
	mock_parts[1].start = 300;
	mock_parts[1].size = 150;
	mock_parts[1].kbh.data_key.key_version = 3;
	test_load_kernel(VB2_SUCCESS, "Two kernels roll forward");
	TEST_EQ(mock_part_next, 2, "  read both");
	TEST_EQ(sd->kernel_version, 0x40001, "  SD version");
	TEST_EQ(sd->kernel_version_secdata, 0x30001, "  SD write back");

	ResetMocks();
	mock_parts[0].kbh.data_key.key_version = 1;
	SET_BOOT_MODE(ctx, VB2_BOOT_MODE_DEVELOPER);
	test_load_kernel(VB2_SUCCESS, "Key version ignored in dev mode");

	ResetMocks();
	mock_parts[0].kbh.data_key.key_version = 1;
	SET_BOOT_MODE(ctx, VB2_BOOT_MODE_MANUAL_RECOVERY,
		      VB2_RECOVERY_RO_MANUAL);
	test_load_kernel(VB2_SUCCESS, "Key version ignored in rec mode");

	ResetMocks();
	unpack_key_fail = 2;
	test_load_kernel(VB2_ERROR_LK_INVALID_KERNEL_FOUND, "Bad data key");

	ResetMocks();
	preamble_verify_fail = 1;
	test_load_kernel(VB2_ERROR_LK_INVALID_KERNEL_FOUND, "Bad preamble");

	ResetMocks();
	kph.kernel_version = 0;
	test_load_kernel(VB2_ERROR_LK_INVALID_KERNEL_FOUND,
			 "Kernel version rollback");

	ResetMocks();
	kph.kernel_version = 0;
	SET_BOOT_MODE(ctx, VB2_BOOT_MODE_DEVELOPER);
	test_load_kernel(VB2_SUCCESS, "Kernel version ignored in dev mode");

	ResetMocks();
	kph.kernel_version = 0;
	SET_BOOT_MODE(ctx, VB2_BOOT_MODE_MANUAL_RECOVERY,
		      VB2_RECOVERY_RO_MANUAL);
	test_load_kernel(VB2_SUCCESS, "Kernel version ignored in rec mode");

	/* Check kernel version (dev mode + signed kernel required) */
	ResetMocks();
	mock_parts[0].kbh.data_key.key_version = 0;
	SET_BOOT_MODE(ctx, VB2_BOOT_MODE_DEVELOPER);
	vb2_nv_set(ctx, VB2_NV_DEV_BOOT_SIGNED_ONLY, 1);
	test_load_kernel(VB2_ERROR_LK_INVALID_KERNEL_FOUND,
			 "Keyblock key version checked in dev mode "
			 "(signed kernel required)");

	ResetMocks();
	mock_parts[0].kbh.data_key.key_version = 0;
	SET_BOOT_MODE(ctx, VB2_BOOT_MODE_DEVELOPER);
	fwmp->flags |= VB2_SECDATA_FWMP_DEV_ENABLE_OFFICIAL_ONLY;
	test_load_kernel(VB2_ERROR_LK_INVALID_KERNEL_FOUND,
			 "Keyblock key version checked in dev mode "
			 "(signed kernel required)");

	/* Check developer key hash - bad */
	ResetMocks();
	SET_BOOT_MODE(ctx, VB2_BOOT_MODE_DEVELOPER);
	fwmp->flags |= VB2_SECDATA_FWMP_DEV_USE_KEY_HASH;
	fwmp->dev_key_hash[0]++;
	test_load_kernel(VB2_ERROR_LK_INVALID_KERNEL_FOUND,
			 "Fail keyblock dev fwmp hash");

	/* Check developer key hash - bad (recovery mode) */
	ResetMocks();
	SET_BOOT_MODE(ctx, VB2_BOOT_MODE_MANUAL_RECOVERY,
		      VB2_RECOVERY_RO_MANUAL);
	fwmp->flags |= VB2_SECDATA_FWMP_DEV_USE_KEY_HASH;
	fwmp->dev_key_hash[0]++;
	test_load_kernel(VB2_SUCCESS,
			 "Bad keyblock dev fwmp hash ignored in rec mode");

	/* Check developer key hash - good */
	ResetMocks();
	SET_BOOT_MODE(ctx, VB2_BOOT_MODE_DEVELOPER);
	fwmp->flags |= VB2_SECDATA_FWMP_DEV_USE_KEY_HASH;
	test_load_kernel(VB2_SUCCESS, "Good keyblock dev fwmp hash");

	ResetMocks();
	kph.preamble_size |= 0x07;
	test_load_kernel(VB2_ERROR_LK_INVALID_KERNEL_FOUND,
			 "Kernel body offset");

	ResetMocks();
	kph.preamble_size += 65536;
	test_load_kernel(VB2_ERROR_LK_INVALID_KERNEL_FOUND,
			 "Kernel body offset huge");

	/* Check getting kernel load address from header */
	ResetMocks();
	kph.body_load_address = (size_t)kernel_buffer;
	lkp.kernel_buffer = NULL;
	test_load_kernel(VB2_SUCCESS, "Get load address from preamble");
	TEST_PTR_EQ(lkp.kernel_buffer, kernel_buffer, "  address");
	/* Size is rounded up to nearest sector */
	TEST_EQ(lkp.kernel_buffer_size, 70144, "  size");
	/* Bootloader offset is relative to body load address */
	TEST_EQ(lkp.bootloader_offset, 0xbeadd008 - kph.body_load_address,
		"  bootloader offset");

	ResetMocks();
	lkp.kernel_buffer_size = 8192;
	test_load_kernel(VB2_ERROR_LK_INVALID_KERNEL_FOUND,
			 "Kernel too big for buffer");

	ResetMocks();
	mock_parts[0].size = 130;
	test_load_kernel(VB2_ERROR_LK_INVALID_KERNEL_FOUND,
			 "Kernel too big for partition");

	ResetMocks();
	kph.body_signature.data_size = 8192;
	test_load_kernel(VB2_SUCCESS, "Kernel tiny");

	ResetMocks();
	disk_read_to_fail = 228;
	test_load_kernel(VB2_ERROR_LK_INVALID_KERNEL_FOUND,
			 "Fail reading kernel data");

	ResetMocks();
	verify_data_fail = 1;
	test_load_kernel(VB2_ERROR_LK_INVALID_KERNEL_FOUND, "Bad data");

	/* Check that EXTERNAL_GPT flag makes it down */
	ResetMocks();
	disk_info.flags |= VB2_DISK_FLAG_EXTERNAL_GPT;
	test_load_kernel(VB2_SUCCESS, "Succeed external GPT");
	TEST_EQ(gpt_flag_external, 1, "GPT was external");

	/* Check recovery from unreadble primary GPT */
	ResetMocks();
	disk_read_to_fail = 1;
	test_load_kernel(VB2_SUCCESS, "Can't read disk");
}

int main(void)
{
	invalid_params_tests();
	load_kernel_tests();

	return gTestSuccess ? 0 : 255;
}
