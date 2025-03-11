/* Copyright 2021 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * Tests for miniOS kernel selection, loading, verification, and booting.
 */

#include "2api.h"
#include "2common.h"
#include "2misc.h"
#include "2nvstorage.h"
#include "2secdata.h"
#include "common/boot_mode.h"
#include "common/tests.h"
#include "vboot_api.h"

#define MAX_MOCK_KERNELS 10
#define KBUF_SIZE 65536

/* Internal struct to simulate a stream for sector-based disks */
struct disk_stream {
	/* Disk handle */
	vb2ex_disk_handle_t handle;

	/* Next sector to read */
	uint64_t sector;

	/* Number of sectors left */
	uint64_t sectors_left;
};

/* Represent a "kernel" located on the disk */
struct mock_kernel {
	/* Sector where the kernel begins */
	uint64_t sector;

	/* Return value from vb2_load_partition */
	vb2_error_t rv;

	/* Number of times the sector was read */
	int read_count;
};

/* Mock data */
static struct vb2_context *ctx;
static struct vb2_shared_data *sd;
static struct vb2_workbuf wb;
static uint8_t workbuf[VB2_KERNEL_WORKBUF_RECOMMENDED_SIZE]
	__attribute__((aligned(VB2_WORKBUF_ALIGN)));

static struct vb2_kernel_params lkp;
static struct vb2_disk_info disk_info;
static struct vb2_keyblock kbh;
static struct vb2_kernel_preamble kph;
static uint8_t kernel_buffer[80000];

static struct mock_kernel kernels[MAX_MOCK_KERNELS];
static int kernel_count;
static struct mock_kernel *cur_kernel;

static void add_mock_kernel(uint64_t sector, vb2_error_t rv)
{
	if (kernel_count >= ARRAY_SIZE(kernels)) {
		TEST_TRUE(0, "  kernel_count ran out of entries!");
		return;
	}

	kernels[kernel_count].sector = sector;
	kernels[kernel_count].rv = rv;
	kernel_count++;
}

static void reset_common_data(void)
{
	TEST_SUCC(vb2api_init(workbuf, sizeof(workbuf), &ctx),
		  "vb2api_init failed");
	vb2_workbuf_from_ctx(ctx, &wb);
	vb2_nv_init(ctx);
	vb2api_secdata_kernel_create(ctx);
	vb2_secdata_kernel_init(ctx);
	ctx->flags = VB2_CONTEXT_RECOVERY_MODE;

	SET_BOOT_MODE(ctx, VB2_BOOT_MODE_MANUAL_RECOVERY,
		      VB2_RECOVERY_RO_MANUAL);

	sd = vb2_get_sd(ctx);
	sd->kernel_version_secdata = 0xabcdef | (1 << 24);

	memset(&lkp, 0, sizeof(lkp));
	lkp.kernel_buffer = kernel_buffer;
	lkp.kernel_buffer_size = sizeof(kernel_buffer);

	memset(&disk_info, 0, sizeof(disk_info));
	disk_info.bytes_per_lba = 512;
	disk_info.lba_count = 1024;
	disk_info.handle = (vb2ex_disk_handle_t)1;

	memset(&kbh, 0, sizeof(kbh));
	kbh.data_key.key_version = 2;
	kbh.keyblock_flags = VB2_KEYBLOCK_FLAG_DEVELOPER_0
		| VB2_KEYBLOCK_FLAG_DEVELOPER_1
		| VB2_KEYBLOCK_FLAG_RECOVERY_1
		| VB2_KEYBLOCK_FLAG_MINIOS_1;
	kbh.keyblock_size = sizeof(kbh);

	memset(&kph, 0, sizeof(kph));
	kph.kernel_version = 1;
	kph.preamble_size = 4096 - kbh.keyblock_size;
	kph.body_signature.data_size = 0;
	kph.bootloader_address = 0xbeadd008;
	kph.bootloader_size = 0x1234;


	memset(&kernels, 0, sizeof(kernels));
	kernel_count = 0;
	cur_kernel = NULL;
}

/* Mocks */

vb2_error_t VbExStreamOpen(vb2ex_disk_handle_t handle, uint64_t lba_start,
			   uint64_t lba_count, VbExStream_t *stream)
{
	struct disk_stream *s;
	uint64_t i;

	if (!handle) {
		*stream = NULL;
		return VB2_ERROR_UNKNOWN;
	}

	if (lba_start + lba_count > disk_info.lba_count)
		return VB2_ERROR_UNKNOWN;

	s = malloc(sizeof(*s));
	s->handle = handle;
	s->sector = lba_start;
	s->sectors_left = lba_count;

	*stream = (void *)s;

	for (i = 0; i < kernel_count; i++) {
		if (kernels[i].sector == lba_start)
			cur_kernel = &kernels[i];
	}

	return VB2_SUCCESS;
}

vb2_error_t VbExStreamRead(VbExStream_t stream, uint32_t bytes, void *buffer)
{
	struct disk_stream *s = (struct disk_stream *)stream;
	uint64_t sectors;
	uint64_t i;

	if (!s)
		return VB2_ERROR_UNKNOWN;

	/* For now, require reads to be a multiple of the LBA size */
	if (bytes % disk_info.bytes_per_lba)
		return VB2_ERROR_UNKNOWN;

	/* Fail on overflow */
	sectors = bytes / disk_info.bytes_per_lba;
	if (sectors > s->sectors_left)
		return VB2_ERROR_UNKNOWN;

	memset(buffer, 0, bytes);
	for (i = 0; i < kernel_count; i++) {
		if (kernels[i].sector >= s->sector &&
		    kernels[i].sector < s->sector + sectors) {
			VB2_DEBUG("Simulating kernel %" PRIu64 " match\n", i);
			uint64_t buf_offset = (kernels[i].sector - s->sector)
				* disk_info.bytes_per_lba;
			memcpy(buffer + buf_offset, VB2_KEYBLOCK_MAGIC,
			       VB2_KEYBLOCK_MAGIC_SIZE);
			kernels[i].read_count++;
			TEST_TRUE(kernels[i].read_count <= 2,
				  "  Max read count exceeded");
		}
	}

	s->sector += sectors;
	s->sectors_left -= sectors;

	return VB2_SUCCESS;
}

void VbExStreamClose(VbExStream_t stream)
{
	free(stream);
}

vb2_error_t vb2_unpack_key_buffer(struct vb2_public_key *key,
				  const uint8_t *buf, uint32_t size)
{
	return cur_kernel->rv;
}

vb2_error_t vb2_verify_keyblock(struct vb2_keyblock *block, uint32_t size,
				const struct vb2_public_key *key,
				const struct vb2_workbuf *w)
{
	/* Use this as an opportunity to override the keyblock */
	memcpy((void *)block, &kbh, sizeof(kbh));

	return cur_kernel->rv;
}

vb2_error_t vb2_verify_keyblock_hash(const struct vb2_keyblock *block,
				     uint32_t size,
				     const struct vb2_workbuf *w)
{
	/* Use this as an opportunity to override the keyblock */
	memcpy((void *)block, &kbh, sizeof(kbh));

	return cur_kernel->rv;
}

vb2_error_t vb2_verify_kernel_preamble(struct vb2_kernel_preamble *preamble,
			       uint32_t size, const struct vb2_public_key *key,
			       const struct vb2_workbuf *w)
{
	/* Use this as an opportunity to override the preamble */
	memcpy((void *)preamble, &kph, sizeof(kph));

	return cur_kernel->rv;
}

vb2_error_t vb2_verify_data(const uint8_t *data, uint32_t size,
			    struct vb2_signature *sig,
			    const struct vb2_public_key *key,
			    const struct vb2_workbuf *w)
{
	return cur_kernel->rv;
}

vb2_error_t vb2_digest_finalize(struct vb2_digest_context *dc, uint8_t *digest,
				uint32_t digest_size)
{
	return cur_kernel->rv;
}

/* Make sure nothing tested here ever calls this directly. */
void vb2api_fail(struct vb2_context *c, uint8_t reason, uint8_t subcode)
{
	TEST_TRUE(0, "  called vb2api_fail()");
}

/* Tests */

static void load_minios_kernel_tests(void)
{
	reset_common_data();
	disk_info.bytes_per_lba = KBUF_SIZE;
	disk_info.lba_count = 1;
	add_mock_kernel(0, VB2_SUCCESS);
	TEST_SUCC(vb2api_load_minios_kernel(ctx, &lkp, &disk_info, 0),
		  "{valid kernel}");
	TEST_PTR_EQ(lkp.disk_handle, disk_info.handle,
		    "  fill disk_handle when success");

	reset_common_data();
	disk_info.bytes_per_lba = KBUF_SIZE;
	disk_info.lba_count = 1;
	TEST_EQ(vb2api_load_minios_kernel(ctx, &lkp, &disk_info, 0),
		VB2_ERROR_LK_NO_KERNEL_FOUND, "{no kernel}");

	reset_common_data();
	disk_info.bytes_per_lba = KBUF_SIZE;
	disk_info.lba_count = 2;
	add_mock_kernel(1, VB2_SUCCESS);
	TEST_SUCC(vb2api_load_minios_kernel(ctx, &lkp, &disk_info, 0),
		  "{no kernel, valid kernel}");
	TEST_EQ(cur_kernel->sector, 1, "  select kernel");
	TEST_PTR_EQ(lkp.disk_handle, disk_info.handle,
		    "  fill disk_handle when success");

	reset_common_data();
	disk_info.bytes_per_lba = KBUF_SIZE;
	disk_info.lba_count = 2;
	add_mock_kernel(0, VB2_ERROR_MOCK);
	add_mock_kernel(1, VB2_SUCCESS);
	TEST_SUCC(vb2api_load_minios_kernel(ctx, &lkp, &disk_info, 0),
		  "{invalid kernel, valid kernel}");
	TEST_EQ(cur_kernel->sector, 1, "  select second kernel");
	TEST_PTR_EQ(lkp.disk_handle, disk_info.handle,
		    "  fill disk_handle when success");

	reset_common_data();
	disk_info.bytes_per_lba = KBUF_SIZE;
	disk_info.lba_count = 2;
	add_mock_kernel(0, VB2_ERROR_MOCK);
	add_mock_kernel(1, VB2_ERROR_MOCK);
	TEST_EQ(vb2api_load_minios_kernel(ctx, &lkp, &disk_info, 0),
		VB2_ERROR_LK_NO_KERNEL_FOUND,
		"{invalid kernel, invalid kernel}");

	reset_common_data();
	disk_info.bytes_per_lba = KBUF_SIZE;
	disk_info.lba_count = 2;
	add_mock_kernel(0, VB2_SUCCESS);
	add_mock_kernel(1, VB2_SUCCESS);
	TEST_SUCC(vb2api_load_minios_kernel(ctx, &lkp, &disk_info, 0),
		  "{valid kernel, valid kernel} minios_priority=0");
	TEST_EQ(cur_kernel->sector, 0, "  select first kernel");
	TEST_PTR_EQ(lkp.disk_handle, disk_info.handle,
		    "  fill disk_handle when success");

	reset_common_data();
	disk_info.bytes_per_lba = KBUF_SIZE;
	disk_info.lba_count = 2;
	add_mock_kernel(0, VB2_SUCCESS);
	add_mock_kernel(1, VB2_SUCCESS);
	vb2_nv_set(ctx, VB2_NV_MINIOS_PRIORITY, 1);
	TEST_SUCC(vb2api_load_minios_kernel(ctx, &lkp, &disk_info, 0),
		  "{valid kernel, valid kernel} minios_priority=1");
	TEST_EQ(cur_kernel->sector, 1, "  select second kernel");
	TEST_PTR_EQ(lkp.disk_handle, disk_info.handle,
		    "  fill disk_handle when success");

	reset_common_data();
	disk_info.bytes_per_lba = KBUF_SIZE;
	disk_info.lba_count = 2;
	add_mock_kernel(0, VB2_SUCCESS);
	add_mock_kernel(1, VB2_SUCCESS);
	TEST_SUCC(vb2api_load_minios_kernel(ctx, &lkp, &disk_info,
					    VB2_MINIOS_FLAG_NON_ACTIVE),
		  "{valid kernel, valid kernel} minios_priority=0 non-active");
	TEST_EQ(cur_kernel->sector, 1, "  select second kernel");
	TEST_PTR_EQ(lkp.disk_handle, disk_info.handle,
		    "  fill disk_handle when success");

	reset_common_data();
	disk_info.bytes_per_lba = KBUF_SIZE;
	disk_info.lba_count = 2;
	add_mock_kernel(0, VB2_ERROR_MOCK);
	add_mock_kernel(1, VB2_SUCCESS);
	vb2_nv_set(ctx, VB2_NV_MINIOS_PRIORITY, 1);
	TEST_EQ(vb2api_load_minios_kernel(ctx, &lkp, &disk_info,
					  VB2_MINIOS_FLAG_NON_ACTIVE),
		VB2_ERROR_LK_NO_KERNEL_FOUND,
		"{invalid kernel, valid kernel} minios_priority=1 non-active");

	reset_common_data();
	disk_info.bytes_per_lba = VB2_KEYBLOCK_MAGIC_SIZE;
	disk_info.lba_count = 4;
	add_mock_kernel(1, VB2_SUCCESS);
	TEST_EQ(vb2api_load_minios_kernel(ctx, &lkp, &disk_info, 0),
		VB2_ERROR_LK_NO_KERNEL_FOUND,
		"valid kernel header near start of disk (disk too small)");

	reset_common_data();
	disk_info.bytes_per_lba = VB2_KEYBLOCK_MAGIC_SIZE;
	disk_info.lba_count = 1000;
	add_mock_kernel(999, VB2_SUCCESS);
	TEST_EQ(vb2api_load_minios_kernel(ctx, &lkp, &disk_info, 0),
		VB2_ERROR_LK_NO_KERNEL_FOUND,
		"valid kernel header near end of disk");

	reset_common_data();
	disk_info.bytes_per_lba = 1024;
	disk_info.lba_count = 128;
	add_mock_kernel(63, VB2_SUCCESS);
	TEST_SUCC(vb2api_load_minios_kernel(ctx, &lkp, &disk_info, 0),
		  "start/end overlap assuming >128 MB search range (start)");
	TEST_PTR_EQ(lkp.disk_handle, disk_info.handle,
		    "  fill disk_handle when success");

	reset_common_data();
	disk_info.bytes_per_lba = 1024;
	disk_info.lba_count = 128;
	add_mock_kernel(64, VB2_SUCCESS);
	TEST_SUCC(vb2api_load_minios_kernel(ctx, &lkp, &disk_info, 0),
		  "start/end overlap assuming >128 MB search range (end)");
	TEST_PTR_EQ(lkp.disk_handle, disk_info.handle,
		    "  fill disk_handle when success");

	reset_common_data();
	disk_info.bytes_per_lba = 128;
	disk_info.lba_count = 1024;
	add_mock_kernel(3, VB2_SUCCESS);
	TEST_SUCC(vb2api_load_minios_kernel(ctx, &lkp, &disk_info, 0),
		  "kernel at last sector in batch assuming 512 KB batches");
	TEST_PTR_EQ(lkp.disk_handle, disk_info.handle,
		    "  fill disk_handle when success");

	reset_common_data();
	disk_info.bytes_per_lba = 256;
	disk_info.lba_count = 1024;
	add_mock_kernel(3, VB2_SUCCESS);
	TEST_SUCC(vb2api_load_minios_kernel(ctx, &lkp, &disk_info, 0),
		  "kernel at last sector in batch assuming 1 MB batches");
	TEST_PTR_EQ(lkp.disk_handle, disk_info.handle,
		    "  fill disk_handle when success");

	reset_common_data();
	disk_info.bytes_per_lba = 512;
	disk_info.lba_count = 1024;
	add_mock_kernel(3, VB2_SUCCESS);
	TEST_SUCC(vb2api_load_minios_kernel(ctx, &lkp, &disk_info, 0),
		  "kernel at last sector in batch assuming 2 MB batches");
	TEST_PTR_EQ(lkp.disk_handle, disk_info.handle,
		    "  fill disk_handle when success");

	reset_common_data();
	kbh.keyblock_flags = VB2_KEYBLOCK_FLAG_DEVELOPER_0
		| VB2_KEYBLOCK_FLAG_RECOVERY_1
		| VB2_KEYBLOCK_FLAG_MINIOS_1;
	disk_info.bytes_per_lba = KBUF_SIZE;
	disk_info.lba_count = 2;
	add_mock_kernel(0, VB2_SUCCESS);
	TEST_SUCC(vb2api_load_minios_kernel(ctx, &lkp, &disk_info, 0),
		  "kernel with minios keyblock flag");
	TEST_PTR_EQ(lkp.disk_handle, disk_info.handle,
		    "  fill disk_handle when success");

	reset_common_data();
	kbh.keyblock_flags = VB2_KEYBLOCK_FLAG_DEVELOPER_0
		| VB2_KEYBLOCK_FLAG_RECOVERY_1
		| VB2_KEYBLOCK_FLAG_MINIOS_0;
	disk_info.bytes_per_lba = KBUF_SIZE;
	disk_info.lba_count = 2;
	add_mock_kernel(0, VB2_SUCCESS);
	TEST_EQ(vb2api_load_minios_kernel(ctx, &lkp, &disk_info, 0),
		VB2_ERROR_LK_NO_KERNEL_FOUND,
		"kernel with !minios keyblock flag");

	reset_common_data();
	disk_info.bytes_per_lba = KBUF_SIZE;
	disk_info.lba_count = 2;
	add_mock_kernel(0, VB2_SUCCESS);
	sd->kernel_version_secdata = 5 << 24;
	kph.kernel_version = 4;
	TEST_EQ(vb2api_load_minios_kernel(ctx, &lkp, &disk_info, 0),
		VB2_ERROR_LK_NO_KERNEL_FOUND,
		"kernel version too old");

	reset_common_data();
	disk_info.bytes_per_lba = KBUF_SIZE;
	disk_info.lba_count = 2;
	add_mock_kernel(0, VB2_SUCCESS);
	sd->kernel_version_secdata = 5 << 24;
	kph.kernel_version = 0x100;
	TEST_EQ(vb2api_load_minios_kernel(ctx, &lkp, &disk_info, 0),
		VB2_ERROR_LK_NO_KERNEL_FOUND,
		"kernel version greater than 0xff");

	reset_common_data();
	disk_info.bytes_per_lba = KBUF_SIZE;
	disk_info.lba_count = 2;
	add_mock_kernel(0, VB2_SUCCESS);
	sd->kernel_version_secdata = 5 << 24;
	kbh.data_key.key_version = 5;
	kph.kernel_version = 6;
	TEST_SUCC(vb2api_load_minios_kernel(ctx, &lkp, &disk_info, 0),
		  "newer kernel version");
	TEST_EQ(sd->kernel_version, 0x50006, "  SD kernel version");
	TEST_PTR_EQ(lkp.disk_handle, disk_info.handle,
		    "  fill disk_handle when success");
}

int main(void)
{
	load_minios_kernel_tests();

	return gTestSuccess ? 0 : 255;
}
