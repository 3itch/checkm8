/* Copyright 2020 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * Tests for crossystem flashrom-based nvdata functions.
 */

#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "2api.h"
#include "2common.h"
#include "2constants.h"
#include "2nvstorage.h"
#include "2return_codes.h"
#include "common/tests.h"
#include "crossystem_vbnv.h"
#include "flashrom.h"

/* Mocked flashrom only supports host programmer, and RW_NVRAM
   region. */
static void assert_mock_params(const char *programmer, const char *region)
{
	TEST_STR_EQ(programmer, FLASHROM_PROGRAMMER_INTERNAL_AP,
		    "Using internal AP programmer");
	TEST_STR_EQ(region, "RW_NVRAM", "Using NVRAM region");
}

static bool mock_flashrom_fail;

/* To support both 16-byte and 64-byte nvdata with the same fake
   eeprom, we can size the flash chip to be 16x64. So, for 16-byte
   nvdata, this is a flash chip with 64 entries, and for 64-byte
   nvdata, this is a flash chip with 16 entries. */
static uint8_t fake_flash_region[VB2_NVDATA_SIZE * VB2_NVDATA_SIZE_V2];
static int fake_flash_entry_count;

static const uint8_t test_nvdata_16b[] = {
	0x60, 0x10, 0x00, 0x00, 0x00, 0x02, 0x00, 0x4e,
	0x00, 0xfe, 0xff, 0x00, 0x00, 0xff, 0xff, 0x5e,
};

static const uint8_t test_nvdata2_16b[] = {
	0x60, 0x10, 0x00, 0x00, 0x00, 0x02, 0x00, 0x4c,
	0x00, 0xfe, 0xff, 0x00, 0x00, 0xff, 0xff, 0x78,
};

static const uint8_t blank_nvdata_16b[] = {
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
};

static void reset_test_data(struct vb2_context *ctx, int nvdata_size)
{
	/* Initialize the context value. */
	ctx->flags = 0;

	switch (nvdata_size) {
	case VB2_NVDATA_SIZE:
		fake_flash_entry_count = VB2_NVDATA_SIZE_V2;
		memcpy(ctx->nvdata, test_nvdata_16b, sizeof(test_nvdata_16b));
		break;
	case VB2_NVDATA_SIZE_V2:
		ctx->flags |= VB2_CONTEXT_NVDATA_V2;
		fake_flash_entry_count = VB2_NVDATA_SIZE;
		/* TODO: create some test data for 64-byte nvdata and
		   put it here. Right now, this only tests 16-byte
		   nvdata. */
		break;
	default:
		/* This is not valid. */
		TEST_TRUE(false, "Test failed, invalid nvdata size");
		fake_flash_entry_count = 0;
		break;
	}

	/* Clear the fake flash chip. */
	memset(fake_flash_region, 0xff, sizeof(fake_flash_region));

	/* Flashrom succeeds unless the test says otherwise. */
	mock_flashrom_fail = false;
}

/* Mocked flashrom_read for tests. */
vb2_error_t flashrom_read(struct firmware_image *image, const char *region)
{
	if (mock_flashrom_fail) {
		image->data = NULL;
		image->size = 0;
		return VB2_ERROR_FLASHROM;
	}

	assert_mock_params(image->programmer, region);

	image->data = malloc(sizeof(fake_flash_region));
	image->size = sizeof(fake_flash_region);
	memcpy(image->data, fake_flash_region, sizeof(fake_flash_region));
	return VB2_SUCCESS;
}

/* Mocked flashrom_write for tests. */
vb2_error_t flashrom_write(struct firmware_image *image, const char *region)
{
	if (mock_flashrom_fail)
		return VB2_ERROR_FLASHROM;

	assert_mock_params(image->programmer, region);

	TEST_EQ(image->size, sizeof(fake_flash_region),
		"The flash size is correct");
	memcpy(fake_flash_region, image->data, image->size);
	return VB2_SUCCESS;
}

static void test_read_ok_beginning(void)
{
	struct vb2_context ctx;

	reset_test_data(&ctx, sizeof(test_nvdata_16b));
	memcpy(fake_flash_region, test_nvdata2_16b, sizeof(test_nvdata2_16b));

	TEST_EQ(vb2_read_nv_storage_flashrom(&ctx), 0,
		"Reading storage succeeds");
	TEST_EQ(memcmp(ctx.nvdata, test_nvdata2_16b, sizeof(test_nvdata2_16b)),
		0, "The nvdata in the vb2_context was updated from flash");
}

static void test_read_ok_2ndentry(void)
{
	struct vb2_context ctx;

	reset_test_data(&ctx, sizeof(test_nvdata_16b));
	memcpy(fake_flash_region, test_nvdata_16b, sizeof(test_nvdata_16b));
	memcpy(fake_flash_region + VB2_NVDATA_SIZE, test_nvdata2_16b,
	       sizeof(test_nvdata2_16b));

	TEST_EQ(vb2_read_nv_storage_flashrom(&ctx), 0,
		"Reading storage succeeds");
	TEST_EQ(memcmp(ctx.nvdata, test_nvdata2_16b, sizeof(test_nvdata2_16b)),
		0, "The nvdata in the vb2_context was updated from flash");
}

static void test_read_ok_full(void)
{
	struct vb2_context ctx;

	reset_test_data(&ctx, sizeof(test_nvdata_16b));

	for (int entry = 0; entry < fake_flash_entry_count - 1; entry++)
		memcpy(fake_flash_region + (entry * VB2_NVDATA_SIZE),
		       test_nvdata_16b, sizeof(test_nvdata_16b));

	memcpy(fake_flash_region +
	       ((fake_flash_entry_count - 1) * VB2_NVDATA_SIZE),
	       test_nvdata2_16b, sizeof(test_nvdata2_16b));

	TEST_EQ(vb2_read_nv_storage_flashrom(&ctx), 0,
		"Reading storage succeeds");
	TEST_EQ(memcmp(ctx.nvdata, test_nvdata2_16b, sizeof(test_nvdata2_16b)),
		0, "The nvdata in the vb2_context was updated from flash");
}

static void test_read_fail_uninitialized(void)
{
	struct vb2_context ctx;

	reset_test_data(&ctx, sizeof(test_nvdata_16b));

	TEST_NEQ(vb2_read_nv_storage_flashrom(&ctx), 0,
		 "Reading storage fails when flash is erased");
}

static void test_read_fail_flashrom(void)
{
	struct vb2_context ctx;

	reset_test_data(&ctx, sizeof(test_nvdata_16b));
	memcpy(fake_flash_region, test_nvdata_16b, sizeof(test_nvdata_16b));
	mock_flashrom_fail = true;

	TEST_NEQ(vb2_read_nv_storage_flashrom(&ctx), 0,
		 "Reading storage fails when flashrom fails");
}

static void test_write_ok_uninitialized(void)
{
	struct vb2_context ctx;

	reset_test_data(&ctx, sizeof(test_nvdata_16b));
	memcpy(ctx.nvdata, test_nvdata2_16b, sizeof(test_nvdata2_16b));

	TEST_EQ(vb2_write_nv_storage_flashrom(&ctx), 0,
		"Writing storage succeeds when the flash is erased");
	TEST_EQ(memcmp(fake_flash_region, test_nvdata2_16b,
		       sizeof(test_nvdata2_16b)),
		0, "Entry 0 in the flash was written");
}

static void test_write_ok_beginning(void)
{
	struct vb2_context ctx;

	reset_test_data(&ctx, sizeof(test_nvdata_16b));
	memcpy(fake_flash_region, test_nvdata_16b, sizeof(test_nvdata_16b));
	memcpy(ctx.nvdata, test_nvdata2_16b, sizeof(test_nvdata2_16b));

	TEST_EQ(vb2_write_nv_storage_flashrom(&ctx), 0,
		"Writing storage succeeds");
	TEST_EQ(memcmp(fake_flash_region + VB2_NVDATA_SIZE, test_nvdata2_16b,
		       sizeof(test_nvdata2_16b)),
		0, "Entry 1 in the flash was written");
}

static void test_write_ok_2ndentry(void)
{
	struct vb2_context ctx;

	reset_test_data(&ctx, sizeof(test_nvdata_16b));
	memcpy(fake_flash_region, test_nvdata_16b, sizeof(test_nvdata_16b));
	memcpy(fake_flash_region + VB2_NVDATA_SIZE, test_nvdata_16b,
	       sizeof(test_nvdata_16b));
	memcpy(ctx.nvdata, test_nvdata2_16b, sizeof(test_nvdata2_16b));

	TEST_EQ(vb2_write_nv_storage_flashrom(&ctx), 0,
		"Writing storage succeeds");
	TEST_EQ(memcmp(fake_flash_region + (2 * VB2_NVDATA_SIZE),
		       test_nvdata2_16b, sizeof(test_nvdata2_16b)),
		0, "Entry 2 in the flash was written");
}

static void test_write_ok_full(void)
{
	struct vb2_context ctx;
	uint8_t expected_flash[sizeof(fake_flash_region)];

	reset_test_data(&ctx, sizeof(test_nvdata_16b));

	for (int entry = 0; entry < fake_flash_entry_count; entry++)
		memcpy(fake_flash_region + (entry * VB2_NVDATA_SIZE),
		       test_nvdata_16b, sizeof(test_nvdata_16b));

	memcpy(expected_flash, test_nvdata2_16b, sizeof(test_nvdata2_16b));
	memset(expected_flash + VB2_NVDATA_SIZE, 0xff,
	       sizeof(expected_flash) - VB2_NVDATA_SIZE);
	memcpy(ctx.nvdata, test_nvdata2_16b, sizeof(test_nvdata2_16b));

	TEST_EQ(vb2_write_nv_storage_flashrom(&ctx), 0,
		"Writing storage succeeds");
	TEST_EQ(memcmp(fake_flash_region, expected_flash,
		       sizeof(expected_flash)),
		0,
		"The flash was erased and the new entry was placed at "
		"the beginning");
}

static void test_write_ok_corrupted_flash(void)
{
	struct vb2_context ctx;

	reset_test_data(&ctx, sizeof(test_nvdata_16b));

	/* Entry 0 is blank, but entry 1 is used */
	memcpy(fake_flash_region + VB2_NVDATA_SIZE,
	       test_nvdata_16b, sizeof(test_nvdata_16b));
	memcpy(ctx.nvdata, test_nvdata2_16b, sizeof(test_nvdata2_16b));

	TEST_EQ(vb2_write_nv_storage_flashrom(&ctx), 0,
		"Writing corrupted storage succeeds");
	TEST_EQ(memcmp(fake_flash_region, test_nvdata2_16b,
		       sizeof(test_nvdata2_16b)),
		0, "Entry 0 in the flash was written");
	TEST_EQ(memcmp(fake_flash_region + VB2_NVDATA_SIZE,
		       blank_nvdata_16b, sizeof(blank_nvdata_16b)),
		0, "Entry 1 in the flash was erased");
	TEST_EQ(memcmp(fake_flash_region + (2 * VB2_NVDATA_SIZE),
		       blank_nvdata_16b, sizeof(blank_nvdata_16b)),
		0, "Entry 2 in the flash was not written");
}

static void test_write_fail_flashrom(void)
{
	struct vb2_context ctx;

	reset_test_data(&ctx, sizeof(test_nvdata_16b));
	memcpy(fake_flash_region, test_nvdata_16b, sizeof(test_nvdata_16b));
	mock_flashrom_fail = true;

	TEST_NEQ(vb2_write_nv_storage_flashrom(&ctx), 0,
		 "Writing storage fails when flashrom fails");
}

int main(int argc, char *argv[])
{
	test_read_ok_beginning();
	test_read_ok_2ndentry();
	test_read_ok_full();
	test_read_fail_uninitialized();
	test_read_fail_flashrom();
	test_write_ok_uninitialized();
	test_write_ok_beginning();
	test_write_ok_2ndentry();
	test_write_ok_full();
	test_write_ok_corrupted_flash();
	test_write_fail_flashrom();

	return gTestSuccess ? 0 : 255;
}
