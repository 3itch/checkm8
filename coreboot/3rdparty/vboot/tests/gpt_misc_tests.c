/* Copyright 2013 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * Tests for vboot_kernel.c
 */

#include "2api.h"
#include "cgptlib.h"
#include "cgptlib_internal.h"
#include "common/tests.h"
#include "gpt.h"

#define LOGCALL(fmt, args...) sprintf(call_log + strlen(call_log), fmt, ##args)
#define TEST_CALLS(expect_log) TEST_STR_EQ(call_log, expect_log, "  calls")

/* Assumes 512-byte disk sectors */
#define MOCK_SECTOR_SIZE  512
#define MOCK_SECTOR_COUNT 1024

/* Mock kernel partition */
struct mock_part {
	uint32_t start;
	uint32_t size;
};

/* Mock data */
static char call_log[4096];
static int disk_read_to_fail;
static int disk_write_to_fail;

static vb2ex_disk_handle_t handle;
static uint8_t mock_disk[MOCK_SECTOR_SIZE * MOCK_SECTOR_COUNT];
static GptHeader *mock_gpt_primary =
	(GptHeader*)&mock_disk[MOCK_SECTOR_SIZE * 1];
static GptHeader *mock_gpt_secondary =
	(GptHeader*)&mock_disk[MOCK_SECTOR_SIZE * (MOCK_SECTOR_COUNT - 1)];

/**
 * Prepare a valid GPT header that will pass CheckHeader() tests
 */
static void SetupGptHeader(GptHeader *h, int is_secondary)
{
	memset(h, '\0', MOCK_SECTOR_SIZE);

	/* "EFI PART" */
	memcpy(h->signature, GPT_HEADER_SIGNATURE, GPT_HEADER_SIGNATURE_SIZE);
	h->revision = GPT_HEADER_REVISION;
	h->size = MIN_SIZE_OF_HEADER;

	/* 16KB: 128 entries of 128 bytes */
	h->size_of_entry = sizeof(GptEntry);
	h->number_of_entries = MAX_NUMBER_OF_ENTRIES;

	/* Set LBA pointers for primary or secondary header */
	if (is_secondary) {
		h->my_lba = MOCK_SECTOR_COUNT - GPT_HEADER_SECTORS;
		h->entries_lba = h->my_lba - CalculateEntriesSectors(h,
							MOCK_SECTOR_SIZE);
	} else {
		h->my_lba = GPT_PMBR_SECTORS;
		h->entries_lba = h->my_lba + 1;
	}

	h->first_usable_lba = 2 + CalculateEntriesSectors(h, MOCK_SECTOR_SIZE);
	h->last_usable_lba = MOCK_SECTOR_COUNT - 2 - CalculateEntriesSectors(h,
								MOCK_SECTOR_SIZE);

	h->header_crc32 = HeaderCrc(h);
}

static void ResetCallLog(void)
{
	*call_log = 0;
}

/**
 * Reset mock data (for use before each test)
 */
static void ResetMocks(void)
{
	ResetCallLog();

	memset(&mock_disk, 0, sizeof(mock_disk));
	SetupGptHeader(mock_gpt_primary, 0);
	SetupGptHeader(mock_gpt_secondary, 1);

	disk_read_to_fail = -1;
	disk_write_to_fail = -1;
}

/* Mocks */

vb2_error_t VbExDiskRead(vb2ex_disk_handle_t h, uint64_t lba_start,
			 uint64_t lba_count, void *buffer)
{
	LOGCALL("VbExDiskRead(h, %d, %d)\n", (int)lba_start, (int)lba_count);

	if ((int)lba_start == disk_read_to_fail)
		return VB2_ERROR_MOCK;

	memcpy(buffer, &mock_disk[lba_start * MOCK_SECTOR_SIZE],
	       lba_count * MOCK_SECTOR_SIZE);

	return VB2_SUCCESS;
}

vb2_error_t VbExDiskWrite(vb2ex_disk_handle_t h, uint64_t lba_start,
			  uint64_t lba_count, const void *buffer)
{
	LOGCALL("VbExDiskWrite(h, %d, %d)\n", (int)lba_start, (int)lba_count);

	if ((int)lba_start == disk_write_to_fail)
		return VB2_ERROR_MOCK;

	memcpy(&mock_disk[lba_start * MOCK_SECTOR_SIZE], buffer,
	       lba_count * MOCK_SECTOR_SIZE);

	return VB2_SUCCESS;
}

/**
 * Test reading/writing GPT
 */
static void ReadWriteGptTest(void)
{
	GptData g;
	GptHeader *h;

	g.sector_bytes = MOCK_SECTOR_SIZE;
	g.streaming_drive_sectors = g.gpt_drive_sectors = MOCK_SECTOR_COUNT;
	g.valid_headers = g.valid_entries = MASK_BOTH;

	ResetMocks();
	TEST_EQ(AllocAndReadGptData(handle, &g), 0, "AllocAndRead");
	TEST_CALLS("VbExDiskRead(h, 1, 1)\n"
		   "VbExDiskRead(h, 2, 32)\n"
		   "VbExDiskRead(h, 1023, 1)\n"
		   "VbExDiskRead(h, 991, 32)\n");
	ResetCallLog();
	/*
	 * Valgrind complains about access to uninitialized memory here, so
	 * zero the primary header before each test.
	 */
	memset(g.primary_header, '\0', g.sector_bytes);
	TEST_EQ(WriteAndFreeGptData(handle, &g), 0, "WriteAndFree");
	TEST_CALLS("");

	/*
	 * Invalidate primary GPT header,
	 * check that AllocAndReadGptData still succeeds
	 */
	ResetMocks();
	memset(mock_gpt_primary, '\0', sizeof(*mock_gpt_primary));
	TEST_EQ(AllocAndReadGptData(handle, &g), 0,
		"AllocAndRead primary invalid");
	TEST_EQ(CheckHeader(mock_gpt_primary, 0, g.streaming_drive_sectors,
		g.gpt_drive_sectors, 0, g.sector_bytes),
		1, "Primary header is invalid");
	TEST_EQ(CheckHeader(mock_gpt_secondary, 1, g.streaming_drive_sectors,
		g.gpt_drive_sectors, 0, g.sector_bytes),
		0, "Secondary header is valid");
	TEST_CALLS("VbExDiskRead(h, 1, 1)\n"
		   "VbExDiskRead(h, 1023, 1)\n"
		   "VbExDiskRead(h, 991, 32)\n");
	WriteAndFreeGptData(handle, &g);

	/*
	 * Invalidate secondary GPT header,
	 * check that AllocAndReadGptData still succeeds
	 */
	ResetMocks();
	memset(mock_gpt_secondary, '\0', sizeof(*mock_gpt_secondary));
	TEST_EQ(AllocAndReadGptData(handle, &g), 0,
		"AllocAndRead secondary invalid");
	TEST_EQ(CheckHeader(mock_gpt_primary, 0, g.streaming_drive_sectors,
		g.gpt_drive_sectors, 0, g.sector_bytes),
		0, "Primary header is valid");
	TEST_EQ(CheckHeader(mock_gpt_secondary, 1, g.streaming_drive_sectors,
		g.gpt_drive_sectors, 0, g.sector_bytes),
		1, "Secondary header is invalid");
	TEST_CALLS("VbExDiskRead(h, 1, 1)\n"
		   "VbExDiskRead(h, 2, 32)\n"
		   "VbExDiskRead(h, 1023, 1)\n");
	WriteAndFreeGptData(handle, &g);

	/*
	 * Invalidate primary AND secondary GPT header,
	 * check that AllocAndReadGptData fails.
	 */
	ResetMocks();
	memset(mock_gpt_primary, '\0', sizeof(*mock_gpt_primary));
	memset(mock_gpt_secondary, '\0', sizeof(*mock_gpt_secondary));
	TEST_EQ(AllocAndReadGptData(handle, &g), 1,
		"AllocAndRead primary and secondary invalid");
	TEST_EQ(CheckHeader(mock_gpt_primary, 0, g.streaming_drive_sectors,
		g.gpt_drive_sectors, 0, g.sector_bytes),
		1, "Primary header is invalid");
	TEST_EQ(CheckHeader(mock_gpt_secondary, 1, g.streaming_drive_sectors,
		g.gpt_drive_sectors, 0, g.sector_bytes),
		1, "Secondary header is invalid");
	TEST_CALLS("VbExDiskRead(h, 1, 1)\n"
		   "VbExDiskRead(h, 1023, 1)\n");
	WriteAndFreeGptData(handle, &g);

	/*
	 * Invalidate primary GPT header and check that it is
	 * repaired by GptRepair().
	 *
	 * This would normally be called by vb2api_load_kernel()->GptInit()
	 * but this callback is mocked in these tests.
	 */
	ResetMocks();
	memset(mock_gpt_primary, '\0', sizeof(*mock_gpt_primary));
	TEST_EQ(AllocAndReadGptData(handle, &g), 0,
		"Fix Primary GPT: AllocAndRead");
	/* Call GptRepair() with input indicating secondary GPT is valid */
	g.valid_headers = g.valid_entries = MASK_SECONDARY;
	GptRepair(&g);
	TEST_EQ(WriteAndFreeGptData(handle, &g), 0,
		"Fix Primary GPT: WriteAndFreeGptData");
	TEST_CALLS("VbExDiskRead(h, 1, 1)\n"
		   "VbExDiskRead(h, 1023, 1)\n"
		   "VbExDiskRead(h, 991, 32)\n"
		   "VbExDiskWrite(h, 1, 1)\n"
		   "VbExDiskWrite(h, 2, 32)\n");
	TEST_EQ(CheckHeader(mock_gpt_primary, 0, g.streaming_drive_sectors,
		g.gpt_drive_sectors, 0, g.sector_bytes),
		0, "Fix Primary GPT: Primary header is valid");

	/*
	 * Invalidate secondary GPT header and check that it can be
	 * repaired by GptRepair().
	 *
	 * This would normally be called by vb2api_load_kernel()->GptInit()
	 * but this callback is mocked in these tests.
	 */
	ResetMocks();
	memset(mock_gpt_secondary, '\0', sizeof(*mock_gpt_secondary));
	TEST_EQ(AllocAndReadGptData(handle, &g), 0,
		"Fix Secondary GPT: AllocAndRead");
	/* Call GptRepair() with input indicating primary GPT is valid */
	g.valid_headers = g.valid_entries = MASK_PRIMARY;
	GptRepair(&g);
	TEST_EQ(WriteAndFreeGptData(handle, &g), 0,
		"Fix Secondary GPT: WriteAndFreeGptData");
	TEST_CALLS("VbExDiskRead(h, 1, 1)\n"
		   "VbExDiskRead(h, 2, 32)\n"
		   "VbExDiskRead(h, 1023, 1)\n"
		   "VbExDiskWrite(h, 1023, 1)\n"
		   "VbExDiskWrite(h, 991, 32)\n");
	TEST_EQ(CheckHeader(mock_gpt_secondary, 1, g.streaming_drive_sectors,
		g.gpt_drive_sectors, 0, g.sector_bytes),
		0, "Fix Secondary GPT: Secondary header is valid");

	/* Data which is changed is written */
	ResetMocks();
	AllocAndReadGptData(handle, &g);
	g.modified |= GPT_MODIFIED_HEADER1 | GPT_MODIFIED_ENTRIES1;
	ResetCallLog();
	memset(g.primary_header, '\0', g.sector_bytes);
	h = (GptHeader*)g.primary_header;
	h->entries_lba = 2;
	h->number_of_entries = MAX_NUMBER_OF_ENTRIES;
	h->size_of_entry = sizeof(GptEntry);
	TEST_EQ(WriteAndFreeGptData(handle, &g), 0, "WriteAndFree mod 1");
	TEST_CALLS("VbExDiskWrite(h, 1, 1)\n"
		   "VbExDiskWrite(h, 2, 32)\n");

	/* Data which is changed is written */
	ResetMocks();
	AllocAndReadGptData(handle, &g);
	g.modified = -1;
	ResetCallLog();
	memset(g.primary_header, '\0', g.sector_bytes);
	h = (GptHeader*)g.primary_header;
	h->entries_lba = 2;
	h->number_of_entries = MAX_NUMBER_OF_ENTRIES;
	h->size_of_entry = sizeof(GptEntry);
	h = (GptHeader*)g.secondary_header;
	h->entries_lba = 991;
	TEST_EQ(WriteAndFreeGptData(handle, &g), 0, "WriteAndFree mod all");
	TEST_CALLS("VbExDiskWrite(h, 1, 1)\n"
		   "VbExDiskWrite(h, 2, 32)\n"
		   "VbExDiskWrite(h, 1023, 1)\n"
		   "VbExDiskWrite(h, 991, 32)\n");

	/* If legacy signature, don't modify GPT header/entries 1 */
	ResetMocks();
	AllocAndReadGptData(handle, &g);
	h = (GptHeader *)g.primary_header;
	memcpy(h->signature, GPT_HEADER_SIGNATURE2, GPT_HEADER_SIGNATURE_SIZE);
	g.modified = -1;
	ResetCallLog();
	TEST_EQ(WriteAndFreeGptData(handle, &g), 0, "WriteAndFree mod all");
	TEST_CALLS("VbExDiskWrite(h, 1023, 1)\n"
		   "VbExDiskWrite(h, 991, 32)\n");

	/* Error reading */
	ResetMocks();
	disk_read_to_fail = 1;
	TEST_EQ(AllocAndReadGptData(handle, &g), 0, "AllocAndRead disk fail");
	g.valid_headers = g.valid_entries = MASK_SECONDARY;
	GptRepair(&g);
	ResetCallLog();
	TEST_EQ(WriteAndFreeGptData(handle, &g), 0, "WriteAndFree mod 1");
	TEST_CALLS("VbExDiskWrite(h, 1, 1)\n"
		   "VbExDiskWrite(h, 2, 32)\n");

	ResetMocks();
	disk_read_to_fail = 2;
	TEST_EQ(AllocAndReadGptData(handle, &g), 0, "AllocAndRead disk fail");
	g.valid_headers = MASK_BOTH;
	g.valid_entries = MASK_SECONDARY;
	GptRepair(&g);
	ResetCallLog();
	TEST_EQ(WriteAndFreeGptData(handle, &g), 0, "WriteAndFree mod 1");
	TEST_CALLS("VbExDiskWrite(h, 2, 32)\n");

	ResetMocks();
	disk_read_to_fail = 991;
	TEST_EQ(AllocAndReadGptData(handle, &g), 0, "AllocAndRead disk fail");
	g.valid_headers = MASK_BOTH;
	g.valid_entries = MASK_PRIMARY;
	GptRepair(&g);
	ResetCallLog();
	TEST_EQ(WriteAndFreeGptData(handle, &g), 0, "WriteAndFree mod 2");
	TEST_CALLS("VbExDiskWrite(h, 991, 32)\n");

	ResetMocks();
	disk_read_to_fail = 1023;
	TEST_EQ(AllocAndReadGptData(handle, &g), 0, "AllocAndRead disk fail");
	g.valid_headers = g.valid_entries = MASK_PRIMARY;
	GptRepair(&g);
	ResetCallLog();
	TEST_EQ(WriteAndFreeGptData(handle, &g), 0, "WriteAndFree mod 2");
	TEST_CALLS("VbExDiskWrite(h, 1023, 1)\n"
		   "VbExDiskWrite(h, 991, 32)\n");

	/* Error writing */
	ResetMocks();
	disk_write_to_fail = 1;
	AllocAndReadGptData(handle, &g);
	g.modified = -1;
	memset(g.primary_header, '\0', g.sector_bytes);
	TEST_NEQ(WriteAndFreeGptData(handle, &g), 0, "WriteAndFree disk fail");

	ResetMocks();
	disk_write_to_fail = 2;
	AllocAndReadGptData(handle, &g);
	g.modified = -1;
	memset(g.primary_header, '\0', g.sector_bytes);
	h = (GptHeader*)g.primary_header;
	h->entries_lba = 2;
	TEST_NEQ(WriteAndFreeGptData(handle, &g), 0, "WriteAndFree disk fail");

	ResetMocks();
	disk_write_to_fail = 991;
	AllocAndReadGptData(handle, &g);
	g.modified = -1;
	memset(g.primary_header, '\0', g.sector_bytes);
	TEST_NEQ(WriteAndFreeGptData(handle, &g), 0, "WriteAndFree disk fail");

	ResetMocks();
	disk_write_to_fail = 1023;
	AllocAndReadGptData(handle, &g);
	g.modified = -1;
	memset(g.primary_header, '\0', g.sector_bytes);
	TEST_NEQ(WriteAndFreeGptData(handle, &g), 0, "WriteAndFree disk fail");

}

int main(void)
{
	ReadWriteGptTest();

	return gTestSuccess ? 0 : 255;
}
