/* Copyright 2020 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * Tests for host flashrom utilities.
 */

/* For strdup */
#define _POSIX_C_SOURCE 200809L

#include <fcntl.h>
#include <getopt.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "2common.h"
#include "2return_codes.h"
#include "common/tests.h"
#include "host_misc.h"
#include "flashrom.h"
#include "subprocess.h"

#define MOCK_TMPFILE_NAME "/tmp/vb2_unittest"
#define MOCK_ROM_CONTENTS "bloop123"

static bool flashrom_mock_success = true;
static enum { FLASHROM_NONE, FLASHROM_READ, FLASHROM_WRITE } captured_operation;
static enum {
	FLASHROM_VERIFY_UNSPECIFIED,
	FLASHROM_VERIFY_FAST,
} captured_verify;
static const char *captured_op_filename;
static const char *captured_region_param;
static const char *captured_programmer;
static uint8_t *captured_rom_contents;
static uint32_t captured_rom_size;

/* Mocked mkstemp for tests. */
int mkstemp(char *template_name)
{
	strncpy(template_name, MOCK_TMPFILE_NAME, strlen(template_name));
	return open(template_name, O_RDWR | O_CREAT | O_TRUNC, 0666);
}

/* Mocked subprocess_run for tests. */
int subprocess_run(const char *const argv[],
		   struct subprocess_target *input,
		   struct subprocess_target *output,
		   struct subprocess_target *error)
{
	int argc;
	int opt;
	int rv;
	/* getopt_long wants an int instead of an enum, bummer... */
	int captured_verify_int = FLASHROM_VERIFY_UNSPECIFIED;
	struct option long_opts[] = {
		{
			.name = "noverify-all",
			.has_arg = no_argument,
			.flag = &captured_verify_int,
			.val = FLASHROM_VERIFY_FAST,
		},
	};

	/* Reset static variables to their defaults. */
	captured_operation = FLASHROM_NONE;
	captured_operation = FLASHROM_VERIFY_UNSPECIFIED;
	captured_op_filename = NULL;
	captured_region_param = NULL;
	captured_programmer = NULL;
	captured_rom_contents = NULL;
	captured_rom_size = 0;
	optind = 0;

	/* Count the number of arguments, a required formalism for
	   getopt. */
	for (argc = 0; argv[argc]; argc++)
		continue;

	/* We only understand the subset of arguments used by the
	   wrapper library.  If it's updated to support more modes of
	   operation, this unit test code should be updated too. */
	while ((opt = getopt_long(argc, (char *const *)argv,
				  ":p:r:w:i:", long_opts, NULL)) != -1) {
		/* Always consume the next argument if it does not
		   start with a dash.  We have to muck with getopt's
		   global variables to make this happen. */
		if (opt == ':' && argv[optind] && argv[optind][0] != '-') {
			optarg = strdup(argv[optind]);
			optind++;
			opt = optopt;
		} else if (optarg && optarg[0] == '-') {
			optarg = NULL;
			optind--;
		} else if (optarg) {
			optarg = strdup(optarg);
		}

		switch (opt) {
		case 'p':
			captured_programmer = optarg;
			break;
		case 'r':
			captured_operation = FLASHROM_READ;
			captured_op_filename = optarg;
			break;
		case 'w':
			captured_operation = FLASHROM_WRITE;
			captured_op_filename = optarg;
			break;
		case 'i':
			captured_region_param = optarg;
			break;
		case 0:
			/* long option */
			break;
		default:
			return 1;
		}
	}

	if (optind != argc) {
		/* Extra arguments we don't understand. */
		return 1;
	}

	rv = !flashrom_mock_success;
	captured_verify = captured_verify_int;

	if (captured_operation == FLASHROM_READ) {
		/* Write the mocked string we read from the ROM. */
		rv |= vb2_write_file(MOCK_TMPFILE_NAME, MOCK_ROM_CONTENTS,
				     strlen(MOCK_ROM_CONTENTS));
	} else if (captured_operation == FLASHROM_WRITE) {
		/* Capture the buffer contents we wrote to the ROM. */
		rv |= vb2_read_file(MOCK_TMPFILE_NAME, &captured_rom_contents,
				    &captured_rom_size);
	}

	return rv;
}

static void test_read_whole_chip(void)
{
	struct firmware_image image = {
		.programmer = "someprog",
	};

	TEST_SUCC(flashrom_read(&image, NULL),
		  "Flashrom read succeeds");
	TEST_STR_EQ(captured_programmer, "someprog",
		    "Using specified programmer");
	TEST_EQ(captured_operation, FLASHROM_READ, "Doing a read operation");
	TEST_EQ(captured_verify, FLASHROM_VERIFY_UNSPECIFIED,
		"Verification not enabled");
	TEST_STR_EQ(captured_op_filename, MOCK_TMPFILE_NAME,
		    "Reading to correct file");
	TEST_PTR_EQ(captured_region_param, NULL, "Not operating on a region");
	TEST_EQ(image.size, strlen(MOCK_ROM_CONTENTS), "Contents correct size");
	TEST_SUCC(memcmp(image.data, MOCK_ROM_CONTENTS, image.size),
		  "Buffer has correct contents");

	free(image.data);
}

static void test_read_region(void)
{
	struct firmware_image image = {
		.programmer = "someprog",
	};

	TEST_SUCC(flashrom_read(&image, "SOME_REGION"),
		  "Flashrom read succeeds");
	TEST_STR_EQ(captured_programmer, "someprog",
		    "Using specified programmer");
	TEST_EQ(captured_operation, FLASHROM_READ, "Doing a read operation");
	TEST_EQ(captured_verify, FLASHROM_VERIFY_UNSPECIFIED,
		"Verification not enabled");
	TEST_PTR_EQ(captured_op_filename, NULL,
		    "Not doing a read of the whole ROM");
	TEST_STR_EQ(captured_region_param, "SOME_REGION:" MOCK_TMPFILE_NAME,
		    "Reading to correct file and from correct region");
	TEST_EQ(image.size, strlen(MOCK_ROM_CONTENTS), "Contents correct size");
	TEST_SUCC(memcmp(image.data, MOCK_ROM_CONTENTS, image.size),
		  "Buffer has correct contents");

	free(image.data);
}

static void test_read_failure(void)
{
	struct firmware_image image = {
		.programmer = "someprog",
	};

	flashrom_mock_success = false;
	TEST_NEQ(flashrom_read(&image, "SOME_REGION"),
		 VB2_SUCCESS, "Flashrom read fails");
	flashrom_mock_success = true;
}

static void test_write_whole_chip(void)
{
	uint8_t buf[sizeof(MOCK_ROM_CONTENTS) - 1];
	struct firmware_image image = {
		.programmer = "someprog",
		.data = buf,
		.size = sizeof(buf),
	};

	memcpy(buf, MOCK_ROM_CONTENTS, sizeof(buf));

	TEST_SUCC(flashrom_write(&image, NULL),
		  "Flashrom write succeeds");
	TEST_STR_EQ(captured_programmer, "someprog",
		    "Using specified programmer");
	TEST_EQ(captured_operation, FLASHROM_WRITE, "Doing a write operation");
	TEST_EQ(captured_verify, FLASHROM_VERIFY_FAST,
		"Fast verification enabled");
	TEST_STR_EQ(captured_op_filename, MOCK_TMPFILE_NAME,
		    "Writing to correct file");
	TEST_PTR_EQ(captured_region_param, NULL, "Not operating on a region");
	TEST_EQ(captured_rom_size, strlen(MOCK_ROM_CONTENTS),
		"Contents correct size");
	TEST_SUCC(memcmp(captured_rom_contents, MOCK_ROM_CONTENTS,
			 captured_rom_size), "Buffer has correct contents");
}

static void test_write_region(void)
{
	uint8_t buf[sizeof(MOCK_ROM_CONTENTS) - 1];
	struct firmware_image image = {
		.programmer = "someprog",
		.data = buf,
		.size = sizeof(buf),
	};

	memcpy(buf, MOCK_ROM_CONTENTS, sizeof(buf));

	TEST_SUCC(flashrom_write(&image, "SOME_REGION"),
		  "Flashrom write succeeds");
	TEST_STR_EQ(captured_programmer, "someprog",
		    "Using specified programmer");
	TEST_EQ(captured_operation, FLASHROM_WRITE, "Doing a write operation");
	TEST_EQ(captured_verify, FLASHROM_VERIFY_FAST,
		"Fast verification enabled");
	TEST_PTR_EQ(captured_op_filename, NULL,
		    "Not doing a write of the whole ROM");
	TEST_STR_EQ(captured_region_param, "SOME_REGION:" MOCK_TMPFILE_NAME,
		    "Writing to correct file and from correct region");
	TEST_EQ(captured_rom_size, strlen(MOCK_ROM_CONTENTS),
		"Contents correct size");
	TEST_SUCC(memcmp(captured_rom_contents, MOCK_ROM_CONTENTS,
			 captured_rom_size), "Buffer has correct contents");
}

static void test_write_failure(void)
{
	uint8_t buf[20] = { 0 };
	struct firmware_image image = {
		.programmer = "someprog",
		.data = buf,
		.size = sizeof(buf),
	};

	flashrom_mock_success = false;
	TEST_NEQ(flashrom_write(&image, "SOME_REGION"),
		 VB2_SUCCESS, "Flashrom write fails");
	flashrom_mock_success = true;
}

int main(int argc, char *argv[])
{
	test_read_whole_chip();
	test_read_region();
	test_read_failure();
	test_write_whole_chip();
	test_write_region();
	test_write_failure();

	return gTestSuccess ? 0 : 255;
}
