/* Copyright 2024 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "2return_codes.h"
#include "cbfstool.h"
#include "common/tests.h"

#define ME "cbfstool_tests"

/* Utility functions. */

static bool is_file(const char *path)
{
	struct stat st = {0};
	return stat(path, &st) == 0 && S_ISREG(st.st_mode);
}

/* Setup and teardown functions. */

const char *tmp_dir;

static void setup(void)
{
	tmp_dir = create_test_tmp_dir(ME);
}

static void teardown(void)
{
	free((char *)tmp_dir);
}

/* Test functions. */

#define IMAGE "tests/futility/data/bios_coachz_cbfs.bin"

static void cbfstool_file_exists_tests(void)
{
	/* Region not exists. */
	TEST_FALSE(cbfstool_file_exists(IMAGE, "NO_SUCH_REGION", "config"),
		   "region NO_SUCH_REGION not exists");

	/* Default FMAP region. */
	TEST_TRUE(cbfstool_file_exists(IMAGE, NULL, "font.bin"),
		  "font.bin found in COREBOOT");

	/* File not found. */
	TEST_FALSE(cbfstool_file_exists(IMAGE, "FW_MAIN_A", "font.bin"),
		   "font.bin not found in FW_MAIN_A");

	/* File found in specified region. */
	TEST_TRUE(cbfstool_file_exists(IMAGE, "FW_MAIN_A", "ecrw"),
		  "ecrw found in FW_MAIN_A");
}

static void cbfstool_extract_tests(void)
{
	char *tmp_file = NULL;
	xasprintf(&tmp_file, "%s/tmp_file", tmp_dir);

	/* Default FMAP region. */
	unlink(tmp_file);
	TEST_EQ(cbfstool_extract(IMAGE, NULL, "font.bin", tmp_file), 0,
		"extract font.bin from COREBOOT");
	TEST_TRUE(is_file(tmp_file), "  extracted");

	/* File not found. */
	unlink(tmp_file);
	TEST_NEQ(cbfstool_extract(IMAGE, "FW_MAIN_A", "font.bin", tmp_file), 0,
		 "extract font.bin from FW_MAIN_A");

	/* File from specified region. */
	unlink(tmp_file);
	TEST_EQ(cbfstool_extract(IMAGE, "FW_MAIN_A", "ecrw", tmp_file), 0,
		"extract ecrw from FW_MAIN_A");
	TEST_TRUE(is_file(tmp_file), "  extracted");

	free(tmp_file);
}

static void cbfstool_get_config_bool_tests(void)
{
	bool value;
	vb2_error_t rv;

	/* File not found */
	value = true;
	rv = cbfstool_get_config_bool("no_such_file", NULL,
				      "CONFIG_CHROMEOS", &value);
	TEST_FAIL(rv, "file not found");
	TEST_FALSE(value, "  value is false");

	/* Config not found */
	value = true;
	rv = cbfstool_get_config_bool(IMAGE, NULL,
				      "CONFIG_NOT_FOUND", &value);
	TEST_SUCC(rv, "config not found");
	TEST_FALSE(value, "  value is false");

	/* Config CHROMEOS */
	value = false;
	rv = cbfstool_get_config_bool(IMAGE, NULL,
				      "CONFIG_CHROMEOS", &value);
	TEST_SUCC(rv, "get CHROMEOS value");
	TEST_TRUE(value, "  value is true");

	/* Config CHROMEOS from FW_MAIN_A */
	value = false;
	rv = cbfstool_get_config_bool(IMAGE, "FW_MAIN_A",
				      "CONFIG_CHROMEOS", &value);
	TEST_SUCC(rv, "get CHROMEOS value from FW_MAIN_A");
	TEST_TRUE(value, "  value is true");
}

static void cbfstool_get_config_string_tests(void)
{
	char *value;
	char init_value[] = "INIT_VALUE";
	vb2_error_t rv;

	/* Config not found */
	value = init_value;
	rv = cbfstool_get_config_string(IMAGE, NULL,
					"CONFIG_NOT_FOUND", &value);
	TEST_FAIL(rv, "config not found");
	TEST_PTR_EQ(value, NULL, "  value is null");

	/* Config MAINBOARD_PART_NUMBER */
	value = NULL;
	rv = cbfstool_get_config_string(IMAGE, NULL,
					"CONFIG_MAINBOARD_PART_NUMBER", &value);
	TEST_SUCC(rv, "get MAINBOARD_PART_NUMBER value");
	TEST_PTR_NEQ(value, NULL, "  value not null");
	TEST_EQ(strcmp(value, "Coachz"), 0, "  value is Coachz");
}

int main(int argc, char *argv[])
{
	setup();

	cbfstool_file_exists_tests();
	cbfstool_extract_tests();
	cbfstool_get_config_bool_tests();
	cbfstool_get_config_string_tests();

	teardown();

	return gTestSuccess ? 0 : 255;
}
