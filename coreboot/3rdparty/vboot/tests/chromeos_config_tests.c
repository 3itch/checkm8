/* Copyright 2020 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "2common.h"
#include "2return_codes.h"
#include "chromeos_config.h"
#include "common/tests.h"
#include "host_misc.h"

static struct {
	const char *path;
	const char *data;
} fakefs[] = {
	{"/run/chromeos-config/v1/name", "bleh_model"},
	{"/run/chromeos-config/v1/brand-code", "ZZCR"},
	{"/run/chromeos-config/v1/identity/sku-id", "7"},
	{"/run/chromeos-config/v1/firmware/image-name", "bloop"},
	{"/run/chromeos-config/v1/auto-night-light", "true"},
	{"/run/chromeos-config/v1/hardware-properties/is-lid-convertible",
	 "false"},
};

vb2_error_t vb2_read_file(const char *filepath, uint8_t **data_ptr,
			  uint32_t *size_ptr)
{
	*data_ptr = NULL;
	*size_ptr = 0;

	for (size_t i = 0; i < ARRAY_SIZE(fakefs); i++) {
		if (!strcmp(fakefs[i].path, filepath)) {
			*size_ptr = strlen(fakefs[i].data);
			*data_ptr = malloc(*size_ptr);

			if (!*data_ptr)
				return VB2_ERROR_READ_FILE_ALLOC;

			memcpy(*data_ptr, fakefs[i].data, *size_ptr);
			return VB2_SUCCESS;
		}
	}

	return VB2_ERROR_READ_FILE_OPEN;
}

static void test_get_string(void)
{
	char *val_out;

	TEST_EQ(chromeos_config_get_string("/firmware", "image-name", &val_out),
		VB2_SUCCESS, "Reading a string is successful");
	TEST_STR_EQ(val_out, "bloop", "The string is the correct value");
	free(val_out);
}

static void test_get_boolean_true(void)
{
	bool val_out;

	TEST_EQ(chromeos_config_get_boolean("/", "auto-night-light", &val_out),
		VB2_SUCCESS, "Reading a true boolean is successful");
	TEST_EQ(val_out, true, "The resulting boolean is true");
}

static void test_get_boolean_false(void)
{
	bool val_out;

	TEST_EQ(chromeos_config_get_boolean("/hardware-properties",
					    "is-lid-convertible", &val_out),
		VB2_SUCCESS, "Reading a false boolean is successful");
	TEST_EQ(val_out, false, "The resulting boolean is false");
}

static void test_get_integer(void)
{
	int val_out;

	TEST_EQ(chromeos_config_get_integer("/identity", "sku-id", &val_out),
		VB2_SUCCESS, "Reading an integer is successful");
	TEST_EQ(val_out, 7, "The resulting integer is correct");
}

static void test_get_no_exist(void)
{
	char *val_out;

	TEST_NEQ(
		chromeos_config_get_string("/this/does", "not-exist", &val_out),
		VB2_SUCCESS, "Reading non-existent property fails");
	free(val_out);
}

static void test_get_bad_path(void)
{
	char *val_out;

	TEST_NEQ(chromeos_config_get_string("name", "name", &val_out),
		 VB2_SUCCESS, "Reading bad path fails");
	free(val_out);
}

static void test_get_bad_path2(void)
{
	char *val_out;

	TEST_NEQ(chromeos_config_get_string("//name", "name", &val_out),
		 VB2_SUCCESS, "Reading bad path fails");
	free(val_out);
}

static void test_get_bad_property(void)
{
	char *val_out;

	TEST_NEQ(chromeos_config_get_string("/firmware", "/image-name",
					    &val_out),
		 VB2_SUCCESS, "Reading bad property fails");
	free(val_out);
}

static void test_get_not_boolean(void)
{
	bool val_out;

	TEST_NEQ(chromeos_config_get_boolean("/identity", "sku-id", &val_out),
		 VB2_SUCCESS, "Reading integer as boolean fails");
}

static void test_get_not_integer(void)
{
	int val_out;

	TEST_NEQ(chromeos_config_get_integer("/", "brand-code", &val_out),
		 VB2_SUCCESS, "Reading string as integer fails");
}

int main(int argc, char *argv[])
{
	test_get_string();
	test_get_boolean_true();
	test_get_boolean_false();
	test_get_integer();
	test_get_no_exist();
	test_get_bad_path();
	test_get_bad_path2();
	test_get_bad_property();
	test_get_not_boolean();
	test_get_not_integer();

	return gTestSuccess ? 0 : 255;
}
