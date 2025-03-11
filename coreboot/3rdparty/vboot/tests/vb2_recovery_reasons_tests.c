/* Copyright 2020 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * Tests for recovery reasons.
 */

#include "2recovery_reasons.h"
#include "common/tests.h"

static void get_recovery_reason_string_tests(void)
{
	int i;

	/* Recovery string should be non-null for any code */
	for (i = 0; i < 0x100; i++)
		TEST_PTR_NEQ(vb2_get_recovery_reason_string(i), NULL,
			     "Non-null reason");

	/* Validity check on one of the strings */
	TEST_EQ(strcmp(vb2_get_recovery_reason_string(VB2_RECOVERY_GBB_HEADER),
		       "Error parsing GBB header"), 0,
		"Recovery reason validity check");
}

int main(void)
{
	get_recovery_reason_string_tests();

	return gTestSuccess ? 0 : 255;
}
