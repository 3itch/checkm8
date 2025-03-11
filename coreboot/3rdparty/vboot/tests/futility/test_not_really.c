/* Copyright 2014 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include <stdio.h>

#include "2struct.h"
#include "common/tests.h"

int main(int argc, char *argv[])
{
	TEST_EQ(sizeof(struct vb2_gbb_header),
		EXPECTED_VB2_GBB_HEADER_SIZE,
		"sizeof(struct vb2_gbb_header)");

	TEST_EQ(0, 0, "Not Really A");

	return !gTestSuccess;
}
