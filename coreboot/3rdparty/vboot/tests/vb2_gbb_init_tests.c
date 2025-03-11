/* Copyright 2022 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * Test that vb2_get_gbb aborts if gbb_offset is not initialized. This
 * is in a separate file from vb2_gbb_tests so that vb2_get_gbb is not
 * mocked.
 */

#include "2common.h"
#include "common/tests.h"

static void test_abort_if_gbb_uninit(void) {
	struct vb2_context *ctx;
	uint8_t workbuf[VB2_KERNEL_WORKBUF_RECOMMENDED_SIZE]
		__attribute__((aligned(VB2_WORKBUF_ALIGN)));
	TEST_SUCC(vb2api_init(workbuf, sizeof(workbuf), &ctx),
		  "vb2api_init failed");
	TEST_ABORT(vb2_get_gbb(ctx), "gbb_offset is not initialized");
}

int main(int argc, char *argv[])
{
	test_abort_if_gbb_uninit();
	return gTestSuccess ? 0 : 255;
}
