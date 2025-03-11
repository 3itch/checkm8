/* Copyright 2019 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include <stdlib.h>
#include <string.h>

#include "subprocess.h"
#include "common/tests.h"

#define TEST_STRING "hello world"
#define TEST_STRING_LN TEST_STRING "\n"

static void test_subprocess_output_to_buffer(void)
{
	char output_buffer[__builtin_strlen(TEST_STRING_LN)];

	struct subprocess_target output = {
		.type = TARGET_BUFFER,
		.buffer = {
			.buf = output_buffer,
			.size = sizeof(output_buffer),
		},
	};
	const char *const argv[] = {
		"echo", TEST_STRING, NULL
	};

	TEST_EQ(subprocess_run(argv, &subprocess_null, &output, NULL), 0,
		"Return value of \"echo 'hello world'\" is 0");
	TEST_EQ(memcmp(output_buffer, TEST_STRING_LN, sizeof(output_buffer)), 0,
		"Output is \"hello world\\n\"");
	TEST_EQ(output.buffer.bytes_consumed, sizeof(output_buffer),
		"The entire output buffer should have been used.");
}

static void test_subprocess_output_to_buffer_null_terminated(void)
{
	char output_buffer[__builtin_strlen(TEST_STRING_LN) + 1];

	struct subprocess_target output = {
		.type = TARGET_BUFFER_NULL_TERMINATED,
		.buffer = {
			.buf = output_buffer,
			.size = sizeof(output_buffer),
		},
	};
	const char *const argv[] = {
		"echo", TEST_STRING, NULL
	};

	TEST_EQ(subprocess_run(argv, &subprocess_null, &output, NULL), 0,
		"Return value of \"echo 'hello world'\" is 0");
	TEST_STR_EQ(output_buffer, TEST_STRING_LN,
		    "Output is \"hello world\\n\"");
	TEST_EQ(output.buffer.bytes_consumed, sizeof(output_buffer) - 1,
		"The entire output buffer should have been used.");
}

#define TEST_STRING_2 "hello\0world!"

static void test_subprocess_input_buffer(void)
{
	char input_buffer[sizeof(TEST_STRING_2)];
	char output_buffer[20];
	char error_buffer[20];

	memcpy(input_buffer, TEST_STRING_2, sizeof(input_buffer));

	struct subprocess_target input = {
		.type = TARGET_BUFFER,
		.buffer = {
			.buf = input_buffer,
			.size = sizeof(input_buffer),
		},
	};
	struct subprocess_target output = {
		.type = TARGET_BUFFER_NULL_TERMINATED,
		.buffer = {
			.buf = output_buffer,
			.size = sizeof(output_buffer),
		},
	};
	struct subprocess_target error = {
		.type = TARGET_BUFFER_NULL_TERMINATED,
		.buffer = {
			.buf = error_buffer,
			.size = sizeof(error_buffer),
		},
	};
	const char *const argv[] = {"cat", NULL};

	TEST_EQ(subprocess_run(argv, &input, &output, &error), 0,
		"Return value of \"cat\" is 0");
	TEST_EQ(memcmp(output_buffer, TEST_STRING_2, sizeof(TEST_STRING_2)),
		0, "Output is \"hello\\0world!\"");
	TEST_STR_EQ(error_buffer, "", "No output captured on stderr");
	TEST_EQ(output.buffer.bytes_consumed, sizeof(TEST_STRING_2),
		"Bytes consumed is correct");
	TEST_EQ(error.buffer.bytes_consumed, 0, "No bytes used for error");
}

static void test_subprocess_input_null_terminated(void)
{
	char input_buffer[20];
	char output_buffer[20];
	char error_buffer[20];

	memcpy(input_buffer, TEST_STRING_2, sizeof(TEST_STRING_2));

	struct subprocess_target input = {
		.type = TARGET_BUFFER_NULL_TERMINATED,
		.buffer = {
			.buf = input_buffer,
		},
	};
	struct subprocess_target output = {
		.type = TARGET_BUFFER_NULL_TERMINATED,
		.buffer = {
			.buf = output_buffer,
			.size = sizeof(output_buffer),
		},
	};
	struct subprocess_target error = {
		.type = TARGET_BUFFER_NULL_TERMINATED,
		.buffer = {
			.buf = error_buffer,
			.size = sizeof(error_buffer),
		},
	};
	const char *const argv[] = {"cat", NULL};

	TEST_EQ(subprocess_run(argv, &input, &output, &error), 0,
		"Return value of \"cat\" is 0");
	TEST_STR_EQ(output_buffer, "hello", "Output is \"hello\"");
	TEST_STR_EQ(error_buffer, "", "No output captured on stderr");
	TEST_EQ(output.buffer.bytes_consumed, 5, "5 bytes used");
	TEST_EQ(error.buffer.bytes_consumed, 0, "No bytes used for error");
}

static void test_subprocess_small_output_buffer(void)
{
	char output_buffer[3];

	struct subprocess_target output = {
		.type = TARGET_BUFFER_NULL_TERMINATED,
		.buffer = {
			.buf = output_buffer,
			.size = sizeof(output_buffer),
		},
	};
	const char *const argv[] = {
		"echo", TEST_STRING, NULL
	};

	TEST_EQ(subprocess_run(argv, &subprocess_null, &output, NULL), 0,
		"Return value of \"echo 'hello world'\" is 0");
	TEST_STR_EQ(output_buffer, "he",
		    "Output is \"he\" (truncated to small buffer)");
	TEST_EQ(output.buffer.bytes_consumed, sizeof(output_buffer) - 1,
		"The entire output buffer should have been used.");
}

static void test_subprocess_return_code_failure(void)
{
	const char *const argv[] = {"false", NULL};

	TEST_NEQ(subprocess_run(argv, NULL, NULL, NULL), 0,
		 "Return value of \"false\" is nonzero");
}

struct cb_ctx {
	char buffer[49 * 1024];
	char *ptr;
};

static ssize_t input_cb(char *buf, size_t buf_sz, void *data)
{
	struct cb_ctx *ctx = (struct cb_ctx *)data;
	size_t len = (ctx->buffer + sizeof(ctx->buffer)) - ctx->ptr;
	if (len > buf_sz)
		len = buf_sz;
	memcpy(buf, ctx->ptr, len);
	ctx->ptr += len;
	return len;
}

static void test_subprocess_input_from_cb(void)
{
	struct cb_ctx ctx;
	char output_buffer[sizeof(ctx.buffer)];
	const char *const argv[] = {"cat", NULL};

	/* Initialize the input buffer with some data */
	for (size_t i = 0; i < sizeof(ctx.buffer); i++)
		ctx.buffer[i] = (char)i;
	ctx.ptr = ctx.buffer;

	struct subprocess_target output = {
		.type = TARGET_BUFFER,
		.buffer = {
			.buf = output_buffer,
			.size = sizeof(output_buffer),
		},
	};

	struct subprocess_target input = {
		.type = TARGET_CALLBACK,
		.callback = {
			.cb = input_cb,
			.data = &ctx,
		},
	};
	TEST_EQ(subprocess_run(argv, &input, &output, NULL), 0,
		"Return value of \"cat\" is zero.");
	TEST_EQ(memcmp(ctx.buffer, output_buffer, sizeof(output_buffer)), 0,
		"The input buffer is equal to the output buffer.");
	TEST_EQ(output.buffer.bytes_consumed, sizeof(output_buffer),
		"The entire output buffer should have been used.");
}

static ssize_t output_cb(char *buf, size_t buf_sz, void *data)
{
	struct cb_ctx *ctx = (struct cb_ctx *)data;
	if (ctx->ptr + buf_sz > ctx->buffer + sizeof(ctx->buffer)) {
		TEST_TRUE(0, "Test failed as there is not enough space in the "
			  "output buffer.");
		return -1;
	}
	memcpy(ctx->ptr, buf, buf_sz);
	ctx->ptr += buf_sz;
	return 0;
}

static void test_subprocess_output_to_cb(void)
{
	struct cb_ctx ctx;
	char output_buffer[sizeof(ctx.buffer)];
	const char *const argv[] = {
		"bc", "-l", NULL
	};

	ctx.ptr = ctx.buffer;

	struct subprocess_target input = {
		.type = TARGET_BUFFER_NULL_TERMINATED,
		.buffer = {
			.buf = (char *)"for (i = 0; i <= 10000; i += 1) i\n",
		},
	};

	struct subprocess_target target_via_buffer = {
		.type = TARGET_BUFFER,
		.buffer = {
			.buf = output_buffer,
			.size = sizeof(output_buffer),
		},
	};

	struct subprocess_target target_via_cb = {
		.type = TARGET_CALLBACK,
		.callback = {
			.cb = output_cb,
			.data = &ctx,
		},
	};

	TEST_EQ(subprocess_run(argv, &input, &target_via_buffer, NULL), 0,
		"Return value is zero when using buffer.");
	TEST_EQ(subprocess_run(argv, &input, &target_via_cb, NULL), 0,
		"Return value is zero when using callback.");
	TEST_EQ(ctx.ptr - ctx.buffer, target_via_buffer.buffer.bytes_consumed,
		"Both commmand invocations used the same number of bytes.");
	TEST_EQ(memcmp(output_buffer, ctx.buffer,
		       target_via_buffer.buffer.bytes_consumed),
		0, "Both output buffers are equivalent.");
}

int main(int argc, char *argv[])
{
	test_subprocess_output_to_buffer();
	test_subprocess_output_to_buffer_null_terminated();
	test_subprocess_input_buffer();
	test_subprocess_input_null_terminated();
	test_subprocess_small_output_buffer();
	test_subprocess_return_code_failure();
	test_subprocess_input_from_cb();
	test_subprocess_output_to_cb();

	return gTestSuccess ? 0 : 255;
}
