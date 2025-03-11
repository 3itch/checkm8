/* Copyright 2011 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * Common functions used by tests.
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "2common.h"
#include "common/tests.h"

#define ENV_BUILD_RUN "BUILD_RUN"

const char *create_test_tmp_dir(const char *name)
{
	const char *build_run = getenv(ENV_BUILD_RUN);
	if (!build_run)
		die("Failed to get env %s\n", ENV_BUILD_RUN);

	char *dir = NULL;
	xasprintf(&dir, "%s/tests/%s.tmp", build_run, name);

	struct stat st = {0};
	if (stat(dir, &st) == -1 && mkdir(dir, 0700))
		die("Failed to create dir %s\n", dir);
	return dir;
}

/* Global test success flag. */
int gTestSuccess = 1;
int gTestAbortArmed = 0;
jmp_buf gTestJmpEnv;

static void print_passed(const char *preamble, const char *desc,
			 const char *comment)
{
	fprintf(stderr, "%s: %s ... " COL_GREEN "PASSED\n" COL_STOP,
		preamble, comment ? comment : desc);
}

static void print_failed(const char *preamble, const char *desc,
			 const char *comment)
{
	fprintf(stderr, "%s: %s ... " COL_RED "FAILED\n" COL_STOP,
		preamble, comment ? comment : desc);
}

int test_eq(int result, int expected,
	    const char *preamble, const char *desc, const char *comment)
{
	if (result == expected) {
		print_passed(preamble, desc, comment);
		return 1;
	} else {
		print_failed(preamble, desc, comment);
		fprintf(stderr, "	Expected: %#x (%d), got: %#x (%d)\n",
			expected, expected, result, result);
		gTestSuccess = 0;
		return 0;
	}
}

int test_neq(int result, int not_expected,
	     const char *preamble, const char *desc, const char *comment)
{
	if (result != not_expected) {
		print_passed(preamble, desc, comment);
		return 1;
	} else {
		print_failed(preamble, desc, comment);
		fprintf(stderr, "	Didn't expect %#x (%d), but got it.\n",
			not_expected, not_expected);
		gTestSuccess = 0;
		return 0;
	}
}

int test_ptr_eq(const void* result, const void* expected,
		const char *preamble, const char *desc, const char *comment)
{
	if (result == expected) {
		print_passed(preamble, desc, comment);
		return 1;
	} else {
		print_failed(preamble, desc, comment);
		fprintf(stderr, "	Expected: %#lx, got: %#lx\n",
			(long)expected, (long)result);
		gTestSuccess = 0;
		return 0;
	}
}

int test_ptr_neq(const void* result, const void* not_expected,
		 const char *preamble, const char *desc, const char *comment)
{
	if (result != not_expected) {
		print_passed(preamble, desc, comment);
		return 1;
	} else {
		print_failed(preamble, desc, comment);
		fprintf(stderr, "	Didn't expect %#lx, but got it\n",
			(long)not_expected);
		gTestSuccess = 0;
		return 0;
	}
}

int test_str_eq(const char* result, const char* expected,
		const char *preamble, const char *desc, const char *comment)
{
	if (!result || !expected) {
		print_failed(preamble, desc, comment);
		fprintf(stderr, "	String compare with NULL\n");
		gTestSuccess = 0;
		return 0;
	} else if (!strcmp(result, expected)) {
		print_passed(preamble, desc, comment);
		return 1;
	} else {
		print_failed(preamble, desc, comment);
		fprintf(stderr, "	Expected: \"%s\", got: \"%s\"\n",
			expected, result);
		gTestSuccess = 0;
		return 0;
	}
}

int test_str_neq(const char* result, const char* not_expected,
		 const char *preamble, const char *desc, const char *comment)
{
	if (!result || !not_expected) {
		print_failed(preamble, desc, comment);
		fprintf(stderr, "	String compare with NULL\n");
		gTestSuccess = 0;
		return 0;
	} else if (strcmp(result, not_expected)) {
		print_passed(preamble, desc, comment);
		fprintf(stderr, "%s: %s, %s ... " COL_GREEN "PASSED\n" COL_STOP,
			preamble, desc, comment);
		return 1;
	} else {
		print_failed(preamble, desc, comment);
		fprintf(stderr, "	Didn't expect: \"%s\", but got it\n",
			not_expected);
		gTestSuccess = 0;
		return 0;
	}
}

int test_succ(int result,
	      const char *preamble, const char *desc, const char *comment)
{
	if (result == 0) {
		print_passed(preamble, desc, comment);
	} else {
		print_failed(preamble, desc, comment);
		fprintf(stderr, "	Expected SUCCESS, got: %#x (%d)\n",
			result, result);
		gTestSuccess = 0;
	}
	return !result;
}

int test_fail(int result,
	      const char *preamble, const char *desc, const char *comment)
{
	if (result != 0) {
		print_passed(preamble, desc, comment);
	} else {
		print_failed(preamble, desc, comment);
		fprintf(stderr,
			"	Didn't expect SUCCESS (0), but got it\n");
		gTestSuccess = 0;
	}
	return result;
}

int test_true(int result,
	      const char *preamble, const char *desc, const char *comment)
{
	if (result) {
		print_passed(preamble, desc, comment);
	} else {
		print_failed(preamble, desc, comment);
		fprintf(stderr, "	Expected TRUE, got 0\n");
		gTestSuccess = 0;
	}
	return result;
}

int test_false(int result,
	       const char *preamble, const char *desc, const char *comment)
{
	if (!result) {
		print_passed(preamble, desc, comment);
	} else {
		print_failed(preamble, desc, comment);
		fprintf(stderr, "	Expected FALSE, got: %#lx\n",
			(long)result);
		gTestSuccess = 0;
	}
	return !result;
}

int test_abort(int aborted,
	       const char *preamble, const char *desc, const char *comment)
{
	if (aborted) {
		print_passed(preamble, desc, comment);
	} else {
		print_failed(preamble, desc, comment);
		fprintf(stderr, "	Expected ABORT, but did not get it\n");
		gTestSuccess = 0;
	}
	return aborted;
}

void vb2ex_abort(void)
{
	/*
	 * If expecting an abort call, jump back to TEST_ABORT macro.
	 * Otherwise, force exit to ensure the test fails.
	 */
	if (gTestAbortArmed) {
		longjmp(gTestJmpEnv, 1);
	} else {
		fprintf(stderr, COL_RED "Unexpected ABORT encountered, "
			"exiting\n" COL_STOP);
		exit(1);
	}
}
