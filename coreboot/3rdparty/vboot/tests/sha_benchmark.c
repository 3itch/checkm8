/* Copyright 2011 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "2common.h"
#include "2sha.h"
#include "2sysincludes.h"
#include "common/timer_utils.h"
#include "host_common.h"

#define TEST_BUFFER_SIZE 4000000

int main(int argc, char *argv[]) {
	int i;
	double speed;
	uint32_t msecs;
	uint8_t *buffer = malloc(TEST_BUFFER_SIZE);
	struct vb2_hash hash;
	ClockTimerState ct;

	/* Iterate through all the hash functions. */
	for (i = VB2_HASH_SHA1; i < VB2_HASH_ALG_COUNT; i++) {
		StartTimer(&ct);
		vb2_hash_calculate(false, buffer, TEST_BUFFER_SIZE, i, &hash);
		StopTimer(&ct);

		msecs = GetDurationMsecs(&ct);
		speed = ((TEST_BUFFER_SIZE / 10e6)
			 / (msecs / 10e3)); /* Mbytes/sec */

		fprintf(stderr,
			"# %s Time taken = %u ms, Speed = %f Mbytes/sec\n",
			vb2_get_hash_algorithm_name(i), msecs, speed);
		fprintf(stdout, "mbytes_per_sec_%s:%f\n",
			vb2_get_hash_algorithm_name(i), speed);
	}

	free(buffer);
	return 0;
}
