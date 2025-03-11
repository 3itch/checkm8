/* Copyright 2020 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include <stdlib.h>
#include <strings.h>

#include "vboot_host.h"

static int lookup_helper(const char *str, const char *table[], size_t size,
			 unsigned int *out)
{
	unsigned int algo;
	char *e;

	/* try string first */
	for (algo = 0; algo < size; algo++)
		if (table[algo] && !strcasecmp(table[algo], str))
			goto found;

	/* fine, try number */
	algo = strtoul(str, &e, 0);
	if (!*str || (e && *e))
		/* that's not a number */
		return false;
	if (algo >= size || !table[algo])
		/* that's not a valid algorithm */
		return false;

 found:
	*out = algo;
	return true;
}

bool vb2_lookup_sig_alg(const char *str, enum vb2_signature_algorithm *sig_alg)
{
	return lookup_helper(str, vb2_sig_names, VB2_SIG_ALG_COUNT, sig_alg);
}

bool vb2_lookup_hash_alg(const char *str, enum vb2_hash_algorithm *hash_alg)
{
	return lookup_helper(str, vb2_hash_names, VB2_HASH_ALG_COUNT, hash_alg);
}
