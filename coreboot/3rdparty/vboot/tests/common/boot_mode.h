/* Copyright 2022 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include "2api.h"

void _set_boot_mode(struct vb2_context *ctx, enum vb2_boot_mode boot_mode,
		    uint32_t recovery_reason, ...);

/*
 * Set the boot mode to the expected boot mode with the recovery reason if
 * given. Also, set the corresponding ctx flag.
 *
 * @param ctx			Vboot context.
 * @param boot_mode		Boot mode to be set.
 * @param recovery_reason	Recovery reason set to sd->recovery_reason.
 */
#define SET_BOOT_MODE(ctx, boot_mode, ...) \
	_set_boot_mode(ctx, boot_mode, ##__VA_ARGS__, 0)
